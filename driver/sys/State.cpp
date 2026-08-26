#include "Kernel.hpp"

namespace splithello::kernel {
namespace {

constexpr Size kPolicySlots = 256;
constexpr Size kTcpSlots = 512;
constexpr Size kUdpSlots = 512;
constexpr Size kDnsSlots = 512;
constexpr Size kQuicSlots = 256;
constexpr Size kHopSlots = 256;
constexpr LONGLONG kPolicyLifetime = 15LL * 10'000'000LL;
constexpr LONGLONG kFlowLifetime = 60LL * 10'000'000LL;
constexpr LONGLONG kDnsLifetime = 15LL * 10'000'000LL;
constexpr LONGLONG kQuicProbeLifetime = 2LL * 10'000'000LL;
constexpr LONG kMaximumOutstanding = 4096;

struct ConfigurationSnapshot {
    EX_RUNDOWN_REF rundown{};
    wfp::Configuration configuration{};
};

struct PolicySlot {
    bool valid = false;
    LONGLONG expires = 0;
    wfp::PolicyCommand command{};
};

struct UdpSlot {
    bool valid = false;
    wfp::AddressFamily family = wfp::AddressFamily::Ipv4;
    U8 localAddress[16]{};
    U8 remoteAddress[16]{};
    U16 localPort = 0;
    U16 remotePort = 0;
    LONGLONG expires = 0;
};

struct TcpSlot {
    bool valid = false;
    wfp::AddressFamily family = wfp::AddressFamily::Ipv4;
    U8 localAddress[16]{};
    U8 remoteAddress[16]{};
    U16 localPort = 0;
    LONGLONG expires = 0;
};

struct DnsSlot {
    bool valid = false;
    wfp::AddressFamily family = wfp::AddressFamily::Ipv4;
    U8 clientAddress[16]{};
    U8 resolverAddress[16]{};
    U16 clientPort = 0;
    U16 transactionId = 0;
    COMPARTMENT_ID compartment = UNSPECIFIED_COMPARTMENT_ID;
    U32 interfaceIndex = 0;
    U32 subInterfaceIndex = 0;
    LONGLONG expires = 0;
};

struct QuicSlot {
    bool valid = false;
    bool responded = false;
    wfp::AddressFamily family = wfp::AddressFamily::Ipv4;
    U8 remoteAddress[16]{};
    U16 localPort = 0;
    LONGLONG deadline = 0;
    LONGLONG expires = 0;
};

struct HopSlot {
    bool valid = false;
    wfp::AddressFamily family = wfp::AddressFamily::Ipv4;
    U8 remoteAddress[16]{};
    U16 localPort = 0;
    U8 pathHops = 0;
    LONGLONG expires = 0;
};

struct Counters {
    volatile LONG64 values[14]{};
    volatile LONG outstanding = 0;
    volatile LONG peak = 0;
};

KSPIN_LOCK gConfigurationLock{};
KSPIN_LOCK gTableLock{};
ConfigurationSnapshot* gConfiguration = nullptr;
PolicySlot gPolicies[kPolicySlots]{};
TcpSlot gTcpFlows[kTcpSlots]{};
UdpSlot gUdpFlows[kUdpSlots]{};
DnsSlot gDnsQueries[kDnsSlots]{};
QuicSlot gQuicFlows[kQuicSlots]{};
HopSlot gHops[kHopSlots]{};
Size gNextPolicy = 0;
Size gNextTcp = 0;
Size gNextUdp = 0;
Size gNextDns = 0;
Size gNextQuic = 0;
Size gNextHop = 0;
volatile LONG gPolicyCount = 0;
volatile LONG gDnsProxyPort = 0;
volatile LONG gQuicMode = static_cast<LONG>(wfp::QuicMode::Allow);
volatile LONG gActive = FALSE;
Counters gCounters{};
KEVENT gNoInjections{};

LONGLONG Now() noexcept {
    LARGE_INTEGER value{};
    KeQuerySystemTimePrecise(&value);
    return value.QuadPart;
}

Size AddressLength(wfp::AddressFamily family) noexcept {
    return family == wfp::AddressFamily::Ipv4 ? 4U : 16U;
}

bool EqualBytes(const U8* left, const U8* right, Size length) noexcept {
    for (Size index = 0; index < length; ++index) {
        if (left[index] != right[index]) return false;
    }
    return true;
}

void CopyBytes(U8* destination, const U8* source, Size length) noexcept {
    for (Size index = 0; index < length; ++index) destination[index] = source[index];
}

wchar_t Fold(wchar_t value) noexcept {
    return value >= L'A' && value <= L'Z'
               ? static_cast<wchar_t>(value + (L'a' - L'A'))
               : value;
}

bool WildcardMatch(const wchar_t* pattern, Size patternLength,
                   const wchar_t* text, Size textLength) noexcept {
    Size patternIndex = 0;
    Size textIndex = 0;
    Size star = static_cast<Size>(-1);
    Size retry = 0;
    while (textIndex < textLength) {
        if (patternIndex < patternLength &&
            (pattern[patternIndex] == L'?' ||
             Fold(pattern[patternIndex]) == Fold(text[textIndex]))) {
            ++patternIndex;
            ++textIndex;
        } else if (patternIndex < patternLength && pattern[patternIndex] == L'*') {
            star = patternIndex++;
            retry = textIndex;
        } else if (star != static_cast<Size>(-1)) {
            patternIndex = star + 1;
            textIndex = ++retry;
        } else {
            return false;
        }
    }
    while (patternIndex < patternLength && pattern[patternIndex] == L'*') {
        ++patternIndex;
    }
    return patternIndex == patternLength;
}

bool RuleMatches(const wfp::ProcessRule& rule,
                 const wchar_t* path, Size pathLength) noexcept {
    const Size ruleLength = rule.length;
    if (ruleLength == 0 || ruleLength > wfp::kMaximumRuleCharacters) return false;
    if (WildcardMatch(rule.pattern, ruleLength, path, pathLength)) return true;
    Size base = pathLength;
    while (base != 0 && path[base - 1] != L'\\' && path[base - 1] != L'/') --base;
    return WildcardMatch(rule.pattern, ruleLength, path + base, pathLength - base);
}

bool ValidConfiguration(const wfp::Configuration& configuration) noexcept {
    if (configuration.header.version != wfp::kProtocolVersion ||
        configuration.header.size != sizeof(configuration) ||
        configuration.proxyProcessId == 0 || configuration.proxyPort == 0 ||
        configuration.dnsProxyPort == 0 ||
        configuration.quicMode > wfp::QuicMode::Allow ||
        configuration.includeCount > wfp::kMaximumRulesPerList ||
        configuration.excludeCount > wfp::kMaximumRulesPerList) {
        return false;
    }
    for (Size index = 0; index < configuration.includeCount; ++index) {
        if (configuration.includes[index].length == 0 ||
            configuration.includes[index].length > wfp::kMaximumRuleCharacters) return false;
    }
    for (Size index = 0; index < configuration.excludeCount; ++index) {
        if (configuration.excludes[index].length == 0 ||
            configuration.excludes[index].length > wfp::kMaximumRuleCharacters) return false;
    }
    return true;
}

}  // namespace

void InitializeState() noexcept {
    KeInitializeSpinLock(&gConfigurationLock);
    KeInitializeSpinLock(&gTableLock);
    KeInitializeEvent(&gNoInjections, NotificationEvent, TRUE);
    InterlockedExchange(&gDnsProxyPort, 0);
    InterlockedExchange(&gQuicMode, static_cast<LONG>(wfp::QuicMode::Allow));
    InterlockedExchange(&gActive, FALSE);
}

void ShutdownState() noexcept {
    SetActive(false);
    InterlockedExchange(&gDnsProxyPort, 0);
    InterlockedExchange(&gQuicMode, static_cast<LONG>(wfp::QuicMode::Allow));
    ConfigurationSnapshot* retired = nullptr;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gConfigurationLock, &oldIrql);
    retired = gConfiguration;
    gConfiguration = nullptr;
    KeReleaseSpinLock(&gConfigurationLock, oldIrql);
    if (retired != nullptr) {
        ExWaitForRundownProtectionRelease(&retired->rundown);
        ExFreePoolWithTag(retired, kPoolTag);
    }
}

NTSTATUS SetConfiguration(const wfp::Configuration& configuration) noexcept {
    if (!ValidConfiguration(configuration)) return STATUS_INVALID_PARAMETER;
    auto* replacement = static_cast<ConfigurationSnapshot*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ConfigurationSnapshot), kPoolTag));
    if (replacement == nullptr) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(replacement, sizeof(*replacement));
    ExInitializeRundownProtection(&replacement->rundown);
    replacement->configuration = configuration;

    ConfigurationSnapshot* retired = nullptr;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gConfigurationLock, &oldIrql);
    retired = gConfiguration;
    gConfiguration = replacement;
    InterlockedExchange(&gDnsProxyPort, configuration.dnsProxyPort);
    InterlockedExchange(&gQuicMode, static_cast<LONG>(configuration.quicMode));
    KeReleaseSpinLock(&gConfigurationLock, oldIrql);
    if (retired != nullptr) {
        ExWaitForRundownProtectionRelease(&retired->rundown);
        ExFreePoolWithTag(retired, kPoolTag);
    }
    return STATUS_SUCCESS;
}

ConfigurationLease AcquireConfiguration() noexcept {
    ConfigurationLease lease{};
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gConfigurationLock, &oldIrql);
    auto* snapshot = gConfiguration;
    if (snapshot != nullptr && ExAcquireRundownProtection(&snapshot->rundown)) {
        lease.value = &snapshot->configuration;
        lease.snapshot = snapshot;
    }
    KeReleaseSpinLock(&gConfigurationLock, oldIrql);
    return lease;
}

void ReleaseConfiguration(ConfigurationLease* lease) noexcept {
    if (lease != nullptr && lease->snapshot != nullptr) {
        auto* snapshot = static_cast<ConfigurationSnapshot*>(lease->snapshot);
        ExReleaseRundownProtection(&snapshot->rundown);
        lease->snapshot = nullptr;
        lease->value = nullptr;
    }
}

bool IsActive() noexcept {
    return InterlockedCompareExchange(&gActive, FALSE, FALSE) != FALSE;
}

U16 FastDnsProxyPort() noexcept {
    return static_cast<U16>(InterlockedCompareExchange(&gDnsProxyPort, 0, 0));
}

wfp::QuicMode FastQuicMode() noexcept {
    return static_cast<wfp::QuicMode>(
        InterlockedCompareExchange(&gQuicMode, 0, 0));
}

void SetActive(bool active) noexcept {
    InterlockedExchange(&gActive, active ? TRUE : FALSE);
    if (active) return;

    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gPolicies) slot.valid = false;
    for (auto& slot : gTcpFlows) slot.valid = false;
    for (auto& slot : gUdpFlows) slot.valid = false;
    for (auto& slot : gDnsQueries) slot.valid = false;
    for (auto& slot : gQuicFlows) slot.valid = false;
    for (auto& slot : gHops) slot.valid = false;
    gNextPolicy = 0;
    gNextTcp = 0;
    gNextUdp = 0;
    gNextDns = 0;
    gNextQuic = 0;
    gNextHop = 0;
    InterlockedExchange(&gPolicyCount, 0);
    KeReleaseSpinLock(&gTableLock, oldIrql);
}

bool ProcessMatches(const wfp::Configuration& configuration,
                    const FWP_BYTE_BLOB* applicationId) noexcept {
    if (applicationId == nullptr || applicationId->data == nullptr ||
        applicationId->size < sizeof(wchar_t)) return false;
    const auto* path = reinterpret_cast<const wchar_t*>(applicationId->data);
    Size pathLength = applicationId->size / sizeof(wchar_t);
    while (pathLength != 0 && path[pathLength - 1] == L'\0') --pathLength;
    for (Size index = 0; index < configuration.excludeCount; ++index) {
        if (RuleMatches(configuration.excludes[index], path, pathLength)) return false;
    }
    if (configuration.includeCount == 0) return true;
    for (Size index = 0; index < configuration.includeCount; ++index) {
        if (RuleMatches(configuration.includes[index], path, pathLength)) return true;
    }
    return false;
}

NTSTATUS ArmPolicy(const wfp::PolicyCommand& command) noexcept {
    if (command.header.version != wfp::kProtocolVersion ||
        command.header.size != sizeof(command) || command.localPort == 0 ||
        (command.family != wfp::AddressFamily::Ipv4 &&
         command.family != wfp::AddressFamily::Ipv6) ||
        command.mode > wfp::PacketMode::IpFragment ||
        command.coverSniLength > wfp::kMaximumCoverSniBytes) {
        return STATUS_INVALID_PARAMETER;
    }
    const auto now = Now();
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    if (!IsActive()) {
        KeReleaseSpinLock(&gTableLock, oldIrql);
        return STATUS_DEVICE_NOT_READY;
    }
    wfp::PolicyCommand prepared = command;
    if (prepared.mode == wfp::PacketMode::FakeAutoTtl) {
        const auto length = AddressLength(prepared.family);
        const HopSlot* match = nullptr;
        for (auto& hop : gHops) {
            if (hop.valid && hop.expires < now) hop.valid = false;
            if (hop.valid && hop.family == prepared.family &&
                hop.localPort == prepared.localPort &&
                EqualBytes(hop.remoteAddress, prepared.remoteAddress, length)) {
                match = &hop;
                break;
            }
        }
        if (match == nullptr || match->pathHops < 3) {
            prepared.mode = wfp::PacketMode::FakeBadSequence;
            prepared.fakeSequenceDelta = -10000;
        } else {
            prepared.fakeTtl = static_cast<U8>(
                match->pathHops > 3 ? match->pathHops - 1 : 2);
        }
    }
    auto& slot = gPolicies[gNextPolicy++ % kPolicySlots];
    const bool occupied = slot.valid;
    slot.valid = true;
    slot.expires = now + kPolicyLifetime;
    slot.command = prepared;
    if (!occupied) InterlockedIncrement(&gPolicyCount);
    KeReleaseSpinLock(&gTableLock, oldIrql);
    Increment(Counter::PoliciesArmed);
    return STATUS_SUCCESS;
}

void ObserveTcpHop(wfp::AddressFamily family, const U8* remoteAddress,
                   U16 localPort, U8 receivedTtl) noexcept {
    if (remoteAddress == nullptr || localPort == 0 || receivedTtl == 0) return;
    U16 initial = 0;
    const U16 candidates[3]{64, 128, 255};
    for (const U16 candidate : candidates) {
        if (receivedTtl <= candidate) {
            initial = candidate;
            break;
        }
    }
    if (initial == 0 || initial == receivedTtl) return;
    const U16 difference = static_cast<U16>(initial - receivedTtl);
    if (difference > 255) return;
    const auto length = AddressLength(family);
    const auto expires = Now() + kPolicyLifetime;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    auto& slot = gHops[gNextHop++ % kHopSlots];
    slot.valid = true;
    slot.family = family;
    CopyBytes(slot.remoteAddress, remoteAddress, length);
    slot.localPort = localPort;
    slot.pathHops = static_cast<U8>(difference);
    slot.expires = expires;
    KeReleaseSpinLock(&gTableLock, oldIrql);
}

bool TakePolicy(wfp::AddressFamily family, const U8* remoteAddress,
                U16 localPort, wfp::PolicyCommand* command) noexcept {
    if (remoteAddress == nullptr || command == nullptr ||
        InterlockedCompareExchange(&gPolicyCount, 0, 0) == 0) return false;
    const auto now = Now();
    const auto addressLength = AddressLength(family);
    bool found = false;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gPolicies) {
        if (slot.valid && slot.expires < now) {
            slot.valid = false;
            InterlockedDecrement(&gPolicyCount);
        }
        if (slot.valid && slot.command.family == family &&
            slot.command.localPort == localPort &&
            EqualBytes(slot.command.remoteAddress, remoteAddress, addressLength)) {
            *command = slot.command;
            slot.valid = false;
            InterlockedDecrement(&gPolicyCount);
            found = true;
            break;
        }
    }
    KeReleaseSpinLock(&gTableLock, oldIrql);
    if (found) Increment(Counter::PoliciesApplied);
    return found;
}

bool HasPolicy(wfp::AddressFamily family, const U8* remoteAddress,
               U16 localPort) noexcept {
    if (remoteAddress == nullptr ||
        InterlockedCompareExchange(&gPolicyCount, 0, 0) == 0) return false;
    const auto now = Now();
    const auto addressLength = AddressLength(family);
    bool found = false;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gPolicies) {
        if (slot.valid && slot.expires < now) {
            slot.valid = false;
            InterlockedDecrement(&gPolicyCount);
        }
        if (slot.valid && slot.command.family == family &&
            slot.command.localPort == localPort &&
            EqualBytes(slot.command.remoteAddress, remoteAddress, addressLength)) {
            found = true;
            break;
        }
    }
    KeReleaseSpinLock(&gTableLock, oldIrql);
    return found;
}

void RememberSelectedTcp(wfp::AddressFamily family, const U8* localAddress,
                         U16 localPort, const U8* remoteAddress) noexcept {
    if (localAddress == nullptr || remoteAddress == nullptr || localPort == 0) return;
    const auto length = AddressLength(family);
    const auto expires = Now() + kFlowLifetime;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    auto& slot = gTcpFlows[gNextTcp++ % kTcpSlots];
    slot.valid = true;
    slot.family = family;
    CopyBytes(slot.localAddress, localAddress, length);
    CopyBytes(slot.remoteAddress, remoteAddress, length);
    slot.localPort = localPort;
    slot.expires = expires;
    KeReleaseSpinLock(&gTableLock, oldIrql);
}

bool IsSelectedTcp(wfp::AddressFamily family, const U8* localAddress,
                   U16 localPort, const U8* remoteAddress) noexcept {
    if (localAddress == nullptr || remoteAddress == nullptr || localPort == 0) return false;
    const auto now = Now();
    const auto length = AddressLength(family);
    bool found = false;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gTcpFlows) {
        if (slot.valid && slot.expires < now) slot.valid = false;
        if (slot.valid && slot.family == family && slot.localPort == localPort &&
            EqualBytes(slot.localAddress, localAddress, length) &&
            EqualBytes(slot.remoteAddress, remoteAddress, length)) {
            slot.expires = now + kFlowLifetime;
            found = true;
            break;
        }
    }
    KeReleaseSpinLock(&gTableLock, oldIrql);
    return found;
}

void RememberSelectedUdp(wfp::AddressFamily family, const U8* localAddress,
                         U16 localPort, const U8* remoteAddress,
                         U16 remotePort) noexcept {
    const auto length = AddressLength(family);
    const auto expires = Now() + kFlowLifetime;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    auto& slot = gUdpFlows[gNextUdp++ % kUdpSlots];
    slot.valid = true;
    slot.family = family;
    CopyBytes(slot.localAddress, localAddress, length);
    CopyBytes(slot.remoteAddress, remoteAddress, length);
    slot.localPort = localPort;
    slot.remotePort = remotePort;
    slot.expires = expires;
    KeReleaseSpinLock(&gTableLock, oldIrql);
}

bool IsSelectedUdp(wfp::AddressFamily family, const U8* localAddress,
                   U16 localPort, const U8* remoteAddress,
                   U16 remotePort) noexcept {
    const auto now = Now();
    const auto length = AddressLength(family);
    bool found = false;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gUdpFlows) {
        if (slot.valid && slot.expires < now) slot.valid = false;
        if (slot.valid && slot.family == family && slot.localPort == localPort &&
            slot.remotePort == remotePort &&
            EqualBytes(slot.localAddress, localAddress, length) &&
            EqualBytes(slot.remoteAddress, remoteAddress, length)) {
            slot.expires = now + kFlowLifetime;
            found = true;
            break;
        }
    }
    KeReleaseSpinLock(&gTableLock, oldIrql);
    return found;
}

void RememberDnsQuery(wfp::AddressFamily family, const U8* clientAddress,
                      U16 clientPort, const U8* resolverAddress,
                      U16 transactionId, COMPARTMENT_ID compartment,
                      U32 interfaceIndex, U32 subInterfaceIndex) noexcept {
    const auto length = AddressLength(family);
    const auto expires = Now() + kDnsLifetime;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    auto& slot = gDnsQueries[gNextDns++ % kDnsSlots];
    slot.valid = true;
    slot.family = family;
    CopyBytes(slot.clientAddress, clientAddress, length);
    CopyBytes(slot.resolverAddress, resolverAddress, length);
    slot.clientPort = clientPort;
    slot.transactionId = transactionId;
    slot.compartment = compartment;
    slot.interfaceIndex = interfaceIndex;
    slot.subInterfaceIndex = subInterfaceIndex;
    slot.expires = expires;
    KeReleaseSpinLock(&gTableLock, oldIrql);
}

bool TakeDnsQuery(wfp::AddressFamily family, U16 clientPortToken,
                  U16 transactionId, U8* clientAddress,
                  U16* clientPort, U8* resolverAddress,
                  COMPARTMENT_ID* compartment, U32* interfaceIndex,
                  U32* subInterfaceIndex) noexcept {
    if (clientAddress == nullptr || clientPort == nullptr ||
        resolverAddress == nullptr || compartment == nullptr ||
        interfaceIndex == nullptr || subInterfaceIndex == nullptr) return false;
    const auto now = Now();
    const auto length = AddressLength(family);
    bool found = false;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gDnsQueries) {
        if (slot.valid && slot.expires < now) slot.valid = false;
        if (slot.valid && slot.family == family &&
            slot.clientPort == clientPortToken &&
            slot.transactionId == transactionId) {
            CopyBytes(clientAddress, slot.clientAddress, length);
            CopyBytes(resolverAddress, slot.resolverAddress, length);
            *clientPort = slot.clientPort;
            *compartment = slot.compartment;
            *interfaceIndex = slot.interfaceIndex;
            *subInterfaceIndex = slot.subInterfaceIndex;
            slot.valid = false;
            found = true;
            break;
        }
    }
    KeReleaseSpinLock(&gTableLock, oldIrql);
    return found;
}

bool AdaptiveQuicShouldBlock(wfp::AddressFamily family,
                             const U8* remoteAddress, U16 localPort) noexcept {
    const auto now = Now();
    const auto length = AddressLength(family);
    bool block = false;
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gQuicFlows) {
        if (slot.valid && slot.expires < now) slot.valid = false;
        if (slot.valid && slot.family == family && slot.localPort == localPort &&
            EqualBytes(slot.remoteAddress, remoteAddress, length)) {
            slot.expires = now + kFlowLifetime;
            block = !slot.responded && now >= slot.deadline;
            KeReleaseSpinLock(&gTableLock, oldIrql);
            return block;
        }
    }
    auto& slot = gQuicFlows[gNextQuic++ % kQuicSlots];
    slot.valid = true;
    slot.responded = false;
    slot.family = family;
    CopyBytes(slot.remoteAddress, remoteAddress, length);
    slot.localPort = localPort;
    slot.deadline = now + kQuicProbeLifetime;
    slot.expires = now + kFlowLifetime;
    KeReleaseSpinLock(&gTableLock, oldIrql);
    Increment(Counter::PrimedQuic);
    return block;
}

void ObserveQuicResponse(wfp::AddressFamily family, const U8* remoteAddress,
                         U16 localPort) noexcept {
    const auto now = Now();
    const auto length = AddressLength(family);
    KIRQL oldIrql{};
    KeAcquireSpinLock(&gTableLock, &oldIrql);
    for (auto& slot : gQuicFlows) {
        if (slot.valid && slot.expires < now) slot.valid = false;
        if (slot.valid && slot.family == family && slot.localPort == localPort &&
            EqualBytes(slot.remoteAddress, remoteAddress, length)) {
            slot.responded = true;
            slot.expires = now + kFlowLifetime;
            break;
        }
    }
    KeReleaseSpinLock(&gTableLock, oldIrql);
}

void Increment(Counter counter) noexcept {
    InterlockedIncrement64(&gCounters.values[static_cast<U32>(counter)]);
}

bool BeginInjection() noexcept {
    const LONG outstanding = InterlockedIncrement(&gCounters.outstanding);
    if (outstanding > kMaximumOutstanding) {
        InterlockedDecrement(&gCounters.outstanding);
        Increment(Counter::QueueFull);
        return false;
    }
    if (outstanding == 1) KeClearEvent(&gNoInjections);
    LONG peak = InterlockedCompareExchange(&gCounters.peak, 0, 0);
    while (outstanding > peak) {
        const LONG previous = InterlockedCompareExchange(&gCounters.peak, outstanding, peak);
        if (previous == peak) break;
        peak = previous;
    }
    return true;
}

void EndInjection() noexcept {
    if (InterlockedDecrement(&gCounters.outstanding) == 0) KeSetEvent(&gNoInjections, IO_NO_INCREMENT, FALSE);
}

void QueryStatistics(wfp::Statistics* statistics) noexcept {
    if (statistics == nullptr) return;
    RtlZeroMemory(statistics, sizeof(*statistics));
    statistics->header.size = sizeof(*statistics);
    statistics->header.version = wfp::kProtocolVersion;
    auto read = [](volatile LONG64* value) -> U64 {
        return static_cast<U64>(InterlockedCompareExchange64(value, 0, 0));
    };
    statistics->classified = read(&gCounters.values[0]);
    statistics->permitted = read(&gCounters.values[1]);
    statistics->redirectedTcp = read(&gCounters.values[2]);
    statistics->redirectedDns = read(&gCounters.values[3]);
    statistics->blockedQuic = read(&gCounters.values[4]);
    statistics->primedQuic = read(&gCounters.values[5]);
    statistics->policiesArmed = read(&gCounters.values[6]);
    statistics->policiesApplied = read(&gCounters.values[7]);
    statistics->selfInjected = read(&gCounters.values[8]);
    statistics->malformed = read(&gCounters.values[9]);
    statistics->unsupported = read(&gCounters.values[10]);
    statistics->allocationFailures = read(&gCounters.values[11]);
    statistics->injectionFailures = read(&gCounters.values[12]);
    statistics->queueFull = read(&gCounters.values[13]);
    statistics->outstandingBatches = static_cast<U64>(InterlockedCompareExchange(&gCounters.outstanding, 0, 0));
    statistics->peakOutstandingBatches = static_cast<U64>(InterlockedCompareExchange(&gCounters.peak, 0, 0));
}

void ResetStatistics() noexcept {
    for (auto& value : gCounters.values) InterlockedExchange64(&value, 0);
    InterlockedExchange(&gCounters.peak,
                        InterlockedCompareExchange(&gCounters.outstanding, 0, 0));
}

void WaitForInjections() noexcept {
    KeWaitForSingleObject(&gNoInjections, Executive, KernelMode, FALSE, nullptr);
}

}  // namespace splithello::kernel
