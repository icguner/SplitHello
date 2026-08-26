#pragma once

#include "Types.hpp"

namespace splithello::wfp {

inline constexpr U32 kProtocolVersion = 1;
inline constexpr Size kMaximumRulesPerList = 64;
inline constexpr Size kMaximumRuleCharacters = 260;
inline constexpr Size kMaximumCoverSniBytes = 253;

inline constexpr wchar_t kNtDeviceName[] = L"\\Device\\SplitHelloWfp";
inline constexpr wchar_t kDosDeviceName[] = L"\\DosDevices\\SplitHelloWfp";
inline constexpr wchar_t kUserDevicePath[] = L"\\\\.\\SplitHelloWfp";
inline constexpr wchar_t kServiceName[] = L"SplitHelloWfp";

struct MessageHeader {
    U32 size = 0;
    U32 version = kProtocolVersion;
};

enum class AddressFamily : U16 {
    Ipv4 = 4,
    Ipv6 = 6,
};

enum class QuicMode : U32 {
    Block = 0,
    Adaptive = 1,
    Allow = 2,
};

enum class PacketMode : U32 {
    None = 0,
    ReverseOrder = 1,
    FakeBadSequence = 2,
    FakeBadChecksum = 3,
    FakeAutoTtl = 4,
    SequenceOverlap = 5,
    IpFragment = 6,
};

struct ProcessRule {
    U16 length = 0;
    U16 reserved = 0;
    wchar_t pattern[kMaximumRuleCharacters]{};
};

struct Configuration {
    MessageHeader header{};
    U32 proxyProcessId = 0;
    U16 proxyPort = 0;
    U16 dnsProxyPort = 0;
    QuicMode quicMode = QuicMode::Allow;
    U16 includeCount = 0;
    U16 excludeCount = 0;
    U32 reserved = 0;
    ProcessRule includes[kMaximumRulesPerList]{};
    ProcessRule excludes[kMaximumRulesPerList]{};
};

struct PolicyCommand {
    MessageHeader header{};
    AddressFamily family = AddressFamily::Ipv4;
    U16 localPort = 0;
    U8 remoteAddress[16]{};
    PacketMode mode = PacketMode::None;
    U32 splitOffset = 2;
    U32 overlapBytes = 8;
    I32 fakeSequenceDelta = -10000;
    U8 fakeTtl = 0;
    U8 reserved0[3]{};
    U16 coverSniLength = 0;
    U16 reserved1 = 0;
    char coverSni[kMaximumCoverSniBytes]{};
};

struct RedirectContext {
    MessageHeader header{};
    AddressFamily family = AddressFamily::Ipv4;
    U16 targetPort = 0;
    U8 targetAddress[16]{};
};

struct Statistics {
    MessageHeader header{};
    U64 classified = 0;
    U64 permitted = 0;
    U64 redirectedTcp = 0;
    U64 redirectedDns = 0;
    U64 blockedQuic = 0;
    U64 primedQuic = 0;
    U64 policiesArmed = 0;
    U64 policiesApplied = 0;
    U64 selfInjected = 0;
    U64 malformed = 0;
    U64 unsupported = 0;
    U64 allocationFailures = 0;
    U64 injectionFailures = 0;
    U64 queueFull = 0;
    U64 outstandingBatches = 0;
    U64 peakOutstandingBatches = 0;
};

static_assert(sizeof(MessageHeader) == 8);
static_assert(sizeof(ProcessRule) == 524);
static_assert(sizeof(Configuration) == 67100);
static_assert(sizeof(PolicyCommand) == 308);
static_assert(sizeof(RedirectContext) == 28);
static_assert(sizeof(Statistics) == 136);

inline constexpr U32 kIoctlGetVersion =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
inline constexpr U32 kIoctlSetConfiguration =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr U32 kIoctlStart =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr U32 kIoctlStop =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr U32 kIoctlArmPolicy =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS);
inline constexpr U32 kIoctlGetStatistics =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS);
inline constexpr U32 kIoctlResetStatistics =
    CTL_CODE(FILE_DEVICE_NETWORK, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS);

}  // namespace splithello::wfp
