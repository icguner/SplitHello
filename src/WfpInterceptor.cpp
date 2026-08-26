#include "WfpInterceptor.hpp"

#include "../driver/shared/Identifiers.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <limits>
#include <span>

#include <mstcpip.h>
#include <objbase.h>
#include <ws2tcpip.h>

namespace {

using splithello::wfp::AddressFamily;

std::filesystem::path executableDirectory() {
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return {};
    buffer.resize(length);
    return std::filesystem::path(buffer).parent_path();
}

std::wstring utf8ToWide(const std::string& input) {
    if (input.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           input.data(),
                                           static_cast<int>(input.size()),
                                           nullptr, 0);
    if (length <= 0) return {};
    std::wstring output(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), output.data(),
                            length) != length) return {};
    return output;
}

std::wstring normalizeProcessRule(std::wstring rule) {
    if (rule.size() >= 3 &&
        ((rule[0] >= L'A' && rule[0] <= L'Z') ||
         (rule[0] >= L'a' && rule[0] <= L'z')) &&
        rule[1] == L':' && (rule[2] == L'\\' || rule[2] == L'/')) {
        wchar_t drive[3]{rule[0], L':', L'\0'};
        std::array<wchar_t, 1024> devicePath{};
        if (QueryDosDeviceW(drive, devicePath.data(),
                            static_cast<DWORD>(devicePath.size())) != 0) {
            rule.replace(0, 2, devicePath.data());
        }
    }
    return rule;
}

bool deviceIo(HANDLE device, DWORD code, void* input, DWORD inputSize,
              void* output = nullptr, DWORD outputSize = 0,
              DWORD* returned = nullptr) {
    DWORD localReturned = 0;
    return DeviceIoControl(device, code, input, inputSize, output, outputSize,
                           returned != nullptr ? returned : &localReturned,
                           nullptr) != FALSE;
}

splithello::wfp::QuicMode convertQuicMode(quic_strategy::Mode mode) {
    switch (mode) {
        case quic_strategy::Mode::Block: return splithello::wfp::QuicMode::Block;
        case quic_strategy::Mode::Adaptive: return splithello::wfp::QuicMode::Adaptive;
        default: return splithello::wfp::QuicMode::Allow;
    }
}

splithello::wfp::PacketMode convertPacketMode(packet_strategy::Mode mode) {
    using Source = packet_strategy::Mode;
    using Target = splithello::wfp::PacketMode;
    switch (mode) {
        case Source::ReverseOrder: return Target::ReverseOrder;
        case Source::FakeBadSequence: return Target::FakeBadSequence;
        case Source::FakeBadChecksum: return Target::FakeBadChecksum;
        case Source::FakeAutoTtl: return Target::FakeAutoTtl;
        case Source::SequenceOverlap: return Target::SequenceOverlap;
        case Source::IpFragment: return Target::IpFragment;
        default: return Target::None;
    }
}

bool addProviderAndSublayer(HANDLE engine) {
    FWPM_PROVIDER0 provider{};
    provider.providerKey = splithello::wfp::kProviderKey;
    provider.displayData.name = const_cast<wchar_t*>(splithello::wfp::kProviderName);
    provider.displayData.description = const_cast<wchar_t*>(
        L"SplitHello kernel packet and redirect provider");
    DWORD result = FwpmProviderAdd0(engine, &provider, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) return false;

    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = splithello::wfp::kSublayerKey;
    sublayer.displayData.name = const_cast<wchar_t*>(splithello::wfp::kSublayerName);
    sublayer.displayData.description = const_cast<wchar_t*>(
        L"SplitHello dynamic fail-open filters");
    sublayer.providerKey = const_cast<GUID*>(&splithello::wfp::kProviderKey);
    sublayer.weight = 0x7000;
    result = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    return result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS;
}

bool addCallout(HANDLE engine, const GUID& key, const GUID& layer,
                const wchar_t* name) {
    FWPM_CALLOUT0 callout{};
    callout.calloutKey = key;
    callout.displayData.name = const_cast<wchar_t*>(name);
    callout.providerKey = const_cast<GUID*>(&splithello::wfp::kProviderKey);
    callout.applicableLayer = layer;
    const DWORD result = FwpmCalloutAdd0(engine, &callout, nullptr, nullptr);
    return result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS;
}

bool addFilter(HANDLE engine, const GUID& layer, const GUID& calloutKey,
               const wchar_t* name, FWP_ACTION_TYPE actionType,
               std::span<FWPM_FILTER_CONDITION0> conditions) {
    FWPM_FILTER0 filter{};
    if (CoCreateGuid(&filter.filterKey) != S_OK) return false;
    filter.displayData.name = const_cast<wchar_t*>(name);
    filter.providerKey = const_cast<GUID*>(&splithello::wfp::kProviderKey);
    filter.layerKey = layer;
    filter.subLayerKey = splithello::wfp::kSublayerKey;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = static_cast<UINT32>(conditions.size());
    filter.filterCondition = conditions.data();
    filter.action.type = actionType;
    filter.action.calloutKey = calloutKey;
    filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    return FwpmFilterAdd0(engine, &filter, nullptr, nullptr) == ERROR_SUCCESS;
}

FWPM_FILTER_CONDITION0 protocolCondition(UINT8 protocol) {
    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT8;
    condition.conditionValue.uint8 = protocol;
    return condition;
}

FWPM_FILTER_CONDITION0 portCondition(UINT16 port) {
    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT16;
    condition.conditionValue.uint16 = port;
    return condition;
}

bool readRedirectRecords(SOCKET socket, std::vector<uint8_t>& output) {
    output.assign(256, 0);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        DWORD returned = 0;
        const int result = WSAIoctl(
            socket, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            nullptr, 0, output.data(), static_cast<DWORD>(output.size()),
            &returned, nullptr, nullptr);
        if (result == 0) {
            output.resize(returned);
            return !output.empty();
        }
        const int error = WSAGetLastError();
        if (error != WSAEFAULT && error != WSAENOBUFS) break;
        if (output.size() >= 64 * 1024) break;
        output.resize(output.size() * 2);
    }
    output.clear();
    return false;
}

}  // namespace

WfpInterceptor::WfpInterceptor(uint16_t proxyPort, uint16_t dnsProxyPort,
                               quic_strategy::Mode quicMode,
                               std::vector<std::string> processIncludes,
                               std::vector<std::string> processExcludes)
    : proxyPort_(proxyPort),
      dnsProxyPort_(dnsProxyPort),
      quicMode_(quicMode),
      processIncludes_(std::move(processIncludes)),
      processExcludes_(std::move(processExcludes)) {}

WfpInterceptor::~WfpInterceptor() {
    stop();
}

bool WfpInterceptor::prepareService() {
    const std::filesystem::path driverPath =
        executableDirectory() / L"SplitHelloWfp.sys";
    if (!std::filesystem::is_regular_file(driverPath)) {
        fatalErrorCode_ = ERROR_FILE_NOT_FOUND;
        spdlog::error("WFP surucusu bulunamadi: {}", driverPath.string());
        return false;
    }
    serviceManager_ = OpenSCManagerW(nullptr, nullptr,
                                     SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (serviceManager_ == nullptr) {
        fatalErrorCode_ = GetLastError();
        return false;
    }
    service_ = OpenServiceW(serviceManager_, splithello::wfp::kServiceName,
                            SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS |
                                SERVICE_CHANGE_CONFIG);
    if (service_ == nullptr && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
        service_ = CreateServiceW(
            serviceManager_, splithello::wfp::kServiceName,
            L"SplitHello WFP Callout Driver", SERVICE_START | SERVICE_STOP |
                SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG,
            SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
            driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    } else if (service_ != nullptr) {
        ChangeServiceConfigW(service_, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                             SERVICE_NO_CHANGE, driverPath.c_str(), nullptr,
                             nullptr, nullptr, nullptr, nullptr, nullptr);
    }
    if (service_ == nullptr) {
        fatalErrorCode_ = GetLastError();
        return false;
    }
    SERVICE_STATUS_PROCESS process{};
    DWORD bytes = 0;
    if (!QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<BYTE*>(&process),
                              sizeof(process), &bytes)) {
        fatalErrorCode_ = GetLastError();
        return false;
    }
    if (process.dwCurrentState != SERVICE_STOPPED) {
        if (process.dwCurrentState != SERVICE_STOP_PENDING) {
            SERVICE_STATUS status{};
            if (!ControlService(service_, SERVICE_CONTROL_STOP, &status)) {
                const DWORD error = GetLastError();
                if (error != ERROR_SERVICE_NOT_ACTIVE) {
                    fatalErrorCode_ = error;
                    return false;
                }
            }
        }
        bool stopped = false;
        for (unsigned waited = 0; waited < 3000; waited += 50) {
            bytes = 0;
            if (!QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
                                      reinterpret_cast<BYTE*>(&process),
                                      sizeof(process), &bytes)) {
                fatalErrorCode_ = GetLastError();
                return false;
            }
            if (process.dwCurrentState == SERVICE_STOPPED) {
                stopped = true;
                break;
            }
            Sleep(50);
        }
        if (!stopped) {
            fatalErrorCode_ = ERROR_SERVICE_REQUEST_TIMEOUT;
            return false;
        }
    }
    return true;
}

bool WfpInterceptor::openEngine() {
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"SplitHello dynamic WFP session");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    const DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT,
                                         nullptr, &session, &engine_);
    if (result != ERROR_SUCCESS) {
        fatalErrorCode_ = result;
        engine_ = nullptr;
        return false;
    }
    if (!addProviderAndSublayer(engine_)) {
        fatalErrorCode_ = static_cast<DWORD>(FWP_E_PROVIDER_NOT_FOUND);
        return false;
    }
    return true;
}

bool WfpInterceptor::startServiceAndOpenDevice() {
    if (!StartServiceW(service_, 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            fatalErrorCode_ = error;
            return false;
        }
    }
    for (unsigned waited = 0; waited <= 3000; waited += 50) {
        device_ = CreateFileW(splithello::wfp::kUserDevicePath,
                              GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (device_ != INVALID_HANDLE_VALUE) break;
        Sleep(50);
    }
    if (device_ == INVALID_HANDLE_VALUE) {
        fatalErrorCode_ = GetLastError();
        return false;
    }
    splithello::U32 version = 0;
    DWORD returned = 0;
    if (!deviceIo(device_, splithello::wfp::kIoctlGetVersion, nullptr, 0,
                  &version, sizeof(version), &returned) ||
        returned != sizeof(version) || version != splithello::wfp::kProtocolVersion) {
        fatalErrorCode_ = ERROR_REVISION_MISMATCH;
        return false;
    }
    return true;
}

bool WfpInterceptor::installFilters() {
    using namespace splithello::wfp;
    if (FwpmTransactionBegin0(engine_, 0) != ERROR_SUCCESS) return false;
    bool ok = true;
    ok = ok && addCallout(engine_, kRedirectV4CalloutKey,
                          FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
                          L"SplitHello TCP redirect v4");
    ok = ok && addCallout(engine_, kRedirectV6CalloutKey,
                          FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
                          L"SplitHello TCP redirect v6");
    ok = ok && addCallout(engine_, kAuthV4CalloutKey,
                          FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                          L"SplitHello UDP authorization v4");
    ok = ok && addCallout(engine_, kAuthV6CalloutKey,
                          FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                          L"SplitHello UDP authorization v6");
    ok = ok && addCallout(engine_, kOutboundV4CalloutKey,
                          FWPM_LAYER_OUTBOUND_IPPACKET_V4,
                          L"SplitHello outbound packets v4");
    ok = ok && addCallout(engine_, kOutboundV6CalloutKey,
                          FWPM_LAYER_OUTBOUND_IPPACKET_V6,
                          L"SplitHello outbound packets v6");
    ok = ok && addCallout(engine_, kInboundV4CalloutKey,
                          FWPM_LAYER_INBOUND_IPPACKET_V4,
                          L"SplitHello inbound packets v4");
    ok = ok && addCallout(engine_, kInboundV6CalloutKey,
                          FWPM_LAYER_INBOUND_IPPACKET_V6,
                          L"SplitHello inbound packets v6");

    std::array tcp443Conditions{protocolCondition(IPPROTO_TCP), portCondition(443)};
    std::array udp53Conditions{protocolCondition(IPPROTO_UDP), portCondition(53)};
    std::array udp443Conditions{protocolCondition(IPPROTO_UDP), portCondition(443)};
    std::span<FWPM_FILTER_CONDITION0> noConditions;
    ok = ok && addFilter(engine_, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
                         kRedirectV4CalloutKey, L"SplitHello redirect TCP/443 v4",
                         FWP_ACTION_CALLOUT_TERMINATING,
                         tcp443Conditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
                         kRedirectV6CalloutKey, L"SplitHello redirect TCP/443 v6",
                         FWP_ACTION_CALLOUT_TERMINATING,
                         tcp443Conditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                         kAuthV4CalloutKey, L"SplitHello select DNS flows v4",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         udp53Conditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                         kAuthV6CalloutKey, L"SplitHello select DNS flows v6",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         udp53Conditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                         kAuthV4CalloutKey, L"SplitHello select relay TCP v4",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         tcp443Conditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                         kAuthV6CalloutKey, L"SplitHello select relay TCP v6",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         tcp443Conditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_OUTBOUND_IPPACKET_V4,
                         kOutboundV4CalloutKey, L"SplitHello outbound network v4",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         noConditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_OUTBOUND_IPPACKET_V6,
                         kOutboundV6CalloutKey, L"SplitHello outbound network v6",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         noConditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_INBOUND_IPPACKET_V4,
                         kInboundV4CalloutKey, L"SplitHello inbound network v4",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         noConditions);
    ok = ok && addFilter(engine_, FWPM_LAYER_INBOUND_IPPACKET_V6,
                         kInboundV6CalloutKey, L"SplitHello inbound network v6",
                         FWP_ACTION_CALLOUT_INSPECTION,
                         noConditions);
    if (quicMode_ != quic_strategy::Mode::Allow) {
        ok = ok && addFilter(engine_, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                             kAuthV4CalloutKey, L"SplitHello select QUIC flows v4",
                             FWP_ACTION_CALLOUT_INSPECTION,
                             udp443Conditions);
        ok = ok && addFilter(engine_, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                             kAuthV6CalloutKey, L"SplitHello select QUIC flows v6",
                             FWP_ACTION_CALLOUT_INSPECTION,
                             udp443Conditions);
    }
    if (!ok || FwpmTransactionCommit0(engine_) != ERROR_SUCCESS) {
        FwpmTransactionAbort0(engine_);
        fatalErrorCode_ = ERROR_GEN_FAILURE;
        return false;
    }
    return true;
}

bool WfpInterceptor::configureDriver() {
    splithello::wfp::Configuration configuration{};
    configuration.header.size = sizeof(configuration);
    configuration.header.version = splithello::wfp::kProtocolVersion;
    configuration.proxyProcessId = GetCurrentProcessId();
    configuration.proxyPort = proxyPort_;
    configuration.dnsProxyPort = dnsProxyPort_;
    configuration.quicMode = convertQuicMode(quicMode_);

    auto appendRules = [](const std::vector<std::string>& source,
                          splithello::wfp::ProcessRule* target,
                          splithello::U16& count) {
        for (const auto& rule : source) {
            if (count >= splithello::wfp::kMaximumRulesPerList) break;
            const std::wstring wide = normalizeProcessRule(utf8ToWide(rule));
            if (wide.empty() || wide.size() > splithello::wfp::kMaximumRuleCharacters) continue;
            auto& output = target[count++];
            output.length = static_cast<splithello::U16>(wide.size());
            std::copy(wide.begin(), wide.end(), output.pattern);
        }
    };
    appendRules(processIncludes_, configuration.includes,
                configuration.includeCount);
    appendRules(processExcludes_, configuration.excludes,
                configuration.excludeCount);
    if (!deviceIo(device_, splithello::wfp::kIoctlSetConfiguration,
                  &configuration, sizeof(configuration)) ||
        !deviceIo(device_, splithello::wfp::kIoctlStart, nullptr, 0)) {
        fatalErrorCode_ = GetLastError();
        return false;
    }
    return true;
}

bool WfpInterceptor::start() {
    if (running_) return true;
    fatalErrorCode_ = ERROR_SUCCESS;
    if (!prepareService() || !openEngine() || !startServiceAndOpenDevice() ||
        !installFilters() || !configureDriver()) {
        spdlog::error("WFP motoru baslatilamadi: Windows hata={}",
                      fatalErrorCode_.load());
        stop();
        return false;
    }
    running_ = true;
    monitor_ = std::jthread([this](std::stop_token stopToken) {
        while (!stopToken.stop_requested()) {
            for (unsigned elapsed = 0;
                 elapsed < 500 && !stopToken.stop_requested(); elapsed += 50) {
                Sleep(50);
            }
            if (stopToken.stop_requested()) break;
            splithello::U32 version = 0;
            DWORD returned = 0;
            bool deviceHealthy = false;
            DWORD deviceStatus = ERROR_SUCCESS;
            {
                std::scoped_lock lock(deviceMutex_);
                if (device_ == INVALID_HANDLE_VALUE) {
                    deviceStatus = ERROR_INVALID_HANDLE;
                } else if (!deviceIo(device_, splithello::wfp::kIoctlGetVersion,
                                     nullptr, 0, &version, sizeof(version),
                                     &returned)) {
                    deviceStatus = GetLastError();
                } else if (version != splithello::wfp::kProtocolVersion) {
                    deviceStatus = ERROR_REVISION_MISMATCH;
                } else {
                    deviceHealthy = true;
                }
            }
            FWP_VALUE0* option = nullptr;
            const DWORD engineStatus = FwpmEngineGetOption0(
                engine_, FWPM_ENGINE_COLLECT_NET_EVENTS, &option);
            if (option != nullptr) {
                FwpmFreeMemory0(reinterpret_cast<void**>(&option));
            }
            if (!deviceHealthy || engineStatus != ERROR_SUCCESS) {
                fatalErrorCode_ = !deviceHealthy ? deviceStatus : engineStatus;
                if (fatalErrorCode_ == ERROR_SUCCESS) {
                    fatalErrorCode_ = ERROR_DEVICE_NOT_AVAILABLE;
                }
                running_ = false;
                break;
            }
        }
    });
    spdlog::info("WFP motoru etkin: TCP redirect + DNS/QUIC + paket profilleri");
    return true;
}

void WfpInterceptor::stop() {
    running_ = false;
    if (monitor_.joinable()) {
        monitor_.request_stop();
        monitor_.join();
    }
    {
        std::scoped_lock lock(deviceMutex_);
        if (device_ != INVALID_HANDLE_VALUE) {
            deviceIo(device_, splithello::wfp::kIoctlStop, nullptr, 0);
            CloseHandle(device_);
            device_ = INVALID_HANDLE_VALUE;
        }
    }
    if (service_ != nullptr) {
        SERVICE_STATUS status{};
        ControlService(service_, SERVICE_CONTROL_STOP, &status);
        for (unsigned waited = 0; waited < 3000; waited += 50) {
            SERVICE_STATUS_PROCESS process{};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
                                      reinterpret_cast<BYTE*>(&process),
                                      sizeof(process), &bytes) ||
                process.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(50);
        }
    }
    closeHandles();
}

void WfpInterceptor::closeHandles() noexcept {
    if (engine_ != nullptr) {
        FwpmEngineClose0(engine_);
        engine_ = nullptr;
    }
    if (service_ != nullptr) {
        CloseServiceHandle(service_);
        service_ = nullptr;
    }
    if (serviceManager_ != nullptr) {
        CloseServiceHandle(serviceManager_);
        serviceManager_ = nullptr;
    }
}

bool WfpInterceptor::armPolicy(const std::string& targetAddress,
                               uint16_t localPort,
                               const packet_strategy::Policy& policy) const {
    if (localPort == 0) return false;
    splithello::wfp::PolicyCommand command{};
    command.header.size = sizeof(command);
    command.header.version = splithello::wfp::kProtocolVersion;
    command.localPort = localPort;
    command.mode = convertPacketMode(policy.mode);
    command.splitOffset = static_cast<splithello::U32>(
        std::min(policy.splitOffset,
                 static_cast<size_t>(std::numeric_limits<splithello::U32>::max())));
    command.overlapBytes = static_cast<splithello::U32>(
        std::min(policy.overlapBytes,
                 static_cast<size_t>(std::numeric_limits<splithello::U32>::max())));
    command.fakeSequenceDelta = policy.fakeSequenceDelta;
    command.fakeTtl = policy.fakeTtl;
    const size_t sniLength = std::min(
        policy.coverSni.size(), splithello::wfp::kMaximumCoverSniBytes);
    command.coverSniLength = static_cast<splithello::U16>(sniLength);
    std::copy_n(policy.coverSni.data(), sniLength, command.coverSni);
    IN_ADDR v4{};
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET, targetAddress.c_str(), &v4) == 1) {
        command.family = AddressFamily::Ipv4;
        std::copy_n(reinterpret_cast<const uint8_t*>(&v4), 4,
                    command.remoteAddress);
    } else if (InetPtonA(AF_INET6, targetAddress.c_str(), &v6) == 1) {
        command.family = AddressFamily::Ipv6;
        std::copy_n(reinterpret_cast<const uint8_t*>(&v6), 16,
                    command.remoteAddress);
    } else {
        return false;
    }
    std::scoped_lock lock(deviceMutex_);
    return device_ != INVALID_HANDLE_VALUE &&
           deviceIo(device_, splithello::wfp::kIoctlArmPolicy,
                    &command, sizeof(command));
}

bool WfpInterceptor::statistics(splithello::wfp::Statistics& output) const {
    std::scoped_lock lock(deviceMutex_);
    if (device_ == INVALID_HANDLE_VALUE) return false;
    DWORD returned = 0;
    return deviceIo(device_, splithello::wfp::kIoctlGetStatistics, nullptr, 0,
                    &output, sizeof(output), &returned) &&
           returned == sizeof(output);
}

bool WfpInterceptor::queryRedirectedConnection(
    SOCKET socket, RedirectedConnection& connection) {
    splithello::wfp::RedirectContext context{};
    DWORD returned = 0;
    if (WSAIoctl(socket, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                 nullptr, 0, &context, sizeof(context), &returned,
                 nullptr, nullptr) != 0 || returned < sizeof(context) ||
        context.header.version != splithello::wfp::kProtocolVersion ||
        context.header.size != sizeof(context)) {
        return false;
    }
    char text[INET6_ADDRSTRLEN]{};
    const int family = context.family == AddressFamily::Ipv4 ? AF_INET : AF_INET6;
    if (InetNtopA(family, context.targetAddress, text,
                  static_cast<DWORD>(sizeof(text))) == nullptr ||
        context.targetPort == 0) return false;
    connection.targetAddress = text;
    connection.targetPort = context.targetPort;
    connection.addressFamily = family;
    return readRedirectRecords(socket, connection.redirectRecords);
}
