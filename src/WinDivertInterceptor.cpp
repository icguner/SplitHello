#include "WinDivertInterceptor.hpp"
#include "RecoveryPolicy.hpp"
#include "WinDivertPacket.hpp"

#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windivert.h>

namespace {

constexpr uint16_t kHttpsPort = 443;
constexpr uint16_t kDnsPort = 53;
constexpr INT16 kDivertPriority = 123;

// Re-injection fails per packet far more often than per engine (an unreachable
// peer, a packet the stack refuses). Only a long unbroken run of failures is
// treated as a dead handle and stops the engine.
constexpr unsigned kFatalSendFailures = 16;
constexpr ULONGLONG kFatalSendWindowMs = 500;
constexpr ULONGLONG kSendStreakGapMs = 1000;

std::string addressText(const WINDIVERT_IPHDR* ipv4,
                        const WINDIVERT_IPV6HDR* ipv6,
                        bool destination) {
    char text[INET6_ADDRSTRLEN] = {};
    if (ipv4) {
        const UINT32 address = destination ? ipv4->DstAddr : ipv4->SrcAddr;
        if (inet_ntop(AF_INET, &address, text, sizeof(text))) return text;
    } else if (ipv6) {
        const UINT32* address = destination ? ipv6->DstAddr : ipv6->SrcAddr;
        if (inet_ntop(AF_INET6, address, text, sizeof(text))) return text;
    }
    return {};
}

// Canonical binary form used for table keys: no text on the packet path.
transparent::Address packetAddress(const WINDIVERT_IPHDR* ipv4,
                                   const WINDIVERT_IPV6HDR* ipv6,
                                   bool destination) {
    if (ipv4) {
        return transparent::addressFromBytes(
            destination ? &ipv4->DstAddr : &ipv4->SrcAddr, false);
    }
    return transparent::addressFromBytes(
        destination ? ipv6->DstAddr : ipv6->SrcAddr, true);
}

void swapAddresses(WINDIVERT_IPHDR* ipv4, WINDIVERT_IPV6HDR* ipv6) {
    if (ipv4) {
        std::swap(ipv4->SrcAddr, ipv4->DstAddr);
        return;
    }
    if (ipv6) {
        for (size_t i = 0; i < 4; ++i) {
            std::swap(ipv6->SrcAddr[i], ipv6->DstAddr[i]);
        }
    }
}

uint8_t packetTtl(const WINDIVERT_IPHDR* ipv4,
                  const WINDIVERT_IPV6HDR* ipv6) {
    if (ipv4) return ipv4->TTL;
    return ipv6 ? ipv6->HopLimit : 0;
}

process_filter::Endpoint processEndpoint(const WINDIVERT_IPHDR* ipv4,
                                         const WINDIVERT_IPV6HDR* ipv6,
                                         uint16_t sourcePort,
                                         uint16_t destinationPort,
                                         process_filter::Protocol protocol,
                                         bool outbound) {
    process_filter::Endpoint endpoint;
    endpoint.ipv6 = ipv6 != nullptr;
    endpoint.protocol = protocol;
    endpoint.localPort = outbound ? sourcePort : destinationPort;
    endpoint.remotePort = outbound ? destinationPort : sourcePort;
    const void* sourceAddress = ipv4
        ? static_cast<const void*>(&ipv4->SrcAddr)
        : static_cast<const void*>(ipv6->SrcAddr);
    const void* destinationAddress = ipv4
        ? static_cast<const void*>(&ipv4->DstAddr)
        : static_cast<const void*>(ipv6->DstAddr);
    const size_t addressLength = ipv4 ? 4 : 16;
    std::memcpy(endpoint.localAddress.data(),
                outbound ? sourceAddress : destinationAddress, addressLength);
    std::memcpy(endpoint.remoteAddress.data(),
                outbound ? destinationAddress : sourceAddress, addressLength);
    return endpoint;
}

// Packets queued for re-injection after one read batch. Lengths are kept so a
// failed batch send can resume packet by packet.
struct PacketBatch {
    std::vector<uint8_t> bytes;
    std::vector<WINDIVERT_ADDRESS> addresses;
    std::vector<UINT> lengths;

    void clear() {
        bytes.clear();
        addresses.clear();
        lengths.clear();
    }
    size_t count() const { return addresses.size(); }

    void append(const uint8_t* packet, size_t packetLength,
                const WINDIVERT_ADDRESS& address) {
        bytes.insert(bytes.end(), packet, packet + packetLength);
        addresses.push_back(address);
        lengths.push_back((UINT)packetLength);
    }
    void rollback(size_t packets, size_t byteCount) {
        addresses.resize(packets);
        lengths.resize(packets);
        bytes.resize(byteCount);
    }
};

std::string openError(DWORD error) {
    switch (error) {
    case ERROR_ACCESS_DENIED:
        return "yonetici yetkisi gerekli";
    case ERROR_FILE_NOT_FOUND:
        return "WinDivert surucu dosyasi bulunamadi";
    case ERROR_INVALID_IMAGE_HASH:
        return "WinDivert surucu imzasi Windows tarafindan reddedildi";
    case ERROR_DRIVER_BLOCKED:
        return "WinDivert guvenlik yazilimi veya Windows tarafindan engellendi";
    default:
        return "Windows hata kodu " + std::to_string(error);
    }
}

} // namespace

WinDivertInterceptor::WinDivertInterceptor(transparent::FlowRegistry& flows,
                                           transparent::DatagramRegistry& datagrams,
                                           packet_strategy::PolicyRegistry& packetPolicies,
                                           uint16_t proxyPort,
                                           uint16_t dnsProxyPort,
                                           uint16_t connectPort,
                                           quic_strategy::Mode quicMode,
                                           process_filter::Filter* processFilter,
                                           bool captureDns)
    : flows_(flows)
    , datagrams_(datagrams)
    , packetPolicies_(packetPolicies)
    , proxyPort_(proxyPort)
    , dnsProxyPort_(dnsProxyPort)
    , connectPort_(connectPort)
    , quicMode_(quicMode)
    , processFilter_(processFilter)
    , captureDns_(captureDns) {}

WinDivertInterceptor::~WinDivertInterceptor() {
    stop();
}

bool WinDivertInterceptor::start() {
    const std::lock_guard lifecycleLock(stopMutex_);
    if (running_) return true;
    if (worker_.joinable()) worker_.join();
    closeHandles();
    tcpFlows_.clear();
    fatalErrorCode_ = ERROR_SUCCESS;
    if (proxyPort_ == 0 || dnsProxyPort_ == 0 || connectPort_ == 0 ||
        proxyPort_ == connectPort_ || proxyPort_ == dnsProxyPort_ ||
        dnsProxyPort_ == connectPort_ || proxyPort_ == kHttpsPort ||
        dnsProxyPort_ == kHttpsPort || dnsProxyPort_ == kDnsPort ||
        connectPort_ == kHttpsPort) {
        spdlog::error("WinDivert port yapilandirmasi gecersiz");
        return false;
    }

    char filter[640] = {};
    const bool processAwareQuicBlock =
        quicMode_ == quic_strategy::Mode::Block && processFilter_ &&
        processFilter_->enabled();
    const char* capturedQuic =
        quicMode_ == quic_strategy::Mode::Adaptive || processAwareQuicBlock
        ? " or (udp and ((outbound and udp.DstPort == 443) or "
          "(inbound and udp.SrcPort == 443)))"
        : "";
    char dnsClause[128] = {};
    if (captureDns_) {
        std::snprintf(dnsClause, sizeof(dnsClause),
                      " or (udp and outbound and (udp.DstPort == %u or udp.SrcPort == %u))",
                      kDnsPort, dnsProxyPort_);
    }
    const int written = std::snprintf(
        filter, sizeof(filter),
        "!loopback and ((tcp and ((outbound and (tcp.DstPort == %u or "
        "tcp.DstPort == %u or tcp.SrcPort == %u)) or "
        "(inbound and tcp.SrcPort == %u)))%s%s)",
        kHttpsPort, connectPort_, proxyPort_, kHttpsPort,
        dnsClause, capturedQuic);
    if (written <= 0 || written >= (int)sizeof(filter)) return false;

    std::array<char, 4096> compiledFilter{};
    const char* filterError = nullptr;
    UINT filterErrorPosition = 0;
    if (!WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_NETWORK,
                                      compiledFilter.data(), (UINT)compiledFilter.size(),
                                      &filterError, &filterErrorPosition)) {
        spdlog::error("WinDivert filtresi gecersiz ({}): {}", filterErrorPosition,
                      filterError ? filterError : "bilinmeyen hata");
        return false;
    }

    packetHandle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK,
                                  kDivertPriority, 0);
    if (packetHandle_ == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        spdlog::error("WinDivert acilamadi: {}", openError(error));
        return false;
    }

    // A short queue absorbs scheduling jitter without retaining a large amount
    // of live network data if the process is suspended. A refused parameter is
    // not fatal (the driver keeps its defaults) but changes the loss behavior
    // under load, so say so.
    const auto setParam = [this](WINDIVERT_PARAM param, UINT64 value, const char* name) {
        if (!WinDivertSetParam(packetHandle_, param, value)) {
            spdlog::warn("WinDivert {} ayarlanamadi: hata={}; surucu varsayilani kullaniliyor",
                         name, GetLastError());
        }
    };
    setParam(WINDIVERT_PARAM_QUEUE_LENGTH, 8192, "QUEUE_LENGTH");
    setParam(WINDIVERT_PARAM_QUEUE_SIZE, 8 * 1024 * 1024, "QUEUE_SIZE");
    setParam(WINDIVERT_PARAM_QUEUE_TIME, 1000, "QUEUE_TIME");

    if (quicMode_ == quic_strategy::Mode::Block && !processAwareQuicBlock) {
        static constexpr const char* kQuicFilter =
            "udp and !loopback and ((outbound and udp.DstPort == 443) or "
            "(inbound and udp.SrcPort == 443))";
        if (!WinDivertHelperCompileFilter(kQuicFilter, WINDIVERT_LAYER_NETWORK,
                                          compiledFilter.data(), (UINT)compiledFilter.size(),
                                          &filterError, &filterErrorPosition)) {
            spdlog::error("WinDivert QUIC filtresi gecersiz ({}): {}",
                          filterErrorPosition,
                          filterError ? filterError : "bilinmeyen hata");
            closeHandles();
            return false;
        }
        quicDropHandle_ = WinDivertOpen(kQuicFilter, WINDIVERT_LAYER_NETWORK,
                                       kDivertPriority + 1, WINDIVERT_FLAG_DROP);
        if (quicDropHandle_ == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            spdlog::error("QUIC filtresi acilamadi: {}", openError(error));
            closeHandles();
            return false;
        }
    }

    running_ = true;
    try {
        worker_ = std::thread([this]() {
            try { run(); }
            catch (...) {
                fatalErrorCode_ = ERROR_UNHANDLED_EXCEPTION;
                running_ = false;
            }
        });
    } catch (...) {
        running_ = false;
        closeHandles();
        return false;
    }
    if (captureDns_) {
        spdlog::info("WinDivert aktif: TCP/443 -> localhost:{}, DNS/53 -> localhost:{}",
                     proxyPort_, dnsProxyPort_);
    } else {
        spdlog::info("WinDivert aktif: TCP/443 -> localhost:{}, DNS sistemde kalir",
                     proxyPort_);
    }
    if (quicMode_ == quic_strategy::Mode::Block) {
        spdlog::info(processAwareQuicBlock
            ? "QUIC modu=block: yalniz surec kuraliyla secilen UDP/443 akislari dusurulecek"
            : "QUIC modu=block: UDP/443 istemcileri TCP'ye dusecek");
    } else if (quicMode_ == quic_strategy::Mode::Adaptive) {
        spdlog::info("QUIC modu=adaptive: Initial prime, yanitsiz hedefte otomatik TCP fallback");
    } else {
        spdlog::info("QUIC modu=allow: UDP/443 degistirilmeden geciyor");
    }
    return true;
}

void WinDivertInterceptor::stop() {
    // Console events, parent shutdown monitoring, and the main runtime loop can
    // all converge here. Serialize joining/handle cleanup so only one caller
    // owns the worker thread at a time.
    const std::lock_guard lock(stopMutex_);
    const bool wasRunning = running_.exchange(false);
    if (wasRunning && packetHandle_ != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(packetHandle_, WINDIVERT_SHUTDOWN_BOTH);
    }
    if (worker_.joinable()) worker_.join();
    closeHandles();
    flows_.clear();
    datagrams_.clear();
    packetPolicies_.clear();
    quicRegistry_.clear();
    tcpFlows_.clear();
    if (processFilter_) processFilter_->clear();
}

void WinDivertInterceptor::closeHandles() {
    if (packetHandle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(packetHandle_);
        packetHandle_ = INVALID_HANDLE_VALUE;
    }
    if (quicDropHandle_ != INVALID_HANDLE_VALUE) {
        WinDivertClose(quicDropHandle_);
        quicDropHandle_ = INVALID_HANDLE_VALUE;
    }
}

void WinDivertInterceptor::run() {
    constexpr size_t kBatchSize = 64;
    std::vector<uint8_t> packets((size_t)WINDIVERT_MTU_MAX * kBatchSize);
    std::array<WINDIVERT_ADDRESS, kBatchSize> addresses{};
    PacketBatch batch;
    unsigned completedReadRetries = 0;

    // Send accounting. A success clears the streak; failures only stop the
    // engine when they form a long unbroken run (see kFatalSendFailures).
    unsigned failedSends = 0;
    ULONGLONG streakStartMs = 0;
    ULONGLONG lastFailureMs = 0;
    const auto sendSucceeded = [&]() { failedSends = 0; };
    // Returns false when the run of failures says the handle is gone.
    const auto sendFailed = [&](DWORD error) {
        const ULONGLONG nowMs = GetTickCount64();
        if (failedSends == 0 || nowMs - lastFailureMs > kSendStreakGapMs) {
            failedSends = 0;
            streakStartMs = nowMs;
        }
        lastFailureMs = nowMs;
        if (++failedSends == 1) {
            spdlog::warn("WinDivert paket geri gonderme hatasi: {}", error);
        }
        if (failedSends >= kFatalSendFailures &&
            nowMs - streakStartMs >= kFatalSendWindowMs) {
            fatalErrorCode_ = error;
            running_ = false;
            return false;
        }
        return true;
    };
    // One packet, retrying only resource exhaustion (the same class the read
    // side treats as transient). Anything else is that packet's own failure.
    const auto sendOne = [&](const uint8_t* data, UINT length,
                             const WINDIVERT_ADDRESS& address, DWORD& error) {
        for (unsigned retries = 0;; ++retries) {
            if (WinDivertSendEx(packetHandle_, data, length, nullptr, 0, &address,
                                (UINT)sizeof(address), nullptr)) {
                return true;
            }
            error = GetLastError();
            if (!running_ || !recovery::shouldRetryWinDivertRead(error, retries)) {
                return false;
            }
            Sleep(recovery::winDivertRetryDelayMs(retries));
        }
    };

    while (running_) {
        UINT packetsLength = 0;
        UINT addressesLength = (UINT)sizeof(addresses);
        if (!WinDivertRecvEx(packetHandle_, packets.data(), (UINT)packets.size(),
                             &packetsLength, 0, addresses.data(),
                             &addressesLength, nullptr)) {
            const DWORD error = GetLastError();
            if (!running_) break;

            if (recovery::shouldRetryWinDivertRead(error,
                                                   completedReadRetries)) {
                const unsigned delayMs =
                    recovery::winDivertRetryDelayMs(completedReadRetries);
                completedReadRetries++;
                spdlog::warn(
                    "WinDivert paket okuma gecici hata={} yeniden deneme={}/{} ({} ms)",
                    error, completedReadRetries,
                    recovery::kMaxWinDivertReadRetries, delayMs);
                Sleep(delayMs);
                continue;
            }

            fatalErrorCode_ = error;
            running_ = false;
            spdlog::error(
                "WinDivert paket okuyucusu durdu: hata={}; fail-open ile filtre kapatiliyor",
                error);
            // The owner observes running_ within 50 ms and closes the handle
            // after joining us. Never race stop() over raw HANDLE storage.
            break;
        }

        if (completedReadRetries != 0) {
            spdlog::info("WinDivert paket okuyucusu {} denemede toparlandi",
                         completedReadRetries);
            completedReadRetries = 0;
        }

        const size_t addressCount = addressesLength / sizeof(WINDIVERT_ADDRESS);
        batch.clear();
        batch.bytes.reserve((size_t)packetsLength * 2);
        batch.addresses.reserve(addressCount * 2);
        batch.lengths.reserve(addressCount * 2);
        uint8_t* packet = packets.data();
        UINT remaining = packetsLength;

        for (size_t index = 0; index < addressCount && remaining > 0; ++index) {
            PWINDIVERT_IPHDR ipv4 = nullptr;
            PWINDIVERT_IPV6HDR ipv6 = nullptr;
            PWINDIVERT_TCPHDR tcp = nullptr;
            PWINDIVERT_UDPHDR udp = nullptr;
            PVOID payload = nullptr;
            UINT payloadLength = 0;
            PVOID nextPacket = nullptr;
            UINT nextLength = 0;

            const BOOL parsed = WinDivertHelperParsePacket(
                packet, remaining, &ipv4, &ipv6, nullptr, nullptr, nullptr,
                &tcp, &udp, &payload, &payloadLength, &nextPacket, &nextLength);
            const UINT packetLength = remaining - nextLength;
            bool packetAppended = false;

            if (parsed && tcp && (ipv4 || ipv6) && packetLength > 0) {
                const uint16_t sourcePort = ntohs(tcp->SrcPort);
                const uint16_t destinationPort = ntohs(tcp->DstPort);
                const bool outbound = addresses[index].Outbound != 0;
                const bool syn = tcp->Syn && !tcp->Ack;
                const transparent::PacketRoute route = transparent::routePacket(
                    outbound, sourcePort, destinationPort,
                    kHttpsPort, proxyPort_, connectPort_);

                // The port alone never decides: a packet is rewritten only when
                // it belongs to a tuple whose SYN passed through here (and, for
                // client flows, the process rules). Connections that predate
                // the engine, processes left alone by a rule, and the relay's
                // own server-side replies are therefore forwarded untouched.
                bool owned = false;
                switch (route) {
                case transparent::PacketRoute::ReflectClientToProxy: {
                    const transparent::Address server = packetAddress(ipv4, ipv6, true);
                    const bool ruled = processFilter_ && processFilter_->enabled();
                    if (syn) {
                        const bool processBypass = ruled &&
                            !processFilter_->shouldIntercept(
                                processEndpoint(ipv4, ipv6, sourcePort, destinationPort,
                                                process_filter::Protocol::Tcp, true),
                                true, true);
                        if (processBypass) {
                            tcpFlows_.remove(transparent::TcpFlowTable::Kind::Client,
                                             server, sourcePort);
                        } else {
                            tcpFlows_.add(transparent::TcpFlowTable::Kind::Client,
                                          server, sourcePort);
                            owned = true;
                        }
                    } else {
                        owned = tcpFlows_.track(transparent::TcpFlowTable::Kind::Client,
                                                server, sourcePort, tcp->Fin, tcp->Rst);
                        if (owned && tcp->Rst && ruled) {
                            processFilter_->forget(
                                processEndpoint(ipv4, ipv6, sourcePort, destinationPort,
                                                process_filter::Protocol::Tcp, true));
                        }
                    }
                    break;
                }
                case transparent::PacketRoute::ReflectProxyToClient:
                    owned = tcpFlows_.track(transparent::TcpFlowTable::Kind::Client,
                                            packetAddress(ipv4, ipv6, true),
                                            destinationPort, tcp->Fin, tcp->Rst);
                    break;
                case transparent::PacketRoute::RedirectProxyToTarget: {
                    // shortcut: any local program dialing the private connect
                    // port is mapped to :443 (the port is a high private one);
                    // upgrade to an owner-PID check on the SYN if that collides.
                    const transparent::Address server = packetAddress(ipv4, ipv6, true);
                    if (syn) {
                        tcpFlows_.add(transparent::TcpFlowTable::Kind::Upstream,
                                      server, sourcePort);
                    } else {
                        tcpFlows_.track(transparent::TcpFlowTable::Kind::Upstream,
                                        server, sourcePort, tcp->Fin, tcp->Rst);
                    }
                    owned = true;
                    break;
                }
                case transparent::PacketRoute::RedirectTargetToProxy:
                    owned = tcpFlows_.track(transparent::TcpFlowTable::Kind::Upstream,
                                            packetAddress(ipv4, ipv6, false),
                                            destinationPort, tcp->Fin, tcp->Rst);
                    break;
                case transparent::PacketRoute::Pass:
                    break;
                }

                if (owned) switch (route) {
                case transparent::PacketRoute::ReflectClientToProxy:
                    if (syn) {
                        flows_.observe(addressText(ipv4, ipv6, true), sourcePort,
                                       kHttpsPort, connectPort_);
                    }
                    tcp->DstPort = htons(proxyPort_);
                    swapAddresses(ipv4, ipv6);
                    addresses[index].Outbound = FALSE;
                    break;

                case transparent::PacketRoute::ReflectProxyToClient:
                    tcp->SrcPort = htons(kHttpsPort);
                    swapAddresses(ipv4, ipv6);
                    addresses[index].Outbound = FALSE;
                    break;

                case transparent::PacketRoute::RedirectProxyToTarget:
                    tcp->DstPort = htons(kHttpsPort);
                    break;

                case transparent::PacketRoute::RedirectTargetToProxy:
                    // Only the SYN-ACK carries a clean TTL sample of the path.
                    if (tcp->Syn && tcp->Ack) {
                        packetPolicies_.observeHop(packetAddress(ipv4, ipv6, false),
                                                   destinationPort,
                                                   packetTtl(ipv4, ipv6));
                    }
                    tcp->SrcPort = htons(connectPort_);
                    break;

                case transparent::PacketRoute::Pass:
                    break;
                }

                if (owned) {
                    WinDivertHelperCalcChecksums(packet, packetLength,
                                                  &addresses[index], 0);
                }

                if (owned &&
                    route == transparent::PacketRoute::RedirectProxyToTarget &&
                    payload && payloadLength >= 2 &&
                    tls::looksLikeTlsRecord(static_cast<const uint8_t*>(payload),
                                            payloadLength)) {
                    const transparent::Address target = packetAddress(ipv4, ipv6, true);
                    const std::optional<packet_strategy::Policy> policy =
                        packetPolicies_.take(target, sourcePort,
                                             (uint32_t)ntohl(tcp->SeqNum));
                    if (policy) {
                        const auto mode = policy->mode;
                        bool applied = false;
                        if (mode == packet_strategy::Mode::IpFragment && ipv4) {
                            const size_t ipHeaderLength = (size_t)ipv4->HdrLength * 4;
                            const size_t transportHeaderLength =
                                (size_t)(static_cast<const uint8_t*>(payload) - packet) -
                                ipHeaderLength;
                            // The cut must be a multiple of 8 and still inside
                            // the hostname; a very short name has no such cut
                            // and is sent whole (and reported as not applied).
                            const size_t boundary = packet_strategy::ipv4FragmentBoundary(
                                transportHeaderLength, *policy, payloadLength);
                            const auto fragments = boundary == 0
                                ? std::vector<std::vector<uint8_t>>{}
                                : packet_strategy::buildIpv4Fragments(
                                      packet, packetLength, ipHeaderLength,
                                      ipHeaderLength + boundary);
                            if (fragments.size() == 2) {
                                for (const auto& fragment : fragments) {
                                    batch.append(fragment.data(), fragment.size(),
                                                 addresses[index]);
                                }
                                packetAppended = true;
                                applied = true;
                            }
                        } else if (mode == packet_strategy::Mode::ReverseOrder ||
                                   mode == packet_strategy::Mode::SequenceOverlap ||
                                   (mode == packet_strategy::Mode::IpFragment && ipv6)) {
                            const size_t outputBefore = batch.count();
                            const size_t outputBytesBefore = batch.bytes.size();
                            packet_strategy::Policy segmentPolicy = *policy;
                            if (mode == packet_strategy::Mode::IpFragment) {
                                segmentPolicy.mode = packet_strategy::Mode::ReverseOrder;
                            }
                            const auto segments = packet_strategy::buildSegments(
                                static_cast<const uint8_t*>(payload), payloadLength,
                                segmentPolicy);
                            for (const auto& segment : segments) {
                                const std::vector<uint8_t> variant = divert_packet::buildTcpVariant(
                                    packet, packetLength, payload, segment.payload,
                                    segment.sequenceOffset, addresses[index], 0, false);
                                if (!variant.empty()) {
                                    batch.append(variant.data(), variant.size(),
                                                 addresses[index]);
                                }
                            }
                            packetAppended = !segments.empty() &&
                                batch.count() - outputBefore == segments.size();
                            if (!packetAppended) {
                                batch.rollback(outputBefore, outputBytesBefore);
                            }
                            // Reordered segments only count as the profile when
                            // the cut really lands inside the hostname.
                            applied = packetAppended && packet_strategy::splitsSni(
                                *policy, packet_strategy::segmentSplit(*policy, payloadLength));
                        } else {
                            const std::vector<uint8_t> fake =
                                packet_strategy::buildFakeClientHello(policy->coverSni);
                            const bool badChecksum =
                                mode == packet_strategy::Mode::FakeBadChecksum;
                            const int32_t sequenceOffset =
                                mode == packet_strategy::Mode::FakeBadSequence
                                    ? policy->fakeSequenceDelta
                                    : 0;
                            const uint8_t ttl =
                                mode == packet_strategy::Mode::FakeAutoTtl
                                    ? policy->fakeTtl
                                    : 0;
                            const std::vector<uint8_t> fakePacket = divert_packet::buildTcpVariant(
                                packet, packetLength, payload, fake, sequenceOffset,
                                addresses[index], ttl, badChecksum);
                            if (!fakePacket.empty()) {
                                // WinDivert trusts an address whose checksum
                                // flag is set and injects the bytes as-is, so a
                                // deliberately wrong TCP checksum survives only
                                // while the flag says "valid". Do not depend on
                                // what the captured address happened to carry.
                                WINDIVERT_ADDRESS fakeAddress = addresses[index];
                                if (badChecksum) {
                                    fakeAddress.IPChecksum = 1;
                                    fakeAddress.TCPChecksum = 1;
                                }
                                batch.append(fakePacket.data(), fakePacket.size(),
                                             fakeAddress);
                                applied = true;
                                if (spdlog::should_log(spdlog::level::trace)) {
                                    spdlog::trace("Paket profili uygulandi: mod={} hedef={}:{}",
                                                  (int)mode, addressText(ipv4, ipv6, true),
                                                  kHttpsPort);
                                }
                            }
                        }
                        if (applied) packetPolicies_.noteApplied(target, sourcePort);
                    }
                }

                if (!packetAppended) {
                    batch.append(packet, packetLength, addresses[index]);
                }
            } else if (parsed && udp && (ipv4 || ipv6) && packetLength > 0) {
                const uint16_t sourcePort = ntohs(udp->SrcPort);
                const uint16_t destinationPort = ntohs(udp->DstPort);
                const bool outbound = addresses[index].Outbound != 0;
                const transparent::DatagramRoute route = transparent::routeDatagram(
                    addresses[index].Outbound != 0, sourcePort, destinationPort,
                    kDnsPort, dnsProxyPort_);
                const bool processScoped = processFilter_ && processFilter_->enabled() &&
                    ((outbound && (destinationPort == kDnsPort ||
                                   destinationPort == kHttpsPort)) ||
                     (!outbound && sourcePort == kHttpsPort));
                const bool processBypass = processScoped &&
                    !processFilter_->shouldIntercept(
                        processEndpoint(ipv4, ipv6, sourcePort, destinationPort,
                                        process_filter::Protocol::Udp, outbound),
                        outbound, false);

                if (!processBypass) switch (route) {
                case transparent::DatagramRoute::ReflectDnsToProxy:
                    datagrams_.observe(addressText(ipv4, ipv6, true), sourcePort);
                    udp->DstPort = htons(dnsProxyPort_);
                    swapAddresses(ipv4, ipv6);
                    addresses[index].Outbound = FALSE;
                    break;

                case transparent::DatagramRoute::ReflectProxyToClient:
                    udp->SrcPort = htons(kDnsPort);
                    swapAddresses(ipv4, ipv6);
                    addresses[index].Outbound = FALSE;
                    break;

                case transparent::DatagramRoute::Pass:
                    break;
                }

                if (!processBypass && route != transparent::DatagramRoute::Pass) {
                    WinDivertHelperCalcChecksums(packet, packetLength,
                                                  &addresses[index], 0);
                }

                bool drop = false;
                if (!processBypass && quicMode_ == quic_strategy::Mode::Block &&
                    route == transparent::DatagramRoute::Pass &&
                    ((outbound && destinationPort == kHttpsPort) ||
                     (!outbound && sourcePort == kHttpsPort))) {
                    drop = true;
                } else if (!processBypass &&
                    quicMode_ == quic_strategy::Mode::Adaptive &&
                    route == transparent::DatagramRoute::Pass) {
                    // Established QUIC data flows dominate here; the registry's
                    // lock-free pre-checks keep them off the mutex and out of
                    // string building.
                    if (outbound && destinationPort == kHttpsPort) {
                        const bool initial = payload &&
                            quic_strategy::looksLikeInitial(
                                static_cast<const uint8_t*>(payload), payloadLength);
                        if (quicRegistry_.needsOutbound(initial)) {
                            const std::string server = addressText(ipv4, ipv6, true);
                            const quic_strategy::Decision decision =
                                quicRegistry_.outbound(server, sourcePort, initial,
                                                       GetTickCount64());
                            drop = decision == quic_strategy::Decision::Drop;
                            if (decision == quic_strategy::Decision::PrimeAndPass) {
                                const std::vector<uint8_t> prime =
                                    quic_strategy::buildPrimePayload();
                                const std::vector<uint8_t> primePacket = divert_packet::buildUdpVariant(
                                    packet, packetLength, payload, prime, addresses[index]);
                                if (!primePacket.empty()) {
                                    batch.append(primePacket.data(), primePacket.size(),
                                                 addresses[index]);
                                    spdlog::trace("QUIC Initial prime: {}:{}", server,
                                                  sourcePort);
                                }
                            } else if (drop) {
                                spdlog::info("QUIC yanitsiz; TCP fallback: {}:{}", server,
                                             sourcePort);
                            }
                        }
                    } else if (!outbound && sourcePort == kHttpsPort &&
                               quicRegistry_.needsInbound()) {
                        quicRegistry_.inbound(addressText(ipv4, ipv6, false),
                                              destinationPort, GetTickCount64());
                    }
                }

                if (!drop) {
                    batch.append(packet, packetLength, addresses[index]);
                }
            } else if (packetLength > 0) {
                batch.append(packet, packetLength, addresses[index]);
            }

            if (!nextPacket || nextLength >= remaining) break;
            packet = static_cast<uint8_t*>(nextPacket);
            remaining = nextLength;
        }

        const size_t count = batch.count();
        if (count == 0) continue;

        // One send for the whole batch is the fast path. If it fails part-way,
        // the packets before the failing one are already on the wire, so the
        // rest are resent one by one: a single bad packet must not take its
        // neighbours (other connections) down with it.
        size_t next = 0;
        if (count > 1) {
            UINT sentBytes = 0;
            if (WinDivertSendEx(packetHandle_, batch.bytes.data(),
                                static_cast<UINT>(batch.bytes.size()), &sentBytes, 0,
                                batch.addresses.data(),
                                (UINT)(count * sizeof(WINDIVERT_ADDRESS)), nullptr)) {
                sendSucceeded();
                continue;
            }
            if (!running_) break;
            UINT covered = 0;
            while (next < count && covered + batch.lengths[next] <= sentBytes) {
                covered += batch.lengths[next++];
            }
            if (covered != sentBytes) next = 0;  // unreliable count: resend all
        }

        size_t offset = 0;
        for (size_t i = 0; i < next; ++i) offset += batch.lengths[i];
        for (size_t i = next; i < count && running_; ++i) {
            DWORD error = ERROR_SUCCESS;
            if (sendOne(batch.bytes.data() + offset, batch.lengths[i],
                        batch.addresses[i], error)) {
                sendSucceeded();
            } else if (running_ && !sendFailed(error)) {
                break;
            }
            offset += batch.lengths[i];
        }
    }
}
