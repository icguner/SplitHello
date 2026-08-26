#include "DirectRelay.hpp"

#include "PacketStrategy.hpp"
#include "Relay.hpp"
#include "TcpConnect.hpp"
#include "Telemetry.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>

namespace {

// Upper bound on what we will buffer while waiting for a complete ClientHello.
// A TLS record cannot exceed 16 KiB; the extra room absorbs whatever the client
// pipelines behind it.
constexpr size_t kMaxHelloBuffer = 64 * 1024;

// How long to wait for the client to produce its first bytes. Server-first
// protocols tunnelled through CONNECT never send anything, so this must expire
// rather than hang the connection.
constexpr unsigned kClientFirstByteTimeoutMs = 4000;
constexpr unsigned kClientContinuationTimeoutMs = 2000;

constexpr unsigned kConnectAttemptDelayMs = 250;   // RFC 8305 recommends 250ms
constexpr unsigned kConnectTimeoutMs = 10000;

// Known paths normally succeed on the first cached profile. An unknown path
// may need both packet-level and TLS-record families before it can be classified.
constexpr size_t kMaxProbeAttempts = 12;

// After a blocked attempt the DPI box often keeps resetting the same 5-tuple
// for a moment. Retrying instantly makes the next profile look broken when it
// is only caught in that residual window.
constexpr unsigned kRetryPauseMs = 150;

constexpr size_t kProbeReadBufferSize = 32 * 1024;
constexpr size_t kPumpBufferSize = 64 * 1024;
constexpr size_t kMaxProbeResponse = 64 * 1024;

// Addresses for hosts the Worker could not answer for. Poisoned for blocked
// domains, but correct for everything else, so it is a useful fallback.
std::vector<std::string> systemResolve(const std::string& host, uint16_t port) {
    std::vector<std::string> out;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &resolved) != 0) {
        return out;
    }

    for (addrinfo* it = resolved; it; it = it->ai_next) {
        char text[INET6_ADDRSTRLEN] = {};
        if (it->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((sockaddr_in*)it->ai_addr)->sin_addr, text, sizeof(text));
        } else if (it->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((sockaddr_in6*)it->ai_addr)->sin6_addr, text, sizeof(text));
        } else {
            continue;
        }
        if (text[0]) out.emplace_back(text);
    }
    freeaddrinfo(resolved);
    return out;
}

} // namespace

DirectRelay::DirectRelay(SOCKET clientSock, const RelayContext& context,
                         std::string targetHost, uint16_t targetPort,
                         std::string originalTargetAddress,
                         uint16_t connectPort)
    : clientSock_(clientSock)
    , context_(context)
    , targetHost_(std::move(targetHost))
    , targetPort_(targetPort)
    , originalTargetAddress_(std::move(originalTargetAddress))
    , connectPort_(connectPort == 0 ? targetPort : connectPort) {}

DirectRelay::~DirectRelay() {
    stop();
}

void DirectRelay::start() {
    std::thread([this]() { run(); }).detach();
}

// ---- Address resolution ----

bool DirectRelay::prepareCandidates() {
    candidates_.clear();

    // Preserve the address selected by the application, then add the cached
    // dual-stack pool. Redirecting the SYN to localhost makes the application
    // believe that its first address connected immediately, so its own Happy
    // Eyeballs fallback can no longer race IPv4 against a broken IPv6 route.
    // The transparent DNS proxy warms this resolver cache before TLS arrives.
    if (!originalTargetAddress_.empty()) {
        candidates_.push_back(originalTargetAddress_);
    }

    if (context_.resolver && !tcp::isIpLiteral(targetHost_)) {
        const dns::Result result = context_.resolver->resolve(targetHost_);
        for (const std::string& address : result.candidates()) {
            if (std::find(candidates_.begin(), candidates_.end(), address) ==
                candidates_.end()) {
                candidates_.push_back(address);
            }
        }
    }

    if (candidates_.empty()) {
        spdlog::warn("DNS: {} Worker uzerinden cozulemedi, sistem cozumleyicisi deneniyor",
                     targetHost_);
        candidates_ = systemResolve(targetHost_, targetPort_);
    }

    if (candidates_.empty()) {
        spdlog::error("Adres cozumlenemedi: {}", targetHost_);
        return false;
    }
    return true;
}

bool DirectRelay::connectTarget() {
    targetSock_ = tcp::connectAny(candidates_, connectPort_, kConnectAttemptDelayMs,
                                  kConnectTimeoutMs, connectedAddress_);
    if (targetSock_ == INVALID_SOCKET) {
        spdlog::error("Baglanti kurulamadi: {}:{}", targetHost_, targetPort_);
        return false;
    }
    spdlog::debug("Baglandi: {} ({}:{})", connectedAddress_, targetHost_, targetPort_);
    return true;
}

bool DirectRelay::reconnect() {
    if (targetSock_ != INVALID_SOCKET) {
        closesocket(targetSock_);
        targetSock_ = INVALID_SOCKET;
    }
    return connectTarget();
}

// ---- ClientHello reassembly ----

bool DirectRelay::collectClientHello() {
    clientBuffer_.clear();
    helloComplete_ = false;

    std::array<uint8_t, 16384> chunk;
    unsigned timeoutMs = kClientFirstByteTimeoutMs;

    while (true) {
        const int received = tcp::recvTimeout(clientSock_, chunk.data(), chunk.size(), timeoutMs);

        if (received == tcp::kTimedOut) {
            // Either a server-first protocol, or a client that stopped mid-hello.
            // Forward whatever we have; the target decides what to make of it.
            if (!clientBuffer_.empty()) {
                spdlog::debug("ClientHello tamamlanmadi ({} bayt), oldugu gibi iletiliyor",
                              clientBuffer_.size());
            }
            return true;
        }
        if (received <= 0) {
            return !clientBuffer_.empty();
        }

        clientBuffer_.insert(clientBuffer_.end(), chunk.begin(), chunk.begin() + received);
        timeoutMs = kClientContinuationTimeoutMs;

        const tls::ParseStatus status =
            tls::parseClientHello(clientBuffer_.data(), clientBuffer_.size(), hello_);

        switch (status) {
        case tls::ParseStatus::Ok:
            helloComplete_ = true;
            if (!hello_.serverName.empty()) {
                targetHost_ = strategy::normalizeHost(hello_.serverName);
            }
            if (hello_.hasEch) {
                spdlog::debug("{}: ECH uzantisi var (gercek ECH veya GREASE); tum guvenli profiller acik",
                             targetHost_);
            } else if (hello_.spansRecords) {
                spdlog::debug("{}: ClientHello zaten birden fazla kayda yayilmis", targetHost_);
            }
            return true;

        case tls::ParseStatus::NeedMore:
            if (clientBuffer_.size() >= kMaxHelloBuffer) {
                spdlog::warn("ClientHello {} bayti asti, parcalanmadan iletiliyor", kMaxHelloBuffer);
                return true;
            }
            break; // keep reading

        case tls::ParseStatus::NotTls:
            spdlog::debug("{}:{} TLS degil, duz iletim", targetHost_, targetPort_);
            return true;

        case tls::ParseStatus::Malformed:
            spdlog::debug("{}:{} bozuk TLS kaydi, duz iletim", targetHost_, targetPort_);
            return true;
        }
    }
}

// ---- Fragmentation ----

void DirectRelay::setNoDelay(bool enabled) {
    if (targetSock_ == INVALID_SOCKET) return;
    int value = enabled ? 1 : 0;
    setsockopt(targetSock_, IPPROTO_TCP, TCP_NODELAY, (const char*)&value, sizeof(value));
}

bool DirectRelay::writeFragmented(const strategy::FragmentPlan& plan) {
    const uint8_t* data = clientBuffer_.data();
    const uint8_t contentType = data[0];
    const uint8_t versionMajor = data[1];
    const uint8_t versionMinor = data[2];
    const uint8_t* payload = data + tls::kRecordHeaderSize;
    const size_t payloadLength = hello_.recordPayloadLength;

    // Split points plus the implicit final boundary.
    std::vector<size_t> boundaries = plan.recordSplits;
    boundaries.push_back(payloadLength);

    size_t start = 0;
    for (const size_t end : boundaries) {
        const size_t length = end - start;
        const uint8_t header[tls::kRecordHeaderSize] = {
            contentType, versionMajor, versionMinor,
            (uint8_t)(length >> 8), (uint8_t)(length & 0xFF)
        };

        if (!tcp::sendAll(targetSock_, header, sizeof(header))) return false;

        if (plan.writeChunk == 0) {
            if (!tcp::sendAll(targetSock_, payload + start, length)) return false;
        } else {
            for (size_t offset = 0; offset < length; offset += plan.writeChunk) {
                const size_t piece = std::min(plan.writeChunk, length - offset);
                if (!tcp::sendAll(targetSock_, payload + start + offset, piece)) return false;
                if (offset + piece < length) Sleep(1);
            }
        }

        start = end;
        if (start < payloadLength && plan.delayMs > 0) Sleep(plan.delayMs);
    }
    return true;
}

bool DirectRelay::writePlan(const strategy::FragmentPlan& plan) {
    // Each send() has to leave as its own segment, so Nagle must be off while
    // we are laying out the fragments.
    setNoDelay(true);

    bool ok = true;

    if (helloComplete_ && plan.splitsAnything()) {
        ok = writeFragmented(plan);
    } else if (helloComplete_) {
        ok = tcp::sendAll(targetSock_, clientBuffer_.data(), hello_.recordTotalLength);
    }

    setNoDelay(false);
    return ok;
}

diagnosis::ProbeSignal DirectRelay::awaitResponse(std::vector<uint8_t>& out) {
    std::array<uint8_t, kProbeReadBufferSize> buffer;
    out.clear();
    if (out.capacity() < kProbeReadBufferSize) out.reserve(kProbeReadBufferSize);

    const ULONGLONG deadline = GetTickCount64() + context_.probeTimeoutMs;
    while (out.size() < kMaxProbeResponse) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return diagnosis::ProbeSignal::Timeout;

        const unsigned remaining = (unsigned)std::min<ULONGLONG>(deadline - now, 0xFFFFFFFFULL);
        const int received = tcp::recvTimeout(targetSock_, buffer.data(), buffer.size(), remaining);

        if (received == tcp::kTimedOut) return diagnosis::ProbeSignal::Timeout;
        if (received == 0) return diagnosis::ProbeSignal::Closed;
        if (received < 0) return diagnosis::ProbeSignal::Reset;

        out.insert(out.end(), buffer.begin(), buffer.begin() + received);
        switch (tls::classifyServerResponse(out.data(), out.size())) {
        case tls::ServerResponseStatus::ServerHello:
            return diagnosis::ProbeSignal::ServerHello;
        case tls::ServerResponseStatus::Alert:
            return diagnosis::ProbeSignal::Alert;
        case tls::ServerResponseStatus::Unexpected:
            return diagnosis::ProbeSignal::Unexpected;
        case tls::ServerResponseStatus::NeedMore:
            break;
        }
    }
    return diagnosis::ProbeSignal::Unexpected;
}

bool DirectRelay::flushTrailingClientData() {
    if (!helloComplete_ || hello_.spansRecords ||
        clientBuffer_.size() <= hello_.recordTotalLength) return true;

    // RFC 8446 permits 0-RTT application data immediately after ClientHello.
    // It must be delivered only to the winning connection: replaying it on
    // every diagnostic attempt could repeat a non-idempotent request.
    return tcp::sendAll(targetSock_, clientBuffer_.data() + hello_.recordTotalLength,
                        clientBuffer_.size() - hello_.recordTotalLength);
}

void DirectRelay::recordTelemetry(
    const std::vector<diagnosis::Attempt>& evidence,
    const diagnosis::Verdict& verdict,
    const std::string& rememberedProfile,
    bool success,
    uint64_t totalElapsedMs) {
    if (success && !verdict.winningProfile.empty()) {
        liveFlow_.setProfile(verdict.winningProfile);
    }
    liveFlow_.decision(
        success, success && verdict.winningProfile != "none");

    if (!context_.telemetry) return;

    telemetry::ProbeRecord record;
    record.networkId = context_.networkId;
    record.host = targetHost_;
    record.rememberedProfile = rememberedProfile;
    record.verdict = verdict;
    record.attempts = evidence;
    record.totalElapsedMs = static_cast<unsigned>(
        std::min<uint64_t>(totalElapsedMs, 0xFFFFFFFFULL));
    record.success = success;
    record.forced = !context_.forcedProfile.empty();
    context_.telemetry->record(std::move(record));
}

bool DirectRelay::deliverHello() {
    if (clientBuffer_.empty()) return true; // server-first protocol: nothing to send yet

    if (!helloComplete_) {
        // Not something we can safely re-frame - forward it byte for byte.
        return tcp::sendAll(targetSock_, clientBuffer_.data(), clientBuffer_.size());
    }

    if (hello_.spansRecords) {
        // We only know the first record is complete; the remainder of the
        // handshake may still be waiting in the client socket. Forward what
        // we have and switch to streaming instead of waiting for a response
        // that the server cannot produce until later records arrive.
        activeProfile_ = "none";
        return tcp::sendAll(targetSock_, clientBuffer_.data(), clientBuffer_.size());
    }

    // --strategy pins one profile: useful for comparing profiles on a given
    // network, and it must not pollute what we have learned. "none" trails it
    // so a hello the forced profile cannot describe (no SNI, ECH, already
    // fragmented) still goes out rather than failing the connection.
    const std::vector<std::string> order =
        context_.forcedProfile.empty()
            ? context_.strategies->probeOrder(context_.networkId, targetHost_, hello_)
            : (context_.forcedProfile == "none"
                   ? std::vector<std::string>{"none"}
                   : std::vector<std::string>{context_.forcedProfile, "none"});
    const std::string remembered = context_.strategies->lookup(context_.networkId, targetHost_);
    const ULONGLONG decisionStarted = GetTickCount64();

    size_t attempts = 0;
    std::vector<diagnosis::Attempt> evidence;
    evidence.reserve(std::min(order.size(), kMaxProbeAttempts));
    for (const std::string& profile : order) {
        if (attempts >= kMaxProbeAttempts) break;

        strategy::FragmentPlan plan;
        const bool applicable = strategy::buildPlan(profile, hello_, context_.splitDelayMs, plan);
        if (!applicable && profile != "none") continue;

        // Every retry needs a fresh connection: the previous one was reset or
        // blackholed, and the server has already seen a partial handshake.
        if (attempts > 0) {
            Sleep(kRetryPauseMs);
            if (!reconnect()) {
                const diagnosis::Verdict verdict = diagnosis::infer(evidence);
                recordTelemetry(evidence, verdict, remembered, false,
                                GetTickCount64() - decisionStarted);
                return false;
            }
        }
        attempts++;

        packet_strategy::Policy packetPolicy;
        if (context_.packetPolicies &&
            packet_strategy::policyForProfile(profile, hello_, packetPolicy)) {
            sockaddr_storage local{};
            int localLength = sizeof(local);
            uint16_t localPort = 0;
            if (getsockname(targetSock_, reinterpret_cast<sockaddr*>(&local),
                            &localLength) == 0) {
                if (local.ss_family == AF_INET) {
                    localPort = ntohs(reinterpret_cast<sockaddr_in*>(&local)->sin_port);
                } else if (local.ss_family == AF_INET6) {
                    localPort = ntohs(reinterpret_cast<sockaddr_in6*>(&local)->sin6_port);
                }
            }
            context_.packetPolicies->arm(connectedAddress_, localPort, packetPolicy);
        }

        const ULONGLONG probeStarted = GetTickCount64();
        if (!writePlan(plan)) {
            spdlog::debug("{}: '{}' profili gonderilemedi", targetHost_, profile);
            continue;
        }

        const diagnosis::ProbeSignal outcome = awaitResponse(firstResponse_);
        const ULONGLONG elapsed = GetTickCount64() - probeStarted;
        evidence.push_back({profile, outcome,
                            (unsigned)std::min<ULONGLONG>(elapsed, 0xFFFFFFFFULL)});

        if (outcome == diagnosis::ProbeSignal::ServerHello) {
            activeProfile_ = profile;
            const diagnosis::Verdict verdict = diagnosis::infer(evidence);
            if (!context_.forcedProfile.empty()) {
                spdlog::debug("{}: '{}' (zorlanan)", targetHost_, profile);
            } else {
                // A healthy baseline has no state to learn. Only touch the
                // store when recording a bypass or removing a stale winner.
                if (profile != "none" || !remembered.empty()) {
                    context_.strategies->remember(context_.networkId, targetHost_, profile,
                                                  verdict.kind, verdict.confidence);
                }
                const bool newlyLearned = profile != remembered || attempts > 1;
                if (verdict.kind == diagnosis::Kind::NoInterference) {
                    spdlog::trace("{}: normal TLS, sure={}ms", targetHost_,
                                  evidence.back().elapsedMs);
                } else if (newlyLearned) {
                    spdlog::info("{}: teshis={} guven={}% profil='{}' sure={}ms ({}. deneme)",
                                 targetHost_, diagnosis::name(verdict.kind), verdict.confidence,
                                 profile, evidence.back().elapsedMs, attempts);
                } else {
                    spdlog::trace("{}: ogrenilmis profil='{}' sure={}ms",
                                  targetHost_, profile, evidence.back().elapsedMs);
                }
            }
            recordTelemetry(evidence, verdict, remembered, true,
                            GetTickCount64() - decisionStarted);
            return true;
        }

        if (profile == remembered && context_.forcedProfile.empty()) {
            context_.strategies->recordFailure(context_.networkId, targetHost_, profile);
        }
        spdlog::debug("{}: '{}' basarisiz - {}", targetHost_, profile,
                      diagnosis::describe(outcome));
        firstResponse_.clear();
    }

    const diagnosis::Verdict verdict = diagnosis::infer(evidence);
    recordTelemetry(evidence, verdict, remembered, false,
                    GetTickCount64() - decisionStarted);
    spdlog::warn("{}:{} icin sonuc yok; teshis={} guven={}%",
                 targetHost_, targetPort_, diagnosis::name(verdict.kind), verdict.confidence);
    return false;
}

// ---- Worker tunnel fallback ----

bool DirectRelay::handOffToTunnel() {
    if (!context_.tunnelFallback || context_.workerUrl.empty()) return false;

    spdlog::info("{}:{} Worker tuneline devrediliyor", targetHost_, targetPort_);

    auto* relay = new Relay(clientSock_, context_.workerUrl, context_.sharedSecret,
                            targetHost_, targetPort_, std::move(clientBuffer_),
                            context_.bypassConnectPort);
    clientSock_ = INVALID_SOCKET; // ownership transferred
    relay->start();
    return true;
}

// ---- Main flow ----

void DirectRelay::run() {
    running_ = true;
    liveFlow_.begin(context_.liveStats.get());

    // Transparent connections initially carry only an IP address. Buffering
    // first lets us recover SNI, resolve it over the Worker, and keep adaptive
    // learning scoped to the hostname instead of a shared CDN address. Manual
    // SOCKS/CONNECT retains its old connect-first behavior for server-first
    // protocols.
    const bool prepared = originalTargetAddress_.empty()
        ? (prepareCandidates() && connectTarget() && collectClientHello())
        : (collectClientHello() && prepareCandidates() && connectTarget());
    if (prepared) {
        if (deliverHello() && flushTrailingClientData()) {
            spdlog::trace("Baglanti kuruldu: {}:{} [{}] via {}",
                          targetHost_, targetPort_, activeProfile_, connectedAddress_);

            // Whatever the probe already read has to reach the client first.
            const bool flushed = firstResponse_.empty() ||
                                 tcp::sendAll(clientSock_, firstResponse_.data(),
                                              firstResponse_.size());
            if (flushed) {
                clientToTarget_ = std::thread([this]() { pumpClientToTarget(); });
                targetToClient_ = std::thread([this]() { pumpTargetToClient(); });
                if (clientToTarget_.joinable()) clientToTarget_.join();
                if (targetToClient_.joinable()) targetToClient_.join();
            }
            spdlog::trace("Baglanti kapandi: {}:{}", targetHost_, targetPort_);
        } else {
            handOffToTunnel(); // takes clientSock_ on success
        }
    }

    // Clear the handles before the destructor runs so a recycled handle value
    // can never be shut down out from under another connection.
    running_ = false;
    if (clientSock_ != INVALID_SOCKET) { closesocket(clientSock_); clientSock_ = INVALID_SOCKET; }
    if (targetSock_ != INVALID_SOCKET) { closesocket(targetSock_); targetSock_ = INVALID_SOCKET; }

    delete this;
}

void DirectRelay::pumpClientToTarget() {
    std::array<uint8_t, kPumpBufferSize> buffer;

    while (running_) {
        const int received = recv(clientSock_, (char*)buffer.data(), (int)buffer.size(), 0);
        if (received <= 0) break;
        if (!tcp::sendAll(targetSock_, buffer.data(), (size_t)received)) break;
    }
    stop();
}

void DirectRelay::pumpTargetToClient() {
    std::array<uint8_t, kPumpBufferSize> buffer;

    while (running_) {
        const int received = recv(targetSock_, (char*)buffer.data(), (int)buffer.size(), 0);
        if (received <= 0) break;
        if (!tcp::sendAll(clientSock_, buffer.data(), (size_t)received)) break;
    }
    stop();
}

void DirectRelay::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (targetSock_ != INVALID_SOCKET) shutdown(targetSock_, SD_BOTH);
        if (clientSock_ != INVALID_SOCKET) shutdown(clientSock_, SD_BOTH);
    }
}
