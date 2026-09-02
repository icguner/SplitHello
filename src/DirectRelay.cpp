#include "DirectRelay.hpp"

#include "PacketStrategy.hpp"
#include "Relay.hpp"
#include "TcpConnect.hpp"
#include "Telemetry.hpp"

#include <spdlog/spdlog.h>

#include <mstcpip.h>

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

// Once one side has sent FIN the other normally follows within a round trip.
// A peer that never does must not keep the connection alive for the full
// idle timeout.
constexpr unsigned kHalfClosedLingerMs = 30 * 1000;

// The pump wakes at least this often so stop() is observed even when neither
// socket produces an event.
constexpr unsigned kPumpMaxWaitMs = 1000;

// A laptop that changes networks leaves the target side of every open flow
// black-holed; without probes the kernel would only notice on the next send.
// Windows sends up to 10 probes, so a dead peer is detected in about 2.5 min.
constexpr unsigned kKeepAliveIdleMs = 60 * 1000;
constexpr unsigned kKeepAliveIntervalMs = 10 * 1000;

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

bool setNonBlocking(SOCKET sock, bool enabled) {
    u_long mode = enabled ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode) != SOCKET_ERROR;
}

// Close that reaches the peer immediately. A graceful close of a non-blocking
// socket that still has bytes queued lets the FIN linger in the background for
// seconds, so a peer waiting to be told the connection is gone is left hanging.
// On an abort we are discarding the connection, so a reset is the honest and
// prompt signal; the winning path still closes gracefully.
void closeAbortive(SOCKET sock) {
    linger reset{};
    reset.l_onoff = 1;
    reset.l_linger = 0;
    setsockopt(sock, SOL_SOCKET, SO_LINGER, (const char*)&reset, sizeof(reset));
    closesocket(sock);
}

void enableKeepAlive(SOCKET sock) {
    tcp_keepalive settings{};
    settings.onoff = 1;
    settings.keepalivetime = kKeepAliveIdleMs;
    settings.keepaliveinterval = kKeepAliveIntervalMs;
    DWORD returned = 0;
    WSAIoctl(sock, SIO_KEEPALIVE_VALS, &settings, sizeof(settings), nullptr, 0, &returned,
             nullptr, nullptr);
}

// Non-blocking send of as much as the socket accepts right now. False only on
// a hard error; a full send buffer simply leaves `sent` short.
bool sendSome(SOCKET sock, const uint8_t* data, size_t length, size_t& sent) {
    sent = 0;
    while (sent < length) {
        const int chunk = (int)std::min<size_t>(length - sent, 1 << 20);
        const int written = ::send(sock, (const char*)data + sent, chunk, 0);
        if (written == SOCKET_ERROR) return WSAGetLastError() == WSAEWOULDBLOCK;
        if (written <= 0) return false;
        sent += (size_t)written;
    }
    return true;
}

// One direction of the pump. Bytes that the destination could not take yet
// wait in `pending`; while it is non-empty the source is not read, which is
// how back-pressure reaches the sender.
struct Direction {
    SOCKET from;
    SOCKET to;
    std::vector<uint8_t> pending;
    size_t offset = 0;
    bool eof = false;       // source sent FIN

    bool finished() const { return eof && pending.empty(); }
};

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
    // run() normally closed everything. A relay that was cancelled before it
    // started still owns the client socket.
    closeSockets();
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
    if (stopping_) return false;

    SOCKET sock = tcp::connectAny(candidates_, connectPort_, kConnectAttemptDelayMs,
                                  kConnectTimeoutMs, connectedAddress_);
    if (sock == INVALID_SOCKET) {
        spdlog::error("Baglanti kurulamadi: {}:{}", targetHost_, targetPort_);
        return false;
    }

    std::lock_guard<std::mutex> lock(socketMutex_);
    if (stopping_) {
        // stop() ran while we were connecting and could not see this handle.
        closesocket(sock);
        return false;
    }
    enableKeepAlive(sock);
    targetSock_ = sock;
    spdlog::debug("Baglandi: {} ({}:{})", connectedAddress_, targetHost_, targetPort_);
    return true;
}

bool DirectRelay::reconnect() {
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        if (targetSock_ != INVALID_SOCKET) {
            closesocket(targetSock_);
            targetSock_ = INVALID_SOCKET;
        }
    }
    return connectTarget();
}

// ---- ClientHello reassembly ----

bool DirectRelay::collectClientHello() {
    clientBuffer_.clear();
    helloComplete_ = false;

    std::array<uint8_t, 16384> chunk;
    unsigned timeoutMs = kClientFirstByteTimeoutMs;

    while (!stopping_) {
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
    return false;
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

    // A pinned profile is a controlled experiment, not learning: nothing it
    // observes feeds the verdict context or the store.
    const bool learning = context_.forcedProfile.empty();
    diagnosis::Context diagnosisContext;
    if (learning) {
        diagnosisContext.rememberedProfile = remembered;
        diagnosisContext.baselineRecentlyHealthy =
            context_.strategies->baselineRecentlyHealthy(context_.networkId, targetHost_);
    }

    // A failed remembered profile is only held against it once the whole
    // event is classified: during a hiccup it fails together with the
    // baseline, and that must not evict a winner that still works.
    bool rememberedFailed = false;
    const auto settleFailure = [&]() {
        if (learning && rememberedFailed) {
            context_.strategies->recordFailure(context_.networkId, targetHost_, remembered);
        }
    };

    size_t attempts = 0;
    std::vector<diagnosis::Attempt> evidence;
    evidence.reserve(std::min(order.size(), kMaxProbeAttempts));
    for (const std::string& profile : order) {
        if (attempts >= kMaxProbeAttempts || stopping_) break;

        strategy::FragmentPlan plan;
        const bool applicable = strategy::buildPlan(profile, hello_, context_.splitDelayMs, plan);
        if (!applicable && profile != "none") continue;

        // Every retry needs a fresh connection: the previous one was reset or
        // blackholed, and the server has already seen a partial handshake.
        if (attempts > 0) {
            Sleep(kRetryPauseMs);
            if (!reconnect()) {
                const diagnosis::Verdict verdict = diagnosis::infer(evidence, diagnosisContext);
                settleFailure();
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
            diagnosis::Verdict verdict = diagnosis::infer(evidence, diagnosisContext);
            const unsigned elapsedMs = evidence.back().elapsedMs;
            if (!learning) {
                spdlog::debug("{}: '{}' (zorlanan)", targetHost_, profile);
            } else if (profile == "none") {
                // A healthy baseline has no state to learn, but it vouches for
                // the host for a while and retires a winner that is no longer
                // needed.
                context_.strategies->noteBaselineHealthy(context_.networkId, targetHost_);
                if (!remembered.empty()) {
                    context_.strategies->remember(context_.networkId, targetHost_, profile,
                                                  verdict.kind, verdict.confidence);
                    spdlog::info("{}: baz cizgi yeniden gecti, '{}' profili unutuldu",
                                 targetHost_, remembered);
                } else if (verdict.kind == diagnosis::Kind::NoInterference) {
                    spdlog::trace("{}: normal TLS, sure={}ms", targetHost_, elapsedMs);
                } else {
                    spdlog::info("{}: teshis={} guven={}% sure={}ms", targetHost_,
                                 diagnosis::name(verdict.kind), verdict.confidence, elapsedMs);
                }
            } else if (verdict.kind == diagnosis::Kind::TransientFailure) {
                spdlog::info("{}: gecici ag hatasi, '{}' ile devam edildi, ogrenilmedi ({}. deneme)",
                             targetHost_, profile, attempts);
            } else {
                settleFailure();
                const strategy::Store::Outcome learned = context_.strategies->remember(
                    context_.networkId, targetHost_, profile, verdict.kind, verdict.confidence);
                if (learned == strategy::Store::Outcome::Candidate) {
                    // One differential is a suspicion. Until a later connection
                    // reproduces it, the record says so rather than "likely".
                    verdict.kind = diagnosis::Kind::InterferenceSuspected;
                    verdict.confidence = std::min(verdict.confidence, 55U);
                    spdlog::info("{}: baz cizgi gecmedi, '{}' gecti; ogrenmek icin ikinci dogrulama bekleniyor ({}. deneme)",
                                 targetHost_, profile, attempts);
                } else if (diagnosis::isVerifiedBypass(verdict.kind)) {
                    spdlog::info("{}: teshis={} guven={}% profil='{}' sure={}ms ({}. deneme{})",
                                 targetHost_, diagnosis::name(verdict.kind), verdict.confidence,
                                 profile, elapsedMs, attempts,
                                 learned == strategy::Store::Outcome::Learned ? ", dogrulandi" : "");
                } else {
                    spdlog::trace("{}: ogrenilmis profil='{}' sure={}ms",
                                  targetHost_, profile, elapsedMs);
                }
            }
            recordTelemetry(evidence, verdict, remembered, true,
                            GetTickCount64() - decisionStarted);
            return true;
        }

        if (learning && profile == remembered) rememberedFailed = true;
        spdlog::debug("{}: '{}' basarisiz - {}", targetHost_, profile,
                      diagnosis::describe(outcome));
        firstResponse_.clear();
    }

    const diagnosis::Verdict verdict = diagnosis::infer(evidence, diagnosisContext);
    settleFailure();
    recordTelemetry(evidence, verdict, remembered, false,
                    GetTickCount64() - decisionStarted);
    spdlog::warn("{}:{} icin sonuc yok; teshis={} guven={}%",
                 targetHost_, targetPort_, diagnosis::name(verdict.kind), verdict.confidence);
    return false;
}

// ---- Worker tunnel fallback ----

bool DirectRelay::handOffToTunnel() {
    if (!context_.tunnelFallback || context_.workerUrl.empty()) return false;
    if (clientSock_ == INVALID_SOCKET) return false;

    spdlog::info("{}:{} Worker tuneline devrediliyor", targetHost_, targetPort_);

    // The tunnel owns the client socket from here on and closes it itself.
    Relay tunnel(clientSock_, context_.workerUrl, context_.sharedSecret,
                 targetHost_, targetPort_, std::move(clientBuffer_),
                 context_.bypassConnectPort);
    {
        std::lock_guard<std::mutex> lock(socketMutex_);
        clientSock_ = INVALID_SOCKET;
        if (stopping_) return false;
        tunnel_ = &tunnel;
    }

    tunnel.run();

    std::lock_guard<std::mutex> lock(socketMutex_);
    tunnel_ = nullptr;
    return true;
}

// ---- Main flow ----

void DirectRelay::run() {
    if (stopping_) {
        closeSockets();
        return;
    }

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
            releaseHandshakeBuffers();
            if (flushed) pump();
            spdlog::trace("Baglanti kapandi: {}:{}", targetHost_, targetPort_);
        } else {
            handOffToTunnel(); // takes clientSock_ on success
        }
    }

    // Clear the handles before returning so a recycled handle value can never
    // be shut down out from under another connection.
    closeSockets();
}

void DirectRelay::pump() {
    if (!setNonBlocking(clientSock_, true) || !setNonBlocking(targetSock_, true)) return;

    std::array<uint8_t, kPumpBufferSize> buffer;
    Direction upstream{clientSock_, targetSock_};
    Direction downstream{targetSock_, clientSock_};
    Direction* const directions[] = {&upstream, &downstream};

    ULONGLONG lastActivity = GetTickCount64();

    while (!stopping_) {
        fd_set readable;
        fd_set writable;
        FD_ZERO(&readable);
        FD_ZERO(&writable);

        bool anyOpen = false;
        for (Direction* direction : directions) {
            if (direction->finished()) continue;
            anyOpen = true;
            if (!direction->pending.empty()) {
                FD_SET(direction->to, &writable);
            } else {
                FD_SET(direction->from, &readable);
            }
        }
        if (!anyOpen) return; // both sides sent FIN and everything was delivered

        const bool halfClosed = upstream.eof || downstream.eof;
        const unsigned idleLimit = halfClosed
            ? std::min(kHalfClosedLingerMs, context_.idleTimeoutMs)
            : context_.idleTimeoutMs;
        const ULONGLONG now = GetTickCount64();
        const ULONGLONG idle = now - lastActivity;
        if (idle >= idleLimit) {
            spdlog::debug("{}:{} {} sn boyunca sessiz kaldi, kapatiliyor",
                          targetHost_, targetPort_, idle / 1000);
            return;
        }

        const ULONGLONG waitMs = std::min<ULONGLONG>(idleLimit - idle, kPumpMaxWaitMs);
        timeval tv{};
        tv.tv_sec = (long)(waitMs / 1000);
        tv.tv_usec = (long)((waitMs % 1000) * 1000);

        const int ready = ::select(0, &readable, &writable, nullptr, &tv);
        if (ready == SOCKET_ERROR) return; // a handle was closed under us
        if (ready == 0) continue;

        for (Direction* direction : directions) {
            if (direction->finished()) continue;

            if (!direction->pending.empty()) {
                if (!FD_ISSET(direction->to, &writable)) continue;
                size_t sent = 0;
                if (!sendSome(direction->to, direction->pending.data() + direction->offset,
                              direction->pending.size() - direction->offset, sent)) {
                    return;
                }
                if (sent > 0) lastActivity = GetTickCount64();
                direction->offset += sent;
                if (direction->offset == direction->pending.size()) {
                    direction->pending.clear();
                    direction->offset = 0;
                    if (direction->eof) shutdown(direction->to, SD_SEND);
                }
                continue;
            }

            if (!FD_ISSET(direction->from, &readable)) continue;
            const int received = ::recv(direction->from, (char*)buffer.data(),
                                        (int)buffer.size(), 0);
            if (received == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAEWOULDBLOCK) continue;
                return; // reset or aborted: tear down both sides
            }
            lastActivity = GetTickCount64();
            if (received == 0) {
                // Propagate the half-close; the other direction keeps flowing
                // until the peer answers with its own FIN.
                direction->eof = true;
                shutdown(direction->to, SD_SEND);
                continue;
            }

            size_t sent = 0;
            if (!sendSome(direction->to, buffer.data(), (size_t)received, sent)) return;
            if (sent < (size_t)received) {
                direction->pending.assign(buffer.begin() + sent, buffer.begin() + received);
                direction->offset = 0;
            }
        }
    }
}

void DirectRelay::releaseHandshakeBuffers() {
    std::vector<uint8_t>().swap(clientBuffer_);
    std::vector<uint8_t>().swap(firstResponse_);
    candidates_.clear();
    candidates_.shrink_to_fit();
}

void DirectRelay::closeSockets() {
    std::lock_guard<std::mutex> lock(socketMutex_);
    // An aborted connection is reset so the peer is told at once; a connection
    // that ended on its own is closed gracefully to flush the last bytes.
    const bool abort = stopping_.load();
    if (clientSock_ != INVALID_SOCKET) {
        if (abort) closeAbortive(clientSock_); else closesocket(clientSock_);
        clientSock_ = INVALID_SOCKET;
    }
    if (targetSock_ != INVALID_SOCKET) {
        if (abort) closeAbortive(targetSock_); else closesocket(targetSock_);
        targetSock_ = INVALID_SOCKET;
    }
}

void DirectRelay::stop() {
    stopping_ = true;
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (tunnel_) tunnel_->stop();
    // Shut down only the receive side. That is enough to unblock a blocking
    // recv or a select() waiting to read, so the owning thread notices the
    // abort and runs closeSockets(); it deliberately does not send a FIN,
    // because a graceful half-close would let the reset that closeSockets()
    // arms degrade into a FIN that lingers for seconds on a non-blocking
    // socket. The peer is then told the connection is gone at once, by RST.
    if (targetSock_ != INVALID_SOCKET) shutdown(targetSock_, SD_RECEIVE);
    if (clientSock_ != INVALID_SOCKET) shutdown(clientSock_, SD_RECEIVE);
}
