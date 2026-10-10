#include "TransparentDnsProxy.hpp"

#include "DnsMessage.hpp"
#include "RecoveryPolicy.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <string>

#include <windows.h>   // GetTickCount64

namespace {

// Each worker can sit in a blocking DoH call, so a handful of slow queries must
// not starve the rest. Still bounded: the owned, joined threads are the
// lifecycle contract (see stopLocked).
constexpr size_t kWorkerCount = 8;
constexpr size_t kMaxQueuedQueries = 1024;
constexpr size_t kMaxDnsDatagram = 4096;
// The OS resolver retries within ~1-2 s and gives up in a few more; an answer
// produced after that is wasted work and a spurious Worker request.
constexpr unsigned long long kMaxQueueAgeMs = 3000;
// Overall budget per query, on top of the per-phase WinHTTP timeouts.
constexpr unsigned long long kJobDeadlineMs = 8000;

bool endpoint(const sockaddr_storage& peer, std::string& address,
              uint16_t& port) {
    char text[INET6_ADDRSTRLEN] = {};
    if (peer.ss_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&peer);
        if (!inet_ntop(AF_INET, &ipv4->sin_addr, text, sizeof(text))) return false;
        port = ntohs(ipv4->sin_port);
    } else if (peer.ss_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&peer);
        if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
            const uint8_t* bytes = ipv6->sin6_addr.u.Byte;
            if (!inet_ntop(AF_INET, bytes + 12, text, sizeof(text))) return false;
        } else if (!inet_ntop(AF_INET6, &ipv6->sin6_addr, text, sizeof(text))) {
            return false;
        }
        port = ntohs(ipv6->sin6_port);
    } else {
        return false;
    }

    address = text;
    return port != 0;
}

} // namespace

TransparentDnsProxy::TransparentDnsProxy(
    dns::Resolver& resolver, transparent::DatagramRegistry& datagrams,
    uint16_t port)
    : resolver_(resolver), datagrams_(datagrams), port_(port) {}

TransparentDnsProxy::~TransparentDnsProxy() {
    stop();
}

bool TransparentDnsProxy::start() {
    const std::lock_guard lifecycleLock(lifecycleMutex_);
    if (running_) return true;
    stopLocked();
    if (port_ == 0 || port_ == 53) return false;

    const SOCKET socket = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) {
        spdlog::error("DNS relay socket hatasi: {}", WSAGetLastError());
        return false;
    }

    int exclusive = 1;
    setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
    int ipv6Only = 0;
    setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
               reinterpret_cast<const char*>(&ipv6Only), sizeof(ipv6Only));

    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_any;
    local.sin6_port = htons(port_);
    if (bind(socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) ==
        SOCKET_ERROR) {
        spdlog::error("DNS relay port {} bind hatasi: {}", port_, WSAGetLastError());
        closesocket(socket);
        return false;
    }

    // Periodically observe stop without closing a socket underneath sendto.
    const DWORD timeoutMs = 250;
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs)) == SOCKET_ERROR) {
        closesocket(socket);
        return false;
    }
    socket_.store(socket);
    running_ = true;
    try {
        workers_.reserve(kWorkerCount);
        for (size_t index = 0; index < kWorkerCount; ++index) {
            workers_.emplace_back([this]() {
                try { workerLoop(); }
                catch (...) { fail(); }
            });
        }
        receiver_ = std::thread([this]() {
            try { receiveLoop(); }
            catch (...) { fail(); }
        });
    } catch (...) {
        stopLocked();
        return false;
    }
    spdlog::info("Transparent DNS relay dinliyor: [::]:{} -> Cloudflare Worker",
                 port_);
    return true;
}

void TransparentDnsProxy::stop() {
    const std::lock_guard lifecycleLock(lifecycleMutex_);
    stopLocked();
}

void TransparentDnsProxy::fail() {
    {
        const std::lock_guard lock(queueMutex_);
        running_ = false;
    }
    queueReady_.notify_all();
}

void TransparentDnsProxy::stopLocked() {
    running_ = false;

    {
        std::lock_guard lock(queueMutex_);
        jobs_.clear();
    }
    queueReady_.notify_all();

    if (receiver_.joinable()) receiver_.join();
    for (std::thread& worker : workers_) {
        if (worker.joinable()) worker.join();
    }
    workers_.clear();
    const SOCKET socket = socket_.exchange(INVALID_SOCKET);
    if (socket != INVALID_SOCKET) closesocket(socket);
    datagrams_.clear();
}

void TransparentDnsProxy::receiveLoop() {
    std::array<uint8_t, kMaxDnsDatagram> buffer{};

    while (running_) {
        Job job;
        job.peerLength = sizeof(job.peer);
        const SOCKET socket = socket_.load();
        if (socket == INVALID_SOCKET) break;

        const int received = recvfrom(
            socket, reinterpret_cast<char*>(buffer.data()), (int)buffer.size(), 0,
            reinterpret_cast<sockaddr*>(&job.peer), &job.peerLength);
        if (received == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (!running_) break;
            if (recovery::shouldContinueDnsReceive(error)) continue;
            spdlog::error("DNS relay alicisi durdu: {}", error);
            fail();
            break;
        }

        std::string peerAddress;
        uint16_t peerPort = 0;
        if (!endpoint(job.peer, peerAddress, peerPort) ||
            !datagrams_.claim(peerAddress, peerPort)) {
            spdlog::debug("Yetkisiz transparent DNS datagrami reddedildi");
            continue;
        }

        job.data.assign(buffer.begin(), buffer.begin() + received);
        job.enqueuedMs = GetTickCount64();
        dns_message::Query query;
        if (dns_message::parseQuery(job.data.data(), job.data.size(), query) &&
            resolver_.isBootstrapHost(query.name)) {
            // WinHTTP workers may all be waiting for this DNS answer. Answer
            // from the bootstrap cache here rather than queuing behind them.
            process(job);
            continue;
        }
        {
            std::lock_guard lock(queueMutex_);
            if (jobs_.size() >= kMaxQueuedQueries) {
                spdlog::warn("DNS relay kuyrugu dolu; sorgu dusuruldu");
                continue;
            }
            jobs_.push_back(std::move(job));
        }
        queueReady_.notify_one();
    }
}

void TransparentDnsProxy::workerLoop() {
    while (true) {
        Job job;
        {
            std::unique_lock lock(queueMutex_);
            queueReady_.wait(lock, [this]() { return !running_ || !jobs_.empty(); });
            if (!running_) return;
            job = std::move(jobs_.front());
            jobs_.pop_front();
        }
        if (GetTickCount64() - job.enqueuedMs > kMaxQueueAgeMs) {
            spdlog::debug("DNS relay: bayat sorgu atlandi (istemci vazgecmis olmali)");
            continue;
        }
        process(job);
    }
}

std::vector<uint8_t> TransparentDnsProxy::buildReply(const uint8_t* data, size_t length,
                                                     unsigned long long deadlineMs) {
    dns_message::Query query;
    if (!dns_message::parseQuery(data, length, query)) {
        // Answer FORMERR/NOTIMP when the header is readable so the client does
        // not wait out its timeout; garbage without a usable header is dropped.
        spdlog::debug("Desteklenmeyen veya bozuk DNS sorgusu (rcode {})", query.error);
        return query.error != 0 ? dns_message::buildError(query, query.error)
                                : std::vector<uint8_t>{};
    }

    std::vector<uint8_t> response;
    if (query.type == dns_message::kTypeA ||
        query.type == dns_message::kTypeAaaa) {
        // /resolve returns both address families at once and warms the same
        // cache used by DirectRelay. That lets the relay restore Happy
        // Eyeballs without a second network lookup for every TLS connection.
        const dns::Result resolved = resolver_.resolve(query.name, deadlineMs);
        const std::vector<std::string>& addresses =
            query.type == dns_message::kTypeA ? resolved.v4 : resolved.v6;
        const uint32_t ttl = resolved.ttlSeconds == 0 ? 60 : resolved.ttlSeconds;
        if (!resolved.empty()) {
            // One family's lookup errored: NODATA for it would be a lie.
            if (!addresses.empty() || !resolved.transient) {
                response = dns_message::buildResponse(query, addresses, ttl);
            }
        } else if (resolved.allowWireFallback) {
            // An older Worker (404 for every negative), or a name /resolve
            // cannot carry: the raw DoH path yields the real RCODE.
            response = resolver_.queryWire(data, length, deadlineMs);
        } else if (!resolved.transient) {
            // The Worker's verdict (NXDOMAIN / NODATA) reaches the app unchanged.
            response = dns_message::buildResponse(query, {}, ttl, false, resolved.rcode);
        }
    } else {
        response = resolver_.queryWire(data, length, deadlineMs);
    }
    if (response.empty()) {
        response = dns_message::buildResponse(query, {}, 60, true);
    }

    dns_message::truncateForUdp(
        response, std::max(dns_message::kClassicUdpPayload, (size_t)query.ednsPayload));
    spdlog::trace("DNS relay: {} tip {} -> {} bayt", query.name, query.type,
                  response.size());
    return response;
}

void TransparentDnsProxy::process(const Job& job) {
    const std::vector<uint8_t> response = buildReply(
        job.data.data(), job.data.size(), job.enqueuedMs + kJobDeadlineMs);
    if (response.empty()) return;

    const SOCKET socket = socket_.load();
    if (socket == INVALID_SOCKET || !running_) return;
    const int sent = sendto(
        socket, reinterpret_cast<const char*>(response.data()),
        (int)response.size(), 0, reinterpret_cast<const sockaddr*>(&job.peer),
        job.peerLength);
    if (sent == SOCKET_ERROR && running_) {
        spdlog::warn("DNS relay cevap gonderme hatasi: {}", WSAGetLastError());
    }
}
