#include "TransparentDnsProxy.hpp"

#include "DnsMessage.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <string>

namespace {

constexpr size_t kWorkerCount = 4;
constexpr size_t kMaxQueuedQueries = 1024;
constexpr size_t kMaxDnsDatagram = 4096;

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
    if (running_) return true;
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

    socket_.store(socket);
    running_ = true;
    workers_.reserve(kWorkerCount);
    for (size_t index = 0; index < kWorkerCount; ++index) {
        workers_.emplace_back([this]() { workerLoop(); });
    }
    receiver_ = std::thread([this]() { receiveLoop(); });
    spdlog::info("Transparent DNS relay dinliyor: [::]:{} -> Cloudflare Worker",
                 port_);
    return true;
}

void TransparentDnsProxy::stop() {
    running_ = false;
    const SOCKET socket = socket_.exchange(INVALID_SOCKET);
    if (socket != INVALID_SOCKET) closesocket(socket);

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
            if (running_) {
                spdlog::warn("DNS relay okuma hatasi: {}", WSAGetLastError());
            }
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
        process(job);
    }
}

void TransparentDnsProxy::process(const Job& job) {
    dns_message::Query query;
    if (!dns_message::parseQuery(job.data.data(), job.data.size(), query)) {
        spdlog::debug("Desteklenmeyen veya bozuk DNS sorgusu reddedildi");
        return;
    }

    std::vector<uint8_t> response;
    if (query.type == dns_message::kTypeA ||
        query.type == dns_message::kTypeAaaa) {
        // /resolve returns both address families at once and warms the same
        // cache used by DirectRelay. That lets the relay restore Happy
        // Eyeballs without a second network lookup for every TLS connection.
        const dns::Result resolved = resolver_.resolve(query.name);
        const std::vector<std::string>& addresses =
            query.type == dns_message::kTypeA ? resolved.v4 : resolved.v6;
        if (!resolved.empty()) {
            response = dns_message::buildResponse(
                query, addresses, resolved.ttlSeconds == 0 ? 60 : resolved.ttlSeconds);
        }
    } else {
        response = resolver_.queryWire(job.data.data(), job.data.size());
    }
    if (response.empty() &&
        (query.type == dns_message::kTypeA ||
         query.type == dns_message::kTypeAaaa)) {
        // Preserve the raw DoH path as a fallback for an older Worker whose
        // /resolve response does not contain the modern multi-address shape.
        response = resolver_.queryWire(job.data.data(), job.data.size());
    }
    if (response.empty()) {
        response = dns_message::buildResponse(query, {}, 60, true);
    }

    const SOCKET socket = socket_.load();
    if (socket == INVALID_SOCKET || !running_) return;
    const int sent = sendto(
        socket, reinterpret_cast<const char*>(response.data()),
        (int)response.size(), 0, reinterpret_cast<const sockaddr*>(&job.peer),
        job.peerLength);
    if (sent == SOCKET_ERROR && running_) {
        spdlog::warn("DNS relay cevap gonderme hatasi: {}", WSAGetLastError());
    } else {
        spdlog::trace("DNS wire relay: {} tip {} -> {} bayt", query.name,
                      query.type, response.size());
    }
}
