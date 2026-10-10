#include "TransparentFlow.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <vector>

namespace transparent {
namespace {

constexpr uint64_t kPendingFlowTtlMs = 15000;
constexpr size_t kMaxPendingFlows = 8192;
constexpr uint32_t kMaxPendingDatagramsPerTuple = 32;
// Registries are swept at most this often; each lookup also checks its own
// entry's expiry, so a late claim can never be authorized by a stale entry.
constexpr uint64_t kPruneIntervalMs = 1000;

// A live HTTPS connection can sit idle for hours (keep-alive, push channels),
// and losing its entry would turn the next packet into an unexplained RST.
constexpr uint64_t kTcpFlowIdleMs = 4ULL * 60ULL * 60ULL * 1000ULL;
constexpr uint64_t kTcpFlowClosingMs = 2ULL * 60ULL * 1000ULL;
constexpr size_t kMaxTcpFlows = 65536;

uint64_t clockMs(uint64_t supplied) {
    return supplied == 0 ? GetTickCount64() : supplied;
}

std::string flowKey(const std::string& address, uint16_t port) {
    return address + "|" + std::to_string(port);
}

} // namespace

Address addressFromBytes(const void* bytes, bool ipv6) {
    Address out{};
    if (!bytes) return out;
    if (ipv6) {
        std::memcpy(out.data(), bytes, 16);
    } else {
        out[10] = 0xFF;
        out[11] = 0xFF;
        std::memcpy(out.data() + 12, bytes, 4);
    }
    return out;
}

bool parseAddress(const std::string& text, Address& out) {
    in_addr v4{};
    if (inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        out = addressFromBytes(&v4, false);
        return true;
    }
    in6_addr v6{};
    if (inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
        out = addressFromBytes(&v6, true);
        return true;
    }
    return false;
}

size_t PeerKeyHash::operator()(const PeerKey& key) const noexcept {
    uint64_t hash = 1469598103934665603ULL;
    const auto add = [&hash](uint8_t value) {
        hash ^= value;
        hash *= 1099511628211ULL;
    };
    for (const uint8_t byte : key.address) add(byte);
    add((uint8_t)(key.port >> 8));
    add((uint8_t)key.port);
    add(key.kind);
    return (size_t)hash;
}

void FlowRegistry::observe(const std::string& serverAddress, uint16_t clientPort,
                           uint16_t targetPort, uint16_t connectPort,
                           uint64_t nowMs) {
    if (serverAddress.empty() || clientPort == 0 || targetPort == 0 || connectPort == 0) {
        return;
    }

    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    if (now >= nextPruneMs_) {
        pruneLocked(now);
        nextPruneMs_ = now + kPruneIntervalMs;
    }

    if (entries_.size() >= kMaxPendingFlows) {
        pruneLocked(now);
        if (entries_.size() >= kMaxPendingFlows) {
            const auto oldest = std::min_element(
                entries_.begin(), entries_.end(),
                [](const auto& left, const auto& right) {
                    return left.second.expiresAtMs < right.second.expiresAtMs;
                });
            if (oldest != entries_.end()) entries_.erase(oldest);
        }
    }

    entries_[flowKey(serverAddress, clientPort)] = {
        {serverAddress, targetPort, connectPort}, now + kPendingFlowTtlMs
    };
}

std::optional<Target> FlowRegistry::claim(const std::string& peerAddress,
                                          uint16_t peerPort,
                                          uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);

    const auto it = entries_.find(flowKey(peerAddress, peerPort));
    if (it == entries_.end()) return std::nullopt;

    const bool live = it->second.expiresAtMs > now;
    Target target = it->second.target;
    entries_.erase(it);
    if (!live) return std::nullopt;
    return target;
}

size_t FlowRegistry::size(uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);
    return entries_.size();
}

void FlowRegistry::clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
}

void FlowRegistry::pruneLocked(uint64_t nowMs) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.expiresAtMs <= nowMs) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void DatagramRegistry::observe(const std::string& serverAddress,
                               uint16_t clientPort, uint64_t nowMs) {
    if (serverAddress.empty() || clientPort == 0) return;

    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    if (now >= nextPruneMs_) {
        pruneLocked(now);
        nextPruneMs_ = now + kPruneIntervalMs;
    }

    const std::string key = flowKey(serverAddress, clientPort);
    auto existing = entries_.find(key);
    if (existing != entries_.end()) {
        if (existing->second.expiresAtMs <= now) existing->second.pending = 0;
        existing->second.pending = std::min(existing->second.pending + 1,
                                            kMaxPendingDatagramsPerTuple);
        existing->second.expiresAtMs = now + kPendingFlowTtlMs;
        return;
    }

    if (entries_.size() >= kMaxPendingFlows) {
        pruneLocked(now);
        if (entries_.size() >= kMaxPendingFlows) {
            const auto oldest = std::min_element(
                entries_.begin(), entries_.end(),
                [](const auto& left, const auto& right) {
                    return left.second.expiresAtMs < right.second.expiresAtMs;
                });
            if (oldest != entries_.end()) entries_.erase(oldest);
        }
    }

    entries_[key] = {1, now + kPendingFlowTtlMs};
}

bool DatagramRegistry::claim(const std::string& peerAddress,
                             uint16_t peerPort, uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);

    const auto it = entries_.find(flowKey(peerAddress, peerPort));
    if (it == entries_.end()) return false;
    if (it->second.expiresAtMs <= now || it->second.pending == 0) {
        entries_.erase(it);
        return false;
    }

    if (--it->second.pending == 0) entries_.erase(it);
    return true;
}

size_t DatagramRegistry::size(uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);
    return entries_.size();
}

void DatagramRegistry::clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
}

void DatagramRegistry::pruneLocked(uint64_t nowMs) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.expiresAtMs <= nowMs) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void TcpFlowTable::add(Kind kind, const Address& server, uint16_t localPort,
                       uint64_t nowMs) {
    if (localPort == 0) return;
    const uint64_t now = clockMs(nowMs);
    const PeerKey key{server, localPort, (uint8_t)kind};

    std::lock_guard lock(mutex_);
    const auto existing = entries_.find(key);
    if (existing != entries_.end()) {
        existing->second = {now + kTcpFlowIdleMs, false};
        return;
    }
    if (entries_.size() >= kMaxTcpFlows) makeRoomLocked(now);
    entries_.emplace(key, Entry{now + kTcpFlowIdleMs, false});
}

bool TcpFlowTable::track(Kind kind, const Address& server, uint16_t localPort,
                         bool fin, bool rst, uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    const PeerKey key{server, localPort, (uint8_t)kind};

    std::lock_guard lock(mutex_);
    const auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    if (it->second.expiresAtMs <= now || rst) {
        const bool live = it->second.expiresAtMs > now;
        entries_.erase(it);
        return live;
    }

    if (fin) it->second.closing = true;
    it->second.expiresAtMs = now + (it->second.closing ? kTcpFlowClosingMs
                                                       : kTcpFlowIdleMs);
    return true;
}

void TcpFlowTable::remove(Kind kind, const Address& server, uint16_t localPort) {
    std::lock_guard lock(mutex_);
    entries_.erase(PeerKey{server, localPort, (uint8_t)kind});
}

size_t TcpFlowTable::size() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

void TcpFlowTable::clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    nextSweepMs_ = 0;
}

// Called with the table full. Expired entries go first (at most one full scan
// per second); only if the table is genuinely full of live flows is the
// least-recently-seen 1/16 evicted, which keeps the cost amortized O(1).
void TcpFlowTable::makeRoomLocked(uint64_t nowMs) {
    if (nowMs >= nextSweepMs_) {
        nextSweepMs_ = nowMs + kPruneIntervalMs;
        std::erase_if(entries_, [nowMs](const auto& item) {
            return item.second.expiresAtMs <= nowMs;
        });
        if (entries_.size() < kMaxTcpFlows) return;
    }

    std::vector<std::pair<uint64_t, PeerKey>> oldest;
    oldest.reserve(entries_.size());
    for (const auto& item : entries_) {
        oldest.emplace_back(item.second.expiresAtMs, item.first);
    }
    const size_t evict = std::max<size_t>(1, oldest.size() / 16);
    std::nth_element(oldest.begin(), oldest.begin() + (ptrdiff_t)(evict - 1),
                     oldest.end(),
                     [](const auto& left, const auto& right) {
                         return left.first < right.first;
                     });
    for (size_t i = 0; i < evict; ++i) entries_.erase(oldest[i].second);
}

// shortcut: classification is by port only. A foreign local program that dials
// the private connect port or sends from the relay port is indistinguishable
// here; the caller's TcpFlowTable check (SYN seen first) narrows it, and an
// owner-PID check on those SYNs is the upgrade if collisions are ever reported.
PacketRoute routePacket(bool outbound, uint16_t sourcePort,
                        uint16_t destinationPort, uint16_t targetPort,
                        uint16_t proxyPort, uint16_t connectPort) {
    if (outbound) {
        if (sourcePort == proxyPort) return PacketRoute::ReflectProxyToClient;
        if (destinationPort == connectPort) return PacketRoute::RedirectProxyToTarget;
        if (destinationPort == targetPort) return PacketRoute::ReflectClientToProxy;
        return PacketRoute::Pass;
    }

    if (sourcePort == targetPort) return PacketRoute::RedirectTargetToProxy;
    return PacketRoute::Pass;
}

DatagramRoute routeDatagram(bool outbound, uint16_t sourcePort,
                            uint16_t destinationPort, uint16_t dnsPort,
                            uint16_t proxyPort) {
    if (!outbound) return DatagramRoute::Pass;
    if (sourcePort == proxyPort) return DatagramRoute::ReflectProxyToClient;
    if (destinationPort == dnsPort) return DatagramRoute::ReflectDnsToProxy;
    return DatagramRoute::Pass;
}

} // namespace transparent
