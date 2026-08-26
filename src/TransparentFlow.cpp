#include "TransparentFlow.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>

namespace transparent {
namespace {

constexpr uint64_t kPendingFlowTtlMs = 15000;
constexpr size_t kMaxPendingFlows = 8192;
constexpr uint32_t kMaxPendingDatagramsPerTuple = 32;

uint64_t clockMs(uint64_t supplied) {
    return supplied == 0 ? GetTickCount64() : supplied;
}

std::string flowKey(const std::string& address, uint16_t port) {
    return address + "|" + std::to_string(port);
}

} // namespace

void FlowRegistry::observe(const std::string& serverAddress, uint16_t clientPort,
                           uint16_t targetPort, uint16_t connectPort,
                           uint64_t nowMs) {
    if (serverAddress.empty() || clientPort == 0 || targetPort == 0 || connectPort == 0) {
        return;
    }

    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);

    if (entries_.size() >= kMaxPendingFlows) {
        const auto oldest = std::min_element(
            entries_.begin(), entries_.end(),
            [](const auto& left, const auto& right) {
                return left.second.expiresAtMs < right.second.expiresAtMs;
            });
        if (oldest != entries_.end()) entries_.erase(oldest);
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
    pruneLocked(now);

    const auto it = entries_.find(flowKey(peerAddress, peerPort));
    if (it == entries_.end()) return std::nullopt;

    Target target = it->second.target;
    entries_.erase(it);
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
    pruneLocked(now);

    const std::string key = flowKey(serverAddress, clientPort);
    auto existing = entries_.find(key);
    if (existing != entries_.end()) {
        existing->second.pending = std::min(existing->second.pending + 1,
                                            kMaxPendingDatagramsPerTuple);
        existing->second.expiresAtMs = now + kPendingFlowTtlMs;
        return;
    }

    if (entries_.size() >= kMaxPendingFlows) {
        const auto oldest = std::min_element(
            entries_.begin(), entries_.end(),
            [](const auto& left, const auto& right) {
                return left.second.expiresAtMs < right.second.expiresAtMs;
            });
        if (oldest != entries_.end()) entries_.erase(oldest);
    }

    entries_[key] = {1, now + kPendingFlowTtlMs};
}

bool DatagramRegistry::claim(const std::string& peerAddress,
                             uint16_t peerPort, uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);

    const auto it = entries_.find(flowKey(peerAddress, peerPort));
    if (it == entries_.end() || it->second.pending == 0) return false;

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
