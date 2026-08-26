#include "QuicStrategy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>

namespace quic_strategy {

namespace {

constexpr uint32_t kQuicV2 = 0x6B3343CF;
constexpr size_t kMinimumInitialSize = 1200;

uint32_t readU32(const uint8_t* value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

} // namespace

bool looksLikeInitial(const uint8_t* payload, size_t length) {
    if (!payload || length < kMinimumInitialSize) return false;
    const uint8_t first = payload[0];
    if ((first & 0xC0) != 0xC0) return false; // long header + fixed bit

    const uint32_t version = readU32(payload + 1);
    if (version == 0) return false; // version negotiation, not Initial

    const uint8_t longPacketType = first & 0x30;
    return version == kQuicV2 ? longPacketType == 0x10
                              : longPacketType == 0x00;
}

std::vector<uint8_t> buildPrimePayload() {
    std::vector<uint8_t> payload(32);
    if (BCryptGenRandom(nullptr, payload.data(), (ULONG)payload.size(),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 29U));
        }
    }
    // QUIC's fixed bit is clear, so a compliant server ignores this datagram.
    payload[0] &= 0x3F;
    return payload;
}

AdaptiveRegistry::AdaptiveRegistry(uint64_t responseTimeoutMs,
                                   uint64_t fallbackMs)
    : responseTimeoutMs_(std::max<uint64_t>(responseTimeoutMs, 1))
    , fallbackMs_(std::max<uint64_t>(fallbackMs, responseTimeoutMs_)) {}

std::string AdaptiveRegistry::flowKey(const std::string& server,
                                      uint16_t localPort) const {
    return server + "|" + std::to_string(localPort);
}

void AdaptiveRegistry::purge(uint64_t nowMs) {
    for (auto it = flows_.begin(); it != flows_.end();) {
        if (nowMs - it->second.touchedMs > fallbackMs_) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = blockedUntil_.begin(); it != blockedUntil_.end();) {
        if (it->second <= nowMs) {
            it = blockedUntil_.erase(it);
        } else {
            ++it;
        }
    }
}

Decision AdaptiveRegistry::outbound(const std::string& server,
                                    uint16_t localPort, bool initial,
                                    uint64_t nowMs) {
    std::lock_guard lock(mutex_);
    purge(nowMs);

    const auto blocked = blockedUntil_.find(server);
    if (blocked != blockedUntil_.end() && blocked->second > nowMs) {
        return Decision::Drop;
    }

    const std::string key = flowKey(server, localPort);
    auto [it, inserted] = flows_.try_emplace(key, Flow{nowMs, nowMs, false});
    Flow& flow = it->second;
    flow.touchedMs = nowMs;

    if (inserted) return initial ? Decision::PrimeAndPass : Decision::Pass;
    if (flow.answered) return Decision::Pass;
    if (nowMs - flow.startedMs >= responseTimeoutMs_) {
        blockedUntil_[server] = nowMs + fallbackMs_;
        return Decision::Drop;
    }
    return Decision::Pass;
}

void AdaptiveRegistry::inbound(const std::string& server, uint16_t localPort,
                               uint64_t nowMs) {
    std::lock_guard lock(mutex_);
    purge(nowMs);
    const auto it = flows_.find(flowKey(server, localPort));
    if (it == flows_.end()) return;
    it->second.answered = true;
    it->second.touchedMs = nowMs;
    blockedUntil_.erase(server);
}

void AdaptiveRegistry::clear() {
    std::lock_guard lock(mutex_);
    flows_.clear();
    blockedUntil_.clear();
}

} // namespace quic_strategy
