#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace quic_strategy {

// "Adaptive" primes the first QUIC Initial, keeps QUIC when the peer answers,
// and temporarily drops an unresponsive target so the client falls back to TCP.
enum class Mode {
    Block,
    Adaptive,
    Allow,
};

enum class Decision {
    Pass,
    PrimeAndPass,
    Drop,
};

bool looksLikeInitial(const uint8_t* payload, size_t length);
std::vector<uint8_t> buildPrimePayload();

class AdaptiveRegistry {
public:
    explicit AdaptiveRegistry(uint64_t responseTimeoutMs = 900,
                              uint64_t fallbackMs = 5 * 60 * 1000);

    Decision outbound(const std::string& server, uint16_t localPort,
                      bool initial, uint64_t nowMs);
    void inbound(const std::string& server, uint16_t localPort, uint64_t nowMs);
    void clear();

    // Lock-free pre-checks for the datagram hot path, so a caller can skip
    // building the server text and taking the mutex when the call would be a
    // no-op: only Initials create state, and only an unanswered flow or a
    // blocked server can change what a datagram needs.
    bool needsOutbound(bool initial) const noexcept {
        return initial || blockedServers_.load(std::memory_order_relaxed) != 0;
    }
    bool needsInbound() const noexcept {
        return unansweredFlows_.load(std::memory_order_relaxed) != 0;
    }

private:
    struct Flow {
        uint64_t startedMs = 0;
        uint64_t touchedMs = 0;
        bool answered = false;
    };

    std::string flowKey(const std::string& server, uint16_t localPort) const;
    void purgeIfDue(uint64_t nowMs);
    void publishBlockedLocked() {
        blockedServers_.store(blockedUntil_.size(), std::memory_order_relaxed);
    }

    uint64_t responseTimeoutMs_;
    uint64_t fallbackMs_;
    uint64_t nextPurgeAtMs_ = 0;
    std::atomic<size_t> unansweredFlows_{0};
    std::atomic<size_t> blockedServers_{0};
    std::mutex mutex_;
    std::unordered_map<std::string, Flow> flows_;
    std::unordered_map<std::string, uint64_t> blockedUntil_;
};

} // namespace quic_strategy
