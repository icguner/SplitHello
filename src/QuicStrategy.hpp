#pragma once

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

private:
    struct Flow {
        uint64_t startedMs = 0;
        uint64_t touchedMs = 0;
        bool answered = false;
    };

    std::string flowKey(const std::string& server, uint16_t localPort) const;
    void purgeIfDue(uint64_t nowMs);

    uint64_t responseTimeoutMs_;
    uint64_t fallbackMs_;
    uint64_t nextPurgeAtMs_ = 0;
    std::mutex mutex_;
    std::unordered_map<std::string, Flow> flows_;
    std::unordered_map<std::string, uint64_t> blockedUntil_;
};

} // namespace quic_strategy
