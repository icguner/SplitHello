#pragma once

#include <cstdint>
#include <deque>
#include <mutex>

namespace recovery {

inline constexpr unsigned kMaxWinDivertReadRetries = 3;
inline constexpr uint64_t kRestartWindowMs = 10 * 60 * 1000;
inline constexpr unsigned kMaxAutomaticRestarts = 3;
inline constexpr int kWorkerUnavailableExitCode = 3;

bool shouldContinueDnsReceive(int error);
bool isTransientWinDivertReadError(uint32_t error);
bool shouldRetryWinDivertRead(uint32_t error, unsigned completedRetries);
unsigned winDivertRetryDelayMs(unsigned completedRetries);
unsigned automaticRestartDelayMs(unsigned attemptNumber);

// Latches after several nearby Worker failures. A successful HTTP response
// clears the streak; an old failure cannot poison an otherwise healthy run.
class WorkerHealth {
public:
    bool observe(int httpStatus, uint64_t nowMs);
    bool unavailable() const;

private:
    mutable std::mutex mutex_;
    unsigned failures_ = 0;
    uint64_t lastFailureMs_ = 0;
    bool unavailable_ = false;
};

// Sliding-window restart budget. `consume` returns a one-based attempt number,
// or zero when another automatic restart would create a crash loop.
class RestartBudget {
public:
    RestartBudget(unsigned maxAttempts = kMaxAutomaticRestarts,
                  uint64_t windowMs = kRestartWindowMs);

    unsigned consume(uint64_t nowMs);
    void reset();

private:
    void purge(uint64_t nowMs);

    unsigned maxAttempts_;
    uint64_t windowMs_;
    std::deque<uint64_t> attempts_;
};

} // namespace recovery
