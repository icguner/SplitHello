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

// A transport error, 401/403 or 5xx is a failure. HTTP 429 is not: the Worker
// is alive and merely asking us to slow down, so it starts a back-off instead.
// The Worker only latches as unavailable after kWorkerFailureThreshold failures
// with no success in between, each within kWorkerFailureGapMs of the previous,
// spread over at least kWorkerMinStreakMs - a burst of timeouts during a short
// network blip must not shut the engine down.
inline constexpr unsigned kWorkerFailureThreshold = 5;
inline constexpr uint64_t kWorkerFailureGapMs = 60'000;
inline constexpr uint64_t kWorkerMinStreakMs = 15'000;
inline constexpr uint64_t kRateLimitDefaultBackoffMs = 5'000;
inline constexpr uint64_t kRateLimitMaxBackoffMs = 30'000;

// Latches after a sustained run of Worker failures. A successful HTTP response
// clears the streak; an old failure cannot poison an otherwise healthy run.
class WorkerHealth {
public:
    // `retryAfterSeconds` is the Retry-After header of a 429 (0 = absent).
    bool observe(int httpStatus, uint64_t nowMs, unsigned retryAfterSeconds = 0);
    bool unavailable() const;
    // True while a 429 told us to hold off; callers should not hit the Worker.
    bool backingOff(uint64_t nowMs) const;

private:
    mutable std::mutex mutex_;
    unsigned failures_ = 0;
    uint64_t streakStartMs_ = 0;
    uint64_t lastFailureMs_ = 0;
    uint64_t backoffUntilMs_ = 0;
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
