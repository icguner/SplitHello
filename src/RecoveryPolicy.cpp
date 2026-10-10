#include "RecoveryPolicy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

#include <algorithm>

namespace recovery {

bool shouldContinueDnsReceive(int error) {
    return error == WSAEMSGSIZE || error == WSAETIMEDOUT ||
           error == WSAEWOULDBLOCK || error == WSAECONNRESET;
}

bool isTransientWinDivertReadError(uint32_t error) {
    switch (error) {
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_NO_SYSTEM_RESOURCES:
    case ERROR_WORKING_SET_QUOTA:
    case ERROR_COMMITMENT_LIMIT:
    case ERROR_NOT_ENOUGH_QUOTA:
        return true;
    default:
        return false;
    }
}

bool shouldRetryWinDivertRead(uint32_t error, unsigned completedRetries) {
    return isTransientWinDivertReadError(error) &&
        completedRetries < kMaxWinDivertReadRetries;
}

unsigned winDivertRetryDelayMs(unsigned completedRetries) {
    constexpr unsigned kInitialDelayMs = 50;
    constexpr unsigned kMaximumDelayMs = 500;
    const unsigned shift = std::min(completedRetries, 3U);
    return std::min(kInitialDelayMs << shift, kMaximumDelayMs);
}

unsigned automaticRestartDelayMs(unsigned attemptNumber) {
    constexpr unsigned kInitialDelayMs = 1000;
    constexpr unsigned kMaximumDelayMs = 8000;
    if (attemptNumber == 0) return 0;
    const unsigned shift = std::min(attemptNumber - 1, 3U);
    return std::min(kInitialDelayMs << shift, kMaximumDelayMs);
}

bool WorkerHealth::observe(int httpStatus, uint64_t nowMs, unsigned retryAfterSeconds) {
    std::lock_guard lock(mutex_);
    if (unavailable_) return true;

    if (httpStatus == 429) {
        // Alive but rate limiting us: neither a failure nor proof of recovery.
        const uint64_t requested = retryAfterSeconds != 0
            ? (uint64_t)retryAfterSeconds * 1000 : kRateLimitDefaultBackoffMs;
        backoffUntilMs_ = std::max(backoffUntilMs_,
                                   nowMs + std::min(requested, kRateLimitMaxBackoffMs));
        return false;
    }

    const bool failed = httpStatus < 0 || httpStatus == 401 ||
        httpStatus == 403 || httpStatus >= 500;
    if (!failed) {
        failures_ = 0;
        return false;
    }
    if (failures_ == 0 || nowMs - lastFailureMs_ > kWorkerFailureGapMs) {
        failures_ = 0;
        streakStartMs_ = nowMs;
    }
    lastFailureMs_ = nowMs;
    ++failures_;
    unavailable_ = failures_ >= kWorkerFailureThreshold &&
                   nowMs - streakStartMs_ >= kWorkerMinStreakMs;
    return unavailable_;
}

bool WorkerHealth::unavailable() const {
    std::lock_guard lock(mutex_);
    return unavailable_;
}

bool WorkerHealth::backingOff(uint64_t nowMs) const {
    std::lock_guard lock(mutex_);
    return nowMs < backoffUntilMs_;
}

RestartBudget::RestartBudget(unsigned maxAttempts, uint64_t windowMs)
    : maxAttempts_(std::max(maxAttempts, 1U)),
      windowMs_(std::max<uint64_t>(windowMs, 1)) {}

unsigned RestartBudget::consume(uint64_t nowMs) {
    purge(nowMs);
    if (attempts_.size() >= maxAttempts_) return 0;
    attempts_.push_back(nowMs);
    return static_cast<unsigned>(attempts_.size());
}

void RestartBudget::reset() {
    attempts_.clear();
}

void RestartBudget::purge(uint64_t nowMs) {
    while (!attempts_.empty() && nowMs - attempts_.front() >= windowMs_) {
        attempts_.pop_front();
    }
}

} // namespace recovery
