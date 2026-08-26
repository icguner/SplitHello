#include "RecoveryPolicy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>

namespace recovery {

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
