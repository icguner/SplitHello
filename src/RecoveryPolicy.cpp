#include "RecoveryPolicy.hpp"

#include <algorithm>

namespace recovery {

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
