#include "Test.hpp"

#include "RecoveryPolicy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

TEST(RecoveryPolicyRetriesTransientWinDivertErrorsOnly) {
    CHECK(recovery::shouldRetryWinDivertRead(ERROR_NO_SYSTEM_RESOURCES, 0));
    CHECK(recovery::shouldRetryWinDivertRead(ERROR_NO_SYSTEM_RESOURCES, 2));
    CHECK(!recovery::shouldRetryWinDivertRead(ERROR_NO_SYSTEM_RESOURCES, 3));
    CHECK(!recovery::shouldRetryWinDivertRead(ERROR_INVALID_HANDLE, 0));
}

TEST(RecoveryPolicyUsesBoundedBackoff) {
    CHECK_EQ(recovery::winDivertRetryDelayMs(0), 50U);
    CHECK_EQ(recovery::winDivertRetryDelayMs(1), 100U);
    CHECK_EQ(recovery::winDivertRetryDelayMs(2), 200U);
    CHECK_EQ(recovery::winDivertRetryDelayMs(20), 400U);

    CHECK_EQ(recovery::automaticRestartDelayMs(1), 1000U);
    CHECK_EQ(recovery::automaticRestartDelayMs(2), 2000U);
    CHECK_EQ(recovery::automaticRestartDelayMs(3), 4000U);
}

TEST(RecoveryPolicyStopsRestartLoopsInsideWindow) {
    recovery::RestartBudget budget(3, 1000);
    CHECK_EQ(budget.consume(100), 1U);
    CHECK_EQ(budget.consume(200), 2U);
    CHECK_EQ(budget.consume(300), 3U);
    CHECK_EQ(budget.consume(400), 0U);

    CHECK_EQ(budget.consume(1100), 3U);
    budget.reset();
    CHECK_EQ(budget.consume(1101), 1U);
}

TEST(WorkerHealthTripsOnSustainedFailuresAndStaysOpen) {
    recovery::WorkerHealth health;
    // A burst of failures inside a short blip is not enough...
    CHECK(!health.observe(-1, 1'000));
    CHECK(!health.observe(503, 1'100));
    CHECK(!health.observe(-1, 1'200));
    CHECK(!health.observe(401, 1'300));
    CHECK(!health.observe(-1, 1'400));
    CHECK(!health.observe(-1, 1'500));
    CHECK(!health.unavailable());
    // ...it has to persist for kWorkerMinStreakMs without a success.
    CHECK(health.observe(-1, 1'000 + recovery::kWorkerMinStreakMs));
    CHECK(health.unavailable());
    CHECK(health.observe(200, 40'000));
}

TEST(WorkerHealthResetsAfterSuccessOrQuietPeriod) {
    recovery::WorkerHealth health;
    for (uint64_t at = 100; at < 500; at += 100) CHECK(!health.observe(-1, at));
    CHECK(!health.observe(200, 600));                       // success clears the streak
    for (uint64_t at = 700; at < 1100; at += 100) CHECK(!health.observe(-1, at));
    // A long quiet gap starts a fresh streak instead of extending the old one.
    const uint64_t later = 1'000 + recovery::kWorkerFailureGapMs + 1;
    for (uint64_t i = 0; i < 4; ++i) CHECK(!health.observe(-1, later + i));
    CHECK(!health.unavailable());
    // 404 is a healthy answer (NXDOMAIN-style), not a failure.
    CHECK(!health.observe(404, later + 10));
    for (uint64_t i = 0; i < 4; ++i) CHECK(!health.observe(500, later + 20 + i));
    CHECK(!health.unavailable());
}

TEST(WorkerHealthTreatsRateLimitingAsBackoffNotFailure) {
    recovery::WorkerHealth health;
    // 429s never latch, however many arrive.
    for (uint64_t i = 0; i < 50; ++i) CHECK(!health.observe(429, 1'000 + i * 1'000));
    CHECK(!health.unavailable());

    recovery::WorkerHealth backoff;
    CHECK(!backoff.backingOff(0));
    CHECK(!backoff.observe(429, 10'000, 7));
    CHECK(backoff.backingOff(10'000));
    CHECK(backoff.backingOff(16'999));
    CHECK(!backoff.backingOff(17'000));

    // Default when Retry-After is absent, and a hostile value is capped.
    recovery::WorkerHealth defaults;
    defaults.observe(429, 0);
    CHECK(defaults.backingOff(recovery::kRateLimitDefaultBackoffMs - 1));
    CHECK(!defaults.backingOff(recovery::kRateLimitDefaultBackoffMs));
    recovery::WorkerHealth capped;
    capped.observe(429, 0, 86'400);
    CHECK(capped.backingOff(recovery::kRateLimitMaxBackoffMs - 1));
    CHECK(!capped.backingOff(recovery::kRateLimitMaxBackoffMs));
}
