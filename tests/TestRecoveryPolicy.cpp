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

TEST(WorkerHealthTripsOnNearbyFailuresAndStaysOpen) {
    recovery::WorkerHealth health;
    CHECK(!health.observe(-1, 100));
    CHECK(!health.observe(503, 200));
    CHECK(health.observe(-1, 300));
    CHECK(health.unavailable());
    CHECK(health.observe(200, 400));
}

TEST(WorkerHealthResetsAfterSuccessOrQuietPeriod) {
    recovery::WorkerHealth health;
    CHECK(!health.observe(-1, 100));
    CHECK(!health.observe(200, 200));
    CHECK(!health.observe(-1, 300));
    CHECK(!health.observe(-1, 31'000));
    CHECK(!health.unavailable());
    CHECK(!health.observe(404, 31'100));
    CHECK(!health.observe(401, 31'200));
    CHECK(!health.observe(429, 31'300));
    CHECK(health.observe(403, 31'400));
}
