#include "Test.hpp"

#include "RecoveryPolicy.hpp"

TEST(RecoveryPolicyUsesBoundedBackoff) {
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
