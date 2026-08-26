#include "Test.hpp"

#include "LiveStats.hpp"

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::wstring liveStatsTestName() {
    return L"Local\\SplitHello-Test-Live-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
}

const live_stats::ProfileSnapshot* findProfile(
    const live_stats::Snapshot& snapshot, const std::string& name) {
    for (const auto& profile : snapshot.profiles) {
        if (profile.name == name) return &profile;
    }
    return nullptr;
}

} // namespace

TEST(LiveStatsTracksFlowLifetimeAndProfileDecisions) {
    const std::wstring mappingName = liveStatsTestName();
    CHECK(!live_stats::read(mappingName).online);

    {
        live_stats::Publisher publisher(mappingName);
        CHECK(publisher.available());

        {
            live_stats::Flow flow;
            flow.begin(&publisher);
            flow.setProfile("sni-mid");

            live_stats::Snapshot active = live_stats::read(mappingName);
            CHECK(active.online);
            CHECK_EQ(active.activeFlows, 1U);
            CHECK_EQ(active.pendingFlows, 0U);
            CHECK_EQ(active.openedFlows, 1U);
            const auto* activeProfile = findProfile(active, "sni-mid");
            CHECK(activeProfile != nullptr);
            CHECK_EQ(activeProfile->active, 1U);

            flow.decision(true, true);
            flow.decision(false, false); // one flow produces at most one decision
            const live_stats::Snapshot decided = live_stats::read(mappingName);
            CHECK_EQ(decided.decisions, 1U);
            CHECK_EQ(decided.successfulDecisions, 1U);
            CHECK_EQ(decided.bypassedDecisions, 1U);
            CHECK_EQ(findProfile(decided, "sni-mid")->decisions, 1U);
        }

        const live_stats::Snapshot closed = live_stats::read(mappingName);
        CHECK_EQ(closed.activeFlows, 0U);
        CHECK_EQ(closed.decisions, 1U);
        CHECK(live_stats::toJson(closed).find("\"messageType\":\"live\"") !=
              std::string::npos);
    }

    CHECK(!live_stats::read(mappingName).online);
}

TEST(LiveStatsKeepsUnclassifiedFlowsVisibleAsPending) {
    const std::wstring mappingName = liveStatsTestName();
    live_stats::Publisher publisher(mappingName);
    live_stats::Flow flow;
    flow.begin(&publisher);

    const live_stats::Snapshot snapshot = live_stats::read(mappingName);
    CHECK_EQ(snapshot.activeFlows, 1U);
    CHECK_EQ(snapshot.pendingFlows, 1U);

    flow.decision(false, false);
    const live_stats::Snapshot failed = live_stats::read(mappingName);
    CHECK_EQ(failed.unresolvedDecisions, 1U);
}
