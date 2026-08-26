#include "Test.hpp"

#include "Json.hpp"
#include "Telemetry.hpp"

#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

std::string telemetryTestPath() {
    return (std::filesystem::temp_directory_path() /
            ("splithello-telemetry-" + std::to_string(GetCurrentProcessId()) +
             "-" + std::to_string(GetTickCount64()) + ".db")).string();
}

void removeDatabase(const std::string& path) {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path + "-wal", ignored);
    std::filesystem::remove(path + "-shm", ignored);
}

telemetry::ProbeRecord makeRecord(
    std::string host,
    std::vector<diagnosis::Attempt> attempts,
    bool success,
    std::string remembered = {}) {
    telemetry::ProbeRecord record;
    record.networkId = "test-network";
    record.host = std::move(host);
    record.rememberedProfile = std::move(remembered);
    record.verdict = diagnosis::infer(attempts);
    record.attempts = std::move(attempts);
    record.totalElapsedMs = 123;
    record.success = success;
    return record;
}

} // namespace

TEST(TelemetryPersistsDashboardEvidence) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    {
        telemetry::Store store(path, 30, 100, 64);
        CHECK(store.start());
        store.record(makeRecord(
            "healthy.example",
            {{"none", diagnosis::ProbeSignal::ServerHello, 42}}, true));
        store.record(makeRecord(
            "blocked.example",
            {{"none", diagnosis::ProbeSignal::Timeout, 3000},
             {"sni-mid", diagnosis::ProbeSignal::ServerHello, 67}}, true));
        store.record(makeRecord(
            "offline.example",
            {{"none", diagnosis::ProbeSignal::Reset, 8},
             {"sni-mid", diagnosis::ProbeSignal::Timeout, 3000}}, false));
        store.stop();
        CHECK_EQ(store.droppedRecords(), static_cast<size_t>(0));
    }

    const std::string snapshot = telemetry::Store::dashboardJson(path, 30);
    CHECK(json::getBool(snapshot, "ready"));
    const std::string summary = json::getRaw(snapshot, "summary");
    CHECK_EQ(json::getInt(summary, "total"), 3LL);
    CHECK_EQ(json::getInt(summary, "bypassed"), 1LL);
    CHECK_EQ(json::getInt(summary, "normal"), 1LL);
    CHECK_EQ(json::getInt(summary, "unresolved"), 1LL);
    CHECK(snapshot.find("blocked.example") != std::string::npos);
    CHECK(snapshot.find("\"signal\":\"timeout\"") != std::string::npos);
    CHECK(snapshot.find("\"winner\":\"sni-mid\"") != std::string::npos);

    removeDatabase(path);
}

TEST(TelemetryMissingDatabaseReturnsSafeEmptySnapshot) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);
    const std::string snapshot = telemetry::Store::dashboardJson(path, 7);
    CHECK(!json::getBool(snapshot, "ready"));
    CHECK_EQ(json::getInt(snapshot, "windowDays"), 7LL);
    CHECK_EQ(json::getInt(json::getRaw(snapshot, "summary"), "total"), 0LL);
}
