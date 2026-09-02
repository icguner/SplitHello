#include "Test.hpp"

#include "Json.hpp"
#include "Telemetry.hpp"

#include <sqlite3.h>

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

TEST(TelemetryCountsOnlyVerifiedDifferentialsAsBypasses) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    {
        telemetry::Store store(path, 30, 100, 64);
        CHECK(store.start());
        // Verified: baseline failed, fragmented hello worked.
        store.record(makeRecord(
            "blocked.example",
            {{"none", diagnosis::ProbeSignal::Timeout, 3000},
             {"sni-mid", diagnosis::ProbeSignal::ServerHello, 67}}, true));
        // Cache hit: remembered winner reused, no baseline in this connection.
        store.record(makeRecord(
            "blocked.example",
            {{"sni-mid", diagnosis::ProbeSignal::ServerHello, 40}}, true, "sni-mid"));
        store.record(makeRecord(
            "blocked.example",
            {{"sni-mid", diagnosis::ProbeSignal::ServerHello, 41}}, true, "sni-mid"));
        store.stop();
    }

    const std::string snapshot = telemetry::Store::dashboardJson(path, 30);
    const std::string summary = json::getRaw(snapshot, "summary");
    CHECK_EQ(json::getInt(summary, "total"), 3LL);
    CHECK_EQ(json::getInt(summary, "bypassed"), 1LL);
    CHECK_EQ(json::getInt(summary, "learned"), 2LL);
    CHECK_EQ(json::getInt(summary, "cacheHits"), 2LL);
    CHECK(snapshot.find("\"key\":\"learned-profile\",\"count\":2") != std::string::npos);

    removeDatabase(path);
}

TEST(TelemetryMigrationReclassifiesLegacyInterferenceRows) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    {
        telemetry::Store store(path, 30, 100, 64);
        CHECK(store.start());
        // Genuinely blocked: no healthy baseline anywhere near it.
        store.record(makeRecord(
            "blocked.example",
            {{"none", diagnosis::ProbeSignal::Timeout, 3000},
             {"sni-mid", diagnosis::ProbeSignal::ServerHello, 67}}, true));
        // A hiccup: the same host had a healthy untouched baseline moments ago.
        store.record(makeRecord(
            "flaky.example",
            {{"none", diagnosis::ProbeSignal::ServerHello, 30}}, true));
        store.record(makeRecord(
            "flaky.example",
            {{"none", diagnosis::ProbeSignal::Timeout, 3000},
             {"record-1", diagnosis::ProbeSignal::ServerHello, 31}}, true));
        // Cache hit.
        store.record(makeRecord(
            "blocked.example",
            {{"sni-mid", diagnosis::ProbeSignal::ServerHello, 40}}, true, "sni-mid"));
        store.stop();
    }

    // Rewrite the rows the way schema 1 stored them.
    {
        sqlite3* database = nullptr;
        CHECK(sqlite3_open(path.c_str(), &database) == SQLITE_OK);
        CHECK(sqlite3_exec(database,
                           "UPDATE probe_events SET diagnosis_kind='sni-interference-likely'"
                           " WHERE diagnosis_kind IN ('learned-profile','transient-failure')"
                           " OR (diagnosis_kind='sni-interference-likely');"
                           "PRAGMA user_version=1;",
                           nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(database);
    }
    {
        const std::string before = telemetry::Store::dashboardJson(path, 30);
        CHECK_EQ(json::getInt(json::getRaw(before, "summary"), "bypassed"), 3LL);
    }

    // Opening the engine-side store performs the one-time migration.
    {
        telemetry::Store store(path, 30, 100, 64);
        CHECK(store.start());
        store.stop();
    }

    const std::string snapshot = telemetry::Store::dashboardJson(path, 30);
    const std::string summary = json::getRaw(snapshot, "summary");
    CHECK_EQ(json::getInt(summary, "total"), 4LL);
    CHECK_EQ(json::getInt(summary, "bypassed"), 1LL);
    CHECK_EQ(json::getInt(summary, "learned"), 2LL);
    CHECK(snapshot.find("\"key\":\"transient-failure\",\"count\":1") != std::string::npos);
    CHECK(snapshot.find("\"key\":\"learned-profile\",\"count\":1") != std::string::npos);

    removeDatabase(path);
}
