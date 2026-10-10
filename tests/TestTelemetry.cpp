#include "Test.hpp"

#include "FileUtil.hpp"
#include "Json.hpp"
#include "Telemetry.hpp"

#include <sqlite3.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>

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

int64_t scalar(const std::string& path, const char* sql) {
    sqlite3* database = nullptr;
    if (sqlite3_open(path.c_str(), &database) != SQLITE_OK) return -1;
    sqlite3_stmt* statement = nullptr;
    int64_t value = -1;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, nullptr) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW) {
        value = sqlite3_column_int64(statement, 0);
    }
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return value;
}

telemetry::ProbeRecord blockedRecord(const std::string& host) {
    return makeRecord(
        host,
        {{"none", diagnosis::ProbeSignal::Timeout, 3000},
         {"sni-mid", diagnosis::ProbeSignal::ServerHello, 67}}, true);
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

TEST(TelemetrySeparatesUnreproducedSuspicionFromLearnedProfiles) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    {
        telemetry::Store store(path, 30, 100, 64);
        CHECK(store.start());
        telemetry::ProbeRecord suspected = blockedRecord("first-strike.example");
        suspected.verdict.kind = diagnosis::Kind::InterferenceSuspected;
        store.record(std::move(suspected));
        store.record(makeRecord(
            "blocked.example",
            {{"sni-mid", diagnosis::ProbeSignal::ServerHello, 40}}, true, "sni-mid"));
        store.stop();
    }

    const std::string snapshot = telemetry::Store::dashboardJson(path, 30);
    const std::string summary = json::getRaw(snapshot, "summary");
    CHECK_EQ(json::getInt(summary, "total"), 2LL);
    CHECK_EQ(json::getInt(summary, "bypassed"), 0LL);
    CHECK_EQ(json::getInt(summary, "learned"), 1LL);
    CHECK_EQ(json::getInt(summary, "suspected"), 1LL);
    const telemetry::DashboardData data = telemetry::Store::dashboardSnapshot(path, 30);
    CHECK_EQ(data.suspected, (int64_t)1);
    CHECK_EQ(data.daily.size(), (size_t)1);
    CHECK_EQ(data.daily[0].suspected, (int64_t)1);
    CHECK_EQ(data.daily[0].learned, (int64_t)1);

    removeDatabase(path);
}

TEST(TelemetryStartStopCyclesNeverHangOrLoseQueuedRecords) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    telemetry::Store store(path, 30, 5000, 64);
    for (int cycle = 0; cycle < 25; ++cycle) {
        CHECK(store.start());
        store.record(blockedRecord("cycle.example"));
        store.record(blockedRecord("cycle.example"));
        store.stop();
    }
    CHECK_EQ(store.droppedRecords(), static_cast<size_t>(0));
    CHECK_EQ(scalar(path, "SELECT COUNT(*) FROM probe_events;"), 50LL);

    removeDatabase(path);
}

TEST(TelemetryStopRacingAProducerNeitherHangsNorCrashes) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    telemetry::Store store(path, 30, 5000, 64);
    std::atomic<bool> run{true};
    std::thread producer([&]() {
        while (run) store.record(blockedRecord("race.example"));
    });
    for (int cycle = 0; cycle < 15; ++cycle) {
        CHECK(store.start());
        Sleep(3);
        store.stop();
    }
    run = false;
    producer.join();

    // Surviving every stop/start under load is the point; the file stays valid.
    CHECK(scalar(path, "SELECT COUNT(*) FROM probe_events;") >= 0);
    removeDatabase(path);
}

TEST(TelemetryStartAfterAFailedWriterDoesNotTerminate) {
    // A directory cannot be opened as a database: the writer gives up by itself
    // and leaves a joinable thread behind.
    const std::string path = (std::filesystem::temp_directory_path()).string();
    telemetry::Store store(path, 30, 100, 64);
    for (int attempt = 0; attempt < 3; ++attempt) {
        store.start();
        Sleep(100);
    }
    store.stop();
}

TEST(TelemetryQueueOverflowIsCountedNotSilentlyLost) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    constexpr int kSent = 2000;
    size_t dropped = 0;
    {
        telemetry::Store store(path, 30, 5000, 64);
        CHECK(store.start());
        for (int i = 0; i < kSent; ++i) store.record(blockedRecord("flood.example"));
        store.stop();
        dropped = store.droppedRecords();
    }

    const int64_t written = scalar(path, "SELECT COUNT(*) FROM probe_events;");
    CHECK(dropped > 0);
    CHECK(written > 0);
    CHECK_EQ(written + static_cast<int64_t>(dropped), static_cast<int64_t>(kSent));

    removeDatabase(path);
}

TEST(TelemetryPruneCascadesToAttemptsAndKeepsTheNewestEvents) {
    const std::string path = telemetryTestPath();
    removeDatabase(path);

    {
        telemetry::Store store(path, 30, 100, 4096);
        CHECK(store.start());
        for (int i = 0; i < 150; ++i) {
            store.record(blockedRecord("host-" + std::to_string(i) + ".example"));
        }
        store.stop();
        CHECK_EQ(store.droppedRecords(), static_cast<size_t>(0));
    }

    CHECK_EQ(scalar(path, "SELECT COUNT(*) FROM probe_events;"), 100LL);
    CHECK_EQ(scalar(path, "SELECT COUNT(*) FROM probe_attempts;"), 200LL);
    CHECK_EQ(scalar(path,
        "SELECT COUNT(*) FROM probe_attempts"
        " WHERE event_id NOT IN (SELECT id FROM probe_events);"), 0LL);
    CHECK_EQ(scalar(path, "SELECT COUNT(*) FROM probe_events WHERE host='host-149.example';"), 1LL);
    CHECK_EQ(scalar(path, "SELECT COUNT(*) FROM probe_events WHERE host='host-0.example';"), 0LL);

    removeDatabase(path);
}

TEST(TelemetryAndFileUtilHandleNonAsciiPaths) {
    // UTF-8 bytes for a Turkish u-umlaut in the file name.
    const std::string path = std::filesystem::temp_directory_path().string() +
        "\\splithello-t\xC3\xBC" "rk-" + std::to_string(GetCurrentProcessId()) + ".db";
    const auto cleanup = [&]() {
        std::error_code ignored;
        for (const char* suffix : {"", "-wal", "-shm", ".txt"}) {
            std::filesystem::remove(std::filesystem::path(fileutil::widen(path + suffix)), ignored);
        }
    };
    cleanup();

    {
        telemetry::Store store(path, 30, 100, 64);
        CHECK(store.start());
        store.record(blockedRecord("unicode.example"));
        store.stop();
    }
    CHECK(fileutil::exists(path));
    const std::string snapshot = telemetry::Store::dashboardJson(path, 30);
    CHECK(json::getBool(snapshot, "ready"));
    CHECK_EQ(json::getInt(json::getRaw(snapshot, "summary"), "total"), 1LL);

    const std::string text = path + ".txt";
    CHECK(fileutil::writeAtomic(text, "hello"));
    std::string read;
    CHECK(fileutil::readAll(text, read));
    CHECK_EQ(read, std::string("hello"));
    CHECK(!fileutil::readAll(path + ".missing", read));

    cleanup();
}
