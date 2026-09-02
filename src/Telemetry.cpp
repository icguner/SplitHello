#include "Telemetry.hpp"

#include "Json.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iterator>
#include <sstream>

namespace telemetry {
namespace {

constexpr size_t kWriteBatchSize = 64;

int64_t unixSeconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

class Statement {
public:
    Statement(sqlite3* database, const char* sql) {
        if (sqlite3_prepare_v2(database, sql, -1, &value_, nullptr) != SQLITE_OK) {
            value_ = nullptr;
        }
    }

    ~Statement() {
        if (value_) sqlite3_finalize(value_);
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    explicit operator bool() const { return value_ != nullptr; }
    sqlite3_stmt* get() const { return value_; }

    void reset() const {
        sqlite3_reset(value_);
        sqlite3_clear_bindings(value_);
    }

private:
    sqlite3_stmt* value_ = nullptr;
};

bool execute(sqlite3* database, const char* sql) {
    char* message = nullptr;
    const int result = sqlite3_exec(database, sql, nullptr, nullptr, &message);
    if (result == SQLITE_OK) return true;
    spdlog::error("Telemetri SQLite hatasi: {}",
                  message ? message : sqlite3_errmsg(database));
    sqlite3_free(message);
    return false;
}

int schemaVersion(sqlite3* database) {
    Statement statement(database, "PRAGMA user_version;");
    if (!statement || sqlite3_step(statement.get()) != SQLITE_ROW) return 0;
    return sqlite3_column_int(statement.get(), 0);
}

// Schema 1 recorded every reuse of a remembered profile as
// "sni-interference-likely" although no baseline had been run, and it had
// no transient class at all. Reclassify the history once so the panel stops
// presenting cache hits and network hiccups as interference evidence.
bool migrateDatabase(sqlite3* database) {
    if (schemaVersion(database) >= 2) return true;
    if (!execute(database, "BEGIN;")) return false;
    const bool ok =
        execute(database,
            "UPDATE probe_events SET diagnosis_kind='learned-profile'"
            " WHERE diagnosis_kind='sni-interference-likely'"
            " AND baseline_signal IS NULL;") &&
        execute(database,
            "UPDATE probe_events SET diagnosis_kind='transient-failure', confidence=70"
            " WHERE diagnosis_kind='sni-interference-likely'"
            " AND baseline_signal<>'server-hello'"
            " AND EXISTS (SELECT 1 FROM probe_events AS healthy"
            "  WHERE healthy.network_id=probe_events.network_id"
            "  AND healthy.host=probe_events.host"
            "  AND healthy.baseline_signal='server-hello'"
            "  AND healthy.occurred_at BETWEEN probe_events.occurred_at-900"
            "  AND probe_events.occurred_at+900);") &&
        execute(database, "PRAGMA user_version=2;");
    execute(database, ok ? "COMMIT;" : "ROLLBACK;");
    return ok;
}

bool initializeDatabase(sqlite3* database) {
    sqlite3_busy_timeout(database, 2000);
    return execute(database, "PRAGMA journal_mode=WAL;") &&
        execute(database, "PRAGMA synchronous=NORMAL;") &&
        execute(database, "PRAGMA foreign_keys=ON;") &&
        execute(database, "PRAGMA wal_autocheckpoint=1000;") &&
        execute(database,
            "CREATE TABLE IF NOT EXISTS probe_events ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " occurred_at INTEGER NOT NULL,"
            " network_id TEXT NOT NULL,"
            " host TEXT NOT NULL,"
            " baseline_signal TEXT,"
            " diagnosis_kind TEXT NOT NULL,"
            " confidence INTEGER NOT NULL,"
            " winning_profile TEXT,"
            " remembered_profile TEXT,"
            " success INTEGER NOT NULL,"
            " forced INTEGER NOT NULL,"
            " attempt_count INTEGER NOT NULL,"
            " total_elapsed_ms INTEGER NOT NULL,"
            " cache_hit INTEGER NOT NULL"
            ");") &&
        execute(database,
            "CREATE TABLE IF NOT EXISTS probe_attempts ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " event_id INTEGER NOT NULL REFERENCES probe_events(id) ON DELETE CASCADE,"
            " ordinal INTEGER NOT NULL,"
            " profile TEXT NOT NULL,"
            " signal TEXT NOT NULL,"
            " elapsed_ms INTEGER NOT NULL"
            ");") &&
        execute(database,
            "CREATE INDEX IF NOT EXISTS idx_probe_events_time "
            "ON probe_events(occurred_at DESC);") &&
        execute(database,
            "CREATE INDEX IF NOT EXISTS idx_probe_events_host "
            "ON probe_events(network_id, host, occurred_at DESC);") &&
        execute(database,
            "CREATE INDEX IF NOT EXISTS idx_probe_attempts_event "
            "ON probe_attempts(event_id, ordinal);") &&
        migrateDatabase(database);
}

void bindText(sqlite3_stmt* statement, int index, const std::string& value) {
    sqlite3_bind_text(statement, index, value.c_str(),
                      static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

std::string columnText(sqlite3_stmt* statement, int column) {
    const unsigned char* value = sqlite3_column_text(statement, column);
    return value ? reinterpret_cast<const char*>(value) : std::string{};
}

bool insertRecord(sqlite3* database, const Statement& eventInsert,
                  const Statement& attemptInsert, const ProbeRecord& record) {
    sqlite3_stmt* event = eventInsert.get();
    eventInsert.reset();

    const diagnosis::Attempt* baseline = nullptr;
    for (const diagnosis::Attempt& attempt : record.attempts) {
        if (attempt.profile == "none") {
            baseline = &attempt;
            break;
        }
    }

    sqlite3_bind_int64(event, 1, record.occurredAt);
    bindText(event, 2, record.networkId);
    bindText(event, 3, record.host);
    if (baseline) bindText(event, 4, diagnosis::signalName(baseline->signal));
    else sqlite3_bind_null(event, 4);
    bindText(event, 5, diagnosis::name(record.verdict.kind));
    sqlite3_bind_int(event, 6, static_cast<int>(record.verdict.confidence));
    if (record.verdict.winningProfile.empty()) sqlite3_bind_null(event, 7);
    else bindText(event, 7, record.verdict.winningProfile);
    if (record.rememberedProfile.empty()) sqlite3_bind_null(event, 8);
    else bindText(event, 8, record.rememberedProfile);
    sqlite3_bind_int(event, 9, record.success ? 1 : 0);
    sqlite3_bind_int(event, 10, record.forced ? 1 : 0);
    sqlite3_bind_int(event, 11, static_cast<int>(record.attempts.size()));
    sqlite3_bind_int64(event, 12, record.totalElapsedMs);
    const bool cacheHit = record.success && !record.rememberedProfile.empty() &&
        record.verdict.winningProfile == record.rememberedProfile &&
        record.attempts.size() == 1;
    sqlite3_bind_int(event, 13, cacheHit ? 1 : 0);

    if (sqlite3_step(event) != SQLITE_DONE) return false;
    const sqlite3_int64 eventId = sqlite3_last_insert_rowid(database);

    for (size_t index = 0; index < record.attempts.size(); ++index) {
        const diagnosis::Attempt& attempt = record.attempts[index];
        sqlite3_stmt* item = attemptInsert.get();
        attemptInsert.reset();
        sqlite3_bind_int64(item, 1, eventId);
        sqlite3_bind_int(item, 2, static_cast<int>(index));
        bindText(item, 3, attempt.profile);
        bindText(item, 4, diagnosis::signalName(attempt.signal));
        sqlite3_bind_int64(item, 5, attempt.elapsedMs);
        if (sqlite3_step(item) != SQLITE_DONE) return false;
    }
    return true;
}

void pruneDatabase(sqlite3* database, unsigned retentionDays, size_t maxEvents) {
    Statement expired(database,
        "DELETE FROM probe_events WHERE occurred_at < ?;");
    if (expired) {
        sqlite3_bind_int64(expired.get(), 1,
            unixSeconds() - static_cast<int64_t>(retentionDays) * 86400);
        sqlite3_step(expired.get());
    }

    Statement overflow(database,
        "DELETE FROM probe_events WHERE id IN ("
        " SELECT id FROM probe_events ORDER BY id DESC LIMIT -1 OFFSET ?"
        ");");
    if (overflow) {
        sqlite3_bind_int64(overflow.get(), 1, static_cast<sqlite3_int64>(maxEvents));
        sqlite3_step(overflow.get());
    }
}

DashboardData emptyDashboard(const std::string& error, unsigned windowDays) {
    DashboardData data;
    data.ready = false;
    data.error = error;
    data.generatedAt = unixSeconds();
    data.windowDays = windowDays;
    return data;
}

void appendKeyCounts(std::ostringstream& output, const char* key,
                     const std::vector<DashboardData::KeyCount>& items) {
    output << ",\"" << key << "\":[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) output << ',';
        output << "{\"key\":\"" << json::escape(items[i].key)
               << "\",\"count\":" << items[i].count << '}';
    }
    output << ']';
}

std::string serializeDashboard(const DashboardData& data) {
    std::ostringstream output;
    output << "{\"ready\":" << (data.ready ? "true" : "false")
           << ",\"generatedAt\":" << data.generatedAt
           << ",\"windowDays\":" << data.windowDays;
    if (!data.ready) {
        output << ",\"error\":\"" << json::escape(data.error) << '"';
    }
    output << ",\"summary\":{\"total\":" << data.total
           << ",\"bypassed\":" << data.bypassed
           << ",\"learned\":" << data.learned
           << ",\"normal\":" << data.normal
           << ",\"unresolved\":" << data.unresolved
           << ",\"averageLatencyMs\":" << std::fixed << std::setprecision(1)
           << data.averageLatencyMs << ",\"cacheHits\":" << data.cacheHits << '}';

    appendKeyCounts(output, "diagnoses", data.diagnoses);
    appendKeyCounts(output, "signals", data.signals);

    output << ",\"profiles\":[";
    for (size_t i = 0; i < data.profiles.size(); ++i) {
        const DashboardData::Profile& profile = data.profiles[i];
        if (i) output << ',';
        output << "{\"name\":\"" << json::escape(profile.name)
               << "\",\"count\":" << profile.count
               << ",\"averageLatencyMs\":" << std::fixed << std::setprecision(1)
               << profile.averageLatencyMs
               << ",\"averageAttempts\":" << profile.averageAttempts << '}';
    }
    output << "]";

    output << ",\"daily\":[";
    for (size_t i = 0; i < data.daily.size(); ++i) {
        const DashboardData::Day& day = data.daily[i];
        if (i) output << ',';
        output << "{\"day\":\"" << json::escape(day.day)
               << "\",\"total\":" << day.total
               << ",\"bypassed\":" << day.bypassed
               << ",\"learned\":" << day.learned
               << ",\"unresolved\":" << day.unresolved << '}';
    }
    output << "]";

    output << ",\"recent\":[";
    for (size_t i = 0; i < data.recent.size(); ++i) {
        const DashboardData::Event& event = data.recent[i];
        if (i) output << ',';
        output << "{\"id\":" << event.id
               << ",\"timestamp\":" << event.timestamp
               << ",\"network\":\"" << json::escape(event.network)
               << "\",\"host\":\"" << json::escape(event.host)
               << "\",\"baseline\":\"" << json::escape(event.baseline)
               << "\",\"diagnosis\":\"" << json::escape(event.diagnosis)
               << "\",\"confidence\":" << event.confidence
               << ",\"winner\":\"" << json::escape(event.winner)
               << "\",\"remembered\":\"" << json::escape(event.remembered)
               << "\",\"success\":" << (event.success ? "true" : "false")
               << ",\"forced\":" << (event.forced ? "true" : "false")
               << ",\"attemptCount\":" << event.attemptCount
               << ",\"totalElapsedMs\":" << event.totalElapsedMs
               << ",\"cacheHit\":" << (event.cacheHit ? "true" : "false")
               << ",\"attempts\":[";
        for (size_t j = 0; j < event.attempts.size(); ++j) {
            const DashboardData::Attempt& attempt = event.attempts[j];
            if (j) output << ',';
            output << "{\"profile\":\"" << json::escape(attempt.profile)
                   << "\",\"signal\":\"" << json::escape(attempt.signal)
                   << "\",\"elapsedMs\":" << attempt.elapsedMs << '}';
        }
        output << "]}";
    }
    output << "]}";
    return output.str();
}

void bindCutoff(const Statement& statement, int64_t cutoff) {
    sqlite3_bind_int64(statement.get(), 1, cutoff);
}

} // namespace

Store::Store(std::string path, unsigned retentionDays,
             size_t maxEvents, size_t maxQueued)
    : path_(std::move(path)),
      retentionDays_(std::max(retentionDays, 1U)),
      maxEvents_(std::max<size_t>(maxEvents, 100)),
      maxQueued_(std::max<size_t>(maxQueued, 64)) {}

Store::~Store() {
    stop();
}

bool Store::start() {
    if (path_.empty() || accepting_.exchange(true)) return !path_.empty();

    stopping_ = false;
    std::error_code error;
    const std::filesystem::path parent = std::filesystem::path(path_).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, error);
    if (error) {
        accepting_ = false;
        spdlog::error("Telemetri dizini olusturulamadi: {}", error.message());
        return false;
    }

    writer_ = std::thread([this]() { writerLoop(); });
    return true;
}

void Store::stop() {
    accepting_ = false;
    stopping_ = true;
    ready_.notify_all();
    if (writer_.joinable()) writer_.join();
}

void Store::record(ProbeRecord record) {
    if (!accepting_) return;
    if (record.occurredAt == 0) record.occurredAt = unixSeconds();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!accepting_) return;
        if (queue_.size() >= maxQueued_) {
            dropped_++;
            return;
        }
        queue_.push_back(std::move(record));
    }
    ready_.notify_one();
}

void Store::writerLoop() {
    sqlite3* database = nullptr;
    const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                      SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path_.c_str(), &database, flags, nullptr) != SQLITE_OK ||
        !database || !initializeDatabase(database)) {
        spdlog::error("Telemetri veritabani acilamadi: {}",
                      database ? sqlite3_errmsg(database) : path_);
        if (database) sqlite3_close(database);
        accepting_ = false;
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        return;
    }

    Statement eventInsert(database,
        "INSERT INTO probe_events("
        " occurred_at,network_id,host,baseline_signal,diagnosis_kind,confidence,"
        " winning_profile,remembered_profile,success,forced,attempt_count,"
        " total_elapsed_ms,cache_hit) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);");
    Statement attemptInsert(database,
        "INSERT INTO probe_attempts(event_id,ordinal,profile,signal,elapsed_ms)"
        " VALUES(?,?,?,?,?);");
    if (!eventInsert || !attemptInsert) {
        spdlog::error("Telemetri sorgulari hazirlanamadi: {}", sqlite3_errmsg(database));
        sqlite3_close(database);
        accepting_ = false;
        return;
    }

    pruneDatabase(database, retentionDays_, maxEvents_);
    size_t batchesSincePrune = 0;

    while (true) {
        std::vector<ProbeRecord> batch;
        batch.reserve(kWriteBatchSize);
        {
            std::unique_lock<std::mutex> lock(mutex_);
            ready_.wait(lock, [this]() { return stopping_ || !queue_.empty(); });
            while (!queue_.empty() && batch.size() < kWriteBatchSize) {
                batch.push_back(std::move(queue_.front()));
                queue_.pop_front();
            }
            if (batch.empty() && stopping_) break;
        }

        bool ok = execute(database, "BEGIN IMMEDIATE;");
        for (const ProbeRecord& record : batch) {
            if (!ok || !insertRecord(database, eventInsert, attemptInsert, record)) {
                ok = false;
                break;
            }
        }
        if (ok) ok = execute(database, "COMMIT;");
        if (!ok) {
            execute(database, "ROLLBACK;");
            spdlog::warn("{} telemetri kaydi yazilamadi", batch.size());
        }

        if (++batchesSincePrune >= 64) {
            pruneDatabase(database, retentionDays_, maxEvents_);
            batchesSincePrune = 0;
        }
    }

    pruneDatabase(database, retentionDays_, maxEvents_);
    sqlite3_close(database);
}

DashboardData Store::dashboardSnapshot(const std::string& path,
                                       unsigned windowDays) {
    windowDays = std::clamp(windowDays, 1U, 90U);
    if (path.empty() || !std::filesystem::exists(path)) {
        return emptyDashboard("Henüz telemetri kaydı oluşmadı.", windowDays);
    }

    sqlite3* database = nullptr;
    if (sqlite3_open_v2(path.c_str(), &database,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                        nullptr) != SQLITE_OK || !database) {
        const std::string error = database ? sqlite3_errmsg(database)
                                           : "Veritabanı açılamadı.";
        if (database) sqlite3_close(database);
        return emptyDashboard(error, windowDays);
    }
    sqlite3_busy_timeout(database, 1000);

    const int64_t now = unixSeconds();
    const int64_t cutoff = now - static_cast<int64_t>(windowDays) * 86400;
    execute(database, "BEGIN;");

    DashboardData data;
    data.ready = true;
    data.generatedAt = now;
    data.windowDays = windowDays;

    Statement summary(database,
        "SELECT COUNT(*),"
        " COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0),"
        " COALESCE(SUM(diagnosis_kind='no-interference'),0),"
        " COALESCE(SUM(success=0),0),"
        " COALESCE(AVG(total_elapsed_ms),0),"
        " COALESCE(SUM(cache_hit),0),"
        " COALESCE(SUM(diagnosis_kind IN ('learned-profile','transient-failure','interference-suspected')),0)"
        " FROM probe_events WHERE occurred_at>=?;");
    if (summary) {
        bindCutoff(summary, cutoff);
        if (sqlite3_step(summary.get()) == SQLITE_ROW) {
            data.total = sqlite3_column_int64(summary.get(), 0);
            data.bypassed = sqlite3_column_int64(summary.get(), 1);
            data.normal = sqlite3_column_int64(summary.get(), 2);
            data.unresolved = sqlite3_column_int64(summary.get(), 3);
            data.averageLatencyMs = sqlite3_column_double(summary.get(), 4);
            data.cacheHits = sqlite3_column_int64(summary.get(), 5);
            data.learned = sqlite3_column_int64(summary.get(), 6);
        }
    }

    // Previous window of equal length, so the panel can show a real trend
    // instead of an unanchored number.
    const int64_t previousCutoff = cutoff - static_cast<int64_t>(windowDays) * 86400;
    Statement previous(database,
        "SELECT COUNT(*),"
        " COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0),"
        " COALESCE(SUM(diagnosis_kind='no-interference'),0),"
        " COALESCE(SUM(success=0),0),"
        " COALESCE(AVG(total_elapsed_ms),0),"
        " COALESCE(SUM(diagnosis_kind IN ('learned-profile','transient-failure','interference-suspected')),0)"
        " FROM probe_events WHERE occurred_at>=? AND occurred_at<?;");
    if (previous) {
        sqlite3_bind_int64(previous.get(), 1, previousCutoff);
        sqlite3_bind_int64(previous.get(), 2, cutoff);
        if (sqlite3_step(previous.get()) == SQLITE_ROW) {
            data.previous.total = sqlite3_column_int64(previous.get(), 0);
            data.previous.bypassed = sqlite3_column_int64(previous.get(), 1);
            data.previous.normal = sqlite3_column_int64(previous.get(), 2);
            data.previous.unresolved = sqlite3_column_int64(previous.get(), 3);
            data.previous.averageLatencyMs = sqlite3_column_double(previous.get(), 4);
            data.previous.learned = sqlite3_column_int64(previous.get(), 5);
        }
    }

    // Order statistics. OFFSET indexes the sorted latency column directly, so
    // these are exact percentiles rather than histogram estimates.
    if (data.total > 0) {
        Statement quantile(database,
            "SELECT total_elapsed_ms FROM probe_events WHERE occurred_at>=?"
            " ORDER BY total_elapsed_ms LIMIT 1 OFFSET ?;");
        const auto at = [&](double fraction) -> int64_t {
            if (!quantile) return 0;
            quantile.reset();
            const int64_t offset = std::clamp<int64_t>(
                static_cast<int64_t>(fraction * static_cast<double>(data.total - 1)),
                0, data.total - 1);
            sqlite3_bind_int64(quantile.get(), 1, cutoff);
            sqlite3_bind_int64(quantile.get(), 2, offset);
            return sqlite3_step(quantile.get()) == SQLITE_ROW
                       ? sqlite3_column_int64(quantile.get(), 0)
                       : 0;
        };
        data.latency.p50 = at(0.50);
        data.latency.p90 = at(0.90);
        data.latency.p99 = at(0.99);
        data.latency.worst = at(1.0);
    }

    // Latency histogram over fixed doubling buckets; the last one is open-ended.
    {
        static constexpr int64_t kEdges[] = {50, 100, 200, 400, 800, 1600, 3200};
        constexpr int kBucketCount =
            static_cast<int>(std::size(kEdges)) + 1;
        std::vector<int64_t> counts(kBucketCount, 0);
        Statement histogram(database,
            "SELECT CASE"
            "  WHEN total_elapsed_ms<50 THEN 0"
            "  WHEN total_elapsed_ms<100 THEN 1"
            "  WHEN total_elapsed_ms<200 THEN 2"
            "  WHEN total_elapsed_ms<400 THEN 3"
            "  WHEN total_elapsed_ms<800 THEN 4"
            "  WHEN total_elapsed_ms<1600 THEN 5"
            "  WHEN total_elapsed_ms<3200 THEN 6"
            "  ELSE 7 END AS bucket, COUNT(*)"
            " FROM probe_events WHERE occurred_at>=? GROUP BY bucket;");
        if (histogram) {
            bindCutoff(histogram, cutoff);
            while (sqlite3_step(histogram.get()) == SQLITE_ROW) {
                const int index = sqlite3_column_int(histogram.get(), 0);
                if (index >= 0 && index < kBucketCount) {
                    counts[static_cast<size_t>(index)] =
                        sqlite3_column_int64(histogram.get(), 1);
                }
            }
        }
        for (int i = 0; i < kBucketCount; ++i) {
            data.latencyHistogram.push_back(
                {i < static_cast<int>(std::size(kEdges)) ? kEdges[i] : 0,
                 counts[static_cast<size_t>(i)]});
        }
    }

    // Hosts ranked by how often they actually needed intervention.
    Statement hosts(database,
        "SELECT host,COUNT(*),"
        " COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0),"
        " COALESCE(SUM(success=0),0),"
        " COALESCE(AVG(total_elapsed_ms),0)"
        " FROM probe_events WHERE occurred_at>=? GROUP BY host"
        " ORDER BY (COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0)"
        "           +COALESCE(SUM(success=0),0)) DESC, COUNT(*) DESC LIMIT 8;");
    if (hosts) {
        bindCutoff(hosts, cutoff);
        while (sqlite3_step(hosts.get()) == SQLITE_ROW) {
            data.topHosts.push_back({columnText(hosts.get(), 0),
                                     sqlite3_column_int64(hosts.get(), 1),
                                     sqlite3_column_int64(hosts.get(), 2),
                                     sqlite3_column_int64(hosts.get(), 3),
                                     sqlite3_column_double(hosts.get(), 4)});
        }
    }

    const auto collectBreakdown = [&](const char* sql) {
        std::vector<DashboardData::KeyCount> items;
        Statement statement(database, sql);
        if (statement) {
            bindCutoff(statement, cutoff);
            while (sqlite3_step(statement.get()) == SQLITE_ROW) {
                items.push_back({columnText(statement.get(), 0),
                                 sqlite3_column_int64(statement.get(), 1)});
            }
        }
        return items;
    };

    data.diagnoses = collectBreakdown(
        "SELECT diagnosis_kind,COUNT(*) FROM probe_events"
        " WHERE occurred_at>=? GROUP BY diagnosis_kind ORDER BY COUNT(*) DESC;");
    data.signals = collectBreakdown(
        "SELECT COALESCE(baseline_signal,'not-tested'),COUNT(*) FROM probe_events"
        " WHERE occurred_at>=? GROUP BY COALESCE(baseline_signal,'not-tested')"
        " ORDER BY COUNT(*) DESC;");

    Statement profiles(database,
        "SELECT winning_profile,COUNT(*),COALESCE(AVG(total_elapsed_ms),0),"
        " COALESCE(AVG(attempt_count),0) FROM probe_events"
        " WHERE occurred_at>=? AND success=1 AND winning_profile IS NOT NULL"
        " GROUP BY winning_profile ORDER BY COUNT(*) DESC LIMIT 16;");
    if (profiles) {
        bindCutoff(profiles, cutoff);
        while (sqlite3_step(profiles.get()) == SQLITE_ROW) {
            data.profiles.push_back({
                columnText(profiles.get(), 0),
                sqlite3_column_int64(profiles.get(), 1),
                sqlite3_column_double(profiles.get(), 2),
                sqlite3_column_double(profiles.get(), 3)});
        }
    }

    Statement daily(database,
        "SELECT strftime('%Y-%m-%d',occurred_at,'unixepoch','localtime'),"
        " COUNT(*),COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0),"
        " COALESCE(SUM(diagnosis_kind IN ('learned-profile','transient-failure','interference-suspected')),0),"
        " COALESCE(SUM(success=0),0) FROM probe_events"
        " WHERE occurred_at>=? GROUP BY 1 ORDER BY 1;");
    if (daily) {
        bindCutoff(daily, cutoff);
        while (sqlite3_step(daily.get()) == SQLITE_ROW) {
            data.daily.push_back({
                columnText(daily.get(), 0),
                sqlite3_column_int64(daily.get(), 1),
                sqlite3_column_int64(daily.get(), 2),
                sqlite3_column_int64(daily.get(), 3),
                sqlite3_column_int64(daily.get(), 4)});
        }
    }

    Statement recent(database,
        "SELECT id,occurred_at,network_id,host,COALESCE(baseline_signal,''),"
        " diagnosis_kind,confidence,COALESCE(winning_profile,''),"
        " COALESCE(remembered_profile,''),success,forced,attempt_count,"
        " total_elapsed_ms,cache_hit FROM probe_events"
        " WHERE occurred_at>=? ORDER BY id DESC LIMIT 250;");
    Statement attempts(database,
        "SELECT profile,signal,elapsed_ms FROM probe_attempts"
        " WHERE event_id=? ORDER BY ordinal;");
    if (recent) {
        bindCutoff(recent, cutoff);
        while (sqlite3_step(recent.get()) == SQLITE_ROW) {
            DashboardData::Event event;
            event.id = sqlite3_column_int64(recent.get(), 0);
            event.timestamp = sqlite3_column_int64(recent.get(), 1);
            event.network = columnText(recent.get(), 2);
            event.host = columnText(recent.get(), 3);
            event.baseline = columnText(recent.get(), 4);
            event.diagnosis = columnText(recent.get(), 5);
            event.confidence = sqlite3_column_int(recent.get(), 6);
            event.winner = columnText(recent.get(), 7);
            event.remembered = columnText(recent.get(), 8);
            event.success = sqlite3_column_int(recent.get(), 9) != 0;
            event.forced = sqlite3_column_int(recent.get(), 10) != 0;
            event.attemptCount = sqlite3_column_int(recent.get(), 11);
            event.totalElapsedMs = sqlite3_column_int64(recent.get(), 12);
            event.cacheHit = sqlite3_column_int(recent.get(), 13) != 0;

            if (attempts) {
                attempts.reset();
                sqlite3_bind_int64(attempts.get(), 1, event.id);
                while (sqlite3_step(attempts.get()) == SQLITE_ROW) {
                    event.attempts.push_back({
                        columnText(attempts.get(), 0),
                        columnText(attempts.get(), 1),
                        sqlite3_column_int64(attempts.get(), 2)});
                }
            }
            data.recent.push_back(std::move(event));
        }
    }

    execute(database, "COMMIT;");
    sqlite3_close(database);
    return data;
}

std::string Store::dashboardJson(const std::string& path, unsigned windowDays) {
    return serializeDashboard(dashboardSnapshot(path, windowDays));
}

} // namespace telemetry
