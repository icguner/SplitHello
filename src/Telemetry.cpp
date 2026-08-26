#include "Telemetry.hpp"

#include "Json.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
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
        execute(database, "PRAGMA user_version=1;");
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

std::string emptyDashboard(const std::string& error, unsigned windowDays) {
    std::ostringstream output;
    output << "{\"ready\":false,\"generatedAt\":" << unixSeconds()
           << ",\"windowDays\":" << windowDays
           << ",\"error\":\"" << json::escape(error) << "\""
           << ",\"summary\":{\"total\":0,\"bypassed\":0,\"normal\":0,"
              "\"unresolved\":0,\"averageLatencyMs\":0,\"cacheHits\":0}"
           << ",\"diagnoses\":[],\"profiles\":[],\"signals\":[],"
              "\"daily\":[],\"recent\":[]}";
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

std::string Store::dashboardJson(const std::string& path, unsigned windowDays) {
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

    std::ostringstream output;
    output << "{\"ready\":true,\"generatedAt\":" << now
           << ",\"windowDays\":" << windowDays;

    Statement summary(database,
        "SELECT COUNT(*),"
        " COALESCE(SUM(success=1 AND winning_profile<>'none'),0),"
        " COALESCE(SUM(diagnosis_kind='no-interference'),0),"
        " COALESCE(SUM(success=0),0),"
        " COALESCE(AVG(total_elapsed_ms),0),"
        " COALESCE(SUM(cache_hit),0)"
        " FROM probe_events WHERE occurred_at>=?;");
    int64_t total = 0, bypassed = 0, normal = 0, unresolved = 0, cacheHits = 0;
    double averageLatency = 0;
    if (summary) {
        bindCutoff(summary, cutoff);
        if (sqlite3_step(summary.get()) == SQLITE_ROW) {
            total = sqlite3_column_int64(summary.get(), 0);
            bypassed = sqlite3_column_int64(summary.get(), 1);
            normal = sqlite3_column_int64(summary.get(), 2);
            unresolved = sqlite3_column_int64(summary.get(), 3);
            averageLatency = sqlite3_column_double(summary.get(), 4);
            cacheHits = sqlite3_column_int64(summary.get(), 5);
        }
    }
    output << ",\"summary\":{\"total\":" << total
           << ",\"bypassed\":" << bypassed
           << ",\"normal\":" << normal
           << ",\"unresolved\":" << unresolved
           << ",\"averageLatencyMs\":" << std::fixed << std::setprecision(1)
           << averageLatency << ",\"cacheHits\":" << cacheHits << "}";

    const auto appendBreakdown = [&](const char* key, const char* sql) {
        output << ",\"" << key << "\":[";
        Statement statement(database, sql);
        bool first = true;
        if (statement) {
            bindCutoff(statement, cutoff);
            while (sqlite3_step(statement.get()) == SQLITE_ROW) {
                if (!first) output << ',';
                first = false;
                output << "{\"key\":\""
                       << json::escape(columnText(statement.get(), 0))
                       << "\",\"count\":" << sqlite3_column_int64(statement.get(), 1)
                       << "}";
            }
        }
        output << ']';
    };

    appendBreakdown("diagnoses",
        "SELECT diagnosis_kind,COUNT(*) FROM probe_events"
        " WHERE occurred_at>=? GROUP BY diagnosis_kind ORDER BY COUNT(*) DESC;");
    appendBreakdown("signals",
        "SELECT COALESCE(baseline_signal,'not-tested'),COUNT(*) FROM probe_events"
        " WHERE occurred_at>=? GROUP BY COALESCE(baseline_signal,'not-tested')"
        " ORDER BY COUNT(*) DESC;");

    output << ",\"profiles\":[";
    Statement profiles(database,
        "SELECT winning_profile,COUNT(*),COALESCE(AVG(total_elapsed_ms),0),"
        " COALESCE(AVG(attempt_count),0) FROM probe_events"
        " WHERE occurred_at>=? AND success=1 AND winning_profile IS NOT NULL"
        " GROUP BY winning_profile ORDER BY COUNT(*) DESC LIMIT 16;");
    bool first = true;
    if (profiles) {
        bindCutoff(profiles, cutoff);
        while (sqlite3_step(profiles.get()) == SQLITE_ROW) {
            if (!first) output << ',';
            first = false;
            output << "{\"name\":\"" << json::escape(columnText(profiles.get(), 0))
                   << "\",\"count\":" << sqlite3_column_int64(profiles.get(), 1)
                   << ",\"averageLatencyMs\":" << std::fixed << std::setprecision(1)
                   << sqlite3_column_double(profiles.get(), 2)
                   << ",\"averageAttempts\":" << sqlite3_column_double(profiles.get(), 3)
                   << "}";
        }
    }
    output << ']';

    output << ",\"daily\":[";
    Statement daily(database,
        "SELECT strftime('%Y-%m-%d',occurred_at,'unixepoch','localtime'),"
        " COUNT(*),COALESCE(SUM(success=1 AND winning_profile<>'none'),0),"
        " COALESCE(SUM(success=0),0) FROM probe_events"
        " WHERE occurred_at>=? GROUP BY 1 ORDER BY 1;");
    first = true;
    if (daily) {
        bindCutoff(daily, cutoff);
        while (sqlite3_step(daily.get()) == SQLITE_ROW) {
            if (!first) output << ',';
            first = false;
            output << "{\"day\":\"" << json::escape(columnText(daily.get(), 0))
                   << "\",\"total\":" << sqlite3_column_int64(daily.get(), 1)
                   << ",\"bypassed\":" << sqlite3_column_int64(daily.get(), 2)
                   << ",\"unresolved\":" << sqlite3_column_int64(daily.get(), 3)
                   << "}";
        }
    }
    output << ']';

    output << ",\"recent\":[";
    Statement recent(database,
        "SELECT id,occurred_at,network_id,host,COALESCE(baseline_signal,''),"
        " diagnosis_kind,confidence,COALESCE(winning_profile,''),"
        " COALESCE(remembered_profile,''),success,forced,attempt_count,"
        " total_elapsed_ms,cache_hit FROM probe_events"
        " WHERE occurred_at>=? ORDER BY id DESC LIMIT 60;");
    Statement attempts(database,
        "SELECT profile,signal,elapsed_ms FROM probe_attempts"
        " WHERE event_id=? ORDER BY ordinal;");
    first = true;
    if (recent) {
        bindCutoff(recent, cutoff);
        while (sqlite3_step(recent.get()) == SQLITE_ROW) {
            if (!first) output << ',';
            first = false;
            const sqlite3_int64 eventId = sqlite3_column_int64(recent.get(), 0);
            output << "{\"id\":" << eventId
                   << ",\"timestamp\":" << sqlite3_column_int64(recent.get(), 1)
                   << ",\"network\":\"" << json::escape(columnText(recent.get(), 2))
                   << "\",\"host\":\"" << json::escape(columnText(recent.get(), 3))
                   << "\",\"baseline\":\"" << json::escape(columnText(recent.get(), 4))
                   << "\",\"diagnosis\":\"" << json::escape(columnText(recent.get(), 5))
                   << "\",\"confidence\":" << sqlite3_column_int(recent.get(), 6)
                   << ",\"winner\":\"" << json::escape(columnText(recent.get(), 7))
                   << "\",\"remembered\":\"" << json::escape(columnText(recent.get(), 8))
                   << "\",\"success\":" << (sqlite3_column_int(recent.get(), 9) ? "true" : "false")
                   << ",\"forced\":" << (sqlite3_column_int(recent.get(), 10) ? "true" : "false")
                   << ",\"attemptCount\":" << sqlite3_column_int(recent.get(), 11)
                   << ",\"totalElapsedMs\":" << sqlite3_column_int64(recent.get(), 12)
                   << ",\"cacheHit\":" << (sqlite3_column_int(recent.get(), 13) ? "true" : "false")
                   << ",\"attempts\":[";

            bool firstAttempt = true;
            if (attempts) {
                attempts.reset();
                sqlite3_bind_int64(attempts.get(), 1, eventId);
                while (sqlite3_step(attempts.get()) == SQLITE_ROW) {
                    if (!firstAttempt) output << ',';
                    firstAttempt = false;
                    output << "{\"profile\":\""
                           << json::escape(columnText(attempts.get(), 0))
                           << "\",\"signal\":\""
                           << json::escape(columnText(attempts.get(), 1))
                           << "\",\"elapsedMs\":"
                           << sqlite3_column_int64(attempts.get(), 2) << "}";
                }
            }
            output << "]}";
        }
    }
    output << "]}";

    execute(database, "COMMIT;");
    sqlite3_close(database);
    return output.str();
}

} // namespace telemetry
