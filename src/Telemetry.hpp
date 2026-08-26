#pragma once

#include "Diagnosis.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace telemetry {

// One completed adaptive decision. The relay only moves this small record into
// a bounded queue; SQLite work happens on the dedicated writer thread.
struct ProbeRecord {
    int64_t occurredAt = 0;
    std::string networkId;
    std::string host;
    std::string rememberedProfile;
    diagnosis::Verdict verdict;
    std::vector<diagnosis::Attempt> attempts;
    unsigned totalElapsedMs = 0;
    bool success = false;
    bool forced = false;
};

// Fully materialised, read-only view of the diagnostics history over a rolling
// window. The native dashboard consumes this directly; dashboardJson() is a
// thin serialiser over the same data for any JSON consumer or test.
struct DashboardData {
    struct KeyCount {
        std::string key;
        int64_t count = 0;
    };
    struct Profile {
        std::string name;
        int64_t count = 0;
        double averageLatencyMs = 0;
        double averageAttempts = 0;
    };
    struct Day {
        std::string day; // YYYY-MM-DD, local time
        int64_t total = 0;
        int64_t bypassed = 0;
        int64_t unresolved = 0;
    };
    struct Attempt {
        std::string profile;
        std::string signal;
        int64_t elapsedMs = 0;
    };
    struct Event {
        int64_t id = 0;
        int64_t timestamp = 0;
        std::string network;
        std::string host;
        std::string baseline;
        std::string diagnosis;
        int confidence = 0;
        std::string winner;
        std::string remembered;
        bool success = false;
        bool forced = false;
        bool cacheHit = false;
        int attemptCount = 0;
        int64_t totalElapsedMs = 0;
        std::vector<Attempt> attempts;
    };

    // Latency order statistics. Averages hide the tail that actually hurts, so
    // the panel reports the median and the slow percentiles beside it.
    struct Percentiles {
        int64_t p50 = 0;
        int64_t p90 = 0;
        int64_t p99 = 0;
        int64_t worst = 0;
    };
    // One latency histogram column. `upperMs == 0` marks the open-ended bucket.
    struct Bucket {
        int64_t upperMs = 0;
        int64_t count = 0;
    };
    struct HostStat {
        std::string host;
        int64_t total = 0;
        int64_t bypassed = 0;
        int64_t unresolved = 0;
        double averageLatencyMs = 0;
    };
    // The immediately preceding window of equal length, for trend deltas.
    struct Previous {
        int64_t total = 0;
        int64_t bypassed = 0;
        int64_t normal = 0;
        int64_t unresolved = 0;
        double averageLatencyMs = 0;
    };

    bool ready = false;
    std::string error;
    int64_t generatedAt = 0;
    unsigned windowDays = 30;

    int64_t total = 0;
    int64_t bypassed = 0;
    int64_t normal = 0;
    int64_t unresolved = 0;
    int64_t cacheHits = 0;
    double averageLatencyMs = 0;

    Percentiles latency;
    Previous previous;

    std::vector<KeyCount> diagnoses;
    std::vector<KeyCount> signals;
    std::vector<Profile> profiles;
    std::vector<Day> daily;
    std::vector<Bucket> latencyHistogram;
    std::vector<HostStat> topHosts;
    std::vector<Event> recent;
};

class Store {
public:
    explicit Store(std::string path, unsigned retentionDays = 30,
                   size_t maxEvents = 50000, size_t maxQueued = 4096);
    ~Store();

    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    bool start();
    void stop();
    void record(ProbeRecord record);

    size_t droppedRecords() const { return dropped_.load(); }
    const std::string& path() const { return path_; }

    // Read-only dashboard snapshot. Safe to call from the tray process while
    // the elevated engine writes through SQLite WAL.
    static DashboardData dashboardSnapshot(const std::string& path,
                                           unsigned windowDays = 30);
    static std::string dashboardJson(const std::string& path,
                                     unsigned windowDays = 30);

private:
    void writerLoop();

    std::string path_;
    unsigned retentionDays_;
    size_t maxEvents_;
    size_t maxQueued_;

    std::atomic<bool> accepting_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<size_t> dropped_{0};
    std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<ProbeRecord> queue_;
    std::thread writer_;
};

} // namespace telemetry
