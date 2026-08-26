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
