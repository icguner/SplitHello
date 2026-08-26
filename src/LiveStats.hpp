#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace live_stats {

struct ProfileSnapshot {
    std::string name;
    uint32_t active = 0;
    uint32_t decisions = 0;
};

struct Snapshot {
    bool online = false;
    uint32_t enginePid = 0;
    uint32_t startedAt = 0;
    uint32_t activeFlows = 0;
    uint32_t pendingFlows = 0;
    uint32_t openedFlows = 0;
    uint32_t decisions = 0;
    uint32_t successfulDecisions = 0;
    uint32_t bypassedDecisions = 0;
    uint32_t unresolvedDecisions = 0;
    uint32_t lastDecisionAt = 0;
    std::vector<ProfileSnapshot> profiles;
};

// Engine-side owner of a small named memory mapping. All write operations are
// fixed-size interlocked increments; no allocation or I/O occurs on a relay
// packet path.
class Publisher {
public:
    explicit Publisher(std::wstring mappingName);
    ~Publisher();

    Publisher(const Publisher&) = delete;
    Publisher& operator=(const Publisher&) = delete;

    [[nodiscard]] bool available() const;

private:
    friend class Flow;
    struct Impl;

    static int profileSlot(std::string_view profile);
    void flowOpened();
    void flowProfileChanged(int previousSlot, int nextSlot);
    void flowDecision(int profileSlot, bool success, bool bypassed);
    void flowClosed(int profileSlot);

    std::unique_ptr<Impl> impl_;
};

// One DirectRelay flow lifetime. The RAII destructor guarantees that active
// counts return to zero on every early-return and tunnel-fallback path.
class Flow {
public:
    Flow() = default;
    ~Flow();

    Flow(const Flow&) = delete;
    Flow& operator=(const Flow&) = delete;

    void begin(Publisher* publisher);
    void setProfile(std::string_view profile);
    void decision(bool success, bool bypassed);
    void finish();

private:
    Publisher* publisher_ = nullptr; // observed; RelayContext owns the publisher
    int profileSlot_ = -1;
    bool decided_ = false;
};

[[nodiscard]] Snapshot read(std::wstring_view mappingName);
[[nodiscard]] std::string toJson(const Snapshot& snapshot);

} // namespace live_stats
