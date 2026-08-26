#include "LiveStats.hpp"

#include "Json.hpp"
#include "Strategy.hpp"

#include <algorithm>
#include <chrono>
#include <sstream>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace live_stats {
namespace {

constexpr LONG kMagic = 0x53484C53; // SHLS
constexpr LONG kVersion = 1;
constexpr size_t kMaxProfiles = 16;

struct SharedState {
    volatile LONG magic = 0;
    LONG version = 0;
    LONG enginePid = 0;
    LONG startedAt = 0;
    volatile LONG activeFlows = 0;
    volatile LONG openedFlows = 0;
    volatile LONG decisions = 0;
    volatile LONG successfulDecisions = 0;
    volatile LONG bypassedDecisions = 0;
    volatile LONG unresolvedDecisions = 0;
    volatile LONG lastDecisionAt = 0;
    volatile LONG activeProfiles[kMaxProfiles]{};
    volatile LONG profileDecisions[kMaxProfiles]{};
};

uint32_t unixSeconds32() {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return static_cast<uint32_t>(std::clamp<int64_t>(seconds, 0, 0x7FFFFFFF));
}

uint32_t nonNegative(LONG value) {
    return value < 0 ? 0U : static_cast<uint32_t>(value);
}

} // namespace

struct Publisher::Impl {
    HANDLE mapping = nullptr;
    SharedState* state = nullptr;

    ~Impl() {
        if (state) {
            InterlockedExchange(&state->magic, 0);
            UnmapViewOfFile(state);
        }
        if (mapping) CloseHandle(mapping);
    }
};

Publisher::Publisher(std::wstring mappingName)
    : impl_(std::make_unique<Impl>()) {
    if (mappingName.empty()) return;

    impl_->mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
        static_cast<DWORD>(sizeof(SharedState)), mappingName.c_str());
    if (!impl_->mapping) return;

    impl_->state = static_cast<SharedState*>(MapViewOfFile(
        impl_->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState)));
    if (!impl_->state) return;

    // The tray reuses one mapping name when it restarts a failed engine. It
    // never runs two engines for that name, so a new publisher owns/reset it.
    ZeroMemory(impl_->state, sizeof(SharedState));
    impl_->state->version = kVersion;
    impl_->state->enginePid = static_cast<LONG>(GetCurrentProcessId());
    impl_->state->startedAt = static_cast<LONG>(unixSeconds32());
    InterlockedExchange(&impl_->state->magic, kMagic);
}

Publisher::~Publisher() = default;

bool Publisher::available() const {
    return impl_ && impl_->state;
}

int Publisher::profileSlot(std::string_view profile) {
    const auto& table = strategy::profiles();
    const size_t count = std::min(table.size(), kMaxProfiles);
    for (size_t index = 0; index < count; ++index) {
        if (table[index].name == profile) return static_cast<int>(index);
    }
    return -1;
}

void Publisher::flowOpened() {
    if (!available()) return;
    InterlockedIncrement(&impl_->state->activeFlows);
    InterlockedIncrement(&impl_->state->openedFlows);
}

void Publisher::flowProfileChanged(int previousSlot, int nextSlot) {
    if (!available() || previousSlot == nextSlot) return;
    if (previousSlot >= 0 && previousSlot < static_cast<int>(kMaxProfiles)) {
        InterlockedDecrement(&impl_->state->activeProfiles[previousSlot]);
    }
    if (nextSlot >= 0 && nextSlot < static_cast<int>(kMaxProfiles)) {
        InterlockedIncrement(&impl_->state->activeProfiles[nextSlot]);
    }
}

void Publisher::flowDecision(int profileSlot, bool success, bool bypassed) {
    if (!available()) return;
    InterlockedIncrement(&impl_->state->decisions);
    if (success) {
        InterlockedIncrement(&impl_->state->successfulDecisions);
        if (profileSlot >= 0 && profileSlot < static_cast<int>(kMaxProfiles)) {
            InterlockedIncrement(&impl_->state->profileDecisions[profileSlot]);
        }
    } else {
        InterlockedIncrement(&impl_->state->unresolvedDecisions);
    }
    if (bypassed) InterlockedIncrement(&impl_->state->bypassedDecisions);
    InterlockedExchange(&impl_->state->lastDecisionAt,
                        static_cast<LONG>(unixSeconds32()));
}

void Publisher::flowClosed(int profileSlot) {
    if (!available()) return;
    if (profileSlot >= 0 && profileSlot < static_cast<int>(kMaxProfiles)) {
        InterlockedDecrement(&impl_->state->activeProfiles[profileSlot]);
    }
    InterlockedDecrement(&impl_->state->activeFlows);
}

Flow::~Flow() {
    finish();
}

void Flow::begin(Publisher* publisher) {
    finish();
    publisher_ = publisher;
    if (publisher_) publisher_->flowOpened();
}

void Flow::setProfile(std::string_view profile) {
    if (!publisher_) return;
    const int nextSlot = Publisher::profileSlot(profile);
    publisher_->flowProfileChanged(profileSlot_, nextSlot);
    profileSlot_ = nextSlot;
}

void Flow::decision(bool success, bool bypassed) {
    if (!publisher_ || decided_) return;
    publisher_->flowDecision(profileSlot_, success, bypassed);
    decided_ = true;
}

void Flow::finish() {
    if (publisher_) publisher_->flowClosed(profileSlot_);
    publisher_ = nullptr;
    profileSlot_ = -1;
    decided_ = false;
}

Snapshot read(std::wstring_view mappingName) {
    Snapshot snapshot;
    if (mappingName.empty()) return snapshot;

    const std::wstring name(mappingName);
    HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name.c_str());
    if (!mapping) return snapshot;

    const auto* state = static_cast<const SharedState*>(MapViewOfFile(
        mapping, FILE_MAP_READ, 0, 0, sizeof(SharedState)));
    if (!state) {
        CloseHandle(mapping);
        return snapshot;
    }

    if (state->magic == kMagic && state->version == kVersion) {
        snapshot.online = true;
        snapshot.enginePid = nonNegative(state->enginePid);
        snapshot.startedAt = nonNegative(state->startedAt);
        snapshot.activeFlows = nonNegative(state->activeFlows);
        snapshot.openedFlows = nonNegative(state->openedFlows);
        snapshot.decisions = nonNegative(state->decisions);
        snapshot.successfulDecisions = nonNegative(state->successfulDecisions);
        snapshot.bypassedDecisions = nonNegative(state->bypassedDecisions);
        snapshot.unresolvedDecisions = nonNegative(state->unresolvedDecisions);
        snapshot.lastDecisionAt = nonNegative(state->lastDecisionAt);

        uint32_t classifiedActive = 0;
        const auto& table = strategy::profiles();
        const size_t count = std::min(table.size(), kMaxProfiles);
        snapshot.profiles.reserve(count);
        for (size_t index = 0; index < count; ++index) {
            ProfileSnapshot profile;
            profile.name = table[index].name;
            profile.active = nonNegative(state->activeProfiles[index]);
            profile.decisions = nonNegative(state->profileDecisions[index]);
            classifiedActive += profile.active;
            snapshot.profiles.push_back(std::move(profile));
        }
        snapshot.pendingFlows = snapshot.activeFlows > classifiedActive
            ? snapshot.activeFlows - classifiedActive : 0;
    }

    UnmapViewOfFile(state);
    CloseHandle(mapping);
    return snapshot;
}

std::string toJson(const Snapshot& snapshot) {
    std::ostringstream output;
    output << "{\"messageType\":\"live\",\"online\":"
           << (snapshot.online ? "true" : "false")
           << ",\"enginePid\":" << snapshot.enginePid
           << ",\"startedAt\":" << snapshot.startedAt
           << ",\"activeFlows\":" << snapshot.activeFlows
           << ",\"pendingFlows\":" << snapshot.pendingFlows
           << ",\"openedFlows\":" << snapshot.openedFlows
           << ",\"decisions\":" << snapshot.decisions
           << ",\"successfulDecisions\":" << snapshot.successfulDecisions
           << ",\"bypassedDecisions\":" << snapshot.bypassedDecisions
           << ",\"unresolvedDecisions\":" << snapshot.unresolvedDecisions
           << ",\"lastDecisionAt\":" << snapshot.lastDecisionAt
           << ",\"profiles\":[";
    bool first = true;
    for (const ProfileSnapshot& profile : snapshot.profiles) {
        if (!first) output << ',';
        first = false;
        output << "{\"name\":\"" << json::escape(profile.name)
               << "\",\"active\":" << profile.active
               << ",\"decisions\":" << profile.decisions << '}';
    }
    output << "]}";
    return output.str();
}

} // namespace live_stats
