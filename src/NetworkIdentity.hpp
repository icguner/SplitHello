#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <string>

namespace network_identity {

inline constexpr const char* kDefaultId = "network-default";

// Returns an opaque, local-only identifier for the set of Windows network
// profiles currently connected. Learned strategies are scoped by this value
// so a rule learned on home broadband is not blindly reused on a hotspot/VPN.
// Initialises COM and queries the network list on every call: use
// currentCached() on per-connection paths.
std::string current();

// current() refreshed at most every ~30 s; safe to call from any thread. If a
// refresh finds nothing (COM failure, or no connected network) the last known
// identity is kept so a brief outage does not rescope learned strategies.
std::string currentCached();

// The cache behind currentCached(), with the fetch and the clock injectable.
// While one thread refreshes, others keep getting the previous value instead
// of queueing behind the COM call.
class CachedIdentity {
public:
    using Clock = std::chrono::steady_clock;
    using Fetch = std::function<std::string()>;

    CachedIdentity(Fetch fetch, std::chrono::milliseconds ttl)
        : fetch_(std::move(fetch)), ttl_(ttl) {}

    std::string get(Clock::time_point now = Clock::now());

private:
    Fetch fetch_;
    std::chrono::milliseconds ttl_;

    std::mutex mutex_;
    std::string value_;               // last known identity; empty before the first fetch
    Clock::time_point fetchedAt_{};
    bool refreshing_ = false;
};

} // namespace network_identity
