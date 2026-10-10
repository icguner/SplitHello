#pragma once

#include "Http.hpp"
#include "RecoveryPolicy.hpp"

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// DNS resolution through the Worker's /resolve endpoint (DNS-over-HTTPS
// upstream), because the ISP resolver returns poisoned answers for blocked
// names. Results are cached for their TTL, and both A and AAAA are fetched so
// the connector has something to race.
namespace dns {

struct Result {
    std::vector<std::string> v4;
    std::vector<std::string> v6;
    unsigned ttlSeconds = 0;
    bool allowWireFallback = false;
    // RCODE the Worker reported for an empty answer (3 = NXDOMAIN), so the
    // application sees the real DNS error instead of a blanket SERVFAIL.
    uint8_t rcode = 0;
    // The lookup failed (rate limit, outage, offline) or only half succeeded
    // (one address family errored). Cached for a few seconds, never a full TTL.
    bool transient = false;

    bool empty() const { return v4.empty() && v6.empty(); }

    // Connect order per RFC 8305: one AAAA first, then alternating families.
    std::vector<std::string> candidates(size_t limit = 8) const;
};

// Test seams. `fetch` replaces http::perform (no network in unit tests) and
// `now` replaces GetTickCount64 (cache expiry without sleeping).
using Fetcher = std::function<http::Response(const http::Request&)>;
struct Hooks {
    Fetcher fetch;
    std::function<unsigned long long()> now;
};

class Resolver {
public:
    Resolver(const std::string& workerUrl, std::string sharedSecret,
             uint16_t connectPort = 0, Hooks hooks = {});
    ~Resolver();

    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;

    // Cached lookup. Returns an empty Result if the Worker could not answer,
    // in which case the caller should fall back to the system resolver.
    // `deadlineMs` (GetTickCount64 scale, 0 = none) bounds the network time.
    Result resolve(const std::string& host, unsigned long long deadlineMs = 0);

    // Authenticated DNS-over-HTTPS wire relay. The exact DNS response is
    // preserved so HTTPS/SVCB, CNAME, EDNS and future record types require no
    // client-side schema changes. Responses are cached for their TTL; the
    // returned message always carries the query's ID.
    std::vector<uint8_t> queryWire(const uint8_t* message, size_t length,
                                   unsigned long long deadlineMs = 0);

    bool isBootstrapHost(const std::string& host) const;
    void clearCache();
    size_t cacheSize() const;
    size_t wireCacheSize() const;
    bool workerUnavailable() const { return workerHealth_.unavailable(); }
    const std::string& workerHost() const { return workerHost_; }

private:
    struct Entry {
        Result result;
        unsigned long long expiresAtMs = 0;
    };

    struct WireEntry {
        std::vector<uint8_t> response;
        unsigned long long storedAtMs = 0;
        unsigned long long expiresAtMs = 0;
    };

    std::string workerHost_;
    std::string sharedSecret_;
    uint16_t connectPort_ = 0;
    Hooks hooks_;
    bool bootstrapNeeded_ = false;

    mutable std::mutex mutex_;
    std::condition_variable cacheReady_;
    std::unordered_map<std::string, Entry> cache_;
    std::unordered_map<std::string, WireEntry> wireCache_;
    std::unordered_set<std::string> inFlight_;
    mutable recovery::WorkerHealth workerHealth_;

    // Earliest time the Worker host's address list may be re-fetched, and a
    // flag so only one thread does it at a time.
    std::atomic<unsigned long long> bootstrapNextMs_{0};
    std::atomic<bool> bootstrapBusy_{false};

    unsigned long long nowMs() const;
    http::Response fetch(const http::Request& request) const;
    unsigned requestTimeoutMs(unsigned long long deadlineMs) const;

    bool lookupViaSystemResolver(Result& out) const;
    bool lookupViaDohByAddress(Result& out) const;
    void refreshBootstrap();
    bool hasBootstrap() const;
    // Gate before every Worker call: refreshes the bootstrap addresses, and
    // refuses when there is nothing to connect to, a 429 back-off is running
    // or the caller's deadline has passed.
    bool prepareWorkerCall(unsigned long long deadlineMs);
    http::Request workerRequest(const std::string& method, const std::string& path,
                                unsigned long long deadlineMs) const;
    void observe(const http::Response& response);

    Result query(const std::string& host, unsigned long long deadlineMs);
};

} // namespace dns
