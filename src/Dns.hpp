#pragma once

#include <cstdint>
#include <condition_variable>
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

    bool empty() const { return v4.empty() && v6.empty(); }

    // Connect order per RFC 8305: one AAAA first, then alternating families.
    std::vector<std::string> candidates(size_t limit = 8) const;
};

class Resolver {
public:
    Resolver(const std::string& workerUrl, std::string sharedSecret,
             uint16_t connectPort = 0);

    // Cached lookup. Returns an empty Result if the Worker could not answer,
    // in which case the caller should fall back to the system resolver.
    Result resolve(const std::string& host);

    // Authenticated DNS-over-HTTPS wire relay. The exact DNS response is
    // preserved so HTTPS/SVCB, CNAME, EDNS and future record types require no
    // client-side schema changes.
    std::vector<uint8_t> queryWire(const uint8_t* message, size_t length);

    void clearCache();
    size_t cacheSize() const;
    const std::string& workerHost() const { return workerHost_; }

private:
    struct Entry {
        Result result;
        unsigned long long expiresAtMs = 0;
    };

    std::string workerHost_;
    std::string sharedSecret_;
    uint16_t connectPort_ = 0;

    mutable std::mutex mutex_;
    std::condition_variable cacheReady_;
    std::unordered_map<std::string, Entry> cache_;
    std::unordered_set<std::string> inFlight_;

    Result query(const std::string& host) const;
};

} // namespace dns
