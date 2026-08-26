#pragma once

#include "Diagnosis.hpp"
#include "TlsHello.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Fragmentation strategies.
//
// A single split point does not defeat every DPI box: some reassemble TLS
// records, some only look at the first TCP segment, some key on the record
// boundary itself. GoodbyeDPI and zapret both ship a set of desync profiles
// for exactly this reason. We do the same and, instead of asking the user to
// pick, probe them in order and remember what worked per domain.
namespace strategy {

// A concrete set of cuts for one ClientHello.
struct FragmentPlan {
    // Offsets *within the record payload* (0 == first byte after the 5-byte
    // record header) where a new TLS record starts. Ascending, deduped, and
    // always strictly inside the payload.
    std::vector<size_t> recordSplits;

    // If non-zero, each record is written in pieces of at most this many bytes
    // so the TCP segmentation is broken up as well as the record framing.
    size_t writeChunk = 0;

    // Pause between records, milliseconds. Keeps the segments from coalescing
    // and defeats DPI that only buffers for a short window.
    unsigned delayMs = 0;

    bool splitsAnything() const { return !recordSplits.empty(); }
};

struct Profile {
    std::string name;
    std::string description;
    bool requiresSni = false;
};

// Probe order: an unknown path starts with an untouched baseline. A learned
// profile is promoted to the front on later connections.
const std::vector<Profile>& profiles();

const Profile* findProfile(const std::string& name);

// Turn a profile into a plan for this particular hello.
// Returns false when the profile cannot apply (needs an SNI that isn't there,
// or the record is too small to cut).
bool buildPlan(const std::string& profileName,
               const tls::ClientHello& hello,
               unsigned baseDelayMs,
               FragmentPlan& out);

// Remembers which profile got through for each domain, so the probe cost is
// paid once rather than on every connection. Persisted next to the config.
class Store {
public:
    explicit Store(std::string path);

    // Reads the file if present. Missing or corrupt files start empty.
    void load();

    // Profile name previously recorded for `host`, or empty.
    std::string lookup(const std::string& host) const;
    std::string lookup(const std::string& networkId, const std::string& host) const;

    // Records `profile` for `host` and persists immediately (writes are rare -
    // only when a domain's winning profile actually changes).
    void remember(const std::string& host, const std::string& profile);
    void remember(const std::string& networkId, const std::string& host,
                  const std::string& profile, diagnosis::Kind kind,
                  unsigned confidence);

    // Degrades a cached profile after a failed re-check. Two consecutive
    // failures evict it so the next connection performs a fresh baseline.
    void recordFailure(const std::string& networkId, const std::string& host,
                       const std::string& profile);

    void forget(const std::string& host);

    // Drops every learned mapping and persists the empty store.
    void clear();

    size_t size() const;

    // Probe order for a host: the remembered profile first, then the rest.
    std::vector<std::string> probeOrder(const std::string& host,
                                        const tls::ClientHello& hello) const;
    std::vector<std::string> probeOrder(const std::string& networkId,
                                        const std::string& host,
                                        const tls::ClientHello& hello) const;

private:
    struct Entry {
        std::string profile;
        diagnosis::Kind kind = diagnosis::Kind::Unknown;
        unsigned confidence = 0;
        uint64_t expiresAt = 0;
        unsigned failures = 0;
    };

    mutable std::mutex mutex_;
    std::string path_;
    std::unordered_map<std::string, Entry> entries_;

    bool saveLocked() const;
};

// Lowercased, trailing-dot-stripped host used as the store key.
std::string normalizeHost(const std::string& host);
std::string scopeKey(const std::string& networkId, const std::string& host);

} // namespace strategy
