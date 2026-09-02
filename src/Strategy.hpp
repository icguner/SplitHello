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

    // Records a bypass `profile` for `host` and persists immediately. The
    // untouched baseline (`none`) removes a stale mapping instead of filling
    // the cache with healthy destinations that need no learned state.
    //
    // What is learned depends on the verdict. A differential
    // (SniInterferenceLikely) re-verifies an existing winner; for a host
    // without one it only nominates a candidate, and a second differential
    // at least a minute later with no healthy baseline in between promotes
    // it. A cache hit (LearnedProfile) keeps a winner alive, a transient
    // failure changes nothing. `nowSeconds` of 0 means the wall clock.
    enum class Outcome {
        Ignored,      // nothing to record
        Forgotten,    // the untouched baseline retired a winner
        Candidate,    // first differential: waiting for a second one
        Learned,      // confirmed and persisted
        Reverified,   // an existing winner re-proved itself
        Refreshed,    // cache hit kept the winner alive
    };
    void remember(const std::string& host, const std::string& profile);
    Outcome remember(const std::string& networkId, const std::string& host,
                     const std::string& profile, diagnosis::Kind kind,
                     unsigned confidence, uint64_t nowSeconds = 0);

    // The untouched baseline just succeeded for `host`. A baseline failure
    // shortly afterwards is then treated as a hiccup rather than as DPI.
    void noteBaselineHealthy(const std::string& networkId, const std::string& host,
                             uint64_t nowSeconds = 0);
    bool baselineRecentlyHealthy(const std::string& networkId, const std::string& host,
                                 uint64_t nowSeconds = 0) const;

    // Degrades a cached profile after a failed re-check. Two consecutive
    // failures evict it so the next connection performs a fresh baseline.
    void recordFailure(const std::string& networkId, const std::string& host,
                       const std::string& profile);

    void forget(const std::string& host);

    // Drops every learned mapping and persists the empty store.
    void clear();

    size_t size() const;

    // Probe order for a host: the remembered profile first, then the rest.
    // A winner that has not been re-proven for a while is re-verified: the
    // untouched baseline goes first and, if it succeeds, the winner is
    // dropped. Only one connection per host starts a re-verification at a
    // time, so a burst of parallel connections does not all pay for it. A
    // pending candidate is placed right behind the baseline so confirming
    // (or clearing) it costs at most one probe timeout.
    std::vector<std::string> probeOrder(const std::string& host,
                                        const tls::ClientHello& hello);
    std::vector<std::string> probeOrder(const std::string& networkId,
                                        const std::string& host,
                                        const tls::ClientHello& hello,
                                        uint64_t nowSeconds = 0);

private:
    struct Entry {
        std::string profile;
        diagnosis::Kind kind = diagnosis::Kind::Unknown;
        unsigned confidence = 0;
        uint64_t expiresAt = 0;
        unsigned failures = 0;
        uint64_t verifiedAt = 0;          // last differential that re-proved it
        uint64_t reverifyStartedAt = 0;   // in-memory only
    };

    // A differential seen once. Never persisted: a restart simply asks for a
    // fresh pair of strikes.
    struct Candidate {
        std::string profile;
        uint64_t firstStrikeAt = 0;   // 0: legacy entry, no strike under the new rules yet
        uint64_t expiresAt = 0;
    };

    mutable std::mutex mutex_;
    std::string path_;
    std::unordered_map<std::string, Entry> entries_;
    std::unordered_map<std::string, Candidate> candidates_;

    // Most recent successful untouched baseline per scoped host. Never
    // persisted: it only needs to outlive a network hiccup.
    std::unordered_map<std::string, uint64_t> healthyAt_;

    bool saveLocked() const;
};

// Lowercased, trailing-dot-stripped host used as the store key.
std::string normalizeHost(const std::string& host);
std::string scopeKey(const std::string& networkId, const std::string& host);

} // namespace strategy
