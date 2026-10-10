#include "Strategy.hpp"

#include "FileUtil.hpp"
#include "Json.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cctype>

namespace strategy {
namespace {

constexpr size_t kMaxRememberedHosts = 1000;
constexpr unsigned kSlowProfileMinDelayMs = 40;
constexpr uint64_t kLearningTtlSeconds = 7ULL * 24ULL * 60ULL * 60ULL;
constexpr const char* kDefaultNetwork = "network-default";

// A learned winner is re-proven against the untouched baseline this often.
// A false positive therefore corrects itself within one interval instead of
// living for the full TTL; a real block pays one probe timeout per interval.
constexpr uint64_t kReverifyIntervalSeconds = 30ULL * 60ULL;

// While one connection is re-verifying, parallel connections to the same host
// keep using the winner rather than all running the baseline at once.
constexpr uint64_t kReverifyHoldSeconds = 15;

// How long a successful baseline vouches for a host. DPI does not toggle
// within minutes; Wi-Fi, upstream and DNS hiccups do.
constexpr uint64_t kBaselineHealthyWindowSeconds = 15ULL * 60ULL;
constexpr size_t kMaxHealthyHosts = 4096;

// A single differential nominates; the second one confirms. Parallel
// connections fail within seconds of each other during a hiccup, so the
// confirming strike has to come from a clearly later connection.
constexpr uint64_t kConfirmMinGapSeconds = 60;
constexpr uint64_t kCandidateTtlSeconds = 6ULL * 60ULL * 60ULL;
constexpr size_t kMaxCandidates = kMaxRememberedHosts;

// Disk timestamps older/newer than this against the wall clock are not
// believed: a skewed clock or a hand-edited file must not mint immortal winners.
constexpr uint64_t kClockSkewSeconds = 5ULL * 60ULL;

// Wall clock: only for what is persisted (verifiedAt, expiresAt).
uint64_t nowSeconds() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Monotonic clock for in-memory gaps. Never 0, so 0 stays usable as "unset".
uint64_t monoSeconds() {
    return 1 + (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// An explicit time (tests) drives both clocks; 0 means the real ones.
uint64_t resolveNow(uint64_t explicitSeconds) {
    return explicitSeconds != 0 ? explicitSeconds : nowSeconds();
}

uint64_t resolveMono(uint64_t explicitSeconds) {
    return explicitSeconds != 0 ? explicitSeconds : monoSeconds();
}

// A nomination from this run lives on the monotonic clock. One loaded from
// disk that has not had a strike yet has no monotonic stamps, so it lives on
// its persisted wall-clock expiry instead.
template <class CandidateT>
bool candidateLive(const CandidateT& candidate, uint64_t wallNow, uint64_t monoNow) {
    return candidate.firstStrikeAt == 0 ? candidate.persistUntil > wallNow
                                        : candidate.expiresAt > monoNow;
}

bool parseUnsigned64(const std::string& text, uint64_t& value) {
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool parseUnsigned32(const std::string& text, unsigned& value) {
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

diagnosis::Kind parseKind(const std::string& text) {
    for (const diagnosis::Kind kind : {
             diagnosis::Kind::Unknown,
             diagnosis::Kind::NoInterference,
             diagnosis::Kind::SniInterferenceLikely,
             diagnosis::Kind::TlsIncompatible,
             diagnosis::Kind::TransportFailure,
             diagnosis::Kind::ThrottlingSuspected,
             diagnosis::Kind::LearnedProfile,
             diagnosis::Kind::TransientFailure,
             diagnosis::Kind::InterferenceSuspected}) {
        if (text == diagnosis::name(kind)) return kind;
    }
    return diagnosis::Kind::Unknown;
}

std::vector<std::string> splitFields(const std::string& encoded) {
    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= encoded.size()) {
        const size_t end = encoded.find(';', start);
        fields.push_back(encoded.substr(start, end - start));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return fields;
}

const std::vector<Profile>& profileTable() {
    // Unknown paths begin with a differential baseline. If it succeeds we do
    // not manipulate that destination at all. Known paths promote their cached
    // winner ahead of this table in Store::probeOrder.
    static const std::vector<Profile> table = {
        {"none",         "Send the ClientHello untouched (diagnostic baseline)", false},
        {"sni-mid",      "Split one TLS record in the middle of the SNI hostname", true},
        {"record-1",     "Split after the first payload byte (cuts the handshake header)", false},
        {"packet-reverse", "Send TCP ClientHello segments in reverse sequence order", false},
        {"packet-ipfrag", "Split the IPv4 packet below TCP (IPv6 uses reverse disorder)", false},
        {"packet-fake-badseq", "Precede ClientHello with an out-of-window cover SNI", false},
        {"packet-autottl", "Expire a cover ClientHello immediately before the server", false},
        {"packet-seqovl", "Mix cover bytes into an out-of-order sequence overlap", false},
        {"sni-pre",      "Split immediately before the SNI hostname starts", true},
        {"sni-multi",    "Four cuts: header, before, inside and after the hostname", true},
        {"packet-fake-badsum", "Precede ClientHello with an invalid-checksum cover SNI", false},
        {"sni-mid-slow", "SNI split plus 4-byte writes and a longer pause", true},
    };
    return table;
}

// Drop out-of-range cuts, sort, dedupe.
void sanitize(std::vector<size_t>& splits, size_t payloadLength) {
    splits.erase(std::remove_if(splits.begin(), splits.end(),
                                [payloadLength](size_t s) {
                                    return s < 1 || s >= payloadLength;
                                }),
                 splits.end());
    std::sort(splits.begin(), splits.end());
    splits.erase(std::unique(splits.begin(), splits.end()), splits.end());
}

} // namespace

const std::vector<Profile>& profiles() { return profileTable(); }

const Profile* findProfile(const std::string& name) {
    for (const Profile& p : profileTable()) {
        if (p.name == name) return &p;
    }
    return nullptr;
}

std::string normalizeHost(const std::string& host) {
    std::string out = host;
    while (!out.empty() && out.back() == '.') out.pop_back();
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return out;
}

std::string scopeKey(const std::string& networkId, const std::string& host) {
    const std::string normalizedHost = normalizeHost(host);
    const std::string network = networkId.empty() ? kDefaultNetwork : networkId;
    return network + "|" + normalizedHost;
}

bool buildPlan(const std::string& profileName,
               const tls::ClientHello& hello,
               unsigned baseDelayMs,
               FragmentPlan& out) {
    out = FragmentPlan{};

    const Profile* profile = findProfile(profileName);
    if (!profile) return false;

    if (profileName == "none") return true;
    if (profileName.starts_with("packet-")) return true;

    // A hello the client already split must be forwarded byte for byte. Merely
    // seeing the ECH extension is not enough to skip: Chromium sends GREASE ECH
    // even when the DNS HTTPS record contains no ECH configuration.
    if (hello.spansRecords) return false;
    if (profile->requiresSni && !hello.hasSni()) return false;

    const size_t payloadLength = hello.recordPayloadLength;
    if (payloadLength < 2) return false;

    // SNI offsets are absolute; the plan speaks in payload offsets.
    const size_t sniStart = hello.hasSni() ? hello.sniOffset - tls::kRecordHeaderSize : 0;
    const size_t sniMiddle = sniStart + hello.sniLength / 2;
    const size_t sniEnd = sniStart + hello.sniLength;

    out.delayMs = baseDelayMs;

    if (profileName == "sni-mid") {
        out.recordSplits = {sniMiddle};
    } else if (profileName == "record-1") {
        out.recordSplits = {1};
    } else if (profileName == "sni-pre") {
        out.recordSplits = {sniStart};
    } else if (profileName == "sni-multi") {
        out.recordSplits = {1, sniStart, sniMiddle, sniEnd};
    } else if (profileName == "sni-mid-slow") {
        out.recordSplits = {sniMiddle};
        out.writeChunk = 4;
        out.delayMs = std::max(baseDelayMs * 2, kSlowProfileMinDelayMs);
    } else {
        return false;
    }

    sanitize(out.recordSplits, payloadLength);
    return out.splitsAnything();
}

// ---- Store ----

Store::Store(std::string path) : path_(std::move(path)) {}

void Store::load() {
    std::string content;
    if (path_.empty() || !fileutil::readAll(path_, content)) return;

    const std::string domains = json::getRaw(content, "domains");
    if (domains.empty() || domains.front() != '{') return;

    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    candidates_.clear();

    const uint64_t loadedAt = nowSeconds();
    size_t pos = 1; // just past '{'
    while (pos < domains.size()) {
        pos = json::skipWs(domains, pos);
        if (pos >= domains.size() || domains[pos] == '}') break;
        if (domains[pos] == ',') { pos++; continue; }
        if (domains[pos] != '"') break;

        size_t end = 0;
        std::string key = json::parseString(domains, pos, end);
        pos = json::skipWs(domains, end);
        if (pos >= domains.size() || domains[pos] != ':') break;

        pos = json::skipWs(domains, pos + 1);
        if (pos >= domains.size() || domains[pos] != '"') break;
        const std::string encoded = json::parseString(domains, pos, end);
        // A value cut off by a torn write has no closing quote: do not trust it.
        if (end < pos + 2 || domains[end - 1] != '"') break;
        pos = end;

        const std::vector<std::string> fields = splitFields(encoded);
        if (key.empty() || fields.empty() || !findProfile(fields[0]) ||
            fields[0] == "none") {
            continue;
        }

        // Version 1 used a bare hostname key and a bare profile value. It has
        // no network to scope to, so it stays under the default network (real
        // sessions use an nla- id and never match it; it only ages out).
        if (key.find('|') == std::string::npos) key = scopeKey(kDefaultNetwork, key);

        Entry entry;
        entry.profile = fields[0];
        entry.kind = fields.size() > 1 ? parseKind(fields[1]) : diagnosis::Kind::Unknown;
        entry.confidence = 50;
        entry.expiresAt = loadedAt + kLearningTtlSeconds;

        if (fields.size() > 2) parseUnsigned32(fields[2], entry.confidence);
        if (fields.size() > 3) parseUnsigned64(fields[3], entry.expiresAt);
        if (fields.size() > 4) parseUnsigned32(fields[4], entry.failures);
        if (fields.size() > 5) parseUnsigned64(fields[5], entry.verifiedAt);
        entry.confidence = std::min(entry.confidence, 100U);

        // Nothing on disk may outlive one TTL from now, and a verification
        // stamp from the future (clock was wrong when written) proves nothing.
        entry.expiresAt = std::min(entry.expiresAt, loadedAt + kLearningTtlSeconds);
        if (entry.verifiedAt > loadedAt + kClockSkewSeconds) entry.verifiedAt = 0;

        if (entry.expiresAt <= loadedAt) continue;
        if (entry.verifiedAt == 0) {
            // Written before winners needed a second differential. Keep it as
            // a candidate: its first use re-tests the baseline instead of
            // trusting a verdict that may have come from a hiccup. It is
            // written back on save until promoted, cancelled or expired.
            if (candidates_.size() < kMaxCandidates) {
                candidates_[key] = {entry.profile, 0, 0, entry.expiresAt};
            }
        } else if (entries_.size() < kMaxRememberedHosts) {
            entries_[key] = std::move(entry);
        }
    }
}

std::string Store::lookup(const std::string& host) const {
    return lookup(kDefaultNetwork, host);
}

std::string Store::lookup(const std::string& networkId, const std::string& host) const {
    const std::string key = scopeKey(networkId, host);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = entries_.find(key);
    if (it == entries_.end() || it->second.expiresAt <= nowSeconds()) return {};
    return it->second.profile;
}

void Store::remember(const std::string& host, const std::string& profile) {
    remember(kDefaultNetwork, host, profile, diagnosis::Kind::Unknown, 50);
}

Store::Outcome Store::remember(const std::string& networkId, const std::string& host,
                               const std::string& profile, diagnosis::Kind kind,
                               unsigned confidence, uint64_t nowSeconds_) {
    Snapshot snapshot;
    Outcome outcome;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        bool dirty = false;
        outcome = rememberLocked(networkId, host, profile, kind, confidence,
                                 nowSeconds_, dirty);
        if (dirty) snapshot = snapshotLocked();
    }
    commit(snapshot); // disk I/O happens outside mutex_
    return outcome;
}

Store::Outcome Store::rememberLocked(const std::string& networkId, const std::string& host,
                                     const std::string& profile, diagnosis::Kind kind,
                                     unsigned confidence, uint64_t explicitNow,
                                     bool& dirty) {
    const std::string normalizedHost = normalizeHost(host);
    if (normalizedHost.empty() || !findProfile(profile)) return Outcome::Ignored;

    const uint64_t now = resolveNow(explicitNow);
    const uint64_t mono = resolveMono(explicitNow);
    const std::string key = scopeKey(networkId, normalizedHost);
    if (profile == "none") {
        const bool hadEntry = entries_.erase(key) != 0;
        const auto candidate = candidates_.find(key);
        const bool hadPersistedCandidate =
            candidate != candidates_.end() && candidate->second.persistUntil != 0;
        if (candidate != candidates_.end()) candidates_.erase(candidate);
        dirty = hadEntry || hadPersistedCandidate;
        return hadEntry ? Outcome::Forgotten : Outcome::Ignored;
    }

    // A hiccup is not a bypass. Whatever profile happened to be tried when the
    // path came back must not become the remembered winner.
    if (kind == diagnosis::Kind::TransientFailure) return Outcome::Ignored;

    const auto it = entries_.find(key);
    const bool live = it != entries_.end() && it->second.expiresAt > now;

    if (kind == diagnosis::Kind::LearnedProfile) {
        // The winner worked again without a fresh baseline. That keeps it
        // alive, but it can neither create a winner nor count as re-proof.
        if (!live || it->second.profile != profile) return Outcome::Ignored;
        if (it->second.failures != 0) {
            it->second.failures = 0;
            dirty = true;
        }
        return Outcome::Refreshed;
    }

    if (live && it->second.profile == profile) {
        // A confirmed winner re-proved itself against a fresh baseline.
        it->second.failures = 0;
        it->second.verifiedAt = now;
        it->second.reverifyStartedAt = 0;
        it->second.expiresAt = now + kLearningTtlSeconds;
        if (confidence > it->second.confidence) {
            it->second.confidence = std::min(confidence, 100U);
            it->second.kind = kind;
        }
        dirty = true;
        return Outcome::Reverified;
    }

    if (kind == diagnosis::Kind::SniInterferenceLikely) {
        // One differential nominates; a second one at least a minute later,
        // with no healthy baseline in between, confirms. A hiccup fails a
        // burst of parallel connections within seconds and is usually gone
        // before a later connection could reproduce it.
        auto candidate = candidates_.find(key);
        if (candidate != candidates_.end() && !candidateLive(candidate->second, now, mono)) {
            candidates_.erase(candidate);
            candidate = candidates_.end();
        }
        if (candidate == candidates_.end()) {
            makeRoomForCandidateLocked(now, mono);
            candidates_[key] = {profile, mono, mono + kCandidateTtlSeconds, 0};
            return Outcome::Candidate;
        }
        Candidate& pending = candidate->second;
        pending.profile = profile; // the latest winner is the one worth keeping
        if (pending.firstStrikeAt == 0) {
            // Legacy entry: this was its first real strike.
            pending.firstStrikeAt = mono;
            pending.expiresAt = mono + kCandidateTtlSeconds;
            return Outcome::Candidate;
        }
        if (mono < pending.firstStrikeAt + kConfirmMinGapSeconds) return Outcome::Candidate;
        candidates_.erase(candidate);
    }

    Entry replacement;
    replacement.profile = profile;
    replacement.kind = kind;
    replacement.confidence = std::min(confidence, 100U);
    replacement.expiresAt = now + kLearningTtlSeconds;
    replacement.verifiedAt = now;

    if (it == entries_.end()) makeRoomForEntryLocked(now); // bounded cache; evicted paths are relearned
    candidates_.erase(key); // a winner supersedes any pending nomination
    entries_[key] = std::move(replacement);
    dirty = true;
    return Outcome::Learned;
}

// Expired winners go first; only then the one verified longest ago, so a
// freshly proven path is never the victim.
void Store::makeRoomForEntryLocked(uint64_t wallNow) {
    if (entries_.size() < kMaxRememberedHosts) return;
    std::erase_if(entries_, [wallNow](const auto& item) {
        return item.second.expiresAt <= wallNow;
    });
    if (entries_.size() < kMaxRememberedHosts) return;

    const auto oldest = std::min_element(
        entries_.begin(), entries_.end(), [](const auto& a, const auto& b) {
            return a.second.verifiedAt < b.second.verifiedAt;
        });
    if (oldest != entries_.end()) entries_.erase(oldest);
}

// Same policy for pending nominations: expired first, then the stalest strike
// (legacy entries carry no strike and go before any real one).
void Store::makeRoomForCandidateLocked(uint64_t wallNow, uint64_t monoNow) {
    if (candidates_.size() < kMaxCandidates) return;
    std::erase_if(candidates_, [wallNow, monoNow](const auto& item) {
        return !candidateLive(item.second, wallNow, monoNow);
    });
    if (candidates_.size() < kMaxCandidates) return;

    const auto oldest = std::min_element(
        candidates_.begin(), candidates_.end(), [](const auto& a, const auto& b) {
            return a.second.firstStrikeAt < b.second.firstStrikeAt;
        });
    if (oldest != candidates_.end()) candidates_.erase(oldest);
}

void Store::noteBaselineHealthy(const std::string& networkId, const std::string& host,
                                uint64_t nowSeconds_) {
    const uint64_t now = resolveMono(nowSeconds_);
    const std::string key = scopeKey(networkId, host);
    Snapshot snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // The path is fine; the earlier strike was a hiccup.
        const auto candidate = candidates_.find(key);
        if (candidate != candidates_.end()) {
            const bool persisted = candidate->second.persistUntil != 0;
            candidates_.erase(candidate);
            if (persisted) snapshot = snapshotLocked();
        }
        if (healthyAt_.size() >= kMaxHealthyHosts && !healthyAt_.contains(key)) {
            std::erase_if(healthyAt_, [now](const auto& item) {
                return item.second + kBaselineHealthyWindowSeconds <= now;
            });
            if (healthyAt_.size() >= kMaxHealthyHosts) healthyAt_.erase(healthyAt_.begin());
        }
        healthyAt_[key] = now;
    }
    commit(snapshot);
}

bool Store::baselineRecentlyHealthy(const std::string& networkId, const std::string& host,
                                    uint64_t nowSeconds_) const {
    const uint64_t now = resolveMono(nowSeconds_);
    const std::string key = scopeKey(networkId, host);
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = healthyAt_.find(key);
    return it != healthyAt_.end() && it->second <= now &&
           it->second + kBaselineHealthyWindowSeconds > now;
}

void Store::recordFailure(const std::string& networkId, const std::string& host,
                          const std::string& profile) {
    const std::string key = scopeKey(networkId, host);
    Snapshot snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);

        const auto it = entries_.find(key);
        if (it == entries_.end() || it->second.profile != profile) return;

        it->second.failures++;
        if (it->second.failures >= 2) {
            entries_.erase(it);
        } else {
            it->second.confidence = it->second.confidence > 20 ? it->second.confidence - 20 : 0;
        }
        snapshot = snapshotLocked();
    }
    commit(snapshot);
}

void Store::forget(const std::string& host) {
    const std::string normalized = normalizeHost(host);
    const std::string suffix = "|" + normalized;
    Snapshot snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        bool changed = false;
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (it->first.ends_with(suffix)) {
                it = entries_.erase(it);
                changed = true;
            } else {
                ++it;
            }
        }
        for (auto it = candidates_.begin(); it != candidates_.end();) {
            if (it->first.ends_with(suffix)) {
                if (it->second.persistUntil != 0) changed = true;
                it = candidates_.erase(it);
            } else {
                ++it;
            }
        }
        if (changed) snapshot = snapshotLocked();
    }
    commit(snapshot);
}

void Store::clear() {
    Snapshot snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
        candidates_.clear();
        healthyAt_.clear();
        snapshot = snapshotLocked();
    }
    commit(snapshot);
}

size_t Store::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t now = nowSeconds();
    return (size_t)std::count_if(entries_.begin(), entries_.end(),
                                 [now](const auto& item) {
                                     return item.second.expiresAt > now;
                                 });
}

size_t Store::candidateCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return candidates_.size();
}

std::vector<std::string> Store::probeOrder(const std::string& host,
                                           const tls::ClientHello& hello) {
    return probeOrder(kDefaultNetwork, host, hello);
}

std::vector<std::string> Store::probeOrder(const std::string& networkId,
                                           const std::string& host,
                                           const tls::ClientHello& hello,
                                           uint64_t nowSeconds_) {
    // A ClientHello already spanning records may still be incomplete in our
    // buffer, so replaying it is unsafe.
    if (hello.spansRecords) return {"none"};

    const uint64_t now = resolveNow(nowSeconds_);
    const uint64_t mono = resolveMono(nowSeconds_);
    std::string remembered;
    std::string pending;
    bool reverify = false;
    {
        const std::string key = scopeKey(networkId, host);
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = entries_.find(key);
        if (it != entries_.end() && it->second.expiresAt > now) {
            Entry& entry = it->second;
            remembered = entry.profile;
            // A stamp far in the future means the wall clock stepped back;
            // treat the winner as overdue instead of waiting out the step.
            const bool due = entry.verifiedAt > now + kClockSkewSeconds ||
                             entry.verifiedAt + kReverifyIntervalSeconds <= now;
            if (due && (entry.reverifyStartedAt == 0 ||
                        entry.reverifyStartedAt + kReverifyHoldSeconds <= mono)) {
                entry.reverifyStartedAt = mono;
                reverify = true;
            }
        } else {
            const auto candidate = candidates_.find(key);
            if (candidate != candidates_.end() &&
                candidateLive(candidate->second, now, mono)) {
                pending = candidate->second.profile;
            }
        }
    }

    std::vector<std::string> order;
    order.reserve(profileTable().size() + 1);

    // Re-verification and candidate confirmation both lead with the baseline
    // and retry with the profile in question, so a host that is really
    // blocked pays exactly one probe timeout.
    std::string lead = remembered;
    bool baselineQueued = false;
    if (!remembered.empty()) {
        if (reverify) {
            order.push_back("none");
            baselineQueued = true;
        }
        order.push_back(remembered);
    } else if (!pending.empty()) {
        order.push_back("none");
        baselineQueued = true;
        order.push_back(pending);
        lead = pending;
    }

    for (const Profile& p : profileTable()) {
        if (p.name == lead) continue;
        if (baselineQueued && p.name == "none") continue;
        if (p.requiresSni && !hello.hasSni()) continue;
        order.push_back(p.name);
    }
    return order;
}

Store::Snapshot Store::snapshotLocked() {
    if (path_.empty()) return {};

    std::string content = "{\n  \"version\": 2,\n  \"domains\": {\n";
    content.reserve(content.size() + (entries_.size() + candidates_.size()) * 96);
    const uint64_t now = nowSeconds();
    bool first = true;
    const auto append = [&](const std::string& key, const std::string& encoded) {
        if (!first) content += ",\n";
        first = false;
        content += "    \"" + json::escape(key) + "\": \"" + json::escape(encoded) + "\"";
    };

    for (const auto& [key, entry] : entries_) {
        if (entry.expiresAt <= now) continue;
        append(key, entry.profile + ";" + diagnosis::name(entry.kind) + ";" +
                    std::to_string(entry.confidence) + ";" +
                    std::to_string(entry.expiresAt) + ";" +
                    std::to_string(entry.failures) + ";" +
                    std::to_string(entry.verifiedAt));
    }
    // Legacy nominations keep their verifiedAt==0 shape, so a reload brings
    // them back as candidates until they are promoted, cancelled or expire.
    for (const auto& [key, candidate] : candidates_) {
        if (candidate.persistUntil <= now || entries_.contains(key)) continue;
        append(key, candidate.profile + ";" + diagnosis::name(diagnosis::Kind::Unknown) +
                    ";50;" + std::to_string(candidate.persistUntil) + ";0;0");
    }
    content += "\n  }\n}\n";

    return {++nextSeq_, std::move(content)};
}

void Store::commit(const Snapshot& snapshot) {
    if (snapshot.seq == 0) return;

    std::lock_guard<std::mutex> lock(writeMutex_);
    // Snapshots are complete states: if a newer one already reached the disk,
    // writing this one would roll the file back.
    if (snapshot.seq <= writtenSeq_) return;

    if (fileutil::writeAtomic(path_, snapshot.text)) {
        writtenSeq_ = snapshot.seq;
        saveFailing_ = false;
    } else if (!saveFailing_.exchange(true)) {
        // Once per failure burst; the next successful save restores the file.
        spdlog::warn("Strateji dosyasi yazilamadi: {}", path_);
    }
}

} // namespace strategy
