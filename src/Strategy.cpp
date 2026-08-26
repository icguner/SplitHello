#include "Strategy.hpp"

#include "FileUtil.hpp"
#include "Json.hpp"

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

uint64_t nowSeconds() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
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
             diagnosis::Kind::ThrottlingSuspected}) {
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
        pos = end;

        const std::vector<std::string> fields = splitFields(encoded);
        if (key.empty() || fields.empty() || !findProfile(fields[0]) ||
            fields[0] == "none") {
            continue;
        }

        // Version 1 used a bare hostname key and a bare profile value.
        if (key.find('|') == std::string::npos) key = scopeKey(kDefaultNetwork, key);

        Entry entry;
        entry.profile = fields[0];
        entry.kind = fields.size() > 1 ? parseKind(fields[1]) : diagnosis::Kind::Unknown;
        entry.confidence = 50;
        entry.expiresAt = loadedAt + kLearningTtlSeconds;

        if (fields.size() > 2) parseUnsigned32(fields[2], entry.confidence);
        if (fields.size() > 3) parseUnsigned64(fields[3], entry.expiresAt);
        if (fields.size() > 4) parseUnsigned32(fields[4], entry.failures);
        entry.confidence = std::min(entry.confidence, 100U);

        if (entry.expiresAt > loadedAt && entries_.size() < kMaxRememberedHosts) {
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

void Store::remember(const std::string& networkId, const std::string& host,
                     const std::string& profile, diagnosis::Kind kind,
                     unsigned confidence) {
    const std::string normalizedHost = normalizeHost(host);
    if (normalizedHost.empty() || !findProfile(profile)) return;

    const std::string key = scopeKey(networkId, normalizedHost);
    if (profile == "none") {
        std::lock_guard<std::mutex> lock(mutex_);
        if (entries_.erase(key) != 0) saveLocked();
        return;
    }

    Entry replacement;
    replacement.profile = profile;
    replacement.kind = kind;
    replacement.confidence = std::min(confidence, 100U);
    replacement.expiresAt = nowSeconds() + kLearningTtlSeconds;

    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = entries_.find(key);
    if (it != entries_.end() && it->second.profile == profile &&
        it->second.expiresAt > nowSeconds()) {
        bool changed = false;
        if (it->second.failures != 0) {
            it->second.failures = 0;
            changed = true;
        }
        if (replacement.confidence > it->second.confidence) {
            it->second.confidence = replacement.confidence;
            it->second.kind = kind;
            changed = true;
        }
        if (!changed) return;
        saveLocked();
        return;
    }

    if (it == entries_.end() && entries_.size() >= kMaxRememberedHosts) {
        entries_.erase(entries_.begin()); // bounded cache; evicted paths are relearned
    }
    entries_[key] = std::move(replacement);
    saveLocked();
}

void Store::recordFailure(const std::string& networkId, const std::string& host,
                          const std::string& profile) {
    const std::string key = scopeKey(networkId, host);
    std::lock_guard<std::mutex> lock(mutex_);

    const auto it = entries_.find(key);
    if (it == entries_.end() || it->second.profile != profile) return;

    it->second.failures++;
    if (it->second.failures >= 2) {
        entries_.erase(it);
    } else {
        it->second.confidence = it->second.confidence > 20 ? it->second.confidence - 20 : 0;
    }
    saveLocked();
}

void Store::forget(const std::string& host) {
    const std::string normalized = normalizeHost(host);
    const std::string suffix = "|" + normalized;
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
    if (changed) saveLocked();
}

void Store::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    saveLocked();
}

size_t Store::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const uint64_t now = nowSeconds();
    return (size_t)std::count_if(entries_.begin(), entries_.end(),
                                 [now](const auto& item) {
                                     return item.second.expiresAt > now;
                                 });
}

std::vector<std::string> Store::probeOrder(const std::string& host,
                                           const tls::ClientHello& hello) const {
    return probeOrder(kDefaultNetwork, host, hello);
}

std::vector<std::string> Store::probeOrder(const std::string& networkId,
                                           const std::string& host,
                                           const tls::ClientHello& hello) const {
    // A ClientHello already spanning records may still be incomplete in our
    // buffer, so replaying it is unsafe.
    if (hello.spansRecords) return {"none"};

    std::vector<std::string> order;
    order.reserve(profileTable().size());
    const std::string remembered = lookup(networkId, host);

    if (!remembered.empty()) order.push_back(remembered);

    for (const Profile& p : profileTable()) {
        if (p.name == remembered) continue;
        if (p.requiresSni && !hello.hasSni()) continue;
        order.push_back(p.name);
    }
    return order;
}

bool Store::saveLocked() const {
    if (path_.empty()) return false;

    std::string content = "{\n  \"version\": 2,\n  \"domains\": {\n";
    content.reserve(content.size() + entries_.size() * 96);
    const uint64_t now = nowSeconds();
    bool first = true;
    for (const auto& [key, entry] : entries_) {
        if (entry.expiresAt <= now) continue;
        if (!first) content += ",\n";
        first = false;
        const std::string encoded = entry.profile + ";" + diagnosis::name(entry.kind) + ";" +
                                    std::to_string(entry.confidence) + ";" +
                                    std::to_string(entry.expiresAt) + ";" +
                                    std::to_string(entry.failures);
        content += "    \"" + json::escape(key) + "\": \"" + json::escape(encoded) + "\"";
    }
    content += "\n  }\n}\n";

    return fileutil::writeAtomic(path_, content);
}

} // namespace strategy
