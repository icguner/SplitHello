#include "ProcessFilter.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tcpmib.h>

namespace process_filter {
namespace {

constexpr size_t kMaximumRules = 128;
constexpr size_t kMaximumRuleLength = 1024;
constexpr size_t kMaximumCachedEndpoints = 8192;
constexpr uint64_t kTcpCacheTtlMs = 10ULL * 60ULL * 1000ULL;
constexpr uint64_t kUdpCacheTtlMs = 2ULL * 60ULL * 1000ULL;
constexpr uint64_t kUnknownCacheTtlMs = 1000;
constexpr uint64_t kProcessNameTtlMs = 30ULL * 1000ULL;

std::string normalize(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1);
    if (value.size() > kMaximumRuleLength) return {};

    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char ch) { return (char)std::tolower(ch); });
    std::replace(result.begin(), result.end(), '/', '\\');
    return result;
}

// `rejected` counts non-blank patterns that could not be kept (too long, or
// past the rule cap), so a silently emptied list can be told from a blank one.
std::vector<std::string> normalizeRules(std::vector<std::string> values,
                                        size_t& rejected) {
    std::vector<std::string> result;
    result.reserve(std::min(values.size(), kMaximumRules));
    for (const std::string& value : values) {
        std::string normalized = normalize(value);
        if (normalized.empty()) {
            if (value.find_first_not_of(" \t\r\n") != std::string::npos) ++rejected;
            continue;
        }
        if (std::find(result.begin(), result.end(), normalized) != result.end()) {
            continue;
        }
        if (result.size() == kMaximumRules) {
            ++rejected;
            continue;
        }
        result.push_back(std::move(normalized));
    }
    return result;
}

bool wildcardMatch(std::string_view pattern, std::string_view text) {
    size_t patternIndex = 0;
    size_t textIndex = 0;
    size_t starIndex = std::string_view::npos;
    size_t retryTextIndex = 0;

    while (textIndex < text.size()) {
        if (patternIndex < pattern.size() &&
            (pattern[patternIndex] == '?' ||
             pattern[patternIndex] == text[textIndex])) {
            ++patternIndex;
            ++textIndex;
        } else if (patternIndex < pattern.size() &&
                   pattern[patternIndex] == '*') {
            starIndex = patternIndex++;
            retryTextIndex = textIndex;
        } else if (starIndex != std::string_view::npos) {
            patternIndex = starIndex + 1;
            textIndex = ++retryTextIndex;
        } else {
            return false;
        }
    }

    while (patternIndex < pattern.size() && pattern[patternIndex] == '*') {
        ++patternIndex;
    }
    return patternIndex == pattern.size();
}

bool matchesAny(const std::vector<std::string>& patterns,
                std::string_view fullPath,
                std::string_view basename) {
    for (const std::string& pattern : patterns) {
        const bool fullPathPattern = pattern.find('\\') != std::string::npos;
        if (wildcardMatch(pattern, fullPathPattern ? fullPath : basename)) {
            return true;
        }
    }
    return false;
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                              (int)value.size(), nullptr, 0,
                                              nullptr, nullptr);
    if (required <= 0) return {};
    std::string result((size_t)required, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), (int)value.size(),
                        result.data(), required, nullptr, nullptr);
    return result;
}

std::string processImage(DWORD processId) {
    if (processId == 0) return {};
    if (processId == 4) return "system";

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                 processId);
    if (!process) return {};

    std::wstring path(32768, L'\0');
    DWORD length = (DWORD)path.size();
    const BOOL ok = QueryFullProcessImageNameW(process, 0, path.data(), &length);
    CloseHandle(process);
    if (!ok || length == 0) return {};
    path.resize(length);
    return normalize(utf8(path));
}

uint16_t tablePort(DWORD value) {
    return ntohs((uint16_t)value);
}

bool zeroAddress(const uint8_t* address, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (address[i] != 0) return false;
    }
    return true;
}

// The connection table can grow between the size query and the fetch (a burst
// of new connections is exactly when this runs), so the buffer is padded and
// the fetch retried instead of treating the race as "owner unknown".
template <typename Fetch>
std::optional<std::vector<uint8_t>> fetchTable(Fetch fetch) {
    constexpr int kAttempts = 4;
    DWORD size = 0;
    DWORD status = fetch(nullptr, &size);
    for (int attempt = 0; attempt < kAttempts &&
                          status == ERROR_INSUFFICIENT_BUFFER && size != 0;
         ++attempt) {
        size += size / 8 + 4096;
        std::vector<uint8_t> bytes(size);
        DWORD length = size;
        status = fetch(bytes.data(), &length);
        if (status == NO_ERROR) return bytes;
        size = length;
    }
    return std::nullopt;
}

template <typename Table>
std::optional<std::vector<uint8_t>> ownerTable(
    ULONG family, TCP_TABLE_CLASS tableClass) {
    auto bytes = fetchTable([&](void* buffer, DWORD* length) -> DWORD {
        return GetExtendedTcpTable(buffer, length, FALSE, family, tableClass, 0);
    });
    if (!bytes || bytes->size() < sizeof(Table)) return std::nullopt;
    return bytes;
}

std::optional<DWORD> tcpOwner(const Endpoint& endpoint) {
    if (!endpoint.ipv6) {
        auto bytes = ownerTable<MIB_TCPTABLE_OWNER_PID>(
            AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (!bytes) return std::nullopt;
        const auto* table =
            reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(bytes->data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (tablePort(row.dwLocalPort) != endpoint.localPort ||
                tablePort(row.dwRemotePort) != endpoint.remotePort) {
                continue;
            }
            if (std::memcmp(&row.dwLocalAddr, endpoint.localAddress.data(), 4) == 0 &&
                std::memcmp(&row.dwRemoteAddr, endpoint.remoteAddress.data(), 4) == 0) {
                return row.dwOwningPid;
            }
        }
        return std::nullopt;
    }

    auto bytes = ownerTable<MIB_TCP6TABLE_OWNER_PID>(
        AF_INET6, TCP_TABLE_OWNER_PID_ALL);
    if (!bytes) return std::nullopt;
    const auto* table =
        reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(bytes->data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (tablePort(row.dwLocalPort) == endpoint.localPort &&
            tablePort(row.dwRemotePort) == endpoint.remotePort &&
            std::memcmp(row.ucLocalAddr, endpoint.localAddress.data(), 16) == 0 &&
            std::memcmp(row.ucRemoteAddr, endpoint.remoteAddress.data(), 16) == 0) {
            return row.dwOwningPid;
        }
    }
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> udpOwnerTable(ULONG family,
                                                  UDP_TABLE_CLASS tableClass) {
    return fetchTable([&](void* buffer, DWORD* length) -> DWORD {
        return GetExtendedUdpTable(buffer, length, FALSE, family, tableClass, 0);
    });
}

template <typename Row>
void selectUdpOwner(DWORD candidate, const Row&, std::optional<DWORD>& selected,
                    bool& ambiguous) {
    if (!selected) {
        selected = candidate;
    } else if (*selected != candidate) {
        ambiguous = true;
    }
}

std::optional<DWORD> udpOwner(const Endpoint& endpoint) {
    std::optional<DWORD> selected;
    bool ambiguous = false;

    if (!endpoint.ipv6) {
        auto bytes = udpOwnerTable(AF_INET, UDP_TABLE_OWNER_PID);
        if (!bytes || bytes->size() < sizeof(MIB_UDPTABLE_OWNER_PID)) {
            return std::nullopt;
        }
        const auto* table =
            reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(bytes->data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (tablePort(row.dwLocalPort) != endpoint.localPort) continue;
            const auto* address = reinterpret_cast<const uint8_t*>(&row.dwLocalAddr);
            if (!zeroAddress(address, 4) &&
                std::memcmp(address, endpoint.localAddress.data(), 4) != 0) {
                continue;
            }
            selectUdpOwner(row.dwOwningPid, row, selected, ambiguous);
        }
    } else {
        auto bytes = udpOwnerTable(AF_INET6, UDP_TABLE_OWNER_PID);
        if (!bytes || bytes->size() < sizeof(MIB_UDP6TABLE_OWNER_PID)) {
            return std::nullopt;
        }
        const auto* table =
            reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(bytes->data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            if (tablePort(row.dwLocalPort) != endpoint.localPort) continue;
            if (!zeroAddress(row.ucLocalAddr, 16) &&
                std::memcmp(row.ucLocalAddr, endpoint.localAddress.data(), 16) != 0) {
                continue;
            }
            selectUdpOwner(row.dwOwningPid, row, selected, ambiguous);
        }
    }

    return ambiguous ? std::nullopt : selected;
}

struct EndpointHash {
    size_t operator()(const Endpoint& endpoint) const noexcept {
        uint64_t hash = 1469598103934665603ULL;
        const auto add = [&hash](uint8_t value) {
            hash ^= value;
            hash *= 1099511628211ULL;
        };
        add(endpoint.ipv6 ? 1 : 0);
        add((uint8_t)endpoint.protocol);
        const size_t addressLength = endpoint.ipv6 ? 16 : 4;
        for (size_t i = 0; i < addressLength; ++i) add(endpoint.localAddress[i]);
        for (size_t i = 0; i < addressLength; ++i) add(endpoint.remoteAddress[i]);
        add((uint8_t)(endpoint.localPort >> 8));
        add((uint8_t)endpoint.localPort);
        add((uint8_t)(endpoint.remotePort >> 8));
        add((uint8_t)endpoint.remotePort);
        return (size_t)hash;
    }
};

} // namespace

bool operator==(const Endpoint& left, const Endpoint& right) noexcept {
    if (left.ipv6 != right.ipv6 || left.protocol != right.protocol ||
        left.localPort != right.localPort ||
        left.remotePort != right.remotePort) {
        return false;
    }
    const size_t addressLength = left.ipv6 ? 16 : 4;
    return std::memcmp(left.localAddress.data(), right.localAddress.data(),
                       addressLength) == 0 &&
        std::memcmp(left.remoteAddress.data(), right.remoteAddress.data(),
                    addressLength) == 0;
}

Rules::Rules(std::vector<std::string> includes,
             std::vector<std::string> excludes)
    : includes_(normalizeRules(std::move(includes), rejectedIncludes_)),
      excludes_(normalizeRules(std::move(excludes), rejectedExcludes_)) {}

bool Rules::enabled() const noexcept {
    return !includes_.empty() || !excludes_.empty() || includeListInvalid();
}

bool Rules::includeListInvalid() const noexcept {
    return includes_.empty() && rejectedIncludes_ != 0;
}

size_t Rules::rejectedIncludeCount() const noexcept { return rejectedIncludes_; }
size_t Rules::rejectedExcludeCount() const noexcept { return rejectedExcludes_; }

bool Rules::allowsImage(std::string_view imagePath) const {
    if (includeListInvalid()) return false;
    const std::string fullPath = normalize(imagePath);
    if (fullPath.empty()) return false;
    const size_t separator = fullPath.find_last_of('\\');
    const std::string_view basename = separator == std::string::npos
        ? std::string_view(fullPath)
        : std::string_view(fullPath).substr(separator + 1);

    if (matchesAny(excludes_, fullPath, basename)) return false;
    return includes_.empty() || matchesAny(includes_, fullPath, basename);
}

size_t Rules::includeCount() const noexcept { return includes_.size(); }
size_t Rules::excludeCount() const noexcept { return excludes_.size(); }

class Filter::Impl {
public:
    explicit Impl(Rules rules) : rules_(std::move(rules)) {}

    bool shouldIntercept(const Endpoint& endpoint, bool outbound,
                         bool newTcpFlow, uint64_t nowMs) {
        if (!rules_.enabled()) return true;
        if (endpoint.localPort == 0 || endpoint.remotePort == 0) return false;

        const uint64_t now = nowMs == 0 ? GetTickCount64() : nowMs;
        {
            std::lock_guard lock(mutex_);
            const auto it = endpoints_.find(endpoint);
            if (it != endpoints_.end() && it->second.expiresAtMs > now) {
                // A resolved decision follows its connection: traffic keeps it
                // alive, so a long-lived intercepted flow is never turned into
                // a bypassed (and therefore reset) one by a fixed deadline.
                if (it->second.resolved) {
                    it->second.expiresAtMs = std::max(
                        it->second.expiresAtMs,
                        now + (endpoint.protocol == Protocol::Tcp ? kTcpCacheTtlMs
                                                                  : kUdpCacheTtlMs));
                }
                return it->second.intercept;
            }
        }

        // Never perform an ownership table walk for an inbound packet or for
        // a TCP flow that was already in progress when SplitHello started.
        if (!outbound ||
            (endpoint.protocol == Protocol::Tcp && !newTcpFlow)) {
            return false;
        }

        const std::optional<DWORD> owner = endpoint.protocol == Protocol::Tcp
            ? tcpOwner(endpoint)
            : udpOwner(endpoint);
        const std::string image = owner ? cachedProcessImage(*owner, now)
                                        : std::string{};
        // shortcut: an unresolved owner is left alone even with exclude-only
        // rules, because it might be the excluded process; the padded table
        // fetch keeps unresolved owners rare. Revisit if users report misses.
        const bool intercept = !image.empty() && rules_.allowsImage(image);
        const uint64_t ttl = image.empty()
            ? kUnknownCacheTtlMs
            : (endpoint.protocol == Protocol::Tcp ? kTcpCacheTtlMs
                                                  : kUdpCacheTtlMs);

        std::lock_guard lock(mutex_);
        if (endpoints_.size() >= kMaximumCachedEndpoints &&
            !endpoints_.contains(endpoint)) {
            makeRoomLocked(now);
        }
        endpoints_[endpoint] = {intercept, now + ttl, !image.empty()};
        return intercept;
    }

    void forget(const Endpoint& endpoint) {
        std::lock_guard lock(mutex_);
        endpoints_.erase(endpoint);
    }

    void clear() {
        std::lock_guard lock(mutex_);
        endpoints_.clear();
        processNames_.clear();
    }

    const Rules& rules() const noexcept { return rules_; }

private:
    struct Decision {
        bool intercept = false;
        uint64_t expiresAtMs = 0;
        bool resolved = false;  // false: owner unknown, short negative cache
    };

    struct ProcessName {
        std::string image;
        uint64_t expiresAtMs = 0;
    };

    std::string cachedProcessImage(DWORD processId, uint64_t now) {
        {
            std::lock_guard lock(mutex_);
            const auto it = processNames_.find(processId);
            if (it != processNames_.end() && it->second.expiresAtMs > now) {
                return it->second.image;
            }
        }

        std::string image = processImage(processId);
        std::lock_guard lock(mutex_);
        if (processNames_.size() >= kMaximumCachedEndpoints) {
            std::erase_if(processNames_, [now](const auto& item) {
                return item.second.expiresAtMs <= now;
            });
            if (processNames_.size() >= kMaximumCachedEndpoints) {
                processNames_.erase(processNames_.begin());
            }
        }
        processNames_[processId] = {image, now + kProcessNameTtlMs};
        return image;
    }

    // Called with the cache full. Expired entries go first, scanned at most
    // once per second; if the cache is genuinely full of live tuples, the
    // least recently used 1/16 is evicted, bypassed tuples before intercepted
    // ones, so inserts stay amortized O(1) under the global mutex.
    void makeRoomLocked(uint64_t now) {
        if (now >= nextSweepMs_) {
            nextSweepMs_ = now + 1000;
            std::erase_if(endpoints_, [now](const auto& item) {
                return item.second.expiresAtMs <= now;
            });
            if (endpoints_.size() < kMaximumCachedEndpoints) return;
        }

        struct Candidate {
            bool intercept;
            uint64_t expiresAtMs;
            Endpoint endpoint;
        };
        std::vector<Candidate> candidates;
        candidates.reserve(endpoints_.size());
        for (const auto& item : endpoints_) {
            candidates.push_back({item.second.intercept, item.second.expiresAtMs,
                                  item.first});
        }
        const size_t evict = std::max<size_t>(1, candidates.size() / 16);
        std::nth_element(candidates.begin(),
                         candidates.begin() + (std::ptrdiff_t)(evict - 1),
                         candidates.end(),
                         [](const Candidate& left, const Candidate& right) {
                             if (left.intercept != right.intercept) {
                                 return !left.intercept;
                             }
                             return left.expiresAtMs < right.expiresAtMs;
                         });
        for (size_t i = 0; i < evict; ++i) endpoints_.erase(candidates[i].endpoint);
    }

    Rules rules_;
    std::mutex mutex_;
    uint64_t nextSweepMs_ = 0;
    std::unordered_map<Endpoint, Decision, EndpointHash> endpoints_;
    std::unordered_map<DWORD, ProcessName> processNames_;
};

Filter::Filter(Rules rules) : impl_(std::make_unique<Impl>(std::move(rules))) {}
Filter::~Filter() = default;
Filter::Filter(Filter&&) noexcept = default;
Filter& Filter::operator=(Filter&&) noexcept = default;

bool Filter::enabled() const noexcept { return impl_->rules().enabled(); }
const Rules& Filter::rules() const noexcept { return impl_->rules(); }

bool Filter::shouldIntercept(const Endpoint& endpoint, bool outbound,
                             bool newTcpFlow, uint64_t nowMs) {
    return impl_->shouldIntercept(endpoint, outbound, newTcpFlow, nowMs);
}

void Filter::forget(const Endpoint& endpoint) { impl_->forget(endpoint); }

void Filter::clear() { impl_->clear(); }

} // namespace process_filter
