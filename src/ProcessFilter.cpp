#include "ProcessFilter.hpp"

#include <algorithm>
#include <cctype>
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

std::vector<std::string> normalizeRules(std::vector<std::string> values) {
    std::vector<std::string> result;
    result.reserve(std::min(values.size(), kMaximumRules));
    for (const std::string& value : values) {
        std::string normalized = normalize(value);
        if (normalized.empty()) continue;
        if (std::find(result.begin(), result.end(), normalized) != result.end()) {
            continue;
        }
        result.push_back(std::move(normalized));
        if (result.size() == kMaximumRules) break;
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

template <typename Table>
std::optional<std::vector<uint8_t>> ownerTable(
    ULONG family, TCP_TABLE_CLASS tableClass) {
    DWORD size = 0;
    const DWORD first = GetExtendedTcpTable(nullptr, &size, FALSE, family,
                                             tableClass, 0);
    if (first != ERROR_INSUFFICIENT_BUFFER || size == 0) return std::nullopt;
    std::vector<uint8_t> bytes(size);
    if (GetExtendedTcpTable(bytes.data(), &size, FALSE, family, tableClass, 0) !=
        NO_ERROR) {
        return std::nullopt;
    }
    if (bytes.size() < sizeof(Table)) return std::nullopt;
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
    DWORD size = 0;
    const DWORD first = GetExtendedUdpTable(nullptr, &size, FALSE, family,
                                             tableClass, 0);
    if (first != ERROR_INSUFFICIENT_BUFFER || size == 0) return std::nullopt;
    std::vector<uint8_t> bytes(size);
    if (GetExtendedUdpTable(bytes.data(), &size, FALSE, family, tableClass, 0) !=
        NO_ERROR) {
        return std::nullopt;
    }
    return bytes;
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
    : includes_(normalizeRules(std::move(includes))),
      excludes_(normalizeRules(std::move(excludes))) {}

bool Rules::enabled() const noexcept {
    return !includes_.empty() || !excludes_.empty();
}

bool Rules::allowsImage(std::string_view imagePath) const {
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
                         bool newTcpFlow) {
        if (!rules_.enabled()) return true;
        if (endpoint.localPort == 0 || endpoint.remotePort == 0) return false;

        const uint64_t now = GetTickCount64();
        {
            std::lock_guard lock(mutex_);
            const auto it = endpoints_.find(endpoint);
            if (it != endpoints_.end() && it->second.expiresAtMs > now) {
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
        const bool intercept = !image.empty() && rules_.allowsImage(image);
        const uint64_t ttl = image.empty()
            ? kUnknownCacheTtlMs
            : (endpoint.protocol == Protocol::Tcp ? kTcpCacheTtlMs
                                                  : kUdpCacheTtlMs);

        std::lock_guard lock(mutex_);
        pruneLocked(now);
        endpoints_[endpoint] = {intercept, now + ttl};
        return intercept;
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
        processNames_[processId] = {image, now + kProcessNameTtlMs};
        return image;
    }

    void pruneLocked(uint64_t now) {
        if (endpoints_.size() < kMaximumCachedEndpoints) return;
        for (auto it = endpoints_.begin(); it != endpoints_.end();) {
            if (it->second.expiresAtMs <= now) {
                it = endpoints_.erase(it);
            } else {
                ++it;
            }
        }
        while (endpoints_.size() >= kMaximumCachedEndpoints) {
            const auto oldest = std::min_element(
                endpoints_.begin(), endpoints_.end(),
                [](const auto& left, const auto& right) {
                    return left.second.expiresAtMs < right.second.expiresAtMs;
                });
            if (oldest == endpoints_.end()) break;
            endpoints_.erase(oldest);
        }
    }

    Rules rules_;
    std::mutex mutex_;
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
                             bool newTcpFlow) {
    return impl_->shouldIntercept(endpoint, outbound, newTcpFlow);
}

void Filter::clear() { impl_->clear(); }

} // namespace process_filter
