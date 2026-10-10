#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace process_filter {

// Exclude rules always win. When at least one include rule exists, processes
// that do not match an include rule are left on the normal Windows path.
// Patterns are case-insensitive and support '*' and '?'. A basename pattern
// (for example "chrome.exe") is matched against the executable filename;
// patterns containing a slash are matched against the full image path.
class Rules {
public:
    Rules() = default;
    Rules(std::vector<std::string> includes,
          std::vector<std::string> excludes);

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] bool allowsImage(std::string_view imagePath) const;
    [[nodiscard]] size_t includeCount() const noexcept;
    [[nodiscard]] size_t excludeCount() const noexcept;

    // Non-blank patterns that were dropped (longer than the limit, or past
    // the 128-rule cap). Blank entries and duplicates are not counted.
    [[nodiscard]] size_t rejectedIncludeCount() const noexcept;
    [[nodiscard]] size_t rejectedExcludeCount() const noexcept;
    // The include list was given but no pattern in it survived. Treating that
    // as "no include rules" would intercept every process, so the rules stay
    // enabled and allow nothing (fail closed); callers should warn.
    [[nodiscard]] bool includeListInvalid() const noexcept;

private:
    // Declared before the lists: the constructor fills them while building
    // includes_/excludes_, so they must already be initialized.
    size_t rejectedIncludes_ = 0;
    size_t rejectedExcludes_ = 0;
    std::vector<std::string> includes_;
    std::vector<std::string> excludes_;
};

enum class Protocol : uint8_t {
    Tcp = 6,
    Udp = 17,
};

// Canonical local/remote tuple. IPv4 uses the first four address bytes.
struct Endpoint {
    bool ipv6 = false;
    Protocol protocol = Protocol::Tcp;
    std::array<uint8_t, 16> localAddress{};
    std::array<uint8_t, 16> remoteAddress{};
    uint16_t localPort = 0;
    uint16_t remotePort = 0;
};

// Process ownership is resolved only for the first outbound packet of a new
// tuple, then cached. Inbound cache misses and TCP mid-stream misses bypass
// interception so enabling a rule can never hijack an unidentified flow.
// Every hit on a resolved entry pushes its expiry out, so a long-lived flow
// keeps its decision while it carries traffic; only idle tuples age out.
// `nowMs` (0 = system tick count) exists so tests can drive the clock.
class Filter {
public:
    explicit Filter(Rules rules);
    ~Filter();

    Filter(const Filter&) = delete;
    Filter& operator=(const Filter&) = delete;
    Filter(Filter&&) noexcept;
    Filter& operator=(Filter&&) noexcept;

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] const Rules& rules() const noexcept;

    [[nodiscard]] bool shouldIntercept(const Endpoint& endpoint,
                                       bool outbound,
                                       bool newTcpFlow,
                                       uint64_t nowMs = 0);
    // Drops the cached decision once the connection is known to be over.
    void forget(const Endpoint& endpoint);
    void clear();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace process_filter
