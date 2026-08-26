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

private:
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
                                       bool newTcpFlow);
    void clear();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace process_filter
