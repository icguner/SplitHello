#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace process_filter {

// Exclude rules always win. When at least one include rule exists, processes
// that do not match an include rule are left on the normal Windows path.
// Patterns are normalized once here and sent unchanged to the WFP driver.
class Rules {
public:
    Rules() = default;
    Rules(std::vector<std::string> includes,
          std::vector<std::string> excludes);

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] bool allowsImage(std::string_view imagePath) const;
    [[nodiscard]] size_t includeCount() const noexcept;
    [[nodiscard]] size_t excludeCount() const noexcept;
    [[nodiscard]] const std::vector<std::string>& includes() const noexcept;
    [[nodiscard]] const std::vector<std::string>& excludes() const noexcept;

private:
    std::vector<std::string> includes_;
    std::vector<std::string> excludes_;
};

} // namespace process_filter
