#include "ProcessFilter.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace process_filter {
namespace {

constexpr size_t kMaximumRulesPerList = 64;
constexpr size_t kMaximumRuleLength = 260;

std::string normalize(std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1);
    if (value.size() > kMaximumRuleLength) return {};

    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    std::replace(result.begin(), result.end(), '/', '\\');
    return result;
}

std::vector<std::string> normalizeRules(std::vector<std::string> values) {
    std::vector<std::string> result;
    result.reserve(std::min(values.size(), kMaximumRulesPerList));
    for (const std::string& value : values) {
        std::string normalized = normalize(value);
        if (normalized.empty() ||
            std::find(result.begin(), result.end(), normalized) != result.end()) {
            continue;
        }
        result.push_back(std::move(normalized));
        if (result.size() == kMaximumRulesPerList) break;
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
        } else if (patternIndex < pattern.size() && pattern[patternIndex] == '*') {
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
                std::string_view fullPath, std::string_view basename) {
    for (const std::string& pattern : patterns) {
        const bool fullPathPattern = pattern.find('\\') != std::string::npos;
        if (wildcardMatch(pattern, fullPathPattern ? fullPath : basename)) {
            return true;
        }
    }
    return false;
}

} // namespace

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

const std::vector<std::string>& Rules::includes() const noexcept {
    return includes_;
}

const std::vector<std::string>& Rules::excludes() const noexcept {
    return excludes_;
}

} // namespace process_filter
