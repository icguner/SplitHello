#include "AdBlock.hpp"

#include "FileUtil.hpp"
#include "Http.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <map>

namespace adblock {

namespace {

constexpr auto kRefreshInterval = std::chrono::hours(24);
constexpr auto kRetryMax = std::chrono::minutes(60);
constexpr auto kTick = std::chrono::seconds(5);
// A real list has thousands of entries; fewer means an error page or a
// truncated body, which must not replace a good list.
constexpr size_t kMinPlausibleEntries = 1000;
constexpr size_t kMaxListBytes = 32 * 1024 * 1024;
constexpr size_t kMaxTrackedHosts = 2000;
constexpr char kListHost[] = "raw.githubusercontent.com";

std::atomic<uint64_t> g_blocked{0};
std::mutex g_tallyMutex;
std::map<std::string, uint32_t> g_tally;

bool validHostname(std::string_view name) {
    if (name.empty() || name.size() > 253 || name.front() == '.' || name.back() == '.') {
        return false;
    }
    bool hasLetter = false;
    for (const char raw : name) {
        const unsigned char c = (unsigned char)raw;
        if (std::isalpha(c)) hasLetter = true;
        if (!(std::isalnum(c) || c == '-' || c == '.' || c == '_')) return false;
    }
    // Rejects IP literals ("0.0.0.0" in hosts files) and bare numbers.
    return hasLetter;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace((unsigned char)s.front())) s.remove_prefix(1);
    while (!s.empty() && std::isspace((unsigned char)s.back())) s.remove_suffix(1);
    return s;
}

std::string lowerHost(std::string_view host) {
    std::string result(host);
    if (!result.empty() && result.back() == '.') result.pop_back();
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return result;
}

} // namespace

DomainSet parseDomains(std::string_view text) {
    DomainSet result;
    while (!text.empty()) {
        const size_t end = text.find('\n');
        std::string_view line = trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);

        if (line.empty() || line.front() == '#' || line.front() == '!') continue;
        if (const size_t hash = line.find('#'); hash != std::string_view::npos) {
            line = trim(line.substr(0, hash));
        }
        if (line.starts_with("||")) {
            line.remove_prefix(2);
            if (const size_t caret = line.find('^'); caret != std::string_view::npos) {
                line = line.substr(0, caret);
            }
        } else if (const size_t space = line.find_last_of(" \t");
                   space != std::string_view::npos) {
            line = line.substr(space + 1); // hosts format: address, then name
        }
        if (line.starts_with("*.")) line.remove_prefix(2);

        const std::string name = lowerHost(line);
        if (validHostname(name)) result.insert(name);
    }
    return result;
}

void Blocklist::replace(DomainSet blocked) {
    auto next = std::make_shared<Sets>();
    next->blocked = std::make_shared<const DomainSet>(std::move(blocked));
    next->allowed = sets_.load()->allowed;
    sets_.store(std::move(next));
}

void Blocklist::setAllow(const std::vector<std::string>& allowed) {
    auto next = std::make_shared<Sets>();
    next->blocked = sets_.load()->blocked; // shared, not copied
    for (const std::string& name : allowed) {
        const std::string host = lowerHost(name);
        if (!host.empty()) next->allowed.insert(host);
    }
    sets_.store(std::move(next));
}

bool Blocklist::blocks(std::string_view host) const {
    const auto sets = sets_.load();
    if (sets->blocked->empty() || host.empty()) return false;
    const std::string name = lowerHost(host);
    if (name.empty() || name.front() == '[' || name.find(':') != std::string::npos) {
        return false;
    }

    // Walk "a.b.example.com" -> "b.example.com" -> "example.com" -> "com".
    bool blocked = false;
    for (std::string_view part = name;;) {
        if (!sets->allowed.empty() && sets->allowed.contains(std::string(part))) {
            return false;
        }
        if (!blocked && sets->blocked->contains(std::string(part))) blocked = true;
        const size_t dot = part.find('.');
        if (dot == std::string_view::npos) break;
        part.remove_prefix(dot + 1);
    }
    return blocked;
}

size_t Blocklist::size() const {
    return sets_.load()->blocked->size();
}

Blocklist& global() {
    static Blocklist list;
    return list;
}

void recordBlocked(std::string_view host) {
    g_blocked.fetch_add(1, std::memory_order_relaxed);
    const std::string name = lowerHost(host);
    const std::lock_guard lock(g_tallyMutex);
    const auto found = g_tally.find(name);
    if (found != g_tally.end()) {
        ++found->second;
    } else if (g_tally.size() < kMaxTrackedHosts) {
        g_tally.emplace(name, 1);
    } // else: counted in the total only, so memory stays bounded
}

uint64_t blockedCount() { return g_blocked.load(std::memory_order_relaxed); }

std::vector<std::pair<std::string, uint32_t>> topBlocked(size_t limit) {
    std::vector<std::pair<std::string, uint32_t>> all;
    {
        const std::lock_guard lock(g_tallyMutex);
        all.assign(g_tally.begin(), g_tally.end());
    }
    std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) {
        return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    if (all.size() > limit) all.resize(limit);
    return all;
}

std::optional<std::string> listPath(std::string_view name) {
    static const std::pair<std::string_view, std::string_view> kLists[] = {
        {"light", "light-onlydomains.txt"},        // fewest false positives
        {"pro", "pro-onlydomains.txt"},            // recommended
        {"tif", "tif.medium-onlydomains.txt"},     // malware / phishing / scam feeds
        {"doh", "doh-onlydomains.txt"},            // DoH servers: pushes apps onto our DNS
    };
    for (const auto& [key, file] : kLists) {
        if (key == name) {
            return "/hagezi/dns-blocklists/main/wildcard/" + std::string(file);
        }
    }
    return std::nullopt;
}

Updater::Updater(UpdaterFiles files, std::vector<std::string> listNames,
                 std::vector<std::string> configAllow)
    : files_(std::move(files)), configAllow_(std::move(configAllow)) {
    for (const std::string& name : listNames) {
        const auto path = listPath(name);
        if (!path) {
            spdlog::warn("ad_block_lists: bilinmeyen liste '{}' atlandi", name);
            continue;
        }
        Source source;
        source.name = name;
        source.path = *path;
        source.cacheFile = files_.cacheDir + "\\adblock-" + name + ".txt";
        sources_.push_back(std::move(source));
    }
    thread_ = std::thread([this]() {
        try { run(); }
        catch (...) { spdlog::warn("Reklam listesi guncelleyici durdu"); }
    });
}

Updater::~Updater() {
    {
        const std::lock_guard lock(mutex_);
        stop_ = true;
    }
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
}

bool Updater::download(Source& source) {
    http::Request request;
    request.host = kListHost;
    request.path = source.path;
    request.timeoutMs = 15000;
    request.maxBodyBytes = kMaxListBytes;
    const http::Response response = http::perform(request);
    if (!response.ok()) {
        spdlog::warn("Reklam listesi '{}' indirilemedi: HTTP {}", source.name,
                     response.status);
        return false;
    }
    if (parseDomains(response.body).size() < kMinPlausibleEntries) {
        spdlog::warn("Reklam listesi '{}' reddedildi: cok az gecerli girdi", source.name);
        return false;
    }
    if (!fileutil::writeAtomic(source.cacheFile, response.body)) {
        spdlog::warn("Reklam listesi diske yazilamadi: {}", source.cacheFile);
        return false;
    }
    return true;
}

void Updater::rebuild() {
    DomainSet merged;
    for (const Source& source : sources_) {
        std::string text;
        if (!fileutil::readAll(source.cacheFile, text)) continue;
        DomainSet parsed = parseDomains(text);
        if (parsed.size() < kMinPlausibleEntries) continue;
        spdlog::info("Reklam listesi '{}': {} alan adi", source.name, parsed.size());
        merged.merge(parsed);
    }
    if (merged.empty()) return;
    spdlog::info("Reklam engeli aktif: toplam {} alan adi", merged.size());
    global().replace(std::move(merged));
}

void Updater::refreshAllow() {
    std::vector<std::string> allowed = configAllow_;
    std::string text;
    if (fileutil::readAll(files_.allowFile, text)) {
        for (const std::string& name : parseDomains(text)) allowed.push_back(name);
    }
    global().setAllow(allowed);
}

void Updater::publishRecent() {
    std::string content = "#total\t" + std::to_string(blockedCount()) + "\n";
    for (const auto& [host, count] : topBlocked(10)) {
        content += host + "\t" + std::to_string(count) + "\n";
    }
    fileutil::writeAtomic(files_.recentFile, content);
}

void Updater::run() {
    namespace fs = std::filesystem;

    rebuild();
    refreshAllow();
    std::error_code ec;
    auto allowStamp = fs::last_write_time(fileutil::widen(files_.allowFile), ec);
    bool allowKnown = !ec;
    uint64_t published = ~0ull;

    while (true) {
        bool changed = false;
        for (Source& source : sources_) {
            const auto now = std::chrono::steady_clock::now();
            if (now < source.nextAttempt) continue;

            std::error_code stampError;
            const auto written = fs::last_write_time(fileutil::widen(source.cacheFile),
                                                     stampError);
            if (!stampError &&
                fs::file_time_type::clock::now() - written < kRefreshInterval) {
                continue;
            }
            if (download(source)) {
                source.retry = std::chrono::minutes(10);
                changed = true;
            } else {
                source.nextAttempt = now + source.retry;
                source.retry = std::min(source.retry * 2, kRetryMax);
            }
        }
        if (changed) rebuild();

        // A tray click appends to the allow file; pick it up without a restart.
        std::error_code allowError;
        const auto stamp = fs::last_write_time(fileutil::widen(files_.allowFile), allowError);
        if (!allowError && (!allowKnown || stamp != allowStamp)) {
            allowStamp = stamp;
            allowKnown = true;
            refreshAllow();
        }

        if (const uint64_t total = blockedCount(); total != published) {
            published = total;
            publishRecent();
        }

        std::unique_lock lock(mutex_);
        if (wake_.wait_for(lock, kTick, [this]() { return stop_; })) return;
    }
}

} // namespace adblock
