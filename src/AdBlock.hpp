#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

// Domain-level ad/tracker blocking. A host is blocked when it or any parent
// domain is in the list (HaGeZi "onlydomains" lists block subdomains too), so
// the check walks the labels right to left. Lookups never take a lock: readers
// hold an immutable snapshot that the updater swaps atomically.
namespace adblock {

using DomainSet = std::unordered_set<std::string>;

// Accepts plain domains, hosts lines ("0.0.0.0 domain") and "||domain^" rules.
// '#' and '!' lines are comments; anything that is not a valid hostname is
// skipped. Names are lowercased.
DomainSet parseDomains(std::string_view text);

class Blocklist {
public:
    void replace(DomainSet blocked);
    void setAllow(const std::vector<std::string>& allowed);

    // True when `host` (or a parent domain) is blocked and no parent of it is
    // allow-listed. IP literals and empty names are never blocked.
    bool blocks(std::string_view host) const;
    size_t size() const;

private:
    struct Sets {
        std::shared_ptr<const DomainSet> blocked = std::make_shared<const DomainSet>();
        DomainSet allowed;
    };
    std::atomic<std::shared_ptr<const Sets>> sets_{std::make_shared<const Sets>()};
};

// Process-wide list shared by the relay and the DNS proxy.
Blocklist& global();

// Called by the relay/DNS proxy for each block: bumps the total and keeps a
// bounded per-host tally so the tray can offer "allow this" for false positives.
void recordBlocked(std::string_view host);
uint64_t blockedCount();
std::vector<std::pair<std::string, uint32_t>> topBlocked(size_t limit);

// HaGeZi list names accepted in config ("ad_block_lists") and their path in the
// dns-blocklists repository. Empty for an unknown name.
std::optional<std::string> listPath(std::string_view name);

struct UpdaterFiles {
    std::string cacheDir;     // one cached file per list
    std::string allowFile;    // user allow-list, one domain per line, re-read live
    std::string recentFile;   // written for the tray: "#total<TAB>N" + "host<TAB>count"
};

// Keeps global() filled: loads the on-disk copies at once, then refreshes each
// list from raw.githubusercontent.com when it is older than a day. Downloads
// never block traffic; a failed or implausibly small download keeps the old
// list. The same thread re-reads the allow file and publishes the recent file.
class Updater {
public:
    Updater(UpdaterFiles files, std::vector<std::string> listNames,
            std::vector<std::string> configAllow);
    ~Updater();
    Updater(const Updater&) = delete;
    Updater& operator=(const Updater&) = delete;

private:
    struct Source {
        std::string name;
        std::string path;                       // URL path on the host
        std::string cacheFile;
        std::chrono::steady_clock::time_point nextAttempt{};
        std::chrono::minutes retry{10};
    };

    void run();
    bool download(Source& source);
    void rebuild();
    void refreshAllow();
    void publishRecent();

    UpdaterFiles files_;
    std::vector<Source> sources_;
    std::vector<std::string> configAllow_;
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stop_ = false;
    std::thread thread_;
};

} // namespace adblock
