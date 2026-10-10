#include "Dns.hpp"

#include "DnsMessage.hpp"
#include "Http.hpp"
#include "Json.hpp"
#include "Secure.hpp"
#include "TcpConnect.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <limits>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace dns {
namespace {

// Very short TTLs would make us re-query on every connection; very long ones
// would pin us to an address that has since moved.
constexpr unsigned kMinTtlSeconds = 60;
constexpr unsigned kMaxTtlSeconds = 3600;
constexpr unsigned kNegativeCacheSeconds = 30;
// Failures and half-answers: long enough to absorb the A/AAAA pair and an
// app's immediate retry, short enough that recovery is not delayed.
constexpr unsigned kTransientCacheSeconds = 3;
constexpr size_t kMaxCacheEntries = 2048;
constexpr size_t kMaxWireCacheEntries = 1024;

// Wire responses honour the record TTL inside these bounds. Errors other than
// NXDOMAIN/NODATA are never cached.
constexpr unsigned kWireMinTtlSeconds = 10;
constexpr unsigned kWireMaxTtlSeconds = 3600;
constexpr unsigned kWireNegativeMaxSeconds = 60;

constexpr unsigned kRequestTimeoutMs = 4000;
constexpr unsigned kMinRequestTimeoutMs = 500;

// The Worker host's own addresses cannot be looked up through the Worker (and
// WinHTTP's lookup of it is answered from this cache), so they are refreshed
// out of band and served stale rather than ever failing outright.
constexpr unsigned long long kBootstrapTtlMs = 10ULL * 60 * 1000;
constexpr unsigned long long kBootstrapRetryMs = 30ULL * 1000;
constexpr unsigned kBootstrapTimeoutMs = 2000;
// Reached by IP literal, so no DNS (and no captured UDP/53) is involved.
constexpr const char* kBootstrapDohHost = "1.1.1.1";

constexpr unsigned long long kNeverExpires = std::numeric_limits<unsigned long long>::max();

std::string lowercase(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    while (!out.empty() && out.back() == '.') out.pop_back();
    return out;
}

// Only these bytes may be placed in /resolve?host=; the Worker accepts the same
// set (no '_'), so nothing needs percent-encoding and nothing can smuggle a
// '&', '#' or CRLF into the request line.
bool isResolvableHost(const std::string& host) {
    if (host.empty() || host.size() > 253) return false;
    return std::all_of(host.begin(), host.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
    });
}

// Remaining lifetime of a cache entry, so a hit does not hand out the full TTL
// again (clients would then cache the record for up to twice its lifetime).
Result agedResult(Result result, unsigned long long expiresAtMs, unsigned long long now) {
    if (expiresAtMs == kNeverExpires || result.ttlSeconds == 0) return result;
    const unsigned long long remainingMs = expiresAtMs > now ? expiresAtMs - now : 0;
    const unsigned long long remaining = (remainingMs + 999) / 1000;
    result.ttlSeconds = (unsigned)std::max<unsigned long long>(
        1, std::min<unsigned long long>(remaining, result.ttlSeconds));
    return result;
}

std::string wireKey(const dns_message::Query& query) {
    std::string key = query.name;
    key += '|';
    key += std::to_string(query.type);
    key += query.recursionDesired ? "|r" : "|-";
    key += query.dnssecOk ? "d" : "-";
    key += query.ednsPayload != 0 ? "e" : "-";
    return key;
}

// Seconds a relayed response may be served from cache; 0 = do not cache.
unsigned wireLifetimeSeconds(const dns_message::ResponseInfo& info) {
    if (info.truncated) return 0;
    if (info.rcode == dns_message::kRcodeNoError && info.answers > 0) {
        if (!info.hasAnswerTtl || info.answerTtl == 0) return 0;
        return std::clamp(info.answerTtl, kWireMinTtlSeconds, kWireMaxTtlSeconds);
    }
    if (info.rcode == dns_message::kRcodeNoError ||
        info.rcode == dns_message::kRcodeNxDomain) {
        return info.hasAuthorityTtl
            ? std::clamp(info.authorityTtl, kWireMinTtlSeconds, kWireNegativeMaxSeconds)
            : kNegativeCacheSeconds;
    }
    return 0;
}

void wipeAuthorization(http::Request& request) {
    for (auto& [name, value] : request.headers) {
        if (name == "Authorization") secure::wipe(value);
    }
}

void appendUnique(std::vector<std::string>& list, const std::string& value) {
    if (std::find(list.begin(), list.end(), value) == list.end()) list.push_back(value);
}

} // namespace

std::vector<std::string> Result::candidates(size_t limit) const {
    std::vector<std::string> out;
    out.reserve(std::min(limit, v4.size() + v6.size()));

    size_t i6 = 0;
    size_t i4 = 0;
    bool preferV6 = true;

    while (out.size() < limit && (i6 < v6.size() || i4 < v4.size())) {
        if (preferV6 && i6 < v6.size()) {
            out.push_back(v6[i6++]);
        } else if (i4 < v4.size()) {
            out.push_back(v4[i4++]);
        } else if (i6 < v6.size()) {
            out.push_back(v6[i6++]);
        }
        preferV6 = !preferV6;
    }
    return out;
}

Resolver::Resolver(const std::string& workerUrl, std::string sharedSecret,
                   uint16_t connectPort, Hooks hooks)
    : workerHost_(http::hostFromUrl(workerUrl))
    , sharedSecret_(std::move(sharedSecret))
    , connectPort_(connectPort)
    , hooks_(std::move(hooks)) {
    if (workerHost_.empty()) {
        if (!workerUrl.empty()) {
            spdlog::warn("DNS: Worker URL cozumlenemedi ({}), sistem DNS kullanilacak",
                         workerUrl);
        }
        return;
    }
    bootstrapNeeded_ = !tcp::isIpLiteral(lowercase(workerHost_));
    if (!bootstrapNeeded_) return;

    // Bootstrap before WinDivert starts. Later WinHTTP requests still ask the
    // system resolver for this hostname; the transparent DNS proxy answers
    // those requests from this cache, preventing a recursive DoH lookup. If the
    // machine is offline right now, refreshBootstrap() retries lazily.
    Result bootstrap;
    if (lookupViaSystemResolver(bootstrap)) {
        std::lock_guard<std::mutex> lock(mutex_);
        cache_[lowercase(workerHost_)] = {bootstrap, kNeverExpires};
        bootstrapNextMs_ = nowMs() + kBootstrapTtlMs;
        spdlog::debug("DNS bootstrap: Worker -> {} A, {} AAAA",
                      bootstrap.v4.size(), bootstrap.v6.size());
    } else {
        spdlog::warn("DNS bootstrap: Worker adresi simdi cozulemedi; sonra tekrar denenecek");
    }
}

Resolver::~Resolver() {
    secure::wipe(sharedSecret_);
}

unsigned long long Resolver::nowMs() const {
    return hooks_.now ? hooks_.now() : GetTickCount64();
}

http::Response Resolver::fetch(const http::Request& request) const {
    return hooks_.fetch ? hooks_.fetch(request) : http::perform(request);
}

// WinHTTP has no total timeout: each of resolve/connect/send/receive gets this
// budget. Shrinking it as the caller's deadline nears bounds the common case
// (a single stalled phase); the callers also stop starting new requests once
// the deadline has passed.
unsigned Resolver::requestTimeoutMs(unsigned long long deadlineMs) const {
    if (deadlineMs == 0) return kRequestTimeoutMs;
    const unsigned long long now = nowMs();
    if (now >= deadlineMs) return kMinRequestTimeoutMs;
    return (unsigned)std::clamp<unsigned long long>(deadlineMs - now, kMinRequestTimeoutMs,
                                                    kRequestTimeoutMs);
}

bool Resolver::lookupViaSystemResolver(Result& out) const {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = nullptr;
    if (getaddrinfo(workerHost_.c_str(), "443", &hints, &resolved) != 0) return false;

    out = {};
    out.ttlSeconds = (unsigned)(kBootstrapTtlMs / 1000);
    for (addrinfo* current = resolved; current; current = current->ai_next) {
        char text[INET6_ADDRSTRLEN] = {};
        if (current->ai_family == AF_INET) {
            const auto* address = reinterpret_cast<const sockaddr_in*>(current->ai_addr);
            if (inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text))) {
                appendUnique(out.v4, text);
            }
        } else if (current->ai_family == AF_INET6) {
            const auto* address = reinterpret_cast<const sockaddr_in6*>(current->ai_addr);
            if (inet_ntop(AF_INET6, &address->sin6_addr, text, sizeof(text))) {
                appendUnique(out.v6, text);
            }
        }
    }
    freeaddrinfo(resolved);
    return !out.empty();
}

// Resolves the Worker host through Cloudflare's JSON DoH endpoint reached by
// IP literal. getaddrinfo cannot be used once WinDivert is active: the query
// would be captured and answered from the very cache being refreshed. No
// secret is sent - this request goes to 1.1.1.1, not to the Worker.
bool Resolver::lookupViaDohByAddress(Result& out) const {
    const std::string name = lowercase(workerHost_);
    if (!isResolvableHost(name)) return false;

    out = {};
    out.ttlSeconds = (unsigned)(kBootstrapTtlMs / 1000);
    for (const char* type : {"A", "AAAA"}) {
        http::Request request;
        request.host = kBootstrapDohHost;
        request.path = "/dns-query?name=" + name + "&type=" + type;
        request.timeoutMs = kBootstrapTimeoutMs;
        request.headers.push_back({"Accept", "application/dns-json"});

        const http::Response response = fetch(request);
        if (!response.ok()) continue;

        size_t position = 0;
        while ((position = json::findValue(response.body, "data", position)) !=
               std::string::npos) {
            size_t end = 0;
            const std::string address = json::parseString(response.body, position, end);
            position = end > position ? end : position + 1;
            if (!tcp::isIpLiteral(address)) continue; // CNAME targets and the like
            const bool v6 = address.find(':') != std::string::npos;
            if (v6 == (type[1] == 'A')) appendUnique(v6 ? out.v6 : out.v4, address);
        }
    }
    return !out.empty();
}

bool Resolver::hasBootstrap() const {
    if (!bootstrapNeeded_) return true;
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = cache_.find(lowercase(workerHost_));
    return found != cache_.end() && !found->second.result.empty();
}

// Rate-limited lazy (re)fetch of the Worker host's addresses: a machine that
// was offline at start-up gets them as soon as the network returns, and they
// are refreshed every kBootstrapTtlMs instead of living forever. A failed
// refresh keeps serving the previous addresses.
void Resolver::refreshBootstrap() {
    if (!bootstrapNeeded_ || nowMs() < bootstrapNextMs_.load()) return;
    if (bootstrapBusy_.exchange(true)) return;

    bool refreshed = false;
    try {
        Result fresh;
        if (lookupViaDohByAddress(fresh)) {
            std::lock_guard<std::mutex> lock(mutex_);
            cache_[lowercase(workerHost_)] = {fresh, kNeverExpires};
            refreshed = true;
            spdlog::debug("DNS bootstrap yenilendi: {} A, {} AAAA", fresh.v4.size(),
                          fresh.v6.size());
        }
    } catch (const std::exception& error) {
        spdlog::warn("DNS bootstrap yenileme hatasi: {}", error.what());
    } catch (...) {
        spdlog::warn("DNS bootstrap yenileme bilinmeyen hatayla sonlandi");
    }
    bootstrapNextMs_ = nowMs() + (refreshed ? kBootstrapTtlMs : kBootstrapRetryMs);
    bootstrapBusy_ = false;
}

bool Resolver::prepareWorkerCall(unsigned long long deadlineMs) {
    if (deadlineMs != 0 && nowMs() >= deadlineMs) return false;
    refreshBootstrap();
    // Nothing to connect to (offline since start-up): fail fast and do not
    // count it against the Worker's health - the network is the problem.
    if (!hasBootstrap()) return false;
    return !workerHealth_.backingOff(nowMs());
}

http::Request Resolver::workerRequest(const std::string& method, const std::string& path,
                                      unsigned long long deadlineMs) const {
    http::Request request;
    request.method = method;
    request.host = workerHost_;
    request.path = path;
    request.timeoutMs = requestTimeoutMs(deadlineMs);
    request.connectPort = connectPort_;
    if (!sharedSecret_.empty()) {
        request.headers.push_back({"Authorization", "Bearer " + sharedSecret_});
    }
    return request;
}

void Resolver::observe(const http::Response& response) {
    workerHealth_.observe(response.status, nowMs(), response.retryAfterSeconds);
}

Result Resolver::query(const std::string& host, unsigned long long deadlineMs) {
    Result result;
    if (workerHost_.empty()) return result;

    // '_' (service labels) and anything else outside [a-z0-9.-] is not a
    // /resolve host; the raw wire path handles any name.
    if (!isResolvableHost(host)) {
        result.allowWireFallback = true;
        return result;
    }
    if (!prepareWorkerCall(deadlineMs)) {
        result.transient = true;
        return result;
    }

    http::Request request = workerRequest("GET", "/resolve?host=" + host, deadlineMs);
    const http::Response response = fetch(request);
    wipeAuthorization(request);
    observe(response);

    if (response.status == 401 || response.status == 403) {
        spdlog::error("DNS: Worker kimlik dogrulamasi reddetti (HTTP {}). "
                      "--redeploy ile worker'i guncelleyin.", response.status);
        result.transient = true;
        return result;
    }
    if (response.status == 429) {
        spdlog::warn("DNS: Worker rate limit (HTTP 429)");
        result.transient = true;
        return result;
    }
    if (response.status == 404) {
        // Workers deployed before the rcode field answered 404 for NXDOMAIN,
        // SERVFAIL and empty answers alike. Ask the wire path for the real code.
        result.allowWireFallback = true;
        return result;
    }
    if (!response.ok()) {
        spdlog::warn("DNS: /resolve HTTP {} ({})", response.status, host);
        result.transient = true;
        return result;
    }

    result.v4 = json::getStringArray(response.body, "a");
    result.v6 = json::getStringArray(response.body, "aaaa");

    // Workers deployed before the multi-address response shape.
    if (result.empty()) {
        const std::string legacy = json::getString(response.body, "ip");
        if (!legacy.empty()) result.v4.push_back(legacy);
    }

    // Never trust the endpoint to return something connectable.
    const auto dropNonLiterals = [](std::vector<std::string>& list) {
        list.erase(std::remove_if(list.begin(), list.end(),
                                  [](const std::string& a) { return !tcp::isIpLiteral(a); }),
                   list.end());
    };
    dropNonLiterals(result.v4);
    dropNonLiterals(result.v6);

    const long long rcode = json::getInt(response.body, "rcode", -1);
    if (rcode >= 0) {
        result.rcode = (uint8_t)std::min<long long>(rcode, 15);
    } else {
        result.allowWireFallback = result.empty(); // old shape: no rcode to trust
    }
    result.transient = json::getBool(response.body, "partial");

    const long long ttl = json::getInt(response.body, "ttl", kMinTtlSeconds);
    result.ttlSeconds = (unsigned)std::clamp<long long>(ttl, kMinTtlSeconds, kMaxTtlSeconds);
    if (result.transient) {
        result.ttlSeconds = std::min(result.ttlSeconds, kTransientCacheSeconds);
    }

    if (!result.empty()) {
        spdlog::trace("DNS: {} -> {} A, {} AAAA (ttl {}s)",
                      host, result.v4.size(), result.v6.size(), result.ttlSeconds);
    } else if (result.rcode == dns_message::kRcodeNxDomain) {
        spdlog::debug("DNS: {} NXDOMAIN", host);
    } else if (result.rcode == dns_message::kRcodeNoError) {
        spdlog::debug("DNS: {} icin adres yok (NODATA)", host);
    } else {
        spdlog::warn("DNS: {} icin adres yok (rcode {})", host, result.rcode);
    }
    return result;
}

Result Resolver::resolve(const std::string& host, unsigned long long deadlineMs) {
    const std::string key = lowercase(host);
    if (key.empty()) return {};

    // An address literal needs no lookup at all.
    if (tcp::isIpLiteral(key)) {
        Result direct;
        if (key.find(':') != std::string::npos) direct.v6.push_back(key);
        else direct.v4.push_back(key);
        return direct;
    }

    // A and AAAA queries for the same hostname usually arrive together. Let
    // only one worker call /resolve while the other waits for its shared result.
    {
        std::unique_lock<std::mutex> lock(mutex_);
        while (true) {
            const unsigned long long now = nowMs();
            const auto cached = cache_.find(key);
            if (cached != cache_.end() && cached->second.expiresAtMs > now) {
                return agedResult(cached->second.result, cached->second.expiresAtMs, now);
            }

            if (key == lowercase(workerHost_)) {
                // No bootstrap address yet: SERVFAIL, not NODATA.
                Result unavailable;
                unavailable.transient = true;
                return unavailable;
            }
            if (inFlight_.insert(key).second) break;
            cacheReady_.wait(lock, [this, &key]() {
                return !inFlight_.contains(key);
            });
        }
    }

    Result result;
    try {
        result = query(key, deadlineMs);
    } catch (const std::exception& error) {
        spdlog::error("DNS: {} sorgusu beklenmeyen hatayla sonlandi: {}", key, error.what());
        result.transient = true;
    } catch (...) {
        spdlog::error("DNS: {} sorgusu bilinmeyen hatayla sonlandi", key);
        result.transient = true;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Avoid the old all-or-nothing clear: besides causing a cache-miss
        // storm, it removed the Worker's bootstrap address and could make its
        // own DoH lookup recurse through the transparent DNS path.
        if (!cache_.contains(key) && cache_.size() >= kMaxCacheEntries) {
            const std::string bootstrapKey = lowercase(workerHost_);
            auto victim = cache_.end();
            for (auto it = cache_.begin(); it != cache_.end(); ++it) {
                if (it->first == bootstrapKey) continue;
                if (victim == cache_.end() ||
                    it->second.expiresAtMs < victim->second.expiresAtMs) {
                    victim = it;
                }
            }
            if (victim != cache_.end()) cache_.erase(victim);
        }

        const unsigned lifetime = result.transient ? kTransientCacheSeconds
            : result.empty() ? kNegativeCacheSeconds
            : result.ttlSeconds;
        cache_[key] = Entry{
            result,
            nowMs() + (unsigned long long)lifetime * 1000ULL
        };
        inFlight_.erase(key);
    }
    cacheReady_.notify_all();
    return result;
}

std::vector<uint8_t> Resolver::queryWire(const uint8_t* message, size_t length,
                                         unsigned long long deadlineMs) {
    dns_message::Query parsed;
    if (!dns_message::parseQuery(message, length, parsed)) return {};
    if (workerHost_.empty()) return {};

    // WinHTTP resolves the Worker hostname before opening the DoH request. Its
    // DNS packet is reflected into this proxy too, so answer that one name from
    // the bootstrap cache instead of recursively asking the Worker about itself.
    if (lowercase(parsed.name) == lowercase(workerHost_)) {
        const Result bootstrap = resolve(parsed.name);
        static const std::vector<std::string> kNoAddresses;
        const std::vector<std::string>* addresses = &kNoAddresses;
        if (parsed.type == dns_message::kTypeA) addresses = &bootstrap.v4;
        if (parsed.type == dns_message::kTypeAaaa) addresses = &bootstrap.v6;
        return dns_message::buildResponse(parsed, *addresses,
                                          bootstrap.ttlSeconds == 0
                                              ? kMinTtlSeconds
                                              : bootstrap.ttlSeconds,
                                          bootstrap.empty());
    }

    // Cache first: an HTTPS/SVCB (type 65) burst per page load would otherwise
    // go to the Worker every time and trip its rate limit.
    const std::string key = wireKey(parsed);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto found = wireCache_.find(key);
        if (found != wireCache_.end()) {
            const unsigned long long now = nowMs();
            if (found->second.expiresAtMs > now) {
                std::vector<uint8_t> cached = found->second.response;
                const unsigned long long age = (now - found->second.storedAtMs) / 1000;
                lock.unlock();
                dns_message::setId(cached, parsed.id);
                dns_message::ageTtls(cached, (uint32_t)std::min<unsigned long long>(age, kWireMaxTtlSeconds));
                return cached;
            }
            wireCache_.erase(found);
        }
    }

    if (!prepareWorkerCall(deadlineMs)) return {};

    http::Request request = workerRequest("POST", "/dns-query", deadlineMs);
    request.headers.push_back({"Accept", "application/dns-message"});
    request.headers.push_back({"Content-Type", "application/dns-message"});
    request.body.assign(reinterpret_cast<const char*>(message), length);

    const http::Response response = fetch(request);
    wipeAuthorization(request);
    observe(response);
    if (response.status == 401 || response.status == 403) {
        spdlog::error("DNS wire: Worker kimlik dogrulamasi reddetti (HTTP {})",
                      response.status);
        return {};
    }
    if (!response.ok() || response.body.size() < 12 ||
        response.body.size() > 65535) {
        spdlog::warn("DNS wire: Worker HTTP {}", response.status);
        return {};
    }

    const auto* begin = reinterpret_cast<const uint8_t*>(response.body.data());
    std::vector<uint8_t> answer(begin, begin + response.body.size());

    // The DoH relay must hand back an answer to *this* question; never pass
    // anything else on to the application.
    dns_message::ResponseInfo info;
    if (!dns_message::inspectResponse(answer.data(), answer.size(), info) ||
        !info.response ||
        !dns_message::echoesQuestion(answer.data(), answer.size(), parsed)) {
        spdlog::warn("DNS wire: Worker gecersiz veya eslesmeyen cevap dondurdu ({})",
                     parsed.name);
        return {};
    }
    dns_message::setId(answer, parsed.id);

    const unsigned lifetime = wireLifetimeSeconds(info);
    if (lifetime != 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!wireCache_.contains(key) && wireCache_.size() >= kMaxWireCacheEntries) {
            auto victim = wireCache_.begin();
            for (auto it = wireCache_.begin(); it != wireCache_.end(); ++it) {
                if (it->second.expiresAtMs < victim->second.expiresAtMs) victim = it;
            }
            wireCache_.erase(victim);
        }
        const unsigned long long now = nowMs();
        wireCache_[key] = WireEntry{answer, now, now + (unsigned long long)lifetime * 1000ULL};
    }
    return answer;
}

bool Resolver::isBootstrapHost(const std::string& host) const {
    return !workerHost_.empty() && lowercase(host) == lowercase(workerHost_);
}

void Resolver::clearCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string bootstrapKey = lowercase(workerHost_);
    std::erase_if(cache_, [&bootstrapKey](const auto& entry) {
        return entry.first != bootstrapKey;
    });
    wireCache_.clear();
}

size_t Resolver::cacheSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

size_t Resolver::wireCacheSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return wireCache_.size();
}

} // namespace dns
