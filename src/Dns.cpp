#include "Dns.hpp"

#include "DnsMessage.hpp"
#include "Http.hpp"
#include "Json.hpp"
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
constexpr size_t kMaxCacheEntries = 2048;

std::string lowercase(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    while (!out.empty() && out.back() == '.') out.pop_back();
    return out;
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
                   uint16_t connectPort)
    : workerHost_(http::hostFromUrl(workerUrl))
    , sharedSecret_(std::move(sharedSecret))
    , connectPort_(connectPort) {
    if (workerHost_.empty()) {
        spdlog::warn("DNS: Worker URL cozumlenemedi ({}), sistem DNS kullanilacak", workerUrl);
        return;
    }

    // Bootstrap before WFP starts. Later WinHTTP requests still ask the
    // system resolver for this hostname; the transparent DNS proxy answers
    // those requests from this cache, preventing a recursive DoH lookup.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* resolved = nullptr;
    if (getaddrinfo(workerHost_.c_str(), "443", &hints, &resolved) == 0) {
        Result bootstrap;
        bootstrap.ttlSeconds = kMaxTtlSeconds;
        for (addrinfo* current = resolved; current; current = current->ai_next) {
            char text[INET6_ADDRSTRLEN] = {};
            if (current->ai_family == AF_INET) {
                const auto* address = reinterpret_cast<const sockaddr_in*>(current->ai_addr);
                if (inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text))) {
                    if (std::find(bootstrap.v4.begin(), bootstrap.v4.end(), text) == bootstrap.v4.end()) {
                        bootstrap.v4.emplace_back(text);
                    }
                }
            } else if (current->ai_family == AF_INET6) {
                const auto* address = reinterpret_cast<const sockaddr_in6*>(current->ai_addr);
                if (inet_ntop(AF_INET6, &address->sin6_addr, text, sizeof(text))) {
                    if (std::find(bootstrap.v6.begin(), bootstrap.v6.end(), text) == bootstrap.v6.end()) {
                        bootstrap.v6.emplace_back(text);
                    }
                }
            }
        }
        freeaddrinfo(resolved);

        if (!bootstrap.empty()) {
            cache_[lowercase(workerHost_)] = {
                bootstrap, std::numeric_limits<unsigned long long>::max()
            };
            spdlog::debug("DNS bootstrap: Worker -> {} A, {} AAAA",
                          bootstrap.v4.size(), bootstrap.v6.size());
        }
    }
}

Result Resolver::query(const std::string& host) const {
    Result result;
    if (workerHost_.empty()) return result;

    http::Request request;
    request.host = workerHost_;
    request.path = "/resolve?host=" + host;
    request.timeoutMs = 5000;
    request.connectPort = connectPort_;
    if (!sharedSecret_.empty()) {
        request.headers.push_back({"Authorization", "Bearer " + sharedSecret_});
    }

    const http::Response response = http::perform(request);

    if (response.status == 401 || response.status == 403) {
        spdlog::error("DNS: Worker kimlik dogrulamasi reddetti (HTTP {}). "
                      "--redeploy ile worker'i guncelleyin.", response.status);
        return result;
    }
    if (response.status == 429) {
        spdlog::warn("DNS: Worker rate limit (HTTP 429)");
        return result;
    }
    if (!response.ok()) {
        spdlog::warn("DNS: /resolve HTTP {} ({})", response.status, host);
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

    const long long ttl = json::getInt(response.body, "ttl", kMinTtlSeconds);
    result.ttlSeconds = (unsigned)std::clamp<long long>(ttl, kMinTtlSeconds, kMaxTtlSeconds);

    if (!result.empty()) {
        spdlog::trace("DNS: {} -> {} A, {} AAAA (ttl {}s)",
                      host, result.v4.size(), result.v6.size(), result.ttlSeconds);
    } else {
        spdlog::warn("DNS: {} icin adres yok", host);
    }
    return result;
}

Result Resolver::resolve(const std::string& host) {
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
            const unsigned long long now = GetTickCount64();
            const auto cached = cache_.find(key);
            if (cached != cache_.end() && cached->second.expiresAtMs > now) {
                return cached->second.result;
            }

            if (inFlight_.insert(key).second) break;
            cacheReady_.wait(lock, [this, &key]() {
                return !inFlight_.contains(key);
            });
        }
    }

    Result result;
    try {
        result = query(key);
    } catch (const std::exception& error) {
        spdlog::error("DNS: {} sorgusu beklenmeyen hatayla sonlandi: {}", key, error.what());
    } catch (...) {
        spdlog::error("DNS: {} sorgusu bilinmeyen hatayla sonlandi", key);
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

        const unsigned lifetime = result.empty() ? kNegativeCacheSeconds : result.ttlSeconds;
        cache_[key] = Entry{
            result,
            GetTickCount64() + (unsigned long long)lifetime * 1000ULL
        };
        inFlight_.erase(key);
    }
    cacheReady_.notify_all();
    return result;
}

std::vector<uint8_t> Resolver::queryWire(const uint8_t* message, size_t length) {
    dns_message::Query parsed;
    if (!dns_message::parseQuery(message, length, parsed)) return {};

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

    http::Request request;
    request.method = "POST";
    request.host = workerHost_;
    request.path = "/dns-query";
    request.timeoutMs = 5000;
    request.connectPort = connectPort_;
    request.headers.push_back({"Accept", "application/dns-message"});
    request.headers.push_back({"Content-Type", "application/dns-message"});
    if (!sharedSecret_.empty()) {
        request.headers.push_back({"Authorization", "Bearer " + sharedSecret_});
    }
    request.body.assign(reinterpret_cast<const char*>(message), length);

    const http::Response response = http::perform(request);
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
    return {begin, begin + response.body.size()};
}

void Resolver::clearCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

size_t Resolver::cacheSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

} // namespace dns
