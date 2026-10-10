// Resolver and TransparentDnsProxy::buildReply against a fake Worker: no network,
// no sockets, and a hand-driven clock so cache expiry needs no sleeping.

#include "Test.hpp"

#include "TransparentDnsProxy.hpp"   // first: pulls in winsock2 before windows.h

#include "Dns.hpp"
#include "DnsMessage.hpp"
#include "DnsQueryBuilder.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using Handler = std::function<http::Response(const http::Request&)>;

struct Winsock {
    Winsock() { WSADATA data{}; WSAStartup(MAKEWORD(2, 2), &data); }
    ~Winsock() { WSACleanup(); }
};

http::Response status(int code, unsigned retryAfterSeconds = 0) {
    http::Response response;
    response.status = code;
    response.retryAfterSeconds = retryAfterSeconds;
    return response;
}

http::Response ok(std::string body) {
    http::Response response;
    response.status = 200;
    response.body = std::move(body);
    return response;
}

std::vector<uint8_t> bytesOf(const std::string& text) {
    return {text.begin(), text.end()};
}

http::Response wireOk(const std::vector<uint8_t>& message) {
    return ok(std::string(message.begin(), message.end()));
}

// What the DoH upstream would say to the posted query.
http::Response upstreamAnswer(const http::Request& request,
                              const std::vector<std::string>& addresses = {"203.0.113.9"},
                              uint32_t ttl = 120, bool failed = false, uint8_t rcode = 0) {
    const std::vector<uint8_t> posted = bytesOf(request.body);
    dns_message::Query query;
    if (!dns_message::parseQuery(posted.data(), posted.size(), query)) return status(400);
    return wireOk(dns_message::buildResponse(query, addresses, ttl, failed, rcode));
}

// A TXT answer with `payload` bytes of RDATA, to exceed UDP size limits.
http::Response bigTxtAnswer(const http::Request& request, size_t payload) {
    const std::vector<uint8_t> posted = bytesOf(request.body);
    dns_message::Query query;
    if (!dns_message::parseQuery(posted.data(), posted.size(), query)) return status(400);
    query.ednsPayload = 0; // an OPT record built here would sit in front of the TXT answer
    std::vector<uint8_t> message = dns_message::buildResponse(query, {}, 60);
    message[7] = 1; // ANCOUNT = 1
    message.push_back(0xC0);
    message.push_back(0x0C);
    dnstest::put16(message, 16);
    dnstest::put16(message, 1);
    dnstest::put16(message, 0);
    dnstest::put16(message, 60);
    dnstest::put16(message, (uint16_t)payload);
    message.insert(message.end(), payload, 'x');
    return wireOk(message);
}

struct FakeWorker {
    std::mutex mutex;
    std::vector<http::Request> seen;
    std::atomic<int> resolveCalls{0};
    std::atomic<int> wireCalls{0};
    std::atomic<int> bootstrapCalls{0};
    std::atomic<unsigned long long> clock{1'000'000};

    Handler resolve = [](const http::Request&) {
        return ok(R"({"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0})");
    };
    Handler wire = [](const http::Request& request) { return upstreamAnswer(request); };
    Handler bootstrap = [](const http::Request&) { return status(-1); };

    http::Response handle(const http::Request& request) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            seen.push_back(request);
        }
        if (request.host == "1.1.1.1") {
            ++bootstrapCalls;
            return bootstrap(request);
        }
        if (request.path == "/dns-query") {
            ++wireCalls;
            return wire(request);
        }
        ++resolveCalls;
        return resolve(request);
    }

    dns::Hooks hooks() {
        dns::Hooks hooks;
        hooks.fetch = [this](const http::Request& request) { return handle(request); };
        hooks.now = [this]() -> unsigned long long { return clock.load(); };
        return hooks;
    }

    void advance(unsigned long long ms) { clock += ms; }
};

bool hasHeader(const http::Request& request, const std::string& name) {
    return std::any_of(request.headers.begin(), request.headers.end(),
                       [&](const auto& header) { return header.first == name; });
}

// "localhost" always resolves, so the bootstrap cache is populated by the
// constructor exactly like a normal start-up.
const char* const kWorkerUrl = "https://localhost";

} // namespace

TEST(ResolverCachesResultsAndAgesTheTtl) {
    Winsock winsock;
    FakeWorker worker;
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    const dns::Result first = resolver.resolve("Example.COM.");
    CHECK_EQ(first.v4.size(), (size_t)1);
    CHECK_EQ(first.ttlSeconds, 300U);
    CHECK_EQ(worker.resolveCalls.load(), 1);
    CHECK_EQ(worker.seen.back().path, std::string("/resolve?host=example.com"));
    CHECK(worker.seen.back().headers.front() ==
          std::make_pair(std::string("Authorization"), std::string("Bearer secret")));

    worker.advance(100'000);
    const dns::Result cached = resolver.resolve("example.com");
    CHECK_EQ(worker.resolveCalls.load(), 1);
    CHECK_EQ(cached.ttlSeconds, 200U);          // 300 s minus the 100 s it sat in the cache

    worker.advance(201'000);                    // past the 300 s lifetime
    resolver.resolve("example.com");
    CHECK_EQ(worker.resolveCalls.load(), 2);
}

TEST(ResolverNegativeCachesNxdomainBriefly) {
    Winsock winsock;
    FakeWorker worker;
    worker.resolve = [](const http::Request&) {
        return ok(R"({"host":"nope.example","a":[],"aaaa":[],"ttl":60,"rcode":3})");
    };
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    const dns::Result result = resolver.resolve("nope.example");
    CHECK(result.empty());
    CHECK_EQ(result.rcode, (uint8_t)dns_message::kRcodeNxDomain);
    CHECK(!result.transient);
    CHECK(!result.allowWireFallback);

    worker.advance(29'000);
    CHECK_EQ(resolver.resolve("nope.example").rcode, (uint8_t)3);
    CHECK_EQ(worker.resolveCalls.load(), 1);
    worker.advance(2'000);                       // 30 s negative lifetime is over
    resolver.resolve("nope.example");
    CHECK_EQ(worker.resolveCalls.load(), 2);
}

TEST(ResolverCachesHalfFailedAnswersOnlyForAMoment) {
    Winsock winsock;
    FakeWorker worker;
    worker.resolve = [](const http::Request&) {
        return ok(R"({"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":3600,"rcode":0,"partial":true})");
    };
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    const dns::Result partial = resolver.resolve("half.example");
    CHECK(partial.transient);
    CHECK(partial.ttlSeconds <= 5U);             // not the Worker's 3600 s
    worker.advance(2'000);
    resolver.resolve("half.example");
    CHECK_EQ(worker.resolveCalls.load(), 1);
    worker.advance(2'000);                       // the A-only answer must not stick
    resolver.resolve("half.example");
    CHECK_EQ(worker.resolveCalls.load(), 2);
}

TEST(ResolverFallsBackToWireForOldWorkersAndUnsafeNames) {
    Winsock winsock;
    FakeWorker worker;
    worker.resolve = [](const http::Request&) { return status(404); };
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    const dns::Result legacy = resolver.resolve("old-worker.example");
    CHECK(legacy.empty());
    CHECK(legacy.allowWireFallback);

    // Names outside [a-z0-9.-] never reach the request line.
    const int before = worker.resolveCalls.load();
    for (const char* bad : {"a&b=c.example", "evil.example/../x", "with space.example",
                            "under_score.example", "x.example\r\nHost: y", "h?x=1.example"}) {
        const dns::Result result = resolver.resolve(bad);
        CHECK(result.empty());
        CHECK(result.allowWireFallback);
    }
    CHECK_EQ(worker.resolveCalls.load(), before);
}

TEST(ResolverBacksOffOnRateLimitWithoutCountingItAsFailure) {
    Winsock winsock;
    FakeWorker worker;
    worker.resolve = [](const http::Request&) { return status(429, 10); };
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    CHECK(resolver.resolve("a.example").transient);
    CHECK_EQ(worker.resolveCalls.load(), 1);

    // During the Retry-After window nothing else is sent to the Worker.
    CHECK(resolver.resolve("b.example").transient);
    const std::vector<uint8_t> txt = dnstest::query("c.example", 16);
    CHECK(resolver.queryWire(txt.data(), txt.size()).empty());
    CHECK_EQ(worker.resolveCalls.load(), 1);
    CHECK_EQ(worker.wireCalls.load(), 0);

    worker.advance(11'000);
    resolver.resolve("d.example");
    CHECK_EQ(worker.resolveCalls.load(), 2);
    for (int i = 0; i < 20; ++i) {
        worker.advance(11'000);
        resolver.resolve("e" + std::to_string(i) + ".example");
    }
    CHECK(!resolver.workerUnavailable());
}

TEST(ResolverSharesOneLookupBetweenConcurrentCallers) {
    Winsock winsock;
    FakeWorker worker;
    worker.resolve = [](const http::Request&) {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        return ok(R"({"host":"x","a":["203.0.113.5"],"aaaa":["2001:db8::5"],"ttl":300,"rcode":0})");
    };
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    std::vector<std::thread> threads;
    std::atomic<int> answered{0};
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&]() {
            if (!resolver.resolve("shared.example").empty()) ++answered;
        });
    }
    for (std::thread& thread : threads) thread.join();
    CHECK_EQ(answered.load(), 4);
    CHECK_EQ(worker.resolveCalls.load(), 1);
}

TEST(ResolverEvictsOldEntriesButNeverTheBootstrapAddress) {
    Winsock winsock;
    FakeWorker worker;
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());
    CHECK(!resolver.resolve("localhost").empty());

    for (int i = 0; i < 2100; ++i) {
        worker.advance(1);
        resolver.resolve("h" + std::to_string(i) + ".example");
    }
    CHECK_EQ(worker.resolveCalls.load(), 2100);
    CHECK(resolver.cacheSize() <= 2048);
    CHECK(!resolver.resolve("localhost").empty());
    CHECK_EQ(worker.resolveCalls.load(), 2100);   // still served from the bootstrap entry
}

TEST(ResolverCachesWireResponsesRewritesIdAndAgesTtls) {
    Winsock winsock;
    FakeWorker worker;
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    const auto first = dnstest::query("www.example.com", dns_message::kTypeA, 0x1111);
    const auto second = dnstest::query("WWW.Example.com", dns_message::kTypeA, 0x2222);
    const auto one = resolver.queryWire(first.data(), first.size());
    CHECK(!one.empty());
    CHECK_EQ(dnstest::read16(one, 0), (uint16_t)0x1111);
    CHECK(hasHeader(worker.seen.back(), "Authorization"));
    CHECK_EQ(worker.seen.back().method, std::string("POST"));

    worker.advance(30'000);
    const auto two = resolver.queryWire(second.data(), second.size());
    CHECK_EQ(worker.wireCalls.load(), 1);
    CHECK_EQ(dnstest::read16(two, 0), (uint16_t)0x2222);   // each client sees its own ID
    dns_message::ResponseInfo info;
    CHECK(dns_message::inspectResponse(two.data(), two.size(), info));
    CHECK_EQ(info.answerTtl, (uint32_t)90);                 // 120 s minus 30 s of cache age

    // A different type is a different key.
    const auto aaaa = dnstest::query("www.example.com", dns_message::kTypeAaaa, 0x3333);
    resolver.queryWire(aaaa.data(), aaaa.size());
    CHECK_EQ(worker.wireCalls.load(), 2);

    worker.advance(91'000);                                 // 121 s after the first fetch
    resolver.queryWire(first.data(), first.size());
    CHECK_EQ(worker.wireCalls.load(), 3);
}

TEST(ResolverWireCacheKeepsNegativesShortAndNeverCachesErrors) {
    Winsock winsock;
    FakeWorker worker;
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    worker.wire = [](const http::Request& request) {
        return upstreamAnswer(request, {}, 0, false, dns_message::kRcodeNxDomain);
    };
    const auto nx = dnstest::query("missing.example", dns_message::kTypeA);
    resolver.queryWire(nx.data(), nx.size());
    worker.advance(29'000);
    resolver.queryWire(nx.data(), nx.size());
    CHECK_EQ(worker.wireCalls.load(), 1);
    worker.advance(2'000);
    resolver.queryWire(nx.data(), nx.size());
    CHECK_EQ(worker.wireCalls.load(), 2);

    // SERVFAIL is never remembered: the next query asks again.
    worker.wire = [](const http::Request& request) {
        return upstreamAnswer(request, {}, 0, true);
    };
    const auto sf = dnstest::query("broken.example", dns_message::kTypeA);
    const int before = worker.wireCalls.load();
    resolver.queryWire(sf.data(), sf.size());
    resolver.queryWire(sf.data(), sf.size());
    CHECK_EQ(worker.wireCalls.load(), before + 2);
}

TEST(ResolverWireRejectsAnswersToADifferentQuestion) {
    Winsock winsock;
    FakeWorker worker;
    worker.wire = [](const http::Request&) {
        dns_message::Query other;
        const auto bytes = dnstest::query("other.example", dns_message::kTypeA);
        dns_message::parseQuery(bytes.data(), bytes.size(), other);
        return wireOk(dns_message::buildResponse(other, {"203.0.113.9"}, 60));
    };
    dns::Resolver resolver(kWorkerUrl, "secret", 0, worker.hooks());

    const auto bytes = dnstest::query("asked.example", dns_message::kTypeA);
    CHECK(resolver.queryWire(bytes.data(), bytes.size()).empty());
    CHECK_EQ(resolver.wireCacheSize(), (size_t)0);
}

TEST(ResolverRetriesBootstrapLazilyAfterAnOfflineStart) {
    Winsock winsock;
    FakeWorker worker;
    const std::string workerHost = "splithello-bootstrap-test.invalid";
    dns::Resolver resolver("https://" + workerHost, "secret", 0, worker.hooks());
    // A network that rewrites NXDOMAIN makes the start-up lookup succeed; then
    // there is no offline start to recover from.
    if (!resolver.resolve(workerHost).empty()) return;

    // Offline: no connection attempt to the Worker, and not a health failure.
    const dns::Result offline = resolver.resolve("first.example");
    CHECK(offline.empty());
    CHECK(offline.transient);
    CHECK_EQ(worker.resolveCalls.load(), 0);
    CHECK(worker.bootstrapCalls.load() >= 1);
    const int attempts = worker.bootstrapCalls.load();
    resolver.resolve("second.example");
    CHECK_EQ(worker.bootstrapCalls.load(), attempts);   // rate limited
    CHECK(!resolver.workerUnavailable());

    // Network is back: the next call after the retry interval bootstraps and goes through.
    worker.bootstrap = [](const http::Request& request) {
        if (request.path.find("type=AAAA") != std::string::npos) {
            return ok(R"({"Status":0})");
        }
        return ok(R"({"Status":0,"Answer":[{"name":"splithello-bootstrap-test.invalid",)"
                  R"("type":1,"TTL":60,"data":"203.0.113.77"}]})");
    };
    worker.advance(31'000);
    CHECK(!resolver.resolve("third.example").empty());
    CHECK_EQ(worker.resolveCalls.load(), 1);

    const dns::Result bootstrap = resolver.resolve(workerHost);
    CHECK_EQ(bootstrap.v4.size(), (size_t)1);
    CHECK_EQ(bootstrap.v4[0], std::string("203.0.113.77"));

    // The secret goes to the Worker only, never to the bootstrap resolver.
    for (const http::Request& request : worker.seen) {
        if (request.host == "1.1.1.1") CHECK(!hasHeader(request, "Authorization"));
    }
}

namespace {

struct ProxyFixture {
    Winsock winsock;
    FakeWorker worker;
    dns::Resolver resolver;
    transparent::DatagramRegistry datagrams;
    TransparentDnsProxy proxy;

    ProxyFixture()
        : resolver(kWorkerUrl, "secret", 0, worker.hooks())
        , proxy(resolver, datagrams, 0) {}

    std::vector<uint8_t> reply(const std::vector<uint8_t>& query) {
        return proxy.buildReply(query.data(), query.size());
    }
};

uint16_t rcodeOf(const std::vector<uint8_t>& reply) {
    return (uint16_t)(dnstest::read16(reply, 2) & 0x000F);
}

} // namespace

TEST(ProxyAnswersAddressQueriesFromTheWorkerWithEdnsAndAgedTtls) {
    ProxyFixture fixture;
    fixture.worker.resolve = [](const http::Request&) {
        return ok(R"({"host":"x","a":["203.0.113.5","203.0.113.6"],"aaaa":["2001:db8::5"],"ttl":300,"rcode":0})");
    };

    const auto a = fixture.reply(dnstest::query("example.com", dns_message::kTypeA, 0x4242, 1232));
    CHECK_EQ(dnstest::read16(a, 0), (uint16_t)0x4242);
    CHECK_EQ(rcodeOf(a), (uint16_t)0);
    CHECK_EQ(dnstest::read16(a, 6), (uint16_t)2);
    CHECK_EQ(dnstest::read16(a, 10), (uint16_t)1);        // OPT answers the client's OPT

    const auto aaaa = fixture.reply(dnstest::query("example.com", dns_message::kTypeAaaa));
    CHECK_EQ(dnstest::read16(aaaa, 6), (uint16_t)1);
    CHECK_EQ(dnstest::read16(aaaa, 10), (uint16_t)0);
    CHECK_EQ(fixture.worker.resolveCalls.load(), 1);       // one /resolve served both

    fixture.worker.advance(100'000);
    const auto later = fixture.reply(dnstest::query("example.com", dns_message::kTypeA));
    dns_message::ResponseInfo info;
    CHECK(dns_message::inspectResponse(later.data(), later.size(), info));
    CHECK_EQ(info.answerTtl, (uint32_t)200);
}

TEST(ProxyPassesNxdomainAndNodataToTheApplication) {
    ProxyFixture fixture;
    fixture.worker.resolve = [](const http::Request& request) {
        if (request.path.find("nope.example") != std::string::npos) {
            return ok(R"({"host":"nope.example","a":[],"aaaa":[],"ttl":60,"rcode":3})");
        }
        return ok(R"({"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0})");
    };

    const auto nx = fixture.reply(dnstest::query("nope.example", dns_message::kTypeA, 0x0001));
    CHECK_EQ(rcodeOf(nx), (uint16_t)dns_message::kRcodeNxDomain);
    CHECK_EQ(dnstest::read16(nx, 6), (uint16_t)0);
    CHECK_EQ(dnstest::read16(nx, 0), (uint16_t)0x0001);

    // The name exists but has no AAAA: NOERROR with an empty answer, not an error.
    const auto nodata = fixture.reply(dnstest::query("v4only.example", dns_message::kTypeAaaa));
    CHECK_EQ(rcodeOf(nodata), (uint16_t)0);
    CHECK_EQ(dnstest::read16(nodata, 6), (uint16_t)0);
}

TEST(ProxyDoesNotReportAHalfFailedLookupAsNodata) {
    ProxyFixture fixture;
    fixture.worker.resolve = [](const http::Request&) {
        return ok(R"({"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0,"partial":true})");
    };
    const auto aaaa = fixture.reply(dnstest::query("half.example", dns_message::kTypeAaaa));
    CHECK_EQ(rcodeOf(aaaa), (uint16_t)dns_message::kRcodeServFail);
    const auto a = fixture.reply(dnstest::query("half.example", dns_message::kTypeA));
    CHECK_EQ(rcodeOf(a), (uint16_t)0);
    CHECK_EQ(dnstest::read16(a, 6), (uint16_t)1);
}

TEST(ProxyUsesTheWireRelayForOldWorkersAndOtherTypes) {
    ProxyFixture fixture;
    fixture.worker.resolve = [](const http::Request&) { return status(404); };
    fixture.worker.wire = [](const http::Request& request) {
        return upstreamAnswer(request, {}, 0, false, dns_message::kRcodeNxDomain);
    };

    // 404 from an old Worker: the real RCODE comes from the wire relay, with the app's ID.
    const auto nx = fixture.reply(dnstest::query("gone.example", dns_message::kTypeA, 0x0A0A));
    CHECK_EQ(rcodeOf(nx), (uint16_t)dns_message::kRcodeNxDomain);
    CHECK_EQ(dnstest::read16(nx, 0), (uint16_t)0x0A0A);
    CHECK_EQ(fixture.worker.wireCalls.load(), 1);

    // Other record types go straight to the wire relay.
    const auto https = fixture.reply(dnstest::query("www.example.com", 65, 0x0B0B));
    CHECK_EQ(dnstest::read16(https, 0), (uint16_t)0x0B0B);
    CHECK_EQ(fixture.worker.wireCalls.load(), 2);
    CHECK_EQ(fixture.worker.resolveCalls.load(), 1);        // only the A query used /resolve
}

TEST(ProxyAnswersServfailWhenTheWorkerIsUnreachable) {
    ProxyFixture fixture;
    fixture.worker.resolve = [](const http::Request&) { return status(-1); };
    fixture.worker.wire = [](const http::Request&) { return status(-1); };

    const auto a = fixture.reply(dnstest::query("down.example", dns_message::kTypeA, 0x0C0C));
    CHECK_EQ(rcodeOf(a), (uint16_t)dns_message::kRcodeServFail);
    CHECK_EQ(dnstest::read16(a, 0), (uint16_t)0x0C0C);
    const auto txt = fixture.reply(dnstest::query("down.example", 16));
    CHECK_EQ(rcodeOf(txt), (uint16_t)dns_message::kRcodeServFail);
    CHECK(!fixture.resolver.workerUnavailable());           // a blip is not an outage
}

TEST(ProxyRepliesFormerrNotimpOrNothing) {
    ProxyFixture fixture;

    const auto statusQuery = fixture.reply(
        dnstest::query("example.com", dns_message::kTypeA, 0x7777, 0, false, 1, 0x1100));
    CHECK_EQ(statusQuery.size(), (size_t)12);
    CHECK_EQ(rcodeOf(statusQuery), (uint16_t)dns_message::kRcodeNotImp);
    CHECK_EQ(dnstest::read16(statusQuery, 0), (uint16_t)0x7777);

    const auto chaos = fixture.reply(dnstest::query("version.bind", 16, 0x5555, 0, false, 3));
    CHECK_EQ(rcodeOf(chaos), (uint16_t)dns_message::kRcodeNotImp);

    const auto badName = fixture.reply(dnstest::query("bad name.example", dns_message::kTypeA, 0x6666));
    CHECK_EQ(rcodeOf(badName), (uint16_t)dns_message::kRcodeFormErr);
    CHECK_EQ(dnstest::read16(badName, 0), (uint16_t)0x6666);

    // Nothing to address a reply to: a response packet, or too short for a header.
    CHECK(fixture.reply(dnstest::query("example.com", dns_message::kTypeA, 1, 0, false, 1, 0x8180)).empty());
    CHECK(fixture.reply({1, 2, 3, 4, 5}).empty());
    CHECK_EQ(fixture.worker.resolveCalls.load() + fixture.worker.wireCalls.load(), 0);
}

TEST(ProxyTruncatesOversizedAnswersToTheClientsUdpSize) {
    ProxyFixture fixture;
    fixture.worker.wire = [](const http::Request& request) { return bigTxtAnswer(request, 700); };

    // No EDNS: 512 bytes. Header + question with TC=1 tells the client to use TCP.
    const auto plainQuery = dnstest::query("big.example", 16, 0x0D0D);
    const auto plain = fixture.reply(plainQuery);
    CHECK((dnstest::read16(plain, 2) & 0x0200) != 0);
    CHECK_EQ(dnstest::read16(plain, 6), (uint16_t)0);
    CHECK_EQ(plain.size(), plainQuery.size());                // no EDNS record in this query
    CHECK_EQ(dnstest::read16(plain, 0), (uint16_t)0x0D0D);

    // An advertised 4096 holds the whole answer; 600 still does not.
    const auto large = fixture.reply(dnstest::query("big.example", 16, 0x0E0E, 4096));
    CHECK((dnstest::read16(large, 2) & 0x0200) == 0);
    CHECK_EQ(dnstest::read16(large, 6), (uint16_t)1);
    CHECK(large.size() > 700);
    const auto small = fixture.reply(dnstest::query("big.example", 16, 0x0F0F, 600));
    CHECK((dnstest::read16(small, 2) & 0x0200) != 0);
    // The plain and the EDNS flavours are separate cache keys; 4096 and 600 share one.
    CHECK_EQ(fixture.worker.wireCalls.load(), 2);
}
