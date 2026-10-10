#include "Test.hpp"

#include "FileUtil.hpp"
#include "HelloBuilder.hpp"
#include "Strategy.hpp"
#include "TlsHello.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

using testing::buildClientHello;

namespace {

tls::ClientHello parse(const std::vector<uint8_t>& data) {
    tls::ClientHello hello;
    tls::parseClientHello(data.data(), data.size(), hello);
    return hello;
}

std::string tempStorePath(const char* name) {
    return (std::filesystem::temp_directory_path() / name).string();
}

// Explicit clocks keep the interval tests deterministic. Entries still expire
// against the wall clock in lookup(), so the timeline sits in the future.
constexpr uint64_t kEpoch = 1'900'000'000ULL;

uint64_t wallClockSeconds() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Two independent differentials a minute apart: what it takes to learn.
void learn(strategy::Store& store, const std::string& network, const std::string& host,
           const std::string& profile, uint64_t at = 0) {
    const uint64_t first = at ? at : wallClockSeconds();
    store.remember(network, host, profile, diagnosis::Kind::SniInterferenceLikely, 92, first);
    store.remember(network, host, profile, diagnosis::Kind::SniInterferenceLikely, 92, first + 61);
}

void writeFile(const std::string& path, const std::string& content) {
    std::FILE* file = nullptr;
    fopen_s(&file, path.c_str(), "wb");
    if (!file) throw std::runtime_error("cannot create " + path);
    fwrite(content.data(), 1, content.size(), file);
    fclose(file);
}

// strategies.json line for a version-2 entry; verifiedAt 0 marks a legacy one.
std::string entryLine(const std::string& key, const std::string& profile,
                      uint64_t expiresAt, uint64_t verifiedAt) {
    return "\"" + key + "\":\"" + profile + ";sni-interference-likely;92;" +
           std::to_string(expiresAt) + ";0;" + std::to_string(verifiedAt) + "\"";
}

} // namespace

TEST(SniMidSplitsInsideTheHostname) {
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);

    strategy::FragmentPlan plan;
    CHECK(strategy::buildPlan("sni-mid", hello, 20, plan));
    CHECK_EQ(plan.recordSplits.size(), (size_t)1);

    // Plan offsets are relative to the record payload.
    const size_t sniStart = hello.sniOffset - tls::kRecordHeaderSize;
    const size_t sniEnd = sniStart + hello.sniLength;

    CHECK(plan.recordSplits[0] > sniStart);
    CHECK(plan.recordSplits[0] < sniEnd);
}

TEST(EverySplitStaysInsideTheRecord) {
    const std::vector<uint8_t> data = buildClientHello({"discord.com", 2000, false, true});
    const tls::ClientHello hello = parse(data);

    for (const strategy::Profile& profile : strategy::profiles()) {
        strategy::FragmentPlan plan;
        if (!strategy::buildPlan(profile.name, hello, 20, plan)) continue;

        for (const size_t split : plan.recordSplits) {
            CHECK(split >= 1);
            CHECK(split < hello.recordPayloadLength);
        }
        CHECK(std::is_sorted(plan.recordSplits.begin(), plan.recordSplits.end()));
        CHECK(std::adjacent_find(plan.recordSplits.begin(), plan.recordSplits.end()) ==
              plan.recordSplits.end());
    }
}

TEST(NoneProfileMakesNoCuts) {
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);

    strategy::FragmentPlan plan;
    CHECK(strategy::buildPlan("none", hello, 20, plan));
    CHECK(!plan.splitsAnything());
}

TEST(UnknownProfileIsRejected) {
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);

    strategy::FragmentPlan plan;
    CHECK(!strategy::buildPlan("does-not-exist", hello, 20, plan));
    CHECK(strategy::findProfile("does-not-exist") == nullptr);
}

// Chromium can send a GREASE ECH extension even without a DNS ECH config, so
// the extension alone must not disable otherwise valid TLS profiles.
TEST(EchExtensionAloneDoesNotDisableProfiles) {
    const std::vector<uint8_t> data = buildClientHello({"cloudflare-ech.com", 0, true, true});
    const tls::ClientHello hello = parse(data);
    CHECK(hello.hasEch);

    strategy::FragmentPlan plan;
    CHECK(strategy::buildPlan("sni-mid", hello, 20, plan));

    strategy::Store store(tempStorePath("splithello_test_unused.json"));
    const std::vector<std::string> order = store.probeOrder("cloudflare-ech.com", hello);
    CHECK_EQ(order.size(), strategy::profiles().size());
    CHECK_EQ(order[0], std::string("none"));
}

TEST(AlreadyFragmentedHelloIsLeftAlone) {
    std::vector<uint8_t> data = buildClientHello();
    const size_t half = (data.size() - tls::kRecordHeaderSize) / 2;
    data[3] = (uint8_t)(half >> 8);
    data[4] = (uint8_t)(half & 0xFF);
    data.resize(tls::kRecordHeaderSize + half);

    const tls::ClientHello hello = parse(data);
    CHECK(hello.spansRecords);

    strategy::FragmentPlan plan;
    CHECK(!strategy::buildPlan("record-1", hello, 20, plan));
}

TEST(ProbeOrderSkipsSniProfilesWhenThereIsNoSni) {
    const std::vector<uint8_t> data = buildClientHello({"", 0, false, false});
    const tls::ClientHello hello = parse(data);
    CHECK(!hello.hasSni());

    strategy::Store store(tempStorePath("splithello_test_unused.json"));
    const std::vector<std::string> order = store.probeOrder("example.com", hello);

    CHECK(!order.empty());
    for (const std::string& name : order) {
        const strategy::Profile* profile = strategy::findProfile(name);
        CHECK(profile != nullptr);
        CHECK(!profile->requiresSni);
    }
}

TEST(UnknownPathStartsWithUntouchedBaseline) {
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);

    strategy::Store store(tempStorePath("splithello_test_unused.json"));
    const std::vector<std::string> order =
        store.probeOrder("network-a", "new.example", hello);

    CHECK(!order.empty());
    CHECK_EQ(order.front(), std::string("none"));
    CHECK_EQ(order.size(), strategy::profiles().size());
}

TEST(LearnedProfilesAreScopedToTheCurrentNetwork) {
    const std::string path = tempStorePath("splithello_test_network_scope.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    learn(store, "home-network", "discord.com", "sni-mid");

    CHECK_EQ(store.lookup("home-network", "discord.com"), std::string("sni-mid"));
    CHECK_EQ(store.lookup("mobile-network", "discord.com"), std::string());

    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    CHECK_EQ(store.probeOrder("home-network", "discord.com", hello).front(),
             std::string("sni-mid"));
    CHECK_EQ(store.probeOrder("mobile-network", "discord.com", hello).front(),
             std::string("none"));

    std::filesystem::remove(path);
}

TEST(CachedProfileIsEvictedAfterTwoConsecutiveFailures) {
    const std::string path = tempStorePath("splithello_test_failure_eviction.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    learn(store, "home-network", "discord.com", "sni-mid");

    store.recordFailure("home-network", "discord.com", "sni-mid");
    CHECK_EQ(store.lookup("home-network", "discord.com"), std::string("sni-mid"));

    store.recordFailure("home-network", "discord.com", "sni-mid");
    CHECK_EQ(store.lookup("home-network", "discord.com"), std::string());

    std::filesystem::remove(path);
}

TEST(StoreRemembersAcrossReloads) {
    const std::string path = tempStorePath("splithello_test_strategies.json");
    std::filesystem::remove(path);

    {
        strategy::Store store(path);
        store.load();
        store.remember("Discord.com.", "record-1");
        store.remember("example.org", "sni-mid");
        CHECK_EQ(store.size(), (size_t)2);
    }

    strategy::Store reloaded(path);
    reloaded.load();
    CHECK_EQ(reloaded.size(), (size_t)2);
    CHECK_EQ(reloaded.lookup("discord.com"), std::string("record-1"));
    CHECK_EQ(reloaded.lookup("DISCORD.COM"), std::string("record-1"));
    CHECK_EQ(reloaded.lookup("unknown.test"), std::string());

    reloaded.forget("discord.com");
    CHECK_EQ(reloaded.lookup("discord.com"), std::string());

    reloaded.clear();
    CHECK_EQ(reloaded.size(), (size_t)0);

    std::filesystem::remove(path);
}

TEST(UntouchedBaselineIsNotPersistedAsLearnedState) {
    const std::string path = tempStorePath("splithello_test_clean_baseline.json");
    std::filesystem::remove(path);

    {
        strategy::Store store(path);
        learn(store, "home-network", "discord.com", "sni-mid");
        CHECK_EQ(store.size(), (size_t)1);

        store.remember("home-network", "discord.com", "none",
                       diagnosis::Kind::NoInterference, 95);
        CHECK_EQ(store.size(), (size_t)0);
        CHECK_EQ(store.lookup("home-network", "discord.com"), std::string());
    }

    strategy::Store reloaded(path);
    reloaded.load();
    CHECK_EQ(reloaded.size(), (size_t)0);

    std::filesystem::remove(path);
}

TEST(StoreDropsProfilesThisBuildDoesNotKnow) {
    const std::string path = tempStorePath("splithello_test_unknown_profile.json");
    const std::string content =
        R"({"version":1,"domains":{"a.test":"sni-mid","b.test":"retired-profile","c.test":"none"}})";

    std::filesystem::remove(path);
    {
        std::FILE* file = nullptr;
        fopen_s(&file, path.c_str(), "wb");
        CHECK(file != nullptr);
        fwrite(content.data(), 1, content.size(), file);
        fclose(file);
    }

    strategy::Store store(path);
    store.load();
    // Version 1 entries carry no verification time: they come back as
    // candidates that must re-prove themselves, never as trusted winners.
    CHECK_EQ(store.size(), (size_t)0);
    CHECK_EQ(store.lookup("a.test"), std::string());
    CHECK_EQ(store.lookup("b.test"), std::string());
    CHECK_EQ(store.lookup("c.test"), std::string());

    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    const std::vector<std::string> pending = store.probeOrder("a.test", hello);
    CHECK(pending.size() >= 2);
    CHECK_EQ(pending[0], std::string("none"));
    CHECK_EQ(pending[1], std::string("sni-mid"));
    for (const std::string& name : store.probeOrder("b.test", hello)) {
        CHECK(strategy::findProfile(name) != nullptr);
    }

    std::filesystem::remove(path);
}

TEST(RememberedProfileIsProbedFirst) {
    const std::string path = tempStorePath("splithello_test_order.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    store.remember("discord.com", "sni-multi");

    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    const std::vector<std::string> order = store.probeOrder("discord.com", hello);

    CHECK(!order.empty());
    CHECK_EQ(order[0], std::string("sni-multi"));
    CHECK_EQ(std::count(order.begin(), order.end(), std::string("sni-multi")), (ptrdiff_t)1);

    std::filesystem::remove(path);
}

TEST(HostNormalisation) {
    CHECK_EQ(strategy::normalizeHost("Discord.COM."), std::string("discord.com"));
    CHECK_EQ(strategy::normalizeHost("example.org"), std::string("example.org"));
    CHECK_EQ(strategy::normalizeHost(""), std::string());
}

TEST(LearnedWinnerIsReverifiedAfterTheInterval) {
    const std::string path = tempStorePath("splithello_test_reverify.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    learn(store, "home", "blocked.test", "sni-mid", kEpoch);
    const uint64_t learnedAt = kEpoch + 61;

    // A fresh winner leads and nothing is re-tested.
    CHECK_EQ(store.probeOrder("home", "blocked.test", hello, learnedAt + 60).front(),
             std::string("sni-mid"));

    // Half an hour later the untouched baseline leads and the winner is the
    // immediate retry, listed exactly once.
    const uint64_t later = learnedAt + 30 * 60;
    const std::vector<std::string> order =
        store.probeOrder("home", "blocked.test", hello, later);
    CHECK(order.size() >= 2);
    CHECK_EQ(order[0], std::string("none"));
    CHECK_EQ(order[1], std::string("sni-mid"));
    CHECK_EQ(std::count(order.begin(), order.end(), std::string("none")), (ptrdiff_t)1);
    CHECK_EQ(std::count(order.begin(), order.end(), std::string("sni-mid")), (ptrdiff_t)1);

    // A parallel connection seconds later does not start a second re-check.
    CHECK_EQ(store.probeOrder("home", "blocked.test", hello, later + 2).front(),
             std::string("sni-mid"));

    // Re-proving the winner restarts the interval.
    CHECK(store.remember("home", "blocked.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, later + 3) ==
          strategy::Store::Outcome::Reverified);
    CHECK_EQ(store.probeOrder("home", "blocked.test", hello, later + 20 * 60).front(),
             std::string("sni-mid"));

    // A baseline that succeeds on re-check retires the winner.
    CHECK(store.remember("home", "blocked.test", "none",
                         diagnosis::Kind::NoInterference, 95, later + 4) ==
          strategy::Store::Outcome::Forgotten);
    CHECK_EQ(store.lookup("home", "blocked.test"), std::string());

    std::filesystem::remove(path);
}

TEST(TransientVerdictIsNeverLearned) {
    const std::string path = tempStorePath("splithello_test_transient.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    store.remember("home", "flaky.test", "record-1",
                   diagnosis::Kind::TransientFailure, 70, kEpoch);
    CHECK_EQ(store.lookup("home", "flaky.test"), std::string());
    CHECK_EQ(store.size(), (size_t)0);

    std::filesystem::remove(path);
}

TEST(CacheHitKeepsAWinnerAliveButCannotCreateOne) {
    const std::string path = tempStorePath("splithello_test_cache_hit.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    CHECK(store.remember("home", "cached.test", "sni-mid",
                         diagnosis::Kind::LearnedProfile, 65, kEpoch) ==
          strategy::Store::Outcome::Ignored);
    CHECK_EQ(store.lookup("home", "cached.test"), std::string());

    learn(store, "home", "cached.test", "sni-mid", kEpoch);
    const uint64_t learnedAt = kEpoch + 61;
    store.recordFailure("home", "cached.test", "sni-mid");
    CHECK(store.remember("home", "cached.test", "sni-mid",
                         diagnosis::Kind::LearnedProfile, 65, learnedAt + 10) ==
          strategy::Store::Outcome::Refreshed);

    // Failures reset, but the cache hit did not count as re-verification.
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    CHECK_EQ(store.probeOrder("home", "cached.test", hello, learnedAt + 31 * 60).front(),
             std::string("none"));
    store.recordFailure("home", "cached.test", "sni-mid");
    CHECK_EQ(store.lookup("home", "cached.test"), std::string("sni-mid"));

    std::filesystem::remove(path);
}

TEST(HealthyBaselineVouchesForAHostForAWhile) {
    strategy::Store store(tempStorePath("splithello_test_unused.json"));
    CHECK(!store.baselineRecentlyHealthy("home", "api.test", kEpoch));

    store.noteBaselineHealthy("home", "API.test.", kEpoch);
    CHECK(store.baselineRecentlyHealthy("home", "api.test", kEpoch + 60));
    CHECK(store.baselineRecentlyHealthy("home", "api.test", kEpoch + 14 * 60));
    CHECK(!store.baselineRecentlyHealthy("home", "api.test", kEpoch + 16 * 60));
    CHECK(!store.baselineRecentlyHealthy("hotspot", "api.test", kEpoch + 60));
}

TEST(VerificationTimeSurvivesReloadAndLegacyEntriesBecomeCandidates) {
    const std::string path = tempStorePath("splithello_test_verified_reload.json");
    std::filesystem::remove(path);

    const uint64_t now = wallClockSeconds();
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    {
        strategy::Store store(path);
        learn(store, "home", "blocked.test", "sni-mid", now);
    }
    {
        strategy::Store reloaded(path);
        reloaded.load();
        CHECK_EQ(reloaded.lookup("home", "blocked.test"), std::string("sni-mid"));
        CHECK_EQ(reloaded.probeOrder("home", "blocked.test", hello, now + 120).front(),
                 std::string("sni-mid"));
    }

    // An entry written before verification times existed is not trusted: it
    // becomes a candidate that has to reproduce its differential twice.
    const std::string legacy =
        "{\"version\":2,\"domains\":{\"home|old.test\":\"record-1;sni-interference-likely;92;" +
        std::to_string(now + 3600) + ";0\"}}";
    std::FILE* file = nullptr;
    fopen_s(&file, path.c_str(), "wb");
    CHECK(file != nullptr);
    fwrite(legacy.data(), 1, legacy.size(), file);
    fclose(file);

    strategy::Store upgraded(path);
    upgraded.load();
    CHECK_EQ(upgraded.lookup("home", "old.test"), std::string());
    const std::vector<std::string> order =
        upgraded.probeOrder("home", "old.test", hello, now + 60);
    CHECK(order.size() >= 2);
    CHECK_EQ(order[0], std::string("none"));
    CHECK_EQ(order[1], std::string("record-1"));

    CHECK(upgraded.remember("home", "old.test", "record-1",
                            diagnosis::Kind::SniInterferenceLikely, 92, now + 70) ==
          strategy::Store::Outcome::Candidate);
    CHECK_EQ(upgraded.lookup("home", "old.test"), std::string());
    CHECK(upgraded.remember("home", "old.test", "record-1",
                            diagnosis::Kind::SniInterferenceLikely, 92, now + 140) ==
          strategy::Store::Outcome::Learned);
    CHECK_EQ(upgraded.lookup("home", "old.test"), std::string("record-1"));

    std::filesystem::remove(path);
}

TEST(SingleDifferentialOnlyNominatesACandidate) {
    const std::string path = tempStorePath("splithello_test_candidate.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);

    CHECK(store.remember("home", "maybe.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch) ==
          strategy::Store::Outcome::Candidate);
    CHECK_EQ(store.lookup("home", "maybe.test"), std::string());
    CHECK_EQ(store.size(), (size_t)0);

    // The candidate rides right behind the baseline so confirming it is cheap.
    const std::vector<std::string> order =
        store.probeOrder("home", "maybe.test", hello, kEpoch + 5);
    CHECK_EQ(order[0], std::string("none"));
    CHECK_EQ(order[1], std::string("sni-mid"));
    CHECK_EQ(std::count(order.begin(), order.end(), std::string("sni-mid")), (ptrdiff_t)1);

    // A parallel connection failing seconds later is the same hiccup.
    CHECK(store.remember("home", "maybe.test", "record-1",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 30) ==
          strategy::Store::Outcome::Candidate);
    CHECK_EQ(store.lookup("home", "maybe.test"), std::string());

    // A clearly later connection reproducing the differential confirms it.
    CHECK(store.remember("home", "maybe.test", "record-1",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 61) ==
          strategy::Store::Outcome::Learned);
    CHECK_EQ(store.lookup("home", "maybe.test"), std::string("record-1"));
    CHECK_EQ(store.probeOrder("home", "maybe.test", hello, kEpoch + 70).front(),
             std::string("record-1"));

    std::filesystem::remove(path);
}

TEST(HealthyBaselineCancelsACandidate) {
    strategy::Store store(tempStorePath("splithello_test_unused.json"));

    store.remember("home", "flaky.test", "sni-mid",
                   diagnosis::Kind::SniInterferenceLikely, 92, kEpoch);
    store.noteBaselineHealthy("home", "flaky.test", kEpoch + 10);

    // The next strike starts over: it is a first strike, not a confirmation.
    CHECK(store.remember("home", "flaky.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 120) ==
          strategy::Store::Outcome::Candidate);
    CHECK_EQ(store.lookup("home", "flaky.test"), std::string());
    CHECK(store.remember("home", "flaky.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 200) ==
          strategy::Store::Outcome::Learned);
}

TEST(StaleCandidateDoesNotConfirm) {
    strategy::Store store(tempStorePath("splithello_test_unused.json"));

    store.remember("home", "rare.test", "sni-mid",
                   diagnosis::Kind::SniInterferenceLikely, 92, kEpoch);
    CHECK(store.remember("home", "rare.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 7 * 3600) ==
          strategy::Store::Outcome::Candidate);
    CHECK_EQ(store.lookup("home", "rare.test"), std::string());
}

TEST(ReverifyWithFailingBaselineThenWinnerSucceedsIsReverified) {
    strategy::Store store("");
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    learn(store, "home", "blocked.test", "sni-mid", kEpoch);
    const uint64_t later = kEpoch + 61 + 31 * 60;

    // Due for a re-check: baseline first, then the winner.
    const std::vector<std::string> order =
        store.probeOrder("home", "blocked.test", hello, later);
    CHECK_EQ(order[0], std::string("none"));
    CHECK_EQ(order[1], std::string("sni-mid"));

    // The baseline failed again and the winner got through: the relay reports
    // the differential and the winner re-proves itself instead of being replaced.
    CHECK(store.remember("home", "blocked.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, later + 3) ==
          strategy::Store::Outcome::Reverified);
    CHECK_EQ(store.lookup("home", "blocked.test"), std::string("sni-mid"));
    CHECK_EQ(store.candidateCount(), (size_t)0);
    CHECK_EQ(store.probeOrder("home", "blocked.test", hello, later + 60).front(),
             std::string("sni-mid"));
    CHECK_EQ(store.probeOrder("home", "blocked.test", hello, later + 3 + 31 * 60).front(),
             std::string("none"));
}

TEST(StrikesInsideTheConfirmationGapNeverLearn) {
    strategy::Store store("");

    // A hiccup fails a burst of parallel connections within seconds.
    for (uint64_t offset = 0; offset < 60; offset += 3) {
        CHECK(store.remember("home", "burst.test", "sni-mid",
                             diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + offset) ==
              strategy::Store::Outcome::Candidate);
    }
    CHECK_EQ(store.lookup("home", "burst.test"), std::string());
    CHECK_EQ(store.size(), (size_t)0);

    // The first strike's clock was never refreshed by the burst.
    CHECK(store.remember("home", "burst.test", "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 60) ==
          strategy::Store::Outcome::Learned);
}

TEST(CandidatesAreCappedAndTheStalestIsEvictedFirst) {
    strategy::Store store("");
    constexpr size_t kCap = 1000;
    const auto host = [](size_t i) { return "h" + std::to_string(i) + ".test"; };

    for (size_t i = 0; i < kCap + 100; ++i) {
        CHECK(store.remember("home", host(i), "sni-mid",
                             diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + i) ==
              strategy::Store::Outcome::Candidate);
    }
    CHECK_EQ(store.candidateCount(), kCap);

    // The oldest nomination is gone: its next strike starts over instead of
    // confirming, however much later it arrives.
    CHECK(store.remember("home", host(0), "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92, kEpoch + 5000) ==
          strategy::Store::Outcome::Candidate);
    CHECK_EQ(store.candidateCount(), kCap);

    // The newest one survived and still confirms.
    CHECK(store.remember("home", host(kCap + 99), "sni-mid",
                         diagnosis::Kind::SniInterferenceLikely, 92,
                         kEpoch + kCap + 99 + 61) == strategy::Store::Outcome::Learned);
}

TEST(FullCacheEvictsTheOldestVerifiedWinnerNotARandomOne) {
    strategy::Store store("");
    constexpr size_t kCap = 1000;
    const auto host = [](size_t i) { return "e" + std::to_string(i) + ".test"; };

    for (size_t i = 0; i < kCap; ++i) {
        learn(store, "home", host(i), "sni-mid", kEpoch + i * 200);
    }
    CHECK_EQ(store.size(), kCap);

    learn(store, "home", host(kCap), "sni-mid", kEpoch + kCap * 200);
    CHECK_EQ(store.size(), kCap);
    CHECK_EQ(store.lookup("home", host(0)), std::string());
    CHECK_EQ(store.lookup("home", host(1)), std::string("sni-mid"));
    CHECK_EQ(store.lookup("home", host(kCap - 1)), std::string("sni-mid"));
    CHECK_EQ(store.lookup("home", host(kCap)), std::string("sni-mid"));
}

TEST(CorruptOrPartialStrategyFilesLoadWhatIsIntact) {
    const std::string path = tempStorePath("splithello_test_corrupt.json");
    const uint64_t now = wallClockSeconds();
    const std::string good = entryLine("home|a.test", "sni-mid", now + 3600, now);

    // Torn write: the second value has no closing quote and must not be trusted.
    std::filesystem::remove(path);
    writeFile(path, "{\"version\":2,\"domains\":{" + good +
                    ",\"home|b.test\":\"record-1;sni-interf");
    {
        strategy::Store store(path);
        store.load();
        CHECK_EQ(store.lookup("home", "a.test"), std::string("sni-mid"));
        CHECK_EQ(store.lookup("home", "b.test"), std::string());
        CHECK_EQ(store.candidateCount(), (size_t)0);
    }

    // Garbage and an empty file leave an empty, usable store.
    for (const char* junk : {"", "not json at all {{{", "{\"domains\":{\"x\":",
                             "{\"domains\":[1,2]}"}) {
        writeFile(path, junk);
        strategy::Store store(path);
        store.load();
        CHECK_EQ(store.size(), (size_t)0);
        CHECK_EQ(store.candidateCount(), (size_t)0);
        store.remember("after.test", "sni-mid");
        CHECK_EQ(store.lookup("after.test"), std::string("sni-mid"));
    }

    // Fields that do not parse fall back to defaults and never earn trust.
    writeFile(path, "{\"domains\":{\"home|c.test\":\"sni-mid;bogus-kind;abc;xyz;?;-5\"}}");
    {
        strategy::Store store(path);
        store.load();
        CHECK_EQ(store.lookup("home", "c.test"), std::string());
    }

    std::filesystem::remove(path);
}

TEST(DiskTimestampsAreClampedAndFutureVerificationIsNotTrusted) {
    const std::string path = tempStorePath("splithello_test_clamp.json");
    std::filesystem::remove(path);
    const uint64_t now = wallClockSeconds();
    const uint64_t farFuture = now + 365ULL * 86400ULL;
    writeFile(path, "{\"version\":2,\"domains\":{" +
                    entryLine("home|far.test", "sni-mid", farFuture, now) + "," +
                    entryLine("home|skewed.test", "record-1", now + 3600,
                              now + 10ULL * 86400ULL) + "}}");

    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    strategy::Store store(path);
    store.load();

    // A verification stamp from the future proves nothing: candidate, not winner.
    CHECK_EQ(store.lookup("home", "skewed.test"), std::string());
    const std::vector<std::string> pending = store.probeOrder("home", "skewed.test", hello);
    CHECK_EQ(pending[0], std::string("none"));
    CHECK_EQ(pending[1], std::string("record-1"));

    // The absurd expiry is cut to one TTL; saving shows what was kept.
    CHECK_EQ(store.lookup("home", "far.test"), std::string("sni-mid"));
    store.remember("trigger.test", "sni-mid");
    std::string saved;
    CHECK(fileutil::readAll(path, saved));
    CHECK(saved.find(std::to_string(farFuture)) == std::string::npos);

    std::filesystem::remove(path);
}

TEST(WallClockStepBackMakesAWinnerOverdueInsteadOfImmortal) {
    strategy::Store store("");
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    learn(store, "home", "blocked.test", "sni-mid", kEpoch);

    // The persisted stamp is hours ahead of the (stepped-back) clock.
    CHECK_EQ(store.probeOrder("home", "blocked.test", hello, kEpoch - 3 * 3600).front(),
             std::string("none"));
}

TEST(LegacyCandidatesSurviveSavesUntilPromotedOrCancelled) {
    const std::string path = tempStorePath("splithello_test_legacy_persist.json");
    std::filesystem::remove(path);
    const uint64_t now = wallClockSeconds();
    const std::vector<uint8_t> data = buildClientHello();
    const tls::ClientHello hello = parse(data);
    writeFile(path, "{\"version\":2,\"domains\":{" +
                    entryLine("home|old.test", "record-1", now + 3600, 0) + "}}");

    const auto isPending = [&](const std::string& host) {
        strategy::Store reloaded(path);
        reloaded.load();
        const std::vector<std::string> order =
            reloaded.probeOrder("home", host, hello, now + 60);
        return order.size() >= 2 && order[0] == "none" && order[1] == "record-1";
    };

    strategy::Store store(path);
    store.load();
    CHECK(isPending("old.test"));

    // An unrelated save rewrites the file; the nomination must still be in it.
    learn(store, "home", "other.test", "sni-mid", now);
    CHECK(isPending("old.test"));

    // A healthy baseline cancels it for good.
    store.noteBaselineHealthy("home", "old.test");
    CHECK(!isPending("old.test"));

    std::filesystem::remove(path);
}

TEST(SequentialSavesLeaveTheNewestStateOnDisk) {
    const std::string path = tempStorePath("splithello_test_snapshot_order.json");
    std::filesystem::remove(path);

    strategy::Store store(path);
    store.remember("first.test", "sni-mid");
    store.remember("second.test", "record-1");

    strategy::Store reloaded(path);
    reloaded.load();
    CHECK_EQ(reloaded.lookup("first.test"), std::string("sni-mid"));
    CHECK_EQ(reloaded.lookup("second.test"), std::string("record-1"));

    std::filesystem::remove(path);
}
