#include "Test.hpp"

#include "HelloBuilder.hpp"
#include "Strategy.hpp"
#include "TlsHello.hpp"

#include <algorithm>
#include <filesystem>
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

    const strategy::Store store(tempStorePath("splithello_test_unused.json"));
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

    const strategy::Store store(tempStorePath("splithello_test_unused.json"));
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

    const strategy::Store store(tempStorePath("splithello_test_unused.json"));
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
    store.remember("home-network", "discord.com", "sni-mid",
                   diagnosis::Kind::SniInterferenceLikely, 92);

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
    store.remember("home-network", "discord.com", "sni-mid",
                   diagnosis::Kind::SniInterferenceLikely, 92);

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
        store.remember("home-network", "discord.com", "sni-mid",
                       diagnosis::Kind::SniInterferenceLikely, 92);
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
    CHECK_EQ(store.size(), (size_t)1);
    CHECK_EQ(store.lookup("a.test"), std::string("sni-mid"));
    CHECK_EQ(store.lookup("b.test"), std::string());
    CHECK_EQ(store.lookup("c.test"), std::string());

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
