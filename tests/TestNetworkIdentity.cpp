#include "Test.hpp"

#include "NetworkIdentity.hpp"

#include <chrono>

TEST(NetworkIdentityIsStableAndOpaque) {
    const std::string first = network_identity::current();
    const std::string second = network_identity::current();

    CHECK(!first.empty());
    CHECK_EQ(first, second);
    CHECK(first.starts_with("nla-") || first == "network-default");
}

TEST(CachedNetworkIdentityMatchesTheLiveValueAndIsStable) {
    const std::string cached = network_identity::currentCached();
    CHECK(!cached.empty());
    CHECK_EQ(cached, network_identity::currentCached());
    CHECK(cached.starts_with("nla-") || cached == network_identity::kDefaultId);
}

TEST(CachedIdentityRefreshesOnlyAfterTheTtl) {
    using namespace std::chrono;
    const network_identity::CachedIdentity::Clock::time_point start{};
    int calls = 0;
    std::string next = "nla-a";
    network_identity::CachedIdentity cache([&]() { ++calls; return next; }, seconds(30));

    CHECK_EQ(cache.get(start), std::string("nla-a"));
    CHECK_EQ(calls, 1);

    // Inside the window the OS is not asked again, even if the answer changed.
    next = "nla-b";
    CHECK_EQ(cache.get(start + seconds(29)), std::string("nla-a"));
    CHECK_EQ(calls, 1);

    CHECK_EQ(cache.get(start + seconds(30)), std::string("nla-b"));
    CHECK_EQ(calls, 2);
    CHECK_EQ(cache.get(start + seconds(31)), std::string("nla-b"));
    CHECK_EQ(calls, 2);
}

TEST(CachedIdentityKeepsTheLastKnownValueWhenTheLookupFails) {
    using namespace std::chrono;
    const network_identity::CachedIdentity::Clock::time_point start{};
    std::string answer = "nla-home";
    int calls = 0;
    network_identity::CachedIdentity cache([&]() { ++calls; return answer; }, seconds(30));

    CHECK_EQ(cache.get(start), std::string("nla-home"));

    // COM failure / no connected network: current() yields the fallback id.
    answer = network_identity::kDefaultId;
    CHECK_EQ(cache.get(start + seconds(40)), std::string("nla-home"));
    CHECK_EQ(calls, 2);
    // The failed refresh still resets the window; no hammering of COM.
    CHECK_EQ(cache.get(start + seconds(50)), std::string("nla-home"));
    CHECK_EQ(calls, 2);

    // A real network eventually replaces it.
    answer = "nla-hotspot";
    CHECK_EQ(cache.get(start + seconds(71)), std::string("nla-hotspot"));
}

TEST(CachedIdentityReportsTheFallbackWhenNothingWasEverKnown) {
    network_identity::CachedIdentity cache(
        []() { return std::string(network_identity::kDefaultId); },
        std::chrono::seconds(30));
    CHECK_EQ(cache.get(), std::string(network_identity::kDefaultId));
}
