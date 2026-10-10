#include "Test.hpp"

#include "TransparentFlow.hpp"

namespace {

using Kind = transparent::TcpFlowTable::Kind;

transparent::Address address(const char* text) {
    transparent::Address out{};
    CHECK(transparent::parseAddress(text, out));
    return out;
}

} // namespace

TEST(TransparentRouteReflectsApplicationHttpsToProxy) {
    CHECK_EQ((int)transparent::routePacket(true, 52000, 443, 443, 1080, 65534),
             (int)transparent::PacketRoute::ReflectClientToProxy);
}

TEST(TransparentRouteReflectsProxyRepliesBackToApplication) {
    CHECK_EQ((int)transparent::routePacket(true, 1080, 52000, 443, 1080, 65534),
             (int)transparent::PacketRoute::ReflectProxyToClient);
}

TEST(TransparentRouteMapsPrivateConnectPortToHttps) {
    CHECK_EQ((int)transparent::routePacket(true, 53000, 65534, 443, 1080, 65534),
             (int)transparent::PacketRoute::RedirectProxyToTarget);
    CHECK_EQ((int)transparent::routePacket(false, 443, 53000, 443, 1080, 65534),
             (int)transparent::PacketRoute::RedirectTargetToProxy);
}

TEST(TransparentFlowMustBeObservedBeforeItCanBeClaimed) {
    transparent::FlowRegistry flows;
    CHECK(!flows.claim("203.0.113.8", 52000, 1000).has_value());

    flows.observe("203.0.113.8", 52000, 443, 65534, 1000);
    const auto target = flows.claim("203.0.113.8", 52000, 1001);
    CHECK(target.has_value());
    CHECK_EQ(target->address, std::string("203.0.113.8"));
    CHECK_EQ(target->targetPort, (uint16_t)443);
    CHECK_EQ(target->connectPort, (uint16_t)65534);
    CHECK(!flows.claim("203.0.113.8", 52000, 1002).has_value());
}

TEST(TransparentFlowExpiresInsteadOfAuthorizingLateConnections) {
    transparent::FlowRegistry flows;
    flows.observe("2001:db8::1", 53000, 443, 65534, 1000);
    CHECK_EQ(flows.size(15999), (size_t)1);
    CHECK(!flows.claim("2001:db8::1", 53000, 16000).has_value());
    CHECK_EQ(flows.size(16001), (size_t)0);
}

TEST(TransparentFlowClaimRejectsExpiredEntriesBetweenSweeps) {
    transparent::FlowRegistry flows;
    flows.observe("203.0.113.20", 52010, 443, 65534, 1000);
    // Inside the sweep interval: no prune ran, expiry is still enforced.
    flows.observe("203.0.113.21", 52011, 443, 65534, 1500);
    CHECK(!flows.claim("203.0.113.20", 52010, 16000).has_value());
    CHECK(flows.claim("203.0.113.21", 52011, 16499).has_value());
}

TEST(TransparentDnsRouteReflectsQueriesAndAnswers) {
    CHECK_EQ((int)transparent::routeDatagram(true, 54000, 53, 53, 1053),
             (int)transparent::DatagramRoute::ReflectDnsToProxy);
    CHECK_EQ((int)transparent::routeDatagram(true, 1053, 54000, 53, 1053),
             (int)transparent::DatagramRoute::ReflectProxyToClient);
    CHECK_EQ((int)transparent::routeDatagram(false, 53, 54000, 53, 1053),
             (int)transparent::DatagramRoute::Pass);
}

TEST(TransparentDnsRegistryCountsConcurrentQueriesOnOneSocket) {
    transparent::DatagramRegistry datagrams;
    datagrams.observe("192.0.2.53", 54000, 1000);
    datagrams.observe("192.0.2.53", 54000, 1001);

    CHECK_EQ(datagrams.size(1002), (size_t)1);
    CHECK(datagrams.claim("192.0.2.53", 54000, 1002));
    CHECK_EQ(datagrams.size(1003), (size_t)1);
    CHECK(datagrams.claim("192.0.2.53", 54000, 1003));
    CHECK_EQ(datagrams.size(1004), (size_t)0);
    CHECK(!datagrams.claim("192.0.2.53", 54000, 1004));
}

TEST(TransparentDnsRegistryRejectsExpiredDatagrams) {
    transparent::DatagramRegistry datagrams;
    datagrams.observe("2001:db8::53", 55000, 1000);
    CHECK(!datagrams.claim("2001:db8::53", 55000, 16000));
    CHECK_EQ(datagrams.size(16001), (size_t)0);
}

TEST(TransparentDnsRegistryDoesNotRevivePendingCountsOfExpiredTuples) {
    transparent::DatagramRegistry datagrams;
    datagrams.observe("192.0.2.54", 54001, 1000);
    datagrams.observe("192.0.2.54", 54001, 1001);   // two pending, expire at 16001
    datagrams.observe("192.0.2.55", 54002, 15500);  // sweeps; next sweep at 16500
    // Still inside the sweep interval, so the stale tuple was not swept: the
    // new query must start from one pending datagram, not inherit the pair.
    datagrams.observe("192.0.2.54", 54001, 16100);
    CHECK(datagrams.claim("192.0.2.54", 54001, 16101));
    CHECK(!datagrams.claim("192.0.2.54", 54001, 16102));
}

TEST(TransparentAddressesAreCanonicalAcrossTextForms) {
    CHECK(address("1.2.3.4") == address("::ffff:1.2.3.4"));
    CHECK(address("2001:DB8::1") == address("2001:db8:0:0:0:0:0:1"));
    CHECK(address("1.2.3.4") != address("1.2.3.5"));

    const uint8_t v4[4] = {1, 2, 3, 4};
    CHECK(transparent::addressFromBytes(v4, false) == address("1.2.3.4"));

    transparent::Address ignored{};
    CHECK(!transparent::parseAddress("not an address", ignored));
    CHECK(!transparent::parseAddress("", ignored));
}

TEST(TcpFlowTableOnlyKnowsTuplesWhoseSynItSaw) {
    transparent::TcpFlowTable flows;
    const auto server = address("203.0.113.30");
    CHECK(!flows.track(Kind::Client, server, 52000, false, false, 1000));

    flows.add(Kind::Client, server, 52000, 1000);
    CHECK(flows.track(Kind::Client, server, 52000, false, false, 1001));
    // Same server and port, but the other side of the relay is a different flow.
    CHECK(!flows.track(Kind::Upstream, server, 52000, false, false, 1002));
    CHECK(!flows.track(Kind::Client, server, 52001, false, false, 1002));
    CHECK(!flows.track(Kind::Client, address("203.0.113.31"), 52000, false, false, 1002));

    flows.remove(Kind::Client, server, 52000);
    CHECK(!flows.track(Kind::Client, server, 52000, false, false, 1003));
}

TEST(TcpFlowTableKeepsAQuietConnectionAliveWhileItCarriesTraffic) {
    transparent::TcpFlowTable flows;
    const auto server = address("2001:db8::30");
    const uint64_t hour = 60ULL * 60ULL * 1000ULL;
    flows.add(Kind::Upstream, server, 52001, 1000);
    // Idle three hours (a keep-alive), then active: still tracked and the
    // idle deadline moves out from the last packet, not from the SYN.
    CHECK(flows.track(Kind::Upstream, server, 52001, false, false, 1000 + 3 * hour));
    CHECK(flows.track(Kind::Upstream, server, 52001, false, false, 1000 + 6 * hour));
    CHECK(!flows.track(Kind::Upstream, server, 52001, false, false, 1000 + 11 * hour));
}

TEST(TcpFlowTableRstEndsTheFlowAndFinOnlyShortensIt) {
    transparent::TcpFlowTable flows;
    const auto server = address("203.0.113.32");
    flows.add(Kind::Client, server, 52002, 1000);
    // The RST itself still belongs to the flow, later packets do not.
    CHECK(flows.track(Kind::Client, server, 52002, false, true, 1001));
    CHECK(!flows.track(Kind::Client, server, 52002, false, false, 1002));

    flows.add(Kind::Client, server, 52003, 1000);
    CHECK(flows.track(Kind::Client, server, 52003, true, false, 2000));
    // The final ACKs after FIN still belong to it ...
    CHECK(flows.track(Kind::Client, server, 52003, false, false, 60000));
    // ... but it does not linger for hours.
    CHECK(!flows.track(Kind::Client, server, 52003, false, false, 60000 + 3 * 60 * 1000));
}

TEST(TcpFlowTableReusedPortStartsAFreshFlow) {
    transparent::TcpFlowTable flows;
    const auto server = address("203.0.113.33");
    flows.add(Kind::Client, server, 52004, 1000);
    CHECK(flows.track(Kind::Client, server, 52004, true, false, 2000));
    flows.add(Kind::Client, server, 52004, 3000);   // new SYN on the same tuple
    // No longer in the closing state: far past the FIN grace period and alive.
    CHECK(flows.track(Kind::Client, server, 52004, false, false, 3000 + 30 * 60 * 1000));
}

TEST(TcpFlowTableEvictsLeastRecentlySeenWhenFull) {
    transparent::TcpFlowTable flows;
    const auto make = [](uint32_t index) {
        transparent::Address out{};
        out[10] = out[11] = 0xFF;
        out[12] = (uint8_t)(index >> 24);
        out[13] = (uint8_t)(index >> 16);
        out[14] = (uint8_t)(index >> 8);
        out[15] = (uint8_t)index;
        return out;
    };
    constexpr uint32_t kCapacity = 65536;
    for (uint32_t i = 0; i <= kCapacity; ++i) {
        flows.add(Kind::Client, make(i), 52005, 1000 + i);
    }
    CHECK(flows.size() <= kCapacity);
    CHECK(flows.size() > kCapacity / 2);
    // Bounded eviction took the stalest tuples, not the one just added.
    CHECK(!flows.track(Kind::Client, make(0), 52005, false, false, 1000 + kCapacity));
    CHECK(flows.track(Kind::Client, make(kCapacity), 52005, false, false, 1000 + kCapacity));
    CHECK(flows.track(Kind::Client, make(kCapacity - 1), 52005, false, false, 1000 + kCapacity));
}
