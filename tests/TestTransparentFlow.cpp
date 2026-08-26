#include "Test.hpp"

#include "TransparentFlow.hpp"

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
