#include "Test.hpp"

#include "PacketStrategy.hpp"

#include <cstdint>
#include <string>
#include <vector>

TEST(PacketStrategyBuildsParseableCoverClientHello) {
    const std::vector<uint8_t> fake =
        packet_strategy::buildFakeClientHello("www.google.com");
    tls::ClientHello parsed;
    CHECK_EQ((int)tls::parseClientHello(fake.data(), fake.size(), parsed),
             (int)tls::ParseStatus::Ok);
    CHECK_EQ(parsed.serverName, std::string("www.google.com"));
}

TEST(PacketStrategyReverseSegmentsPreserveTcpByteStream) {
    const std::vector<uint8_t> payload = {0, 1, 2, 3, 4, 5};
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::ReverseOrder;
    policy.splitOffset = 2;

    const auto segments =
        packet_strategy::buildSegments(payload.data(), payload.size(), policy);
    CHECK_EQ(segments.size(), (size_t)2);
    CHECK_EQ(segments[0].sequenceOffset, (int32_t)2);
    CHECK_EQ(segments[0].payload.size(), (size_t)4);
    CHECK_EQ(segments[1].sequenceOffset, (int32_t)0);
    CHECK_EQ(segments[1].payload.size(), (size_t)2);
    CHECK_EQ(segments[0].payload[0], (uint8_t)2);
    CHECK_EQ(segments[1].payload[1], (uint8_t)1);
}

TEST(PacketStrategySequenceOverlapPrecedesRealSecondSegment) {
    const std::vector<uint8_t> payload = {0, 1, 2, 3, 4, 5};
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::SequenceOverlap;
    policy.splitOffset = 4;
    policy.overlapBytes = 2;

    const auto segments =
        packet_strategy::buildSegments(payload.data(), payload.size(), policy);
    CHECK_EQ(segments.size(), (size_t)2);
    CHECK_EQ(segments[0].sequenceOffset, (int32_t)2);
    CHECK_EQ(segments[0].payload.size(), (size_t)4);
    CHECK_EQ(segments[1].payload.size(), (size_t)4);
    CHECK_EQ(segments[0].payload[2], (uint8_t)4);
}

TEST(PacketPolicyRegistryIsOneShotAndInfersAutoTtl) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::FakeAutoTtl;

    registry.observeHop("203.0.113.8", 52000, 120, 1000); // 128 - 120 = 8 hops
    registry.arm("203.0.113.8", 52000, policy, 1001);
    const auto taken = registry.take("203.0.113.8", 52000, 1002);
    CHECK(taken.has_value());
    CHECK_EQ(taken->fakeTtl, (uint8_t)7);
    CHECK(!registry.take("203.0.113.8", 52000, 1003).has_value());
}

TEST(PacketPolicyRegistryExpiresUnusedPolicies) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::FakeBadSequence;
    registry.arm("2001:db8::8", 53000, policy, 1000);
    CHECK(!registry.take("2001:db8::8", 53000, 16000).has_value());
}

TEST(AutoTtlFallsBackToBadSequenceWithoutHopSample) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::FakeAutoTtl;
    registry.arm("203.0.113.9", 52001, policy, 1000);

    const auto taken = registry.take("203.0.113.9", 52001, 1001);
    CHECK(taken.has_value());
    CHECK(taken->mode == packet_strategy::Mode::FakeBadSequence);
    CHECK_EQ(taken->fakeSequenceDelta, (int32_t)-10000);
}

TEST(Ipv4FragmentationBuildsAlignedReassemblablePieces) {
    std::vector<uint8_t> packet(104);
    packet[0] = 0x45;
    packet[2] = 0;
    packet[3] = (uint8_t)packet.size();
    packet[8] = 64;
    packet[9] = 6;
    for (size_t i = 20; i < packet.size(); ++i) packet[i] = (uint8_t)i;

    const auto fragments = packet_strategy::buildIpv4Fragments(
        packet.data(), packet.size(), 20, 50);
    CHECK_EQ(fragments.size(), (size_t)2);
    CHECK_EQ(fragments[0].size(), (size_t)52);
    CHECK_EQ(fragments[1].size(), (size_t)72);
    CHECK((fragments[0][6] & 0x20) != 0);
    CHECK_EQ(fragments[1][6], (uint8_t)0);
    CHECK_EQ(fragments[1][7], (uint8_t)4);
    CHECK_EQ(fragments[0][20], packet[20]);
    CHECK_EQ(fragments[1][20], packet[52]);
    CHECK(fragments[0][10] != 0 || fragments[0][11] != 0);
}
