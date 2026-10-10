#include "Test.hpp"

#include "HelloBuilder.hpp"
#include "PacketStrategy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace {

transparent::Address address(const std::string& text) {
    transparent::Address out{};
    CHECK(transparent::parseAddress(text, out));
    return out;
}

} // namespace

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

TEST(PacketPolicyRetransmitOfTheSameSegmentIsTransformedAgain) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::FakeAutoTtl;
    registry.observeHop(address("203.0.113.10"), 52002, 120, 1000);
    registry.arm("203.0.113.10", 52002, policy, 1001);

    const auto first = registry.take(address("203.0.113.10"), 52002, 777u, 1002);
    CHECK(first.has_value());
    CHECK_EQ(first->fakeTtl, (uint8_t)7);
    // The stack retransmits the ClientHello with the same sequence number.
    const auto again = registry.take(address("203.0.113.10"), 52002, 777u, 4000);
    CHECK(again.has_value());
    CHECK_EQ(again->fakeTtl, (uint8_t)7);
    // A different segment of the connection is real traffic, not the hello.
    CHECK(!registry.take(address("203.0.113.10"), 52002, 778u, 4001).has_value());
    // Without a sequence number (legacy callers) the policy stays one-shot.
    CHECK(!registry.take(address("203.0.113.10"), 52002, std::nullopt, 4002).has_value());
}

TEST(PacketPolicyAddressesCompareInCanonicalForm) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::ReverseOrder;
    // DirectRelay arms with whatever text it connected to; the packet loop
    // looks up with the bytes it read from the wire.
    registry.arm("2001:DB8:0:0:0:0:0:8", 53001, policy, 1000);
    registry.arm("::ffff:203.0.113.11", 53002, policy, 1000);

    const std::array<uint8_t, 16> v6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 8};
    const uint8_t v4[4] = {203, 0, 113, 11};
    CHECK(registry.take(transparent::addressFromBytes(v6.data(), true), 53001,
                        std::nullopt, 1001).has_value());
    CHECK(registry.take(transparent::addressFromBytes(v4, false), 53002,
                        std::nullopt, 1001).has_value());
}

TEST(PacketPolicyReportsOnlyTransformationsThatReallyHappened) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::ReverseOrder;

    // Armed but the packet loop never touched the hello (expired, wrong
    // address, ClientHello not in the first packet, ...).
    registry.arm("203.0.113.12", 54000, policy, 1000);
    CHECK(!registry.consumeApplied("203.0.113.12", 54000, 1500));
    CHECK(!registry.take("203.0.113.12", 54000, 1501).has_value());

    registry.arm("203.0.113.12", 54001, policy, 1000);
    CHECK(registry.take(address("203.0.113.12"), 54001, 5u, 1100).has_value());
    registry.noteApplied(address("203.0.113.12"), 54001, 1101);
    // The probe may wait for the server far longer than the policy TTL.
    CHECK(registry.consumeApplied("203.0.113.12", 54001, 30000));
    CHECK(!registry.consumeApplied("203.0.113.12", 54001, 30001));
}

TEST(PacketPolicyRegistryEvictsOldestInsteadOfDroppingEverything) {
    packet_strategy::PolicyRegistry registry;
    packet_strategy::Policy policy;
    policy.mode = packet_strategy::Mode::ReverseOrder;
    const transparent::Address server = address("203.0.113.13");
    for (uint32_t port = 1; port <= 8193; ++port) {
        registry.arm("203.0.113.13", (uint16_t)port, policy, 1000 + port);
    }
    CHECK(!registry.take(server, 1, std::nullopt, 9300).has_value());
    CHECK(registry.take(server, 2, std::nullopt, 9300).has_value());
    CHECK(registry.take(server, 8193, std::nullopt, 9300).has_value());
}

TEST(PolicyKeepsTheHostnameBoundsItWasBuiltFor) {
    testing::HelloOptions options;
    options.serverName = "discord.com";
    const std::vector<uint8_t> data = testing::buildClientHello(options);
    tls::ClientHello hello;
    CHECK_EQ((int)tls::parseClientHello(data.data(), data.size(), hello),
             (int)tls::ParseStatus::Ok);

    packet_strategy::Policy policy;
    CHECK(packet_strategy::policyForProfile("packet-reverse", hello, policy));
    CHECK_EQ(policy.sniBegin, hello.sniOffset);
    CHECK_EQ(policy.sniEnd, hello.sniOffset + hello.sniLength);
    CHECK(packet_strategy::splitsSni(policy, policy.splitOffset));
    CHECK(!packet_strategy::splitsSni(policy, policy.sniBegin));
    CHECK(!packet_strategy::splitsSni(policy, policy.sniEnd));
    // A hello whose hostname starts past the first packet is cut at the last
    // byte of the packet, which is outside the hostname.
    CHECK(!packet_strategy::splitsSni(
        policy, packet_strategy::segmentSplit(policy, policy.sniBegin)));

    packet_strategy::Policy unknown;
    CHECK(packet_strategy::splitsSni(unknown, 1));
}

TEST(Ipv4FragmentBoundaryStaysInsideTheHostnameOnAnEightByteGrid) {
    packet_strategy::Policy policy;
    policy.sniBegin = 10;
    policy.sniEnd = 30;
    policy.splitOffset = 20;
    // 20-byte TCP header: stream offset 20 is IP-payload offset 40.
    CHECK_EQ(packet_strategy::ipv4FragmentBoundary(20, policy, 100), (size_t)40);

    // Four-byte hostname: only IP-payload offset 32 (stream 12) fits inside.
    policy.sniBegin = 10;
    policy.sniEnd = 14;
    policy.splitOffset = 12;
    const size_t boundary = packet_strategy::ipv4FragmentBoundary(20, policy, 100);
    CHECK_EQ(boundary, (size_t)32);
    CHECK(packet_strategy::splitsSni(policy, boundary - 20));

    // A two-character hostname has no multiple-of-8 cut inside it.
    policy.sniBegin = 10;
    policy.sniEnd = 12;
    policy.splitOffset = 11;
    CHECK_EQ(packet_strategy::ipv4FragmentBoundary(20, policy, 100), (size_t)0);

    // Hostname beyond the packet: nothing to cut.
    policy.sniBegin = 200;
    policy.sniEnd = 220;
    policy.splitOffset = 210;
    CHECK_EQ(packet_strategy::ipv4FragmentBoundary(20, policy, 100), (size_t)0);
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
