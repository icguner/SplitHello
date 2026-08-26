#include "Test.hpp"

#include "PacketStrategy.hpp"

#include <array>
#include <utility>

TEST(PacketStrategyMapsEveryDriverProfile) {
    tls::ClientHello hello;
    hello.sniOffset = 20;
    hello.sniLength = 10;

    const std::array profiles{
        std::pair{"packet-reverse", packet_strategy::Mode::ReverseOrder},
        std::pair{"packet-fake-badseq", packet_strategy::Mode::FakeBadSequence},
        std::pair{"packet-fake-badsum", packet_strategy::Mode::FakeBadChecksum},
        std::pair{"packet-autottl", packet_strategy::Mode::FakeAutoTtl},
        std::pair{"packet-seqovl", packet_strategy::Mode::SequenceOverlap},
        std::pair{"packet-ipfrag", packet_strategy::Mode::IpFragment},
    };
    for (const auto& [name, expected] : profiles) {
        packet_strategy::Policy policy;
        CHECK(packet_strategy::policyForProfile(name, hello, policy));
        CHECK(policy.mode == expected);
        CHECK_EQ(policy.splitOffset, static_cast<size_t>(25));
    }
}

TEST(PacketStrategyRejectsUnknownProfile) {
    tls::ClientHello hello;
    packet_strategy::Policy policy;
    CHECK(!packet_strategy::policyForProfile("packet-unknown", hello, policy));
    CHECK(policy.mode == packet_strategy::Mode::None);
}
