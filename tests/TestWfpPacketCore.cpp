#include "Test.hpp"

#include "../driver/shared/PacketCore.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace {

void write16(uint8_t* value, uint16_t input) {
    value[0] = static_cast<uint8_t>(input >> 8);
    value[1] = static_cast<uint8_t>(input);
}

void write32(uint8_t* value, uint32_t input) {
    value[0] = static_cast<uint8_t>(input >> 24);
    value[1] = static_cast<uint8_t>(input >> 16);
    value[2] = static_cast<uint8_t>(input >> 8);
    value[3] = static_cast<uint8_t>(input);
}

std::vector<uint8_t> ipv4Tcp(std::vector<uint8_t> payload) {
    std::vector<uint8_t> packet(40 + payload.size());
    packet[0] = 0x45;
    write16(packet.data() + 2, static_cast<uint16_t>(packet.size()));
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 10;
    packet[15] = 2;
    packet[16] = 203;
    packet[17] = 0;
    packet[18] = 113;
    packet[19] = 8;
    write16(packet.data() + 20, 52000);
    write16(packet.data() + 22, 443);
    write32(packet.data() + 24, 1000);
    packet[32] = 0x50;
    packet[33] = 0x18;
    std::copy(payload.begin(), payload.end(), packet.begin() + 40);
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    splithello::packet::RecalculateChecksums(packet.data(), view);
    return packet;
}

std::vector<uint8_t> ipv4Udp(std::vector<uint8_t> payload) {
    std::vector<uint8_t> packet(28 + payload.size());
    packet[0] = 0x45;
    write16(packet.data() + 2, static_cast<uint16_t>(packet.size()));
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 10;
    packet[15] = 2;
    packet[16] = 1;
    packet[17] = 1;
    packet[18] = 1;
    packet[19] = 1;
    write16(packet.data() + 20, 53000);
    write16(packet.data() + 22, 53);
    write16(packet.data() + 24, static_cast<uint16_t>(8 + payload.size()));
    std::copy(payload.begin(), payload.end(), packet.begin() + 28);
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    splithello::packet::RecalculateChecksums(packet.data(), view);
    return packet;
}

}  // namespace

TEST(WfpPacketCoreParsesIpv4TcpTls) {
    const auto packet = ipv4Tcp({0x16, 0x03, 0x03, 0, 1, 0});
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    CHECK_EQ(view.family, static_cast<uint8_t>(4));
    CHECK_EQ(view.sourcePort, static_cast<uint16_t>(52000));
    CHECK_EQ(view.destinationPort, static_cast<uint16_t>(443));
    CHECK_EQ(view.tcpSequence, static_cast<uint32_t>(1000));
    CHECK(splithello::packet::LooksLikeTlsRecord(
        packet.data() + view.payloadOffset, view.payloadLength));
}

TEST(WfpPacketCoreParsesTupleFromHeaderPrefix) {
    auto packet = ipv4Tcp(std::vector<uint8_t>(1400, 0xAB));
    packet[33] = 0x12;
    splithello::packet::View view{};
    CHECK(splithello::packet::ParseHeaders(packet.data(), 64, &view) ==
          splithello::packet::ParseResult::Ok);
    CHECK_EQ(view.packetLength, packet.size());
    CHECK_EQ(view.payloadLength, static_cast<size_t>(1400));
    CHECK_EQ(view.destinationPort, static_cast<uint16_t>(443));
    CHECK_EQ(view.tcpFlags, static_cast<uint8_t>(0x12));
}

TEST(WfpPacketCoreBuildsTcpSequenceAndTtlVariant) {
    const auto packet = ipv4Tcp({1, 2, 3, 4});
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    const std::array<uint8_t, 3> replacement{9, 8, 7};
    std::array<uint8_t, 128> output{};
    const size_t length = splithello::packet::BuildTcpVariant(
        packet.data(), view, replacement.data(), replacement.size(),
        -100, 3, false, output.data(), output.size());
    splithello::packet::View variant{};
    CHECK(splithello::packet::Parse(output.data(), length, &variant) ==
          splithello::packet::ParseResult::Ok);
    CHECK_EQ(variant.tcpSequence, static_cast<uint32_t>(900));
    CHECK_EQ(variant.ttl, static_cast<uint8_t>(3));
    CHECK_EQ(variant.payloadLength, replacement.size());
    CHECK_EQ(output[variant.payloadOffset], static_cast<uint8_t>(9));
}

TEST(WfpPacketCoreBuildsFakeSequenceOverlap) {
    const auto packet = ipv4Tcp({0, 1, 2, 3, 4, 5});
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    std::array<uint8_t, 128> output{};
    const char cover[] = "www.google.com";
    const size_t length = splithello::packet::BuildTcpOverlapVariant(
        packet.data(), view, 4, 2, cover, sizeof(cover) - 1,
        output.data(), output.size());
    splithello::packet::View variant{};
    CHECK(splithello::packet::Parse(output.data(), length, &variant) ==
          splithello::packet::ParseResult::Ok);
    CHECK_EQ(variant.tcpSequence, static_cast<uint32_t>(1002));
    CHECK_EQ(variant.payloadLength, static_cast<size_t>(4));
    CHECK_EQ(output[variant.payloadOffset], static_cast<uint8_t>(0x16));
    CHECK_EQ(output[variant.payloadOffset + 2], static_cast<uint8_t>(4));
}

TEST(WfpPacketCoreReflectsDnsTuple) {
    const auto packet = ipv4Udp({0x12, 0x34, 1, 0});
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    std::array<uint8_t, 128> output{};
    CHECK_EQ(splithello::packet::BuildReflectedUdp(
                 packet.data(), view, 53000, 1053,
                 output.data(), output.size()), packet.size());
    splithello::packet::View reflected{};
    CHECK(splithello::packet::Parse(output.data(), packet.size(), &reflected) ==
          splithello::packet::ParseResult::Ok);
    CHECK_EQ(reflected.sourcePort, static_cast<uint16_t>(53000));
    CHECK_EQ(reflected.destinationPort, static_cast<uint16_t>(1053));
    CHECK_EQ(reflected.sourceAddress[0], static_cast<uint8_t>(1));
    CHECK_EQ(reflected.destinationAddress[0], static_cast<uint8_t>(10));
}

TEST(WfpPacketCoreBuildsAlignedIpv4Fragments) {
    auto packet = ipv4Tcp(std::vector<uint8_t>(80, 0xAB));
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Ok);
    packet[view.transportOffset + 16] = 0;
    packet[view.transportOffset + 17] = 0;
    std::array<uint8_t, 256> first{};
    std::array<uint8_t, 256> second{};
    size_t firstLength = 0;
    size_t secondLength = 0;
    CHECK(splithello::packet::BuildIpv4Fragments(
        packet.data(), view, view.payloadOffset + 2,
        first.data(), first.size(), &firstLength,
        second.data(), second.size(), &secondLength));
    CHECK((first[6] & 0x20) != 0);
    CHECK_EQ(static_cast<unsigned>(second[7] & 0x1F),
             static_cast<unsigned>((firstLength - 20) / 8));
    CHECK_EQ(firstLength + secondLength - 40, packet.size() - 20);
    CHECK(first[view.transportOffset + 16] != 0 ||
          first[view.transportOffset + 17] != 0);
}

TEST(WfpPacketCoreRejectsTruncationAndUnknownVersion) {
    const std::array<uint8_t, 4> shortIpv4{0x45, 0, 0, 40};
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(shortIpv4.data(), shortIpv4.size(), &view) ==
          splithello::packet::ParseResult::Truncated);
    const std::array<uint8_t, 1> unknown{0x70};
    CHECK(splithello::packet::Parse(unknown.data(), unknown.size(), &view) ==
          splithello::packet::ParseResult::Unsupported);
}

TEST(WfpPacketCoreRejectsUdpLengthMismatch) {
    auto packet = ipv4Udp({0x12, 0x34, 1, 0});
    write16(packet.data() + 24, 10);
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Malformed);
}

TEST(WfpPacketCoreRejectsFirstIpv4Fragment) {
    auto packet = ipv4Tcp({1, 2, 3, 4});
    write16(packet.data() + 6, 0x2000);
    splithello::packet::View view{};
    CHECK(splithello::packet::Parse(packet.data(), packet.size(), &view) ==
          splithello::packet::ParseResult::Fragment);
}

TEST(WfpPacketCoreBuildsParseableCoverHello) {
    std::array<uint8_t, 512> output{};
    const char host[] = "www.google.com";
    const size_t length = splithello::packet::BuildFakeClientHello(
        host, sizeof(host) - 1, output.data(), output.size());
    CHECK(length > 64);
    CHECK_EQ(output[0], static_cast<uint8_t>(0x16));
    CHECK_EQ(output[5], static_cast<uint8_t>(0x01));
}
