#include "Test.hpp"
#include "WinDivertPacket.hpp"
#include <algorithm>
#include <cstring>

namespace {
std::vector<uint8_t> packet(bool ipv6, bool udp, size_t payloadLength) {
    const size_t ipLength = ipv6 ? 40 : 20;
    const size_t transportLength = udp ? 8 : 20;
    std::vector<uint8_t> bytes(ipLength + transportLength + payloadLength, 0);
    bytes[0] = ipv6 ? 0x60 : 0x45;
    const uint16_t length = htons(static_cast<uint16_t>(bytes.size() - (ipv6 ? 40 : 0)));
    std::memcpy(bytes.data() + (ipv6 ? 4 : 2), &length, 2);
    bytes[ipv6 ? 6 : 9] = udp ? 17 : 6;
    bytes[ipv6 ? 7 : 8] = 64;
    if (udp) {
        const uint16_t udpLength = htons(static_cast<uint16_t>(8 + payloadLength));
        std::memcpy(bytes.data() + ipLength + 4, &udpLength, 2);
    } else {
        bytes[ipLength + 12] = 0x50;
    }
    return bytes;
}

void checkVariant(bool ipv6, bool udp) {
    auto original = packet(ipv6, udp, 100);
    const size_t headerLength = (ipv6 ? 40 : 20) + (udp ? 8 : 20);
    WINDIVERT_ADDRESS address{};
    for (size_t size : {size_t{1}, size_t{20}, size_t{100}, size_t{200}}) {
        const std::vector<uint8_t> payload(size, 0xab);
        auto variant = udp
            ? divert_packet::buildUdpVariant(original.data(), static_cast<UINT>(original.size()),
                  original.data() + headerLength, payload, address)
            : divert_packet::buildTcpVariant(original.data(), static_cast<UINT>(original.size()),
                  original.data() + headerLength, payload, 7, address, 32, false);
        CHECK_EQ(variant.size(), headerLength + size);
        PWINDIVERT_TCPHDR tcp = nullptr;
        PWINDIVERT_UDPHDR udpHeader = nullptr;
        void* data = nullptr;
        UINT dataLength = 0;
        CHECK(WinDivertHelperParsePacket(variant.data(), static_cast<UINT>(variant.size()),
            nullptr, nullptr, nullptr, nullptr, nullptr, &tcp, &udpHeader,
            &data, &dataLength, nullptr, nullptr));
        CHECK_EQ(dataLength, size);
        CHECK(std::memcmp(data, payload.data(), size) == 0);
        if (udp) CHECK_EQ(ntohs(udpHeader->Length), size + 8);
        else CHECK_EQ(ntohl(tcp->SeqNum), 7U);
        // Recomputing valid checksums must not alter the emitted packet.
        const auto before = variant;
        CHECK(WinDivertHelperCalcChecksums(variant.data(), static_cast<UINT>(variant.size()), &address, 0));
        CHECK(variant == before);
    }
}
}

TEST(tcp_ipv4_variants_shrink_and_grow) { checkVariant(false, false); }
TEST(tcp_ipv6_variants_shrink_and_grow) { checkVariant(true, false); }
TEST(udp_ipv4_variants_shrink_and_grow) { checkVariant(false, true); }
TEST(udp_ipv6_variants_shrink_and_grow) { checkVariant(true, true); }

TEST(variant_rejects_ipv4_wire_length_overflow) {
    auto original = packet(false, false, 100);
    WINDIVERT_ADDRESS address{};
    CHECK(divert_packet::buildTcpVariant(original.data(), static_cast<UINT>(original.size()),
        original.data() + 40, std::vector<uint8_t>(65500), 0, address, 0, false).empty());
}

TEST(bad_checksum_variant_carries_only_a_wrong_tcp_checksum) {
    auto original = packet(false, false, 100);
    WINDIVERT_ADDRESS address{};
    const std::vector<uint8_t> payload(20, 0xab);
    const auto good = divert_packet::buildTcpVariant(
        original.data(), static_cast<UINT>(original.size()), original.data() + 40,
        payload, 0, address, 0, false);
    auto bad = divert_packet::buildTcpVariant(
        original.data(), static_cast<UINT>(original.size()), original.data() + 40,
        payload, 0, address, 0, true);
    CHECK_EQ(bad.size(), good.size());

    // Exactly the two TCP checksum bytes differ; the IP header stays valid.
    size_t differing = 0;
    for (size_t i = 0; i < good.size(); ++i) {
        if (good[i] != bad[i]) {
            CHECK(i == 20 + 16 || i == 20 + 17);
            ++differing;
        }
    }
    CHECK_EQ(differing, 2U);

    // A packet whose address flags claim valid checksums is injected as-is, so
    // recomputing the checksums here must repair it - proving it really was wrong.
    WINDIVERT_ADDRESS claimsValid{};
    claimsValid.IPChecksum = 1;
    claimsValid.TCPChecksum = 1;
    auto repaired = bad;
    CHECK(WinDivertHelperCalcChecksums(repaired.data(), static_cast<UINT>(repaired.size()),
                                       &claimsValid, 0));
    CHECK(repaired == good);
}

TEST(variant_rejects_invalid_payload_pointer) {
    auto original = packet(false, false, 100);
    WINDIVERT_ADDRESS address{};
    CHECK(divert_packet::buildTcpVariant(original.data(), static_cast<UINT>(original.size()),
        original.data() + 1, {1,2,3}, 0, address, 0, false).empty());
}
