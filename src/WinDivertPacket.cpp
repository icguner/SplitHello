#include "WinDivertPacket.hpp"
#include <cstring>

namespace divert_packet {

std::vector<uint8_t> buildTcpVariant(
    const uint8_t* packet, UINT packetLength, const void* payload,
    const std::vector<uint8_t>& replacement, int32_t sequenceOffset,
    const WINDIVERT_ADDRESS& address, uint8_t ttl, bool corruptChecksum) {
    if (!packet || !payload) return {};
    PVOID parsedPayload = nullptr;
    PWINDIVERT_TCPHDR transport = nullptr;
    if (!WinDivertHelperParsePacket(packet, packetLength, nullptr, nullptr,
                                    nullptr, nullptr, nullptr, &transport, nullptr,
                                    &parsedPayload, nullptr, nullptr, nullptr) ||
        !transport || parsedPayload != payload) return {};
    const auto* payloadBytes = static_cast<const uint8_t*>(parsedPayload);

    const size_t headerLength = (size_t)(payloadBytes - packet);
    const size_t totalLength = headerLength + replacement.size();
    if (headerLength == 0 || totalLength > WINDIVERT_MTU_MAX) {
        return {};
    }

    std::vector<uint8_t> out(totalLength);
    std::memcpy(out.data(), packet, headerLength);
    if (!replacement.empty()) {
        std::memcpy(out.data() + headerLength, replacement.data(), replacement.size());
    }

    // The copied header still describes the original payload. Fix the wire
    // length before parsing; smaller variants would otherwise be rejected.
    const bool isIpv6 = (out[0] >> 4) == 6;
    const size_t ipBase = isIpv6 ? sizeof(WINDIVERT_IPV6HDR) : 0;
    if (out.size() < ipBase || out.size() - ipBase > UINT16_MAX) return {};
    const uint16_t wireLength = htons(static_cast<uint16_t>(out.size() - ipBase));
    std::memcpy(out.data() + (isIpv6 ? 4 : 2), &wireLength, sizeof(wireLength));

    PWINDIVERT_IPHDR variantIpv4 = nullptr;
    PWINDIVERT_IPV6HDR variantIpv6 = nullptr;
    PWINDIVERT_TCPHDR variantTcp = nullptr;
    if (!WinDivertHelperParsePacket(out.data(), (UINT)out.size(), &variantIpv4,
                                    &variantIpv6, nullptr, nullptr, nullptr,
                                    &variantTcp, nullptr, nullptr, nullptr,
                                    nullptr, nullptr) ||
        !variantTcp || (!variantIpv4 && !variantIpv6)) {
        return {};
    }

    if (variantIpv4) {
        variantIpv4->Length = htons((uint16_t)out.size());
        if (ttl != 0) variantIpv4->TTL = ttl;
    } else {
        variantIpv6->Length = htons((uint16_t)(out.size() - sizeof(WINDIVERT_IPV6HDR)));
        if (ttl != 0) variantIpv6->HopLimit = ttl;
    }

    const uint32_t sequence = ntohl(variantTcp->SeqNum);
    variantTcp->SeqNum = htonl(sequence + (uint32_t)sequenceOffset);
    WINDIVERT_ADDRESS checksumAddress = address;
    WinDivertHelperCalcChecksums(out.data(), (UINT)out.size(), &checksumAddress, 0);
    if (corruptChecksum) variantTcp->Checksum ^= htons(0xFFFF);
    return out;
}

std::vector<uint8_t> buildUdpVariant(
    const uint8_t* packet, UINT packetLength, const void* payload,
    const std::vector<uint8_t>& replacement,
    const WINDIVERT_ADDRESS& address) {
    if (!packet || !payload) return {};
    PVOID parsedPayload = nullptr;
    PWINDIVERT_UDPHDR transport = nullptr;
    if (!WinDivertHelperParsePacket(packet, packetLength, nullptr, nullptr,
                                    nullptr, nullptr, nullptr, nullptr, &transport,
                                    &parsedPayload, nullptr, nullptr, nullptr) ||
        !transport || parsedPayload != payload) return {};
    const auto* payloadBytes = static_cast<const uint8_t*>(parsedPayload);

    const size_t headerLength = (size_t)(payloadBytes - packet);
    const size_t totalLength = headerLength + replacement.size();
    if (headerLength == 0 || totalLength > WINDIVERT_MTU_MAX) return {};

    std::vector<uint8_t> out(totalLength);
    std::memcpy(out.data(), packet, headerLength);
    if (!replacement.empty()) {
        std::memcpy(out.data() + headerLength, replacement.data(), replacement.size());
    }

    // The copied header still describes the original payload. Fix the wire
    // length before parsing; smaller variants would otherwise be rejected.
    const bool isIpv6 = (out[0] >> 4) == 6;
    const size_t ipBase = isIpv6 ? sizeof(WINDIVERT_IPV6HDR) : 0;
    if (out.size() < ipBase || out.size() - ipBase > UINT16_MAX) return {};
    const uint16_t wireLength = htons(static_cast<uint16_t>(out.size() - ipBase));
    std::memcpy(out.data() + (isIpv6 ? 4 : 2), &wireLength, sizeof(wireLength));

    if (headerLength < sizeof(WINDIVERT_UDPHDR) ||
        replacement.size() > UINT16_MAX - sizeof(WINDIVERT_UDPHDR)) return {};
    const uint16_t udpLength = htons(static_cast<uint16_t>(
        sizeof(WINDIVERT_UDPHDR) + replacement.size()));
    std::memcpy(out.data() + headerLength - sizeof(WINDIVERT_UDPHDR) + 4,
                &udpLength, sizeof(udpLength));

    PWINDIVERT_IPHDR variantIpv4 = nullptr;
    PWINDIVERT_IPV6HDR variantIpv6 = nullptr;
    PWINDIVERT_UDPHDR variantUdp = nullptr;
    if (!WinDivertHelperParsePacket(out.data(), (UINT)out.size(), &variantIpv4,
                                    &variantIpv6, nullptr, nullptr, nullptr,
                                    nullptr, &variantUdp, nullptr, nullptr,
                                    nullptr, nullptr) ||
        !variantUdp || (!variantIpv4 && !variantIpv6)) {
        return {};
    }

    if (variantIpv4) {
        variantIpv4->Length = htons((uint16_t)out.size());
    } else {
        variantIpv6->Length = htons((uint16_t)(out.size() - sizeof(WINDIVERT_IPV6HDR)));
    }
    variantUdp->Length = htons((uint16_t)(sizeof(WINDIVERT_UDPHDR) + replacement.size()));
    WINDIVERT_ADDRESS checksumAddress = address;
    WinDivertHelperCalcChecksums(out.data(), (UINT)out.size(), &checksumAddress, 0);
    return out;
}

} // namespace divert_packet
