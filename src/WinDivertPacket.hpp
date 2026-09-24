#pragma once
#include <cstdint>
#include <vector>
#include <winsock2.h>
#include <windivert.h>

namespace divert_packet {
std::vector<uint8_t> buildTcpVariant(
    const uint8_t* packet, UINT packetLength, const void* payload,
    const std::vector<uint8_t>& replacement, int32_t sequenceOffset,
    const WINDIVERT_ADDRESS& address, uint8_t ttl, bool corruptChecksum);
std::vector<uint8_t> buildUdpVariant(
    const uint8_t* packet, UINT packetLength, const void* payload,
    const std::vector<uint8_t>& replacement, const WINDIVERT_ADDRESS& address);
}
