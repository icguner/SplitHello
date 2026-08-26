#pragma once

#include "TlsHello.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace packet_strategy {

enum class Mode {
    None,
    ReverseOrder,
    FakeBadSequence,
    FakeBadChecksum,
    FakeAutoTtl,
    SequenceOverlap,
    IpFragment,
};

struct Policy {
    Mode mode = Mode::None;
    size_t splitOffset = 2;
    size_t overlapBytes = 8;
    int32_t fakeSequenceDelta = -10000;
    uint8_t fakeTtl = 0;
    std::string coverSni = "www.google.com";
};

// Converts a learned profile name into the versioned policy sent to the WFP
// driver. Packet construction itself lives in driver/shared/PacketCore.
bool policyForProfile(const std::string& profile, const tls::ClientHello& hello,
                      Policy& out);

} // namespace packet_strategy
