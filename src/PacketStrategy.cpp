#include "PacketStrategy.hpp"

#include <algorithm>

namespace packet_strategy {

bool policyForProfile(const std::string& profile, const tls::ClientHello& hello,
                      Policy& out) {
    out = {};
    const size_t preferredSplit = hello.hasSni()
        ? hello.sniOffset + hello.sniLength / 2
        : 2;

    if (profile == "packet-reverse") {
        out.mode = Mode::ReverseOrder;
    } else if (profile == "packet-fake-badseq") {
        out.mode = Mode::FakeBadSequence;
    } else if (profile == "packet-fake-badsum") {
        out.mode = Mode::FakeBadChecksum;
    } else if (profile == "packet-autottl") {
        out.mode = Mode::FakeAutoTtl;
    } else if (profile == "packet-seqovl") {
        out.mode = Mode::SequenceOverlap;
    } else if (profile == "packet-ipfrag") {
        out.mode = Mode::IpFragment;
    } else {
        return false;
    }

    // The ClientHello may span several IP packets. The driver clamps this
    // stream-relative hint into the first packet if the SNI is not there yet.
    out.splitOffset = std::max<size_t>(2, preferredSplit);
    return true;
}

} // namespace packet_strategy
