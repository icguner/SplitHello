#pragma once

#include "TlsHello.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

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

struct Segment {
    int32_t sequenceOffset = 0;
    std::vector<uint8_t> payload;
};

bool isPacketProfile(const std::string& profile);
bool policyForProfile(const std::string& profile, const tls::ClientHello& hello,
                      Policy& out);

std::vector<uint8_t> buildFakeClientHello(const std::string& hostname);
std::vector<Segment> buildSegments(const uint8_t* payload, size_t length,
                                   const Policy& policy);
std::vector<std::vector<uint8_t>> buildIpv4Fragments(
    const uint8_t* packet, size_t length, size_t ipHeaderLength,
    size_t firstFragmentEnd);

// Joins the relay socket chosen by DirectRelay with the packet seen on the
// private WinDivert connect port. Policies are one-shot: only the first TLS
// payload on that fresh connection is transformed.
class PolicyRegistry {
public:
    void arm(const std::string& targetAddress, uint16_t sourcePort,
             const Policy& policy, uint64_t nowMs = 0);
    void observeHop(const std::string& targetAddress, uint16_t sourcePort,
                    uint8_t receivedTtl, uint64_t nowMs = 0);
    std::optional<Policy> take(const std::string& targetAddress,
                               uint16_t sourcePort, uint64_t nowMs = 0);
    void clear();

private:
    struct Entry {
        Policy policy;
        uint64_t expiresAtMs = 0;
    };
    struct HopEntry {
        uint8_t pathHops = 0;
        uint64_t expiresAtMs = 0;
    };

    void pruneLocked(uint64_t nowMs);

    std::mutex mutex_;
    std::unordered_map<std::string, Entry> policies_;
    std::unordered_map<std::string, HopEntry> hops_;
};

} // namespace packet_strategy
