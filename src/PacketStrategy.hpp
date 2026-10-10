#pragma once

#include "TlsHello.hpp"
#include "TransparentFlow.hpp"

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
    // Stream offsets of the hostname inside the first ClientHello record
    // (sniEnd == 0: unknown). A split that does not fall strictly inside
    // them cannot hide the SNI, so it must not count as an applied profile.
    size_t sniBegin = 0;
    size_t sniEnd = 0;
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

// The payload offset buildSegments cuts at for a payload of `length` bytes.
size_t segmentSplit(const Policy& policy, size_t length);
// True when `split` falls strictly inside the SNI (or the SNI is unknown).
bool splitsSni(const Policy& policy, size_t split);
// IPv4 fragment offsets are multiples of 8 from the start of the IP payload.
// Returns that boundary (bytes from the IP payload start, `transportHeaderLength`
// being the TCP header size) closest to the policy's split that still lies
// inside the SNI, or 0 when no such boundary exists (a very short hostname).
size_t ipv4FragmentBoundary(size_t transportHeaderLength, const Policy& policy,
                            size_t payloadLength);

// Joins the relay socket chosen by DirectRelay with the packet seen on the
// private WinDivert connect port. A policy transforms the first TLS payload of
// that fresh connection and any retransmission of the same segment (same TCP
// sequence number); later records pass untouched. The packet loop reports back
// with noteApplied() when a transformation really changed the wire, and the
// prober asks with consumeApplied() - a profile whose policy was never applied
// (expired, address mismatch, ClientHello split across packets, hostname too
// short to cut) is a plain unmodified hello and must not be learned.
//
// Addresses are compared in canonical binary form, so the text DirectRelay
// connected to and the address read from the packet always agree.
class PolicyRegistry {
public:
    using Address = transparent::Address;

    void arm(const std::string& targetAddress, uint16_t sourcePort,
             const Policy& policy, uint64_t nowMs = 0);
    void observeHop(const std::string& targetAddress, uint16_t sourcePort,
                    uint8_t receivedTtl, uint64_t nowMs = 0);
    void observeHop(const Address& target, uint16_t sourcePort,
                    uint8_t receivedTtl, uint64_t nowMs = 0);

    // Hands out the policy once, with no retransmission awareness.
    std::optional<Policy> take(const std::string& targetAddress,
                               uint16_t sourcePort, uint64_t nowMs = 0);
    // Packet-loop entry: `sequence` is the TCP sequence number of the packet.
    // The first call fixes the segment; later calls with the same sequence
    // (retransmissions) get the same policy, anything else gets nullopt.
    std::optional<Policy> take(const Address& target, uint16_t sourcePort,
                               std::optional<uint32_t> sequence,
                               uint64_t nowMs = 0);

    // The packet loop actually transformed the packet taken for this key.
    void noteApplied(const Address& target, uint16_t sourcePort,
                     uint64_t nowMs = 0);
    // True exactly when noteApplied() was called for the policy armed on this
    // key. Always forgets the key, so call it once after the probe finished.
    bool consumeApplied(const std::string& targetAddress, uint16_t sourcePort,
                        uint64_t nowMs = 0);
    void clear();

private:
    struct Entry {
        Policy policy;
        uint64_t expiresAtMs = 0;
        bool taken = false;
        bool hasSequence = false;
        uint32_t sequence = 0;
        bool applied = false;
    };
    struct HopEntry {
        uint8_t pathHops = 0;
        uint64_t expiresAtMs = 0;
    };

    template <typename Map>
    void makeRoomLocked(Map& entries, uint64_t nowMs);
    void pruneIfDueLocked(uint64_t nowMs);

    std::mutex mutex_;
    std::unordered_map<transparent::PeerKey, Entry, transparent::PeerKeyHash> policies_;
    std::unordered_map<transparent::PeerKey, HopEntry, transparent::PeerKeyHash> hops_;
    uint64_t nextPruneMs_ = 0;
};

} // namespace packet_strategy
