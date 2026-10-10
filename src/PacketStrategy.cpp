#include "PacketStrategy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>

namespace packet_strategy {
namespace {

constexpr uint64_t kPolicyTtlMs = 15000;
constexpr uint64_t kAppliedTtlMs = 60000;
constexpr uint64_t kPruneIntervalMs = 1000;
constexpr size_t kMaxEntries = 8192;

uint64_t clockMs(uint64_t supplied) {
    return supplied == 0 ? GetTickCount64() : supplied;
}

void append16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

void append24(std::vector<uint8_t>& out, size_t value) {
    out.push_back((uint8_t)(value >> 16));
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

uint8_t inferPathHops(uint8_t receivedTtl) {
    const std::array<unsigned, 3> defaults = {64, 128, 255};
    for (const unsigned initial : defaults) {
        if (receivedTtl <= initial) return (uint8_t)(initial - receivedTtl);
    }
    return 0;
}

} // namespace

bool isPacketProfile(const std::string& profile) {
    return profile.starts_with("packet-");
}

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

    // The ClientHello may span several IP packets. The interceptor clamps this
    // stream-relative hint into the first packet if the SNI is not there yet.
    out.splitOffset = std::max<size_t>(2, preferredSplit);
    if (hello.hasSni()) {
        out.sniBegin = hello.sniOffset;
        out.sniEnd = hello.sniOffset + hello.sniLength;
    }
    return true;
}

std::vector<uint8_t> buildFakeClientHello(const std::string& hostname) {
    if (hostname.empty() || hostname.size() > 253) return {};

    std::vector<uint8_t> extensions;
    append16(extensions, 0x0000); // server_name
    append16(extensions, (uint16_t)(hostname.size() + 5));
    append16(extensions, (uint16_t)(hostname.size() + 3));
    extensions.push_back(0);
    append16(extensions, (uint16_t)hostname.size());
    extensions.insert(extensions.end(), hostname.begin(), hostname.end());
    append16(extensions, 0x002b); // supported_versions
    append16(extensions, 3);
    extensions.push_back(2);
    append16(extensions, 0x0304);

    std::vector<uint8_t> body;
    append16(body, 0x0303);
    for (uint8_t value = 0; value < 32; ++value) body.push_back((uint8_t)(value + 1));
    body.push_back(0);          // session id
    append16(body, 2);         // cipher suites length
    append16(body, 0x1301);    // TLS_AES_128_GCM_SHA256
    body.push_back(1);          // compression methods length
    body.push_back(0);
    append16(body, (uint16_t)extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(1); // ClientHello
    append24(handshake, body.size());
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record;
    record.push_back(0x16);
    append16(record, 0x0301);
    append16(record, (uint16_t)handshake.size());
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

size_t segmentSplit(const Policy& policy, size_t length) {
    if (length < 2) return 0;
    return std::clamp(policy.splitOffset, (size_t)1, length - 1);
}

bool splitsSni(const Policy& policy, size_t split) {
    return policy.sniEnd == 0 ||
        (split > policy.sniBegin && split < policy.sniEnd);
}

std::vector<Segment> buildSegments(const uint8_t* payload, size_t length,
                                   const Policy& policy) {
    if (!payload || length < 2) return {};
    const size_t split = segmentSplit(policy, length);

    if (policy.mode == Mode::ReverseOrder) {
        return {
            {(int32_t)split, {payload + split, payload + length}},
            {0, {payload, payload + split}},
        };
    }

    if (policy.mode == Mode::SequenceOverlap) {
        const size_t overlap = std::clamp(policy.overlapBytes, (size_t)1, split);
        const std::vector<uint8_t> fake = buildFakeClientHello(policy.coverSni);
        std::vector<uint8_t> second;
        second.reserve(overlap + length - split);
        for (size_t index = 0; index < overlap; ++index) {
            second.push_back(fake.empty() ? 0x20 : fake[index % fake.size()]);
        }
        second.insert(second.end(), payload + split, payload + length);
        return {
            {(int32_t)(split - overlap), std::move(second)},
            {0, {payload, payload + split}},
        };
    }
    return {};
}

size_t ipv4FragmentBoundary(size_t transportHeaderLength, const Policy& policy,
                            size_t payloadLength) {
    if (payloadLength < 2) return 0;
    // Cut offsets that leave bytes on both sides, and that cut the hostname.
    size_t lo = 1;
    size_t hi = payloadLength - 1;
    if (policy.sniEnd > policy.sniBegin) {
        lo = std::max(lo, policy.sniBegin + 1);
        hi = std::min(hi, policy.sniEnd - 1);
    }
    if (lo > hi) return 0;

    const size_t target = transportHeaderLength + std::clamp(policy.splitOffset, lo, hi);
    const size_t down = target & ~(size_t)7;
    const size_t up = (target + 7) & ~(size_t)7;
    const auto distance = [target](size_t value) {
        return value > target ? value - target : target - value;
    };

    size_t best = 0;
    for (const size_t candidate : {down, up}) {
        if (candidate < transportHeaderLength + lo ||
            candidate > transportHeaderLength + hi) {
            continue;
        }
        if (best == 0 || distance(candidate) < distance(best)) best = candidate;
    }
    return best;
}

std::vector<std::vector<uint8_t>> buildIpv4Fragments(
    const uint8_t* packet, size_t length, size_t ipHeaderLength,
    size_t firstFragmentEnd) {
    if (!packet || length > 0xFFFF || ipHeaderLength < 20 ||
        ipHeaderLength > length || firstFragmentEnd <= ipHeaderLength ||
        firstFragmentEnd >= length || (packet[0] >> 4) != 4) {
        return {};
    }

    const uint16_t existingFragment =
        (uint16_t)(((uint16_t)packet[6] << 8) | packet[7]);
    if ((existingFragment & 0x3FFF) != 0) return {};

    // Fragment offsets count 8-byte units; callers that care where the cut
    // lands pass a multiple of 8 (see ipv4FragmentBoundary).
    const size_t ipPayloadLength = length - ipHeaderLength;
    size_t firstPayloadLength = firstFragmentEnd - ipHeaderLength;
    firstPayloadLength = (firstPayloadLength + 7) & ~(size_t)7;
    if (firstPayloadLength == 0 || firstPayloadLength >= ipPayloadLength) return {};

    std::vector<uint8_t> first(ipHeaderLength + firstPayloadLength);
    std::vector<uint8_t> second(ipHeaderLength + ipPayloadLength - firstPayloadLength);
    std::copy(packet, packet + first.size(), first.begin());
    std::copy(packet, packet + ipHeaderLength, second.begin());
    std::copy(packet + ipHeaderLength + firstPayloadLength, packet + length,
              second.begin() + ipHeaderLength);

    const auto finishHeader = [ipHeaderLength](std::vector<uint8_t>& fragment,
                                                uint16_t fragmentField) {
        const uint16_t totalLength = (uint16_t)fragment.size();
        fragment[2] = (uint8_t)(totalLength >> 8);
        fragment[3] = (uint8_t)totalLength;
        fragment[6] = (uint8_t)(fragmentField >> 8);
        fragment[7] = (uint8_t)fragmentField;
        fragment[10] = 0;
        fragment[11] = 0;

        uint32_t sum = 0;
        for (size_t i = 0; i < ipHeaderLength; i += 2) {
            sum += ((uint32_t)fragment[i] << 8) | fragment[i + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        const uint16_t checksum = (uint16_t)~sum;
        fragment[10] = (uint8_t)(checksum >> 8);
        fragment[11] = (uint8_t)checksum;
    };

    finishHeader(first, 0x2000); // More Fragments
    finishHeader(second, (uint16_t)(firstPayloadLength / 8));
    return {std::move(first), std::move(second)};
}

template <typename Map>
void PolicyRegistry::makeRoomLocked(Map& entries, uint64_t nowMs) {
    std::erase_if(entries, [nowMs](const auto& item) {
        return item.second.expiresAtMs <= nowMs;
    });
    if (entries.size() < kMaxEntries) return;
    // Genuinely full of live entries: drop the one closest to expiry instead
    // of wiping the table and every in-flight policy with it.
    const auto oldest = std::min_element(
        entries.begin(), entries.end(), [](const auto& left, const auto& right) {
            return left.second.expiresAtMs < right.second.expiresAtMs;
        });
    if (oldest != entries.end()) entries.erase(oldest);
}

// Lookups check their own entry's expiry, so this sweep only bounds memory and
// does not have to run for every packet of the hot path.
void PolicyRegistry::pruneIfDueLocked(uint64_t nowMs) {
    if (nowMs < nextPruneMs_) return;
    nextPruneMs_ = nowMs + kPruneIntervalMs;
    const auto expired = [nowMs](const auto& item) {
        return item.second.expiresAtMs <= nowMs;
    };
    std::erase_if(policies_, expired);
    std::erase_if(hops_, expired);
}

void PolicyRegistry::arm(const std::string& targetAddress, uint16_t sourcePort,
                         const Policy& policy, uint64_t nowMs) {
    Address address;
    if (sourcePort == 0 || policy.mode == Mode::None ||
        !transparent::parseAddress(targetAddress, address)) {
        return;
    }
    const uint64_t now = clockMs(nowMs);
    const transparent::PeerKey entryKey{address, sourcePort, 0};
    std::lock_guard lock(mutex_);
    pruneIfDueLocked(now);
    if (policies_.size() >= kMaxEntries && !policies_.contains(entryKey)) {
        makeRoomLocked(policies_, now);
    }
    policies_[entryKey] = Entry{policy, now + kPolicyTtlMs};
}

void PolicyRegistry::observeHop(const std::string& targetAddress,
                                uint16_t sourcePort, uint8_t receivedTtl,
                                uint64_t nowMs) {
    Address address;
    if (transparent::parseAddress(targetAddress, address)) {
        observeHop(address, sourcePort, receivedTtl, nowMs);
    }
}

void PolicyRegistry::observeHop(const Address& target, uint16_t sourcePort,
                                uint8_t receivedTtl, uint64_t nowMs) {
    if (sourcePort == 0 || receivedTtl == 0) return;
    const uint8_t hops = inferPathHops(receivedTtl);
    if (hops == 0) return;

    const uint64_t now = clockMs(nowMs);
    const transparent::PeerKey entryKey{target, sourcePort, 0};
    std::lock_guard lock(mutex_);
    pruneIfDueLocked(now);
    if (hops_.size() >= kMaxEntries && !hops_.contains(entryKey)) {
        makeRoomLocked(hops_, now);
    }
    hops_[entryKey] = {hops, now + kPolicyTtlMs};
}

std::optional<Policy> PolicyRegistry::take(const std::string& targetAddress,
                                           uint16_t sourcePort, uint64_t nowMs) {
    Address address;
    if (!transparent::parseAddress(targetAddress, address)) return std::nullopt;
    return take(address, sourcePort, std::nullopt, nowMs);
}

std::optional<Policy> PolicyRegistry::take(const Address& target,
                                           uint16_t sourcePort,
                                           std::optional<uint32_t> sequence,
                                           uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    const transparent::PeerKey entryKey{target, sourcePort, 0};
    std::lock_guard lock(mutex_);

    const auto found = policies_.find(entryKey);
    if (found == policies_.end()) return std::nullopt;
    Entry& entry = found->second;
    if (entry.expiresAtMs <= now) {
        policies_.erase(found);
        return std::nullopt;
    }

    if (entry.taken) {
        // A retransmitted ClientHello must get the same treatment as the
        // original; sending it clear would leak the SNI the profile hides.
        if (sequence && entry.hasSequence && entry.sequence == *sequence) {
            return entry.policy;
        }
        return std::nullopt;
    }

    entry.taken = true;
    if (sequence) {
        entry.hasSequence = true;
        entry.sequence = *sequence;
    }
    if (entry.policy.mode == Mode::FakeAutoTtl) {
        const auto hop = hops_.find(entryKey);
        if (hop == hops_.end() || hop->second.expiresAtMs <= now ||
            hop->second.pathHops < 3) {
            // Never let a missing SYN/ACK sample turn the AutoTTL profile into
            // an untouched hello that could be learned as a false winner.
            entry.policy.mode = Mode::FakeBadSequence;
            entry.policy.fakeSequenceDelta = -10000;
        } else {
            entry.policy.fakeTtl =
                (uint8_t)std::max<unsigned>(2, hop->second.pathHops - 1);
        }
    }
    return entry.policy;
}

void PolicyRegistry::noteApplied(const Address& target, uint16_t sourcePort,
                                 uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    const auto found = policies_.find(transparent::PeerKey{target, sourcePort, 0});
    if (found == policies_.end()) return;
    found->second.applied = true;
    // Outlive the probe: the prober asks only after it saw the server answer.
    found->second.expiresAtMs =
        std::max(found->second.expiresAtMs, now + kAppliedTtlMs);
}

bool PolicyRegistry::consumeApplied(const std::string& targetAddress,
                                    uint16_t sourcePort, uint64_t nowMs) {
    Address address;
    if (!transparent::parseAddress(targetAddress, address)) return false;
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    const auto found = policies_.find(transparent::PeerKey{address, sourcePort, 0});
    if (found == policies_.end()) return false;
    const bool applied = found->second.applied && found->second.expiresAtMs > now;
    policies_.erase(found);
    return applied;
}

void PolicyRegistry::clear() {
    std::lock_guard lock(mutex_);
    policies_.clear();
    hops_.clear();
    nextPruneMs_ = 0;
}

} // namespace packet_strategy
