#include "PacketStrategy.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <array>

namespace packet_strategy {
namespace {

constexpr uint64_t kPolicyTtlMs = 15000;
constexpr size_t kMaxEntries = 8192;

uint64_t clockMs(uint64_t supplied) {
    return supplied == 0 ? GetTickCount64() : supplied;
}

std::string key(const std::string& address, uint16_t port) {
    return address + "|" + std::to_string(port);
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

std::vector<Segment> buildSegments(const uint8_t* payload, size_t length,
                                   const Policy& policy) {
    if (!payload || length < 2) return {};
    const size_t split = std::clamp(policy.splitOffset, (size_t)1, length - 1);

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

void PolicyRegistry::arm(const std::string& targetAddress, uint16_t sourcePort,
                         const Policy& policy, uint64_t nowMs) {
    if (targetAddress.empty() || sourcePort == 0 || policy.mode == Mode::None) return;
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);
    if (policies_.size() >= kMaxEntries) policies_.clear();
    policies_[key(targetAddress, sourcePort)] = {policy, now + kPolicyTtlMs};
}

void PolicyRegistry::observeHop(const std::string& targetAddress,
                                uint16_t sourcePort, uint8_t receivedTtl,
                                uint64_t nowMs) {
    if (targetAddress.empty() || sourcePort == 0 || receivedTtl == 0) return;
    const uint8_t hops = inferPathHops(receivedTtl);
    if (hops == 0) return;

    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);
    if (hops_.size() >= kMaxEntries) hops_.clear();
    hops_[key(targetAddress, sourcePort)] = {hops, now + kPolicyTtlMs};
}

std::optional<Policy> PolicyRegistry::take(const std::string& targetAddress,
                                           uint16_t sourcePort,
                                           uint64_t nowMs) {
    const uint64_t now = clockMs(nowMs);
    std::lock_guard lock(mutex_);
    pruneLocked(now);

    const std::string entryKey = key(targetAddress, sourcePort);
    const auto found = policies_.find(entryKey);
    if (found == policies_.end()) return std::nullopt;

    Policy policy = found->second.policy;
    policies_.erase(found);
    if (policy.mode == Mode::FakeAutoTtl) {
        const auto hop = hops_.find(entryKey);
        if (hop == hops_.end() || hop->second.pathHops < 3) {
            // Never let a missing SYN/ACK sample turn the AutoTTL profile into
            // an untouched hello that could be learned as a false winner.
            policy.mode = Mode::FakeBadSequence;
            policy.fakeSequenceDelta = -10000;
        } else {
            policy.fakeTtl = (uint8_t)std::max<unsigned>(2, hop->second.pathHops - 1);
        }
    }
    return policy;
}

void PolicyRegistry::clear() {
    std::lock_guard lock(mutex_);
    policies_.clear();
    hops_.clear();
}

void PolicyRegistry::pruneLocked(uint64_t nowMs) {
    const auto prune = [nowMs](auto& entries) {
        for (auto it = entries.begin(); it != entries.end();) {
            if (it->second.expiresAtMs <= nowMs) it = entries.erase(it);
            else ++it;
        }
    };
    prune(policies_);
    prune(hops_);
}

} // namespace packet_strategy
