#include "DnsMessage.hpp"

#include <array>
#include <cctype>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

namespace dns_message {
namespace {

constexpr size_t kHeaderSize = 12;
constexpr uint16_t kClassInternet = 1;
constexpr size_t kMaxNameLength = 253;
constexpr size_t kMaxAnswers = 8;

uint16_t read16(const uint8_t* data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

void append16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

void append32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back((uint8_t)(value >> 24));
    out.push_back((uint8_t)(value >> 16));
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

} // namespace

bool parseQuery(const uint8_t* data, size_t length, Query& out) {
    out = {};
    if (!data || length < kHeaderSize) return false;

    const uint16_t flags = read16(data + 2);
    if ((flags & 0x8000) != 0 || (flags & 0x7800) != 0 || read16(data + 4) != 1) {
        return false;
    }

    size_t offset = kHeaderSize;
    std::string name;
    while (true) {
        if (offset >= length) return false;
        const uint8_t labelLength = data[offset++];
        if (labelLength == 0) break;
        if ((labelLength & 0xC0) != 0 || labelLength > 63 ||
            offset + labelLength > length) {
            return false;
        }

        if (!name.empty()) name.push_back('.');
        if (name.size() + labelLength > kMaxNameLength) return false;
        for (size_t index = 0; index < labelLength; ++index) {
            const unsigned char character = data[offset + index];
            if (character <= 0x20 || character >= 0x7F) return false;
            name.push_back((char)std::tolower(character));
        }
        offset += labelLength;
    }

    if (name.empty() || offset + 4 > length) return false;
    const uint16_t type = read16(data + offset);
    const uint16_t queryClass = read16(data + offset + 2);
    offset += 4;
    if (queryClass != kClassInternet) return false;

    out.id = read16(data);
    out.type = type;
    out.recursionDesired = (flags & 0x0100) != 0;
    out.name = std::move(name);
    out.question.assign(data + kHeaderSize, data + offset);
    return true;
}

std::vector<uint8_t> buildResponse(const Query& query,
                                   const std::vector<std::string>& addresses,
                                   uint32_t ttlSeconds,
                                   bool failed) {
    std::vector<std::array<uint8_t, 16>> encoded;
    size_t addressLength = 0;

    if (!failed && (query.type == kTypeA || query.type == kTypeAaaa)) {
        addressLength = query.type == kTypeA ? 4 : 16;
        const int family = query.type == kTypeA ? AF_INET : AF_INET6;
        for (const std::string& address : addresses) {
            std::array<uint8_t, 16> bytes{};
            if (inet_pton(family, address.c_str(), bytes.data()) == 1) {
                encoded.push_back(bytes);
                if (encoded.size() >= kMaxAnswers) break;
            }
        }
    }

    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + query.question.size() + encoded.size() * (12 + addressLength));
    append16(out, query.id);

    uint16_t flags = 0x8080; // response + recursion available
    if (query.recursionDesired) flags |= 0x0100;
    if (failed) flags |= 0x0002; // SERVFAIL
    append16(out, flags);
    append16(out, 1);
    append16(out, failed ? 0 : (uint16_t)encoded.size());
    append16(out, 0);
    append16(out, 0);
    out.insert(out.end(), query.question.begin(), query.question.end());

    if (!failed) {
        for (const auto& address : encoded) {
            append16(out, 0xC00C);
            append16(out, query.type);
            append16(out, kClassInternet);
            append32(out, ttlSeconds);
            append16(out, (uint16_t)addressLength);
            out.insert(out.end(), address.begin(),
                       address.begin() + (ptrdiff_t)addressLength);
        }
    }
    return out;
}

} // namespace dns_message
