#include "DnsMessage.hpp"

#include <algorithm>
#include <array>
#include <utility>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

namespace dns_message {
namespace {

constexpr size_t kHeaderSize = 12;
constexpr uint16_t kClassInternet = 1;
constexpr uint16_t kTypeOpt = 41;
constexpr size_t kMaxNameLength = 253;
constexpr size_t kMaxAnswers = 8;
// Payload size we advertise in the OPT record of hand-built answers; the
// de-facto safe value that avoids IP fragmentation (DNS Flag Day 2020).
constexpr uint16_t kAdvertisedPayload = 1232;

uint16_t read16(const uint8_t* data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

uint32_t read32(const uint8_t* data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | data[3];
}

void write16(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)value;
}

void write32(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)value;
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

bool isNameChar(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

// Pulls the requestor's payload size / DO bit out of an OPT record in the
// additional section. Tolerant on purpose: a malformed tail only means "no EDNS".
void parseEdns(const uint8_t* data, size_t length, size_t offset, Query& out) {
    if (read16(data + 6) != 0 || read16(data + 8) != 0) return;

    for (unsigned count = read16(data + 10); count > 0; --count) {
        // Only a root-named record can be OPT; anything else ends the scan.
        if (offset + 11 > length || data[offset] != 0) return;
        const uint16_t type = read16(data + offset + 1);
        const uint16_t recordClass = read16(data + offset + 3);
        const uint32_t ttl = read32(data + offset + 5);
        const uint16_t rdLength = read16(data + offset + 9);
        if (offset + 11 + rdLength > length) return;
        if (type == kTypeOpt) {
            out.ednsPayload = recordClass;
            out.dnssecOk = (ttl & 0x8000) != 0;
            return;
        }
        offset += 11 + rdLength;
    }
}

// Advances `offset` past a (possibly compressed) name.
bool skipName(const uint8_t* data, size_t length, size_t& offset) {
    while (true) {
        if (offset >= length) return false;
        const uint8_t first = data[offset];
        if (first == 0) { ++offset; return true; }
        if ((first & 0xC0) == 0xC0) {
            if (offset + 2 > length) return false;
            offset += 2;
            return true;
        }
        if ((first & 0xC0) != 0) return false;
        offset += 1 + (size_t)first;
    }
}

struct RecordRef {
    uint16_t type = 0;
    uint8_t section = 0;    // 0 answer, 1 authority, 2 additional
    size_t ttlOffset = 0;
};

// Walks header, questions and every resource record. Offsets only ever move
// forward and are checked against `length` before each read.
bool walk(const uint8_t* data, size_t length, size_t& questionEnd,
          std::vector<RecordRef>& records) {
    records.clear();
    if (!data || length < kHeaderSize) return false;

    const size_t questions = read16(data + 4);
    const size_t counts[3] = {read16(data + 6), read16(data + 8), read16(data + 10)};
    const size_t total = counts[0] + counts[1] + counts[2];
    // Every question needs >= 5 bytes and every record >= 11; reject counts
    // that cannot possibly fit before looping on them.
    if (questions * 5 + total * 11 > length) return false;

    size_t offset = kHeaderSize;
    for (size_t index = 0; index < questions; ++index) {
        if (!skipName(data, length, offset) || offset + 4 > length) return false;
        offset += 4;
    }
    questionEnd = offset;

    for (uint8_t section = 0; section < 3; ++section) {
        for (size_t index = 0; index < counts[section]; ++index) {
            if (!skipName(data, length, offset) || offset + 10 > length) return false;
            RecordRef ref;
            ref.type = read16(data + offset);
            ref.section = section;
            ref.ttlOffset = offset + 4;
            const size_t rdLength = read16(data + offset + 8);
            offset += 10;
            if (offset + rdLength > length) return false;
            offset += rdLength;
            records.push_back(ref);
        }
    }
    return true;
}

char lowerAscii(uint8_t c) {
    return (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
}

} // namespace

bool parseQuery(const uint8_t* data, size_t length, Query& out) {
    out = {};
    if (!data || length < kHeaderSize) return false;

    const uint16_t flags = read16(data + 2);
    if ((flags & 0x8000) != 0) return false; // a response: never answer one

    out.id = read16(data);
    out.opcode = (uint8_t)((flags >> 11) & 0x0F);
    out.recursionDesired = (flags & 0x0100) != 0;
    if (out.opcode != 0) {
        out.error = kRcodeNotImp;
        return false;
    }
    // Every remaining failure is a malformed query unless said otherwise.
    out.error = kRcodeFormErr;
    if (read16(data + 4) != 1) return false;

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
            const char character = lowerAscii(data[offset + index]);
            if (!isNameChar((unsigned char)character)) return false;
            name.push_back(character);
        }
        offset += labelLength;
    }

    if (name.empty() || offset + 4 > length) return false;
    const uint16_t type = read16(data + offset);
    const uint16_t queryClass = read16(data + offset + 2);
    offset += 4;
    if (queryClass != kClassInternet) {
        out.error = kRcodeNotImp;
        return false;
    }

    out.error = 0;
    out.type = type;
    out.name = std::move(name);
    out.question.assign(data + kHeaderSize, data + offset);
    parseEdns(data, length, offset, out);
    return true;
}

std::vector<uint8_t> buildResponse(const Query& query,
                                   const std::vector<std::string>& addresses,
                                   uint32_t ttlSeconds,
                                   bool failed,
                                   uint8_t rcode) {
    const uint8_t effectiveRcode = failed && rcode == 0 ? kRcodeServFail : rcode;
    const bool carriesAnswers = effectiveRcode == 0;

    std::vector<std::array<uint8_t, 16>> encoded;
    size_t addressLength = 0;

    if (carriesAnswers && (query.type == kTypeA || query.type == kTypeAaaa)) {
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

    const bool withOpt = query.ednsPayload != 0;
    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + query.question.size() +
                encoded.size() * (12 + addressLength) + (withOpt ? 11 : 0));
    append16(out, query.id);

    uint16_t flags = 0x8080; // response + recursion available
    if (query.recursionDesired) flags |= 0x0100;
    flags = (uint16_t)(flags | (effectiveRcode & 0x0F));
    append16(out, flags);
    append16(out, 1);
    append16(out, (uint16_t)encoded.size());
    append16(out, 0);
    append16(out, withOpt ? 1 : 0);
    out.insert(out.end(), query.question.begin(), query.question.end());

    for (const auto& address : encoded) {
        append16(out, 0xC00C);
        append16(out, query.type);
        append16(out, kClassInternet);
        append32(out, ttlSeconds);
        append16(out, (uint16_t)addressLength);
        out.insert(out.end(), address.begin(),
                   address.begin() + (ptrdiff_t)addressLength);
    }

    if (withOpt) {
        out.push_back(0);                   // root name
        append16(out, kTypeOpt);
        append16(out, kAdvertisedPayload);  // CLASS = UDP payload size
        append32(out, 0);                   // extended RCODE, version, flags
        append16(out, 0);                   // no options
    }
    return out;
}

std::vector<uint8_t> buildError(const Query& query, uint8_t rcode) {
    std::vector<uint8_t> out;
    out.reserve(kHeaderSize);
    append16(out, query.id);
    uint16_t flags = (uint16_t)(0x8080 | ((query.opcode & 0x0F) << 11));
    if (query.recursionDesired) flags |= 0x0100;
    flags = (uint16_t)(flags | (rcode & 0x0F));
    append16(out, flags);
    for (int field = 0; field < 4; ++field) append16(out, 0);
    return out;
}

bool inspectResponse(const uint8_t* data, size_t length, ResponseInfo& out) {
    out = {};
    size_t questionEnd = 0;
    std::vector<RecordRef> records;
    if (!walk(data, length, questionEnd, records)) return false;

    const uint16_t flags = read16(data + 2);
    out.response = (flags & 0x8000) != 0;
    out.truncated = (flags & 0x0200) != 0;
    out.rcode = (uint8_t)(flags & 0x000F);
    out.answers = read16(data + 6);

    for (const RecordRef& record : records) {
        if (record.type == kTypeOpt) continue;
        const uint32_t ttl = read32(data + record.ttlOffset);
        if (record.section == 0) {
            out.answerTtl = out.hasAnswerTtl ? std::min(out.answerTtl, ttl) : ttl;
            out.hasAnswerTtl = true;
        } else if (record.section == 1) {
            out.authorityTtl = out.hasAuthorityTtl ? std::min(out.authorityTtl, ttl) : ttl;
            out.hasAuthorityTtl = true;
        }
    }
    return true;
}

bool echoesQuestion(const uint8_t* data, size_t length, const Query& query) {
    if (!data || length < kHeaderSize + query.question.size() ||
        read16(data + 4) != 1 || query.question.empty()) {
        return false;
    }
    for (size_t index = 0; index < query.question.size(); ++index) {
        if (lowerAscii(data[kHeaderSize + index]) != lowerAscii(query.question[index])) {
            return false;
        }
    }
    return true;
}

void setId(std::vector<uint8_t>& message, uint16_t id) {
    if (message.size() >= 2) write16(message.data(), id);
}

void ageTtls(std::vector<uint8_t>& message, uint32_t ageSeconds) {
    size_t questionEnd = 0;
    std::vector<RecordRef> records;
    if (!walk(message.data(), message.size(), questionEnd, records)) return;

    for (const RecordRef& record : records) {
        if (record.type == kTypeOpt) continue;
        uint8_t* field = message.data() + record.ttlOffset;
        const uint32_t ttl = read32(field);
        write32(field, ttl > ageSeconds ? ttl - ageSeconds : (ttl > 0 ? 1 : 0));
    }
}

bool truncateForUdp(std::vector<uint8_t>& message, size_t limit) {
    if (message.size() <= limit || message.size() < kHeaderSize) return false;

    size_t questionEnd = 0;
    std::vector<RecordRef> records;
    const bool wellFormed = walk(message.data(), message.size(), questionEnd, records);

    message.resize(wellFormed ? questionEnd : kHeaderSize);
    write16(message.data() + 2, (uint16_t)(read16(message.data() + 2) | 0x0200));
    if (!wellFormed) write16(message.data() + 4, 0);
    write16(message.data() + 6, 0);
    write16(message.data() + 8, 0);
    write16(message.data() + 10, 0);
    return true;
}

} // namespace dns_message
