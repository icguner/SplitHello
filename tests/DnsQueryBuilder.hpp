#pragma once

// Hand-built DNS wire messages for the DNS tests.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dnstest {

inline uint16_t read16(const std::vector<uint8_t>& data, size_t offset) {
    return (uint16_t)(((uint16_t)data.at(offset) << 8) | data.at(offset + 1));
}

inline void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

// One question; an EDNS0 OPT record is appended when `ednsPayload` is non-zero.
inline std::vector<uint8_t> query(const std::string& name, uint16_t type,
                                  uint16_t id = 0x1234, uint16_t ednsPayload = 0,
                                  bool dnssecOk = false, uint16_t queryClass = 1,
                                  uint16_t flags = 0x0100) {
    std::vector<uint8_t> out;
    put16(out, id);
    put16(out, flags);
    put16(out, 1);
    put16(out, 0);
    put16(out, 0);
    put16(out, ednsPayload != 0 ? 1 : 0);

    size_t begin = 0;
    while (begin < name.size()) {
        const size_t end = name.find('.', begin);
        const size_t length = (end == std::string::npos ? name.size() : end) - begin;
        out.push_back((uint8_t)length);
        out.insert(out.end(), name.begin() + (ptrdiff_t)begin,
                   name.begin() + (ptrdiff_t)(begin + length));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    out.push_back(0);
    put16(out, type);
    put16(out, queryClass);

    if (ednsPayload != 0) {
        out.push_back(0);                  // root name
        put16(out, 41);                    // OPT
        put16(out, ednsPayload);           // CLASS = UDP payload size
        out.push_back(0);                  // extended RCODE
        out.push_back(0);                  // version
        out.push_back((uint8_t)(dnssecOk ? 0x80 : 0x00));
        out.push_back(0);
        put16(out, 0);                     // no options
    }
    return out;
}

} // namespace dnstest
