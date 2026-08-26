#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dns_message {

inline constexpr uint16_t kTypeA = 1;
inline constexpr uint16_t kTypeAaaa = 28;

struct Query {
    uint16_t id = 0;
    uint16_t type = 0;
    bool recursionDesired = false;
    std::string name;
    std::vector<uint8_t> question;
};

bool parseQuery(const uint8_t* data, size_t length, Query& out);

// `failed` emits SERVFAIL; an empty address set without failure emits
// NOERROR/NODATA, which is correct when only the other address family exists.
std::vector<uint8_t> buildResponse(const Query& query,
                                   const std::vector<std::string>& addresses,
                                   uint32_t ttlSeconds,
                                   bool failed = false);

} // namespace dns_message
