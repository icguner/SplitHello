#include "DnsMessage.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 64 * 1024) return 0;

    dns_message::Query query;
    if (!dns_message::parseQuery(data, size, query)) return 0;

    const std::vector<std::string> addresses = query.type == dns_message::kTypeAaaa
        ? std::vector<std::string>{"::1", "2001:db8::1", "invalid"}
        : std::vector<std::string>{"127.0.0.1", "192.0.2.1", "invalid"};
    const uint32_t ttl = size >= 4
        ? ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
              ((uint32_t)data[2] << 8) | data[3]
        : 0;
    (void)dns_message::buildResponse(query, addresses, ttl, false);
    (void)dns_message::buildResponse(query, {}, ttl, true);
    return 0;
}
