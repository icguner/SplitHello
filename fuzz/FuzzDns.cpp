#include "DnsMessage.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 64 * 1024) return 0;

    const uint32_t ttl = size >= 4
        ? ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
              ((uint32_t)data[2] << 8) | data[3]
        : 0;

    // The same bytes as a *response* from the relay: the walker, the TTL
    // rewrite and the UDP truncation must survive any structure.
    dns_message::ResponseInfo info;
    (void)dns_message::inspectResponse(data, size, info);
    std::vector<uint8_t> message = size == 0 ? std::vector<uint8_t>{}
                                             : std::vector<uint8_t>(data, data + size);
    dns_message::ageTtls(message, ttl);
    dns_message::setId(message, (uint16_t)ttl);
    (void)dns_message::truncateForUdp(message, size / 2);

    dns_message::Query query;
    if (!dns_message::parseQuery(data, size, query)) {
        if (query.error != 0) (void)dns_message::buildError(query, query.error);
        return 0;
    }

    const std::vector<std::string> addresses = query.type == dns_message::kTypeAaaa
        ? std::vector<std::string>{"::1", "2001:db8::1", "invalid"}
        : std::vector<std::string>{"127.0.0.1", "192.0.2.1", "invalid"};
    std::vector<uint8_t> built = dns_message::buildResponse(query, addresses, ttl, false);
    (void)dns_message::buildResponse(query, {}, ttl, true);
    (void)dns_message::buildResponse(query, {}, ttl, false, (uint8_t)(ttl & 0x0F));
    (void)dns_message::echoesQuestion(built.data(), built.size(), query);
    (void)dns_message::inspectResponse(built.data(), built.size(), info);
    return 0;
}
