#include "Test.hpp"

#include "DnsMessage.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace {

uint16_t read16(const std::vector<uint8_t>& data, size_t offset) {
    return (uint16_t)(((uint16_t)data.at(offset) << 8) | data.at(offset + 1));
}

std::vector<uint8_t> query(const std::string& name, uint16_t type) {
    std::vector<uint8_t> out = {
        0x12, 0x34, 0x01, 0x00, // ID, recursion desired
        0x00, 0x01, 0x00, 0x00, // one question, no answers
        0x00, 0x00, 0x00, 0x00
    };

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
    out.push_back((uint8_t)(type >> 8));
    out.push_back((uint8_t)type);
    out.push_back(0);
    out.push_back(1);
    return out;
}

} // namespace

TEST(DnsMessageParsesOneUncompressedQuestion) {
    const std::vector<uint8_t> bytes = query("Discord.COM", dns_message::kTypeA);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(bytes.data(), bytes.size(), parsed));
    CHECK_EQ(parsed.id, (uint16_t)0x1234);
    CHECK_EQ(parsed.name, std::string("discord.com"));
    CHECK_EQ(parsed.type, dns_message::kTypeA);
    CHECK(parsed.recursionDesired);
}

TEST(DnsMessageRejectsCompressedQuestions) {
    std::vector<uint8_t> bytes = query("discord.com", dns_message::kTypeA);
    bytes[12] = 0xC0;
    dns_message::Query parsed;
    CHECK(!dns_message::parseQuery(bytes.data(), bytes.size(), parsed));
}

TEST(DnsMessageBuildsOnlyMatchingAAnswers) {
    const std::vector<uint8_t> bytes = query("discord.com", dns_message::kTypeA);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(bytes.data(), bytes.size(), parsed));

    const std::vector<uint8_t> response = dns_message::buildResponse(
        parsed, {"203.0.113.7", "not-an-address", "2001:db8::7"}, 120, false);
    CHECK_EQ(read16(response, 0), (uint16_t)0x1234);
    CHECK_EQ(read16(response, 6), (uint16_t)1);
    CHECK_EQ((read16(response, 2) & 0x000F), (uint16_t)0);
    CHECK_EQ(response[response.size() - 4], (uint8_t)203);
    CHECK_EQ(response[response.size() - 3], (uint8_t)0);
    CHECK_EQ(response[response.size() - 2], (uint8_t)113);
    CHECK_EQ(response[response.size() - 1], (uint8_t)7);
}

TEST(DnsMessageBuildsAaaaAndServfailResponses) {
    const std::vector<uint8_t> bytes = query("discord.com", dns_message::kTypeAaaa);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(bytes.data(), bytes.size(), parsed));

    const std::vector<uint8_t> aaaa = dns_message::buildResponse(
        parsed, {"2001:db8::7", "203.0.113.7"}, 300, false);
    CHECK_EQ(read16(aaaa, 6), (uint16_t)1);
    CHECK_EQ(read16(aaaa, aaaa.size() - 18), (uint16_t)16);

    const std::vector<uint8_t> failed =
        dns_message::buildResponse(parsed, {}, 60, true);
    CHECK_EQ(read16(failed, 6), (uint16_t)0);
    CHECK_EQ((read16(failed, 2) & 0x000F), (uint16_t)2);
}
