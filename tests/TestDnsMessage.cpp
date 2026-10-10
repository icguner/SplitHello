#include "Test.hpp"

#include "DnsMessage.hpp"
#include "DnsQueryBuilder.hpp"

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

TEST(DnsMessageParsesEdnsAndOnlyAcceptsSaneNames) {
    const auto edns = dnstest::query("Example.COM", dns_message::kTypeA, 0x0042, 1232, true);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(edns.data(), edns.size(), parsed));
    CHECK_EQ(parsed.id, (uint16_t)0x0042);
    CHECK_EQ(parsed.name, std::string("example.com"));
    CHECK_EQ(parsed.ednsPayload, (uint16_t)1232);
    CHECK(parsed.dnssecOk);
    CHECK_EQ(parsed.error, (uint8_t)0);

    const auto plain = dnstest::query("example.com", dns_message::kTypeA);
    CHECK(dns_message::parseQuery(plain.data(), plain.size(), parsed));
    CHECK_EQ(parsed.ednsPayload, (uint16_t)0);
    CHECK(!parsed.dnssecOk);

    // Service labels use '_'; hyphens and digits are ordinary.
    const auto service = dnstest::query("_dmarc.x-1.example.com", 16);
    CHECK(dns_message::parseQuery(service.data(), service.size(), parsed));

    // Anything that does not belong in a hostname is refused (and answered FORMERR).
    for (const char* bad : {"bad name.example", "a$b.example", "a&b.example",
                            "x/../y.example", "caf\xC3\xA9.example", "del\x7f.example"}) {
        const auto bytes = dnstest::query(bad, dns_message::kTypeA);
        CHECK(!dns_message::parseQuery(bytes.data(), bytes.size(), parsed));
        CHECK_EQ(parsed.error, dns_message::kRcodeFormErr);
    }
}

TEST(DnsMessageClassifiesUnusableQueries) {
    dns_message::Query parsed;

    // Unsupported opcode (STATUS) and non-IN class are NOTIMP, ID still known.
    auto opcode = dnstest::query("example.com", dns_message::kTypeA, 0x7777, 0, false, 1, 0x1100);
    CHECK(!dns_message::parseQuery(opcode.data(), opcode.size(), parsed));
    CHECK_EQ(parsed.error, dns_message::kRcodeNotImp);
    CHECK_EQ(parsed.id, (uint16_t)0x7777);

    auto chaos = dnstest::query("version.bind", 16, 0x5555, 0, false, 3);
    CHECK(!dns_message::parseQuery(chaos.data(), chaos.size(), parsed));
    CHECK_EQ(parsed.error, dns_message::kRcodeNotImp);

    // Two questions: malformed for our purposes.
    auto two = dnstest::query("example.com", dns_message::kTypeA);
    two[5] = 2;
    CHECK(!dns_message::parseQuery(two.data(), two.size(), parsed));
    CHECK_EQ(parsed.error, dns_message::kRcodeFormErr);

    // A response (QR=1) or a runt has no header worth answering.
    auto response = dnstest::query("example.com", dns_message::kTypeA, 1, 0, false, 1, 0x8180);
    CHECK(!dns_message::parseQuery(response.data(), response.size(), parsed));
    CHECK_EQ(parsed.error, (uint8_t)0);
    const uint8_t runt[4] = {1, 2, 3, 4};
    CHECK(!dns_message::parseQuery(runt, sizeof(runt), parsed));
    CHECK_EQ(parsed.error, (uint8_t)0);

    // The error reply is header-only, echoes ID/RD and carries the code.
    CHECK(!dns_message::parseQuery(opcode.data(), opcode.size(), parsed));
    const auto reply = dns_message::buildError(parsed, parsed.error);
    CHECK_EQ(reply.size(), (size_t)12);
    CHECK_EQ(dnstest::read16(reply, 0), (uint16_t)0x7777);
    CHECK((dnstest::read16(reply, 2) & 0x8000) != 0);
    CHECK((dnstest::read16(reply, 2) & 0x0100) != 0);
    CHECK_EQ((dnstest::read16(reply, 2) & 0x000F), (uint16_t)dns_message::kRcodeNotImp);
    CHECK_EQ(dnstest::read16(reply, 4), (uint16_t)0);
}

TEST(DnsMessageCarriesRealRcodesAndAnswersEdnsWithOpt) {
    const auto edns = dnstest::query("gone.example", dns_message::kTypeA, 9, 4096);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(edns.data(), edns.size(), parsed));

    const auto nx = dns_message::buildResponse(parsed, {}, 60, false, dns_message::kRcodeNxDomain);
    CHECK_EQ((dnstest::read16(nx, 2) & 0x000F), (uint16_t)dns_message::kRcodeNxDomain);
    CHECK_EQ(dnstest::read16(nx, 6), (uint16_t)0);
    CHECK_EQ(dnstest::read16(nx, 10), (uint16_t)1);          // OPT echoed
    CHECK_EQ(nx[nx.size() - 10], (uint8_t)0);                 // OPT type 41 ...
    CHECK_EQ(nx[nx.size() - 9], (uint8_t)41);

    // A non-zero rcode never carries answers, even if addresses are supplied.
    const auto refused = dns_message::buildResponse(parsed, {"203.0.113.1"}, 60, false, 5);
    CHECK_EQ(dnstest::read16(refused, 6), (uint16_t)0);

    const auto positive = dns_message::buildResponse(parsed, {"203.0.113.1"}, 60);
    CHECK_EQ(dnstest::read16(positive, 6), (uint16_t)1);
    CHECK_EQ(dnstest::read16(positive, 10), (uint16_t)1);

    // No OPT in the query, none in the answer.
    const auto plain = dnstest::query("gone.example", dns_message::kTypeA);
    CHECK(dns_message::parseQuery(plain.data(), plain.size(), parsed));
    CHECK_EQ(dnstest::read16(dns_message::buildResponse(parsed, {}, 60), 10), (uint16_t)0);
}

TEST(DnsMessageAgesTtlsEchoesQuestionAndTruncates) {
    const auto bytes = dnstest::query("Example.com", dns_message::kTypeA, 0x0A0B);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(bytes.data(), bytes.size(), parsed));

    std::vector<uint8_t> response = dns_message::buildResponse(parsed, {"203.0.113.7"}, 120);
    dns_message::ResponseInfo info;
    CHECK(dns_message::inspectResponse(response.data(), response.size(), info));
    CHECK(info.response);
    CHECK(!info.truncated);
    CHECK_EQ(info.answers, (size_t)1);
    CHECK(info.hasAnswerTtl);
    CHECK_EQ(info.answerTtl, (uint32_t)120);

    CHECK(dns_message::echoesQuestion(response.data(), response.size(), parsed));
    dns_message::Query other;
    const auto otherBytes = dnstest::query("other.example", dns_message::kTypeA);
    CHECK(dns_message::parseQuery(otherBytes.data(), otherBytes.size(), other));
    CHECK(!dns_message::echoesQuestion(response.data(), response.size(), other));

    dns_message::setId(response, 0xBEEF);
    CHECK_EQ(dnstest::read16(response, 0), (uint16_t)0xBEEF);

    dns_message::ageTtls(response, 30);
    CHECK(dns_message::inspectResponse(response.data(), response.size(), info));
    CHECK_EQ(info.answerTtl, (uint32_t)90);
    dns_message::ageTtls(response, 100000);                 // never reaches 0 from non-zero
    CHECK(dns_message::inspectResponse(response.data(), response.size(), info));
    CHECK_EQ(info.answerTtl, (uint32_t)1);

    // Fits: untouched. Too big: header + question only, TC set, counts zeroed.
    CHECK(!dns_message::truncateForUdp(response, 512));
    const size_t full = response.size();
    CHECK(dns_message::truncateForUdp(response, full - 1));
    CHECK_EQ(response.size(), (size_t)12 + parsed.question.size());
    CHECK((dnstest::read16(response, 2) & 0x0200) != 0);
    CHECK_EQ(dnstest::read16(response, 6), (uint16_t)0);
    CHECK_EQ(dnstest::read16(response, 4), (uint16_t)1);
}

TEST(DnsMessageInspectRejectsTruncatedAndLyingMessages) {
    const auto bytes = dnstest::query("example.com", dns_message::kTypeA);
    dns_message::Query parsed;
    CHECK(dns_message::parseQuery(bytes.data(), bytes.size(), parsed));
    const auto response = dns_message::buildResponse(parsed, {"203.0.113.7", "203.0.113.8"}, 60);

    dns_message::ResponseInfo info;
    for (size_t length = 0; length < response.size(); ++length) {
        CHECK(!dns_message::inspectResponse(response.data(), length, info));
    }
    CHECK(dns_message::inspectResponse(response.data(), response.size(), info));

    // Counts that promise far more records than the bytes can hold.
    auto lying = response;
    lying[6] = 0xFF;
    lying[7] = 0xFF;
    CHECK(!dns_message::inspectResponse(lying.data(), lying.size(), info));

    // A record whose RDLENGTH runs past the end.
    auto overrun = response;
    overrun[overrun.size() - 5] = 0x7F;
    CHECK(!dns_message::inspectResponse(overrun.data(), overrun.size(), info));
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
