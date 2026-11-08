#include "Test.hpp"

#include "AdBlock.hpp"
#include "DnsMessage.hpp"

#include <algorithm>
#include <iterator>
#include <vector>

TEST(adblockParsesDomainFormats) {
    const adblock::DomainSet parsed = adblock::parseDomains(
        "# Title: demo\r\n"
        "ads.example.com\r\n"
        "0.0.0.0 Tracker.Example.NET\n"
        "||adserver.test^\n"
        "*.wild.example.org\n"
        "! comment\n"
        "   \n"
        "1.2.3.4\n"          // IP literal: not a hostname
        "bad name.com\n"     // would be taken as hosts line "name.com"
        "trailing.example.com # note\n");
    CHECK(parsed.contains("ads.example.com"));
    CHECK(parsed.contains("tracker.example.net"));
    CHECK(parsed.contains("adserver.test"));
    CHECK(parsed.contains("wild.example.org"));
    CHECK(parsed.contains("trailing.example.com"));
    CHECK(!parsed.contains("1.2.3.4"));
    CHECK(!parsed.contains("0.0.0.0"));
}

TEST(adblockBlocksSubdomainsButNotSiblings) {
    adblock::Blocklist list;
    list.replace(adblock::parseDomains("doubleclick.net\nads.example.com\n"));

    CHECK(list.blocks("doubleclick.net"));
    CHECK(list.blocks("stats.g.DoubleClick.net."));   // case and trailing dot
    CHECK(list.blocks("x.ads.example.com"));
    CHECK(!list.blocks("example.com"));                // parent of a blocked name
    CHECK(!list.blocks("notdoubleclick.net"));         // label boundary, not substring
    CHECK(!list.blocks("twitch.tv"));
    CHECK(!list.blocks("1.2.3.4"));
    CHECK(!list.blocks("[2001:db8::1]"));
    CHECK(!list.blocks(""));
}

TEST(adblockAllowListWinsOverBlocklist) {
    adblock::Blocklist list;
    list.replace(adblock::parseDomains("tracker.com\n"));
    list.setAllow({"Good.Tracker.com"});

    CHECK(list.blocks("tracker.com"));
    CHECK(list.blocks("a.tracker.com"));
    CHECK(!list.blocks("good.tracker.com"));
    CHECK(!list.blocks("x.good.tracker.com"));

    // Replacing the list keeps the allow-list.
    list.replace(adblock::parseDomains("tracker.com\nother.com\n"));
    CHECK(!list.blocks("good.tracker.com"));
    CHECK(list.blocks("other.com"));
}

TEST(adblockEmptyListBlocksNothing) {
    adblock::Blocklist list;
    CHECK(!list.blocks("doubleclick.net"));
    CHECK_EQ(list.size(), (size_t)0);
}

TEST(adblockTalliesBlockedHostsLowercased) {
    const uint64_t before = adblock::blockedCount();
    adblock::recordBlocked("Tally-Test.Example.COM");
    adblock::recordBlocked("tally-test.example.com");
    adblock::recordBlocked("tally-other.example.com");
    CHECK_EQ(adblock::blockedCount(), before + 3);

    uint32_t count = 0;
    for (const auto& [host, hits] : adblock::topBlocked(2000)) {
        if (host == "tally-test.example.com") count = hits;
    }
    CHECK_EQ(count, (uint32_t)2);
}

TEST(adblockListNames) {
    CHECK(adblock::listPath("pro").has_value());
    CHECK(adblock::listPath("tif").has_value());
    CHECK(!adblock::listPath("nope").has_value());
    CHECK(adblock::listPath("pro")->ends_with("pro-onlydomains.txt"));
}

namespace {

void put16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

// One-question response whose single answer is `type` with `rdata`, plus an OPT.
std::vector<uint8_t> responseWith(uint16_t type, const std::vector<uint8_t>& rdata) {
    std::vector<uint8_t> out;
    put16(out, 0x1234); put16(out, 0x8180);
    put16(out, 1); put16(out, 1); put16(out, 0); put16(out, 1);
    const uint8_t name[] = {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    out.insert(out.end(), std::begin(name), std::end(name));
    put16(out, type); put16(out, 1);
    out.push_back(0xC0); out.push_back(0x0C);               // answer owner -> question
    put16(out, type); put16(out, 1);
    put16(out, 0); put16(out, 300);                         // TTL
    put16(out, (uint16_t)rdata.size());
    out.insert(out.end(), rdata.begin(), rdata.end());
    out.push_back(0); put16(out, 41); put16(out, 1232);     // OPT
    put16(out, 0); put16(out, 0); put16(out, 0);
    return out;
}

bool contains(const std::vector<uint8_t>& haystack, const std::vector<uint8_t>& needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) !=
           haystack.end();
}

} // namespace

TEST(dnsStripEchRemovesOnlyTheEchParam) {
    const std::vector<uint8_t> rdata = {
        0, 1, 0,                              // priority 1, target "."
        0, 1, 0, 3, 2, 'h', '2',              // alpn
        0, 4, 0, 4, 1, 2, 3, 4,               // ipv4hint
        0, 5, 0, 4, 'A', 'B', 'C', 'D',       // ech
    };
    std::vector<uint8_t> reply = responseWith(65, rdata);
    const size_t before = reply.size();

    CHECK(dns_message::stripEch(reply));
    CHECK_EQ(reply.size(), before - 8);
    CHECK(!contains(reply, {0, 5, 0, 4, 'A', 'B', 'C', 'D'}));
    CHECK(contains(reply, {0, 1, 0, 3, 2, 'h', '2'}));
    CHECK(contains(reply, {0, 4, 0, 4, 1, 2, 3, 4}));

    dns_message::ResponseInfo info;
    CHECK(dns_message::inspectResponse(reply.data(), reply.size(), info));
    CHECK_EQ(info.answers, (size_t)1);
    CHECK(!dns_message::stripEch(reply));   // nothing left to remove
}

TEST(dnsStripEchLeavesOtherMessagesAlone) {
    std::vector<uint8_t> noEch = responseWith(65, {0, 1, 0, 0, 1, 0, 3, 2, 'h', '2'});
    const std::vector<uint8_t> noEchCopy = noEch;
    CHECK(!dns_message::stripEch(noEch));
    CHECK(noEch == noEchCopy);

    std::vector<uint8_t> mx = responseWith(15, {0, 10, 0});   // type this cannot rewrite
    const std::vector<uint8_t> mxCopy = mx;
    CHECK(!dns_message::stripEch(mx));
    CHECK(mx == mxCopy);

    std::vector<uint8_t> garbage = {1, 2, 3};
    CHECK(!dns_message::stripEch(garbage));
}
