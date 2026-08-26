#include "Test.hpp"

#include "HelloBuilder.hpp"
#include "TlsHello.hpp"

#include <cstdint>
#include <string>
#include <vector>

using testing::buildClientHello;
using testing::sniText;

TEST(ParsesCompleteClientHello) {
    const std::vector<uint8_t> data = buildClientHello();
    tls::ClientHello hello;

    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Ok);
    CHECK_EQ(hello.recordTotalLength, data.size());
    CHECK_EQ(hello.serverName, std::string("discord.com"));
    CHECK_EQ(sniText(data, hello), std::string("discord.com"));
    CHECK(!hello.hasEch);
    CHECK(!hello.spansRecords);
    CHECK(hello.sniOffset + hello.sniLength <= data.size());
}

// The bug this guards against: reading the tail of a ClientHello that has not
// arrived yet. Every prefix must report NeedMore, never Ok.
TEST(TruncatedHelloNeverReportsComplete) {
    const std::vector<uint8_t> data = buildClientHello();

    for (size_t prefix = 1; prefix < data.size(); ++prefix) {
        tls::ClientHello hello;
        const tls::ParseStatus status = tls::parseClientHello(data.data(), prefix, hello);
        CHECK(status == tls::ParseStatus::NeedMore);
        CHECK(!hello.serverName.size());
    }
}

TEST(TruncatedPostQuantumHelloNeverReportsComplete) {
    // ~4 KB hello: spread over several reads by any real client.
    const std::vector<uint8_t> data = buildClientHello({"discord.com", 4000, false, true});
    CHECK(data.size() > 4000);

    for (size_t prefix = 1; prefix < data.size(); prefix += 7) {
        tls::ClientHello hello;
        CHECK(tls::parseClientHello(data.data(), prefix, hello) == tls::ParseStatus::NeedMore);
    }

    tls::ClientHello hello;
    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Ok);
    CHECK_EQ(sniText(data, hello), std::string("discord.com"));
}

TEST(TrailingBytesAreNotPartOfTheRecord) {
    std::vector<uint8_t> data = buildClientHello();
    const size_t recordSize = data.size();
    data.insert(data.end(), 128, (uint8_t)0x99);

    tls::ClientHello hello;
    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Ok);
    CHECK_EQ(hello.recordTotalLength, recordSize);
}

TEST(RejectsNonTlsTraffic) {
    const std::string request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    tls::ClientHello hello;
    CHECK(tls::parseClientHello((const uint8_t*)request.data(), request.size(), hello) ==
          tls::ParseStatus::NotTls);
}

TEST(RejectsEmptyRecord) {
    const uint8_t data[] = {0x16, 0x03, 0x01, 0x00, 0x00};
    tls::ClientHello hello;
    CHECK(tls::parseClientHello(data, sizeof(data), hello) == tls::ParseStatus::Malformed);
}

TEST(RejectsSessionIdThatOverrunsTheBody) {
    std::vector<uint8_t> data = buildClientHello();

    // Byte layout: 5 record header + 4 handshake header + 2 version + 32 random
    constexpr size_t kSessionIdLengthOffset = 5 + 4 + 2 + 32;
    data[kSessionIdLengthOffset] = 0xFF;

    tls::ClientHello hello;
    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Malformed);
}

TEST(RejectsExtensionsLengthThatOverrunsTheBody) {
    std::vector<uint8_t> data = buildClientHello();

    // ... + 1 session id length + 2 cipher length + 2 ciphers + 1 + 1 compression
    constexpr size_t kExtensionsLengthOffset = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
    data[kExtensionsLengthOffset] = 0x7F;
    data[kExtensionsLengthOffset + 1] = 0xFF;

    tls::ClientHello hello;
    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Malformed);
}

TEST(DetectsEncryptedClientHello) {
    const std::vector<uint8_t> data = buildClientHello({"cloudflare-ech.com", 0, true, true});
    tls::ClientHello hello;

    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Ok);
    CHECK(hello.hasEch);
}

TEST(HelloWithoutSniIsStillValid) {
    const std::vector<uint8_t> data = buildClientHello({"", 0, false, false});
    tls::ClientHello hello;

    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Ok);
    CHECK(!hello.hasSni());
    CHECK_EQ(hello.sniLength, (size_t)0);
}

TEST(DetectsHandshakeSpanningRecords) {
    std::vector<uint8_t> data = buildClientHello();

    // Shrink the record so the handshake message no longer fits inside it,
    // as happens when a client fragments its own hello.
    const size_t half = (data.size() - tls::kRecordHeaderSize) / 2;
    data[3] = (uint8_t)(half >> 8);
    data[4] = (uint8_t)(half & 0xFF);
    data.resize(tls::kRecordHeaderSize + half);

    tls::ClientHello hello;
    CHECK(tls::parseClientHello(data.data(), data.size(), hello) == tls::ParseStatus::Ok);
    CHECK(hello.spansRecords);
    CHECK(!hello.hasSni());
}

TEST(RecognisesServerHello) {
    const uint8_t serverHello[] = {0x16, 0x03, 0x03, 0x00, 0x04,
                                   0x02, 0x00, 0x00, 0x00};
    CHECK(tls::isServerHello(serverHello, sizeof(serverHello)));

    const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
    CHECK(!tls::isServerHello(alert, sizeof(alert)));
    CHECK(tls::classifyServerResponse(alert, sizeof(alert)) ==
          tls::ServerResponseStatus::Alert);

    CHECK(!tls::isServerHello(serverHello, 3));
    CHECK(tls::classifyServerResponse(serverHello, 3) ==
          tls::ServerResponseStatus::NeedMore);
}

TEST(ServerResponseSkipsCompatibilityChangeCipherSpec) {
    const uint8_t response[] = {
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
        0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00,
    };

    CHECK(tls::classifyServerResponse(response, sizeof(response)) ==
          tls::ServerResponseStatus::ServerHello);
}

TEST(HttpBlockPageIsNotAHandshakeSuccess) {
    const std::string response = "HTTP/1.1 302 Found\r\n\r\n";
    CHECK(tls::classifyServerResponse((const uint8_t*)response.data(), response.size()) ==
          tls::ServerResponseStatus::Unexpected);
}
