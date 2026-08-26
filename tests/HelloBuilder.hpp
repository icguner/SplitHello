#pragma once

// Synthetic TLS ClientHello construction, shared by the parser and strategy
// tests. Mirrors the RFC 8446 layout closely enough that offsets computed by
// the tests line up with what the parser reports.

#include "TlsHello.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace testing {

inline void appendU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)(value & 0xFF));
}

struct HelloOptions {
    std::string serverName = "discord.com";
    size_t paddingBytes = 0;   // stands in for the bulk of a post-quantum key share
    bool withEch = false;
    bool withSni = true;
};

inline std::vector<uint8_t> buildClientHello(const HelloOptions& options = {}) {
    std::vector<uint8_t> extensions;

    if (options.withSni) {
        std::vector<uint8_t> serverNameExtension;
        appendU16(serverNameExtension, (uint16_t)(options.serverName.size() + 3));
        serverNameExtension.push_back(0x00); // host_name
        appendU16(serverNameExtension, (uint16_t)options.serverName.size());
        serverNameExtension.insert(serverNameExtension.end(),
                                   options.serverName.begin(), options.serverName.end());

        appendU16(extensions, tls::kExtServerName);
        appendU16(extensions, (uint16_t)serverNameExtension.size());
        extensions.insert(extensions.end(), serverNameExtension.begin(), serverNameExtension.end());
    }

    if (options.withEch) {
        appendU16(extensions, tls::kExtEncryptedClientHello);
        appendU16(extensions, 4);
        extensions.insert(extensions.end(), {0x00, 0x01, 0x02, 0x03});
    }

    if (options.paddingBytes > 0) {
        appendU16(extensions, 0x0015); // padding
        appendU16(extensions, (uint16_t)options.paddingBytes);
        extensions.insert(extensions.end(), options.paddingBytes, (uint8_t)0x00);
    }

    std::vector<uint8_t> body;
    appendU16(body, 0x0303);                     // legacy_version
    body.insert(body.end(), 32, (uint8_t)0xAB);  // random
    body.push_back(0x00);                        // legacy_session_id length
    appendU16(body, 2);                          // cipher_suites length
    appendU16(body, 0x1301);                     // TLS_AES_128_GCM_SHA256
    body.push_back(0x01);                        // compression methods length
    body.push_back(0x00);                        // null compression
    appendU16(body, (uint16_t)extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> record;
    record.push_back(tls::kRecordHandshake);
    record.push_back(0x03);
    record.push_back(0x01);
    appendU16(record, (uint16_t)(body.size() + 4));
    record.push_back(tls::kHandshakeClientHello);
    record.push_back((uint8_t)(body.size() >> 16));
    record.push_back((uint8_t)(body.size() >> 8));
    record.push_back((uint8_t)(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

inline std::string sniText(const std::vector<uint8_t>& data, const tls::ClientHello& hello) {
    return std::string((const char*)data.data() + hello.sniOffset, hello.sniLength);
}

} // namespace testing
