#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Bounds-checked TLS ClientHello inspection.
//
// Everything here is pure logic over a byte span - no sockets, no Windows API -
// so it can be unit tested. The parser never reads past `len`; a truncated
// ClientHello reports NeedMore instead of pretending the rest is in memory.
namespace tls {

inline constexpr uint8_t kRecordHandshake = 0x16;
inline constexpr uint8_t kRecordChangeCipherSpec = 0x14;
inline constexpr uint8_t kRecordAlert = 0x15;
inline constexpr uint8_t kHandshakeClientHello = 0x01;
inline constexpr uint8_t kHandshakeServerHello = 0x02;

inline constexpr size_t kRecordHeaderSize = 5;
inline constexpr size_t kMaxRecordPayload = 16384;   // 2^14, TLSPlaintext limit
inline constexpr uint16_t kExtServerName = 0x0000;
inline constexpr uint16_t kExtEncryptedClientHello = 0xfe0d;  // RFC 9849

enum class ParseStatus {
    Ok,         // a complete ClientHello record is present in [data, data+len)
    NeedMore,   // consistent so far, but more bytes are required
    NotTls,     // not a TLS handshake record - forward untouched
    Malformed,  // TLS-shaped but self-inconsistent - forward untouched
};

// Classification of the server's first TLS flight during an adaptive probe.
// NeedMore is intentionally distinct from Unexpected: a TCP read can end in
// the middle of a perfectly valid record and must not poison learned state.
enum class ServerResponseStatus {
    NeedMore,
    ServerHello,
    Alert,
    Unexpected,
};

struct ClientHello {
    // Byte counts of the *first* TLS record only.
    size_t recordPayloadLength = 0;                 // value of the record header length field
    size_t recordTotalLength = 0;                   // kRecordHeaderSize + recordPayloadLength

    // Absolute offsets into the buffer that was parsed. Zero when absent.
    size_t sniOffset = 0;                           // first byte of the hostname
    size_t sniLength = 0;

    std::string serverName;                         // decoded hostname, empty if absent
    bool hasEch = false;                            // outer SNI is a cover name; splitting is pointless
    bool spansRecords = false;                      // handshake message continues past the first record

    bool hasSni() const { return sniLength > 0; }
};

// Inspect a buffer that begins with a TLS record.
// On ParseStatus::Ok, `out` describes the first record. On NeedMore, `out` is
// only partially filled and the caller must keep buffering.
ParseStatus parseClientHello(const uint8_t* data, size_t len, ClientHello& out);

// Inspect one or more complete TLS records from the beginning of `data`.
// Compatibility ChangeCipherSpec records are skipped. Only a complete
// ServerHello is success; Alerts and non-TLS block pages are reported
// separately so the adaptive engine does not learn a broken profile.
ServerResponseStatus classifyServerResponse(const uint8_t* data, size_t len);

// Compatibility helper used by callers that only need a boolean.
bool isServerHello(const uint8_t* data, size_t len);

// True if the buffer starts with something that could become a TLS record.
// A single byte is enough to rule most traffic out.
bool looksLikeTlsRecord(const uint8_t* data, size_t len);

} // namespace tls
