#include "TlsHello.hpp"

namespace tls {
namespace {

// Cursor that refuses to read past the end of the region it was given.
// Every accessor returns false instead of touching out-of-range memory.
class Reader {
public:
    Reader(const uint8_t* data, size_t pos, size_t end)
        : data_(data), pos_(pos), end_(end) {}

    size_t pos() const { return pos_; }
    size_t remaining() const { return end_ - pos_; }

    bool skip(size_t n) {
        if (n > remaining()) return false;
        pos_ += n;
        return true;
    }

    bool u8(uint8_t& value) {
        if (remaining() < 1) return false;
        value = data_[pos_++];
        return true;
    }

    bool u16(uint16_t& value) {
        if (remaining() < 2) return false;
        value = (uint16_t)((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return true;
    }

private:
    const uint8_t* data_;
    size_t pos_;
    size_t end_;
};

// Walk the server_name extension body and record the first host_name entry.
// Layout: list_length(2) { name_type(1) name_length(2) name } *
bool readServerName(const uint8_t* data, size_t extStart, size_t extEnd, ClientHello& out) {
    Reader r(data, extStart, extEnd);

    uint16_t listLength = 0;
    if (!r.u16(listLength)) return false;
    if (listLength > r.remaining()) return false;

    const size_t listEnd = r.pos() + listLength;
    while (r.pos() < listEnd) {
        uint8_t nameType = 0;
        uint16_t nameLength = 0;
        if (!r.u8(nameType) || !r.u16(nameLength)) return false;
        if (nameLength > listEnd - r.pos()) return false;

        if (nameType == 0x00) { // host_name
            out.sniOffset = r.pos();
            out.sniLength = nameLength;
            out.serverName.assign((const char*)data + r.pos(), nameLength);
            return true;
        }
        if (!r.skip(nameLength)) return false;
    }
    return false; // well-formed list, but no host_name in it
}

ParseStatus parseExtensions(const uint8_t* data, size_t pos, size_t bodyEnd, ClientHello& out) {
    Reader r(data, pos, bodyEnd);

    uint16_t extensionsLength = 0;
    if (!r.u16(extensionsLength)) return ParseStatus::Malformed;
    if (extensionsLength > r.remaining()) return ParseStatus::Malformed;

    const size_t extensionsEnd = r.pos() + extensionsLength;
    while (r.pos() < extensionsEnd) {
        uint16_t extType = 0;
        uint16_t extLength = 0;
        if (!r.u16(extType) || !r.u16(extLength)) return ParseStatus::Malformed;
        if (extLength > extensionsEnd - r.pos()) return ParseStatus::Malformed;

        const size_t extStart = r.pos();
        if (extType == kExtEncryptedClientHello) {
            out.hasEch = true;
        } else if (extType == kExtServerName && !out.hasSni()) {
            readServerName(data, extStart, extStart + extLength, out);
        }

        if (!r.skip(extLength)) return ParseStatus::Malformed;
    }
    return ParseStatus::Ok;
}

} // namespace

ParseStatus parseClientHello(const uint8_t* data, size_t len, ClientHello& out) {
    out = ClientHello{};

    if (len == 0) return ParseStatus::NeedMore;
    if (data[0] != kRecordHandshake) return ParseStatus::NotTls;
    if (len < 2) return ParseStatus::NeedMore;
    if (data[1] != 0x03) return ParseStatus::NotTls; // legacy_record_version is always 3.x
    if (len < kRecordHeaderSize) return ParseStatus::NeedMore;

    const size_t payloadLength = (size_t)((data[3] << 8) | data[4]);
    if (payloadLength == 0 || payloadLength > kMaxRecordPayload) return ParseStatus::Malformed;

    out.recordPayloadLength = payloadLength;
    out.recordTotalLength = kRecordHeaderSize + payloadLength;

    // Everything below indexes into the record, so the whole record must be here.
    if (len < out.recordTotalLength) return ParseStatus::NeedMore;

    if (payloadLength < 4) return ParseStatus::Malformed;
    if (data[kRecordHeaderSize] != kHandshakeClientHello) return ParseStatus::NotTls;

    const size_t handshakeLength = ((size_t)data[kRecordHeaderSize + 1] << 16) |
                                   ((size_t)data[kRecordHeaderSize + 2] << 8) |
                                   (size_t)data[kRecordHeaderSize + 3];

    const size_t bodyStart = kRecordHeaderSize + 4;
    const size_t bodyEnd = bodyStart + handshakeLength;

    if (bodyEnd > out.recordTotalLength) {
        // The handshake message is already spread over several records - a client
        // that fragments its own hello needs no help from us, and re-framing a
        // partial message would corrupt it.
        out.spansRecords = true;
        return ParseStatus::Ok;
    }

    Reader r(data, bodyStart, bodyEnd);
    uint8_t sessionIdLength = 0;
    uint16_t cipherSuitesLength = 0;
    uint8_t compressionLength = 0;

    if (!r.skip(2)) return ParseStatus::Malformed;                  // client_version
    if (!r.skip(32)) return ParseStatus::Malformed;                 // random
    if (!r.u8(sessionIdLength) || !r.skip(sessionIdLength)) return ParseStatus::Malformed;
    if (!r.u16(cipherSuitesLength) || !r.skip(cipherSuitesLength)) return ParseStatus::Malformed;
    if (!r.u8(compressionLength) || !r.skip(compressionLength)) return ParseStatus::Malformed;

    // A hello with no extension block at all is legal (and has no SNI to hide).
    if (r.remaining() == 0) return ParseStatus::Ok;

    return parseExtensions(data, r.pos(), bodyEnd, out);
}

ServerResponseStatus classifyServerResponse(const uint8_t* data, size_t len) {
    size_t offset = 0;

    while (offset < len) {
        if (len - offset < kRecordHeaderSize) return ServerResponseStatus::NeedMore;

        const uint8_t contentType = data[offset];
        if (data[offset + 1] != 0x03) return ServerResponseStatus::Unexpected;

        const size_t payloadLength = ((size_t)data[offset + 3] << 8) |
                                     (size_t)data[offset + 4];
        if (payloadLength == 0 || payloadLength > kMaxRecordPayload) {
            return ServerResponseStatus::Unexpected;
        }

        const size_t totalLength = kRecordHeaderSize + payloadLength;
        if (len - offset < totalLength) return ServerResponseStatus::NeedMore;

        const uint8_t* payload = data + offset + kRecordHeaderSize;
        if (contentType == kRecordAlert) return ServerResponseStatus::Alert;
        if (contentType == kRecordHandshake) {
            if (payloadLength >= 4 && payload[0] == kHandshakeServerHello) {
                return ServerResponseStatus::ServerHello;
            }
            return ServerResponseStatus::Unexpected;
        }
        if (contentType != kRecordChangeCipherSpec) {
            return ServerResponseStatus::Unexpected;
        }

        offset += totalLength;
    }

    return ServerResponseStatus::NeedMore;
}

bool isServerHello(const uint8_t* data, size_t len) {
    return classifyServerResponse(data, len) == ServerResponseStatus::ServerHello;
}

bool looksLikeTlsRecord(const uint8_t* data, size_t len) {
    if (len == 0) return false;
    if (data[0] != kRecordHandshake) return false;
    return len < 2 || data[1] == 0x03;
}

} // namespace tls
