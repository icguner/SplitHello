#include "PacketCore.hpp"

namespace splithello::packet {
namespace {

constexpr U8 kTcp = 6;
constexpr U8 kUdp = 17;

void CopyBytes(void* destination, const void* source,
               Size length) noexcept {
    auto* output = static_cast<U8*>(destination);
    const auto* input = static_cast<const U8*>(source);
    for (Size index = 0; index < length; ++index) {
        output[index] = input[index];
    }
}

[[nodiscard]] bool Fits(Size offset, Size amount,
                        Size length) noexcept {
    return offset <= length && amount <= length - offset;
}

[[nodiscard]] U16 Read16(const U8* value) noexcept {
    return static_cast<U16>(
        (static_cast<U16>(value[0]) << 8) | value[1]);
}

[[nodiscard]] U32 Read32(const U8* value) noexcept {
    return (static_cast<U32>(value[0]) << 24) |
           (static_cast<U32>(value[1]) << 16) |
           (static_cast<U32>(value[2]) << 8) | value[3];
}

void Write16(U8* value, U16 input) noexcept {
    value[0] = static_cast<U8>(input >> 8);
    value[1] = static_cast<U8>(input);
}

void Write24(U8* value, Size input) noexcept {
    value[0] = static_cast<U8>(input >> 16);
    value[1] = static_cast<U8>(input >> 8);
    value[2] = static_cast<U8>(input);
}

void Write32(U8* value, U32 input) noexcept {
    value[0] = static_cast<U8>(input >> 24);
    value[1] = static_cast<U8>(input >> 16);
    value[2] = static_cast<U8>(input >> 8);
    value[3] = static_cast<U8>(input);
}

[[nodiscard]] U32 AddBytes(U32 sum,
                                     const U8* data,
                                     Size length) noexcept {
    while (length >= 2) {
        sum += Read16(data);
        data += 2;
        length -= 2;
    }
    if (length != 0) sum += static_cast<U32>(data[0]) << 8;
    return sum;
}

[[nodiscard]] U16 FinishChecksum(U32 sum) noexcept {
    while ((sum >> 16) != 0) sum = (sum & 0xFFFFU) + (sum >> 16);
    return static_cast<U16>(~sum);
}

[[nodiscard]] U16 TcpChecksum(const U8* packet,
                              const View& view) noexcept {
    const Size transportLength = view.packetLength - view.transportOffset;
    U32 sum = AddBytes(0, packet + 12, 8);
    sum += kTcp;
    sum += static_cast<U16>(transportLength);
    const U8* tcp = packet + view.transportOffset;
    for (Size offset = 0; offset < transportLength; offset += 2) {
        if (offset == 16) continue;
        sum += offset + 1 < transportLength
                   ? Read16(tcp + offset)
                   : static_cast<U32>(tcp[offset]) << 8;
    }
    return FinishChecksum(sum);
}

void UpdateLengths(U8* packet, const View& view,
                   Size packetLength) noexcept {
    if (view.family == 4) {
        Write16(packet + 2, static_cast<U16>(packetLength));
    } else {
        Write16(packet + 4,
                static_cast<U16>(packetLength - 40));
    }
    if (view.protocol == kUdp) {
        Write16(packet + view.transportOffset + 4,
                static_cast<U16>(
                    packetLength - view.transportOffset));
    }
}

[[nodiscard]] ParseResult ParseTransport(const U8* packet,
                                         Size readableLength,
                                         Size packetLength,
                                         View* view) noexcept {
    if (view->protocol == kTcp) {
        if (!Fits(view->transportOffset, 20, readableLength) ||
            !Fits(view->transportOffset, 20, packetLength)) {
            return ParseResult::Truncated;
        }
        const U8* tcp = packet + view->transportOffset;
        const Size headerLength =
            static_cast<Size>(tcp[12] >> 4) * 4;
        if (headerLength < 20 ||
            !Fits(view->transportOffset, headerLength, packetLength)) {
            return ParseResult::Malformed;
        }
        if (!Fits(view->transportOffset, headerLength, readableLength)) {
            return ParseResult::Truncated;
        }
        view->transportHeaderLength = headerLength;
        view->sourcePort = Read16(tcp);
        view->destinationPort = Read16(tcp + 2);
        view->tcpSequence = Read32(tcp + 4);
        view->tcpFlags = tcp[13];
    } else if (view->protocol == kUdp) {
        if (!Fits(view->transportOffset, 8, readableLength) ||
            !Fits(view->transportOffset, 8, packetLength)) {
            return ParseResult::Truncated;
        }
        const U8* udp = packet + view->transportOffset;
        const Size udpLength = Read16(udp + 4);
        if (udpLength < 8 ||
            !Fits(view->transportOffset, udpLength, packetLength) ||
            view->transportOffset + udpLength != packetLength) {
            return ParseResult::Malformed;
        }
        view->transportHeaderLength = 8;
        view->sourcePort = Read16(udp);
        view->destinationPort = Read16(udp + 2);
    } else {
        return ParseResult::Unsupported;
    }

    view->payloadOffset = view->transportOffset + view->transportHeaderLength;
    view->payloadLength = packetLength - view->payloadOffset;
    return ParseResult::Ok;
}

ParseResult ParseInternal(const U8* packet, Size length,
                          bool requireComplete, View* view) noexcept {
    if (packet == nullptr || view == nullptr || length < 1) {
        return ParseResult::Truncated;
    }
    *view = {};

    const U8 version = packet[0] >> 4;
    if (version == 4) {
        if (length < 20) return ParseResult::Truncated;
        const Size headerLength =
            static_cast<Size>(packet[0] & 0x0F) * 4;
        const Size packetLength = Read16(packet + 2);
        if (headerLength < 20 || packetLength < headerLength) {
            return ParseResult::Malformed;
        }
        if (packetLength > length && requireComplete) return ParseResult::Truncated;
        if (!Fits(0, headerLength, length)) return ParseResult::Truncated;

        const U16 fragment = Read16(packet + 6);
        if ((fragment & 0x3FFFU) != 0) return ParseResult::Fragment;

        view->family = 4;
        view->protocol = packet[9];
        view->ttl = packet[8];
        view->packetLength = packetLength;
        view->ipHeaderLength = headerLength;
        view->transportOffset = headerLength;
        CopyBytes(view->sourceAddress, packet + 12, 4);
        CopyBytes(view->destinationAddress, packet + 16, 4);
        return ParseTransport(packet, length, packetLength, view);
    }

    if (version != 6) return ParseResult::Unsupported;
    if (length < 40) return ParseResult::Truncated;
    const Size payloadLength = Read16(packet + 4);
    if (payloadLength == 0) return ParseResult::Unsupported;
    const Size packetLength = 40 + payloadLength;
    if (packetLength > length && requireComplete) return ParseResult::Truncated;

    view->family = 6;
    view->ttl = packet[7];
    view->packetLength = packetLength;
    view->ipHeaderLength = 40;
    CopyBytes(view->sourceAddress, packet + 8, 16);
    CopyBytes(view->destinationAddress, packet + 24, 16);

    U8 next = packet[6];
    Size offset = 40;
    for (unsigned extensionCount = 0; extensionCount < 8; ++extensionCount) {
        if (next == kTcp || next == kUdp) break;
        if (next == 44) {
            if (!Fits(offset, 8, packetLength) ||
                !Fits(offset, 8, length)) return ParseResult::Truncated;
            return ParseResult::Fragment;
        } else if (next == 0 || next == 43 || next == 60) {
            if (!Fits(offset, 2, packetLength) ||
                !Fits(offset, 2, length)) return ParseResult::Truncated;
            const Size extensionLength =
                (static_cast<Size>(packet[offset + 1]) + 1) * 8;
            if (!Fits(offset, extensionLength, packetLength)) {
                return ParseResult::Malformed;
            }
            if (!Fits(offset, extensionLength, length)) {
                return ParseResult::Truncated;
            }
            next = packet[offset];
            offset += extensionLength;
        } else if (next == 51) {
            if (!Fits(offset, 2, packetLength) ||
                !Fits(offset, 2, length)) return ParseResult::Truncated;
            const Size extensionLength =
                (static_cast<Size>(packet[offset + 1]) + 2) * 4;
            if (!Fits(offset, extensionLength, packetLength)) {
                return ParseResult::Malformed;
            }
            if (!Fits(offset, extensionLength, length)) {
                return ParseResult::Truncated;
            }
            next = packet[offset];
            offset += extensionLength;
        } else {
            return ParseResult::Unsupported;
        }
    }

    view->protocol = next;
    view->transportOffset = offset;
    return ParseTransport(packet, length, packetLength, view);
}

}  // namespace

ParseResult Parse(const U8* packet, Size length,
                  View* view) noexcept {
    return ParseInternal(packet, length, true, view);
}

ParseResult ParseHeaders(const U8* packet, Size availableLength,
                         View* view) noexcept {
    return ParseInternal(packet, availableLength, false, view);
}

bool LooksLikeTlsRecord(const U8* payload,
                        Size length) noexcept {
    return payload != nullptr && length >= 5 && payload[0] == 0x16 &&
           payload[1] == 0x03 && payload[2] <= 0x04;
}

void RecalculateChecksums(U8* packet, const View& view) noexcept {
    const Size minimumTransport = view.protocol == kTcp ? 20U : 8U;
    if (packet == nullptr ||
        (view.protocol != kTcp && view.protocol != kUdp) ||
        view.packetLength < view.payloadOffset ||
        !Fits(view.transportOffset, minimumTransport, view.packetLength)) return;

    if (view.family == 4) {
        packet[10] = 0;
        packet[11] = 0;
        Write16(packet + 10,
                FinishChecksum(AddBytes(0, packet, view.ipHeaderLength)));
    }

    const Size transportLength =
        view.packetLength - view.transportOffset;
    const Size checksumOffset =
        view.transportOffset + (view.protocol == kTcp ? 16 : 6);
    packet[checksumOffset] = 0;
    packet[checksumOffset + 1] = 0;

    U32 sum = 0;
    if (view.family == 4) {
        sum = AddBytes(sum, packet + 12, 8);
        sum += view.protocol;
        sum += static_cast<U16>(transportLength);
    } else {
        sum = AddBytes(sum, packet + 8, 32);
        sum += static_cast<U16>(transportLength >> 16);
        sum += static_cast<U16>(transportLength);
        sum += view.protocol;
    }
    sum = AddBytes(sum, packet + view.transportOffset, transportLength);
    U16 checksum = FinishChecksum(sum);
    if (view.protocol == kUdp && checksum == 0) checksum = 0xFFFF;
    Write16(packet + checksumOffset, checksum);
}

Size BuildTcpVariant(const U8* packet, const View& view,
                            const U8* replacement,
                            Size replacementLength,
                            I32 sequenceOffset,
                            U8 ttlOverride,
                            bool corruptChecksum,
                            U8* output,
                            Size outputCapacity) noexcept {
    if (packet == nullptr || output == nullptr || view.protocol != kTcp ||
        (replacementLength != 0 && replacement == nullptr)) {
        return 0;
    }
    const Size headerLength = view.payloadOffset;
    if (replacementLength > 0xFFFFU || headerLength > 0xFFFFU - replacementLength) {
        return 0;
    }
    const Size totalLength = headerLength + replacementLength;
    if (totalLength > outputCapacity) return 0;

    CopyBytes(output, packet, headerLength);
    if (replacementLength != 0) {
        CopyBytes(output + headerLength, replacement, replacementLength);
    }
    View variant = view;
    variant.packetLength = totalLength;
    variant.payloadLength = replacementLength;
    UpdateLengths(output, variant, totalLength);
    Write32(output + view.transportOffset + 4,
            view.tcpSequence + static_cast<U32>(sequenceOffset));
    if (ttlOverride != 0) {
        output[view.family == 4 ? 8 : 7] = ttlOverride;
    }
    RecalculateChecksums(output, variant);
    if (corruptChecksum) output[view.transportOffset + 16] ^= 0xFF;
    return totalLength;
}

Size BuildTcpOverlapVariant(const U8* packet, const View& view,
                            Size splitOffset, Size overlapBytes,
                            const char* coverHostname,
                            Size coverHostnameLength,
                            U8* output, Size outputCapacity) noexcept {
    if (packet == nullptr || output == nullptr || view.protocol != kTcp ||
        splitOffset == 0 || splitOffset >= view.payloadLength) {
        return 0;
    }
    U8 fake[384]{};
    const Size fakeLength = BuildFakeClientHello(
        coverHostname, coverHostnameLength, fake, sizeof(fake));
    if (fakeLength == 0) return 0;

    const Size requestedOverlap = overlapBytes == 0 ? 1U : overlapBytes;
    const Size overlap = requestedOverlap < splitOffset
                             ? requestedOverlap : splitOffset;
    const Size replacementLength = view.payloadLength - splitOffset + overlap;
    const U8* replacement = packet + view.payloadOffset + splitOffset - overlap;
    const Size totalLength = BuildTcpVariant(
        packet, view, replacement, replacementLength,
        static_cast<I32>(splitOffset - overlap), 0, false,
        output, outputCapacity);
    if (totalLength == 0) return 0;

    for (Size index = 0; index < overlap; ++index) {
        output[view.payloadOffset + index] = fake[index % fakeLength];
    }
    View variant = view;
    variant.packetLength = totalLength;
    variant.payloadLength = replacementLength;
    RecalculateChecksums(output, variant);
    return totalLength;
}

Size BuildUdpVariant(const U8* packet, const View& view,
                            const U8* replacement,
                            Size replacementLength,
                            U8* output,
                            Size outputCapacity) noexcept {
    if (packet == nullptr || output == nullptr || view.protocol != kUdp ||
        (replacementLength != 0 && replacement == nullptr)) {
        return 0;
    }
    const Size headerLength = view.payloadOffset;
    if (replacementLength > 0xFFFFU || headerLength > 0xFFFFU - replacementLength) {
        return 0;
    }
    const Size totalLength = headerLength + replacementLength;
    if (totalLength > outputCapacity) return 0;

    CopyBytes(output, packet, headerLength);
    if (replacementLength != 0) {
        CopyBytes(output + headerLength, replacement, replacementLength);
    }
    View variant = view;
    variant.packetLength = totalLength;
    variant.payloadLength = replacementLength;
    UpdateLengths(output, variant, totalLength);
    RecalculateChecksums(output, variant);
    return totalLength;
}

Size BuildReflectedUdp(const U8* packet, const View& view,
                              U16 sourcePort,
                              U16 destinationPort,
                              U8* output,
                              Size outputCapacity) noexcept {
    if (packet == nullptr || output == nullptr || view.protocol != kUdp ||
        view.packetLength > outputCapacity) {
        return 0;
    }
    CopyBytes(output, packet, view.packetLength);
    const Size addressLength = view.family == 4 ? 4 : 16;
    const Size sourceOffset = view.family == 4 ? 12 : 8;
    const Size destinationOffset = view.family == 4 ? 16 : 24;
    U8 temporary[16]{};
    CopyBytes(temporary, output + sourceOffset, addressLength);
    CopyBytes(output + sourceOffset, output + destinationOffset, addressLength);
    CopyBytes(output + destinationOffset, temporary, addressLength);
    Write16(output + view.transportOffset, sourcePort);
    Write16(output + view.transportOffset + 2, destinationPort);
    RecalculateChecksums(output, view);
    return view.packetLength;
}

bool BuildIpv4Fragments(const U8* packet, const View& view,
                        Size desiredFirstEnd, U8* first,
                        Size firstCapacity, Size* firstLength,
                        U8* second, Size secondCapacity,
                        Size* secondLength) noexcept {
    if (firstLength != nullptr) *firstLength = 0;
    if (secondLength != nullptr) *secondLength = 0;
    if (packet == nullptr || first == nullptr || second == nullptr ||
        firstLength == nullptr || secondLength == nullptr || view.family != 4 ||
        view.protocol != kTcp || view.ipHeaderLength != 20 ||
        desiredFirstEnd <= view.ipHeaderLength ||
        desiredFirstEnd >= view.packetLength) {
        return false;
    }

    const U16 existing = Read16(packet + 6);
    if ((existing & 0x3FFFU) != 0) return false;
    const Size ipPayloadLength = view.packetLength - view.ipHeaderLength;
    Size firstPayloadLength = desiredFirstEnd - view.ipHeaderLength;
    firstPayloadLength = (firstPayloadLength + 7U) & ~static_cast<Size>(7U);
    if (firstPayloadLength == 0 || firstPayloadLength >= ipPayloadLength) {
        return false;
    }

    const Size firstSize = view.ipHeaderLength + firstPayloadLength;
    const Size secondSize =
        view.ipHeaderLength + ipPayloadLength - firstPayloadLength;
    if (firstSize > firstCapacity || secondSize > secondCapacity) return false;

    CopyBytes(first, packet, firstSize);
    CopyBytes(second, packet, view.ipHeaderLength);
    CopyBytes(second + view.ipHeaderLength,
                packet + view.ipHeaderLength + firstPayloadLength,
                ipPayloadLength - firstPayloadLength);
    Write16(first + view.transportOffset + 16, TcpChecksum(packet, view));

    Write16(first + 2, static_cast<U16>(firstSize));
    Write16(first + 6, 0x2000);
    first[10] = 0;
    first[11] = 0;
    Write16(first + 10,
            FinishChecksum(AddBytes(0, first, view.ipHeaderLength)));

    Write16(second + 2, static_cast<U16>(secondSize));
    Write16(second + 6,
            static_cast<U16>(firstPayloadLength / 8));
    second[10] = 0;
    second[11] = 0;
    Write16(second + 10,
            FinishChecksum(AddBytes(0, second, view.ipHeaderLength)));

    *firstLength = firstSize;
    *secondLength = secondSize;
    return true;
}

Size BuildFakeClientHello(const char* hostname,
                                 Size hostnameLength,
                                 U8* output,
                                 Size outputCapacity) noexcept {
    if (hostname == nullptr || output == nullptr || hostnameLength == 0 ||
        hostnameLength > 253) {
        return 0;
    }
    constexpr Size kFixedSize = 68;
    const Size total = kFixedSize + hostnameLength;
    if (total > outputCapacity || total > 0xFFFFU) return 0;

    Size cursor = 0;
    output[cursor++] = 0x16;
    Write16(output + cursor, 0x0301);
    cursor += 2;
    const Size recordLengthOffset = cursor;
    cursor += 2;
    output[cursor++] = 0x01;
    const Size handshakeLengthOffset = cursor;
    cursor += 3;
    Write16(output + cursor, 0x0303);
    cursor += 2;
    for (U8 value = 1; value <= 32; ++value) output[cursor++] = value;
    output[cursor++] = 0;
    Write16(output + cursor, 2);
    cursor += 2;
    Write16(output + cursor, 0x1301);
    cursor += 2;
    output[cursor++] = 1;
    output[cursor++] = 0;

    const Size extensionsLengthOffset = cursor;
    cursor += 2;
    const Size extensionsStart = cursor;
    Write16(output + cursor, 0x0000);
    cursor += 2;
    Write16(output + cursor,
            static_cast<U16>(hostnameLength + 5));
    cursor += 2;
    Write16(output + cursor,
            static_cast<U16>(hostnameLength + 3));
    cursor += 2;
    output[cursor++] = 0;
    Write16(output + cursor, static_cast<U16>(hostnameLength));
    cursor += 2;
    CopyBytes(output + cursor, hostname, hostnameLength);
    cursor += hostnameLength;
    Write16(output + cursor, 0x002B);
    cursor += 2;
    Write16(output + cursor, 3);
    cursor += 2;
    output[cursor++] = 2;
    Write16(output + cursor, 0x0304);
    cursor += 2;

    Write16(output + extensionsLengthOffset,
            static_cast<U16>(cursor - extensionsStart));
    Write24(output + handshakeLengthOffset, cursor - 9);
    Write16(output + recordLengthOffset,
            static_cast<U16>(cursor - 5));
    return cursor;
}

}  // namespace splithello::packet
