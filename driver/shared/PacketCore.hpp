#pragma once

#include "Types.hpp"

namespace splithello::packet {

enum class ParseResult : U8 {
    Ok,
    Truncated,
    Malformed,
    Unsupported,
    Fragment,
};

struct View {
    U8 family = 0;
    U8 protocol = 0;
    U8 ttl = 0;
    U8 tcpFlags = 0;
    Size packetLength = 0;
    Size ipHeaderLength = 0;
    Size transportOffset = 0;
    Size transportHeaderLength = 0;
    Size payloadOffset = 0;
    Size payloadLength = 0;
    U16 sourcePort = 0;
    U16 destinationPort = 0;
    U32 tcpSequence = 0;
    U8 sourceAddress[16]{};
    U8 destinationAddress[16]{};
};

[[nodiscard]] ParseResult Parse(const U8* packet,
                                Size length,
                                View* view) noexcept;

// Parses a complete IP and transport header from a bounded prefix while using
// the length declared by the IP header for payload metadata. This avoids a
// full packet copy when a callout only needs tuple/TTL information.
[[nodiscard]] ParseResult ParseHeaders(const U8* packet,
                                       Size availableLength,
                                       View* view) noexcept;

[[nodiscard]] bool LooksLikeTlsRecord(const U8* payload,
                                      Size length) noexcept;

[[nodiscard]] Size BuildTcpVariant(
    const U8* packet,
    const View& view,
    const U8* replacement,
    Size replacementLength,
    I32 sequenceOffset,
    U8 ttlOverride,
    bool corruptChecksum,
    U8* output,
    Size outputCapacity) noexcept;

[[nodiscard]] Size BuildTcpOverlapVariant(
    const U8* packet,
    const View& view,
    Size splitOffset,
    Size overlapBytes,
    const char* coverHostname,
    Size coverHostnameLength,
    U8* output,
    Size outputCapacity) noexcept;

[[nodiscard]] Size BuildUdpVariant(
    const U8* packet,
    const View& view,
    const U8* replacement,
    Size replacementLength,
    U8* output,
    Size outputCapacity) noexcept;

[[nodiscard]] Size BuildReflectedUdp(
    const U8* packet,
    const View& view,
    U16 sourcePort,
    U16 destinationPort,
    U8* output,
    Size outputCapacity) noexcept;

[[nodiscard]] bool BuildIpv4Fragments(
    const U8* packet,
    const View& view,
    Size desiredFirstEnd,
    U8* first,
    Size firstCapacity,
    Size* firstLength,
    U8* second,
    Size secondCapacity,
    Size* secondLength) noexcept;

[[nodiscard]] Size BuildFakeClientHello(
    const char* hostname,
    Size hostnameLength,
    U8* output,
    Size outputCapacity) noexcept;

void RecalculateChecksums(U8* packet,
                          const View& view) noexcept;

}  // namespace splithello::packet
