#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dns_message {

inline constexpr uint16_t kTypeA = 1;
inline constexpr uint16_t kTypeAaaa = 28;

inline constexpr uint8_t kRcodeNoError = 0;
inline constexpr uint8_t kRcodeFormErr = 1;
inline constexpr uint8_t kRcodeServFail = 2;
inline constexpr uint8_t kRcodeNxDomain = 3;
inline constexpr uint8_t kRcodeNotImp = 4;

// A UDP client that sends no EDNS0 OPT record can only take 512 bytes (RFC 1035).
inline constexpr size_t kClassicUdpPayload = 512;

struct Query {
    uint16_t id = 0;
    uint16_t type = 0;
    bool recursionDesired = false;
    uint8_t opcode = 0;
    uint16_t ednsPayload = 0;   // requestor's UDP payload size; 0 = no OPT record
    bool dnssecOk = false;      // DO bit of that OPT record
    // Set when parseQuery fails although the header was readable: the RCODE a
    // reply should carry (FORMERR / NOTIMP). 0 = unrecoverable, drop silently.
    uint8_t error = 0;
    std::string name;
    std::vector<uint8_t> question;
};

// Accepts exactly one uncompressed IN question. Names are limited to
// [a-z0-9_-] labels (after lowercasing): SNI-derived and application hosts end
// up in URLs and logs, so anything else is refused here instead of downstream.
bool parseQuery(const uint8_t* data, size_t length, Query& out);

// `failed` emits SERVFAIL (or `rcode` when given); a non-zero `rcode` such as
// NXDOMAIN carries no answers. An empty address set without failure emits
// NOERROR/NODATA, which is correct when only the other address family exists.
// An OPT record is appended when the query carried one.
std::vector<uint8_t> buildResponse(const Query& query,
                                   const std::vector<std::string>& addresses,
                                   uint32_t ttlSeconds,
                                   bool failed = false,
                                   uint8_t rcode = 0);

// Header-only error reply (no question section) for a query that failed to
// parse; `query.id`/`opcode`/`recursionDesired` are echoed.
std::vector<uint8_t> buildError(const Query& query, uint8_t rcode);

// ---- helpers for relayed (wire) responses ----

struct ResponseInfo {
    bool response = false;          // QR bit
    bool truncated = false;         // TC bit
    uint8_t rcode = 0;
    size_t answers = 0;             // records in the answer section
    bool hasAnswerTtl = false;
    uint32_t answerTtl = 0;         // minimum TTL over answer records (OPT excluded)
    bool hasAuthorityTtl = false;
    uint32_t authorityTtl = 0;      // minimum TTL over authority records (SOA)
};

// Bounds-checked walk of a whole message. False if it is malformed/truncated.
bool inspectResponse(const uint8_t* data, size_t length, ResponseInfo& out);

// True when `data` repeats the query's single question (ASCII case-insensitive).
bool echoesQuestion(const uint8_t* data, size_t length, const Query& query);

void setId(std::vector<uint8_t>& message, uint16_t id);

// Subtract `ageSeconds` from every non-OPT record TTL (never below 1 for a
// record whose TTL was non-zero). Leaves a malformed message untouched.
void ageTtls(std::vector<uint8_t>& message, uint32_t ageSeconds);

// If `message` is larger than `limit`, cut it down to header + question with
// TC=1 so the client retries over TCP. Returns whether it truncated.
bool truncateForUdp(std::vector<uint8_t>& message, size_t limit);

} // namespace dns_message
