#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

namespace tcp {

// recvTimeout() sentinel: nothing arrived before the deadline, the socket is
// still usable. Distinct from 0 (orderly close) and -1 (error).
inline constexpr int kTimedOut = -2;

// send() until the whole buffer is gone. A single send() may accept fewer
// bytes than asked for, which silently truncates a TLS record if ignored.
bool sendAll(SOCKET sock, const void* data, size_t length);

// recv() bounded by a deadline.
int recvTimeout(SOCKET sock, void* buffer, size_t length, unsigned timeoutMs);

// Happy Eyeballs (RFC 8305): race the candidate addresses, starting a new
// attempt every `attemptDelayMs` instead of waiting for each to time out.
// First socket to complete its handshake wins; the rest are closed.
// `chosenAddress` receives the winner. INVALID_SOCKET if all fail.
SOCKET connectAny(const std::vector<std::string>& addresses,
                  uint16_t port,
                  unsigned attemptDelayMs,
                  unsigned totalTimeoutMs,
                  std::string& chosenAddress,
                  std::span<const uint8_t> redirectRecords = {},
                  int redirectRecordFamily = AF_UNSPEC);

// True if the string is a bare IPv4/IPv6 literal rather than a hostname.
bool isIpLiteral(const std::string& value);

} // namespace tcp
