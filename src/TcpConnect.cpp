#include "TcpConnect.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>

namespace tcp {
namespace {

// select() uses fd_set, which holds FD_SETSIZE (64) sockets. We never need
// anywhere near that many candidates for one hostname.
constexpr size_t kMaxParallelAttempts = 8;

struct Attempt {
    SOCKET sock = INVALID_SOCKET;
    std::string address;
};

// Kick off a non-blocking connect. Returns INVALID_SOCKET if the address is
// unusable or the socket could not be created.
SOCKET beginConnect(const std::string& address, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    addrinfo* resolved = nullptr;
    const std::string service = std::to_string(port);
    if (getaddrinfo(address.c_str(), service.c_str(), &hints, &resolved) != 0 || !resolved) {
        return INVALID_SOCKET;
    }

    SOCKET sock = socket(resolved->ai_family, resolved->ai_socktype, resolved->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(resolved);
        return INVALID_SOCKET;
    }

    u_long nonBlocking = 1;
    ioctlsocket(sock, FIONBIO, &nonBlocking);

    const int result = ::connect(sock, resolved->ai_addr, (int)resolved->ai_addrlen);
    freeaddrinfo(resolved);

    if (result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

void makeBlocking(SOCKET sock) {
    u_long blocking = 0;
    ioctlsocket(sock, FIONBIO, &blocking);
}

} // namespace

bool sendAll(SOCKET sock, const void* data, size_t length) {
    const char* cursor = (const char*)data;
    size_t left = length;

    while (left > 0) {
        const int chunk = (int)std::min<size_t>(left, 1 << 20);
        const int sent = ::send(sock, cursor, chunk, 0);
        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) continue; // blocking socket: rare but legal
            return false;
        }
        if (sent == 0) return false;
        cursor += sent;
        left -= (size_t)sent;
    }
    return true;
}

int recvTimeout(SOCKET sock, void* buffer, size_t length, unsigned timeoutMs) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(sock, &readable);

    timeval tv{};
    tv.tv_sec = (long)(timeoutMs / 1000);
    tv.tv_usec = (long)((timeoutMs % 1000) * 1000);

    const int ready = ::select(0, &readable, nullptr, nullptr, &tv);
    if (ready == 0) return kTimedOut;
    if (ready == SOCKET_ERROR) return -1;

    return ::recv(sock, (char*)buffer, (int)length, 0);
}

SOCKET connectAny(const std::vector<std::string>& addresses,
                  uint16_t port,
                  unsigned attemptDelayMs,
                  unsigned totalTimeoutMs,
                  std::string& chosenAddress) {
    chosenAddress.clear();
    if (addresses.empty()) return INVALID_SOCKET;

    const ULONGLONG deadline = GetTickCount64() + totalTimeoutMs;
    std::vector<Attempt> inFlight;
    size_t nextCandidate = 0;
    ULONGLONG nextStartAt = 0; // first attempt fires immediately

    SOCKET winner = INVALID_SOCKET;

    while (winner == INVALID_SOCKET) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) break;

        const bool candidatesLeft = nextCandidate < addresses.size();
        if (candidatesLeft && inFlight.size() < kMaxParallelAttempts && now >= nextStartAt) {
            const std::string& address = addresses[nextCandidate++];
            SOCKET sock = beginConnect(address, port);
            if (sock != INVALID_SOCKET) {
                inFlight.push_back({sock, address});
            } else {
                spdlog::debug("Baglanti denemesi baslatilamadi: {}", address);
            }
            nextStartAt = now + attemptDelayMs;
            continue;
        }

        if (inFlight.empty()) {
            if (!candidatesLeft) break;
            Sleep((DWORD)std::min<ULONGLONG>(nextStartAt - now, deadline - now));
            continue;
        }

        fd_set writable, failed;
        FD_ZERO(&writable);
        FD_ZERO(&failed);
        for (const Attempt& attempt : inFlight) {
            FD_SET(attempt.sock, &writable);
            FD_SET(attempt.sock, &failed);
        }

        ULONGLONG waitUntil = deadline;
        if (candidatesLeft) waitUntil = std::min(waitUntil, nextStartAt);
        const ULONGLONG waitMs = waitUntil > now ? waitUntil - now : 0;

        timeval tv{};
        tv.tv_sec = (long)(waitMs / 1000);
        tv.tv_usec = (long)((waitMs % 1000) * 1000);

        const int ready = ::select(0, nullptr, &writable, &failed, &tv);
        if (ready <= 0) continue; // timeout or error: fall through to start the next candidate

        for (size_t i = 0; i < inFlight.size();) {
            const SOCKET sock = inFlight[i].sock;
            const bool signalledWritable = FD_ISSET(sock, &writable) != 0;
            const bool signalledFailed = FD_ISSET(sock, &failed) != 0;

            if (!signalledWritable && !signalledFailed) { i++; continue; }

            int soError = 0;
            int soErrorSize = sizeof(soError);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&soError, &soErrorSize);

            if (signalledWritable && soError == 0) {
                winner = sock;
                chosenAddress = inFlight[i].address;
                inFlight.erase(inFlight.begin() + (ptrdiff_t)i);
                break;
            }

            spdlog::debug("Baglanti basarisiz: {} (WSA {})", inFlight[i].address, soError);
            closesocket(sock);
            inFlight.erase(inFlight.begin() + (ptrdiff_t)i);
        }
    }

    for (const Attempt& attempt : inFlight) closesocket(attempt.sock);

    if (winner != INVALID_SOCKET) makeBlocking(winner);
    return winner;
}

bool isIpLiteral(const std::string& value) {
    if (value.empty()) return false;

    in_addr v4{};
    if (inet_pton(AF_INET, value.c_str(), &v4) == 1) return true;

    in6_addr v6{};
    return inet_pton(AF_INET6, value.c_str(), &v6) == 1;
}

} // namespace tcp
