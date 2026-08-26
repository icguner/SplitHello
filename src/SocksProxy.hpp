#pragma once

#include "DirectRelay.hpp"

#include <string>
#include <cstdint>
#include <atomic>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

// Local relay listener. WFP-redirected connections carry kernel-owned redirect
// context and need no application-level handshake. Explicit
// SOCKS5 and HTTP CONNECT remain available as a recovery/debugging path.
class SocksProxy {
public:
    explicit SocksProxy(RelayContext context, uint16_t port = 1080,
                        bool wfpRedirects = false);
    ~SocksProxy();

    SocksProxy(const SocksProxy&) = delete;
    SocksProxy& operator=(const SocksProxy&) = delete;

    bool run();
    void stop();

    uint16_t port() const { return port_; }
    bool running() const { return running_.load(); }

private:
    RelayContext context_;
    uint16_t port_;
    bool wfpRedirects_ = false;
    SOCKET listenSock_ = INVALID_SOCKET;
    std::atomic<bool> running_{false};

    void handleClient(SOCKET clientSock);

    // Protocol handlers
    bool socks5Handshake(SOCKET sock, std::string& targetHost, uint16_t& targetPort);
    bool httpConnectHandshake(SOCKET sock, std::string& targetHost, uint16_t& targetPort);

    static bool recvExact(SOCKET sock, uint8_t* buf, int n);
    static std::string recvLine(SOCKET sock); // read until \r\n
};
