#pragma once

#include <string>
#include <cstdint>
#include <thread>
#include <atomic>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

// Direct TCP relay with TLS ClientHello fragmentation for DPI bypass.
// Resolves DNS via Worker's DoH endpoint (ISP poisons DNS),
// then connects directly to the real IP and fragments the first
// TLS packet so DPI can't read the SNI field.
class DirectRelay {
public:
    DirectRelay(SOCKET clientSock, const std::string& workerUrl,
                const std::string& targetHost, uint16_t targetPort);
    ~DirectRelay();

    DirectRelay(const DirectRelay&) = delete;
    DirectRelay& operator=(const DirectRelay&) = delete;

    // Start in background thread. Self-destructs when done.
    void start();

private:
    SOCKET clientSock_;
    SOCKET targetSock_ = INVALID_SOCKET;
    std::string workerUrl_;
    std::string targetHost_;
    uint16_t targetPort_;
    std::atomic<bool> running_{false};

    std::thread clientToTarget_;
    std::thread targetToClient_;

    void run();

    // Resolve hostname via Worker's /resolve endpoint (DoH).
    std::string resolveDns(const std::string& host);

    // Connect to target IP:port. Returns INVALID_SOCKET on failure.
    SOCKET connectTarget(const std::string& ip, uint16_t port);

    // Fragment TLS ClientHello and send to target.
    // Splits after first 1 byte so DPI can't read SNI.
    bool fragmentAndSend(const uint8_t* data, size_t len);

    // Pump data from one socket to another.
    void pumpClientToTarget();
    void pumpTargetToClient();

    void stop();
};
