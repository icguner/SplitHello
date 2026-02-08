#pragma once

#include "WsClient.hpp"
#include <cstdint>
#include <string>
#include <thread>
#include <atomic>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

// Bidirectional relay: TCP socket <-> WebSocket frames.
// Sends a JSON connect command (with optional relay info) to the Worker,
// then pipes raw bytes between the local TCP socket and the WebSocket.
class Relay {
public:
    Relay(SOCKET clientSock, const std::string& workerUrl,
          const std::string& targetHost, uint16_t targetPort);

    ~Relay();

    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;

    void start();

private:
    SOCKET clientSock_;
    std::string workerUrl_;
    std::string targetHost_;
    uint16_t targetPort_;
    WsClient ws_;
    std::atomic<bool> running_{false};

    std::thread sockToWs_;
    std::thread wsToSock_;

    void run();
    void pumpSockToWs();
    void pumpWsToSock();
    void stop();
};
