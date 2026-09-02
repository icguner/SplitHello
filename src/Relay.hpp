#pragma once

#include "WsClient.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

// Bidirectional relay: local TCP socket <-> Worker WebSocket tunnel.
//
// This is the fallback path, used only when every fragmentation profile
// failed and --tunnel-fallback is on. Unlike the direct path it routes the
// payload through the Worker, so it costs latency and Cloudflare quota.
//
// Runs on the caller's thread (DirectRelay hands over mid-connection) and
// owns the client socket for the rest of its life.
class Relay {
public:
    Relay(SOCKET clientSock, std::string workerUrl, std::string sharedSecret,
          std::string targetHost, uint16_t targetPort,
          std::vector<uint8_t> initialData = {},
          uint16_t workerConnectPort = 0);

    // Closes the client socket if run() did not get to.
    ~Relay();

    Relay(const Relay&) = delete;
    Relay& operator=(const Relay&) = delete;

    // Serves the tunnel on the calling thread and returns once it has ended.
    void run();

    // Aborts the tunnel from another thread; run() unwinds shortly after.
    void stop();

private:
    SOCKET clientSock_;
    std::string workerUrl_;
    std::string sharedSecret_;
    std::string targetHost_;
    uint16_t targetPort_;
    uint16_t workerConnectPort_;

    // Bytes already read from the client before the fallback kicked in - they
    // must be replayed into the tunnel before normal pumping starts.
    std::vector<uint8_t> initialData_;

    WsClient ws_;
    std::atomic<bool> stopping_{false};

    // WinHTTP cannot be multiplexed with a socket in one select(), so the
    // socket->WebSocket direction needs its own thread. It is always joined
    // before run() returns.
    std::thread sockToWs_;

    void pumpSockToWs();
    void pumpWsToSock();
};
