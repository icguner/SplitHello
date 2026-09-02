#pragma once

#include "DirectRelay.hpp"
#include "TransparentFlow.hpp"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

// Local relay listener. Connections reflected by WinDivert are authenticated
// against FlowRegistry and need no application-level handshake. Explicit
// SOCKS5 and HTTP CONNECT remain available as a recovery/debugging path.
//
// Every accepted connection is served by exactly one thread that the proxy
// owns: handshake, probing and the bidirectional pump all run on it. The
// number of live connections is capped, and stop() aborts every one of them
// and joins their threads, so nothing outlives the proxy or the shared
// context it hands to each relay.
class SocksProxy {
public:
    static constexpr size_t kDefaultMaxConnections = 1024;

    explicit SocksProxy(RelayContext context, uint16_t port = 1080,
                        transparent::FlowRegistry* transparentFlows = nullptr,
                        size_t maxConnections = kDefaultMaxConnections);
    ~SocksProxy();

    SocksProxy(const SocksProxy&) = delete;
    SocksProxy& operator=(const SocksProxy&) = delete;

    // Accept loop. Blocks until stop() is called. Port 0 picks a free port,
    // readable through port() once running() is true.
    bool run();

    // Closes the listener, aborts every live connection and waits for their
    // threads. Idempotent and safe from any thread.
    void stop();

    uint16_t port() const { return port_; }
    bool running() const { return running_.load(); }

    size_t activeConnections() const;
    uint64_t rejectedConnections() const { return rejected_.load(); }

private:
    struct Session {
        SOCKET clientSock = INVALID_SOCKET; // until handed to the relay
        std::thread thread;
        DirectRelay* relay = nullptr;       // set while run() is executing
        bool cancelled = false;
    };

    RelayContext context_;
    uint16_t port_;
    transparent::FlowRegistry* transparentFlows_;
    size_t maxConnections_;

    std::mutex listenMutex_;
    SOCKET listenSock_ = INVALID_SOCKET;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};

    // Session bookkeeping. Every field of Session except `thread` (touched
    // only by the owning thread and the reaper) is guarded by sessionsMutex_.
    mutable std::mutex sessionsMutex_;
    std::condition_variable sessionsChanged_;
    std::unordered_map<uint64_t, std::unique_ptr<Session>> sessions_;
    std::vector<std::thread> finished_;     // exited threads awaiting join
    uint64_t nextSessionId_ = 1;
    std::atomic<uint64_t> rejected_{0};
    ULONGLONG lastRejectLogAt_ = 0;

    void spawnSession(SOCKET clientSock);
    void sessionMain(uint64_t id, Session* session);
    void serve(Session& session);
    void cancel(Session& session);          // sessionsMutex_ held
    void reapFinished();

    // Resolves where the client wants to go. Transparent connections are
    // looked up in the flow registry; explicit ones negotiate SOCKS5 or CONNECT.
    bool negotiate(SOCKET clientSock, std::string& targetHost, uint16_t& targetPort,
                   std::string& originalAddress, uint16_t& connectPort);

    // Protocol handlers
    bool socks5Handshake(SOCKET sock, std::string& targetHost, uint16_t& targetPort);
    bool httpConnectHandshake(SOCKET sock, std::string& targetHost, uint16_t& targetPort);

    static bool recvExact(SOCKET sock, uint8_t* buf, int n);
    static std::string recvLine(SOCKET sock); // read until \r\n
};
