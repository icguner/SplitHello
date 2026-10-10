#pragma once

#include "Dns.hpp"
#include "TransparentFlow.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

// Receives UDP/53 datagrams reflected by WinDivert, resolves their single DNS
// question through the Cloudflare Worker, and sends a compact DNS answer back
// through the same reflected tuple. Several workers are required because a
// WinHTTP request can itself trigger a DNS query for the Worker hostname.
class TransparentDnsProxy {
public:
    TransparentDnsProxy(dns::Resolver& resolver,
                        transparent::DatagramRegistry& datagrams,
                        uint16_t port);
    ~TransparentDnsProxy();

    TransparentDnsProxy(const TransparentDnsProxy&) = delete;
    TransparentDnsProxy& operator=(const TransparentDnsProxy&) = delete;

    bool start();
    void stop();
    bool running() const { return running_.load(); }
    uint16_t port() const { return port_; }

    // The whole resolution policy, without a socket: the DNS reply for one
    // client datagram (A/AAAA via /resolve with real NXDOMAIN/NODATA, wire relay
    // for everything else, FORMERR/NOTIMP for unusable queries, TC=1 when the
    // answer exceeds the client's UDP size). Empty means "send nothing".
    // `deadlineMs` is on the GetTickCount64 scale, 0 = none.
    std::vector<uint8_t> buildReply(const uint8_t* data, size_t length,
                                    unsigned long long deadlineMs = 0);

private:
    struct Job {
        std::vector<uint8_t> data;
        sockaddr_storage peer{};
        int peerLength = 0;
        unsigned long long enqueuedMs = 0;
    };

    dns::Resolver& resolver_;
    transparent::DatagramRegistry& datagrams_;
    uint16_t port_;
    std::atomic<SOCKET> socket_{INVALID_SOCKET};
    std::atomic<bool> running_{false};
    std::thread receiver_;
    std::vector<std::thread> workers_;

    std::mutex lifecycleMutex_;
    std::mutex queueMutex_;
    std::condition_variable queueReady_;
    std::deque<Job> jobs_;

    void stopLocked();
    void fail();
    void receiveLoop();
    void workerLoop();
    void process(const Job& job);
};
