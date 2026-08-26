#pragma once

#include "Dns.hpp"

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

// Receives UDP/53 datagrams reflected by the WFP callout, resolves their single DNS
// question through the Cloudflare Worker, and sends a compact DNS answer back
// through the same reflected tuple. Several workers are required because a
// WinHTTP request can itself trigger a DNS query for the Worker hostname.
class TransparentDnsProxy {
public:
    TransparentDnsProxy(dns::Resolver& resolver, uint16_t port,
                        bool trustWfpLoopback = false);
    ~TransparentDnsProxy();

    TransparentDnsProxy(const TransparentDnsProxy&) = delete;
    TransparentDnsProxy& operator=(const TransparentDnsProxy&) = delete;

    bool start();
    void stop();
    bool running() const { return running_.load(); }
    uint16_t port() const { return port_; }

private:
    struct Job {
        std::vector<uint8_t> data;
        sockaddr_storage peer{};
        int peerLength = 0;
    };

    dns::Resolver& resolver_;
    uint16_t port_;
    bool trustWfpLoopback_ = false;
    std::atomic<SOCKET> socket_{INVALID_SOCKET};
    std::atomic<bool> running_{false};
    std::thread receiver_;
    std::vector<std::thread> workers_;

    std::mutex queueMutex_;
    std::condition_variable queueReady_;
    std::deque<Job> jobs_;

    void receiveLoop();
    void workerLoop();
    void process(const Job& job);
};
