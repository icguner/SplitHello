#pragma once

#include "TransparentFlow.hpp"
#include "PacketStrategy.hpp"
#include "QuicStrategy.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

// Transparent network ingress for HTTPS and DNS. TCP/443 is reflected into the
// TLS relay, UDP/53 into the local Worker-backed resolver, and the relay's
// private connect port is mapped back to TCP/443. UDP/443 is optionally dropped
// in-kernel so HTTP/3 clients fall back to the diagnosable TCP path.
class WinDivertInterceptor {
public:
    WinDivertInterceptor(transparent::FlowRegistry& flows,
                         transparent::DatagramRegistry& datagrams,
                         packet_strategy::PolicyRegistry& packetPolicies,
                         uint16_t proxyPort, uint16_t dnsProxyPort,
                         uint16_t connectPort,
                         quic_strategy::Mode quicMode = quic_strategy::Mode::Allow);
    ~WinDivertInterceptor();

    WinDivertInterceptor(const WinDivertInterceptor&) = delete;
    WinDivertInterceptor& operator=(const WinDivertInterceptor&) = delete;

    bool start();
    void stop();
    bool running() const { return running_.load(); }
    DWORD fatalErrorCode() const { return fatalErrorCode_.load(); }

private:
    transparent::FlowRegistry& flows_;
    transparent::DatagramRegistry& datagrams_;
    packet_strategy::PolicyRegistry& packetPolicies_;
    uint16_t proxyPort_;
    uint16_t dnsProxyPort_;
    uint16_t connectPort_;
    quic_strategy::Mode quicMode_;
    quic_strategy::AdaptiveRegistry quicRegistry_;

    HANDLE packetHandle_ = INVALID_HANDLE_VALUE;
    HANDLE quicDropHandle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> running_{false};
    std::atomic<DWORD> fatalErrorCode_{ERROR_SUCCESS};
    std::thread worker_;
    std::mutex stopMutex_;

    void run();
    void closeHandles();
};
