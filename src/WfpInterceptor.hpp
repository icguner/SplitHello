#pragma once

#include "PacketStrategy.hpp"
#include "QuicStrategy.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <mutex>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <fwpmu.h>

#include "../driver/shared/Protocol.hpp"

class WfpInterceptor {
public:
    WfpInterceptor(uint16_t proxyPort, uint16_t dnsProxyPort,
                   quic_strategy::Mode quicMode,
                   std::vector<std::string> processIncludes,
                   std::vector<std::string> processExcludes);
    ~WfpInterceptor();

    WfpInterceptor(const WfpInterceptor&) = delete;
    WfpInterceptor& operator=(const WfpInterceptor&) = delete;

    [[nodiscard]] bool start();
    void stop();
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] DWORD fatalErrorCode() const noexcept { return fatalErrorCode_.load(); }
    [[nodiscard]] bool armPolicy(const std::string& targetAddress,
                                 uint16_t localPort,
                                 const packet_strategy::Policy& policy) const;
    [[nodiscard]] bool statistics(splithello::wfp::Statistics& output) const;

    struct RedirectedConnection {
        std::string targetAddress;
        uint16_t targetPort = 0;
        std::vector<uint8_t> redirectRecords;
        int addressFamily = AF_UNSPEC;
    };

    [[nodiscard]] static bool queryRedirectedConnection(
        SOCKET socket, RedirectedConnection& connection);

private:
    uint16_t proxyPort_;
    uint16_t dnsProxyPort_;
    quic_strategy::Mode quicMode_;
    std::vector<std::string> processIncludes_;
    std::vector<std::string> processExcludes_;
    HANDLE device_ = INVALID_HANDLE_VALUE;
    HANDLE engine_ = nullptr;
    SC_HANDLE serviceManager_ = nullptr;
    SC_HANDLE service_ = nullptr;
    std::atomic<bool> running_{false};
    std::atomic<DWORD> fatalErrorCode_{ERROR_SUCCESS};
    mutable std::mutex deviceMutex_;
    std::jthread monitor_;

    [[nodiscard]] bool prepareService();
    [[nodiscard]] bool openEngine();
    [[nodiscard]] bool startServiceAndOpenDevice();
    [[nodiscard]] bool installFilters();
    [[nodiscard]] bool configureDriver();
    void closeHandles() noexcept;
};
