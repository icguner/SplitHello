#include "Test.hpp"
#include <winsock2.h>
#include <windivert.h>
#include <atomic>
#include <cstring>
#include <string>
#include <thread>

namespace {
std::atomic<unsigned> closes{0};
std::atomic<unsigned> sends{0};
std::atomic<bool> sendFailure{false};
std::string openedFilter;
HANDLE fakeOpen(const char* filter, WINDIVERT_LAYER, INT16, UINT64) {
    openedFilter = filter;
    return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(1));
}
BOOL fakeSetParam(HANDLE, WINDIVERT_PARAM, UINT64) { return TRUE; }
BOOL fakeClose(HANDLE) { ++closes; return TRUE; }
BOOL fakeShutdown(HANDLE, WINDIVERT_SHUTDOWN) { return TRUE; }
BOOL fakeRecv(HANDLE, PVOID packet, UINT, UINT* length, UINT64,
              WINDIVERT_ADDRESS* addresses, UINT* addressLength, LPOVERLAPPED) {
    if (!sendFailure) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    auto* bytes = static_cast<unsigned char*>(packet);
    std::memset(bytes, 0, 40);
    bytes[0] = 0x45; bytes[3] = 40; bytes[8] = 64; bytes[9] = 6; bytes[32] = 0x50;
    *length = 40;
    std::memset(addresses, 0, sizeof(*addresses));
    *addressLength = sizeof(*addresses);
    return TRUE;
}
BOOL fakeSend(HANDLE, const VOID*, UINT, UINT*, UINT64,
              const WINDIVERT_ADDRESS*, UINT, LPOVERLAPPED) {
    ++sends; SetLastError(ERROR_INVALID_DATA); return FALSE;
}
}

// Exercise the production receive/send and shutdown code with a fake driver.
// The real parser/checksum helpers still run; no network filter is opened.
#define WinDivertOpen fakeOpen
#define WinDivertSetParam fakeSetParam
#define WinDivertClose fakeClose
#define WinDivertShutdown fakeShutdown
#define WinDivertRecvEx fakeRecv
#define WinDivertSendEx fakeSend
#include "../src/WinDivertInterceptor.cpp"
#undef WinDivertOpen
#undef WinDivertSetParam
#undef WinDivertClose
#undef WinDivertShutdown
#undef WinDivertRecvEx
#undef WinDivertSendEx

namespace {
void checkFailure(bool failSends) {
    closes = 0; sends = 0; sendFailure = failSends;
    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    packet_strategy::PolicyRegistry policies;
    WinDivertInterceptor interceptor(flows, datagrams, policies, 1080, 1053, 1443);
    CHECK(interceptor.start());
    CHECK(openedFilter.find("udp.DstPort == 53") != std::string::npos);
    const ULONGLONG deadline = GetTickCount64() + 2000;
    while (interceptor.running() && GetTickCount64() < deadline) Sleep(1);
    const bool exited = !interceptor.running();
    std::thread first([&]() { interceptor.stop(); });
    std::thread second([&]() { interceptor.stop(); });
    first.join(); second.join();
    CHECK(exited);
    CHECK_EQ(interceptor.fatalErrorCode(), static_cast<DWORD>(ERROR_INVALID_DATA));
    CHECK_EQ(closes.load(), 1U);
    CHECK_EQ(sends.load(), failSends ? 3U : 0U);
}
}
TEST(divert_read_failure_closes_once_under_concurrent_stop) { checkFailure(false); }
TEST(divert_repeated_send_failure_releases_interception) { checkFailure(true); }

TEST(system_dns_mode_does_not_capture_dns_packets) {
    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    packet_strategy::PolicyRegistry policies;
    sendFailure = false;
    WinDivertInterceptor interceptor(flows, datagrams, policies, 1080, 1053, 1443,
                                     quic_strategy::Mode::Allow, nullptr, false);
    CHECK(interceptor.start());
    interceptor.stop();
    CHECK(openedFilter.find("tcp.DstPort == 443") != std::string::npos);
    CHECK(openedFilter.find("udp.DstPort == 53") == std::string::npos);
}
