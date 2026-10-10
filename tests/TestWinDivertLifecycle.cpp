#include "Test.hpp"
#include <winsock2.h>
#include <windivert.h>
#include <array>
#include <atomic>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
std::atomic<unsigned> closes{0};
std::atomic<unsigned> sends{0};
std::atomic<bool> sendFailure{false};
std::string openedFilter;

// Scripted mode: WinDivertRecvEx hands out prepared packet batches, and
// WinDivertSendEx records what the interceptor re-injected.
struct ScriptedPacket {
    std::vector<uint8_t> bytes;
    bool outbound = true;
};
struct SentPacket {
    bool outbound = false;
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    std::array<uint8_t, 4> source{};
    std::array<uint8_t, 4> destination{};
    bool syn = false;
};
std::atomic<bool> scripted{false};
std::atomic<bool> shuttingDown{false};
std::atomic<unsigned> failDestinationPort{0};
std::mutex scriptMutex;
std::deque<std::vector<ScriptedPacket>> script;
std::vector<SentPacket> sentPackets;

HANDLE fakeOpen(const char* filter, WINDIVERT_LAYER, INT16, UINT64) {
    openedFilter = filter;
    return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(1));
}
BOOL fakeSetParam(HANDLE, WINDIVERT_PARAM, UINT64) { return TRUE; }
BOOL fakeClose(HANDLE) { ++closes; return TRUE; }
BOOL fakeShutdown(HANDLE, WINDIVERT_SHUTDOWN) { shuttingDown = true; return TRUE; }
BOOL fakeRecv(HANDLE, PVOID packet, UINT, UINT* length, UINT64,
              WINDIVERT_ADDRESS* addresses, UINT* addressLength, LPOVERLAPPED) {
    auto* bytes = static_cast<unsigned char*>(packet);
    if (scripted) {
        std::vector<ScriptedPacket> batch;
        for (;;) {
            {
                std::lock_guard lock(scriptMutex);
                if (!script.empty()) {
                    batch = std::move(script.front());
                    script.pop_front();
                    break;
                }
            }
            if (shuttingDown) { SetLastError(ERROR_NO_DATA); return FALSE; }
            Sleep(1);
        }
        size_t offset = 0;
        for (size_t i = 0; i < batch.size(); ++i) {
            std::memcpy(bytes + offset, batch[i].bytes.data(), batch[i].bytes.size());
            offset += batch[i].bytes.size();
            std::memset(&addresses[i], 0, sizeof(addresses[i]));
            addresses[i].Outbound = batch[i].outbound ? 1 : 0;
        }
        *length = (UINT)offset;
        *addressLength = (UINT)(batch.size() * sizeof(WINDIVERT_ADDRESS));
        return TRUE;
    }

    if (!sendFailure) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    std::memset(bytes, 0, 40);
    bytes[0] = 0x45; bytes[3] = 40; bytes[8] = 64; bytes[9] = 6; bytes[32] = 0x50;
    *length = 40;
    std::memset(addresses, 0, sizeof(*addresses));
    *addressLength = sizeof(*addresses);
    return TRUE;
}
BOOL fakeSend(HANDLE, const VOID* packets, UINT length, UINT* sentLength, UINT64,
              const WINDIVERT_ADDRESS* addresses, UINT, LPOVERLAPPED) {
    ++sends;
    if (!scripted) { SetLastError(ERROR_INVALID_DATA); return FALSE; }

    // Inject packet by packet like the driver: a packet it refuses fails the
    // call, but everything before it has already gone out.
    const VOID* cursor = packets;
    UINT remaining = length;
    UINT done = 0;
    for (size_t index = 0; remaining > 0; ++index) {
        PWINDIVERT_IPHDR ip = nullptr;
        PWINDIVERT_TCPHDR tcp = nullptr;
        PVOID next = nullptr;
        UINT nextLength = 0;
        if (!WinDivertHelperParsePacket(cursor, remaining, &ip, nullptr, nullptr,
                                        nullptr, nullptr, &tcp, nullptr, nullptr,
                                        nullptr, &next, &nextLength) ||
            !ip || !tcp) {
            break;
        }
        const UINT size = remaining - nextLength;
        if (failDestinationPort != 0 && ntohs(tcp->DstPort) == failDestinationPort) {
            if (sentLength) *sentLength = done;
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        SentPacket record;
        record.outbound = addresses[index].Outbound != 0;
        record.sourcePort = ntohs(tcp->SrcPort);
        record.destinationPort = ntohs(tcp->DstPort);
        std::memcpy(record.source.data(), &ip->SrcAddr, 4);
        std::memcpy(record.destination.data(), &ip->DstAddr, 4);
        record.syn = tcp->Syn && !tcp->Ack;
        {
            std::lock_guard lock(scriptMutex);
            sentPackets.push_back(record);
        }
        done += size;
        remaining = nextLength;
        cursor = next;
    }
    if (sentLength) *sentLength = done;
    return TRUE;
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
    scripted = false;
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
    // A send failure is only fatal as a sustained run, never after a couple.
    if (failSends) CHECK(sends.load() >= 16U);
    else CHECK_EQ(sends.load(), 0U);
}

constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kAck = 0x10;

using Ip = std::array<uint8_t, 4>;
const Ip kLocal = {10, 0, 0, 2};
const Ip kServer = {203, 0, 113, 9};
const Ip kOtherServer = {203, 0, 113, 10};
constexpr uint16_t kProxyPort = 1080;
constexpr uint16_t kConnectPort = 1443;

ScriptedPacket tcpPacket(const Ip& source, uint16_t sourcePort, const Ip& destination,
                         uint16_t destinationPort, uint8_t flags, bool outbound) {
    ScriptedPacket out;
    out.outbound = outbound;
    out.bytes.assign(40, 0);
    auto& b = out.bytes;
    b[0] = 0x45; b[3] = 40; b[8] = 64; b[9] = 6;
    std::memcpy(&b[12], source.data(), 4);
    std::memcpy(&b[16], destination.data(), 4);
    b[20] = (uint8_t)(sourcePort >> 8); b[21] = (uint8_t)sourcePort;
    b[22] = (uint8_t)(destinationPort >> 8); b[23] = (uint8_t)destinationPort;
    b[32] = 0x50; b[33] = flags;
    return out;
}

void feed(std::vector<ScriptedPacket> batch) {
    std::lock_guard lock(scriptMutex);
    script.push_back(std::move(batch));
}

std::vector<SentPacket> waitForSent(size_t count) {
    const ULONGLONG deadline = GetTickCount64() + 3000;
    for (;;) {
        {
            std::lock_guard lock(scriptMutex);
            if (sentPackets.size() >= count || GetTickCount64() >= deadline) {
                return sentPackets;
            }
        }
        Sleep(2);
    }
}

void resetScript() {
    closes = 0; sends = 0; sendFailure = false;
    scripted = true; shuttingDown = false; failDestinationPort = 0;
    std::lock_guard lock(scriptMutex);
    script.clear();
    sentPackets.clear();
}

// Expected shape of one re-injected packet.
void expectPacket(const SentPacket& packet, bool outbound, const Ip& source,
                  uint16_t sourcePort, const Ip& destination, uint16_t destinationPort) {
    CHECK_EQ(packet.outbound, outbound);
    CHECK(packet.source == source);
    CHECK(packet.destination == destination);
    CHECK_EQ(packet.sourcePort, sourcePort);
    CHECK_EQ(packet.destinationPort, destinationPort);
}
}
TEST(divert_read_failure_closes_once_under_concurrent_stop) { checkFailure(false); }
TEST(divert_repeated_send_failure_releases_interception) { checkFailure(true); }

TEST(system_dns_mode_does_not_capture_dns_packets) {
    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    packet_strategy::PolicyRegistry policies;
    sendFailure = false;
    scripted = false;
    WinDivertInterceptor interceptor(flows, datagrams, policies, 1080, 1053, 1443,
                                     quic_strategy::Mode::Allow, nullptr, false);
    CHECK(interceptor.start());
    interceptor.stop();
    CHECK(openedFilter.find("tcp.DstPort == 443") != std::string::npos);
    CHECK(openedFilter.find("udp.DstPort == 53") == std::string::npos);
}

TEST(divert_rewrites_only_flows_whose_syn_it_saw) {
    resetScript();
    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    packet_strategy::PolicyRegistry policies;
    WinDivertInterceptor interceptor(flows, datagrams, policies, kProxyPort, 1053,
                                     kConnectPort);
    CHECK(interceptor.start());

    feed({
        // 0: the application's SYN, 1: its next packet - both reflected.
        tcpPacket(kLocal, 50000, kServer, 443, kSyn, true),
        tcpPacket(kLocal, 50000, kServer, 443, kAck, true),
        // 2: a connection that predates the engine - left alone.
        tcpPacket(kLocal, 50001, kServer, 443, kAck, true),
        // 3: the relay's reply to the tracked client, 4: to an unknown peer.
        tcpPacket(kLocal, kProxyPort, kServer, 50000, kAck, true),
        tcpPacket(kLocal, kProxyPort, kServer, 50009, kAck, true),
    });
    feed({
        // 5: relay SYN to the private connect port, 6: the server's SYN-ACK.
        tcpPacket(kLocal, 50100, kServer, kConnectPort, kSyn, true),
        tcpPacket(kServer, 443, kLocal, 50100, kSyn | kAck, false),
        // 7: inbound from a server we never dialed through the relay.
        tcpPacket(kOtherServer, 443, kLocal, 50200, kAck, false),
        // 8: RST of the tracked client flow still belongs to it, 9: later ones do not.
        tcpPacket(kLocal, 50000, kServer, 443, kRst, true),
        tcpPacket(kLocal, 50000, kServer, 443, kAck, true),
    });
    const std::vector<SentPacket> sent = waitForSent(10);
    CHECK(flows.claim("203.0.113.9", 50000).has_value());
    CHECK(!flows.claim("203.0.113.9", 50001).has_value());
    interceptor.stop();

    CHECK_EQ(sent.size(), (size_t)10);
    // Reflected: addresses swapped, destination port is the relay's, now inbound.
    expectPacket(sent[0], false, kServer, 50000, kLocal, kProxyPort);
    CHECK(sent[0].syn);
    expectPacket(sent[1], false, kServer, 50000, kLocal, kProxyPort);
    expectPacket(sent[2], true, kLocal, 50001, kServer, 443);
    expectPacket(sent[3], false, kServer, 443, kLocal, 50000);
    expectPacket(sent[4], true, kLocal, kProxyPort, kServer, 50009);
    expectPacket(sent[5], true, kLocal, 50100, kServer, 443);
    expectPacket(sent[6], false, kServer, kConnectPort, kLocal, 50100);
    expectPacket(sent[7], false, kOtherServer, 443, kLocal, 50200);
    expectPacket(sent[8], false, kServer, 50000, kLocal, kProxyPort);
    expectPacket(sent[9], true, kLocal, 50000, kServer, 443);
}

TEST(divert_process_rules_never_break_the_relays_own_upstream_connection) {
    resetScript();
    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    packet_strategy::PolicyRegistry policies;
    // Nothing on this machine matches: every client SYN is left alone.
    process_filter::Filter filter(
        process_filter::Rules({"no-such-program-for-the-test.exe"}, {}));
    WinDivertInterceptor interceptor(flows, datagrams, policies, kProxyPort, 1053,
                                     kConnectPort, quic_strategy::Mode::Allow, &filter);
    CHECK(interceptor.start());

    feed({
        // 0/1: an application the rules leave alone, SYN and its server reply.
        tcpPacket(kLocal, 50300, kServer, 443, kSyn, true),
        tcpPacket(kServer, 443, kLocal, 50300, kSyn | kAck, false),
        // 2/3: the relay's upstream handshake, which has no process of its own to
        // match and must still be mapped between :1443 and :443.
        tcpPacket(kLocal, 50301, kOtherServer, kConnectPort, kSyn, true),
        tcpPacket(kOtherServer, 443, kLocal, 50301, kSyn | kAck, false),
    });
    const std::vector<SentPacket> sent = waitForSent(4);
    CHECK(!flows.claim("203.0.113.9", 50300).has_value());
    interceptor.stop();

    CHECK_EQ(sent.size(), (size_t)4);
    expectPacket(sent[0], true, kLocal, 50300, kServer, 443);
    expectPacket(sent[1], false, kServer, 443, kLocal, 50300);
    expectPacket(sent[2], true, kLocal, 50301, kOtherServer, 443);
    expectPacket(sent[3], false, kOtherServer, kConnectPort, kLocal, 50301);
}

TEST(divert_one_refused_packet_does_not_drop_the_rest_of_the_batch) {
    resetScript();
    failDestinationPort = 9999;
    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    packet_strategy::PolicyRegistry policies;
    WinDivertInterceptor interceptor(flows, datagrams, policies, kProxyPort, 1053,
                                     kConnectPort);
    CHECK(interceptor.start());

    feed({
        tcpPacket(kLocal, 50400, kServer, 8001, kAck, true),
        tcpPacket(kLocal, 50401, kServer, 9999, kAck, true),   // refused by the driver
        tcpPacket(kLocal, 50402, kServer, 8002, kAck, true),
        tcpPacket(kLocal, 50403, kServer, 8003, kFin | kAck, true),
    });
    const std::vector<SentPacket> sent = waitForSent(3);
    const bool stillRunning = interceptor.running();
    interceptor.stop();

    CHECK(stillRunning);
    CHECK_EQ(interceptor.fatalErrorCode(), static_cast<DWORD>(ERROR_SUCCESS));
    CHECK_EQ(sent.size(), (size_t)3);
    CHECK_EQ(sent[0].destinationPort, (uint16_t)8001);
    CHECK_EQ(sent[1].destinationPort, (uint16_t)8002);
    CHECK_EQ(sent[2].destinationPort, (uint16_t)8003);
}
