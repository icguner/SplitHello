#include "Test.hpp"
#include "Dns.hpp"
#include "RecoveryPolicy.hpp"
#include "TransparentDnsProxy.hpp"
#include <thread>
#include <winsock2.h>

TEST(dns_datagram_errors_do_not_kill_receiver) {
    CHECK(recovery::shouldContinueDnsReceive(WSAEMSGSIZE));
    CHECK(recovery::shouldContinueDnsReceive(WSAECONNRESET));
    CHECK(recovery::shouldContinueDnsReceive(WSAETIMEDOUT));
    CHECK(!recovery::shouldContinueDnsReceive(WSAENOTSOCK));
    CHECK(!recovery::shouldContinueDnsReceive(WSAENETDOWN));
}

TEST(dns_bootstrap_survives_cache_clear) {
    WSADATA data{};
    CHECK_EQ(WSAStartup(MAKEWORD(2, 2), &data), 0);
    {
        dns::Resolver resolver("https://localhost", "");
        const auto before = resolver.resolve("localhost");
        CHECK(!before.empty());
        resolver.clearCache();
        CHECK(resolver.isBootstrapHost("LOCALHOST."));
        CHECK(!resolver.isBootstrapHost("unrelated.invalid"));
        const auto after = resolver.resolve("localhost");
        CHECK(after.v4 == before.v4);
        CHECK(after.v6 == before.v6);
    }
    WSACleanup();
}

TEST(dns_stop_can_be_requested_concurrently) {
    WSADATA data{};
    CHECK_EQ(WSAStartup(MAKEWORD(2, 2), &data), 0);
    dns::Resolver resolver("", "");
    transparent::DatagramRegistry datagrams;
    SOCKET reservation = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(reservation != INVALID_SOCKET);
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_loopback;
    CHECK_EQ(bind(reservation, reinterpret_cast<sockaddr*>(&local), sizeof(local)), 0);
    int length = sizeof(local);
    CHECK_EQ(getsockname(reservation, reinterpret_cast<sockaddr*>(&local), &length), 0);
    const uint16_t port = ntohs(local.sin6_port);
    closesocket(reservation);
    {
        TransparentDnsProxy proxy(resolver, datagrams, port);
        for (int i = 0; i < 4; ++i) {
            CHECK(proxy.start());
            std::thread first([&]() { proxy.stop(); });
            std::thread second([&]() { proxy.stop(); });
            first.join(); second.join();
            CHECK(!proxy.running());
        }
    }
    WSACleanup();
}
