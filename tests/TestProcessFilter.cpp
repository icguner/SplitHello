#include "Test.hpp"

#include "ProcessFilter.hpp"

#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {

class WinsockScope {
public:
    WinsockScope() { ready = WSAStartup(MAKEWORD(2, 2), &data) == 0; }
    ~WinsockScope() { if (ready) WSACleanup(); }
    bool ready = false;

private:
    WSADATA data{};
};

class SocketScope {
public:
    explicit SocketScope(SOCKET value = INVALID_SOCKET) : value_(value) {}
    ~SocketScope() { if (value_ != INVALID_SOCKET) closesocket(value_); }
    SocketScope(const SocketScope&) = delete;
    SocketScope& operator=(const SocketScope&) = delete;
    SOCKET get() const { return value_; }

private:
    SOCKET value_;
};

} // namespace

TEST(ProcessRulesAllowEverythingWhenEmpty) {
    const process_filter::Rules rules({}, {});
    CHECK(!rules.enabled());
    CHECK(rules.allowsImage("C:\\Program Files\\Browser\\browser.exe"));
}

TEST(ProcessRulesUseIncludeAsAllowList) {
    const process_filter::Rules rules({"chrome.exe", "firefox*.exe"}, {});
    CHECK(rules.enabled());
    CHECK(rules.allowsImage("C:\\Program Files\\Google\\Chrome.EXE"));
    CHECK(rules.allowsImage("firefox-nightly.exe"));
    CHECK(!rules.allowsImage("C:\\Windows\\System32\\curl.exe"));
}

TEST(ProcessRulesGiveExcludePrecedence) {
    const process_filter::Rules rules({"*.exe"}, {"steam*.exe"});
    CHECK(rules.allowsImage("browser.exe"));
    CHECK(!rules.allowsImage("C:\\Games\\Steam.exe"));
    CHECK(!rules.allowsImage("steamwebhelper.exe"));
}

TEST(ProcessRulesCanMatchFullPathsAndQuestionMarks) {
    const process_filter::Rules rules(
        {"c:/portable/*/app?.exe"}, {});
    CHECK(rules.allowsImage("C:\\Portable\\Browser\\App1.exe"));
    CHECK(!rules.allowsImage("C:\\Installed\\Browser\\App1.exe"));
    CHECK(!rules.allowsImage("C:\\Portable\\Browser\\App10.exe"));
}

TEST(ProcessRulesNormalizeAndDeduplicatePatterns) {
    const process_filter::Rules rules(
        {" Chrome.exe ", "chrome.EXE", ""},
        {" helper.exe ", "HELPER.EXE"});
    CHECK_EQ(rules.includeCount(), 1U);
    CHECK_EQ(rules.excludeCount(), 1U);
    CHECK(rules.allowsImage("chrome.exe"));
    CHECK(!rules.allowsImage("helper.exe"));
}

TEST(ProcessFilterResolvesOwnerOnceForANewTcpTuple) {
    WinsockScope winsock;
    CHECK(winsock.ready);

    SocketScope listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    CHECK(listener.get() != INVALID_SOCKET);
    sockaddr_in listenAddress{};
    listenAddress.sin_family = AF_INET;
    listenAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listener.get(), reinterpret_cast<sockaddr*>(&listenAddress),
               sizeof(listenAddress)) == 0);
    CHECK(listen(listener.get(), 1) == 0);
    int listenLength = sizeof(listenAddress);
    CHECK(getsockname(listener.get(), reinterpret_cast<sockaddr*>(&listenAddress),
                      &listenLength) == 0);

    SocketScope client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    CHECK(client.get() != INVALID_SOCKET);
    CHECK(connect(client.get(), reinterpret_cast<sockaddr*>(&listenAddress),
                  sizeof(listenAddress)) == 0);
    SocketScope accepted(accept(listener.get(), nullptr, nullptr));
    CHECK(accepted.get() != INVALID_SOCKET);

    sockaddr_in local{};
    sockaddr_in remote{};
    int localLength = sizeof(local);
    int remoteLength = sizeof(remote);
    CHECK(getsockname(client.get(), reinterpret_cast<sockaddr*>(&local),
                      &localLength) == 0);
    CHECK(getpeername(client.get(), reinterpret_cast<sockaddr*>(&remote),
                      &remoteLength) == 0);

    process_filter::Endpoint endpoint;
    endpoint.protocol = process_filter::Protocol::Tcp;
    endpoint.localPort = ntohs(local.sin_port);
    endpoint.remotePort = ntohs(remote.sin_port);
    std::memcpy(endpoint.localAddress.data(), &local.sin_addr.s_addr, 4);
    std::memcpy(endpoint.remoteAddress.data(), &remote.sin_addr.s_addr, 4);

    process_filter::Filter filter(
        process_filter::Rules({"splithello_tests.exe"}, {}));
    CHECK(filter.shouldIntercept(endpoint, true, true));
    // The second read is served by the tuple cache, including after the
    // connection's initial ownership lookup has completed.
    CHECK(filter.shouldIntercept(endpoint, true, false));
}
