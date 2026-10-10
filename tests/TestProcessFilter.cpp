#include "Test.hpp"

#include "ProcessFilter.hpp"

#include <cstring>
#include <string>
#include <vector>

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
    ~SocketScope() { reset(INVALID_SOCKET); }
    SocketScope(const SocketScope&) = delete;
    SocketScope& operator=(const SocketScope&) = delete;
    SOCKET get() const { return value_; }
    void reset(SOCKET value) {
        if (value_ != INVALID_SOCKET) closesocket(value_);
        value_ = value;
    }

private:
    SOCKET value_;
};

// A real loopback TCP connection owned by this test process, so the ownership
// lookup has a genuine row to resolve.
struct LoopbackFlow {
    SocketScope listener;
    SocketScope client;
    SocketScope accepted;
    process_filter::Endpoint endpoint;
};

void openLoopbackFlow(LoopbackFlow& flow) {
    flow.listener.reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    CHECK(flow.listener.get() != INVALID_SOCKET);
    sockaddr_in listenAddress{};
    listenAddress.sin_family = AF_INET;
    listenAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(flow.listener.get(), reinterpret_cast<sockaddr*>(&listenAddress),
               sizeof(listenAddress)) == 0);
    CHECK(listen(flow.listener.get(), 1) == 0);
    int listenLength = sizeof(listenAddress);
    CHECK(getsockname(flow.listener.get(), reinterpret_cast<sockaddr*>(&listenAddress),
                      &listenLength) == 0);

    flow.client.reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    CHECK(flow.client.get() != INVALID_SOCKET);
    CHECK(connect(flow.client.get(), reinterpret_cast<sockaddr*>(&listenAddress),
                  sizeof(listenAddress)) == 0);
    flow.accepted.reset(accept(flow.listener.get(), nullptr, nullptr));
    CHECK(flow.accepted.get() != INVALID_SOCKET);

    sockaddr_in local{};
    sockaddr_in remote{};
    int localLength = sizeof(local);
    int remoteLength = sizeof(remote);
    CHECK(getsockname(flow.client.get(), reinterpret_cast<sockaddr*>(&local),
                      &localLength) == 0);
    CHECK(getpeername(flow.client.get(), reinterpret_cast<sockaddr*>(&remote),
                      &remoteLength) == 0);

    flow.endpoint.protocol = process_filter::Protocol::Tcp;
    flow.endpoint.localPort = ntohs(local.sin_port);
    flow.endpoint.remotePort = ntohs(remote.sin_port);
    std::memcpy(flow.endpoint.localAddress.data(), &local.sin_addr.s_addr, 4);
    std::memcpy(flow.endpoint.remoteAddress.data(), &remote.sin_addr.s_addr, 4);
}

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
    CHECK_EQ(rules.rejectedIncludeCount(), 0U);
    CHECK(!rules.includeListInvalid());
}

TEST(ProcessRulesFailClosedWhenAnIncludeListNormalizesToNothing) {
    // A pattern over the length limit is dropped. If that empties the include
    // list, "no include rules" would silently mean "intercept everything".
    const process_filter::Rules rules({std::string(2000, 'a')}, {});
    CHECK_EQ(rules.includeCount(), 0U);
    CHECK_EQ(rules.rejectedIncludeCount(), 1U);
    CHECK(rules.includeListInvalid());
    CHECK(rules.enabled());
    CHECK(!rules.allowsImage("chrome.exe"));

    // Blank entries are not a request for anything.
    const process_filter::Rules blank({" ", "\t", ""}, {});
    CHECK(!blank.enabled());
    CHECK(!blank.includeListInvalid());
    CHECK(blank.allowsImage("chrome.exe"));

    // A partly usable list keeps working and reports what it dropped.
    const process_filter::Rules partial({"chrome.exe", std::string(2000, 'b')},
                                        {std::string(2000, 'c')});
    CHECK(!partial.includeListInvalid());
    CHECK_EQ(partial.rejectedIncludeCount(), 1U);
    CHECK_EQ(partial.rejectedExcludeCount(), 1U);
    CHECK(partial.allowsImage("chrome.exe"));
    CHECK(!partial.allowsImage("curl.exe"));
}

TEST(ProcessRulesReportPatternsBeyondTheRuleCap) {
    std::vector<std::string> includes;
    for (int i = 0; i < 130; ++i) includes.push_back("app" + std::to_string(i) + ".exe");
    const process_filter::Rules rules(includes, {});
    CHECK_EQ(rules.includeCount(), 128U);
    CHECK_EQ(rules.rejectedIncludeCount(), 2U);
    CHECK(rules.allowsImage("app127.exe"));
    CHECK(!rules.allowsImage("app128.exe"));
}

TEST(ProcessFilterResolvesOwnerOnceForANewTcpTuple) {
    WinsockScope winsock;
    CHECK(winsock.ready);

    LoopbackFlow flow;
    openLoopbackFlow(flow);

    process_filter::Filter filter(
        process_filter::Rules({"splithello_tests.exe"}, {}));
    CHECK(filter.shouldIntercept(flow.endpoint, true, true));
    // The second read is served by the tuple cache, including after the
    // connection's initial ownership lookup has completed.
    CHECK(filter.shouldIntercept(flow.endpoint, true, false));
}

TEST(ProcessFilterKeepsALiveFlowInterceptedPastTheIdleTtl) {
    WinsockScope winsock;
    CHECK(winsock.ready);

    LoopbackFlow flow;
    openLoopbackFlow(flow);
    process_filter::Filter filter(
        process_filter::Rules({"splithello_tests.exe"}, {}));

    const uint64_t minute = 60ULL * 1000ULL;
    uint64_t now = 1000;
    CHECK(filter.shouldIntercept(flow.endpoint, true, true, now));
    // A packet every 9 minutes outlives the 10-minute TTL many times over: the
    // decision follows the connection instead of expiring at a fixed deadline
    // (which used to reset the flow mid-stream).
    for (int i = 0; i < 6; ++i) {
        now += 9 * minute;
        CHECK(filter.shouldIntercept(flow.endpoint, true, false, now));
    }
    // Only a genuinely idle tuple ages out, and then it is bypassed, not guessed.
    now += 11 * minute;
    CHECK(!filter.shouldIntercept(flow.endpoint, true, false, now));
}

TEST(ProcessFilterForgetEndsTheCachedDecision) {
    WinsockScope winsock;
    CHECK(winsock.ready);

    LoopbackFlow flow;
    openLoopbackFlow(flow);
    process_filter::Filter filter(
        process_filter::Rules({"splithello_tests.exe"}, {}));

    CHECK(filter.shouldIntercept(flow.endpoint, true, true, 5000));
    CHECK(filter.shouldIntercept(flow.endpoint, true, false, 5001));
    filter.forget(flow.endpoint);
    CHECK(!filter.shouldIntercept(flow.endpoint, true, false, 5002));
}
