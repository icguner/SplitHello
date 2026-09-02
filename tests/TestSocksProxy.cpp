#include "Test.hpp"

#include "SocksProxy.hpp"
#include "TcpConnect.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

// Connection lifecycle tests. They drive the manual SOCKS5 path through a
// loopback echo server with non-TLS payloads, so the relay forwards bytes
// untouched and no DNS, strategy store or Worker is needed.

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
    ~SocketScope() { close(); }
    SocketScope(const SocketScope&) = delete;
    SocketScope& operator=(const SocketScope&) = delete;
    SOCKET get() const { return value_; }
    void close() {
        if (value_ != INVALID_SOCKET) closesocket(value_);
        value_ = INVALID_SOCKET;
    }

private:
    SOCKET value_;
};

SOCKET listenLoopback(uint16_t& port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }

    int length = sizeof(address);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&address), &length) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    port = ntohs(address.sin_port);
    return sock;
}

SOCKET connectLoopback(uint16_t port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (connect(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

// Echoes every byte back to each client until that client closes.
class EchoServer {
public:
    ~EchoServer() { stop(); }

    bool start() {
        listen_ = listenLoopback(port_);
        if (listen_ == INVALID_SOCKET) return false;
        running_ = true;
        acceptThread_ = std::thread([this]() { acceptLoop(); });
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        closesocket(listen_);
        listen_ = INVALID_SOCKET;
        if (acceptThread_.joinable()) acceptThread_.join();

        std::vector<std::thread> workers;
        std::vector<SOCKET> clients;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            workers.swap(workers_);
            clients.swap(clients_);
        }
        for (SOCKET client : clients) shutdown(client, SD_BOTH);
        for (std::thread& worker : workers) {
            if (worker.joinable()) worker.join();
        }
        for (SOCKET client : clients) closesocket(client);
    }

    uint16_t port() const { return port_; }

private:
    SOCKET listen_ = INVALID_SOCKET;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    std::mutex mutex_;
    std::vector<SOCKET> clients_;
    std::vector<std::thread> workers_;

    void acceptLoop() {
        while (running_) {
            SOCKET client = accept(listen_, nullptr, nullptr);
            if (client == INVALID_SOCKET) continue;
            std::lock_guard<std::mutex> lock(mutex_);
            clients_.push_back(client);
            workers_.emplace_back([client]() {
                std::vector<uint8_t> buffer(16 * 1024);
                while (true) {
                    const int received = recv(client, (char*)buffer.data(), (int)buffer.size(), 0);
                    if (received <= 0) break;
                    if (!tcp::sendAll(client, buffer.data(), (size_t)received)) break;
                }
                shutdown(client, SD_SEND);
            });
        }
    }
};

// Runs a manual-mode proxy on a free loopback port on its own thread.
class ProxyHarness {
public:
    ~ProxyHarness() { stop(); }

    bool start(size_t maxConnections, unsigned idleTimeoutMs = 10 * 60 * 1000) {
        RelayContext context;
        context.idleTimeoutMs = idleTimeoutMs;
        proxy = std::make_unique<SocksProxy>(context, (uint16_t)0, nullptr, maxConnections);
        thread_ = std::thread([this]() {
            proxy->run();
            runReturned = true;
        });
        for (int waited = 0; waited < 200 && !proxy->running() && !runReturned; waited++) {
            Sleep(10);
        }
        return proxy->running();
    }

    void stop() {
        if (proxy) proxy->stop();
        if (thread_.joinable()) thread_.join();
    }

    std::unique_ptr<SocksProxy> proxy;
    std::atomic<bool> runReturned{false};

private:
    std::thread thread_;
};

bool recvExactTimeout(SOCKET sock, void* buffer, size_t length, unsigned timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    size_t total = 0;
    while (total < length) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return false;
        const int received = tcp::recvTimeout(sock, (uint8_t*)buffer + total, length - total,
                                              (unsigned)(deadline - now));
        if (received <= 0) return false;
        total += (size_t)received;
    }
    return true;
}

// True once the peer has closed (or reset) the connection; false only if it
// stays open for the whole budget. A single select() waking early with no
// event is not proof the peer is still there, so keep waiting until the
// deadline instead of giving up on the first timeout.
bool waitForClose(SOCKET sock, unsigned timeoutMs) {
    uint8_t byte = 0;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (true) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return false;
        const int received = tcp::recvTimeout(sock, &byte, 1, (unsigned)(deadline - now));
        if (received == tcp::kTimedOut) continue; // spurious wake: keep waiting
        if (received <= 0) return true;           // FIN (0) or reset (<0)
        // Unexpected leftover payload; drain and keep watching for the close.
    }
}

template <typename Predicate>
bool waitUntil(Predicate predicate, unsigned timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    while (!predicate()) {
        if (GetTickCount64() >= deadline) return false;
        Sleep(10);
    }
    return true;
}

// SOCKS5 no-auth CONNECT to 127.0.0.1:port.
bool socks5Connect(SOCKET sock, uint16_t port) {
    const uint8_t greeting[] = {0x05, 0x01, 0x00};
    if (!tcp::sendAll(sock, greeting, sizeof(greeting))) return false;
    uint8_t choice[2] = {};
    if (!recvExactTimeout(sock, choice, sizeof(choice), 5000)) return false;
    if (choice[0] != 0x05 || choice[1] != 0x00) return false;

    const uint8_t request[] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                               (uint8_t)(port >> 8), (uint8_t)(port & 0xFF)};
    if (!tcp::sendAll(sock, request, sizeof(request))) return false;
    uint8_t reply[10] = {};
    if (!recvExactTimeout(sock, reply, sizeof(reply), 5000)) return false;
    return reply[0] == 0x05 && reply[1] == 0x00;
}

bool echoRoundTrip(SOCKET sock, const std::string& payload) {
    if (!tcp::sendAll(sock, payload.data(), payload.size())) return false;
    std::string echoed(payload.size(), '\0');
    if (!recvExactTimeout(sock, echoed.data(), echoed.size(), 5000)) return false;
    return echoed == payload;
}

// Opens a proxied connection to the echo server and proves it is relaying.
SOCKET openRelayed(const ProxyHarness& proxy, const EchoServer& echo) {
    SOCKET sock = connectLoopback(proxy.proxy->port());
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;
    if (!socks5Connect(sock, echo.port()) || !echoRoundTrip(sock, "ping")) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

} // namespace

TEST(SocksProxyRelaysBytesInBothDirections) {
    WinsockScope winsock;
    CHECK(winsock.ready);
    EchoServer echo;
    CHECK(echo.start());
    ProxyHarness proxy;
    CHECK(proxy.start(8));
    CHECK(proxy.proxy->port() != 0);

    SocketScope client(connectLoopback(proxy.proxy->port()));
    CHECK(client.get() != INVALID_SOCKET);
    CHECK(socks5Connect(client.get(), echo.port()));

    // Not TLS, so the relay forwards it as-is and moves on to the pump.
    CHECK(echoRoundTrip(client.get(), "hello relay"));
    CHECK_EQ(proxy.proxy->activeConnections(), (size_t)1);

    // Several pump buffers' worth, sent while nothing reads on this side yet:
    // exercises the pending-bytes/back-pressure path of the single-thread pump.
    const std::string bulk(300 * 1024, 'x');
    std::thread sender([&]() { tcp::sendAll(client.get(), bulk.data(), bulk.size()); });
    std::string echoed(bulk.size(), '\0');
    const bool received = recvExactTimeout(client.get(), echoed.data(), echoed.size(), 10000);
    sender.join();
    CHECK(received);
    CHECK(echoed == bulk);

    // Closing the client ends the session and frees its slot.
    client.close();
    CHECK(waitUntil([&]() { return proxy.proxy->activeConnections() == 0; }, 5000));
    CHECK_EQ(proxy.proxy->rejectedConnections(), (uint64_t)0);

    proxy.stop();
    CHECK(waitUntil([&]() { return proxy.runReturned.load(); }, 5000));
}

TEST(SocksProxyRejectsConnectionsOverTheLimit) {
    WinsockScope winsock;
    CHECK(winsock.ready);
    EchoServer echo;
    CHECK(echo.start());
    ProxyHarness proxy;
    CHECK(proxy.start(1));

    SocketScope first(openRelayed(proxy, echo));
    CHECK(first.get() != INVALID_SOCKET);
    CHECK_EQ(proxy.proxy->activeConnections(), (size_t)1);

    // The limit is reached: the next connection is accepted and closed at once.
    SocketScope second(connectLoopback(proxy.proxy->port()));
    CHECK(second.get() != INVALID_SOCKET);
    CHECK(waitForClose(second.get(), 5000));
    CHECK_EQ(proxy.proxy->rejectedConnections(), (uint64_t)1);
    CHECK_EQ(proxy.proxy->activeConnections(), (size_t)1);

    // The slot is reusable once the live connection ends.
    first.close();
    CHECK(waitUntil([&]() { return proxy.proxy->activeConnections() == 0; }, 5000));
    SocketScope third(openRelayed(proxy, echo));
    CHECK(third.get() != INVALID_SOCKET);
    CHECK_EQ(proxy.proxy->rejectedConnections(), (uint64_t)1);
}

TEST(SocksProxyStopAbortsLiveConnectionsAndJoinsThreads) {
    WinsockScope winsock;
    CHECK(winsock.ready);
    EchoServer echo;
    CHECK(echo.start());
    ProxyHarness proxy;
    CHECK(proxy.start(8));

    std::vector<std::unique_ptr<SocketScope>> clients;
    for (int i = 0; i < 3; i++) {
        clients.push_back(std::make_unique<SocketScope>(openRelayed(proxy, echo)));
        CHECK(clients.back()->get() != INVALID_SOCKET);
    }
    CHECK_EQ(proxy.proxy->activeConnections(), (size_t)3);

    // Nobody closes anything on the client side: stop() has to abort the
    // relays itself and must not return before their threads are gone.
    const ULONGLONG started = GetTickCount64();
    proxy.proxy->stop();
    const ULONGLONG elapsedMs = GetTickCount64() - started;
    CHECK(elapsedMs < 10000);
    CHECK_EQ(proxy.proxy->activeConnections(), (size_t)0);
    CHECK(waitUntil([&]() { return proxy.runReturned.load(); }, 5000));

    for (const auto& client : clients) {
        CHECK(waitForClose(client->get(), 5000));
    }
}

TEST(SocksProxyClosesIdleConnections) {
    WinsockScope winsock;
    CHECK(winsock.ready);
    EchoServer echo;
    CHECK(echo.start());
    ProxyHarness proxy;
    CHECK(proxy.start(8, /*idleTimeoutMs=*/300));

    SocketScope client(openRelayed(proxy, echo));
    CHECK(client.get() != INVALID_SOCKET);

    // Both peers stay open but silent; the relay must give the connection up.
    CHECK(waitForClose(client.get(), 5000));
    CHECK(waitUntil([&]() { return proxy.proxy->activeConnections() == 0; }, 5000));
}
