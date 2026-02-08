#include "SocksProxy.hpp"
#include "DirectRelay.hpp"
#include <spdlog/spdlog.h>
#include <format>

// SOCKS5 constants (RFC 1928)
namespace socks5 {
    constexpr uint8_t VERSION      = 0x05;
    constexpr uint8_t AUTH_NONE    = 0x00;
    constexpr uint8_t AUTH_REJECT  = 0xFF;
    constexpr uint8_t CMD_CONNECT  = 0x01;
    constexpr uint8_t ATYP_IPV4   = 0x01;
    constexpr uint8_t ATYP_DOMAIN = 0x03;
    constexpr uint8_t ATYP_IPV6   = 0x04;
    constexpr uint8_t REP_SUCCESS = 0x00;
    constexpr uint8_t REP_FAILURE = 0x01;
    constexpr uint8_t REP_CMD_NOT_SUPPORTED = 0x07;
}

SocksProxy::SocksProxy(const std::string& workerUrl, uint16_t port)
    : workerUrl_(workerUrl), port_(port)
{}

SocksProxy::~SocksProxy() {
    stop();
}

bool SocksProxy::recvExact(SOCKET sock, uint8_t* buf, int n) {
    int total = 0;
    while (total < n) {
        int r = recv(sock, reinterpret_cast<char*>(buf + total), n - total, 0);
        if (r <= 0) return false;
        total += r;
    }
    return true;
}

std::string SocksProxy::recvLine(SOCKET sock) {
    std::string line;
    char c;
    while (true) {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return {};
        line += c;
        if (line.size() >= 2 && line.ends_with("\r\n")) {
            line.resize(line.size() - 2); // strip \r\n
            return line;
        }
        if (line.size() > 8192) return {}; // safety limit
    }
}

bool SocksProxy::run() {
    listenSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock_ == INVALID_SOCKET) {
        spdlog::error("Listen socket olusturulamadi: {}", WSAGetLastError());
        return false;
    }

    int opt = 1;
    setsockopt(listenSock_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port_);

    if (bind(listenSock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        spdlog::error("Port {} bind hatasi: {}", port_, WSAGetLastError());
        closesocket(listenSock_);
        listenSock_ = INVALID_SOCKET;
        return false;
    }

    if (listen(listenSock_, SOMAXCONN) == SOCKET_ERROR) {
        spdlog::error("Listen hatasi: {}", WSAGetLastError());
        closesocket(listenSock_);
        listenSock_ = INVALID_SOCKET;
        return false;
    }

    running_ = true;
    spdlog::info("Proxy dinliyor: 127.0.0.1:{} (SOCKS5 + HTTP CONNECT)", port_);

    while (running_) {
        sockaddr_in clientAddr{};
        int addrLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSock_, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);

        if (clientSock == INVALID_SOCKET) {
            if (running_) spdlog::warn("Accept hatasi: {}", WSAGetLastError());
            continue;
        }

        std::thread([this, clientSock]() {
            handleClient(clientSock);
        }).detach();
    }

    return true;
}

void SocksProxy::stop() {
    running_ = false;
    if (listenSock_ != INVALID_SOCKET) {
        closesocket(listenSock_);
        listenSock_ = INVALID_SOCKET;
    }
}

void SocksProxy::handleClient(SOCKET clientSock) {
    // Peek first byte to detect protocol
    uint8_t firstByte;
    int peeked = recv(clientSock, reinterpret_cast<char*>(&firstByte), 1, MSG_PEEK);
    if (peeked <= 0) {
        closesocket(clientSock);
        return;
    }

    std::string targetHost;
    uint16_t targetPort = 0;
    bool ok = false;

    if (firstByte == socks5::VERSION) {
        // SOCKS5 protocol
        ok = socks5Handshake(clientSock, targetHost, targetPort);
    } else if (firstByte >= 'A' && firstByte <= 'Z') {
        // HTTP method (CONNECT, GET, etc.)
        ok = httpConnectHandshake(clientSock, targetHost, targetPort);
    } else {
        spdlog::warn("Bilinmeyen protokol: ilk byte=0x{:02x}", firstByte);
    }

    if (!ok) {
        closesocket(clientSock);
        return;
    }

    spdlog::info("CONNECT {}:{}", targetHost, targetPort);

    // Create direct relay (takes ownership, self-destructs)
    auto* relay = new DirectRelay(clientSock, workerUrl_, targetHost, targetPort);
    relay->start();
}

// ---- HTTP CONNECT ----

bool SocksProxy::httpConnectHandshake(SOCKET sock, std::string& targetHost, uint16_t& targetPort) {
    // Read request line: "CONNECT host:port HTTP/1.1"
    std::string requestLine = recvLine(sock);
    if (requestLine.empty()) return false;

    // Parse method
    auto spacePos = requestLine.find(' ');
    if (spacePos == std::string::npos) return false;

    std::string method = requestLine.substr(0, spacePos);

    if (method != "CONNECT") {
        // Non-CONNECT HTTP requests - return 405
        spdlog::debug("HTTP {} istegi reddedildi (sadece CONNECT desteklenir)", method);
        const char* resp = "HTTP/1.1 405 Method Not Allowed\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
        send(sock, resp, (int)strlen(resp), 0);
        return false;
    }

    // Parse host:port
    auto afterMethod = requestLine.substr(spacePos + 1);
    auto nextSpace = afterMethod.find(' ');
    std::string hostPort = afterMethod.substr(0, nextSpace);

    auto colonPos = hostPort.rfind(':');
    if (colonPos == std::string::npos) return false;

    targetHost = hostPort.substr(0, colonPos);
    targetPort = static_cast<uint16_t>(std::stoi(hostPort.substr(colonPos + 1)));

    // Read remaining headers until empty line
    while (true) {
        std::string line = recvLine(sock);
        if (line.empty()) break; // empty line = end of headers
    }

    // Send 200 Connection Established
    const char* response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(sock, response, (int)strlen(response), 0);

    return true;
}

// ---- SOCKS5 ----

bool SocksProxy::socks5Handshake(SOCKET sock, std::string& targetHost, uint16_t& targetPort) {
    // Phase 1: Auth negotiation
    uint8_t header[2];
    if (!recvExact(sock, header, 2)) return false;
    if (header[0] != socks5::VERSION) return false;

    uint8_t nMethods = header[1];
    if (nMethods == 0) return false;

    std::vector<uint8_t> methods(nMethods);
    if (!recvExact(sock, methods.data(), nMethods)) return false;

    bool hasNoAuth = false;
    for (uint8_t m : methods) {
        if (m == socks5::AUTH_NONE) { hasNoAuth = true; break; }
    }

    uint8_t authReply[2] = { socks5::VERSION, hasNoAuth ? socks5::AUTH_NONE : socks5::AUTH_REJECT };
    send(sock, reinterpret_cast<char*>(authReply), 2, 0);
    if (!hasNoAuth) return false;

    // Phase 2: Connect request
    uint8_t req[4];
    if (!recvExact(sock, req, 4)) return false;
    if (req[0] != socks5::VERSION) return false;

    if (req[1] != socks5::CMD_CONNECT) {
        uint8_t reply[10] = { socks5::VERSION, socks5::REP_CMD_NOT_SUPPORTED, 0x00, socks5::ATYP_IPV4 };
        send(sock, reinterpret_cast<char*>(reply), 10, 0);
        return false;
    }

    uint8_t atyp = req[3];

    switch (atyp) {
    case socks5::ATYP_IPV4: {
        uint8_t ipBytes[4];
        if (!recvExact(sock, ipBytes, 4)) return false;
        targetHost = std::format("{}.{}.{}.{}", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]);
        break;
    }
    case socks5::ATYP_DOMAIN: {
        uint8_t domainLen;
        if (!recvExact(sock, &domainLen, 1)) return false;
        std::string domain(domainLen, '\0');
        if (!recvExact(sock, reinterpret_cast<uint8_t*>(domain.data()), domainLen)) return false;
        targetHost = std::move(domain);
        break;
    }
    case socks5::ATYP_IPV6: {
        uint8_t ipv6Bytes[16];
        if (!recvExact(sock, ipv6Bytes, 16)) return false;
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipv6Bytes, buf, sizeof(buf));
        targetHost = buf;
        break;
    }
    default:
        return false;
    }

    uint8_t portBytes[2];
    if (!recvExact(sock, portBytes, 2)) return false;
    targetPort = (static_cast<uint16_t>(portBytes[0]) << 8) | portBytes[1];

    // Success reply
    uint8_t reply[10] = {};
    reply[0] = socks5::VERSION;
    reply[1] = socks5::REP_SUCCESS;
    reply[3] = socks5::ATYP_IPV4;
    send(sock, reinterpret_cast<char*>(reply), 10, 0);

    return true;
}
