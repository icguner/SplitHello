#include "DirectRelay.hpp"
#include <spdlog/spdlog.h>
#include <vector>
#include <format>

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

DirectRelay::DirectRelay(SOCKET clientSock, const std::string& workerUrl,
                         const std::string& targetHost, uint16_t targetPort)
    : clientSock_(clientSock)
    , workerUrl_(workerUrl)
    , targetHost_(targetHost)
    , targetPort_(targetPort)
{}

DirectRelay::~DirectRelay() {
    stop();
}

void DirectRelay::start() {
    std::thread([this]() { run(); }).detach();
}

// --- DNS Resolution via Worker /resolve endpoint ---

static std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), sz);
    return w;
}

// Extract a string value from simple JSON: "key":"value"
static std::string jsonGet(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) pos++;
    if (pos >= json.size() || json[pos] != '"') return {};
    pos++;
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) pos++;
        result += json[pos++];
    }
    return result;
}

std::string DirectRelay::resolveDns(const std::string& host) {
    // Parse Worker URL to get the HTTPS host
    // workerUrl_ is like "wss://workerdpi-relay.xxx.workers.dev"
    std::string workerHost;
    auto pos = workerUrl_.find("://");
    if (pos != std::string::npos) {
        workerHost = workerUrl_.substr(pos + 3);
        auto slash = workerHost.find('/');
        if (slash != std::string::npos) workerHost.resize(slash);
    }

    if (workerHost.empty()) {
        spdlog::warn("DNS: Worker URL parse hatasi, hostname olarak kullaniliyor");
        return {};
    }

    std::wstring wHost = toWide(workerHost);
    std::wstring wPath = toWide("/resolve?host=" + host);

    HINTERNET session = WinHttpOpen(L"WorkerDPI-DNS/1.0",
                                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        spdlog::error("DNS: WinHttpOpen failed: {}", GetLastError());
        return {};
    }

    // Set timeouts: resolve=5s, connect=5s, send=5s, receive=5s
    DWORD timeout = 5000;
    WinHttpSetTimeouts(session, timeout, timeout, timeout, timeout);

    HINTERNET conn = WinHttpConnect(session, wHost.c_str(),
                                    INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) {
        spdlog::error("DNS: WinHttpConnect failed: {}", GetLastError());
        WinHttpCloseHandle(session);
        return {};
    }

    HINTERNET req = WinHttpOpenRequest(conn, L"GET", wPath.c_str(),
                                       nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!req) {
        spdlog::error("DNS: WinHttpOpenRequest failed: {}", GetLastError());
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        spdlog::error("DNS: WinHttpSendRequest failed: {}", GetLastError());
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    if (!WinHttpReceiveResponse(req, nullptr)) {
        spdlog::error("DNS: WinHttpReceiveResponse failed: {}", GetLastError());
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return {};
    }

    // Check HTTP status
    DWORD statusCode = 0;
    DWORD scSize = sizeof(statusCode);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &scSize,
                        WINHTTP_NO_HEADER_INDEX);

    // Read response body
    std::string body;
    DWORD available = 0;
    do {
        WinHttpQueryDataAvailable(req, &available);
        if (available == 0) break;
        std::vector<char> buf(available);
        DWORD bytesRead = 0;
        WinHttpReadData(req, buf.data(), available, &bytesRead);
        body.append(buf.data(), bytesRead);
    } while (available > 0);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);

    if (statusCode != 200) {
        spdlog::warn("DNS: /resolve HTTP {} for {}: {}", statusCode, host, body);
        return {};
    }

    std::string ip = jsonGet(body, "ip");
    if (!ip.empty()) {
        spdlog::info("DNS: {} -> {}", host, ip);
    } else {
        spdlog::warn("DNS: bos yanit for {}: {}", host, body);
    }
    return ip;
}

// --- Direct TCP Connection ---

SOCKET DirectRelay::connectTarget(const std::string& ip, uint16_t port) {
    // Try to resolve as address (could be IP or hostname)
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    std::string portStr = std::to_string(port);

    if (getaddrinfo(ip.c_str(), portStr.c_str(), &hints, &result) != 0) {
        spdlog::error("getaddrinfo hatasi: {} ({})", ip, WSAGetLastError());
        return INVALID_SOCKET;
    }

    SOCKET sock = INVALID_SOCKET;
    for (auto* ptr = result; ptr; ptr = ptr->ai_next) {
        sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) continue;

        if (::connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break; // connected
    }
    freeaddrinfo(result);

    return sock;
}

// --- TLS Fragmentation ---

// Find SNI hostname offset and length within a TLS ClientHello
static bool findSniOffset(const uint8_t* data, size_t len, size_t& sniOffset, size_t& sniLen) {
    // Minimum: 5 (record) + 4 (handshake) + 2 (version) + 32 (random) = 43
    if (len < 43) return false;

    size_t pos = 5; // skip TLS record header
    pos += 4;       // skip handshake header (type + length)
    pos += 2;       // skip client version
    pos += 32;      // skip random

    // Session ID
    if (pos >= len) return false;
    uint8_t sidLen = data[pos++];
    pos += sidLen;

    // Cipher suites
    if (pos + 2 > len) return false;
    uint16_t csLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + csLen;

    // Compression methods
    if (pos >= len) return false;
    uint8_t cmLen = data[pos++];
    pos += cmLen;

    // Extensions length
    if (pos + 2 > len) return false;
    uint16_t extTotalLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    size_t extEnd = pos + extTotalLen;
    if (extEnd > len) extEnd = len;

    while (pos + 4 <= extEnd) {
        uint16_t extType = (data[pos] << 8) | data[pos + 1];
        uint16_t extLen = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (extType == 0x0000 && pos + extLen <= extEnd) {
            // SNI extension found
            // SNI list: listLen(2) + nameType(1) + nameLen(2) + name
            if (extLen >= 5) {
                size_t nameLen = (data[pos + 3] << 8) | data[pos + 4];
                sniOffset = pos + 5;  // start of hostname
                sniLen = nameLen;
                return (sniOffset + sniLen <= len);
            }
        }
        pos += extLen;
    }
    return false;
}

bool DirectRelay::fragmentAndSend(const uint8_t* data, size_t len) {
    if (len < 6) {
        return send(targetSock_, (const char*)data, (int)len, 0) > 0;
    }

    bool isTls = (data[0] == 0x16 && data[1] == 0x03);
    if (!isTls) {
        return send(targetSock_, (const char*)data, (int)len, 0) > 0;
    }

    // Enable TCP_NODELAY so each send() goes as a separate TCP segment
    int nodelay = 1;
    setsockopt(targetSock_, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    uint16_t recordLen = (data[3] << 8) | data[4];
    size_t totalRecord = 5 + recordLen;
    if (totalRecord > len) totalRecord = len;

    // Strategy: TLS Record Fragmentation
    // Split the single TLS record into two valid TLS records.
    // DPI that inspects within a single TLS record won't find the full SNI.
    // This is valid per TLS RFC - handshake messages can span multiple records.

    // Find SNI to split right in the middle of the hostname
    size_t sniOff = 0, sniLen = 0;
    size_t splitPayloadAt;

    if (findSniOffset(data, len, sniOff, sniLen) && sniLen > 2) {
        // Split in the middle of the SNI hostname
        splitPayloadAt = (sniOff + sniLen / 2) - 5; // offset within payload (subtract record header)
        spdlog::debug("SNI found at offset {}, len {}, split at payload byte {}",
                      sniOff, sniLen, splitPayloadAt);
    } else {
        // SNI not found, split after 2 bytes of payload
        splitPayloadAt = 2;
    }

    if (splitPayloadAt < 1) splitPayloadAt = 1;
    if (splitPayloadAt >= recordLen) splitPayloadAt = recordLen / 2;

    size_t part1Len = splitPayloadAt;
    size_t part2Len = recordLen - splitPayloadAt;

    // Build and send first TLS record: [type][ver][len1][payload_part1]
    uint8_t hdr1[5] = { data[0], data[1], data[2],
                        (uint8_t)(part1Len >> 8), (uint8_t)(part1Len & 0xFF) };
    send(targetSock_, (const char*)hdr1, 5, 0);
    send(targetSock_, (const char*)(data + 5), (int)part1Len, 0);

    Sleep(50);

    // Build and send second TLS record: [type][ver][len2][payload_part2]
    uint8_t hdr2[5] = { data[0], data[1], data[2],
                        (uint8_t)(part2Len >> 8), (uint8_t)(part2Len & 0xFF) };
    send(targetSock_, (const char*)hdr2, 5, 0);

    // Send second payload in small chunks for extra TCP fragmentation
    const uint8_t* part2Data = data + 5 + part1Len;
    size_t sent = 0;
    while (sent < part2Len) {
        size_t chunk = (part2Len - sent > 5) ? 5 : (part2Len - sent);
        send(targetSock_, (const char*)(part2Data + sent), (int)chunk, 0);
        sent += chunk;
        if (sent < part2Len) Sleep(1);
    }

    // Send any trailing data after the TLS record
    if (totalRecord < len) {
        send(targetSock_, (const char*)(data + totalRecord), (int)(len - totalRecord), 0);
    }

    spdlog::debug("TLS record split: {}+{} payload bytes (record total {})",
                  part1Len, part2Len, recordLen);

    // Disable TCP_NODELAY
    nodelay = 0;
    setsockopt(targetSock_, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

    return true;
}

// --- Main Flow ---

void DirectRelay::run() {
    running_ = true;

    // Step 1: Resolve DNS via Worker (bypass ISP DNS poisoning)
    std::string connectAddr = targetHost_;

    // Check if it's already an IP address
    bool isIp = true;
    for (char c : targetHost_) {
        if (c != '.' && (c < '0' || c > '9')) { isIp = false; break; }
    }

    if (!isIp) {
        std::string resolved = resolveDns(targetHost_);
        if (!resolved.empty()) {
            connectAddr = resolved;
        } else {
            spdlog::warn("DNS cozumlenemedi: {}, direkt deneniyor", targetHost_);
        }
    }

    // Step 2: Direct TCP connection
    spdlog::info("Direkt baglanti: {}:{} ({})", connectAddr, targetPort_, targetHost_);

    targetSock_ = connectTarget(connectAddr, targetPort_);
    if (targetSock_ == INVALID_SOCKET) {
        spdlog::error("Baglanti hatasi: {}:{}", connectAddr, targetPort_);
        closesocket(clientSock_);
        delete this;
        return;
    }

    spdlog::info("Baglanti kuruldu: {}:{}", targetHost_, targetPort_);

    // Step 3: Start bidirectional relay
    // Client→Target pump handles TLS fragmentation on first packet
    clientToTarget_ = std::thread([this]() { pumpClientToTarget(); });
    targetToClient_ = std::thread([this]() { pumpTargetToClient(); });

    if (clientToTarget_.joinable()) clientToTarget_.join();
    if (targetToClient_.joinable()) targetToClient_.join();

    spdlog::debug("Baglanti kapandi: {}:{}", targetHost_, targetPort_);

    closesocket(clientSock_);
    if (targetSock_ != INVALID_SOCKET) closesocket(targetSock_);
    delete this;
}

void DirectRelay::pumpClientToTarget() {
    uint8_t buf[8192];
    bool firstPacket = true;

    while (running_) {
        int n = recv(clientSock_, (char*)buf, sizeof(buf), 0);
        if (n <= 0) { stop(); return; }

        if (firstPacket) {
            // Fragment the first TLS packet (ClientHello with SNI)
            if (!fragmentAndSend(buf, n)) { stop(); return; }
            firstPacket = false;
        } else {
            if (send(targetSock_, (char*)buf, n, 0) <= 0) { stop(); return; }
        }
    }
}

void DirectRelay::pumpTargetToClient() {
    uint8_t buf[8192];

    while (running_) {
        int n = recv(targetSock_, (char*)buf, sizeof(buf), 0);
        if (n <= 0) { stop(); return; }

        const char* ptr = (const char*)buf;
        int remaining = n;
        while (remaining > 0 && running_) {
            int sent = send(clientSock_, ptr, remaining, 0);
            if (sent <= 0) { stop(); return; }
            ptr += sent;
            remaining -= sent;
        }
    }
}

void DirectRelay::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (targetSock_ != INVALID_SOCKET) shutdown(targetSock_, SD_BOTH);
        shutdown(clientSock_, SD_BOTH);
    }
}
