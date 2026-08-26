#include "WsClient.hpp"
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

WsClient::WsClient() = default;

WsClient::~WsClient() {
    close();
    cleanup();
}

void WsClient::cleanup() {
    if (websocket_) { WinHttpCloseHandle(websocket_); websocket_ = nullptr; }
    if (request_)   { WinHttpCloseHandle(request_);   request_   = nullptr; }
    if (connect_)   { WinHttpCloseHandle(connect_);   connect_   = nullptr; }
    if (session_)   { WinHttpCloseHandle(session_);   session_   = nullptr; }
    connected_ = false;
}

bool WsClient::connect(std::string_view url,
                       const std::vector<std::pair<std::string, std::string>>& headers,
                       uint16_t connectPortOverride) {
    cleanup();

    // Parse URL: wss://host[:port]/path
    std::string urlStr(url);

    bool secure = true;
    std::string_view sv = urlStr;

    if (sv.starts_with("wss://")) {
        sv.remove_prefix(6);
    } else if (sv.starts_with("ws://")) {
        sv.remove_prefix(5);
        secure = false;
    } else {
        spdlog::error("Invalid WebSocket URL: {}", urlStr);
        return false;
    }

    // Split host and path
    auto slashPos = sv.find('/');
    std::string hostPort(sv.substr(0, slashPos));
    std::string path = (slashPos != std::string_view::npos) ? std::string(sv.substr(slashPos)) : "/";

    // Split host and port
    std::string host;
    INTERNET_PORT port = secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    auto colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        host = hostPort.substr(0, colonPos);
        port = static_cast<INTERNET_PORT>(std::stoi(hostPort.substr(colonPos + 1)));
    } else {
        host = hostPort;
    }

    const INTERNET_PORT transportPort = connectPortOverride == 0
        ? port : (INTERNET_PORT)connectPortOverride;
    spdlog::debug("Connecting to {}:{} via port {}{} (secure={})",
                  host, port, transportPort, path, secure);

    // Convert strings to wide
    auto toWide = [](const std::string& s) -> std::wstring {
        if (s.empty()) return {};
        int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        std::wstring w(sz, 0);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), sz);
        return w;
    };

    std::wstring wHost = toWide(host);
    std::wstring wPath = toWide(path);

    // Create session - use NO_PROXY to avoid circular proxy loop
    // (we ARE the proxy, so our outgoing connections must go direct)
    session_ = WinHttpOpen(L"SplitHello/1.0",
                           WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session_) {
        spdlog::error("WinHttpOpen failed: {}", GetLastError());
        return false;
    }

    // Create connection
    connect_ = WinHttpConnect(session_, wHost.c_str(), transportPort, 0);
    if (!connect_) {
        spdlog::error("WinHttpConnect failed: {}", GetLastError());
        cleanup();
        return false;
    }

    // Create request
    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    request_ = WinHttpOpenRequest(connect_, L"GET", wPath.c_str(),
                                  nullptr, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request_) {
        spdlog::error("WinHttpOpenRequest failed: {}", GetLastError());
        cleanup();
        return false;
    }

    if (connectPortOverride != 0 && connectPortOverride != port) {
        const std::wstring hostHeader = toWide("Host: " + host);
        WinHttpAddRequestHeaders(request_, hostHeader.c_str(), (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    // Authorization for the Worker's /tunnel endpoint.
    for (const auto& [name, value] : headers) {
        const std::wstring line = toWide(name + ": " + value);
        WinHttpAddRequestHeaders(request_, line.c_str(), (DWORD)-1,
                                 WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    // Set WebSocket upgrade option (MSDN: NULL, 0 parameters)
    if (!WinHttpSetOption(request_, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        spdlog::error("Failed to set WebSocket option: {}", GetLastError());
        cleanup();
        return false;
    }

    // Send request
    if (!WinHttpSendRequest(request_, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        spdlog::error("WinHttpSendRequest failed: {}", GetLastError());
        cleanup();
        return false;
    }

    // Receive response
    if (!WinHttpReceiveResponse(request_, nullptr)) {
        spdlog::error("WinHttpReceiveResponse failed: {}", GetLastError());
        cleanup();
        return false;
    }

    // Check status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(request_,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

    if (statusCode != 101) {
        if (statusCode == 401 || statusCode == 403) {
            spdlog::error("Tunel kimlik dogrulamasi reddedildi (HTTP {}). "
                          "--redeploy ile worker'i guncelleyin.", statusCode);
        } else {
            spdlog::error("WebSocket upgrade failed, HTTP status: {}", statusCode);
        }
        cleanup();
        return false;
    }

    // Complete the WebSocket upgrade
    websocket_ = WinHttpWebSocketCompleteUpgrade(request_, 0);
    if (!websocket_) {
        spdlog::error("WinHttpWebSocketCompleteUpgrade failed: {}", GetLastError());
        cleanup();
        return false;
    }

    // Close the request handle - no longer needed after upgrade
    WinHttpCloseHandle(request_);
    request_ = nullptr;

    connected_ = true;
    spdlog::info("WebSocket connected to {}", urlStr);
    return true;
}

bool WsClient::sendText(std::string_view data) {
    if (!websocket_ || !connected_) return false;

    DWORD err = WinHttpWebSocketSend(websocket_,
                                     WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                     (PVOID)data.data(), (DWORD)data.size());
    if (err != NO_ERROR) {
        spdlog::error("WebSocket sendText failed: {}", err);
        connected_ = false;
        return false;
    }
    return true;
}

bool WsClient::sendBinary(const uint8_t* data, size_t len) {
    if (!websocket_ || !connected_) return false;

    DWORD err = WinHttpWebSocketSend(websocket_,
                                     WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                                     (PVOID)data, (DWORD)len);
    if (err != NO_ERROR) {
        spdlog::error("WebSocket sendBinary failed: {}", err);
        connected_ = false;
        return false;
    }
    return true;
}

int WsClient::receive(std::vector<uint8_t>& out, bool& isText) {
    if (!websocket_ || !connected_) return -1;

    out.clear();

    // Read in chunks until we get a complete message
    constexpr DWORD CHUNK_SIZE = 8192;
    uint8_t chunk[CHUNK_SIZE];

    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType;

    do {
        DWORD err = WinHttpWebSocketReceive(websocket_, chunk, CHUNK_SIZE, &bytesRead, &bufType);
        if (err != NO_ERROR) {
            spdlog::error("WebSocket receive failed: {}", err);
            connected_ = false;
            return -1;
        }

        // Check for close frame
        if (bufType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            spdlog::info("WebSocket received close frame");
            connected_ = false;
            return 0;
        }

        out.insert(out.end(), chunk, chunk + bytesRead);

    } while (bufType == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE ||
             bufType == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE);

    isText = (bufType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE);
    return (int)out.size();
}

void WsClient::close() {
    if (websocket_ && connected_) {
        WinHttpWebSocketClose(websocket_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        connected_ = false;
    }
}
