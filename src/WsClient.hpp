#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <functional>
#include <atomic>
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

// WinHTTP WebSocket client wrapper.
// Connects to a Cloudflare Worker relay via wss:// and provides
// send/receive for binary and text frames.
class WsClient {
public:
    WsClient();
    ~WsClient();

    WsClient(const WsClient&) = delete;
    WsClient& operator=(const WsClient&) = delete;

    // Connect to the relay. url must be like "wss://relay.workers.dev/tunnel".
    // `headers` carries the bearer secret the Worker requires.
    // Returns true on success.
    bool connect(std::string_view url,
                 const std::vector<std::pair<std::string, std::string>>& headers = {},
                 uint16_t connectPortOverride = 0);

    // Send a text frame (JSON control messages).
    bool sendText(std::string_view data);

    // Send a binary frame (raw TCP relay data).
    bool sendBinary(const uint8_t* data, size_t len);

    // Receive a frame. Returns number of bytes received, 0 on close, -1 on error.
    // out is resized to fit. isText is set to true for text frames.
    int receive(std::vector<uint8_t>& out, bool& isText);

    // Close the WebSocket gracefully.
    void close();

    bool isConnected() const { return connected_.load(); }

private:
    HINTERNET session_  = nullptr;
    HINTERNET connect_  = nullptr;
    HINTERNET request_  = nullptr;
    HINTERNET websocket_ = nullptr;
    std::atomic<bool> connected_{false};

    void cleanup();
};
