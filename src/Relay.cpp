#include "Relay.hpp"
#include <spdlog/spdlog.h>
#include <format>

Relay::Relay(SOCKET clientSock, const std::string& workerUrl,
             const std::string& targetHost, uint16_t targetPort)
    : clientSock_(clientSock)
    , workerUrl_(workerUrl)
    , targetHost_(targetHost)
    , targetPort_(targetPort)
{}

Relay::~Relay() {
    stop();
}

void Relay::start() {
    // Run the connection + pump in a detached thread.
    // The relay will clean itself up when done.
    std::thread([this]() { run(); }).detach();
}

void Relay::run() {
    running_ = true;

    // Build the tunnel endpoint URL
    std::string tunnelUrl = workerUrl_;
    if (!tunnelUrl.ends_with("/")) tunnelUrl += "/";
    tunnelUrl += "tunnel";

    spdlog::info("Relay: connecting to worker {} for {}:{}", tunnelUrl, targetHost_, targetPort_);

    if (!ws_.connect(tunnelUrl)) {
        spdlog::error("Relay: WebSocket connection failed for {}:{}", targetHost_, targetPort_);
        closesocket(clientSock_);
        delete this;
        return;
    }

    // Send connect command
    std::string connectCmd = std::format(
        R"({{"cmd":"connect","host":"{}","port":{}}})",
        targetHost_, targetPort_);

    if (!ws_.sendText(connectCmd)) {
        spdlog::error("Relay: failed to send connect command");
        closesocket(clientSock_);
        delete this;
        return;
    }

    // Wait for connected response
    std::vector<uint8_t> resp;
    bool isText = false;
    int n = ws_.receive(resp, isText);
    if (n <= 0) {
        spdlog::error("Relay: no response from worker");
        closesocket(clientSock_);
        delete this;
        return;
    }

    std::string respStr(resp.begin(), resp.end());
    if (respStr.find("\"connected\"") == std::string::npos) {
        spdlog::error("Relay: worker refused connection: {}", respStr);
        closesocket(clientSock_);
        delete this;
        return;
    }

    spdlog::info("Relay: tunnel established for {}:{}", targetHost_, targetPort_);

    // Start bidirectional pumps
    sockToWs_ = std::thread([this]() { pumpSockToWs(); });
    wsToSock_ = std::thread([this]() { pumpWsToSock(); });

    // Wait for both to finish
    if (sockToWs_.joinable()) sockToWs_.join();
    if (wsToSock_.joinable()) wsToSock_.join();

    spdlog::info("Relay: connection closed for {}:{}", targetHost_, targetPort_);
    closesocket(clientSock_);
    delete this;
}

void Relay::pumpSockToWs() {
    uint8_t buf[8192];

    while (running_) {
        int n = recv(clientSock_, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) {
            spdlog::debug("Relay: TCP socket closed/error (recv={})", n);
            stop();
            return;
        }

        if (!ws_.sendBinary(buf, n)) {
            spdlog::debug("Relay: WebSocket send failed");
            stop();
            return;
        }
    }
}

void Relay::pumpWsToSock() {
    std::vector<uint8_t> buf;
    bool isText = false;

    while (running_) {
        int n = ws_.receive(buf, isText);
        if (n <= 0) {
            spdlog::debug("Relay: WebSocket closed/error (recv={})", n);
            stop();
            return;
        }

        // Send all received data to the TCP socket
        const char* ptr = reinterpret_cast<const char*>(buf.data());
        int remaining = n;

        while (remaining > 0 && running_) {
            int sent = send(clientSock_, ptr, remaining, 0);
            if (sent <= 0) {
                spdlog::debug("Relay: TCP socket send failed");
                stop();
                return;
            }
            ptr += sent;
            remaining -= sent;
        }
    }
}

void Relay::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        ws_.close();
        // Shutdown the TCP socket to unblock recv/send
        shutdown(clientSock_, SD_BOTH);
    }
}
