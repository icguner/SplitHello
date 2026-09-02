#include "Relay.hpp"

#include "Json.hpp"
#include "TcpConnect.hpp"

#include <spdlog/spdlog.h>

#include <format>
#include <system_error>

Relay::Relay(SOCKET clientSock, std::string workerUrl, std::string sharedSecret,
             std::string targetHost, uint16_t targetPort,
             std::vector<uint8_t> initialData,
             uint16_t workerConnectPort)
    : clientSock_(clientSock)
    , workerUrl_(std::move(workerUrl))
    , sharedSecret_(std::move(sharedSecret))
    , targetHost_(std::move(targetHost))
    , targetPort_(targetPort)
    , workerConnectPort_(workerConnectPort)
    , initialData_(std::move(initialData)) {}

Relay::~Relay() {
    stop();
    if (sockToWs_.joinable()) sockToWs_.join();
    if (clientSock_ != INVALID_SOCKET) {
        closesocket(clientSock_);
        clientSock_ = INVALID_SOCKET;
    }
}

void Relay::run() {
    if (stopping_) return;

    std::string tunnelUrl = workerUrl_;
    if (!tunnelUrl.ends_with("/")) tunnelUrl += "/";
    tunnelUrl += "tunnel";

    spdlog::info("Tunel: {} -> {}:{}", tunnelUrl, targetHost_, targetPort_);

    std::vector<std::pair<std::string, std::string>> headers;
    if (!sharedSecret_.empty()) {
        headers.push_back({"Authorization", "Bearer " + sharedSecret_});
    }

    const auto fail = [this](const char* reason) {
        spdlog::error("Tunel hatasi ({}): {}:{}", reason, targetHost_, targetPort_);
    };

    if (!ws_.connect(tunnelUrl, headers, workerConnectPort_)) { fail("baglanti"); return; }
    if (stopping_) return;

    const std::string command = std::format(
        R"({{"cmd":"connect","host":"{}","port":{}}})",
        json::escape(targetHost_), targetPort_);

    if (!ws_.sendText(command)) { fail("connect komutu"); return; }

    std::vector<uint8_t> response;
    bool isText = false;
    if (ws_.receive(response, isText) <= 0) { fail("yanit yok"); return; }

    const std::string responseText(response.begin(), response.end());
    if (responseText.find("\"connected\"") == std::string::npos) {
        spdlog::error("Tunel reddedildi: {}", responseText);
        fail("reddedildi");
        return;
    }

    // Replay what the client already sent before we fell back to the tunnel.
    if (!initialData_.empty() && !ws_.sendBinary(initialData_.data(), initialData_.size())) {
        fail("ilk veri");
        return;
    }
    std::vector<uint8_t>().swap(initialData_);

    spdlog::info("Tunel kuruldu: {}:{}", targetHost_, targetPort_);

    try {
        sockToWs_ = std::thread([this]() { pumpSockToWs(); });
    } catch (const std::system_error& error) {
        spdlog::error("Tunel is parcacigi baslatilamadi: {}", error.what());
        return;
    }

    pumpWsToSock();

    // Whichever direction ended first already called stop(); make sure the
    // other one is unblocked before waiting for it.
    stop();
    if (sockToWs_.joinable()) sockToWs_.join();

    spdlog::debug("Tunel kapandi: {}:{}", targetHost_, targetPort_);
}

void Relay::pumpSockToWs() {
    std::vector<uint8_t> buffer(32 * 1024);

    while (!stopping_) {
        const int received = recv(clientSock_, (char*)buffer.data(), (int)buffer.size(), 0);
        if (received <= 0) break;
        if (!ws_.sendBinary(buffer.data(), (size_t)received)) break;
    }
    stop();
}

void Relay::pumpWsToSock() {
    std::vector<uint8_t> buffer;
    bool isText = false;

    while (!stopping_) {
        const int received = ws_.receive(buffer, isText);
        if (received <= 0) break;
        if (!tcp::sendAll(clientSock_, buffer.data(), (size_t)received)) break;
    }
    stop();
}

void Relay::stop() {
    bool expected = false;
    if (!stopping_.compare_exchange_strong(expected, true)) return;
    ws_.close();
    if (clientSock_ != INVALID_SOCKET) shutdown(clientSock_, SD_BOTH);
}
