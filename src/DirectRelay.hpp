#pragma once

#include "Diagnosis.hpp"
#include "Dns.hpp"
#include "LiveStats.hpp"
#include "Strategy.hpp"
#include "TlsHello.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

namespace packet_strategy { struct Policy; }
namespace telemetry { class Store; }

// Shared, read-only state handed to every connection.
struct RelayContext {
    std::string workerUrl;
    std::string sharedSecret;
    std::string networkId = "network-default";
    dns::Resolver* resolver = nullptr;
    strategy::Store* strategies = nullptr;
    std::function<bool(const std::string&, uint16_t,
                       const packet_strategy::Policy&)> armPacketPolicy;
    std::shared_ptr<telemetry::Store> telemetry;
    std::shared_ptr<live_stats::Publisher> liveStats;
    unsigned splitDelayMs = 20;
    unsigned probeTimeoutMs = 3000;
    bool tunnelFallback = false;
    uint16_t bypassConnectPort = 0;

    // When set, this profile is used for every connection and nothing is
    // probed or learned. Debugging aid for comparing profiles on one network.
    std::string forcedProfile;
};

// One proxied TCP connection.
//
// Reuses the transparently resolved target when available, connects straight
// to it, and runs an untouched differential baseline before trying bounded
// packet/TLS transformations. A learned winner is promoted on later flows.
//
// The ClientHello is buffered until it is *complete* before anything is cut:
// a browser can deliver it across several reads, and post-quantum key shares
// push it well past a single segment. If a profile does not get a reply, the
// connection is retried with the next one and a proven bypass winner is
// remembered for that network and domain.
class DirectRelay {
public:
    DirectRelay(SOCKET clientSock, const RelayContext& context,
                std::string targetHost, uint16_t targetPort,
                std::string originalTargetAddress = {},
                uint16_t connectPort = 0,
                std::vector<uint8_t> redirectRecords = {},
                int redirectRecordFamily = AF_UNSPEC);
    ~DirectRelay();

    DirectRelay(const DirectRelay&) = delete;
    DirectRelay& operator=(const DirectRelay&) = delete;

    // Runs on a detached thread and deletes itself when the connection ends.
    void start();

private:
    SOCKET clientSock_;
    SOCKET targetSock_ = INVALID_SOCKET;
    RelayContext context_;
    live_stats::Flow liveFlow_;
    std::string targetHost_;
    uint16_t targetPort_;
    std::string originalTargetAddress_;
    uint16_t connectPort_;
    std::vector<uint8_t> redirectRecords_;
    int redirectRecordFamily_ = AF_UNSPEC;

    std::vector<std::string> candidates_;   // resolved addresses, in connect order
    std::string connectedAddress_;

    std::vector<uint8_t> clientBuffer_;     // ClientHello (+ anything trailing it)
    tls::ClientHello hello_;
    bool helloComplete_ = false;
    std::vector<uint8_t> firstResponse_;    // target bytes read during probing
    std::string activeProfile_ = "none";

    std::atomic<bool> running_{false};
    std::thread clientToTarget_;
    std::thread targetToClient_;

    void run();

    bool prepareCandidates();
    bool connectTarget();
    bool reconnect();

    // Reads from the client until a complete ClientHello is buffered, the data
    // is clearly not TLS, or the client goes quiet. False means the client
    // hung up with nothing useful.
    bool collectClientHello();

    // Applies profiles in order until one draws a reply. False if none did.
    bool deliverHello();
    void recordTelemetry(const std::vector<diagnosis::Attempt>& evidence,
                         const diagnosis::Verdict& verdict,
                         const std::string& rememberedProfile,
                         bool success, uint64_t totalElapsedMs);

    bool writePlan(const strategy::FragmentPlan& plan);
    bool writeFragmented(const strategy::FragmentPlan& plan);
    diagnosis::ProbeSignal awaitResponse(std::vector<uint8_t>& out);
    bool flushTrailingClientData();

    // Last resort: hand the connection to the Worker's WebSocket relay.
    // Takes ownership of clientSock_ on success.
    bool handOffToTunnel();

    void setNoDelay(bool enabled);

    void pumpClientToTarget();
    void pumpTargetToClient();

    void stop();
};
