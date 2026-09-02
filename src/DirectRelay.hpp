#pragma once

#include "Diagnosis.hpp"
#include "Dns.hpp"
#include "LiveStats.hpp"
#include "Strategy.hpp"
#include "TlsHello.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

namespace packet_strategy { class PolicyRegistry; }
namespace telemetry { class Store; }
class Relay;

// Shared, read-only state handed to every connection.
struct RelayContext {
    std::string workerUrl;
    std::string sharedSecret;
    std::string networkId = "network-default";
    dns::Resolver* resolver = nullptr;
    strategy::Store* strategies = nullptr;
    packet_strategy::PolicyRegistry* packetPolicies = nullptr;
    std::shared_ptr<telemetry::Store> telemetry;
    std::shared_ptr<live_stats::Publisher> liveStats;
    unsigned splitDelayMs = 20;
    unsigned probeTimeoutMs = 3000;
    bool tunnelFallback = false;
    uint16_t bypassConnectPort = 0;

    // An established connection that moves no bytes in either direction for
    // this long is closed. Abandoned flows would otherwise hold a thread, two
    // sockets and their buffers for as long as the process lives.
    unsigned idleTimeoutMs = 10 * 60 * 1000;

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
//
// The whole connection is served on the thread that calls run(): handshake,
// probing and the bidirectional pump. There are no detached threads and no
// self-deletion, so the owner (SocksProxy) can abort the connection with
// stop() and know exactly when it has finished.
class DirectRelay {
public:
    // Takes ownership of clientSock.
    DirectRelay(SOCKET clientSock, const RelayContext& context,
                std::string targetHost, uint16_t targetPort,
                std::string originalTargetAddress = {},
                uint16_t connectPort = 0);
    ~DirectRelay();

    DirectRelay(const DirectRelay&) = delete;
    DirectRelay& operator=(const DirectRelay&) = delete;

    // Serves the connection on the calling thread and returns once it has
    // ended. Both sockets are closed by the time it returns.
    void run();

    // Aborts the connection from another thread. Safe to call at any point,
    // including before run() and after it returned; run() then unwinds within
    // a bounded time (the longest single wait is a connect attempt).
    void stop();

private:
    SOCKET clientSock_;
    SOCKET targetSock_ = INVALID_SOCKET;
    RelayContext context_;
    live_stats::Flow liveFlow_;
    std::string targetHost_;
    uint16_t targetPort_;
    std::string originalTargetAddress_;
    uint16_t connectPort_;

    std::vector<std::string> candidates_;   // resolved addresses, in connect order
    std::string connectedAddress_;

    std::vector<uint8_t> clientBuffer_;     // ClientHello (+ anything trailing it)
    tls::ClientHello hello_;
    bool helloComplete_ = false;
    std::vector<uint8_t> firstResponse_;    // target bytes read during probing
    std::string activeProfile_ = "none";

    // Handle values change while probing (every retry reconnects) and are
    // cleared at the end. stop() runs on a foreign thread, so every mutation
    // and every shutdown() of a handle happens under this mutex; otherwise a
    // recycled handle value could be shut down under a different connection.
    std::mutex socketMutex_;
    std::atomic<bool> stopping_{false};
    Relay* tunnel_ = nullptr;               // guarded by socketMutex_

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

    // Last resort: hand the connection to the Worker's WebSocket relay. Runs
    // the tunnel on this thread and takes ownership of clientSock_ on success.
    bool handOffToTunnel();

    void setNoDelay(bool enabled);

    // Moves bytes in both directions on this thread until either side has
    // finished, an error occurs, the idle timeout expires or stop() is called.
    void pump();

    // The handshake buffers are only needed until the first bytes are
    // flowing; an established connection should not pin 100 KiB for hours.
    void releaseHandshakeBuffers();
    void closeSockets();
};
