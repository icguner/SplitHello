#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace transparent {

// Canonical binary peer address shared by the packet loop and the registries.
// IPv4 is stored as the IPv4-mapped IPv6 form, so "1.2.3.4" and "::ffff:1.2.3.4"
// compare equal and no text is built on the packet hot path.
using Address = std::array<uint8_t, 16>;

// `bytes` points at 4 (IPv4) or 16 (IPv6) network-order address bytes.
Address addressFromBytes(const void* bytes, bool ipv6);
// Parses inet_ntop-style text (dotted quad or IPv6). False when malformed.
bool parseAddress(const std::string& text, Address& out);

struct PeerKey {
    Address address{};
    uint16_t port = 0;
    uint8_t kind = 0;

    bool operator==(const PeerKey&) const = default;
};

struct PeerKeyHash {
    size_t operator()(const PeerKey& key) const noexcept;
};

struct Target {
    std::string address;
    uint16_t targetPort = 443;
    uint16_t connectPort = 0;
};

// The network-layer reflector makes the original server address appear as the
// accepted socket's peer address and preserves the application's source port.
// This short-lived registry proves that an accepted connection really came
// from a SYN observed by WinDivert and carries the original destination into
// the relay without putting metadata in the TLS stream.
class FlowRegistry {
public:
    void observe(const std::string& serverAddress, uint16_t clientPort,
                 uint16_t targetPort, uint16_t connectPort,
                 uint64_t nowMs = 0);

    std::optional<Target> claim(const std::string& peerAddress,
                                uint16_t peerPort,
                                uint64_t nowMs = 0);

    size_t size(uint64_t nowMs = 0);
    void clear();

private:
    struct Entry {
        Target target;
        uint64_t expiresAtMs = 0;
    };

    void pruneLocked(uint64_t nowMs);

    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    uint64_t nextPruneMs_ = 0;
};

// UDP DNS clients commonly reuse one socket for several concurrent queries.
// Keep a bounded pending count for each reflected DNS-server/client-port tuple
// instead of consuming the whole tuple after the first datagram.
class DatagramRegistry {
public:
    void observe(const std::string& serverAddress, uint16_t clientPort,
                 uint64_t nowMs = 0);
    bool claim(const std::string& peerAddress, uint16_t peerPort,
               uint64_t nowMs = 0);

    size_t size(uint64_t nowMs = 0);
    void clear();

private:
    struct Entry {
        uint32_t pending = 0;
        uint64_t expiresAtMs = 0;
    };

    void pruneLocked(uint64_t nowMs);

    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    uint64_t nextPruneMs_ = 0;
};

// Live TCP tuples the packet loop has rewritten. Only packets of a tuple that
// was added on its SYN are rewritten afterwards; everything else (connections
// that predate the engine, flows a process rule left alone, foreign traffic
// that happens to use a SplitHello port) is forwarded untouched.
//   Client   - application <-> relay, keyed by (server address, client port)
//   Upstream - relay <-> server,      keyed by (server address, relay port)
// An entry lives until RST, a short grace period after FIN, or a long idle
// timeout; every packet refreshes it, so a quiet but live connection is never
// dropped from the table.
class TcpFlowTable {
public:
    enum class Kind : uint8_t { Client = 1, Upstream = 2 };

    void add(Kind kind, const Address& server, uint16_t localPort,
             uint64_t nowMs = 0);
    // True when the tuple is live. Refreshes it; RST removes it (the RST
    // packet itself still counts as belonging to the flow).
    bool track(Kind kind, const Address& server, uint16_t localPort,
               bool fin, bool rst, uint64_t nowMs = 0);
    void remove(Kind kind, const Address& server, uint16_t localPort);

    size_t size() const;
    void clear();

private:
    struct Entry {
        uint64_t expiresAtMs = 0;
        bool closing = false;
    };

    void makeRoomLocked(uint64_t nowMs);

    mutable std::mutex mutex_;
    std::unordered_map<PeerKey, Entry, PeerKeyHash> entries_;
    uint64_t nextSweepMs_ = 0;
};

enum class PacketRoute {
    Pass,
    ReflectClientToProxy,
    ReflectProxyToClient,
    RedirectProxyToTarget,
    RedirectTargetToProxy,
};

// Pure routing decision shared by the WinDivert loop and unit tests. Ports are
// in host byte order. It only classifies by port; the caller must still check
// that the tuple is a tracked flow (TcpFlowTable) before rewriting.
PacketRoute routePacket(bool outbound, uint16_t sourcePort,
                        uint16_t destinationPort, uint16_t targetPort,
                        uint16_t proxyPort, uint16_t connectPort);

enum class DatagramRoute {
    Pass,
    ReflectDnsToProxy,
    ReflectProxyToClient,
};

DatagramRoute routeDatagram(bool outbound, uint16_t sourcePort,
                            uint16_t destinationPort, uint16_t dnsPort,
                            uint16_t proxyPort);

} // namespace transparent
