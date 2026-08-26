#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace transparent {

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
};

enum class PacketRoute {
    Pass,
    ReflectClientToProxy,
    ReflectProxyToClient,
    RedirectProxyToTarget,
    RedirectTargetToProxy,
};

// Pure routing decision shared by the WinDivert loop and unit tests. Ports are
// in host byte order.
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
