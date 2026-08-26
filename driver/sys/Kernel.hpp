#pragma once

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>

#include "../shared/PacketCore.hpp"
#include "../shared/Protocol.hpp"

namespace splithello::kernel {

inline constexpr ULONG kPoolTag = 'HlpS';
inline constexpr Size kMaximumPacketBytes = 0xFFFFU;

struct ConfigurationLease {
    const wfp::Configuration* value = nullptr;
    void* snapshot = nullptr;
};

void InitializeState() noexcept;
void ShutdownState() noexcept;
[[nodiscard]] NTSTATUS SetConfiguration(
    const wfp::Configuration& configuration) noexcept;
[[nodiscard]] ConfigurationLease AcquireConfiguration() noexcept;
void ReleaseConfiguration(ConfigurationLease* lease) noexcept;
[[nodiscard]] bool IsActive() noexcept;
void SetActive(bool active) noexcept;
[[nodiscard]] U16 FastDnsProxyPort() noexcept;
[[nodiscard]] wfp::QuicMode FastQuicMode() noexcept;

[[nodiscard]] bool ProcessMatches(const wfp::Configuration& configuration,
                                  const FWP_BYTE_BLOB* applicationId) noexcept;
[[nodiscard]] NTSTATUS ArmPolicy(const wfp::PolicyCommand& command) noexcept;
[[nodiscard]] bool TakePolicy(wfp::AddressFamily family,
                              const U8* remoteAddress,
                              U16 localPort,
                              wfp::PolicyCommand* command) noexcept;
[[nodiscard]] bool HasPolicy(wfp::AddressFamily family,
                             const U8* remoteAddress,
                             U16 localPort) noexcept;
void ObserveTcpHop(wfp::AddressFamily family,
                   const U8* remoteAddress,
                   U16 localPort,
                   U8 receivedTtl) noexcept;

void RememberSelectedUdp(wfp::AddressFamily family,
                         const U8* localAddress,
                         U16 localPort,
                         const U8* remoteAddress,
                         U16 remotePort) noexcept;
[[nodiscard]] bool IsSelectedUdp(wfp::AddressFamily family,
                                 const U8* localAddress,
                                 U16 localPort,
                                 const U8* remoteAddress,
                                 U16 remotePort) noexcept;
void RememberSelectedTcp(wfp::AddressFamily family,
                         const U8* localAddress,
                         U16 localPort,
                         const U8* remoteAddress) noexcept;
[[nodiscard]] bool IsSelectedTcp(wfp::AddressFamily family,
                                 const U8* localAddress,
                                 U16 localPort,
                                 const U8* remoteAddress) noexcept;
void RememberDnsQuery(wfp::AddressFamily family,
                      const U8* clientAddress,
                      U16 clientPort,
                      const U8* resolverAddress,
                      U16 transactionId,
                      COMPARTMENT_ID compartment,
                      U32 interfaceIndex,
                      U32 subInterfaceIndex) noexcept;
[[nodiscard]] bool TakeDnsQuery(wfp::AddressFamily family,
                                U16 clientPortToken,
                                U16 transactionId,
                                U8* clientAddress,
                                U16* clientPort,
                                U8* resolverAddress,
                                COMPARTMENT_ID* compartment,
                                U32* interfaceIndex,
                                U32* subInterfaceIndex) noexcept;

[[nodiscard]] bool AdaptiveQuicShouldBlock(wfp::AddressFamily family,
                                           const U8* remoteAddress,
                                           U16 localPort) noexcept;
void ObserveQuicResponse(wfp::AddressFamily family,
                         const U8* remoteAddress,
                         U16 localPort) noexcept;

enum class Counter : U32 {
    Classified,
    Permitted,
    RedirectedTcp,
    RedirectedDns,
    BlockedQuic,
    PrimedQuic,
    PoliciesArmed,
    PoliciesApplied,
    SelfInjected,
    Malformed,
    Unsupported,
    AllocationFailures,
    InjectionFailures,
    QueueFull,
};

void Increment(Counter counter) noexcept;
[[nodiscard]] bool BeginInjection() noexcept;
void EndInjection() noexcept;
void QueryStatistics(wfp::Statistics* statistics) noexcept;
void ResetStatistics() noexcept;
void WaitForInjections() noexcept;

[[nodiscard]] NTSTATUS InitializeDataPath(PDEVICE_OBJECT deviceObject) noexcept;
void ShutdownDataPath() noexcept;

void NTAPI ClassifyRedirect(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER2* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut);
void NTAPI ClassifyAuthorize(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER2* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut);
void NTAPI ClassifyOutbound(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER2* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut);
void NTAPI ClassifyInbound(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER2* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut);
NTSTATUS NTAPI NotifyCallout(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                            const GUID* filterKey,
                            FWPS_FILTER2* filter);

}  // namespace splithello::kernel
