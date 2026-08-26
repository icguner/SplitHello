#include "Kernel.hpp"

#include "../shared/Identifiers.hpp"

namespace splithello::kernel {
namespace {

struct InjectionAllocation {
    NET_BUFFER_LIST* nbl = nullptr;
    MDL* mdl = nullptr;
    U8* bytes = nullptr;
};

EX_RUNDOWN_REF gClassifyRundown{};
volatile LONG gStopping = TRUE;
volatile LONG gDataPathInitialized = FALSE;
HANDLE gRedirectHandle = nullptr;
HANDLE gNetworkV4Handle = nullptr;
HANDLE gNetworkV6Handle = nullptr;
NDIS_HANDLE gNblPool = nullptr;

void Permit(FWPS_CLASSIFY_OUT0* classifyOut) noexcept {
    if (classifyOut != nullptr &&
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }
}

void Continue(FWPS_CLASSIFY_OUT0* classifyOut) noexcept {
    if (classifyOut != nullptr &&
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

void Block(FWPS_CLASSIFY_OUT0* classifyOut) noexcept {
    if (classifyOut != nullptr &&
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

bool CanWrite(const FWPS_CLASSIFY_OUT0* classifyOut) noexcept {
    return classifyOut != nullptr &&
           (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0;
}

bool Enter() noexcept {
    if (InterlockedCompareExchange(&gStopping, FALSE, FALSE) != FALSE ||
        !IsActive() ||
        ExAcquireRundownProtection(&gClassifyRundown) == FALSE) return false;
    if (InterlockedCompareExchange(&gStopping, FALSE, FALSE) != FALSE ||
        !IsActive()) {
        ExReleaseRundownProtection(&gClassifyRundown);
        return false;
    }
    return true;
}

void Leave() noexcept {
    ExReleaseRundownProtection(&gClassifyRundown);
}

wfp::AddressFamily FamilyFromLayer(UINT16 layerId) noexcept {
    switch (layerId) {
        case FWPS_LAYER_ALE_CONNECT_REDIRECT_V6:
        case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
        case FWPS_LAYER_INBOUND_IPPACKET_V6:
            return wfp::AddressFamily::Ipv6;
        default:
            return wfp::AddressFamily::Ipv4;
    }
}

void CopyV4(U8* destination, U32 address) noexcept {
    destination[0] = static_cast<U8>(address >> 24);
    destination[1] = static_cast<U8>(address >> 16);
    destination[2] = static_cast<U8>(address >> 8);
    destination[3] = static_cast<U8>(address);
}

void CopyV6(U8* destination, const FWP_BYTE_ARRAY16* address) noexcept {
    if (address != nullptr) RtlCopyMemory(destination, address->byteArray16, 16);
}

bool ReadAleTuple(const FWPS_INCOMING_VALUES0* values,
                  wfp::AddressFamily family,
                  bool redirectLayer,
                  U8* localAddress,
                  U16* localPort,
                  U8* remoteAddress,
                  U16* remotePort,
                  U8* protocol,
                  const FWP_BYTE_BLOB** applicationId) noexcept {
    if (values == nullptr || localAddress == nullptr || localPort == nullptr ||
        remoteAddress == nullptr || remotePort == nullptr || protocol == nullptr ||
        applicationId == nullptr) return false;
    UINT localAddressField = 0;
    UINT localPortField = 0;
    UINT remoteAddressField = 0;
    UINT remotePortField = 0;
    UINT protocolField = 0;
    UINT appIdField = 0;
    if (family == wfp::AddressFamily::Ipv4) {
        if (redirectLayer) {
            localAddressField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS;
            localPortField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT;
            remoteAddressField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS;
            remotePortField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT;
            protocolField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL;
            appIdField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ALE_APP_ID;
        } else {
            localAddressField = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
            localPortField = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
            remoteAddressField = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
            remotePortField = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
            protocolField = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
            appIdField = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID;
        }
        CopyV4(localAddress, values->incomingValue[localAddressField].value.uint32);
        CopyV4(remoteAddress, values->incomingValue[remoteAddressField].value.uint32);
    } else {
        if (redirectLayer) {
            localAddressField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_ADDRESS;
            localPortField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT;
            remoteAddressField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS;
            remotePortField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT;
            protocolField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL;
            appIdField = FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ALE_APP_ID;
        } else {
            localAddressField = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS;
            localPortField = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT;
            remoteAddressField = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS;
            remotePortField = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT;
            protocolField = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL;
            appIdField = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID;
        }
        CopyV6(localAddress, values->incomingValue[localAddressField].value.byteArray16);
        CopyV6(remoteAddress, values->incomingValue[remoteAddressField].value.byteArray16);
    }
    *localPort = values->incomingValue[localPortField].value.uint16;
    *remotePort = values->incomingValue[remotePortField].value.uint16;
    *protocol = values->incomingValue[protocolField].value.uint8;
    const auto& appValue = values->incomingValue[appIdField].value;
    *applicationId = appValue.type == FWP_BYTE_BLOB_TYPE ? appValue.byteBlob : nullptr;
    return true;
}

bool IsProxyProcess(const FWPS_INCOMING_METADATA_VALUES0* metadata,
                    U32 processId) noexcept {
    return metadata != nullptr &&
           (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0 &&
           metadata->processId == processId;
}

bool HasProcessId(const FWPS_INCOMING_METADATA_VALUES0* metadata) noexcept {
    return metadata != nullptr &&
           (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) != 0;
}

bool IsLoopback(wfp::AddressFamily family, const U8* address) noexcept {
    if (address == nullptr) return false;
    if (family == wfp::AddressFamily::Ipv4) return address[0] == 127;
    bool zeroPrefix = true;
    for (Size index = 0; index < 15; ++index) {
        if (address[index] != 0) {
            zeroPrefix = false;
            break;
        }
    }
    if (zeroPrefix && address[15] == 1) return true;
    for (Size index = 0; index < 10; ++index) {
        if (address[index] != 0) return false;
    }
    return address[10] == 0xFF && address[11] == 0xFF &&
           address[12] == 127;
}

bool IsLocalNetwork(wfp::AddressFamily family, const U8* address) noexcept {
    if (address == nullptr || IsLoopback(family, address)) return true;
    if (family == wfp::AddressFamily::Ipv4) {
        return address[0] == 0 || address[0] == 10 ||
               (address[0] == 100 && (address[1] & 0xC0U) == 0x40U) ||
               (address[0] == 169 && address[1] == 254) ||
               (address[0] == 172 && (address[1] & 0xF0U) == 16U) ||
               (address[0] == 192 && address[1] == 168) ||
               address[0] >= 224;
    }
    bool mapped = true;
    for (Size index = 0; index < 10; ++index) {
        if (address[index] != 0) {
            mapped = false;
            break;
        }
    }
    if (mapped && address[10] == 0xFF && address[11] == 0xFF) {
        return IsLocalNetwork(wfp::AddressFamily::Ipv4, address + 12);
    }
    bool unspecified = true;
    for (Size index = 0; index < 16; ++index) {
        if (address[index] != 0) {
            unspecified = false;
            break;
        }
    }
    return unspecified || (address[0] & 0xFEU) == 0xFCU ||
           (address[0] == 0xFE && (address[1] & 0xC0U) == 0x80U) ||
           address[0] == 0xFF;
}

void StoreRedirectAddress(wfp::RedirectContext* context,
                          const SOCKADDR_STORAGE* address) noexcept {
    if (address->ss_family == AF_INET) {
        const auto* v4 = reinterpret_cast<const SOCKADDR_IN*>(address);
        context->family = wfp::AddressFamily::Ipv4;
        context->targetPort = RtlUshortByteSwap(v4->sin_port);
        RtlCopyMemory(context->targetAddress, &v4->sin_addr, 4);
    } else {
        const auto* v6 = reinterpret_cast<const SOCKADDR_IN6*>(address);
        context->family = wfp::AddressFamily::Ipv6;
        context->targetPort = RtlUshortByteSwap(v6->sin6_port);
        RtlCopyMemory(context->targetAddress, &v6->sin6_addr, 16);
    }
}

void SetLoopbackTarget(FWPS_CONNECT_REQUEST0* request,
                       wfp::AddressFamily family, U16 proxyPort) noexcept {
    RtlZeroMemory(&request->remoteAddressAndPort, sizeof(SOCKADDR_STORAGE));
    if (family == wfp::AddressFamily::Ipv4) {
        auto* address = reinterpret_cast<SOCKADDR_IN*>(&request->remoteAddressAndPort);
        address->sin_family = AF_INET;
        address->sin_port = RtlUshortByteSwap(proxyPort);
        address->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7F000001U);
    } else {
        auto* address = reinterpret_cast<SOCKADDR_IN6*>(&request->remoteAddressAndPort);
        address->sin6_family = AF_INET6;
        address->sin6_port = RtlUshortByteSwap(proxyPort);
        address->sin6_addr.u.Byte[15] = 1;
    }
}

InjectionAllocation* AllocatePacket(Size length) noexcept {
    if (length == 0 || length > kMaximumPacketBytes || !BeginInjection()) return nullptr;
    auto* allocation = static_cast<InjectionAllocation*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(InjectionAllocation), kPoolTag));
    if (allocation == nullptr) {
        EndInjection();
        Increment(Counter::AllocationFailures);
        return nullptr;
    }
    RtlZeroMemory(allocation, sizeof(*allocation));
    allocation->bytes = static_cast<U8*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, length, kPoolTag));
    if (allocation->bytes != nullptr) {
        allocation->mdl = IoAllocateMdl(allocation->bytes,
                                        static_cast<ULONG>(length),
                                        FALSE, FALSE, nullptr);
    }
    if (allocation->mdl != nullptr) {
        MmBuildMdlForNonPagedPool(allocation->mdl);
        allocation->nbl = NdisAllocateNetBufferAndNetBufferList(
            gNblPool, 0, 0, allocation->mdl, 0, static_cast<ULONG>(length));
    }
    if (allocation->nbl == nullptr) {
        if (allocation->mdl != nullptr) IoFreeMdl(allocation->mdl);
        if (allocation->bytes != nullptr) ExFreePoolWithTag(allocation->bytes, kPoolTag);
        ExFreePoolWithTag(allocation, kPoolTag);
        EndInjection();
        Increment(Counter::AllocationFailures);
        return nullptr;
    }
    return allocation;
}

void FreePacket(InjectionAllocation* allocation) noexcept {
    if (allocation == nullptr) return;
    if (allocation->nbl != nullptr) NdisFreeNetBufferList(allocation->nbl);
    if (allocation->mdl != nullptr) IoFreeMdl(allocation->mdl);
    if (allocation->bytes != nullptr) ExFreePoolWithTag(allocation->bytes, kPoolTag);
    ExFreePoolWithTag(allocation, kPoolTag);
    EndInjection();
}

void NTAPI InjectionComplete(void* context, NET_BUFFER_LIST* netBufferList,
                             BOOLEAN dispatchLevel) noexcept {
    UNREFERENCED_PARAMETER(netBufferList);
    UNREFERENCED_PARAMETER(dispatchLevel);
    FreePacket(static_cast<InjectionAllocation*>(context));
}

bool InjectSend(InjectionAllocation* allocation, wfp::AddressFamily family,
                COMPARTMENT_ID compartment) noexcept {
    if (allocation == nullptr) return false;
    const HANDLE handle = family == wfp::AddressFamily::Ipv4
                              ? gNetworkV4Handle : gNetworkV6Handle;
    const NTSTATUS status = FwpsInjectNetworkSendAsync0(
        handle, nullptr, 0, compartment, allocation->nbl,
        InjectionComplete, allocation);
    if (!NT_SUCCESS(status)) {
        Increment(Counter::InjectionFailures);
        FreePacket(allocation);
        return false;
    }
    return true;
}

bool InjectReceive(InjectionAllocation* allocation,
                   wfp::AddressFamily family,
                   COMPARTMENT_ID compartment,
                   U32 interfaceIndex,
                   U32 subInterfaceIndex) noexcept {
    if (allocation == nullptr) return false;
    const HANDLE handle = family == wfp::AddressFamily::Ipv4
                              ? gNetworkV4Handle : gNetworkV6Handle;
    const NTSTATUS status = FwpsInjectNetworkReceiveAsync0(
        handle, nullptr, 0, compartment, interfaceIndex, subInterfaceIndex,
        allocation->nbl, InjectionComplete, allocation);
    if (!NT_SUCCESS(status)) {
        Increment(Counter::InjectionFailures);
        FreePacket(allocation);
        return false;
    }
    return true;
}

bool CopyNetworkBuffer(NET_BUFFER_LIST* nbl, U8** bytes,
                       Size* length) noexcept {
    if (nbl == nullptr || bytes == nullptr || length == nullptr) return false;
    if (NET_BUFFER_LIST_NEXT_NBL(nbl) != nullptr) return false;
    auto* buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (buffer == nullptr || NET_BUFFER_NEXT_NB(buffer) != nullptr) return false;
    const ULONG packetLength = NET_BUFFER_DATA_LENGTH(buffer);
    if (packetLength == 0 || packetLength > kMaximumPacketBytes) return false;
    auto* copy = static_cast<U8*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, packetLength, kPoolTag));
    if (copy == nullptr) {
        Increment(Counter::AllocationFailures);
        return false;
    }
    const auto* contiguous = static_cast<const U8*>(
        NdisGetDataBuffer(buffer, packetLength, copy, 1, 0));
    if (contiguous == nullptr) {
        ExFreePoolWithTag(copy, kPoolTag);
        return false;
    }
    if (contiguous != copy) RtlCopyMemory(copy, contiguous, packetLength);
    *bytes = copy;
    *length = packetLength;
    return true;
}

bool ReadNetworkHeaders(NET_BUFFER_LIST* nbl,
                        packet::View* view) noexcept {
    if (nbl == nullptr || view == nullptr) return false;
    if (NET_BUFFER_LIST_NEXT_NBL(nbl) != nullptr) return false;
    auto* buffer = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (buffer == nullptr || NET_BUFFER_NEXT_NB(buffer) != nullptr) return false;
    constexpr ULONG kHeaderPrefixBytes = 256;
    const ULONG packetLength = NET_BUFFER_DATA_LENGTH(buffer);
    const ULONG prefixLength = packetLength < kHeaderPrefixBytes
                                   ? packetLength : kHeaderPrefixBytes;
    if (prefixLength == 0) return false;
    alignas(void*) U8 scratch[kHeaderPrefixBytes]{};
    const auto* prefix = static_cast<const U8*>(
        NdisGetDataBuffer(buffer, prefixLength, scratch, 1, 0));
    return prefix != nullptr &&
           packet::ParseHeaders(prefix, prefixLength, view) ==
               packet::ParseResult::Ok;
}

COMPARTMENT_ID Compartment(const FWPS_INCOMING_METADATA_VALUES0* metadata) noexcept {
    if (metadata != nullptr &&
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID) != 0) {
        return static_cast<COMPARTMENT_ID>(metadata->compartmentId);
    }
    return UNSPECIFIED_COMPARTMENT_ID;
}

void InterfaceIndexes(const FWPS_INCOMING_VALUES0* values,
                      wfp::AddressFamily family,
                      U32* interfaceIndex,
                      U32* subInterfaceIndex) noexcept {
    if (interfaceIndex == nullptr || subInterfaceIndex == nullptr) return;
    *interfaceIndex = 0;
    *subInterfaceIndex = 0;
    if (values == nullptr) return;
    if (family == wfp::AddressFamily::Ipv4) {
        *interfaceIndex = values->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
        *subInterfaceIndex = values->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;
    } else {
        *interfaceIndex = values->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_INTERFACE_INDEX].value.uint32;
        *subInterfaceIndex = values->incomingValue[
            FWPS_FIELD_OUTBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX].value.uint32;
    }
}

bool InjectTcpPolicy(const U8* packet, const packet::View& view,
                     const wfp::PolicyCommand& policy,
                     COMPARTMENT_ID compartment) noexcept {
    InjectionAllocation* packets[2]{};
    Size count = 0;
    auto addVariant = [&](const U8* payload, Size payloadLength,
                          I32 sequenceDelta, U8 ttl, bool badChecksum) -> bool {
        auto* allocation = AllocatePacket(view.payloadOffset + payloadLength);
        if (allocation == nullptr) return false;
        const Size built = packet::BuildTcpVariant(
            packet, view, payload, payloadLength, sequenceDelta, ttl,
            badChecksum, allocation->bytes, view.payloadOffset + payloadLength);
        if (built == 0) {
            FreePacket(allocation);
            return false;
        }
        NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(allocation->nbl)) =
            static_cast<ULONG>(built);
        packets[count++] = allocation;
        return true;
    };

    const U8* payload = packet + view.payloadOffset;
    const Size payloadLength = view.payloadLength;
    bool anyInjected = false;
    switch (policy.mode) {
        case wfp::PacketMode::None:
            return false;
        case wfp::PacketMode::ReverseOrder: {
            const Size split = policy.splitOffset < payloadLength
                                   ? policy.splitOffset : payloadLength / 2U;
            if (split == 0 || split >= payloadLength ||
                !addVariant(payload + split, payloadLength - split,
                            static_cast<I32>(split), 0, false) ||
                !addVariant(payload, split, 0, 0, false)) goto fail;
            break;
        }
        case wfp::PacketMode::SequenceOverlap: {
            const Size split = policy.splitOffset < payloadLength
                                   ? policy.splitOffset : payloadLength / 2U;
            packets[count] = AllocatePacket(view.packetLength);
            if (packets[count] == nullptr) goto fail;
            const Size overlapLength = packet::BuildTcpOverlapVariant(
                packet, view, split, policy.overlapBytes,
                policy.coverSni, policy.coverSniLength,
                packets[count]->bytes, view.packetLength);
            if (overlapLength == 0) goto fail;
            NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(packets[count]->nbl)) =
                static_cast<ULONG>(overlapLength);
            ++count;
            if (!addVariant(payload, split, 0, 0, false)) goto fail;
            break;
        }
        case wfp::PacketMode::FakeBadSequence:
        case wfp::PacketMode::FakeBadChecksum:
        case wfp::PacketMode::FakeAutoTtl: {
            U8 fake[384]{};
            Size fakeLength = packet::BuildFakeClientHello(
                policy.coverSni, policy.coverSniLength, fake, sizeof(fake));
            if (fakeLength == 0) goto fail;
            const bool badChecksum = policy.mode == wfp::PacketMode::FakeBadChecksum;
            const I32 sequenceDelta = policy.mode == wfp::PacketMode::FakeBadSequence
                                          ? policy.fakeSequenceDelta : 0;
            const U8 ttl = policy.mode == wfp::PacketMode::FakeAutoTtl
                               ? (policy.fakeTtl == 0 ? 3 : policy.fakeTtl) : 0;
            if (!addVariant(fake, fakeLength, sequenceDelta, ttl, badChecksum) ||
                !addVariant(payload, payloadLength, 0, 0, false)) goto fail;
            break;
        }
        case wfp::PacketMode::IpFragment: {
            if (view.family != 4) {
                const Size split = policy.splitOffset < payloadLength
                                       ? policy.splitOffset : payloadLength / 2U;
                if (split == 0 || split >= payloadLength ||
                    !addVariant(payload + split, payloadLength - split,
                                static_cast<I32>(split), 0, false) ||
                    !addVariant(payload, split, 0, 0, false)) goto fail;
                break;
            }
            packets[0] = AllocatePacket(view.packetLength);
            packets[1] = AllocatePacket(view.packetLength);
            if (packets[0] == nullptr || packets[1] == nullptr) goto fail;
            count = 2;
            Size firstLength = 0;
            Size secondLength = 0;
            if (!packet::BuildIpv4Fragments(
                    packet, view, view.payloadOffset + policy.splitOffset,
                    packets[0]->bytes, view.packetLength, &firstLength,
                    packets[1]->bytes, view.packetLength, &secondLength)) goto fail;
            NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(packets[0]->nbl)) =
                static_cast<ULONG>(firstLength);
            NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(packets[1]->nbl)) =
                static_cast<ULONG>(secondLength);
            break;
        }
        default:
            return false;
    }

    for (Size index = 0; index < count; ++index) {
        if (InjectSend(packets[index], policy.family, compartment)) anyInjected = true;
        packets[index] = nullptr;
    }
    return anyInjected;

fail:
    for (auto*& allocation : packets) {
        FreePacket(allocation);
        allocation = nullptr;
    }
    return false;
}

bool InjectDns(const U8* packet, const packet::View& view,
               U16 sourcePort, U16 destinationPort,
               const U8* sourceAddress,
               const U8* destinationAddress,
               COMPARTMENT_ID compartment,
               bool receive,
               U32 interfaceIndex = 0,
               U32 subInterfaceIndex = 0) noexcept {
    auto* allocation = AllocatePacket(view.packetLength);
    if (allocation == nullptr) return false;
    if (packet::BuildReflectedUdp(packet, view, sourcePort, destinationPort,
                                  allocation->bytes, view.packetLength) == 0) {
        FreePacket(allocation);
        return false;
    }
    if (sourceAddress != nullptr || destinationAddress != nullptr) {
        const Size length = view.family == 4 ? 4U : 16U;
        if (sourceAddress != nullptr) {
            const Size offset = view.family == 4 ? 12U : 8U;
            RtlCopyMemory(allocation->bytes + offset, sourceAddress, length);
        }
        if (destinationAddress != nullptr) {
            const Size offset = view.family == 4 ? 16U : 24U;
            RtlCopyMemory(allocation->bytes + offset, destinationAddress, length);
        }
        packet::RecalculateChecksums(allocation->bytes, view);
    }
    const auto family = view.family == 4 ? wfp::AddressFamily::Ipv4
                                         : wfp::AddressFamily::Ipv6;
    return receive
               ? InjectReceive(allocation, family, compartment,
                               interfaceIndex, subInterfaceIndex)
               : InjectSend(allocation, family, compartment);
}

U16 ReadTransactionId(const U8* packet, const packet::View& view) noexcept {
    if (view.payloadLength < 2) return 0;
    return static_cast<U16>((static_cast<U16>(packet[view.payloadOffset]) << 8) |
                            packet[view.payloadOffset + 1]);
}

}  // namespace

NTSTATUS InitializeDataPath(PDEVICE_OBJECT deviceObject) noexcept {
    UNREFERENCED_PARAMETER(deviceObject);
    ExInitializeRundownProtection(&gClassifyRundown);
    InterlockedExchange(&gStopping, TRUE);
    InterlockedExchange(&gDataPathInitialized, TRUE);

    NET_BUFFER_LIST_POOL_PARAMETERS parameters{};
    parameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    parameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    parameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    parameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    parameters.fAllocateNetBuffer = TRUE;
    parameters.PoolTag = kPoolTag;
    gNblPool = NdisAllocateNetBufferListPool(nullptr, &parameters);
    if (gNblPool == nullptr) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = FwpsInjectionHandleCreate0(AF_INET,
                                                 FWPS_INJECTION_TYPE_NETWORK,
                                                 &gNetworkV4Handle);
    if (NT_SUCCESS(status)) {
        status = FwpsInjectionHandleCreate0(AF_INET6,
                                            FWPS_INJECTION_TYPE_NETWORK,
                                            &gNetworkV6Handle);
    }
    if (NT_SUCCESS(status)) {
        status = FwpsRedirectHandleCreate0(&wfp::kProviderKey, 0, &gRedirectHandle);
    }
    if (!NT_SUCCESS(status)) {
        ShutdownDataPath();
        return status;
    }
    InterlockedExchange(&gStopping, FALSE);
    return STATUS_SUCCESS;
}

void ShutdownDataPath() noexcept {
    if (InterlockedExchange(&gDataPathInitialized, FALSE) == FALSE) return;
    InterlockedExchange(&gStopping, TRUE);
    ExWaitForRundownProtectionRelease(&gClassifyRundown);
    WaitForInjections();
    if (gRedirectHandle != nullptr) {
        FwpsRedirectHandleDestroy0(gRedirectHandle);
        gRedirectHandle = nullptr;
    }
    if (gNetworkV6Handle != nullptr) {
        FwpsInjectionHandleDestroy0(gNetworkV6Handle);
        gNetworkV6Handle = nullptr;
    }
    if (gNetworkV4Handle != nullptr) {
        FwpsInjectionHandleDestroy0(gNetworkV4Handle);
        gNetworkV4Handle = nullptr;
    }
    if (gNblPool != nullptr) {
        NdisFreeNetBufferListPool(gNblPool);
        gNblPool = nullptr;
    }
}

void NTAPI ClassifyRedirect(const FWPS_INCOMING_VALUES0* values,
                            const FWPS_INCOMING_METADATA_VALUES0* metadata,
                            void* layerData, const void* classifyContext,
                            const FWPS_FILTER2* filter, UINT64 flowContext,
                            FWPS_CLASSIFY_OUT0* classifyOut) {
    UNREFERENCED_PARAMETER(flowContext);
    Permit(classifyOut);
    if (values == nullptr || metadata == nullptr || layerData == nullptr ||
        classifyContext == nullptr || filter == nullptr ||
        !CanWrite(classifyOut) || !Enter()) return;
    Increment(Counter::Classified);
    auto lease = AcquireConfiguration();
    if (lease.value == nullptr) {
        Increment(Counter::Permitted);
        Leave();
        return;
    }
    const auto family = FamilyFromLayer(values->layerId);
    U8 localAddress[16]{};
    U8 remoteAddress[16]{};
    U16 localPort = 0;
    U16 remotePort = 0;
    U8 protocol = 0;
    const FWP_BYTE_BLOB* appId = nullptr;
    const bool candidate = ReadAleTuple(values, family, true, localAddress,
                                        &localPort, remoteAddress, &remotePort,
                                        &protocol, &appId) &&
                           protocol == IPPROTO_TCP && remotePort == 443 &&
                           !IsLocalNetwork(family, remoteAddress) &&
                           HasProcessId(metadata) &&
                           !IsProxyProcess(metadata, lease.value->proxyProcessId) &&
                           ProcessMatches(*lease.value, appId) &&
                           FwpsQueryConnectionRedirectState0(layerData,
                               gRedirectHandle, nullptr) ==
                               FWPS_CONNECTION_NOT_REDIRECTED;
    if (!candidate) {
        Increment(Counter::Permitted);
        ReleaseConfiguration(&lease);
        Leave();
        return;
    }

    UINT64 classifyHandle = 0;
    void* writableLayerData = nullptr;
    auto* context = static_cast<wfp::RedirectContext*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(wfp::RedirectContext), kPoolTag));
    NTSTATUS status = context == nullptr
                          ? STATUS_INSUFFICIENT_RESOURCES
                          : FwpsAcquireClassifyHandle0(
                                const_cast<void*>(classifyContext), 0,
                                &classifyHandle);
    if (NT_SUCCESS(status)) {
        status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle, filter->filterId, 0, &writableLayerData, classifyOut);
    }
    if (NT_SUCCESS(status) && writableLayerData != nullptr && context != nullptr) {
        RtlZeroMemory(context, sizeof(*context));
        context->header.size = sizeof(*context);
        context->header.version = wfp::kProtocolVersion;
        auto* request = static_cast<FWPS_CONNECT_REQUEST0*>(writableLayerData);
        StoreRedirectAddress(context, &request->remoteAddressAndPort);
        SetLoopbackTarget(request, family, lease.value->proxyPort);
        request->localRedirectHandle = gRedirectHandle;
        request->localRedirectTargetPID = lease.value->proxyProcessId;
        request->localRedirectContext = context;
        request->localRedirectContextSize = sizeof(*context);
        FwpsApplyModifiedLayerData0(classifyHandle, writableLayerData, 0);
        context = nullptr;
        Increment(Counter::RedirectedTcp);
    } else {
        Increment(Counter::Permitted);
    }
    if (context != nullptr) ExFreePoolWithTag(context, kPoolTag);
    if (classifyHandle != 0) FwpsReleaseClassifyHandle0(classifyHandle);
    ReleaseConfiguration(&lease);
    Leave();
}

void NTAPI ClassifyAuthorize(const FWPS_INCOMING_VALUES0* values,
                             const FWPS_INCOMING_METADATA_VALUES0* metadata,
                             void* layerData, const void* classifyContext,
                             const FWPS_FILTER2* filter, UINT64 flowContext,
                             FWPS_CLASSIFY_OUT0* classifyOut) {
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    Continue(classifyOut);
    if (values == nullptr || metadata == nullptr || !Enter()) return;
    Increment(Counter::Classified);
    auto lease = AcquireConfiguration();
    if (lease.value != nullptr) {
        const auto family = FamilyFromLayer(values->layerId);
        U8 localAddress[16]{};
        U8 remoteAddress[16]{};
        U16 localPort = 0;
        U16 remotePort = 0;
        U8 protocol = 0;
        const FWP_BYTE_BLOB* appId = nullptr;
        if (ReadAleTuple(values, family, false, localAddress, &localPort,
                         remoteAddress, &remotePort, &protocol, &appId) &&
            HasProcessId(metadata)) {
            if (protocol == IPPROTO_TCP && remotePort == 443 &&
                !IsLocalNetwork(family, remoteAddress) &&
                IsProxyProcess(metadata, lease.value->proxyProcessId)) {
                RememberSelectedTcp(family, localAddress, localPort,
                                    remoteAddress);
            } else if (protocol == IPPROTO_UDP &&
                       (remotePort == 53 || remotePort == 443) &&
                       !IsLoopback(family, remoteAddress) &&
                       (remotePort != 443 ||
                        !IsLocalNetwork(family, remoteAddress)) &&
                       !IsProxyProcess(metadata, lease.value->proxyProcessId) &&
                       ProcessMatches(*lease.value, appId)) {
                RememberSelectedUdp(family, localAddress, localPort,
                                    remoteAddress, remotePort);
            }
        }
    }
    Increment(Counter::Permitted);
    ReleaseConfiguration(&lease);
    Leave();
}

void NTAPI ClassifyOutbound(const FWPS_INCOMING_VALUES0* values,
                            const FWPS_INCOMING_METADATA_VALUES0* metadata,
                            void* layerData, const void* classifyContext,
                            const FWPS_FILTER2* filter, UINT64 flowContext,
                            FWPS_CLASSIFY_OUT0* classifyOut) {
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    Continue(classifyOut);
    if (values == nullptr || layerData == nullptr ||
        !CanWrite(classifyOut) || !Enter()) return;
    const auto family = FamilyFromLayer(values->layerId);
    const HANDLE injectionHandle = family == wfp::AddressFamily::Ipv4
                                       ? gNetworkV4Handle : gNetworkV6Handle;
    if (FwpsQueryPacketInjectionState0(injectionHandle,
            static_cast<NET_BUFFER_LIST*>(layerData), nullptr) !=
        FWPS_PACKET_NOT_INJECTED) {
        Increment(Counter::SelfInjected);
        Leave();
        return;
    }
    packet::View headerView{};
    if (!ReadNetworkHeaders(static_cast<NET_BUFFER_LIST*>(layerData),
                            &headerView)) {
        Leave();
        return;
    }
    const U16 dnsProxyPort = FastDnsProxyPort();
    const auto quicMode = FastQuicMode();
    bool selectedUdp = false;
    if (headerView.protocol == IPPROTO_UDP &&
        (headerView.destinationPort == 53 ||
         (headerView.destinationPort == 443 &&
          quicMode != wfp::QuicMode::Allow))) {
        selectedUdp = IsSelectedUdp(
            family, headerView.sourceAddress, headerView.sourcePort,
            headerView.destinationAddress, headerView.destinationPort);
    }
    const bool relevant =
        (headerView.protocol == IPPROTO_TCP &&
         headerView.destinationPort == 443 &&
         headerView.payloadLength != 0 &&
         HasPolicy(family, headerView.destinationAddress,
                   headerView.sourcePort)) ||
        (headerView.protocol == IPPROTO_UDP &&
         headerView.destinationPort == 53 && selectedUdp) ||
        (headerView.protocol == IPPROTO_UDP &&
         headerView.sourcePort == dnsProxyPort) ||
        (headerView.protocol == IPPROTO_UDP &&
         headerView.destinationPort == 443 && selectedUdp &&
         quicMode != wfp::QuicMode::Allow);
    if (!relevant) {
        Leave();
        return;
    }
    auto lease = AcquireConfiguration();
    if (lease.value == nullptr) {
        Leave();
        return;
    }
    Increment(Counter::Classified);
    U8* bytes = nullptr;
    Size length = 0;
    if (!CopyNetworkBuffer(static_cast<NET_BUFFER_LIST*>(layerData), &bytes, &length)) {
        Increment(Counter::Unsupported);
        ReleaseConfiguration(&lease);
        Leave();
        return;
    }
    packet::View view{};
    const auto result = packet::Parse(bytes, length, &view);
    if (result != packet::ParseResult::Ok) {
        Increment(result == packet::ParseResult::Unsupported
                      ? Counter::Unsupported : Counter::Malformed);
        ExFreePoolWithTag(bytes, kPoolTag);
        ReleaseConfiguration(&lease);
        Leave();
        return;
    }
    const auto compartment = Compartment(metadata);
    U32 interfaceIndex = 0;
    U32 subInterfaceIndex = 0;
    InterfaceIndexes(values, family, &interfaceIndex, &subInterfaceIndex);
    const U8 loopbackV4[4]{127, 0, 0, 1};
    const U8 loopbackV6[16]{0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 1};
    const U8* loopback = family == wfp::AddressFamily::Ipv4
                             ? loopbackV4 : loopbackV6;
    bool consumed = false;
    if (view.protocol == IPPROTO_UDP && view.destinationPort == 53 &&
        IsSelectedUdp(family, view.sourceAddress, view.sourcePort,
                      view.destinationAddress, view.destinationPort)) {
        const U16 transactionId = ReadTransactionId(bytes, view);
        RememberDnsQuery(family, view.sourceAddress, view.sourcePort,
                         view.destinationAddress, transactionId,
                         compartment, interfaceIndex, subInterfaceIndex);
        consumed = InjectDns(bytes, view, view.sourcePort,
                             lease.value->dnsProxyPort,
                             loopback, loopback, compartment, false);
        if (consumed) Increment(Counter::RedirectedDns);
    } else if (view.protocol == IPPROTO_UDP &&
               view.sourcePort == lease.value->dnsProxyPort) {
        U8 clientAddress[16]{};
        U8 resolverAddress[16]{};
        U16 clientPort = 0;
        COMPARTMENT_ID originalCompartment = UNSPECIFIED_COMPARTMENT_ID;
        U32 originalInterfaceIndex = 0;
        U32 originalSubInterfaceIndex = 0;
        const U16 transactionId = ReadTransactionId(bytes, view);
        if (TakeDnsQuery(family, view.destinationPort, transactionId,
                         clientAddress, &clientPort, resolverAddress,
                         &originalCompartment, &originalInterfaceIndex,
                         &originalSubInterfaceIndex)) {
            consumed = InjectDns(bytes, view, 53, clientPort,
                                 resolverAddress, clientAddress,
                                 originalCompartment, true,
                                 originalInterfaceIndex,
                                 originalSubInterfaceIndex);
            if (consumed) Increment(Counter::RedirectedDns);
        }
    } else if (view.protocol == IPPROTO_UDP && view.destinationPort == 443 &&
               IsSelectedUdp(family, view.sourceAddress, view.sourcePort,
                             view.destinationAddress, view.destinationPort)) {
        if (lease.value->quicMode == wfp::QuicMode::Block ||
            (lease.value->quicMode == wfp::QuicMode::Adaptive &&
             AdaptiveQuicShouldBlock(family, view.destinationAddress,
                                     view.sourcePort))) {
            Block(classifyOut);
            Increment(Counter::BlockedQuic);
        }
    } else if (view.protocol == IPPROTO_TCP && view.destinationPort == 443 &&
               view.payloadLength != 0 &&
               packet::LooksLikeTlsRecord(bytes + view.payloadOffset,
                                           view.payloadLength)) {
        wfp::PolicyCommand policy{};
        if (TakePolicy(family, view.destinationAddress, view.sourcePort, &policy)) {
            consumed = InjectTcpPolicy(bytes, view, policy, compartment);
        }
    }
    if (consumed) Block(classifyOut);
    else if (classifyOut->actionType != FWP_ACTION_BLOCK) Increment(Counter::Permitted);
    ReleaseConfiguration(&lease);
    ExFreePoolWithTag(bytes, kPoolTag);
    Leave();
}

void NTAPI ClassifyInbound(const FWPS_INCOMING_VALUES0* values,
                           const FWPS_INCOMING_METADATA_VALUES0* metadata,
                           void* layerData, const void* classifyContext,
                           const FWPS_FILTER2* filter, UINT64 flowContext,
                           FWPS_CLASSIFY_OUT0* classifyOut) {
    UNREFERENCED_PARAMETER(metadata);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    Continue(classifyOut);
    if (values == nullptr || layerData == nullptr || !Enter()) return;
    bool observed = false;
    packet::View view{};
    if (ReadNetworkHeaders(static_cast<NET_BUFFER_LIST*>(layerData), &view)) {
        const auto family = FamilyFromLayer(values->layerId);
        if (view.protocol == IPPROTO_UDP && view.sourcePort == 443) {
            auto lease = AcquireConfiguration();
            if (lease.value != nullptr &&
                lease.value->quicMode == wfp::QuicMode::Adaptive) {
                ObserveQuicResponse(family, view.sourceAddress,
                                    view.destinationPort);
                observed = true;
            }
            ReleaseConfiguration(&lease);
        } else if (view.protocol == IPPROTO_TCP && view.sourcePort == 443 &&
                   (view.tcpFlags & 0x12U) == 0x12U &&
                   IsSelectedTcp(family, view.destinationAddress,
                                 view.destinationPort, view.sourceAddress)) {
            ObserveTcpHop(family, view.sourceAddress,
                          view.destinationPort, view.ttl);
            observed = true;
        }
    }
    if (observed) {
        Increment(Counter::Classified);
        Increment(Counter::Permitted);
    }
    Leave();
}

NTSTATUS NTAPI NotifyCallout(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                             const GUID* filterKey,
                             FWPS_FILTER2* filter) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

}  // namespace splithello::kernel
