#include "Kernel.hpp"
#include <wdmsec.h>
#include "../shared/Identifiers.hpp"

namespace splithello::kernel {
namespace {

PDEVICE_OBJECT gDeviceObject = nullptr;
UNICODE_STRING gSymbolicLink{};
UINT32 gCalloutIds[8]{};

struct CalloutRegistration {
    const GUID* key;
    FWPS_CALLOUT_CLASSIFY_FN2 classify;
};

const CalloutRegistration kCallouts[] = {
    {&wfp::kRedirectV4CalloutKey, ClassifyRedirect},
    {&wfp::kRedirectV6CalloutKey, ClassifyRedirect},
    {&wfp::kAuthV4CalloutKey, ClassifyAuthorize},
    {&wfp::kAuthV6CalloutKey, ClassifyAuthorize},
    {&wfp::kOutboundV4CalloutKey, ClassifyOutbound},
    {&wfp::kOutboundV6CalloutKey, ClassifyOutbound},
    {&wfp::kInboundV4CalloutKey, ClassifyInbound},
    {&wfp::kInboundV6CalloutKey, ClassifyInbound},
};

void CompleteIrp(IRP* irp, NTSTATUS status, ULONG_PTR information) noexcept {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT deviceObject, IRP* irp) noexcept {
    UNREFERENCED_PARAMETER(deviceObject);
    CompleteIrp(irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchCleanup(PDEVICE_OBJECT deviceObject, IRP* irp) noexcept {
    UNREFERENCED_PARAMETER(deviceObject);
    auto* stack = IoGetCurrentIrpStackLocation(irp);
    if (stack->FileObject != nullptr && stack->FileObject->FsContext != nullptr) {
        SetActive(false);
        stack->FileObject->FsContext = nullptr;
    }
    CompleteIrp(irp, STATUS_SUCCESS, 0);
    return STATUS_SUCCESS;
}

bool HasBuffer(const IO_STACK_LOCATION* stack, ULONG required,
               bool input) noexcept {
    return input ? stack->Parameters.DeviceIoControl.InputBufferLength >= required
                 : stack->Parameters.DeviceIoControl.OutputBufferLength >= required;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT deviceObject, IRP* irp) noexcept {
    UNREFERENCED_PARAMETER(deviceObject);
    auto* stack = IoGetCurrentIrpStackLocation(irp);
    auto* buffer = irp->AssociatedIrp.SystemBuffer;
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    switch (code) {
        case wfp::kIoctlGetVersion:
            if (buffer != nullptr && HasBuffer(stack, sizeof(U32), false)) {
                *static_cast<U32*>(buffer) = wfp::kProtocolVersion;
                information = sizeof(U32);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        case wfp::kIoctlSetConfiguration:
            if (buffer != nullptr && HasBuffer(stack, sizeof(wfp::Configuration), true)) {
                status = SetConfiguration(*static_cast<wfp::Configuration*>(buffer));
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        case wfp::kIoctlStart: {
            auto lease = AcquireConfiguration();
            if (lease.value == nullptr) {
                status = STATUS_DEVICE_NOT_READY;
            } else if (stack->FileObject == nullptr) {
                status = STATUS_INVALID_HANDLE;
            } else {
                SetActive(true);
                stack->FileObject->FsContext = reinterpret_cast<void*>(1);
                status = STATUS_SUCCESS;
            }
            ReleaseConfiguration(&lease);
            break;
        }
        case wfp::kIoctlStop:
            SetActive(false);
            if (stack->FileObject != nullptr) stack->FileObject->FsContext = nullptr;
            status = STATUS_SUCCESS;
            break;
        case wfp::kIoctlArmPolicy:
            if (buffer != nullptr && HasBuffer(stack, sizeof(wfp::PolicyCommand), true)) {
                status = ArmPolicy(*static_cast<wfp::PolicyCommand*>(buffer));
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        case wfp::kIoctlGetStatistics:
            if (buffer != nullptr && HasBuffer(stack, sizeof(wfp::Statistics), false)) {
                QueryStatistics(static_cast<wfp::Statistics*>(buffer));
                information = sizeof(wfp::Statistics);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        case wfp::kIoctlResetStatistics:
            ResetStatistics();
            status = STATUS_SUCCESS;
            break;
        default:
            break;
    }
    CompleteIrp(irp, status, information);
    return status;
}

void UnregisterCallouts() noexcept {
    for (Size index = RTL_NUMBER_OF(gCalloutIds); index != 0; --index) {
        auto& calloutId = gCalloutIds[index - 1];
        if (calloutId != 0) {
            const NTSTATUS status = FwpsCalloutUnregisterById0(calloutId);
            if (NT_SUCCESS(status)) calloutId = 0;
        }
    }
}

NTSTATUS RegisterCallouts() noexcept {
    for (Size index = 0; index < RTL_NUMBER_OF(kCallouts); ++index) {
        FWPS_CALLOUT2 callout{};
        callout.calloutKey = *kCallouts[index].key;
        callout.classifyFn = kCallouts[index].classify;
        callout.notifyFn = NotifyCallout;
        const NTSTATUS status = FwpsCalloutRegister2(
            gDeviceObject, &callout, &gCalloutIds[index]);
        if (!NT_SUCCESS(status)) {
            UnregisterCallouts();
            return status;
        }
    }
    return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);
    SetActive(false);
    ShutdownDataPath();
    UnregisterCallouts();
    ShutdownState();
    if (gSymbolicLink.Buffer != nullptr) IoDeleteSymbolicLink(&gSymbolicLink);
    if (gDeviceObject != nullptr) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = nullptr;
    }
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
               "SplitHelloWfp: unloaded cleanly\n");
}

}  // namespace
}  // namespace splithello::kernel

extern "C" {

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject,
                     PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);
    using namespace splithello;
    using namespace splithello::kernel;

    InitializeState();
    UNICODE_STRING deviceName{};
    RtlInitUnicodeString(&deviceName, wfp::kNtDeviceName);
    RtlInitUnicodeString(&gSymbolicLink, wfp::kDosDeviceName);
    UNICODE_STRING sddl{};
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NTSTATUS status = IoCreateDeviceSecure(
        driverObject, 0, &deviceName, FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN, FALSE, &sddl,
        &wfp::kDeviceClassGuid, &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        ShutdownState();
        return status;
    }
    gDeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&gSymbolicLink, &deviceName);
    if (NT_SUCCESS(status)) status = InitializeDataPath(gDeviceObject);
    if (NT_SUCCESS(status)) status = RegisterCallouts();
    if (!NT_SUCCESS(status)) {
        ShutdownDataPath();
        UnregisterCallouts();
        IoDeleteSymbolicLink(&gSymbolicLink);
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = nullptr;
        ShutdownState();
        return status;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = DispatchCleanup;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    driverObject->DriverUnload = DriverUnload;
    gDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
               "SplitHelloWfp: eight WFP callouts registered\n");
    return STATUS_SUCCESS;
}

}  // extern "C"
