#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>
#include <fwpmu.h>

#include <cstdlib>
#include <iostream>
#include <string_view>

#include "../shared/Identifiers.hpp"
#include "../shared/Protocol.hpp"

namespace {

class Engine final {
public:
    ~Engine() { if (handle_ != nullptr) FwpmEngineClose0(handle_); }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine() = default;

    DWORD open() noexcept {
        FWPM_SESSION0 session{};
        session.displayData.name = const_cast<wchar_t*>(
            L"SplitHello verifier probe");
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr,
                               &session, &handle_);
    }

    DWORD addProvider() noexcept {
        FWPM_PROVIDER0 provider{};
        provider.providerKey = splithello::wfp::kProviderKey;
        provider.displayData.name = const_cast<wchar_t*>(
            splithello::wfp::kProviderName);
        const DWORD status = FwpmProviderAdd0(handle_, &provider, nullptr);
        return status == FWP_E_ALREADY_EXISTS ? ERROR_SUCCESS : status;
    }

private:
    HANDLE handle_ = nullptr;
};

class Service final {
public:
    ~Service() {
        if (service_ != nullptr) CloseServiceHandle(service_);
        if (manager_ != nullptr) CloseServiceHandle(manager_);
    }
    Service(const Service&) = delete;
    Service& operator=(const Service&) = delete;
    Service() = default;

    DWORD open() noexcept {
        manager_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager_ == nullptr) return GetLastError();
        service_ = OpenServiceW(manager_, splithello::wfp::kServiceName,
                                SERVICE_START | SERVICE_STOP |
                                    SERVICE_QUERY_STATUS);
        return service_ == nullptr ? GetLastError() : ERROR_SUCCESS;
    }

    DWORD start() noexcept {
        if (!StartServiceW(service_, 0, nullptr)) {
            const DWORD error = GetLastError();
            if (error != ERROR_SERVICE_ALREADY_RUNNING) return error;
        }
        return waitFor(SERVICE_RUNNING);
    }

    DWORD stop() noexcept {
        SERVICE_STATUS status{};
        if (!ControlService(service_, SERVICE_CONTROL_STOP, &status)) {
            const DWORD error = GetLastError();
            if (error == ERROR_SERVICE_NOT_ACTIVE) return ERROR_SUCCESS;
            return error;
        }
        return waitFor(SERVICE_STOPPED);
    }

    DWORD state(DWORD& output) noexcept {
        SERVICE_STATUS_PROCESS status{};
        DWORD bytes = 0;
        if (!QueryServiceStatusEx(service_, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<BYTE*>(&status),
                                  sizeof(status), &bytes)) return GetLastError();
        output = status.dwCurrentState;
        return ERROR_SUCCESS;
    }

private:
    DWORD waitFor(DWORD desired) noexcept {
        for (unsigned waited = 0; waited <= 5000; waited += 50) {
            DWORD current = 0;
            const DWORD result = state(current);
            if (result != ERROR_SUCCESS) return result;
            if (current == desired) return ERROR_SUCCESS;
            Sleep(50);
        }
        return ERROR_TIMEOUT;
    }

    SC_HANDLE manager_ = nullptr;
    SC_HANDLE service_ = nullptr;
};

DWORD queryDriver(splithello::wfp::Statistics* statistics = nullptr) {
    HANDLE device = CreateFileW(splithello::wfp::kUserDevicePath,
                                GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE) return GetLastError();
    splithello::U32 version = 0;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(device, splithello::wfp::kIoctlGetVersion,
                              nullptr, 0, &version, sizeof(version),
                              &returned, nullptr);
    if (ok && statistics != nullptr) {
        ok = DeviceIoControl(device, splithello::wfp::kIoctlGetStatistics,
                             nullptr, 0, statistics, sizeof(*statistics),
                             &returned, nullptr);
    }
    const DWORD result = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (result == ERROR_SUCCESS && version != splithello::wfp::kProtocolVersion) {
        return ERROR_REVISION_MISMATCH;
    }
    return result;
}

DWORD probe(unsigned cycles) {
    Engine engine;
    DWORD status = engine.open();
    if (status == ERROR_SUCCESS) status = engine.addProvider();
    if (status != ERROR_SUCCESS) return status;
    Service service;
    status = service.open();
    if (status != ERROR_SUCCESS) return status;
    for (unsigned cycle = 1; cycle <= cycles; ++cycle) {
        status = service.start();
        if (status == ERROR_SUCCESS) status = queryDriver();
        const DWORD stopStatus = service.stop();
        if (status == ERROR_SUCCESS) status = stopStatus;
        if (status != ERROR_SUCCESS) return status;
        std::wcout << L"cycle " << cycle << L"/" << cycles << L" passed\n";
    }
    return ERROR_SUCCESS;
}

DWORD printStatus() {
    Service service;
    DWORD status = service.open();
    if (status != ERROR_SUCCESS) return status;
    DWORD state = 0;
    status = service.state(state);
    if (status != ERROR_SUCCESS) return status;
    std::wcout << L"service state: " << state << L'\n';
    if (state == SERVICE_RUNNING) {
        splithello::wfp::Statistics statistics{};
        status = queryDriver(&statistics);
        if (status == ERROR_SUCCESS) {
            std::wcout << L"protocol: " << statistics.header.version
                       << L"\nclassified: " << statistics.classified
                       << L"\noutstanding injections: "
                       << statistics.outstandingBatches << L'\n';
        }
    }
    return status;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2 || argc > 3) {
        std::wcerr << L"usage: SplitHelloWfpCtl <status|probe [cycles]>\n";
        return 2;
    }
    DWORD status = ERROR_INVALID_PARAMETER;
    const std::wstring_view command(argv[1]);
    if (command == L"status" && argc == 2) {
        status = printStatus();
    } else if (command == L"probe") {
        unsigned cycles = 1;
        if (argc == 3) {
            const std::wstring_view input(argv[2]);
            if (input.empty() || input.size() > 5 || input.front() == L'-') return 2;
            wchar_t* end = nullptr;
            const unsigned long parsed = std::wcstoul(argv[2], &end, 10);
            if (end == argv[2] || *end != L'\0' || parsed == 0 || parsed > 1000) return 2;
            cycles = static_cast<unsigned>(parsed);
        }
        status = probe(cycles);
    }
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"operation failed: " << status << L'\n';
        return 1;
    }
    return 0;
}
