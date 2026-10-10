#include "TrayApp.hpp"

#include "CommandLine.hpp"
#include "DashboardPanel.hpp"
#include "EngineExitCodes.hpp"
#include "SplitHelloIcon.hpp"

#include <spdlog/spdlog.h>

#include <aclapi.h>
#include <sddl.h>

#include <algorithm>
#include <filesystem>
#include <optional>
#include <stop_token>
#include <string_view>

namespace {

constexpr wchar_t kWindowClass[] = L"SplitHello.TrayWindow";
constexpr wchar_t kTaskName[] = L"\\SplitHello";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallback = WM_APP + 1;
constexpr UINT kStartupQueried = WM_APP + 2;  // wParam: 1 enabled, 0 disabled
constexpr UINT kStartupChanged = WM_APP + 3;  // wParam: StartupResult, lParam: target
constexpr UINT_PTR kPollTimerId = 1;

constexpr UINT kCommandStart = 1001;
constexpr UINT kCommandStop = 1002;
constexpr UINT kCommandStartup = 1003;
constexpr UINT kCommandOpenLogs = 1004;
constexpr UINT kCommandExit = 1005;
constexpr UINT kCommandDashboard = 1006;
constexpr UINT kCommandDnsWorker = 1007;
constexpr UINT kCommandDnsSystem = 1008;
constexpr UINT kCommandSetup = 1009;

// An engine that stays in Starting/Stopping this long is hung. Terminating it
// closes its WinDivert handle in the kernel, which removes the filter (fail-open).
constexpr uint64_t kEngineTransitionTimeoutMs = 10000;
constexpr DWORD kEngineKilledExitCode = 0xDEAD0001;
// Task Scheduler calls must never block the tray for long.
constexpr DWORD kSchedulerTimeoutMs = 5000;

std::wstring executablePath() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return {};
    path.resize(length);
    return path;
}

std::wstring systemExecutable(const wchar_t* name) {
    std::wstring directory(MAX_PATH, L'\0');
    const UINT length = GetSystemDirectoryW(directory.data(),
                                            static_cast<UINT>(directory.size()));
    if (length == 0 || length >= directory.size()) return name;
    directory.resize(length);
    return directory + L"\\" + name;
}

// Runs a hidden child and returns its exit code, or nullopt when it could not
// start, ran past `timeoutMs` or `stop` was requested (it is killed then).
std::optional<DWORD> runHiddenProcess(const std::wstring& application,
                                      const std::vector<std::wstring>& arguments,
                                      DWORD timeoutMs, std::stop_token stop) {
    std::wstring commandLine = cmdline::quoteArgument(application);
    for (const std::wstring& argument : arguments) {
        commandLine.push_back(L' ');
        commandLine += cmdline::quoteArgument(argument);
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(application.c_str(), commandLine.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process)) {
        return std::nullopt;
    }

    CloseHandle(process.hThread);
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    DWORD wait = WAIT_TIMEOUT;
    while (wait == WAIT_TIMEOUT && !stop.stop_requested() &&
           GetTickCount64() < deadline) {
        wait = WaitForSingleObject(process.hProcess, 100);
    }

    std::optional<DWORD> result;
    if (wait == WAIT_OBJECT_0) {
        DWORD exitCode = 1;
        GetExitCodeProcess(process.hProcess, &exitCode);
        result = exitCode;
    } else {
        spdlog::warn("Gorev zamanlayici komutu zaman asimina ugradi, sonlandiriliyor");
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 1000);
    }
    CloseHandle(process.hProcess);
    return result;
}

std::wstring uniqueEventName(std::wstring_view purpose) {
    return L"Local\\SplitHello-" + std::wstring(purpose) + L"-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
}

const wchar_t* stateText(TrayApp::EngineState state) {
    switch (state) {
    case TrayApp::EngineState::Starting: return L"Başlatılıyor";
    case TrayApp::EngineState::Running: return L"Koruma aktif";
    case TrayApp::EngineState::Stopping: return L"Durduruluyor";
    case TrayApp::EngineState::Failed: return L"Başlatma başarısız";
    case TrayApp::EngineState::Stopped: return L"Koruma kapalı";
    }
    return L"Koruma kapalı";
}

HICON stateIcon(TrayApp::EngineState state) {
    if (state == TrayApp::EngineState::Running ||
        state == TrayApp::EngineState::Stopped) {
        return static_cast<HICON>(LoadImageW(
            GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_SPLITHELLO), IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED));
    }
    LPCWSTR resource = MAKEINTRESOURCEW(32512); // IDI_APPLICATION
    if (state == TrayApp::EngineState::Starting) resource = MAKEINTRESOURCEW(32516); // IDI_INFORMATION
    else if (state == TrayApp::EngineState::Stopping) resource = MAKEINTRESOURCEW(32515); // IDI_WARNING
    else if (state == TrayApp::EngineState::Failed) resource = MAKEINTRESOURCEW(32513); // IDI_ERROR
    return LoadIconW(nullptr, resource);
}

// Turkish reason shown to the user for an engine exit code (see
// EngineExitCodes.hpp), or nullptr when the code carries no extra information.
const wchar_t* engineFailureReason(DWORD exitCode) {
    switch (exitCode) {
    case engine_exit::kRelayPortInUse:
        return L"Relay portu başka bir uygulama tarafından kullanılıyor.";
    case engine_exit::kDnsRelayPortInUse:
        return L"DNS relay portu başka bir uygulama tarafından kullanılıyor.";
    case engine_exit::kWinDivertOpenFailed:
        return L"WinDivert açılamadı. WinDivert.dll ve WinDivert64.sys exe ile aynı "
               L"klasörde olmalı; antivirüs sürücüyü engelliyor olabilir.";
    case engine_exit::kInvalidProcessRules:
        return L"Süreç filtresindeki include kuralları geçersiz. Teşhis panelinden "
               L"düzeltin veya boşaltın.";
    case engine_exit::kSetupRequired:
        return L"Worker kurulumu yok. splithello.exe --setup çalıştırın veya DNS "
               L"modunu Sistem yapın.";
    case engine_exit::kMonitorUnavailable:
        return L"Tray kontrol kanalı açılamadı.";
    case engine_exit::kConfigUnreadable:
        return L"Yapılandırma dosyası okunamadı.";
    case kEngineKilledExitCode:
        return L"Ağ motoru 10 saniye içinde yanıt vermedi ve sonlandırıldı.";
    default:
        break;
    }
    if (exitCode == engine_exit::kDllNotFound) {
        return L"WinDivert.dll bulunamadı; exe ile aynı klasörde olmalı.";
    }
    return nullptr;
}

// ---- "Windows ile başlat" scheduled task -----------------------------------

enum class StartupResult : WPARAM { Ok = 0, Failed = 1, UnsafeLocation = 2 };

// True when `path` has an effective-access ACE (not inherit-only) matching
// `mask` for a principal that is not an administrator: Everyone, Authenticated
// Users, Users, Interactive or the current user. Unknown ACLs count as risky.
bool lowPrivilegeCanModify(const std::wstring& path, DWORD mask, PSID currentUser) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, &dacl, nullptr, &descriptor) !=
        ERROR_SUCCESS) {
        return true;
    }

    bool risky = dacl == nullptr; // a NULL DACL grants everyone full control
    for (DWORD i = 0; dacl && i < dacl->AceCount && !risky; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw) || !raw) continue;
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (header->AceFlags & INHERIT_ONLY_ACE) != 0) {
            continue;
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        if ((ace->Mask & mask) == 0) continue;
        PSID sid = (PSID)&ace->SidStart;
        risky = IsWellKnownSid(sid, WinWorldSid) ||
                IsWellKnownSid(sid, WinAuthenticatedUserSid) ||
                IsWellKnownSid(sid, WinBuiltinUsersSid) ||
                IsWellKnownSid(sid, WinInteractiveSid) ||
                (currentUser && EqualSid(sid, currentUser));
    }
    LocalFree(descriptor);
    return risky;
}

// The task runs this exe elevated at every logon, so anything a standard user
// can replace (the exe, its folder, or a parent folder they can rename) would be
// a privilege escalation. Only accept locations that need admin rights to change.
bool locationNeedsAdminToModify(const std::wstring& executable) {
    std::error_code error;
    const std::filesystem::path real = std::filesystem::canonical(executable, error);
    if (error) return false;

    std::vector<BYTE> userBuffer;
    PSID currentUser = nullptr;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        userBuffer.resize(size);
        if (size != 0 && GetTokenInformation(token, TokenUser, userBuffer.data(), size, &size)) {
            currentUser = reinterpret_cast<TOKEN_USER*>(userBuffer.data())->User.Sid;
        }
        CloseHandle(token);
    }

    constexpr DWORD kObjectMask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD |
                                  DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE |
                                  GENERIC_ALL;
    // Parents only matter if the user can rename/replace the child below them.
    constexpr DWORD kAncestorMask = FILE_DELETE_CHILD | DELETE | WRITE_DAC |
                                    WRITE_OWNER | GENERIC_ALL;

    if (lowPrivilegeCanModify(real.wstring(), kObjectMask, currentUser)) return false;
    std::filesystem::path current = real.parent_path();
    bool directory = true;
    while (!current.empty()) {
        if (lowPrivilegeCanModify(current.wstring(),
                                  directory ? kObjectMask : kAncestorMask, currentUser)) {
            return false;
        }
        directory = false;
        const std::filesystem::path parent = current.parent_path();
        if (parent == current) break;
        current = parent;
    }
    return true;
}

// "DOMAIN\user" for the task's UserId, falling back to the SID string.
std::wstring currentUserId() {
    std::wstring result;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return result;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<BYTE> buffer(size);
    if (size != 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        PSID sid = reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid;
        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD nameLength = 256;
        DWORD domainLength = 256;
        SID_NAME_USE use{};
        if (LookupAccountSidW(nullptr, sid, name, &nameLength, domain, &domainLength, &use) &&
            name[0] != L'\0') {
            result = (domain[0] ? std::wstring(domain) + L"\\" : std::wstring()) + name;
        } else {
            LPWSTR text = nullptr;
            if (ConvertSidToStringSidW(sid, &text)) {
                result = text;
                LocalFree(text);
            }
        }
    }
    CloseHandle(token);
    return result;
}

std::wstring xmlEscape(const std::wstring& text) {
    std::wstring result;
    for (const wchar_t c : text) {
        switch (c) {
        case L'&': result += L"&amp;"; break;
        case L'<': result += L"&lt;"; break;
        case L'>': result += L"&gt;"; break;
        case L'"': result += L"&quot;"; break;
        default: result.push_back(c); break;
        }
    }
    return result;
}

// schtasks flags alone cannot clear the 72 h execution limit or the battery
// conditions, so the task is registered from XML.
std::wstring startupTaskXml(const std::wstring& executable, const std::wstring& userId) {
    const std::wstring user = xmlEscape(userId);
    const std::filesystem::path exePath(executable);
    return std::wstring(L"<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        L"  <RegistrationInfo><Description>SplitHello</Description></RegistrationInfo>\r\n"
        L"  <Triggers>\r\n"
        L"    <LogonTrigger>\r\n"
        L"      <Enabled>true</Enabled>\r\n"
        L"      <UserId>") + user + L"</UserId>\r\n"
        L"      <Delay>PT5S</Delay>\r\n"
        L"    </LogonTrigger>\r\n"
        L"  </Triggers>\r\n"
        L"  <Principals>\r\n"
        L"    <Principal id=\"Author\">\r\n"
        L"      <UserId>" + user + L"</UserId>\r\n"
        L"      <LogonType>InteractiveToken</LogonType>\r\n"
        L"      <RunLevel>HighestAvailable</RunLevel>\r\n"
        L"    </Principal>\r\n"
        L"  </Principals>\r\n"
        L"  <Settings>\r\n"
        L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
        L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
        L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
        L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
        L"    <StartWhenAvailable>false</StartWhenAvailable>\r\n"
        L"    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n"
        L"    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n"
        L"    <Enabled>true</Enabled>\r\n"
        L"    <Hidden>false</Hidden>\r\n"
        L"    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n"
        L"    <Priority>7</Priority>\r\n"
        L"  </Settings>\r\n"
        L"  <Actions Context=\"Author\">\r\n"
        L"    <Exec>\r\n"
        L"      <Command>\"" + xmlEscape(executable) + L"\"</Command>\r\n"
        L"      <WorkingDirectory>" + xmlEscape(exePath.parent_path().wstring()) +
        L"</WorkingDirectory>\r\n"
        L"    </Exec>\r\n"
        L"  </Actions>\r\n"
        L"</Task>\r\n";
}

// schtasks wants UTF-16 (with BOM) for /XML.
bool writeUtf16File(const std::wstring& path, const std::wstring& text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const WORD bom = 0xFEFF;
    DWORD written = 0;
    bool ok = WriteFile(file, &bom, sizeof(bom), &written, nullptr) != FALSE &&
              WriteFile(file, text.data(), static_cast<DWORD>(text.size() * sizeof(wchar_t)),
                        &written, nullptr) != FALSE;
    ok = CloseHandle(file) != FALSE && ok;
    return ok;
}

// nullopt: the Task Scheduler did not answer in time.
std::optional<bool> startupTaskExists(std::stop_token stop) {
    const std::optional<DWORD> code = runHiddenProcess(
        systemExecutable(L"schtasks.exe"), {L"/Query", L"/TN", kTaskName},
        kSchedulerTimeoutMs, stop);
    if (!code) return std::nullopt;
    return *code == 0;
}

StartupResult setStartupEnabled(bool enabled, std::stop_token stop) {
    const std::wstring scheduler = systemExecutable(L"schtasks.exe");
    if (!enabled) {
        const std::optional<bool> exists = startupTaskExists(stop);
        if (exists && !*exists) return StartupResult::Ok;
        const std::optional<DWORD> code = runHiddenProcess(
            scheduler, {L"/Delete", L"/TN", kTaskName, L"/F"}, kSchedulerTimeoutMs, stop);
        return code && *code == 0 ? StartupResult::Ok : StartupResult::Failed;
    }

    const std::wstring executable = executablePath();
    if (executable.empty()) return StartupResult::Failed;
    if (!locationNeedsAdminToModify(executable)) return StartupResult::UnsafeLocation;

    const std::wstring user = currentUserId();
    if (user.empty()) return StartupResult::Failed;

    // The XML lives next to the exe: that folder was just verified to be
    // admin-only, so a standard user cannot swap it between write and import.
    const std::wstring xmlPath =
        (std::filesystem::path(executable).parent_path() / L"splithello-startup-task.xml")
            .wstring();
    if (!writeUtf16File(xmlPath, startupTaskXml(executable, user))) {
        DeleteFileW(xmlPath.c_str());
        return StartupResult::Failed;
    }
    const std::optional<DWORD> code = runHiddenProcess(
        scheduler, {L"/Create", L"/TN", kTaskName, L"/XML", xmlPath, L"/F"},
        kSchedulerTimeoutMs, stop);
    DeleteFileW(xmlPath.c_str());
    return code && *code == 0 ? StartupResult::Ok : StartupResult::Failed;
}

} // namespace

TrayApp::TrayApp(std::vector<std::wstring> engineArguments,
                 std::wstring logDirectory,
                 std::string telemetryPath,
                 bool canStart)
    : engineArguments_(std::move(engineArguments)),
      logDirectory_(std::move(logDirectory)),
      liveStatsName_(uniqueEventName(L"live-stats")),
      telemetryPath_(std::move(telemetryPath)),
      canStart_(canStart) {}

TrayApp::~TrayApp() {
    removeIcon();
    closeEngineHandles();
    if (setupProcess_) CloseHandle(setupProcess_);
    if (window_) DestroyWindow(window_);
}

int TrayApp::run() {
    if (!createWindow() || !addIcon()) return 1;

    refreshStartupAsync();
    SetTimer(window_, kPollTimerId, 250, nullptr);

    if (canStart_) {
        startEngine();
    } else {
        showBalloon(L"SplitHello kurulumu gerekli",
                    L"Cloudflare kurulumu açılıyor; tarayıcıda izin verin.",
                    NIIF_WARNING);
        launchSetup(true);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        // Tab/Enter/Esc traversal for the dashboard's child controls.
        if (dashboard_ && dashboard_->translateMessage(message)) continue;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}

bool TrayApp::createWindow() {
    taskbarCreatedMessage_ = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = windowProc;
    windowClass.hInstance = GetModuleHandleW(nullptr);
    windowClass.hIcon = LoadIconW(windowClass.hInstance,
                                  MAKEINTRESOURCEW(IDI_SPLITHELLO));
    windowClass.hIconSm = stateIcon(EngineState::Stopped);
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        spdlog::error("Tray pencere sinifi olusturulamadi: {}", GetLastError());
        return false;
    }

    window_ = CreateWindowExW(0, kWindowClass, L"SplitHello", WS_OVERLAPPED,
                              0, 0, 0, 0, nullptr, nullptr,
                              GetModuleHandleW(nullptr), this);
    if (!window_) {
        spdlog::error("Tray penceresi olusturulamadi: {}", GetLastError());
        return false;
    }
    return true;
}

bool TrayApp::addIcon() {
    iconData_ = {};
    iconData_.cbSize = sizeof(iconData_);
    iconData_.hWnd = window_;
    iconData_.uID = kTrayIconId;
    iconData_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    iconData_.uCallbackMessage = kTrayCallback;
    iconData_.hIcon = stateIcon(state_);
    wcsncpy_s(iconData_.szTip, L"SplitHello — Koruma kapalı", _TRUNCATE);
    if (!Shell_NotifyIconW(NIM_ADD, &iconData_)) {
        spdlog::error("Tray simgesi eklenemedi");
        return false;
    }
    iconData_.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &iconData_);
    return true;
}

void TrayApp::removeIcon() {
    if (!iconData_.hWnd) return;
    Shell_NotifyIconW(NIM_DELETE, &iconData_);
    iconData_.hWnd = nullptr;
}

void TrayApp::updateIcon() {
    if (!iconData_.hWnd) return;
    iconData_.uFlags = NIF_ICON | NIF_TIP;
    iconData_.hIcon = stateIcon(state_);
    const std::wstring tooltip = L"SplitHello — " + std::wstring(stateText(state_));
    wcsncpy_s(iconData_.szTip, tooltip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &iconData_);
}

void TrayApp::showBalloon(const std::wstring& title,
                          const std::wstring& message,
                          DWORD icon) {
    if (!iconData_.hWnd) return;
    iconData_.uFlags = NIF_INFO;
    iconData_.dwInfoFlags = icon | NIIF_NOSOUND;
    wcsncpy_s(iconData_.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(iconData_.szInfo, message.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &iconData_);
}

void TrayApp::showMenu() {
    // Ask again for the next time the menu opens; this one uses the cached value
    // so a hung Task Scheduler can never freeze the tray.
    refreshStartupAsync();
    Config config;
    config.load();

    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, stateText(state_));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kCommandDashboard, L"Teşhis panelini aç");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    const bool stopped = state_ == EngineState::Stopped || state_ == EngineState::Failed;
    AppendMenuW(menu, MF_STRING | ((!stopped || !canStart_) ? MF_DISABLED : 0),
                kCommandStart, L"Başlat");
    AppendMenuW(menu, MF_STRING | (stopped ? MF_DISABLED : 0),
                kCommandStop, L"Durdur");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING |
                    (config.dnsMode == DnsMode::Worker ? MF_CHECKED : 0),
                kCommandDnsWorker, L"DNS: Worker");
    AppendMenuW(menu, MF_STRING |
                    (config.dnsMode == DnsMode::System ? MF_CHECKED : 0),
                kCommandDnsSystem, L"DNS: Sistem (Worker'sız)");
    AppendMenuW(menu, MF_STRING | (setupProcess_ ? MF_DISABLED : 0),
                kCommandSetup, L"Cloudflare Worker kurulumunu çalıştır");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | (startupEnabled_ ? MF_CHECKED : 0),
                kCommandStartup, L"Windows ile başlat");
    AppendMenuW(menu, MF_STRING, kCommandOpenLogs, L"Log klasörünü aç");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kCommandExit, L"Çıkış");

    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(window_);
    const UINT command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                        cursor.x, cursor.y, 0, window_, nullptr);
    DestroyMenu(menu);
    if (command != 0) PostMessageW(window_, WM_COMMAND, command, 0);
}

void TrayApp::startEngine(bool automatic) {
    if (!canStart_ || engineProcess_) return;
    restartPending_ = false;
    restartAtMs_ = 0;
    engineKilled_ = false;
    if (!automatic) restartBudget_.reset();

    const std::wstring executable = executablePath();
    if (executable.empty()) {
        setState(EngineState::Failed);
        showBalloon(L"SplitHello başlatılamadı", L"Uygulama yolu bulunamadı.", NIIF_ERROR);
        return;
    }

    const std::wstring shutdownName = uniqueEventName(L"shutdown");
    const std::wstring readyName = uniqueEventName(L"ready");
    shutdownEvent_ = CreateEventW(nullptr, TRUE, FALSE, shutdownName.c_str());
    readyEvent_ = CreateEventW(nullptr, TRUE, FALSE, readyName.c_str());
    if (!shutdownEvent_ || !readyEvent_) {
        closeEngineHandles();
        setState(EngineState::Failed);
        showBalloon(L"SplitHello başlatılamadı", L"Kontrol kanalı oluşturulamadı.", NIIF_ERROR);
        return;
    }

    std::vector<std::wstring> arguments = engineArguments_;
    arguments.emplace_back(L"--engine");
    arguments.emplace_back(L"--shutdown-event");
    arguments.push_back(shutdownName);
    arguments.emplace_back(L"--ready-event");
    arguments.push_back(readyName);
    arguments.emplace_back(L"--parent-pid");
    arguments.push_back(std::to_wstring(GetCurrentProcessId()));
    arguments.emplace_back(L"--live-stats");
    arguments.push_back(liveStatsName_);

    std::wstring commandLine = cmdline::quoteArgument(executable);
    for (const std::wstring& argument : arguments) {
        commandLine.push_back(L' ');
        commandLine += cmdline::quoteArgument(argument);
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process)) {
        const DWORD error = GetLastError();
        closeEngineHandles();
        setState(EngineState::Failed);
        spdlog::error("Ag motoru baslatilamadi: {}", error);
        showBalloon(L"SplitHello başlatılamadı", L"Ağ motoru açılamadı.", NIIF_ERROR);
        return;
    }

    CloseHandle(process.hThread);
    engineProcess_ = process.hProcess;
    setState(EngineState::Starting);
}

void TrayApp::requestStop() {
    if (restartPending_) {
        restartPending_ = false;
        restartAtMs_ = 0;
        setState(EngineState::Stopped);
        showBalloon(L"SplitHello", L"Otomatik yeniden başlatma iptal edildi.");
        return;
    }
    if (!engineProcess_) return;
    // A second request while stopping re-signals; pollEngine() terminates the
    // process if it still has not exited after kEngineTransitionTimeoutMs.
    if (state_ != EngineState::Stopping) setState(EngineState::Stopping);
    if (shutdownEvent_) SetEvent(shutdownEvent_);
}

void TrayApp::requestExit() {
    exiting_ = true;
    restartPending_ = false;
    restartAtMs_ = 0;
    configurationRestartPending_ = false;
    if (engineProcess_) {
        requestStop();
    } else {
        DestroyWindow(window_);
    }
}

void TrayApp::launchSetup(bool wantWorkerMode) {
    if (setupProcess_) {
        showBalloon(L"SplitHello", L"Kurulum zaten çalışıyor.");
        return;
    }
    const std::wstring executable = executablePath();
    if (executable.empty()) {
        showBalloon(L"Kurulum başlatılamadı", L"Uygulama yolu bulunamadı.", NIIF_ERROR);
        return;
    }

    std::wstring commandLine = cmdline::quoteArgument(executable) + L" --setup-only";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    // The tray is already elevated, so the child is too and shows no UAC prompt.
    if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr,
                        FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr,
                        &startup, &process)) {
        spdlog::error("Kurulum baslatilamadi: {}", GetLastError());
        showBalloon(L"Kurulum başlatılamadı", L"Kurulum penceresi açılamadı.", NIIF_ERROR);
        return;
    }
    CloseHandle(process.hThread);
    setupProcess_ = process.hProcess;
    setupWantsWorker_ = wantWorkerMode;
}

void TrayApp::pollSetup() {
    if (!setupProcess_ || WaitForSingleObject(setupProcess_, 0) != WAIT_OBJECT_0) return;

    DWORD exitCode = 1;
    GetExitCodeProcess(setupProcess_, &exitCode);
    CloseHandle(setupProcess_);
    setupProcess_ = nullptr;
    if (exiting_) return;

    Config config;
    config.load();
    if (exitCode != 0 || config.loadFailed || config.workerUrl.empty()) {
        showBalloon(L"Kurulum tamamlanamadı",
                    L"Ayrıntı için log klasörüne bakın; menüden kurulumu yeniden çalıştırabilirsiniz.",
                    NIIF_WARNING);
        return;
    }
    if (setupWantsWorker_ && config.dnsMode != DnsMode::Worker) {
        config.dnsMode = DnsMode::Worker;
        if (!config.save()) {
            showBalloon(L"DNS modu değişmedi", L"Yapılandırma kaydedilemedi.", NIIF_ERROR);
            return;
        }
    }
    canStart_ = config.isValid();
    showBalloon(L"SplitHello", L"Worker kurulumu tamamlandı.");
    if (!canStart_) return;
    if (!engineProcess_ && (state_ == EngineState::Stopped || state_ == EngineState::Failed)) {
        startEngine();
    } else {
        restartEngineForConfiguration();
    }
}

void TrayApp::pollEngine() {
    pollSetup();
    const uint64_t nowMs = GetTickCount64();
    if (!engineProcess_) {
        if (restartPending_ && nowMs >= restartAtMs_) {
            startEngine(true);
        }
        return;
    }

    if (state_ == EngineState::Starting && readyEvent_ &&
        WaitForSingleObject(readyEvent_, 0) == WAIT_OBJECT_0) {
        setState(EngineState::Running);
        showBalloon(L"SplitHello", L"Koruma aktif.");
    }

    // Hung engine: the kernel closes its WinDivert handle on termination, so
    // traffic is no longer intercepted. The exit is then handled below like any
    // other (Stopping -> Stopped, Starting -> Failed + restart budget).
    if (!engineKilled_ &&
        (state_ == EngineState::Starting || state_ == EngineState::Stopping) &&
        nowMs - stateSinceMs_ >= kEngineTransitionTimeoutMs &&
        WaitForSingleObject(engineProcess_, 0) != WAIT_OBJECT_0) {
        spdlog::error("Ag motoru {} ms icinde gecis tamamlamadi ({}); sonlandiriliyor",
                      kEngineTransitionTimeoutMs,
                      state_ == EngineState::Starting ? "baslatma" : "durdurma");
        engineKilled_ = true;
        TerminateProcess(engineProcess_, kEngineKilledExitCode);
    }

    if (WaitForSingleObject(engineProcess_, 0) != WAIT_OBJECT_0) return;

    DWORD exitCode = 1;
    GetExitCodeProcess(engineProcess_, &exitCode);
    handleEngineExit(exitCode, nowMs);
}

void TrayApp::handleEngineExit(DWORD exitCode, uint64_t nowMs) {
    const bool expected = state_ == EngineState::Stopping || exiting_;
    closeEngineHandles();

    if (exiting_) {
        DestroyWindow(window_);
        return;
    }

    const wchar_t* reason = engineFailureReason(exitCode);
    if (expected) {
        if (configurationRestartPending_) {
            configurationRestartPending_ = false;
            setState(EngineState::Stopped);
            startEngine();
        } else {
            setState(EngineState::Stopped);
            showBalloon(L"SplitHello", L"Koruma durduruldu.");
        }
    } else if (exitCode == recovery::kWorkerUnavailableExitCode) {
        restartPending_ = false;
        restartAtMs_ = 0;
        setState(EngineState::Failed);
        showBalloon(L"SplitHello koruması durdu",
                    L"Worker erişilemedi. Normal internet yolu açık; yeniden denemek için Başlat seçin.",
                    NIIF_WARNING);
    } else if (engine_exit::needsUserAction(exitCode)) {
        // Restarting cannot fix a missing driver or a bad configuration.
        restartPending_ = false;
        restartAtMs_ = 0;
        setState(EngineState::Failed);
        spdlog::error("Ag motoru baslatilamadi (cikis={}); otomatik yeniden baslatma yok",
                      exitCode);
        showBalloon(L"SplitHello başlatılamadı",
                    std::wstring(reason ? reason : L"Ağ motoru başlatılamadı.") +
                        L" Düzelttikten sonra Başlat seçin.",
                    NIIF_ERROR);
    } else {
        scheduleAutomaticRestart(exitCode, nowMs, reason);
    }
}

void TrayApp::scheduleAutomaticRestart(DWORD exitCode, uint64_t nowMs,
                                       const wchar_t* reason) {
    setState(EngineState::Failed);
    const std::wstring detail = reason ? std::wstring(L" ") + reason : std::wstring();
    const unsigned attempt = restartBudget_.consume(nowMs);
    if (attempt == 0) {
        spdlog::error(
            "Ag motoru cok sik durdu (son cikis={}); otomatik yeniden baslatma durduruldu",
            exitCode);
        showBalloon(
            L"SplitHello koruması durdu",
            L"Normal internet yolu açık. Yeniden başlatma sınırına ulaşıldı; tray'den Başlat seçin." +
                detail,
            NIIF_ERROR);
        return;
    }

    const unsigned delayMs = recovery::automaticRestartDelayMs(attempt);
    restartPending_ = true;
    restartAtMs_ = nowMs + delayMs;
    spdlog::warn(
        "Ag motoru beklenmedik cikis={} verdi; otomatik yeniden baslatma {}/{} ({} ms)",
        exitCode, attempt, recovery::kMaxAutomaticRestarts, delayMs);
    showBalloon(
        L"SplitHello kendini toparlıyor",
        L"Filtre kapatıldı; normal internet yolu açık. Ağ motoru kısa süre içinde yeniden başlayacak." +
            detail,
        NIIF_WARNING);
}

void TrayApp::closeEngineHandles() {
    if (engineProcess_) CloseHandle(engineProcess_);
    if (shutdownEvent_) CloseHandle(shutdownEvent_);
    if (readyEvent_) CloseHandle(readyEvent_);
    engineProcess_ = nullptr;
    shutdownEvent_ = nullptr;
    readyEvent_ = nullptr;
    engineKilled_ = false;
}

void TrayApp::setState(EngineState state) {
    if (state_ != state) stateSinceMs_ = GetTickCount64();
    state_ = state;
    updateIcon();
}

void TrayApp::refreshStartupAsync() {
    if (startupBusy_.exchange(true)) return;
    if (startupWorker_.joinable()) startupWorker_.join(); // previous run is finished
    const HWND target = window_;
    startupWorker_ = std::jthread([this, target](std::stop_token stop) {
        const std::optional<bool> exists = startupTaskExists(stop);
        startupBusy_ = false;
        if (exists && !stop.stop_requested()) {
            PostMessageW(target, kStartupQueried, *exists ? 1 : 0, 0);
        }
    });
}

void TrayApp::toggleStartup() {
    if (startupBusy_.exchange(true)) {
        showBalloon(L"SplitHello", L"Görev Zamanlayıcı işlemi sürüyor; birazdan tekrar deneyin.");
        return;
    }
    if (startupWorker_.joinable()) startupWorker_.join();
    const bool target = !startupEnabled_;
    const HWND window = window_;
    startupWorker_ = std::jthread([this, window, target](std::stop_token stop) {
        const StartupResult result = setStartupEnabled(target, stop);
        startupBusy_ = false;
        if (!stop.stop_requested()) {
            PostMessageW(window, kStartupChanged, static_cast<WPARAM>(result),
                         target ? 1 : 0);
        }
    });
}

void TrayApp::openLogDirectory() const {
    if (logDirectory_.empty()) return;
    ShellExecuteW(window_, L"open", logDirectory_.c_str(), nullptr, nullptr,
                  SW_SHOWNORMAL);
}

void TrayApp::openDashboard() {
    if (!dashboard_) {
        // Rules passed on the command line are merged into the engine's rules
        // but live outside config.json; the panel only needs to know about them.
        const auto cliRules = static_cast<unsigned>(std::count_if(
            engineArguments_.begin(), engineArguments_.end(),
            [](const std::wstring& argument) {
                return argument == L"--include-process" ||
                       argument == L"--exclude-process";
            }));
        dashboard_ = std::make_unique<DashboardPanel>(telemetryPath_,
                                                       liveStatsName_,
                                                       [this]() {
                                                           restartEngineForConfiguration();
                                                       },
                                                       cliRules);
    }
    dashboard_->show();
}

void TrayApp::restartEngineForConfiguration() {
    if (exiting_ || !canStart_) return;
    switch (state_) {
    case EngineState::Stopped:
    case EngineState::Stopping:
        // The user (or a pending exit) stopped protection; new settings apply on
        // the next manual Başlat instead of silently turning protection back on.
        return;
    case EngineState::Starting:
    case EngineState::Running:
        restartPending_ = false;
        restartAtMs_ = 0;
        configurationRestartPending_ = true;
        requestStop();
        return;
    case EngineState::Failed:
        // Crashed/failed on its own: the changed configuration may fix it.
        restartPending_ = false;
        restartAtMs_ = 0;
        if (!engineProcess_) startEngine();
        return;
    }
}

void TrayApp::setDnsMode(DnsMode mode) {
    Config config;
    config.load();
    if (config.loadFailed) {
        // Saving would replace the unreadable file with defaults.
        showBalloon(L"DNS modu değişmedi", L"Yapılandırma dosyası okunamadı.", NIIF_ERROR);
        return;
    }
    if (config.dnsMode == mode) return;
    if (mode == DnsMode::Worker && config.workerUrl.empty()) {
        showBalloon(L"Worker kurulumu gerekli",
                    L"Cloudflare kurulumu açılıyor; tarayıcıda izin verin.",
                    NIIF_WARNING);
        launchSetup(true);
        return;
    }
    config.dnsMode = mode;
    if (!config.save()) {
        showBalloon(L"DNS modu değişmedi", L"Yapılandırma kaydedilemedi.", NIIF_ERROR);
        return;
    }
    canStart_ = config.isValid();
    spdlog::info("DNS modu secildi: {}", mode == DnsMode::Worker ? "Worker" : "sistem");
    restartEngineForConfiguration();
}

LRESULT CALLBACK TrayApp::windowProc(HWND window, UINT message,
                                     WPARAM wParam, LPARAM lParam) {
    TrayApp* app = reinterpret_cast<TrayApp*>(
        GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        app = static_cast<TrayApp*>(create->lpCreateParams);
        app->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(app));
    }
    return app ? app->handleMessage(message, wParam, lParam)
               : DefWindowProcW(window, message, wParam, lParam);
}

LRESULT TrayApp::handleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == taskbarCreatedMessage_) {
        addIcon();
        updateIcon();
        return 0;
    }

    switch (message) {
    case kTrayCallback: {
        const UINT notification = LOWORD(lParam);
        if (notification == WM_CONTEXTMENU || notification == WM_RBUTTONUP) {
            showMenu();
        } else if (notification == WM_LBUTTONDBLCLK) {
            openDashboard();
        }
        return 0;
    }
    case kStartupQueried:
        startupEnabled_ = wParam != 0;
        return 0;
    case kStartupChanged: {
        const bool target = lParam != 0;
        switch (static_cast<StartupResult>(wParam)) {
        case StartupResult::Ok:
            startupEnabled_ = target;
            showBalloon(L"SplitHello",
                        target ? L"Windows ile otomatik başlangıç açıldı."
                               : L"Windows ile otomatik başlangıç kapatıldı.");
            break;
        case StartupResult::UnsafeLocation:
            showBalloon(L"Otomatik başlangıç açılamadı",
                        L"SplitHello yönetici yetkisiyle her oturumda çalışacağı için yalnızca "
                        L"standart kullanıcıların değiştiremeyeceği bir klasörden (örn. "
                        L"C:\\Program Files\\SplitHello) etkinleştirilebilir. Uygulamayı oraya "
                        L"taşıyıp tekrar deneyin.",
                        NIIF_WARNING);
            break;
        case StartupResult::Failed:
            showBalloon(L"Otomatik başlangıç değiştirilemedi",
                        L"Windows Görev Zamanlayıcı ayarı kaydedilemedi.", NIIF_ERROR);
            break;
        }
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case kCommandStart: startEngine(); break;
        case kCommandStop:
            configurationRestartPending_ = false; // an explicit stop wins
            requestStop();
            break;
        case kCommandStartup: toggleStartup(); break;
        case kCommandDnsWorker: setDnsMode(DnsMode::Worker); break;
        case kCommandDnsSystem: setDnsMode(DnsMode::System); break;
        case kCommandSetup: launchSetup(true); break;
        case kCommandOpenLogs: openLogDirectory(); break;
        case kCommandDashboard: openDashboard(); break;
        case kCommandExit: requestExit(); break;
        default: break;
        }
        return 0;
    case WM_TIMER:
        if (wParam == kPollTimerId) pollEngine();
        return 0;
    case WM_QUERYENDSESSION:
        return TRUE;
    case WM_ENDSESSION:
        if (wParam) requestExit();
        return 0;
    case WM_CLOSE:
        requestExit();
        return 0;
    case WM_DESTROY:
        KillTimer(window_, kPollTimerId);
        removeIcon();
        window_ = nullptr;
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window_, message, wParam, lParam);
    }
}
