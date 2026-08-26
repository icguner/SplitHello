#include "TrayApp.hpp"

#include <spdlog/spdlog.h>

#include <filesystem>
#include <string_view>

namespace {

constexpr wchar_t kWindowClass[] = L"SplitHello.TrayWindow";
constexpr wchar_t kTaskName[] = L"\\SplitHello";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallback = WM_APP + 1;
constexpr UINT_PTR kPollTimerId = 1;

constexpr UINT kCommandStart = 1001;
constexpr UINT kCommandStop = 1002;
constexpr UINT kCommandStartup = 1003;
constexpr UINT kCommandOpenLogs = 1004;
constexpr UINT kCommandExit = 1005;

std::wstring quoteWindowsArgument(const std::wstring& argument) {
    if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) return argument;

    std::wstring result = L"\"";
    size_t backslashes = 0;
    for (const wchar_t character : argument) {
        if (character == L'\\') {
            backslashes++;
            continue;
        }
        if (character == L'\"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(character);
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(character);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

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

bool runHiddenProcess(const std::wstring& application,
                      const std::vector<std::wstring>& arguments) {
    std::wstring commandLine = quoteWindowsArgument(application);
    for (const std::wstring& argument : arguments) {
        commandLine.push_back(L' ');
        commandLine += quoteWindowsArgument(argument);
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(application.c_str(), commandLine.data(), nullptr, nullptr,
                        FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                        &startup, &process)) {
        return false;
    }

    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    return exitCode == 0;
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
    LPCWSTR resource = MAKEINTRESOURCEW(32512); // IDI_APPLICATION
    if (state == TrayApp::EngineState::Running) resource = MAKEINTRESOURCEW(32518); // IDI_SHIELD
    else if (state == TrayApp::EngineState::Starting) resource = MAKEINTRESOURCEW(32516); // IDI_INFORMATION
    else if (state == TrayApp::EngineState::Stopping) resource = MAKEINTRESOURCEW(32515); // IDI_WARNING
    else if (state == TrayApp::EngineState::Failed) resource = MAKEINTRESOURCEW(32513); // IDI_ERROR
    return LoadIconW(nullptr, resource);
}

} // namespace

TrayApp::TrayApp(std::vector<std::wstring> engineArguments,
                 std::wstring logDirectory,
                 bool canStart)
    : engineArguments_(std::move(engineArguments)),
      logDirectory_(std::move(logDirectory)),
      canStart_(canStart) {}

TrayApp::~TrayApp() {
    removeIcon();
    closeEngineHandles();
    if (window_) DestroyWindow(window_);
}

int TrayApp::run() {
    if (!createWindow() || !addIcon()) return 1;

    startupEnabled_ = isStartupEnabled();
    SetTimer(window_, kPollTimerId, 250, nullptr);

    if (canStart_) {
        startEngine();
    } else {
        showBalloon(L"SplitHello kurulumu gerekli",
                    L"Önce bir terminalde splithello.exe --setup çalıştırın.",
                    NIIF_WARNING);
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
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
    startupEnabled_ = isStartupEnabled();

    HMENU menu = CreatePopupMenu();
    if (!menu) return;

    AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, stateText(state_));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    const bool stopped = state_ == EngineState::Stopped || state_ == EngineState::Failed;
    AppendMenuW(menu, MF_STRING | ((!stopped || !canStart_) ? MF_DISABLED : 0),
                kCommandStart, L"Başlat");
    AppendMenuW(menu, MF_STRING | (stopped ? MF_DISABLED : 0),
                kCommandStop, L"Durdur");
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

    std::wstring commandLine = quoteWindowsArgument(executable);
    for (const std::wstring& argument : arguments) {
        commandLine.push_back(L' ');
        commandLine += quoteWindowsArgument(argument);
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
    if (!engineProcess_ || state_ == EngineState::Stopping) return;
    setState(EngineState::Stopping);
    if (shutdownEvent_) SetEvent(shutdownEvent_);
}

void TrayApp::requestExit() {
    exiting_ = true;
    restartPending_ = false;
    restartAtMs_ = 0;
    if (engineProcess_) {
        requestStop();
    } else {
        DestroyWindow(window_);
    }
}

void TrayApp::pollEngine() {
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

    if (WaitForSingleObject(engineProcess_, 0) != WAIT_OBJECT_0) return;

    DWORD exitCode = 1;
    GetExitCodeProcess(engineProcess_, &exitCode);
    const bool expected = state_ == EngineState::Stopping || exiting_;
    closeEngineHandles();

    if (exiting_) {
        DestroyWindow(window_);
        return;
    }

    if (expected) {
        setState(EngineState::Stopped);
        showBalloon(L"SplitHello", L"Koruma durduruldu.");
    } else {
        scheduleAutomaticRestart(exitCode, nowMs);
    }
}

void TrayApp::scheduleAutomaticRestart(DWORD exitCode, uint64_t nowMs) {
    setState(EngineState::Failed);
    const unsigned attempt = restartBudget_.consume(nowMs);
    if (attempt == 0) {
        spdlog::error(
            "Ag motoru cok sik durdu (son cikis={}); otomatik yeniden baslatma durduruldu",
            exitCode);
        showBalloon(
            L"SplitHello koruması durdu",
            L"Normal internet yolu açık. Yeniden başlatma sınırına ulaşıldı; tray'den Başlat seçin.",
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
        L"Filtre kapatıldı; normal internet yolu açık. Ağ motoru kısa süre içinde yeniden başlayacak.",
        NIIF_WARNING);
}

void TrayApp::closeEngineHandles() {
    if (engineProcess_) CloseHandle(engineProcess_);
    if (shutdownEvent_) CloseHandle(shutdownEvent_);
    if (readyEvent_) CloseHandle(readyEvent_);
    engineProcess_ = nullptr;
    shutdownEvent_ = nullptr;
    readyEvent_ = nullptr;
}

void TrayApp::setState(EngineState state) {
    state_ = state;
    updateIcon();
}

bool TrayApp::isStartupEnabled() const {
    return runHiddenProcess(systemExecutable(L"schtasks.exe"),
                            {L"/Query", L"/TN", kTaskName});
}

bool TrayApp::setStartupEnabled(bool enabled) const {
    const std::wstring scheduler = systemExecutable(L"schtasks.exe");
    if (!enabled) {
        if (!isStartupEnabled()) return true;
        return runHiddenProcess(scheduler, {L"/Delete", L"/TN", kTaskName, L"/F"});
    }

    const std::wstring executable = executablePath();
    if (executable.empty()) return false;
    const std::wstring taskAction = quoteWindowsArgument(executable);
    return runHiddenProcess(scheduler,
                            {L"/Create", L"/TN", kTaskName,
                             L"/SC", L"ONLOGON", L"/RL", L"HIGHEST",
                             L"/DELAY", L"0000:05", L"/TR", taskAction,
                             L"/F"});
}

void TrayApp::toggleStartup() {
    const bool target = !startupEnabled_;
    if (!setStartupEnabled(target)) {
        showBalloon(L"Otomatik başlangıç değiştirilemedi",
                    L"Windows Görev Zamanlayıcı ayarı kaydedilemedi.", NIIF_ERROR);
        return;
    }
    startupEnabled_ = target;
    showBalloon(L"SplitHello",
                target ? L"Windows ile otomatik başlangıç açıldı."
                       : L"Windows ile otomatik başlangıç kapatıldı.");
}

void TrayApp::openLogDirectory() const {
    if (logDirectory_.empty()) return;
    ShellExecuteW(window_, L"open", logDirectory_.c_str(), nullptr, nullptr,
                  SW_SHOWNORMAL);
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
            if (state_ == EngineState::Stopped || state_ == EngineState::Failed) {
                startEngine();
            } else if (state_ == EngineState::Running) {
                requestStop();
            }
        }
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case kCommandStart: startEngine(); break;
        case kCommandStop: requestStop(); break;
        case kCommandStartup: toggleStartup(); break;
        case kCommandOpenLogs: openLogDirectory(); break;
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
