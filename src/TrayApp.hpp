#pragma once

#include "Config.hpp"
#include "RecoveryPolicy.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

class DashboardPanel;

class TrayApp {
public:
    enum class EngineState {
        Stopped,
        Starting,
        Running,
        Stopping,
        Failed,
    };

    TrayApp(std::vector<std::wstring> engineArguments,
            std::wstring logDirectory,
            std::string telemetryPath,
            bool canStart);
    ~TrayApp();

    TrayApp(const TrayApp&) = delete;
    TrayApp& operator=(const TrayApp&) = delete;

    int run();

private:
    static LRESULT CALLBACK windowProc(HWND window, UINT message,
                                       WPARAM wParam, LPARAM lParam);
    LRESULT handleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    bool createWindow();
    bool addIcon();
    void removeIcon();
    void updateIcon();
    void showMenu();
    void showBalloon(const std::wstring& title, const std::wstring& message,
                     DWORD icon = NIIF_INFO);

    void startEngine(bool automatic = false);
    void requestStop();
    void requestExit();
    void pollEngine();
    void handleEngineExit(DWORD exitCode, uint64_t nowMs);
    void scheduleAutomaticRestart(DWORD exitCode, uint64_t nowMs,
                                  const wchar_t* reason = nullptr);
    void closeEngineHandles();
    void setState(EngineState state);

    // The Task Scheduler is only ever touched from startupWorker_ (with finite
    // timeouts); the UI thread reads the cached startupEnabled_.
    void refreshStartupAsync();
    void toggleStartup();
    void setDnsMode(DnsMode mode);
    void openLogDirectory() const;
    void openDashboard();
    void restartEngineForConfiguration();
    // Runs "splithello.exe --setup-only" in its own console (Cloudflare login +
    // Worker deploy). pollSetup() picks up the result and starts the engine.
    void launchSetup(bool wantWorkerMode);
    void pollSetup();

    std::vector<std::wstring> engineArguments_;
    std::wstring logDirectory_;
    std::wstring liveStatsName_;
    std::string telemetryPath_;
    std::unique_ptr<DashboardPanel> dashboard_;
    bool canStart_ = false;
    bool startupEnabled_ = false;
    bool exiting_ = false;
    bool restartPending_ = false;
    bool configurationRestartPending_ = false;
    bool engineKilled_ = false;
    uint64_t restartAtMs_ = 0;
    uint64_t stateSinceMs_ = 0;
    recovery::RestartBudget restartBudget_;
    EngineState state_ = EngineState::Stopped;

    HWND window_ = nullptr;
    NOTIFYICONDATAW iconData_{};
    UINT taskbarCreatedMessage_ = 0;
    HANDLE engineProcess_ = nullptr;
    HANDLE shutdownEvent_ = nullptr;
    HANDLE readyEvent_ = nullptr;
    HANDLE setupProcess_ = nullptr;
    bool setupWantsWorker_ = false;

    // Declared last so it is joined before any member it could touch.
    std::atomic<bool> startupBusy_{false};
    std::jthread startupWorker_;
};
