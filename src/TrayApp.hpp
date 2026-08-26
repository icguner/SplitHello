#pragma once

#include "RecoveryPolicy.hpp"

#include <memory>
#include <string>
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
    void scheduleAutomaticRestart(DWORD exitCode, uint64_t nowMs);
    void closeEngineHandles();
    void setState(EngineState state);

    bool isStartupEnabled() const;
    bool setStartupEnabled(bool enabled) const;
    void toggleStartup();
    void openLogDirectory() const;
    void openDashboard();
    void restartEngineForConfiguration();

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
    uint64_t restartAtMs_ = 0;
    recovery::RestartBudget restartBudget_;
    EngineState state_ = EngineState::Stopped;

    HWND window_ = nullptr;
    NOTIFYICONDATAW iconData_{};
    UINT taskbarCreatedMessage_ = 0;
    HANDLE engineProcess_ = nullptr;
    HANDLE shutdownEvent_ = nullptr;
    HANDLE readyEvent_ = nullptr;
};
