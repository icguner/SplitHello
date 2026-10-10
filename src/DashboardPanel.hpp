#pragma once

#include <functional>
#include <memory>
#include <string>

// Native Direct2D/DirectWrite host for the local diagnostics dashboard. The
// implementation lives behind a pimpl so the Win32/Direct2D headers do not leak
// into the tray code.
struct tagMSG;

class DashboardPanel {
public:
    // `cliProcessRules` is how many --include/--exclude-process rules were given
    // on the command line; they are merged into the engine but not editable here.
    DashboardPanel(std::string telemetryPath, std::wstring liveStatsName,
                   std::function<void()> onProcessRulesChanged = {},
                   unsigned cliProcessRules = 0);
    ~DashboardPanel();

    DashboardPanel(const DashboardPanel&) = delete;
    DashboardPanel& operator=(const DashboardPanel&) = delete;

    bool show();
    void refresh();

    // Call from the thread's message loop before TranslateMessage; true means the
    // dashboard consumed the message (Tab/Enter/Esc dialog navigation).
    bool translateMessage(tagMSG& message);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
