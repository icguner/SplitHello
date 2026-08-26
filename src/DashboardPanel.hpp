#pragma once

#include <functional>
#include <memory>
#include <string>

// Lazy WebView2 host for the local diagnostics dashboard. The implementation
// lives behind a pimpl so WebView2 headers do not leak into the tray code.
class DashboardPanel {
public:
    DashboardPanel(std::string telemetryPath, std::wstring liveStatsName,
                   std::function<void()> onProcessRulesChanged = {});
    ~DashboardPanel();

    DashboardPanel(const DashboardPanel&) = delete;
    DashboardPanel& operator=(const DashboardPanel&) = delete;

    bool show();
    void refresh();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
