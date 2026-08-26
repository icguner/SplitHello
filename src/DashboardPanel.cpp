#include "DashboardPanel.hpp"

#include "Config.hpp"
#include "DashboardSource.g.hpp"
#include "Http.hpp"
#include "Json.hpp"
#include "LiveStats.hpp"
#include "Telemetry.hpp"

#include <WebView2.h>
#include <wrl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;

namespace {

constexpr wchar_t kWindowClass[] = L"SplitHello.DashboardWindow";
constexpr UINT kTestCompletedMessage = WM_APP + 20;

std::wstring widen(std::string_view value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           value.data(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), length);
    return result;
}

std::string narrow(std::wstring_view value) {
    if (value.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                           value.data(), (int)value.size(),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string result((size_t)length, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                        (int)value.size(), result.data(), length,
                        nullptr, nullptr);
    return result;
}

} // namespace

struct DashboardPanel::Impl {
    Impl(std::string databasePath, std::wstring statsName,
         std::function<void()> rulesChanged)
        : telemetryPath(std::move(databasePath)),
          liveStatsName(std::move(statsName)),
          onProcessRulesChanged(std::move(rulesChanged)) {}

    ~Impl() {
        testWorker.request_stop();
        if (testWorker.joinable()) testWorker.join();
        if (controller) controller->Close();
        webview.Reset();
        controller.Reset();
        environment.Reset();
        if (window) DestroyWindow(window);
        if (comInitialized) CoUninitialize();
    }

    bool show() {
        if (!ensureWindow()) return false;
        ShowWindow(window, SW_SHOW);
        SetForegroundWindow(window);
        if (webview) {
            refresh();
        } else if (!initializing) {
            initializeWebView();
        }
        return true;
    }

    void refresh() {
        if (!webview) return;
        postJson(telemetry::Store::dashboardJson(telemetryPath, windowDays));
        postLive();
    }

    void postJson(std::string_view json) const {
        if (!webview) return;
        const std::wstring message = widen(json);
        if (!message.empty()) webview->PostWebMessageAsJson(message.c_str());
    }

    void postLive() const {
        postJson(live_stats::toJson(live_stats::read(liveStatsName)));
    }

    static std::string jsonArray(const std::vector<std::string>& values) {
        std::string result = "[";
        for (size_t i = 0; i < values.size(); ++i) {
            if (i != 0) result += ',';
            result += "\"" + json::escape(values[i]) + "\"";
        }
        result += ']';
        return result;
    }

    void postProcessRules(std::string_view state = {},
                          std::string_view message = {}) const {
        Config config;
        if (!config.load()) {
            postJson("{\"messageType\":\"processRules\",\"state\":\"failed\","
                     "\"message\":\"Yapılandırma okunamadı.\","
                     "\"include\":[],\"exclude\":[]}");
            return;
        }

        std::ostringstream output;
        output << "{\"messageType\":\"processRules\",\"state\":\""
               << json::escape(std::string(state)) << "\",\"message\":\""
               << json::escape(std::string(message)) << "\",\"include\":"
               << jsonArray(config.processInclude) << ",\"exclude\":"
               << jsonArray(config.processExclude) << '}';
        postJson(output.str());
    }

    void saveProcessRules(std::string_view payload) {
        constexpr size_t kMaximumRules = 128;
        constexpr size_t kMaximumRuleLength = 1024;
        auto sanitize = [=](std::vector<std::string> rules) {
            std::vector<std::string> result;
            result.reserve(std::min(rules.size(), kMaximumRules));
            for (std::string& rule : rules) {
                if (rule.empty() || rule.size() > kMaximumRuleLength) continue;
                result.push_back(std::move(rule));
                if (result.size() == kMaximumRules) break;
            }
            return result;
        };

        std::vector<std::string> includes = sanitize(
            json::getStringArray(std::string(payload), "include"));
        std::vector<std::string> excludes = sanitize(
            json::getStringArray(std::string(payload), "exclude"));
        Config config;
        if (!config.load()) {
            postProcessRules("failed", "Yapılandırma okunamadı; kurallar değişmedi.");
            return;
        }
        if (config.processInclude == includes && config.processExclude == excludes) {
            postProcessRules("success", "Kurallar zaten güncel.");
            return;
        }

        config.processInclude = std::move(includes);
        config.processExclude = std::move(excludes);
        if (!config.save()) {
            postProcessRules("failed", "Kurallar kaydedilemedi.");
            return;
        }

        postProcessRules("success", "Kurallar kaydedildi; ağ motoru yenileniyor…");
        if (onProcessRulesChanged) onProcessRulesChanged();
    }

    void postTestState(std::string_view state, std::string_view message,
                       int status = 0, uint64_t elapsedMs = 0) const {
        std::ostringstream output;
        output << "{\"messageType\":\"test\",\"state\":\""
               << json::escape(std::string(state)) << "\",\"message\":\""
               << json::escape(std::string(message)) << "\",\"status\":"
               << status << ",\"elapsedMs\":" << elapsedMs << '}';
        postJson(output.str());
    }

    void startConnectionTest() {
        if (testRunning.exchange(true)) return;
        if (!live_stats::read(liveStatsName).online) {
            testRunning = false;
            postTestState("offline", "Önce ağ motorunu başlatın.");
            return;
        }

        postTestState("running", "HTTPS yolu sınanıyor…");
        if (testWorker.joinable()) testWorker.join();
        testWorker = std::jthread([this](std::stop_token stopToken) {
            const live_stats::Snapshot before = live_stats::read(liveStatsName);
            const auto started = std::chrono::steady_clock::now();
            http::Request request;
            request.method = "HEAD";
            request.host = "www.example.com";
            request.path = "/";
            request.timeoutMs = 6000;
            const http::Response response = http::perform(request);
            const uint64_t elapsedMs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started).count());

            const bool succeeded = response.status >= 200 && response.status < 400;
            const live_stats::Snapshot after = live_stats::read(liveStatsName);
            const bool relayObserved = after.online &&
                after.openedFlows > before.openedFlows;
            std::ostringstream result;
            result << "{\"messageType\":\"test\",\"state\":\""
                   << (succeeded && relayObserved
                           ? "success"
                           : (succeeded ? "warning" : "failed"))
                   << "\",\"message\":\""
                   << (succeeded && relayObserved
                           ? "HTTPS relay zinciri yanıt verdi."
                           : (succeeded
                                  ? "HTTPS yanıt verdi ancak relay akışı görülmedi; süreç filtresi bu uygulamayı atlıyor olabilir."
                                  : "HTTPS yolu yanıt vermedi; son kanıt zincirini kontrol edin."))
                   << "\",\"status\":" << response.status
                   << ",\"elapsedMs\":" << elapsedMs << '}';
            {
                std::scoped_lock lock(testMutex);
                testResult = result.str();
            }
            testRunning = false;
            if (!stopToken.stop_requested() && window) {
                PostMessageW(window, kTestCompletedMessage, 0, 0);
            }
        });
    }

    bool ensureWindow() {
        if (window) return true;

        if (!comInitialized) {
            const HRESULT comResult = CoInitializeEx(
                nullptr, COINIT_APARTMENTTHREADED);
            if (FAILED(comResult)) {
                MessageBoxW(nullptr, L"Windows COM altyapısı başlatılamadı.",
                            L"SplitHello — Teşhis", MB_OK | MB_ICONERROR);
                return false;
            }
            comInitialized = true;
        }

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = windowProc;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = kWindowClass;
        if (!RegisterClassExW(&windowClass) &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            MessageBoxW(nullptr, L"Teşhis penceresi oluşturulamadı.",
                        L"SplitHello", MB_OK | MB_ICONERROR);
            return false;
        }

        window = CreateWindowExW(
            WS_EX_APPWINDOW, kWindowClass, L"SplitHello — Yerel Teşhis",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1180, 780,
            nullptr, nullptr, GetModuleHandleW(nullptr), this);
        return window != nullptr;
    }

    void initializeWebView() {
        initializing = true;

        LPWSTR runtimeVersion = nullptr;
        if (FAILED(GetAvailableCoreWebView2BrowserVersionString(
                nullptr, &runtimeVersion))) {
            initializing = false;
            MessageBoxW(
                window,
                L"Teşhis paneli için Microsoft Edge WebView2 Runtime gerekli.",
                L"SplitHello", MB_OK | MB_ICONERROR);
            return;
        }
        CoTaskMemFree(runtimeVersion);

        std::filesystem::path userData =
            std::filesystem::path(telemetryPath).parent_path() / "webview2";
        std::error_code error;
        std::filesystem::create_directories(userData, error);
        const std::wstring userDataPath = userData.wstring();

        const HRESULT result = CreateCoreWebView2EnvironmentWithOptions(
            nullptr, userDataPath.c_str(), nullptr,
            Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
                [this](HRESULT status,
                       ICoreWebView2Environment* createdEnvironment) -> HRESULT {
                    if (FAILED(status) || !createdEnvironment) {
                        initializing = false;
                        showInitializationError();
                        return S_OK;
                    }
                    environment = createdEnvironment;
                    const HRESULT controllerResult =
                        environment->CreateCoreWebView2Controller(
                        window,
                        Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                            [this](HRESULT controllerStatus,
                                   ICoreWebView2Controller* createdController) -> HRESULT {
                                initializing = false;
                                if (FAILED(controllerStatus) || !createdController) {
                                    showInitializationError();
                                    return S_OK;
                                }
                                controller = createdController;
                                controller->get_CoreWebView2(&webview);
                                configureWebView();
                                return S_OK;
                            }).Get());
                    if (FAILED(controllerResult)) {
                        initializing = false;
                        showInitializationError();
                    }
                    return S_OK;
                }).Get());

        if (FAILED(result)) {
            initializing = false;
            showInitializationError();
        }
    }

    void configureWebView() {
        if (!webview || !controller) return;
        updateBounds();

        ComPtr<ICoreWebView2Settings> settings;
        if (SUCCEEDED(webview->get_Settings(&settings)) && settings) {
            settings->put_AreDevToolsEnabled(FALSE);
            settings->put_AreDefaultContextMenusEnabled(FALSE);
            settings->put_IsStatusBarEnabled(FALSE);
            settings->put_IsZoomControlEnabled(TRUE);
        }

        webview->add_WebMessageReceived(
            Callback<ICoreWebView2WebMessageReceivedEventHandler>(
                [this](ICoreWebView2*,
                       ICoreWebView2WebMessageReceivedEventArgs* arguments) -> HRESULT {
                    LPWSTR rawMessage = nullptr;
                    if (FAILED(arguments->TryGetWebMessageAsString(&rawMessage)) ||
                        !rawMessage) {
                        return S_OK;
                    }
                    const std::wstring message(rawMessage);
                    CoTaskMemFree(rawMessage);
                    constexpr std::wstring_view prefix = L"refresh:";
                    if (message.starts_with(prefix)) {
                        try {
                            const unsigned requested = static_cast<unsigned>(
                                std::stoul(message.substr(prefix.size())));
                            windowDays = std::clamp(requested, 1U, 90U);
                        } catch (...) {
                            // Ignore malformed messages from the embedded page.
                        }
                        refresh();
                    } else if (message == L"live") {
                        postLive();
                    } else if (message == L"test") {
                        startConnectionTest();
                    } else if (message == L"process-rules") {
                        postProcessRules();
                    } else {
                        static constexpr std::wstring_view savePrefix =
                            L"save-process-rules:";
                        if (message.starts_with(savePrefix)) {
                            const std::wstring payload = message.substr(savePrefix.size());
                            saveProcessRules(narrow(payload));
                        }
                    }
                    return S_OK;
                }).Get(),
            &messageToken);

        webview->add_NavigationCompleted(
            Callback<ICoreWebView2NavigationCompletedEventHandler>(
                [this](ICoreWebView2*,
                       ICoreWebView2NavigationCompletedEventArgs*) -> HRESULT {
                    refresh();
                    postProcessRules();
                    return S_OK;
                }).Get(),
            &navigationToken);

        const std::wstring html = widen(kDashboardHtml);
        if (html.empty() || FAILED(webview->NavigateToString(html.c_str()))) {
            showInitializationError();
        }
    }

    void updateBounds() const {
        if (!controller || !window) return;
        RECT bounds{};
        GetClientRect(window, &bounds);
        controller->put_Bounds(bounds);
    }

    void showInitializationError() const {
        MessageBoxW(window,
                    L"Yerel teşhis paneli başlatılamadı. WebView2 Runtime'ı "
                    L"denetleyip yeniden deneyin.",
                    L"SplitHello", MB_OK | MB_ICONERROR);
    }

    static LRESULT CALLBACK windowProc(HWND target, UINT message,
                                       WPARAM wParam, LPARAM lParam) {
        Impl* self = reinterpret_cast<Impl*>(
            GetWindowLongPtrW(target, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            self = static_cast<Impl*>(create->lpCreateParams);
            self->window = target;
            SetWindowLongPtrW(target, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(target, message, wParam, lParam);

        switch (message) {
        case WM_SIZE:
            self->updateBounds();
            return 0;
        case WM_DPICHANGED: {
            const auto* bounds = reinterpret_cast<const RECT*>(lParam);
            SetWindowPos(target, nullptr, bounds->left, bounds->top,
                         bounds->right - bounds->left,
                         bounds->bottom - bounds->top,
                         SWP_NOACTIVATE | SWP_NOZORDER);
            return 0;
        }
        case WM_CLOSE:
            ShowWindow(target, SW_HIDE);
            return 0;
        case kTestCompletedMessage: {
            std::string result;
            {
                std::scoped_lock lock(self->testMutex);
                result = self->testResult;
            }
            if (!result.empty()) self->postJson(result);
            self->postLive();
            return 0;
        }
        case WM_DESTROY:
            self->window = nullptr;
            return 0;
        default:
            return DefWindowProcW(target, message, wParam, lParam);
        }
    }

    std::string telemetryPath;
    std::wstring liveStatsName;
    std::function<void()> onProcessRulesChanged;
    unsigned windowDays = 30;
    bool initializing = false;
    bool comInitialized = false;
    HWND window = nullptr;
    EventRegistrationToken messageToken{};
    EventRegistrationToken navigationToken{};
    std::atomic<bool> testRunning{false};
    std::mutex testMutex;
    std::string testResult;
    std::jthread testWorker;
    ComPtr<ICoreWebView2Environment> environment;
    ComPtr<ICoreWebView2Controller> controller;
    ComPtr<ICoreWebView2> webview;
};

DashboardPanel::DashboardPanel(std::string telemetryPath,
                               std::wstring liveStatsName,
                               std::function<void()> onProcessRulesChanged)
    : impl_(std::make_unique<Impl>(std::move(telemetryPath),
                                  std::move(liveStatsName),
                                  std::move(onProcessRulesChanged))) {}

DashboardPanel::~DashboardPanel() = default;

bool DashboardPanel::show() {
    return impl_->show();
}

void DashboardPanel::refresh() {
    impl_->refresh();
}
