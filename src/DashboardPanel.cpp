#include "DashboardPanel.hpp"

#include "Config.hpp"
#include "Http.hpp"
#include "LiveStats.hpp"
#include "Telemetry.hpp"

#include <d2d1.h>
#include <d2d1helper.h>
#include <dwrite_1.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <dwmapi.h>

// Note: <windows.h> defines DrawText as a macro (-> DrawTextW). d2d1.h includes
// windows.h itself, so ID2D1RenderTarget's method is likewise declared as
// DrawTextW; the calls below spell it DrawText and rely on that same macro. We
// never call the Win32 DrawText API here.

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

using Microsoft::WRL::ComPtr;

// ---------------------------------------------------------------------------
// SplitHello - native diagnostics console.
//
// Design language: a technical bulletin, not a widget dashboard. There are no
// cards, shadows or rounded panels; content sits directly on a warm paper
// ground and is organised by numbered sections and hairline rules, the way a
// printed instrument report is. Density and typography carry the hierarchy.
//
// Colour is reserved for meaning and is never decorative. Exactly four signals
// are used, and each means the same thing everywhere it appears:
//
//     quiet     the untouched baseline - nothing was done, so it recedes
//     acted     SplitHello intervened and a profile won (prussian)
//     failed    unresolved: no successful counter-experiment (vermillion)
//     caution   slow, or a qualified result
//
// Everything else - rules, labels, axes, prose - is ink on paper at varying
// strength. A window with no incidents therefore shows almost no colour.
//
// Rendering is Direct2D/DirectWrite on one surface; everything interactive is a
// real Win32 child control, so focus, keyboard traversal and screen readers
// work without a custom UI Automation provider.
// ---------------------------------------------------------------------------

namespace {

constexpr wchar_t kWindowClass[] = L"SplitHello.DashboardWindow";
constexpr UINT kTestCompletedMessage = WM_APP + 20;

constexpr int kIdRange24 = 3001;
constexpr int kIdRange7 = 3002;
constexpr int kIdRange30 = 3003;
constexpr int kIdRefresh = 3004;
constexpr int kIdTest = 3005;
constexpr int kIdInclude = 3006;
constexpr int kIdExclude = 3007;
constexpr int kIdSave = 3008;
constexpr int kIdSearch = 3009;
constexpr int kIdOutcomeAll = 3010;
constexpr int kIdOutcomeBypassed = 3011;
constexpr int kIdOutcomeClean = 3012;
constexpr int kIdOutcomeUnresolved = 3013;
constexpr int kIdSortRecent = 3014;
constexpr int kIdSortSlowest = 3015;
constexpr int kIdSortAttempts = 3016;

constexpr UINT_PTR kTimerLive = 1;
constexpr UINT_PTR kTimerData = 2;

// How many ledger rows are laid out at once. The query keeps far more so the
// filters have material to work with; the panel draws a readable slice.
constexpr size_t kMaxLedgerRows = 40;

std::wstring widen(std::string_view value) {
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(),
                        static_cast<int>(value.size()), result.data(), length);
    return result;
}

std::string narrow(std::wstring_view value) {
    if (value.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string result(static_cast<size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), length, nullptr, nullptr);
    return result;
}

std::string lowered(std::string value) {
    for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return value;
}

std::wstring trLabel(const std::string& key) {
    struct Pair { const char* k; const wchar_t* v; };
    static const Pair table[] = {
        {"unknown", L"belirsiz"},
        {"no-interference", L"müdahale yok"},
        {"sni-interference-likely", L"SNI müdahalesi olası"},
        {"tls-incompatible", L"TLS uyumsuzluğu"},
        {"transport-failure", L"taşıma hatası"},
        {"throttling-suspected", L"yavaşlatma şüphesi"},
        {"server-hello", L"ServerHello"},
        {"tls-alert", L"TLS Alert"},
        {"timeout", L"zaman aşımı"},
        {"reset", L"RST"},
        {"closed", L"kapandı"},
        {"unexpected", L"beklenmeyen"},
        {"not-tested", L"denenmedi"},
        {"none", L"dokunulmadı"},
    };
    for (const Pair& pair : table) {
        if (key == pair.k) return pair.v;
    }
    if (key.empty()) return L"—";
    return widen(key);
}

// Thousands grouping with a dot separator, matching tr-TR formatting.
std::wstring groupCount(int64_t value) {
    const bool negative = value < 0;
    const uint64_t magnitude = negative ? static_cast<uint64_t>(-value)
                                        : static_cast<uint64_t>(value);
    const std::wstring digits = std::to_wstring(magnitude);
    std::wstring grouped;
    int seen = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (seen && seen % 3 == 0) grouped.push_back(L'.');
        grouped.push_back(*it);
        ++seen;
    }
    std::reverse(grouped.begin(), grouped.end());
    if (negative) grouped.insert(grouped.begin(), L'-');
    return grouped;
}

// Milliseconds at a readable magnitude: 84 ms, 1,20 s, 12,4 s.
std::wstring formatMs(int64_t milliseconds) {
    wchar_t buffer[32];
    if (milliseconds < 1000) {
        std::swprintf(buffer, 32, L"%lld ms", static_cast<long long>(milliseconds));
    } else if (milliseconds < 10000) {
        std::swprintf(buffer, 32, L"%.2f s", milliseconds / 1000.0);
    } else {
        std::swprintf(buffer, 32, L"%.1f s", milliseconds / 1000.0);
    }
    std::wstring result = buffer;
    const size_t dot = result.find(L'.');
    if (dot != std::wstring::npos) result[dot] = L',';
    return result;
}

std::wstring shortStamp(int64_t unixSeconds) {
    const std::time_t raw = static_cast<std::time_t>(unixSeconds);
    std::tm local{};
    localtime_s(&local, &raw);
    wchar_t buffer[40];
    if (!std::wcsftime(buffer, 40, L"%d.%m.%Y  %H:%M:%S", &local)) return L"";
    return buffer;
}

std::wstring clockStamp(int64_t unixSeconds) {
    const std::time_t raw = static_cast<std::time_t>(unixSeconds);
    std::tm local{};
    localtime_s(&local, &raw);
    wchar_t buffer[16];
    if (!std::wcsftime(buffer, 16, L"%H:%M:%S", &local)) return L"";
    return buffer;
}

std::wstring formatUptime(int64_t seconds) {
    if (seconds < 0) return L"yeni başladı";
    const int64_t hours = seconds / 3600;
    const int64_t minutes = (seconds % 3600) / 60;
    wchar_t buffer[64];
    if (hours) {
        std::swprintf(buffer, 64, L"%lld sa %lld dk", hours, minutes);
    } else {
        std::swprintf(buffer, 64, L"%lld dk", minutes);
    }
    return buffer;
}

int64_t nowUnix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Rounds an axis bound up to 1, 2, 2.5 or 5 times a power of ten so gridline
// labels land on values a reader can do arithmetic with.
double niceCeil(double value) {
    if (value <= 0) return 1;
    const double magnitude = std::pow(10.0, std::floor(std::log10(value)));
    const double normalised = value / magnitude;
    double nice;
    if (normalised <= 1.0) nice = 1.0;
    else if (normalised <= 2.0) nice = 2.0;
    else if (normalised <= 2.5) nice = 2.5;
    else if (normalised <= 5.0) nice = 5.0;
    else nice = 10.0;
    return nice * magnitude;
}

// --- palette ---------------------------------------------------------------
//
// Warm paper and ink with four signal colours. See the file header: colour is
// meaning, never decoration.

struct Theme {
    D2D1_COLOR_F ground;      // page
    D2D1_COLOR_F band;        // tonal band (status strip, table headings)
    D2D1_COLOR_F bandSoft;    // alternating row wash
    D2D1_COLOR_F hover;       // pointer highlight
    D2D1_COLOR_F ink;         // primary text
    D2D1_COLOR_F inkSoft;     // secondary text
    D2D1_COLOR_F inkFaint;    // metadata, axis labels
    D2D1_COLOR_F mastRule;    // heavy masthead rule
    D2D1_COLOR_F rule;        // structural hairline
    D2D1_COLOR_F ruleFaint;   // gridline, meter track
    D2D1_COLOR_F quiet;    // signal: untouched baseline
    D2D1_COLOR_F acted;      // signal: intervened, a profile won
    D2D1_COLOR_F actedWash;
    D2D1_COLOR_F failed;  // signal: unresolved
    D2D1_COLOR_F failedWash;
    D2D1_COLOR_F caution;       // signal: caution / slow
    D2D1_COLOR_F cautionWash;
    bool dark = false;
};

D2D1_COLOR_F rgb(UINT32 hex, float alpha = 1.0f) {
    return D2D1::ColorF(hex, alpha);
}

Theme paperTheme() {
    Theme t{};
    t.ground = rgb(0xF5F2EA);
    t.band = rgb(0xEAE5D9);
    t.bandSoft = rgb(0x221F1B, 0.028f);
    t.hover = rgb(0x1F4E79, 0.070f);
    t.ink = rgb(0x221F1B);
    t.inkSoft = rgb(0x554F46);
    t.inkFaint = rgb(0x8A8175);
    t.mastRule = rgb(0x221F1B);
    t.rule = rgb(0xCBC3B3);
    t.ruleFaint = rgb(0xE1DBCE);
    t.quiet = rgb(0xA69B8B);
    t.acted = rgb(0x1F4E79);
    t.actedWash = rgb(0xD8E3EE);
    t.failed = rgb(0xB03A1E);
    t.failedWash = rgb(0xF3DFD7);
    t.caution = rgb(0x94670F);
    t.cautionWash = rgb(0xF1E4C6);
    t.dark = false;
    return t;
}

Theme inkTheme() {
    Theme t{};
    t.ground = rgb(0x15140F);
    t.band = rgb(0x1E1C15);
    t.bandSoft = rgb(0xF0EBE0, 0.030f);
    t.hover = rgb(0x77A9D8, 0.100f);
    t.ink = rgb(0xF0EBE0);
    t.inkSoft = rgb(0xB4AC9C);
    t.inkFaint = rgb(0x827A6B);
    t.mastRule = rgb(0x3E382E);
    t.rule = rgb(0x332E25);
    t.ruleFaint = rgb(0x252117);
    t.quiet = rgb(0x7C7364);
    t.acted = rgb(0x77A9D8);
    t.actedWash = rgb(0x18293A);
    t.failed = rgb(0xE0705A);
    t.failedWash = rgb(0x3A221B);
    t.caution = rgb(0xD8A445);
    t.cautionWash = rgb(0x33280E);
    t.dark = true;
    return t;
}

bool systemUsesDarkMode() {
    // SPLITHELLO_THEME=light|dark forces a palette. The panel otherwise follows
    // the system setting; the override exists so either theme can be inspected
    // without changing the machine's appearance.
    wchar_t forced[16];
    const DWORD length = GetEnvironmentVariableW(L"SPLITHELLO_THEME", forced, 16);
    if (length > 0 && length < 16) {
        if (_wcsicmp(forced, L"dark") == 0) return true;
        if (_wcsicmp(forced, L"light") == 0) return false;
    }

    DWORD value = 1;
    DWORD size = sizeof(value);
    if (RegGetValueW(HKEY_CURRENT_USER,
                     L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\"
                     L"Personalize",
                     L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &value,
                     &size) == ERROR_SUCCESS) {
        return value == 0;
    }
    return false;
}

std::vector<std::string> splitLines(const std::wstring& text) {
    std::vector<std::string> lines;
    std::unordered_set<std::string> seen;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find(L'\n', start);
        std::wstring raw = text.substr(
            start, end == std::wstring::npos ? std::wstring::npos : end - start);
        while (!raw.empty() && (raw.back() == L'\r' || raw.back() == L' ' ||
                                raw.back() == L'\t')) {
            raw.pop_back();
        }
        const size_t begin = raw.find_first_not_of(L" \t");
        if (begin != std::wstring::npos) {
            std::string value = narrow(raw.substr(begin));
            if (!value.empty() && value.size() <= 1024 &&
                seen.insert(value).second) {
                lines.push_back(std::move(value));
                if (lines.size() >= 128) break;
            }
        }
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
    return lines;
}

enum class Outcome { All, Bypassed, Clean, Unresolved };
enum class Ordering { Recent, Slowest, Attempts };

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
        if (window) DestroyWindow(window);
        if (controlFont) DeleteObject(controlFont);
    }

    // ---- lifecycle ---------------------------------------------------------

    bool show() {
        if (!ensureWindow()) return false;
        loadData();
        loadProcessRules();
        ShowWindow(window, SW_SHOW);
        SetForegroundWindow(window);
        SetTimer(window, kTimerLive, 1000, nullptr);
        SetTimer(window, kTimerData, 10000, nullptr);
        relayout();
        invalidate();
        return true;
    }

    void refresh() {
        if (!window) return;
        loadData();
        relayout();
        invalidate();
    }

    void invalidate() const {
        if (window) InvalidateRect(window, nullptr, FALSE);
    }

    // ---- data --------------------------------------------------------------

    void loadData() {
        data = telemetry::Store::dashboardSnapshot(telemetryPath, windowDays);
        live = live_stats::read(liveStatsName);
        applyFilters();
        syncTestButton();
    }

    void loadLive() {
        live = live_stats::read(liveStatsName);
        syncTestButton();
    }

    // Host search, outcome filter and ordering, applied over the fetched window.
    void applyFilters() {
        visible.clear();
        // Read the box directly so every refresh path agrees with what is shown,
        // rather than depending on an EN_CHANGE having been observed.
        const std::string needle = lowered(narrow(editText(searchEdit)));
        for (size_t i = 0; i < data.recent.size(); ++i) {
            const telemetry::DashboardData::Event& event = data.recent[i];
            if (!needle.empty() &&
                lowered(event.host).find(needle) == std::string::npos) {
                continue;
            }
            const bool bypassed = event.success && event.winner != "none";
            const bool clean = event.success && event.winner == "none";
            switch (outcome) {
            case Outcome::Bypassed: if (!bypassed) continue; break;
            case Outcome::Clean: if (!clean) continue; break;
            case Outcome::Unresolved: if (event.success) continue; break;
            case Outcome::All: break;
            }
            visible.push_back(i);
        }

        const auto& events = data.recent;
        if (ordering == Ordering::Slowest) {
            std::stable_sort(visible.begin(), visible.end(),
                             [&events](size_t left, size_t right) {
                                 return events[left].totalElapsedMs >
                                        events[right].totalElapsedMs;
                             });
        } else if (ordering == Ordering::Attempts) {
            std::stable_sort(visible.begin(), visible.end(),
                             [&events](size_t left, size_t right) {
                                 return events[left].attemptCount >
                                        events[right].attemptCount;
                             });
        }
        // Ordering::Recent keeps the query's id-descending order.
        hoverEvent = -1;
    }

    void loadProcessRules() {
        Config config;
        if (!config.load()) {
            ruleStatus = L"Yapılandırma okunamadı.";
            ruleStatusKind = 2;
            return;
        }
        std::wstring include;
        for (const std::string& rule : config.processInclude) {
            include += widen(rule);
            include += L"\r\n";
        }
        std::wstring exclude;
        for (const std::string& rule : config.processExclude) {
            exclude += widen(rule);
            exclude += L"\r\n";
        }
        if (includeEdit) SetWindowTextW(includeEdit, include.c_str());
        if (excludeEdit) SetWindowTextW(excludeEdit, exclude.c_str());
        ruleStatus = L"Kurallar hazır. Boş include tüm süreçleri kapsar.";
        ruleStatusKind = 0;
    }

    std::wstring editText(HWND edit) const {
        if (!edit) return {};
        const int length = GetWindowTextLengthW(edit);
        if (length <= 0) return {};
        std::wstring buffer(static_cast<size_t>(length) + 1, L'\0');
        GetWindowTextW(edit, buffer.data(), length + 1);
        buffer.resize(static_cast<size_t>(length));
        return buffer;
    }

    void saveProcessRules() {
        std::vector<std::string> includes = splitLines(editText(includeEdit));
        std::vector<std::string> excludes = splitLines(editText(excludeEdit));
        Config config;
        if (!config.load()) {
            ruleStatus = L"Yapılandırma okunamadı; kurallar değişmedi.";
            ruleStatusKind = 2;
            invalidate();
            return;
        }
        if (config.processInclude == includes &&
            config.processExclude == excludes) {
            ruleStatus = L"Kurallar zaten güncel.";
            ruleStatusKind = 1;
            invalidate();
            return;
        }
        config.processInclude = std::move(includes);
        config.processExclude = std::move(excludes);
        if (!config.save()) {
            ruleStatus = L"Kurallar kaydedilemedi.";
            ruleStatusKind = 2;
            invalidate();
            return;
        }
        ruleStatus = L"Kurallar kaydedildi; ağ motoru yenileniyor…";
        ruleStatusKind = 1;
        invalidate();
        if (onProcessRulesChanged) onProcessRulesChanged();
    }

    void syncTestButton() {
        if (!testButton) return;
        if (testRunning.load()) {
            EnableWindow(testButton, FALSE);
            SetWindowTextW(testButton, L"Test ediliyor…");
        } else {
            EnableWindow(testButton, live.online ? TRUE : FALSE);
            SetWindowTextW(testButton, L"Bağlantıyı sına");
        }
    }

    void startConnectionTest() {
        if (testRunning.exchange(true)) return;
        if (!live_stats::read(liveStatsName).online) {
            testRunning = false;
            testState = 3;
            testMessage = L"Önce ağ motorunu başlatın.";
            syncTestButton();
            invalidate();
            return;
        }
        testState = 4;
        testMessage = L"HTTPS yolu sınanıyor…";
        testStatus = 0;
        testElapsedMs = 0;
        syncTestButton();
        invalidate();

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
                    std::chrono::steady_clock::now() - started)
                    .count());
            const bool succeeded = response.status >= 200 && response.status < 400;
            const live_stats::Snapshot after = live_stats::read(liveStatsName);
            const bool relayObserved =
                after.online && after.openedFlows > before.openedFlows;
            {
                std::scoped_lock lock(testMutex);
                pendingStatus = response.status;
                pendingElapsedMs = elapsedMs;
                if (succeeded && relayObserved) {
                    pendingState = 0;
                    pendingMessage = L"Relay zinciri yanıt verdi.";
                } else if (succeeded) {
                    pendingState = 1;
                    pendingMessage =
                        L"HTTPS yanıt verdi, relay akışı görülmedi; süreç "
                        L"filtresi bu uygulamayı atlıyor olabilir.";
                } else {
                    pendingState = 2;
                    pendingMessage =
                        L"HTTPS yolu yanıt vermedi; kanıt defterine bakın.";
                }
            }
            testRunning = false;
            if (!stopToken.stop_requested() && window) {
                PostMessageW(window, kTestCompletedMessage, 0, 0);
            }
        });
    }

    void applyTestResult() {
        std::scoped_lock lock(testMutex);
        testState = pendingState;
        testMessage = pendingMessage;
        testStatus = pendingStatus;
        testElapsedMs = pendingElapsedMs;
    }

    // ---- window & controls -------------------------------------------------

    bool ensureWindow() {
        if (window) return true;

        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.style = CS_HREDRAW | CS_VREDRAW;
        windowClass.lpfnWndProc = windowProc;
        windowClass.hInstance = GetModuleHandleW(nullptr);
        windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hbrBackground = nullptr;
        windowClass.lpszClassName = kWindowClass;
        if (!RegisterClassExW(&windowClass) &&
            GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            MessageBoxW(nullptr, L"Teşhis penceresi oluşturulamadı.",
                        L"SplitHello", MB_OK | MB_ICONERROR);
            return false;
        }

        window = CreateWindowExW(
            WS_EX_APPWINDOW, kWindowClass, L"SplitHello — Yerel Teşhis",
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VSCROLL, CW_USEDEFAULT,
            CW_USEDEFAULT, 1320, 900, nullptr, nullptr,
            GetModuleHandleW(nullptr), this);
        if (!window) return false;

        dark = systemUsesDarkMode();
        theme = dark ? inkTheme() : paperTheme();
        const BOOL darkFlag = dark ? TRUE : FALSE;
        DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkFlag,
                              sizeof(darkFlag));

        dpi = GetDpiForWindow(window);
        if (dpi == 0) dpi = 96;
        scale = static_cast<float>(dpi) / 96.0f;

        if (!createGraphics()) {
            MessageBoxW(window, L"Direct2D başlatılamadı.", L"SplitHello",
                        MB_OK | MB_ICONERROR);
            return false;
        }
        createFonts();
        createControls();
        return true;
    }

    bool createGraphics() {
        if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,
                                     d2dFactory.GetAddressOf()))) {
            return false;
        }
        if (FAILED(DWriteCreateFactory(
                DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                reinterpret_cast<IUnknown**>(dwrite.GetAddressOf())))) {
            return false;
        }
        createTextFormats();
        return true;
    }

    ComPtr<IDWriteTextFormat> makeFormat(const wchar_t* family, float sizeLogical,
                                         DWRITE_FONT_WEIGHT weight,
                                         bool singleLine) const {
        ComPtr<IDWriteTextFormat> format;
        dwrite->CreateTextFormat(family, nullptr, weight, DWRITE_FONT_STYLE_NORMAL,
                                 DWRITE_FONT_STRETCH_NORMAL, sizeLogical * scale,
                                 L"", format.GetAddressOf());
        if (!format) return format;
        format->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);
        format->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        if (singleLine) {
            format->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
            DWRITE_TRIMMING trimming{DWRITE_TRIMMING_GRANULARITY_CHARACTER, 0, 0};
            ComPtr<IDWriteInlineObject> sign;
            dwrite->CreateEllipsisTrimmingSign(format.Get(), sign.GetAddressOf());
            format->SetTrimming(&trimming, sign.Get());
        } else {
            format->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
        }
        return format;
    }

    void createTextFormats() {
        // A DIN-derived grotesque for figures and titles (instrument lettering),
        // a mono for labels and tabular data, and a humanist sans for prose.
        const wchar_t* figure = L"Bahnschrift";
        const wchar_t* mono = L"Cascadia Mono";
        const wchar_t* prose = L"Segoe UI";
        fmtWordmark = makeFormat(figure, 17, DWRITE_FONT_WEIGHT_BOLD, true);
        fmtLede = makeFormat(figure, 27, DWRITE_FONT_WEIGHT_SEMI_BOLD, true);
        fmtFigure = makeFormat(figure, 34, DWRITE_FONT_WEIGHT_SEMI_BOLD, true);
        fmtFigureSm = makeFormat(figure, 21, DWRITE_FONT_WEIGHT_SEMI_BOLD, true);
        fmtSection = makeFormat(figure, 15, DWRITE_FONT_WEIGHT_SEMI_BOLD, true);
        fmtHost = makeFormat(figure, 14.5f, DWRITE_FONT_WEIGHT_SEMI_BOLD, true);
        fmtBody = makeFormat(prose, 13, DWRITE_FONT_WEIGHT_NORMAL, false);
        fmtBodyLine = makeFormat(prose, 12.5f, DWRITE_FONT_WEIGHT_NORMAL, true);
        fmtMono = makeFormat(mono, 11, DWRITE_FONT_WEIGHT_NORMAL, true);
        fmtMonoSm = makeFormat(mono, 9.5f, DWRITE_FONT_WEIGHT_NORMAL, true);
        fmtTicker = makeFormat(mono, 9.5f, DWRITE_FONT_WEIGHT_SEMI_BOLD, true);
    }

    void createFonts() {
        if (controlFont) DeleteObject(controlFont);
        LOGFONTW logfont{};
        logfont.lfHeight = -MulDiv(10, static_cast<int>(dpi), 72);
        logfont.lfWeight = FW_NORMAL;
        wcscpy_s(logfont.lfFaceName, L"Segoe UI");
        controlFont = CreateFontIndirectW(&logfont);
    }

    HWND makeControl(const wchar_t* cls, const wchar_t* text, int id,
                     DWORD style) {
        HWND control = CreateWindowExW(
            0, cls, text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | style, 0, 0, 10,
            10, window, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            GetModuleHandleW(nullptr), nullptr);
        SendMessageW(control, WM_SETFONT,
                     reinterpret_cast<WPARAM>(controlFont), TRUE);
        if (dark) SetWindowTheme(control, L"DarkMode_Explorer", nullptr);
        return control;
    }

    HWND makeButton(const wchar_t* text, int id, DWORD extra) {
        return makeControl(L"BUTTON", text, id, extra);
    }

    void createControls() {
        range24 = makeButton(L"24 sa", kIdRange24,
                             BS_AUTORADIOBUTTON | BS_PUSHLIKE | WS_GROUP);
        range7 = makeButton(L"7 gün", kIdRange7, BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        range30 = makeButton(L"30 gün", kIdRange30,
                             BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        SendMessageW(range30, BM_SETCHECK, BST_CHECKED, 0);
        refreshButton = makeButton(L"Yenile", kIdRefresh, BS_PUSHBUTTON);

        searchEdit = makeControl(L"EDIT", L"", kIdSearch,
                                 WS_BORDER | ES_AUTOHSCROLL);
        SendMessageW(searchEdit, EM_SETCUEBANNER, TRUE,
                     reinterpret_cast<LPARAM>(L"Alan adı ara…"));
        SendMessageW(searchEdit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELPARAM(8, 8));

        outcomeAll = makeButton(L"Tümü", kIdOutcomeAll,
                                BS_AUTORADIOBUTTON | BS_PUSHLIKE | WS_GROUP);
        outcomeBypassed = makeButton(L"Atlatılan", kIdOutcomeBypassed,
                                     BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        outcomeClean = makeButton(L"Dokunulmadı", kIdOutcomeClean,
                                  BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        outcomeUnresolved = makeButton(L"Çözülemeyen", kIdOutcomeUnresolved,
                                       BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        SendMessageW(outcomeAll, BM_SETCHECK, BST_CHECKED, 0);

        sortRecent = makeButton(L"En yeni", kIdSortRecent,
                                BS_AUTORADIOBUTTON | BS_PUSHLIKE | WS_GROUP);
        sortSlowest = makeButton(L"En yavaş", kIdSortSlowest,
                                 BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        sortAttempts = makeButton(L"En çok deneme", kIdSortAttempts,
                                  BS_AUTORADIOBUTTON | BS_PUSHLIKE);
        SendMessageW(sortRecent, BM_SETCHECK, BST_CHECKED, 0);

        testButton = makeButton(L"Bağlantıyı sına", kIdTest, BS_PUSHBUTTON);
        saveButton = makeButton(L"Kaydet ve motoru yenile", kIdSave,
                                BS_PUSHBUTTON | BS_DEFPUSHBUTTON);

        const DWORD editStyle = WS_BORDER | WS_VSCROLL | ES_MULTILINE |
                                ES_WANTRETURN | ES_AUTOVSCROLL;
        includeEdit = makeControl(L"EDIT", L"", kIdInclude, editStyle);
        excludeEdit = makeControl(L"EDIT", L"", kIdExclude, editStyle);
        for (HWND edit : {includeEdit, excludeEdit}) {
            SendMessageW(edit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                         MAKELPARAM(8, 8));
        }
    }

    // ---- drawing primitives ------------------------------------------------

    float S(float logical) const { return std::round(logical * scale); }

    bool ensureRenderTarget() {
        if (renderTarget) return true;
        RECT client{};
        GetClientRect(window, &client);
        const D2D1_SIZE_U size = D2D1::SizeU(
            static_cast<UINT32>(std::max<LONG>(1, client.right - client.left)),
            static_cast<UINT32>(std::max<LONG>(1, client.bottom - client.top)));
        if (FAILED(d2dFactory->CreateHwndRenderTarget(
                D2D1::RenderTargetProperties(),
                D2D1::HwndRenderTargetProperties(window, size),
                renderTarget.GetAddressOf()))) {
            return false;
        }
        renderTarget->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::Black),
                                            brush.GetAddressOf());
        return true;
    }

    void discardRenderTarget() {
        brush.Reset();
        renderTarget.Reset();
    }

    void fill(const D2D1_RECT_F& rect, const D2D1_COLOR_F& color) {
        brush->SetColor(color);
        renderTarget->FillRectangle(rect, brush.Get());
    }

    // Rules are drawn as snapped rectangles rather than lines so they stay a
    // crisp single pixel at every DPI.
    void hRule(float x1, float x2, float y, const D2D1_COLOR_F& color,
               float thickness = 1.0f) {
        const float top = std::round(y);
        fill({std::round(x1), top, std::round(x2), top + std::round(thickness * scale)},
             color);
    }

    void vRule(float x, float y1, float y2, const D2D1_COLOR_F& color,
               float thickness = 1.0f) {
        const float left = std::round(x);
        fill({left, std::round(y1), left + std::round(thickness * scale), std::round(y2)},
             color);
    }

    // A small filled square. The ledger, legends and the status strip all use
    // the same mark so a colour always reads as the same category.
    void mark(float x, float y, const D2D1_COLOR_F& color, float size = 8.0f) {
        const float s = S(size);
        fill({std::round(x), std::round(y), std::round(x) + s, std::round(y) + s},
             color);
    }

    void text(const std::wstring& value, const ComPtr<IDWriteTextFormat>& format,
              const D2D1_RECT_F& rect, const D2D1_COLOR_F& color,
              DWRITE_TEXT_ALIGNMENT ha = DWRITE_TEXT_ALIGNMENT_LEADING,
              DWRITE_PARAGRAPH_ALIGNMENT va = DWRITE_PARAGRAPH_ALIGNMENT_NEAR) {
        if (!format.Get() || value.empty()) return;
        format->SetTextAlignment(ha);
        format->SetParagraphAlignment(va);
        brush->SetColor(color);
        renderTarget->DrawText(value.c_str(), static_cast<UINT32>(value.size()),
                               format.Get(), rect, brush.Get(),
                               D2D1_DRAW_TEXT_OPTIONS_CLIP);
    }

    // Letterspaced small-caps label. Tracking is what makes a 9px uppercase run
    // legible instead of a dense smudge, so the field labels all go through here.
    void label(const std::wstring& value, const D2D1_RECT_F& rect,
               const D2D1_COLOR_F& color,
               DWRITE_TEXT_ALIGNMENT ha = DWRITE_TEXT_ALIGNMENT_LEADING) {
        if (value.empty() || !fmtMonoSm.Get()) return;
        ComPtr<IDWriteTextLayout> layout;
        if (FAILED(dwrite->CreateTextLayout(
                value.c_str(), static_cast<UINT32>(value.size()), fmtMonoSm.Get(),
                std::max(1.0f, rect.right - rect.left),
                std::max(1.0f, rect.bottom - rect.top), layout.GetAddressOf())) ||
            !layout) {
            return;
        }
        layout->SetTextAlignment(ha);
        layout->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);
        ComPtr<IDWriteTextLayout1> tracked;
        if (SUCCEEDED(layout.As(&tracked)) && tracked) {
            const DWRITE_TEXT_RANGE all{0, static_cast<UINT32>(value.size())};
            tracked->SetCharacterSpacing(S(0.9f), S(0.9f), 0, all);
        }
        brush->SetColor(color);
        renderTarget->DrawTextLayout(D2D1::Point2F(rect.left, rect.top),
                                     layout.Get(), brush.Get(),
                                     D2D1_DRAW_TEXT_OPTIONS_CLIP);
    }

    float measureWidth(const std::wstring& value,
                       const ComPtr<IDWriteTextFormat>& format) {
        if (!format.Get() || value.empty()) return 0;
        ComPtr<IDWriteTextLayout> layout;
        if (FAILED(dwrite->CreateTextLayout(value.c_str(),
                                            static_cast<UINT32>(value.size()),
                                            format.Get(), 8000, 200,
                                            layout.GetAddressOf())) ||
            !layout) {
            return 0;
        }
        DWRITE_TEXT_METRICS metrics{};
        layout->GetMetrics(&metrics);
        return metrics.width;
    }

    // A numbered section rule: "04  NEDEN DAĞILIMI ............... kicker".
    // Returns the y at which the section's content begins.
    float sectionHead(float left, float right, float y, const wchar_t* number,
                      const std::wstring& title, const std::wstring& kicker) {
        label(number, {left, y + S(5), left + S(26), y + S(20)}, theme.inkFaint);
        text(title, fmtSection, {left + S(30), y, right - S(330), y + S(22)},
             theme.ink);
        if (!kicker.empty()) {
            label(kicker, {right - S(430), y + S(6), right, y + S(20)},
                  theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);
        }
        hRule(left, right, y + S(27), theme.rule);
        return y + kSectionHeadH();
    }

    float kSectionHeadH() const { return S(40); }

    D2D1_RECT_F contentRect(float top, float height) const {
        return {contentX, top, contentX + contentW, top + height};
    }

    // ---- layout ------------------------------------------------------------

    void relayout() {
        if (!window) return;
        RECT client{};
        GetClientRect(window, &client);
        clientW = static_cast<float>(client.right - client.left);
        clientH = static_cast<float>(client.bottom - client.top);
        headerH = S(56);

        const float margin = S(36);
        contentW = std::min(clientW - 2 * margin, S(1240));
        if (contentW < S(320)) {
            contentW = std::max(clientW - 2 * margin, S(280));
        }
        contentX = std::round((clientW - contentW) / 2.0f);

        const float gutter = S(40);
        const float sectionGap = S(38);
        float y = S(30);

        // Status strip ---------------------------------------------------------
        statusTop = y;
        statusH = contentW >= S(880) ? S(86) : S(150);
        y += statusH + sectionGap;

        // 01 Summary figures ---------------------------------------------------
        summaryTop = y;
        summaryCols = std::clamp(
            static_cast<int>(std::floor(contentW / S(190))), 1, 5);
        summaryRows = (5 + summaryCols - 1) / summaryCols;
        summaryRowH = S(104);
        summaryH = kSectionHeadH() + summaryRows * summaryRowH;
        y += summaryH + sectionGap;

        // 02 volume + 03 latency ----------------------------------------------
        rowAWide = contentW >= S(900);
        const float plotH = S(258);
        rowATop = y;
        if (rowAWide) {
            const float volumeW = std::round((contentW - gutter) * 0.58f);
            volumeRect = {contentX, rowATop, contentX + volumeW,
                          rowATop + kSectionHeadH() + plotH};
            latencyRect = {contentX + volumeW + gutter, rowATop,
                           contentX + contentW, rowATop + kSectionHeadH() + plotH};
            rowAH = kSectionHeadH() + plotH;
        } else {
            volumeRect = {contentX, rowATop, contentX + contentW,
                          rowATop + kSectionHeadH() + plotH};
            latencyRect = {contentX, volumeRect.bottom + sectionGap,
                           contentX + contentW,
                           volumeRect.bottom + sectionGap + kSectionHeadH() + plotH};
            rowAH = latencyRect.bottom - rowATop;
        }
        y += rowAH + sectionGap;

        // 04 reasons + 05 hosts ------------------------------------------------
        rowBWide = contentW >= S(900);
        const float reasonH = computeReasonHeight();
        const float hostsH = computeHostsHeight();
        rowBTop = y;
        if (rowBWide) {
            const float reasonW = std::round((contentW - gutter) * 0.48f);
            const float tall = std::max(reasonH, hostsH);
            reasonRect = {contentX, rowBTop, contentX + reasonW, rowBTop + tall};
            hostsRect = {contentX + reasonW + gutter, rowBTop, contentX + contentW,
                         rowBTop + tall};
            rowBH = tall;
        } else {
            reasonRect = {contentX, rowBTop, contentX + contentW, rowBTop + reasonH};
            hostsRect = {contentX, reasonRect.bottom + sectionGap,
                         contentX + contentW,
                         reasonRect.bottom + sectionGap + hostsH};
            rowBH = hostsRect.bottom - rowBTop;
        }
        y += rowBH + sectionGap;

        // 06 profiles ----------------------------------------------------------
        profilesTop = y;
        profilesH = computeProfilesHeight();
        y += profilesH + sectionGap;

        // 07 ledger ------------------------------------------------------------
        ledgerTop = y;
        ledgerH = computeLedgerHeight();
        ledgerRect = contentRect(ledgerTop, ledgerH);
        y += ledgerH + sectionGap;

        // 08 process scope -----------------------------------------------------
        processTop = y;
        processH = computeProcessHeight();
        processRect = contentRect(processTop, processH);
        y += processH + S(26);

        footerTop = y;
        footerH = S(40);
        y += footerH;

        contentHeight = y + S(20);
        clampScroll();
        updateScrollbar();
        positionControls();
    }

    float computeReasonHeight() const {
        const int diagnoses = std::clamp<int>(
            static_cast<int>(data.diagnoses.size()), 1, 6);
        const int signals = std::clamp<int>(
            static_cast<int>(data.signals.size()), 1, 6);
        return kSectionHeadH() + S(14) + S(18) + diagnoses * S(26) + S(22) +
               S(18) + signals * S(26);
    }

    float computeHostsHeight() const {
        if (data.topHosts.empty()) return kSectionHeadH() + S(120);
        return kSectionHeadH() + S(24) +
               static_cast<float>(data.topHosts.size()) * S(36);
    }

    float computeProfilesHeight() const {
        if (data.profiles.empty()) return kSectionHeadH() + S(110);
        return kSectionHeadH() + S(26) +
               static_cast<float>(data.profiles.size()) * S(38);
    }

    size_t ledgerRowCount() const {
        return std::min(visible.size(), kMaxLedgerRows);
    }

    float eventHeight(const telemetry::DashboardData::Event& event) const {
        return event.attempts.empty() ? S(62) : S(82);
    }

    float computeLedgerHeight() const {
        const float head = kSectionHeadH() + S(44); // section rule + filter row
        if (visible.empty()) return head + S(110);
        float total = head;
        for (size_t i = 0; i < ledgerRowCount(); ++i) {
            total += eventHeight(data.recent[visible[i]]);
        }
        return total + S(30);
    }

    float computeProcessHeight() const {
        const bool wide = contentW >= S(760);
        const float edits = wide ? S(112) : (S(112) * 2 + S(14));
        return kSectionHeadH() + S(36) + S(22) + edits + S(52);
    }

    void positionControls() {
        if (!window) return;

        // --- fixed masthead ---
        const float ctlH = S(28);
        const float ctlY = std::round((headerH - ctlH) / 2.0f);
        const float rangeW = S(62);
        const float refreshW = S(62);
        float right = contentX + contentW;
        moveControl(refreshButton, right - refreshW, ctlY, refreshW, ctlH, true);
        right -= refreshW + S(12);
        moveControl(range30, right - rangeW, ctlY, rangeW, ctlH, true);
        right -= rangeW;
        moveControl(range7, right - rangeW, ctlY, rangeW, ctlH, true);
        right -= rangeW;
        moveControl(range24, right - rangeW, ctlY, rangeW, ctlH, true);
        right -= rangeW + S(14);

        const float searchW = S(210);
        const bool showSearch = right - searchW > contentX + S(300);
        moveControl(searchEdit, right - searchW, ctlY, searchW, ctlH, showSearch);

        // --- status strip: connection test ---
        {
            const D2D1_RECT_F strip = contentRect(statusTop, statusH);
            const float buttonW = S(150);
            placeContentControl(testButton, strip.right - S(18) - buttonW,
                                strip.top + S(14), buttonW, S(28));
        }

        // --- ledger filter row ---
        {
            const float chipY = ledgerRect.top + kSectionHeadH() + S(4);
            const float chipH = S(28);
            float x = ledgerRect.left;
            const float outcomeW[4] = {S(56), S(84), S(96), S(102)};
            HWND chips[4] = {outcomeAll, outcomeBypassed, outcomeClean,
                             outcomeUnresolved};
            for (int i = 0; i < 4; ++i) {
                placeContentControl(chips[i], x, chipY, outcomeW[i], chipH);
                x += outcomeW[i];
            }
            const float sortW[3] = {S(68), S(74), S(104)};
            float sx = ledgerRect.right - (sortW[0] + sortW[1] + sortW[2]);
            const bool showSort = sx > x + S(24);
            HWND sorts[3] = {sortRecent, sortSlowest, sortAttempts};
            for (int i = 0; i < 3; ++i) {
                if (showSort) {
                    placeContentControl(sorts[i], sx, chipY, sortW[i], chipH);
                    sx += sortW[i];
                } else {
                    ShowWindow(sorts[i], SW_HIDE);
                }
            }
        }

        // --- process scope editors ---
        {
            const float ex = processRect.left;
            const float ew = processRect.right - processRect.left;
            const bool wide = contentW >= S(760);
            const float editTop = processRect.top + kSectionHeadH() + S(36) + S(22);
            const float editH = S(112);
            if (wide) {
                const float half = (ew - S(20)) / 2.0f;
                placeContentControl(includeEdit, ex, editTop, half, editH);
                placeContentControl(excludeEdit, ex + half + S(20), editTop, half,
                                    editH);
            } else {
                placeContentControl(includeEdit, ex, editTop, ew, editH);
                placeContentControl(excludeEdit, ex, editTop + editH + S(14), ew,
                                    editH);
            }
            const float saveW = S(214);
            const float saveH = S(30);
            placeContentControl(saveButton, processRect.right - saveW,
                                processRect.bottom - S(40), saveW, saveH);
        }
    }

    void moveControl(HWND control, float x, float y, float w, float h,
                     bool visibleNow) {
        if (!control) return;
        ShowWindow(control, visibleNow ? SW_SHOW : SW_HIDE);
        if (visibleNow) {
            MoveWindow(control, static_cast<int>(std::round(x)),
                       static_cast<int>(std::round(y)),
                       static_cast<int>(std::round(w)),
                       static_cast<int>(std::round(h)), TRUE);
        }
    }

    // Anchors a control in document space, hiding it once it scrolls under the
    // fixed masthead or past the bottom of the viewport.
    void placeContentControl(HWND control, float docX, float docY, float w,
                             float h) {
        if (!control) return;
        const float top = headerH - scrollY + docY;
        const bool showing = (top >= headerH - S(2)) && (top < clientH);
        moveControl(control, docX, top, w, h, showing);
    }

    void clampScroll() {
        maxScroll = std::max(0.0f, contentHeight - (clientH - headerH));
        scrollY = std::clamp(scrollY, 0.0f, maxScroll);
    }

    void updateScrollbar() {
        SCROLLINFO info{};
        info.cbSize = sizeof(info);
        info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS | SIF_DISABLENOSCROLL;
        info.nMin = 0;
        info.nMax = static_cast<int>(contentHeight);
        info.nPage = static_cast<UINT>(std::max(1.0f, clientH - headerH));
        info.nPos = static_cast<int>(scrollY);
        SetScrollInfo(window, SB_VERT, &info, TRUE);
    }

    void scrollTo(float target) {
        clampScroll();
        target = std::clamp(target, 0.0f, maxScroll);
        if (std::abs(target - scrollY) < 0.5f) return;
        scrollY = target;
        SetScrollPos(window, SB_VERT, static_cast<int>(scrollY), TRUE);
        positionControls();
        invalidate();
    }

    // ---- paint -------------------------------------------------------------

    void paint() {
        if (!ensureRenderTarget()) return;
        renderTarget->BeginDraw();
        renderTarget->SetTransform(D2D1::Matrix3x2F::Identity());
        renderTarget->Clear(theme.ground);

        drawContent();
        drawMasthead();

        if (renderTarget->EndDraw() == D2DERR_RECREATE_TARGET) {
            discardRenderTarget();
            InvalidateRect(window, nullptr, FALSE);
        }
    }

    void drawMasthead() {
        renderTarget->SetTransform(D2D1::Matrix3x2F::Identity());
        fill({0, 0, clientW, headerH}, theme.ground);
        hRule(0, clientW, headerH - S(2), theme.mastRule, 2);

        const float baseline = std::round(headerH / 2) - S(11);
        text(L"SPLITHELLO", fmtWordmark,
             {contentX, baseline, contentX + S(180), baseline + S(24)}, theme.ink);

        const float wordmarkW = measureWidth(L"SPLITHELLO", fmtWordmark);
        float x = contentX + wordmarkW + S(16);
        vRule(x, headerH / 2 - S(9), headerH / 2 + S(9), theme.rule);
        x += S(14);
        label(L"DPI KANIT DEFTERİ",
              {x, headerH / 2 - S(7), x + S(220), headerH / 2 + S(8)},
              theme.inkFaint);
    }

    void drawContent() {
        renderTarget->PushAxisAlignedClip({0, headerH, clientW, clientH},
                                          D2D1_ANTIALIAS_MODE_ALIASED);
        renderTarget->SetTransform(
            D2D1::Matrix3x2F::Translation(0, headerH - scrollY));

        drawStatusStrip();
        drawSummary();
        drawVolume();
        drawLatency();
        drawReasons();
        drawHosts();
        drawProfiles();
        drawLedger();
        drawProcess();
        drawFooter();
        drawTooltip(); // last, so it floats above the volume chart

        renderTarget->SetTransform(D2D1::Matrix3x2F::Identity());
        renderTarget->PopAxisAlignedClip();
    }

    // The live engine session. A band rather than a card: tonal ground with a
    // rule above and below, cells divided by hairlines.
    void drawStatusStrip() {
        const D2D1_RECT_F strip = contentRect(statusTop, statusH);
        fill(strip, theme.band);
        hRule(strip.left, strip.right, strip.top, theme.rule);
        hRule(strip.left, strip.right, strip.bottom - S(1), theme.rule);

        const float pad = S(18);
        const float top = strip.top + S(14);
        const float cellH = S(46);

        // Engine block.
        mark(strip.left + pad, top + S(4),
             live.online ? theme.acted : theme.inkFaint, 9);
        label(L"MOTOR", {strip.left + pad + S(16), top + S(2),
                         strip.left + pad + S(120), top + S(16)},
              theme.inkFaint);
        text(live.online ? L"çalışıyor" : L"çevrimdışı", fmtFigureSm,
             {strip.left + pad, top + S(18), strip.left + pad + S(180),
              top + S(46)},
             live.online ? theme.ink : theme.inkFaint);

        std::wstring detail = L"oturum yok";
        if (live.online) {
            wchar_t buffer[96];
            std::swprintf(buffer, 96, L"%s · PID %u",
                          formatUptime(nowUnix() -
                                       static_cast<int64_t>(live.startedAt))
                              .c_str(),
                          live.enginePid);
            detail = buffer;
        }

        const bool wide = contentW >= S(880);
        const float testReserve = wide ? S(186) : 0.0f;
        float x = strip.left + pad + S(190);

        struct Cell { const wchar_t* label; std::wstring value; };
        const Cell cells[3] = {
            {L"AKTİF AKIŞ", groupCount(live.activeFlows)},
            {L"KARAR BEKLEYEN", groupCount(live.pendingFlows)},
            {L"OTURUM KARARI", groupCount(live.decisions)},
        };

        if (wide) {
            const float cellW = S(148);
            for (const Cell& cell : cells) {
                vRule(x - S(18), top - S(2), top + cellH, theme.rule);
                label(cell.label, {x, top + S(2), x + cellW, top + S(16)},
                      theme.inkFaint);
                text(cell.value, fmtFigureSm,
                     {x, top + S(18), x + cellW, top + S(46)}, theme.ink);
                x += cellW;
            }
            vRule(x - S(18), top - S(2), top + cellH, theme.rule);
            label(L"PROFİLLER", {x, top + S(2), strip.right - testReserve,
                                 top + S(16)},
                  theme.inkFaint);
            drawProfileTicker({x, top + S(18), strip.right - testReserve - S(18),
                               top + S(46)});
            // Test result sits under its button, which positionControls placed.
            text(testResultText(), fmtMonoSm,
                 {strip.left + S(208), top + S(50), strip.right - S(18),
                  top + S(66)},
                 testResultColour(), DWRITE_TEXT_ALIGNMENT_TRAILING);
        } else {
            float ny = top + S(52);
            for (const Cell& cell : cells) {
                label(cell.label, {strip.left + pad, ny, strip.left + pad + S(160),
                                   ny + S(14)},
                      theme.inkFaint);
                text(cell.value, fmtMono,
                     {strip.left + pad + S(170), ny, strip.right - pad, ny + S(16)},
                     theme.ink, DWRITE_TEXT_ALIGNMENT_TRAILING);
                ny += S(20);
            }
        }
        text(detail, fmtMonoSm,
             {strip.left + pad, top + S(46), strip.left + pad + S(180),
              top + S(62)},
             theme.inkFaint);
    }

    // Active profiles as a single dense line: "dokunulmadı 4 · sni-mid 2".
    void drawProfileTicker(const D2D1_RECT_F& rect) {
        std::vector<live_stats::ProfileSnapshot> used;
        for (const auto& profile : live.profiles) {
            if (profile.active || profile.decisions) used.push_back(profile);
        }
        std::sort(used.begin(), used.end(), [](const auto& a, const auto& b) {
            if (a.active != b.active) return a.active > b.active;
            return a.decisions > b.decisions;
        });
        if (used.empty()) {
            text(live.online ? L"akış bekleniyor" : L"motor kapalı", fmtMonoSm,
                 rect, theme.inkFaint);
            return;
        }
        std::wstring line;
        int drawn = 0;
        for (const auto& profile : used) {
            if (drawn >= 4) break;
            if (drawn) line += L"   ";
            wchar_t buffer[96];
            std::swprintf(buffer, 96, L"%s %u/%u", trLabel(profile.name).c_str(),
                          profile.active, profile.decisions);
            line += buffer;
            ++drawn;
        }
        text(line, fmtTicker, rect, theme.inkSoft);
    }

    std::wstring testResultText() const {
        std::wstring base = testMessage.empty()
                                ? L"motor açıkken relay yolu sınanabilir"
                                : testMessage;
        if (testStatus > 0) {
            wchar_t suffix[48];
            std::swprintf(suffix, 48, L" · HTTP %d", testStatus);
            base += suffix;
        }
        if (testElapsedMs > 0) {
            base += L" · " + formatMs(static_cast<int64_t>(testElapsedMs));
        }
        return base;
    }

    D2D1_COLOR_F testResultColour() const {
        switch (testState) {
        case 0: return theme.acted;
        case 1: return theme.caution;
        case 2:
        case 3: return theme.failed;
        default: return theme.inkFaint;
        }
    }

    // ---- 01 summary --------------------------------------------------------

    struct Figure {
        const wchar_t* label;
        std::wstring value;
        std::wstring note;
        D2D1_COLOR_F colour;
        double current;
        double previous;
        int polarity; // +1 rising is good, -1 rising is bad, 0 neutral
    };

    void drawSummary() {
        const float left = contentX;
        const float right = contentX + contentW;
        wchar_t kicker[128];
        std::swprintf(kicker, 128, L"%s · ÖNCEKİ DÖNEME GÖRE",
                      data.ready ? (L"SON OKUMA " + clockStamp(data.generatedAt)).c_str()
                                 : L"VERİ BEKLENİYOR");
        const float top = sectionHead(left, right, summaryTop, L"01", L"Özet",
                                      kicker);

        const int hitRate =
            data.total ? static_cast<int>(std::llround(
                             static_cast<double>(data.cacheHits) / data.total * 100))
                       : 0;
        wchar_t cacheNote[80];
        std::swprintf(cacheNote, 80, L"öğrenilmiş profil isabeti %%%d", hitRate);
        wchar_t tailNote[96];
        std::swprintf(tailNote, 96, L"p90 %s · p99 %s",
                      formatMs(data.latency.p90).c_str(),
                      formatMs(data.latency.p99).c_str());

        std::array<Figure, 5> figures = {{
            {L"TOPLAM KARAR", groupCount(data.total), cacheNote, theme.ink,
             static_cast<double>(data.total),
             static_cast<double>(data.previous.total), 0},
            {L"DOKUNULMADI", groupCount(data.normal), L"müdahale kanıtı yok",
             theme.quiet, static_cast<double>(data.normal),
             static_cast<double>(data.previous.normal), 1},
            {L"ATLATILDI", groupCount(data.bypassed), L"alternatif profil kazandı",
             theme.acted, static_cast<double>(data.bypassed),
             static_cast<double>(data.previous.bypassed), 0},
            {L"ÇÖZÜLEMEDİ", groupCount(data.unresolved),
             L"başarılı karşı-deney yok", theme.failed,
             static_cast<double>(data.unresolved),
             static_cast<double>(data.previous.unresolved), -1},
            {L"KARAR SÜRESİ p50", formatMs(data.latency.p50), tailNote,
             theme.ink, static_cast<double>(data.latency.p50),
             data.previous.averageLatencyMs, -1},
        }};

        const float cellW = contentW / summaryCols;
        for (int i = 0; i < 5; ++i) {
            const int col = i % summaryCols;
            const int row = i / summaryCols;
            const float x = left + col * cellW;
            const float y = top + row * summaryRowH;
            if (col != 0) {
                vRule(x - S(1), y + S(4), y + summaryRowH - S(16), theme.rule);
            }
            const float inner = (col == 0) ? x : x + S(20);
            const float innerRight = x + cellW - S(16);

            label(figures[i].label, {inner, y + S(2), innerRight, y + S(16)},
                  theme.inkFaint);
            text(figures[i].value, fmtFigure,
                 {inner, y + S(20), innerRight, y + S(62)}, figures[i].colour);
            drawDelta({inner, y + S(64), innerRight, y + S(82)}, figures[i]);
            text(figures[i].note, fmtMonoSm,
                 {inner, y + S(82), innerRight, y + S(98)}, theme.inkFaint);
        }
    }

    // Period-over-period change, coloured only when the direction has meaning.
    void drawDelta(const D2D1_RECT_F& rect, const Figure& figure) {
        if (!data.ready || figure.previous <= 0) {
            text(L"önceki dönem yok", fmtMonoSm, rect, theme.inkFaint);
            return;
        }
        const double change =
            (figure.current - figure.previous) / figure.previous * 100.0;
        if (!std::isfinite(change)) return;
        if (std::abs(change) < 0.5) {
            text(L"değişim yok", fmtMonoSm, rect, theme.inkFaint);
            return;
        }
        const bool rising = change > 0;
        const bool adverse =
            figure.polarity != 0 && ((figure.polarity > 0) != rising);
        const D2D1_COLOR_F colour = adverse ? theme.failed : theme.inkFaint;
        wchar_t badge[32];
        std::swprintf(badge, 32, L"%s %%%.0f", rising ? L"▲" : L"▼",
                      std::abs(change));
        text(badge, fmtMonoSm, rect, colour);
    }

    // ---- 02 daily volume ---------------------------------------------------

    void drawVolume() {
        const D2D1_RECT_F rect = volumeRect;
        wchar_t kicker[64];
        std::swprintf(kicker, 64, L"%zu GÜN", data.daily.size());
        float top = sectionHead(rect.left, rect.right, rect.top, L"02",
                                L"Günlük karar hacmi", kicker);

        // Legend on the same line the plot starts from.
        {
            struct Item { const wchar_t* label; D2D1_COLOR_F colour; };
            const Item items[3] = {{L"dokunulmadı", theme.quiet},
                                   {L"atlatıldı", theme.acted},
                                   {L"çözülemedi", theme.failed}};
            float x = rect.left;
            for (const Item& item : items) {
                mark(x, top + S(4), item.colour, 7);
                const float width = measureWidth(item.label, fmtMonoSm);
                text(item.label, fmtMonoSm,
                     {x + S(12), top, x + S(12) + width + S(4), top + S(16)},
                     theme.inkSoft);
                x += S(12) + width + S(18);
            }
        }
        top += S(24);

        chartBars.clear();
        const float plotLeft = rect.left + S(42);
        const float plotRight = rect.right;
        const float plotBottom = rect.bottom - S(22);
        const float plotTop = top;
        const float plotH = plotBottom - plotTop;

        if (data.daily.empty() || plotH <= 0) {
            hRule(plotLeft, plotRight, plotBottom, theme.rule);
            text(L"Motor karar verdikçe grafik burada oluşacak.", fmtBody,
                 {plotLeft, plotTop, plotRight, plotBottom}, theme.inkFaint,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            return;
        }

        int64_t peak = 1;
        for (const auto& day : data.daily) peak = std::max(peak, day.total);
        constexpr int kTicks = 4;
        const double axisMax =
            niceCeil(static_cast<double>(peak) / kTicks) * kTicks;

        for (int i = 0; i <= kTicks; ++i) {
            const float ratio = static_cast<float>(i) / kTicks;
            const float y = plotBottom - ratio * plotH;
            hRule(plotLeft, plotRight, y, i == 0 ? theme.rule : theme.ruleFaint);
            text(groupCount(static_cast<int64_t>(std::llround(axisMax * ratio))),
                 fmtMonoSm, {rect.left, y - S(8), plotLeft - S(10), y + S(8)},
                 theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING,
                 DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        }

        const size_t n = data.daily.size();
        const float slot = (plotRight - plotLeft) / static_cast<float>(n);
        const float barW = std::max(S(2), std::min(slot * 0.56f, S(22)));
        const float labelW = measureWidth(L"88.88", fmtMonoSm) + S(16);
        const size_t labelStep =
            std::max<size_t>(1, static_cast<size_t>(std::ceil(labelW / slot)));

        for (size_t i = 0; i < n; ++i) {
            const auto& day = data.daily[i];
            const float cx = plotLeft + slot * i + slot / 2;
            const float barLeft = std::round(cx - barW / 2);
            const bool hot = (hoverBar == static_cast<int>(i));

            if (hot) {
                fill({cx - slot / 2, plotTop, cx + slot / 2, plotBottom},
                     theme.hover);
            }

            const int64_t clean =
                std::max<int64_t>(0, day.total - day.bypassed - day.unresolved);
            struct Segment { int64_t value; D2D1_COLOR_F colour; };
            const Segment segments[3] = {{clean, theme.quiet},
                                         {day.bypassed, theme.acted},
                                         {day.unresolved, theme.failed}};
            float bottom = plotBottom;
            for (const Segment& segment : segments) {
                if (segment.value <= 0) continue;
                const float height = std::max(
                    S(1.5f), static_cast<float>(segment.value / axisMax * plotH));
                fill({barLeft, bottom - height, barLeft + barW, bottom},
                     segment.colour);
                bottom -= height;
            }
            chartBars.push_back({{cx - slot / 2, plotTop, cx + slot / 2, plotBottom},
                                 static_cast<int>(i)});

            if (i % labelStep == 0) {
                std::wstring stamp = widen(day.day);
                if (stamp.size() == 10) {
                    stamp = stamp.substr(8, 2) + L"." + stamp.substr(5, 2);
                }
                text(stamp, fmtMonoSm,
                     {cx - slot, plotBottom + S(5), cx + slot, plotBottom + S(20)},
                     hot ? theme.ink : theme.inkFaint,
                     DWRITE_TEXT_ALIGNMENT_CENTER);
            }
        }
    }

    void drawTooltip() {
        if (hoverBar < 0 || hoverBar >= static_cast<int>(data.daily.size())) return;
        const telemetry::DashboardData::Day& day =
            data.daily[static_cast<size_t>(hoverBar)];
        const int64_t clean =
            std::max<int64_t>(0, day.total - day.bypassed - day.unresolved);

        std::wstring stamp = widen(day.day);
        if (stamp.size() == 10) {
            stamp = stamp.substr(8, 2) + L"." + stamp.substr(5, 2) + L"." +
                    stamp.substr(0, 4);
        }
        struct Row { const wchar_t* label; int64_t value; D2D1_COLOR_F colour; };
        const Row rows[3] = {{L"dokunulmadı", clean, theme.quiet},
                             {L"atlatıldı", day.bypassed, theme.acted},
                             {L"çözülemedi", day.unresolved, theme.failed}};

        const float width = S(186);
        const float height = S(104);
        D2D1_RECT_F anchor =
            chartBars.empty()
                ? volumeRect
                : chartBars[static_cast<size_t>(
                                std::min<int>(hoverBar,
                                              static_cast<int>(chartBars.size()) - 1))]
                      .rect;
        float left = (anchor.left + anchor.right) / 2 - width / 2;
        left = std::clamp(left, volumeRect.left, volumeRect.right - width);
        const float top = volumeRect.top + kSectionHeadH() + S(30);
        D2D1_RECT_F box{left, top, left + width, top + height};

        fill(box, theme.ground);
        hRule(box.left, box.right, box.top, theme.ink, 2);
        hRule(box.left, box.right, box.bottom - S(1), theme.rule);
        vRule(box.left, box.top, box.bottom, theme.rule);
        vRule(box.right - S(1), box.top, box.bottom, theme.rule);

        text(stamp, fmtMono,
             {box.left + S(12), box.top + S(10), box.right - S(10), box.top + S(28)},
             theme.ink);
        wchar_t total[64];
        std::swprintf(total, 64, L"toplam %s karar", groupCount(day.total).c_str());
        text(total, fmtMonoSm,
             {box.left + S(12), box.top + S(28), box.right - S(10), box.top + S(44)},
             theme.inkFaint);
        float y = box.top + S(50);
        for (const Row& row : rows) {
            mark(box.left + S(12), y + S(5), row.colour, 7);
            text(row.label, fmtMonoSm,
                 {box.left + S(24), y, box.right - S(50), y + S(17)}, theme.inkSoft);
            text(groupCount(row.value), fmtMonoSm,
                 {box.right - S(48), y, box.right - S(12), y + S(17)}, theme.ink,
                 DWRITE_TEXT_ALIGNMENT_TRAILING);
            y += S(17);
        }
    }

    // ---- 03 latency profile ------------------------------------------------

    void drawLatency() {
        const D2D1_RECT_F rect = latencyRect;
        float top = sectionHead(rect.left, rect.right, rect.top, L"03",
                                L"Karar süresi", L"YÜZDELİK VE DAĞILIM");

        // Percentile row: three figures divided by hairlines.
        const float statH = S(50);
        const float statW = (rect.right - rect.left) / 3;
        struct Stat { const wchar_t* label; int64_t value; D2D1_COLOR_F colour; };
        const Stat stats[3] = {{L"MEDYAN p50", data.latency.p50, theme.ink},
                               {L"YAVAŞ p90", data.latency.p90, theme.caution},
                               {L"KUYRUK p99", data.latency.p99, theme.failed}};
        for (int i = 0; i < 3; ++i) {
            const float x = rect.left + statW * i;
            if (i) vRule(x - S(12), top, top + statH - S(8), theme.rule);
            label(stats[i].label, {x, top, x + statW - S(14), top + S(14)},
                  theme.inkFaint);
            text(data.total ? formatMs(stats[i].value) : L"—", fmtFigureSm,
                 {x, top + S(16), x + statW - S(14), top + S(46)},
                 data.total ? stats[i].colour : theme.inkFaint);
        }
        top += statH + S(16);

        // Histogram. Bucket colour states how the duration should be read:
        // quiet is unremarkable, caution is slow, failed is a stall.
        const float plotLeft = rect.left;
        const float plotRight = rect.right;
        const float plotBottom = rect.bottom - S(22);
        const float plotTop = top + S(18);
        const float plotH = plotBottom - plotTop;

        label(L"DAĞILIM", {plotLeft, top, plotLeft + S(120), top + S(14)},
              theme.inkFaint);
        label(L"MS ÜST SINIRI", {plotRight - S(200), top, plotRight, top + S(14)},
              theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);

        int64_t peak = 0;
        for (const auto& bucket : data.latencyHistogram) {
            peak = std::max(peak, bucket.count);
        }
        hRule(plotLeft, plotRight, plotBottom, theme.rule);
        if (peak <= 0 || plotH <= 0) {
            text(L"Kararlar biriktikçe dağılım burada görünecek.", fmtBody,
                 {plotLeft, plotTop, plotRight, plotBottom}, theme.inkFaint,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            return;
        }

        const size_t count = data.latencyHistogram.size();
        const float slot = (plotRight - plotLeft) / static_cast<float>(count);
        const float barW = std::max(S(4), slot * 0.62f);
        for (size_t i = 0; i < count; ++i) {
            const auto& bucket = data.latencyHistogram[i];
            const float cx = plotLeft + slot * i + slot / 2;
            const float height =
                bucket.count > 0
                    ? std::max(S(1.5f),
                               static_cast<float>(bucket.count) / peak * plotH)
                    : 0.0f;
            const D2D1_COLOR_F colour =
                (bucket.upperMs != 0 && bucket.upperMs <= 200)   ? theme.quiet
                : (bucket.upperMs != 0 && bucket.upperMs <= 800) ? theme.caution
                                                                 : theme.failed;
            if (height > 0) {
                fill({std::round(cx - barW / 2), plotBottom - height,
                      std::round(cx + barW / 2), plotBottom},
                     colour);
            }
            std::wstring edge;
            if (bucket.upperMs == 0) {
                edge = L"3s+";
            } else if (bucket.upperMs < 1000) {
                edge = std::to_wstring(bucket.upperMs);
            } else {
                wchar_t buffer[16];
                std::swprintf(buffer, 16, L"%llds",
                              static_cast<long long>(bucket.upperMs / 1000));
                edge = buffer;
            }
            text(edge, fmtMonoSm,
                 {cx - slot / 2, plotBottom + S(5), cx + slot / 2, plotBottom + S(20)},
                 theme.inkFaint, DWRITE_TEXT_ALIGNMENT_CENTER);
            if (bucket.count > 0 && slot > S(28)) {
                text(groupCount(bucket.count), fmtMonoSm,
                     {cx - slot / 2, plotBottom - height - S(16), cx + slot / 2,
                      plotBottom - height - S(1)},
                     theme.inkSoft, DWRITE_TEXT_ALIGNMENT_CENTER);
            }
        }
    }

    // ---- 04 reason breakdown -----------------------------------------------

    void drawReasons() {
        const D2D1_RECT_F rect = reasonRect;
        float y = sectionHead(rect.left, rect.right, rect.top, L"04",
                              L"Neden dağılımı", L"KARAR VE BAZ SİNYALİ");
        y += S(14);
        y = drawMeterGroup(rect, y, L"TEŞHİS", data.diagnoses, theme.acted);
        y += S(22);
        drawMeterGroup(rect, y, L"BAZ ÇİZGİ SONUCU", data.signals, theme.quiet);
    }

    float drawMeterGroup(
        const D2D1_RECT_F& rect, float y, const wchar_t* title,
        const std::vector<telemetry::DashboardData::KeyCount>& items,
        const D2D1_COLOR_F& colour) {
        label(title, {rect.left, y, rect.right, y + S(14)}, theme.inkFaint);
        y += S(18);
        if (items.empty()) {
            text(L"Henüz dağılım oluşmadı.", fmtMonoSm,
                 {rect.left, y, rect.right, y + S(18)}, theme.inkFaint);
            return y + S(26);
        }

        int64_t sum = 0;
        int64_t peak = 1;
        for (const auto& item : items) {
            sum += item.count;
            peak = std::max(peak, item.count);
        }
        const float labelW = std::min(S(168), (rect.right - rect.left) * 0.38f);
        const float valueW = S(84);
        const int shown = std::min<int>(6, static_cast<int>(items.size()));
        for (int i = 0; i < shown; ++i) {
            const auto& item = items[i];
            text(trLabel(item.key), fmtBodyLine,
                 {rect.left, y + S(3), rect.left + labelW, y + S(21)}, theme.ink);
            const float trackLeft = rect.left + labelW + S(12);
            const float trackRight = rect.right - valueW;
            if (trackRight > trackLeft) {
                // A baseline rule the bar sits on, rather than a filled track:
                // lighter, and it keeps the eye on the ink that means something.
                hRule(trackLeft, trackRight, y + S(15), theme.ruleFaint);
                const float width = std::max(
                    S(2), (trackRight - trackLeft) *
                              (static_cast<float>(item.count) / peak));
                fill({trackLeft, y + S(9), trackLeft + width, y + S(15)}, colour);
            }
            wchar_t value[48];
            std::swprintf(value, 48, L"%s  %%%.0f", groupCount(item.count).c_str(),
                          sum ? item.count * 100.0 / sum : 0.0);
            text(value, fmtMonoSm,
                 {rect.right - valueW, y + S(4), rect.right, y + S(20)},
                 theme.inkSoft, DWRITE_TEXT_ALIGNMENT_TRAILING);
            y += S(26);
        }
        return y;
    }

    // ---- 05 most-affected hosts --------------------------------------------

    void drawHosts() {
        const D2D1_RECT_F rect = hostsRect;
        float y = sectionHead(rect.left, rect.right, rect.top, L"05",
                              L"Müdahale gerektiren alanlar",
                              L"ATLATILAN VE ÇÖZÜLEMEYEN");

        if (data.topHosts.empty()) {
            text(L"Bir alan adı için profil denendiğinde burada listelenecek.",
                 fmtBody, {rect.left, y, rect.right, rect.bottom}, theme.inkFaint,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            return;
        }

        const float countW = S(120);
        const float countLeft = rect.right - countW;
        label(L"ALAN ADI", {rect.left, y, rect.left + S(200), y + S(14)},
              theme.inkFaint);
        label(L"ATL. / ÇÖZ. / TOP.", {countLeft - S(60), y, rect.right, y + S(14)},
              theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);
        y += S(20);

        for (const auto& host : data.topHosts) {
            const float barLeft = rect.left;
            const float barRight = countLeft - S(24);
            text(widen(host.host), fmtMono,
                 {barLeft, y, barRight, y + S(18)}, theme.ink);

            // Proportion bar: acted for what a profile fixed, failed for
            // what stayed unresolved, the remainder left as a faint rule.
            if (barRight > barLeft && host.total > 0) {
                const float full = barRight - barLeft;
                const float barY = y + S(21);
                hRule(barLeft, barRight, barY, theme.ruleFaint);
                const float bypassW =
                    full * static_cast<float>(host.bypassed) / host.total;
                const float unresolvedW =
                    full * static_cast<float>(host.unresolved) / host.total;
                if (bypassW > 0) {
                    fill({barLeft, barY, barLeft + std::max(S(2), bypassW),
                          barY + S(4)},
                         theme.acted);
                }
                if (unresolvedW > 0) {
                    const float start = barLeft + bypassW;
                    fill({start, barY, start + std::max(S(2), unresolvedW),
                          barY + S(4)},
                         theme.failed);
                }
            }

            wchar_t counts[64];
            std::swprintf(counts, 64, L"%s / %s / %s",
                          groupCount(host.bypassed).c_str(),
                          groupCount(host.unresolved).c_str(),
                          groupCount(host.total).c_str());
            text(counts, fmtMono, {countLeft - S(60), y, rect.right, y + S(18)},
                 theme.inkSoft, DWRITE_TEXT_ALIGNMENT_TRAILING);
            text(L"ort. " + formatMs(static_cast<int64_t>(
                     std::llround(host.averageLatencyMs))),
                 fmtMonoSm, {countLeft - S(60), y + S(18), rect.right, y + S(33)},
                 theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);
            y += S(36);
        }
    }

    // ---- 06 winning profiles -----------------------------------------------

    void drawProfiles() {
        const D2D1_RECT_F rect = contentRect(profilesTop, profilesH);
        float y = sectionHead(rect.left, rect.right, rect.top, L"06",
                              L"Kazanan profil performansı",
                              L"YALNIZ BAŞARILI KARARLAR");

        if (data.profiles.empty()) {
            text(L"Başarılı kararlar burada süre ve deneme sayısıyla karşılaştırılacak.",
                 fmtBody, {rect.left, y, rect.right, rect.bottom}, theme.inkFaint,
                 DWRITE_TEXT_ALIGNMENT_CENTER, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            return;
        }

        // Numeric columns are anchored right with a fixed measure so headings
        // never collide as the window narrows.
        const float numberW = S(96);
        const float rAttempts = rect.right;
        const float rLatency = rAttempts - S(108);
        const float rCount = rLatency - S(108);
        const float shareLeft =
            std::min(rect.left + S(168), rCount - numberW - S(150));
        const float shareRight = rCount - numberW - S(28);

        label(L"PROFİL", {rect.left, y, shareLeft - S(10), y + S(14)},
              theme.inkFaint);
        label(L"PAY", {shareLeft, y, shareRight, y + S(14)}, theme.inkFaint);
        label(L"KARAR", {rCount - numberW, y, rCount, y + S(14)}, theme.inkFaint,
              DWRITE_TEXT_ALIGNMENT_TRAILING);
        label(L"ORT. SÜRE", {rLatency - numberW, y, rLatency, y + S(14)},
              theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);
        label(L"ORT. DENEME", {rAttempts - numberW, y, rAttempts, y + S(14)},
              theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);
        y += S(20);
        hRule(rect.left, rect.right, y - S(4), theme.rule);

        int64_t sum = 0;
        for (const auto& profile : data.profiles) sum += profile.count;

        for (const auto& profile : data.profiles) {
            const float rowH = S(38);
            const bool untouched = profile.name == "none";
            const D2D1_COLOR_F signal = untouched ? theme.quiet : theme.acted;

            mark(rect.left, y + rowH / 2 - S(3), signal, 6);
            text(trLabel(profile.name), fmtMono,
                 {rect.left + S(14), y, shareLeft - S(10), y + rowH}, theme.ink,
                 DWRITE_TEXT_ALIGNMENT_LEADING, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

            if (shareRight > shareLeft && sum > 0) {
                const float cy = std::round(y + rowH / 2);
                hRule(shareLeft, shareRight, cy, theme.ruleFaint);
                const float width =
                    std::max(S(2), (shareRight - shareLeft) *
                                       static_cast<float>(profile.count) / sum);
                fill({shareLeft, cy - S(3), shareLeft + width, cy + S(3)}, signal);
            }

            const auto number = [&](const std::wstring& value, float right) {
                text(value, fmtMono, {right - numberW, y, right, y + rowH},
                     theme.ink, DWRITE_TEXT_ALIGNMENT_TRAILING,
                     DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            };
            number(groupCount(profile.count), rCount);
            number(formatMs(static_cast<int64_t>(
                       std::llround(profile.averageLatencyMs))),
                   rLatency);
            wchar_t attempts[24];
            std::swprintf(attempts, 24, L"%.1f", profile.averageAttempts);
            number(attempts, rAttempts);

            hRule(rect.left, rect.right, y + rowH - S(1), theme.ruleFaint);
            y += rowH;
        }
    }

    // ---- 07 evidence ledger ------------------------------------------------

    void drawLedger() {
        const D2D1_RECT_F rect = ledgerRect;
        wchar_t kicker[96];
        std::swprintf(kicker, 96, L"%zu / %zu OLAY", visible.size(),
                      data.recent.size());
        float y = sectionHead(rect.left, rect.right, rect.top, L"07",
                              L"Kanıt defteri", kicker);
        y += S(44); // filter chip row, drawn as real controls

        eventRows.clear();
        if (visible.empty()) {
            text(data.recent.empty()
                     ? L"Bir TLS kararı tamamlandığında baz çizgi, profil ve hüküm burada yan yana görünecek."
                     : L"Arama veya filtre bu pencerede hiçbir olayla eşleşmedi.",
                 fmtBody, {rect.left, y, rect.right, rect.bottom - S(20)},
                 theme.inkFaint, DWRITE_TEXT_ALIGNMENT_CENTER,
                 DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
            return;
        }

        hRule(rect.left, rect.right, y - S(6), theme.rule);
        const size_t shown = ledgerRowCount();
        for (size_t i = 0; i < shown; ++i) {
            y = drawEvent(rect, y, visible[i]);
        }

        wchar_t footer[128];
        std::swprintf(footer, 128,
                      L"%zu olay gösteriliyor · %zu eşleşme · pencerede %zu kayıt",
                      shown, visible.size(), data.recent.size());
        text(footer, fmtMonoSm,
             {rect.left, rect.bottom - S(24), rect.right, rect.bottom - S(6)},
             theme.inkFaint);
    }

    float drawEvent(const D2D1_RECT_F& rect, float y, size_t index) {
        const telemetry::DashboardData::Event& event = data.recent[index];
        const float height = eventHeight(event);
        const bool hot = hoverEvent == static_cast<int>(index);

        if (hot) fill({rect.left, y, rect.right, y + height - S(1)}, theme.hover);
        eventRows.push_back(
            {{rect.left, y, rect.right, y + height}, static_cast<int>(index)});

        // The outcome mark in the margin is the only colour most rows carry.
        const D2D1_COLOR_F signal = !event.success        ? theme.failed
                                    : event.winner == "none" ? theme.quiet
                                                             : theme.acted;
        mark(rect.left, y + S(11), signal, 8);

        const float textLeft = rect.left + S(18);
        const float confidenceW = S(64);
        const float chainLeft = rect.left + (rect.right - rect.left) * 0.42f;

        text(widen(event.host), fmtHost,
             {textLeft, y + S(6), chainLeft - S(16), y + S(26)}, theme.ink);

        wchar_t meta[192];
        std::swprintf(meta, 192, L"%s · %s · %d deneme%s%s",
                      shortStamp(event.timestamp).c_str(),
                      formatMs(event.totalElapsedMs).c_str(), event.attemptCount,
                      event.forced ? L" · zorlanmış" : L"",
                      event.cacheHit ? L" · öğrenilmiş" : L"");
        text(meta, fmtMonoSm,
             {textLeft, y + S(27), chainLeft - S(16), y + S(43)}, theme.inkFaint);

        // Evidence chain as plain typography rather than boxed chips.
        drawChain(chainLeft, rect.right - confidenceW - S(14), y + S(8), event);

        wchar_t confidence[16];
        std::swprintf(confidence, 16, L"%%%d", event.confidence);
        text(confidence, fmtMono,
             {rect.right - confidenceW, y + S(6), rect.right, y + S(26)},
             event.confidence >= 80   ? theme.ink
             : event.confidence >= 50 ? theme.inkSoft
                                      : theme.failed,
             DWRITE_TEXT_ALIGNMENT_TRAILING);
        label(L"GÜVEN", {rect.right - confidenceW, y + S(27), rect.right, y + S(41)},
              theme.inkFaint, DWRITE_TEXT_ALIGNMENT_TRAILING);

        if (!event.attempts.empty()) {
            std::wstring chain;
            for (size_t i = 0; i < event.attempts.size(); ++i) {
                if (i) chain += L"   →   ";
                const auto& attempt = event.attempts[i];
                chain += trLabel(attempt.profile) + L" · " +
                         trLabel(attempt.signal) + L" · " +
                         formatMs(attempt.elapsedMs);
            }
            text(chain, fmtMonoSm, {textLeft, y + S(48), rect.right, y + S(64)},
                 theme.inkSoft);
        }

        hRule(rect.left, rect.right, y + height - S(1), theme.ruleFaint);
        return y + height;
    }

    // baz çizgi → kazanan profil → hüküm, laid out as measured runs so the
    // middle term can carry the outcome colour.
    void drawChain(float left, float right, float top,
                   const telemetry::DashboardData::Event& event) {
        if (right - left < S(160)) return; // the meta line already carries it

        const std::wstring baseline =
            event.baseline.empty() ? L"denenmedi" : trLabel(event.baseline);
        const std::wstring winner =
            event.success ? trLabel(event.winner) : L"sonuç yok";
        const std::wstring verdict = trLabel(event.diagnosis);
        const D2D1_COLOR_F winnerColour =
            !event.success              ? theme.failed
            : event.winner == "none"    ? theme.quiet
                                        : theme.acted;

        const float rowTop = top;
        const float rowBottom = top + S(18);
        const float arrowW = S(18);
        float x = left;

        label(L"BAZ", {x, rowTop + S(2), x + S(30), rowBottom}, theme.inkFaint);
        x += S(32);
        const float baselineW =
            std::min(measureWidth(baseline, fmtMono), (right - left) * 0.30f);
        text(baseline, fmtMono, {x, rowTop, x + baselineW, rowBottom},
             theme.inkSoft);
        x += baselineW + S(6);

        text(L"→", fmtMonoSm, {x, rowTop + S(1), x + arrowW, rowBottom},
             theme.inkFaint);
        x += arrowW;

        const float winnerW =
            std::min(measureWidth(winner, fmtMono), (right - left) * 0.30f);
        text(winner, fmtMono, {x, rowTop, x + winnerW, rowBottom}, winnerColour);
        x += winnerW + S(6);

        text(L"→", fmtMonoSm, {x, rowTop + S(1), x + arrowW, rowBottom},
             theme.inkFaint);
        x += arrowW;

        text(verdict, fmtMono, {x, rowTop, right, rowBottom}, theme.ink);
    }

    // ---- 08 process scope --------------------------------------------------

    void drawProcess() {
        const D2D1_RECT_F rect = processRect;
        float y = sectionHead(rect.left, rect.right, rect.top, L"08",
                              L"Süreç kapsamı", L"MOTORU YENİDEN BAŞLATIR");

        text(L"Her satıra bir exe adı, tam yol veya * / ? deseni yaz. Include "
             L"doluysa yalnız eşleşenler işlenir; exclude her zaman önceliklidir.",
             fmtBody, {rect.left, y, rect.right - S(240), y + S(34)}, theme.inkSoft);
        y += S(36);

        const bool wide = contentW >= S(760);
        const float ew = rect.right - rect.left;
        if (wide) {
            const float half = (ew - S(20)) / 2.0f;
            label(L"INCLUDE — YALNIZ BUNLARI İŞLE",
                  {rect.left, y, rect.left + half, y + S(14)}, theme.inkFaint);
            label(L"EXCLUDE — BUNLARA DOKUNMA",
                  {rect.left + half + S(20), y, rect.right, y + S(14)},
                  theme.inkFaint);
        } else {
            label(L"INCLUDE — YALNIZ BUNLARI İŞLE",
                  {rect.left, y, rect.right, y + S(14)}, theme.inkFaint);
        }

        D2D1_COLOR_F statusColour = theme.inkFaint;
        if (ruleStatusKind == 1) statusColour = theme.acted;
        else if (ruleStatusKind == 2) statusColour = theme.failed;
        text(ruleStatus, fmtBodyLine,
             {rect.left, rect.bottom - S(40), rect.right - S(230), rect.bottom - S(10)},
             statusColour, DWRITE_TEXT_ALIGNMENT_LEADING,
             DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
    }

    void drawFooter() {
        const float left = contentX;
        const float right = contentX + contentW;
        hRule(left, right, footerTop, theme.rule);
        text(L"Alan adı ve ağ kimliği yalnızca %APPDATA%\\splithello\\telemetry.db "
             L"içinde saklanır. Panel yalnızca “Bağlantıyı sına” seçildiğinde ağ "
             L"isteği gönderir.",
             fmtMonoSm, {left, footerTop + S(12), right, footerTop + footerH},
             theme.inkFaint);
    }

    // ---- interaction -------------------------------------------------------

    void onMouseMove(int clientX, int clientY) {
        if (!trackingMouse) {
            TRACKMOUSEEVENT track{};
            track.cbSize = sizeof(track);
            track.dwFlags = TME_LEAVE;
            track.hwndTrack = window;
            TrackMouseEvent(&track);
            trackingMouse = true;
        }
        const float docX = static_cast<float>(clientX);
        const float docY = static_cast<float>(clientY) - headerH + scrollY;

        int bar = -1;
        int row = -1;
        if (clientY > headerH) {
            for (const auto& item : chartBars) {
                if (docX >= item.rect.left && docX < item.rect.right &&
                    docY >= item.rect.top && docY < item.rect.bottom) {
                    bar = item.index;
                    break;
                }
            }
            for (const auto& item : eventRows) {
                if (docX >= item.rect.left && docX < item.rect.right &&
                    docY >= item.rect.top && docY < item.rect.bottom) {
                    row = item.index;
                    break;
                }
            }
        }
        if (bar != hoverBar || row != hoverEvent) {
            hoverBar = bar;
            hoverEvent = row;
            invalidate();
        }
    }

    void clearHover() {
        trackingMouse = false;
        if (hoverBar != -1 || hoverEvent != -1) {
            hoverBar = -1;
            hoverEvent = -1;
            invalidate();
        }
    }

    void onSize() {
        if (renderTarget) {
            RECT client{};
            GetClientRect(window, &client);
            renderTarget->Resize(D2D1::SizeU(
                static_cast<UINT32>(std::max<LONG>(1, client.right - client.left)),
                static_cast<UINT32>(std::max<LONG>(1, client.bottom - client.top))));
        }
        relayout();
        invalidate();
    }

    void onDpiChanged(UINT newDpi, const RECT* suggested) {
        dpi = newDpi ? newDpi : 96;
        scale = static_cast<float>(dpi) / 96.0f;
        createTextFormats();
        createFonts();
        for (HWND control :
             {range24, range7, range30, refreshButton, searchEdit, outcomeAll,
              outcomeBypassed, outcomeClean, outcomeUnresolved, sortRecent,
              sortSlowest, sortAttempts, testButton, includeEdit, excludeEdit,
              saveButton}) {
            if (control) {
                SendMessageW(control, WM_SETFONT,
                             reinterpret_cast<WPARAM>(controlFont), TRUE);
            }
        }
        if (suggested) {
            SetWindowPos(window, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left,
                         suggested->bottom - suggested->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        }
        onSize();
    }

    void onVScroll(WPARAM wParam) {
        SCROLLINFO info{};
        info.cbSize = sizeof(info);
        info.fMask = SIF_ALL;
        GetScrollInfo(window, SB_VERT, &info);
        float position = static_cast<float>(info.nPos);
        switch (LOWORD(wParam)) {
        case SB_LINEUP: position -= S(52); break;
        case SB_LINEDOWN: position += S(52); break;
        case SB_PAGEUP: position -= info.nPage; break;
        case SB_PAGEDOWN: position += info.nPage; break;
        case SB_TOP: position = 0; break;
        case SB_BOTTOM: position = maxScroll; break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: position = static_cast<float>(info.nTrackPos); break;
        default: break;
        }
        scrollTo(position);
    }

    LRESULT handleCommand(WPARAM wParam) {
        const int id = LOWORD(wParam);
        const int notification = HIWORD(wParam);
        switch (id) {
        case kIdRange24: windowDays = 1; refresh(); break;
        case kIdRange7: windowDays = 7; refresh(); break;
        case kIdRange30: windowDays = 30; refresh(); break;
        case kIdRefresh: refresh(); break;
        case kIdTest:
            if (notification == BN_CLICKED) startConnectionTest();
            break;
        case kIdSave:
            if (notification == BN_CLICKED) saveProcessRules();
            break;
        case kIdSearch:
            if (notification == EN_CHANGE) {
                applyFilters();
                relayout();
                invalidate();
            }
            break;
        case kIdOutcomeAll:
        case kIdOutcomeBypassed:
        case kIdOutcomeClean:
        case kIdOutcomeUnresolved:
            outcome = id == kIdOutcomeBypassed      ? Outcome::Bypassed
                      : id == kIdOutcomeClean       ? Outcome::Clean
                      : id == kIdOutcomeUnresolved  ? Outcome::Unresolved
                                                    : Outcome::All;
            applyFilters();
            relayout();
            invalidate();
            break;
        case kIdSortRecent:
        case kIdSortSlowest:
        case kIdSortAttempts:
            ordering = id == kIdSortSlowest    ? Ordering::Slowest
                       : id == kIdSortAttempts ? Ordering::Attempts
                                               : Ordering::Recent;
            applyFilters();
            relayout();
            invalidate();
            break;
        default: break;
        }
        return 0;
    }

    static LRESULT CALLBACK windowProc(HWND target, UINT message, WPARAM wParam,
                                       LPARAM lParam) {
        Impl* self =
            reinterpret_cast<Impl*>(GetWindowLongPtrW(target, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            self = static_cast<Impl*>(create->lpCreateParams);
            self->window = target;
            SetWindowLongPtrW(target, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
        }
        if (!self) return DefWindowProcW(target, message, wParam, lParam);

        switch (message) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            BeginPaint(target, &ps);
            self->paint();
            EndPaint(target, &ps);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_SIZE:
            self->onSize();
            return 0;
        case WM_DPICHANGED:
            self->onDpiChanged(HIWORD(wParam),
                               reinterpret_cast<const RECT*>(lParam));
            return 0;
        case WM_VSCROLL:
            self->onVScroll(wParam);
            return 0;
        case WM_MOUSEMOVE:
            self->onMouseMove(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        case WM_MOUSELEAVE:
            self->clearHover();
            return 0;
        case WM_MOUSEWHEEL:
            self->scrollTo(self->scrollY -
                           static_cast<float>(GET_WHEEL_DELTA_WPARAM(wParam)) /
                               WHEEL_DELTA * self->S(64));
            return 0;
        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = 760;
            info->ptMinTrackSize.y = 540;
            return 0;
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT: {
            auto dc = reinterpret_cast<HDC>(wParam);
            if (self->theme.dark) {
                SetTextColor(dc, RGB(0xEF, 0xEA, 0xE0));
                SetBkColor(dc, RGB(0x1D, 0x1B, 0x16));
                if (!self->editBrush) {
                    self->editBrush = CreateSolidBrush(RGB(0x1D, 0x1B, 0x16));
                }
            } else {
                SetTextColor(dc, RGB(0x1B, 0x19, 0x17));
                SetBkColor(dc, RGB(0xFA, 0xF8, 0xF4));
                if (!self->editBrush) {
                    self->editBrush = CreateSolidBrush(RGB(0xFA, 0xF8, 0xF4));
                }
            }
            return reinterpret_cast<LRESULT>(self->editBrush);
        }
        case WM_COMMAND:
            return self->handleCommand(wParam);
        case kTestCompletedMessage:
            self->applyTestResult();
            self->loadLive();
            self->syncTestButton();
            self->invalidate();
            return 0;
        case WM_KEYDOWN:
            if (wParam == VK_F5) { self->refresh(); return 0; }
            if (wParam == VK_ESCAPE) { ShowWindow(target, SW_HIDE); return 0; }
            break;
        case WM_TIMER:
            if (wParam == kTimerLive) {
                self->loadLive();
                self->invalidate();
            } else if (wParam == kTimerData) {
                self->refresh();
            }
            return 0;
        case WM_CLOSE:
            ShowWindow(target, SW_HIDE);
            return 0;
        case WM_DESTROY:
            KillTimer(target, kTimerLive);
            KillTimer(target, kTimerData);
            if (self->editBrush) {
                DeleteObject(self->editBrush);
                self->editBrush = nullptr;
            }
            self->discardRenderTarget();
            self->window = nullptr;
            return 0;
        default:
            break;
        }
        return DefWindowProcW(target, message, wParam, lParam);
    }

    // ---- state -------------------------------------------------------------

    std::string telemetryPath;
    std::wstring liveStatsName;
    std::function<void()> onProcessRulesChanged;
    unsigned windowDays = 30;

    HWND window = nullptr;
    HWND range24 = nullptr, range7 = nullptr, range30 = nullptr;
    HWND refreshButton = nullptr, testButton = nullptr, saveButton = nullptr;
    HWND searchEdit = nullptr, includeEdit = nullptr, excludeEdit = nullptr;
    HWND outcomeAll = nullptr, outcomeBypassed = nullptr, outcomeClean = nullptr,
         outcomeUnresolved = nullptr;
    HWND sortRecent = nullptr, sortSlowest = nullptr, sortAttempts = nullptr;
    HFONT controlFont = nullptr;
    HBRUSH editBrush = nullptr;

    UINT dpi = 96;
    float scale = 1.0f;
    bool dark = false;
    Theme theme = paperTheme();

    telemetry::DashboardData data;
    live_stats::Snapshot live;

    // Filter state. The host search string lives in searchEdit itself.
    Outcome outcome = Outcome::All;
    Ordering ordering = Ordering::Recent;
    std::vector<size_t> visible;

    // Hover state.
    struct HitRegion {
        D2D1_RECT_F rect;
        int index;
    };
    std::vector<HitRegion> chartBars;
    std::vector<HitRegion> eventRows;
    int hoverBar = -1;
    int hoverEvent = -1;
    bool trackingMouse = false;

    // Connection test.
    std::atomic<bool> testRunning{false};
    std::jthread testWorker;
    std::mutex testMutex;
    int testState = -1; // -1 idle, 0 ok, 1 warn, 2 fail, 3 offline, 4 running
    std::wstring testMessage;
    int testStatus = 0;
    uint64_t testElapsedMs = 0;
    int pendingState = -1;
    std::wstring pendingMessage;
    int pendingStatus = 0;
    uint64_t pendingElapsedMs = 0;

    // Process rules status: 0 neutral, 1 success, 2 error.
    std::wstring ruleStatus = L"Kurallar yükleniyor…";
    int ruleStatusKind = 0;

    // Layout metrics, in document space.
    float clientW = 0, clientH = 0;
    float headerH = 0, contentW = 0, contentX = 0;
    float scrollY = 0, maxScroll = 0, contentHeight = 0;
    float statusTop = 0, statusH = 0;
    float summaryTop = 0, summaryH = 0, summaryRowH = 0;
    int summaryCols = 5, summaryRows = 1;
    float rowATop = 0, rowAH = 0;
    bool rowAWide = true;
    D2D1_RECT_F volumeRect{}, latencyRect{};
    float rowBTop = 0, rowBH = 0;
    bool rowBWide = true;
    D2D1_RECT_F reasonRect{}, hostsRect{};
    float profilesTop = 0, profilesH = 0;
    float ledgerTop = 0, ledgerH = 0;
    D2D1_RECT_F ledgerRect{};
    float processTop = 0, processH = 0;
    D2D1_RECT_F processRect{};
    float footerTop = 0, footerH = 0;

    // Direct2D / DirectWrite.
    ComPtr<ID2D1Factory> d2dFactory;
    ComPtr<IDWriteFactory> dwrite;
    ComPtr<ID2D1HwndRenderTarget> renderTarget;
    ComPtr<ID2D1SolidColorBrush> brush;
    ComPtr<IDWriteTextFormat> fmtWordmark, fmtLede, fmtFigure, fmtFigureSm,
        fmtSection, fmtHost, fmtBody, fmtBodyLine, fmtMono, fmtMonoSm, fmtTicker;
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
