#include "Config.hpp"
#include "Dns.hpp"
#include "DirectRelay.hpp"
#include "NetworkIdentity.hpp"
#include "PacketStrategy.hpp"
#include "Setup.hpp"
#include "SocksProxy.hpp"
#include "Strategy.hpp"
#include "SystemProxy.hpp"
#include "TransparentDnsProxy.hpp"
#include "TransparentFlow.hpp"
#include "TrayApp.hpp"
#include "WinDivertInterceptor.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <iostream>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <shellapi.h>

#pragma comment(lib, "ws2_32.lib")

namespace {

constexpr int kEngineFailOpenExitCode = 2;

SocksProxy* g_proxy = nullptr;
TransparentDnsProxy* g_dnsProxy = nullptr;
WinDivertInterceptor* g_interceptor = nullptr;
HANDLE g_elevationShutdownEvent = nullptr;

void cleanup(int = 0) {
    // Stop redirection before closing the listener. No new flow may be sent to
    // a port that is already shutting down.
    if (g_interceptor) g_interceptor->stop();
    if (g_dnsProxy) g_dnsProxy->stop();
    if (g_proxy) g_proxy->stop();
}

BOOL WINAPI consoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_CLOSE_EVENT ||
        event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT) {
        if (g_elevationShutdownEvent) SetEvent(g_elevationShutdownEvent);
        cleanup();
        return TRUE;
    }
    return FALSE;
}

void printUsage(const char* exe) {
    std::cout
        << "SplitHello - TLS ClientHello fragmentation for censorship bypass\n\n"
        << "Kullanim: " << exe << " [secenekler]\n\n"
        << "Secenekler:\n"
        << "  --setup              Cloudflare hesabini bagla ve worker deploy et\n"
        << "  --redeploy           Worker kodunu guncelle, gizli anahtari yenile\n"
        << "  --worker <url>       Worker URL (config yerine manuel belirt)\n"
        << "  --port <port>        Transparent relay portu (varsayilan: 1080)\n"
        << "  --split-delay <ms>   Parcalar arasi bekleme (varsayilan: 20)\n"
        << "  --strategy <ad>      Otomatik secim yerine tek profili zorla\n"
        << "  --tunnel-fallback    Tum profiller basarisizsa Worker tunelini kullan\n"
        << "  --manual-proxy       WinDivert olmadan SOCKS5/CONNECT dinle\n"
        << "  --quic-mode <mod>    allow (varsayilan), adaptive veya block\n"
        << "  --allow-quic         Eski ad; --quic-mode allow ile ayni\n"
        << "  --restore-proxy      Cokme sonrasi kalan proxy yedegini geri yukle ve cik\n"
        << "  --forget-token       Kayitli Cloudflare token'ini sil ve cik\n"
        << "  --forget-strategies  Ogrenilen alan adi stratejilerini sifirla ve cik\n"
        << "  --list-strategies    Parcalama profillerini listele ve cik\n"
        << "  --console            Tray yerine konsolda calistir\n"
        << "  --verbose            Debug loglama (konsol modunu acar)\n"
        << "  --help               Bu yardimi goster\n\n"
        << "Ilk kullanim:\n"
        << "  " << exe << " --setup\n\n"
        << "Sonraki kullanimlar:\n"
        << "  " << exe << "\n"
        << "    WinDivert baslar ve tum uygulamalarin TCP/443 trafigi otomatik yakalanir.\n"
        << "    Yonetici yetkisi gerekir; Ctrl+C ile filtre tamamen kaldirilir.\n";
}

void printStrategies() {
    std::cout << "Parcalama profilleri (deneme sirasiyla):\n\n";
    for (const strategy::Profile& profile : strategy::profiles()) {
        std::cout << "  " << profile.name;
        for (size_t i = profile.name.size(); i < 16; ++i) std::cout << ' ';
        std::cout << profile.description;
        if (profile.requiresSni) std::cout << " (SNI gerektirir)";
        std::cout << "\n";
    }
    std::cout << "\nCalisan profil ag + alan adi bazinda ogrenilir ve "
              << Config::strategyPath() << " dosyasinda saklanir.\n";
}

void initializeLogging(bool verbose, bool persistent) {
    try {
        std::vector<spdlog::sink_ptr> sinks;
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());

        const std::string path = Config::logPath();
        if (persistent && !path.empty()) {
            const std::filesystem::path logPath(path);
            const std::filesystem::path logDirectory = logPath.parent_path();
            std::filesystem::create_directories(logDirectory);

            // Keep diagnostics useful without building a permanent browsing
            // history. Size rotation caps normal growth; age pruning also
            // removes manually archived SplitHello logs after one week.
            const auto oldestAllowed =
                std::filesystem::file_time_type::clock::now() -
                std::chrono::hours(24 * 7);
            std::error_code iterationError;
            for (const auto& entry :
                 std::filesystem::directory_iterator(logDirectory, iterationError)) {
                if (iterationError || !entry.is_regular_file()) continue;
                const std::wstring name = entry.path().filename().wstring();
                if (!name.starts_with(L"splithello") || entry.path() == logPath) {
                    continue;
                }
                std::error_code timeError;
                const auto modified = entry.last_write_time(timeError);
                if (!timeError && modified < oldestAllowed) {
                    std::error_code removeError;
                    std::filesystem::remove(entry.path(), removeError);
                }
            }

            auto fileSink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                path, 512 * 1024, 2);
            // Persistent logs stay operational even when --verbose is used;
            // verbose packet/DNS chatter is console-only.
            fileSink->set_level(spdlog::level::info);
            sinks.push_back(std::move(fileSink));
        }

        auto logger = std::make_shared<spdlog::logger>("splithello", sinks.begin(),
                                                       sinks.end());
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%P] [%^%l%$] %v");
        logger->set_level(verbose ? spdlog::level::debug : spdlog::level::info);
        logger->flush_on(spdlog::level::info);
        spdlog::set_default_logger(std::move(logger));
    } catch (const std::exception& error) {
        spdlog::warn("Kalici log acilamadi: {}", error.what());
    }
}

bool parseUnsigned(const char* text, unsigned& out) {
    const std::string_view view(text);
    unsigned value = 0;
    const auto result = std::from_chars(view.data(), view.data() + view.size(), value);
    if (result.ec != std::errc{} || result.ptr != view.data() + view.size()) return false;
    out = value;
    return true;
}

bool isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;

    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    const bool elevated = GetTokenInformation(token, TokenElevation, &elevation,
                                              sizeof(elevation), &returned) != FALSE &&
                          elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

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

int relaunchElevated(bool waitForExit = true) {
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (!arguments || argumentCount == 0) return -1;

    std::wstring parameters;
    for (int i = 1; i < argumentCount; ++i) {
        if (!parameters.empty()) parameters.push_back(L' ');
        parameters += quoteWindowsArgument(arguments[i]);
    }

    HANDLE shutdownEvent = nullptr;
    if (waitForExit) {
        const std::wstring shutdownEventName =
            L"Local\\SplitHello-shutdown-" + std::to_wstring(GetCurrentProcessId()) +
            L"-" + std::to_wstring(GetTickCount64());
        shutdownEvent = CreateEventW(nullptr, TRUE, FALSE,
                                    shutdownEventName.c_str());
        if (!shutdownEvent) {
            LocalFree(arguments);
            return -1;
        }
        parameters += L" --shutdown-event ";
        parameters += quoteWindowsArgument(shutdownEventName);
        parameters += L" --parent-pid ";
        parameters += std::to_wstring(GetCurrentProcessId());
    }

    wchar_t executable[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    LocalFree(arguments);
    if (length == 0 || length >= MAX_PATH) {
        if (shutdownEvent) CloseHandle(shutdownEvent);
        return -1;
    }

    SHELLEXECUTEINFOW launch{};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS;
    launch.lpVerb = L"runas";
    launch.lpFile = executable;
    launch.lpParameters = parameters.c_str();
    launch.nShow = waitForExit ? SW_SHOWNORMAL : SW_HIDE;
    if (!ShellExecuteExW(&launch)) {
        spdlog::error("UAC baslatma hatasi: {}", GetLastError());
        if (shutdownEvent) CloseHandle(shutdownEvent);
        return -1;
    }

    if (!waitForExit) {
        CloseHandle(launch.hProcess);
        return 0;
    }

    g_elevationShutdownEvent = shutdownEvent;
    WaitForSingleObject(launch.hProcess, INFINITE);
    g_elevationShutdownEvent = nullptr;
    DWORD exitCode = 1;
    GetExitCodeProcess(launch.hProcess, &exitCode);
    CloseHandle(launch.hProcess);
    CloseHandle(shutdownEvent);
    return (int)exitCode;
}

class ShutdownEventMonitor {
public:
    ShutdownEventMonitor(const std::string& name, DWORD parentPid) {
        stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!name.empty()) {
            const std::wstring wideName(name.begin(), name.end());
            event_ = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE,
                                wideName.c_str());
        }
        if (parentPid != 0) {
            parent_ = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
        }
        if (!stopEvent_ || (!event_ && !parent_)) {
            spdlog::warn("Ebeveyn kapanis olayi acilamadi: {}", GetLastError());
            return;
        }
        worker_ = std::thread([this]() {
            HANDLE handles[3] = {};
            DWORD count = 0;
            if (event_) handles[count++] = event_;
            if (parent_) handles[count++] = parent_;
            handles[count++] = stopEvent_;
            const DWORD result = WaitForMultipleObjects(count, handles, FALSE, INFINITE);
            if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + count - 1 &&
                !stopping_) {
                cleanup();
            }
        });
    }

    ~ShutdownEventMonitor() {
        stopping_ = true;
        if (stopEvent_) SetEvent(stopEvent_);
        if (worker_.joinable()) worker_.join();
        if (event_) CloseHandle(event_);
        if (parent_) CloseHandle(parent_);
        if (stopEvent_) CloseHandle(stopEvent_);
    }

    ShutdownEventMonitor(const ShutdownEventMonitor&) = delete;
    ShutdownEventMonitor& operator=(const ShutdownEventMonitor&) = delete;

private:
    HANDLE event_ = nullptr;
    HANDLE parent_ = nullptr;
    HANDLE stopEvent_ = nullptr;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
};

struct Options {
    std::string workerUrl;
    std::string forcedStrategy;
    uint16_t port = 1080;
    unsigned splitDelayMs = 0;
    bool splitDelaySet = false;
    bool setup = false;
    bool redeploy = false;
    bool manualProxy = false;
    quic_strategy::Mode quicMode = quic_strategy::Mode::Allow;
    bool tunnelFallback = false;
    bool restoreProxy = false;
    bool forgetToken = false;
    bool forgetStrategies = false;
    bool listStrategies = false;
    bool verbose = false;
    bool console = false;
    bool engine = false;
    std::string shutdownEventName;
    std::string readyEventName;
    DWORD parentPid = 0;
};

// Returns false when the program should exit; `exitCode` says with what.
bool parseArgs(int argc, char* argv[], Options& options, int& exitCode) {
    exitCode = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool hasValue = (i + 1 < argc);

        if (arg == "--worker" && hasValue) {
            options.workerUrl = argv[++i];
        } else if (arg == "--port" && hasValue) {
            unsigned port = 0;
            if (!parseUnsigned(argv[++i], port) || port == 0 || port > 65535) {
                std::cerr << "Gecersiz port: " << argv[i] << "\n";
                exitCode = 1;
                return false;
            }
            options.port = (uint16_t)port;
        } else if (arg == "--split-delay" && hasValue) {
            if (!parseUnsigned(argv[++i], options.splitDelayMs) || options.splitDelayMs > 2000) {
                std::cerr << "Gecersiz gecikme (0-2000 ms): " << argv[i] << "\n";
                exitCode = 1;
                return false;
            }
            options.splitDelaySet = true;
        } else if (arg == "--strategy" && hasValue) {
            options.forcedStrategy = argv[++i];
            if (!strategy::findProfile(options.forcedStrategy)) {
                std::cerr << "Bilinmeyen profil: " << options.forcedStrategy << "\n\n";
                printStrategies();
                exitCode = 1;
                return false;
            }
        } else if (arg == "--manual-proxy" || arg == "--no-system-proxy") {
            options.manualProxy = true;
        } else if (arg == "--allow-quic") {
            options.quicMode = quic_strategy::Mode::Allow;
        } else if (arg == "--quic-mode" && hasValue) {
            const std::string mode = argv[++i];
            if (mode == "adaptive") {
                options.quicMode = quic_strategy::Mode::Adaptive;
            } else if (mode == "block") {
                options.quicMode = quic_strategy::Mode::Block;
            } else if (mode == "allow") {
                options.quicMode = quic_strategy::Mode::Allow;
            } else {
                std::cerr << "Gecersiz QUIC modu: " << mode
                          << " (adaptive, block veya allow)\n";
                exitCode = 1;
                return false;
            }
        } else if (arg == "--tunnel-fallback") {
            options.tunnelFallback = true;
        } else if (arg == "--restore-proxy") {
            options.restoreProxy = true;
        } else if (arg == "--forget-token") {
            options.forgetToken = true;
        } else if (arg == "--forget-strategies") {
            options.forgetStrategies = true;
        } else if (arg == "--list-strategies") {
            options.listStrategies = true;
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "--console") {
            options.console = true;
        } else if (arg == "--engine") {
            // Internal mode: the elevated tray controller owns this process.
            options.engine = true;
        } else if (arg == "--shutdown-event" && hasValue) {
            // Internal parent/child lifecycle channel used after UAC relaunch.
            options.shutdownEventName = argv[++i];
        } else if (arg == "--ready-event" && hasValue) {
            options.readyEventName = argv[++i];
        } else if (arg == "--parent-pid" && hasValue) {
            unsigned parentPid = 0;
            if (!parseUnsigned(argv[++i], parentPid)) {
                exitCode = 1;
                return false;
            }
            options.parentPid = (DWORD)parentPid;
        } else if (arg == "--setup") {
            options.setup = true;
        } else if (arg == "--redeploy") {
            options.redeploy = true;
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return false;
        } else {
            std::cerr << "Bilinmeyen parametre: " << arg << "\n";
            printUsage(argv[0]);
            exitCode = 1;
            return false;
        }
    }
    return true;
}

bool shouldRunTray(const Options& options) {
    return !options.engine && !options.console && !options.verbose &&
        !options.manualProxy && !options.setup && !options.redeploy &&
        !options.restoreProxy && !options.forgetToken &&
        !options.forgetStrategies && !options.listStrategies;
}

std::vector<std::wstring> collectEngineArguments() {
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (!arguments) return {};

    std::vector<std::wstring> result;
    for (int i = 1; i < argumentCount; ++i) {
        const std::wstring argument = arguments[i];
        const bool internalValue = argument == L"--shutdown-event" ||
            argument == L"--ready-event" || argument == L"--parent-pid";
        if (internalValue) {
            if (i + 1 < argumentCount) ++i;
            continue;
        }
        if (argument == L"--engine") continue;
        result.push_back(argument);
    }
    LocalFree(arguments);
    return result;
}

void signalReadyEvent(const std::string& eventName) {
    if (eventName.empty()) return;
    const std::wstring wideName(eventName.begin(), eventName.end());
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, wideName.c_str());
    if (!event) {
        spdlog::warn("Tray hazir olayi acilamadi: {}", GetLastError());
        return;
    }
    SetEvent(event);
    CloseHandle(event);
}

} // namespace

int main(int argc, char* argv[]) {
    spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");

    Options options;
    int exitCode = 0;
    if (!parseArgs(argc, argv, options, exitCode)) return exitCode;
    const bool trayMode = shouldRunTray(options);
    // The tray controller and engine are separate processes. Only the engine
    // owns the rotating file sink, avoiding inter-process rotation races.
    initializeLogging(options.verbose, !trayMode);

    if (trayMode || options.engine) {
        if (HWND console = GetConsoleWindow()) ShowWindow(console, SW_HIDE);
    }

    if (options.listStrategies) {
        printStrategies();
        return 0;
    }

    const bool exitsWithoutInterception = options.restoreProxy || options.forgetToken ||
        options.forgetStrategies || options.redeploy;
    if (!options.manualProxy && !exitsWithoutInterception && !isElevated()) {
        spdlog::info("WinDivert icin yonetici izni isteniyor");
        const int elevatedExitCode = relaunchElevated(!trayMode);
        if (elevatedExitCode < 0) {
            spdlog::error("Yonetici olarak yeniden baslatma reddedildi veya basarisiz oldu");
            if (trayMode) {
                MessageBoxW(nullptr,
                            L"SplitHello ağ koruması için yönetici izni gerekiyor.",
                            L"SplitHello", MB_OK | MB_ICONERROR);
            }
            return 1;
        }
        return elevatedExitCode;
    }

    if (trayMode) {
        HANDLE instanceMutex = CreateMutexW(nullptr, TRUE,
                                            L"Local\\SplitHello-Tray");
        if (!instanceMutex) return 1;
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(instanceMutex);
            return 0;
        }

        Config trayConfig;
        trayConfig.load();
        const bool configured = !options.workerUrl.empty() ||
            !trayConfig.workerUrl.empty();
        const std::wstring logDirectory =
            std::filesystem::path(Config::logPath()).parent_path().wstring();
        TrayApp tray(collectEngineArguments(), logDirectory, configured);
        const int trayExitCode = tray.run();
        ReleaseMutex(instanceMutex);
        CloseHandle(instanceMutex);
        return trayExitCode;
    }

    ShutdownEventMonitor shutdownMonitor(options.shutdownEventName,
                                         options.parentPid);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        spdlog::error("WSAStartup hatasi");
        return 1;
    }

    struct WinsockGuard {
        ~WinsockGuard() { WSACleanup(); }
    } winsockGuard;

    Config config;
    config.load();

    // An older build stored the token in clear text; rewrite it encrypted.
    if (config.migratedFromPlaintext) config.save();

    if (options.restoreProxy) {
        const bool restored = SystemProxy::restoreLeftovers(Config::proxyBackupPath(), true);
        std::cout << (restored ? "Sistem proxy ayarlari geri yuklendi.\n"
                               : "Geri yuklenecek proxy yedegi bulunamadi.\n");
        return restored ? 0 : 1;
    }

    if (options.forgetToken) {
        const bool ok = config.forgetToken();
        std::cout << (ok ? "Cloudflare token silindi. Worker calismaya devam eder;\n"
                           "yeniden deploy icin --setup veya --redeploy gerekir.\n"
                         : "Token silinemedi.\n");
        return ok ? 0 : 1;
    }

    if (options.forgetStrategies) {
        strategy::Store store(Config::strategyPath());
        store.load();
        const size_t count = store.size();
        store.clear();
        std::cout << count << " alan adi icin ogrenilen strateji silindi.\n";
        return 0;
    }

    if (options.redeploy) {
        if (config.workerName.empty()) {
            std::cerr << "Once --setup calistirin.\n";
            return 1;
        }
        return redeployWorker(config) ? 0 : 1;
    }

    if (options.setup && !runSetup(config)) return 1;

    std::string workerUrl = options.workerUrl.empty() ? config.workerUrl : options.workerUrl;

    if (workerUrl.empty()) {
        std::cout << "SplitHello - TLS ClientHello fragmentation for censorship bypass\n\n"
                  << "Yapilandirma bulunamadi. Setup baslatiliyor...\n";
        if (!runSetup(config)) return 1;
        workerUrl = config.workerUrl;
    }

    if (config.sharedSecret.empty()) {
        spdlog::warn("Worker gizli anahtari yok. Eski bir deploy kullaniyorsunuz: "
                     "'--redeploy' calistirin, aksi halde worker herkese acik kalir.");
    }

    if (options.splitDelaySet) config.splitDelayMs = options.splitDelayMs;
    if (options.tunnelFallback) config.tunnelFallback = true;

    // Full interception no longer needs Internet Options. Undo a setting left
    // by older builds before opening WinDivert.
    SystemProxy::restoreLeftovers(Config::proxyBackupPath());

    constexpr uint16_t kPreferredConnectPort = 65534;
    constexpr uint16_t kAlternateConnectPort = 65533;
    constexpr uint16_t kPreferredDnsProxyPort = 1053;
    constexpr uint16_t kAlternateDnsProxyPort = 1054;
    const uint16_t connectPort = options.port == kPreferredConnectPort
        ? kAlternateConnectPort : kPreferredConnectPort;
    const uint16_t dnsProxyPort = options.port == kPreferredDnsProxyPort
        ? kAlternateDnsProxyPort : kPreferredDnsProxyPort;

    dns::Resolver resolver(workerUrl, config.sharedSecret,
                           options.manualProxy ? 0 : connectPort);
    strategy::Store strategies(Config::strategyPath());
    packet_strategy::PolicyRegistry packetPolicies;
    strategies.load();
    const std::string networkId = network_identity::current();

    if (!options.forcedStrategy.empty()) {
        spdlog::info("Profil zorlandi: '{}' (otomatik secim devre disi)", options.forcedStrategy);
    }

    RelayContext context;
    context.workerUrl = workerUrl;
    context.sharedSecret = config.sharedSecret;
    context.networkId = networkId;
    context.resolver = &resolver;
    context.strategies = &strategies;
    context.packetPolicies = options.manualProxy ? nullptr : &packetPolicies;
    context.splitDelayMs = config.splitDelayMs;
    context.probeTimeoutMs = config.probeTimeoutMs;
    context.tunnelFallback = config.tunnelFallback;
    context.bypassConnectPort = options.manualProxy ? 0 : connectPort;
    context.forcedProfile = options.forcedStrategy;

    spdlog::info("SplitHello baslatiliyor");
    spdlog::info("Worker: {}", workerUrl);
    spdlog::info("Ag profili: {}", networkId);
    spdlog::info("Relay portu: {} | split-delay: {} ms | ogrenilen alan adi: {}",
                 options.port, config.splitDelayMs, strategies.size());

    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    SocksProxy proxy(context, options.port, options.manualProxy ? nullptr : &flows);
    TransparentDnsProxy dnsProxy(resolver, datagrams, dnsProxyPort);
    g_proxy = &proxy;
    g_dnsProxy = options.manualProxy ? nullptr : &dnsProxy;

    std::signal(SIGINT, cleanup);
    std::signal(SIGTERM, cleanup);
    SetConsoleCtrlHandler(consoleHandler, TRUE);

    int runtimeExitCode = 0;
    if (options.manualProxy) {
        spdlog::warn("Manuel proxy modu: yalniz SOCKS5/HTTP CONNECT kullanan uygulamalar yakalanir");
        proxy.run();
    } else {
        std::atomic<bool> proxyExited{false};
        bool proxyResult = false;
        std::thread proxyThread([&]() {
            proxyResult = proxy.run();
            proxyExited = true;
        });

        // WinDivert must never reflect into a listener that has not bound yet.
        for (unsigned waited = 0; waited < 2000 && !proxy.running() && !proxyExited;
             waited += 10) {
            Sleep(10);
        }

        if (!proxy.running()) {
            proxy.stop();
            if (proxyThread.joinable()) proxyThread.join();
            spdlog::error("Transparent relay baslatilamadi");
            return proxyResult ? 0 : 1;
        }

        if (!dnsProxy.start()) {
            proxy.stop();
            if (proxyThread.joinable()) proxyThread.join();
            g_dnsProxy = nullptr;
            spdlog::error("Transparent DNS relay baslatilamadi");
            return 1;
        }

        WinDivertInterceptor interceptor(flows, datagrams, packetPolicies, options.port,
                                         dnsProxyPort, connectPort,
                                         options.quicMode);
        g_interceptor = &interceptor;
        if (!interceptor.start()) {
            dnsProxy.stop();
            proxy.stop();
            if (proxyThread.joinable()) proxyThread.join();
            g_interceptor = nullptr;
            g_dnsProxy = nullptr;
            return 1;
        }

        signalReadyEvent(options.readyEventName);

        // Do not block only on the relay. If the packet reader dies, its
        // WinDivert handle closes first (fail-open), then this loop tears down
        // the remaining local listeners so the tray can restart a clean engine.
        while (!proxyExited && interceptor.running()) {
            Sleep(50);
        }

        const DWORD fatalWinDivertError = interceptor.fatalErrorCode();
        const bool relayExitedUnexpectedly = proxyExited && interceptor.running();
        if (fatalWinDivertError != ERROR_SUCCESS) {
            runtimeExitCode = kEngineFailOpenExitCode;
            spdlog::error(
                "Ag motoru fail-open ile kapandi: WinDivert hata={}; tray yeniden baslatabilir",
                fatalWinDivertError);
        } else if (relayExitedUnexpectedly) {
            runtimeExitCode = kEngineFailOpenExitCode;
            spdlog::error(
                "Transparent relay beklenmedik sekilde durdu; WinDivert fail-open kapatiliyor");
        }

        interceptor.stop();
        dnsProxy.stop();
        proxy.stop();
        if (proxyThread.joinable()) proxyThread.join();
        g_interceptor = nullptr;
        g_dnsProxy = nullptr;
    }

    cleanup();
    g_proxy = nullptr;
    spdlog::info("SplitHello durduruldu");
    return runtimeExitCode;
}
