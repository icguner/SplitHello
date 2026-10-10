#include "CommandLine.hpp"
#include "Config.hpp"
#include "Dns.hpp"
#include "DirectRelay.hpp"
#include "EngineExitCodes.hpp"
#include "LiveStats.hpp"
#include "NetworkIdentity.hpp"
#include "PacketStrategy.hpp"
#include "ProcessFilter.hpp"
#include "Secure.hpp"
#include "Setup.hpp"
#include "SocksProxy.hpp"
#include "Strategy.hpp"
#include "SystemProxy.hpp"
#include "Telemetry.hpp"
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
#include <memory>
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

std::atomic<bool> g_shutdownRequested{false};
static_assert(std::atomic<bool>::is_always_lock_free);
HANDLE g_elevationShutdownEvent = nullptr;

void cleanup(int = 0) {
    g_shutdownRequested.store(true);
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
        << "SplitHello - adaptive DPI diagnosis and direct-path bypass\n\n"
        << "Kullanim: " << exe << " [secenekler]\n\n"
        << "Secenekler:\n"
        << "  --setup              Cloudflare hesabini bagla ve worker deploy et\n"
        << "  --redeploy           Worker kodunu guncelle, gizli anahtari yenile\n"
        << "  --worker <url>       Worker URL (config yerine manuel belirt)\n"
        << "  --port <port>        Transparent relay portu (varsayilan: 1080)\n"
        << "  --split-delay <ms>   TLS kayit parcalari arasi bekleme (varsayilan: 20)\n"
        << "  --strategy <ad>      Tanilama: profile sabitle ve ogrenmeyi kapat\n"
        << "  --tunnel-fallback    Tum profiller basarisizsa Worker tunelini kullan\n"
        << "  --manual-proxy       WinDivert olmadan SOCKS5/CONNECT dinle\n"
        << "  --quic-mode <mod>    allow (varsayilan), adaptive veya block\n"
        << "  --allow-quic         Eski ad; --quic-mode allow ile ayni\n"
        << "  --include-process <desen>  Yalniz eslesen exe yollarini isle (tekrarlanabilir)\n"
        << "  --exclude-process <desen>  Eslesen exe yollarini atla (tekrarlanabilir)\n"
        << "  --restore-proxy      Cokme sonrasi kalan proxy yedegini geri yukle ve cik\n"
        << "  --forget-token       Eski surumden kalan API token alanini sil ve cik\n"
        << "  --forget-strategies  Ogrenilen alan adi stratejilerini sifirla ve cik\n"
        << "  --list-strategies    DPI uyarlama profillerini listele ve cik\n"
        << "  --console            Tray yerine konsolda calistir\n"
        << "  --verbose            Debug loglama (konsol modunu acar)\n"
        << "  --help               Bu yardimi goster\n\n"
        << "Ilk kullanim:\n"
        << "  " << exe << " --setup\n\n"
        << "Sonraki kullanimlar:\n"
        << "  " << exe << "\n"
        << "    WinDivert baslar ve tum uygulamalarin TCP/443 trafigi otomatik yakalanir.\n"
        << "    Yonetici yetkisi gerekir; varsayilan yonetim sistem tepsisindedir.\n"
        << "    --console modunda Ctrl+C filtreyi tamamen kaldirir.\n";
}

void printStrategies() {
    std::cout << "Parcalama profilleri (deneme sirasiyla):\n\n";
    for (const strategy::Profile& profile : strategy::profiles()) {
        std::cout << "  " << profile.name;
        for (size_t i = profile.name.size(); i < 22; ++i) std::cout << ' ';
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

// Same limits Config applies when it reads process rules from disk.
bool validProcessPattern(const char* pattern) {
    const size_t length = std::string_view(pattern).size();
    return length > 0 && length <= 1024;
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

// The tray holds this mutex for its whole lifetime. A tray running elevated
// owns an admin-only DACL, so an access-denied open also means "exists".
bool trayInstanceRunning() {
    HANDLE existing = OpenMutexW(SYNCHRONIZE, FALSE, L"Local\\SplitHello-Tray");
    if (existing) {
        CloseHandle(existing);
        return true;
    }
    return GetLastError() == ERROR_ACCESS_DENIED;
}

int relaunchElevated(bool waitForExit = true) {
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (!arguments || argumentCount == 0) return -1;

    std::wstring parameters;
    for (int i = 1; i < argumentCount; ++i) {
        if (!parameters.empty()) parameters.push_back(L' ');
        parameters += cmdline::quoteArgument(arguments[i]);
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
        parameters += cmdline::quoteArgument(shutdownEventName);
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

    // True once a thread is watching the event and/or the parent process.
    bool active() const { return worker_.joinable(); }

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
    std::vector<std::string> processInclude;
    std::vector<std::string> processExclude;
    uint16_t port = 1080;
    unsigned splitDelayMs = 0;
    bool splitDelaySet = false;
    bool setup = false;
    bool setupOnly = false; // tray-launched: run setup, wait for a key, exit
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
    std::string liveStatsName;
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
        } else if (arg == "--include-process" && hasValue) {
            // An empty/oversized pattern would be dropped later, and a dropped
            // include list silently widens the scope to every process.
            if (!validProcessPattern(argv[++i])) {
                std::cerr << "Gecersiz surec deseni (bos veya 1024 bayttan uzun)\n";
                exitCode = 1;
                return false;
            }
            options.processInclude.push_back(argv[i]);
        } else if (arg == "--exclude-process" && hasValue) {
            if (!validProcessPattern(argv[++i])) {
                std::cerr << "Gecersiz surec deseni (bos veya 1024 bayttan uzun)\n";
                exitCode = 1;
                return false;
            }
            options.processExclude.push_back(argv[i]);
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
        } else if (arg == "--live-stats" && hasValue) {
            options.liveStatsName = argv[++i];
        } else if (arg == "--parent-pid" && hasValue) {
            unsigned parentPid = 0;
            if (!parseUnsigned(argv[++i], parentPid)) {
                exitCode = 1;
                return false;
            }
            options.parentPid = (DWORD)parentPid;
        } else if (arg == "--setup") {
            options.setup = true;
        } else if (arg == "--setup-only") {
            options.setup = true;
            options.setupOnly = true;
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
            argument == L"--ready-event" || argument == L"--parent-pid" ||
            argument == L"--live-stats";
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
    // WinDivert.dll is a static import and is already mapped by the loader; this
    // only restricts later LoadLibrary calls to System32 and the exe directory.
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");

    Options options;
    int exitCode = 0;
    if (!parseArgs(argc, argv, options, exitCode)) return exitCode;
    const bool trayMode = shouldRunTray(options);

    // This is a console-subsystem exe: hide the window as early as possible so
    // a tray/engine start does not flash a console.
    if (trayMode || options.engine) {
        if (HWND console = GetConsoleWindow()) ShowWindow(console, SW_HIDE);
    }

    // Installed before the elevation relaunch so Ctrl+C / console close reach
    // the elevated child through g_elevationShutdownEvent while we wait on it.
    std::signal(SIGINT, cleanup);
    std::signal(SIGTERM, cleanup);
    SetConsoleCtrlHandler(consoleHandler, TRUE);

    // The tray controller and engine are separate processes. Only the engine
    // owns the rotating file sink, avoiding inter-process rotation races.
    initializeLogging(options.verbose, !trayMode);

    if (options.listStrategies) {
        printStrategies();
        return 0;
    }

    const bool exitsWithoutInterception = options.restoreProxy || options.forgetToken ||
        options.forgetStrategies || options.redeploy;
    if (!options.manualProxy && !exitsWithoutInterception && !isElevated()) {
        // Decide "already running" before the UAC prompt; otherwise a second
        // launch asks for elevation and then exits without a word.
        if (trayMode && trayInstanceRunning()) {
            spdlog::info("SplitHello tray zaten calisiyor");
            return 0;
        }
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
        // An unreadable config is not "setup missing": let the engine start and
        // report the precise reason (exit code 16) instead of asking for --setup.
        const bool configured = !options.workerUrl.empty() || trayConfig.isValid() ||
                                trayConfig.loadFailed;
        const std::wstring logDirectory = Config::configDirPath().wstring();
        TrayApp tray(collectEngineArguments(), logDirectory,
                     Config::telemetryPath(), configured);
        const int trayExitCode = tray.run();
        ReleaseMutex(instanceMutex);
        CloseHandle(instanceMutex);
        return trayExitCode;
    }

    ShutdownEventMonitor shutdownMonitor(options.shutdownEventName,
                                         options.parentPid);
    // The hidden engine must always be stoppable by its tray. If neither the
    // shutdown event nor the parent process could be opened, running on would
    // leave WinDivert interception that nobody can turn off: exit (fail-open).
    const bool monitorRequested = options.engine || !options.shutdownEventName.empty() ||
                                  options.parentPid != 0;
    if (monitorRequested && !shutdownMonitor.active()) {
        spdlog::error("Tray kapatma kanali acilamadi; denetimsiz calismamak icin cikiliyor");
        return engine_exit::kMonitorUnavailable;
    }

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
    if (config.loadFailed && !options.restoreProxy) {
        // Defaults would be saved over the real file by the migration/--forget
        // paths below, and the engine would run with the wrong settings.
        spdlog::error("Yapilandirma dosyasi var ama okunamadi: {}", Config::configPath());
        std::cerr << "Yapilandirma okunamadi: " << Config::configPath() << "\n";
        return engine_exit::kConfigUnreadable;
    }

    // Current releases delegate Cloudflare OAuth storage to Wrangler's OS
    // keyring. Rewrite old configs once to remove every legacy API-token field
    // while retaining/migrating the Worker shared secret.
    if (config.migratedFromPlaintext || config.legacyApiTokenPresent) {
        secure::wipe(config.apiToken);
        config.save();
    }

    if (options.restoreProxy) {
        const bool restored = SystemProxy::restoreLeftovers(Config::proxyBackupPath(), true);
        std::cout << (restored ? "Sistem proxy ayarlari geri yuklendi.\n"
                               : "Geri yuklenecek proxy yedegi bulunamadi.\n");
        return restored ? 0 : 1;
    }

    if (options.forgetToken) {
        const bool ok = config.forgetToken();
        std::cout << (ok ? "Eski Cloudflare API token alani silindi.\n"
                           "Wrangler OAuth oturumu etkilenmedi.\n"
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

    if (options.setup) {
        const bool done = runSetup(config);
        if (options.setupOnly) {
            // The console belongs to the tray-launched child and closes on exit.
            std::cout << "\nKapatmak icin Enter'a basin...";
            std::cin.get();
            return done ? 0 : 1;
        }
        if (!done) return 1;
    }

    std::string workerUrl = options.workerUrl.empty() ? config.workerUrl : options.workerUrl;

    if (workerUrl.empty() && config.dnsMode == DnsMode::Worker) {
        if (options.engine) {
            // The hidden engine has no console; never block it on interactive setup.
            spdlog::error("Worker yapilandirmasi yok; once splithello.exe --setup calistirin");
            return engine_exit::kSetupRequired;
        }
        std::cout << "SplitHello - TLS ClientHello fragmentation for censorship bypass\n\n"
                  << "Yapilandirma bulunamadi. Setup baslatiliyor...\n";
        if (!runSetup(config)) return 1;
        workerUrl = config.workerUrl;
    }

    if (config.dnsMode == DnsMode::Worker && config.sharedSecret.empty()) {
        spdlog::warn("Worker gizli anahtari yok. Worker istekleri guvenli bicimde "
                     "reddeder; kullanmak icin '--redeploy' calistirin.");
    }

    if (options.splitDelaySet) config.splitDelayMs = options.splitDelayMs;
    if (options.tunnelFallback) config.tunnelFallback = true;

    // An include list that is present but entirely unusable must not turn into
    // "no include rules" (= intercept every process). Refuse to intercept; the
    // network stays on its normal path. Fix or clear process_include to start.
    if (config.processIncludeInvalid) {
        spdlog::error("process_include dolu ama tum girdiler gecersiz; kapsam "
                      "genisletilmeyecek, ag motoru baslatilmiyor");
        std::cerr << "process_include gecersiz: duzeltin veya bosaltin ("
                  << Config::configPath() << ")\n";
        return engine_exit::kInvalidProcessRules;
    }

    // shortcut: CLI rules are merged for this run only and are not shown in the
    // dashboard; the tray tells the dashboard how many were passed.
    config.processInclude.insert(config.processInclude.end(),
                                 options.processInclude.begin(),
                                 options.processInclude.end());
    config.processExclude.insert(config.processExclude.end(),
                                 options.processExclude.begin(),
                                 options.processExclude.end());

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

    const bool useWorkerDns = config.dnsMode == DnsMode::Worker;
    dns::Resolver resolver(useWorkerDns ? workerUrl : std::string{},
                           useWorkerDns ? config.sharedSecret : std::string{},
                           options.manualProxy ? 0 : connectPort);
    strategy::Store strategies(Config::strategyPath());
    auto telemetryStore = std::make_shared<telemetry::Store>(Config::telemetryPath());
    std::shared_ptr<live_stats::Publisher> liveStats;
    if (!options.liveStatsName.empty()) {
        const std::wstring mappingName(options.liveStatsName.begin(),
                                       options.liveStatsName.end());
        liveStats = std::make_shared<live_stats::Publisher>(mappingName);
        if (!liveStats->available()) {
            spdlog::warn("Canli tray istatistik kanali acilamadi");
        }
    }
    packet_strategy::PolicyRegistry packetPolicies;
    process_filter::Filter processFilter(process_filter::Rules(
        config.processInclude, config.processExclude));
    strategies.load();
    if (!telemetryStore->start()) {
        spdlog::warn("Yerel telemetri baslatilamadi; ag motoru istatistiksiz devam ediyor");
    }
    const std::string networkId = network_identity::current();

    if (!options.forcedStrategy.empty()) {
        spdlog::info("Profil zorlandi: '{}' (otomatik secim devre disi)", options.forcedStrategy);
    }

    RelayContext context;
    context.workerUrl = useWorkerDns ? workerUrl : std::string{};
    context.sharedSecret = useWorkerDns ? config.sharedSecret : std::string{};
    context.networkId = networkId;
    // The network can change while the engine runs (Wi-Fi roaming, VPN); the
    // relay asks for the identity per decision instead of using the start value.
    context.networkIdProvider = [] { return network_identity::currentCached(); };
    context.resolver = useWorkerDns ? &resolver : nullptr;
    context.strategies = &strategies;
    context.packetPolicies = options.manualProxy ? nullptr : &packetPolicies;
    context.telemetry = telemetryStore;
    context.liveStats = liveStats;
    context.splitDelayMs = config.splitDelayMs;
    context.probeTimeoutMs = config.probeTimeoutMs;
    context.tunnelFallback = useWorkerDns && config.tunnelFallback;
    context.bypassConnectPort = options.manualProxy ? 0 : connectPort;
    context.forcedProfile = options.forcedStrategy;

    spdlog::info("SplitHello baslatiliyor");
    spdlog::info("DNS modu: {}", useWorkerDns ? "Worker" : "sistem (Worker yok)");
    if (useWorkerDns) spdlog::info("Worker: {}", workerUrl);
    spdlog::info("Ag profili: {}", networkId);
    spdlog::info("Relay portu: {} | split-delay: {} ms | ogrenilen alan adi: {}",
                 options.port, config.splitDelayMs, strategies.size());
    if (processFilter.enabled()) {
        spdlog::info("Surec filtresi: {} include, {} exclude kurali",
                     processFilter.rules().includeCount(),
                     processFilter.rules().excludeCount());
    }

    transparent::FlowRegistry flows;
    transparent::DatagramRegistry datagrams;
    SocksProxy proxy(context, options.port, options.manualProxy ? nullptr : &flows);
    TransparentDnsProxy dnsProxy(resolver, datagrams, dnsProxyPort);

    int runtimeExitCode = 0;
    if (options.manualProxy) {
        spdlog::warn("Manuel proxy modu: yalniz SOCKS5/HTTP CONNECT kullanan uygulamalar yakalanir");
        std::atomic<bool> exited{false};
        std::thread proxyThread([&]() {
            try { proxy.run(); } catch (...) {}
            exited = true;
        });
        while (!g_shutdownRequested && !exited) Sleep(50);
        proxy.stop();
        proxyThread.join();
    } else {
        std::atomic<bool> proxyExited{false};
        bool proxyResult = false;
        std::thread proxyThread([&]() {
            try { proxyResult = proxy.run(); } catch (...) { proxyResult = false; }
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
            spdlog::error("Transparent relay baslatilamadi (port {} kullanimda olabilir)",
                          options.port);
            return proxyResult ? 0 : engine_exit::kRelayPortInUse;
        }

        if (useWorkerDns && !dnsProxy.start()) {
            proxy.stop();
            if (proxyThread.joinable()) proxyThread.join();
            spdlog::error("Transparent DNS relay baslatilamadi (port {} kullanimda olabilir)",
                          dnsProxyPort);
            return engine_exit::kDnsRelayPortInUse;
        }

        WinDivertInterceptor interceptor(flows, datagrams, packetPolicies, options.port,
                                         dnsProxyPort, connectPort,
                                         options.quicMode, &processFilter, useWorkerDns);
        if (!interceptor.start()) {
            dnsProxy.stop();
            proxy.stop();
            if (proxyThread.joinable()) proxyThread.join();
            return engine_exit::kWinDivertOpenFailed;
        }

        signalReadyEvent(options.readyEventName);

        // One owner closes interception before any listeners. Observe both
        // packet and DNS reader health so either failure releases interception.
        while (!g_shutdownRequested && !proxyExited && interceptor.running() &&
               (!useWorkerDns || (dnsProxy.running() && !resolver.workerUnavailable()))) {
            Sleep(50);
        }

        const DWORD fatalWinDivertError = interceptor.fatalErrorCode();
        const bool relayExitedUnexpectedly = proxyExited && interceptor.running();
        if (!g_shutdownRequested && useWorkerDns && resolver.workerUnavailable()) {
            runtimeExitCode = recovery::kWorkerUnavailableExitCode;
            spdlog::error("Worker erisilemiyor; trafik yakalama kapatiliyor. "
                          "Tray otomatik yeniden baslatmayacak");
        } else if (!g_shutdownRequested && useWorkerDns && !dnsProxy.running()) {
            runtimeExitCode = kEngineFailOpenExitCode;
            spdlog::error("DNS alicisi durdu; trafik yakalama kapatiliyor");
        } else if (fatalWinDivertError != ERROR_SUCCESS) {
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
    }

    cleanup();
    spdlog::info("SplitHello durduruldu");
    return runtimeExitCode;
}
