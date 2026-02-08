#include "SocksProxy.hpp"
#include "Config.hpp"
#include "Setup.hpp"
#include "SystemProxy.hpp"
#include <spdlog/spdlog.h>

#include <string>
#include <iostream>
#include <csignal>
#include <filesystem>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

static SocksProxy* g_proxy = nullptr;
static bool g_systemProxySet = false;

static void cleanup(int = 0) {
    if (g_systemProxySet) {
        SystemProxy::disable();
        g_systemProxySet = false;
    }
    if (g_proxy) g_proxy->stop();
}

static BOOL WINAPI consoleHandler(DWORD event) {
    if (event == CTRL_C_EVENT || event == CTRL_CLOSE_EVENT ||
        event == CTRL_LOGOFF_EVENT || event == CTRL_SHUTDOWN_EVENT) {
        cleanup();
        return TRUE;
    }
    return FALSE;
}

static void printUsage(const char* exe) {
    std::cout << "SplitHello - TLS ClientHello fragmentation for censorship bypass\n\n"
              << "Usage: " << exe << " [options]\n\n"
              << "Options:\n"
              << "  --setup              Cloudflare hesabini bagla ve worker deploy et\n"
              << "  --redeploy           Worker kodunu guncelle (mevcut config ile)\n"
              << "  --worker <url>       Worker URL (config yerine manuel belirt)\n"
              << "  --port <port>        Lokal proxy port (varsayilan: 1080)\n"
              << "  --no-system-proxy    Sistem proxy ayarlama (sadece dinle)\n"
              << "  --verbose            Debug loglama\n"
              << "  --help               Bu yardimi goster\n\n"
              << "Ilk kullanim:\n"
              << "  " << exe << " --setup\n\n"
              << "Sonraki kullanimlar:\n"
              << "  " << exe << "\n"
              << "    Proxy baslar, sistem proxy ayarlanir, TUM uygulamalar otomatik kullanir.\n"
              << "    Kapatinca (Ctrl+C) sistem proxy geri alinir.\n";
}

int main(int argc, char* argv[]) {
    spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");

    std::string workerUrl;
    uint16_t port = 1080;
    bool setupFlag = false;
    bool redeployFlag = false;
    bool noSystemProxy = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--worker" && i + 1 < argc) {
            workerUrl = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--no-system-proxy") {
            noSystemProxy = true;
        } else if (arg == "--verbose") {
            spdlog::set_level(spdlog::level::debug);
        } else if (arg == "--setup") {
            setupFlag = true;
        } else if (arg == "--redeploy") {
            redeployFlag = true;
        } else if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Bilinmeyen parametre: " << arg << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        spdlog::error("WSAStartup hatasi");
        return 1;
    }

    // Load existing config
    Config config;
    config.load();

    // Handle --redeploy
    if (redeployFlag) {
        if (!config.canDeploy()) {
            std::cerr << "Once --setup calistirin.\n";
            WSACleanup();
            return 1;
        }
        bool ok = redeployWorker(config);
        WSACleanup();
        return ok ? 0 : 1;
    }

    // Handle --setup
    if (setupFlag) {
        if (!runSetup(config)) {
            WSACleanup();
            return 1;
        }
        workerUrl = config.workerUrl;
    }

    // If no --worker, use config
    if (workerUrl.empty()) {
        workerUrl = config.workerUrl;
    }

    // If still empty, auto-trigger setup
    if (workerUrl.empty()) {
        std::cout << "SplitHello - TLS ClientHello fragmentation for censorship bypass\n\n"
                  << "Yapilandirma bulunamadi. Setup baslatiliyor...\n";

        if (!runSetup(config)) {
            WSACleanup();
            return 1;
        }
        workerUrl = config.workerUrl;
    }

    // Crash recovery: if system proxy is stuck from a previous crash
    if (SystemProxy::isOurs(port)) {
        spdlog::warn("Onceki calismadan kalan sistem proxy temizleniyor...");
        SystemProxy::disable();
    }

    // Start proxy
    spdlog::info("SplitHello baslatiliyor");
    spdlog::info("Worker: {}", workerUrl);
    spdlog::info("Port: 127.0.0.1:{}", port);

    SocksProxy proxy(workerUrl, port);
    g_proxy = &proxy;

    // Set up cleanup handlers
    std::signal(SIGINT, cleanup);
    std::signal(SIGTERM, cleanup);
    SetConsoleCtrlHandler(consoleHandler, TRUE);

    // Set system proxy AFTER the proxy socket is ready
    if (!noSystemProxy) {
        // Start proxy in a background thread so we can set system proxy after bind
        std::thread proxyThread([&proxy]() {
            proxy.run();
        });

        // Give the proxy a moment to bind
        Sleep(200);

        if (SystemProxy::enable(port)) {
            g_systemProxySet = true;
            spdlog::info("Sistem proxy ayarlandi - tum uygulamalar otomatik kullanacak");
        } else {
            spdlog::warn("Sistem proxy ayarlanamadi. Uygulamalari manuel yapilandirin.");
        }

        proxyThread.join();
    } else {
        spdlog::info("Sistem proxy devre disi (--no-system-proxy)");
        proxy.run();
    }

    cleanup();
    spdlog::info("SplitHello durduruldu");
    WSACleanup();
    return 0;
}
