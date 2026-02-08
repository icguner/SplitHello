#include "SystemProxy.hpp"
#include <spdlog/spdlog.h>
#include <format>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

static const char* REG_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

bool SystemProxy::saved_ = false;
uint32_t SystemProxy::savedEnabled_ = 0;
std::string SystemProxy::savedProxy_;
std::string SystemProxy::savedOverride_;

static std::string regGetString(HKEY key, const char* name) {
    char buf[512] = {};
    DWORD size = sizeof(buf) - 1;
    DWORD type = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, (BYTE*)buf, &size) == ERROR_SUCCESS
        && type == REG_SZ) {
        return std::string(buf, size > 0 ? size - 1 : 0); // exclude null terminator
    }
    return {};
}

static DWORD regGetDword(HKEY key, const char* name) {
    DWORD val = 0, size = sizeof(val), type = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, (BYTE*)&val, &size) == ERROR_SUCCESS
        && type == REG_DWORD) {
        return val;
    }
    return 0;
}

void SystemProxy::notifySystem() {
    InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}

bool SystemProxy::enable(uint16_t port) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_PATH, 0, KEY_ALL_ACCESS, &key) != ERROR_SUCCESS) {
        spdlog::error("Sistem proxy: Registry acilamadi");
        return false;
    }

    // Save current settings (only once)
    if (!saved_) {
        savedEnabled_ = regGetDword(key, "ProxyEnable");
        savedProxy_   = regGetString(key, "ProxyServer");
        savedOverride_ = regGetString(key, "ProxyOverride");
        saved_ = true;
    }

    // Set our proxy
    std::string proxyServer = std::format("127.0.0.1:{}", port);
    std::string proxyOverride = "localhost;127.0.0.1;<local>";

    DWORD enabled = 1;
    RegSetValueExA(key, "ProxyEnable", 0, REG_DWORD, (BYTE*)&enabled, sizeof(enabled));
    RegSetValueExA(key, "ProxyServer", 0, REG_SZ, (BYTE*)proxyServer.c_str(), (DWORD)proxyServer.size() + 1);
    RegSetValueExA(key, "ProxyOverride", 0, REG_SZ, (BYTE*)proxyOverride.c_str(), (DWORD)proxyOverride.size() + 1);

    RegCloseKey(key);
    notifySystem();

    spdlog::info("Sistem proxy ayarlandi: {}", proxyServer);
    return true;
}

bool SystemProxy::disable() {
    if (!saved_) return true; // nothing to restore

    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_PATH, 0, KEY_ALL_ACCESS, &key) != ERROR_SUCCESS) {
        spdlog::error("Sistem proxy: Registry acilamadi (geri alma)");
        return false;
    }

    // Restore original settings
    RegSetValueExA(key, "ProxyEnable", 0, REG_DWORD, (BYTE*)&savedEnabled_, sizeof(savedEnabled_));

    if (!savedProxy_.empty()) {
        RegSetValueExA(key, "ProxyServer", 0, REG_SZ, (BYTE*)savedProxy_.c_str(), (DWORD)savedProxy_.size() + 1);
    } else {
        RegDeleteValueA(key, "ProxyServer");
    }

    if (!savedOverride_.empty()) {
        RegSetValueExA(key, "ProxyOverride", 0, REG_SZ, (BYTE*)savedOverride_.c_str(), (DWORD)savedOverride_.size() + 1);
    } else {
        RegDeleteValueA(key, "ProxyOverride");
    }

    RegCloseKey(key);
    notifySystem();

    saved_ = false;
    spdlog::info("Sistem proxy ayarlari geri alindi");
    return true;
}

bool SystemProxy::isOurs(uint16_t port) {
    HKEY key;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REG_PATH, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;

    DWORD enabled = regGetDword(key, "ProxyEnable");
    std::string proxy = regGetString(key, "ProxyServer");
    RegCloseKey(key);

    std::string expected = std::format("127.0.0.1:{}", port);
    return enabled == 1 && proxy == expected;
}
