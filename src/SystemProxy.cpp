#include "SystemProxy.hpp"

#include "FileUtil.hpp"
#include "Json.hpp"

#include <spdlog/spdlog.h>

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

namespace {

const char* kRegPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const char* kBypassList = "localhost;127.0.0.1;<local>";

// Register for https only. A bare "127.0.0.1:port" claims every scheme,
// including plain http - which we deliberately do not proxy, since a port 80
// request carries no ClientHello to fragment. Claiming it would break ordinary
// http:// browsing system-wide; leaving it unset lets those requests go direct.
std::string ourProxyValue(uint16_t port) {
    return "https=127.0.0.1:" + std::to_string(port);
}

// Accept the value written by older builds too, so an upgrade still recognises
// (and cleans up) a proxy those builds left behind.
bool pointsAtUs(const std::string& value, uint16_t port) {
    const std::string bare = "127.0.0.1:" + std::to_string(port);
    return value == ourProxyValue(port) || value == bare;
}

std::string regGetString(HKEY key, const char* name) {
    char buffer[1024] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, (BYTE*)buffer, &size) != ERROR_SUCCESS ||
        type != REG_SZ) {
        return {};
    }
    // The stored size may or may not include the terminator.
    std::string value(buffer, size);
    while (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

DWORD regGetDword(HKEY key, const char* name) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    if (RegQueryValueExA(key, name, nullptr, &type, (BYTE*)&value, &size) == ERROR_SUCCESS &&
        type == REG_DWORD) {
        return value;
    }
    return 0;
}

void regSetOrDelete(HKEY key, const char* name, const std::string& value) {
    if (value.empty()) {
        RegDeleteValueA(key, name);
    } else {
        RegSetValueExA(key, name, 0, REG_SZ, (const BYTE*)value.c_str(),
                       (DWORD)value.size() + 1);
    }
}

} // namespace

bool SystemProxy::saved_ = false;
SystemProxy::Snapshot SystemProxy::snapshot_;
std::string SystemProxy::backupPath_;

void SystemProxy::notifySystem() {
    InternetSetOptionA(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionA(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}

bool SystemProxy::readCurrent(Snapshot& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kRegPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return false;
    }
    out.enabled = regGetDword(key, "ProxyEnable");
    out.server = regGetString(key, "ProxyServer");
    out.bypass = regGetString(key, "ProxyOverride");
    RegCloseKey(key);
    return true;
}

bool SystemProxy::applySnapshot(const Snapshot& snapshot) {
    HKEY key = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, kRegPath, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        spdlog::error("Sistem proxy: Registry yazma icin acilamadi");
        return false;
    }

    const DWORD enabled = snapshot.enabled;
    RegSetValueExA(key, "ProxyEnable", 0, REG_DWORD, (const BYTE*)&enabled, sizeof(enabled));
    regSetOrDelete(key, "ProxyServer", snapshot.server);
    regSetOrDelete(key, "ProxyOverride", snapshot.bypass);

    RegCloseKey(key);
    notifySystem();
    return true;
}

bool SystemProxy::writeBackup(const std::string& path, const Snapshot& snapshot) {
    if (path.empty()) return false;

    std::string content;
    content += "{\n";
    content += "  \"version\": 1,\n";
    content += "  \"our_port\": " + std::to_string(snapshot.ourPort) + ",\n";
    content += "  \"proxy_enable\": " + std::to_string(snapshot.enabled) + ",\n";
    content += "  \"proxy_server\": \"" + json::escape(snapshot.server) + "\",\n";
    content += "  \"proxy_override\": \"" + json::escape(snapshot.bypass) + "\"\n";
    content += "}\n";

    return fileutil::writeAtomic(path, content);
}

bool SystemProxy::readBackup(const std::string& path, Snapshot& out) {
    std::string content;
    if (path.empty() || !fileutil::readAll(path, content) || content.empty()) return false;

    out.enabled = (uint32_t)json::getInt(content, "proxy_enable", 0);
    out.server = json::getString(content, "proxy_server");
    out.bypass = json::getString(content, "proxy_override");
    out.ourPort = (uint16_t)json::getInt(content, "our_port", 0);
    return true;
}

bool SystemProxy::enable(uint16_t port, const std::string& backupPath) {
    Snapshot current;
    if (!readCurrent(current)) {
        spdlog::error("Sistem proxy: mevcut ayarlar okunamadi");
        return false;
    }

    // Never snapshot our own settings on top of a real one (e.g. enable()
    // called twice, or a leftover we failed to clean up).
    const std::string ours = ourProxyValue(port);
    if (current.enabled == 1 && pointsAtUs(current.server, port)) {
        spdlog::warn("Sistem proxy zaten bizi gosteriyor, onceki yedek korunuyor");
    } else if (!saved_) {
        current.ourPort = port;
        snapshot_ = current;
        saved_ = true;
        backupPath_ = backupPath;

        // Write the backup before touching the registry: if we die between the
        // two, the worst case is a stale backup file, not a lost setting.
        if (!writeBackup(backupPath, snapshot_)) {
            spdlog::error("Sistem proxy yedegi diske yazilamadi ({}). "
                          "Cokme durumunda ayarlar elle geri alinmali.", backupPath);
        }
    }

    Snapshot ourSettings;
    ourSettings.enabled = 1;
    ourSettings.server = ours;
    ourSettings.bypass = kBypassList;

    if (!applySnapshot(ourSettings)) return false;

    spdlog::info("Sistem proxy ayarlandi: {}", ours);
    return true;
}

bool SystemProxy::disable() {
    if (!saved_) return true;

    const bool restored = applySnapshot(snapshot_);
    if (restored) {
        spdlog::info("Sistem proxy ayarlari geri alindi");
    }

    fileutil::remove(backupPath_);
    saved_ = false;
    backupPath_.clear();
    return restored;
}

bool SystemProxy::isOurs(uint16_t port) {
    Snapshot current;
    if (!readCurrent(current)) return false;
    return current.enabled == 1 && pointsAtUs(current.server, port);
}

bool SystemProxy::restoreLeftovers(const std::string& backupPath, bool force) {
    Snapshot backup;
    if (!readBackup(backupPath, backup)) return false;

    if (!force && !isOurs(backup.ourPort)) {
        spdlog::warn("Onceki calismadan bir proxy yedegi var ({}) ama sistem proxy artik "
                     "bizi gostermiyor. Uzerine yazilmadi; geri yuklemek icin: --restore-proxy",
                     backupPath);
        return false;
    }

    spdlog::warn("Onceki calismadan kalan sistem proxy geri yukleniyor "
                 "(enable={}, server='{}')", backup.enabled, backup.server);

    const bool restored = applySnapshot(backup);
    if (restored) fileutil::remove(backupPath);
    return restored;
}
