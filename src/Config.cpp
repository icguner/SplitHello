#include "Config.hpp"

#include "FileUtil.hpp"
#include "Json.hpp"
#include "Secure.hpp"

#include <spdlog/spdlog.h>

#include <filesystem>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;

namespace {

// Reads either the DPAPI-protected key or, for configs written by older
// builds, its plaintext counterpart. `migrated` is set when the fallback hits.
std::string readSecret(const std::string& json,
                       const std::string& protectedKey,
                       const std::string& legacyKey,
                       bool& migrated) {
    const std::string blob = json::getString(json, protectedKey);
    if (!blob.empty()) {
        std::string plaintext = secure::unprotect(blob);
        if (plaintext.empty()) {
            spdlog::warn("Config: '{}' cozulemedi, alan bos birakiliyor", protectedKey);
        }
        return plaintext;
    }

    const std::string legacy = json::getString(json, legacyKey);
    if (!legacy.empty()) migrated = true;
    return legacy;
}

unsigned readUnsigned(const std::string& json, const std::string& key,
                      unsigned fallback, unsigned low, unsigned high) {
    const long long value = json::getInt(json, key, (long long)fallback);
    if (value < (long long)low || value > (long long)high) return fallback;
    return (unsigned)value;
}

std::vector<std::string> readProcessRules(const std::string& content,
                                          const std::string& key) {
    constexpr size_t kMaximumRules = 128;
    constexpr size_t kMaximumRuleLength = 1024;
    std::vector<std::string> result;
    for (std::string rule : json::getStringArray(content, key)) {
        if (rule.empty() || rule.size() > kMaximumRuleLength) continue;
        result.push_back(std::move(rule));
        if (result.size() == kMaximumRules) break;
    }
    return result;
}

std::string stringArrayJson(const std::vector<std::string>& values) {
    std::string result = "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) result += ", ";
        result += "\"" + json::escape(values[i]) + "\"";
    }
    result += "]";
    return result;
}

} // namespace

std::string Config::configDir() {
    char appdata[MAX_PATH] = {};
    const DWORD length = GetEnvironmentVariableA("APPDATA", appdata, (DWORD)sizeof(appdata));
    if (length == 0 || length >= sizeof(appdata)) return {};
    return (fs::path(appdata) / "splithello").string();
}

std::string Config::configPath() {
    const std::string dir = configDir();
    return dir.empty() ? std::string{} : (fs::path(dir) / "config.json").string();
}

std::string Config::strategyPath() {
    const std::string dir = configDir();
    return dir.empty() ? std::string{} : (fs::path(dir) / "strategies.json").string();
}

std::string Config::telemetryPath() {
    const std::string dir = configDir();
    return dir.empty() ? std::string{} : (fs::path(dir) / "telemetry.db").string();
}

std::string Config::logPath() {
    const std::string dir = configDir();
    return dir.empty() ? std::string{} : (fs::path(dir) / "splithello.log").string();
}

std::string Config::proxyBackupPath() {
    const std::string dir = configDir();
    return dir.empty() ? std::string{} : (fs::path(dir) / "proxy-backup.json").string();
}

bool Config::load() {
    const std::string path = configPath();
    if (path.empty()) return false;

    std::string json;
    if (!fileutil::readAll(path, json)) return false;

    legacyApiTokenPresent = !json::getString(json, "api_token_dpapi").empty() ||
                            !json::getString(json, "api_token").empty();
    apiToken     = readSecret(json, "api_token_dpapi", "api_token", migratedFromPlaintext);
    sharedSecret = readSecret(json, "shared_secret_dpapi", "shared_secret", migratedFromPlaintext);
    accountId    = json::getString(json, "account_id");
    workerName   = json::getString(json, "worker_name");
    workerUrl    = json::getString(json, "worker_url");

    if (workerName.empty()) workerName = "splithello-relay";

    splitDelayMs   = readUnsigned(json, "split_delay_ms", splitDelayMs, 0, 2000);
    probeTimeoutMs = readUnsigned(json, "probe_timeout_ms", probeTimeoutMs, 250, 30000);
    tunnelFallback = json::getBool(json, "tunnel_fallback");
    processInclude = readProcessRules(json, "process_include");
    processExclude = readProcessRules(json, "process_exclude");

    if (migratedFromPlaintext) {
        spdlog::warn("Config: duz metin sirlar bulundu, DPAPI ile yeniden sifreleniyor");
    }
    spdlog::debug("Config yuklendi: {}", path);
    return true;
}

bool Config::save() const {
    const std::string dir = configDir();
    if (dir.empty()) {
        spdlog::error("APPDATA yolu belirlenemedi");
        return false;
    }

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        spdlog::error("Config dizini olusturulamadi: {}", ec.message());
        return false;
    }

    // If encryption fails we drop the secret rather than fall back to writing
    // it in the clear. Wrangler owns OAuth credentials; config never stores a
    // Cloudflare access token anymore.
    std::string protectedSecret;
    if (!sharedSecret.empty()) {
        protectedSecret = secure::protect(sharedSecret);
        if (protectedSecret.empty()) {
            spdlog::error("Worker gizli anahtari sifrelenemedi, kaydedilmiyor.");
        }
    }

    std::string content;
    content += "{\n";
    content += "  \"shared_secret_dpapi\": \"" + json::escape(protectedSecret) + "\",\n";
    content += "  \"account_id\": \"" + json::escape(accountId) + "\",\n";
    content += "  \"worker_name\": \"" + json::escape(workerName) + "\",\n";
    content += "  \"worker_url\": \"" + json::escape(workerUrl) + "\",\n";
    content += "  \"split_delay_ms\": " + std::to_string(splitDelayMs) + ",\n";
    content += "  \"probe_timeout_ms\": " + std::to_string(probeTimeoutMs) + ",\n";
    content += "  \"tunnel_fallback\": " + std::string(tunnelFallback ? "true" : "false") + ",\n";
    content += "  \"process_include\": " + stringArrayJson(processInclude) + ",\n";
    content += "  \"process_exclude\": " + stringArrayJson(processExclude) + "\n";
    content += "}\n";

    const std::string path = configPath();
    if (!fileutil::writeAtomic(path, content)) {
        spdlog::error("Config yazilamadi: {}", path);
        return false;
    }

    spdlog::info("Config kaydedildi: {}", path);
    return true;
}

bool Config::forgetToken() {
    // accountId stays: it is not a secret and selects the same account when
    // Wrangler OAuth exposes multiple memberships.
    secure::wipe(apiToken);
    return save();
}
