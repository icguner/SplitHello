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
// When decryption fails the original blob is handed back through `keptBlob` so
// save() can write it back unchanged instead of replacing it with nothing.
std::string readSecret(const std::string& json,
                       const std::string& protectedKey,
                       const std::string& legacyKey,
                       bool& migrated,
                       std::string* keptBlob = nullptr) {
    const std::string blob = json::getString(json, protectedKey);
    if (!blob.empty()) {
        std::string plaintext = secure::unprotect(blob);
        if (plaintext.empty()) {
            spdlog::warn("Config: '{}' cozulemedi; alan bos ama diskteki sifreli deger "
                         "korunuyor (baska Windows kullanicisi veya bozuk dosya olabilir)",
                         protectedKey);
            if (keptBlob) *keptBlob = blob;
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

std::string toUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string result((size_t)length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), result.data(), length,
                        nullptr, nullptr);
    return result;
}

std::string pathUtf8(const fs::path& path) {
    return path.empty() ? std::string{} : toUtf8(path.wstring());
}

std::string inConfigDir(const wchar_t* name) {
    const fs::path dir = Config::configDirPath();
    return dir.empty() ? std::string{} : pathUtf8(dir / name);
}

} // namespace

fs::path Config::configDirPath() {
    // Wide API: a profile path with non-ANSI characters must not be mangled.
    std::wstring appdata(MAX_PATH, L'\0');
    DWORD length = GetEnvironmentVariableW(L"APPDATA", appdata.data(), (DWORD)appdata.size());
    if (length >= appdata.size()) {
        appdata.resize(length);
        length = GetEnvironmentVariableW(L"APPDATA", appdata.data(), (DWORD)appdata.size());
    }
    if (length == 0 || length >= appdata.size()) return {};
    appdata.resize(length);
    return fs::path(appdata) / L"splithello";
}

std::string Config::configDir() {
    return pathUtf8(configDirPath());
}

std::string Config::configPath() {
    return inConfigDir(L"config.json");
}

std::string Config::strategyPath() {
    return inConfigDir(L"strategies.json");
}

std::string Config::telemetryPath() {
    return inConfigDir(L"telemetry.db");
}

std::string Config::logPath() {
    return inConfigDir(L"splithello.log");
}

std::string Config::proxyBackupPath() {
    return inConfigDir(L"proxy-backup.json");
}

bool Config::load() {
    loadFailed = false;
    const std::string path = configPath();
    if (path.empty()) return false;

    std::string json;
    if (!fileutil::readAll(path, json)) {
        // A missing file is a fresh install; an existing unreadable one must not
        // be overwritten by defaults.
        loadFailed = fileutil::exists(path);
        if (loadFailed) spdlog::error("Config okunamadi (dosya var): {}", path);
        return false;
    }

    legacyApiTokenPresent = !json::getString(json, "api_token_dpapi").empty() ||
                            !json::getString(json, "api_token").empty();
    apiToken     = readSecret(json, "api_token_dpapi", "api_token", migratedFromPlaintext);
    sharedSecretBlob.clear();
    sharedSecret = readSecret(json, "shared_secret_dpapi", "shared_secret",
                              migratedFromPlaintext, &sharedSecretBlob);
    accountId    = json::getString(json, "account_id");
    workerName   = json::getString(json, "worker_name");
    workerUrl    = json::getString(json, "worker_url");
    dnsMode      = json::getString(json, "dns_mode") == "system"
        ? DnsMode::System : DnsMode::Worker;

    if (workerName.empty()) workerName = "splithello-relay";

    splitDelayMs   = readUnsigned(json, "split_delay_ms", splitDelayMs, 0, 2000);
    probeTimeoutMs = readUnsigned(json, "probe_timeout_ms", probeTimeoutMs, 250, 30000);
    tunnelFallback = json::getBool(json, "tunnel_fallback");
    processInclude = readProcessRules(json, "process_include");
    processExclude = readProcessRules(json, "process_exclude");

    // An include list that normalizes to nothing would read as "no include
    // rules" = every process. Flag it so the engine fails closed instead.
    processIncludeInvalid = processInclude.empty() &&
        !json::getStringArray(json, "process_include").empty();
    if (processIncludeInvalid) {
        spdlog::warn("Config: process_include dolu ama hicbir girdi gecerli degil; "
                     "kapsam genisletilmeyecek, ag motoru baslatilmayacak");
    }

    if (migratedFromPlaintext) {
        spdlog::warn("Config: duz metin sirlar bulundu, DPAPI ile yeniden sifreleniyor");
    }
    spdlog::debug("Config yuklendi: {}", path);
    return true;
}

bool Config::save() const {
    const fs::path dir = configDirPath();
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
    // Cloudflare access token anymore. An undecryptable blob from load() is
    // written back untouched until a new secret is set explicitly.
    std::string protectedSecret = sharedSecret.empty() ? sharedSecretBlob : std::string{};
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
    content += "  \"dns_mode\": \"" +
        std::string(dnsMode == DnsMode::System ? "system" : "worker") + "\",\n";
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
