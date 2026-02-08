#include "Config.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <filesystem>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;

// Minimal JSON helpers (only for our simple flat config)
namespace {
    std::string jsonExtractString(const std::string& json, const std::string& key) {
        std::string needle = "\"" + key + "\"";
        auto pos = json.find(needle);
        if (pos == std::string::npos) return {};

        pos += needle.size();
        // Skip whitespace and colon
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r'))
            pos++;

        if (pos >= json.size() || json[pos] != '"') return {};
        pos++; // skip opening quote

        std::string result;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                pos++; // skip backslash, take next char
            }
            result += json[pos++];
        }
        return result;
    }

    std::string jsonEscape(const std::string& s) {
        std::string out;
        for (char c : s) {
            if (c == '"') out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else out += c;
        }
        return out;
    }
}

std::string Config::configDir() {
    const char* appdata = std::getenv("APPDATA");
    if (!appdata) return {};
    return (fs::path(appdata) / "splithello").string();
}

std::string Config::configPath() {
    std::string dir = configDir();
    if (dir.empty()) return {};
    return (fs::path(dir) / "config.json").string();
}

bool Config::load() {
    std::string path = configPath();
    if (path.empty()) return false;

    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::ostringstream ss;
    ss << f.rdbuf();
    std::string json = ss.str();

    apiToken   = jsonExtractString(json, "api_token");
    accountId  = jsonExtractString(json, "account_id");
    workerName = jsonExtractString(json, "worker_name");
    workerUrl  = jsonExtractString(json, "worker_url");

    if (workerName.empty()) workerName = "workerdpi-relay";

    spdlog::debug("Config loaded from {}", path);
    return true;
}

bool Config::save() const {
    std::string dir = configDir();
    if (dir.empty()) {
        spdlog::error("Cannot determine APPDATA path");
        return false;
    }

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        spdlog::error("Failed to create config directory: {}", ec.message());
        return false;
    }

    std::string path = configPath();
    std::ofstream f(path);
    if (!f.is_open()) {
        spdlog::error("Failed to write config: {}", path);
        return false;
    }

    f << "{\n"
      << "  \"api_token\": \"" << jsonEscape(apiToken) << "\",\n"
      << "  \"account_id\": \"" << jsonEscape(accountId) << "\",\n"
      << "  \"worker_name\": \"" << jsonEscape(workerName) << "\",\n"
      << "  \"worker_url\": \"" << jsonEscape(workerUrl) << "\"\n"
      << "}\n";

    spdlog::info("Config saved to {}", path);
    return true;
}
