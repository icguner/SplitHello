#include "Test.hpp"

#include "Config.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fs = std::filesystem;

namespace {

// Points %APPDATA% at a scratch directory for the lifetime of the object so the
// tests never touch the real config.
class ScratchAppData {
public:
    explicit ScratchAppData(const wchar_t* name) {
        wchar_t previous[4096] = {};
        const DWORD length = GetEnvironmentVariableW(L"APPDATA", previous, 4096);
        if (length > 0 && length < 4096) {
            hadPrevious_ = true;
            previous_ = previous;
        }
        root_ = fs::temp_directory_path() /
                (std::wstring(name) + L"-" + std::to_wstring(GetCurrentProcessId()));
        fs::remove_all(root_);
        fs::create_directories(root_ / L"splithello");
        SetEnvironmentVariableW(L"APPDATA", root_.c_str());
    }

    ~ScratchAppData() {
        SetEnvironmentVariableW(L"APPDATA", hadPrevious_ ? previous_.c_str() : nullptr);
        std::error_code ignored;
        fs::remove_all(root_, ignored);
    }

    ScratchAppData(const ScratchAppData&) = delete;
    ScratchAppData& operator=(const ScratchAppData&) = delete;

    void writeConfig(const std::string& json) const {
        std::ofstream out(root_ / L"splithello" / L"config.json", std::ios::binary);
        out << json;
    }

    std::string readConfig() const {
        std::ifstream in(root_ / L"splithello" / L"config.json", std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), {});
    }

private:
    fs::path root_;
    std::wstring previous_;
    bool hadPrevious_ = false;
};

} // namespace

TEST(ConfigKeepsUndecryptableSecretBlobAcrossSave) {
    ScratchAppData appData(L"splithello-config-blob");
    // Valid base64 that DPAPI cannot decrypt, like a blob from another user.
    const std::string foreignBlob = "bm90LWEtZHBhcGktYmxvYi1ub3QtYS1kcGFwaS1ibG9i";
    appData.writeConfig("{\"shared_secret_dpapi\": \"" + foreignBlob +
                        "\", \"dns_mode\": \"worker\", \"worker_url\": \"wss://x\"}");

    Config config;
    CHECK(config.load());
    CHECK(config.sharedSecret.empty());
    CHECK(config.sharedSecretBlob == foreignBlob);

    // An unrelated change (e.g. the dashboard saving rules) keeps the blob.
    config.splitDelayMs = 40;
    CHECK(config.save());
    CHECK(appData.readConfig().find(foreignBlob) != std::string::npos);

    // Setting a secret explicitly replaces it.
    config.sharedSecret = "fresh-secret";
    CHECK(config.save());
    CHECK(appData.readConfig().find(foreignBlob) == std::string::npos);

    Config reloaded;
    CHECK(reloaded.load());
    CHECK(reloaded.sharedSecret == "fresh-secret");
    CHECK(reloaded.sharedSecretBlob.empty());
}

TEST(ConfigFlagsProcessIncludeThatNormalizesToNothing) {
    ScratchAppData appData(L"splithello-config-include");

    appData.writeConfig("{\"process_include\": [\"\", \"\"], \"process_exclude\": [\"a.exe\"]}");
    Config invalid;
    CHECK(invalid.load());
    CHECK(invalid.processInclude.empty());
    CHECK(invalid.processIncludeInvalid);
    CHECK_EQ(invalid.processExclude.size(), size_t{1});

    appData.writeConfig("{\"process_include\": []}");
    Config absent;
    CHECK(absent.load());
    CHECK(!absent.processIncludeInvalid);

    appData.writeConfig("{\"process_include\": [\"chrome.exe\"]}");
    Config valid;
    CHECK(valid.load());
    CHECK(!valid.processIncludeInvalid);
    CHECK_EQ(valid.processInclude.size(), size_t{1});
}

TEST(ConfigMissingFileIsNotALoadFailure) {
    ScratchAppData appData(L"splithello-config-missing");
    Config config;
    CHECK(!config.load());
    CHECK(!config.loadFailed);
}

TEST(ConfigPathsKeepNonAnsiCharacters) {
    ScratchAppData restoreOnExit(L"splithello-config-paths");
    // U+015E U+011F as UTF-16 escapes and their UTF-8 bytes, so the test does
    // not depend on the source file's encoding.
    SetEnvironmentVariableW(L"APPDATA", L"C:\\Users\\\u015e\u011f\\Roaming");

    CHECK(Config::configDirPath().wstring() ==
          L"C:\\Users\\\u015e\u011f\\Roaming\\splithello");
    CHECK(Config::configDir() ==
          "C:\\Users\\\xC5\x9E\xC4\x9F\\Roaming\\splithello");
}
