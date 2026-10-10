#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

enum class DnsMode { Worker, System };

// Persistent configuration in %APPDATA%\splithello\config.json.
//
// The Worker shared secret is DPAPI-encrypted on disk - see Secure.hpp. API
// token fields from older releases are migration-only and removed on load;
// current Cloudflare authentication belongs to Wrangler's OS keyring.
struct Config {
    std::string apiToken;                        // legacy migration buffer only
    std::string accountId;
    std::string workerName = "splithello-relay";
    std::string workerUrl;                       // wss://name.subdomain.workers.dev
    std::string sharedSecret;                    // bearer secret the Worker requires
    DnsMode dnsMode = DnsMode::Worker;            // system leaves DNS/53 untouched

    // Tuning
    unsigned splitDelayMs = 20;                  // pause between fragmented records
    unsigned probeTimeoutMs = 3000;              // how long to wait for a ServerHello
    bool tunnelFallback = false;                 // use the Worker /tunnel relay as a last resort
    std::vector<std::string> processInclude;     // wildcard executable allow-list
    std::vector<std::string> processExclude;     // wildcard executable deny-list

    // True when load() upgraded a plaintext token; main() re-saves in that case.
    bool migratedFromPlaintext = false;
    bool legacyApiTokenPresent = false;

    // The stored DPAPI blob could not be decrypted (other Windows user, damaged
    // file). It is kept verbatim and written back by save() unless sharedSecret
    // is set explicitly, so a transient failure never destroys the secret.
    std::string sharedSecretBlob;

    // A config file exists but could not be read. Callers must not save() such a
    // config: it holds defaults and would overwrite the real file.
    bool loadFailed = false;

    // process_include was non-empty on disk but every entry was unusable. The
    // engine refuses to start (fail-open for traffic) rather than silently widen
    // the scope to "all processes".
    bool processIncludeInvalid = false;

    // False when there is no readable file; check loadFailed to tell a fresh
    // install (false) from a file that exists but could not be read (true).
    bool load();
    bool save() const;

    bool isValid() const { return dnsMode == DnsMode::System || !workerUrl.empty(); }

    // Compatibility command for configs created before Wrangler OAuth.
    bool forgetToken();

    // Paths are UTF-8 (the manifest sets the process code page to UTF-8, so the
    // narrow Win32/SQLite/std::filesystem calls agree); the *Path variant keeps
    // the original wide characters for callers that can use them directly.
    static std::filesystem::path configDirPath();
    static std::string configDir();
    static std::string configPath();
    static std::string strategyPath();
    static std::string telemetryPath();
    static std::string logPath();
    static std::string proxyBackupPath();
};
