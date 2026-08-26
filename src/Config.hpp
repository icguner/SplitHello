#pragma once

#include <cstdint>
#include <string>
#include <vector>

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

    // Tuning
    unsigned splitDelayMs = 20;                  // pause between fragmented records
    unsigned probeTimeoutMs = 3000;              // how long to wait for a ServerHello
    bool tunnelFallback = false;                 // use the Worker /tunnel relay as a last resort
    std::vector<std::string> processInclude;     // wildcard executable allow-list
    std::vector<std::string> processExclude;     // wildcard executable deny-list

    // True when load() upgraded a plaintext token; main() re-saves in that case.
    bool migratedFromPlaintext = false;
    bool legacyApiTokenPresent = false;

    bool load();
    bool save() const;

    bool isValid() const { return !workerUrl.empty(); }

    // Compatibility command for configs created before Wrangler OAuth.
    bool forgetToken();

    static std::string configDir();
    static std::string configPath();
    static std::string strategyPath();
    static std::string telemetryPath();
    static std::string logPath();
    static std::string proxyBackupPath();
};
