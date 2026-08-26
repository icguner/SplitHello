#pragma once

#include <cstdint>
#include <string>

// Persistent configuration in %APPDATA%\splithello\config.json.
//
// Secrets (Cloudflare API token, Worker shared secret) are DPAPI-encrypted on
// disk - see Secure.hpp. Older configs that stored the token in clear text are
// migrated on first load, and the plaintext key is removed.
struct Config {
    std::string apiToken;                        // decrypted, in memory only
    std::string accountId;
    std::string workerName = "splithello-relay";
    std::string workerUrl;                       // wss://name.subdomain.workers.dev
    std::string sharedSecret;                    // bearer secret the Worker requires

    // Tuning
    unsigned splitDelayMs = 20;                  // pause between fragmented records
    unsigned probeTimeoutMs = 3000;              // how long to wait for a ServerHello
    bool tunnelFallback = false;                 // use the Worker /tunnel relay as a last resort

    // True when load() upgraded a plaintext token; main() re-saves in that case.
    bool migratedFromPlaintext = false;

    bool load();
    bool save() const;

    bool isValid() const { return !workerUrl.empty(); }
    bool canDeploy() const { return !apiToken.empty() && !accountId.empty(); }

    // Wipe the stored API token (the Worker keeps running without it; only
    // --setup / --redeploy need it again).
    bool forgetToken();

    static std::string configDir();
    static std::string configPath();
    static std::string strategyPath();
    static std::string logPath();
    static std::string proxyBackupPath();
};
