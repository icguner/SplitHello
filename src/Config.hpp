#pragma once

#include <string>

// Persistent configuration stored in %APPDATA%/splithello/config.json.
struct Config {
    std::string apiToken;
    std::string accountId;
    std::string workerName = "splithello-relay";
    std::string workerUrl;   // wss://name.subdomain.workers.dev

    // Load from disk. Returns true if config file exists and was parsed.
    bool load();

    // Save to disk. Creates directory if needed.
    bool save() const;

    // True if we have enough info to start the proxy.
    bool isValid() const { return !workerUrl.empty(); }

    // True if we have enough info to deploy/redeploy.
    bool canDeploy() const { return !apiToken.empty() && !accountId.empty(); }

    static std::string configDir();
    static std::string configPath();
};
