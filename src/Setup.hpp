#pragma once

#include "Config.hpp"

// Interactive setup: starts Wrangler OAuth with OS-keyring storage, deploys
// the Worker, rotates its shared secret and saves config.
// Returns true on success.
bool runSetup(Config& config);

// Re-deploy using the existing keyring-backed Wrangler session. If the OAuth
// session expired, the browser login is started again automatically.
bool redeployWorker(Config& config);
