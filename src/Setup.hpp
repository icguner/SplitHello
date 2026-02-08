#pragma once

#include "Config.hpp"

// Interactive setup: opens browser for Cloudflare API token,
// verifies it, deploys the worker, saves config.
// Returns true on success.
bool runSetup(Config& config);

// Re-deploy the worker code using existing config.
// Useful after updating the worker JS.
bool redeployWorker(Config& config);
