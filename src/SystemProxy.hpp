#pragma once

#include <string>
#include <cstdint>

// Manages Windows system proxy settings (Internet Options).
// Sets HTTP proxy to our local server so ALL apps use it automatically.
// Restores original settings on disable().
class SystemProxy {
public:
    static bool enable(uint16_t port);
    static bool disable();
    static bool isOurs(uint16_t port);

private:
    static bool saved_;
    static uint32_t savedEnabled_;
    static std::string savedProxy_;
    static std::string savedOverride_;

    static void notifySystem();
};
