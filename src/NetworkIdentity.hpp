#pragma once

#include <string>

namespace network_identity {

// Returns an opaque, local-only identifier for the set of Windows network
// profiles currently connected. Learned strategies are scoped by this value
// so a rule learned on home broadband is not blindly reused on a hotspot/VPN.
std::string current();

} // namespace network_identity
