#pragma once

#include <string>

// Secret handling.
//
// The Worker's shared secret is wrapped with Windows DPAPI (CryptProtectData)
// before it touches the disk, so the ciphertext is only decryptable by the same
// Windows user on the same machine. Cloudflare OAuth credentials are owned by
// Wrangler's OS keyring and never enter config.json.
namespace secure {

// DPAPI-encrypt and base64 the result. Returns empty on failure.
std::string protect(const std::string& plaintext);

// Reverse of protect(). Returns empty if the blob is corrupt or was written
// by a different Windows user.
std::string unprotect(const std::string& base64Blob);

// Cryptographically random lowercase hex string of `byteCount` bytes.
std::string randomHex(size_t byteCount);

// Overwrite a secret in memory before dropping it.
void wipe(std::string& secret);

} // namespace secure
