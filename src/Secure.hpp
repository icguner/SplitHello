#pragma once

#include <string>

// Secret handling.
//
// The Cloudflare API token and the Worker's shared secret are wrapped with
// Windows DPAPI (CryptProtectData) before they touch the disk, so the ciphertext
// is only decryptable by the same Windows user on the same machine. Copying
// config.json to another account or another PC yields nothing.
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
