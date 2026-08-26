#include "Secure.hpp"

#include <spdlog/spdlog.h>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dpapi.h>
#include <wincrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace secure {
namespace {

// Application-specific entropy: a blob protected by another program on this
// account cannot be dropped into our config and decrypted by us.
const char kEntropy[] = "SplitHello/config/v1";

DATA_BLOB entropyBlob() {
    DATA_BLOB blob{};
    blob.pbData = (BYTE*)kEntropy;
    blob.cbData = (DWORD)(sizeof(kEntropy) - 1);
    return blob;
}

std::string base64Encode(const BYTE* data, DWORD length) {
    DWORD chars = 0;
    if (!CryptBinaryToStringA(data, length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              nullptr, &chars)) {
        return {};
    }
    std::string out(chars, '\0');
    if (!CryptBinaryToStringA(data, length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              out.data(), &chars)) {
        return {};
    }
    out.resize(strnlen(out.c_str(), out.size()));
    return out;
}

bool base64Decode(const std::string& text, std::vector<BYTE>& out) {
    DWORD bytes = 0;
    if (!CryptStringToBinaryA(text.c_str(), (DWORD)text.size(), CRYPT_STRING_BASE64,
                              nullptr, &bytes, nullptr, nullptr)) {
        return false;
    }
    out.resize(bytes);
    return CryptStringToBinaryA(text.c_str(), (DWORD)text.size(), CRYPT_STRING_BASE64,
                                out.data(), &bytes, nullptr, nullptr) != 0;
}

} // namespace

std::string protect(const std::string& plaintext) {
    if (plaintext.empty()) return {};

    DATA_BLOB input{};
    input.pbData = (BYTE*)plaintext.data();
    input.cbData = (DWORD)plaintext.size();

    DATA_BLOB entropy = entropyBlob();
    DATA_BLOB output{};

    if (!CryptProtectData(&input, L"SplitHello", &entropy, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        spdlog::error("DPAPI sifreleme hatasi: {}", GetLastError());
        return {};
    }

    std::string encoded = base64Encode(output.pbData, output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return encoded;
}

std::string unprotect(const std::string& base64Blob) {
    if (base64Blob.empty()) return {};

    std::vector<BYTE> raw;
    if (!base64Decode(base64Blob, raw) || raw.empty()) {
        spdlog::warn("DPAPI: base64 cozulemedi");
        return {};
    }

    DATA_BLOB input{};
    input.pbData = raw.data();
    input.cbData = (DWORD)raw.size();

    DATA_BLOB entropy = entropyBlob();
    DATA_BLOB output{};

    if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        spdlog::warn("DPAPI cozme hatasi ({}). Config baska bir Windows kullanicisina ait olabilir.",
                     GetLastError());
        return {};
    }

    std::string plaintext((const char*)output.pbData, output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return plaintext;
}

std::string randomHex(size_t byteCount) {
    std::vector<BYTE> bytes(byteCount);
    const NTSTATUS status = BCryptGenRandom(nullptr, bytes.data(), (ULONG)bytes.size(),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        spdlog::error("BCryptGenRandom hatasi: 0x{:x}", (unsigned)status);
        return {};
    }

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(byteCount * 2);
    for (BYTE b : bytes) {
        out += hex[b >> 4];
        out += hex[b & 0x0F];
    }
    return out;
}

void wipe(std::string& secret) {
    if (!secret.empty()) SecureZeroMemory(secret.data(), secret.size());
    secret.clear();
}

} // namespace secure
