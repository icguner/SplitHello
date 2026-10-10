#include "FileUtil.hpp"

#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fileutil {

std::wstring widen(const std::string& path) {
    if (path.empty()) return {};

    // Paths reach us either as UTF-8 or as the ANSI string std::filesystem
    // hands out. Valid multi-byte UTF-8 is practically never valid ANSI text
    // by accident, so try it first and fall back to the code page.
    for (const UINT codePage : {(UINT)CP_UTF8, (UINT)CP_ACP}) {
        const DWORD flags = codePage == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0;
        const int length = MultiByteToWideChar(codePage, flags, path.data(),
                                               (int)path.size(), nullptr, 0);
        if (length <= 0) continue;
        std::wstring wide((size_t)length, L'\0');
        MultiByteToWideChar(codePage, flags, path.data(), (int)path.size(),
                            wide.data(), length);
        return wide;
    }
    return {};
}

std::string toUtf8(const std::string& path) {
    const std::wstring wide = widen(path);
    if (wide.empty()) return {};

    const int length = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(),
                                           nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string utf8((size_t)length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(),
                        utf8.data(), length, nullptr, nullptr);
    return utf8;
}

bool writeAtomic(const std::string& path, const std::string& content) {
    const std::wstring target = widen(path);
    if (target.empty()) return false;
    const std::wstring tempPath = target + L".tmp";

    HANDLE file = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    const char* cursor = content.data();
    DWORD left = (DWORD)content.size();
    while (left > 0) {
        DWORD written = 0;
        if (!WriteFile(file, cursor, left, &written, nullptr) || written == 0) {
            CloseHandle(file);
            DeleteFileW(tempPath.c_str());
            return false;
        }
        cursor += written;
        left -= written;
    }

    // Without this the rename can land before the bytes do.
    FlushFileBuffers(file);
    CloseHandle(file);

    if (!MoveFileExW(tempPath.c_str(), target.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tempPath.c_str());
        return false;
    }
    return true;
}

bool readAll(const std::string& path, std::string& out) {
    const std::wstring source = widen(path);
    if (source.empty()) return false;

    HANDLE file = CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    out.clear();
    char buffer[4096];
    bool complete = false;
    while (true) {
        DWORD read = 0;
        if (!ReadFile(file, buffer, sizeof(buffer), &read, nullptr)) break;
        if (read == 0) { complete = true; break; } // EOF
        out.append(buffer, read);
    }
    CloseHandle(file);

    // A partial read must not look like a valid (truncated) file.
    if (!complete) out.clear();
    return complete;
}

bool exists(const std::string& path) {
    const std::wstring wide = widen(path);
    return !wide.empty() && GetFileAttributesW(wide.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool remove(const std::string& path) {
    const std::wstring wide = widen(path);
    if (wide.empty()) return false;
    return DeleteFileW(wide.c_str()) != 0 || GetLastError() == ERROR_FILE_NOT_FOUND;
}

} // namespace fileutil
