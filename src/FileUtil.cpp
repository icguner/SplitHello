#include "FileUtil.hpp"

#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace fileutil {

bool writeAtomic(const std::string& path, const std::string& content) {
    const std::string tempPath = path + ".tmp";

    HANDLE file = CreateFileA(tempPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    const char* cursor = content.data();
    DWORD left = (DWORD)content.size();
    while (left > 0) {
        DWORD written = 0;
        if (!WriteFile(file, cursor, left, &written, nullptr) || written == 0) {
            CloseHandle(file);
            DeleteFileA(tempPath.c_str());
            return false;
        }
        cursor += written;
        left -= written;
    }

    // Without this the rename can land before the bytes do.
    FlushFileBuffers(file);
    CloseHandle(file);

    if (!MoveFileExA(tempPath.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tempPath.c_str());
        return false;
    }
    return true;
}

bool readAll(const std::string& path, std::string& out) {
    HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    out.clear();
    char buffer[4096];
    DWORD read = 0;
    while (ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        out.append(buffer, read);
    }
    CloseHandle(file);
    return true;
}

bool exists(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool remove(const std::string& path) {
    return DeleteFileA(path.c_str()) != 0 || GetLastError() == ERROR_FILE_NOT_FOUND;
}

} // namespace fileutil
