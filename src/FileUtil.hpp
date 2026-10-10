#pragma once

#include <string>

// Small file helpers used wherever we persist state that must survive a
// hard kill: the write goes to a sibling temp file, is flushed to the disk
// controller, and only then replaces the target. A crash therefore leaves
// either the old file or the new one, never a truncated mix.
namespace fileutil {

// Path strings may be UTF-8 or ANSI (see the .cpp); these turn either into
// the form the wide Win32 APIs and SQLite expect. Empty on conversion failure.
std::wstring widen(const std::string& path);
std::string toUtf8(const std::string& path);

bool writeAtomic(const std::string& path, const std::string& content);
bool readAll(const std::string& path, std::string& out);
bool exists(const std::string& path);
bool remove(const std::string& path);

} // namespace fileutil
