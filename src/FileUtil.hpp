#pragma once

#include <string>

// Small file helpers used wherever we persist state that must survive a
// hard kill: the write goes to a sibling temp file, is flushed to the disk
// controller, and only then replaces the target. A crash therefore leaves
// either the old file or the new one, never a truncated mix.
namespace fileutil {

bool writeAtomic(const std::string& path, const std::string& content);
bool readAll(const std::string& path, std::string& out);
bool exists(const std::string& path);
bool remove(const std::string& path);

} // namespace fileutil
