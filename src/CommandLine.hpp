#pragma once

#include <string>

// Windows command-line quoting, shared by the elevation relaunch, the tray's
// engine/schtasks spawns and the tests. The result round-trips through
// CommandLineToArgvW / the MSVC CRT argv rules.
namespace cmdline {

inline std::wstring quoteArgument(const std::wstring& argument) {
    // An empty argument must still be one argv element, so it is written as "".
    if (!argument.empty() &&
        argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return argument;
    }

    std::wstring result = L"\"";
    size_t backslashes = 0;
    for (const wchar_t character : argument) {
        if (character == L'\\') {
            backslashes++;
            continue;
        }
        if (character == L'\"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(character);
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(character);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

} // namespace cmdline
