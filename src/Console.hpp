#pragma once

#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Minimal ANSI colouring for the setup console. Falls back to plain text when
// stdout is not a console that accepts virtual-terminal sequences.
namespace console {

inline bool colorEnabled() {
    static const bool enabled = [] {
        const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (out == INVALID_HANDLE_VALUE || !GetConsoleMode(out, &mode)) return false;
        return SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }();
    return enabled;
}

inline std::string paint(const char* code, const std::string& text) {
    if (!colorEnabled()) return text;
    return std::string("\x1b[") + code + "m" + text + "\x1b[0m";
}

inline std::string green(const std::string& text) { return paint("32", text); }
inline std::string red(const std::string& text) { return paint("31", text); }
inline std::string yellow(const std::string& text) { return paint("33", text); }
inline std::string cyan(const std::string& text) { return paint("36;1", text); }
inline std::string dim(const std::string& text) { return paint("90", text); }

// Last meaningful error line of a child tool's captured output: ANSI codes and
// the "[ERROR]" decoration are removed. Empty when nothing looks like an error.
inline std::string lastErrorLine(const std::string& output) {
    std::string plain;
    for (size_t i = 0; i < output.size(); ++i) {
        if (output[i] == '\x1b' && i + 1 < output.size() && output[i + 1] == '[') {
            i += 2;
            while (i < output.size() && !(output[i] >= '@' && output[i] <= '~')) ++i;
            continue;
        }
        plain.push_back(output[i]);
    }

    std::string found;
    size_t start = 0;
    while (start <= plain.size()) {
        size_t end = plain.find('\n', start);
        if (end == std::string::npos) end = plain.size();
        std::string line = plain.substr(start, end - start);
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        const size_t marker = line.find("[ERROR]");
        if (marker != std::string::npos) {
            found = line.substr(marker + 7);
            const size_t first = found.find_first_not_of(' ');
            found = first == std::string::npos ? std::string{} : found.substr(first);
            if (found.rfind("Error: ", 0) == 0) found.erase(0, 7);
        }
        start = end + 1;
    }
    return found;
}

} // namespace console
