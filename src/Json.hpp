#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>

// Minimal read-only JSON helpers shared by Config, Setup and Dns.
// Not a general parser: it handles the flat/shallow shapes we actually
// exchange with the Cloudflare API and our own Worker. Every function is
// bounds-checked and returns a default value on malformed input.
namespace json {

inline size_t skipWs(const std::string& s, size_t pos) {
    while (pos < s.size() &&
           (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) {
        pos++;
    }
    return pos;
}

// Position just after the colon following "key", or npos.
inline size_t findValue(const std::string& s, const std::string& key, size_t from = 0) {
    const std::string needle = "\"" + key + "\"";
    size_t pos = s.find(needle, from);
    if (pos == std::string::npos) return std::string::npos;
    pos = skipWs(s, pos + needle.size());
    if (pos >= s.size() || s[pos] != ':') return std::string::npos;
    return skipWs(s, pos + 1);
}

// Parse a JSON string literal starting at pos (which must point at '"').
// endPos receives the index just past the closing quote.
inline std::string parseString(const std::string& s, size_t pos, size_t& endPos) {
    endPos = pos;
    if (pos >= s.size() || s[pos] != '"') return {};
    pos++;

    std::string out;
    while (pos < s.size() && s[pos] != '"') {
        if (s[pos] != '\\') { out += s[pos++]; continue; }

        pos++;
        if (pos >= s.size()) break;
        const char esc = s[pos++];
        switch (esc) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'r': out += '\r'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'u': {
            // We only ever carry ASCII (hostnames, IPs, account ids).
            unsigned code = 0;
            int digits = 0;
            while (digits < 4 && pos < s.size() && isxdigit((unsigned char)s[pos])) {
                const char c = s[pos++];
                code = code * 16 + (unsigned)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
                digits++;
            }
            out += (digits == 4 && code < 0x80) ? (char)code : '?';
            break;
        }
        default: out += esc; break;
        }
    }
    endPos = (pos < s.size()) ? pos + 1 : s.size();
    return out;
}

inline std::string getString(const std::string& s, const std::string& key, size_t from = 0) {
    const size_t pos = findValue(s, key, from);
    if (pos == std::string::npos) return {};
    size_t end = 0;
    return parseString(s, pos, end);
}

inline bool getBool(const std::string& s, const std::string& key) {
    const size_t pos = findValue(s, key);
    return pos != std::string::npos && s.compare(pos, 4, "true") == 0;
}

inline long long getInt(const std::string& s, const std::string& key, long long fallback = 0) {
    const size_t pos = findValue(s, key);
    if (pos == std::string::npos) return fallback;
    if (pos >= s.size() || (!isdigit((unsigned char)s[pos]) && s[pos] != '-')) return fallback;
    return std::strtoll(s.c_str() + pos, nullptr, 10);
}

// All string elements of the array value of "key". Empty if absent/not an array.
inline std::vector<std::string> getStringArray(const std::string& s, const std::string& key) {
    std::vector<std::string> out;
    size_t pos = findValue(s, key);
    if (pos == std::string::npos || pos >= s.size() || s[pos] != '[') return out;

    pos++;
    while (pos < s.size()) {
        pos = skipWs(s, pos);
        if (pos >= s.size() || s[pos] == ']') break;
        if (s[pos] == ',') { pos++; continue; }
        if (s[pos] != '"') break; // non-string element: give up rather than guess
        size_t end = 0;
        out.push_back(parseString(s, pos, end));
        pos = end;
    }
    return out;
}

// Raw substring of the value of "key", with balanced braces/brackets.
// Used to scope lookups into a nested object (e.g. Cloudflare's "result").
inline std::string getRaw(const std::string& s, const std::string& key) {
    size_t pos = findValue(s, key);
    if (pos == std::string::npos || pos >= s.size()) return {};

    const char open = s[pos];
    if (open != '{' && open != '[') return s.substr(pos);

    const char close = (open == '{') ? '}' : ']';
    const size_t start = pos;
    int depth = 0;
    bool inString = false;

    for (; pos < s.size(); pos++) {
        const char c = s[pos];
        if (inString) {
            if (c == '\\') pos++;
            else if (c == '"') inString = false;
            continue;
        }
        if (c == '"') inString = true;
        else if (c == open) depth++;
        else if (c == close && --depth == 0) return s.substr(start, pos - start + 1);
    }
    return s.substr(start);
}

inline std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) {
                static const char* hex = "0123456789abcdef";
                out += "\\u00";
                out += hex[c >> 4];
                out += hex[c & 0xF];
            } else {
                out += (char)c;
            }
        }
    }
    return out;
}

} // namespace json
