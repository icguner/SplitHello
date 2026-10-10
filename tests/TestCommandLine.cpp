#include "Test.hpp"

#include "CommandLine.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

namespace {

// Builds a command line from `arguments`, parses it back with the same
// routine the CRT/Windows uses and returns the argv (without the program).
std::vector<std::wstring> roundTrip(const std::vector<std::wstring>& arguments) {
    std::wstring line = L"prog.exe";
    for (const std::wstring& argument : arguments) {
        line.push_back(L' ');
        line += cmdline::quoteArgument(argument);
    }

    int count = 0;
    LPWSTR* parsed = CommandLineToArgvW(line.c_str(), &count);
    std::vector<std::wstring> result;
    if (parsed) {
        for (int i = 1; i < count; ++i) result.push_back(parsed[i]);
        LocalFree(parsed);
    }
    return result;
}

} // namespace

TEST(CommandLineQuotesEmptyArgumentAsEmptyPair) {
    CHECK(cmdline::quoteArgument(L"") == L"\"\"");
    CHECK(cmdline::quoteArgument(L"plain") == L"plain");
}

TEST(CommandLineQuoteRoundTripsThroughCommandLineToArgv) {
    const std::vector<std::wstring> arguments = {
        L"plain",
        L"",
        L"with space",
        L"quote\"inside",
        L"C:\\Program Files\\SplitHello\\splithello.exe",
        L"trailing\\",
        L"trailing space\\",
        L"two\\\\",
        L"back\\\\\"quote",
        L"tab\there",
        L"--include-process",
        L"*\\chrome?.exe",
        L"ş ğ İ unicode yol",
    };
    const std::vector<std::wstring> parsed = roundTrip(arguments);
    CHECK_EQ(parsed.size(), arguments.size());
    for (size_t i = 0; i < arguments.size(); ++i) {
        CHECK(parsed[i] == arguments[i]);
    }
}
