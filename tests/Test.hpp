#pragma once

// Minimal assertion harness. The point of these tests is the byte-level TLS
// parsing, so a dependency-free runner keeps the build to one FetchContent.

#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

struct TestCase {
    std::string name;
    std::function<void()> body;
};

std::vector<TestCase>& testRegistry();

struct TestRegistrar {
    TestRegistrar(const char* name, std::function<void()> body) {
        testRegistry().push_back({name, std::move(body)});
    }
};

#define TEST(name)                                                    \
    static void name();                                               \
    static const TestRegistrar registrar_##name(#name, name);         \
    static void name()

#define CHECK(condition)                                              \
    do {                                                              \
        if (!(condition)) {                                           \
            std::ostringstream message;                               \
            message << __FILE__ << ":" << __LINE__                    \
                    << " CHECK failed: " #condition;                  \
            throw std::runtime_error(message.str());                  \
        }                                                             \
    } while (false)

#define CHECK_EQ(actual, expected)                                    \
    do {                                                              \
        const auto actualValue = (actual);                            \
        const auto expectedValue = (expected);                        \
        if (!(actualValue == expectedValue)) {                        \
            std::ostringstream message;                               \
            message << __FILE__ << ":" << __LINE__                    \
                    << " CHECK_EQ failed: " #actual " == " #expected  \
                    << " (got " << actualValue                        \
                    << ", want " << expectedValue << ")";             \
            throw std::runtime_error(message.str());                  \
        }                                                             \
    } while (false)
