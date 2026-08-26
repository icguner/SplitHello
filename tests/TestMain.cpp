#include "Test.hpp"

#include <spdlog/spdlog.h>

#include <iostream>

std::vector<TestCase>& testRegistry() {
    static std::vector<TestCase> registry;
    return registry;
}

int main() {
    spdlog::set_level(spdlog::level::off); // the code under test logs a lot

    size_t passed = 0;
    std::vector<std::string> failures;

    for (const TestCase& test : testRegistry()) {
        try {
            test.body();
            passed++;
        } catch (const std::exception& error) {
            failures.push_back(test.name + ": " + error.what());
        } catch (...) {
            failures.push_back(test.name + ": bilinmeyen istisna");
        }
    }

    for (const std::string& failure : failures) {
        std::cout << "FAIL  " << failure << "\n";
    }

    std::cout << passed << "/" << testRegistry().size() << " test gecti\n";
    return failures.empty() ? 0 : 1;
}
