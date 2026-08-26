#include "Json.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 64 * 1024) return 0;

    const char* bytes = size == 0 ? "" : reinterpret_cast<const char*>(data);
    const std::string input(bytes, size);
    const size_t keyLength = std::min<size_t>(size, 64);
    const std::string dynamicKey(bytes, keyLength);
    for (const std::string& key : {std::string("result"), std::string("host"),
                                   dynamicKey}) {
        (void)json::getString(input, key);
        (void)json::getBool(input, key);
        (void)json::getInt(input, key);
        (void)json::getStringArray(input, key);
        (void)json::getRaw(input, key);
    }
    (void)json::escape(input);
    return 0;
}
