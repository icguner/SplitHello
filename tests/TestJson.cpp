#include "Test.hpp"

#include "Json.hpp"

#include <string>
#include <vector>

TEST(ReadsStringsAndEscapes) {
    const std::string document = R"({"name":"a\"b\\c","tab":"x\ty"})";

    CHECK_EQ(json::getString(document, "name"), std::string("a\"b\\c"));
    CHECK_EQ(json::getString(document, "tab"), std::string("x\ty"));
    CHECK_EQ(json::getString(document, "missing"), std::string());
}

TEST(EscapeRoundTrip) {
    const std::string original = "quote\" backslash\\ newline\n tab\t";
    const std::string document = "{\"v\": \"" + json::escape(original) + "\"}";
    CHECK_EQ(json::getString(document, "v"), original);
}

TEST(ReadsNumbersAndBooleans) {
    const std::string document = R"({"ttl": 300, "negative": -7, "success": true, "off": false})";

    CHECK_EQ(json::getInt(document, "ttl", 0), (long long)300);
    CHECK_EQ(json::getInt(document, "negative", 0), (long long)-7);
    CHECK_EQ(json::getInt(document, "absent", 42), (long long)42);
    CHECK(json::getBool(document, "success"));
    CHECK(!json::getBool(document, "off"));
    CHECK(!json::getBool(document, "absent"));
}

TEST(ReadsStringArrays) {
    const std::string document =
        R"({"a":["1.2.3.4","5.6.7.8"],"aaaa":[],"ttl":60})";

    const std::vector<std::string> v4 = json::getStringArray(document, "a");
    CHECK_EQ(v4.size(), (size_t)2);
    CHECK_EQ(v4[0], std::string("1.2.3.4"));
    CHECK_EQ(v4[1], std::string("5.6.7.8"));

    CHECK(json::getStringArray(document, "aaaa").empty());
    CHECK(json::getStringArray(document, "ttl").empty());
    CHECK(json::getStringArray(document, "missing").empty());
}

// The Cloudflare API nests the interesting fields under "result", and the
// envelope has same-named keys of its own.
TEST(ScopesLookupsToNestedValues) {
    const std::string object = R"({"success":true,"result":{"id":"inner"},"id":"outer"})";
    CHECK_EQ(json::getString(json::getRaw(object, "result"), "id"), std::string("inner"));

    const std::string array = R"({"result":[{"id":"first"},{"id":"second"}],"id":"outer"})";
    CHECK_EQ(json::getString(json::getRaw(array, "result"), "id"), std::string("first"));
}

TEST(BracesInsideStringsDoNotConfuseScoping) {
    const std::string document = R"({"result":{"name":"a}b","id":"good"},"id":"outer"})";
    CHECK_EQ(json::getString(json::getRaw(document, "result"), "id"), std::string("good"));
}

TEST(HandlesTruncatedInputWithoutReadingPastTheEnd) {
    CHECK_EQ(json::getString(R"({"a":"unterminated)", "a"), std::string("unterminated"));
    CHECK_EQ(json::getString(R"({"a")", "a"), std::string());
    CHECK_EQ(json::getString("", "a"), std::string());
    CHECK(json::getStringArray(R"({"a":["x")", "a").size() == 1);
    CHECK_EQ(json::getRaw(R"({"a":{"b":1)", "a"), std::string(R"({"b":1)"));
}
