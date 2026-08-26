#include "Test.hpp"

#include "ProcessFilter.hpp"

TEST(ProcessRulesAllowEverythingWhenEmpty) {
    const process_filter::Rules rules({}, {});
    CHECK(!rules.enabled());
    CHECK(rules.allowsImage("C:\\Program Files\\Browser\\browser.exe"));
}

TEST(ProcessRulesUseIncludeAsAllowList) {
    const process_filter::Rules rules({"chrome.exe", "firefox*.exe"}, {});
    CHECK(rules.enabled());
    CHECK(rules.allowsImage("C:\\Program Files\\Google\\Chrome.EXE"));
    CHECK(rules.allowsImage("firefox-nightly.exe"));
    CHECK(!rules.allowsImage("C:\\Windows\\System32\\curl.exe"));
}

TEST(ProcessRulesGiveExcludePrecedence) {
    const process_filter::Rules rules({"*.exe"}, {"steam*.exe"});
    CHECK(rules.allowsImage("browser.exe"));
    CHECK(!rules.allowsImage("C:\\Games\\Steam.exe"));
    CHECK(!rules.allowsImage("steamwebhelper.exe"));
}

TEST(ProcessRulesCanMatchFullPathsAndQuestionMarks) {
    const process_filter::Rules rules({"c:/portable/*/app?.exe"}, {});
    CHECK(rules.allowsImage("C:\\Portable\\Browser\\App1.exe"));
    CHECK(!rules.allowsImage("C:\\Installed\\Browser\\App1.exe"));
    CHECK(!rules.allowsImage("C:\\Portable\\Browser\\App10.exe"));
}

TEST(ProcessRulesNormalizeAndExposeDriverRules) {
    const process_filter::Rules rules(
        {" Chrome.exe ", "chrome.EXE", ""},
        {" helper.exe ", "HELPER.EXE"});
    CHECK_EQ(rules.includeCount(), 1U);
    CHECK_EQ(rules.excludeCount(), 1U);
    CHECK_EQ(rules.includes().front(), std::string("chrome.exe"));
    CHECK_EQ(rules.excludes().front(), std::string("helper.exe"));
    CHECK(rules.allowsImage("chrome.exe"));
    CHECK(!rules.allowsImage("helper.exe"));
}
