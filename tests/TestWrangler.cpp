#include "Test.hpp"

#include "Wrangler.hpp"

#include <string>

TEST(ParsesWranglerIdentityJson) {
    const std::string output =
        "npm notice cached\\n"
        R"({"email":"can@example.com","accounts":[)"
        R"({"id":"0123456789abcdef0123456789abcdef","name":"Personal"},)"
        R"({"id":"fedcba9876543210fedcba9876543210"}]})";

    const auto identity = wrangler::parseIdentity(output);
    CHECK(identity.has_value());
    CHECK_EQ(identity->email, std::string("can@example.com"));
    CHECK_EQ(identity->accounts.size(), (size_t)2);
    CHECK_EQ(identity->accounts[0].name, std::string("Personal"));
    CHECK(identity->accounts[1].name.empty());
}

TEST(RejectsMalformedWranglerIdentity) {
    CHECK(!wrangler::parseIdentity(R"({"accounts":[]})").has_value());
    CHECK(!wrangler::parseIdentity(
        R"({"accounts":[{"id":"not-an-account-id","name":"x"}]})")
               .has_value());
}

TEST(ExtractsWorkersDevUrlFromWranglerOutput) {
    const std::string output =
        "Uploaded splithello-relay\\nDeployed splithello-relay triggers\\n"
        "  https://SplitHello-Relay.Can-Subdomain.workers.dev\\n";
    CHECK_EQ(wrangler::parseWorkersDevUrl(output),
             std::string("wss://splithello-relay.can-subdomain.workers.dev"));
    CHECK(wrangler::parseWorkersDevUrl("https://dash.cloudflare.com/workers").empty());
}

TEST(ValidatesCloudflareWorkerNames) {
    CHECK(wrangler::isValidWorkerName("splithello-relay"));
    CHECK(wrangler::isValidWorkerName("a1"));
    CHECK(!wrangler::isValidWorkerName("SplitHello"));
    CHECK(!wrangler::isValidWorkerName("-relay"));
    CHECK(!wrangler::isValidWorkerName("relay-"));
    CHECK(!wrangler::isValidWorkerName("relay;whoami"));
    CHECK(!wrangler::isValidWorkerName(std::string(64, 'a')));
}
