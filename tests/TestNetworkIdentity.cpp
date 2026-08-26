#include "Test.hpp"

#include "NetworkIdentity.hpp"

TEST(NetworkIdentityIsStableAndOpaque) {
    const std::string first = network_identity::current();
    const std::string second = network_identity::current();

    CHECK(!first.empty());
    CHECK_EQ(first, second);
    CHECK(first.starts_with("nla-") || first == "network-default");
}
