#include "Test.hpp"

#include "QuicStrategy.hpp"

#include <vector>

TEST(RecognizesQuicV1InitialAndRejectsShortDatagrams) {
    std::vector<uint8_t> initial(1200);
    initial[0] = 0xC0;
    initial[4] = 1;
    CHECK(quic_strategy::looksLikeInitial(initial.data(), initial.size()));
    CHECK(!quic_strategy::looksLikeInitial(initial.data(), 1199));
    initial[0] = 0x40;
    CHECK(!quic_strategy::looksLikeInitial(initial.data(), initial.size()));
}

TEST(PrimePayloadCannotBeParsedAsQuic) {
    const std::vector<uint8_t> prime = quic_strategy::buildPrimePayload();
    CHECK_EQ(prime.size(), (size_t)32);
    CHECK((prime[0] & 0x40) == 0);
}

TEST(AdaptiveQuicPrimesThenKeepsAResponsiveFlow) {
    quic_strategy::AdaptiveRegistry registry(900, 5000);
    CHECK(registry.outbound("203.0.113.1", 50000, true, 1000) ==
          quic_strategy::Decision::PrimeAndPass);
    registry.inbound("203.0.113.1", 50000, 1100);
    CHECK(registry.outbound("203.0.113.1", 50000, false, 3000) ==
          quic_strategy::Decision::Pass);
}

TEST(AdaptiveQuicIgnoresPreInitialTrafficUntilTheRealProbe) {
    quic_strategy::AdaptiveRegistry registry(900, 5000);
    CHECK(registry.outbound("203.0.113.3", 50000, false, 1000) ==
          quic_strategy::Decision::Pass);
    CHECK(registry.outbound("203.0.113.3", 50000, true, 1100) ==
          quic_strategy::Decision::PrimeAndPass);
}

TEST(AdaptiveQuicFallsBackAfterNoResponse) {
    quic_strategy::AdaptiveRegistry registry(900, 5000);
    CHECK(registry.outbound("203.0.113.2", 50000, true, 1000) ==
          quic_strategy::Decision::PrimeAndPass);
    CHECK(registry.outbound("203.0.113.2", 50000, true, 1900) ==
          quic_strategy::Decision::Drop);
    CHECK(registry.outbound("203.0.113.2", 50001, true, 2000) ==
          quic_strategy::Decision::Drop);
    CHECK(registry.outbound("203.0.113.2", 50001, true, 7000) ==
          quic_strategy::Decision::PrimeAndPass);
}

TEST(AdaptiveQuicPrechecksLetSettledTrafficSkipTheRegistry) {
    quic_strategy::AdaptiveRegistry registry(900, 5000);
    CHECK(!registry.needsInbound());
    CHECK(!registry.needsOutbound(false));
    CHECK(registry.needsOutbound(true));

    registry.outbound("203.0.113.4", 50000, true, 1000);
    CHECK(registry.needsInbound());
    registry.inbound("203.0.113.4", 50000, 1100);
    // Answered: the data datagrams that follow need neither direction.
    CHECK(!registry.needsInbound());
    CHECK(!registry.needsOutbound(false));

    // An unanswered Initial gets blocked; non-Initial datagrams must then be
    // checked against the block list until it expires.
    registry.outbound("203.0.113.5", 50001, true, 2000);
    CHECK(registry.outbound("203.0.113.5", 50001, true, 2900) ==
          quic_strategy::Decision::Drop);
    CHECK(registry.needsOutbound(false));
    CHECK(registry.outbound("203.0.113.5", 50002, false, 3000) ==
          quic_strategy::Decision::Drop);
    CHECK(registry.outbound("203.0.113.5", 50002, false, 8000) ==
          quic_strategy::Decision::Pass);
    CHECK(!registry.needsOutbound(false));
    CHECK(!registry.needsInbound());

    registry.outbound("203.0.113.6", 50003, true, 9000);
    CHECK(registry.needsInbound());
    registry.clear();
    CHECK(!registry.needsInbound());
}
