#include "Test.hpp"

#include "Diagnosis.hpp"

#include <vector>

TEST(UntouchedServerHelloMeansNoInterference) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"none", diagnosis::ProbeSignal::ServerHello},
    });

    CHECK(verdict.kind == diagnosis::Kind::NoInterference);
    CHECK_EQ(verdict.winningProfile, std::string("none"));
    CHECK(verdict.confidence >= 90);
}

TEST(FragmentSuccessAfterBaselineTimeoutSuggestsSniInterference) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"none", diagnosis::ProbeSignal::Timeout},
        {"sni-mid", diagnosis::ProbeSignal::ServerHello},
    });

    CHECK(verdict.kind == diagnosis::Kind::SniInterferenceLikely);
    CHECK_EQ(verdict.winningProfile, std::string("sni-mid"));
    CHECK(verdict.confidence >= 90);
}

TEST(AlertWithoutWorkingProfileMeansTlsIncompatible) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"none", diagnosis::ProbeSignal::Alert},
        {"sni-mid", diagnosis::ProbeSignal::Alert},
    });

    CHECK(verdict.kind == diagnosis::Kind::TlsIncompatible);
    CHECK(verdict.winningProfile.empty());
}

TEST(OnlyTransportFailuresRemainAmbiguous) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"none", diagnosis::ProbeSignal::Reset},
        {"sni-mid", diagnosis::ProbeSignal::Timeout},
    });

    CHECK(verdict.kind == diagnosis::Kind::TransportFailure);
    CHECK(verdict.confidence < 50);
}

TEST(SlowUntouchedServerHelloIsOnlyThrottlingSuspicion) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"none", diagnosis::ProbeSignal::ServerHello, 1800},
    });

    CHECK(verdict.kind == diagnosis::Kind::ThrottlingSuspected);
    CHECK_EQ(verdict.winningProfile, std::string("none"));
    CHECK(verdict.confidence >= 50);
    CHECK(verdict.confidence < 70);
}
