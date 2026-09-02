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

TEST(RememberedProfileWithoutBaselineIsNotInterferenceEvidence) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"sni-mid", diagnosis::ProbeSignal::ServerHello, 30},
    });

    CHECK(verdict.kind == diagnosis::Kind::LearnedProfile);
    CHECK_EQ(verdict.winningProfile, std::string("sni-mid"));
    CHECK(!diagnosis::isVerifiedBypass(verdict.kind));
}

TEST(BaselineFailureRightAfterHealthyBaselineIsTransient) {
    diagnosis::Context context;
    context.baselineRecentlyHealthy = true;
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"none", diagnosis::ProbeSignal::Timeout, 3000},
        {"sni-mid", diagnosis::ProbeSignal::ServerHello, 31},
    }, context);

    CHECK(verdict.kind == diagnosis::Kind::TransientFailure);
    CHECK_EQ(verdict.winningProfile, std::string("sni-mid"));
    CHECK(!diagnosis::isVerifiedBypass(verdict.kind));
}

TEST(RememberedProfileDyingWithBaselineIsTransient) {
    diagnosis::Context context;
    context.rememberedProfile = "record-1";
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"record-1", diagnosis::ProbeSignal::Timeout, 3000},
        {"none", diagnosis::ProbeSignal::Timeout, 3000},
        {"sni-mid", diagnosis::ProbeSignal::ServerHello, 32},
    }, context);

    CHECK(verdict.kind == diagnosis::Kind::TransientFailure);
    CHECK_EQ(verdict.winningProfile, std::string("sni-mid"));
}

TEST(FreshDifferentialWithoutContextStillCountsAsInterference) {
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"record-1", diagnosis::ProbeSignal::Timeout, 3000},
        {"none", diagnosis::ProbeSignal::Timeout, 3000},
        {"sni-mid", diagnosis::ProbeSignal::ServerHello, 32},
    });

    CHECK(verdict.kind == diagnosis::Kind::SniInterferenceLikely);
    CHECK(diagnosis::isVerifiedBypass(verdict.kind));
    CHECK(verdict.confidence >= 90);
}

TEST(RememberedProfileFailingDifferentlyIsNotTransient) {
    // The winner drew a TLS Alert while the baseline was black-holed: that is
    // not the uniform failure of a hiccup, so the differential stands.
    diagnosis::Context context;
    context.rememberedProfile = "record-1";
    const diagnosis::Verdict verdict = diagnosis::infer({
        {"record-1", diagnosis::ProbeSignal::Alert, 20},
        {"none", diagnosis::ProbeSignal::Timeout, 3000},
        {"sni-mid", diagnosis::ProbeSignal::ServerHello, 32},
    }, context);

    CHECK(verdict.kind == diagnosis::Kind::SniInterferenceLikely);
}
