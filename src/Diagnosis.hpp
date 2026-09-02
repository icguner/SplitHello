#pragma once

#include <string>
#include <vector>

// Differential DPI diagnosis.
//
// A timeout or reset by itself is ambiguous: the origin may simply be down.
// The useful signal is a controlled difference on the same destination and
// ClientHello. If the untouched hello fails while a fragmented copy receives
// a valid ServerHello, SNI-path interference is the most likely explanation.
//
// One differential sample is still not proof. A network that hiccups for a
// few seconds fails the baseline *and* whichever profiles were tried during
// the hiccup, then lets the next profile through: exactly the shape of a
// successful bypass. Two pieces of context separate the two cases, and both
// are supplied by the caller because they live outside a single connection.
namespace diagnosis {

enum class ProbeSignal {
    ServerHello,
    Alert,
    Timeout,
    Reset,
    Closed,
    Unexpected,
};

enum class Kind {
    Unknown,
    NoInterference,
    SniInterferenceLikely,   // untouched hello failed, a transformed one worked
    TlsIncompatible,
    TransportFailure,
    ThrottlingSuspected,
    LearnedProfile,          // a remembered profile was applied; cause not re-proven
    TransientFailure,        // baseline failed, but the evidence points at a hiccup
    InterferenceSuspected,   // one differential; not yet reproduced on a later connection
};

struct Attempt {
    std::string profile;
    ProbeSignal signal = ProbeSignal::Unexpected;
    unsigned elapsedMs = 0;
};

struct Verdict {
    Kind kind = Kind::Unknown;
    unsigned confidence = 0; // 0..100; confidence in the classification, not availability
    std::string winningProfile;
};

// What the caller knew before this connection's attempts.
struct Context {
    // Profile promoted to the front of the probe order, if any. A proven
    // bypass that fails with the same transport failure as the baseline is
    // a hiccup signature, not a change in DPI behaviour.
    std::string rememberedProfile;

    // The untouched baseline to this host succeeded a few minutes ago. DPI
    // does not switch on and off within minutes; a hiccup does.
    bool baselineRecentlyHealthy = false;
};

Verdict infer(const std::vector<Attempt>& attempts, const Context& context = {});

// True for a verdict that should update the learned-winner store.
bool isVerifiedBypass(Kind kind);

const char* name(Kind kind);
const char* signalName(ProbeSignal signal);
const char* describe(ProbeSignal signal);

} // namespace diagnosis
