#pragma once

#include <string>
#include <vector>

// Differential DPI diagnosis.
//
// A timeout or reset by itself is ambiguous: the origin may simply be down.
// The useful signal is a controlled difference on the same destination and
// ClientHello. If the untouched hello fails while a fragmented copy receives
// a valid ServerHello, SNI-path interference is the most likely explanation.
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
    SniInterferenceLikely,
    TlsIncompatible,
    TransportFailure,
    ThrottlingSuspected,
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

Verdict infer(const std::vector<Attempt>& attempts);

const char* name(Kind kind);
const char* signalName(ProbeSignal signal);
const char* describe(ProbeSignal signal);

} // namespace diagnosis
