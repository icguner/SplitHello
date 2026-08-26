#include "Diagnosis.hpp"

#include <algorithm>

namespace diagnosis {

namespace {

constexpr unsigned kSlowServerHelloMs = 1500;

const Attempt* findProfile(const std::vector<Attempt>& attempts, const std::string& profile) {
    const auto it = std::find_if(attempts.begin(), attempts.end(),
                                 [&profile](const Attempt& attempt) {
                                     return attempt.profile == profile;
                                 });
    return it == attempts.end() ? nullptr : &*it;
}

const Attempt* findSuccess(const std::vector<Attempt>& attempts) {
    const auto it = std::find_if(attempts.begin(), attempts.end(),
                                 [](const Attempt& attempt) {
                                     return attempt.signal == ProbeSignal::ServerHello;
                                 });
    return it == attempts.end() ? nullptr : &*it;
}

bool hasSignal(const std::vector<Attempt>& attempts, ProbeSignal signal) {
    return std::any_of(attempts.begin(), attempts.end(),
                       [signal](const Attempt& attempt) {
                           return attempt.signal == signal;
                       });
}

} // namespace

Verdict infer(const std::vector<Attempt>& attempts) {
    if (attempts.empty()) return {};

    const Attempt* success = findSuccess(attempts);
    if (success) {
        if (success->profile == "none") {
            if (success->elapsedMs >= kSlowServerHelloMs) {
                // A slow origin or congested path can look identical from one
                // sample, so this is intentionally a suspicion, not a claim.
                return {Kind::ThrottlingSuspected, 55, success->profile};
            }
            return {Kind::NoInterference, 95, success->profile};
        }

        const Attempt* baseline = findProfile(attempts, "none");
        if (baseline && baseline->signal != ProbeSignal::ServerHello) {
            // A strict TLS Alert is weaker evidence of censorship than a
            // blackhole/reset: it can also mean endpoint intolerance.
            const unsigned confidence = baseline->signal == ProbeSignal::Alert ? 70 : 92;
            return {Kind::SniInterferenceLikely, confidence, success->profile};
        }

        // A remembered profile may be tried without a fresh baseline. It is a
        // known workaround, but this individual connection did not re-prove
        // the cause of the interference.
        return {Kind::SniInterferenceLikely, 65, success->profile};
    }

    if (hasSignal(attempts, ProbeSignal::Alert)) {
        return {Kind::TlsIncompatible, 75, {}};
    }

    const bool onlyTransportFailures = std::all_of(
        attempts.begin(), attempts.end(), [](const Attempt& attempt) {
            return attempt.signal == ProbeSignal::Timeout ||
                   attempt.signal == ProbeSignal::Reset ||
                   attempt.signal == ProbeSignal::Closed;
        });
    if (onlyTransportFailures) {
        // Without a successful differential probe this deliberately does not
        // claim censorship: an outage and an IP/TCP block look the same here.
        return {Kind::TransportFailure, 45, {}};
    }

    return {Kind::Unknown, 25, {}};
}

const char* name(Kind kind) {
    switch (kind) {
    case Kind::Unknown:               return "unknown";
    case Kind::NoInterference:        return "no-interference";
    case Kind::SniInterferenceLikely: return "sni-interference-likely";
    case Kind::TlsIncompatible:       return "tls-incompatible";
    case Kind::TransportFailure:      return "transport-failure";
    case Kind::ThrottlingSuspected:   return "throttling-suspected";
    }
    return "unknown";
}

const char* signalName(ProbeSignal signal) {
    switch (signal) {
    case ProbeSignal::ServerHello: return "server-hello";
    case ProbeSignal::Alert:       return "tls-alert";
    case ProbeSignal::Timeout:     return "timeout";
    case ProbeSignal::Reset:       return "reset";
    case ProbeSignal::Closed:      return "closed";
    case ProbeSignal::Unexpected:  return "unexpected";
    }
    return "unexpected";
}

const char* describe(ProbeSignal signal) {
    switch (signal) {
    case ProbeSignal::ServerHello: return "ServerHello";
    case ProbeSignal::Alert:       return "TLS Alert";
    case ProbeSignal::Timeout:     return "zaman asimi";
    case ProbeSignal::Reset:       return "RST";
    case ProbeSignal::Closed:      return "baglanti kapatildi";
    case ProbeSignal::Unexpected:  return "beklenmeyen yanit";
    }
    return "bilinmeyen";
}

} // namespace diagnosis
