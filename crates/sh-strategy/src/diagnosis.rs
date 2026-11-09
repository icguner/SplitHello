//! Differential DPI diagnosis (port of `src/Diagnosis.cpp`).
//!
//! A timeout or reset alone is ambiguous: the origin may simply be down. The
//! useful signal is a controlled difference on the same destination and
//! ClientHello: the untouched hello fails while a transformed copy gets a valid
//! ServerHello. One differential sample is still not proof: a network that
//! hiccups for a few seconds fails the baseline and the profiles tried during
//! the hiccup, then lets the next one through. The caller supplies the context
//! that separates the two cases.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSignal {
    ServerHello,
    Alert,
    Timeout,
    Reset,
    Closed,
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    Unknown,
    NoInterference,
    /// Untouched hello failed, a transformed one worked.
    SniInterferenceLikely,
    TlsIncompatible,
    TransportFailure,
    ThrottlingSuspected,
    /// A remembered profile was applied; the cause was not re-proven.
    LearnedProfile,
    /// Baseline failed, but the evidence points at a hiccup.
    TransientFailure,
    /// One differential; not yet reproduced on a later connection.
    InterferenceSuspected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub profile: String,
    pub signal: ProbeSignal,
    pub elapsed_ms: u32,
}

impl Attempt {
    pub fn new(profile: &str, signal: ProbeSignal, elapsed_ms: u32) -> Self {
        Self {
            profile: profile.to_owned(),
            signal,
            elapsed_ms,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    pub kind: Kind,
    /// 0..100: confidence in the classification, not availability.
    pub confidence: u32,
    pub winning_profile: String,
}

/// What the caller knew before this connection's attempts.
#[derive(Debug, Clone, Default)]
pub struct Context {
    /// Profile promoted to the front of the probe order, if any. A proven bypass
    /// failing the same way as the baseline is a hiccup signature.
    pub remembered_profile: String,
    /// The untouched baseline to this host succeeded a few minutes ago. DPI does
    /// not switch on and off within minutes; a hiccup does.
    pub baseline_recently_healthy: bool,
}

const SLOW_SERVER_HELLO_MS: u32 = 1500;

fn is_transport_failure(signal: ProbeSignal) -> bool {
    matches!(
        signal,
        ProbeSignal::Timeout | ProbeSignal::Reset | ProbeSignal::Closed
    )
}

fn verdict(kind: Kind, confidence: u32, winner: &str) -> Verdict {
    Verdict {
        kind,
        confidence,
        winning_profile: winner.to_owned(),
    }
}

pub fn infer(attempts: &[Attempt], context: &Context) -> Verdict {
    if attempts.is_empty() {
        return Verdict::default();
    }
    let find = |profile: &str| attempts.iter().find(|a| a.profile == profile);

    if let Some(success) = attempts
        .iter()
        .find(|a| a.signal == ProbeSignal::ServerHello)
    {
        if success.profile == "none" {
            // A slow origin or congested path looks identical from one sample,
            // so this is a suspicion, not a claim.
            return if success.elapsed_ms >= SLOW_SERVER_HELLO_MS {
                verdict(Kind::ThrottlingSuspected, 55, &success.profile)
            } else {
                verdict(Kind::NoInterference, 95, &success.profile)
            };
        }

        let baseline = match find("none") {
            Some(baseline) if baseline.signal != ProbeSignal::ServerHello => baseline,
            // A remembered profile tried without a fresh baseline: a known
            // workaround, but this connection did not re-prove the cause.
            _ => return verdict(Kind::LearnedProfile, 65, &success.profile),
        };

        if context.baseline_recently_healthy {
            return verdict(Kind::TransientFailure, 70, &success.profile);
        }

        // The proven bypass and the baseline died the same way and a third
        // profile got through moments later: the path blinked.
        let remembered_died_with_baseline = !context.remembered_profile.is_empty()
            && context.remembered_profile != success.profile
            && find(&context.remembered_profile).is_some_and(|remembered| {
                is_transport_failure(remembered.signal) && is_transport_failure(baseline.signal)
            });
        if remembered_died_with_baseline {
            return verdict(Kind::TransientFailure, 60, &success.profile);
        }

        // A strict TLS Alert is weaker evidence of censorship than a blackhole
        // or reset: it can also mean endpoint intolerance.
        let confidence = if baseline.signal == ProbeSignal::Alert {
            70
        } else {
            92
        };
        return verdict(Kind::SniInterferenceLikely, confidence, &success.profile);
    }

    if attempts.iter().any(|a| a.signal == ProbeSignal::Alert) {
        return verdict(Kind::TlsIncompatible, 75, "");
    }
    if attempts.iter().all(|a| is_transport_failure(a.signal)) {
        // Without a successful differential this does not claim censorship: an
        // outage and an IP/TCP block look the same here.
        return verdict(Kind::TransportFailure, 45, "");
    }
    verdict(Kind::Unknown, 25, "")
}

/// True for a verdict that should update the learned-winner store.
pub fn is_verified_bypass(kind: Kind) -> bool {
    kind == Kind::SniInterferenceLikely
}

impl Kind {
    /// Stable name used in strategies.json and telemetry.db.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Unknown => "unknown",
            Kind::NoInterference => "no-interference",
            Kind::SniInterferenceLikely => "sni-interference-likely",
            Kind::TlsIncompatible => "tls-incompatible",
            Kind::TransportFailure => "transport-failure",
            Kind::ThrottlingSuspected => "throttling-suspected",
            Kind::LearnedProfile => "learned-profile",
            Kind::TransientFailure => "transient-failure",
            Kind::InterferenceSuspected => "interference-suspected",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [
            Kind::Unknown,
            Kind::NoInterference,
            Kind::SniInterferenceLikely,
            Kind::TlsIncompatible,
            Kind::TransportFailure,
            Kind::ThrottlingSuspected,
            Kind::LearnedProfile,
            Kind::TransientFailure,
            Kind::InterferenceSuspected,
        ]
        .into_iter()
        .find(|kind| kind.name() == name)
    }
}

impl ProbeSignal {
    /// Stable name used in telemetry.db.
    pub fn name(self) -> &'static str {
        match self {
            ProbeSignal::ServerHello => "server-hello",
            ProbeSignal::Alert => "tls-alert",
            ProbeSignal::Timeout => "timeout",
            ProbeSignal::Reset => "reset",
            ProbeSignal::Closed => "closed",
            ProbeSignal::Unexpected => "unexpected",
        }
    }

    /// Turkish text for logs.
    pub fn describe(self) -> &'static str {
        match self {
            ProbeSignal::ServerHello => "ServerHello",
            ProbeSignal::Alert => "TLS Alert",
            ProbeSignal::Timeout => "zaman asimi",
            ProbeSignal::Reset => "RST",
            ProbeSignal::Closed => "baglanti kapatildi",
            ProbeSignal::Unexpected => "beklenmeyen yanit",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProbeSignal::*;

    fn run(attempts: &[(&str, ProbeSignal, u32)], context: &Context) -> Verdict {
        let attempts: Vec<_> = attempts
            .iter()
            .map(|&(p, s, ms)| Attempt::new(p, s, ms))
            .collect();
        infer(&attempts, context)
    }

    fn remembered(profile: &str) -> Context {
        Context {
            remembered_profile: profile.into(),
            ..Context::default()
        }
    }

    #[test]
    fn untouched_server_hello_means_no_interference() {
        let v = run(&[("none", ServerHello, 0)], &Context::default());
        assert_eq!(v.kind, Kind::NoInterference);
        assert_eq!(v.winning_profile, "none");
        assert!(v.confidence >= 90);
    }

    #[test]
    fn fragment_success_after_baseline_timeout_suggests_sni_interference() {
        let v = run(
            &[("none", Timeout, 0), ("sni-mid", ServerHello, 0)],
            &Context::default(),
        );
        assert_eq!(v.kind, Kind::SniInterferenceLikely);
        assert_eq!(v.winning_profile, "sni-mid");
        assert!(v.confidence >= 90);
    }

    #[test]
    fn alert_without_working_profile_means_tls_incompatible() {
        let v = run(
            &[("none", Alert, 0), ("sni-mid", Alert, 0)],
            &Context::default(),
        );
        assert_eq!(v.kind, Kind::TlsIncompatible);
        assert!(v.winning_profile.is_empty());
    }

    #[test]
    fn only_transport_failures_remain_ambiguous() {
        let v = run(
            &[("none", Reset, 0), ("sni-mid", Timeout, 0)],
            &Context::default(),
        );
        assert_eq!(v.kind, Kind::TransportFailure);
        assert!(v.confidence < 50);
    }

    #[test]
    fn slow_untouched_server_hello_is_only_throttling_suspicion() {
        let v = run(&[("none", ServerHello, 1800)], &Context::default());
        assert_eq!(v.kind, Kind::ThrottlingSuspected);
        assert_eq!(v.winning_profile, "none");
        assert!((50..70).contains(&v.confidence));
    }

    #[test]
    fn remembered_profile_without_baseline_is_not_interference_evidence() {
        let v = run(&[("sni-mid", ServerHello, 30)], &Context::default());
        assert_eq!(v.kind, Kind::LearnedProfile);
        assert_eq!(v.winning_profile, "sni-mid");
        assert!(!is_verified_bypass(v.kind));
    }

    #[test]
    fn baseline_failure_right_after_healthy_baseline_is_transient() {
        let context = Context {
            baseline_recently_healthy: true,
            ..Context::default()
        };
        let v = run(
            &[("none", Timeout, 3000), ("sni-mid", ServerHello, 31)],
            &context,
        );
        assert_eq!(v.kind, Kind::TransientFailure);
        assert_eq!(v.winning_profile, "sni-mid");
        assert!(!is_verified_bypass(v.kind));
    }

    #[test]
    fn remembered_profile_dying_with_baseline_is_transient() {
        let v = run(
            &[
                ("record-1", Timeout, 3000),
                ("none", Timeout, 3000),
                ("sni-mid", ServerHello, 32),
            ],
            &remembered("record-1"),
        );
        assert_eq!(v.kind, Kind::TransientFailure);
        assert_eq!(v.winning_profile, "sni-mid");
    }

    #[test]
    fn fresh_differential_without_context_still_counts_as_interference() {
        let v = run(
            &[
                ("record-1", Timeout, 3000),
                ("none", Timeout, 3000),
                ("sni-mid", ServerHello, 32),
            ],
            &Context::default(),
        );
        assert_eq!(v.kind, Kind::SniInterferenceLikely);
        assert!(is_verified_bypass(v.kind));
        assert!(v.confidence >= 90);
    }

    /// The winner drew a TLS Alert while the baseline was black-holed: not the
    /// uniform failure of a hiccup, so the differential stands.
    #[test]
    fn remembered_profile_failing_differently_is_not_transient() {
        let v = run(
            &[
                ("record-1", Alert, 20),
                ("none", Timeout, 3000),
                ("sni-mid", ServerHello, 32),
            ],
            &remembered("record-1"),
        );
        assert_eq!(v.kind, Kind::SniInterferenceLikely);
    }

    #[test]
    fn names_round_trip() {
        for name in [
            "unknown",
            "sni-interference-likely",
            "interference-suspected",
        ] {
            assert_eq!(Kind::from_name(name).map(Kind::name), Some(name));
        }
        assert!(Kind::from_name("bogus").is_none());
    }
}
