//! Fragmentation profiles. A single split point does not defeat every DPI box:
//! some reassemble TLS records, some only look at the first TCP segment, some
//! key on the record boundary. Profiles are probed in order and the winner is
//! remembered per domain.

use sh_proto::tls::{ClientHello, RECORD_HEADER_SIZE};

use crate::store::DEFAULT_NETWORK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub name: &'static str,
    pub description: &'static str,
    pub requires_sni: bool,
}

const fn profile(name: &'static str, description: &'static str, requires_sni: bool) -> Profile {
    Profile {
        name,
        description,
        requires_sni,
    }
}

/// Probe order for an unknown path: the untouched baseline first. The order is
/// also the live-stats slot table (`src/LiveStats.cpp`): never reorder it.
pub const PROFILES: [Profile; 12] = [
    profile(
        "none",
        "Send the ClientHello untouched (diagnostic baseline)",
        false,
    ),
    profile(
        "sni-mid",
        "Split one TLS record in the middle of the SNI hostname",
        true,
    ),
    profile(
        "record-1",
        "Split after the first payload byte (cuts the handshake header)",
        false,
    ),
    profile(
        "packet-reverse",
        "Send TCP ClientHello segments in reverse sequence order",
        false,
    ),
    profile(
        "packet-ipfrag",
        "Split the IPv4 packet below TCP (IPv6 uses reverse disorder)",
        false,
    ),
    profile(
        "packet-fake-badseq",
        "Precede ClientHello with an out-of-window cover SNI",
        false,
    ),
    profile(
        "packet-autottl",
        "Expire a cover ClientHello immediately before the server",
        false,
    ),
    profile(
        "packet-seqovl",
        "Mix cover bytes into an out-of-order sequence overlap",
        false,
    ),
    profile(
        "sni-pre",
        "Split immediately before the SNI hostname starts",
        true,
    ),
    profile(
        "sni-multi",
        "Four cuts: header, before, inside and after the hostname",
        true,
    ),
    profile(
        "packet-fake-badsum",
        "Precede ClientHello with an invalid-checksum cover SNI",
        false,
    ),
    profile(
        "sni-mid-slow",
        "SNI split plus 4-byte writes and a longer pause",
        true,
    ),
];

const SLOW_PROFILE_MIN_DELAY_MS: u32 = 40;

pub fn find_profile(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

/// A concrete set of cuts for one ClientHello.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FragmentPlan {
    /// Offsets within the record payload where a new TLS record starts.
    /// Ascending, deduplicated, strictly inside the payload.
    pub record_splits: Vec<usize>,
    /// If non-zero, each record is written in pieces of at most this many bytes.
    pub write_chunk: usize,
    /// Pause between records; keeps segments from coalescing.
    pub delay_ms: u32,
}

impl FragmentPlan {
    pub fn splits_anything(&self) -> bool {
        !self.record_splits.is_empty()
    }
}

/// Turns a profile into a plan for this hello. None when the profile cannot
/// apply (needs a missing SNI, or the record is too small to cut).
pub fn build_plan(
    profile_name: &str,
    hello: &ClientHello,
    base_delay_ms: u32,
) -> Option<FragmentPlan> {
    let profile = find_profile(profile_name)?;
    if profile_name == "none" || profile_name.starts_with("packet-") {
        return Some(FragmentPlan::default());
    }
    // A hello the client already split must be forwarded byte for byte. The ECH
    // extension alone is no reason to skip: Chromium sends GREASE ECH.
    if hello.spans_records || (profile.requires_sni && !hello.has_sni()) {
        return None;
    }
    let payload_length = hello.record_payload_length;
    if payload_length < 2 {
        return None;
    }

    // SNI offsets are absolute; the plan speaks in payload offsets.
    let sni_start = if hello.has_sni() {
        hello.sni_offset - RECORD_HEADER_SIZE
    } else {
        0
    };
    let sni_middle = sni_start + hello.sni_length / 2;
    let sni_end = sni_start + hello.sni_length;

    let mut plan = FragmentPlan {
        delay_ms: base_delay_ms,
        ..FragmentPlan::default()
    };
    plan.record_splits = match profile_name {
        "sni-mid" => vec![sni_middle],
        "record-1" => vec![1],
        "sni-pre" => vec![sni_start],
        "sni-multi" => vec![1, sni_start, sni_middle, sni_end],
        "sni-mid-slow" => {
            plan.write_chunk = 4;
            plan.delay_ms = (base_delay_ms * 2).max(SLOW_PROFILE_MIN_DELAY_MS);
            vec![sni_middle]
        }
        _ => return None,
    };
    plan.record_splits
        .retain(|&s| (1..payload_length).contains(&s));
    plan.record_splits.sort_unstable();
    plan.record_splits.dedup();
    plan.splits_anything().then_some(plan)
}

/// Lowercased, trailing-dot-stripped host used as the store key.
pub fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

pub fn scope_key(network_id: &str, host: &str) -> String {
    let network = if network_id.is_empty() {
        DEFAULT_NETWORK
    } else {
        network_id
    };
    format!("{network}|{}", normalize_host(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_proto::testing::{HelloOptions, build_client_hello};
    use sh_proto::tls::parse_client_hello;

    pub(crate) fn hello_for(options: &HelloOptions) -> (Vec<u8>, ClientHello) {
        let data = build_client_hello(options);
        let mut hello = ClientHello::default();
        parse_client_hello(&data, &mut hello);
        (data, hello)
    }

    #[test]
    fn sni_mid_splits_inside_the_hostname() {
        let (_, hello) = hello_for(&HelloOptions::default());
        let plan = build_plan("sni-mid", &hello, 20).expect("applies");
        assert_eq!(plan.record_splits.len(), 1);
        let sni_start = hello.sni_offset - RECORD_HEADER_SIZE;
        assert!(plan.record_splits[0] > sni_start);
        assert!(plan.record_splits[0] < sni_start + hello.sni_length);
    }

    #[test]
    fn every_split_stays_inside_the_record() {
        let (_, hello) = hello_for(&HelloOptions {
            padding_bytes: 2000,
            ..Default::default()
        });
        for profile in PROFILES {
            let Some(plan) = build_plan(profile.name, &hello, 20) else {
                continue;
            };
            for &split in &plan.record_splits {
                assert!(split >= 1 && split < hello.record_payload_length);
            }
            assert!(plan.record_splits.windows(2).all(|w| w[0] < w[1]));
        }
    }

    #[test]
    fn none_profile_makes_no_cuts() {
        let (_, hello) = hello_for(&HelloOptions::default());
        assert!(
            !build_plan("none", &hello, 20)
                .expect("applies")
                .splits_anything()
        );
    }

    #[test]
    fn unknown_profile_is_rejected() {
        let (_, hello) = hello_for(&HelloOptions::default());
        assert!(build_plan("does-not-exist", &hello, 20).is_none());
        assert!(find_profile("does-not-exist").is_none());
    }

    #[test]
    fn already_fragmented_hello_is_left_alone() {
        let mut data = build_client_hello(&HelloOptions::default());
        let half = (data.len() - RECORD_HEADER_SIZE) / 2;
        data[3] = (half >> 8) as u8;
        data[4] = half as u8;
        data.truncate(RECORD_HEADER_SIZE + half);
        let mut hello = ClientHello::default();
        parse_client_hello(&data, &mut hello);
        assert!(hello.spans_records);
        assert!(build_plan("record-1", &hello, 20).is_none());
    }

    #[test]
    fn host_normalisation() {
        assert_eq!(normalize_host("Discord.COM."), "discord.com");
        assert_eq!(normalize_host("example.org"), "example.org");
        assert_eq!(normalize_host(""), "");
    }

    #[test]
    fn profile_table_order_matches_the_live_stats_slots() {
        let names: Vec<_> = PROFILES.iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            [
                "none",
                "sni-mid",
                "record-1",
                "packet-reverse",
                "packet-ipfrag",
                "packet-fake-badseq",
                "packet-autottl",
                "packet-seqovl",
                "sni-pre",
                "sni-multi",
                "packet-fake-badsum",
                "sni-mid-slow",
            ]
        );
    }
}
