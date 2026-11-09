//! Pure packet-level strategy logic (port of the builders in
//! `src/PacketStrategy.cpp`): which profile maps to which wire transformation,
//! where to cut, and how to build segments and IPv4 fragments.

use crate::tls::ClientHello;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    None,
    ReverseOrder,
    FakeBadSequence,
    FakeBadChecksum,
    FakeAutoTtl,
    SequenceOverlap,
    IpFragment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    pub split_offset: usize,
    pub overlap_bytes: usize,
    pub fake_sequence_delta: i32,
    pub fake_ttl: u8,
    pub cover_sni: String,
    /// Stream offsets of the hostname inside the first ClientHello record
    /// (`sni_end == 0`: unknown). A split outside them cannot hide the SNI, so
    /// it must not count as an applied profile.
    pub sni_begin: usize,
    pub sni_end: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::None,
            split_offset: 2,
            overlap_bytes: 8,
            fake_sequence_delta: -10000,
            fake_ttl: 0,
            cover_sni: "www.google.com".into(),
            sni_begin: 0,
            sni_end: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub sequence_offset: i32,
    pub payload: Vec<u8>,
}

pub fn is_packet_profile(profile: &str) -> bool {
    profile.starts_with("packet-")
}

pub fn policy_for_profile(profile: &str, hello: &ClientHello) -> Option<Policy> {
    let mode = match profile {
        "packet-reverse" => Mode::ReverseOrder,
        "packet-fake-badseq" => Mode::FakeBadSequence,
        "packet-fake-badsum" => Mode::FakeBadChecksum,
        "packet-autottl" => Mode::FakeAutoTtl,
        "packet-seqovl" => Mode::SequenceOverlap,
        "packet-ipfrag" => Mode::IpFragment,
        _ => return None,
    };
    let preferred_split = if hello.has_sni() {
        hello.sni_offset + hello.sni_length / 2
    } else {
        2
    };
    let mut policy = Policy {
        mode,
        // The ClientHello may span several IP packets; the interceptor clamps
        // this stream-relative hint into the first packet.
        split_offset: preferred_split.max(2),
        ..Policy::default()
    };
    if hello.has_sni() {
        policy.sni_begin = hello.sni_offset;
        policy.sni_end = hello.sni_offset + hello.sni_length;
    }
    Some(policy)
}

/// A minimal TLS 1.3 ClientHello for `hostname` (the decoy in fake profiles).
pub fn build_fake_client_hello(hostname: &str) -> Vec<u8> {
    let name = hostname.as_bytes();
    if name.is_empty() || name.len() > 253 {
        return Vec::new();
    }
    let mut extensions = Vec::new();
    extensions.extend(0x0000u16.to_be_bytes()); // server_name
    extensions.extend(((name.len() + 5) as u16).to_be_bytes());
    extensions.extend(((name.len() + 3) as u16).to_be_bytes());
    extensions.push(0);
    extensions.extend((name.len() as u16).to_be_bytes());
    extensions.extend(name);
    extensions.extend(0x002bu16.to_be_bytes()); // supported_versions
    extensions.extend(3u16.to_be_bytes());
    extensions.push(2);
    extensions.extend(0x0304u16.to_be_bytes());

    let mut body = Vec::new();
    body.extend(0x0303u16.to_be_bytes());
    body.extend(1..=32u8);
    body.push(0); // session id
    body.extend(2u16.to_be_bytes()); // cipher suites length
    body.extend(0x1301u16.to_be_bytes()); // TLS_AES_128_GCM_SHA256
    body.extend([1, 0]); // compression methods
    body.extend((extensions.len() as u16).to_be_bytes());
    body.extend(extensions);

    let mut handshake = vec![1]; // ClientHello
    handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

/// The payload offset `build_segments` cuts at for a payload of `length` bytes.
pub fn segment_split(policy: &Policy, length: usize) -> usize {
    if length < 2 {
        0
    } else {
        policy.split_offset.clamp(1, length - 1)
    }
}

/// True when `split` falls strictly inside the SNI (or the SNI is unknown).
pub fn splits_sni(policy: &Policy, split: usize) -> bool {
    policy.sni_end == 0 || (split > policy.sni_begin && split < policy.sni_end)
}

pub fn build_segments(payload: &[u8], policy: &Policy) -> Vec<Segment> {
    if payload.len() < 2 {
        return Vec::new();
    }
    let split = segment_split(policy, payload.len());
    match policy.mode {
        Mode::ReverseOrder => vec![
            Segment {
                sequence_offset: split as i32,
                payload: payload[split..].to_vec(),
            },
            Segment {
                sequence_offset: 0,
                payload: payload[..split].to_vec(),
            },
        ],
        Mode::SequenceOverlap => {
            let overlap = policy.overlap_bytes.clamp(1, split);
            let fake = build_fake_client_hello(&policy.cover_sni);
            let mut second = Vec::with_capacity(overlap + payload.len() - split);
            second.extend((0..overlap).map(|i| {
                if fake.is_empty() {
                    0x20
                } else {
                    fake[i % fake.len()]
                }
            }));
            second.extend(&payload[split..]);
            vec![
                Segment {
                    sequence_offset: (split - overlap) as i32,
                    payload: second,
                },
                Segment {
                    sequence_offset: 0,
                    payload: payload[..split].to_vec(),
                },
            ]
        }
        _ => Vec::new(),
    }
}

/// IPv4 fragment offsets are multiples of 8 from the start of the IP payload.
/// Returns that boundary (bytes from the IP payload start) closest to the
/// policy's split that still lies inside the SNI, or 0 when none exists.
pub fn ipv4_fragment_boundary(
    transport_header_len: usize,
    policy: &Policy,
    payload_len: usize,
) -> usize {
    if payload_len < 2 {
        return 0;
    }
    // Cut offsets that leave bytes on both sides, and that cut the hostname.
    let mut lo = 1;
    let mut hi = payload_len - 1;
    if policy.sni_end > policy.sni_begin {
        lo = lo.max(policy.sni_begin + 1);
        hi = hi.min(policy.sni_end - 1);
    }
    if lo > hi {
        return 0;
    }
    let target = transport_header_len + policy.split_offset.clamp(lo, hi);
    let down = target & !7;
    let up = (target + 7) & !7;
    let mut best: usize = 0;
    for candidate in [down, up] {
        if candidate < transport_header_len + lo || candidate > transport_header_len + hi {
            continue;
        }
        if best == 0 || candidate.abs_diff(target) < best.abs_diff(target) {
            best = candidate;
        }
    }
    best
}

/// Splits an unfragmented IPv4 packet into two fragments, the first ending at
/// `first_fragment_end` (rounded up to the 8-byte grid). Empty when the packet
/// cannot be fragmented.
pub fn build_ipv4_fragments(
    packet: &[u8],
    ip_header_len: usize,
    first_fragment_end: usize,
) -> Vec<Vec<u8>> {
    let length = packet.len();
    if length > 0xFFFF
        || ip_header_len < 20
        || ip_header_len > length
        || first_fragment_end <= ip_header_len
        || first_fragment_end >= length
        || packet[0] >> 4 != 4
    {
        return Vec::new();
    }
    let existing_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if existing_fragment & 0x3FFF != 0 {
        return Vec::new();
    }

    let ip_payload_len = length - ip_header_len;
    let first_payload_len = (first_fragment_end - ip_header_len + 7) & !7;
    if first_payload_len == 0 || first_payload_len >= ip_payload_len {
        return Vec::new();
    }

    let mut first = packet[..ip_header_len + first_payload_len].to_vec();
    let mut second = packet[..ip_header_len].to_vec();
    second.extend(&packet[ip_header_len + first_payload_len..]);

    let finish = |fragment: &mut Vec<u8>, fragment_field: u16| {
        let total = fragment.len() as u16;
        fragment[2..4].copy_from_slice(&total.to_be_bytes());
        fragment[6..8].copy_from_slice(&fragment_field.to_be_bytes());
        fragment[10..12].copy_from_slice(&[0, 0]);
        let checksum = ipv4_header_checksum(&fragment[..ip_header_len]);
        fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
    };
    finish(&mut first, 0x2000); // More Fragments
    finish(&mut second, (first_payload_len / 8) as u16);
    vec![first, second]
}

/// Internet checksum over an IPv4 header whose checksum field is zero.
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{HelloOptions, build_client_hello};
    use crate::tls::{ParseStatus, parse_client_hello};

    #[test]
    fn builds_parseable_cover_client_hello() {
        let fake = build_fake_client_hello("www.google.com");
        let mut parsed = ClientHello::default();
        assert_eq!(parse_client_hello(&fake, &mut parsed), ParseStatus::Ok);
        assert_eq!(parsed.server_name, "www.google.com");
    }

    #[test]
    fn reverse_segments_preserve_tcp_byte_stream() {
        let payload = [0, 1, 2, 3, 4, 5];
        let policy = Policy {
            mode: Mode::ReverseOrder,
            split_offset: 2,
            ..Policy::default()
        };
        let segments = build_segments(&payload, &policy);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].sequence_offset, 2);
        assert_eq!(segments[0].payload.len(), 4);
        assert_eq!(segments[1].sequence_offset, 0);
        assert_eq!(segments[1].payload.len(), 2);
        assert_eq!(segments[0].payload[0], 2);
        assert_eq!(segments[1].payload[1], 1);
    }

    #[test]
    fn sequence_overlap_precedes_real_second_segment() {
        let payload = [0, 1, 2, 3, 4, 5];
        let policy = Policy {
            mode: Mode::SequenceOverlap,
            split_offset: 4,
            overlap_bytes: 2,
            ..Policy::default()
        };
        let segments = build_segments(&payload, &policy);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].sequence_offset, 2);
        assert_eq!(segments[0].payload.len(), 4);
        assert_eq!(segments[1].payload.len(), 4);
        assert_eq!(segments[0].payload[2], 4);
    }

    #[test]
    fn policy_keeps_the_hostname_bounds_it_was_built_for() {
        let data = build_client_hello(&HelloOptions::default());
        let mut hello = ClientHello::default();
        assert_eq!(parse_client_hello(&data, &mut hello), ParseStatus::Ok);

        let policy = policy_for_profile("packet-reverse", &hello).expect("packet profile");
        assert_eq!(policy.sni_begin, hello.sni_offset);
        assert_eq!(policy.sni_end, hello.sni_offset + hello.sni_length);
        assert!(splits_sni(&policy, policy.split_offset));
        assert!(!splits_sni(&policy, policy.sni_begin));
        assert!(!splits_sni(&policy, policy.sni_end));
        // A hostname that starts past the first packet is cut at the packet's
        // last byte, which is outside the hostname.
        assert!(!splits_sni(
            &policy,
            segment_split(&policy, policy.sni_begin)
        ));

        assert!(splits_sni(&Policy::default(), 1));
        assert!(policy_for_profile("sni-mid", &hello).is_none());
    }

    #[test]
    fn ipv4_fragment_boundary_stays_inside_the_hostname_on_an_eight_byte_grid() {
        let mut policy = Policy {
            sni_begin: 10,
            sni_end: 30,
            split_offset: 20,
            ..Policy::default()
        };
        // 20-byte TCP header: stream offset 20 is IP-payload offset 40.
        assert_eq!(ipv4_fragment_boundary(20, &policy, 100), 40);

        // Four-byte hostname: only IP-payload offset 32 (stream 12) fits inside.
        (policy.sni_begin, policy.sni_end, policy.split_offset) = (10, 14, 12);
        let boundary = ipv4_fragment_boundary(20, &policy, 100);
        assert_eq!(boundary, 32);
        assert!(splits_sni(&policy, boundary - 20));

        // A two-character hostname has no multiple-of-8 cut inside it.
        (policy.sni_begin, policy.sni_end, policy.split_offset) = (10, 12, 11);
        assert_eq!(ipv4_fragment_boundary(20, &policy, 100), 0);

        // Hostname beyond the packet: nothing to cut.
        (policy.sni_begin, policy.sni_end, policy.split_offset) = (200, 220, 210);
        assert_eq!(ipv4_fragment_boundary(20, &policy, 100), 0);
    }

    #[test]
    fn ipv4_fragmentation_builds_aligned_reassemblable_pieces() {
        let mut packet = vec![0u8; 104];
        packet[0] = 0x45;
        packet[3] = packet.len() as u8;
        packet[8] = 64;
        packet[9] = 6;
        for (i, byte) in packet.iter_mut().enumerate().skip(20) {
            *byte = i as u8;
        }
        let fragments = build_ipv4_fragments(&packet, 20, 50);
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].len(), 52);
        assert_eq!(fragments[1].len(), 72);
        assert_ne!(fragments[0][6] & 0x20, 0);
        assert_eq!(fragments[1][6], 0);
        assert_eq!(fragments[1][7], 4);
        assert_eq!(fragments[0][20], packet[20]);
        assert_eq!(fragments[1][20], packet[52]);
        assert!(fragments[0][10] != 0 || fragments[0][11] != 0);
        // A correct header checksum sums to zero.
        assert_eq!(ipv4_header_checksum(&fragments[0][..20]), 0);
        assert_eq!(ipv4_header_checksum(&fragments[1][..20]), 0);
    }
}
