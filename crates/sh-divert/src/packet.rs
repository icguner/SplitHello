//! Pure IPv4/IPv6 + TCP/UDP parsing, checksums and packet variants: the
//! subset of `WinDivertHelperParsePacket` / `WinDivertHelperCalcChecksums` the
//! packet loop needs, plus `src/WinDivertPacket.cpp`. No I/O, so the whole
//! rewrite path is testable without the driver.

use sh_flow::PeerAddr;

/// `WINDIVERT_MTU_MAX`: the largest packet the driver hands out.
pub const MTU_MAX: usize = 40 + 0xFFFF;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const IPV6_HEADER: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Offsets into one packet. `transport` is None for anything the loop
/// forwards untouched (other protocols, IPv4 fragments, IPv6 fragment headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parsed {
    pub ipv6: bool,
    pub transport: Option<Transport>,
    pub transport_offset: usize,
    pub payload_offset: usize,
}

/// Wire length of the first packet in `data` (a receive batch is several
/// packets back to back), or None when the header is not a sane IP header.
pub fn packet_len(data: &[u8]) -> Option<usize> {
    let length = match data.first()? >> 4 {
        4 if data.len() >= 20 => usize::from(u16::from_be_bytes([data[2], data[3]])),
        6 if data.len() >= IPV6_HEADER => {
            IPV6_HEADER + usize::from(u16::from_be_bytes([data[4], data[5]]))
        }
        _ => return None,
    };
    (length >= 20 && length <= data.len()).then_some(length)
}

/// Parses exactly one packet (as cut by `packet_len`).
pub fn parse(data: &[u8]) -> Option<Parsed> {
    let (ipv6, mut protocol, transport_offset) = match data.first()? >> 4 {
        4 => {
            let header = usize::from(data[0] & 0x0F) * 4;
            if header < 20 || header > data.len() {
                return None;
            }
            // Only the first fragment carries the transport header, and a
            // fragmented first packet never belongs to a flow we rewrite.
            let fragment = u16::from_be_bytes([data[6], data[7]]);
            let protocol = if fragment & 0x3FFF != 0 { 0 } else { data[9] };
            (false, protocol, header)
        }
        6 if data.len() >= IPV6_HEADER => {
            let mut next = data[6];
            let mut offset = IPV6_HEADER;
            // Hop-by-hop, routing and destination options; a fragment header
            // (44) or anything else ends the walk as "not ours".
            while matches!(next, 0 | 43 | 60) {
                let header = data.get(offset..offset + 2)?;
                next = header[0];
                offset += (usize::from(header[1]) + 1) * 8;
            }
            (true, next, offset)
        }
        _ => return None,
    };
    if transport_offset > data.len() {
        protocol = 0;
    }
    let (transport, payload_offset) = match protocol {
        PROTO_TCP if data.len() >= transport_offset + 20 => {
            let header = usize::from(data[transport_offset + 12] >> 4) * 4;
            if header < 20 || transport_offset + header > data.len() {
                return None;
            }
            (Some(Transport::Tcp), transport_offset + header)
        }
        PROTO_UDP if data.len() >= transport_offset + 8 => {
            (Some(Transport::Udp), transport_offset + 8)
        }
        _ => (None, data.len()),
    };
    Some(Parsed {
        ipv6,
        transport,
        transport_offset,
        payload_offset,
    })
}

fn be16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

pub fn source_port(data: &[u8], p: &Parsed) -> u16 {
    be16(data, p.transport_offset)
}

pub fn destination_port(data: &[u8], p: &Parsed) -> u16 {
    be16(data, p.transport_offset + 2)
}

pub fn set_source_port(data: &mut [u8], p: &Parsed, port: u16) {
    put16(data, p.transport_offset, port);
}

pub fn set_destination_port(data: &mut [u8], p: &Parsed, port: u16) {
    put16(data, p.transport_offset + 2, port);
}

pub fn tcp_flags(data: &[u8], p: &Parsed) -> u8 {
    data[p.transport_offset + 13]
}

pub fn tcp_sequence(data: &[u8], p: &Parsed) -> u32 {
    let at = p.transport_offset + 4;
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn address_range(p: &Parsed, destination: bool) -> std::ops::Range<usize> {
    match (p.ipv6, destination) {
        (false, false) => 12..16,
        (false, true) => 16..20,
        (true, false) => 8..24,
        (true, true) => 24..40,
    }
}

pub fn address(data: &[u8], p: &Parsed, destination: bool) -> PeerAddr {
    let bytes = &data[address_range(p, destination)];
    match bytes.try_into() {
        Ok(v4) => PeerAddr::from_v4_bytes(v4),
        Err(_) => PeerAddr::from_v6_bytes(bytes.try_into().unwrap_or([0; 16])),
    }
}

/// Raw address bytes (4 or 16) for the process-owner tables.
pub fn address_bytes(data: &[u8], p: &Parsed, destination: bool) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = &data[address_range(p, destination)];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

pub fn swap_addresses(data: &mut [u8], p: &Parsed) {
    let (source, destination) = (address_range(p, false), address_range(p, true));
    let length = source.len();
    let (head, tail) = data.split_at_mut(destination.start);
    head[source].swap_with_slice(&mut tail[..length]);
}

pub fn ttl(data: &[u8], p: &Parsed) -> u8 {
    data[if p.ipv6 { 7 } else { 8 }]
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

fn add_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    // Keeps the accumulator from overflowing on jumbo-sized inputs.
    u32::from(fold(sum))
}

/// Recomputes the IPv4 header and TCP/UDP checksums in place (what
/// `WinDivertHelperCalcChecksums` does for the packets we rewrite).
pub fn fix_checksums(data: &mut [u8], p: &Parsed) {
    if !p.ipv6 {
        let header = p.transport_offset;
        put16(data, 10, 0);
        let sum = !fold(add_words(0, &data[..header]));
        put16(data, 10, sum);
    }
    let Some(transport) = p.transport else {
        return;
    };
    let checksum_at = p.transport_offset + if transport == Transport::Tcp { 16 } else { 6 };
    put16(data, checksum_at, 0);
    let segment_len = data.len() - p.transport_offset;
    let protocol = if transport == Transport::Tcp {
        PROTO_TCP
    } else {
        PROTO_UDP
    };
    let source = address_range(p, false);
    let destination = address_range(p, true);
    let mut sum = add_words(0, &data[source]);
    sum = add_words(sum, &data[destination]);
    sum += u32::from(protocol);
    sum += (segment_len as u32) >> 16;
    sum += (segment_len as u32) & 0xFFFF;
    sum = add_words(sum, &data[p.transport_offset..]);
    let mut checksum = !fold(sum);
    if transport == Transport::Udp && checksum == 0 {
        checksum = 0xFFFF; // zero means "no checksum" for UDP
    }
    put16(data, checksum_at, checksum);
}

/// Copy of `packet` with its payload replaced, lengths and checksums fixed
/// (port of `buildTcpVariant` / `buildUdpVariant`). TCP only: the sequence is
/// shifted by `sequence_offset`, a non-zero `ttl` overrides TTL / hop limit,
/// and `corrupt_checksum` flips the TCP checksum afterwards.
pub fn build_variant(
    packet: &[u8],
    p: &Parsed,
    replacement: &[u8],
    sequence_offset: i32,
    ttl: u8,
    corrupt_checksum: bool,
) -> Option<Vec<u8>> {
    let transport = p.transport?;
    let total = p.payload_offset + replacement.len();
    if total > MTU_MAX {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&packet[..p.payload_offset]);
    out.extend_from_slice(replacement);

    if p.ipv6 {
        put16(&mut out, 4, u16::try_from(total - IPV6_HEADER).ok()?);
    } else {
        put16(&mut out, 2, u16::try_from(total).ok()?);
    }
    match transport {
        Transport::Tcp => {
            if ttl != 0 {
                out[if p.ipv6 { 7 } else { 8 }] = ttl;
            }
            let sequence = tcp_sequence(&out, p).wrapping_add(sequence_offset as u32);
            let at = p.transport_offset + 4;
            out[at..at + 4].copy_from_slice(&sequence.to_be_bytes());
        }
        Transport::Udp => {
            let length = u16::try_from(total - p.transport_offset).ok()?;
            put16(&mut out, p.transport_offset + 4, length);
        }
    }
    fix_checksums(&mut out, p);
    if corrupt_checksum && transport == Transport::Tcp {
        let at = p.transport_offset + 16;
        let value = be16(&out, at) ^ 0xFFFF;
        put16(&mut out, at, value);
    }
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a minimal IPv4 or IPv6 TCP/UDP packet with valid checksums.
    pub(crate) fn build(
        ipv6: bool,
        tcp: bool,
        source: (&str, u16),
        destination: (&str, u16),
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let transport_len = if tcp { 20 } else { 8 };
        let mut out = Vec::new();
        let total;
        if ipv6 {
            total = IPV6_HEADER + transport_len + payload.len();
            out.extend([0x60, 0, 0, 0]);
            out.extend(((total - IPV6_HEADER) as u16).to_be_bytes());
            out.push(if tcp { PROTO_TCP } else { PROTO_UDP });
            out.push(64);
            for text in [source.0, destination.0] {
                let ip: std::net::Ipv6Addr = text.parse().unwrap();
                out.extend(ip.octets());
            }
        } else {
            total = 20 + transport_len + payload.len();
            out.extend([0x45, 0]);
            out.extend((total as u16).to_be_bytes());
            out.extend([
                0x12,
                0x34,
                0x40,
                0,
                64,
                if tcp { PROTO_TCP } else { PROTO_UDP },
                0,
                0,
            ]);
            for text in [source.0, destination.0] {
                let ip: std::net::Ipv4Addr = text.parse().unwrap();
                out.extend(ip.octets());
            }
        }
        out.extend(source.1.to_be_bytes());
        out.extend(destination.1.to_be_bytes());
        if tcp {
            out.extend(1000u32.to_be_bytes()); // seq
            out.extend(0u32.to_be_bytes()); // ack
            out.extend([0x50, flags, 0xFF, 0xFF, 0, 0, 0, 0]);
        } else {
            out.extend(((8 + payload.len()) as u16).to_be_bytes());
            out.extend([0, 0]);
        }
        out.extend(payload);
        let parsed = parse(&out).unwrap();
        fix_checksums(&mut out, &parsed);
        out
    }

    /// Independent check: a correct checksum sums (with the pseudo header) to 0xFFFF.
    fn transport_sum_ok(data: &[u8], p: &Parsed) -> bool {
        let segment = &data[p.transport_offset..];
        let mut sum = add_words(0, &data[address_range(p, false)]);
        sum = add_words(sum, &data[address_range(p, true)]);
        sum += u32::from(if p.transport == Some(Transport::Tcp) {
            6u8
        } else {
            17
        });
        sum += segment.len() as u32;
        fold(add_words(sum, segment)) == 0xFFFF
    }

    #[test]
    fn known_ipv4_header_checksum() {
        // Classic example header (checksum 0xB861).
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ]
        .to_vec();
        header.resize(0x73, 0);
        header[20..22].copy_from_slice(&1u16.to_be_bytes());
        let parsed = parse(&header).unwrap();
        fix_checksums(&mut header, &parsed);
        assert_eq!(be16(&header, 10), 0xB861);
    }

    #[test]
    fn parses_and_checksums_all_four_shapes() {
        for (ipv6, tcp) in [(false, true), (false, false), (true, true), (true, false)] {
            let (a, b) = if ipv6 {
                ("2001:db8::1", "2001:db8::2")
            } else {
                ("10.0.0.1", "10.0.0.2")
            };
            let packet = build(ipv6, tcp, (a, 50000), (b, 443), TCP_SYN, b"hello");
            assert_eq!(packet_len(&packet), Some(packet.len()));
            let p = parse(&packet).unwrap();
            assert_eq!(p.ipv6, ipv6);
            assert_eq!(&packet[p.payload_offset..], b"hello");
            assert_eq!(source_port(&packet, &p), 50000);
            assert_eq!(destination_port(&packet, &p), 443);
            assert!(transport_sum_ok(&packet, &p), "ipv6={ipv6} tcp={tcp}");
            assert_eq!(address(&packet, &p, true), PeerAddr::parse(b).unwrap());
        }
    }

    #[test]
    fn swap_and_rewrite_keep_checksums_valid() {
        let mut packet = build(
            false,
            true,
            ("10.0.0.1", 50000),
            ("1.2.3.4", 443),
            TCP_ACK,
            b"x",
        );
        let p = parse(&packet).unwrap();
        swap_addresses(&mut packet, &p);
        set_destination_port(&mut packet, &p, 1080);
        fix_checksums(&mut packet, &p);
        assert_eq!(
            address(&packet, &p, false),
            PeerAddr::parse("1.2.3.4").unwrap()
        );
        assert_eq!(
            address(&packet, &p, true),
            PeerAddr::parse("10.0.0.1").unwrap()
        );
        assert!(transport_sum_ok(&packet, &p));
        assert_eq!(fold(add_words(0, &packet[..20])), 0xFFFF);
    }

    #[test]
    fn tcp_variant_moves_sequence_and_can_corrupt() {
        let packet = build(
            true,
            true,
            ("2001:db8::1", 5),
            ("2001:db8::2", 443),
            TCP_ACK,
            b"abc",
        );
        let p = parse(&packet).unwrap();
        let variant = build_variant(&packet, &p, b"longer payload", -10, 3, false).unwrap();
        assert_eq!(packet_len(&variant), Some(variant.len()));
        assert_eq!(tcp_sequence(&variant, &p), 990);
        assert_eq!(ttl(&variant, &p), 3);
        assert!(transport_sum_ok(&variant, &p));
        let broken = build_variant(&packet, &p, b"x", 0, 0, true).unwrap();
        assert!(!transport_sum_ok(&broken, &p));
    }

    #[test]
    fn udp_variant_fixes_udp_length() {
        let packet = build(false, false, ("10.0.0.1", 5000), ("1.1.1.1", 443), 0, b"q");
        let p = parse(&packet).unwrap();
        let variant = build_variant(&packet, &p, &[7; 100], 0, 0, false).unwrap();
        assert_eq!(be16(&variant, p.transport_offset + 4), 108);
        assert!(transport_sum_ok(&variant, &p));
    }

    #[test]
    fn rejects_garbage_and_fragments() {
        assert_eq!(packet_len(&[0x45, 0, 0, 10]), None);
        assert!(parse(&[0x30; 40]).is_none());
        let mut packet = build(false, true, ("10.0.0.1", 1), ("10.0.0.2", 443), 0, b"");
        packet[6] = 0x20; // More Fragments
        assert_eq!(parse(&packet).unwrap().transport, None);
    }
}
