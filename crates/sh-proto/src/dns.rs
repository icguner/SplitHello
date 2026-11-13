//! DNS wire messages (port of `src/DnsMessage.cpp`): query parsing, answer
//! building, and helpers for relayed responses. Every read is bounds-checked;
//! offsets only move forward.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;

pub const RCODE_NO_ERROR: u8 = 0;
pub const RCODE_FORM_ERR: u8 = 1;
pub const RCODE_SERV_FAIL: u8 = 2;
pub const RCODE_NX_DOMAIN: u8 = 3;
pub const RCODE_NOT_IMP: u8 = 4;

/// A UDP client without an EDNS0 OPT record can only take 512 bytes (RFC 1035).
pub const CLASSIC_UDP_PAYLOAD: usize = 512;

const HEADER_SIZE: usize = 12;
const CLASS_INTERNET: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_TXT: u16 = 16;
const TYPE_OPT: u16 = 41;
const TYPE_RRSIG: u16 = 46;
const SVC_PARAM_ECH: u16 = 5;
const MAX_NAME_LENGTH: usize = 253;
const MAX_ANSWERS: usize = 8;
/// Payload size advertised in hand-built answers (DNS Flag Day 2020).
const ADVERTISED_PAYLOAD: u16 = 1232;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    pub qtype: u16,
    pub recursion_desired: bool,
    pub opcode: u8,
    /// Requestor's UDP payload size; 0 = no OPT record.
    pub edns_payload: u16,
    /// DO bit of that OPT record.
    pub dnssec_ok: bool,
    /// Set when parsing fails although the header was readable: the RCODE a
    /// reply should carry (FORMERR / NOTIMP). 0 = unrecoverable, drop silently.
    pub error: u8,
    pub name: String,
    pub question: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseInfo {
    pub response: bool,
    pub truncated: bool,
    pub rcode: u8,
    pub answers: usize,
    pub has_answer_ttl: bool,
    /// Minimum TTL over answer records (OPT excluded).
    pub answer_ttl: u32,
    pub has_authority_ttl: bool,
    /// Minimum TTL over authority records (SOA).
    pub authority_ttl: u32,
}

fn read16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

fn read32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

fn write16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

fn is_name_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_'
}

/// Pulls the requestor's payload size / DO bit out of an OPT record in the
/// additional section. Tolerant: a malformed tail only means "no EDNS".
fn parse_edns(data: &[u8], mut offset: usize, out: &mut Query) {
    if read16(data, 6) != 0 || read16(data, 8) != 0 {
        return;
    }
    for _ in 0..read16(data, 10) {
        // Only a root-named record can be OPT; anything else ends the scan.
        if offset + 11 > data.len() || data[offset] != 0 {
            return;
        }
        let rtype = read16(data, offset + 1);
        let class = read16(data, offset + 3);
        let ttl = read32(data, offset + 5);
        let rd_length = read16(data, offset + 9) as usize;
        if offset + 11 + rd_length > data.len() {
            return;
        }
        if rtype == TYPE_OPT {
            out.edns_payload = class;
            out.dnssec_ok = ttl & 0x8000 != 0;
            return;
        }
        offset += 11 + rd_length;
    }
}

/// Advances `offset` past a (possibly compressed) name.
fn skip_name(data: &[u8], offset: &mut usize) -> bool {
    loop {
        let Some(&first) = data.get(*offset) else {
            return false;
        };
        if first == 0 {
            *offset += 1;
            return true;
        }
        if first & 0xC0 == 0xC0 {
            if *offset + 2 > data.len() {
                return false;
            }
            *offset += 2;
            return true;
        }
        if first & 0xC0 != 0 {
            return false;
        }
        *offset += 1 + first as usize;
    }
}

struct RecordRef {
    rtype: u16,
    /// 0 answer, 1 authority, 2 additional.
    section: u8,
    ttl_offset: usize,
}

/// Walks header, questions and every record. Returns the end of the question
/// section, or None for a malformed/truncated message.
fn walk(data: &[u8], records: &mut Vec<RecordRef>) -> Option<usize> {
    records.clear();
    if data.len() < HEADER_SIZE {
        return None;
    }
    let questions = read16(data, 4) as usize;
    let counts = [
        read16(data, 6) as usize,
        read16(data, 8) as usize,
        read16(data, 10) as usize,
    ];
    // Every question needs >= 5 bytes and every record >= 11: reject counts that
    // cannot fit before looping on them.
    if questions * 5 + counts.iter().sum::<usize>() * 11 > data.len() {
        return None;
    }

    let mut offset = HEADER_SIZE;
    for _ in 0..questions {
        if !skip_name(data, &mut offset) || offset + 4 > data.len() {
            return None;
        }
        offset += 4;
    }
    let question_end = offset;

    for (section, &count) in counts.iter().enumerate() {
        for _ in 0..count {
            if !skip_name(data, &mut offset) || offset + 10 > data.len() {
                return None;
            }
            let rtype = read16(data, offset);
            let ttl_offset = offset + 4;
            let rd_length = read16(data, offset + 8) as usize;
            offset += 10;
            if offset + rd_length > data.len() {
                return None;
            }
            offset += rd_length;
            records.push(RecordRef {
                rtype,
                section: section as u8,
                ttl_offset,
            });
        }
    }
    Some(question_end)
}

/// Accepts exactly one uncompressed IN question. Names are limited to
/// `[a-z0-9_-]` labels (after lowercasing): SNI-derived and application hosts
/// end up in URLs and logs, so anything else is refused here.
pub fn parse_query(data: &[u8], out: &mut Query) -> bool {
    *out = Query::default();
    if data.len() < HEADER_SIZE {
        return false;
    }
    let flags = read16(data, 2);
    if flags & 0x8000 != 0 {
        return false; // a response: never answer one
    }
    out.id = read16(data, 0);
    out.opcode = ((flags >> 11) & 0x0F) as u8;
    out.recursion_desired = flags & 0x0100 != 0;
    if out.opcode != 0 {
        out.error = RCODE_NOT_IMP;
        return false;
    }
    // Every remaining failure is a malformed query unless said otherwise.
    out.error = RCODE_FORM_ERR;
    if read16(data, 4) != 1 {
        return false;
    }

    let mut offset = HEADER_SIZE;
    let mut name = String::new();
    loop {
        let Some(&label_length) = data.get(offset) else {
            return false;
        };
        offset += 1;
        if label_length == 0 {
            break;
        }
        let label_length = label_length as usize;
        if label_length & 0xC0 != 0 || label_length > 63 || offset + label_length > data.len() {
            return false;
        }
        if !name.is_empty() {
            name.push('.');
        }
        if name.len() + label_length > MAX_NAME_LENGTH {
            return false;
        }
        for &byte in &data[offset..offset + label_length] {
            let c = byte.to_ascii_lowercase();
            if !is_name_char(c) {
                return false;
            }
            name.push(c as char);
        }
        offset += label_length;
    }

    if name.is_empty() || offset + 4 > data.len() {
        return false;
    }
    let qtype = read16(data, offset);
    let class = read16(data, offset + 2);
    offset += 4;
    if class != CLASS_INTERNET {
        out.error = RCODE_NOT_IMP;
        return false;
    }

    out.error = 0;
    out.qtype = qtype;
    out.name = name;
    out.question = data[HEADER_SIZE..offset].to_vec();
    parse_edns(data, offset, out);
    true
}

/// `failed` emits SERVFAIL (or `rcode` when given); a non-zero rcode carries no
/// answers. An empty address set without failure is NOERROR/NODATA. An OPT
/// record is appended when the query carried one.
pub fn build_response<S: AsRef<str>>(
    query: &Query,
    addresses: &[S],
    ttl_seconds: u32,
    failed: bool,
    rcode: u8,
) -> Vec<u8> {
    let effective_rcode = if failed && rcode == 0 {
        RCODE_SERV_FAIL
    } else {
        rcode
    };
    let mut encoded: Vec<Vec<u8>> = Vec::new();
    if effective_rcode == 0 {
        for address in addresses {
            let bytes = match query.qtype {
                TYPE_A => address
                    .as_ref()
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(|a| a.octets().to_vec()),
                TYPE_AAAA => address
                    .as_ref()
                    .parse::<Ipv6Addr>()
                    .ok()
                    .map(|a| a.octets().to_vec()),
                _ => None,
            };
            if let Some(bytes) = bytes {
                encoded.push(bytes);
                if encoded.len() >= MAX_ANSWERS {
                    break;
                }
            }
        }
    }

    let with_opt = query.edns_payload != 0;
    let mut out = Vec::with_capacity(HEADER_SIZE + query.question.len() + encoded.len() * 28 + 11);
    out.extend(query.id.to_be_bytes());
    let mut flags: u16 = 0x8080; // response + recursion available
    if query.recursion_desired {
        flags |= 0x0100;
    }
    flags |= u16::from(effective_rcode & 0x0F);
    out.extend(flags.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    out.extend((encoded.len() as u16).to_be_bytes());
    out.extend(0u16.to_be_bytes());
    out.extend(u16::from(with_opt).to_be_bytes());
    out.extend(&query.question);

    for address in &encoded {
        out.extend(0xC00Cu16.to_be_bytes());
        out.extend(query.qtype.to_be_bytes());
        out.extend(CLASS_INTERNET.to_be_bytes());
        out.extend(ttl_seconds.to_be_bytes());
        out.extend((address.len() as u16).to_be_bytes());
        out.extend(address);
    }
    if with_opt {
        out.push(0); // root name
        out.extend(TYPE_OPT.to_be_bytes());
        out.extend(ADVERTISED_PAYLOAD.to_be_bytes()); // CLASS = UDP payload size
        out.extend(0u32.to_be_bytes()); // extended RCODE, version, flags
        out.extend(0u16.to_be_bytes()); // no options
    }
    out
}

/// The answer for a name on a protection list. A sinkhole address makes
/// connect() fail at once; NXDOMAIN would send some apps to another resolver.
/// Other types get NOERROR/NODATA.
pub fn build_blocked(query: &Query) -> Vec<u8> {
    let sink: &[&str] = match query.qtype {
        TYPE_A => &["0.0.0.0"],
        TYPE_AAAA => &["::"],
        _ => &[],
    };
    build_response(query, sink, 30, false, 0)
}

/// Header-only error reply for a query that failed to parse.
pub fn build_error(query: &Query, rcode: u8) -> Vec<u8> {
    let mut flags: u16 = 0x8080 | (u16::from(query.opcode & 0x0F) << 11);
    if query.recursion_desired {
        flags |= 0x0100;
    }
    flags |= u16::from(rcode & 0x0F);
    let mut out = Vec::with_capacity(HEADER_SIZE);
    out.extend(query.id.to_be_bytes());
    out.extend(flags.to_be_bytes());
    out.extend([0u8; 8]);
    out
}

/// Bounds-checked walk of a whole message. None if malformed/truncated.
pub fn inspect_response(data: &[u8]) -> Option<ResponseInfo> {
    let mut records = Vec::new();
    walk(data, &mut records)?;
    let flags = read16(data, 2);
    let mut info = ResponseInfo {
        response: flags & 0x8000 != 0,
        truncated: flags & 0x0200 != 0,
        rcode: (flags & 0x000F) as u8,
        answers: read16(data, 6) as usize,
        ..Default::default()
    };
    for record in records.iter().filter(|r| r.rtype != TYPE_OPT) {
        let ttl = read32(data, record.ttl_offset);
        match record.section {
            0 => {
                info.answer_ttl = if info.has_answer_ttl {
                    info.answer_ttl.min(ttl)
                } else {
                    ttl
                };
                info.has_answer_ttl = true;
            }
            1 => {
                info.authority_ttl = if info.has_authority_ttl {
                    info.authority_ttl.min(ttl)
                } else {
                    ttl
                };
                info.has_authority_ttl = true;
            }
            _ => {}
        }
    }
    Some(info)
}

/// True when `data` repeats the query's single question (ASCII case-insensitive).
pub fn echoes_question(data: &[u8], query: &Query) -> bool {
    if query.question.is_empty()
        || data.len() < HEADER_SIZE + query.question.len()
        || read16(data, 4) != 1
    {
        return false;
    }
    data[HEADER_SIZE..HEADER_SIZE + query.question.len()].eq_ignore_ascii_case(&query.question)
}

pub fn set_id(message: &mut [u8], id: u16) {
    if message.len() >= 2 {
        write16(message, 0, id);
    }
}

/// Subtracts `age_seconds` from every non-OPT TTL, never below 1 for a record
/// whose TTL was non-zero. A malformed message is left untouched.
pub fn age_ttls(message: &mut [u8], age_seconds: u32) {
    let mut records = Vec::new();
    if walk(message, &mut records).is_none() {
        return;
    }
    for record in records.iter().filter(|r| r.rtype != TYPE_OPT) {
        let at = record.ttl_offset;
        let ttl = read32(message, at);
        let aged = if ttl > age_seconds {
            ttl - age_seconds
        } else {
            u32::from(ttl > 0)
        };
        message[at..at + 4].copy_from_slice(&aged.to_be_bytes());
    }
}

/// If `message` exceeds `limit`, cuts it to header + question with TC=1 so the
/// client retries over TCP. Returns whether it truncated.
pub fn truncate_for_udp(message: &mut Vec<u8>, limit: usize) -> bool {
    if message.len() <= limit || message.len() < HEADER_SIZE {
        return false;
    }
    let mut records = Vec::new();
    let question_end = walk(message, &mut records);
    message.truncate(question_end.unwrap_or(HEADER_SIZE));
    let flags = read16(message, 2) | 0x0200;
    write16(message, 2, flags);
    if question_end.is_none() {
        write16(message, 4, 0);
    }
    for at in [6, 8, 10] {
        write16(message, at, 0);
    }
    true
}

/// Reads the name at `offset`, following compression pointers, as uncompressed
/// wire bytes. Returns the name and the offset just past it as written.
fn read_name(data: &[u8], offset: usize) -> Option<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    let mut cursor = offset;
    let mut end = None;
    let mut hops = 0;
    loop {
        let first = *data.get(cursor)?;
        if first == 0 {
            out.push(0);
            return Some((out, end.unwrap_or(cursor + 1)));
        }
        if first & 0xC0 == 0xC0 {
            hops += 1;
            if cursor + 2 > data.len() || hops > 16 {
                return None;
            }
            end.get_or_insert(cursor + 2);
            cursor = (usize::from(first & 0x3F) << 8) | usize::from(data[cursor + 1]);
            continue;
        }
        let label = first as usize;
        if first & 0xC0 != 0 || cursor + 1 + label > data.len() || out.len() + label + 2 > 255 {
            return None;
        }
        out.extend(&data[cursor..cursor + 1 + label]);
        cursor += 1 + label;
    }
}

/// Removes the "ech" SvcParam from every HTTPS/SVCB record so a browser falls
/// back to a plain ClientHello whose SNI can be filtered. The message is
/// rebuilt with uncompressed names. Returns true only when something was
/// removed; a malformed message, or one with record types whose RDATA cannot be
/// rewritten safely, is left exactly as it was.
pub fn strip_ech(message: &mut Vec<u8>) -> bool {
    match rebuild_without_ech(message) {
        Some(rebuilt) => {
            *message = rebuilt;
            true
        }
        None => false,
    }
}

fn rebuild_without_ech(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    let questions = read16(data, 4);
    let counts = [read16(data, 6), read16(data, 8), read16(data, 10)];
    let mut offset = HEADER_SIZE;
    for _ in 0..questions {
        if !skip_name(data, &mut offset) || offset + 4 > data.len() {
            return None;
        }
        offset += 4;
    }

    // Header and questions are copied verbatim, so a 0xC00C pointer to the
    // question name stays valid in the rebuilt message.
    let mut out = data[..offset].to_vec();
    let mut removed = 0;
    for count in counts {
        for _ in 0..count {
            let name_start = offset;
            let (owner, name_end) = read_name(data, offset)?;
            if name_end + 10 > data.len() {
                return None;
            }
            let rtype = read16(data, name_end);
            let rd_start = name_end + 10;
            let rd_end = rd_start + read16(data, name_end + 8) as usize;
            if rd_end > data.len() {
                return None;
            }

            if name_end - name_start == 2 && data[name_start..name_end] == [0xC0, 0x0C] {
                out.extend([0xC0, 0x0C]);
            } else {
                out.extend(&owner);
            }
            out.extend(&data[name_end..name_end + 8]); // type, class, TTL
            let length_at = out.len();
            out.extend([0, 0]);
            let rdata_begin = out.len();

            match rtype {
                TYPE_HTTPS | TYPE_SVCB => {
                    if rd_end - rd_start < 3 {
                        return None;
                    }
                    let (target, target_end) = read_name(data, rd_start + 2)?;
                    if target_end > rd_end {
                        return None;
                    }
                    out.extend(&data[rd_start..rd_start + 2]); // priority
                    out.extend(&target);
                    let mut cursor = target_end;
                    while cursor < rd_end {
                        if cursor + 4 > rd_end {
                            return None;
                        }
                        let key = read16(data, cursor);
                        let value_length = read16(data, cursor + 2) as usize;
                        if cursor + 4 + value_length > rd_end {
                            return None;
                        }
                        if key == SVC_PARAM_ECH {
                            removed += 1;
                        } else {
                            out.extend(&data[cursor..cursor + 4 + value_length]);
                        }
                        cursor += 4 + value_length;
                    }
                }
                TYPE_CNAME => {
                    let (target, target_end) = read_name(data, rd_start)?;
                    if target_end != rd_end {
                        return None;
                    }
                    out.extend(&target);
                }
                TYPE_A | TYPE_AAAA | TYPE_OPT | TYPE_RRSIG | TYPE_TXT => {
                    out.extend(&data[rd_start..rd_end]);
                }
                _ => return None, // may hold compressed names this cannot rewrite
            }

            let new_length = u16::try_from(out.len() - rdata_begin).ok()?;
            write16(&mut out, length_at, new_length);
            offset = rd_end;
        }
    }
    (removed > 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::dns_query as query;

    fn parsed(bytes: &[u8]) -> Query {
        let mut q = Query::default();
        assert!(parse_query(bytes, &mut q));
        q
    }

    fn read(data: &[u8], at: usize) -> u16 {
        read16(data, at)
    }

    const NONE: [&str; 0] = [];

    #[test]
    fn parses_one_uncompressed_question() {
        let q = parsed(&query("Discord.COM", TYPE_A).build());
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "discord.com");
        assert_eq!(q.qtype, TYPE_A);
        assert!(q.recursion_desired);
    }

    #[test]
    fn rejects_compressed_questions() {
        let mut bytes = query("discord.com", TYPE_A).build();
        bytes[12] = 0xC0;
        assert!(!parse_query(&bytes, &mut Query::default()));
    }

    #[test]
    fn builds_only_matching_a_answers() {
        let q = parsed(&query("discord.com", TYPE_A).build());
        let response = build_response(
            &q,
            &["203.0.113.7", "not-an-address", "2001:db8::7"],
            120,
            false,
            0,
        );
        assert_eq!(read(&response, 0), 0x1234);
        assert_eq!(read(&response, 6), 1);
        assert_eq!(read(&response, 2) & 0x000F, 0);
        assert_eq!(response[response.len() - 4..], [203, 0, 113, 7]);
    }

    #[test]
    fn parses_edns_and_only_accepts_sane_names() {
        let q = parsed(
            &query("Example.COM", TYPE_A)
                .id(0x0042)
                .edns(1232, true)
                .build(),
        );
        assert_eq!(q.id, 0x0042);
        assert_eq!(q.name, "example.com");
        assert_eq!(q.edns_payload, 1232);
        assert!(q.dnssec_ok);
        assert_eq!(q.error, 0);

        let plain = parsed(&query("example.com", TYPE_A).build());
        assert_eq!(plain.edns_payload, 0);
        assert!(!plain.dnssec_ok);

        // Service labels use '_'; hyphens and digits are ordinary.
        parsed(&query("_dmarc.x-1.example.com", 16).build());

        // Anything that does not belong in a hostname is refused (FORMERR).
        let bad: [&[u8]; 6] = [
            b"bad name.example",
            b"a$b.example",
            b"a&b.example",
            b"x/../y.example",
            b"caf\xC3\xA9.example",
            b"del\x7f.example",
        ];
        for name in bad {
            let mut q = Query::default();
            assert!(!parse_query(&query(name, TYPE_A).build(), &mut q));
            assert_eq!(q.error, RCODE_FORM_ERR);
        }
    }

    #[test]
    fn classifies_unusable_queries() {
        let mut q = Query::default();

        // Unsupported opcode (STATUS) and non-IN class are NOTIMP, ID still known.
        let opcode = query("example.com", TYPE_A)
            .id(0x7777)
            .flags(0x1100)
            .build();
        assert!(!parse_query(&opcode, &mut q));
        assert_eq!(q.error, RCODE_NOT_IMP);
        assert_eq!(q.id, 0x7777);

        let chaos = query("version.bind", 16).id(0x5555).class(3).build();
        assert!(!parse_query(&chaos, &mut q));
        assert_eq!(q.error, RCODE_NOT_IMP);

        // Two questions: malformed for our purposes.
        let mut two = query("example.com", TYPE_A).build();
        two[5] = 2;
        assert!(!parse_query(&two, &mut q));
        assert_eq!(q.error, RCODE_FORM_ERR);

        // A response (QR=1) or a runt has no header worth answering.
        let response = query("example.com", TYPE_A).id(1).flags(0x8180).build();
        assert!(!parse_query(&response, &mut q));
        assert_eq!(q.error, 0);
        assert!(!parse_query(&[1, 2, 3, 4], &mut q));
        assert_eq!(q.error, 0);

        // The error reply is header-only, echoes ID/RD and carries the code.
        assert!(!parse_query(&opcode, &mut q));
        let reply = build_error(&q, q.error);
        assert_eq!(reply.len(), 12);
        assert_eq!(read(&reply, 0), 0x7777);
        assert_ne!(read(&reply, 2) & 0x8000, 0);
        assert_ne!(read(&reply, 2) & 0x0100, 0);
        assert_eq!(read(&reply, 2) & 0x000F, u16::from(RCODE_NOT_IMP));
        assert_eq!(read(&reply, 4), 0);
    }

    #[test]
    fn carries_real_rcodes_and_answers_edns_with_opt() {
        let q = parsed(
            &query("gone.example", TYPE_A)
                .id(9)
                .edns(4096, false)
                .build(),
        );

        let nx = build_response(&q, &NONE, 60, false, RCODE_NX_DOMAIN);
        assert_eq!(read(&nx, 2) & 0x000F, u16::from(RCODE_NX_DOMAIN));
        assert_eq!(read(&nx, 6), 0);
        assert_eq!(read(&nx, 10), 1); // OPT echoed
        assert_eq!(nx[nx.len() - 10..nx.len() - 8], [0, 41]);

        // A non-zero rcode never carries answers, even if addresses are supplied.
        assert_eq!(
            read(&build_response(&q, &["203.0.113.1"], 60, false, 5), 6),
            0
        );

        let positive = build_response(&q, &["203.0.113.1"], 60, false, 0);
        assert_eq!(read(&positive, 6), 1);
        assert_eq!(read(&positive, 10), 1);

        // No OPT in the query, none in the answer.
        let plain = parsed(&query("gone.example", TYPE_A).build());
        assert_eq!(read(&build_response(&plain, &NONE, 60, false, 0), 10), 0);
    }

    #[test]
    fn ages_ttls_echoes_question_and_truncates() {
        let q = parsed(&query("Example.com", TYPE_A).id(0x0A0B).build());
        let mut response = build_response(&q, &["203.0.113.7"], 120, false, 0);
        let info = inspect_response(&response).expect("well formed");
        assert!(info.response);
        assert!(!info.truncated);
        assert_eq!(info.answers, 1);
        assert!(info.has_answer_ttl);
        assert_eq!(info.answer_ttl, 120);

        assert!(echoes_question(&response, &q));
        let other = parsed(&query("other.example", TYPE_A).build());
        assert!(!echoes_question(&response, &other));

        set_id(&mut response, 0xBEEF);
        assert_eq!(read(&response, 0), 0xBEEF);

        age_ttls(&mut response, 30);
        assert_eq!(inspect_response(&response).unwrap().answer_ttl, 90);
        age_ttls(&mut response, 100_000); // never reaches 0 from non-zero
        assert_eq!(inspect_response(&response).unwrap().answer_ttl, 1);

        // Fits: untouched. Too big: header + question only, TC set, counts zeroed.
        assert!(!truncate_for_udp(&mut response, 512));
        let full = response.len();
        assert!(truncate_for_udp(&mut response, full - 1));
        assert_eq!(response.len(), 12 + q.question.len());
        assert_ne!(read(&response, 2) & 0x0200, 0);
        assert_eq!(read(&response, 6), 0);
        assert_eq!(read(&response, 4), 1);
    }

    #[test]
    fn inspect_rejects_truncated_and_lying_messages() {
        let q = parsed(&query("example.com", TYPE_A).build());
        let response = build_response(&q, &["203.0.113.7", "203.0.113.8"], 60, false, 0);
        for length in 0..response.len() {
            assert!(
                inspect_response(&response[..length]).is_none(),
                "length {length}"
            );
        }
        assert!(inspect_response(&response).is_some());

        // Counts that promise far more records than the bytes can hold.
        let mut lying = response.clone();
        lying[6] = 0xFF;
        lying[7] = 0xFF;
        assert!(inspect_response(&lying).is_none());

        // A record whose RDLENGTH runs past the end.
        let mut overrun = response.clone();
        let at = overrun.len() - 5;
        overrun[at] = 0x7F;
        assert!(inspect_response(&overrun).is_none());
    }

    #[test]
    fn builds_aaaa_and_servfail_responses() {
        let q = parsed(&query("discord.com", TYPE_AAAA).build());
        let aaaa = build_response(&q, &["2001:db8::7", "203.0.113.7"], 300, false, 0);
        assert_eq!(read(&aaaa, 6), 1);
        assert_eq!(read(&aaaa, aaaa.len() - 18), 16);

        let failed = build_response(&q, &NONE, 60, true, 0);
        assert_eq!(read(&failed, 6), 0);
        assert_eq!(read(&failed, 2) & 0x000F, 2);
    }

    /// One-question response whose single answer is `rtype` with `rdata`, plus an OPT.
    fn response_with(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [0x1234u16, 0x8180, 1, 1, 0, 1] {
            out.extend(value.to_be_bytes());
        }
        out.extend(b"\x07example\x03com\x00");
        out.extend(rtype.to_be_bytes());
        out.extend(1u16.to_be_bytes());
        out.extend([0xC0, 0x0C]); // answer owner -> question
        out.extend(rtype.to_be_bytes());
        out.extend(1u16.to_be_bytes());
        out.extend(300u32.to_be_bytes());
        out.extend((rdata.len() as u16).to_be_bytes());
        out.extend(rdata);
        out.push(0); // OPT
        for value in [41u16, 1232, 0, 0, 0] {
            out.extend(value.to_be_bytes());
        }
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn strip_ech_removes_only_the_ech_param() {
        let rdata = [
            0, 1, 0, // priority 1, target "."
            0, 1, 0, 3, 2, b'h', b'2', // alpn
            0, 4, 0, 4, 1, 2, 3, 4, // ipv4hint
            0, 5, 0, 4, b'A', b'B', b'C', b'D', // ech
        ];
        let mut reply = response_with(65, &rdata);
        let before = reply.len();
        assert!(strip_ech(&mut reply));
        assert_eq!(reply.len(), before - 8);
        assert!(!contains(&reply, &[0, 5, 0, 4, b'A', b'B', b'C', b'D']));
        assert!(contains(&reply, &[0, 1, 0, 3, 2, b'h', b'2']));
        assert!(contains(&reply, &[0, 4, 0, 4, 1, 2, 3, 4]));
        assert_eq!(inspect_response(&reply).unwrap().answers, 1);
        assert!(!strip_ech(&mut reply)); // nothing left to remove
    }

    #[test]
    fn strip_ech_leaves_other_messages_alone() {
        let mut no_ech = response_with(65, &[0, 1, 0, 0, 1, 0, 3, 2, b'h', b'2']);
        let copy = no_ech.clone();
        assert!(!strip_ech(&mut no_ech));
        assert_eq!(no_ech, copy);

        let mut mx = response_with(15, &[0, 10, 0]); // a type this cannot rewrite
        let copy = mx.clone();
        assert!(!strip_ech(&mut mx));
        assert_eq!(mx, copy);

        assert!(!strip_ech(&mut vec![1, 2, 3]));
    }
}
