//! Bounds-checked TLS ClientHello inspection (port of `src/TlsHello.cpp`).
//!
//! The parser never reads past the slice; a truncated ClientHello reports
//! `NeedMore` instead of pretending the rest is in memory.

pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const RECORD_ALERT: u8 = 0x15;
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

pub const RECORD_HEADER_SIZE: usize = 5;
/// 2^14, the TLSPlaintext limit.
pub const MAX_RECORD_PAYLOAD: usize = 16384;
pub const EXT_SERVER_NAME: u16 = 0x0000;
/// RFC 9849.
pub const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseStatus {
    /// A complete ClientHello record is present.
    Ok,
    /// Consistent so far, but more bytes are required.
    NeedMore,
    /// Not a TLS handshake record: forward untouched.
    NotTls,
    /// TLS-shaped but self-inconsistent: forward untouched.
    Malformed,
}

/// Classification of the server's first TLS flight during an adaptive probe.
/// `NeedMore` is distinct from `Unexpected`: a TCP read can end in the middle of
/// a valid record and must not poison learned state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerResponseStatus {
    NeedMore,
    ServerHello,
    Alert,
    Unexpected,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// Value of the first record's length field.
    pub record_payload_length: usize,
    /// `RECORD_HEADER_SIZE + record_payload_length`.
    pub record_total_length: usize,
    /// Absolute offset of the hostname's first byte; zero when absent.
    pub sni_offset: usize,
    pub sni_length: usize,
    /// Decoded hostname, empty if absent.
    pub server_name: String,
    /// The outer SNI is a cover name; splitting it is pointless.
    pub has_ech: bool,
    /// The handshake message continues past the first record.
    pub spans_records: bool,
}

impl ClientHello {
    pub fn has_sni(&self) -> bool {
        self.sni_length > 0
    }
}

/// Cursor that refuses to read past the end of the region it was given.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Self { data, pos, end }
    }

    fn remaining(&self) -> usize {
        self.end - self.pos
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        (n <= self.remaining()).then(|| self.pos += n)
    }

    fn u8(&mut self) -> Option<u8> {
        (self.remaining() >= 1).then(|| {
            self.pos += 1;
            self.data[self.pos - 1]
        })
    }

    fn u16(&mut self) -> Option<u16> {
        (self.remaining() >= 2).then(|| {
            self.pos += 2;
            u16::from_be_bytes([self.data[self.pos - 2], self.data[self.pos - 1]])
        })
    }
}

/// Walks the server_name extension body and records the first host_name entry.
/// Layout: list_length(2) { name_type(1) name_length(2) name } *
fn read_server_name(data: &[u8], start: usize, end: usize, out: &mut ClientHello) -> Option<()> {
    let mut r = Reader::new(data, start, end);
    let list_length = r.u16()? as usize;
    if list_length > r.remaining() {
        return None;
    }
    // Bounded to the declared list: a header that straddles its end is not read.
    let mut list = Reader::new(data, r.pos, r.pos + list_length);
    while list.remaining() > 0 {
        let name_type = list.u8()?;
        let name_length = list.u16()? as usize;
        if name_length > list.remaining() {
            return None;
        }
        if name_type == 0x00 {
            out.sni_offset = list.pos;
            out.sni_length = name_length;
            out.server_name =
                String::from_utf8_lossy(&data[list.pos..list.pos + name_length]).into_owned();
            return Some(());
        }
        list.skip(name_length)?;
    }
    None // well-formed list, but no host_name in it
}

fn parse_extensions(
    data: &[u8],
    pos: usize,
    body_end: usize,
    out: &mut ClientHello,
) -> ParseStatus {
    let mut r = Reader::new(data, pos, body_end);
    let Some(extensions_length) = r.u16().map(usize::from) else {
        return ParseStatus::Malformed;
    };
    if extensions_length > r.remaining() {
        return ParseStatus::Malformed;
    }

    // Bounded to the declared block so an extension header that runs past it is
    // Malformed instead of an out-of-range read (found by the C++ fuzzer).
    let mut block = Reader::new(data, r.pos, r.pos + extensions_length);
    while block.remaining() > 0 {
        let (Some(ext_type), Some(ext_length)) = (block.u16(), block.u16()) else {
            return ParseStatus::Malformed;
        };
        let ext_length = ext_length as usize;
        if ext_length > block.remaining() {
            return ParseStatus::Malformed;
        }
        let start = block.pos;
        if ext_type == EXT_ENCRYPTED_CLIENT_HELLO {
            out.has_ech = true;
        } else if ext_type == EXT_SERVER_NAME && !out.has_sni() {
            let _ = read_server_name(data, start, start + ext_length, out);
        }
        if block.skip(ext_length).is_none() {
            return ParseStatus::Malformed;
        }
    }
    ParseStatus::Ok
}

/// Inspects a buffer that begins with a TLS record. On `Ok`, `out` describes
/// the first record; on `NeedMore` it is only partially filled.
pub fn parse_client_hello(data: &[u8], out: &mut ClientHello) -> ParseStatus {
    *out = ClientHello::default();
    let len = data.len();

    if len == 0 {
        return ParseStatus::NeedMore;
    }
    if data[0] != RECORD_HANDSHAKE {
        return ParseStatus::NotTls;
    }
    if len < 2 {
        return ParseStatus::NeedMore;
    }
    if data[1] != 0x03 {
        return ParseStatus::NotTls; // legacy_record_version is always 3.x
    }
    if len < RECORD_HEADER_SIZE {
        return ParseStatus::NeedMore;
    }

    let payload_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if payload_length == 0 || payload_length > MAX_RECORD_PAYLOAD {
        return ParseStatus::Malformed;
    }
    out.record_payload_length = payload_length;
    out.record_total_length = RECORD_HEADER_SIZE + payload_length;

    // Everything below indexes into the record, so the whole record must be here.
    if len < out.record_total_length {
        return ParseStatus::NeedMore;
    }
    if payload_length < 4 {
        return ParseStatus::Malformed;
    }
    if data[RECORD_HEADER_SIZE] != HANDSHAKE_CLIENT_HELLO {
        return ParseStatus::NotTls;
    }

    let handshake_length = (data[RECORD_HEADER_SIZE + 1] as usize) << 16
        | (data[RECORD_HEADER_SIZE + 2] as usize) << 8
        | data[RECORD_HEADER_SIZE + 3] as usize;
    let body_start = RECORD_HEADER_SIZE + 4;
    let body_end = body_start + handshake_length;

    if body_end > out.record_total_length {
        // The client already spread its hello over several records: it needs no
        // help, and re-framing a partial message would corrupt it.
        out.spans_records = true;
        return ParseStatus::Ok;
    }

    let mut r = Reader::new(data, body_start, body_end);
    let fixed = (|| {
        r.skip(2)?; // client_version
        r.skip(32)?; // random
        let session_id = r.u8()? as usize;
        r.skip(session_id)?;
        let suites = r.u16()? as usize;
        r.skip(suites)?;
        let compression = r.u8()? as usize;
        r.skip(compression)
    })();
    if fixed.is_none() {
        return ParseStatus::Malformed;
    }

    // A hello with no extension block at all is legal (and has no SNI to hide).
    if r.remaining() == 0 {
        return ParseStatus::Ok;
    }
    parse_extensions(data, r.pos, body_end, out)
}

/// Inspects complete TLS records from the start of `data`. Compatibility
/// ChangeCipherSpec records are skipped; only a complete ServerHello is success.
pub fn classify_server_response(data: &[u8]) -> ServerResponseStatus {
    let mut offset = 0;
    while offset < data.len() {
        let rest = &data[offset..];
        if rest.len() < RECORD_HEADER_SIZE {
            return ServerResponseStatus::NeedMore;
        }
        let content_type = rest[0];
        if rest[1] != 0x03 {
            return ServerResponseStatus::Unexpected;
        }
        let payload_length = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if payload_length == 0 || payload_length > MAX_RECORD_PAYLOAD {
            return ServerResponseStatus::Unexpected;
        }
        let total = RECORD_HEADER_SIZE + payload_length;
        if rest.len() < total {
            return ServerResponseStatus::NeedMore;
        }
        let payload = &rest[RECORD_HEADER_SIZE..total];
        match content_type {
            RECORD_ALERT => return ServerResponseStatus::Alert,
            RECORD_HANDSHAKE => {
                return if payload_length >= 4 && payload[0] == HANDSHAKE_SERVER_HELLO {
                    ServerResponseStatus::ServerHello
                } else {
                    ServerResponseStatus::Unexpected
                };
            }
            RECORD_CHANGE_CIPHER_SPEC => offset += total,
            _ => return ServerResponseStatus::Unexpected,
        }
    }
    ServerResponseStatus::NeedMore
}

pub fn is_server_hello(data: &[u8]) -> bool {
    classify_server_response(data) == ServerResponseStatus::ServerHello
}

/// True if the buffer starts with something that could become a TLS record.
pub fn looks_like_tls_record(data: &[u8]) -> bool {
    match data {
        [] => false,
        [first] => *first == RECORD_HANDSHAKE,
        [first, version, ..] => *first == RECORD_HANDSHAKE && *version == 0x03,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{HelloOptions, build_client_hello, sni_text};

    fn parse(data: &[u8]) -> (ParseStatus, ClientHello) {
        let mut hello = ClientHello::default();
        let status = parse_client_hello(data, &mut hello);
        (status, hello)
    }

    #[test]
    fn parses_complete_client_hello() {
        let data = build_client_hello(&HelloOptions::default());
        let (status, hello) = parse(&data);
        assert_eq!(status, ParseStatus::Ok);
        assert_eq!(hello.record_total_length, data.len());
        assert_eq!(hello.server_name, "discord.com");
        assert_eq!(sni_text(&data, &hello), "discord.com");
        assert!(!hello.has_ech);
        assert!(!hello.spans_records);
        assert!(hello.sni_offset + hello.sni_length <= data.len());
    }

    /// Reading the tail of a ClientHello that has not arrived yet: every prefix
    /// must report NeedMore, never Ok.
    #[test]
    fn truncated_hello_never_reports_complete() {
        let data = build_client_hello(&HelloOptions::default());
        for prefix in 1..data.len() {
            let (status, hello) = parse(&data[..prefix]);
            assert_eq!(status, ParseStatus::NeedMore, "prefix {prefix}");
            assert!(hello.server_name.is_empty());
        }
    }

    #[test]
    fn truncated_post_quantum_hello_never_reports_complete() {
        let data = build_client_hello(&HelloOptions {
            padding_bytes: 4000,
            ..Default::default()
        });
        assert!(data.len() > 4000);
        for prefix in (1..data.len()).step_by(7) {
            assert_eq!(parse(&data[..prefix]).0, ParseStatus::NeedMore);
        }
        let (status, hello) = parse(&data);
        assert_eq!(status, ParseStatus::Ok);
        assert_eq!(sni_text(&data, &hello), "discord.com");
    }

    #[test]
    fn trailing_bytes_are_not_part_of_the_record() {
        let mut data = build_client_hello(&HelloOptions::default());
        let record_size = data.len();
        data.extend(std::iter::repeat_n(0x99, 128));
        let (status, hello) = parse(&data);
        assert_eq!(status, ParseStatus::Ok);
        assert_eq!(hello.record_total_length, record_size);
    }

    #[test]
    fn rejects_non_tls_traffic() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse(request).0, ParseStatus::NotTls);
    }

    #[test]
    fn rejects_empty_record() {
        assert_eq!(
            parse(&[0x16, 0x03, 0x01, 0x00, 0x00]).0,
            ParseStatus::Malformed
        );
    }

    #[test]
    fn rejects_session_id_that_overruns_the_body() {
        let mut data = build_client_hello(&HelloOptions::default());
        // 5 record header + 4 handshake header + 2 version + 32 random
        data[5 + 4 + 2 + 32] = 0xFF;
        assert_eq!(parse(&data).0, ParseStatus::Malformed);
    }

    #[test]
    fn rejects_extensions_length_that_overruns_the_body() {
        let mut data = build_client_hello(&HelloOptions::default());
        // ... + 1 session id length + 2 cipher length + 2 ciphers + 1 + 1 compression
        let offset = 5 + 4 + 2 + 32 + 1 + 2 + 2 + 1 + 1;
        data[offset] = 0x7F;
        data[offset + 1] = 0xFF;
        assert_eq!(parse(&data).0, ParseStatus::Malformed);
    }

    #[test]
    fn detects_encrypted_client_hello() {
        let data = build_client_hello(&HelloOptions {
            server_name: "cloudflare-ech.com".into(),
            with_ech: true,
            ..Default::default()
        });
        let (status, hello) = parse(&data);
        assert_eq!(status, ParseStatus::Ok);
        assert!(hello.has_ech);
    }

    #[test]
    fn hello_without_sni_is_still_valid() {
        let data = build_client_hello(&HelloOptions {
            server_name: String::new(),
            with_sni: false,
            ..Default::default()
        });
        let (status, hello) = parse(&data);
        assert_eq!(status, ParseStatus::Ok);
        assert!(!hello.has_sni());
        assert_eq!(hello.sni_length, 0);
    }

    #[test]
    fn detects_handshake_spanning_records() {
        let mut data = build_client_hello(&HelloOptions::default());
        // Shrink the record so the handshake no longer fits, as when a client
        // fragments its own hello.
        let half = (data.len() - RECORD_HEADER_SIZE) / 2;
        data[3] = (half >> 8) as u8;
        data[4] = half as u8;
        data.truncate(RECORD_HEADER_SIZE + half);
        let (status, hello) = parse(&data);
        assert_eq!(status, ParseStatus::Ok);
        assert!(hello.spans_records);
        assert!(!hello.has_sni());
    }

    #[test]
    fn recognises_server_hello() {
        let server_hello = [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
        assert!(is_server_hello(&server_hello));

        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert!(!is_server_hello(&alert));
        assert_eq!(
            classify_server_response(&alert),
            ServerResponseStatus::Alert
        );

        assert!(!is_server_hello(&server_hello[..3]));
        assert_eq!(
            classify_server_response(&server_hello[..3]),
            ServerResponseStatus::NeedMore
        );
    }

    #[test]
    fn server_response_skips_compatibility_change_cipher_spec() {
        let response = [
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, //
            0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            classify_server_response(&response),
            ServerResponseStatus::ServerHello
        );
    }

    #[test]
    fn http_block_page_is_not_a_handshake_success() {
        assert_eq!(
            classify_server_response(b"HTTP/1.1 302 Found\r\n\r\n"),
            ServerResponseStatus::Unexpected
        );
    }

    /// Found by the C++ CI fuzzer: extensions_length (3) is shorter than one
    /// extension header (4).
    #[test]
    fn extension_header_longer_than_declared_block_is_malformed() {
        let mut record = vec![
            0x16, 0x03, 0x10, 0x00, 0x3e, 0x01, 0x00, 0x00, 0x3a, 0x02, 0xff,
        ];
        record.extend([0u8; 32]);
        record.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x7e, 0x00]);
        record.resize(5 + 62, 0x00);
        let (status, hello) = parse(&record);
        assert_eq!(status, ParseStatus::Malformed);
        assert!(!hello.has_sni());
    }

    #[test]
    fn server_name_list_shorter_than_entry_header_is_ignored() {
        let mut record = vec![
            0x16, 0x03, 0x01, 0x00, 0x34, 0x01, 0x00, 0x00, 0x30, 0x03, 0x03,
        ];
        record.extend([0u8; 32]);
        record.extend([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00,
        ]);
        record.resize(5 + 0x34, 0x00);
        let (_, hello) = parse(&record);
        assert!(!hello.has_sni());
    }

    #[test]
    fn looks_like_tls_record_matches_cpp() {
        assert!(!looks_like_tls_record(&[]));
        assert!(looks_like_tls_record(&[0x16]));
        assert!(looks_like_tls_record(&[0x16, 0x03]));
        assert!(!looks_like_tls_record(&[0x16, 0x02]));
        assert!(!looks_like_tls_record(b"GET"));
    }
}
