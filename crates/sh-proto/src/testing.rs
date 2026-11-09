//! Synthetic test vectors shared by this crate's tests and, through the
//! `testing` feature, by other crates (port of `tests/HelloBuilder.hpp` and
//! `tests/DnsQueryBuilder.hpp`).

use crate::tls::{self, ClientHello};

#[derive(Debug, Clone)]
pub struct HelloOptions {
    pub server_name: String,
    /// Stands in for the bulk of a post-quantum key share.
    pub padding_bytes: usize,
    pub with_ech: bool,
    pub with_sni: bool,
}

impl Default for HelloOptions {
    fn default() -> Self {
        Self {
            server_name: "discord.com".into(),
            padding_bytes: 0,
            with_ech: false,
            with_sni: true,
        }
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend(value.to_be_bytes());
}

/// RFC 8446 layout, close enough that offsets line up with the parser's.
pub fn build_client_hello(options: &HelloOptions) -> Vec<u8> {
    let mut extensions = Vec::new();
    if options.with_sni {
        let name = options.server_name.as_bytes();
        let mut server_name = Vec::new();
        push_u16(&mut server_name, (name.len() + 3) as u16);
        server_name.push(0x00); // host_name
        push_u16(&mut server_name, name.len() as u16);
        server_name.extend(name);
        push_u16(&mut extensions, tls::EXT_SERVER_NAME);
        push_u16(&mut extensions, server_name.len() as u16);
        extensions.extend(server_name);
    }
    if options.with_ech {
        push_u16(&mut extensions, tls::EXT_ENCRYPTED_CLIENT_HELLO);
        push_u16(&mut extensions, 4);
        extensions.extend([0x00, 0x01, 0x02, 0x03]);
    }
    if options.padding_bytes > 0 {
        push_u16(&mut extensions, 0x0015); // padding
        push_u16(&mut extensions, options.padding_bytes as u16);
        extensions.extend(std::iter::repeat_n(0u8, options.padding_bytes));
    }

    let mut body = Vec::new();
    push_u16(&mut body, 0x0303); // legacy_version
    body.extend([0xABu8; 32]); // random
    body.push(0x00); // legacy_session_id length
    push_u16(&mut body, 2); // cipher_suites length
    push_u16(&mut body, 0x1301); // TLS_AES_128_GCM_SHA256
    body.push(0x01); // compression methods length
    body.push(0x00); // null compression
    push_u16(&mut body, extensions.len() as u16);
    body.extend(extensions);

    let mut record = vec![tls::RECORD_HANDSHAKE, 0x03, 0x01];
    push_u16(&mut record, (body.len() + 4) as u16);
    record.push(tls::HANDSHAKE_CLIENT_HELLO);
    record.extend(&(body.len() as u32).to_be_bytes()[1..]);
    record.extend(body);
    record
}

/// Hand-built DNS query: one question, optional EDNS0 OPT record.
#[derive(Debug, Clone)]
pub struct DnsQueryBuilder {
    name: Vec<u8>,
    qtype: u16,
    id: u16,
    edns_payload: u16,
    dnssec_ok: bool,
    class: u16,
    flags: u16,
}

pub fn dns_query(name: impl AsRef<[u8]>, qtype: u16) -> DnsQueryBuilder {
    DnsQueryBuilder {
        name: name.as_ref().to_vec(),
        qtype,
        id: 0x1234,
        edns_payload: 0,
        dnssec_ok: false,
        class: 1,
        flags: 0x0100,
    }
}

impl DnsQueryBuilder {
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }
    pub fn edns(mut self, payload: u16, dnssec_ok: bool) -> Self {
        self.edns_payload = payload;
        self.dnssec_ok = dnssec_ok;
        self
    }
    pub fn class(mut self, class: u16) -> Self {
        self.class = class;
        self
    }
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [
            self.id,
            self.flags,
            1,
            0,
            0,
            u16::from(self.edns_payload != 0),
        ] {
            push_u16(&mut out, value);
        }
        for label in self.name.split(|&b| b == b'.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend(label);
        }
        out.push(0);
        push_u16(&mut out, self.qtype);
        push_u16(&mut out, self.class);
        if self.edns_payload != 0 {
            out.push(0); // root name
            push_u16(&mut out, 41); // OPT
            push_u16(&mut out, self.edns_payload); // CLASS = UDP payload size
            out.extend([0, 0, if self.dnssec_ok { 0x80 } else { 0 }, 0]);
            push_u16(&mut out, 0); // no options
        }
        out
    }
}

pub fn sni_text(data: &[u8], hello: &ClientHello) -> String {
    String::from_utf8_lossy(&data[hello.sni_offset..hello.sni_offset + hello.sni_length])
        .into_owned()
}
