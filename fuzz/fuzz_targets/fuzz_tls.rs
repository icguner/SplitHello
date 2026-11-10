#![no_main]

use libfuzzer_sys::fuzz_target;
use sh_proto::tls::{ClientHello, ParseStatus, classify_server_response, looks_like_tls_record, parse_client_hello};

fuzz_target!(|data: &[u8]| {
    let mut hello = ClientHello::default();
    if parse_client_hello(data, &mut hello) == ParseStatus::Ok && hello.has_sni() {
        // The reported hostname must lie inside the first record.
        assert!(hello.sni_offset + hello.sni_length <= hello.record_total_length);
        assert!(hello.record_total_length <= data.len());
    }
    let _ = classify_server_response(data);
    let _ = looks_like_tls_record(data);
});
