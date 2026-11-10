#![no_main]

use libfuzzer_sys::fuzz_target;
use sh_proto::dns;

fuzz_target!(|data: &[u8]| {
    let mut query = dns::Query::default();
    if dns::parse_query(data, &mut query) {
        let reply = dns::build_response(&query, &["203.0.113.7", "2001:db8::7"], 60, false, 0);
        assert!(dns::inspect_response(&reply).is_some());
        assert!(dns::echoes_question(&reply, &query));
    } else if query.error != 0 {
        assert_eq!(dns::build_error(&query, query.error).len(), 12);
    }

    let _ = dns::inspect_response(data);
    let mut message = data.to_vec();
    dns::age_ttls(&mut message, 30);
    dns::set_id(&mut message, 0xBEEF);
    let mut stripped = data.to_vec();
    if dns::strip_ech(&mut stripped) {
        // A rewritten message must still be well formed.
        assert!(dns::inspect_response(&stripped).is_some());
    }
    let mut truncated = data.to_vec();
    dns::truncate_for_udp(&mut truncated, 512);
});
