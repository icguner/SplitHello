#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let domains = sh_adblock::parse_domains(&text);
    let list = sh_adblock::Blocklist::default();
    list.replace(domains);
    for line in text.lines().take(64) {
        let _ = list.blocks(line);
    }
});
