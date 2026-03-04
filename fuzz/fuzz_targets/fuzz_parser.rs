#![no_main]

use libfuzzer_sys::fuzz_target;
use scb_vka_common::util::parse_hex_object_id;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary byte slices to the Hex Parser.
    // It should safely return an error or Ok, but NEVER panic or OOM
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_hex_object_id(s);
    }
});
