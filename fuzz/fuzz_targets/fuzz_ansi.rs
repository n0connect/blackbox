#![no_main]

use libfuzzer_sys::fuzz_target;
use scb_vka_shell::sanitize_terminal_output;

fuzz_target!(|data: &[u8]| {
    // Attempt to sanitize random fuzzer-generated terminal bytes
    // Ensures that the logic never panics on malformed Unicode or control characters
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = sanitize_terminal_output(s);
    }
});
