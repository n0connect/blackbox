#![no_main]

use libfuzzer_sys::fuzz_target;
use scb_vka_crypto::engine::{AadBuilder, CryptoEngine, DefaultCryptoEngine};
use scb_vka_crypto::{AadPurpose, CryptoVersion, Epoch, KeyKEK, Nonce, ObjectId};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Basic structural requirements for the cryptography engine:
    // It expects a certain layout.
    // We will simulate passing the fuzzed data as a corrupted ciphertext block

    let dek = KeyKEK::new([0u8; 32]); // Dummy DEK
    let nonce = Nonce::new([0u8; 24]);

    let oid = ObjectId::new([0; 16]);
    let ver = CryptoVersion::new(1);
    let ep = Epoch::new(1);
    let pur = AadPurpose::UserPurpose([0; 32]);
    let aad = match AadBuilder::new()
        .object_id(oid)
        .version(ver)
        .epoch(ep)
        .purpose(pur)
        .build()
    {
        Ok(v) => v,
        Err(_) => return,
    };

    let engine = DefaultCryptoEngine;
    let mut reader = Cursor::new(data);
    let mut writer = Cursor::new(Vec::new());

    // The function might return errors (e.g. Integrity/MAC checks failing),
    // which is perfectly fine. It just shouldn't PANIC.
    // `expected_data_len` is just arbitrary 1024 for testing chunk iterators
    let _ = engine.decrypt_stream(&dek, &mut reader, &mut writer, &aad, nonce, 1024);
});
