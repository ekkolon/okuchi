#![allow(
    dead_code, 
    unused_imports, 
    unused_variables, 
    clippy::all, 
    clippy::no_mangle_with_rust_abi // Fixes a common libfuzzer lint
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use okuchi::{Decrypt, Encrypt, KeyPair};

static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let key_pair = KEYPAIR.get_or_init(|| KeyPair::generate_with_size(128).unwrap());

    // For 128-bit key: n = p²q
    // - n has 128 bits
    // - p has approximately 128/3 ≈ 42.67 bits
    // - Plaintext must be < p
    // - Safe limit: 42 bits = 5.25 bytes
    // - Conservative: use 4 bytes = 32 bits to be safe
    let max_bytes = 4;

    let plaintext_bytes = if data.len() > max_bytes { &data[..max_bytes] } else { data };

    // Encrypt the raw bytes
    let ciphertext = match key_pair.encrypt(plaintext_bytes) {
        Ok(ct) => ct,
        Err(_) => {
            // Plaintext too large (>= p), skip this test
            return;
        }
    };

    // Decrypt
    let decrypted_bytes = match key_pair.decrypt(&ciphertext) {
        Ok(pt) => pt,
        Err(_) => {
            panic!("Decryption failed for valid ciphertext! Input was: {:?}", plaintext_bytes);
        }
    };

    // Convert both to BigUint for comparison (this normalizes representations)
    use num_bigint_dig::BigUint;
    let original = BigUint::from_bytes_be(plaintext_bytes);
    let decrypted = BigUint::from_bytes_be(&decrypted_bytes);

    assert_eq!(
        original, decrypted,
        "Plaintext mismatch!\nOriginal bytes: {:?}\nDecrypted bytes: {:?}\nOriginal BigUint: {}\nDecrypted BigUint: {}",
        plaintext_bytes, decrypted_bytes, original, decrypted
    );
});
