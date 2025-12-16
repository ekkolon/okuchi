#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use okuchi::{Decrypt, Encrypt, KeyPair};

static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let key_pair = KEYPAIR.get_or_init(|| KeyPair::generate_with_size(128).unwrap());

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
    let original = num_bigint_dig::BigUint::from_bytes_be(plaintext_bytes);
    let decrypted = num_bigint_dig::BigUint::from_bytes_be(&decrypted_bytes);

    assert_eq!(
        original, decrypted,
        "Plaintext mismatch!\nOriginal bytes: {:?}\nDecrypted bytes: {:?}\nOriginal BigUint: {}\nDecrypted BigUint: {}",
        plaintext_bytes, decrypted_bytes, original, decrypted
    );
});
