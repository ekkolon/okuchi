#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use okuchi::{Okuchi, generate_keypair};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Use deterministic key for fuzzing
    let (private_key, public_key) = generate_keypair(512).unwrap();

    // Convert fuzz input to plaintext
    let plaintext = BigUint::from_bytes_be(data);

    // Only test valid plaintexts
    if plaintext >= *private_key.p() {
        return;
    }

    if let Ok(ciphertext) = Okuchi::encrypt(&public_key, &plaintext) {
        if let Ok(decrypted) = Okuchi::decrypt(&private_key, &ciphertext) {
            assert_eq!(plaintext, decrypted);
        }
    }
});
