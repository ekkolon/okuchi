#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint_dig::BigUint;
use okuchi::{KeyPair, Okuchi};
use std::sync::OnceLock;

static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let key_pair = KEYPAIR.get_or_init(|| KeyPair::new(512).unwrap());
    let pub_key = key_pair.pub_key();
    let priv_key = key_pair.priv_key();
    let n = pub_key.n();

    // Limit input to modulus size
    let truncated = if data.len() > n.to_bytes_be().len() {
        &data[..n.to_bytes_be().len()]
    } else {
        data
    };

    let mut plaintext = BigUint::from_bytes_be(truncated);

    // Ensure plaintext < n
    plaintext %= n;

    let Ok(ciphertext) = Okuchi::encrypt(pub_key, plaintext.to_bytes_be()) else {
        return;
    };
    let Ok(decrypted) = Okuchi::decrypt(priv_key, &ciphertext) else {
        return;
    };

    let decrypted = BigUint::from_bytes_be(&decrypted);

    assert_eq!(plaintext, decrypted);
});
