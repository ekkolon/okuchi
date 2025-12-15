#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint_dig::BigUint;
use okuchi::{Ciphertext, KeyPair, Okuchi};

use std::sync::OnceLock;

static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let keypair = KEYPAIR.get_or_init(|| KeyPair::new(512).unwrap());

    let private_key = keypair.priv_key();
    let public_key = keypair.pub_key();

    let (m1_bytes, m2_bytes) = data.split_at(data.len() / 2);
    let m1 = BigUint::from_bytes_be(m1_bytes);
    let m2 = BigUint::from_bytes_be(m2_bytes);

    let Ok(c1) = Okuchi::encrypt(&public_key, m1.to_bytes_be()) else {
        return;
    };
    let Ok(c2) = Okuchi::encrypt(&public_key, m2.to_bytes_be()) else {
        return;
    };

    let c_prod = &c1 * &c2;
    let c_prod_mod = Ciphertext::new(c_prod.value() % public_key.n());

    let decryption_res = Okuchi::decrypt(&private_key, &c_prod_mod);
    assert!(decryption_res.is_ok());
});
