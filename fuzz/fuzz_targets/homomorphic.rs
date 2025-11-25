#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use okuchi::{Ciphertext, Okuchi, generate_keypair};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let (private_key, public_key) = generate_keypair(512).unwrap();

    let (m1_bytes, m2_bytes) = data.split_at(data.len() / 2);
    let m1 = BigUint::from_bytes_be(m1_bytes);
    let m2 = BigUint::from_bytes_be(m2_bytes);

    if m1 >= *private_key.p() || m2 >= *private_key.p() {
        return;
    }

    if let (Ok(c1), Ok(c2)) = (Okuchi::encrypt(&public_key, &m1), Okuchi::encrypt(&public_key, &m2)) {
        let c_prod = &c1 * &c2;
        let c_prod_mod = Ciphertext::new(c_prod.value() % public_key.n());

        if let Ok(decrypted) = Okuchi::decrypt(&private_key, &c_prod_mod) {
            let expected = (&m1 + &m2) % private_key.p();
            assert_eq!(expected, decrypted);
        }
    }
});
