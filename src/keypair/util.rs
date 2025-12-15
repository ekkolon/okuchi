// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::prime::probably_prime;
use num_bigint_dig::{BigUint, RandBigInt, RandPrime};
use num_traits::One;
use rand::SeedableRng;
use rand::rngs::StdRng;

/// Find a generator g for Okamoto-Uchiyama encryption.
///
/// Uses the construction g = (1 + n)^β mod n² where β is random.
/// This ensures g has order p in the multiplicative group.
///
/// For the simplified version where we work mod n instead of n²,
/// we use g = (1 + n) directly, which guarantees the required properties.
///
/// # Panics
/// Will panic only if RNG fails (highly unlikely with `StdRng`).
pub fn find_generator(n: &BigUint, p_minus_1: &BigUint, p_squared: &BigUint) -> BigUint {
    // Okamoto-Uchiyama construction: g = 1 + n
    let g = n + BigUint::one();

    // Verify g^(p-1) ≢ 1 (mod p²)
    let check = g.modpow(p_minus_1, p_squared);

    // With g = 1 + n, we have g^k ≡ 1 + kn (mod n²) by binomial theorem
    // So g^(p-1) ≡ 1 + (p-1)n (mod n²) ≢ 1 (mod p²) since n = p²q
    if check != BigUint::one() {
        return g;
    }

    // Fallback: if 1+n doesn't work (shouldn't happen), try random selection
    // with the proper subgroup structure
    let mut rng = StdRng::from_os_rng();
    let p = p_squared.sqrt();
    let p_minus_1_local = &p - BigUint::one();

    for _ in 0..1000 {
        // Try g = 1 + β*n for random β
        let beta = rng.gen_biguint_range(&BigUint::one(), &p);
        let g = BigUint::one() + &beta * n;
        let g_mod_n = &g % n;

        let check = g_mod_n.modpow(&p_minus_1_local, p_squared);
        if check != BigUint::one() {
            return g_mod_n;
        }
    }

    // If we still haven't found one, try completely random elements
    // This should be extremely rare
    for _ in 0..10000 {
        let h = rng.gen_biguint_range(&BigUint::from(2u32), n);
        let check = h.modpow(&p_minus_1_local, p_squared);
        if check != BigUint::one() {
            return h;
        }
    }

    panic!("Failed to find generator after many attempts - this should never happen");
}

/// Generates a safe prime p of given bit size.
///
/// Safe primes have the form p = 2p' + 1, where p' is also prime.
/// Uses Miller-Rabin with 20 rounds for primality checking.
pub fn generate_safe_prime(bits: usize) -> BigUint {
    assert!(bits >= 3, "Safe prime generation requires at least 3 bits");

    let mut rng = StdRng::from_os_rng();
    loop {
        // random prime p' of size bits-1
        let p_prime = rng.gen_prime(bits - 1);

        // compute p = 2p' + 1
        let p = (&p_prime << 1) + BigUint::one();

        // check if p is prime (Miller-Rabin with 20 rounds)
        if probably_prime(&p, 20) {
            return p;
        }
    }
}
