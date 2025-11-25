// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::{BigUint, RandPrime, prime::probably_prime};
use num_traits::One;
use rand::rngs::OsRng;

/// L(x) = (x - 1) / p
///
/// This function appears in the decryption algorithm. It's well-defined
/// because x ≡ 1 (mod p) when x = c^(p-1) mod p².
#[inline]
pub fn l_function(x: &BigUint, p: &BigUint) -> BigUint {
    (x - BigUint::one()) / p
}

/// Generates a safe prime p where p = 2p' + 1 and p' is also prime.
///
/// Safe primes provide additional security margin against certain
/// factorization attacks by ensuring the group order has a large
/// prime factor.
pub fn generate_safe_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
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
