// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Error, Result, util::generate_safe_prime};
use num_bigint_dig::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) n: BigUint,
    pub(crate) g: BigUint,
    pub(crate) h: BigUint,
    pub(crate) bit_length: usize,
}

impl PublicKey {
    pub fn new(n: BigUint, g: BigUint, h: BigUint, bit_length: usize) -> Result<Self> {
        if n.is_zero() || g.is_zero() || h.is_zero() {
            return Err(Error::InvalidPublicKey);
        }
        if g >= n || h >= n {
            return Err(Error::InvalidPublicKey);
        }

        Ok(Self {
            n,
            g,
            h,
            bit_length,
        })
    }

    pub fn n(&self) -> &BigUint {
        &self.n
    }

    pub fn g(&self) -> &BigUint {
        &self.g
    }

    pub fn h(&self) -> &BigUint {
        &self.h
    }

    pub fn bit_length(&self) -> usize {
        self.bit_length
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop, Clone)]
pub struct PrivateKey {
    #[zeroize(skip)]
    pub(crate) public_key: PublicKey,
    pub(crate) p: BigUint,
    pub(crate) q: BigUint,
    pub(crate) g_p_precomputed: BigUint,
}

impl PrivateKey {
    pub fn new(public_key: PublicKey, p: BigUint, q: BigUint) -> Result<Self> {
        if p.is_zero() || q.is_zero() {
            return Err(Error::InvalidPrivateKey);
        }

        let p_squared = &p * &p;
        let computed_n = &p_squared * &q;

        if computed_n != *public_key.n() {
            return Err(Error::InvalidPrivateKey);
        }

        // Precompute g^(p-1) mod p² for faster decryption
        let p_minus_1 = &p - BigUint::one();
        let g_p_precomputed = public_key.g().modpow(&p_minus_1, &p_squared);

        Ok(Self {
            public_key,
            p,
            q,
            g_p_precomputed,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    public: PublicKey,
    secret: PrivateKey,
}

impl KeyPair {
    /// Generate a keypair with default parameters (2048 bits).
    pub fn generate() -> Result<Self> {
        KeyPairBuilder::new().build()
    }

    /// Generate with specific bit length (minimum 512).
    // TODO: Should we enforce a minimum?!
    pub fn generate_with_size(bit_length: usize) -> Result<Self> {
        KeyPairBuilder::new().bit_length(bit_length).build()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret_key(&self) -> &PrivateKey {
        &self.secret
    }

    /// Split into public and secret components.
    ///
    /// Useful for scenarios where you want to send the public key elsewhere.
    pub fn into_parts(self) -> (PublicKey, PrivateKey) {
        (self.public.clone(), self.secret.clone())
    }
}

pub struct KeyPairBuilder {
    bit_length: usize,
}

impl KeyPairBuilder {
    pub fn new() -> Self {
        Self { bit_length: 2048 }
    }

    pub fn bit_length(mut self, bits: usize) -> Self {
        self.bit_length = bits;
        self
    }

    pub fn build(self) -> Result<KeyPair> {
        const MIN_BITS: usize = 512;
        if self.bit_length < MIN_BITS {
            return Err(Error::InvalidKeySize {
                min: MIN_BITS,
                actual: self.bit_length,
            });
        }

        let mut rng = OsRng;

        // bit distribution: n = p²q implies |n| = 2|p| + |q|
        let p_bits = self.bit_length / 3;
        let q_bits = self.bit_length - (2 * p_bits);

        let p = generate_safe_prime(p_bits);
        let q = generate_safe_prime(q_bits);

        if p == q {
            return Err(Error::KeyGenerationFailed("Primes must be distinct".into()));
        }

        let p_squared = &p * &p;
        let n = &p_squared * &q;
        let p_minus_1 = &p - BigUint::one();

        // find valid generator: g^(p-1) ≢ 1 (mod p²)
        let g = loop {
            let candidate = rng.gen_biguint_range(&BigUint::from(2u32), &n);
            let check = candidate.modpow(&p_minus_1, &p_squared);
            if check != BigUint::one() {
                break candidate;
            }
        };

        let h = g.modpow(&n, &n);

        let public = PublicKey::new(n, g, h, self.bit_length)?;
        let secret = PrivateKey::new(public.clone(), p, q)?;

        Ok(KeyPair { public, secret })
    }
}

impl Default for KeyPairBuilder {
    fn default() -> Self {
        Self::new()
    }
}
