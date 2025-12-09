// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Error, Result};

use num_bigint_dig::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    n: BigUint,
    g: BigUint,
    h: BigUint,
    bit_length: usize,
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

    #[inline]
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    #[inline]
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    #[inline]
    pub fn h(&self) -> &BigUint {
        &self.h
    }

    #[inline]
    pub fn bit_length(&self) -> usize {
        self.bit_length
    }
}

/// Private key with automatic secure erasure.
///
/// The `Zeroize` and `ZeroizeOnDrop` traits ensure that p, q, and the
/// precomputed value are wiped from memory when this struct is dropped.
/// `num-bigint-dig` implements `Zeroize` for `BigUint`, which recursively
/// zeroes the underlying heap-allocated digit vectors.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop, Clone)]
pub struct PrivateKey {
    #[zeroize(skip)]
    public_key: PublicKey,

    /// Prime factor p where n = p²q
    pub(crate) p: BigUint,

    /// Prime factor q
    pub(crate) q: BigUint,

    /// Cached g^(p-1) mod p² for faster decryption
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

        // Precompute g^(p-1) mod p² once during key creation
        let p_minus_1 = &p - BigUint::one();
        let g_p_precomputed = public_key.g().modpow(&p_minus_1, &p_squared);

        Ok(Self {
            public_key,
            p,
            q,
            g_p_precomputed,
        })
    }

    #[inline]
    pub fn pub_key(&self) -> &PublicKey {
        &self.public_key
    }
}

const MIN_BIT_LENGTH: usize = 512;

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub_key: PublicKey,
    priv_key: PrivateKey,
}

impl KeyPair {
    /// Generates a new Okamoto-Uchiyama keypair.
    ///
    /// ## Security Parameters
    ///
    /// - `bit_length`: Total security parameter (≥ 512 bits, recommend 2048+)
    ///
    /// The primes p and q are chosen such that |n| ≈ bit_length:
    /// - |p| ≈ bit_length / 3
    /// - |q| ≈ bit_length - 2|p|
    ///
    /// Both p and q are safe primes (p = 2p' + 1 where p' is prime) to
    /// maximize factorization difficulty.
    ///
    /// ## Generator Selection
    ///
    /// The generator g is chosen uniformly from [2, n-1] subject to:
    /// g^(p-1) ≢ 1 (mod p²)
    ///
    /// This ensures the discrete log problem in the p-subgroup is hard.
    pub fn new(bit_length: usize) -> Result<Self> {
        if bit_length < MIN_BIT_LENGTH {
            return Err(Error::InvalidKeySize {
                min: MIN_BIT_LENGTH,
                actual: bit_length,
            });
        }

        let mut rng = OsRng;

        // Bit distribution: n = p²q implies |n| = 2|p| + |q|
        let p_bits = bit_length / 3;
        let q_bits = bit_length - (2 * p_bits);

        let p = crate::util::generate_safe_prime(p_bits);
        let q = crate::util::generate_safe_prime(q_bits);

        if p == q {
            // astronomically unlikely, but we must guarantee distinct p,q  primes
            return Err(Error::KeyGenerationFailed("Primes must be distinct".into()));
        }

        let p_squared = &p * &p;
        let n = &p_squared * &q;
        let p_minus_1 = &p - BigUint::one();

        // find a valid generator
        let g = loop {
            let candidate = rng.gen_biguint_range(&BigUint::from(2u32), &n);

            // Core requirement: g^(p-1) ≢ 1 (mod p²)
            let check = candidate.modpow(&p_minus_1, &p_squared);
            if check != BigUint::one() {
                break candidate;
            }
        };

        // compute h = g^n mod n
        let h = g.modpow(&n, &n);

        let public_key = PublicKey::new(n, g, h, bit_length)?;
        let private_key = PrivateKey::new(public_key.clone(), p, q)?;

        Ok(Self {
            pub_key: public_key,
            priv_key: private_key,
        })
    }

    #[inline]
    pub fn pub_key(&self) -> &PublicKey {
        &self.pub_key
    }

    #[allow(unused)]
    #[inline]
    pub fn priv_key(&self) -> &PrivateKey {
        &self.priv_key
    }
}
