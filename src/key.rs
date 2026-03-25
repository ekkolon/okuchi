// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::{BigUint, ModInverse, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::util::l_function;
use crate::{Error, Result};

/// Okamoto-Uchiyama public key `(n, g, h)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    // `n = p²q` where `p` and `q` are distinct large primes
    n: BigUint,
    // `g ∈ ℤ_n*` with `g^(p-1) ≢ 1 (mod p²)` (OU generator condition)
    g: BigUint,
    // `h = g^n mod n`, has order `p` in `ℤ_n*`
    h: BigUint,
    bit_length: usize,
}

impl PublicKey {
    /// Construct a [`PublicKey`] from raw parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if any parameter is zero or if `g >= n` or `h >= n`.
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

    /// The modulus `n = p²q`.
    #[inline]
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// The OU generator `g`, satisfying `g^(p-1) ≢ 1 (mod p²)` and `gcd(g, n) = 1`.
    #[inline]
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// The randomization base `h = g^n mod n`, which has order `p` in `ℤ_n*`.
    ///
    /// Used as the blinding factor base during encryption: `h^r mod n`.
    #[inline]
    pub fn h(&self) -> &BigUint {
        &self.h
    }

    /// The nominal bit length of `n` as supplied at construction.
    #[inline]
    pub fn bit_length(&self) -> usize {
        self.bit_length
    }

    /// Conservative upper bound on the plaintext bit length.
    /// [`Error::PlaintextTooLarge`].
    #[inline]
    pub fn plaintext_bound_bits(&self) -> usize {
        (self.bit_length / 3).saturating_sub(1)
    }
}

/// Okamoto-Uchiyama private key.
///
/// Holds the secret prime factorization of `n` and precomputed decryption
/// constants derived from it.
///
/// # Security
///
/// All secret fields (`p`, `q`, `p_squared`, `l_gp_inv`) are zeroed on drop
/// via [`ZeroizeOnDrop`].
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop, Clone)]
pub struct PrivateKey {
    #[zeroize(skip)]
    public_key: PublicKey,

    // Secret prime `p` where `n = p²q`.
    p: BigUint,

    // Secret prime `q`.
    q: BigUint,

    /// Cached `p²`, used as the modulus for the decryption exponentiation.
    p_squared: BigUint,

    // Precomputed `L(g^(p-1) mod p²)^(-1) mod p`.
    //
    // Eliminates a modular inverse from every decryption call. Treated as
    // secret key material because it is derived from `g` and `p`.
    l_gp_inv: BigUint,
}

impl PrivateKey {
    /// Construct a [`PrivateKey`] and precompute decryption constants.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if:
    /// - `p` or `q` is zero
    /// - `p²q != n`
    /// - `L(g^(p-1) mod p²)` has no inverse mod `p`, which means `g` does not
    ///   satisfy the OU generator condition and decryption would be undefined
    ///
    /// # Notes
    ///
    /// The `modpow` used here (`num-bigint-dig`) is variable-time. This call
    /// occurs only at key construction, not during decryption.
    pub fn new(public_key: PublicKey, p: BigUint, q: BigUint) -> Result<PrivateKey> {
        if p.is_zero() || q.is_zero() {
            return Err(Error::InvalidPrivateKey);
        }
        let p_squared = &p * &p;
        if &p_squared * &q != *public_key.n() {
            return Err(Error::InvalidPrivateKey);
        }

        let p_minus_1 = &p - BigUint::one();
        let g_p = public_key.g().modpow(&p_minus_1, &p_squared);

        // g^(p-1) ≢ 1 (mod p²) was enforced at generator selection; L(g_p) ≠ 0.
        let l_gp = l_function(&g_p, &p);
        let l_gp_inv = l_gp
            .mod_inverse(&p)
            .ok_or(Error::InvalidPrivateKey)?
            .to_biguint()
            .ok_or(Error::InvalidPrivateKey)?;

        Ok(Self {
            public_key,
            p,
            q,
            p_squared,
            l_gp_inv,
        })
    }

    /// Returns the public key associated with this private key.
    #[inline]
    pub fn pub_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Secret prime `p`.
    #[inline]
    pub(crate) fn p(&self) -> &BigUint {
        &self.p
    }

    /// Cached value of `p²`.
    #[inline]
    pub(crate) fn p_squared(&self) -> &BigUint {
        &self.p_squared
    }

    /// Precomputed `L(g^(p-1) mod p²)^(-1) mod p`.
    #[inline]
    pub(crate) fn l_gp_inv(&self) -> &BigUint {
        &self.l_gp_inv
    }
}

/// Minimum key size enforced by [`KeyPair::new`].
const MIN_BIT_LENGTH: usize = 2048;

/// A matched Okamoto-Uchiyama key pair `(PublicKey, PrivateKey)`.
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub_key: PublicKey,
    priv_key: PrivateKey,
}

impl KeyPair {
    const BITS_2048: usize = 2048;
    const BITS_3072: usize = 3072;
    const BITS_4096: usize = 4096;

    /// Generate a fresh Okamoto-Uchiyama key pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeySize`] if `bit_length < 2048`.
    ///
    /// Returns [`Error::KeyGenerationFailed`] if:
    /// - Safe prime generation exceeds 2048 retries for either prime
    /// - The generated primes `p` and `q` are equal (negligible probability)
    ///
    /// # Notes
    ///
    /// Generator selection uses rejection sampling over `ℤ_n*` and terminates
    /// in expected constant iterations. Entropy is sourced from [`OsRng`].
    pub fn new(bit_length: usize) -> Result<Self> {
        if bit_length < MIN_BIT_LENGTH {
            return Err(Error::InvalidKeySize {
                min: MIN_BIT_LENGTH,
                actual: bit_length,
            });
        }

        let mut rng = OsRng;
        let p_bits = bit_length / 3;
        let q_bits = bit_length - (2 * p_bits);

        let p = crate::util::generate_prime(p_bits)?;
        let q = crate::util::generate_prime(q_bits)?;

        if p == q {
            return Err(Error::KeyGenerationFailed("Primes must be distinct".into()));
        }

        let p_squared = &p * &p;
        let n = &p_squared * &q;
        let p_minus_1 = &p - BigUint::one();

        let g = loop {
            let candidate = rng.gen_biguint_range(&BigUint::from(2u32), &n);

            // core OU generator requirement:
            //   g^(p-1) ≢ 1 (mod p²)
            //   gcd(g, n) = 1, where g in ℤ_n*
            if candidate.modpow(&p_minus_1, &p_squared) != BigUint::one()
                && candidate.gcd(&n).is_one()
            {
                break candidate;
            }
        };

        // h = g^n mod n
        let h = g.modpow(&n, &n);

        let public_key = PublicKey::new(n, g, h, bit_length)?;
        let private_key = PrivateKey::new(public_key.clone(), p, q)?;

        Ok(Self {
            pub_key: public_key,
            priv_key: private_key,
        })
    }

    /// Generate a 2048 bits sized Okamoto-Uchiyama key pair.
    pub fn new_2048() -> Result<Self> {
        Self::new(Self::BITS_2048)
    }

    /// Generate a 3072 bits sized Okamoto-Uchiyama key pair.
    pub fn new_3072() -> Result<Self> {
        Self::new(Self::BITS_3072)
    }

    /// Generate a 4096 bits sized Okamoto-Uchiyama key pair.
    pub fn new_4096() -> Result<Self> {
        Self::new(Self::BITS_4096)
    }

    /// Returns a reference to the public key.
    #[inline]
    pub fn pub_key(&self) -> &PublicKey {
        &self.pub_key
    }

    /// Returns a reference to the private key.
    #[inline]
    pub fn priv_key(&self) -> &PrivateKey {
        &self.priv_key
    }
}
