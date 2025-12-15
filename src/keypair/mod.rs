// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(unused_assignments)]

mod util;

use crate::ciphertext::Ciphertext;
use crate::crypto::{Decryptor, Encryptor};
use crate::error::{Error, Result};
use crate::{Decrypt, DecryptBytes, Encrypt, EncryptBytes};

use num_bigint_dig::BigUint;
use num_traits::{One, Zero};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public parameters of the cryptosystem.
///
/// The modulus follows the form `n = p²q`. The values `g` and `h` are generators
/// derived from `n` and are required for encryption and homomorphic operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) n: BigUint,
    pub(crate) g: BigUint,
    pub(crate) h: BigUint,
    pub(crate) bit_length: usize,
}

impl PublicKey {
    /// Construct a new public key from its components.
    ///
    /// All parameters must be non-zero and strictly smaller than `n`.
    pub fn new(n: BigUint, g: BigUint, h: BigUint, bit_length: usize) -> Result<Self> {
        if n.is_zero() || g.is_zero() || h.is_zero() {
            return Err(Error::InvalidPublicKey);
        }
        if g >= n || h >= n {
            return Err(Error::InvalidPublicKey);
        }

        Ok(Self { n, g, h, bit_length })
    }

    /// Return the public modulus `n`.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// Return the generator `g`.
    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// Return the auxiliary generator `h`.
    pub fn h(&self) -> &BigUint {
        &self.h
    }

    /// Return the configured bit length of the modulus.
    pub fn bit_length(&self) -> usize {
        self.bit_length
    }
}

/// Secret key material.
///
/// Contains the factorization of the public modulus and precomputed values
/// required for efficient decryption. Sensitive fields are zeroized on drop.
#[allow(missing_debug_implementations)]
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "expose-secret", derive(Debug))]
pub struct PrivateKey {
    #[zeroize(skip)]
    pub(crate) public_key: PublicKey,
    pub(crate) p: BigUint,
    pub(crate) q: BigUint,

    /// Precomputed value `g^(p-1) mod p²` used during decryption.
    pub(crate) g_p_precomputed: BigUint,
}

impl PrivateKey {
    /// Construct a private key from its components.
    ///
    /// Validates that the provided factors reconstruct the public modulus.
    pub fn new(public_key: PublicKey, p: BigUint, q: BigUint) -> Result<Self> {
        if p.is_zero() || q.is_zero() {
            return Err(Error::InvalidPrivateKey);
        }

        let p_squared = &p * &p;
        let computed_n = &p_squared * &q;

        if computed_n != *public_key.n() {
            return Err(Error::InvalidPrivateKey);
        }

        let p_minus_1 = &p - BigUint::one();
        let g_p_precomputed = public_key.g().modpow(&p_minus_1, &p_squared);

        Ok(Self { public_key, p, q, g_p_precomputed })
    }

    /// Return a reference to the associated public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

/// A complete key pair consisting of public and private components.
///
/// Secret material is zeroized when dropped.
#[allow(missing_debug_implementations)]
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "expose-secret", derive(Debug))]
pub struct KeyPair {
    #[zeroize(skip)]
    #[allow(dead_code)]
    public: PublicKey,
    secret: PrivateKey,
}

impl<'a> KeyPair {
    /// Generate a key pair with default parameters (2048-bit modulus).
    pub fn generate() -> Result<Self> {
        KeyPairBuilder::new().build()
    }

    /// Generate a key pair with a custom modulus size.
    pub fn generate_with_size(bit_length: usize) -> Result<Self> {
        KeyPairBuilder::new().bit_length(bit_length).build()
    }

    /// Return the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Return the private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.secret
    }

    /// Create a streaming encryptor bound to this public key.
    pub fn encryptor(&'a self) -> Encryptor<'a> {
        self.public.encryptor()
    }

    /// Create a streaming decryptor bound to this private key.
    pub fn decryptor(&'a self) -> Decryptor<'a> {
        self.secret.decryptor()
    }
}

impl Encrypt for KeyPair {
    fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Ciphertext> {
        self.public.encrypt(plaintext)
    }
}

impl EncryptBytes for KeyPair {
    fn encrypt_bytes<P: AsRef<[u8]>>(&self, data: P) -> Result<Vec<u8>> {
        self.public.encrypt_bytes(data)
    }
}

impl Decrypt for KeyPair {
    fn decrypt(&self, ciphertext: &crate::Ciphertext) -> Result<Vec<u8>> {
        self.secret.decrypt(ciphertext)
    }
}

impl DecryptBytes for KeyPair {
    fn decrypt_bytes<P: AsRef<[u8]>>(&self, packed: P) -> Result<Vec<u8>> {
        self.secret.decrypt_bytes(packed)
    }
}

/// Builder for generating key pairs with configurable parameters.
#[derive(Debug)]
pub struct KeyPairBuilder {
    bit_length: usize,
}

impl KeyPairBuilder {
    /// Create a builder with default parameters.
    pub fn new() -> Self {
        Self { bit_length: 2048 }
    }

    /// Minimum recommended for production (NIST/ENISA standard)
    pub const MIN_SECURE_BITS: usize = 2048;

    /// Absolute minimum enforced in production builds
    /// Can be bypassed with `allow-weak-keys` feature flag
    #[cfg(not(feature = "allow-weak-keys"))]
    const ABSOLUTE_MIN_BITS: usize = 512;

    #[cfg(feature = "allow-weak-keys")]
    const ABSOLUTE_MIN_BITS: usize = 128;

    /// Set the desired modulus bit length.
    pub fn bit_length(mut self, bits: usize) -> Self {
        self.bit_length = bits;
        self
    }

    /// Generate the key pair.
    pub fn build(self) -> Result<KeyPair> {
        // Hard block dangerously small keys
        if self.bit_length < Self::ABSOLUTE_MIN_BITS {
            return Err(Error::InvalidKeySize);
        }

        // Loud warning for weak keys
        if self.bit_length < Self::MIN_SECURE_BITS {
            eprintln!(
                "⚠️  SECURITY WARNING: {}-bit key is cryptographically weak!",
                self.bit_length
            );
            eprintln!("⚠️  Use {} bits minimum for production", Self::MIN_SECURE_BITS);
        }

        // Modulus structure: n = p²q, so |n| = 2|p| + |q|.
        let p_bits = self.bit_length / 3;
        let p = util::generate_safe_prime(p_bits);

        let q_bits = self.bit_length - (2 * p_bits);
        let q = util::generate_safe_prime(q_bits);

        if p == q {
            return Err(Error::KeyGenerationFailed("Primes must be distinct".into()));
        }

        let p_squared = &p * &p;
        let p_minus_1 = &p - BigUint::one();
        let n = &p_squared * &q;

        let g = util::find_generator(&n, &p_minus_1, &p_squared);
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
