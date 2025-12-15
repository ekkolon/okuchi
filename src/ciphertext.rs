// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::{Error, Result};
use crate::keypair::PublicKey;

use num_bigint_dig::BigUint;
use std::ops::Deref;

/// A Paillier ciphertext bound to a specific public-key modulus.
///
/// The stored modulus bit length acts as a lightweight fingerprint to prevent
/// accidental mixing of ciphertexts originating from different key pairs.
/// This is a safety check, not a cryptographic binding.
#[derive(Debug, Clone, Eq)]
pub struct Ciphertext {
    value: BigUint,

    /// Bit length of the public modulus used to create this ciphertext.
    pub(crate) modulus_bits: usize,
}

impl Ciphertext {
    /// Construct a new ciphertext with the given modulus context.
    pub(crate) fn new(value: BigUint, modulus_bits: usize) -> Self {
        Self { value, modulus_bits }
    }

    /// Return a reference to the underlying ciphertext value.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Serialize the ciphertext value as big-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }

    /// Deserialize a ciphertext from big-endian bytes.
    ///
    /// The caller must supply the modulus bit length to restore the
    /// key context.
    pub fn from_bytes(bytes: &[u8], modulus_bits: usize) -> Self {
        Self::new(BigUint::from_bytes_be(bytes), modulus_bits)
    }

    /// Homomorphic addition.
    ///
    /// Given ciphertexts `E(m₁)` and `E(m₂)`, returns `E(m₁ + m₂)`.
    /// Both operands must originate from the same public key.
    pub fn add(&self, other: &Self, pub_key: &PublicKey) -> Result<Self> {
        if self.modulus_bits != other.modulus_bits {
            return Err(Error::KeyMismatch);
        }

        let n = pub_key.n();
        let sum = (&self.value * &other.value) % n;

        Ok(Self::new(sum, self.modulus_bits))
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.modulus_bits == other.modulus_bits
    }
}

impl Deref for Ciphertext {
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
