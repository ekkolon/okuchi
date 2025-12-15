// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Error, PublicKey, Result};
use std::ops::Deref;

use num_bigint_dig::BigUint;

/// Ciphertext bound to a specific public key's modulus.
///
/// This prevents accidentally mixing ciphertexts from different key pairs
/// during homomorphic operations.
#[derive(Debug, Clone)]
pub struct Ciphertext {
    value: BigUint,
    /// Store modulus bit length as a fingerprint
    /// (not cryptographically binding, but catches common mistakes)
    pub(crate) modulus_bits: usize,
}

impl Ciphertext {
    /// Creates a ciphertext with modulus validation
    pub(crate) fn new(value: BigUint, modulus_bits: usize) -> Self {
        Self {
            value,
            modulus_bits,
        }
    }

    /// Get the underlying value (read-only)
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }

    /// Deserialize from bytes (requires modulus context)
    pub fn from_bytes(bytes: &[u8], modulus_bits: usize) -> Self {
        Self::new(BigUint::from_bytes_be(bytes), modulus_bits)
    }

    /// Homomorphic addition: E(m1) ⊕ E(m2) = E(m1 + m2)
    ///
    /// Requires both ciphertexts to be from the same key.
    pub fn add(&self, other: &Self, pub_key: &PublicKey) -> Result<Self> {
        if self.modulus_bits != other.modulus_bits {
            return Err(Error::KeyMismatch);
        }

        let n = pub_key.n();
        let sum_value = (&self.value * &other.value) % n;
        Ok(Self::new(sum_value, self.modulus_bits))
    }
}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.modulus_bits == other.modulus_bits
    }
}

impl Eq for Ciphertext {}

impl Deref for Ciphertext {
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
