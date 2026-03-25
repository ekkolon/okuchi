// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::BigUint;

use crate::{Error, Result};

/// An Okamoto-Uchiyama ciphertext element in `ℤ_n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    value: BigUint,
}

impl Ciphertext {
    /// Construct from a raw `BigUint`.
    pub(crate) fn new(value: BigUint) -> Self {
        Self { value }
    }

    /// Construct a [`Ciphertext`] from a big-endian byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCiphertext`] if the decoded value is `>= n`.
    ///
    /// # Notes
    ///
    /// Leading zero bytes are accepted and ignored by `BigUint::from_bytes_be`.
    /// An empty slice decodes to zero, which is a valid ciphertext value.
    pub fn from_bytes(bytes: &[u8], n: &BigUint) -> Result<Self> {
        let value = BigUint::from_bytes_be(bytes);
        if &value >= n {
            return Err(Error::InvalidCiphertext);
        }
        Ok(Self { value })
    }

    /// Returns a reference to the raw ciphertext integer.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Serialize the ciphertext to big-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }
}
