// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::ops::{Deref, Mul};

use num_bigint_dig::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    value: BigUint,
}

impl Ciphertext {
    pub fn new(value: BigUint) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &BigUint {
        &self.value
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }
}

impl Deref for Ciphertext {
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

use std::convert::From;

impl<T> From<T> for Ciphertext
where
    T: AsRef<[u8]>,
{
    fn from(data: T) -> Self {
        let bytes = data.as_ref();
        Self {
            value: BigUint::from_bytes_be(bytes),
        }
    }
}

// Homomorphic multiplication: E(m₁) · E(m₂) = E(m₁ + m₂)
impl Mul for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: Self) -> Ciphertext {
        Ciphertext::new(&self.value * &rhs.value)
    }
}

impl Mul for Ciphertext {
    type Output = Ciphertext;

    fn mul(self, rhs: Self) -> Ciphertext {
        Ciphertext::new(self.value * rhs.value)
    }
}
