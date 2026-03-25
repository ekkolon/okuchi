// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::BigUint;
use num_traits::Zero;

use crate::error::{Error, Result};
use crate::key::PublicKey;

/// A validated plaintext value in the OU plaintext space `ℤ_p`.
///
/// ## Homomorphic Accumulation
///
/// OU homomorphic addition computes `(m1 + m2) mod p` in the ciphertext domain.
/// If the true sum meets or exceeds the secret `p`, the result wraps silently
/// with no error at decryption time. [`Plaintext::checked_add`] detects overflow
/// against the conservative public bound before encryption.
///
/// Use [`checked_add`](Plaintext::checked_add) whenever accumulating values
/// that will later be combined homomorphically. Note that passing the bound
/// check does not guarantee the sum is below the actual `p`; it only
/// guarantees it is below `2^(p_bits - 1)`, a strict subset of `ℤ_p`.
///
/// ```rust,no_run
/// use okuchi::{KeyPair, Okuchi, Plaintext};
/// use num_bigint_dig::BigUint;
///
/// let keypair = KeyPair::new(2048).unwrap();
/// let pub_key = keypair.pub_key();
///
/// let a = Plaintext::new(BigUint::from(100u32), pub_key).unwrap();
/// let b = Plaintext::new(BigUint::from(200u32), pub_key).unwrap();
/// let sum = a.checked_add(b, pub_key).unwrap(); // Err if sum exceeds bound
///
/// let ct = Okuchi::encrypt_plaintext(pub_key, &sum).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plaintext(BigUint);

impl Plaintext {
    /// Construct a [`Plaintext`], validating that `value` fits within the conservative OU plaintext bound.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PlaintextTooLarge`] if `value.bits() > pub_key.plaintext_bound_bits()`.
    pub fn new(value: impl Into<BigUint>, pub_key: &PublicKey) -> Result<Plaintext> {
        let value = value.into();
        let max_bits = pub_key.plaintext_bound_bits();
        if value.bits() as usize > max_bits {
            return Err(Error::PlaintextTooLarge);
        }
        Ok(Self(value))
    }

    /// Construct a [`Plaintext`] from a big-endian byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PlaintextTooLarge`] if the decoded value exceeds the bound.
    pub fn from_bytes_be(bytes: &[u8], pub_key: &PublicKey) -> Result<Plaintext> {
        Self::new(BigUint::from_bytes_be(bytes), pub_key)
    }

    /// Checked addition in the plaintext domain.
    ///
    /// Returns a new [`Plaintext`] containing `self + other` if the result
    /// satisfies the plaintext bound. Consumes both operands.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PlaintextTooLarge`] if `self + other` exceeds
    /// `2^(p_bits - 1) - 1`.
    ///
    /// # Notes
    ///
    /// A sum that passes this check may still equal or exceed the secret `p`
    /// if the actual `p` is close to `2^(p_bits - 1)`. For values well below
    /// the bound this risk is negligible. The check is conservative, not exact.
    pub fn checked_add(self, other: Plaintext, pub_key: &PublicKey) -> Result<Plaintext> {
        Plaintext::new(self.0 + other.0, pub_key)
    }

    /// Returns a reference to the inner plaintext integer.
    pub fn value(&self) -> &BigUint {
        &self.0
    }

    /// Whether the plaintext value is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Encode the plaintext as big-endian bytes.
    ///
    /// The output is suitable for direct use as input to [`Okuchi::encrypt`](crate::Okuchi::encrypt).
    /// `BigUint::to_bytes_be` strips leading zero bytes; a zero value returns an empty `Vec`.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.to_bytes_be()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;
    use num_traits::One;

    const TEST_KEY_SIZE: usize = 2048;

    #[test]
    fn plaintext_bounds_enforced() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let pub_key = keypair.pub_key();
        let max_bits = pub_key.plaintext_bound_bits();

        // Exactly at the bound: ok
        let max_val = (BigUint::one() << max_bits) - BigUint::one();
        assert!(Plaintext::new(max_val.clone(), pub_key).is_ok());

        // One bit over: rejected
        let over = max_val + BigUint::one();
        assert!(matches!(
            Plaintext::new(over, pub_key),
            Err(Error::PlaintextTooLarge)
        ));
    }

    #[test]
    fn checked_add_rejects_overflow() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let pub_key = keypair.pub_key();
        let max_bits = pub_key.plaintext_bound_bits();

        // Two values that individually fit but sum to overflow
        let half = BigUint::one() << (max_bits - 1);
        let a = Plaintext::new(half.clone(), pub_key).unwrap();
        let b = Plaintext::new(half.clone(), pub_key).unwrap();
        // half + half = 2^(max_bits-1) * 2 = 2^max_bits which is one bit over
        let result = a.checked_add(b, pub_key);
        assert!(matches!(result, Err(Error::PlaintextTooLarge)));
    }

    #[test]
    fn checked_add_within_bound() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let pub_key = keypair.pub_key();
        let a = Plaintext::new(BigUint::from(10u32), pub_key).unwrap();
        let b = Plaintext::new(BigUint::from(20u32), pub_key).unwrap();
        let sum = a.checked_add(b, pub_key).unwrap();
        assert_eq!(sum.value(), &BigUint::from(30u32));
    }
}
