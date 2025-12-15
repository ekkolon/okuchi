// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::{BigUint, ModInverse};
use num_traits::{CheckedSub, One, Zero};

/// L(x) = (x - 1) / p
///
/// # Panics
/// Panics if `x < 1` or `p == 0`.
/// For Okamoto-Uchiyama, `x ≡ 1 (mod p)` so this is safe under correct usage.
///
/// # Crypto Note
/// Explicitly checks `x >= 1` and `p != 0` to satisfy Clippy's `arithmetic_side_effects`.
#[allow(clippy::expect_used)]
#[inline]
pub fn l_function(x: &BigUint, p: &BigUint) -> BigUint {
    debug_assert!(!x.is_zero(), "x must be ≥ 1 in L function");
    debug_assert!(!p.is_zero(), "p must be nonzero in L function");

    x.checked_sub(&BigUint::one()).expect("Subtraction underflow in L function") / p
}

/// Computes modular inverse a⁻¹ mod b.
///
/// Returns an opaque `DecryptionFailed` error if inversion fails.
pub fn mod_inverse<'i>(a: &'i BigUint, b: &'i BigUint) -> crate::Result<BigUint> {
    let modinv = a
        .mod_inverse(b)
        .ok_or_else(|| crate::Error::DecryptionFailed("Modular inverse failed".into()))?
        .to_biguint()
        .ok_or_else(|| {
            crate::Error::DecryptionFailed("Inverse resulted in negative value".into())
        })?;

    Ok(modinv)
}

/// Converts a recovered plaintext [`BigUint`] into its minimal byte form.
///
/// This function defines how zero is interpreted when converting from the
/// mathematical plaintext value `m` back to bytes:
///
/// - `m == 0` is treated as an empty message and yields `b""`.
/// - `m != 0` is converted to its minimal big-endian byte representation.
///
/// This convention is required because, in modular arithmetic, both `b""` and
/// `b"\x00"` map to the same numeric value (`m == 0`). As a result, this function
/// cannot distinguish between them.
///
/// Higher-level encryption logic must ensure that a literal zero byte
/// (`b"\x00"`) is preserved via padding or an unambiguous encoding if that
/// distinction matters. At this stage, `m == 0` always maps to an empty message.
///
/// # Arguments
///
/// * `m` - The recovered plaintext value.
///
/// # Returns
///
/// A `Vec<u8>` containing the plaintext bytes in big-endian order.
pub fn biguint_to_bytes_minimal(m: &BigUint) -> Vec<u8> {
    if m.is_zero() {
        return Vec::new();
    }
    m.to_bytes_be()
}
