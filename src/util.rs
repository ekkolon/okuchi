// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Internal cryptographic utilities.
//!
//! All items in this module are crate-private. None are part of the public API.

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use num_bigint_dig::{BigUint, RandPrime};
use num_traits::One;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::{Error, Result};

/// Computes the OU `L` function: `L(x) = (x - 1) / p`.
///
/// Well-defined only when `x ≡ 1 (mod p)`, which holds when `x = c^(p-1) mod p²`
/// by Fermat's little theorem. Integer division is exact in this case; no rounding
/// occurs.
///
/// # Requirements
///
/// - `x` must satisfy `x ≡ 1 (mod p)`; otherwise the division is inexact and
///   the result is cryptographically meaningless
/// - `p` must be non-zero; a zero `p` causes a panic in `BigUint` division
#[inline]
pub fn l_function(x: &BigUint, p: &BigUint) -> BigUint {
    (x - BigUint::one()) / p
}

/// Constant-time modular exponentiation: `base^exp mod modulus`.
///
/// Implemented via `crypto-bigint` Montgomery form, which provides
/// constant-time guarantees for the exponentiation itself. Used in
/// [`Okuchi::decrypt`] for the sensitive operation `c^(p-1) mod p²`
/// to mitigate timing side-channels over the secret exponent `p - 1`.
///
/// # Requirements
///
/// - `modulus` must be odd; `p²` is always odd for any prime `p`
/// - `exp` and `base` may be any non-negative integers; `base` is
///   reduced mod `modulus` internally before conversion
///
/// # Notes
///
/// Bit precision is rounded up to the next multiple of 64 (one limb) to
/// satisfy `crypto-bigint`'s alignment requirement. This does not affect
/// the result.
///
/// The conversion from `num-bigint-dig` to `crypto-bigint` types is
/// variable-time. Only the Montgomery exponentiation itself is constant-time.
pub fn ct_modpow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    // Montgomery form requires base < modulus; c < n but c may be >= p²
    let base = base % modulus;

    // Precision: round modulus bit-length up to a multiple of 64 (limb size)
    let raw_bits = modulus.bits() as u32;
    let bits = raw_bits.div_ceil(64) * 64;
    let bits = bits.max(64);

    let base_b = to_boxed(&base, bits);
    let exp_b = to_boxed(exp, bits);
    let mod_b = to_boxed(modulus, bits);

    let odd_mod = Odd::new(mod_b).expect("p² is always odd");
    let params = BoxedMontyParams::new(odd_mod);
    let base_m = BoxedMontyForm::new(base_b, &params);
    let result = base_m.pow(&exp_b);

    BigUint::from_bytes_be(result.retrieve().to_be_bytes().as_ref())
}

/// Encode `n` as a big-endian [`BoxedUint`] with exactly `bits` bits of precision.
///
/// # Requirements
///
/// - `bits` must be a positive multiple of 64
/// - `n.bits() <= bits`; callers must pre-reduce `n` to ensure this
///
/// Padding is applied on the left (big-endian) to reach `bits / 8` bytes.
/// If `n` requires more bytes than `bits / 8`, the most-significant bytes
/// of `n` are silently truncated. Callers are responsible for preventing this.
fn to_boxed(n: &BigUint, bits: u32) -> BoxedUint {
    let byte_len = (bits / 8) as usize;
    let src = n.to_bytes_be();
    let mut padded = vec![0u8; byte_len];
    // src.len() <= byte_len after pre-reduction
    let copy_len = src.len().min(byte_len);
    padded[byte_len - copy_len..].copy_from_slice(&src[src.len() - copy_len..]);
    BoxedUint::from_be_slice(&padded, bits).expect("padded length matches declared bit precision")
}

/// Generate a prime of the requested bit length.
pub fn generate_prime(bits: usize) -> Result<BigUint> {
    if bits < 2 {
        return Err(Error::KeyGenerationFailed(
            "prime bit length must be >= 2".into(),
        ));
    }
    let mut rng = StdRng::from_os_rng();
    Ok(rng.gen_prime(bits)) // gen_prime uses Miller-Rabin internally
}
