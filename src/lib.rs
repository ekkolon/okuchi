// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Okamoto-Uchiyama Cryptosystem
//!
//! This crate provides an implementation of the Okamoto-Uchiyama public-key
//! cryptosystem, a probabilistic encryption scheme with additive homomorphic
//! properties.
//!
//! The construction is based on the hardness of factoring an RSA-like modulus
//! of the form `n = p²q` and computing discrete logarithms modulo `p²`.
//!
//! ## Features
//!
//! - Probabilistic public-key encryption
//! - Additive homomorphism over encrypted messages
//! - Explicit key separation and validation
//! - Streaming encryption and decryption interfaces
//! - Automatic zeroization of secret key material
//!
//! ## Security Model
//!
//! Security relies on the *p-subgroup assumption* as described in the original
//! paper. The private key components `(p, q)` are treated as sensitive material
//! and are zeroized on drop using the [`zeroize`] crate.
//!
//! This crate aims to follow established Rust cryptography practices:
//! failures during sensitive operations are reported conservatively, and
//! error messages avoid leaking internal state or validation details.
//!
//! ## References
//!
//! - T. Okamoto, S. Uchiyama, *A New Public-Key Cryptosystem as Secure as Factoring*,
//!   EUROCRYPT 1998.
//!   <https://link.springer.com/chapter/10.1007/BFb0054135>

#![deny(unsafe_code)] // forbid unsafe
#![deny(missing_docs)] // require docs everywhere
#![deny(missing_debug_implementations)] // require Debug for public structs
#![deny(unused_must_use)] // catch ignored results
#![deny(nonstandard_style)] // enforce Rust naming conventions
#![deny(rust_2018_idioms)] // enforce idiomatic code
#![warn(clippy::unwrap_used)] // discourage unwrap
#![warn(clippy::expect_used)] // discourage expect
#![warn(clippy::large_enum_variant)]
#![warn(clippy::manual_memcpy)] // prefer safe copying
#![warn(clippy::mut_mut)] // avoid double mut
#![warn(clippy::clone_on_ref_ptr)] // avoid unnecessary clones

mod ciphertext;
mod crypto;
mod error;
mod keypair;

pub use ciphertext::Ciphertext;
pub use crypto::{Decrypt, DecryptBytes, Encrypt, EncryptBytes, Stream};
pub use error::{Error, Result};
pub use keypair::{KeyPair, KeyPairBuilder, PrivateKey, PublicKey};
