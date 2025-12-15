// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Okamoto-Uchiyama Cryptosystem
//!
//! Probabilistic encryption scheme with additive homomorphism, based on the
//! hardness of factoring n = p²q and computing discrete logs mod p².
//!
//! Reference: [Okamoto & Uchiyama (1998), EUROCRYPT](https://link.springer.com/chapter/10.1007/BFb0054135)
//!
//! ## Security
//!
//! The scheme is secure under the p-subgroup assumption. The private key
//! (p, q) is automatically zeroized on drop via the `zeroize` crate.

mod ciphertext;
mod error;
mod key;
mod util;

mod decrypt;
mod encrypt;
mod stream;

pub use ciphertext::*;
pub use decrypt::*;
pub use encrypt::*;
pub use error::*;
pub use key::*;
pub use stream::*;
