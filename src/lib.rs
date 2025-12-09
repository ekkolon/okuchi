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
//!
//! ## Example
//!
//! ```rust,no_run
//! use okuchi::{KeyPair, Okuchi};
//! use num_bigint_dig::BigUint;
//!
//! let keypair = KeyPair::new(2048).expect("key generation failed");
//! let message = "hello world";
//!
//! let ciphertext = Okuchi::encrypt(keypair.pub_key(), &message).expect("encryption failed");
//! let decrypted = Okuchi::decrypt(keypair.priv_key(), &ciphertext).expect("decryption failed");
//! assert_eq!(message.as_bytes(), decrypted);
//! ```

mod ciphertext;
mod error;
mod key;
mod okuchi;
mod util;

pub use ciphertext::*;
pub use error::*;
pub use key::*;
pub use okuchi::*;
