// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Okamoto-Uchiyama Cryptosystem
//!
//! A pure Rust implementation of the Okamoto-Uchiyama (OU) probabilistic
//! public-key encryption scheme with additive homomorphism.
//!
//! Security relies on the hardness of factoring `n = p²q` and computing
//! discrete logarithms modulo `p²`.
//!
//! Reference:
//!   Okamoto & Uchiyama, "A New Public-Key Cryptosystem as Secure as Factoring", EUROCRYPT 1998.
//!
//! ## Quick Start
//!
//! ```rust
//! use okuchi::{KeyPair, Okuchi};
//!
//! let keypair = KeyPair::new_2048().unwrap();
//!
//! let ciphertext = Okuchi::encrypt(keypair.pub_key(), b"hello").unwrap();
//! let plaintext  = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();
//!
//! assert_eq!(plaintext, b"hello");
//! ```
//!
//! ## Homomorphic Addition
//!
//! Multiplying two ciphertexts mod `n` decrypts to the sum of their plaintexts
//! mod `p`:
//!
//! ```rust
//! use okuchi::{KeyPair, Okuchi};
//!
//! let keypair = KeyPair::new_2048().unwrap();
//! let pub_key  = keypair.pub_key();
//!
//! let c1  = Okuchi::encrypt(pub_key, 10u32.to_be_bytes()).unwrap();
//! let c2  = Okuchi::encrypt(pub_key, 20u32.to_be_bytes()).unwrap();
//! let sum = Okuchi::homomorphic_add(pub_key, &c1, &c2);
//! // Decrypts to 30
//! ```
//!
//! ## Security Notice
//!
//! Decryption uses `num-bigint-dig` for `modpow`, `mod_inverse`, and integer
//! division over secret values. These operations are **not** constant-time.
//! Timing side-channels are possible in adversarial environments.
//!
//! The sensitive modular exponentiation in the decrypt path (`c^(p-1) mod p²`)
//! is routed through `crypto-bigint` Montgomery form for constant-time
//! guarantees. All other big-integer operations remain variable-time.
//!
//! Do not use this crate in contexts where timing oracles are a threat model
//! concern without a full audit of the remaining variable-time paths.
//!
//! ## Key Size
//!
//! The minimum enforced key size is 2048 bits (`KeyPair::new` rejects smaller
//! values). For production use, at least 2048 bits or larger is recommended.

mod ciphertext;
mod error;
mod key;
mod okuchi;
mod plaintext;
#[cfg(feature = "seal")]
mod seal;
#[cfg(feature = "stream")]
mod stream;
mod util;

pub use ciphertext::Ciphertext;
pub use error::{Error, Result};
pub use key::{KeyPair, PrivateKey, PublicKey};
pub use okuchi::Okuchi;
pub use plaintext::Plaintext;
