// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Errors that can occur during cryptographic operations.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid key size: must be at least {min} bits, got {actual}")]
    InvalidKeySize { min: usize, actual: usize },

    #[error("Ciphertext is invalid or corrupted")]
    InvalidCiphertext,

    #[error("Plaintext exceeds maximum allowed value")]
    PlaintextTooLarge,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Arithmetic overflow detected")]
    ArithmeticOverflow,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;
