// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Crate-wide result type alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Error variants produced by OU cryptographic operations
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The requested key size is below the minimum safe threshold.
    #[error("Invalid key size: must be at least {min} bits, got {actual}")]
    InvalidKeySize { min: usize, actual: usize },

    /// The ciphertext value is out of range or the packed byte format is malformed.
    #[error("Ciphertext is invalid or corrupted")]
    InvalidCiphertext,

    /// The plaintext integer exceeds the conservative OU plaintext bound.
    #[error("Plaintext exceeds maximum allowed value")]
    PlaintextTooLarge,

    /// Prime generation or key assembly failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Reserved for arithmetic overflow conditions.
    #[error("Arithmetic overflow detected")]
    ArithmeticOverflow,

    /// The supplied public key parameters are structurally invalid.
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// The supplied private key parameters are structurally invalid.
    #[error("Invalid private key")]
    InvalidPrivateKey,

    /// A stream decryption or packed-format operation failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}
