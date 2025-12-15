// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

/// A specialized `Result` type for cryptographic operations in this crate.
///
/// This is a convenience alias for `std::result::Result<T, Error>`, where
/// `Error` enumerates all failure modes that can occur during key
/// generation, encryption, decryption, and other cryptographic operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations.
///
/// Error messages are intentionally conservative. For failure modes that may
/// leak information through error distinctions (in particular during
/// encryption, decryption, and key handling), messages are kept opaque and
/// non-diagnostic, following common practice in cryptographic libraries.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The requested key size does not meet the minimum security requirements.
    #[error("invalid key size")]
    InvalidKeySize,

    /// The ciphertext is malformed, corrupted, or otherwise invalid.
    ///
    /// This error is intentionally non-specific to avoid revealing details
    /// about internal validation steps.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// The plaintext value exceeds the representable or permitted range.
    #[error("plaintext too large")]
    PlaintextTooLarge,

    /// Key generation failed due to an internal error.
    ///
    /// This typically indicates an unexpected condition such as invalid
    /// parameters or failure to satisfy required mathematical properties.
    #[error("key generation failed")]
    KeyGenerationFailed(String),

    /// An arithmetic operation overflowed or violated internal invariants.
    #[error("arithmetic error")]
    ArithmeticOverflow,

    /// The provided public key is structurally invalid.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// The provided private key is structurally invalid or inconsistent with
    /// the associated public key.
    #[error("invalid private key")]
    InvalidPrivateKey,

    /// Encryption failed.
    ///
    /// The underlying cause is intentionally not exposed to avoid creating
    /// distinguishable failure modes.
    #[error("encryption failed")]
    EncryptionFailed(String),

    /// Decryption failed.
    ///
    /// This error deliberately does not distinguish between different failure
    /// causes (e.g. invalid ciphertext, incorrect key, or internal errors).
    #[error("decryption failed")]
    DecryptionFailed(String),

    /// The provided keys do not form a valid matching pair.
    #[error("key mismatch")]
    KeyMismatch,
}
