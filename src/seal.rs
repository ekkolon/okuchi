// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Error, Okuchi, PrivateKey, PublicKey, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

fn generate_nonce() -> XNonce {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    StdRng::from_os_rng().fill_bytes(&mut nonce_bytes);
    XNonce::from(nonce_bytes)
}

impl Okuchi {
    /// Encrypt `data` under OU then wrap the packed stream in XChaCha20-Poly1305.
    ///
    /// Wire format: `[24-byte nonce][XChaCha20-Poly1305 ciphertext + 16-byte tag]`
    ///
    /// `n` is bound as AEAD associated data, preventing cross-keypair blob reuse.
    pub fn seal(pub_key: &PublicKey, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let packed = Self::encrypt_stream(pub_key, data)?;

        let cipher = XChaCha20Poly1305::new(key.into());
        let nonce = generate_nonce();
        let aad = pub_key.n().to_bytes_be();

        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &packed,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::SealFailed)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Authenticate and decrypt a blob produced by [`seal`](Okuchi::seal).
    ///
    /// This method fails fast, before any OU decryption is attempted, with [`Error::VerificationFailed`]
    /// on any AEAD tag mismatch, truncated input, or wrong key.
    pub fn open(priv_key: &PrivateKey, key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::VerificationFailed);
        }

        let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        let cipher = XChaCha20Poly1305::new(key.into());
        let aad = priv_key.pub_key().n().to_bytes_be();

        let packed = cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| Error::VerificationFailed)?;

        Self::decrypt_stream(priv_key, &packed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    const TEST_KEY_SIZE: usize = 2048;

    fn random_key() -> [u8; 32] {
        use rand::RngCore;
        let mut k = [0u8; 32];
        StdRng::from_os_rng().fill_bytes(&mut k);
        k
    }

    #[test]
    fn seal_open_roundtrip() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();
        let msg = b"authenticated hybrid encryption over OU";

        let sealed = Okuchi::seal(keypair.pub_key(), &key, msg).unwrap();
        let opened = Okuchi::open(keypair.priv_key(), &key, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn wrong_key_fails_verification() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();
        let bad_key = random_key();

        let sealed = Okuchi::seal(keypair.pub_key(), &key, b"secret").unwrap();
        assert_eq!(
            Okuchi::open(keypair.priv_key(), &bad_key, &sealed),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_verification() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();

        let mut sealed = Okuchi::seal(keypair.pub_key(), &key, b"integrity check").unwrap();
        let flip_idx = NONCE_LEN + 4;
        sealed[flip_idx] ^= 0xFF;
        assert_eq!(
            Okuchi::open(keypair.priv_key(), &key, &sealed),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn tampered_header_fails_verification() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();

        let mut sealed = Okuchi::seal(keypair.pub_key(), &key, b"header tamper").unwrap();
        sealed[NONCE_LEN] ^= 0x01; // flip first byte of AEAD ct (hits the packed header)
        assert_eq!(
            Okuchi::open(keypair.priv_key(), &key, &sealed),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn truncated_blob_fails() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();

        let sealed = Okuchi::seal(keypair.pub_key(), &key, b"truncate me").unwrap();
        assert_eq!(
            Okuchi::open(keypair.priv_key(), &key, &sealed[..NONCE_LEN + TAG_LEN - 1]),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn cross_keypair_reuse_fails() {
        let kp1 = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let kp2 = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();

        // Sealed under kp1's n (AAD) — must not open under kp2's n
        let sealed = Okuchi::seal(kp1.pub_key(), &key, b"wrong keypair").unwrap();
        assert_eq!(
            Okuchi::open(kp2.priv_key(), &key, &sealed),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn seal_open_empty_payload() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let key = random_key();

        let sealed = Okuchi::seal(keypair.pub_key(), &key, b"").unwrap();
        let opened = Okuchi::open(keypair.priv_key(), &key, &sealed).unwrap();
        assert!(opened.is_empty());
    }
}
