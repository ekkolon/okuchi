// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(unused_assignments)]

use super::{Decrypt, DecryptBytes, Stream, util};
use crate::ciphertext::Ciphertext;
use crate::error::{Error, Result};
use crate::keypair::PrivateKey;

use num_bigint_dig::BigUint;
use num_traits::One;
use zeroize::{Zeroize, ZeroizeOnDrop};

impl Decrypt for PrivateKey {
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        // Ensure the ciphertext was produced for this key.
        if ciphertext.modulus_bits != self.public_key.bit_length {
            return Err(Error::KeyMismatch);
        }

        let c = ciphertext.value();
        if c >= self.public_key.n() {
            return Err(Error::InvalidCiphertext);
        }

        // Optimized Paillier decryption using only the prime factor `p`.
        //
        // Given the restriction m < p, decryption can be performed modulo p²
        // instead of n². This yields a substantial performance improvement.
        //
        // m = L(c^(p-1) mod p²) · (L(g^(p-1) mod p²))⁻¹ mod p

        let p_squared = &self.p * &self.p;
        let p_minus_1 = &self.p - BigUint::one();

        // Compute c^(p-1) mod p²
        let c_to_p_minus_1 = c.modpow(&p_minus_1, &p_squared);

        // Apply L function: L(c^(p-1)) = (c^(p-1) - 1) / p
        let l_c = util::l_function(&c_to_p_minus_1, &self.p);

        // Apply L function to precomputed value: L(g^(p-1)) = (g^(p-1) - 1) / p
        let l_g = util::l_function(&self.g_p_precomputed, &self.p);

        // Compute modular inverse of L(g^(p-1)) mod p
        let l_g_inv = util::mod_inverse(&l_g, &self.p)?;

        // Recover plaintext: m = L(c^(p-1)) * L(g^(p-1))^(-1) mod p
        let m = (l_c * l_g_inv) % &self.p;

        Ok(util::biguint_to_bytes_minimal(&m))
    }
}

impl DecryptBytes for PrivateKey {
    fn decrypt_bytes<P: AsRef<[u8]>>(&self, packed: P) -> Result<Vec<u8>> {
        let mut decryptor = self.decryptor();
        let mut output = Vec::new();

        output.extend(decryptor.update(packed)?);
        output.extend(decryptor.finalize()?);

        Ok(output)
    }
}

/// Internal state of the streaming decryptor.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
enum DecryptorState {
    /// Awaiting the stream header (version and block count).
    WaitingHeader,
    /// Reading encrypted blocks.
    ReadingBlocks { remaining_blocks: usize },
    /// All blocks processed successfully.
    Complete,
    /// Finalized; no further input is accepted.
    Finalized,
}

/// Incremental (streaming) decryption context.
///
/// Designed for decrypting large ciphertexts without buffering the entire
/// input in memory.
#[allow(missing_debug_implementations)]
#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "expose-secret", derive(Debug))]
pub struct Decryptor<'a> {
    #[zeroize(skip)]
    priv_key: &'a PrivateKey,
    buffer: Vec<u8>,
    state: DecryptorState,
    blocks_remaining: usize,
    output: Vec<u8>,
}

impl<'a> Decryptor<'a> {
    /// Construct a new decryptor bound to the given private key.
    pub(crate) fn new(priv_key: &'a PrivateKey) -> Self {
        Self {
            priv_key,
            buffer: Vec::new(),
            state: DecryptorState::WaitingHeader,
            blocks_remaining: 0,
            output: Vec::new(),
        }
    }

    /// Parse and validate the stream header.
    fn process_header(&mut self) -> Result<()> {
        if self.buffer.len() < 5 {
            return Ok(());
        }

        let version = self.buffer[0];
        if version != 1 {
            return Err(Error::DecryptionFailed(format!("Unsupported version: {}", version)));
        }

        #[allow(clippy::unwrap_used)]
        let block_count = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap()) as usize;

        self.buffer.drain(0..5);
        self.state = DecryptorState::ReadingBlocks { remaining_blocks: block_count };
        self.blocks_remaining = block_count;

        Ok(())
    }

    /// Attempt to decrypt a single complete block from the buffer.
    fn process_one_block(&mut self) -> Result<bool> {
        if self.buffer.len() < 4 {
            return Ok(false);
        }

        #[allow(clippy::unwrap_used)]
        let block_len = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap()) as usize;

        if self.buffer.len() < 4 + block_len {
            return Ok(false);
        }

        let c_bytes = &self.buffer[4..4 + block_len];
        let c = Ciphertext::from_bytes(c_bytes, self.priv_key.public_key().bit_length());

        let plaintext = self.priv_key.decrypt(&c)?;
        self.output.extend_from_slice(&plaintext);

        self.buffer.drain(0..4 + block_len);
        self.blocks_remaining = self.blocks_remaining.saturating_sub(1);

        Ok(true)
    }

    /// Decrypt all fully available blocks in the buffer.
    fn process_blocks(&mut self) -> Result<()> {
        while self.blocks_remaining > 0 {
            if !self.process_one_block()? {
                break;
            }
        }

        if self.blocks_remaining == 0 {
            self.state = DecryptorState::Complete;
        }

        Ok(())
    }
}

impl<'a> Stream for Decryptor<'a> {
    fn update<D: AsRef<[u8]>>(&mut self, data: D) -> Result<Vec<u8>> {
        if self.state == DecryptorState::Finalized {
            return Err(Error::DecryptionFailed("Cannot update after finalize".into()));
        }

        self.buffer.extend_from_slice(data.as_ref());

        if self.state == DecryptorState::WaitingHeader {
            self.process_header()?;
        }

        if matches!(self.state, DecryptorState::ReadingBlocks { .. }) {
            self.process_blocks()?;
        }

        Ok(std::mem::take(&mut self.output))
    }

    fn finalize(mut self) -> Result<Vec<u8>> {
        if self.state == DecryptorState::Finalized {
            return Err(Error::DecryptionFailed("Already finalized".into()));
        }

        match self.state {
            DecryptorState::WaitingHeader => {
                if !self.buffer.is_empty() {
                    return Err(Error::DecryptionFailed(
                        "Stream ended with incomplete header".into(),
                    ));
                }
            }
            DecryptorState::ReadingBlocks { remaining_blocks } => {
                if remaining_blocks > 0 {
                    return Err(Error::DecryptionFailed(format!(
                        "Stream ended prematurely: missing {} blocks",
                        remaining_blocks
                    )));
                }
                if !self.buffer.is_empty() {
                    return Err(Error::DecryptionFailed(format!(
                        "Stream ended with {} trailing bytes",
                        self.buffer.len()
                    )));
                }
            }
            DecryptorState::Complete => {
                if !self.buffer.is_empty() {
                    return Err(Error::DecryptionFailed(format!(
                        "Stream ended with {} trailing bytes",
                        self.buffer.len()
                    )));
                }
            }
            DecryptorState::Finalized => unreachable!(),
        }

        self.state = DecryptorState::Finalized;
        Ok(Vec::new())
    }
}

impl<'a> PrivateKey {
    /// Create a streaming decryptor bound to this key.
    pub fn decryptor(&'a self) -> Decryptor<'a> {
        Decryptor::new(self)
    }
}
