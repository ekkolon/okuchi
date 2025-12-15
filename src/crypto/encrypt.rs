// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{Encrypt, EncryptBytes, Stream};
use crate::ciphertext::Ciphertext;
use crate::error::{Error, Result};
use crate::keypair::PublicKey;

use num_bigint_dig::{BigUint, RandBigInt};
use num_traits::One;
use rand::SeedableRng;
use rand::rngs::StdRng;

impl Encrypt for PublicKey {
    fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Ciphertext> {
        let m = BigUint::from_bytes_be(plaintext.as_ref());
        if m >= self.n {
            return Err(Error::PlaintextTooLarge);
        }

        // Sample fresh randomness for probabilistic encryption.
        let mut rng = StdRng::from_os_rng();
        let r = rng.gen_biguint_range(&BigUint::one(), &self.n);

        // c = g^m · h^r mod n
        let gm = self.g.modpow(&m, &self.n);
        let hr = self.h.modpow(&r, &self.n);
        let c = (gm * hr) % &self.n;

        Ok(Ciphertext::new(c, self.bit_length))
    }
}

impl EncryptBytes for PublicKey {
    fn encrypt_bytes<P: AsRef<[u8]>>(&self, data: P) -> Result<Vec<u8>> {
        let mut encryptor = self.encryptor();
        encryptor.update(data)?;
        encryptor.finalize()
    }
}

/// Internal state of the streaming encryptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncryptorState {
    /// Accepting plaintext input.
    Encrypting,
    /// Finalized; no further input is allowed.
    Finalized,
}

/// Streaming encryption context.
///
/// Supports incremental encryption of large inputs without buffering the
/// entire plaintext in memory.
#[derive(Debug)]
pub struct Encryptor<'a> {
    pub_key: &'a PublicKey,

    /// Buffer holding incomplete plaintext blocks.
    buffer: Vec<u8>,

    /// Encrypted ciphertext blocks (serialized form).
    encrypted_blocks: Vec<Vec<u8>>,

    state: EncryptorState,

    /// Maximum number of plaintext bytes per block.
    max_block_size: usize,

    /// Tracks whether any non-empty input was provided.
    has_data: bool,
}

impl<'a> Encryptor<'a> {
    /// Create a new encryptor bound to the given public key.
    pub(crate) fn new(pub_key: &'a PublicKey) -> Self {
        let max_block_size = pub_key.max_plaintext_bytes();

        Self {
            pub_key,
            buffer: Vec::new(),
            encrypted_blocks: Vec::new(),
            state: EncryptorState::Encrypting,
            max_block_size,
            has_data: false,
        }
    }

    /// Encrypt a complete plaintext block and store its serialized ciphertext.
    fn encrypt_block(&mut self, block: &[u8]) -> Result<()> {
        let ciphertext = self.pub_key.encrypt(block)?;
        self.encrypted_blocks.push(ciphertext.to_bytes());
        Ok(())
    }

    /// Encrypt all complete blocks currently available in the buffer.
    fn process_buffer(&mut self) -> Result<()> {
        while self.buffer.len() >= self.max_block_size {
            let block: Vec<u8> = self.buffer.drain(..self.max_block_size).collect();
            self.encrypt_block(&block)?;
        }
        Ok(())
    }

    /// Serialize encrypted blocks into the packed wire format.
    ///
    /// Format:
    /// `[version:u8][block_count:u32][len:u32][block]...`
    fn serialize_blocks(&self) -> Vec<u8> {
        let mut packed = Vec::new();

        packed.push(1u8); // version
        packed.extend_from_slice(&(self.encrypted_blocks.len() as u32).to_be_bytes());

        for block in &self.encrypted_blocks {
            packed.extend_from_slice(&(block.len() as u32).to_be_bytes());
            packed.extend_from_slice(block);
        }

        packed
    }
}

impl<'a> PublicKey {
    /// Create a streaming encryptor for this key.
    pub fn encryptor(&'a self) -> Encryptor<'a> {
        Encryptor::new(self)
    }

    /// Conservative upper bound on plaintext bytes per block.
    ///
    /// The effective plaintext space is modulo `p`, while the public modulus
    /// exposes `n`. Assuming similarly sized factors, `bits(p) ≈ bits(n) / 3`.
    pub(crate) fn max_plaintext_bytes(&self) -> usize {
        let n_bits = self.n.bits();
        let p_bits = n_bits / 3;
        let bytes = p_bits.saturating_sub(8) / 8;
        bytes.max(1)
    }
}

impl<'a> Stream for Encryptor<'a> {
    fn update<D: AsRef<[u8]>>(&mut self, data: D) -> Result<Vec<u8>> {
        if self.state == EncryptorState::Finalized {
            return Err(Error::EncryptionFailed("Cannot update after finalize".into()));
        }

        let data = data.as_ref();
        if !data.is_empty() {
            self.has_data = true;
        }

        self.buffer.extend_from_slice(data);
        self.process_buffer()?;

        // Output is emitted only during finalize to preserve the packed format.
        Ok(Vec::new())
    }

    fn finalize(mut self) -> Result<Vec<u8>> {
        if self.state == EncryptorState::Finalized {
            return Err(Error::EncryptionFailed("Already finalized".into()));
        }

        // Distinguish empty input from missing data by emitting a single empty block.
        if !self.has_data {
            let ciphertext = self.pub_key.encrypt([])?;
            self.encrypted_blocks.push(ciphertext.to_bytes());
        } else if !self.buffer.is_empty() {
            let remaining: Vec<u8> = self.buffer.drain(..).collect();
            self.encrypt_block(&remaining)?;
        }

        self.state = EncryptorState::Finalized;
        Ok(self.serialize_blocks())
    }
}
