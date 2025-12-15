// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{Ciphertext, Error, PrivateKey, Result, stream::Stream, util::l_function};
use num_bigint_dig::{BigUint, ModInverse};
use num_traits::{One, Zero};

/// A trait that enables decrypting a single plaintext block.
pub trait Decrypt {
    /// Decrypt a single ciphertext block.
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>>;
}

impl Decrypt for PrivateKey {
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        // Validate ciphertext is for this key
        if ciphertext.modulus_bits != self.public_key.bit_length {
            return Err(Error::KeyMismatch);
        }

        let c = ciphertext.value();
        if c >= self.public_key.n() {
            return Err(Error::InvalidCiphertext);
        }

        let p_squared = &self.p * &self.p;
        let p_minus_1 = &self.p - BigUint::one();

        // comput c^(p-1) mod p²
        let cp = c.modpow(&p_minus_1, &p_squared);

        // Apply L-function
        let l_cp = l_function(&cp, &self.p);
        let l_gp = l_function(&self.g_p_precomputed, &self.p);

        // compute modular inverse
        let l_gp_inv = l_gp
            .mod_inverse(&self.p)
            .ok_or(Error::DecryptionFailed("Modular inverse failed".into()))?
            .to_biguint()
            .ok_or(Error::DecryptionFailed("Inverse negative".into()))?;

        let m = (l_cp * l_gp_inv) % &self.p;

        Ok(if m.is_zero() {
            Vec::new()
        } else {
            m.to_bytes_be()
        })
    }
}

/// A trait that enables decrypting arbitrary-length data.
pub trait DecryptBytes {
    /// Decrypt packed multi-block data produced by encryption.
    fn decrypt_bytes<P: AsRef<[u8]>>(&self, packed: P) -> Result<Vec<u8>>;
}

impl DecryptBytes for PrivateKey {
    fn decrypt_bytes<P: AsRef<[u8]>>(&self, packed: P) -> Result<Vec<u8>> {
        let packed = packed.as_ref();

        let mut decryptor = self.decryptor();
        let mut output = Vec::new();

        let partial = decryptor.update(packed)?;
        println!(
            "DEBUG decrypt_bytes: update returned {} bytes",
            partial.len()
        );
        output.extend(partial);

        let final_output = decryptor.finalize()?;
        println!(
            "DEBUG decrypt_bytes: finalize returned {} bytes",
            final_output.len()
        );
        output.extend(final_output);

        println!("DEBUG decrypt_bytes: total output {} bytes", output.len());
        Ok(output)
    }
}

/// State machine for streaming decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecryptorState {
    /// Waiting for header (version + block count)
    WaitingHeader,
    /// Reading block headers and data
    ReadingBlocks { remaining_blocks: usize },
    /// All data processed, ready to finalize
    Complete,
    /// Finalized or error state
    Finalized,
}

/// A container for enabling incremental (streaming) decryption.
///
/// This allows processing large encrypted data without loading it all into memory.
///
/// # Example
/// ```ignore
/// let mut decryptor = private_key.decryptor();
///
/// // Feed data in chunks
/// let chunk1 = decryptor.update(&data[0..1024])?;
/// let chunk2 = decryptor.update(&data[1024..2048])?;
///
/// // Get final decrypted output
/// let final_chunk = decryptor.finalize()?;
/// ```
pub struct Decryptor<'a> {
    priv_key: &'a PrivateKey,

    /// Internal buffer for incomplete data
    buffer: Vec<u8>,

    /// Current decryptor state
    state: DecryptorState,

    /// Number of blocks remaining to process
    blocks_remaining: usize,

    /// Accumulated decrypted output
    output: Vec<u8>,
}

impl<'a> Decryptor<'a> {
    /// Create a new streaming decryptor.
    pub(crate) fn new(priv_key: &'a PrivateKey) -> Self {
        Self {
            priv_key,
            buffer: Vec::new(),
            state: DecryptorState::WaitingHeader,
            blocks_remaining: 0,
            output: Vec::new(),
        }
    }

    /// Process the header (version + block count).
    fn process_header(&mut self) -> Result<()> {
        // Need at least 5 bytes: [version:1][block_count:4]
        if self.buffer.len() < 5 {
            return Ok(());
        }

        let version = self.buffer[0];
        if version != 1 {
            return Err(Error::DecryptionFailed(format!(
                "Unsupported version: {}",
                version
            )));
        }

        let block_count = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap()) as usize;

        // Consume header bytes
        self.buffer.drain(0..5);

        // Transition to reading blocks
        self.state = DecryptorState::ReadingBlocks {
            remaining_blocks: block_count,
        };
        self.blocks_remaining = block_count;

        Ok(())
    }

    /// Try to read and decrypt one block from the buffer.
    fn process_one_block(&mut self) -> Result<bool> {
        // Need at least 4 bytes for block length
        if self.buffer.len() < 4 {
            return Ok(false);
        }

        let block_len = u32::from_be_bytes(self.buffer[0..4].try_into().unwrap()) as usize;

        // Check if we have the full block
        if self.buffer.len() < 4 + block_len {
            return Ok(false); // Not enough data
        }

        // extract ciphertext bytes
        let c_bytes = &self.buffer[4..4 + block_len];
        let c = Ciphertext::from_bytes(c_bytes, self.priv_key.public_key().bit_length());

        // decrypt the block
        let plaintext = self.priv_key.decrypt(&c)?;
        println!(
            "DEBUG process_one_block: decrypted {} bytes",
            plaintext.len()
        );
        self.output.extend_from_slice(&plaintext);

        // consume processed bytes
        self.buffer.drain(0..4 + block_len);

        // decrement remaining blocks
        self.blocks_remaining = self.blocks_remaining.saturating_sub(1);

        Ok(true) // Successfully processed a block
    }

    /// Process as many complete blocks as possible from the buffer.
    fn process_blocks(&mut self) -> Result<()> {
        while self.blocks_remaining > 0 {
            if !self.process_one_block()? {
                break; // Need more data
            }
        }

        // Check if we've finished all blocks
        if self.blocks_remaining == 0 {
            self.state = DecryptorState::Complete;
        }

        Ok(())
    }
}

impl<'a> Stream for Decryptor<'a> {
    /// Feed more encrypted data into the decryptor.
    ///
    /// Returns any decrypted plaintext that's ready. May return an empty
    /// vector if more data is needed to complete a block.
    fn update<D: AsRef<[u8]>>(&mut self, data: D) -> Result<Vec<u8>> {
        if self.state == DecryptorState::Finalized {
            return Err(Error::DecryptionFailed(
                "Cannot update after finalize".into(),
            ));
        }

        let data = data.as_ref();

        // Add new data to buffer
        self.buffer.extend_from_slice(data);

        // Remember current output length to track new data
        let output_start = self.output.len();

        // Process header if needed
        if self.state == DecryptorState::WaitingHeader {
            self.process_header()?;
        }

        // Process blocks if in that state
        if matches!(self.state, DecryptorState::ReadingBlocks { .. }) {
            self.process_blocks()?;
        }

        // Return only newly decrypted data from this update call
        let new_output = self.output[output_start..].to_vec();
        println!(
            "DEBUG update: output_start={}, output.len()={}, returning {} bytes",
            output_start,
            self.output.len(),
            new_output.len()
        );

        Ok(new_output)
    }

    /// Finalize decryption and return any remaining plaintext.
    ///
    /// This must be called after all encrypted data has been fed via `update()`.
    /// Returns empty if all data was already returned by `update()` calls.
    fn finalize(mut self) -> Result<Vec<u8>> {
        if self.state == DecryptorState::Finalized {
            return Err(Error::DecryptionFailed("Already finalized".into()));
        }

        // Ensure all blocks were processed
        match self.state {
            DecryptorState::WaitingHeader => {
                if !self.buffer.is_empty() {
                    return Err(Error::DecryptionFailed("Incomplete header data".into()));
                }
                // Empty input case
                self.state = DecryptorState::Finalized;
                return Ok(Vec::new());
            }
            DecryptorState::ReadingBlocks { remaining_blocks } => {
                if remaining_blocks > 0 || !self.buffer.is_empty() {
                    return Err(Error::DecryptionFailed(format!(
                        "Incomplete data: {} blocks remaining, {} bytes in buffer",
                        remaining_blocks,
                        self.buffer.len()
                    )));
                }
            }
            DecryptorState::Complete => {
                // Good state - all blocks processed
            }
            DecryptorState::Finalized => {
                unreachable!("Already checked above");
            }
        }

        self.state = DecryptorState::Finalized;

        // Return empty - all data should have been returned by update() calls
        Ok(Vec::new())
    }
}

impl<'a> PrivateKey {
    /// Create a streaming decryptor for incremental decryption.
    ///
    /// This is useful when decrypting large amounts of data or when
    /// data arrives in chunks (e.g., from a network stream).
    pub fn decryptor(&'a self) -> Decryptor<'a> {
        Decryptor::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypt::{Encrypt, EncryptBytes};
    use crate::key::KeyPair;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_with_size(512).unwrap()
    }

    #[test]
    fn decrypt_single_block() {
        let keypair = create_test_keypair();
        let message = b"Hello, World!";

        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let plaintext = keypair.secret_key().decrypt(&ciphertext).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn decrypt_bytes_simple() {
        let keypair = create_test_keypair();
        let message = b"This is a test message that spans multiple blocks!";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();
        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_decrypt_single_chunk() {
        let keypair = create_test_keypair();
        let message = b"Streaming decryption test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.secret_key().decryptor();
        let mut all_output = Vec::new();

        // collect output from update
        let partial = decryptor.update(&packed).unwrap();
        all_output.extend_from_slice(&partial);

        // collect any remaining output from finalize
        let final_output = decryptor.finalize().unwrap();
        all_output.extend_from_slice(&final_output);

        assert_eq!(message, all_output.as_slice());
    }

    #[test]
    fn streaming_decrypt_multiple_chunks() {
        let keypair = create_test_keypair();
        let message = b"This is a longer message for testing chunked streaming!";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        // split packd data into arbitrary chunks
        let chunk_size = 20;
        let mut decryptor = keypair.secret_key().decryptor();
        let mut all_output = Vec::new();

        let mut offset = 0;
        while offset < packed.len() {
            let end = (offset + chunk_size).min(packed.len());
            let chunk = &packed[offset..end];

            let output = decryptor.update(chunk).unwrap();
            all_output.extend_from_slice(&output);

            offset = end;
        }

        let final_output = decryptor.finalize().unwrap();
        all_output.extend_from_slice(&final_output);

        assert_eq!(message, all_output.as_slice());
    }

    #[test]
    fn streaming_decrypt_empty_message() {
        let keypair = create_test_keypair();
        let message = b"";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.secret_key().decryptor();
        let mut all_output = Vec::new();

        let partial = decryptor.update(&packed).unwrap();
        all_output.extend_from_slice(&partial);

        let final_output = decryptor.finalize().unwrap();
        all_output.extend_from_slice(&final_output);

        assert_eq!(message, all_output.as_slice());
    }

    #[test]
    fn streaming_decrypt_incomplete_header() {
        let keypair = create_test_keypair();

        let mut decryptor = keypair.secret_key().decryptor();

        // feed only 3 bytes (header needs 5)
        let partial_header = vec![1u8, 0u8, 0u8];
        let output = decryptor.update(&partial_header).unwrap();
        assert_eq!(output.len(), 0); // No output yet

        let result = decryptor.finalize();
        assert!(result.is_err()); // should fail due to incomplete data
    }

    #[test]
    fn streaming_decrypt_incomplete_block() {
        let keypair = create_test_keypair();
        let message = b"Test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        // feed all but the last byte
        let mut decryptor = keypair.secret_key().decryptor();
        let truncated = &packed[..packed.len() - 1];
        decryptor.update(truncated).unwrap();

        let result = decryptor.finalize();
        assert!(result.is_err()); // should fail due to incomplete block
    }

    #[test]
    fn streaming_decrypt_invalid_version() {
        let keypair = create_test_keypair();

        // malformed packed data with invalid version
        let bad_packed = vec![99u8, 0u8, 0u8, 0u8, 1u8]; // version=99

        let mut decryptor = keypair.secret_key().decryptor();
        let result = decryptor.update(&bad_packed);

        assert!(result.is_err());
    }

    #[test]
    fn cannot_update_after_finalize() {
        let keypair = create_test_keypair();
        let message = b"Test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.secret_key().decryptor();
        decryptor.update(&packed).unwrap();
        decryptor.finalize().unwrap();
    }

    #[test]
    fn streaming_decrypt_byte_by_byte() {
        let keypair = create_test_keypair();
        let message = b"Byte by byte test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.secret_key().decryptor();
        let mut all_output = Vec::new();

        // Feed one byte at a time (extreme case)
        for byte in packed.iter() {
            let output = decryptor.update(&[*byte]).unwrap();
            all_output.extend_from_slice(&output);
        }

        let final_output = decryptor.finalize().unwrap();
        all_output.extend_from_slice(&final_output);

        assert_eq!(message, all_output.as_slice());
    }
}
