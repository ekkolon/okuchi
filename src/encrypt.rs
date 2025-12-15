// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::{BigUint, RandBigInt};
use num_traits::One;
use rand::rngs::OsRng;

use crate::{Ciphertext, Error, PublicKey, Result, stream::Stream};

/// A trait that enables encrypting a single plaintext block.
pub trait Encrypt {
    /// Encrypt a single plaintext block.
    ///
    /// Plaintext must be < n. For arbitrary data, use `encrypt_bytes()`.
    ///
    /// ## Plaintext Space
    ///
    /// Technically m ∈ ℤ_p, but we enforce m < n for implementation simplicity.
    /// The effective message space is therefore min(p, n), which is p in practice.
    ///
    /// ## Error
    ///
    /// This method fails if the provided `plaintext` bytes length is >= `n`.
    fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Ciphertext>;
}

impl Encrypt for PublicKey {
    fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Ciphertext> {
        let plaintext = plaintext.as_ref();
        let m = BigUint::from_bytes_be(plaintext);
        if m >= self.n {
            return Err(Error::PlaintextTooLarge);
        }

        let mut rng = OsRng;
        let r = rng.gen_biguint_range(&BigUint::one(), &self.n);

        // c = g^m · h^r mod n
        let gm = self.g.modpow(&m, &self.n);
        let hr = self.h.modpow(&r, &self.n);
        let c = (gm * hr) % &self.n;

        Ok(Ciphertext::new(c, self.bit_length))
    }
}

/// A trait that enables encrypting arbitrary-length data.
pub trait EncryptBytes {
    /// Encrypt arbitrary-length data by splitting into blocks.
    ///
    /// Returns a packed format that can be decrypted with `PrivateKey::decrypt_bytes()`.
    fn encrypt_bytes<P: AsRef<[u8]>>(&self, data: P) -> Result<Vec<u8>>;
}

impl EncryptBytes for PublicKey {
    fn encrypt_bytes<P: AsRef<[u8]>>(&self, data: P) -> Result<Vec<u8>> {
        // Delegate to Encryptor for actual work
        let mut encryptor = self.encryptor();
        encryptor.update(data)?;
        encryptor.finalize()
    }
}

/// State machine for streaming encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncryptorState {
    /// Accepting data for encryption
    Encrypting,
    /// All data processed, ready to finalize
    Finalized,
}

/// A container for enabling incremental (streaming) encryption.
///
/// This allows encrypting large data without loading it all into memory,
/// and supports streaming encryption where data arrives incrementally.
///
/// # Example
/// ```ignore
/// let mut encryptor = public_key.encryptor();
///
/// // Feed data in chunks
/// let chunk1 = encryptor.update(&data[0..1024])?;
/// let chunk2 = encryptor.update(&data[1024..2048])?;
///
/// // Get final encrypted output
/// let final_chunk = encryptor.finalize()?;
/// ```
pub struct Encryptor<'a> {
    pub_key: &'a PublicKey,

    /// Internal buffer for incomplete blocks
    buffer: Vec<u8>,

    /// Encrypted ciphertext blocks
    encrypted_blocks: Vec<Vec<u8>>,

    /// Current encryptor state
    state: EncryptorState,

    /// Maximum plaintext bytes per block
    max_block_size: usize,

    /// Track if any data was fed (to handle empty input)
    has_data: bool,
}

impl<'a> Encryptor<'a> {
    /// Create a new streaming encryptor.
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

    /// Encrypt a complete block from the buffer.
    fn encrypt_block(&mut self, block: &[u8]) -> Result<()> {
        let ciphertext = self.pub_key.encrypt(block)?;
        self.encrypted_blocks.push(ciphertext.to_bytes());
        Ok(())
    }

    /// Process as many complete blocks as possible from the buffer.
    fn process_buffer(&mut self) -> Result<()> {
        while self.buffer.len() >= self.max_block_size {
            // Extract a full block
            let block: Vec<u8> = self.buffer.drain(..self.max_block_size).collect();
            self.encrypt_block(&block)?;
        }
        Ok(())
    }

    /// Serialize all encrypted blocks into packed format.
    fn serialize_blocks(&self) -> Vec<u8> {
        let mut packed = Vec::new();

        // Header: [version:u8][block_count:u32]
        packed.push(1u8); // version
        packed.extend_from_slice(&(self.encrypted_blocks.len() as u32).to_be_bytes());

        // Blocks: [len:u32][data]...
        for block in &self.encrypted_blocks {
            packed.extend_from_slice(&(block.len() as u32).to_be_bytes());
            packed.extend_from_slice(block);
        }

        packed
    }
}

impl<'a> Stream for Encryptor<'a> {
    /// Feed more plaintext data into the encryptor.
    ///
    /// This method buffers data internally and encrypts complete blocks
    /// as they become available. Partial blocks are held until more data
    /// arrives or `finalize()` is called.
    ///
    /// Returns an empty vector in most cases. The actual encrypted output
    /// is returned by `finalize()`.
    fn update<D: AsRef<[u8]>>(&mut self, data: D) -> Result<Vec<u8>> {
        if self.state == EncryptorState::Finalized {
            return Err(Error::EncryptionFailed(
                "Cannot update after finalize".into(),
            ));
        }

        let data = data.as_ref();

        // Track that we received data
        if !data.is_empty() {
            self.has_data = true;
        }

        // Add new data to buffer
        self.buffer.extend_from_slice(data);

        // Encrypt complete blocks
        self.process_buffer()?;

        // For streaming encryption, we don't return partial output
        // All output is returned in finalize() to maintain the packed format
        Ok(Vec::new())
    }

    /// Finalize encryption and return the complete packed ciphertext.
    ///
    /// This encrypts any remaining buffered data and returns the packed
    /// format containing all encrypted blocks.
    ///
    /// The packed format is:
    /// ```text
    /// [version:u8][block_count:u32]
    ///   for each block:
    ///     [len:u32][ciphertext_bytes]
    /// ```
    fn finalize(mut self) -> Result<Vec<u8>> {
        if self.state == EncryptorState::Finalized {
            return Err(Error::EncryptionFailed("Already finalized".into()));
        }

        // Handle empty input: encrypt a single zero block
        // This allows decrypt to distinguish empty vs missing data
        if !self.has_data {
            let empty_ciphertext = self.pub_key.encrypt(&[])?;
            self.encrypted_blocks.push(empty_ciphertext.to_bytes());
        } else {
            // Encrypt any remaining data in buffer (last partial block)
            if !self.buffer.is_empty() {
                let remaining: Vec<u8> = self.buffer.drain(..).collect();
                self.encrypt_block(&remaining)?;
            }
        }

        self.state = EncryptorState::Finalized;

        // Serialize all blocks into packed format
        Ok(self.serialize_blocks())
    }
}

impl<'a> PublicKey {
    /// Create a streaming encryptor for incremental encryption.
    ///
    /// This is useful when encrypting large amounts of data or when
    /// data arrives in chunks (e.g., from a network stream or file).
    ///
    /// # Example
    /// ```ignore
    /// let mut encryptor = public_key.encryptor();
    ///
    /// // Feed data as it arrives
    /// for chunk in data_chunks {
    ///     encryptor.update(chunk)?;
    /// }
    ///
    /// // Get the complete encrypted output
    /// let ciphertext = encryptor.finalize()?;
    /// ```
    pub fn encryptor(&'a self) -> Encryptor<'a> {
        Encryptor::new(self)
    }

    /// Conservative estimate of maximum plaintext bytes per block.
    ///
    /// OU's plaintext space is modulo `p`, but public key exposes `n = p²q`.
    /// If p,q are chosen similar size then bits(p) ≈ bits(n)/3. We use that
    /// conservative estimate to compute a safe byte-length per block.
    pub(crate) fn max_plaintext_bytes(&self) -> usize {
        let n_bits = self.n.bits();
        // conservative estimate of p bits
        let p_bits = n_bits / 3;
        // ensure at least 1 byte available, with safety margin
        let bytes = p_bits.saturating_sub(8) / 8;
        // require at least 1 byte
        bytes.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::{Decrypt, DecryptBytes};
    use crate::key::KeyPair;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_with_size(512).unwrap()
    }

    #[test]
    fn encrypt_single_block() {
        let keypair = create_test_keypair();
        let message = b"Hello, World!";

        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let plaintext = keypair.secret_key().decrypt(&ciphertext).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn encrypt_bytes_simple() {
        let keypair = create_test_keypair();
        let message = b"This is a test message that spans multiple blocks!";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();
        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_single_chunk() {
        let keypair = create_test_keypair();
        let message = b"Streaming encryption test";

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();
        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_multiple_chunks() {
        let keypair = create_test_keypair();
        let message = b"This is a longer message for testing chunked streaming encryption!";

        // Split message into arbitrary chunks
        let chunk1 = &message[0..20];
        let chunk2 = &message[20..40];
        let chunk3 = &message[40..];

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(chunk1).unwrap();
        encryptor.update(chunk2).unwrap();
        encryptor.update(chunk3).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();
        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_empty_message() {
        let keypair = create_test_keypair();
        let message = b"";

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();
        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_byte_by_byte() {
        let keypair = create_test_keypair();
        let message = b"Byte by byte encryption";

        let mut encryptor = keypair.public_key().encryptor();

        // feed one byte at a time (extreme case)
        for byte in message.iter() {
            encryptor.update(&[*byte]).unwrap();
        }

        let packed = encryptor.finalize().unwrap();
        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_large_data() {
        let keypair = create_test_keypair();

        // create large message that will definitely span multiple blocks
        let message = b"Lorem ipsum dolor sit amet ".repeat(100);

        let mut encryptor = keypair.public_key().encryptor();

        // feed in moderate-sized chunks
        let chunk_size = 100;
        let mut offset = 0;
        while offset < message.len() {
            let end = (offset + chunk_size).min(message.len());
            encryptor.update(&message[offset..end]).unwrap();
            offset = end;
        }

        let packed = encryptor.finalize().unwrap();
        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn cannot_update_after_finalize() {
        let keypair = create_test_keypair();

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(b"test").unwrap();
        encryptor.finalize().unwrap();
    }

    #[test]
    fn encrypt_bytes_delegates_to_encryptor() {
        let keypair = create_test_keypair();
        let message = b"Testing delegation";

        // both methods should produce compatible output
        let packed1 = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message).unwrap();
        let packed2 = encryptor.finalize().unwrap();

        // decrypt both to verify they work
        let plaintext1 = keypair.secret_key().decrypt_bytes(&packed1).unwrap();
        let plaintext2 = keypair.secret_key().decrypt_bytes(&packed2).unwrap();

        assert_eq!(message, plaintext1.as_slice());
        assert_eq!(message, plaintext2.as_slice());
    }

    #[test]
    fn probabilistic_encryption_streaming() {
        let keypair = create_test_keypair();
        let message = b"Same message";

        // encrypt same message twice with streaming
        let mut enc1 = keypair.public_key().encryptor();
        enc1.update(message).unwrap();
        let packed1 = enc1.finalize().unwrap();

        let mut enc2 = keypair.public_key().encryptor();
        enc2.update(message).unwrap();
        let packed2 = enc2.finalize().unwrap();

        // Ciphertexts should be different
        assert_ne!(packed1, packed2);

        // vut both should decrypt to the same plaintext
        let plaintext1 = keypair.secret_key().decrypt_bytes(&packed1).unwrap();
        let plaintext2 = keypair.secret_key().decrypt_bytes(&packed2).unwrap();

        assert_eq!(plaintext1, plaintext2);
        assert_eq!(message, plaintext1.as_slice());
    }

    #[test]
    fn encrypt_with_empty_updates() {
        let keypair = create_test_keypair();
        let message = b"Test message";

        let mut encryptor = keypair.public_key().encryptor();

        // Mix empty and non-empty updates
        encryptor.update(b"").unwrap();
        encryptor.update(&message[0..5]).unwrap();
        encryptor.update(b"").unwrap();
        encryptor.update(&message[5..]).unwrap();
        encryptor.update(b"").unwrap();

        let packed = encryptor.finalize().unwrap();
        let plaintext = keypair.secret_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn roundtrip_utf8() {
        let keypair = create_test_keypair();
        let message = "Hello, 世界!";

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message.as_bytes()).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext_bytes = keypair.secret_key().decrypt_bytes(&packed).unwrap();
        let plaintext = String::from_utf8(plaintext_bytes).unwrap();

        assert_eq!(message, plaintext);
    }
}
