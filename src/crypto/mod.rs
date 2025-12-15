mod decrypt;
mod encrypt;
mod util;

pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

use crate::ciphertext::Ciphertext;
use crate::error::Result;

/// Encrypts a single plaintext block.
pub trait Encrypt {
    /// Encrypt a single plaintext block.
    ///
    /// The plaintext, interpreted as a big-endian integer, must be strictly
    /// smaller than the public modulus `n`. For arbitrary-length data, use
    /// [`EncryptBytes::encrypt_bytes`].
    fn encrypt<P: AsRef<[u8]>>(&self, plaintext: P) -> Result<Ciphertext>;
}

/// Encrypts arbitrary-length data by splitting it into blocks.
pub trait EncryptBytes {
    /// Encrypt arbitrary-length input and return it in packed form.
    ///
    /// The output can be decrypted with `PrivateKey::decrypt_bytes`.
    fn encrypt_bytes<P: AsRef<[u8]>>(&self, data: P) -> Result<Vec<u8>>;
}

/// Decrypts a single ciphertext block into its plaintext representation.
pub trait Decrypt {
    /// Recover the plaintext `m` from a ciphertext `c`.
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<Vec<u8>>;
}

/// Decrypts variable-length plaintext that was encrypted in block form.
///
/// Typically implemented by delegating to the single-block [`Decrypt`] trait.
/// Supports packed formats that include block headers, lengths, and versioning.
pub trait DecryptBytes {
    /// Decrypt packed multi-block ciphertext and return the full plaintext.
    fn decrypt_bytes<P: AsRef<[u8]>>(&self, packed: P) -> Result<Vec<u8>>;
}

/// Stateful interface for incremental cryptographic processing.
///
/// Implementations accept input in chunks via [`update`] and produce any
/// immediately available output. Remaining buffered state is processed and
/// returned by [`finalize`]. After finalization, the instance must not be used.
///
/// This abstraction is intended for streaming encryption and decryption where
/// input data may not be available as a single contiguous buffer.
pub trait Stream {
    /// Processes the next chunk of input data.
    ///
    /// The returned bytes correspond to output that can be produced
    /// immediately from this input chunk. Implementations may buffer data
    /// internally and return an empty vector.
    fn update<D: AsRef<[u8]>>(&mut self, data: D) -> Result<Vec<u8>>;

    /// Completes processing and returns any remaining output.
    ///
    /// This consumes the stream instance and flushes all internal state.
    fn finalize(self) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod test_encryption {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::keypair::KeyPair;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_with_size(512).unwrap()
    }

    #[test]
    fn encrypt_single_block() {
        let keypair = create_test_keypair();
        let message = b"Hello, World!";

        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let plaintext = keypair.private_key().decrypt(&ciphertext).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn encrypt_bytes_simple() {
        let keypair = create_test_keypair();
        let message = b"This is a test message that spans multiple blocks!";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();
        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_single_chunk() {
        let keypair = create_test_keypair();
        let message = b"Streaming encryption test";

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();
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

        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();
        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_empty_message() {
        let keypair = create_test_keypair();
        let message = b"";

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();
        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_encrypt_byte_by_byte() {
        let keypair = create_test_keypair();
        let message = b"Byte by byte encryption";

        let mut encryptor = keypair.public_key().encryptor();

        // feed one byte at a time (extreme case)
        for byte in message.iter() {
            encryptor.update([*byte]).unwrap();
        }

        let packed = encryptor.finalize().unwrap();
        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();

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
        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();

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
        let plaintext1 = keypair.private_key().decrypt_bytes(&packed1).unwrap();
        let plaintext2 = keypair.private_key().decrypt_bytes(&packed2).unwrap();

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
        let plaintext1 = keypair.private_key().decrypt_bytes(&packed1).unwrap();
        let plaintext2 = keypair.private_key().decrypt_bytes(&packed2).unwrap();

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
        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn roundtrip_utf8() {
        let keypair = create_test_keypair();
        let message = "Hello, 世界!";

        let mut encryptor = keypair.public_key().encryptor();
        encryptor.update(message.as_bytes()).unwrap();
        let packed = encryptor.finalize().unwrap();

        let plaintext_bytes = keypair.private_key().decrypt_bytes(&packed).unwrap();
        let plaintext = String::from_utf8(plaintext_bytes).unwrap();

        assert_eq!(message, plaintext);
    }
}

#[cfg(test)]
mod test_decryption {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::keypair::KeyPair;

    fn create_test_keypair() -> KeyPair {
        KeyPair::generate_with_size(512).unwrap()
    }

    #[test]
    fn decrypt_single_block() {
        let keypair = create_test_keypair();
        let message = b"Hello, World!";

        let ciphertext = keypair.public_key().encrypt(message).unwrap();
        let plaintext = keypair.private_key().decrypt(&ciphertext).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn decrypt_bytes_simple() {
        let keypair = create_test_keypair();
        let message = b"This is a test message that spans multiple blocks!";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();
        let plaintext = keypair.private_key().decrypt_bytes(&packed).unwrap();

        assert_eq!(message, plaintext.as_slice());
    }

    #[test]
    fn streaming_decrypt_single_chunk() {
        let keypair = create_test_keypair();
        let message = b"Streaming decryption test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.private_key().decryptor();
        let mut all_output = Vec::new();

        // Feed header and some data
        let partial = decryptor.update(&packed).unwrap();
        all_output.extend_from_slice(&partial);

        // Finalize
        let final_output = decryptor.finalize().unwrap();
        all_output.extend_from_slice(&final_output);

        assert_eq!(message, all_output.as_slice());
    }

    #[test]
    fn streaming_decrypt_fragmented() {
        let keypair = create_test_keypair();
        let message = b"Test fragmented stream delivery";
        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.private_key().decryptor();
        let mut decrypted = Vec::new();

        // Feed byte by byte to simulate extreme fragmentation
        for byte in packed {
            let chunk = decryptor.update([byte]).unwrap();
            decrypted.extend(chunk);
        }
        decrypted.extend(decryptor.finalize().unwrap());

        assert_eq!(message, decrypted.as_slice());
    }

    #[test]
    fn streaming_decrypt_multiple_chunks() {
        let keypair = create_test_keypair();
        let message = b"This is a longer message for testing chunked streaming!";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        // split packd data into arbitrary chunks
        let chunk_size = 20;
        let mut decryptor = keypair.private_key().decryptor();
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

        let mut decryptor = keypair.private_key().decryptor();
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

        let mut decryptor = keypair.private_key().decryptor();

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
        let mut decryptor = keypair.private_key().decryptor();
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

        let mut decryptor = keypair.private_key().decryptor();
        let result = decryptor.update(&bad_packed);

        assert!(result.is_err());
    }

    #[test]
    fn cannot_update_after_finalize() {
        let keypair = create_test_keypair();
        let message = b"Test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.private_key().decryptor();
        decryptor.update(&packed).unwrap();
        decryptor.finalize().unwrap();
    }

    #[test]
    fn streaming_decrypt_byte_by_byte() {
        let keypair = create_test_keypair();
        let message = b"Byte by byte test";

        let packed = keypair.public_key().encrypt_bytes(message).unwrap();

        let mut decryptor = keypair.private_key().decryptor();
        let mut all_output = Vec::new();

        // Feed one byte at a time (extreme case)
        for byte in packed.iter() {
            let output = decryptor.update([*byte]).unwrap();
            all_output.extend_from_slice(&output);
        }

        let final_output = decryptor.finalize().unwrap();
        all_output.extend_from_slice(&final_output);

        assert_eq!(message, all_output.as_slice());
    }
}
