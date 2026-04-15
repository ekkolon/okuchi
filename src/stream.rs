use crate::{Ciphertext, Error, Okuchi, PrivateKey, PublicKey, Result};

impl Okuchi {
    /// Encrypt an arbitrary-length byte sequence as a packed multi-block stream.
    ///
    /// The output is a self-describing binary format suitable for [`decrypt_stream`](Okuchi::decrypt_stream).
    ///
    /// # Packed Format
    ///
    /// ```text
    /// [u32 BE block_count][u32 BE original_data_len]
    /// for each block: [u32 BE ciphertext_len][ciphertext bytes]
    /// ```
    ///
    /// `original_data_len` is stored so `decrypt_stream` can restore leading-zero
    /// bytes that `BigUint::to_bytes_be` drops. A value of `0` is a sentinel
    /// meaning "lengths unknown; skip per-block padding" and is written only by
    /// [`homomorphic_add_packed`](Okuchi::homomorphic_add_packed).
    ///
    /// # Errors
    ///
    /// Propagates [`Error::PlaintextTooLarge`] from [`encrypt`](Okuchi::encrypt)
    /// if a block exceeds the plaintext bound, which should not occur under
    /// correct block-size computation.
    pub fn encrypt_stream<P: AsRef<[u8]>>(pub_key: &PublicKey, data: P) -> Result<Vec<u8>> {
        let bytes = data.as_ref();
        let original_len = bytes.len() as u32;
        let max_block = Self::max_plaintext_bytes(pub_key);

        let block_count = if bytes.is_empty() {
            0usize
        } else {
            bytes.len().div_ceil(max_block)
        };
        let est_ct_bytes = pub_key.n().bits() / 8 + 1;
        let mut out = Vec::with_capacity(8 + block_count * (4 + est_ct_bytes));

        out.extend_from_slice(&(block_count as u32).to_be_bytes());
        out.extend_from_slice(&original_len.to_be_bytes());

        let mut i = 0usize;
        while i < bytes.len() {
            let end = std::cmp::min(i + max_block, bytes.len());
            let c = Self::encrypt(pub_key, &bytes[i..end])?;
            let c_bytes = c.to_bytes();
            out.extend_from_slice(&(c_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&c_bytes);
            i = end;
        }

        Ok(out)
    }

    /// Decrypt a packed stream produced by [`encrypt_stream`](Okuchi::encrypt_stream).
    ///
    /// If `original_data_len == 0` (the sentinel written by
    /// [`homomorphic_add_packed`](Okuchi::homomorphic_add_packed)), per-block
    /// padding is skipped and raw decrypted bytes are concatenated directly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptionFailed`] if:
    /// - The packed buffer is shorter than 8 bytes
    /// - `block_count` exceeds the 4M-block limit
    /// - Any block length field extends beyond the buffer boundary
    ///
    /// Returns [`Error::InvalidCiphertext`] if any deserialized ciphertext value is `>= n`.
    pub fn decrypt_stream<B: AsRef<[u8]>>(priv_key: &PrivateKey, packed: B) -> Result<Vec<u8>> {
        let bytes = packed.as_ref();
        // Header: block_count(4) + original_data_len(4) = 8 bytes
        if bytes.len() < 8 {
            return Err(Error::DecryptionFailed("Packed data too short".into()));
        }

        let block_count = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let original_data_len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;

        const MAX_BLOCKS: usize = 1 << 22; // 4M blocks
        if block_count > MAX_BLOCKS {
            return Err(Error::DecryptionFailed(format!(
                "block count {block_count} exceeds limit {MAX_BLOCKS}"
            )));
        }

        if block_count == 0 {
            return Ok(Vec::new());
        }

        let max_block = Self::max_plaintext_bytes(priv_key.pub_key());
        let do_padding = original_data_len > 0;
        let last_block_len = if do_padding {
            original_data_len.saturating_sub((block_count - 1) * max_block)
        } else {
            0
        };

        let mut offset = 8usize;
        let mut result = Vec::with_capacity(original_data_len.max(block_count));

        for idx in 0..block_count {
            if offset + 4 > bytes.len() {
                return Err(Error::DecryptionFailed("Truncated packed data".into()));
            }
            let c_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + c_len > bytes.len() {
                return Err(Error::DecryptionFailed("Truncated ciphertext block".into()));
            }
            let c = Ciphertext::from_bytes(&bytes[offset..offset + c_len], priv_key.pub_key().n())?;
            offset += c_len;

            let plain = Self::decrypt(priv_key, &c)?;

            if do_padding {
                // Restore leading zeros stripped by BigUint::to_bytes_be
                let expected = if idx == block_count - 1 {
                    last_block_len
                } else {
                    max_block
                };
                let pad = expected.saturating_sub(plain.len());
                result.extend(std::iter::repeat_n(0u8, pad));
            }

            result.extend_from_slice(&plain);
        }

        Ok(result)
    }

    /// Compute the maximum plaintext block size in bytes for a given public key.
    ///
    /// Derived as `floor((n_bits/3 - 1) / 8)`, clamped to a minimum of 1.
    /// This is the byte-level counterpart of [`PublicKey::plaintext_bound_bits`] and determines
    /// the block boundaries used by [`encrypt_stream`](Okuchi::encrypt_stream) and
    /// [`decrypt_stream`](Okuchi::decrypt_stream).
    fn max_plaintext_bytes(pub_key: &PublicKey) -> usize {
        let n_bits = pub_key.n().bits();
        let p_bits = n_bits / 3;
        let bytes = p_bits.saturating_sub(1) / 8;
        std::cmp::max(1, bytes)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint_dig::BigUint;

    use crate::KeyPair;

    use super::*;

    const TEST_KEY_SIZE: usize = 2048;

    #[test]
    fn encrypt_decrypt_long_text() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let msg = "Rust cryptography long text test".repeat(50);
        let packed = Okuchi::encrypt_stream(keypair.pub_key(), &msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt_stream(keypair.priv_key(), &packed).unwrap();
        assert_eq!(String::from_utf8(decrypted_bytes).unwrap(), msg);
    }

    #[test]
    fn encrypt_decrypt_empty_string() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let packed = Okuchi::encrypt_stream(keypair.pub_key(), b"").unwrap();
        let decrypted = Okuchi::decrypt_stream(keypair.priv_key(), &packed).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn leading_zero_bytes_preserved() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let max_block = {
            let n_bits = keypair.pub_key().n().bits();
            std::cmp::max(1, ((n_bits / 3).saturating_sub(1)) / 8)
        };
        let mut data = vec![0u8; max_block];
        data[max_block - 1] = 0xFF;
        let packed = Okuchi::encrypt_stream(keypair.pub_key(), &data).unwrap();
        let decrypted = Okuchi::decrypt_stream(keypair.priv_key(), &packed).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn homomorphic_addition() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let m1 = BigUint::from(50u32);
        let m2 = BigUint::from(25u32);

        let packed1 = Okuchi::encrypt_stream(pub_key, m1.to_bytes_be()).unwrap();
        let packed2 = Okuchi::encrypt_stream(pub_key, m2.to_bytes_be()).unwrap();
        let packed_sum = Okuchi::homomorphic_add_packed(pub_key, &packed1, &packed2).unwrap();
        let decrypted_bytes = Okuchi::decrypt_stream(priv_key, &packed_sum).unwrap();
        assert_eq!(BigUint::from_bytes_be(&decrypted_bytes), &m1 + &m2);
    }
}
