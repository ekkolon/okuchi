// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;

use crate::ciphertext::Ciphertext;
use crate::error::{Error, Result};
use crate::key::{PrivateKey, PublicKey};

/// Entry point for all Okamoto-Uchiyama cryptographic operations.
///
/// All methods are stateless. The key material required for each operation
/// is passed explicitly on every call.
pub struct Okuchi;

impl Okuchi {
    /// Encrypt a plaintext byte slice under the Okamoto-Uchiyama scheme.
    ///
    /// Computes `c = g^m * h^r mod n` where `m` is the big-endian integer
    /// encoded by `plaintext` and `r` is a fresh random value in `[1, n)`
    /// with `gcd(r, n) = 1`.
    ///
    /// Encryption is probabilistic: two calls with identical inputs produce
    /// distinct ciphertexts with overwhelming probability.
    ///
    /// # Requirements
    ///
    /// - `plaintext`, interpreted as a big-endian integer, must satisfy
    ///   `m.bits() <= pub_key.plaintext_bound_bits()`
    /// - The public key must have been produced by [`KeyPair::new`](crate::KeyPair::new)
    ///   or satisfy the OU parameter invariants documented on [`PublicKey`]
    ///
    /// # Errors
    ///
    /// Returns [`Error::PlaintextTooLarge`] if the plaintext exceeds the
    /// conservative bound `2^(n_bits/3 - 1) - 1`.
    ///
    /// # Security
    ///
    /// `r` is sampled from [`OsRng`] and rejection-sampled until
    /// `gcd(r, n) = 1`.
    pub fn encrypt<P: AsRef<[u8]>>(pub_key: &PublicKey, plaintext: P) -> Result<Ciphertext> {
        let n = pub_key.n();
        let plaintext = BigUint::from_bytes_be(plaintext.as_ref());

        // Enforce m < p. p is secret; use conservative bound: p ≥ 2^(p_bits-1).
        let max_bits = pub_key.plaintext_bound_bits();
        if plaintext.bits() > max_bits {
            return Err(Error::PlaintextTooLarge);
        }

        let mut rng = OsRng;

        // OU requires gcd(r, n) = 1. With n = p²q the failure probability is
        // ≈ 1/p + 1/q. This is negligible but the protocol is undefined otherwise.
        let r = loop {
            let candidate = rng.gen_biguint_range(&BigUint::one(), n);
            if candidate.gcd(n).is_one() {
                break candidate;
            }
        };

        let gm = pub_key.g().modpow(&plaintext, n);
        let hr = pub_key.h().modpow(&r, n);
        let c = (gm * hr) % n;

        Ok(Ciphertext::new(c))
    }

    /// Homomorphically add two ciphertexts.
    ///
    /// # Security
    ///
    /// Addition wraps silently mod `p` with no error or indication. If the
    /// sum of the underlying plaintexts meets or exceeds `p`, the decrypted
    /// result is incorrect. Use [`Plaintext::checked_add`](crate::Plaintext::checked_add)
    /// before encryption to detect overflow against the conservative public bound.
    pub fn homomorphic_add(pub_key: &PublicKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
        // Computes `E(m1) * E(m2) mod n`, which decrypts to `(m1 + m2) mod p`.
        Ciphertext::new((a.value() * b.value()) % pub_key.n())
    }

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

    /// Encrypt a pre-validated [`Plaintext`](crate::Plaintext).
    ///
    /// Skips the bit-length check performed by [`encrypt`](Okuchi::encrypt)
    /// because [`Plaintext`](crate::Plaintext) construction already enforces the bound.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying [`encrypt`](Okuchi::encrypt) call.
    pub fn encrypt_plaintext(
        pub_key: &PublicKey,
        pt: &crate::plaintext::Plaintext,
    ) -> Result<Ciphertext> {
        Self::encrypt(pub_key, pt.to_bytes_be())
    }

    /// Decrypt a single [`Ciphertext`] to raw big-endian bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCiphertext`] if `ciphertext.value() >= n`.
    ///
    /// # Security
    ///
    /// The modular exponentiation `c^(p-1) mod p²` is performed via using
    /// `crypto-bigint` Montgomery form, providing constant-time guarantees
    /// for that step. The subsequent `L` function computation and modular
    /// multiplication use `num-bigint-dig` and are variable-time.
    pub fn decrypt(priv_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        let p = priv_key.p();
        let p_squared = priv_key.p_squared();
        let c = ciphertext.value();

        if c >= priv_key.pub_key().n() {
            return Err(Error::InvalidCiphertext);
        }

        // c^(p-1) mod p²: constant-time via crypto-bigint
        let p_minus_1 = p - BigUint::one();
        let cp = crate::util::ct_modpow(c, &p_minus_1, p_squared);

        let l_cp = crate::util::l_function(&cp, p);

        // m = L(c^(p-1) mod p²) * L(g^(p-1) mod p²)^(-1) mod p, where L(x) = (x - 1) / p
        // l_gp_inv precomputed in PrivateKey::new
        let m = (l_cp * priv_key.l_gp_inv()) % p;

        let bytes = if m.is_zero() {
            Vec::new()
        } else {
            m.to_bytes_be()
        };
        Ok(bytes)
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

    /// Homomorphically add two packed streams block-by-block.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCiphertext`] if either buffer is shorter than 8 bytes.
    ///
    /// Returns [`Error::DecryptionFailed`] if the two streams have different `block_count` values.
    ///
    /// # Security
    ///
    /// Addition wraps silently mod `p` per block.
    /// See [`homomorphic_add`](Okuchi::homomorphic_add) for the overflow caveat.
    pub fn homomorphic_add_packed(
        pub_key: &PublicKey,
        packed_a: &[u8],
        packed_b: &[u8],
    ) -> Result<Vec<u8>> {
        if packed_a.len() < 8 || packed_b.len() < 8 {
            return Err(Error::InvalidCiphertext);
        }

        // Both streams must have equal `block_count` values. Each pair of
        // corresponding blocks is combined as `E(m1_i) * E(m2_i) mod n`,
        // which decrypts to `(m1_i + m2_i) mod p`.
        let a_cnt = u32::from_be_bytes(packed_a[0..4].try_into().unwrap()) as usize;
        let b_cnt = u32::from_be_bytes(packed_b[0..4].try_into().unwrap()) as usize;
        if a_cnt != b_cnt {
            return Err(Error::DecryptionFailed("Block count mismatch".into()));
        }

        let blocks_a = Self::parse_blocks(packed_a)?;
        let blocks_b = Self::parse_blocks(packed_b)?;
        let n = pub_key.n();

        let est_ct_bytes = n.bits() / 8 + 1;
        let mut out = Vec::with_capacity(8 + a_cnt * (4 + est_ct_bytes));
        out.extend_from_slice(&(a_cnt as u32).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // original_data_len = 0 sentinel

        for (a_bytes, b_bytes) in blocks_a.into_iter().zip(blocks_b) {
            let a_c = Ciphertext::from_bytes(&a_bytes, n)?;
            let b_c = Ciphertext::from_bytes(&b_bytes, n)?;
            // E(m1) * E(m2) mod n = E(m1 + m2 mod p)
            let prod = Ciphertext::new((a_c.value() * b_c.value()) % n);
            let prod_bytes = prod.to_bytes();
            out.extend_from_slice(&(prod_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&prod_bytes);
        }

        Ok(out)
    }

    /// Extract raw ciphertext byte blocks from a packed stream.
    ///
    /// Reads `block_count` from the 4-byte header and parses each block's
    /// length-prefixed ciphertext bytes. The 8-byte header (block count +
    /// original data length) is skipped entirely.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DecryptionFailed`] if any length field extends beyond
    /// the buffer boundary.
    fn parse_blocks(packed: &[u8]) -> Result<Vec<Vec<u8>>> {
        let cnt = u32::from_be_bytes(packed[0..4].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(cnt);
        let mut off = 8usize; // skip 8-byte header
        for _ in 0..cnt {
            if off + 4 > packed.len() {
                return Err(Error::DecryptionFailed("Truncated packed data".into()));
            }
            let len = u32::from_be_bytes(packed[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + len > packed.len() {
                return Err(Error::DecryptionFailed("Truncated ciphertext block".into()));
            }
            out.push(packed[off..off + len].to_vec());
            off += len;
        }
        Ok(out)
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
    use super::*;
    use crate::key::KeyPair;
    use num_traits::Zero;

    const TEST_KEY_SIZE: usize = 2048;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let message = "hello world!";
        let ciphertext = Okuchi::encrypt(keypair.pub_key(), message).unwrap();
        let decrypted = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();
        assert_eq!(message.as_bytes(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_utf8_emoji() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let msg = "Testing OU encryption";
        let packed = Okuchi::encrypt_stream(keypair.pub_key(), msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt_stream(keypair.priv_key(), &packed).unwrap();
        assert_eq!(String::from_utf8(decrypted_bytes).unwrap(), msg);
    }

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

    #[test]
    fn homomorphic_add_direct() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let m1 = BigUint::from(10u32);
        let m2 = BigUint::from(20u32);
        let m3 = BigUint::from(30u32);

        let c1 = Okuchi::encrypt(pub_key, m1.to_bytes_be()).unwrap();
        let c2 = Okuchi::encrypt(pub_key, m2.to_bytes_be()).unwrap();
        let c3 = Okuchi::encrypt(pub_key, m3.to_bytes_be()).unwrap();

        let c12 = Okuchi::homomorphic_add(pub_key, &c1, &c2);
        let c123 = Okuchi::homomorphic_add(pub_key, &c12, &c3);

        let decrypted = Okuchi::decrypt(priv_key, &c123).unwrap();
        let expected = (&m1 + &m2 + &m3) % priv_key.p();
        assert_eq!(expected.to_bytes_be(), decrypted);
    }

    #[test]
    fn probabilistic_encryption() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let message = "Hello world";
        let c1 = Okuchi::encrypt(keypair.pub_key(), message).unwrap();
        let c2 = Okuchi::encrypt(keypair.pub_key(), message).unwrap();
        assert_ne!(c1.value(), c2.value());
    }

    #[test]
    fn plaintext_too_large() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let max_bits = keypair.pub_key().plaintext_bound_bits();
        let too_large = BigUint::one() << (max_bits + 1);
        assert!(matches!(
            Okuchi::encrypt(keypair.pub_key(), too_large.to_bytes_be()),
            Err(Error::PlaintextTooLarge)
        ));
    }

    #[test]
    fn invalid_ciphertext() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let bad_val = keypair.pub_key().n() + BigUint::one();
        let bad_cipher = Ciphertext::new(bad_val);
        assert!(matches!(
            Okuchi::decrypt(keypair.priv_key(), &bad_cipher),
            Err(Error::InvalidCiphertext)
        ));
    }

    #[test]
    fn zero_message() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let message = BigUint::zero();
        let c = Okuchi::encrypt(keypair.pub_key(), message.to_bytes_be()).unwrap();
        let decrypted = Okuchi::decrypt(keypair.priv_key(), &c).unwrap();
        assert_eq!(message, BigUint::from_bytes_be(&decrypted));
    }

    #[test]
    fn key_structure_validation() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let priv_key = keypair.priv_key();
        assert_eq!(priv_key.p_squared(), &(priv_key.p() * priv_key.p()));
        assert!(!priv_key.pub_key().n().is_zero());
    }

    #[test]
    fn max_safe_plaintext() {
        let keypair = KeyPair::new(TEST_KEY_SIZE).unwrap();
        let max_bits = keypair.pub_key().plaintext_bound_bits();
        let max_safe = (BigUint::one() << max_bits) - BigUint::one();
        let max_safe_bytes = max_safe.to_bytes_be();
        let ciphertext = Okuchi::encrypt(keypair.pub_key(), &max_safe_bytes).unwrap();
        let decrypted = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();
        assert_eq!(max_safe_bytes, decrypted);
    }
}
