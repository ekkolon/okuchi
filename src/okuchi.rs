// Copyright 2025 Nelson Dominguez
// SPDX-License-Identifier: MIT OR Apache-2.0

use num_bigint_dig::{BigUint, ModInverse, RandBigInt};
use num_traits::One;
use num_traits::Zero;
use rand::rngs::OsRng;

use crate::ciphertext::Ciphertext;
use crate::error::{Error, Result};
use crate::key::{PrivateKey, PublicKey};

pub struct Okuchi;

impl Okuchi {
    /// Encrypts a plaintext under the Okamoto-Uchiyama scheme.
    ///
    /// ## Plaintext Space
    ///
    /// Technically m ∈ ℤ_p, but we enforce m < n for implementation simplicity.
    /// The effective message space is therefore min(p, n), which is p in practice.
    pub fn encrypt<P: AsRef<[u8]>>(pub_key: &PublicKey, plaintext: P) -> Result<Ciphertext> {
        let n = pub_key.n();

        let bytes = plaintext.as_ref();
        let plaintext = BigUint::from_bytes_be(bytes);
        if &plaintext >= n {
            return Err(Error::PlaintextTooLarge);
        }

        let mut rng = OsRng;
        let r = rng.gen_biguint_range(&BigUint::one(), n);

        // c = g^m · h^r mod n
        let gm = pub_key.g().modpow(&plaintext, n);
        let hr = pub_key.h().modpow(&r, n);
        let c = (gm * hr) % n;

        Ok(Ciphertext::new(c))
    }

    /// Encrypt an arbitrary-length byte sequence. Returns a packed byte vector
    /// containing version, block count and each ciphertext's length-prefixed bytes.
    ///
    /// Packed format:
    /// [u8 version=1][u32 BE block_count]
    ///   for each block:
    ///     [u32 BE len][len bytes ciphertext]
    pub fn encrypt_stream<P: AsRef<[u8]>>(pub_key: &PublicKey, data: P) -> Result<Vec<u8>> {
        let bytes = data.as_ref();
        let max_block = Self::max_plaintext_bytes(pub_key);

        let mut blocks: Vec<Vec<u8>> = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let end = std::cmp::min(i + max_block, bytes.len());
            let block = &bytes[i..end];
            let c = Self::encrypt(pub_key, block)?;
            blocks.push(c.to_bytes());
            i = end;
        }

        // If data is empty, encrypt a single zero-block so decrypt can distinguish empty vs missing.
        if bytes.is_empty() {
            let c = Self::encrypt(pub_key, [])?;
            blocks.push(c.to_bytes());
        }

        // serialize
        let mut out = Vec::new();
        out.push(1u8); // version
        let cnt = blocks.len() as u32;
        out.extend_from_slice(&cnt.to_be_bytes());
        for b in blocks {
            let len = b.len() as u32;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&b);
        }

        Ok(out)
    }

    /// Decrypt a single Ciphertext to raw bytes.
    pub fn decrypt(priv_key: &PrivateKey, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
        let p = &priv_key.p;
        let p_squared = p * p;
        let c = ciphertext.value();

        if c >= priv_key.pub_key().n() {
            return Err(Error::InvalidCiphertext);
        }

        let p_minus_1 = p - BigUint::one();
        let cp = c.modpow(&p_minus_1, &p_squared);

        let l_cp = crate::util::l_function(&cp, p);
        let l_gp = crate::util::l_function(&priv_key.g_p_precomputed, p);

        let l_gp_inv = l_gp
            .mod_inverse(p)
            .ok_or(Error::DecryptionFailed("Modular inverse failed".into()))?
            .to_biguint()
            .ok_or(Error::DecryptionFailed("Inverse negative".into()))?;

        let m = (l_cp * l_gp_inv) % p;

        // special-case zero -> empty vec (so empty plaintext roundtrips correctly)
        let bytes = if m.is_zero() {
            Vec::new()
        } else {
            m.to_bytes_be()
        };

        Ok(bytes)
    }

    /// Decrypt a packed stream produced by `encrypt_stream`.
    ///
    /// Returns reassembled plaintext bytes.
    pub fn decrypt_stream<B: AsRef<[u8]>>(priv_key: &PrivateKey, packed: B) -> Result<Vec<u8>> {
        let bytes = packed.as_ref();
        // parse header
        if bytes.len() < 5 {
            return Err(Error::DecryptionFailed("Packed data too short".into()));
        }
        let version = bytes[0];
        if version != 1u8 {
            return Err(Error::DecryptionFailed("Unsupported packed version".into()));
        }
        let mut offset = 1usize;
        let block_count = {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[offset..offset + 4]);
            offset += 4;
            u32::from_be_bytes(buf) as usize
        };

        let mut result: Vec<u8> = Vec::new();

        for _ in 0..block_count {
            if offset + 4 > bytes.len() {
                return Err(Error::DecryptionFailed("Truncated packed data".into()));
            }
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&bytes[offset..offset + 4]);
            offset += 4;
            let len = u32::from_be_bytes(len_buf) as usize;

            if offset + len > bytes.len() {
                return Err(Error::DecryptionFailed("Truncated ciphertext block".into()));
            }
            let c_bytes = &bytes[offset..offset + len];
            offset += len;

            // reconstruct Ciphertext and decrypt block
            let c = Ciphertext::from(c_bytes);
            let block_plain = Self::decrypt(priv_key, &c)?;
            result.extend_from_slice(&block_plain);
        }

        Ok(result)
    }

    /// Homomorphically add two packed ciphertext streams (produced by `encrypt_stream`).
    ///
    /// Both packed inputs must use the same block count and version. Returns a new
    /// packed stream with each block = (c1_block * c2_block) mod n.
    #[allow(unused)]
    fn homomorphic_add_packed(
        pub_key: &PublicKey,
        packed_a: &[u8],
        packed_b: &[u8],
    ) -> Result<Vec<u8>> {
        // Parse both headers quickly (reuse format from encrypt_stream)
        if packed_a.len() < 5 || packed_b.len() < 5 {
            return Err(Error::DecryptionFailed("Packed input too short".into()));
        }
        if packed_a[0] != 1 || packed_b[0] != 1 {
            return Err(Error::DecryptionFailed("Unsupported packed version".into()));
        }

        let a_cnt = u32::from_be_bytes(packed_a[1..5].try_into().unwrap()) as usize;
        let b_cnt = u32::from_be_bytes(packed_b[1..5].try_into().unwrap()) as usize;
        if a_cnt != b_cnt {
            return Err(Error::DecryptionFailed("Block count mismatch".into()));
        }

        // helper to iterate blocks
        fn iter_blocks(packed: &[u8]) -> Result<Vec<Vec<u8>>> {
            let mut out = Vec::new();
            let mut off = 1usize + 4usize;
            let cnt = u32::from_be_bytes(packed[1..5].try_into().unwrap()) as usize;
            for _ in 0..cnt {
                if off + 4 > packed.len() {
                    return Err(Error::DecryptionFailed("Truncated packed data".into()));
                }
                let len = u32::from_be_bytes(packed[off..off + 4].try_into().unwrap()) as usize;
                off += 4;
                if off + len > packed.len() {
                    return Err(Error::DecryptionFailed("Truncated packed data".into()));
                }
                out.push(packed[off..off + len].to_vec());
                off += len;
            }
            Ok(out)
        }

        let blocks_a = iter_blocks(packed_a)?;
        let blocks_b = iter_blocks(packed_b)?;

        let mut out_blocks: Vec<Vec<u8>> = Vec::with_capacity(a_cnt);
        let n = pub_key.n();

        for (a_bytes, b_bytes) in blocks_a.into_iter().zip(blocks_b.into_iter()) {
            let a_c = Ciphertext::from(&a_bytes);
            let b_c = Ciphertext::from(&b_bytes);
            // multiply ciphertexts (homomorphic addition)
            let prod = Ciphertext::new((&a_c * &b_c).value().clone() % n);
            out_blocks.push(prod.to_bytes());
        }

        // serialize packed format
        let mut out = Vec::new();
        out.push(1u8);
        let cnt_u32 = out_blocks.len() as u32;
        out.extend_from_slice(&cnt_u32.to_be_bytes());
        for b in out_blocks {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(&b);
        }

        Ok(out)
    }

    /// Conservative estimate of maximum plaintext bytes per block.
    ///
    /// OU's plaintext space is modulo `p`, but public key exposes `n = p^2 q`.
    /// If p,q are chosen similar size then bits(p) ≈ bits(n)/3. We use that
    /// conservative estimate to compute a safe byte-length per block.
    fn max_plaintext_bytes(pub_key: &PublicKey) -> usize {
        let n_bits = pub_key.n().bits();
        // conservative estimate of p bits
        let p_bits = n_bits / 3;
        // ensure at least 1 byte available
        let bytes = p_bits.saturating_sub(1) / 8;
        // require at least 1 byte
        std::cmp::max(1, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair;

    use num_traits::Zero;

    #[test]
    fn encrypt_decrypt_utf8_emoji() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let msg = "Testing OU encryption";

        // Use packed stream API for arbitrary UTF-8
        let packed = Okuchi::encrypt_stream(pub_key, msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt_stream(priv_key, &packed).unwrap();

        let decrypted = String::from_utf8(decrypted_bytes).expect("decrypted not valid UTF-8");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_decrypt_long_text() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        // make a long message that will definitely exceed a single block
        let msg = "Rust cryptography long text test".repeat(50);

        let packed = Okuchi::encrypt_stream(pub_key, &msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt_stream(priv_key, &packed).unwrap();

        let decrypted = String::from_utf8(decrypted_bytes).expect("decrypted not valid UTF-8");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn homomorphic_addition() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        // small integers that fit in one block
        // test homomorphic addition via packed streams
        let m1 = BigUint::from(50u32);
        let m2 = BigUint::from(25u32);

        let packed1 = Okuchi::encrypt_stream(pub_key, m1.to_bytes_be()).unwrap();
        let packed2 = Okuchi::encrypt_stream(pub_key, m2.to_bytes_be()).unwrap();

        // homomorphically add the two packed streams (block by block)
        let packed_sum = Okuchi::homomorphic_add_packed(pub_key, &packed1, &packed2).unwrap();

        let decrypted_sum_bytes = Okuchi::decrypt_stream(priv_key, &packed_sum).unwrap();
        let decrypted_sum_bn = BigUint::from_bytes_be(&decrypted_sum_bytes);

        let expected = &m1 + &m2;
        assert_eq!(decrypted_sum_bn, expected);
    }

    #[test]
    fn keygen_consistency() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        assert_eq!(priv_key.pub_key(), pub_key);
        assert!(!pub_key.n().is_zero());
        assert!(!pub_key.g().is_zero());
        assert!(!pub_key.h().is_zero());

        // n should be roughly the right size
        assert!(pub_key.n().bits() >= 504);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let keypair = KeyPair::new(512).unwrap();
        let message = "hello world!";

        let ciphertext = Okuchi::encrypt(keypair.pub_key(), message).unwrap();
        let decrypted = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();

        assert_eq!(message.as_bytes(), decrypted);
    }

    #[test]
    fn encrypt_decrypt_utf8_ascii() {
        let keypair = KeyPair::new(512).unwrap();
        let msg = "Hello from Japan";

        let ciphertext = Okuchi::encrypt(keypair.pub_key(), msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();

        let decrypted = String::from_utf8(decrypted_bytes).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_decrypt_utf8_japanese() {
        let keypair = KeyPair::new(512).unwrap();
        let msg = "こんにちは世界"; // Japanese UTF-8

        let ciphertext = Okuchi::encrypt(keypair.pub_key(), msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();

        let decrypted = String::from_utf8(decrypted_bytes).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_decrypt_empty_string() {
        let keypair = KeyPair::new(512).unwrap();
        let msg = "";

        let ciphertext = Okuchi::encrypt(keypair.pub_key(), msg).unwrap();
        let decrypted_bytes = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();

        let decrypted = String::from_utf8(decrypted_bytes).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn probabilistic_encryption() {
        let keypair = KeyPair::new(512).unwrap();
        let message = "Hello world";

        let c1 = Okuchi::encrypt(keypair.pub_key(), message).unwrap();
        let c2 = Okuchi::encrypt(keypair.pub_key(), message).unwrap();

        // different random r values MUST produce different ciphertexts
        assert_ne!(c1.value(), c2.value());
    }

    #[test]
    fn plaintext_too_large() {
        let keypair = KeyPair::new(512).unwrap();
        let too_large = keypair.pub_key().n() + BigUint::one();

        let result = Okuchi::encrypt(keypair.pub_key(), too_large.to_bytes_be());
        assert!(matches!(result, Err(Error::PlaintextTooLarge)));
    }

    #[test]
    fn invalid_ciphertext() {
        let keypair = KeyPair::new(512).unwrap();
        let bad_val = keypair.pub_key().n() + BigUint::one();
        let bad_cipher = Ciphertext::new(bad_val);

        let result = Okuchi::decrypt(keypair.priv_key(), &bad_cipher);
        assert!(matches!(result, Err(Error::InvalidCiphertext)));
    }

    #[test]
    fn ciphertext_serialization() {
        let val = BigUint::from(0xDEADBEEFu64);
        let c = Ciphertext::new(val.clone());

        let bytes = c.to_bytes();
        let c_restored = Ciphertext::from(&bytes);

        assert_eq!(c, c_restored);
        assert_eq!(c_restored.value(), &val);
    }

    #[test]
    fn zero_message() {
        let keypair = KeyPair::new(512).unwrap();
        let message = BigUint::zero();

        let c = Okuchi::encrypt(keypair.pub_key(), message.to_bytes_be()).unwrap();
        let decrypted = Okuchi::decrypt(keypair.priv_key(), &c).unwrap();

        assert_eq!(message, BigUint::from_bytes_be(&decrypted));
    }

    #[test]
    fn homomorphic_triple_addition() {
        let keypair = KeyPair::new(512).unwrap();
        let pub_key = keypair.pub_key();
        let priv_key = keypair.priv_key();

        let m1 = BigUint::from(10u32);
        let m2 = BigUint::from(20u32);
        let m3 = BigUint::from(30u32);

        let c1 = Okuchi::encrypt(pub_key, m1.to_bytes_be()).unwrap();
        let c2 = Okuchi::encrypt(pub_key, m2.to_bytes_be()).unwrap();
        let c3 = Okuchi::encrypt(pub_key, m3.to_bytes_be()).unwrap();

        let c_prod = &(&c1 * &c2) * &c3;
        let c_final = Ciphertext::new(c_prod.value() % pub_key.n());

        let decrypted = Okuchi::decrypt(priv_key, &c_final).unwrap();
        let expected = (&m1 + &m2 + &m3) % &priv_key.p;

        assert_eq!(expected.to_bytes_be(), decrypted);
    }

    #[test]
    fn key_structure_validation() {
        let keypair = KeyPair::new(512).unwrap();
        let priv_key = keypair.priv_key();

        // verify n = p²q
        let p_squared = &priv_key.p * &priv_key.p;
        let n = &p_squared * &priv_key.q;

        assert_eq!(&n, priv_key.pub_key().n());
    }

    #[test]
    fn max_safe_plaintext() {
        let keypair = KeyPair::new(512).unwrap();
        let priv_key = keypair.priv_key();

        // max safe value is p - 1
        let max_safe = &priv_key.p - BigUint::one();
        let max_safe_bytes = max_safe.to_bytes_be();
        let ciphertext = Okuchi::encrypt(keypair.pub_key(), &max_safe_bytes).unwrap();
        let decrypted = Okuchi::decrypt(keypair.priv_key(), &ciphertext).unwrap();

        assert_eq!(max_safe_bytes, decrypted);
    }
}
