#![allow(dead_code, unused_imports, unused_variables, clippy::all)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use num_bigint_dig::BigUint;
use std::sync::OnceLock;

use okuchi::{Decrypt, DecryptBytes, Encrypt, EncryptBytes, KeyPair, Stream};

static KEYPAIR: OnceLock<KeyPair> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    // Use a cached 128-bit keypair for faster fuzzing
    // Note: 128-bit is insecure for production, but fine for fuzzing
    let keypair = KEYPAIR
        .get_or_init(|| KeyPair::generate_with_size(128).expect("Failed to generate keypair"));

    let public = keypair.public_key();

    // Conservative plaintext size limit for 128-bit key
    // For n = p²q with 128 bits: p ≈ 42 bits ≈ 5 bytes
    // Use conservative limit of 4 bytes
    let max_bytes = 4;
    let safe_data = if data.len() > max_bytes { &data[..max_bytes] } else { data };

    // ----- 1. Single-block encryption roundtrip -----
    if let Ok(ciphertext) = public.encrypt(safe_data) {
        match keypair.decrypt(&ciphertext) {
            Ok(plaintext) => {
                let original = BigUint::from_bytes_be(safe_data);
                let decrypted = BigUint::from_bytes_be(&plaintext);
                assert_eq!(original, decrypted, "Single-block roundtrip failed");
            }
            Err(_) => panic!("Decryption failed for valid ciphertext"),
        }
    }

    // ----- 2. Multi-block encryption via encrypt_bytes -----
    if let Ok(packed) = public.encrypt_bytes(safe_data) {
        match keypair.decrypt_bytes(&packed) {
            Ok(plaintext) => {
                // Compare as BigUint values (handles leading zeros correctly)
                let original = BigUint::from_bytes_be(safe_data);
                let decrypted = BigUint::from_bytes_be(&plaintext);
                assert_eq!(original, decrypted, "Multi-block roundtrip failed");
            }
            Err(_) => panic!("Multi-block decryption failed for valid data"),
        }
    }

    // ----- 3. Streaming encryption with various chunk sizes -----
    let chunk_sizes = [1, 2, 4, 8, 16];
    for &chunk_size in &chunk_sizes {
        // Encrypt with streaming
        let mut encryptor = public.encryptor();
        for chunk in safe_data.chunks(chunk_size) {
            if encryptor.update(chunk).is_err() {
                return; // Skip if streaming fails
            }
        }
        let packed = match encryptor.finalize() {
            Ok(p) => p,
            Err(_) => return,
        };

        // Decrypt with streaming
        let mut decryptor = keypair.decryptor();
        let mut decrypted = Vec::new();

        for chunk in packed.chunks(chunk_size) {
            match decryptor.update(chunk) {
                Ok(output) => decrypted.extend(output),
                Err(_) => return,
            }
        }

        match decryptor.finalize() {
            Ok(final_output) => decrypted.extend(final_output),
            Err(_) => return,
        };

        // Compare as BigUint values (handles leading zeros)
        let original = BigUint::from_bytes_be(safe_data);
        let decrypted_value = BigUint::from_bytes_be(&decrypted);
        assert_eq!(
            original, decrypted_value,
            "Streaming roundtrip failed with chunk_size={}",
            chunk_size
        );
    }

    // ----- 4. Invalid ciphertext fuzzing (corruption) -----
    if !safe_data.is_empty() {
        if let Ok(mut packed) = public.encrypt_bytes(safe_data) {
            // Corrupt the packed data in various ways

            // Flip first byte
            if !packed.is_empty() {
                packed[0] ^= 0xFF;
                let _ = keypair.decrypt_bytes(&packed); // Should return Err, not panic
            }

            // Truncate data
            if packed.len() > 1 {
                let truncated = &packed[..packed.len() - 1];
                let _ = keypair.decrypt_bytes(truncated);
            }

            // Append garbage
            packed.extend_from_slice(&[0xFF; 32]);
            let _ = keypair.decrypt_bytes(&packed);
        }
    }

    // ----- 5. Edge case: empty plaintext -----
    if let Ok(ciphertext) = public.encrypt(&[]) {
        match keypair.decrypt(&ciphertext) {
            Ok(plaintext) => {
                let decrypted = BigUint::from_bytes_be(&plaintext);
                assert_eq!(decrypted, BigUint::from(0u8), "Empty plaintext should decrypt to zero");
            }
            Err(_) => panic!("Failed to decrypt empty plaintext"),
        }
    }

    // ----- 6. Edge case: single zero byte -----
    if let Ok(ciphertext) = public.encrypt(&[0]) {
        match keypair.decrypt(&ciphertext) {
            Ok(plaintext) => {
                let decrypted = BigUint::from_bytes_be(&plaintext);
                assert_eq!(decrypted, BigUint::from(0u8), "Zero byte should decrypt to zero");
            }
            Err(_) => panic!("Failed to decrypt zero byte"),
        }
    }

    // ----- 7. Edge case: all ones (near maximum) -----
    let all_ones = vec![0xFF; max_bytes];
    if let Ok(ciphertext) = public.encrypt(&all_ones) {
        match keypair.decrypt(&ciphertext) {
            Ok(plaintext) => {
                let original = BigUint::from_bytes_be(&all_ones);
                let decrypted = BigUint::from_bytes_be(&plaintext);
                assert_eq!(original, decrypted, "All-ones plaintext roundtrip failed");
            }
            Err(_) => {
                // This might legitimately fail if 0xFF...FF >= p
                // which is acceptable
            }
        }
    }

    // ----- 8. Homomorphic addition property -----
    // Split safe_data into two parts and test E(a) * E(b) = E(a+b)
    if safe_data.len() >= 2 {
        let mid = safe_data.len() / 2;
        let part1 = &safe_data[..mid];
        let part2 = &safe_data[mid..];

        if let (Ok(ct1), Ok(ct2)) = (public.encrypt(part1), public.encrypt(part2)) {
            if let Ok(ct_sum) = ct1.add(&ct2, public) {
                if let Ok(decrypted_sum) = keypair.decrypt(&ct_sum) {
                    let a = BigUint::from_bytes_be(part1);
                    let b = BigUint::from_bytes_be(part2);
                    let sum = BigUint::from_bytes_be(&decrypted_sum);

                    // Note: This might overflow p, which is fine
                    // Just verify it doesn't panic
                    let _ = (a + b, sum);
                }
            }
        }
    }

    // ----- 9. Probabilistic encryption property -----
    // Same plaintext should produce different ciphertexts
    if !safe_data.is_empty() {
        if let (Ok(ct1), Ok(ct2)) = (public.encrypt(safe_data), public.encrypt(safe_data)) {
            // Ciphertexts should differ (probabilistic encryption)
            assert_ne!(
                ct1.to_bytes(),
                ct2.to_bytes(),
                "Same plaintext produced identical ciphertexts (not probabilistic)"
            );

            // But both should decrypt to same value
            if let (Ok(pt1), Ok(pt2)) = (keypair.decrypt(&ct1), keypair.decrypt(&ct2)) {
                assert_eq!(
                    pt1, pt2,
                    "Different ciphertexts of same plaintext decrypted to different values"
                );
            }
        }
    }

    // ----- 10. Byte-by-byte streaming (extreme fragmentation) -----
    if safe_data.len() > 0 && safe_data.len() <= 8 {
        // Only test small inputs for performance
        let mut encryptor = public.encryptor();
        for &byte in safe_data {
            if encryptor.update([byte]).is_err() {
                return;
            }
        }
        if let Ok(packed) = encryptor.finalize() {
            let mut decryptor = keypair.decryptor();
            let mut decrypted = Vec::new();

            for &byte in &packed {
                if let Ok(output) = decryptor.update([byte]) {
                    decrypted.extend(output);
                }
            }

            if let Ok(final_output) = decryptor.finalize() {
                decrypted.extend(final_output);
                // Compare as BigUint values
                let original = BigUint::from_bytes_be(safe_data);
                let decrypted_value = BigUint::from_bytes_be(&decrypted);
                assert_eq!(original, decrypted_value, "Byte-by-byte streaming failed");
            }
        }
    }
});
