# Okuchi

A pure Rust implementation of the **Okamoto–Uchiyama (OU)** public-key cryptosystem.

Okamoto–Uchiyama is a probabilistic encryption scheme whose security is based on the hardness of integer factorization and related problems in modular arithmetic over composite moduli.

**Okuchi** is a portmanteau of **Ok**amoto and **Uchi**yama.

---

## Example

```rust
use okuchi::{KeyPair, EncryptBytes, DecryptBytes};

let keypair = KeyPair::new(2048).expect("key generation failed");
let message = "hello world";

// Encrypt (stream API)
let ciphertext = keypair.encrypt_bytes(message).unwrap();

// Decrypt
let decrypted_bytes = keypair.decrypt_bytes(priv_key, &ciphertext).unwrap();
let decrypted = String::from_utf8(decrypted_bytes).unwrap();

assert_eq!(message, decrypted);
```

---

## Project Goals

Okuchi is intentionally narrow in scope. Its goals are to:

- Provide a **clear and readable** Rust implementation of the Okamoto–Uchiyama cryptosystem
- Favor **explicitness and correctness** over performance tricks
- Keep cryptographic concepts and data flow easy to follow
- Serve as a **learning and reference implementation**

This project explicitly does **not** aim to be:

- A production-grade cryptographic library
- Constant-time or side-channel resistant
- API-stable
- Optimized for performance

---

## Status and Scope

⚠️ **This project is experimental.**

Okuchi is under active development and should be considered a **work in progress**. The API, internal structure, and cryptographic choices may change without notice. No backwards-compatibility guarantees are provided at this stage.

This implementation is:

- **Incomplete**
- **Unaudited**
- **Not hardened against side-channels**
- **Not reviewed by external cryptography professionals**

It may contain:

- Logical or mathematical errors
- Insecure parameter choices
- Side-channel vulnerabilities
- Implementation bugs affecting correctness or security

**Do not use this library in production, high-risk environments, or any system where security or correctness matters.**

If you decide to experiment with this code despite these warnings, you do so entirely at your own risk. No guarantees are made regarding security, correctness, performance, or suitability for any purpose. The author(s) assume no liability for damages or losses resulting from its use.

---

## Intended Use

Until the implementation matures and undergoes proper cryptographic review, usage should be limited to:

- Academic study
- Cryptography research and experimentation
- Prototyping
- Code reading and educational purposes

**Production use is strongly discouraged.**
