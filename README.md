# Okuchi

A pure-Rust implementation of the **Okamoto-Uchiyama (OU)** cryptosystem: a
probabilistic public-key encryption scheme with additive homomorphism, whose
security relies on the hardness of factoring `n = p²q` and computing discrete
logarithms modulo `p²`.

**Okuchi** is a portmanteau of **Ok**amoto and **Uchi**yama.

---

## ⚠️ Important Notice

This implementation is **experimental**, **incomplete**, and **not audited** by
any external security professionals. It may contain defects, conceptual
mistakes, side-channel vulnerabilities, insecure parameter choices, or other
issues that could compromise confidentiality, integrity, or availability of
data.

The project is a **work in progress**. Breaking changes, API removals, or
redesigns may occur without notice.

**Do not use Okuchi in production systems, high-risk environments, or anywhere
security or correctness is critical.**

If you choose to use this code despite these warnings, you do so entirely at
your own risk. No guarantees, explicit or implied, are made regarding
correctness, security, or fitness for any purpose. The author(s) assume no
liability for any damages or consequences resulting from use or misuse of this
software.

---

## Goals

- Provide a correct, readable, and safe Rust implementation of the OU
  cryptosystem
- Serve as a reference for learning and experimentation
- Maintain minimal dependencies and a clear internal structure

This project does **not** aim to be a hardened or production-quality
cryptographic library.

---

## Features

- **Probabilistic encryption**: two encryptions of the same plaintext produce
  distinct ciphertexts
- **Additive homomorphism**: `E(m1) * E(m2) mod n` decrypts to
  `(m1 + m2) mod p`, without decrypting either operand
- **Stream API**: encrypt and decrypt arbitrary-length byte sequences via
  automatic block splitting and reassembly
- **Validated plaintext type**: [`Plaintext`] enforces the OU plaintext bound
  at construction and provides checked addition for safe homomorphic
  accumulation
- **Zeroize on drop**: secret key material (`p`, `q`, derived constants) is
  zeroed when the key is dropped

---

## Security Notes

- The minimum enforced key size is **512 bits** (testing only). Use **2048
  bits or larger** for any non-trivial use.
- The modular exponentiation `c^(p-1) mod p²` in decryption is routed through
  `crypto-bigint` Montgomery form for constant-time guarantees. All other
  big-integer operations (`num-bigint-dig`) are **variable-time** and may leak
  information about secret values through timing.
- No formal audit has been performed. Do not deploy in adversarial environments.

---

## Usage

Intended use cases:

- Academic experiments
- Prototyping
- Security research
- Code reading and learning

**Production use is strongly discouraged.**

### Encrypt and Decrypt

```rust
use okuchi::{KeyPair, Okuchi};

let keypair  = KeyPair::new(2048).expect("key generation failed");
let pub_key  = keypair.pub_key();
let priv_key = keypair.priv_key();

let message = "hello world 🌍";

// Encrypt arbitrary-length data via the stream API
let packed = Okuchi::encrypt_stream(pub_key, message).unwrap();

// Decrypt
let decrypted_bytes = Okuchi::decrypt_stream(priv_key, &packed).unwrap();
let decrypted = String::from_utf8(decrypted_bytes).unwrap();

assert_eq!(message, decrypted);
```
