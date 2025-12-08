# Okuchi

A pure Rust implementation of the **Okamoto–Uchiyama** cryptosystem - a probabilistic public-key scheme whose security relies on the hardness of factoring and discrete logarithms modulo a composite number.

**Okuchi** is a portmanteau of **Ok**amoto and **Uchi**yama.

## ⚠️ Important Notice

The project is evolving and should be treated as a **work in progress**.
Breaking changes, redesigns, or API removals may occur without notice.

This implementation is (still) **experimental**, **incomplete**, and **not audited** by any external security professionals.
It may contain defects, conceptual mistakes, side-channel vulnerabilities, insecure parameter choices, or other issues that could compromise confidentiality, integrity, or availability of data.

**Do not use Okuchi in production systems, high-risk environments, or anywhere security or correctness is critical.**

If you choose to use this code despite these warnings, **you do so entirely at your own risk**. No guarantees - explicit or implied - are made regarding performance, correctness, security, or fitness for any purpose.
The author(s) **assume no liability** for any damages, losses, or consequences resulting from the use, misuse, or inability to use this software.

## Goals

- Provide a correct, readable and safe Rust implementation of the **OU** cryptosystem
- Serve as a reference for learning and experimentation
- Maintain minimal dependencies and clear internal structure

This project **does not** aim to be a hardened or production-quality cryptographic library.

## Usage

As mentioned above, until the library matures and receives proper review, usage should be limited to:

- academic experiments
- prototyping
- security research
- code reading and learning

**Production use is strongly discouraged.**

### Example

```rs
use okuchi::{KeyPair, Okuchi};

let keypair = KeyPair::new(2048).expect("key generation failed");
let pub_key = keypair.pub_key();
let priv_key = keypair.priv_key();

let message = "hello world 🌍";

// Encrypt (stream API)
let packed = Okuchi::encrypt_stream(pub_key, message).unwrap();

// Decrypt
let decrypted_bytes = Okuchi::decrypt_stream(priv_key, &packed).unwrap();
let decrypted = String::from_utf8(decrypted_bytes).unwrap();

assert_eq!(message, decrypted);
```

## References

- Okamoto, T., Uchiyama, S. (1998). _A New Public-Key Cryptosystem as Secure as Factoring._
