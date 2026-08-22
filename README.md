# 🦀 Rust Crypto CLI

> A high-performance, secure command-line tool for encrypting and decrypting sensitive data like seed phrases, built with Rust.

[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Crypto](https://img.shields.io/badge/Encryption-AES--256--GCM-blue.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

## 🛡️ Security Features

This tool implements modern, industry-standard cryptographic primitives to ensure your sensitive data remains protected:

* **Authenticated Encryption:** Uses **AES-256-GCM** to provide both confidentiality and integrity protection against tampering.
* **Key Derivation:** Employs **PBKDF2-HMAC-SHA256** with a high iteration count (`600,000`) to harden user passwords against brute-force attacks.
* **Randomness:** Generates unique, cryptographically secure 16-byte **Salts** and 12-byte **Nonces** for every encryption operation using `getrandom`.
* **Memory Safety:** Automatically wipes derived cryptographic keys from RAM immediately after use utilizing the `zeroize` crate.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have Rust and Cargo installed on your system. If not, get it from [rustup.rs](https://rustup.rs/).
