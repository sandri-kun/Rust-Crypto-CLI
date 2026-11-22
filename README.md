# 🦀 Rust Crypto CLI

> A high-performance, secure command-line tool for encrypting and decrypting sensitive data like seed phrases, built with Rust.

[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Crypto](https://img.shields.io/badge/Encryption-AES--256--GCM-blue.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

## 🛡️ Security Features

This tool implements modern, industry-standard cryptographic primitives to ensure your sensitive data remains protected:

* **Authenticated Encryption:** Uses **AES-256-GCM** to provide both confidentiality and integrity protection against tampering.
* **Key Derivation:** Defaults to **Argon2id v1.3** (64 MiB, 3 iterations, 1 lane, 32-byte key). **PBKDF2-HMAC-SHA256** (600,000 iterations) remains available. Both derive keys for AES-256-GCM; Argon2 is not itself the encryption cipher.
* **Randomness:** Generates unique, cryptographically secure 16-byte **Salts** and 12-byte **Nonces** for every encryption operation using `getrandom`.
* **Memory Cleanup:** Uses `Zeroizing` guards for passwords, plaintext, derived keys, decrypted output, and Argon2 working memory, including error paths. Enables zeroization features for AES/GHASH internals. Password entry displays one `*` per Unicode character. Backspace removes the last character; Enter submits, and Esc or Ctrl+C cancels. The number of stars reveals password length. Cleanup cannot guarantee erasure of OS swap, crash dumps, terminal history, compiler temporaries, or data after forced process termination.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have Rust and Cargo installed on your system. If not, get it from [rustup.rs](https://rustup.rs/).


## Ciphertext format and compatibility

New encryption outputs standard Base64 over:

`SEEDCRYPT (9 bytes) | version 0x01 | KDF ID | salt (16 bytes) | nonce (12 bytes) | ciphertext | GCM tag (16 bytes)`

KDF `0x01` selects PBKDF2; `0x02` selects Argon2id. The magic, version, and KDF ID are authenticated as GCM additional data. Parameters above are fixed for version 1; future parameter changes require a new format version. Each encryption generates fresh salt and nonce.

Decryption automatically reads metadata and also supports the original `salt | nonce | ciphertext | tag` PBKDF2 format. It tries authenticated legacy decryption if new-format parsing or authentication fails, including the rare case where an old random salt matches the new marker. Unknown metadata cannot successfully decrypt unless the entire input is independently valid legacy ciphertext. Older application versions cannot decrypt the new format, including new PBKDF2 outputs.

Run `cargo run --release`, select encryption, then press Enter for Argon2id or choose PBKDF2. Decryption requires no algorithm selection. Plaintext leading/trailing spaces are preserved; only the input line ending is removed.

Validation: `cargo test --release` and `cargo clippy --all-targets -- -D warnings`.


## Save encrypted notes

After encryption, choose `[1] Save encrypted note as JSON` and enter a filename such as `wallet_backup` or `wallet_backup.json`. Files are saved relative to the working directory under `secret_notes/`. Existing files are never overwritten. Names accept 1?100 ASCII letters, numbers, hyphens, or underscores, with an optional `.json` extension; paths and Windows device names are rejected. The directory is excluded by `.gitignore`.

JSON stores only ciphertext and non-secret format metadata: schema/version, AES-256-GCM, Base64 encoding, and KDF parameters. No password, plaintext, preview, or password hash is saved. Choose a filename that does not reveal sensitive details. Public metadata does not require secrecy, but ciphertext can still be attacked offline if someone obtains the file and the password is weak.

To decrypt a saved note, choose main menu `[4] Browse saved notes`, select a numbered JSON file, and enter its password. Press Enter to cancel file selection or to clear the decrypted result. Missing or empty folders are handled without creating files. Only regular files with supported filenames are listed; JSON reads are limited to 16 MiB. The manual Base64 decrypt prompt remains available. Descriptive JSON metadata is not authenticated; decryption relies on the authenticated header inside the ciphertext, not the external JSON fields.


## Open a dropped JSON file

Choose menu `[5] Open JSON file / Drag and drop`, drag one JSON note into the terminal at the path prompt, then press Enter. You can also type or paste its path. Paths containing spaces and paths wrapped in matching single or double quotes are supported, including files outside `secret_notes/`. Enter on an empty prompt cancels. The path is opened as a file and never executed as a shell command.

Enter the note password to decrypt, then press Enter to clear the result. The same JSON validation and 16 MiB limit apply. Drag-and-drop must be supported by your terminal; pasting a path remains available otherwise.


## Terminal interface

The CLI uses English labels, consistent section headings, numbered options, and `[ok]`, `[info]`, and `[error]` status messages. The ASCII layout works without color or special fonts. Existing menu numbers are preserved. End-of-input at the main menu exits cleanly. This presentation update does not imply security certification or an independent audit.
