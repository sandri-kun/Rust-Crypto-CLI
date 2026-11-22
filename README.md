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


## Multiline and masked secret input

Encryption offers four input modes: single line visible (default), multiline visible, single line masked, and multiline masked. Masked input displays `*` characters instead of the secret. Backspace removes the last character; Esc or Ctrl+C cancels masked input. Visible input is echoed by the terminal.

For multiline input, enter `.end` on its own line to finish. Enter `..end` to include a literal `.end` line. Spaces and blank lines are preserved, lines are joined with LF, and the terminator is excluded. A final empty content line preserves a trailing LF. End-of-input during visible entry cancels the operation rather than encrypting partial content.

## Change password / Re-encrypt note

Choose menu `[6] Change password / Re-encrypt note`. Type or drop the source JSON path, enter its current password, then enter and confirm the new password. The source is authenticated before requesting the new password. Plaintext is never displayed or written to disk during this operation and remains in its zeroizing buffer until re-encryption completes.

The output uses Argon2id (64 MiB, 3 iterations, one lane) and AES-256-GCM with fresh random salt and nonce. Choose `Save encrypted note as JSON` and enter a new filename to persist the change. Existing files are never overwritten. Cancelling without saving discards the new ciphertext. The original file and any older copies still accept the old password; creating a new note does not revoke access to those copies.


## Encrypt files with drag and drop

Choose `[7] Encrypt file / Drag and drop`, drop one source file into the path prompt (or type its path), and press Enter. Files up to 8 MiB are supported, including PDFs, images, archives, text, and empty files. Directories and symlinks are rejected. Enter and confirm a password, then choose to save the result as JSON in `secret_notes/`. The source is never changed or deleted. Encryption uses Argon2id and AES-256-GCM with fresh random salt and nonce. File contents are read as bytes, not converted to text.

Choose `[8] Decrypt file / Export original bytes`, provide the encrypted JSON path and password, then enter an output filename including the extension you want. The original filename and extension can optionally be stored inside encryption. Timestamps, permissions, and directory structure are not stored. Only the file contents are restored, byte for byte. Outputs are written unencrypted to `decrypted_files/`, which is ignored by Git; existing files are never overwritten. On Unix, newly exported files are created with mode 0600. On Windows, access follows the destination folder permissions. Authentication must succeed before any plaintext file is created. RAM buffers are zeroized when finished or cancelled; this does not erase source or exported files from disk.

Menu 6 also supports changing the password of encrypted binary files. Use menu 8 to export their contents; the text viewer requires valid UTF-8. Existing text notes and legacy ciphertext remain supported. The 8 MiB input cap keeps Base64 JSON output within the existing 16 MiB JSON read limit. This implementation loads each file into RAM and does not provide streaming encryption.


## Remember the original filename (optional)

Menu 7 asks `Remember original filename inside encryption? [y/N]`. Enter `y` to store only the basename (including extension) inside the encrypted, authenticated content. Enter `n` or press Enter to keep the previous raw-byte format. No source folder path is saved; the basename does not appear in public JSON metadata.

When opening a named file in menu 8, `Output filename [original-name.ext]` lets you press Enter to use its original name, type a replacement, or enter `/cancel`. For older files or files encrypted without a name, Enter still cancels and the output filename must be entered manually. Existing files are never overwritten. Filenames with spaces and Unicode are supported up to 240 UTF-8 bytes; path separators, Windows-invalid characters, reserved device names and unsafe endings are rejected.

Named files use authenticated payload version 2. KDF parameters and AES-GCM remain the same as version 1; decrypted content is `name_length_u16_le | UTF-8 basename | file bytes`. Version 1 remains raw content, so older files cannot be accidentally interpreted as filename metadata. Menu 6 preserves this file-container version when changing a password. Older application versions cannot open version 2 notes. The text viewer directs named files to menu 8.
