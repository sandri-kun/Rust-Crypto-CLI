# SeedCrypt

A Rust command-line application for encrypting text notes and files locally with password-based AES-256-GCM encryption.

SeedCrypt supports multiline and masked input, encrypted JSON notes, drag-and-drop file paths, password changes, and optional storage of the original filename inside encryption. It does not upload your notes or passwords to a service.

## Quick start

Install Rust and Cargo, then run these commands from the project directory:

```sh
cargo build --release
cargo run --release
```

An interactive terminal is required for all prompts; redirected input and output are rejected. Password entry displays `*` characters, supports Backspace, and accepts Enter to submit. Esc or Ctrl+C cancels masked input.

Folders are relative to the directory from which you launch the application:

| Folder | Contents |
| --- | --- |
| `secret_notes/` | Encrypted JSON notes you choose to save |
| `decrypted_files/` | Unencrypted files you explicitly export |

Both folders are excluded by `.gitignore`. This prevents normal Git tracking; it does not encrypt, hide, or back up their contents.

## Main menu

| Option | Action |
| --- | --- |
| `1` | Encrypt text |
| `2` | Decrypt Base64 text |
| `3` | Exit |
| `4` | Browse saved notes in `secret_notes/` |
| `5` | Open a JSON note by path or drag and drop |
| `6` | Change password / Re-encrypt note |
| `7` | Encrypt a file by path or drag and drop |
| `8` | Decrypt a file / Export original bytes |
| `9` | Batch encrypt a folder |
| `10` | Batch decrypt a folder |

### Encrypt text

1. Choose `1`, then enter and confirm a new password.
2. Select Argon2id (default) or PBKDF2-SHA256.
3. Select an input mode:

   | Mode | Input |
   | --- | --- |
   | `1` | Single line, visible (default) |
   | `2` | Multiple lines, visible |
   | `3` | Single line, masked with `*` |
   | `4` | Multiple lines, masked with `*` |

4. Enter your text. For multiline input, enter `.end` on its own line to finish. Use `..end` for a literal `.end` line.
5. Copy the resulting Base64 ciphertext or choose `Save encrypted note as JSON`.

Spaces and blank lines are preserved. Multiline input joins lines with LF (`\n`); the terminator is excluded. Include a final empty content line if you need a trailing LF. Visible text is echoed to the terminal. Masked input hides characters but reveals their count. Both modes use terminal events and guarded buffers rather than the shared buffered `stdin` reader. Text input is limited to 8 MiB in total, including multiline separators; passwords are limited to 1,024 UTF-8 bytes. Esc or Ctrl+C cancels either input mode.

### Save encrypted notes

After encryption, choose `Save encrypted note as JSON` and enter a name such as `backup_01` or `backup_01.json`. The `.json` extension is added when omitted.

Saved-note names accept 1-100 ASCII letters, digits, hyphens, or underscores, plus the optional `.json` suffix. Paths and reserved Windows device names are rejected. Existing files are never overwritten; choose another name if a file already exists.

Saving is optional. Returning to the menu without saving discards the generated result unless you have copied the displayed ciphertext elsewhere. File encryption and re-encryption do not print their ciphertext, so save those results to retain them.

### Read encrypted text

Choose one of these options:

- `2`: paste Base64 ciphertext directly.
- `4`: select a numbered JSON note from `secret_notes/`.
- `5`: type, paste, or drop a JSON note path, including a file outside `secret_notes/`.

Enter the password. Decrypted text appears on a temporary terminal screen. Press Enter to clear it and return; Esc or Ctrl+C also dismisses the result. The plaintext buffer is cleared after rendering, before waiting for dismissal. Terminal-control characters other than LF are escaped when displayed.

Use `8` to restore binary files. Named file containers also require option `8`; the text viewer does not render their metadata as text.

### Encrypt files

1. Choose `7`.
2. Drag one source file into the path prompt, or type or paste its path, then press Enter.
3. Answer `Remember original filename inside encryption? [y/N]`:
   - `y`: store the basename and extension inside authenticated encryption.
   - Enter or `n`: store file contents without a filename.
4. Enter and confirm a new password.
5. Save the encrypted JSON note under a chosen name in `secret_notes/`.

Files up to **8 MiB** are supported, including PDFs, images, archives, text, and empty files. Contents are handled as bytes without UTF-8 conversion. File encryption uses Argon2id and AES-256-GCM. The source is never modified or deleted.

Remembering a filename does not store its folder path. The name is encrypted and does not appear in the public JSON metadata. Timestamps, permissions, and directory structure are not preserved.

### Restore files

1. Choose `8` and provide the encrypted JSON path.
2. Enter its password.
3. Choose an output filename:
   - If the original name was stored, press Enter to accept it or type a replacement.
   - Otherwise, enter a name including the desired extension, such as `restored.pdf`. Empty input cancels.
   - Enter `/cancel` to cancel either workflow.

The application restores the original file bytes to `decrypted_files/`. These exported files are **unencrypted**. Existing files are never overwritten, and authentication must succeed before an output file is created.

Output filenames accept spaces and Unicode, up to 240 UTF-8 bytes. Paths, control characters, Windows-invalid characters, reserved device names, leading dots, and trailing dots or spaces are rejected. Newly exported files use mode `0600` on Unix. Windows exports inherit the destination folder's access controls.

### Change a password

1. Choose `6` and provide the source JSON path.
2. Enter the current password. The application authenticates the note first.
3. Enter and confirm the new password.
4. Save the result under a new filename.

The new ciphertext uses Argon2id with fresh salt and nonce. Plaintext is neither displayed nor written to disk during re-encryption. Text, raw binary files, and named file containers are supported; stored filename metadata is preserved.

The original note is retained and still accepts the original password. Re-encrypting does not revoke access to old copies. Cancelling before saving discards the newly generated ciphertext.

### Drag and drop

Choose the relevant menu first, then drop **one file** at the path prompt and press Enter. Drag and drop must be supported by your terminal. If it is unavailable, paste or type the path instead.

Paths containing spaces and paths wrapped in matching single or double quotes are supported. Paths are opened as data and are never executed as shell commands. Enter at an empty path prompt cancels. File reads and writes reject links or reparse points throughout the path, and reject parent-directory (`..`) components. On Windows, only local drive paths are accepted; UNC/network and device paths are rejected. Move the file to a regular local folder if its path passes through a junction.

### Batch encrypt and decrypt

Choose `9` to encrypt all regular files directly inside one source folder, or `10` to decrypt its `.json` files. Subfolders, links, and non-JSON files in decrypt mode are skipped. A batch supports up to 1,000 eligible files; each encrypted source file still has the 8 MiB input limit.

1. Type, paste, or drop the source folder path.
2. Accept the proposed fresh output folder or enter another output folder. Defaults are `secret_notes/batch_<random-id>/` for encryption and `decrypted_files/batch_<random-id>/` for decryption.
3. For encryption, choose whether to remember original filenames inside encryption (default: yes).
4. Review the file list and output folder, then enter `y` to proceed.
5. Enter one password for the batch; encryption asks for confirmation.

Processing is sequential, so only one file's content and Argon2 working memory are needed at a time. Each file gets fresh random salt and nonce and is encrypted independently using Argon2id and AES-256-GCM. Output JSON filenames are opaque (`note_0001.json`, etc.). If original names are stored, menu 10 restores them; older or unnamed files are exported as `restored_0001.bin`, etc. These fallback names do not preserve extensions.

Existing output files are never overwritten. Duplicate restored names, wrong passwords, invalid notes, unsafe filenames, oversized files, and read/write errors fail that file while the batch continues. Files encrypted with different passwords must be retried separately with the appropriate password. The final summary reports successes, failures, skipped entries, and files not processed. Batch decrypt writes **unencrypted** data to the selected output folder, so choose a trusted private folder.

Press Esc or Ctrl+C during processing to stop after the current file completes. Completed outputs remain; unprocessed files are left alone. Folder contents are listed before output is written, so newly generated files do not get added to the current batch. The source files are never modified or deleted. Folder scanning is nonrecursive: use menu 10 on the specific generated batch subfolder rather than its parent `secret_notes/` folder.

## Cryptography and memory handling

| Component | Configuration |
| --- | --- |
| Encryption | AES-256-GCM, 16-byte authentication tag |
| Default key derivation | Argon2id v1.3, 64 MiB, 3 iterations, 1 lane |
| Alternative for text encryption | PBKDF2-HMAC-SHA256, 600,000 iterations |
| Derived key | 32 bytes |
| Salt | 16 random bytes per encryption |
| Nonce | 12 random bytes per encryption |
| Random source | Operating-system randomness via `getrandom` |

Argon2id and PBKDF2 derive encryption keys from passwords; AES-GCM performs authenticated encryption. File encryption and password changes always use Argon2id.

Passwords, plaintext, derived keys, decrypted buffers, and Argon2 working memory use `Zeroizing` guards, including error paths. Application-owned terminal input buffers grow by copying into a new guarded allocation and wiping the previous allocation; plaintext is not read through `stdin().read_line()`. Terminal libraries and the operating system can still hold their own copies. Derived keys are dropped after initializing the cipher. AES/GHASH zeroization features are enabled. Decrypted text borrows from its guarded byte buffer through `SecretText`, avoiding an extra plaintext string copy. Encryption reserves room for the authentication tag before copying plaintext.

This is an application-level memory cleanup strategy, not a guarantee that every copy of sensitive data is erased. It does not lock RAM or guarantee removal of OS swap, crash dumps, compiler temporaries, terminal buffers, clipboard contents, source files, or exported plaintext. Forced termination may bypass cleanup. Clearing the temporary result screen cannot erase screenshots or terminal recording logs.

Encrypted data can be attacked offline by someone who obtains it. Use strong, unique passwords and retain backups and passwords separately. Lost passwords cannot be recovered by the application. This project does not claim independent security auditing or certification.

## JSON note format

A saved note contains ciphertext and descriptive format metadata:

```json
{
  "schema": "seedcrypt-note",
  "schema_version": 1,
  "payload_version": 1,
  "cipher": "AES-256-GCM",
  "encoding": "base64",
  "kdf": {
    "name": "Argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "key_bytes": 32
  },
  "ciphertext": "<Base64-encoded encrypted payload>"
}
```

The example uses a placeholder, not valid ciphertext. Named files use `payload_version: 2`. JSON never intentionally stores plaintext, passwords, plaintext previews, or password verification hashes. Filenames you choose for JSON notes are visible on disk; avoid sensitive names.

External JSON metadata is descriptive and is not authenticated. The reader validates the schema, schema version, encoding, and ciphertext structure; algorithm selection comes from the authenticated payload header rather than the external `kdf` fields.

JSON reads are limited to **16 MiB**. The **8 MiB** file input limit leaves room for Base64 expansion and metadata. File operations load content into RAM; streaming encryption is not implemented. Shared limits in `src/limits.rs` cap encryption input, Base64 decoding and note storage. A successfully saved note fits within the JSON read limit, including maximum-size named files.

## Payload format and compatibility

Standard Base64 wraps this binary payload:

```text
SEEDCRYPT | version | KDF ID | salt | nonce | ciphertext | authentication tag
 9 bytes    1 byte   1 byte   16 B   12 B      variable          16 B
```

The magic, version, and KDF ID are authenticated as AES-GCM additional data.

| Field | Values |
| --- | --- |
| Payload version `0x01` | Raw content: UTF-8 text or arbitrary file bytes |
| Payload version `0x02` | File container with an encrypted original filename |
| KDF ID `0x01` | PBKDF2-HMAC-SHA256 |
| KDF ID `0x02` | Argon2id |

Version 2 encrypts `filename_length_u16_le | UTF-8 basename | original file bytes`. Versions 1 and 2 use the KDF parameters listed above. Future parameter changes must not silently reinterpret these versions.

Decryption also accepts the original headerless PBKDF2 format:

```text
salt (16 B) | nonce (12 B) | ciphertext | authentication tag (16 B)
```

If new-format parsing or authentication fails, the application attempts authenticated legacy decryption. This preserves old ciphertext even if its random salt happens to match the new marker. Successful decryption still requires a valid GCM tag. The successful authentication path returns the payload type alongside its guarded plaintext. Text display, file export and password changes use that authenticated type rather than reinterpreting the input prefix. Older application versions cannot necessarily read newer versioned payloads, including named file containers.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --release
```

Tests cover independent compatibility vectors, both KDFs, authentication failures, malformed input, legacy marker collisions, plaintext buffer reuse, multiline input, JSON handling, safe filenames, binary file restoration, optional encrypted filenames, password rotation, and overwrite prevention.

Password masking, visible multiline input, legacy decryption, result-screen dismissal and menu exit have been exercised in an interactive Windows terminal with dummy data. Unit tests do not verify every terminal or drag-and-drop integration; check those in your target terminal. Windows and Unix/Android paths pass Clippy; Unix filesystem behavior has not been runtime-tested in this Windows workspace.

| Source | Responsibility |
| --- | --- |
| `src/main.rs` | Application entry point |
| `src/app.rs` | CLI menus, masked input, and user workflows |
| `src/batch.rs` | Nonrecursive batch planning, sequential processing, and per-file results |
| `src/cryphase.rs` | Key derivation, encryption, decryption, and payload compatibility |
| `src/notes.rs` | JSON note storage, validation, and file-path handling |
| `src/files.rs` | Binary input, encrypted filename containers, and plaintext export |
| `src/limits.rs` | Shared input, ciphertext, and JSON size limits |
| `src/secure_fs.rs` | Handle-based file access and link/reparse-point rejection |


### Filesystem hardening

On Windows, the application opens each ancestor with reparse-point processing disabled, checks its metadata through the handle, and holds handles that deny write/delete sharing while resolving and accessing the child. File handles also prevent concurrent replacement. On Unix, it walks directories using `openat` with `O_DIRECTORY` and `O_NOFOLLOW`, then opens the final basename relative to the pinned parent descriptor. New output files use exclusive creation. Incomplete writes trigger best-effort removal through the file handle on Windows or pinned parent on Unix.

Use a trusted working directory and appropriate folder permissions. These protections do not defend against administrators, malware already able to inspect the process, or an account that can read exported plaintext through inherited filesystem permissions. Removing an incomplete file is not secure disk erasure, and a crash or failed cleanup can leave partial output.


### Dependency advisory checks

The local audit tool can be installed inside the ignored build directory:

```sh
cargo install cargo-audit --locked --root target/audit-tools
```

On Windows, run:

```powershell
.\target\audit-tools\bin\cargo-audit.exe audit --db target/rustsec-db --file Cargo.lock
```

On Unix, run:

```sh
./target/audit-tools/bin/cargo-audit audit --db target/rustsec-db --file Cargo.lock
```

The security remediation run checked 78 locked dependencies against the RustSec database updated on 2026-11-21 and reported no known vulnerabilities or warnings. This is a point-in-time result, not a permanent guarantee; refresh the database and repeat the check when dependencies change.
