use crate::{
    cryphase::{self, Kdf, PayloadKind},
    files, notes, secure_fs,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const MAX_FILES: usize = 1_000;

#[derive(Clone, Copy)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// Snapshot filenames before writing any output. Keep the source directory pinned.
pub struct Plan {
    pub files: Vec<PathBuf>,
    pub skipped: usize,
    mode: Mode,
    _source: secure_fs::SecureFile,
}

#[derive(Default)]
pub struct Summary {
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub cancelled: bool,
}

pub fn prepare(source: &Path, mode: Mode) -> io::Result<Plan> {
    let guard = secure_fs::open_directory(source)?;
    let mut paths = Vec::new();
    let mut skipped = 0;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if !kind.is_file()
            || kind.is_symlink()
            || (matches!(mode, Mode::Decrypt)
                && !entry
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json")))
        {
            skipped += 1;
            continue;
        }
        if paths.len() == MAX_FILES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "A batch supports at most 1,000 files. Split this folder into smaller batches.",
            ));
        }
        paths.push(entry.path());
    }
    paths.sort();
    Ok(Plan {
        files: paths,
        skipped,
        mode,
        _source: guard,
    })
}

fn process_one(
    source: &Path,
    index: usize,
    destination: &Path,
    password: &[u8],
    mode: Mode,
    remember_name: bool,
) -> io::Result<PathBuf> {
    match mode {
        Mode::Encrypt => {
            let mut bytes = files::read_source(source)?;
            let ciphertext = if remember_name {
                let name = source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Source filename is not valid UTF-8.",
                        )
                    })?;
                bytes = files::pack(&bytes, name)?;
                cryphase::encrypt_file_container(&bytes, password, Kdf::Argon2id)
            } else {
                cryphase::encrypt_bytes(&bytes, password, Kdf::Argon2id)
            }
            .map_err(io::Error::other)?;
            drop(bytes);
            // Opaque filenames do not disclose original names in the output directory.
            notes::save(
                destination,
                &format!("note_{:04}", index + 1),
                &ciphertext,
                Kdf::Argon2id,
            )
        }
        Mode::Decrypt => {
            let ciphertext = notes::load_path(source)?;
            let decrypted =
                cryphase::decrypt_authenticated(&ciphertext, password).map_err(io::Error::other)?;
            if decrypted.kind == PayloadKind::NamedFile {
                let (name, bytes) = files::unpack(&decrypted.bytes)?;
                files::export(destination, name, bytes)
            } else {
                files::export(
                    destination,
                    &format!("restored_{:04}.bin", index + 1),
                    &decrypted.bytes,
                )
            }
        }
    }
}

/// Runs sequentially. The callback returns false to stop after a completed file.
pub fn run(
    plan: &Plan,
    destination: &Path,
    password: &[u8],
    remember_name: bool,
    mut progress: impl FnMut(usize, &Path, &io::Result<PathBuf>) -> bool,
) -> Summary {
    let mut summary = Summary {
        skipped: plan.skipped,
        ..Summary::default()
    };
    for (index, source) in plan.files.iter().enumerate() {
        let result = process_one(
            source,
            index,
            destination,
            password,
            plan.mode,
            remember_name,
        );
        if result.is_ok() {
            summary.succeeded += 1;
        } else {
            summary.failed += 1;
        }
        if !progress(index, source, &result) {
            summary.cancelled = index + 1 < plan.files.len();
            break;
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_roundtrip_continues_after_failure_and_never_overwrites() {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("seedcrypt-batch-{:x}", u128::from_le_bytes(id)));
        let source = root.join("source");
        let encrypted = root.join("encrypted");
        let restored = root.join("restored");
        fs::create_dir_all(source.join("subfolder")).unwrap();
        fs::write(source.join("a.bin"), [0, 255, 0, 1]).unwrap();
        fs::write(source.join("empty.txt"), []).unwrap();
        let plan = prepare(&source, Mode::Encrypt).unwrap();
        assert_eq!(plan.skipped, 1);
        let result = run(&plan, &encrypted, b"password", true, |_, _, _| true);
        assert_eq!((result.succeeded, result.failed), (2, 0));
        let first_ciphertext = notes::load(&encrypted, "note_0001").unwrap();
        assert_eq!(fs::read(source.join("a.bin")).unwrap(), [0, 255, 0, 1]);
        let repeat = run(&plan, &encrypted, b"password", true, |_, _, _| true);
        assert_eq!((repeat.succeeded, repeat.failed), (0, 2));
        assert_eq!(
            notes::load(&encrypted, "note_0001").unwrap(),
            first_ciphertext
        );
        fs::write(encrypted.join("broken.json"), b"invalid JSON").unwrap();
        let decode = prepare(&encrypted, Mode::Decrypt).unwrap();
        let wrong = run(&decode, &restored, b"wrong password", false, |_, _, _| true);
        assert_eq!((wrong.succeeded, wrong.failed), (0, 3));
        assert!(!restored.exists());
        let decoded = run(&decode, &restored, b"password", false, |_, _, _| true);
        assert_eq!((decoded.succeeded, decoded.failed), (2, 1));
        assert_eq!(fs::read(restored.join("a.bin")).unwrap(), [0, 255, 0, 1]);
        assert_eq!(fs::read(restored.join("empty.txt")).unwrap(), b"");
        let cancelled = run(
            &plan,
            &root.join("cancelled"),
            b"password",
            true,
            |_, _, _| false,
        );
        assert!(cancelled.cancelled);
        assert_eq!(cancelled.succeeded, 1);
        let fresh_ciphertext = notes::load(&root.join("cancelled"), "note_0001").unwrap();
        use base64::Engine;
        let first = base64::engine::general_purpose::STANDARD
            .decode(first_ciphertext)
            .unwrap();
        let fresh = base64::engine::general_purpose::STANDARD
            .decode(fresh_ciphertext)
            .unwrap();
        assert_ne!(&first[11..27], &fresh[11..27]);
        assert_ne!(&first[27..39], &fresh[27..39]);
        // Raw/older payloads receive safe fallback names rather than guessed extensions.
        let raw = root.join("raw");
        let raw_restored = root.join("raw-restored");
        assert_eq!(
            run(&plan, &raw, b"password", false, |_, _, _| true).succeeded,
            2
        );
        let raw_plan = prepare(&raw, Mode::Decrypt).unwrap();
        assert_eq!(
            run(&raw_plan, &raw_restored, b"password", false, |_, _, _| true).succeeded,
            2
        );
        assert_eq!(
            fs::read(raw_restored.join("restored_0001.bin")).unwrap(),
            [0, 255, 0, 1]
        );
        assert_eq!(
            fs::read(raw_restored.join("restored_0002.bin")).unwrap(),
            b""
        );
        drop(raw_plan);
        drop(decode);
        drop(plan);
        // Explicit, nonrecursive cleanup of this test's own generated paths only.
        for path in [
            source.join("a.bin"),
            source.join("empty.txt"),
            encrypted.join("note_0001.json"),
            encrypted.join("note_0002.json"),
            encrypted.join("broken.json"),
            restored.join("a.bin"),
            restored.join("empty.txt"),
            root.join("cancelled/note_0001.json"),
            raw.join("note_0001.json"),
            raw.join("note_0002.json"),
            raw_restored.join("restored_0001.bin"),
            raw_restored.join("restored_0002.bin"),
        ] {
            fs::remove_file(path).unwrap();
        }
        for path in [
            source.join("subfolder"),
            source,
            encrypted,
            restored,
            root.join("cancelled"),
            raw,
            raw_restored,
            root,
        ] {
            fs::remove_dir(path).unwrap();
        }
    }
}
