use crate::{
    cryphase::{self, Kdf, PayloadKind},
    files, notes, secure_fs,
};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_FILES: usize = 1_000;
const MANIFEST: &str = "batch_manifest.json";

#[derive(Clone, Copy)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

pub struct Plan {
    pub files: Vec<PathBuf>,
    pub skipped: usize,
    pub has_manifest: bool,
    pub allow_legacy: bool,
    mode: Mode,
    source: PathBuf,
    _source: secure_fs::SecureFile,
}

#[derive(Default)]
pub struct Summary {
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub total: usize,
    pub cancelled: bool,
    pub verified: bool,
    pub error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    index: usize,
    filename: String,
    digest: [u8; 32],
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    version: u32,
    batch_id: [u8; 16],
    planned: usize,
    complete: bool,
    entries: Vec<Entry>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn digest(ciphertext: &str) -> [u8; 32] {
    Sha256::digest(ciphertext.as_bytes()).into()
}

pub fn prepare(source: &Path, mode: Mode) -> io::Result<Plan> {
    let guard = secure_fs::open_directory(source)?;
    let mut paths = Vec::new();
    let mut skipped = 0;
    let mut has_manifest = false;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if entry.file_name() == MANIFEST && matches!(mode, Mode::Decrypt) {
            if !kind.is_file() || kind.is_symlink() {
                return Err(invalid("The batch manifest must be a regular file."));
            }
            has_manifest = true;
            continue;
        }
        if !kind.is_file()
            || kind.is_symlink()
            || entry
                .file_name()
                .to_string_lossy()
                .starts_with(".seedcrypt-")
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
            return Err(invalid("A batch supports at most 1,000 files."));
        }
        paths.push(entry.path());
    }
    paths.sort();
    Ok(Plan {
        files: paths,
        skipped,
        has_manifest,
        allow_legacy: false,
        mode,
        source: source.to_owned(),
        _source: guard,
    })
}

fn verify_manifest(plan: &Plan, password: &[u8]) -> io::Result<Manifest> {
    let encoded = notes::load_path(&plan.source.join(MANIFEST))?;
    let decrypted =
        cryphase::decrypt_authenticated(&encoded, password).map_err(io::Error::other)?;
    if decrypted.kind != PayloadKind::BatchManifest {
        return Err(invalid(
            "The manifest has the wrong authenticated payload type.",
        ));
    }
    let manifest: Manifest =
        serde_json::from_slice(&decrypted.bytes).map_err(|_| invalid("Invalid batch manifest."))?;
    if manifest.schema != "seedcrypt-batch"
        || manifest.version != 1
        || manifest.planned > MAX_FILES
        || manifest.entries.len() != manifest.planned
        || !manifest.complete
    {
        return Err(invalid(
            "The batch is incomplete. Use individual recovery (menu 8) for remaining files.",
        ));
    }
    for (index, entry) in manifest.entries.iter().enumerate() {
        if entry.index != index || entry.filename != format!("note_{:04}.json", index + 1) {
            return Err(invalid("Invalid file identity in manifest."));
        }
        let ciphertext = notes::load_path(&plan.source.join(&entry.filename))?;
        if digest(&ciphertext) != entry.digest {
            return Err(invalid("A batch member was replaced or modified."));
        }
    }
    Ok(manifest)
}

fn process_one(
    source: &Path,
    index: usize,
    destination: &Path,
    password: &[u8],
    mode: (Mode, bool),
    manifest: &Manifest,
    verified: bool,
) -> io::Result<PathBuf> {
    let (mode, remember) = mode;
    match mode {
        Mode::Encrypt => {
            let mut content = files::read_source(source)?;
            if remember {
                let name = source
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| invalid("Invalid UTF-8 filename."))?;
                content = files::pack(&content, name)?;
            }
            let mut bound = Zeroizing::new(Vec::with_capacity(20 + content.len()));
            bound.extend_from_slice(&manifest.batch_id);
            bound.extend_from_slice(&(index as u32).to_le_bytes());
            bound.extend_from_slice(&content);
            drop(content);
            let ciphertext = cryphase::encrypt_batch_member(&bound, password, remember)
                .map_err(io::Error::other)?;
            drop(bound);
            notes::save(
                destination,
                &format!("note_{:04}", index + 1),
                &ciphertext,
                Kdf::Argon2id,
            )
        }
        Mode::Decrypt => {
            let ciphertext = notes::load_path(source)?;
            if verified && digest(&ciphertext) != manifest.entries[index].digest {
                return Err(invalid("Batch member changed after verification."));
            }
            let decrypted =
                cryphase::decrypt_authenticated(&ciphertext, password).map_err(io::Error::other)?;
            if verified {
                if !matches!(
                    decrypted.kind,
                    PayloadKind::BatchRaw | PayloadKind::BatchNamed
                ) || decrypted.bytes.get(..16) != Some(manifest.batch_id.as_slice())
                    || decrypted.bytes.get(16..20) != Some((index as u32).to_le_bytes().as_slice())
                {
                    return Err(invalid("Authenticated batch identity mismatch."));
                }
            } else if matches!(
                decrypted.kind,
                PayloadKind::BatchRaw | PayloadKind::BatchNamed | PayloadKind::BatchManifest
            ) {
                return Err(invalid(
                    "This member requires its authenticated batch manifest. Use menu 8 for individual recovery.",
                ));
            }
            let (name, bytes) = files::restore_parts(&decrypted)?;
            files::export(
                destination,
                name.unwrap_or(&format!("restored_{:04}.bin", index + 1)),
                bytes,
            )
        }
    }
}

pub fn run(
    plan: &Plan,
    destination: &Path,
    password: &[u8],
    remember: bool,
    mut progress: impl FnMut(usize, &Path, &io::Result<PathBuf>) -> bool,
) -> Summary {
    let mut summary = Summary {
        skipped: plan.skipped,
        total: plan.files.len(),
        ..Summary::default()
    };
    let mut manifest = Manifest {
        schema: "seedcrypt-batch".into(),
        version: 1,
        batch_id: [0; 16],
        planned: plan.files.len(),
        complete: false,
        entries: Vec::new(),
    };
    let effective;
    let paths = if matches!(plan.mode, Mode::Decrypt) && plan.has_manifest {
        match verify_manifest(plan, password) {
            Ok(verified) => {
                manifest = verified;
                summary.verified = true;
                summary.total = manifest.entries.len();
                summary.skipped += plan.files.len().saturating_sub(manifest.entries.len());
                effective = manifest
                    .entries
                    .iter()
                    .map(|e| plan.source.join(&e.filename))
                    .collect::<Vec<_>>();
                &effective
            }
            Err(error) => {
                summary.error = Some(format!("Batch verification failed before export: {error}"));
                return summary;
            }
        }
    } else {
        &plan.files
    };
    if matches!(plan.mode, Mode::Decrypt) && !plan.has_manifest && !plan.allow_legacy {
        summary.error =
            Some("No authenticated manifest. Explicit legacy-folder consent is required.".into());
        return summary;
    }
    if matches!(plan.mode, Mode::Encrypt) {
        match secure_fs::open_directory(destination)
            .and_then(|_guard| fs::read_dir(destination)?.next().transpose())
        {
            Ok(Some(_)) => {
                summary.error = Some("Choose a new or empty batch output folder.".into());
                return summary;
            }
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                summary.error = Some(error.to_string());
                return summary;
            }
        }
        if let Err(error) = getrandom::fill(&mut manifest.batch_id) {
            summary.error = Some(error.to_string());
            return summary;
        }
    }
    for (index, source) in paths.iter().enumerate() {
        let result = process_one(
            source,
            index,
            destination,
            password,
            (plan.mode, remember),
            &manifest,
            summary.verified,
        )
        .and_then(|path| {
            if matches!(plan.mode, Mode::Encrypt) {
                let ciphertext = notes::load_path(&path)?;
                manifest.entries.push(Entry {
                    index,
                    filename: format!("note_{:04}.json", index + 1),
                    digest: digest(&ciphertext),
                });
            }
            Ok(path)
        });
        if result.is_ok() {
            summary.succeeded += 1;
        } else {
            summary.failed += 1;
        }
        if !progress(index, source, &result) {
            summary.cancelled = index + 1 < paths.len();
            break;
        }
    }
    if matches!(plan.mode, Mode::Encrypt) {
        manifest.complete =
            !summary.cancelled && summary.failed == 0 && manifest.entries.len() == manifest.planned;
        let stored = (|| {
            let serialized =
                Zeroizing::new(serde_json::to_vec(&manifest).map_err(io::Error::other)?);
            let ciphertext = cryphase::encrypt_batch_manifest(&serialized, password)
                .map_err(io::Error::other)?;
            notes::save(destination, "batch_manifest", &ciphertext, Kdf::Argon2id)
        })();
        if let Err(error) = stored {
            summary.error = Some(format!(
                "Manifest could not be committed. Batch is not complete: {error}"
            ));
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_modified_manifest_and_members_fail_before_plaintext_export() {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("seedcrypt-manifest-{:x}", u128::from_le_bytes(id)));
        let source = root.join("source");
        let encrypted = root.join("encrypted");
        let output = root.join("recovered");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("one.txt"), b"one").unwrap();
        fs::write(source.join("two.txt"), b"two").unwrap();
        let plan = prepare(&source, Mode::Encrypt).unwrap();
        assert!(
            run(&plan, &encrypted, b"password", true, |_, _, _| true)
                .error
                .is_none()
        );
        drop(plan);
        let member_path = encrypted.join("note_0001.json");
        let original_member = fs::read(&member_path).unwrap();
        fs::remove_file(&member_path).unwrap();
        let plan = prepare(&encrypted, Mode::Decrypt).unwrap();
        let result = run(&plan, &output, b"password", false, |_, _, _| true);
        assert!(result.error.is_some());
        assert_eq!(result.succeeded, 0);
        assert!(!output.exists());
        drop(plan);
        fs::write(&member_path, &original_member).unwrap();
        // Replace a member by another valid ciphertext encrypted with the same password.
        fs::copy(encrypted.join("note_0002.json"), &member_path).unwrap();
        let plan = prepare(&encrypted, Mode::Decrypt).unwrap();
        assert!(
            run(&plan, &output, b"password", false, |_, _, _| true)
                .error
                .is_some()
        );
        assert!(!output.exists());
        drop(plan);
        fs::write(&member_path, &original_member).unwrap();
        let manifest_path = encrypted.join(MANIFEST);
        let original_manifest = fs::read(&manifest_path).unwrap();
        fs::write(&manifest_path, b"invalid JSON").unwrap();
        let plan = prepare(&encrypted, Mode::Decrypt).unwrap();
        assert!(
            run(&plan, &output, b"password", false, |_, _, _| true)
                .error
                .is_some()
        );
        assert!(!output.exists());
        drop(plan);
        fs::remove_file(&manifest_path).unwrap();
        let mut plan = prepare(&encrypted, Mode::Decrypt).unwrap();
        assert!(
            run(&plan, &output, b"password", false, |_, _, _| true)
                .error
                .is_some()
        );
        // Explicit legacy consent must not downgrade bound batch members to ordinary files.
        plan.allow_legacy = true;
        let result = run(&plan, &output, b"password", false, |_, _, _| true);
        assert_eq!((result.succeeded, result.failed), (0, 2));
        assert!(!output.exists());
        drop(plan);
        fs::write(&manifest_path, original_manifest).unwrap();
        let plan = prepare(&encrypted, Mode::Decrypt).unwrap();
        let result = run(&plan, &output, b"password", false, |_, _, _| true);
        assert!(result.verified);
        assert_eq!(result.succeeded, 2);
        drop(plan);
        for path in [
            source.join("one.txt"),
            source.join("two.txt"),
            encrypted.join("note_0001.json"),
            encrypted.join("note_0002.json"),
            manifest_path,
            output.join("one.txt"),
            output.join("two.txt"),
        ] {
            fs::remove_file(path).unwrap();
        }
        for path in [source, encrypted, output, root] {
            fs::remove_dir(path).unwrap();
        }
    }

    #[test]
    fn legacy_folders_require_consent_and_preserve_old_weak_password_compatibility() {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "seedcrypt-legacy-batch-{:x}",
            u128::from_le_bytes(id)
        ));
        let legacy = root.join("legacy");
        let output = root.join("output");
        let encrypted = cryphase::encrypt("old text", b"a", Kdf::Pbkdf2).unwrap();
        let path = notes::save(&legacy, "old", &encrypted, Kdf::Pbkdf2).unwrap();
        let mut plan = prepare(&legacy, Mode::Decrypt).unwrap();
        assert!(
            run(&plan, &output, b"a", false, |_, _, _| true)
                .error
                .is_some()
        );
        plan.allow_legacy = true;
        assert_eq!(
            run(&plan, &output, b"a", false, |_, _, _| true).succeeded,
            1
        );
        assert_eq!(
            fs::read(output.join("restored_0001.bin")).unwrap(),
            b"old text"
        );
        drop(plan);
        fs::remove_file(path).unwrap();
        fs::remove_file(output.join("restored_0001.bin")).unwrap();
        fs::remove_dir(legacy).unwrap();
        fs::remove_dir(output).unwrap();
        fs::remove_dir(root).unwrap();
    }

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
        assert!(repeat.error.is_some());
        assert_eq!((repeat.succeeded, repeat.failed), (0, 0));
        assert_eq!(
            notes::load(&encrypted, "note_0001").unwrap(),
            first_ciphertext
        );
        fs::write(encrypted.join("broken.json"), b"invalid JSON").unwrap();
        let decode = prepare(&encrypted, Mode::Decrypt).unwrap();
        let wrong = run(&decode, &restored, b"wrong password", false, |_, _, _| true);
        assert!(wrong.error.is_some());
        assert_eq!((wrong.succeeded, wrong.failed), (0, 0));
        assert!(!restored.exists());
        let decoded = run(&decode, &restored, b"password", false, |_, _, _| true);
        assert_eq!((decoded.succeeded, decoded.failed), (2, 0));
        assert_eq!(decoded.skipped, 1);
        assert!(decoded.verified);
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
        let incomplete = prepare(&root.join("cancelled"), Mode::Decrypt).unwrap();
        assert!(
            run(
                &incomplete,
                &root.join("incomplete-output"),
                b"password",
                false,
                |_, _, _| true
            )
            .error
            .is_some()
        );
        assert!(!root.join("incomplete-output").exists());
        drop(incomplete);
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
            encrypted.join(MANIFEST),
            root.join("cancelled").join(MANIFEST),
            raw.join(MANIFEST),
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
