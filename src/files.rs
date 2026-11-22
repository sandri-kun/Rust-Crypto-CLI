use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

pub fn read_source(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Choose a regular file.",
        ));
    }
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File exceeds the 8 MiB limit.",
        ));
    }
    // Reserve once so reading sensitive content cannot leave old reallocations behind.
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_FILE_BYTES + 1));
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File exceeds the 8 MiB limit.",
        ));
    }
    Ok(bytes)
}

fn validate_name(name: &str) -> io::Result<()> {
    let base = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if name.is_empty()
        || name.len() > 120
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
        || matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use a filename with ASCII letters, digits, dots, hyphens or underscores; no folders or reserved device names.",
        ));
    }
    Ok(())
}

pub fn export(directory: &Path, name: &str, plaintext: &[u8]) -> io::Result<PathBuf> {
    validate_name(name)?;
    fs::create_dir_all(directory)?;
    let path = directory.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&path)?;
    if let Err(error) = output.write_all(plaintext).and_then(|()| output.sync_all()) {
        drop(output);
        // Best-effort removal of an incomplete plaintext file; this is not secure disk erasure.
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryphase::{self, Kdf};

    #[test]
    fn binary_file_roundtrip_and_no_overwrite() {
        let mut id = [0; 16];
        getrandom::fill(&mut id).unwrap();
        let dir =
            std::env::temp_dir().join(format!("seedcrypt-file-test-{:x}", u128::from_le_bytes(id)));
        fs::create_dir(&dir).unwrap();
        let original = dir.join("original.bin");
        let bytes: Vec<u8> = (0..=255).cycle().take(4096).collect();
        fs::write(&original, &bytes).unwrap();
        let source = read_source(&original).unwrap();
        let encrypted = cryphase::encrypt_bytes(&source, b"password", Kdf::Argon2id).unwrap();
        let note = crate::notes::save(&dir, "encrypted", &encrypted, Kdf::Argon2id).unwrap();
        let loaded = crate::notes::load_path(&note).unwrap();
        assert!(cryphase::decrypt_bytes(&loaded, b"wrong").is_err());
        assert!(cryphase::decrypt(&loaded, b"password").is_err());
        let decrypted = cryphase::decrypt_bytes(&loaded, b"password").unwrap();
        assert_eq!(&*decrypted, &bytes);
        let result = export(&dir, "restored.bin", &decrypted).unwrap();
        assert_eq!(fs::read(&result).unwrap(), bytes);
        assert_eq!(
            export(&dir, "restored.bin", b"overwrite")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&original).unwrap(), bytes);
        for name in ["../escape", "a/b", "C:\\file", "NUL.txt", ".", "name.", ""] {
            assert!(export(&dir, name, b"data").is_err());
        }
        let oversized = dir.join("oversized.bin");
        fs::File::create(&oversized)
            .unwrap()
            .set_len((MAX_FILE_BYTES + 1) as u64)
            .unwrap();
        assert!(read_source(&oversized).is_err());
        assert!(read_source(&dir).is_err());
        for path in [original, note, result, oversized] {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(dir).unwrap();
    }
}
