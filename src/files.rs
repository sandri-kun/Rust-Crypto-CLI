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

pub fn validate_name(name: &str) -> io::Result<()> {
    let base = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    if name.is_empty()
        || name.len() > 240
        || name.starts_with('.')
        || name.ends_with('.')
        || name.ends_with(' ')
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '/' | '\\' | ':' | '"' | '<' | '>' | '|' | '?' | '*')
        })
        || matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use a filename up to 240 UTF-8 bytes; no paths, reserved device names, control characters or Windows-invalid characters.",
        ));
    }
    Ok(())
}

/// Version 2 authenticated file content: [name length: u16 LE][UTF-8 name][file bytes].
/// Called only when the authenticated ciphertext header selects a file container.
pub fn pack(bytes: &[u8], name: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    validate_name(name)?;
    let mut packed = Zeroizing::new(Vec::with_capacity(2 + name.len() + bytes.len()));
    packed.extend_from_slice(&(name.len() as u16).to_le_bytes());
    packed.extend_from_slice(name.as_bytes());
    packed.extend_from_slice(bytes);
    Ok(packed)
}

pub fn unpack(bytes: &[u8]) -> io::Result<(&str, &[u8])> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid encrypted file metadata.",
        )
    };
    let length = u16::from_le_bytes(
        bytes
            .get(..2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ) as usize;
    let name = std::str::from_utf8(bytes.get(2..2 + length).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    validate_name(name)?;
    Ok((name, &bytes[2 + length..]))
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
    fn encrypted_filename_roundtrip_and_password_rotation() {
        let file_bytes = b"\x00\xff\x01file contents";
        let packed = pack(file_bytes, "My document 01.pdf").unwrap();
        let encrypted =
            cryphase::encrypt_file_container(&packed, b"old password", Kdf::Argon2id).unwrap();
        assert!(cryphase::is_file_container(&encrypted));
        let plaintext = cryphase::decrypt_bytes(&encrypted, b"old password").unwrap();
        let (name, bytes) = unpack(&plaintext).unwrap();
        assert_eq!(name, "My document 01.pdf");
        assert_eq!(bytes, file_bytes);
        assert!(cryphase::decrypt_bytes(&encrypted, b"wrong").is_err());
        let rotated =
            cryphase::encrypt_file_container(&plaintext, b"new password", Kdf::Argon2id).unwrap();
        let restored = cryphase::decrypt_bytes(&rotated, b"new password").unwrap();
        assert_eq!(unpack(&restored).unwrap(), (name, file_bytes.as_slice()));
        assert!(cryphase::decrypt_bytes(&rotated, b"old password").is_err());
        let mut raw =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encrypted).unwrap();
        raw[9] = 1;
        let tampered = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
        assert!(cryphase::decrypt_bytes(&tampered, b"old password").is_err());
        // Arbitrary legacy bytes must never be mistaken for a new file container.
        let legacy = cryphase::encrypt_bytes(&packed, b"password", Kdf::Argon2id).unwrap();
        assert!(!cryphase::is_file_container(&legacy));
        assert_eq!(
            &*cryphase::decrypt_bytes(&legacy, b"password").unwrap(),
            &*packed
        );
        for malformed in [
            &b""[..],
            &b"\xff\xffshort"[..],
            &b"\x01\x00\xff"[..],
            &b"\x04\x00../x"[..],
        ] {
            assert!(unpack(malformed).is_err());
        }
        assert!(pack(b"", "CON .txt").is_err());
        let empty = pack(b"", "empty.txt").unwrap();
        assert_eq!(unpack(&empty).unwrap(), ("empty.txt", &b""[..]));
    }

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
        let named = pack(&bytes, "original.bin").unwrap();
        let named_encrypted =
            cryphase::encrypt_file_container(&named, b"password", Kdf::Argon2id).unwrap();
        let named_path =
            crate::notes::save(&dir, "named", &named_encrypted, Kdf::Argon2id).unwrap();
        assert_eq!(
            crate::notes::load_path(&named_path).unwrap(),
            named_encrypted
        );
        let named_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&named_path).unwrap()).unwrap();
        assert_eq!(named_json["payload_version"], 2);
        assert!(
            !fs::read_to_string(&named_path)
                .unwrap()
                .contains("original.bin")
        );
        fs::remove_file(named_path).unwrap();
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
