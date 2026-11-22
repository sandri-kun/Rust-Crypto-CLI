use crate::cryphase::Kdf;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub fn list(directory: &Path) -> io::Result<Vec<String>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && name.ends_with(".json")
            && json_filename(name).is_ok()
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

#[derive(serde::Deserialize)]
struct StoredNote {
    schema: String,
    schema_version: u32,
    encoding: String,
    ciphertext: String,
}

pub fn load(directory: &Path, name: &str) -> io::Result<String> {
    let path = directory.join(json_filename(name)?);
    load_path(&path)
}

/// Interpret one dropped path as data, never as a shell command.
pub fn dropped_path(input: &str) -> io::Result<PathBuf> {
    let input = input.trim();
    let path = if input.starts_with('"') || input.starts_with('\'') {
        let quote = input.as_bytes()[0] as char;
        input
            .strip_prefix(quote)
            .and_then(|s| s.strip_suffix(quote))
            .filter(|s| !s.contains(quote))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Enter one file path with matching quotes.",
                )
            })?
    } else {
        input
    };
    if path.is_empty() || path.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid file path.",
        ));
    }
    Ok(PathBuf::from(path))
}

pub fn load_path(path: &Path) -> io::Result<String> {
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Choose a .json note file.",
        ));
    }
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The note must be a regular file.",
        ));
    }
    // Bound reads even when a file grows after its metadata is inspected.
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "File exceeds the 16 MiB size limit.",
        ));
    }
    let note: StoredNote = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid note JSON."))?;
    if note.schema != "seedcrypt-note" || note.schema_version != 1 || note.encoding != "base64" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported note format.",
        ));
    }
    let decoded = BASE64.decode(&note.ciphertext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Ciphertext Invalid Base64 data.",
        )
    })?;
    if decoded.len() < 44 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Ciphertext is too short.",
        ));
    }
    // External algorithm metadata is descriptive only; decrypt authenticates the payload.
    Ok(note.ciphertext)
}

fn json_filename(name: &str) -> io::Result<String> {
    let stem = name.strip_suffix(".json").unwrap_or(name);
    // Restrict to a portable filename, never a path or Windows device name.
    let reserved = stem.split('.').next().unwrap_or("").to_ascii_uppercase();
    if stem.is_empty()
        || stem.len() > 100
        || !stem
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        || matches!(reserved.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (reserved.len() == 4
            && (reserved.starts_with("COM") || reserved.starts_with("LPT"))
            && matches!(reserved.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use 1-100 ASCII letters, digits, hyphens or underscores; no folders or reserved Windows device names.",
        ));
    }
    Ok(format!("{stem}.json"))
}

pub fn save(directory: &Path, name: &str, ciphertext: &str, kdf: Kdf) -> io::Result<PathBuf> {
    let filename = json_filename(name)?;
    // Only canonical Base64 and fixed metadata enter JSON, so no user text can inject fields.
    let bytes = BASE64.decode(ciphertext).map_err(io::Error::other)?;
    let id = kdf as u8;
    if !bytes.starts_with(b"SEEDCRYPT\x01")
        || bytes.get(10) != Some(&id)
        || bytes.len() < 55
        || BASE64.encode(&bytes) != ciphertext
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Ciphertext format does not match the selected algorithm.",
        ));
    }
    let kdf_json = match kdf {
        Kdf::Argon2id => {
            r#"{"name":"Argon2id","version":19,"memory_kib":65536,"iterations":3,"parallelism":1,"key_bytes":32}"#
        }
        Kdf::Pbkdf2 => r#"{"name":"PBKDF2-HMAC-SHA256","iterations":600000,"key_bytes":32}"#,
    };
    let json = format!(
        "{{\n  \"schema\": \"seedcrypt-note\",\n  \"schema_version\": 1,\n  \"payload_version\": 1,\n  \"cipher\": \"AES-256-GCM\",\n  \"encoding\": \"base64\",\n  \"kdf\": {kdf_json},\n  \"ciphertext\": \"{ciphertext}\"\n}}\n"
    );
    fs::create_dir_all(directory)?;
    let path = directory.join(filename);
    // Refuse overwrites, including existing symlinks, rather than silently losing a note.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    if let Err(error) = file
        .write_all(json.as_bytes())
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_paths_handle_spaces_and_quotes_without_shell_execution() {
        for input in [
            r#"C:\My Notes\catatan.json"#,
            r#" "C:\My Notes\catatan.json" "#,
            r#"'C:\My Notes\catatan.json'"#,
        ] {
            assert_eq!(
                dropped_path(input).unwrap(),
                PathBuf::from(r"C:\My Notes\catatan.json")
            );
        }
        for input in [
            "",
            "\"\"",
            "\"missing quote",
            "\"a.json\" \"b.json\"",
            "a\nb.json",
        ] {
            assert!(dropped_path(input).is_err());
        }
        assert!(load_path(Path::new("note.txt")).is_err());
        assert!(load_path(Path::new("missing-note.json")).is_err());
    }

    #[test]
    fn reject_paths_and_reserved_names() {
        for name in [
            "",
            "../secret",
            "a/b",
            "a\\b",
            "CON",
            "nul.json",
            "COM1",
            "a\"",
            "a.json.json",
        ] {
            assert!(json_filename(name).is_err(), "{name}");
        }
        assert_eq!(json_filename("catatan-01.json").unwrap(), "catatan-01.json");
    }

    #[test]
    fn save_ciphertext_without_overwriting() {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory =
            std::env::temp_dir().join(format!("seedcrypt-test-{:x}", u128::from_le_bytes(random)));
        let ciphertext =
            crate::cryphase::encrypt("private plaintext", b"private password", Kdf::Argon2id)
                .unwrap();
        let path = save(&directory, "note", &ciphertext, Kdf::Argon2id).unwrap();
        let json = fs::read_to_string(&path).unwrap();
        assert_eq!(list(&directory).unwrap(), vec!["note.json"]);
        let loaded = load(&directory, "note.json").unwrap();
        let external_path = directory.join("catatan dengan spasi.json");
        fs::copy(&path, &external_path).unwrap();
        assert_eq!(load_path(&external_path).unwrap(), ciphertext);
        fs::remove_file(external_path).unwrap();
        assert_eq!(loaded, ciphertext);
        assert_eq!(
            crate::cryphase::decrypt(&loaded, b"private password")
                .unwrap()
                .as_str(),
            "private plaintext"
        );
        assert!(crate::cryphase::decrypt(&loaded, b"wrong password").is_err());
        assert!(load(&directory, "../note").is_err());
        assert!(json.contains(&format!("\"ciphertext\": \"{ciphertext}\"")));
        assert!(!json.contains("private plaintext"));
        assert!(!json.contains("private password"));
        assert_eq!(
            save(&directory, "note", &ciphertext, Kdf::Argon2id)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), json);
        // Password rotation preserves the source and migrates a legacy note.
        let legacy = "AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKC9dXGW9MgtR/TgTT96LHt4EJwQCxqqBKwMSbHN+DLQrV1u7BLg==";
        let old_plaintext = crate::cryphase::decrypt(legacy, b"password").unwrap();
        let rotated =
            crate::cryphase::encrypt(old_plaintext.as_str(), b"new password", Kdf::Argon2id)
                .unwrap();
        drop(old_plaintext);
        let new_path = save(&directory, "rotated", &rotated, Kdf::Argon2id).unwrap();
        let new_ciphertext = load(&directory, "rotated").unwrap();
        assert_eq!(
            crate::cryphase::decrypt(&new_ciphertext, b"new password")
                .unwrap()
                .as_str(),
            "legacy compatibility"
        );
        assert!(crate::cryphase::decrypt(&new_ciphertext, b"password").is_err());
        assert!(crate::cryphase::decrypt(legacy, b"password").is_ok());
        assert_eq!(fs::read_to_string(&path).unwrap(), json);
        fs::remove_file(new_path).unwrap();
        assert!(save(&directory, "wrong", &ciphertext, Kdf::Pbkdf2).is_err());
        for invalid in [
            "not JSON".to_owned(),
            json.replace("\"schema_version\": 1", "\"schema_version\": 99"),
            json.replace(&ciphertext, "!invalid"),
            json.replace(
                "\"ciphertext\":",
                "\"ciphertext\": \"AAAA\", \"ciphertext\":",
            ),
        ] {
            fs::write(&path, invalid).unwrap();
            assert!(load(&directory, "note").is_err());
        }
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
