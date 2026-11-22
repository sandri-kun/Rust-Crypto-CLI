use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInOut, KeyInit},
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use getrandom::fill;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Valid UTF-8 backed by the original guarded decryption buffer.
/// Intentionally does not implement Clone, Debug, or Display.
pub struct SecretText(Zeroizing<Vec<u8>>);

impl SecretText {
    fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, String> {
        std::str::from_utf8(&bytes).map_err(|_| "Decrypted text is not valid UTF-8.")?;
        Ok(Self(bytes))
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("SecretText contains validated UTF-8")
    }
}

const ITERATIONS: u32 = 600_000;
const MAGIC: &[u8] = b"SEEDCRYPT";
const VERSION: u8 = 1;
const ARGON_MEMORY_KIB: u32 = 65_536;
const FAILURE: &str = "Decryption failed. Incorrect password or damaged data.";

#[derive(Clone, Copy)]
pub enum Kdf {
    Pbkdf2 = 1,
    Argon2id = 2,
}

fn derive_key(password: &[u8], salt: &[u8], kdf: Kdf) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut key = Zeroizing::new([0u8; 32]);
    match kdf {
        Kdf::Pbkdf2 => pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, &mut *key),
        Kdf::Argon2id => {
            // Parameters belong to format version 1; never change them in place.
            let params = Params::new(ARGON_MEMORY_KIB, 3, 1, Some(32))
                .map_err(|_| "Invalid Argon2 parameters.".to_string())?;
            let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into_with_memory(password, salt, &mut *key, &mut *memory)
                .map_err(|_| "Argon2 key derivation failed.".to_string())?;
        }
    }
    Ok(key)
}

pub fn encrypt(plain_text: &str, password: &[u8], kdf: Kdf) -> Result<String, String> {
    if password.is_empty() {
        return Err("[error] Password cannot be empty.".to_string());
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    fill(&mut salt).map_err(|e| format!("Random salt error: {e}"))?;
    fill(&mut nonce).map_err(|e| format!("Random nonce error: {e}"))?;
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(&[VERSION, kdf as u8]);
    let key = derive_key(password, &salt, kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "Cipher init error")?;
    drop(key);
    // Reserve the GCM tag before copying plaintext, avoiding sensitive reallocations.
    let mut ciphertext = Zeroizing::new(Vec::with_capacity(plain_text.len() + 16));
    ciphertext.extend_from_slice(plain_text.as_bytes());
    cipher
        .encrypt_in_place(&Nonce::from(nonce), &header, &mut *ciphertext)
        .map_err(|_| "Encryption failed.")?;
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(header))
}

fn decrypt_payload(
    payload: &[u8],
    password: &[u8],
    kdf: Kdf,
    aad: &[u8],
) -> Result<SecretText, String> {
    if payload.len() < 44 {
        return Err(FAILURE.to_string());
    }
    let key = derive_key(password, &payload[..16], kdf)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| FAILURE)?;
    drop(key);
    let mut plaintext = Zeroizing::new(payload[28..].to_vec());
    cipher
        .decrypt_in_place(
            &Nonce::try_from(&payload[16..28]).map_err(|_| FAILURE)?,
            aad,
            &mut *plaintext,
        )
        .map_err(|_| FAILURE.to_string())?;
    SecretText::from_bytes(plaintext)
}

pub fn decrypt(encrypted_base64: &str, password: &[u8]) -> Result<SecretText, String> {
    let payload = BASE64
        .decode(encrypted_base64)
        .map_err(|_| "Invalid Base64 data.")?;
    let header_len = MAGIC.len() + 2;
    if payload.starts_with(MAGIC) && payload.len() >= header_len {
        let kdf = match (payload[MAGIC.len()], payload[MAGIC.len() + 1]) {
            (VERSION, 1) => Some(Kdf::Pbkdf2),
            (VERSION, 2) => Some(Kdf::Argon2id),
            _ => None,
        };
        if let Some(kdf) = kdf
            && let Ok(text) = decrypt_payload(
                &payload[header_len..],
                password,
                kdf,
                &payload[..header_len],
            )
        {
            return Ok(text);
        }
    }
    // Legacy salts are arbitrary bytes, including possible matches with MAGIC.
    // A fallback can only succeed if the legacy GCM authentication tag verifies.
    decrypt_payload(&payload, password, Kdf::Pbkdf2, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_text_preserves_allocation_and_validates_utf8() {
        let bytes = Zeroizing::new("rahasia 🌱".as_bytes().to_vec());
        let original_pointer = bytes.as_ptr();
        let original_capacity = bytes.capacity();
        let text = SecretText::from_bytes(bytes).unwrap();
        assert_eq!(text.as_str(), "rahasia 🌱");
        assert_eq!(text.as_str().as_ptr(), original_pointer);
        assert_eq!(text.0.capacity(), original_capacity);
        assert!(SecretText::from_bytes(Zeroizing::new(vec![0xff])).is_err());
    }

    #[test]
    fn independent_compatibility_vectors() {
        // Generated independently with Python cryptography (AESGCM/Argon2id)
        // and hashlib.pbkdf2_hmac, salt 0..15, nonce 0..11, password "password".
        // Fixed vectors catch changes that a same-implementation roundtrip misses.
        let vectors = [
            (
                "AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKC9dXGW9MgtR/TgTT96LHt4EJwQCxqqBKwMSbHN+DLQrV1u7BLg==",
                "legacy compatibility",
            ),
            (
                "U0VFRENSWVBUAQIAAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcICQoLDoQcBoQobSEuxGz8NFn9i+hoSlb6s/o12Rb/ljICf8UTCM3B",
                "argon2 compatibility",
            ),
        ];
        for (ciphertext, expected) in vectors {
            assert_eq!(decrypt(ciphertext, b"password").unwrap().as_str(), expected);
        }
    }

    fn legacy(text: &[u8], salt: [u8; 16]) -> String {
        let key = derive_key(b"password", &salt, Kdf::Pbkdf2).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
        let nonce = [7u8; 12];
        let mut data = text.to_vec();
        cipher
            .encrypt_in_place(&Nonce::from(nonce), &[], &mut data)
            .unwrap();
        let mut payload = salt.to_vec();
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&data);
        BASE64.encode(payload)
    }

    #[test]
    fn both_kdfs_roundtrip_and_reject_tampering() {
        for kdf in [Kdf::Pbkdf2, Kdf::Argon2id] {
            for text in ["", "rahasia 🌱\nbaris dua"] {
                let encrypted = encrypt(text, b"password", kdf).unwrap();
                assert_eq!(decrypt(&encrypted, b"password").unwrap().as_str(), text);
            }
            let encrypted = encrypt("secret", b"password", kdf).unwrap();
            assert!(decrypt(&encrypted, b"wrong").is_err());
            let bytes = BASE64.decode(&encrypted).unwrap();
            for index in [
                0,
                MAGIC.len(),
                MAGIC.len() + 1,
                MAGIC.len() + 2,
                bytes.len() - 1,
            ] {
                let mut modified = bytes.clone();
                modified[index] ^= 1;
                assert!(decrypt(&BASE64.encode(modified), b"password").is_err());
            }
        }
    }

    #[test]
    fn legacy_including_marker_collision() {
        for id in [0, 1, 2, 255] {
            let mut salt = [0u8; 16];
            salt[..MAGIC.len()].copy_from_slice(MAGIC);
            salt[MAGIC.len()] = VERSION;
            salt[MAGIC.len() + 1] = id;
            assert_eq!(
                decrypt(&legacy(b"old secret", salt), b"password")
                    .unwrap()
                    .as_str(),
                "old secret"
            );
        }
        assert!(decrypt(&legacy(&[255], [0; 16]), b"password").is_err());
    }

    #[test]
    fn malformed_and_randomized() {
        for input in ["", "!", "AAAA"] {
            assert!(decrypt(input, b"password").is_err());
        }
        assert!(encrypt("secret", b"", Kdf::Argon2id).is_err());
        assert_ne!(
            encrypt("same", b"password", Kdf::Argon2id).unwrap(),
            encrypt("same", b"password", Kdf::Argon2id).unwrap()
        );
    }
}
