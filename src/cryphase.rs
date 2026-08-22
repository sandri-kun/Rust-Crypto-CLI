use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use getrandom::getrandom;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;

const ITERATIONS: u32 = 600_000;

// --- ENKRIPSI ---
pub fn encrypt(plain_text: &str, password: &[u8]) -> Result<String, String> {
    // 1. Buat Salt (16B) dan Nonce (12B) acak
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    getrandom(&mut salt).map_err(|e| format!("Random salt error: {}", e))?;
    getrandom(&mut nonce_bytes).map_err(|e| format!("Random nonce error: {}", e))?;

    // 2. Turunkan kunci dengan PBKDF2
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, &salt, ITERATIONS, &mut derived_key);

    // 3. Enkripsi AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|e| format!("Cipher init error: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plain_text.as_bytes())
        .map_err(|_| "Gagal melakukan enkripsi!".to_string())?;

    // Hapus kunci dari RAM!
    derived_key.zeroize();

    // 4. Gabungkan Payload: [Salt] + [Nonce] + [Ciphertext]
    let mut payload = Vec::with_capacity(16 + 12 + ciphertext.len());
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(payload))
}

// --- DEKRIPSI ---
pub fn decrypt(encrypted_base64: &str, password: &[u8]) -> Result<String, String> {
    let payload = BASE64
        .decode(encrypted_base64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    if payload.len() < 16 + 12 + 16 {
        return Err("Payload terenkripsi tidak valid!".to_string());
    }

    // Ekstrak Salt, Nonce, Ciphertext
    let salt = &payload[0..16];
    let nonce_bytes = &payload[16..28];
    let ciphertext = &payload[28..];

    // Turunkan kunci PBKDF2
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, &mut derived_key);

    // Dekripsi AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|e| format!("Cipher init error: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Dekripsi GAGAL! Password salah atau data dirusak.".to_string())?;

    // Hapus kunci dari RAM!
    derived_key.zeroize();

    String::from_utf8(decrypted_bytes).map_err(|e| format!("Invalid UTF-8: {}", e))
}