use std::io;

/// Policy for NEW passwords only. Legacy decryption never applies this policy.
pub fn validate_new(bytes: &[u8]) -> io::Result<()> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use a unique passphrase of at least 16 characters with at least 5 distinct non-space characters. Avoid common or repeated patterns.",
        )
    };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if bytes.len() > crate::limits::MAX_PASSWORD_BYTES || text.chars().count() < 16 {
        return Err(invalid());
    }
    // Avoid constructing lowercase/copy strings containing the password.
    let mut distinct = [None; 5];
    let mut count = 0;
    for c in text.chars().filter(|c| !c.is_whitespace()) {
        if !distinct[..count].contains(&Some(c)) {
            distinct[count] = Some(c);
            count += 1;
            if count == 5 {
                break;
            }
        }
    }
    // Explicitly wipe the small character sample too.
    use zeroize::Zeroize;
    distinct.zeroize();
    if count < 5 {
        return Err(invalid());
    }
    let common = [
        "passwordpassword",
        "1234567890123456",
        "qwertyuiopasdfgh",
        "correct horse battery staple",
    ];
    if common.iter().any(|value| text.eq_ignore_ascii_case(value)) {
        return Err(invalid());
    }
    // Reject a short byte pattern repeated to make an apparently long password.
    if (1..=8).any(|length| {
        bytes.len().is_multiple_of(length)
            && bytes.chunks(length).all(|chunk| chunk == &bytes[..length])
    }) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_weak_new_passwords_without_restricting_passphrase_character_classes() {
        for weak in [
            "a",
            "aaaaaaaaaaaaaaaa",
            "passwordpassword",
            "1234567890123456",
            "abcdefghabcdefgh",
            "                ",
        ] {
            assert!(validate_new(weak.as_bytes()).is_err());
        }
        assert!(validate_new(b"violet river lantern orbit").is_ok());
        assert!(validate_new("\u{1f331} cedar ocean sunrise trail".as_bytes()).is_ok());
    }
}
