use crate::cryphase;
use crossterm::{
    cursor::MoveTo,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{
        Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode, is_raw_mode_enabled,
    },
};
use std::io::{self, IsTerminal, Write};
use zeroize::{Zeroize, Zeroizing};

struct PasswordTerminal {
    restore: bool,
}

impl Drop for PasswordTerminal {
    fn drop(&mut self) {
        if self.restore {
            let _ = disable_raw_mode();
        }
    }
}

fn password_prompt(prompt: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    secret_line(prompt, true, crate::limits::MAX_PASSWORD_BYTES)
}

fn secret_line(prompt: &str, masked: bool, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let restore = !is_raw_mode_enabled()?;
    enable_raw_mode()?;
    let terminal = PasswordTerminal { restore };
    let mut output = io::stdout();
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut password = Zeroizing::new(Vec::<u8>::with_capacity(128));
    let result = loop {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match key.code {
            KeyCode::Enter => {
                break Ok(password);
            }
            KeyCode::Esc => {
                break Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Input cancelled.",
                ));
            }
            KeyCode::Char('c' | 'C') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                break Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Input cancelled.",
                ));
            }
            KeyCode::Backspace => {
                if let Some((index, _)) = std::str::from_utf8(&password)
                    .expect("password contains valid UTF-8")
                    .char_indices()
                    .next_back()
                {
                    // Wipe removed UTF-8 bytes too, rather than leaving them after truncation.
                    password[index..].zeroize();
                    password.truncate(index);
                    write!(output, "\x08 \x08")?;
                }
            }
            KeyCode::Char(mut character)
                if !character.is_control()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if password.len() + character.len_utf8() > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Input exceeds the supported size limit. Operation cancelled.",
                    ));
                }
                // Grow into a guarded allocation so the previous allocation is wiped.
                if password.len() + character.len_utf8() > password.capacity() {
                    let mut larger = Zeroizing::new(Vec::with_capacity(password.capacity() * 2));
                    larger.extend_from_slice(&password);
                    password = larger;
                }
                let mut encoded = Zeroizing::new([0u8; 4]);
                password.extend_from_slice(character.encode_utf8(&mut *encoded).as_bytes());
                let rendered = if masked {
                    write!(output, "*")
                } else {
                    write!(output, "{character}")
                };
                character.zeroize();
                rendered?;
            }
            _ => {}
        }
        output.flush()?;
    };
    drop(terminal);
    writeln!(output)?;
    result
}

pub fn run() {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        eprintln!(
            "[error] An interactive terminal is required. Redirected input/output is not supported."
        );
        return;
    }
    loop {
        println!("\n  SEEDCRYPT  v{}", env!("CARGO_PKG_VERSION"));
        println!("  Private notes / Local encryption");
        println!("  ----------------------------------------");
        println!("  [1] Encrypt text");
        println!("  [2] Decrypt Base64 text");
        println!("  [4] Browse saved notes");
        println!("  [5] Open JSON file / Drag and drop");
        println!("  [6] Change password / Re-encrypt note");
        println!("  [7] Encrypt file / Drag and drop");
        println!("  [8] Decrypt file / Export original bytes");
        println!();
        println!("  [3] Exit");
        println!("  ----------------------------------------");
        let choice = match public_prompt("  Select an option: ") {
            Ok(choice) => choice,
            Err(error) => {
                eprintln!("[error] Could not read input: {error}");
                break;
            }
        };
        let choice = choice.trim();

        match choice {
            "1" => encrypt_menu(),
            "2" => decrypt_menu(),
            "4" => read_note_menu(),
            "5" => dropped_note_menu(),
            "6" => reencrypt_menu(),
            "7" => file_menu(true),
            "8" => file_menu(false),
            "3" => {
                println!("\nGoodbye.");
                break;
            }
            _ => println!("[error] Invalid selection. Choose one of the listed options."),
        }
    }
}

fn public_prompt(prompt: &str) -> io::Result<Zeroizing<String>> {
    let mut bytes = secret_line(prompt, false, crate::limits::MAX_BASE64_BYTES)?;
    // Move the allocation; all typed characters were encoded as UTF-8 by secret_line.
    Ok(Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes))
            .expect("terminal input contains valid UTF-8"),
    ))
}

fn input_prompt(prompt: &str) -> Zeroizing<String> {
    match public_prompt(prompt) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("[error] {error}");
            // Invalid sentinel prevents an input error selecting an empty-input default.
            Zeroizing::new("\0".to_string())
        }
    }
}

fn run_with_loading<F, R>(loading_message: &str, task: F) -> R
where
    F: FnOnce() -> R,
{
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    let running = AtomicBool::new(true);

    thread::scope(|s| {
        let msg = loading_message.to_string();
        let running_ref = &running;

        s.spawn(move || {
            let spinner_chars = ['|', '/', '-', '\\'];
            let mut i = 0;
            while running_ref.load(Ordering::SeqCst) {
                print!("\r{} {}", msg, spinner_chars[i]);
                io::stdout().flush().unwrap();
                i = (i + 1) % 4;
                thread::sleep(Duration::from_millis(100));
            }
            print!("\r{} \r", " ".repeat(msg.len() + 2));
            io::stdout().flush().unwrap();
        });

        let result = task();
        running.store(false, Ordering::SeqCst);
        result
    })
}

fn encrypt_menu() {
    section(
        "ENCRYPT TEXT",
        "Create an encrypted note. Confirm your password to continue.",
    );
    let password = match confirmed_password() {
        Ok(password) => password,
        Err(error) => {
            println!("[error] {error}");
            return;
        }
    };
    println!("  [1] Argon2id       Recommended / 64 MiB memory");
    println!("  [2] PBKDF2-SHA256  600,000 iterations");
    let selection = input_prompt("  Key derivation [1]: ");
    let kdf = match selection.trim() {
        "" | "1" => cryphase::Kdf::Argon2id,
        "2" => cryphase::Kdf::Pbkdf2,
        _ => {
            println!("[error] Invalid selection. Choose one of the listed options.");
            return;
        }
    };
    let text = match secret_input() {
        Ok(text) => text,
        Err(error) => {
            println!("[error] Could not read secret text: {error}");
            return;
        }
    };

    let result = run_with_loading("  Encrypting", || {
        cryphase::encrypt(
            std::str::from_utf8(&text).expect("valid UTF-8 input"),
            &password,
            kdf,
        )
    });
    drop(password);
    drop(text);

    match result {
        Ok(encrypted) => {
            println!("\n[ok] Encryption complete.\n\nCiphertext / Base64\n-------------------");
            println!("{}", encrypted);
            save_encrypted_menu(&encrypted, kdf);
        }
        Err(e) => println!("[error] Encryption failed: {}", e),
    }
}

fn save_encrypted_menu(encrypted: &str, kdf: cryphase::Kdf) {
    loop {
        println!("\n  [1] Save encrypted note as JSON");
        println!("  [2] Back to main menu");
        let choice = input_prompt("  Select [2]: ");
        match choice.trim() {
            "1" => {
                let name = input_prompt("  Filename (no folders; Enter to cancel): ");
                if name.trim().is_empty() {
                    continue;
                }
                match crate::notes::save(
                    std::path::Path::new("secret_notes"),
                    name.trim(),
                    encrypted,
                    kdf,
                ) {
                    Ok(path) => {
                        println!("[ok] Saved to {}", path.display());
                        return;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        println!("[error] File already exists. Choose a different name.");
                    }
                    Err(error) => println!("[error] Could not save note: {error}"),
                }
            }
            "" | "2" => return,
            _ => println!("[error] Invalid selection. Choose one of the listed options."),
        }
    }
}

fn decrypt_menu() {
    section("DECRYPT TEXT", "Paste your Base64 ciphertext below.");
    let encrypted_text = input_prompt("  Ciphertext / Base64: ");
    decrypt_text(encrypted_text.trim());
}

fn read_note_menu() {
    let directory = std::path::Path::new("secret_notes");
    let names = match crate::notes::list(directory) {
        Ok(names) => names,
        Err(error) => {
            println!("[error] Could not read notes folder: {error}");
            return;
        }
    };
    if names.is_empty() {
        println!("[info] No JSON notes found in secret_notes/.");
        return;
    }
    section("SAVED NOTES", "Location: secret_notes/");
    for (index, name) in names.iter().enumerate() {
        println!("  [{}] {}", index + 1, name);
    }
    let selection = input_prompt("  Note number (Enter to cancel): ");
    if selection.trim().is_empty() {
        return;
    }
    let selected = selection
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| names.get(index));
    let Some(name) = selected else {
        println!("[error] Invalid selection. Choose one of the listed options.");
        return;
    };
    match crate::notes::load(directory, name) {
        Ok(ciphertext) => decrypt_text(&ciphertext),
        Err(error) => println!("[error] Could not read note: {error}"),
    }
}

fn dropped_note_menu() {
    section(
        "OPEN JSON NOTE",
        "Open an encrypted note from your computer.",
    );
    println!(
        "\n  Drop one JSON note into the terminal, then press Enter.\n  You can also paste or type its path."
    );
    let input = input_prompt("  File path (Enter to cancel): ");
    if input.trim().is_empty() {
        return;
    }
    let result = crate::notes::dropped_path(&input).and_then(|path| crate::notes::load_path(&path));
    match result {
        Ok(ciphertext) => decrypt_text(&ciphertext),
        Err(error) => println!("[error] Could not open note: {error}"),
    }
}

fn section(title: &str, description: &str) {
    println!("\n  {title}");
    println!("  ----------------------------------------");
    println!("  {description}\n");
}

fn decrypt_text(encrypted_text: &str) {
    let password = match password_prompt("  Password: ") {
        Ok(password) => password,
        Err(error) => {
            println!("[error] Could not read password: {error}");
            return;
        }
    };

    let result = run_with_loading("  Decrypting", || {
        cryphase::decrypt(encrypted_text, &password)
    });
    drop(password);

    match result {
        Ok(decrypted) => {
            if let Err(error) = show_decrypted(decrypted) {
                println!("[error] Could not display or clear result: {error}");
            }
        }
        Err(e) => println!("[error] Decryption failed: {}", e),
    }
}

struct DecryptionScreen;

impl Drop for DecryptionScreen {
    fn drop(&mut self) {
        // Clear while still on the alternate screen, then restore the menu screen.
        let _ = execute!(io::stdout(), Clear(ClearType::All), MoveTo(0, 0));
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn show_decrypted(decrypted: cryphase::SecretText) -> io::Result<()> {
    let mut output = io::stdout();
    execute!(output, EnterAlternateScreen)?;
    let _screen = DecryptionScreen;
    execute!(output, Clear(ClearType::All), MoveTo(0, 0))?;
    writeln!(
        output,
        "DECRYPTED NOTE\n----------------------------------------\n"
    )?;
    // Render control characters safely so plaintext cannot inject terminal commands.
    for character in decrypted.as_str().chars() {
        if character.is_control() && character != '\n' {
            write!(output, "{}", character.escape_default())?;
        } else {
            write!(output, "{character}")?;
        }
    }
    // The terminal has the visible result; the plaintext buffer is no longer needed.
    drop(decrypted);
    writeln!(
        output,
        "\n\n----------------------------------------\nPress Enter to clear this result and return."
    )?;
    output.flush()?;
    let restore = !is_raw_mode_enabled()?;
    enable_raw_mode()?;
    let _terminal = PasswordTerminal { restore };
    loop {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc)
                || (matches!(key.code, KeyCode::Char('c' | 'C'))
                    && key.modifiers.contains(KeyModifiers::CONTROL))
            {
                return Ok(());
            }
        }
    }
}

fn confirmed_password() -> io::Result<Zeroizing<Vec<u8>>> {
    let password = password_prompt("  New password: ")?;
    if password.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password cannot be empty.",
        ));
    }
    let confirmation = password_prompt("  Confirm new password: ")?;
    let matches = password.as_slice() == confirmation.as_slice();
    drop(confirmation);
    if !matches {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match. Operation cancelled.",
        ));
    }
    Ok(password)
}

fn append_secret(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    if buffer.len() + bytes.len() > buffer.capacity() {
        let mut larger = Zeroizing::new(Vec::with_capacity(
            (buffer.len() + bytes.len()).max(buffer.capacity().saturating_mul(2)),
        ));
        larger.extend_from_slice(buffer);
        *buffer = larger;
    }
    buffer.extend_from_slice(bytes);
}

fn secret_input() -> io::Result<Zeroizing<Vec<u8>>> {
    println!("\n  [1] Single line / visible");
    println!("  [2] Multiple lines / visible");
    println!("  [3] Single line / masked");
    println!("  [4] Multiple lines / masked");
    let selection = input_prompt("  Input mode [1]: ");
    let (multiline, masked) = match selection.trim() {
        "" | "1" => (false, false),
        "2" => (true, false),
        "3" => (false, true),
        "4" => (true, true),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid input mode.",
            ));
        }
    };
    if multiline {
        println!("  Enter .end on its own line to finish. Use ..end for a literal .end line.");
        println!("  Lines are joined with LF; spaces and blank lines are preserved.");
    }
    let mut text = Zeroizing::new(Vec::with_capacity(128));
    let mut first = true;
    loop {
        let line = secret_line("  Secret text: ", masked, crate::limits::MAX_INPUT_BYTES)?;
        if finish_input_line(&mut text, &mut first, &line, multiline)? {
            break;
        }
    }
    Ok(text)
}

fn reencrypt_menu() {
    section(
        "CHANGE PASSWORD / RE-ENCRYPT NOTE",
        "The original file is preserved. Save the result under a new filename.",
    );
    println!("  Drop a JSON note here, or enter its path (for example secret_notes/note.json).");
    let input = input_prompt("  File path (Enter to cancel): ");
    if input.trim().is_empty() {
        return;
    }
    let ciphertext =
        match crate::notes::dropped_path(&input).and_then(|path| crate::notes::load_path(&path)) {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                println!("[error] Could not open note: {error}");
                return;
            }
        };
    let old_password = match password_prompt("  Current password: ") {
        Ok(password) => password,
        Err(error) => {
            println!("[error] {error}");
            return;
        }
    };
    let result = run_with_loading("  Authenticating note", || {
        cryphase::decrypt_authenticated(&ciphertext, &old_password)
    });
    drop(old_password);
    let plaintext = match result {
        Ok(plaintext) => plaintext,
        Err(error) => {
            println!("[error] {error}");
            return;
        }
    };
    let new_password = match confirmed_password() {
        Ok(password) => password,
        Err(error) => {
            println!("[error] {error}");
            return;
        }
    };
    println!("  The new note will use Argon2id (64 MiB, 3 iterations).");
    let result = run_with_loading("  Re-encrypting", || {
        if plaintext.kind == cryphase::PayloadKind::NamedFile {
            cryphase::encrypt_file_container(
                &plaintext.bytes,
                &new_password,
                cryphase::Kdf::Argon2id,
            )
        } else {
            cryphase::encrypt_bytes(&plaintext.bytes, &new_password, cryphase::Kdf::Argon2id)
        }
    });
    drop(plaintext);
    drop(new_password);
    match result {
        Ok(encrypted) => {
            println!("[ok] Re-encryption complete. Save the new note below.");
            println!("[info] The original note still accepts its original password.");
            save_encrypted_menu(&encrypted, cryphase::Kdf::Argon2id);
        }
        Err(error) => println!("[error] Re-encryption failed: {error}"),
    }
}

fn finish_input_line(
    text: &mut Zeroizing<Vec<u8>>,
    first: &mut bool,
    line: &[u8],
    multiline: bool,
) -> io::Result<bool> {
    if multiline && line == b".end" {
        return Ok(true);
    }
    let added = if multiline && line == b"..end" {
        4
    } else {
        line.len()
    };
    if text
        .len()
        .saturating_add(added)
        .saturating_add(usize::from(!*first))
        > crate::limits::MAX_INPUT_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Text exceeds the 8 MiB limit. Operation cancelled.",
        ));
    }
    if !*first {
        append_secret(text, b"\n");
    }
    append_secret(
        text,
        if multiline && line == b"..end" {
            b".end"
        } else {
            line
        },
    );
    *first = false;
    Ok(!multiline)
}

fn file_menu(encrypting: bool) {
    section(
        if encrypting {
            "ENCRYPT FILE"
        } else {
            "DECRYPT FILE"
        },
        if encrypting {
            "Encrypt any regular file up to 8 MiB. The source is preserved."
        } else {
            "Restore original bytes from an encrypted JSON note."
        },
    );
    println!("  Drag and drop one file, or paste its path.");
    let input = input_prompt("  File path (Enter to cancel): ");
    if input.trim().is_empty() {
        return;
    }
    let path = match crate::notes::dropped_path(&input) {
        Ok(path) => path,
        Err(error) => {
            println!("[error] {error}");
            return;
        }
    };
    if encrypting {
        let mut source = match crate::files::read_source(&path) {
            Ok(source) => source,
            Err(error) => {
                println!("[error] Could not read file: {error}");
                return;
            }
        };
        let remember = loop {
            let choice = input_prompt("  Remember original filename inside encryption? [y/N]: ");
            match choice.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => break true,
                "" | "n" | "no" => break false,
                _ => println!("[error] Enter y or n."),
            }
        };
        if remember {
            let packed = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Original filename is not valid UTF-8.",
                    )
                })
                .and_then(|name| crate::files::pack(&source, name));
            source = match packed {
                Ok(packed) => packed,
                Err(error) => {
                    println!("[error] Cannot store original filename: {error}");
                    println!("[info] Try again without remembering the original filename.");
                    return;
                }
            };
        }
        let password = match confirmed_password() {
            Ok(password) => password,
            Err(error) => {
                println!("[error] {error}");
                return;
            }
        };
        let result = run_with_loading("  Encrypting file", || {
            if remember {
                cryphase::encrypt_file_container(&source, &password, cryphase::Kdf::Argon2id)
            } else {
                cryphase::encrypt_bytes(&source, &password, cryphase::Kdf::Argon2id)
            }
        });
        drop(source);
        drop(password);
        match result {
            Ok(encrypted) => {
                println!("[ok] File encrypted with Argon2id and AES-256-GCM.");
                println!("[info] Save the encrypted JSON below. Restore it using menu 8.");
                save_encrypted_menu(&encrypted, cryphase::Kdf::Argon2id);
            }
            Err(error) => println!("[error] Encryption failed: {error}"),
        }
    } else {
        let ciphertext = match crate::notes::load_path(&path) {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                println!("[error] Could not read encrypted file: {error}");
                return;
            }
        };
        let password = match password_prompt("  Password: ") {
            Ok(password) => password,
            Err(error) => {
                println!("[error] {error}");
                return;
            }
        };
        let result = run_with_loading("  Decrypting file", || {
            cryphase::decrypt_authenticated(&ciphertext, &password)
        });
        drop(password);
        let plaintext = match result {
            Ok(plaintext) => plaintext,
            Err(error) => {
                println!("[error] {error}");
                return;
            }
        };
        let (original_name, file_bytes) = if plaintext.kind == cryphase::PayloadKind::NamedFile {
            match crate::files::unpack(&plaintext.bytes) {
                Ok((name, bytes)) => (Some(name), bytes),
                Err(error) => {
                    println!("[error] {error}");
                    return;
                }
            }
        } else {
            (None, plaintext.bytes.as_slice())
        };
        println!("[info] Export writes unencrypted data to decrypted_files/.");
        println!("  Type /cancel to cancel. Existing files are never overwritten.");
        loop {
            let name = if let Some(original_name) = original_name {
                input_prompt(&format!("  Output filename [{original_name}]: "))
            } else {
                input_prompt("  Output filename with extension (Enter to cancel): ")
            };
            if name.trim() == "/cancel" {
                return;
            }
            let selected_name = if name.trim().is_empty() {
                match original_name {
                    Some(name) => name,
                    None => return,
                }
            } else {
                name.trim()
            };
            match crate::files::export(
                std::path::Path::new("decrypted_files"),
                selected_name,
                file_bytes,
            ) {
                Ok(path) => {
                    drop(plaintext);
                    println!("[ok] Restored file: {}", path.display());
                    return;
                }
                Err(error) => println!("[error] Could not export file: {error}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiline_limit_includes_separator_and_does_not_append_partial_input() {
        let mut bytes = Zeroizing::new(vec![b'x'; crate::limits::MAX_INPUT_BYTES]);
        let mut first = false;
        assert!(finish_input_line(&mut bytes, &mut first, b"more", true).is_err());
        assert_eq!(bytes.len(), crate::limits::MAX_INPUT_BYTES);
        assert!(finish_input_line(&mut bytes, &mut first, b".end", true).unwrap());
    }

    #[test]
    fn multiline_preserves_spaces_blank_lines_and_escaped_terminator() {
        let mut text = Zeroizing::new(Vec::new());
        let mut first = true;
        for line in ["  first  ", "", "??", "..end", ""] {
            assert!(!finish_input_line(&mut text, &mut first, line.as_bytes(), true).unwrap());
        }
        assert!(finish_input_line(&mut text, &mut first, b".end", true).unwrap());
        assert_eq!(&*text, "  first  \n\n??\n.end\n".as_bytes());
        let mut single = Zeroizing::new(Vec::new());
        assert!(finish_input_line(&mut single, &mut true, b".end", false).unwrap());
        assert_eq!(&*single, b".end");
    }
}
