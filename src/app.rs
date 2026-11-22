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
use std::io::{self, Write};
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
                // Grow into a guarded allocation so the previous allocation is wiped.
                if password.len() + character.len_utf8() > password.capacity() {
                    let mut larger = Zeroizing::new(Vec::with_capacity(password.capacity() * 2));
                    larger.extend_from_slice(&password);
                    password = larger;
                }
                let mut encoded = Zeroizing::new([0u8; 4]);
                password.extend_from_slice(character.encode_utf8(&mut *encoded).as_bytes());
                character.zeroize();
                write!(output, "*")?;
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
    loop {
        println!("\n  SEEDCRYPT  v{}", env!("CARGO_PKG_VERSION"));
        println!("  Private notes / Local encryption");
        println!("  ----------------------------------------");
        println!("  [1] Encrypt text");
        println!("  [2] Decrypt Base64 text");
        println!("  [4] Browse saved notes");
        println!("  [5] Open JSON file / Drag and drop");
        println!();
        println!("  [3] Exit");
        println!("  ----------------------------------------");
        print!("  Select an option: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        match io::stdin().read_line(&mut choice) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                eprintln!("[error] Could not read input: {error}");
                break;
            }
        }
        let choice = choice.trim();

        match choice {
            "1" => encrypt_menu(),
            "2" => decrypt_menu(),
            "4" => read_note_menu(),
            "5" => dropped_note_menu(),
            "3" => {
                println!("\nGoodbye.");
                break;
            }
            _ => println!("[error] Invalid selection. Choose one of the listed options."),
        }
    }
}

fn input_prompt(prompt: &str) -> Zeroizing<String> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = Zeroizing::new(String::new());
    io::stdin().read_line(&mut input).unwrap();
    while input.ends_with(['\r', '\n']) {
        input.pop();
    }
    input
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
    let password = match password_prompt("  Password: ") {
        Ok(password) => password,
        Err(error) => {
            println!("[error] Could not read password: {error}");
            return;
        }
    };
    if password.is_empty() {
        println!("[error] Password cannot be empty.");
        return;
    }
    let confirmation = match password_prompt("  Confirm password: ") {
        Ok(password) => password,
        Err(error) => {
            println!("[error] Could not read confirmation: {error}");
            return;
        }
    };
    let matches = password.as_slice() == confirmation.as_slice();
    drop(confirmation);
    if !matches {
        println!("[error] Passwords do not match. Encryption cancelled.");
        return;
    }
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
    let text = input_prompt("  Secret text: ");

    let result = run_with_loading("  Encrypting", || cryphase::encrypt(&text, &password, kdf));
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
