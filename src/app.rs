use crate::cryphase;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, is_raw_mode_enabled},
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

fn password_prompt(prompt: &str) -> io::Result<Zeroizing<String>> {
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
                let text = std::str::from_utf8(&password).expect("password contains valid UTF-8");
                break Ok(Zeroizing::new(text.to_owned()));
            }
            KeyCode::Esc => {
                break Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Input dibatalkan",
                ));
            }
            KeyCode::Char('c' | 'C') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                break Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Input dibatalkan",
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
        println!("\n=== SEEDCRYPT MENU ===");
        println!("1. Enkripsi Teks");
        println!("2. Dekripsi Teks");
        println!("3. Keluar");
        print!("Pilih menu (1/2/3): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => encrypt_menu(),
            "2" => decrypt_menu(),
            "3" => {
                println!("Keluar dari aplikasi...");
                break;
            }
            _ => println!("Pilihan tidak valid!"),
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
    println!("\n--- ENKRIPSI ---");
    let password = match password_prompt("Masukkan password: ") {
        Ok(password) => password,
        Err(error) => {
            println!("Gagal membaca password: {error}");
            return;
        }
    };
    println!("1. Argon2id (default, memori 64 MiB)");
    println!("2. PBKDF2-SHA256 (600.000 iterasi)");
    let selection = input_prompt("Pilih derivasi kunci (1/2, Enter = 1): ");
    let kdf = match selection.trim() {
        "" | "1" => cryphase::Kdf::Argon2id,
        "2" => cryphase::Kdf::Pbkdf2,
        _ => {
            println!("Pilihan tidak valid!");
            return;
        }
    };
    let text = input_prompt("Masukkan teks rahasia: ");

    let result = run_with_loading("Sedang mengenkripsi", || {
        cryphase::encrypt(&text, password.as_bytes(), kdf)
    });
    drop(password);
    drop(text);

    match result {
        Ok(encrypted) => {
            println!("\nHasil Enkripsi (Base64):");
            println!("{}", encrypted);
        }
        Err(e) => println!("Gagal melakukan enkripsi: {:?}", e),
    }
}

fn decrypt_menu() {
    println!("\n--- DEKRIPSI ---");
    let password = match password_prompt("Masukkan password: ") {
        Ok(password) => password,
        Err(error) => {
            println!("Gagal membaca password: {error}");
            return;
        }
    };
    let encrypted_text = input_prompt("Masukkan teks terenkripsi (Base64): ");

    let result = run_with_loading("Sedang mendekripsi", || {
        cryphase::decrypt(encrypted_text.trim(), password.as_bytes())
    });
    drop(password);

    match result {
        Ok(decrypted) => {
            println!("\nHasil Dekripsi:");
            println!("{}", decrypted.as_str());
        }
        Err(e) => println!("Gagal melakukan dekripsi: {:?}", e),
    }
}
