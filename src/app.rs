use std::io::{self, Write};
use crate::cryphase;

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

fn input_prompt(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
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
    let password = input_prompt("Masukkan password: ");
    let text = input_prompt("Masukkan teks rahasia: ");

    let result = run_with_loading("Sedang mengenkripsi", || {
        cryphase::encrypt(&text, password.as_bytes())
    });

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
    let password = input_prompt("Masukkan password: ");
    let encrypted_text = input_prompt("Masukkan teks terenkripsi (Base64): ");

    let result = run_with_loading("Sedang mendekripsi", || {
        cryphase::decrypt(&encrypted_text, password.as_bytes())
    });

    match result {
        Ok(decrypted) => {
            println!("\nHasil Dekripsi:");
            println!("{}", decrypted);
        }
        Err(e) => println!("Gagal melakukan dekripsi: {:?}", e),
    }
}
