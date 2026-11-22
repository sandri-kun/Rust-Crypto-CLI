mod app;
mod batch;
mod cryphase;
mod files;
mod limits;
mod notes;
mod password;
mod secure_fs;

fn main() -> std::process::ExitCode {
    use std::io::Write;
    std::panic::set_hook(Box::new(|_| {
        let _ = writeln!(
            std::io::stderr(),
            "[error] Internal failure. Sensitive values are not logged."
        );
    }));
    match std::panic::catch_unwind(app::run) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}
