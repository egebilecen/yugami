#[cfg(debug_assertions)]
mod debug;

use argh::FromArgs;
use indicatif::{ProgressBar, ProgressStyle};
use std::error::Error;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use kekkai::crypto::xor_in_place;
use kekkai::random_u64;

const XOR_KEY: u64 = random_u64!();

#[derive(FromArgs, Debug)]
#[argh(description = "Kekkai (結界) - A lightweight, low-entropy binary packer.")]
struct CliArgs {
    #[argh(option, description = "path to the payload executable")]
    path: String,
}

fn run(args: CliArgs) -> Result<(), Box<dyn Error>> {
    // ─── Spinner Setup ───────────────────────────────────────────────────
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.green} {msg}")?,
    );
    spinner.enable_steady_tick(Duration::from_millis(80));

    // ─── Load The Payload ────────────────────────────────────────────────
    spinner.set_message("Reading the payload executable...");
    let path = Path::new(&args.path);

    if !path.exists() {
        return Err(format!("No such file found in given path: {}", args.path).into());
    }

    let mut file_data = std::fs::read(&args.path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;

    // ─── Encrypt The Payload ─────────────────────────────────────────────
    spinner.set_message("Applying low-entropy XOR obfuscation...");
    xor_in_place(&mut file_data, &XOR_KEY.to_be_bytes());

    // ─── End ─────────────────────────────────────────────────────────────
    spinner.finish_with_message("Payload successfully obfuscated!");
    Ok(())
}

fn main() -> ExitCode {
    let args: CliArgs = argh::from_env();

    if let Err(error) = run(args) {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
