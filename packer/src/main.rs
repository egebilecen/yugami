#[cfg(debug_assertions)]
mod debug;
mod random;

use argh::FromArgs;
use indicatif::{ProgressBar, ProgressStyle};
use pe_parser::pe::parse_portable_executable;
use std::error::Error;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use kekkai::{crypto::encrypt_payload, payload::PayloadInfo};
use proc_macros::random_bytes;

#[derive(FromArgs, Debug)]
#[argh(description = "Kekkai (結界) - A binary packer.")]
struct CliArgs {
    #[argh(option, description = "path to the payload")]
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

    // ─── Generate Key ────────────────────────────────────────────────────
    let base_key = random_bytes!(32);

    // ─── Load The Payload ────────────────────────────────────────────────
    spinner.set_message("Reading the payload...");
    let path = Path::new(&args.path);

    if !path.exists() {
        return Err(format!("No such file found in given path: {}", args.path).into());
    }

    let mut file_data = std::fs::read(&args.path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;

    // ─── Extract Metadata ────────────────────────────────────────────────
    let pe = parse_portable_executable(&file_data)
        .map_err(|err| format!("Couldn't parse the PE file: {}", err))?;

    let (iat_rva, iat_size) = if let Some(opt_header) = pe.optional_header_64 {
        let iat = opt_header.data_directories.import_address_table;
        (iat.virtual_address, iat.size)
    } else if let Some(opt_header) = pe.optional_header_32 {
        let iat = opt_header.data_directories.import_address_table;
        (iat.virtual_address, iat.size)
    } else {
        return Err("Couldn't find IAT RVA.".into());
    };

    let payload_info = PayloadInfo::new(base_key, iat_rva as usize, (iat_rva + iat_size) as usize);

    // ─── Encrypt The Payload ─────────────────────────────────────────────
    spinner.set_message("Obfuscating the payload...");
    encrypt_payload(&mut file_data, &base_key);

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
