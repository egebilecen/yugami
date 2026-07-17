#[cfg(debug_assertions)]
mod debug;
mod random;

use argh::FromArgs;
use indicatif::{ProgressBar, ProgressStyle};
use pe_parser::pe::parse_portable_executable;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use std::{error::Error, fs};

use crate::random::get_random_bytes;
use kekkai::{crypto::encrypt_payload, payload::PayloadInfo};

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

    // ─── Locate The Stub ─────────────────────────────────────────────────
    spinner.set_message("Locating the stub...");

    let path_list = ["stub.exe", env!("STUB_PATH")];
    let stub_path = if let Some(path) = path_list.iter().find(|path| Path::new(path).exists()) {
        *path
    } else {
        return Err("Couldn't find the stub.".into());
    };
    let stub_path = Path::new(stub_path);

    // ─── Read The Stub ───────────────────────────────────────────────────
    spinner.set_message("Reading the stub...");
    let mut stub_data = fs::read(stub_path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;

    // ─── Read The Payload ────────────────────────────────────────────────
    spinner.set_message("Reading the payload...");
    let path = Path::new(&args.path);

    if !path.exists() {
        spinner.finish_and_clear();
        return Err(format!("No such file found in given path: {}", args.path).into());
    }

    let mut file_data = fs::read(&args.path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;

    // ─── Extract PE Information From Payload ─────────────────────────────
    let pe = parse_portable_executable(&file_data)
        .map_err(|err| format!("Couldn't parse the PE file: {}", err))?;

    let (iat_rva, iat_size) = if let Some(opt_header) = pe.optional_header_64 {
        let iat = opt_header.data_directories.import_address_table;
        (iat.virtual_address, iat.size)
    } else if let Some(opt_header) = pe.optional_header_32 {
        let iat = opt_header.data_directories.import_address_table;
        (iat.virtual_address, iat.size)
    } else {
        spinner.finish_and_clear();
        return Err("Couldn't find IAT RVA.".into());
    };

    // ─── Generate Key And Create Payload Info ────────────────────────────
    let base_key = get_random_bytes(32);
    let base_key: &[u8; 32] = base_key
        .as_slice()
        .try_into()
        .map_err(|_| "Couldn't convert key vector to slice.".to_string())?;

    let payload_info = PayloadInfo::new(base_key, iat_rva as usize, (iat_rva + iat_size) as usize);

    // ─── Add Payload As Overlay To Stub ──────────────────────────────────
    spinner.set_message("Appending target payload ({} bytes) as PE overlay...");
    // TODO: Append `payload_info` after padding it to 128 bytes.
    stub_data.extend_from_slice(&file_data);

    // ─── Encrypt The Payload ─────────────────────────────────────────────
    spinner.set_message("Obfuscating the payload...");
    encrypt_payload(&mut file_data, base_key);

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
