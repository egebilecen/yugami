use std::path::Path;
use std::process::ExitCode;
use std::slice;
use std::thread;
use std::time::Duration;
use std::{error::Error, fs};

use argh::FromArgs;
use indicatif::{ProgressBar, ProgressStyle};
use pe_parser::pe::parse_portable_executable;

use debug::dprintln;
use kekkai::random::get_random_bytes;
use kekkai::{crypto::encrypt_payload, payload::PayloadInfo};

#[derive(FromArgs, Debug)]
#[argh(description = "Kekkai (結界) - A binary packer.")]
struct CliArgs {
    #[argh(option, description = "path to the payload")]
    path: String,
}

const BANNER: &str = r#"
 ____  __.      __    __           .__ 
|    |/ _|____ |  | _|  | _______  |__|
|      <_/ __ \|  |/ /  |/ /\__  \ |  |
|    |  \  ___/|    <|    <  / __ \|  |
|____|__ \___  >__|_ \__|_ \(____  /__|
        \/   \/     \/    \/     \/       結界
"#;

fn run(args: CliArgs) -> Result<(), Box<dyn Error>> {
    // ─── Spinner Setup ───────────────────────────────────────────────────
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.green} {msg}")?,
    );
    spinner.enable_steady_tick(Duration::from_millis(80));
    let sleep_dur = Duration::from_millis(250);

    // ─── Locate The Stub ─────────────────────────────────────────────────
    spinner.set_message("Locating the stub...");

    let path_list = ["stub.exe", env!("STUB_PATH")];
    let stub_path = if let Some(path) = path_list.iter().find(|path| Path::new(path).exists()) {
        *path
    } else {
        return Err("Couldn't find the stub.".into());
    };
    let stub_path = Path::new(stub_path);

    thread::sleep(sleep_dur);

    // ─── Read The Stub ───────────────────────────────────────────────────
    spinner.set_message("Reading the stub...");
    let mut stub = fs::read(stub_path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;

    thread::sleep(sleep_dur);

    // ─── Read The Payload ────────────────────────────────────────────────
    spinner.set_message("Reading the payload...");
    let path = Path::new(&args.path);

    if !path.exists() {
        spinner.finish_and_clear();
        return Err(format!("No such file found in given path: {}", args.path).into());
    }

    let mut payload = fs::read(&args.path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;
    dprintln!("Payload size: {}", payload.len());

    // ─── Extract PE Information From Payload ─────────────────────────────
    let pe = parse_portable_executable(&payload)
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

    dprintln!("IAT RVA: {}", iat_rva);
    dprintln!("IAT size: {}", iat_size);

    thread::sleep(sleep_dur);

    // ─── Encrypt The Payload ─────────────────────────────────────────────
    spinner.set_message("Encrypting the payload...");

    let base_key = get_random_bytes(32);
    let base_key: &[u8; 32] = base_key
        .as_slice()
        .try_into()
        .map_err(|_| "Couldn't convert key vector to slice.".to_string())?;
    dprintln!(
        "Generated random base key: {}",
        base_key.map(|b| format!("{:02X}", b)).join(" ")
    );

    let prev_payload_size = payload.len();
    encrypt_payload(&mut payload, base_key);
    dprintln!(
        "Payload is padded by {} bytes.",
        payload.len() - prev_payload_size
    );

    thread::sleep(sleep_dur);

    // ─── Add Payload As Overlay To Stub ──────────────────────────────────
    spinner.set_message("Appending target payload as PE overlay...");

    let payload_info = PayloadInfo::new(base_key.to_owned(), iat_rva, iat_size);
    let payload_info_bytes = unsafe {
        slice::from_raw_parts(
            &payload_info as *const PayloadInfo as *const u8,
            size_of::<PayloadInfo>(),
        )
    };

    dprintln!("Payload info size: {}", payload_info_bytes.len());
    dprintln!(
        "Total overlay size: {}",
        payload_info_bytes.len() + payload.len()
    );

    stub.extend_from_slice(payload_info_bytes);
    stub.extend_from_slice(&payload);

    thread::sleep(sleep_dur);

    // ─── Write The Packed Payload Into A File ────────────────────────────
    fs::write("packed.exe", stub)
        .map_err(|err| format!("Couldn't write packed payload into a file: {}", err).to_string())?;

    // ─── End ─────────────────────────────────────────────────────────────
    spinner.finish_with_message("Successfully packed the payload!");
    Ok(())
}

fn main() -> ExitCode {
    println!("{}", BANNER);
    let args: CliArgs = argh::from_env();

    if let Err(error) = run(args) {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
