use std::cmp::min;
use std::path::Path;
use std::process::ExitCode;
use std::slice;
use std::thread;
use std::time::Duration;
use std::{error::Error, fs};

use argh::FromArgs;
use indicatif::{ProgressBar, ProgressStyle};
use pe_parser::pe::parse_portable_executable;

use common::crypto::PAGE_SIZE;
use common::random::get_random_bytes;
use common::{crypto::encrypt_payload, payload::PayloadInfo};
use debug::dprintln;

#[derive(FromArgs, Debug)]
#[argh(description = "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")]
struct CliArgs {
    #[argh(option, description = "path to the payload")]
    path: String,
}

const BANNER: &str = r#"
 ____  __.      __    __           .__ 
|    |/ _|____ |  | _|  | _______  |__|
|      <_/ __ \|  |/ /  |/ /\__  \ |  |
|    |  \  ___/|    <|    <  / __ \|  |  結界 - A binary packer.
|____|__ \___  >__|_ \__|_ \(____  /__|
        \/   \/     \/    \/     \/    
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

    let raw_payload = fs::read(&args.path)
        .map_err(|err| format!("Couldn't read file `{}`: {}", args.path, err))?;
    dprintln!(
        "Raw payload size: {} (0x{:02X})",
        raw_payload.len(),
        raw_payload.len()
    );

    // ─── Extract PE Information From Payload ─────────────────────────────
    let pe = parse_portable_executable(&raw_payload)
        .map_err(|err| format!("Couldn't parse the PE headers of payload: {}", err))?;

    if pe.coff.machine != 0x8664 {
        return Err("Only x64 payloads are supported.".into());
    }

    let (_iat_rva, _iat_size, _entry_point_rva, image_size, header_size) =
        if let Some(opt_header) = pe.optional_header_64 {
            dprintln!(
                "TLS directory RVA: 0x{:02X}",
                opt_header.data_directories.tls_table.virtual_address
            );
            dprintln!(
                "TLS directory size: {} (0x{:02X})",
                opt_header.data_directories.tls_table.size,
                opt_header.data_directories.tls_table.size
            );

            let iat = opt_header.data_directories.import_address_table;
            (
                iat.virtual_address,
                iat.size,
                opt_header.address_of_entry_point,
                opt_header.size_of_image,
                opt_header.size_of_headers,
            )
        } else if pe.optional_header_32.is_some() {
            spinner.finish_and_clear();
            return Err("32-bit payloads are not supported.".into());
        } else {
            spinner.finish_and_clear();
            return Err("Couldn't find IAT RVA.".into());
        };

    dprintln!("Image size: {}", image_size);
    dprintln!("Header size: {}", header_size);
    dprintln!("Entry point RVA: 0x{:02X}", _entry_point_rva);
    dprintln!("IAT RVA: {}", _iat_rva);
    dprintln!("IAT size: {}", _iat_size);

    thread::sleep(sleep_dur);

    // ─── Map Payload Layout ──────────────────────────────────────────────
    // TODO: Move mapping payload layout process to stub. Create a new
    //       function like `map_exe()`, which would perform all steps
    //       taken in the stub.
    spinner.set_message("Mapping payload layout...");
    let mut mapped_payload = vec![0u8; image_size as usize];

    spinner.set_message("Mapping payload layout (header)...");
    mapped_payload[0..header_size as usize].copy_from_slice(&raw_payload[0..header_size as usize]);

    for section in pe.section_table {
        if section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0 {
            continue;
        }

        let section_name = section_name_to_str(&section.name);
        spinner.set_message(format!(
            "Mapping payload layout (section {})...",
            section_name
        ));

        dprintln!("Section name: {}", section_name);
        dprintln!(
            "Section file RVA: 0x{:02X} ({})",
            section.pointer_to_raw_data,
            section.pointer_to_raw_data
        );
        dprintln!(
            "Section file size: {} (0x{:02X})",
            section.size_of_raw_data,
            section.size_of_raw_data
        );
        dprintln!(
            "Section RVA: 0x{:02X} ({})",
            section.virtual_address,
            section.virtual_address
        );
        dprintln!(
            "Section virtual size: {} (0x{:02X})",
            section.virtual_size,
            section.virtual_size
        );

        let copy_len = min(
            section.virtual_size as usize,
            section.size_of_raw_data as usize,
        );

        let start_rva = section.virtual_address as usize;
        let end_rva = start_rva + copy_len;

        let start_file_offset = section.pointer_to_raw_data as usize;
        let end_file_offset = start_file_offset + copy_len;

        mapped_payload[start_rva..end_rva]
            .copy_from_slice(&raw_payload[start_file_offset..end_file_offset]);
    }

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

    let _prev_payload_size = mapped_payload.len();
    encrypt_payload(&mut mapped_payload, base_key);
    dprintln!(
        "Mapped payload is padded by {} bytes.",
        mapped_payload.len() - _prev_payload_size
    );
    dprintln!(
        "Total number of pages: {}",
        mapped_payload.len() / PAGE_SIZE
    );

    thread::sleep(sleep_dur);

    // ─── Add Payload As Overlay To Stub ──────────────────────────────────
    spinner.set_message("Appending target payload as PE overlay...");

    let payload_info = PayloadInfo::new(base_key.to_owned());
    let payload_info_bytes = unsafe {
        slice::from_raw_parts(
            &payload_info as *const PayloadInfo as *const u8,
            size_of::<PayloadInfo>(),
        )
    };

    dprintln!("Payload info size: {}", payload_info_bytes.len());
    dprintln!(
        "Total overlay size: {}",
        payload_info_bytes.len() + mapped_payload.len()
    );

    stub.extend_from_slice(payload_info_bytes);
    stub.extend_from_slice(&mapped_payload);

    thread::sleep(sleep_dur);

    // ─── Write The Packed Payload Into A File ────────────────────────────
    fs::write("packed.exe", stub)
        .map_err(|err| format!("Couldn't write packed payload into a file: {}", err).to_string())?;

    // ─── End ─────────────────────────────────────────────────────────────
    spinner.finish_with_message("Successfully packed the payload!");
    Ok(())
}

fn section_name_to_str(buf: &[u8; 8]) -> &str {
    std::str::from_utf8(match buf.iter().position(|b| *b == 0x00) {
        Some(i) => &buf[..i],
        None => buf,
    })
    .unwrap_or("<error>")
}

/* -------------------------------------------------------------------------- */
/*                                    Main                                    */
/* -------------------------------------------------------------------------- */
fn main() -> ExitCode {
    println!("{}", BANNER);
    let args: CliArgs = argh::from_env();

    if let Err(error) = run(args) {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
