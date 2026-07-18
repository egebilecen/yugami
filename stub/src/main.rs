use pe_parser::pe::parse_portable_executable;
use std::cmp::max;
use std::error::Error;
use std::fs;
use std::process::ExitCode;
use std::{env, ptr};

use debug::dprintln;
use kekkai::payload::PayloadInfo;
use proc_macros::xor_string;

fn run() -> Result<(), Box<dyn Error>> {
    // ─── Read Current Executable Headers ─────────────────────────────────
    let exe_path = env::current_exe()?;
    let exe_bytes = fs::read(&exe_path)?;

    // ─── Find The Last Section ───────────────────────────────────────────
    let pe = parse_portable_executable(&exe_bytes)?;
    let mut highest_section_offset = 0_usize;

    for section in pe.section_table {
        let section_end = section.pointer_to_raw_data + section.size_of_raw_data;
        highest_section_offset = max(section_end as usize, highest_section_offset);
    }

    // ─── Check And Read Overlay ──────────────────────────────────────────
    if exe_bytes.len() <= highest_section_offset {
        return Err(xor_string!("No overlay found!").into());
    }

    dprintln!("Overlay found in the stub, extracting...");
    let overlay = &exe_bytes[highest_section_offset..];

    if overlay.len() < size_of::<PayloadInfo>() {
        return Err(xor_string!(
            "The overlay is smaller than expected. Something might have gone wrong during the packing process."
        ).into());
    }

    let payload_info = unsafe { ptr::read(overlay.as_ptr() as *const PayloadInfo) };
    dprintln!("[Payload Info]");
    dprintln!(
        "Base key: {}",
        payload_info
            .base_key
            .map(|b| format!("{:02X}", b))
            .join(" ")
    );
    dprintln!("IAT RVA: {}", payload_info.iat_rva);
    dprintln!("IAT size: {}", payload_info.iat_size);

    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
