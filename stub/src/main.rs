use pe_parser::pe::parse_portable_executable;
use std::cmp::max;
use std::env;
use std::error::Error;
use std::fs;
use std::process::ExitCode;

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

    // ─── Check Overlay ───────────────────────────────────────────────────
    if exe_bytes.len() <= highest_section_offset {
        return Err(xor_string!("No overlay found!").into());
    }

    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
