mod handlers;

use std::cmp::max;
use std::error::Error;
use std::fs;
use std::process::ExitCode;
use std::{env, ptr};

use pe_parser::pe::parse_portable_executable;
use region::Protection;
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

use crate::handlers::{BASE_KEY, PAYLOAD_END_ADDR, PAYLOAD_START_ADDR, page_fault_handler};
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

    dprintln!("Overlay found in stub, extracting...");
    let overlay = &exe_bytes[highest_section_offset..];

    if overlay.len() < size_of::<PayloadInfo>() {
        return Err(xor_string!(
            "The overlay is smaller than expected! Something might have gone wrong during packing process."
        ).into());
    }

    let payload_info = unsafe { ptr::read(overlay.as_ptr() as *const PayloadInfo) };
    BASE_KEY
        .set(payload_info.base_key)
        .map_err(|_| xor_string!("Couldn't set base key!").to_string())?;

    dprintln!("[Payload Info]");
    dprintln!(
        "Base key: {}",
        payload_info
            .base_key
            .map(|b| format!("{:02X}", b))
            .join(" ")
    );
    dprintln!("Entry point RVA: 0x{:02X}", payload_info.entry_point_rva);
    dprintln!("IAT RVA: {}", payload_info.iat_rva);
    dprintln!("IAT size: {}", payload_info.iat_size);

    // ─── Copy Payload To Memory ──────────────────────────────────────────
    let payload = &overlay[size_of::<PayloadInfo>()..];
    dprintln!("Payload size: {}", payload.len());

    let payload_alloc = region::alloc(payload.len(), Protection::READ_WRITE).map_err(|_| {
        xor_string!("Couldn't allocate memory region to store payload!").to_string()
    })?;
    let payload_base_addr = payload_alloc.as_ptr::<u8>() as usize;

    PAYLOAD_START_ADDR
        .set(payload_base_addr)
        .map_err(|_| xor_string!("Couldn't set payload start address!").to_string())?;
    PAYLOAD_END_ADDR
        .set(payload_base_addr + payload.len())
        .map_err(|_| xor_string!("Couldn't set payload end address!").to_string())?;

    dprintln!(
        "Memory allocated at 0x{:02X} to store payload.",
        payload_base_addr as usize
    );

    unsafe {
        ptr::copy_nonoverlapping::<u8>(
            payload.as_ptr(),
            payload_base_addr as *mut _,
            payload.len(),
        );

        region::protect::<u8>(payload_base_addr as *mut _, payload.len(), Protection::NONE)
            .map_err(|_| {
                xor_string!("Couldn't update protection level of allocated payload region!")
                    .to_string()
            })?
    }

    // ─── Register VEH ────────────────────────────────────────────────────
    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(page_fault_handler));
        if handle.is_null() {
            return Err(xor_string!("Failed to register VEH!").into());
        }
    }

    // ─── Run Payload ─────────────────────────────────────────────────────
    unsafe {
        let payload_entry_point = payload_base_addr + payload_info.entry_point_rva as usize;
        let payload_code: extern "C" fn() = std::mem::transmute(payload_entry_point);

        payload_code();
    }

    // ─── End ─────────────────────────────────────────────────────────────
    Ok(())
}

fn main() -> ExitCode {
    if let Err(error) = run() {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
