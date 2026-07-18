mod handlers;

use core::slice;
use std::cmp::max;
use std::error::Error;
use std::fs;
use std::process::ExitCode;
use std::{env, ptr};

use pe_parser::pe::parse_portable_executable;
use region::Protection;
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

use crate::handlers::page_fault_handler;
use debug::dprintln;
use kekkai::crypto::{PAGE_SIZE, decrypt_page, derive_page_key};
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
            "The overlay is smaller than expected! Something might have gone wrong during the packing process."
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
    }

    unsafe {
        region::protect::<u8>(payload_base_addr as *mut _, payload.len(), Protection::NONE)
            .map_err(|_| {
                xor_string!("Couldn't update protection level of the allocated payload region!")
                    .to_string()
            })?
    };

    // ─── Register VEH ────────────────────────────────────────────────────
    unsafe {
        let handle = AddVectoredExceptionHandler(1, Some(page_fault_handler));
        if handle.is_null() {
            return Err(xor_string!("Failed to register VEH!").into());
        }
    }

    // ─── Run The Payload ─────────────────────────────────────────────────
    let payload_entry_point = payload_base_addr + payload_info.entry_point_rva as usize;
    let region_start_addr = payload_entry_point & !(PAGE_SIZE - 1);

    unsafe {
        dprintln!(
            "Updating the protection level of payload entry point (0x{:02X}) to READ/EXECUTE.",
            payload_entry_point
        );
        region::protect::<u8>(
            region_start_addr as *const _,
            PAGE_SIZE,
            Protection::READ_EXECUTE,
        )
        .map_err(|_| {
            xor_string!("Couldn't update protection level of a memory region!").to_string()
        })?;
    };

    // let mut page_key = [0u8; 32];
    // for i in 0..(payload.len() / PAGE_SIZE) {
    //     derive_page_key(&payload_info.base_key, i, &mut page_key);

    //     unsafe {
    //         let page_addr = payload_base_addr + (i * PAGE_SIZE);
    //         decrypt_page(
    //             slice::from_raw_parts_mut::<u8>(page_addr as *mut _, PAGE_SIZE)
    //                 .try_into()
    //                 .unwrap(),
    //             &page_key,
    //         );
    //     }
    // }

    unsafe {
        let func: extern "C" fn() = std::mem::transmute(payload_entry_point);
        func();
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
