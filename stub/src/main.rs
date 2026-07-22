mod handlers;
mod mapper;

use core::slice;
use std::arch::asm;
use std::cmp::max;
use std::error::Error;
use std::ffi::c_void;
use std::fs;
use std::process::ExitCode;
use std::{env, ptr};

use pe_parser::pe::parse_portable_executable;
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualAlloc,
    VirtualProtect,
};

use crate::handlers::page_fault::{
    BASE_KEY, PAYLOAD_END_ADDR, PAYLOAD_START_ADDR, page_fault_handler,
};
use crate::mapper::map_pe;
use debug::dprintln;
use kekkai::payload::PayloadInfo;
use proc_macros::xor_string;

fn run() -> Result<(), Box<dyn Error>> {
    // ─── Read Current Executable Headers ─────────────────────────────────
    let exe_path = env::current_exe()?;
    let exe_bytes = fs::read(&exe_path)?;

    // ─── Find The Last Section ───────────────────────────────────────────
    let stub_pe = parse_portable_executable(&exe_bytes)?;
    let mut highest_section_offset = 0_usize;

    for section in &stub_pe.section_table {
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

    // ─── Allocate Memory To Store Payload ────────────────────────────────
    let payload = &overlay[size_of::<PayloadInfo>()..];
    dprintln!("Payload size: {} (0x{:02X})", payload.len(), payload.len());

    let payload_alloc = unsafe {
        VirtualAlloc(
            ptr::null(),
            payload.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_NOACCESS,
        )
    };
    if payload_alloc.is_null() {
        return Err(xor_string!("Couldn't allocate memory region to store payload!").into());
    }

    let payload_base_addr = payload_alloc as usize;
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

    // We could have set the protection as READ/WRITE in the `region::alloc()`
    // call above, however, debuggers are keeping record of initial protection
    // of the allocated pages so we are setting it to READ/WRITE here instead.
    let mut old_protect: PAGE_PROTECTION_FLAGS = 0x00;
    if unsafe {
        VirtualProtect(
            payload_alloc,
            payload.len(),
            PAGE_READWRITE,
            &mut old_protect,
        )
    } == 0
    {
        return Err(
            xor_string!("Couldn't update protection level of allocated payload region!").into(),
        );
    }

    // ─── Copy Payload To Memory ──────────────────────────────────────────
    unsafe {
        ptr::copy_nonoverlapping::<u8>(
            payload.as_ptr(),
            payload_base_addr as *mut _,
            payload.len(),
        );
    }

    // Set protection back to NONE so page can be decrypted on page fault.
    if unsafe {
        VirtualProtect(
            payload_alloc,
            payload.len(),
            PAGE_NOACCESS,
            &mut old_protect,
        )
    } == 0
    {
        return Err(
            xor_string!("Couldn't update protection level of allocated payload region!").into(),
        );
    }

    // ─── Register VEH ────────────────────────────────────────────────────
    // VEH should be registered after payload is copied to memory. Because,
    // if a page fault occurs at the payload memory region before the payload
    // is copied, page fault handler will just decrypt empty memory.
    let handle = unsafe { AddVectoredExceptionHandler(1, Some(page_fault_handler)) };
    if handle.is_null() {
        return Err(xor_string!("Failed to register VEH!").into());
    }

    // ─── Override Image Base Address In PEB With Payload's ───────────────
    let teb_ptr = get_teb();

    unsafe {
        let peb_ptr = *((teb_ptr as usize + 0x60) as *const *mut c_void);

        if !peb_ptr.is_null() {
            let image_base_ptr = (peb_ptr as usize + 0x10) as *mut *mut c_void;
            *image_base_ptr = payload_base_addr as *mut c_void;
        } else {
            dprintln!("PEB pointer is null!");
        }
    }

    // ─── Map PE ──────────────────────────────────────────────────────────
    let entry_fn =
        map_pe(unsafe { slice::from_raw_parts(payload_base_addr as *const _, payload.len()) })?;
    entry_fn();

    // ─── End ─────────────────────────────────────────────────────────────
    Ok(())
}

fn get_teb() -> *const usize {
    let teb;

    unsafe {
        asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, pure, readonly)
        )
    }

    teb
}

/* -------------------------------------------------------------------------- */
/*                                    Main                                    */
/* -------------------------------------------------------------------------- */
fn main() -> ExitCode {
    if let Err(error) = run() {
        println!("Error: {}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
