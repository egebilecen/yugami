mod handlers;
mod resolvers;

use core::slice;
use std::cmp::max;
use std::error::Error;
use std::fs;
use std::process::ExitCode;
use std::{env, ptr};

use pe_parser::pe::parse_portable_executable;
use pe_parser::section::SectionFlags;
use region::Protection;
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, IMAGE_TLS_DIRECTORY64, PIMAGE_TLS_CALLBACK,
};

use crate::handlers::{
    BASE_KEY, PAGE_PROTECTIONS, PAYLOAD_END_ADDR, PAYLOAD_START_ADDR, PROTECTION_OVERRIDE,
    page_fault_handler,
};
use crate::resolvers::import_dir::resolve_imports;
use crate::resolvers::reloc::resolve_relocations;
use debug::dprintln;
use kekkai::crypto::PAGE_SIZE;
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

    // ─── Copy Payload To Memory ──────────────────────────────────────────
    let payload = &overlay[size_of::<PayloadInfo>()..];
    dprintln!("Payload size: {} (0x{:02X})", payload.len(), payload.len());

    let payload_alloc = region::alloc(payload.len(), Protection::NONE).map_err(|_| {
        xor_string!("Couldn't allocate memory region to store payload!").to_string()
    })?;
    let payload_base_addr = payload_alloc.as_ptr::<u8>() as usize;

    // We could have set the protection as READ/WRITE in the `region::alloc()`
    // call above, however, debuggers are keeping record of initial protection
    // of the allocated pages so we are setting it to READ/WRITE here instead.
    unsafe {
        region::protect::<u8>(
            payload_base_addr as *mut _,
            payload.len(),
            Protection::READ_WRITE,
        )
        .map_err(|_| {
            xor_string!("Couldn't update protection level of allocated payload region!").to_string()
        })?
    }

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
    // VEH should be registered after payload is copied to memory. Because,
    // if a page fault occurs at the payload memory region before the payload
    // is copied, page fault handler will just decrypt empty memory.
    let handle = unsafe { AddVectoredExceptionHandler(1, Some(page_fault_handler)) };
    if handle.is_null() {
        return Err(xor_string!("Failed to register VEH!").into());
    }

    let payload_pe = parse_portable_executable(unsafe {
        slice::from_raw_parts(payload_base_addr as *const u8, payload.len())
    })
    .map_err(|err| {
        let mut temp = xor_string!("Couldn't parse the payload PE: ");
        temp += err.to_string().as_str();
        temp
    })?;

    // ─── Resolve IAT ─────────────────────────────────────────────────────
    dprintln!("Resolving IAT...");

    unsafe {
        region::protect::<u8>(payload_base_addr as *mut _, payload.len(), Protection::NONE)
            .map_err(|_| {
                xor_string!("Couldn't update protection level of allocated payload region!")
                    .to_string()
            })?
    }

    let (preferred_image_base, entry_point_rva, import_table_rva, import_table_size, tls_table_rva) =
        if let Some(opt_header) = payload_pe.optional_header_64 {
            let _iat = opt_header.data_directories.import_address_table;
            dprintln!(
                "Entry point RVA: 0x{:02X} ({})",
                opt_header.address_of_entry_point,
                opt_header.address_of_entry_point
            );
            dprintln!(
                "IAT RVA: 0x{:02X} ({})",
                opt_header
                    .data_directories
                    .import_address_table
                    .virtual_address,
                opt_header
                    .data_directories
                    .import_address_table
                    .virtual_address
            );
            dprintln!(
                "IAT size: {} (0x{:02X})",
                opt_header.data_directories.import_address_table.size,
                opt_header.data_directories.import_address_table.size
            );

            (
                opt_header.image_base,
                opt_header.address_of_entry_point,
                opt_header.data_directories.import_table.virtual_address,
                opt_header.data_directories.import_table.size,
                opt_header.data_directories.tls_table.virtual_address,
            )
        } else if payload_pe.optional_header_32.is_some() {
            return Err(xor_string!("32-bit payload is not supported!").into());
        } else {
            return Err(xor_string!("Couldn't find optional header in the payload PE!").into());
        };

    if let Err(err) = resolve_imports(payload_base_addr, import_table_rva, import_table_size) {
        let mut temp = xor_string!("An error occurred while resolving imports: ");
        temp += err.as_str();

        return Err(temp.into());
    }

    // ─── Resolve Relocations ─────────────────────────────────────────────
    if let Some(reloc_section) = payload_pe.section_table.iter().find(|e| {
        e.get_name().unwrap_or("".to_string()).trim_matches('\0') == xor_string!(".reloc")
    }) {
        if let Err(err) = resolve_relocations(
            payload_base_addr,
            preferred_image_base as usize,
            reloc_section,
        ) {
            let mut temp = xor_string!("An error occurred while resolving relocations: ");
            temp += err.as_str();

            return Err(temp.into());
        }
    } else {
        dprintln!("No relocation section found. Skipping resolving relocations...");
    }

    // ─── Handle TLS Callbacks ────────────────────────────────────────────
    dprintln!("Handling TLS callbacks...");
    dprintln!("TLS table RVA: 0x{:02X}", tls_table_rva);

    let tls_dir =
        unsafe { &*((payload_base_addr + tls_table_rva as usize) as *const IMAGE_TLS_DIRECTORY64) };
    let address_of_callbacks = tls_dir.AddressOfCallBacks;
    dprintln!("TLS callbacks address: 0x{:02X}", address_of_callbacks);

    if tls_dir.AddressOfCallBacks != 0 {
        let mut callback_ptr = address_of_callbacks as *const PIMAGE_TLS_CALLBACK;
        while let Some(callback) = unsafe { *callback_ptr } {
            dprintln!("Executing TLS callback at 0x{:02X}.", callback_ptr as usize);
            unsafe {
                callback(
                    payload_base_addr as *mut _,
                    DLL_PROCESS_ATTACH,
                    std::ptr::null_mut(),
                );
            }

            callback_ptr = unsafe { callback_ptr.add(1) }
        }
    }

    // TODO: Hook into thread creation.

    // ─── Save Section Protections ────────────────────────────────────────
    for section in payload_pe.section_table.iter() {
        let mut protection = Protection::NONE;

        if section.characteristics & SectionFlags::IMAGE_SCN_MEM_READ.bits() != 0 {
            protection |= Protection::READ;
        }

        if section.characteristics & SectionFlags::IMAGE_SCN_MEM_WRITE.bits() != 0 {
            protection |= Protection::WRITE;
        }

        if section.characteristics & SectionFlags::IMAGE_SCN_MEM_EXECUTE.bits() != 0 {
            protection |= Protection::EXECUTE;
        }

        let section_name = section_name_to_str(&section.name);
        let section_addr = payload_base_addr + section.virtual_address as usize;
        let section_page_index = section_addr.wrapping_sub(payload_base_addr) / PAGE_SIZE;

        dprintln!("Section name: {}", section_name);
        dprintln!("Section VA: 0x{:02X}", section_addr);
        dprintln!("Section page index: {}", section_page_index);
        dprintln!("Section protection: {}", protection);

        PAGE_PROTECTIONS
            .lock()?
            .insert(section_page_index, protection);
    }

    // ─── Run Payload ─────────────────────────────────────────────────────
    *PROTECTION_OVERRIDE.write()? = None;

    let payload_entry_point = payload_base_addr + entry_point_rva as usize;
    let payload_code: extern "C" fn() -> i32 = unsafe { std::mem::transmute(payload_entry_point) };

    payload_code();

    // ─── End ─────────────────────────────────────────────────────────────
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
    if let Err(error) = run() {
        println!("{}", error);
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
