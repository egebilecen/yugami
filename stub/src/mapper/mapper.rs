use std::{error::Error, ffi::CStr};

use pe_parser::{pe::parse_portable_executable, section::SectionFlags};
use windows_sys::Win32::System::{
    LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
    Memory::{
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
        PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
    },
    SystemServices::{IMAGE_BASE_RELOCATION, IMAGE_IMPORT_DESCRIPTOR},
    WindowsProgramming::IMAGE_THUNK_DATA64,
};

use super::error::MapperError;
use crate::handlers::page_fault::PAGE_PROTECTIONS;
#[allow(unused_imports)]
use debug::dprintln;
use kekkai::crypto::PAGE_SIZE;

pub type EntryFn = extern "C" fn() -> i32;

// Temporary shadowing to disable debug logs.
macro_rules! dprintln {
    ($($tt:tt)*) => {};
}

pub fn map_pe(pe_bytes: &[u8]) -> Result<EntryFn, Box<dyn Error>> {
    let image_base_addr = pe_bytes.as_ptr() as usize;
    let pe = parse_portable_executable(pe_bytes)?;

    let (preferred_image_base, entry_point_rva, import_table_rva, reloc_table_rva) =
        if let Some(opt_header) = pe.optional_header_64 {
            (
                opt_header.image_base,
                opt_header.address_of_entry_point,
                opt_header.data_directories.import_table.virtual_address,
                opt_header
                    .data_directories
                    .base_relocation_table
                    .virtual_address,
            )
        } else {
            return Err(MapperError::InvalidArchitectureError.into());
        };

    dprintln!(
        "Entry point RVA: 0x{:02X} ({})",
        entry_point_rva,
        entry_point_rva
    );
    dprintln!(
        "Import table RVA: 0x{:02X} ({})",
        import_table_rva,
        import_table_rva
    );
    dprintln!(
        "Relocations table RVA: 0x{:02X} ({})",
        reloc_table_rva,
        reloc_table_rva
    );

    // ─── Save Section Protections ────────────────────────────────────────
    for section in pe.section_table.iter() {
        let mut r = false;
        let mut w = false;
        let mut x = false;

        if section.characteristics & SectionFlags::IMAGE_SCN_MEM_READ.bits() != 0 {
            r = true;
        }

        if section.characteristics & SectionFlags::IMAGE_SCN_MEM_WRITE.bits() != 0 {
            w = true;
        }

        if section.characteristics & SectionFlags::IMAGE_SCN_MEM_EXECUTE.bits() != 0 {
            x = true;
        }

        let _section_name = section_name_to_str(&section.name);
        let section_addr = image_base_addr + section.virtual_address as usize;
        let section_page_index = section_addr.wrapping_sub(image_base_addr) / PAGE_SIZE;

        dprintln!("Section name: {}", _section_name);
        dprintln!("Section VA: 0x{:02X}", section_addr);
        dprintln!("Section page index: {}", section_page_index);
        dprintln!(
            "Section protection: r: {}, w: {}, x: {}",
            r as u8,
            w as u8,
            x as u8
        );

        PAGE_PROTECTIONS
            .lock()?
            .insert(section_page_index, to_prot_flags(r, w, x));
    }

    // ─── Resolve IAT ─────────────────────────────────────────────────────
    resolve_imports(image_base_addr, import_table_rva)?;

    // ─── Resolve Relocations ─────────────────────────────────────────────
    resolve_relocations(
        image_base_addr,
        preferred_image_base as usize,
        reloc_table_rva,
    )?;

    // ─── Return Entry Point ──────────────────────────────────────────────
    let pe_entry_point = image_base_addr.wrapping_add(entry_point_rva as usize);
    let entry_fn: EntryFn = unsafe { std::mem::transmute(pe_entry_point) };

    Ok(entry_fn)
}

fn resolve_imports(image_base_addr: usize, table_rva: u32) -> Result<(), Box<dyn Error>> {
    if table_rva == 0 {
        return Ok(());
    }

    dprintln!("Resolving imports...");

    let mut i = 0;
    loop {
        let offset = i * size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        let entry = unsafe {
            &*((image_base_addr + table_rva as usize + offset) as *const IMAGE_IMPORT_DESCRIPTOR)
        };

        if unsafe { entry.Anonymous.OriginalFirstThunk } == 0 && entry.Name == 0 {
            break;
        }

        if entry.Name == 0 {
            i += 1;
            continue;
        }

        let entry_name =
            unsafe { CStr::from_ptr((image_base_addr + entry.Name as usize) as *const i8) };
        let ilt_rva = unsafe { entry.Anonymous.OriginalFirstThunk };
        let iat_rva = entry.FirstThunk;

        dprintln!("[Import Directory Entry {}]", i);
        dprintln!("ILT RVA: 0x{:02X} ({})", ilt_rva, ilt_rva);
        dprintln!("IAT RVA: 0x{:02X} ({})", iat_rva, iat_rva);
        dprintln!(
            "Time/Date Stamp: 0x{:02X} ({})",
            entry.TimeDateStamp,
            entry.TimeDateStamp
        );
        dprintln!(
            "Forwarder Chain: 0x{:02X} ({})",
            entry.ForwarderChain,
            entry.ForwarderChain
        );
        dprintln!("Name RVA: 0x{:02X} ({})", entry.Name, entry.Name);
        dprintln!("Name: {}", entry_name.to_string_lossy());

        let mut module_handle =
            unsafe { GetModuleHandleA((image_base_addr + entry.Name as usize) as *const u8) };

        if module_handle.is_null() {
            dprintln!("Couldn't get module handle! Trying to load library...");
            module_handle = unsafe { LoadLibraryA(entry_name.as_ptr() as *const u8) };

            if module_handle.is_null() {
                dprintln!("Couldn't load library: {}", entry_name.to_string_lossy());
                return Err(MapperError::ImportedModuleError.into());
            }
        }

        dprintln!("Module handle: 0x{:02X}", module_handle as usize);

        // ─── Iterate Through Import Lookup Table ─────────────────────
        let mut j = 0;

        loop {
            let elem = unsafe {
                &*((image_base_addr + ilt_rva as usize + (j * size_of::<IMAGE_THUNK_DATA64>()))
                    as *const IMAGE_THUNK_DATA64)
            };
            let elem_val = unsafe { elem.u1.Function };

            if elem_val == 0x00 {
                break;
            }

            // ─── Get Function Pointer ────────────────────────────
            let is_ordinal = (elem_val & 0x8000_0000_0000_0000) != 0;
            let func_name_ptr = if is_ordinal {
                // Ordinal Import
                dprintln!("Detected ordinal import...");
                let ordinal_number = elem_val & 0xFFFF;
                ordinal_number as usize
            } else {
                // Import by Name
                let name_table_rva = elem_val & 0x7FFF_FFFF;
                image_base_addr + name_table_rva as usize + 2
            } as *const u8;
            let func_ptr = unsafe { GetProcAddress(module_handle, func_name_ptr) };

            let func_addr = if let Some(ptr) = func_ptr {
                ptr as usize
            } else {
                return Err(MapperError::ImportedFunctionError.into());
            };

            dprintln!(
                "    Imported function: {} (0x{:02X})",
                if !is_ordinal {
                    unsafe { CStr::from_ptr(func_name_ptr as *const _).to_string_lossy() }
                } else {
                    "<ord>".into()
                },
                func_addr
            );

            // ─── Write Function Pointer To IAT ───────────────────
            unsafe {
                *((image_base_addr + iat_rva as usize + (j * size_of::<usize>())) as *mut usize) =
                    func_addr;
            }

            j += 1;
        }

        i += 1;
    }

    Ok(())
}

pub(crate) fn resolve_relocations(
    image_base_addr: usize,
    preferred_image_base: usize,
    reloc_table_rva: u32,
) -> Result<(), Box<dyn Error>> {
    dprintln!("Resolving relocations...");
    dprintln!("Relocations block start RVA: 0x{:02X}", reloc_table_rva);

    let mut block_offset = 0;

    loop {
        let reloc_block = unsafe {
            &*((image_base_addr + reloc_table_rva as usize + block_offset)
                as *const IMAGE_BASE_RELOCATION)
        };

        if reloc_block.VirtualAddress == 0 || reloc_block.SizeOfBlock == 0 {
            break;
        }

        dprintln!("Page RVA: 0x{:02X}", reloc_block.VirtualAddress);
        dprintln!(
            "Block size: {} (0x{:02X})",
            reloc_block.SizeOfBlock,
            reloc_block.SizeOfBlock
        );

        let total_reloc_entries = (reloc_block.SizeOfBlock as usize
            - size_of::<IMAGE_BASE_RELOCATION>())
            / size_of::<u16>();

        for i in 0..total_reloc_entries {
            let val = unsafe {
                *((reloc_block as *const _ as usize
                    + size_of::<IMAGE_BASE_RELOCATION>()
                    + (i * size_of::<u16>())) as *const u16)
            };

            let mask = 0b1111_0000_0000_0000;
            let reloc_type = ((val & mask) >> 12) as u8;
            let reloc_offset = val & !(mask);

            dprintln!("    [Relocation Entry {}]", i);
            dprintln!("    Relocation type: 0x{:02X} ({})", reloc_type, reloc_type);
            dprintln!(
                "    Relocation offset: 0x{:02X} ({})",
                reloc_offset,
                reloc_offset
            );

            if reloc_type != 10 {
                dprintln!("Skipping unsupported relocation type...");
                continue;
            }

            let delta = image_base_addr.wrapping_sub(preferred_image_base);
            let patch_target = (image_base_addr
                + reloc_block.VirtualAddress as usize
                + reloc_offset as usize) as *mut usize;

            unsafe {
                let curr_ptr = *patch_target;
                *patch_target = curr_ptr.wrapping_add(delta);
            }

            dprintln!("Resolved relocation.");
        }

        block_offset += reloc_block.SizeOfBlock as usize;
    }

    Ok(())
}

fn to_prot_flags(r: bool, w: bool, x: bool) -> PAGE_PROTECTION_FLAGS {
    match (r, w, x) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, false, true) => PAGE_EXECUTE,
        (true, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        (false, false, false) => PAGE_NOACCESS,
        (false, true, true) => PAGE_EXECUTE_READWRITE,
        (false, true, false) => PAGE_READWRITE,
    }
}

fn section_name_to_str(buf: &[u8; 8]) -> &str {
    std::str::from_utf8(match buf.iter().position(|b| *b == 0x00) {
        Some(i) => &buf[..i],
        None => buf,
    })
    .unwrap_or("<error>")
}
