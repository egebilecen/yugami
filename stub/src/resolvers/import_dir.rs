use std::ffi::CStr;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

use debug::dprintln;
use proc_macros::xor_string;

pub(crate) fn resolve_imports(
    image_base_addr: usize,
    table_rva: u32,
    table_size: u32,
) -> Result<(), String> {
    if table_rva == 0 || table_size == 0 {
        return Ok(());
    }

    dprintln!("Resolving imports...");

    let mut i = 0;
    loop {
        let offset = i * size_of::<IMAGE_IMPORT_DESCRIPTOR>();
        if offset >= table_size as usize {
            break;
        }

        let entry = unsafe {
            &*((image_base_addr + table_rva as usize + offset) as *const IMAGE_IMPORT_DESCRIPTOR)
        };

        // PE spec: "The last entry is set to zero (NULL) to indicate the end of the table."
        // Check if we are at the last entry.
        unsafe {
            if entry.Anonymous.OriginalFirstThunk == 0 && entry.Name == 0 {
                break;
            }
        }

        // Invalid name pointer.
        if entry.Name == 0 {
            dprintln!("Invalid name pointer found...");
            i += 1;
            continue;
        }

        let _entry_name =
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
        dprintln!(
            "Name: {}",
            _entry_name
                .to_str()
                .unwrap_or(xor_string!("<error>").as_str())
        );

        let module_handle =
            unsafe { GetModuleHandleA((image_base_addr + entry.Name as usize) as *const _) };
        if module_handle.is_null() {
            return Err(xor_string!("Couldn't get module handle!"));
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

            // PE spec: "The last entry is set to zero (NULL) to indicate the end of the table."
            // Check if we are at the last entry.
            if elem_val == 0x00 {
                break;
            }

            // ─── Get Function Pointer ────────────────────────────
            let mut elem_name_ptr = 0_usize;
            let func_ptr = unsafe {
                GetProcAddress(
                    module_handle,
                    if (elem_val & 0x8000_0000_0000_0000) != 0 {
                        dprintln!("Detected ordinal import...");

                        // Ordinal Import
                        let ordinal_number = elem_val & 0xFFFF;
                        ordinal_number as usize
                    } else {
                        // Import by Name
                        let name_table_rva = elem_val & 0x7FFF_FFFF;
                        elem_name_ptr = image_base_addr + name_table_rva as usize + 2;
                        elem_name_ptr
                    } as *const _,
                )
            };

            let ordinal_func_name = xor_string!("<ord>");
            let func_name = if elem_name_ptr != 0 {
                unsafe {
                    CStr::from_ptr(elem_name_ptr as *const _)
                        .to_str()
                        .unwrap_or("<error>")
                }
            } else {
                ordinal_func_name.as_str()
            };
            let func_addr = if let Some(ptr) = func_ptr {
                ptr as usize
            } else {
                let mut temp = xor_string!("Couldn't get pointer for function: ");
                temp += func_name;

                return Err(temp);
            };

            dprintln!("Imported function: {} (0x{:02X})", func_name, func_addr);

            // ─── Write Function Pointer To IAT ───────────────────
            unsafe {
                *((image_base_addr + iat_rva as usize + (j * size_of::<usize>())) as *mut usize) =
                    func_addr;
            }

            j += 1;
        }

        i += 1;
        dprintln!("");
    }

    Ok(())
}
