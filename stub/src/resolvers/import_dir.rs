use std::ffi::CStr;

use windows_sys::Win32::System::SystemServices::IMAGE_IMPORT_DESCRIPTOR;

use debug::dprintln;
use proc_macros::xor_string;

pub(crate) fn resolve_imports(image_base_addr: usize, table_rva: u32, table_size: u32) {
    if table_rva == 0 || table_size == 0 {
        return;
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
        // Check if we are at last entry.
        unsafe {
            if entry.Anonymous.OriginalFirstThunk == 0 && entry.Name == 0 {
                break;
            }
        }

        // Invalid name pointer.
        if entry.Name == 0 {
            i += 1;
            continue;
        }

        let entry_name =
            unsafe { CStr::from_ptr((image_base_addr + entry.Name as usize) as *const i8) };

        dprintln!("[Import Directory Entry {}]", i);
        dprintln!(
            "ILT RVA: 0x{:02X} ({})",
            unsafe { entry.Anonymous.OriginalFirstThunk },
            unsafe { entry.Anonymous.OriginalFirstThunk }
        );
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
            entry_name
                .to_str()
                .unwrap_or(xor_string!("<error>").as_str())
        );
        dprintln!("IAT RVA: 0x{:02X} ({})", entry.FirstThunk, entry.FirstThunk);
        dprintln!("");

        i += 1;
    }
}
