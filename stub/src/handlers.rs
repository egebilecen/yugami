use core::slice;
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};

use debug::dprintln;
use region::Protection;
use windows_sys::Win32::{
    Foundation::EXCEPTION_ACCESS_VIOLATION,
    System::Diagnostics::Debug::{
        EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    },
};

use kekkai::crypto::{PAGE_SIZE, U8_32, decrypt_page, derive_page_key, encrypt_page};

pub(crate) static BASE_KEY: OnceLock<U8_32> = OnceLock::new();
pub(crate) static PAYLOAD_START_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PAYLOAD_END_ADDR: OnceLock<usize> = OnceLock::new();
static DECRYPTED_PAGES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

// Temporary shadowing to disable debug logs.
macro_rules! dprintln {
    ($($tt:tt)*) => {};
}

pub(crate) unsafe extern "system" fn page_fault_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    // ─── Variables ───────────────────────────────────────────────────────
    let mut decrpyted_pages = match DECRYPTED_PAGES
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
    {
        Ok(data) => data,
        Err(err) => err.into_inner(),
    };
    let base_key = if let Some(key) = BASE_KEY.get() {
        key
    } else {
        dprintln!("Base key is not set! Skipping page fault handler...");
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let (payload_start_addr, payload_end_addr) = if let Some(start_addr) = PAYLOAD_START_ADDR.get()
        && let Some(end_addr) = PAYLOAD_END_ADDR.get()
    {
        (start_addr.to_owned(), end_addr.to_owned())
    } else {
        dprintln!("Payload start or end address is not set! Skipping page fault handler...");
        return EXCEPTION_CONTINUE_SEARCH;
    };
    let exception_record = unsafe { exception_info.read().ExceptionRecord.read() };
    let exception_location = exception_record.ExceptionAddress as usize;
    let exception_fault_addr = exception_record.ExceptionInformation[1];

    dprintln!(">>> Exception handler invoked! <<<");
    dprintln!(
        "Exception code: 0x{:02X}",
        exception_record.ExceptionCode as usize
    );
    dprintln!("Exception location: 0x{:02X}", exception_location);
    dprintln!("Payload start address: 0x{:02X}", payload_start_addr);
    dprintln!("Payload end address: 0x{:02X}", payload_end_addr);

    // ─── Handle Exception ────────────────────────────────────────────────
    match exception_record.ExceptionCode {
        EXCEPTION_ACCESS_VIOLATION => {
            dprintln!("Exception data address: 0x{:02X}", exception_fault_addr);

            // ─── Check If Exception Occured In Payload Memory Region ─────────────
            if exception_fault_addr < payload_start_addr || exception_fault_addr > payload_end_addr
            {
                dprintln!("Page fault didn't occur in payload memory region. Skipping...");
                return EXCEPTION_CONTINUE_SEARCH;
            }

            let page_addr = exception_fault_addr & !(PAGE_SIZE - 1);
            let page_index = (page_addr - payload_start_addr) / PAGE_SIZE;
            let mut page_key: U8_32 = [0u8; 32];

            dprintln!("Page index: {}", page_index);
            dprintln!("Page addr: 0x{:02X}", page_addr);

            if decrpyted_pages.contains(&page_index) {
                dprintln!("Faulting page is already decrypted. Skipping...");
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // ─── Encrypt Previous Pages ──────────────────────────
            decrpyted_pages.retain(|i| {
                dprintln!("Re-encrypting page at index {}...", i);

                let prev_page_addr = payload_start_addr + (i * PAGE_SIZE);
                derive_page_key(base_key, *i, &mut page_key);
                dprintln!("Derived key to re-encrypt page...");

                unsafe {
                    if let Err(_) = region::protect::<u8>(
                        prev_page_addr as *const _,
                        PAGE_SIZE,
                        Protection::READ_WRITE,
                    ) {
                        dprintln!("Failed to update memory protection for previous page! (1)");
                        return true;
                    }

                    encrypt_page(
                        slice::from_raw_parts_mut::<u8>(prev_page_addr as *mut _, PAGE_SIZE)
                            .try_into()
                            .unwrap(),
                        &page_key,
                    );

                    if let Err(_) =
                        region::protect::<u8>(prev_page_addr as *mut _, PAGE_SIZE, Protection::NONE)
                    {
                        dprintln!("Failed to update memory protection for previous page! (2)");
                    }
                }

                dprintln!("Re-encrypted page at index {}.", i);
                false
            });

            // ─── Decrypt Current Page ────────────────────────────
            unsafe {
                dprintln!(
                    "Updating protection level of page at index {} to READ/WRITE.",
                    page_index
                );

                if let Err(_) =
                    region::protect::<u8>(page_addr as *const _, PAGE_SIZE, Protection::READ_WRITE)
                {
                    dprintln!("Failed to update memory protection on faulting page!");
                    return EXCEPTION_CONTINUE_SEARCH;
                }
            }

            derive_page_key(base_key, page_index, &mut page_key);
            dprintln!(
                "Derived page key: {}",
                page_key.map(|b| format!("{:02X}", b)).join(" ")
            );

            unsafe {
                decrypt_page(
                    slice::from_raw_parts_mut::<u8>(page_addr as *mut _, PAGE_SIZE)
                        .try_into()
                        .unwrap(),
                    &page_key,
                );
            }

            unsafe {
                dprintln!(
                    "Updating protection level of page at index {} to READ/EXECUTE.",
                    page_index
                );

                if let Err(_) = region::protect::<u8>(
                    page_addr as *const _,
                    PAGE_SIZE,
                    Protection::READ_EXECUTE,
                ) {
                    dprintln!("Failed to update memory protection on faulting page!");
                    return EXCEPTION_CONTINUE_SEARCH;
                }
            }

            decrpyted_pages.insert(page_index);

            dprintln!("Continuing execution...");
            EXCEPTION_CONTINUE_EXECUTION
        }
        _ => EXCEPTION_CONTINUE_SEARCH,
    }
}
