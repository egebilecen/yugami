use core::slice;
use std::sync::{Mutex, OnceLock, RwLock};

use region::Protection;
use windows_sys::Win32::{
    Foundation::EXCEPTION_ACCESS_VIOLATION,
    System::Diagnostics::Debug::{
        EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    },
};

use debug::dprintln;
use kekkai::crypto::{PAGE_SIZE, U8_32, decrypt_page, derive_page_key, encrypt_page};
use proc_macros::xor_string;

pub(crate) static BASE_KEY: OnceLock<U8_32> = OnceLock::new();
pub(crate) static PAYLOAD_START_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PAYLOAD_END_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PROTECTION_OVERRIDE: RwLock<Option<Protection>> = RwLock::new(None);

const MAX_DECRYPTED_PAGES: usize = 2;
static DECRYPTED_PAGES: OnceLock<Mutex<Vec<usize>>> = OnceLock::new();

// Temporary shadowing to disable debug logs.
// macro_rules! dprintln {
//     ($($tt:tt)*) => {};
// }

#[inline]
fn _page_fault_handler(exception_info: *mut EXCEPTION_POINTERS) -> Result<i32, String> {
    dprintln!(">>> Exception handler invoked! <<<");

    // ─── Variables ───────────────────────────────────────────────────────
    let mut decrpyted_pages = match DECRYPTED_PAGES
        .get_or_init(|| Mutex::new(Vec::with_capacity(MAX_DECRYPTED_PAGES)))
        .lock()
    {
        Ok(data) => data,
        Err(err) => err.into_inner(),
    };
    let base_key = if let Some(key) = BASE_KEY.get() {
        key
    } else {
        dprintln!("Base key is not set! Skipping page fault handler...");
        return Ok(EXCEPTION_CONTINUE_SEARCH);
    };
    let (payload_start_addr, payload_end_addr) = if let Some(start_addr) = PAYLOAD_START_ADDR.get()
        && let Some(end_addr) = PAYLOAD_END_ADDR.get()
    {
        (start_addr.to_owned(), end_addr.to_owned())
    } else {
        dprintln!("Payload start or end address is not set! Skipping page fault handler...");
        return Ok(EXCEPTION_CONTINUE_SEARCH);
    };
    let exception_record = unsafe { exception_info.read().ExceptionRecord.read() };
    let exception_location = exception_record.ExceptionAddress as usize;
    let exception_fault_addr = exception_record.ExceptionInformation[1];

    dprintln!("Currently decrypted pages: {:?}", decrpyted_pages);
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
            dprintln!("Exception fault address: 0x{:02X}", exception_fault_addr);

            // ─── Check If Exception Occurred In Payload Memory Region ────────────
            if exception_fault_addr < payload_start_addr || exception_fault_addr > payload_end_addr
            {
                dprintln!("Page fault didn't occur in payload memory region. Skipping...");
                return Ok(EXCEPTION_CONTINUE_SEARCH);
            }

            let page_addr = exception_fault_addr & !(PAGE_SIZE - 1);
            let page_index = (page_addr - payload_start_addr) / PAGE_SIZE;
            let mut page_key: U8_32 = [0u8; 32];

            dprintln!("Page index: {}", page_index);
            dprintln!("Page addr: 0x{:02X}", page_addr);

            let protection = if let Some(val) = *(PROTECTION_OVERRIDE
                .read()
                .map_err(|_| xor_string!("Couldn't get lock!"))?)
            {
                dprintln!("~~~ Protection override is set, which is {} ~~~", val);
                val
            } else {
                Protection::READ_EXECUTE
            };

            if decrpyted_pages.contains(&page_index) {
                dprintln!(
                    "Faulting page is already decrypted. Querying memory region for its protection..."
                );
                let fault_page_addr = exception_fault_addr & !(PAGE_SIZE - 1);

                if let Ok(result) = region::query(fault_page_addr as *const u8) {
                    if result.protection() != protection {
                        dprintln!(
                            "Faulting page's protection is different than the overriden protection. Updating..."
                        );

                        unsafe {

                            if let Ok(_) =
                                region::protect(fault_page_addr as *const u8, PAGE_SIZE, protection)
                            {
                                dprintln!(
                                    "Successfully updated page protection to {}.",
                                    protection
                                );
                                return Ok(EXCEPTION_CONTINUE_EXECUTION);
                            } else {
                                dprintln!("Couldn't update page protection! Skipping...");
                            }
                        }
                    }
                } else {
                    dprintln!("Couldn't query the memory region. Skipping...");
                }

                return Ok(EXCEPTION_CONTINUE_SEARCH);
            }

            // ─── Encrypt Previous Pages ──────────────────────────
            if decrpyted_pages.len() >= MAX_DECRYPTED_PAGES {
                dprintln!("Max decrypted pages limit reached!");

                let prev_page_index = decrpyted_pages[0];
                dprintln!("Re-encrypting page {}...", prev_page_index);

                let prev_page_addr = payload_start_addr + (prev_page_index * PAGE_SIZE);
                derive_page_key(base_key, prev_page_index, &mut page_key);
                dprintln!("Derived key to re-encrypt page...");

                unsafe {
                    if let Err(_) = region::protect::<u8>(
                        prev_page_addr as *const _,
                        PAGE_SIZE,
                        Protection::READ_WRITE,
                    ) {
                        dprintln!("Failed to update memory protection for previous page! (1)");
                    } else {
                        encrypt_page(
                            slice::from_raw_parts_mut::<u8>(prev_page_addr as *mut _, PAGE_SIZE)
                                .try_into()
                                .unwrap(),
                            &page_key,
                        );

                        if let Err(_) = region::protect::<u8>(
                            prev_page_addr as *mut _,
                            PAGE_SIZE,
                            Protection::NONE,
                        ) {
                            dprintln!("Failed to update memory protection for previous page! (2)");
                        }
                    }
                }

                dprintln!("Re-encrypted page {}.", prev_page_index);
                decrpyted_pages.remove(0);
            }

            // ─── Decrypt Current Page ────────────────────────────
            unsafe {
                let protection = Protection::READ_WRITE;
                dprintln!(
                    "Updating protection level of page {} to {}.",
                    page_index,
                    protection
                );

                if let Err(_) = region::protect::<u8>(page_addr as *const _, PAGE_SIZE, protection)
                {
                    dprintln!("Failed to update memory protection on faulting page!");
                    return Ok(EXCEPTION_CONTINUE_SEARCH);
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
            dprintln!("Decrypted page {}.", page_index);

            unsafe {
                dprintln!(
                    "Updating protection level of page {} to {}.",
                    page_index,
                    protection
                );

                if let Err(_) = region::protect::<u8>(page_addr as *const _, PAGE_SIZE, protection)
                {
                    dprintln!("Failed to update memory protection on faulting page!");
                    return Ok(EXCEPTION_CONTINUE_SEARCH);
                }
            }

            decrpyted_pages.push(page_index);

            dprintln!("Continuing execution...");
            Ok(EXCEPTION_CONTINUE_EXECUTION)
        }
        _ => Ok(EXCEPTION_CONTINUE_SEARCH),
    }
}

pub(crate) unsafe extern "system" fn page_fault_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    match _page_fault_handler(exception_info) {
        Ok(val) => val,
        Err(err) => {
            dprintln!("!!! An error occurred during handling page fault !!!");
            dprintln!("{}", err);

            EXCEPTION_CONTINUE_SEARCH
        },
    }
}

const _: () = assert!(MAX_DECRYPTED_PAGES >= 1);
