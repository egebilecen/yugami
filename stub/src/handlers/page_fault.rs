use core::slice;
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex, OnceLock, RwLock},
};

use region::Protection;
use windows_sys::Win32::{
    Foundation::EXCEPTION_ACCESS_VIOLATION,
    System::Diagnostics::Debug::{
        EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    },
};

use super::lru::LruPageList;
#[allow(unused_imports)]
use debug::dprintln;
use kekkai::crypto::{PAGE_SIZE, U8_32, decrypt_page, derive_page_key, encrypt_page};
use proc_macros::xor_str;

pub(crate) static BASE_KEY: OnceLock<U8_32> = OnceLock::new();
pub(crate) static PAYLOAD_START_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PAYLOAD_END_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PAGE_PROTECTIONS: LazyLock<Mutex<HashMap<usize, Protection>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub(crate) static PROTECTION_OVERRIDE: RwLock<Option<Protection>> = RwLock::new(None);

const MAX_DECRYPTED_PAGES: usize = 20;
static DECRYPTED_PAGES: OnceLock<Mutex<LruPageList<MAX_DECRYPTED_PAGES>>> = OnceLock::new();

// Shadow macro to append prefix.
macro_rules! dprintln {
    ($fmt:expr $(, $($arg:tt)*)?) => {
        $crate::dprintln!(concat!("[PFH] ", $fmt) $(, $($arg)*)?);
    };
}

// Temporary shadowing to disable debug logs.
// macro_rules! dprintln {
//     ($($tt:tt)*) => {};
// }

// TODO: Do NOT use dynamic memory allocations in the fault handler.
#[inline]
fn _page_fault_handler(exception_info: *mut EXCEPTION_POINTERS) -> Result<i32, String> {
    let exception_record = unsafe { exception_info.read().ExceptionRecord.read() };
    if exception_record.ExceptionCode != EXCEPTION_ACCESS_VIOLATION {
        return Ok(EXCEPTION_CONTINUE_SEARCH);
    }

    dprintln!(">>> Exception handler invoked! <<<");

    // ─── Variables ───────────────────────────────────────────────────────
    let mut decrpyted_pages = match DECRYPTED_PAGES
        .get_or_init(|| Mutex::new(LruPageList::new()))
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
    let _exception_location = exception_record.ExceptionAddress as usize;
    let _exception_reason = exception_record.ExceptionInformation[0];
    let exception_fault_addr = exception_record.ExceptionInformation[1];
    let fault_page_addr = exception_fault_addr & !(PAGE_SIZE - 1);

    dprintln!("Currently decrypted pages: {}", decrpyted_pages);
    dprintln!(
        "Exception code: 0x{:02X}",
        exception_record.ExceptionCode as usize
    );
    dprintln!(
        "Exception reason: {} (0x{:02X})",
        if _exception_reason == 0 {
            "READ"
        } else if _exception_reason == 1 {
            "WRITE"
        } else if _exception_reason == 8 {
            "EXECUTE"
        } else {
            "UNKNOWN"
        },
        _exception_reason,
    );
    dprintln!("Exception location: 0x{:02X}", _exception_location);
    dprintln!("Payload start address: 0x{:02X}", payload_start_addr);
    dprintln!("Payload end address: 0x{:02X}", payload_end_addr);

    // ─── Handle Exception ────────────────────────────────────────────────
    dprintln!("Exception fault address: 0x{:02X}", exception_fault_addr);

    // ─── Check If Exception Occurred In Payload Memory Region ────────────
    if exception_fault_addr < payload_start_addr || exception_fault_addr > payload_end_addr {
        dprintln!("Page fault didn't occur in payload memory region. Skipping...");
        return Ok(EXCEPTION_CONTINUE_SEARCH);
    }

    let page_index = (fault_page_addr - payload_start_addr) / PAGE_SIZE;
    let mut page_key: U8_32 = [0u8; 32];

    dprintln!("Page index: {}", page_index);
    dprintln!("Page addr: 0x{:02X}", fault_page_addr);

    let protection = if let Some(val) = *(PROTECTION_OVERRIDE
        .read()
        .map_err(|_| xor_str!("Couldn't get lock!"))?)
    {
        dprintln!("~~~ Protection override is set, which is {} ~~~", val);
        val
    } else {
        if let Some(page_protection) = PAGE_PROTECTIONS
            .lock()
            .map_err(|_| xor_str!("Couldn't get lock! (2)"))?
            .get(&page_index)
        {
            dprintln!(
                "~~~ Specific protection is set for page {}, which is {} ~~~",
                page_index,
                page_protection
            );

            *page_protection
        } else {
            let default_protection = Protection::READ_WRITE_EXECUTE;
            dprintln!(
                "~~~ No specific protection is set for page {}, defaulting to {} ~~~",
                page_index,
                default_protection
            );

            default_protection
        }
    };

    // ─── Handle JIT Page Encryption / Decryption ─────────────────────────
    // Page is not decrypted yet.
    if decrpyted_pages.get(page_index).is_none() {
        // ─── Re-encrypt Evicted Page ─────────────────────────────────
        if let Some(evicted_page_index) = decrpyted_pages.add(page_index) {
            dprintln!(
                "A LRU page is evicted! Evicted page index: {}",
                evicted_page_index
            );
            dprintln!("Re-encrypting evicted page {}...", evicted_page_index);

            let evicted_page_addr = payload_start_addr + (evicted_page_index * PAGE_SIZE);
            derive_page_key(base_key, evicted_page_index, &mut page_key);
            dprintln!(
                "Derived key to re-encrypt evicted page {}...",
                evicted_page_index
            );

            if unsafe {
                region::protect::<u8>(
                    evicted_page_addr as *const _,
                    PAGE_SIZE,
                    Protection::READ_WRITE,
                )
            }
            .is_err()
            {
                dprintln!("Failed to update memory protection for evicted page! (1)");
            } else {
                encrypt_page(
                    unsafe {
                        slice::from_raw_parts_mut::<u8>(evicted_page_addr as *mut _, PAGE_SIZE)
                            .try_into()
                            .unwrap()
                    },
                    &page_key,
                );

                if unsafe {
                    region::protect::<u8>(evicted_page_addr as *mut _, PAGE_SIZE, Protection::NONE)
                }
                .is_err()
                {
                    dprintln!("Failed to update memory protection for evicted page! (2)");
                }
            }

            dprintln!("Re-encrypted evicted page {}.", evicted_page_index);
        }
    } else {
        dprintln!("Faulting page is already decrypted. Querying page for its protection...");

        if let Ok(result) = region::query(fault_page_addr as *const u8) {
            if result.protection() != protection {
                dprintln!(
                    "Faulting page has different protection than default/overridden protection. Updating..."
                );

                if unsafe { region::protect(fault_page_addr as *const u8, PAGE_SIZE, protection) }
                    .is_ok()
                {
                    dprintln!("Successfully updated page protection to {}.", protection);
                    return Ok(EXCEPTION_CONTINUE_EXECUTION);
                } else {
                    dprintln!("Couldn't update page protection! Skipping...");
                }
            } else {
                dprintln!("Queried page has same protection. Skipping...");
            }
        } else {
            dprintln!("Couldn't query the page. Skipping...");
        }

        return Ok(EXCEPTION_CONTINUE_SEARCH);
    }

    // ─── Decrypt Current Page ────────────────────────────
    dprintln!(
        "Updating protection level of page {} to {}.",
        page_index,
        protection
    );

    if unsafe {
        region::protect::<u8>(
            fault_page_addr as *const _,
            PAGE_SIZE,
            Protection::READ_WRITE,
        )
    }
    .is_err()
    {
        dprintln!("Failed to update memory protection on faulting page!");
        return Ok(EXCEPTION_CONTINUE_SEARCH);
    }

    derive_page_key(base_key, page_index, &mut page_key);
    dprintln!(
        "Derived page key: {}",
        page_key.map(|b| format!("{:02X}", b)).join(" ")
    );

    decrypt_page(
        unsafe {
            slice::from_raw_parts_mut::<u8>(fault_page_addr as *mut _, PAGE_SIZE)
                .try_into()
                .unwrap()
        },
        &page_key,
    );
    dprintln!("Decrypted page {}.", page_index);

    dprintln!(
        "Updating protection level of page {} to {}.",
        page_index,
        protection
    );

    if unsafe { region::protect::<u8>(fault_page_addr as *const _, PAGE_SIZE, protection) }.is_err()
    {
        dprintln!("Failed to update memory protection on faulting page!");
        return Ok(EXCEPTION_CONTINUE_SEARCH);
    }

    dprintln!("Continuing execution...");
    Ok(EXCEPTION_CONTINUE_EXECUTION)
}

pub(crate) unsafe extern "system" fn page_fault_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    match _page_fault_handler(exception_info) {
        Ok(val) => val,
        Err(_err) => {
            dprintln!("!!! An error occurred during handling page fault !!!");
            dprintln!("{}", _err);

            EXCEPTION_CONTINUE_SEARCH
        }
    }
}

const _: () = assert!(MAX_DECRYPTED_PAGES >= 1);
