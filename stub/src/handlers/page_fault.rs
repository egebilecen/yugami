use core::slice;
use std::{
    collections::HashMap,
    mem,
    sync::{LazyLock, Mutex, OnceLock},
};

use windows_sys::Win32::{
    Foundation::EXCEPTION_ACCESS_VIOLATION,
    System::{
        Diagnostics::Debug::{
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
        },
        Memory::{
            MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
            PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, VirtualProtect, VirtualQuery,
        },
    },
};

use super::lru::LruPageList;
use crate::handlers::lock::WinLock;
#[allow(unused_imports)]
use debug::dprintln;
use common::crypto::{PAGE_SIZE, U8_32, decrypt_page, derive_page_key, encrypt_page};
use proc_macros::xor_str;

pub(crate) static BASE_KEY: OnceLock<U8_32> = OnceLock::new();
pub(crate) static PAYLOAD_START_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PAYLOAD_END_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static PAGE_PROTECTIONS: LazyLock<Mutex<HashMap<usize, PAGE_PROTECTION_FLAGS>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const MAX_DECRYPTED_PAGES: usize = 256;
static DECRYPTED_PAGES: OnceLock<Mutex<LruPageList<MAX_DECRYPTED_PAGES>>> = OnceLock::new();
static FAULT_HANDLER_LOCK: WinLock = WinLock::new();

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

#[inline]
fn _page_fault_handler(exception_info: *mut EXCEPTION_POINTERS) -> Result<(), ()> {
    let _guard = FAULT_HANDLER_LOCK.lock();
    dprintln!(">>> Exception handler invoked! <<<");

    // ─── Variables ───────────────────────────────────────────────────────
    let exception_record = unsafe { exception_info.read().ExceptionRecord.read() };
    let exception_code = exception_record.ExceptionCode as u32;
    let exception_addr = exception_record.ExceptionAddress as usize;
    let exception_reason = exception_record.ExceptionInformation[0];
    let exception_data_addr = exception_record.ExceptionInformation[1];

    let (_payload_start_addr, _payload_end_addr) = if let Some(start_addr) = PAYLOAD_START_ADDR.get()
        && let Some(end_addr) = PAYLOAD_END_ADDR.get()
    {
        (start_addr.to_owned(), end_addr.to_owned())
    } else {
        dprintln!("Payload start or end address is not set! Skipping page fault handler...");
        return Err(());
    };

    // dprintln!("Currently decrypted pages: {}", decrpyted_pages);
    dprintln!("Exception code: 0x{:02X}", exception_code);
    dprintln!(
        "Exception reason: {} (0x{:02X})",
        if exception_reason == 0 {
            "READ"
        } else if exception_reason == 1 {
            "WRITE"
        } else if exception_reason == 8 {
            "EXECUTE"
        } else {
            "UNKNOWN"
        },
        exception_reason,
    );
    dprintln!("Exception location address: 0x{:02X}", exception_addr);
    dprintln!(
        "Exception inacessible data address: 0x{:02X}",
        exception_data_addr
    );
    dprintln!("Payload start address: 0x{:02X}", _payload_start_addr);
    dprintln!("Payload end address: 0x{:02X}", _payload_end_addr);

    if exception_code != EXCEPTION_ACCESS_VIOLATION as u32 {
        return Err(());
    }

    // ─── Handle JIT Page Encryption / Decryption ─────────────────────────
    if exception_reason == 8 {
        let exec_page_addr = get_page_addr(exception_addr);
        ensure_page_ready(exec_page_addr)?;

        let page_offset = exception_addr & (PAGE_SIZE - 1);
        const MAX_INSTRUCTION_SIZE: usize = 15;

        if page_offset > PAGE_SIZE - MAX_INSTRUCTION_SIZE {
            dprintln!("Instruction spans page boundary! Preparing adjacent page...");
            let _ = ensure_page_ready(exec_page_addr + PAGE_SIZE);
        }
    } else if exception_reason == 0 || exception_reason == 1 {
        let data_page_addr = get_page_addr(exception_data_addr);

        ensure_page_ready(data_page_addr)?;

        let page_offset = exception_data_addr & (PAGE_SIZE - 1);
        const MAX_ACCESS_SIZE: usize = 64;

        if page_offset > PAGE_SIZE - MAX_ACCESS_SIZE {
            dprintln!("Data access spans page boundary! Preparing next page...");
            let next_page_addr = data_page_addr + PAGE_SIZE;
            let _ = ensure_page_ready(next_page_addr);
        }
    } else {
        dprintln!("Unknown exception reason detected!");
    }

    dprintln!("Continuing execution...");
    Ok(())
}

fn ensure_page_ready(page_addr: usize) -> Result<(), ()> {
    let mut decrypted_pages = DECRYPTED_PAGES
        .get_or_init(|| Mutex::new(LruPageList::new()))
        .lock()
        .expect(xor_str!("Decrypted pages lock is poisoned!"));

    let base_key = if let Some(key) = BASE_KEY.get() {
        key
    } else {
        dprintln!("Base key is not set! Skipping page fault handler...");
        return Err(());
    };

    let (payload_start_addr, payload_end_addr) = if let Some(start_addr) = PAYLOAD_START_ADDR.get()
        && let Some(end_addr) = PAYLOAD_END_ADDR.get()
    {
        (start_addr.to_owned(), end_addr.to_owned())
    } else {
        dprintln!("Payload start address is not set! Skipping page fault handler...");
        return Err(());
    };

    if page_addr < payload_start_addr || page_addr >= payload_end_addr {
        dprintln!("Given page address is outside payload memory region.");
        return Err(());
    }

    let default_protection = PAGE_EXECUTE_READWRITE;
    let page_index = get_page_index(payload_start_addr, page_addr);

    // Page is not decrypted yet.
    if decrypted_pages.get(page_index).is_none() {
        return do_page_decryption(
            payload_start_addr,
            page_index,
            base_key,
            default_protection,
            &mut decrypted_pages,
        );
    }

    dprintln!("Faulting page is already decrypted. Querying page for its protection...");

    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    if unsafe {
        VirtualQuery(
            page_addr as *const _,
            &mut mem_info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } == 0
    {
        dprintln!("Couldn't query the page protection!");
        return Err(());
    }

    if mem_info.Protect != default_protection {
        dprintln!("Page protection changed unexpectedly. Restoring...");

        let mut old_protect: PAGE_PROTECTION_FLAGS = 0x00;
        if unsafe {
            VirtualProtect(
                page_addr as *const _,
                PAGE_SIZE,
                default_protection,
                &mut old_protect,
            ) == 0
        } {
            dprintln!("Couldn't update page protection!");
            return Err(());
        }
    }

    dprintln!("Queried page is ready.");
    Ok(())
}

fn do_page_decryption<const N: usize>(
    payload_start_addr: usize,
    page_index: usize,
    base_key: &U8_32,
    default_protection: PAGE_PROTECTION_FLAGS,
    decrypted_pages: &mut LruPageList<N>,
) -> Result<(), ()> {
    let mut page_key_buf: U8_32 = [0u8; 32];
    let mut old_protect: PAGE_PROTECTION_FLAGS = 0x00;

    // ─── Re-encrypt Evicted Page ─────────────────────────────────
    if let Some(evicted_page_index) = decrypted_pages.add(page_index) {
        dprintln!(
            "A LRU page is evicted! Evicted page index: {}",
            evicted_page_index
        );
        dprintln!("Re-encrypting evicted page {}...", evicted_page_index);

        let evicted_page_addr = payload_start_addr + (evicted_page_index * PAGE_SIZE);
        derive_page_key(base_key, evicted_page_index, &mut page_key_buf);

        dprintln!(
            "Derived key to re-encrypt evicted page {}...",
            evicted_page_index
        );

        if unsafe {
            VirtualProtect(
                evicted_page_addr as *const _,
                PAGE_SIZE,
                PAGE_READWRITE,
                &mut old_protect,
            )
        } == 0
        {
            dprintln!("Failed to update memory protection for evicted page! (1)");
            return Err(());
        } else {
            encrypt_page(
                unsafe {
                    slice::from_raw_parts_mut::<u8>(evicted_page_addr as *mut _, PAGE_SIZE)
                        .try_into()
                        .unwrap()
                },
                &page_key_buf,
            );

            if unsafe {
                VirtualProtect(
                    evicted_page_addr as *const _,
                    PAGE_SIZE,
                    PAGE_NOACCESS,
                    &mut old_protect,
                )
            } == 0
            {
                dprintln!("Failed to update memory protection for evicted page! (2)");
                return Err(());
            }
        }

        dprintln!("Re-encrypted evicted page {}.", evicted_page_index);
    }

    // ─── Decrypt Current Page ────────────────────────────
    dprintln!("Updating protection level of page {} to rw-.", page_index);
    let fault_page_addr = payload_start_addr + (page_index * PAGE_SIZE);

    if unsafe {
        VirtualProtect(
            fault_page_addr as *const _,
            PAGE_SIZE,
            PAGE_READWRITE,
            &mut old_protect,
        )
    } == 0
    {
        dprintln!("Failed to update memory protection on faulting page!");
        return Err(());
    }

    derive_page_key(base_key, page_index, &mut page_key_buf);
    dprintln!(
        "Derived page key: {}",
        page_key_buf.map(|b| format!("{:02X}", b)).join(" ")
    );

    decrypt_page(
        unsafe {
            slice::from_raw_parts_mut::<u8>(fault_page_addr as *mut _, PAGE_SIZE)
                .try_into()
                .unwrap()
        },
        &page_key_buf,
    );
    dprintln!("Decrypted page {}.", page_index);

    dprintln!(
        "Updating protection level of page {} to {}.",
        page_index,
        prot_to_str(default_protection)
    );

    if unsafe {
        VirtualProtect(
            fault_page_addr as *const _,
            PAGE_SIZE,
            default_protection,
            &mut old_protect,
        )
    } == 0
    {
        dprintln!("Failed to update memory protection on faulting page!");
        return Err(());
    }

    Ok(())
}

#[inline]
fn get_page_addr(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

#[inline]
fn get_page_index(payload_start_addr: usize, addr: usize) -> usize {
    (get_page_addr(addr) - payload_start_addr) / PAGE_SIZE
}

#[allow(unused)]
fn prot_to_str(protect: PAGE_PROTECTION_FLAGS) -> &'static str {
    let base_protect = protect & 0xFF;

    match base_protect {
        PAGE_NOACCESS => "---",
        PAGE_READONLY => "r--",
        PAGE_READWRITE => "rw-",
        PAGE_EXECUTE_READ => "r-x",
        PAGE_EXECUTE_READWRITE => "rwx",
        _ => "unknown",
    }
}

/* -------------------------------------------------------------------------- */
/*                                    Main                                    */
/* -------------------------------------------------------------------------- */
pub(crate) unsafe extern "system" fn page_fault_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    match _page_fault_handler(exception_info) {
        Ok(_) => EXCEPTION_CONTINUE_EXECUTION,
        Err(_) => EXCEPTION_CONTINUE_SEARCH,
    }
}

const _: () = assert!(MAX_DECRYPTED_PAGES >= 1);
