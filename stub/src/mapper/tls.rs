use std::{
    alloc::{Layout, alloc_zeroed},
    error::Error,
    os::raw::c_void,
    ptr::{self},
    sync::OnceLock,
};

use windows_sys::Win32::System::{
    SystemServices::{
        DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
        IMAGE_TLS_DIRECTORY64, PIMAGE_TLS_CALLBACK,
    },
    Threading::{TLS_OUT_OF_INDEXES, TlsSetValue},
};

#[allow(unused_imports)]
use debug::dprintln;

use crate::mapper::error::MapperError;

pub(crate) static TLS_CALLBACKS_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static TLS_DIR_ADDR: OnceLock<usize> = OnceLock::new();
pub(crate) static ALLOCATED_TLS_INDEX: OnceLock<u32> = OnceLock::new();

// Shadow macro to append prefix.
macro_rules! dprintln {
    ($fmt:expr $(, $($arg:tt)*)?) => {
        $crate::dprintln!(concat!("[TLS] ", $fmt) $(, $($arg)*)?);
    };
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "system" fn tls_callback(
    dll_handle: *mut c_void,
    reason: u32,
    reserved: *mut c_void,
) {
    dprintln!(
        "TLS callback invoked! Reason: {} (0x{:02X})",
        reason,
        reason
    );

    let tls_callbacks_addr = if let Some(val) = TLS_CALLBACKS_ADDR.get() {
        *val
    } else {
        dprintln!("No payload TLS callbacks address is set yet! Skipping...");
        return;
    };

    let tls_dir_addr = if let Some(val) = TLS_DIR_ADDR.get() {
        val
    } else {
        dprintln!("No payload TLS directory address is set yet! Skipping...");
        return;
    };

    let tls_allocated_index = if let Some(val) = ALLOCATED_TLS_INDEX.get() {
        val
    } else {
        dprintln!("No payload TLS allocated index is set yet! Skipping...");
        return;
    };

    match reason {
        DLL_PROCESS_ATTACH | DLL_THREAD_ATTACH => unsafe {
            let _ = setup_current_thread_tls(
                &*(*tls_dir_addr as *const IMAGE_TLS_DIRECTORY64),
                *tls_allocated_index as u32,
            );
        },
        DLL_PROCESS_DETACH | DLL_THREAD_DETACH => {
            // TODO: Free thread TLS buffers.
        }
        _ => {}
    }

    let mut callback_ptr = tls_callbacks_addr as *const PIMAGE_TLS_CALLBACK;

    unsafe {
        while let Some(callback) = *callback_ptr {
            dprintln!("Executing TLS callback at 0x{:02X}.", callback_ptr as usize);
            callback(dll_handle, reason, reserved);
            callback_ptr = callback_ptr.add(1);
        }
    }
}

pub(crate) unsafe fn setup_current_thread_tls(
    tls_dir: &IMAGE_TLS_DIRECTORY64,
    tls_index: u32,
) -> Result<(), Box<dyn Error>> {
    if tls_index == TLS_OUT_OF_INDEXES {
        return Ok(());
    }

    let data_size = (tls_dir.EndAddressOfRawData - tls_dir.StartAddressOfRawData) as usize;
    let zero_fill_size = tls_dir.SizeOfZeroFill as usize;
    let total_size = data_size + zero_fill_size;

    dprintln!("TLS template size: {} (0x{:02X})", data_size, data_size);
    dprintln!(
        "TLS template zero fill size: {} (0x{:02X})",
        zero_fill_size,
        zero_fill_size
    );

    if total_size == 0 {
        return Ok(());
    }

    let layout = Layout::from_size_align(total_size, 16)?;
    let buf = unsafe { alloc_zeroed(layout) };

    if buf.is_null() {
        return Err(MapperError::BufferAllocationError.into());
    }

    let raw_data_start_ptr = tls_dir.StartAddressOfRawData as *const u8;
    if data_size > 0 && !raw_data_start_ptr.is_null() {
        unsafe { ptr::copy_nonoverlapping(raw_data_start_ptr, buf, data_size) };
    }

    let res = unsafe { TlsSetValue(tls_index, buf as *mut c_void) };
    if res == 0 {
        return Err(MapperError::TlsSetValueError.into());
    }

    dprintln!(
        "Successfully assigned TLS buffer 0x{:02X} to TLS index {}.",
        buf as usize,
        tls_index
    );

    Ok(())
}

#[unsafe(link_section = ".CRT$XLB")]
#[used]
pub static STUB_TLS_ENTRY: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) = tls_callback;
