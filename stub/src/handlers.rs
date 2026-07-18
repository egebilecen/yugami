use debug::dprintln;
use windows_sys::Win32::{Foundation::EXCEPTION_ACCESS_VIOLATION, System::Diagnostics::Debug::{
    EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
}};

pub(crate) unsafe extern "system" fn page_fault_handler(
    exception_info: *mut EXCEPTION_POINTERS,
) -> i32 {
    let exception_record = unsafe { exception_info.read().ExceptionRecord.read() };

    dprintln!("Page fault handler invoked!");
    dprintln!("Exception code: 0x{:02X}", exception_record.ExceptionCode as usize);
    dprintln!("Exception address: 0x{:02X}", exception_record.ExceptionAddress as usize);
    
    match exception_record.ExceptionCode {
        EXCEPTION_ACCESS_VIOLATION => {
            EXCEPTION_CONTINUE_SEARCH
        },
        _ => EXCEPTION_CONTINUE_SEARCH
    }
}
