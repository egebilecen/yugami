use debug::dprintln;
use windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS;

pub(crate) unsafe extern "system" fn page_fault_handler(_exception_info: *mut EXCEPTION_POINTERS) -> i32 {
    dprintln!("Page fault handler invoked!");
    0
}
