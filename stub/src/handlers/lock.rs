use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use windows_sys::Win32::System::Threading::{
    CRITICAL_SECTION, EnterCriticalSection, InitializeCriticalSection, LeaveCriticalSection,
};

pub struct WinLock {
    lock: UnsafeCell<CRITICAL_SECTION>,
    is_initialized: AtomicBool,
}

unsafe impl Sync for WinLock {}
unsafe impl Send for WinLock {}

impl WinLock {
    pub const fn new() -> Self {
        Self {
            lock: UnsafeCell::new(unsafe { std::mem::zeroed() }),
            is_initialized: AtomicBool::new(false),
        }
    }

    pub fn lock(&self) -> WinLockGuard {
        if !self.is_initialized.load(Ordering::Acquire) {
            unsafe { InitializeCriticalSection(self.lock.get()) };
            self.is_initialized.store(true, Ordering::Release);
        }

        unsafe { EnterCriticalSection(self.lock.get()) };
        WinLockGuard(self.lock.get())
    }
}

pub struct WinLockGuard(*mut CRITICAL_SECTION);

impl Drop for WinLockGuard {
    fn drop(&mut self) {
        unsafe { LeaveCriticalSection(self.0) };
    }
}
