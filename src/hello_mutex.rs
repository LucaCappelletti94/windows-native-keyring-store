use std::time::Duration;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use crate::hello::HelloError;

pub(crate) struct TargetLock(HANDLE);

pub(crate) fn lock_target(target: &str) -> Result<TargetLock, HelloError> {
    lock_target_with_timeout(target, Duration::from_secs(30))
}

pub(crate) fn lock_target_with_timeout(
    target: &str,
    timeout: Duration,
) -> Result<TargetLock, HelloError> {
    let digest = Sha256::digest(target.as_bytes());
    let mut name: Vec<u16> = "Global\\windows-native-keyring-store-v1-"
        .encode_utf16()
        .collect();
    for byte in digest {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        name.push(u16::from(HEX[usize::from(byte >> 4)]));
        name.push(u16::from(HEX[usize::from(byte & 15)]));
    }
    name.push(0);
    // SAFETY: `name` is NUL-terminated and outlives the call, and null security attributes are allowed.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(HelloError::Platform(format!(
            "create credential mutex failed with {}",
            // SAFETY: reads this thread's last-error value with no preconditions.
            unsafe { GetLastError() }
        )));
    }
    let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: `handle` is a live mutex handle owned here, and the finite wait excludes `INFINITE`.
    match unsafe { WaitForSingleObject(handle, millis.min(u32::MAX - 1)) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(TargetLock(handle)),
        WAIT_TIMEOUT => {
            // SAFETY: `handle` is owned here and not used again after closing.
            unsafe { CloseHandle(handle) };
            Err(HelloError::TimedOut)
        }
        _ => {
            // SAFETY: reads this thread's last-error value with no preconditions.
            let error = unsafe { GetLastError() };
            // SAFETY: `handle` is owned here and not used again after closing.
            unsafe { CloseHandle(handle) };
            Err(HelloError::Platform(format!(
                "wait for credential mutex failed with {error}"
            )))
        }
    }
}

impl Drop for TargetLock {
    fn drop(&mut self) {
        // SAFETY: the guard owns a mutex acquired by this thread and releases and closes it once.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
