use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use crate::hello::HelloError;

pub(crate) struct TargetLock(HANDLE);

pub(crate) fn lock_target(target: &str) -> Result<TargetLock, HelloError> {
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
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(HelloError::Platform(format!(
            "create credential mutex failed with {}",
            unsafe { GetLastError() }
        )));
    }
    match unsafe { WaitForSingleObject(handle, 30_000) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(TargetLock(handle)),
        WAIT_TIMEOUT => {
            unsafe { CloseHandle(handle) };
            Err(HelloError::TimedOut)
        }
        _ => {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            Err(HelloError::Platform(format!(
                "wait for credential mutex failed with {error}"
            )))
        }
    }
}

impl Drop for TargetLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
