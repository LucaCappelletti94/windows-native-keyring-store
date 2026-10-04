//! Cross-process locks for sealed store records, isolated to the current Windows user.
#![expect(dead_code, reason = "lock_target is called by Gate")]

use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, LocalFree, WAIT_ABANDONED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::System::Threading::{
    AddSIDToBoundaryDescriptor, CreateBoundaryDescriptorW, CreateMutexW, CreatePrivateNamespaceW,
    DeleteBoundaryDescriptor, GetCurrentProcess, OpenPrivateNamespaceW, OpenProcessToken,
    ReleaseMutex, WaitForSingleObject,
};

use crate::sealed::{SealError, unpoison};
use crate::utils::{from_wstr, hex};

const NAMESPACE: &str = "windows-native-keyring-store-v1";

pub(crate) struct TargetLock(HANDLE);

pub(crate) fn lock_target(target: &str) -> Result<TargetLock, SealError> {
    lock_target_with_timeout(target, Duration::from_secs(30))
}

pub(crate) fn lock_target_with_timeout(
    target: &str,
    timeout: Duration,
) -> Result<TargetLock, SealError> {
    enter_namespace()?;
    let digest = Sha256::digest(target.as_bytes());
    let name: Vec<u16> = format!("{NAMESPACE}\\{}\0", hex(&digest))
        .encode_utf16()
        .collect();
    // SAFETY: `name` is NUL-terminated and outlives the call, and null security attributes are allowed.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(last_error("create credential mutex"));
    }
    let millis = u32::try_from(timeout.as_millis()).map_or(u32::MAX - 1, |ms| ms.min(u32::MAX - 1));
    // SAFETY: `handle` is a live mutex handle owned here, and the finite wait excludes `INFINITE`.
    match unsafe { WaitForSingleObject(handle, millis) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(TargetLock(handle)),
        wait => {
            let error = if wait == WAIT_TIMEOUT {
                SealError::TimedOut
            } else {
                last_error("wait for credential mutex")
            };
            // SAFETY: `handle` is owned here and not used again after closing.
            unsafe { CloseHandle(handle) };
            Err(error)
        }
    }
}

fn last_error(operation: &str) -> SealError {
    // SAFETY: reads this thread's last-error value with no preconditions.
    let code = unsafe { GetLastError() };
    SealError::Platform(format!("{operation} failed with {code}"))
}

/// Enters this user's private lock namespace once per process and keeps it open.
///
/// Its boundary holds the user's SID, so another account cannot create it first, and its DACL
/// admits only that user.
fn enter_namespace() -> Result<(), SealError> {
    static ENTERED: Mutex<bool> = Mutex::new(false);
    let mut entered = unpoison(ENTERED.lock());
    if !*entered {
        let mut token_user = [0u64; 64];
        let sid = current_user_sid(&mut token_user)?;
        open_namespace(sid)?;
        *entered = true;
    }
    Ok(())
}

/// Writes the process token's user into `buffer` and returns its SID, which points into `buffer`.
fn current_user_sid(buffer: &mut [u64; 64]) -> Result<PSID, SealError> {
    let mut token = std::ptr::null_mut();
    // SAFETY: the process pseudo-handle and the out pointer are valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("open process token"));
    }
    let mut length = 0;
    // SAFETY: `buffer` is writable and `u64`-aligned, which satisfies `TOKEN_USER`, for its length.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size_of_val(buffer) as u32,
            &mut length,
        )
    };
    let error = (queried == 0).then(|| last_error("query token user"));
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    match error {
        Some(error) => Err(error),
        // SAFETY: a successful query wrote a `TOKEN_USER` at the start of `buffer`.
        None => Ok(unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }),
    }
}

fn open_namespace(sid: PSID) -> Result<(), SealError> {
    let mut sid_string = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID and the out pointer is writable.
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_string) } == 0 {
        return Err(last_error("format user SID"));
    }
    // SAFETY: the conversion returned a NUL-terminated string.
    let sid_text = unsafe { from_wstr(sid_string) };
    // SAFETY: `sid_string` came from `ConvertSidToStringSidW` and is freed once.
    unsafe { LocalFree(sid_string.cast()) };
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid_text})\0")
        .encode_utf16()
        .collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and the out pointer is writable.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(last_error("build lock namespace DACL"));
    }
    let name: Vec<u16> = format!("{NAMESPACE}\0").encode_utf16().collect();
    // SAFETY: `name` is NUL-terminated.
    let mut boundary = unsafe { CreateBoundaryDescriptorW(name.as_ptr(), 0) };
    let result = if boundary.is_null() {
        Err(last_error("create lock namespace boundary"))
    } else {
        bind_namespace(&mut boundary, sid, descriptor, &name)
    };
    if !boundary.is_null() {
        // SAFETY: `boundary` came from `CreateBoundaryDescriptorW` and is deleted once.
        unsafe { DeleteBoundaryDescriptor(boundary) };
    }
    // SAFETY: `descriptor` came from the SDDL conversion and is freed once.
    unsafe { LocalFree(descriptor) };
    result
}

/// Creates the user-bound namespace, or opens it if another process of this user already did.
fn bind_namespace(
    boundary: &mut HANDLE,
    sid: PSID,
    descriptor: PSECURITY_DESCRIPTOR,
    name: &[u16],
) -> Result<(), SealError> {
    // SAFETY: `boundary` is a live boundary descriptor and `sid` is a valid SID.
    if unsafe { AddSIDToBoundaryDescriptor(boundary, sid) } == 0 {
        return Err(last_error("bind lock namespace to the user"));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // The last other holder can exit between a failed create and the open, so retry a few times.
    for _ in 0..8 {
        // SAFETY: `attributes`, `boundary` and the NUL-terminated `name` are live for the call.
        if !unsafe { CreatePrivateNamespaceW(&attributes, *boundary, name.as_ptr()) }.is_null() {
            return Ok(());
        }
        // SAFETY: reads this thread's last-error value with no preconditions.
        if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(last_error("create lock namespace"));
        }
        // SAFETY: `boundary` and the NUL-terminated `name` are live for the call.
        if !unsafe { OpenPrivateNamespaceW(*boundary, name.as_ptr()) }.is_null() {
            return Ok(());
        }
    }
    Err(last_error("open lock namespace"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn a_global_squatter_cannot_hold_store_locks() {
        let target = format!("squat-{}", fastrand::u64(..));
        let digest = hex(&Sha256::digest(target.as_bytes()));
        let squatted: Vec<u16> = format!("Global\\windows-native-keyring-store-v1-{digest}\0")
            .encode_utf16()
            .collect();
        // SAFETY: the name is NUL-terminated, and this thread takes initial ownership.
        let squatter = unsafe { CreateMutexW(std::ptr::null(), 1, squatted.as_ptr()) };
        assert!(!squatter.is_null());
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = lock_target_with_timeout(&target, Duration::from_millis(200)).is_ok();
            tx.send(acquired).unwrap();
        });
        let acquired = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        // SAFETY: this thread owns `squatter` and releases and closes it once.
        unsafe {
            ReleaseMutex(squatter);
            CloseHandle(squatter);
        }
        assert!(
            acquired,
            "a same-named machine-global mutex blocked the store lock"
        );
    }
}
