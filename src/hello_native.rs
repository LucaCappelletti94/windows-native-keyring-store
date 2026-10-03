//! Dynamic binding to `webauthn.dll` for the Windows Hello platform authenticator.
//!
//! The DLL is loaded at run time from System32 only, so a machine without WebAuthn API 9
//! reports [`SealError::Unsupported`] instead of failing to start.

use libloading::Library;
use libloading::os::windows::{LOAD_LIBRARY_SEARCH_SYSTEM32, Library as WindowsLibrary};

use crate::sealed::SealError;
use crate::utils::from_wstr;
use crate::webauthn::{
    BOOL, HRESULT, PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST, WEBAUTHN_API_VERSION_9,
    WEBAUTHN_AUTHENTICATOR_DETAILS_LIST, WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION, WebAuthNFreeAuthenticatorList,
    WebAuthNGetApiVersionNumber, WebAuthNGetAuthenticatorList, WebAuthNGetErrorName,
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
};

const S_OK: HRESULT = 0;
const NTE_NOT_FOUND: HRESULT = 0x8009_0011u32.cast_signed();
const HELLO_NAME: &str = "Windows Hello";

/// Function pointers copied out of `webauthn.dll`, valid while `_lib` keeps it loaded.
struct WebAuthn {
    _lib: Library,
    uv_available: WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
    get_authenticator_list: WebAuthNGetAuthenticatorList,
    free_authenticator_list: WebAuthNFreeAuthenticatorList,
    // Optional because it only decorates error messages.
    get_error_name: Option<WebAuthNGetErrorName>,
}

/// Copies the `name` export out of `lib` as a function pointer.
///
/// # Safety
/// `T` must be the export's exact function-pointer type, and `lib` must outlive every use.
unsafe fn resolve<T: Copy>(lib: &Library, name: &str) -> Result<T, SealError> {
    // SAFETY: the caller guarantees `T` matches the export's signature.
    let symbol = unsafe { lib.get::<T>(name) }.map_err(|_| {
        SealError::Unsupported(format!("webauthn.dll is missing the {name} export"))
    })?;
    Ok(*symbol)
}

fn load() -> Result<WebAuthn, SealError> {
    // SAFETY: webauthn.dll is a system library whose initialisation has no preconditions, and
    // the System32-only search prevents loading a substitute from the application path.
    let lib: Library =
        unsafe { WindowsLibrary::load_with_flags("webauthn.dll", LOAD_LIBRARY_SEARCH_SYSTEM32) }
            .map_err(|error| {
                SealError::Unsupported(format!("webauthn.dll could not be loaded. {error}"))
            })?
            .into();
    let required = WEBAUTHN_API_VERSION_9.cast_unsigned();
    // SAFETY: each type is the webauthn.h signature of the export it is resolved from, and
    // `WebAuthn` keeps `lib` loaded for as long as the copied pointers are used.
    unsafe {
        let version =
            resolve::<WebAuthNGetApiVersionNumber>(&lib, "WebAuthNGetApiVersionNumber")?();
        if version < required {
            return Err(SealError::Unsupported(format!(
                "webauthn API version {version} is below the required {required}"
            )));
        }
        Ok(WebAuthn {
            uv_available: resolve(
                &lib,
                "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
            )?,
            get_authenticator_list: resolve(&lib, "WebAuthNGetAuthenticatorList")?,
            free_authenticator_list: resolve(&lib, "WebAuthNFreeAuthenticatorList")?,
            get_error_name: resolve(&lib, "WebAuthNGetErrorName").ok(),
            _lib: lib,
        })
    }
}

/// Reports whether Windows Hello can back a sealed store on this machine.
pub(crate) fn available() -> Result<(), SealError> {
    let api = load()?;
    platform_authenticator_available(&api)?;
    select_hello_authenticator(&api)?;
    Ok(())
}

fn platform_authenticator_available(api: &WebAuthn) -> Result<(), SealError> {
    let mut available: BOOL = 0;
    // SAFETY: the out pointer is a valid, writable BOOL.
    let hr = unsafe { (api.uv_available)(&mut available) };
    if hr != S_OK {
        return Err(hr_error(
            api,
            hr,
            "query platform authenticator availability",
        ));
    }
    if available == 0 {
        return Err(SealError::Unsupported(
            "no user-verifying platform authenticator available".into(),
        ));
    }
    Ok(())
}

/// The identifier of the one Windows Hello authenticator WebAuthn lists.
fn select_hello_authenticator(api: &WebAuthn) -> Result<Vec<u8>, SealError> {
    let options = WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION.cast_unsigned(),
    };
    let mut list: PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST = std::ptr::null_mut();
    // SAFETY: `options` and the out pointer are live locals.
    let hr = unsafe { (api.get_authenticator_list)(&options, &mut list) };
    if hr != S_OK && hr != NTE_NOT_FOUND {
        return Err(hr_error(api, hr, "enumerate authenticators"));
    }
    let empty = WEBAUTHN_AUTHENTICATOR_DETAILS_LIST::default();
    // SAFETY: a non-null list from WebAuthNGetAuthenticatorList stays valid until the free
    // call below, and the empty list holds no entries.
    let selected = unsafe { hello_authenticator_id(list.as_ref().unwrap_or(&empty)) };
    if !list.is_null() {
        // SAFETY: `list` was allocated by webauthn.dll and is freed exactly once.
        unsafe { (api.free_authenticator_list)(list) };
    }
    selected
}

/// Picks the single Windows Hello entry of an authenticator list, by name.
///
/// # Safety
/// `list` must hold `cAuthenticatorDetails` entry pointers, each null or a valid entry whose
/// identifier bytes and NUL-terminated name, at any alignment, live as long as `list`.
unsafe fn hello_authenticator_id(
    list: &WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
) -> Result<Vec<u8>, SealError> {
    let mut ids: Vec<Vec<u8>> = Vec::new();
    let mut locked = false;
    // SAFETY: the caller guarantees the entry pointers.
    for entry in unsafe { native_entries(list.cAuthenticatorDetails, list.ppAuthenticatorDetails) }
    {
        // SAFETY: the caller guarantees a NUL-terminated name, read without alignment.
        if !unsafe { from_wstr(entry.pwszAuthenticatorName) }.eq_ignore_ascii_case(HELLO_NAME) {
            continue;
        }
        if entry.cbAuthenticatorId == 0 || entry.pbAuthenticatorId.is_null() {
            continue;
        }
        // SAFETY: the caller guarantees `cbAuthenticatorId` readable bytes.
        let id = unsafe {
            std::slice::from_raw_parts(entry.pbAuthenticatorId, entry.cbAuthenticatorId as usize)
        };
        locked |= entry.bLocked != 0;
        if !ids.iter().any(|existing| existing == id) {
            ids.push(id.to_vec());
        }
    }
    match ids.len() {
        0 => Err(SealError::Unsupported(
            "Windows Hello authenticator not found in the WebAuthn authenticator enumeration"
                .into(),
        )),
        1 if locked => Err(SealError::Locked),
        1 => Ok(ids.remove(0)),
        count => Err(SealError::Conflict(format!(
            "{count} Windows Hello authenticators enumerated, expected one"
        ))),
    }
}

fn hr_error(api: &WebAuthn, hr: HRESULT, operation: &str) -> SealError {
    let name = api
        .get_error_name
        // SAFETY: the export returns null or a static NUL-terminated string.
        .map(|get_error_name| unsafe { from_wstr(get_error_name(hr)) })
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".into());
    SealError::Platform(format!("{operation} failed with {name} (0x{hr:08X})"))
}

/// Non-null entries of a native array of `count` entry pointers.
///
/// # Safety
/// `entries` must hold `count` pointers, each null or valid for `'a`.
unsafe fn native_entries<'a, T: 'a>(
    count: u32,
    entries: *const *mut T,
) -> impl Iterator<Item = &'a T> {
    // SAFETY: the caller guarantees `count` readable pointers, each null or valid for `'a`.
    (0..count as usize).filter_map(move |index| unsafe { (*entries.add(index)).as_ref() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::WEBAUTHN_AUTHENTICATOR_DETAILS;

    /// An authenticator list whose entries and strings live in Rust buffers.
    struct FakeList {
        _names: Vec<Vec<u8>>,
        _ids: Vec<Vec<u8>>,
        entries: Vec<WEBAUTHN_AUTHENTICATOR_DETAILS>,
        pointers: Vec<*mut WEBAUTHN_AUTHENTICATOR_DETAILS>,
    }

    impl FakeList {
        /// Builds entries of `(name, id, locked)`, each name stored at an odd address.
        fn new(authenticators: &[(&str, &[u8], bool)]) -> Self {
            let mut names = Vec::new();
            let mut ids = Vec::new();
            let mut entries = Vec::new();
            for &(name, id, locked) in authenticators {
                let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
                let mut bytes = vec![0u8; units.len() * 2 + 1];
                let start = 1 - bytes.as_ptr() as usize % 2;
                for (at, unit) in units.iter().enumerate() {
                    bytes[start + 2 * at..start + 2 * at + 2].copy_from_slice(&unit.to_ne_bytes());
                }
                let mut id = id.to_vec();
                entries.push(WEBAUTHN_AUTHENTICATOR_DETAILS {
                    dwVersion: 1,
                    cbAuthenticatorId: u32::try_from(id.len()).unwrap(),
                    pbAuthenticatorId: id.as_mut_ptr(),
                    pwszAuthenticatorName: bytes[start..].as_ptr().cast(),
                    bLocked: BOOL::from(locked),
                    ..Default::default()
                });
                names.push(bytes);
                ids.push(id);
            }
            let pointers = entries.iter_mut().map(std::ptr::from_mut).collect();
            Self {
                _names: names,
                _ids: ids,
                entries,
                pointers,
            }
        }

        fn select(&mut self) -> Result<Vec<u8>, SealError> {
            let list = WEBAUTHN_AUTHENTICATOR_DETAILS_LIST {
                cAuthenticatorDetails: u32::try_from(self.entries.len()).unwrap(),
                ppAuthenticatorDetails: self.pointers.as_mut_ptr(),
            };
            // SAFETY: every entry, identifier and name is owned by `self` for the call.
            unsafe { hello_authenticator_id(&list) }
        }
    }

    #[test]
    fn windows_hello_is_selected_by_name_at_any_alignment() {
        let mut list = FakeList::new(&[
            ("Security Key", &[1], false),
            ("windows hello", &[2, 3], false),
        ]);
        assert_eq!(list.select(), Ok(vec![2, 3]));
    }

    #[test]
    fn missing_or_identifierless_hello_is_unsupported() {
        for authenticators in [
            &[][..],
            &[("Security Key", &[1][..], false)][..],
            &[("Windows Hello", &[][..], false)][..],
        ] {
            assert!(matches!(
                FakeList::new(authenticators).select(),
                Err(SealError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn a_locked_hello_authenticator_is_reported_locked() {
        let mut list = FakeList::new(&[("Windows Hello", &[4], true)]);
        assert_eq!(list.select(), Err(SealError::Locked));
    }

    #[test]
    fn several_distinct_hello_authenticators_conflict() {
        let mut duplicate = FakeList::new(&[
            ("Windows Hello", &[5], false),
            ("Windows Hello", &[5], false),
        ]);
        assert_eq!(duplicate.select(), Ok(vec![5]));
        let mut distinct = FakeList::new(&[
            ("Windows Hello", &[5], false),
            ("Windows Hello", &[6], false),
        ]);
        assert!(matches!(distinct.select(), Err(SealError::Conflict(_))));
    }
}
