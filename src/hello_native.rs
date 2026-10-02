//! Win32 WebAuthn native backend for the optional Windows Hello PRF gate.
//!
//! `webauthn.dll` is loaded dynamically for every call, so a machine without
//! the WebAuthn API or below API version 9 reports
//! [crate::hello::HelloError::Unsupported] instead of failing to link.
//!
//! Both operations require user verification, use the raw 32-byte PRF salt,
//! and bind to the genuine Windows Hello platform authenticator selected by
//! name and id from the API 9 authenticator enumeration. The caller runs the
//! blocking call on its own thread, keeps the owner window alive, and drives
//! bounded cancellation through [HelloCancellation].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use getrandom::fill;
use libloading::{
    Library,
    os::windows::{LOAD_LIBRARY_SEARCH_SYSTEM32, Library as WindowsLibrary},
};
use zeroize::Zeroizing;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;

use crate::hello::{HelloError, MAX_CREDENTIAL_ID};

const API_VERSION_REQUIRED: u32 = 9;
const MAKE_OPTIONS_VERSION: u32 = 9;
const GET_OPTIONS_VERSION: u32 = 9;
// PRF fields (pHmacSecret) exist from attestation 7 and assertion 3.
const ATTESTATION_VERSION_MIN: u32 = 7;
const ASSERTION_VERSION_MIN: u32 = 3;
const HMAC_SECRET_LENGTH: u32 = 32;
const RAW_SALT_FLAG: u32 = 0x00100000;
const TRANSPORT_INTERNAL: u32 = 0x0000_0010;
const ATTACHMENT_PLATFORM: u32 = 1;
const UV_REQUIREMENT_REQUIRED: u32 = 1;
const ATTESTATION_CONVEYANCE_NONE: u32 = 1;
const ALG_ES256: i32 = -7;
// authenticatorData is 32-byte rpIdHash plus a flags byte plus a counter.
const AUTHENTICATOR_DATA_HEADER_LEN: u32 = 37;
const AUTHENTICATOR_DATA_FLAGS_OFFSET: usize = 32;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
// HRESULTs from the webauthn.h WebAuthNGetErrorName error table.
const S_OK: i32 = 0;
const NTE_NOT_FOUND: i32 = 0x8009_0011u32.cast_signed();
const NTE_USER_CANCELLED: i32 = 0x8009_0121u32.cast_signed();
const ERROR_CANCELLED_HRESULT: i32 = 0x8007_04C7u32.cast_signed();
const ERROR_TIMEOUT_HRESULT: i32 = 0x8007_0584u32.cast_signed();
const HELLO_NAME: &str = "Windows Hello";

/// A live window that may anchor a Windows Hello prompt.
///
/// Implementors must be kept owned in the caller's `Arc` and must keep the
/// actual OS window alive for the whole operation. `hwnd` is that window's
/// handle, not a copy of a window the caller is not keeping alive.
pub trait HelloWindow: Send + Sync {
    fn hwnd(&self) -> HWND;
}

/// Shared cancellation state for one or more in-flight Hello operations.
///
/// Clones observe and drive the same flag and the same native cancellation
/// id. [HelloCancellation::cancel] is safe to call from another thread while
/// the blocking native call is running.
#[derive(Clone)]
pub struct HelloCancellation {
    inner: Arc<CancellationState>,
}

struct CancellationState {
    cancelled: AtomicBool,
    active: Mutex<Option<Guid>>,
}

impl Default for HelloCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloCancellation {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                active: Mutex::new(None),
            }),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        // Set the flag before delivering to native so any concurrent reader
        // sees the cancellation even if the native call already returned.
        if self.inner.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(guid) = self.active_guid() else {
            return;
        };
        let Ok(lib) = load_system_webauthn() else {
            return;
        };
        let Ok(symbol) =
            (unsafe { lib.get::<CancelCurrentOperation>(b"WebAuthNCancelCurrentOperation") })
        else {
            return;
        };
        // A copied function pointer is stable for the process lifetime.
        let cancel = *symbol;
        let _ = unsafe { cancel(&guid) };
    }

    fn install_active(&self, guid: Guid) {
        *self.lock_active() = Some(guid);
    }

    fn clear_active(&self) {
        *self.lock_active() = None;
    }

    fn active_guid(&self) -> Option<Guid> {
        *self.lock_active()
    }

    fn lock_active(&self) -> MutexGuard<'_, Option<Guid>> {
        // A poisoned lock leaves no state this type depends on, so recover the guard.
        self.inner
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Result of one successful Hello PRF enrollment.
pub(crate) struct Enrollment {
    pub credential_id: Vec<u8>,
    pub key: Zeroizing<[u8; 32]>,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct RpEntity {
    version: u32,
    id: *const u16,
    name: *const u16,
    icon: *const u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct UserEntity {
    version: u32,
    cb_id: u32,
    pb_id: *const u8,
    name: *const u16,
    icon: *const u16,
    display_name: *const u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CoseParam {
    version: u32,
    credential_type: *const u16,
    alg: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CoseParams {
    count: u32,
    params: *const CoseParam,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ClientData {
    version: u32,
    cb_json: u32,
    pb_json: *const u8,
    hash_alg_id: *const u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Credential {
    version: u32,
    cb_id: u32,
    pb_id: *const u8,
    credential_type: *const u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Credentials {
    count: u32,
    credentials: *const Credential,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Extensions {
    count: u32,
    extensions: *const (),
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CredentialEx {
    version: u32,
    cb_id: u32,
    pb_id: *const u8,
    credential_type: *const u16,
    transports: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CredentialList {
    count: u32,
    // WEBAUTHN_CREDENTIAL_LIST holds an array of pointers, not inline structs.
    credentials: *const *const CredentialEx,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct HmacSalt {
    cb_first: u32,
    pb_first: *const u8,
    cb_second: u32,
    pb_second: *const u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct HmacSaltValues {
    global_salt: *const HmacSalt,
    count_with_salt: u32,
    with_salt_list: *const (),
}

#[derive(Clone, Copy)]
#[repr(C)]
struct MakeOptions {
    version: u32,
    timeout_ms: u32,
    credential_list: Credentials,
    extensions: Extensions,
    authenticator_attachment: u32,
    require_resident_key: i32,
    uv_requirement: u32,
    attestation_conveyance: u32,
    flags: u32,
    cancellation_id: *const Guid,
    exclude_credential_list: *const CredentialList,
    enterprise_attestation: u32,
    large_blob_support: u32,
    prefer_resident_key: i32,
    browser_in_private_mode: i32,
    enable_prf: i32,
    linked_device: *const (),
    cb_json_ext: u32,
    pb_json_ext: *const u8,
    prf_global_eval: *const HmacSalt,
    credential_hints_count: u32,
    credential_hints: *const *const u16,
    third_party_payment: i32,
    remote_web_origin: *const u16,
    cb_creation_options_json: u32,
    pb_creation_options_json: *const u8,
    cb_authenticator_id: u32,
    pb_authenticator_id: *const u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct GetOptions {
    version: u32,
    timeout_ms: u32,
    credential_list: Credentials,
    extensions: Extensions,
    authenticator_attachment: u32,
    uv_requirement: u32,
    flags: u32,
    u2f_app_id: *const u16,
    u2f_app_id_used: *mut i32,
    cancellation_id: *const Guid,
    allow_credential_list: *const CredentialList,
    cred_large_blob_operation: u32,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *const u8,
    hmac_secret_salt_values: *const HmacSaltValues,
    browser_in_private_mode: i32,
    linked_device: *const (),
    auto_fill: i32,
    cb_json_ext: u32,
    pb_json_ext: *const u8,
    credential_hints_count: u32,
    credential_hints: *const *const u16,
    remote_web_origin: *const u16,
    cb_request_options_json: u32,
    pb_request_options_json: *const u8,
    cb_authenticator_id: u32,
    pb_authenticator_id: *const u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Attestation {
    version: u32,
    format_type: *const u16,
    cb_authenticator_data: u32,
    pb_authenticator_data: *const u8,
    cb_attestation: u32,
    pb_attestation: *const u8,
    attestation_decode_type: u32,
    attestation_decode: *const (),
    cb_attestation_object: u32,
    pb_attestation_object: *const u8,
    cb_credential_id: u32,
    pb_credential_id: *const u8,
    extensions: Extensions,
    used_transport: u32,
    ep_att: i32,
    large_blob_supported: i32,
    resident_key: i32,
    prf_enabled: i32,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *const u8,
    hmac_secret: *const HmacSalt,
    third_party_payment: i32,
    transports: u32,
    cb_client_data_json: u32,
    pb_client_data_json: *const u8,
    cb_registration_response_json: u32,
    pb_registration_response_json: *const u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Assertion {
    version: u32,
    cb_authenticator_data: u32,
    pb_authenticator_data: *const u8,
    cb_signature: u32,
    pb_signature: *const u8,
    credential: Credential,
    cb_user_id: u32,
    pb_user_id: *const u8,
    extensions: Extensions,
    cb_cred_large_blob: u32,
    pb_cred_large_blob: *const u8,
    cred_large_blob_status: u32,
    hmac_secret: *const HmacSalt,
    used_transport: u32,
    cb_unsigned_extension_outputs: u32,
    pb_unsigned_extension_outputs: *const u8,
    cb_client_data_json: u32,
    pb_client_data_json: *const u8,
    cb_authentication_response_json: u32,
    pb_authentication_response_json: *const u8,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct GetCredentialsOptions {
    version: u32,
    rp_id: *const u16,
    browser_in_private_mode: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CredentialDetails {
    version: u32,
    cb_credential_id: u32,
    pb_credential_id: *const u8,
    rp_information: *const RpEntity,
    user_information: *const UserEntity,
    removable: i32,
    backed_up: i32,
    authenticator_name: *const u16,
    cb_authenticator_logo: u32,
    pb_authenticator_logo: *const u8,
    third_party_payment: i32,
    transports: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CredentialDetailsList {
    count: u32,
    details: *const *const CredentialDetails,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AuthenticatorDetailsOptions {
    version: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AuthenticatorDetails {
    version: u32,
    cb_authenticator_id: u32,
    pb_authenticator_id: *const u8,
    authenticator_name: *const u16,
    cb_authenticator_logo: u32,
    pb_authenticator_logo: *const u8,
    locked: i32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AuthenticatorDetailsList {
    count: u32,
    details: *const *const AuthenticatorDetails,
}

type GetApiVersionNumber = unsafe extern "system" fn() -> u32;
type UvAvailable = unsafe extern "system" fn(*mut i32) -> i32;
type MakeCredential = unsafe extern "system" fn(
    HWND,
    *const RpEntity,
    *const UserEntity,
    *const CoseParams,
    *const ClientData,
    *const MakeOptions,
    *mut *const Attestation,
) -> i32;
type GetAssertion = unsafe extern "system" fn(
    HWND,
    *const u16,
    *const ClientData,
    *const GetOptions,
    *mut *const Assertion,
) -> i32;
type FreeAttestation = unsafe extern "system" fn(*const Attestation);
type FreeAssertion = unsafe extern "system" fn(*const Assertion);
type GetCancellationId = unsafe extern "system" fn(*mut Guid) -> i32;
type CancelCurrentOperation = unsafe extern "system" fn(*const Guid) -> i32;
type GetPlatformCredentialList = unsafe extern "system" fn(
    *const GetCredentialsOptions,
    *mut *const CredentialDetailsList,
) -> i32;
type FreePlatformCredentialList = unsafe extern "system" fn(*const CredentialDetailsList);
type GetAuthenticatorList = unsafe extern "system" fn(
    *const AuthenticatorDetailsOptions,
    *mut *const AuthenticatorDetailsList,
) -> i32;
type FreeAuthenticatorList = unsafe extern "system" fn(*const AuthenticatorDetailsList);
type DeletePlatformCredential = unsafe extern "system" fn(u32, *const u8) -> i32;
type GetErrorName = unsafe extern "system" fn(i32) -> *const u16;

/// Dynamic binding to webauthn.dll, copied out as process-stable pointers.
struct WebAuthn {
    // Keeps webauthn.dll loaded for the lifetime of this value.
    _lib: Library,
    uv_available: UvAvailable,
    make_credential: MakeCredential,
    get_assertion: GetAssertion,
    free_attestation: FreeAttestation,
    free_assertion: FreeAssertion,
    get_cancellation_id: GetCancellationId,
    get_platform_credential_list: GetPlatformCredentialList,
    free_platform_credential_list: FreePlatformCredentialList,
    get_authenticator_list: GetAuthenticatorList,
    free_authenticator_list: FreeAuthenticatorList,
    delete_platform_credential: DeletePlatformCredential,
    get_error_name: GetErrorName,
}

macro_rules! resolve_symbol {
    ($lib:expr, $ty:ty, $name:literal) => {{
        // A copied function pointer is stable for the process lifetime.
        let symbol = (unsafe { $lib.get::<$ty>($name.as_bytes()) }).map_err(|_| {
            HelloError::Unsupported(
                concat!("webauthn.dll is missing the ", $name, " export").into(),
            )
        })?;
        *symbol
    }};
}

fn load_system_webauthn() -> Result<Library, libloading::Error> {
    // System32-only lookup prevents application-path DLL substitution.
    unsafe { WindowsLibrary::load_with_flags("webauthn.dll", LOAD_LIBRARY_SEARCH_SYSTEM32) }
        .map(Into::into)
}

fn load() -> Result<WebAuthn, HelloError> {
    let lib = load_system_webauthn().map_err(|error| {
        HelloError::Unsupported(format!("webauthn.dll could not be loaded. {error}"))
    })?;
    let api_version_number =
        resolve_symbol!(lib, GetApiVersionNumber, "WebAuthNGetApiVersionNumber");
    // SAFETY: the call takes no arguments and returns a version number.
    let version = unsafe { api_version_number() };
    if version < API_VERSION_REQUIRED {
        return Err(HelloError::Unsupported(format!(
            "webauthn API version {version} is below the required {API_VERSION_REQUIRED}"
        )));
    }
    let uv_available = resolve_symbol!(
        lib,
        UvAvailable,
        "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable"
    );
    let make_credential =
        resolve_symbol!(lib, MakeCredential, "WebAuthNAuthenticatorMakeCredential");
    let get_assertion = resolve_symbol!(lib, GetAssertion, "WebAuthNAuthenticatorGetAssertion");
    let free_attestation =
        resolve_symbol!(lib, FreeAttestation, "WebAuthNFreeCredentialAttestation");
    let free_assertion = resolve_symbol!(lib, FreeAssertion, "WebAuthNFreeAssertion");
    let get_cancellation_id = resolve_symbol!(lib, GetCancellationId, "WebAuthNGetCancellationId");
    let get_platform_credential_list = resolve_symbol!(
        lib,
        GetPlatformCredentialList,
        "WebAuthNGetPlatformCredentialList"
    );
    let free_platform_credential_list = resolve_symbol!(
        lib,
        FreePlatformCredentialList,
        "WebAuthNFreePlatformCredentialList"
    );
    let get_authenticator_list =
        resolve_symbol!(lib, GetAuthenticatorList, "WebAuthNGetAuthenticatorList");
    let free_authenticator_list =
        resolve_symbol!(lib, FreeAuthenticatorList, "WebAuthNFreeAuthenticatorList");
    let delete_platform_credential = resolve_symbol!(
        lib,
        DeletePlatformCredential,
        "WebAuthNDeletePlatformCredential"
    );
    let get_error_name = resolve_symbol!(lib, GetErrorName, "WebAuthNGetErrorName");
    Ok(WebAuthn {
        _lib: lib,
        uv_available,
        make_credential,
        get_assertion,
        free_attestation,
        free_assertion,
        get_cancellation_id,
        get_platform_credential_list,
        free_platform_credential_list,
        get_authenticator_list,
        free_authenticator_list,
        delete_platform_credential,
        get_error_name,
    })
}

/// Owns native scratch buffers not borrowed from the operation frame.
struct NativeBuffers {
    bytes: Vec<Vec<u8>>,
    wide: Vec<Vec<u16>>,
}

impl NativeBuffers {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            wide: Vec::new(),
        }
    }

    fn add_bytes_owned(&mut self, block: Vec<u8>) -> *const u8 {
        let ptr = block.as_ptr();
        self.bytes.push(block);
        ptr
    }

    fn add_wide(&mut self, text: &str) -> *const u16 {
        let mut block: Vec<u16> = text.encode_utf16().collect();
        block.push(0);
        let ptr = block.as_ptr();
        self.wide.push(block);
        ptr
    }
}

/// Reports whether the Hello PRF gate is usable on this machine.
pub(crate) fn available() -> Result<(), HelloError> {
    let api = load()?;
    platform_authenticator_available(&api)?;
    select_hello_authenticator(&api)?;
    Ok(())
}

/// Enrolls the Hello PRF credential for `rp_id` under the caller-provided
/// `user_id` and raw `salt`.
pub(crate) fn enroll(
    owner: Arc<dyn HelloWindow>,
    rp_id: &str,
    user_id: &[u8; 32],
    salt: &[u8; 32],
    cancel: &HelloCancellation,
    timeout: Duration,
) -> Result<Enrollment, HelloError> {
    let hwnd = live_owner_window(&owner)?;
    if cancel.is_cancelled() {
        return Err(HelloError::Cancelled);
    }
    let api = load()?;
    platform_authenticator_available(&api)?;
    let selector = select_hello_authenticator(&api)?;
    let guid = get_cancellation_id(&api)?;
    let selector_len = u32::try_from(selector.id.len())
        .map_err(|_| HelloError::Corrupt("authenticator ID is too long".into()))?;

    let mut bufs = NativeBuffers::new();
    let rp = build_rp_entity(&mut bufs, rp_id);
    let rp_ptr = &rp;
    let user = UserEntity {
        version: 1,
        cb_id: 32,
        pb_id: user_id.as_ptr(),
        name: bufs.add_wide("hello-prf-store"),
        icon: std::ptr::null(),
        display_name: bufs.add_wide("Windows Hello PRF Store"),
    };
    let user_ptr = &user;
    let param = CoseParam {
        version: 1,
        credential_type: bufs.add_wide("public-key"),
        alg: ALG_ES256,
    };
    let param_ptr = &param;
    let params = CoseParams {
        count: 1,
        params: param_ptr,
    };
    let params_ptr = &params;
    let client = build_client_data(&mut bufs, "create", rp_id)?;
    let client_ptr = &client;
    let cancellation_ptr = &guid;
    let salt_value = HmacSalt {
        cb_first: HMAC_SECRET_LENGTH,
        pb_first: salt.as_ptr(),
        cb_second: 0,
        pb_second: std::ptr::null(),
    };
    let salt_ptr = &salt_value;
    let selector_id = selector.id.as_ptr();
    let options = MakeOptions {
        version: MAKE_OPTIONS_VERSION,
        timeout_ms: timeout_ms(timeout),
        credential_list: Credentials {
            count: 0,
            credentials: std::ptr::null(),
        },
        extensions: Extensions {
            count: 0,
            extensions: std::ptr::null(),
        },
        authenticator_attachment: ATTACHMENT_PLATFORM,
        require_resident_key: 0,
        uv_requirement: UV_REQUIREMENT_REQUIRED,
        attestation_conveyance: ATTESTATION_CONVEYANCE_NONE,
        flags: RAW_SALT_FLAG,
        cancellation_id: cancellation_ptr,
        exclude_credential_list: std::ptr::null(),
        enterprise_attestation: 0,
        large_blob_support: 0,
        prefer_resident_key: 0,
        browser_in_private_mode: 0,
        enable_prf: 1,
        linked_device: std::ptr::null(),
        cb_json_ext: 0,
        pb_json_ext: std::ptr::null(),
        prf_global_eval: salt_ptr,
        credential_hints_count: 0,
        credential_hints: std::ptr::null(),
        third_party_payment: 0,
        remote_web_origin: std::ptr::null(),
        cb_creation_options_json: 0,
        pb_creation_options_json: std::ptr::null(),
        cb_authenticator_id: selector_len,
        pb_authenticator_id: selector_id,
    };
    let options_ptr = &options;

    cancel.install_active(guid);
    if cancel.is_cancelled() {
        cancel.clear_active();
        return Err(HelloError::Cancelled);
    }
    // The owner Arc outlives the blocking native call.
    let mut attestation: *const Attestation = std::ptr::null();
    // SAFETY: every pointer passed in is owned by bufs or the stack and stays
    // valid until the call returns. The out pointer is initialized.
    let hr = unsafe {
        (api.make_credential)(
            hwnd,
            rp_ptr,
            user_ptr,
            params_ptr,
            client_ptr,
            options_ptr,
            &mut attestation,
        )
    };
    cancel.clear_active();
    if hr != S_OK {
        delete_created_credential(&api, rp_id, user_id)?;
        return Err(operation_error(&api, hr, "make credential", cancel));
    }
    let outcome = if attestation.is_null() {
        Err(HelloError::Corrupt(
            "make credential returned a null attestation".into(),
        ))
    } else {
        // SAFETY: a successful make returns a valid, non-null attestation.
        read_attestation(unsafe { &*attestation })
    };
    if !attestation.is_null() {
        // SAFETY: webauthn.dll allocated this attestation and owns its free function.
        unsafe { (api.free_attestation)(attestation) };
    }
    match outcome {
        Ok((credential_id, key)) => Ok(Enrollment { credential_id, key }),
        Err(error) => {
            delete_created_credential(&api, rp_id, user_id)?;
            Err(error)
        }
    }
}

/// Asserts the enrolled credential and returns the PRF-derived 32-byte key.
pub(crate) fn assert_prf(
    owner: Arc<dyn HelloWindow>,
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; 32],
    cancel: &HelloCancellation,
    timeout: Duration,
) -> Result<Zeroizing<[u8; 32]>, HelloError> {
    let hwnd = live_owner_window(&owner)?;
    if cancel.is_cancelled() {
        return Err(HelloError::Cancelled);
    }
    let api = load()?;
    platform_authenticator_available(&api)?;
    let selector = select_hello_authenticator(&api)?;
    let guid = get_cancellation_id(&api)?;
    let selector_len = u32::try_from(selector.id.len())
        .map_err(|_| HelloError::Corrupt("authenticator ID is too long".into()))?;
    let credential_len = u32::try_from(credential_id.len())
        .map_err(|_| HelloError::Corrupt("credential ID is too long".into()))?;

    let mut bufs = NativeBuffers::new();
    let client = build_client_data(&mut bufs, "get", rp_id)?;
    let client_ptr = &client;
    let credential_ex = CredentialEx {
        version: 1,
        cb_id: credential_len,
        pb_id: credential_id.as_ptr(),
        credential_type: bufs.add_wide("public-key"),
        // 0 means no transport restriction, since the authenticator id binding routes the call.
        transports: 0,
    };
    let credential_ptr: *const CredentialEx = &credential_ex;
    let allow_array = [credential_ptr];
    let allow_array_ptr = allow_array.as_ptr();
    let allow_list = CredentialList {
        count: 1,
        credentials: allow_array_ptr,
    };
    let allow_list_ptr = &allow_list;
    let first = HmacSalt {
        cb_first: HMAC_SECRET_LENGTH,
        pb_first: salt.as_ptr(),
        cb_second: 0,
        pb_second: std::ptr::null(),
    };
    let first_ptr = &first;
    let salt_values = HmacSaltValues {
        global_salt: first_ptr,
        count_with_salt: 0,
        with_salt_list: std::ptr::null(),
    };
    let salt_values_ptr = &salt_values;
    let cancellation_ptr = &guid;
    let selector_id = selector.id.as_ptr();
    let options = GetOptions {
        version: GET_OPTIONS_VERSION,
        timeout_ms: timeout_ms(timeout),
        credential_list: Credentials {
            count: 0,
            credentials: std::ptr::null(),
        },
        extensions: Extensions {
            count: 0,
            extensions: std::ptr::null(),
        },
        authenticator_attachment: ATTACHMENT_PLATFORM,
        uv_requirement: UV_REQUIREMENT_REQUIRED,
        flags: RAW_SALT_FLAG,
        u2f_app_id: std::ptr::null(),
        u2f_app_id_used: std::ptr::null_mut(),
        cancellation_id: cancellation_ptr,
        allow_credential_list: allow_list_ptr,
        cred_large_blob_operation: 0,
        cb_cred_large_blob: 0,
        pb_cred_large_blob: std::ptr::null(),
        hmac_secret_salt_values: salt_values_ptr,
        browser_in_private_mode: 0,
        linked_device: std::ptr::null(),
        auto_fill: 0,
        cb_json_ext: 0,
        pb_json_ext: std::ptr::null(),
        credential_hints_count: 0,
        credential_hints: std::ptr::null(),
        remote_web_origin: std::ptr::null(),
        cb_request_options_json: 0,
        pb_request_options_json: std::ptr::null(),
        cb_authenticator_id: selector_len,
        pb_authenticator_id: selector_id,
    };
    let options_ptr = &options;
    let rp_wide = bufs.add_wide(rp_id);

    cancel.install_active(guid);
    if cancel.is_cancelled() {
        cancel.clear_active();
        return Err(HelloError::Cancelled);
    }
    let mut assertion: *const Assertion = std::ptr::null();
    // SAFETY: every pointer passed in is owned by bufs or the stack and stays
    // valid until the call returns. The out pointer is initialized.
    let hr = unsafe { (api.get_assertion)(hwnd, rp_wide, client_ptr, options_ptr, &mut assertion) };
    cancel.clear_active();
    if hr != S_OK {
        return Err(operation_error(&api, hr, "get assertion", cancel));
    }
    if assertion.is_null() {
        return Err(HelloError::Corrupt(
            "get assertion returned a null assertion".into(),
        ));
    }
    // SAFETY: a successful get returns a valid, non-null assertion.
    let outcome = read_assertion(unsafe { &*assertion }, credential_id);
    // SAFETY: assertion was allocated by webauthn.dll and is freed here.
    unsafe { (api.free_assertion)(assertion) };
    outcome
}

/// Finds the platform credential created for exactly `rp_id` and `user_id`.
///
/// Used at startup to salvage a credential left behind by a crashed
/// enrollment. Returns an error when more than one credential matches.
pub(crate) fn recover_created(
    rp_id: &str,
    user_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, HelloError> {
    let api = load()?;
    let entries = list_platform_credentials(&api, rp_id)?;
    let mut matches = entries.iter().filter(|entry| {
        entry.rp_id.as_deref() == Some(rp_id)
            && entry.user_id.as_deref() == Some(user_id.as_slice())
            && !entry.credential_id.is_empty()
    });
    let Some(first) = matches.next() else {
        return Ok(None);
    };
    let additional = matches.count();
    if additional != 0 {
        return Err(HelloError::Conflict(format!(
            "{} platform credentials match the exact RP and user id",
            additional + 1
        )));
    }
    Ok(Some(first.credential_id.clone()))
}

/// Deletes the platform credential with the exact `credential_id`.
///
/// A credential that is already absent is not an error, and the removal is
/// verified through the exact RP filter before returning.
pub(crate) fn remove_exact(rp_id: &str, credential_id: &[u8]) -> Result<(), HelloError> {
    let api = load()?;
    delete_credential(&api, credential_id)?;
    let entries = list_platform_credentials(&api, rp_id)?;
    if entries
        .iter()
        .any(|entry| entry.credential_id.as_slice() == credential_id)
    {
        return Err(HelloError::Corrupt(
            "credential still listed after successful deletion".into(),
        ));
    }
    Ok(())
}

/// Deletes every platform credential listed under exactly `rp_id`, verifying their absence.
///
/// The RP identifier is derived from one store's identity, so it cannot match another store.
pub(crate) fn remove_all_for_rp(rp_id: &str) -> Result<(), HelloError> {
    let api = match load() {
        Ok(api) => api,
        // Enrollment requires this API, so no credential for the store can exist without it.
        Err(HelloError::Unsupported(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let owned = |entry: &ListedCredential| {
        entry.rp_id.as_deref() == Some(rp_id) && !entry.credential_id.is_empty()
    };
    for entry in list_platform_credentials(&api, rp_id)?
        .iter()
        .filter(|entry| owned(entry))
    {
        delete_credential(&api, &entry.credential_id)?;
    }
    if list_platform_credentials(&api, rp_id)?.iter().any(owned) {
        return Err(HelloError::Corrupt(
            "store credential still listed after deletion".into(),
        ));
    }
    Ok(())
}

fn build_rp_entity(bufs: &mut NativeBuffers, rp_id: &str) -> RpEntity {
    RpEntity {
        version: 1,
        id: bufs.add_wide(rp_id),
        name: bufs.add_wide("Windows Hello PRF Store"),
        icon: std::ptr::null(),
    }
}

fn live_owner_window(owner: &Arc<dyn HelloWindow>) -> Result<HWND, HelloError> {
    let hwnd = owner.hwnd();
    // A dead or null owner must fail before any native prompt can appear.
    if unsafe { IsWindow(hwnd) } == 0 {
        return Err(HelloError::MissingOwner);
    }
    Ok(hwnd)
}

fn platform_authenticator_available(api: &WebAuthn) -> Result<(), HelloError> {
    let mut available: i32 = 0;
    // SAFETY: the out pointer is a valid, writable BOOL-sized integer.
    let hr = unsafe { (api.uv_available)(&mut available) };
    if hr != S_OK {
        return Err(hr_error(
            api,
            hr,
            "query platform authenticator availability",
        ));
    }
    if available == 0 {
        return Err(HelloError::Unsupported(
            "no user-verifying platform authenticator available".into(),
        ));
    }
    Ok(())
}

struct HelloSelector {
    id: Vec<u8>,
}

fn select_hello_authenticator(api: &WebAuthn) -> Result<HelloSelector, HelloError> {
    let options = AuthenticatorDetailsOptions { version: 1 };
    let options_ptr = &options;
    let mut list: *const AuthenticatorDetailsList = std::ptr::null();
    // SAFETY: options_ptr points to the live stack local and list is initialized.
    let hr = unsafe { (api.get_authenticator_list)(options_ptr, &mut list) };
    if hr != S_OK && hr != NTE_NOT_FOUND {
        return Err(hr_error(api, hr, "enumerate authenticators"));
    }
    let mut ids: Vec<Vec<u8>> = Vec::new();
    let mut locked = false;
    if !list.is_null() {
        // SAFETY: a non-null list is a valid list until the free call.
        let details = unsafe { &*list };
        for index in 0..details.count {
            // SAFETY: index is within the array length declared by count.
            let entry_ptr = unsafe { *details.details.add(index as usize) };
            if entry_ptr.is_null() {
                continue;
            }
            // SAFETY: non-null entry pointer from the native list.
            let entry = unsafe { &*entry_ptr };
            let name = wide_to_string(entry.authenticator_name);
            if !name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(HELLO_NAME))
            {
                continue;
            }
            if entry.cb_authenticator_id == 0 || entry.pb_authenticator_id.is_null() {
                continue;
            }
            // SAFETY: count and pointer come from the native entry.
            let id: Vec<u8> = unsafe {
                std::slice::from_raw_parts(
                    entry.pb_authenticator_id,
                    entry.cb_authenticator_id as usize,
                )
            }
            .to_vec();
            if entry.locked != 0 {
                locked = true;
            }
            if !ids.iter().any(|existing| existing == &id) {
                ids.push(id);
            }
        }
        // SAFETY: list was allocated by webauthn.dll and is freed here.
        unsafe { (api.free_authenticator_list)(list) };
    }
    match ids.len() {
        0 => Err(HelloError::Unsupported(
            "Windows Hello authenticator not found in the WebAuthn authenticator enumeration"
                .into(),
        )),
        1 => {
            if locked {
                Err(HelloError::Locked)
            } else {
                Ok(HelloSelector {
                    id: ids.into_iter().next().unwrap(),
                })
            }
        }
        _ => Err(HelloError::Conflict(format!(
            "{} Windows Hello authenticators enumerated, expected one",
            ids.len()
        ))),
    }
}

fn get_cancellation_id(api: &WebAuthn) -> Result<Guid, HelloError> {
    let mut guid = Guid {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };
    // SAFETY: the out pointer is a valid, writable GUID-sized struct.
    let hr = unsafe { (api.get_cancellation_id)(&mut guid) };
    if hr == S_OK {
        Ok(guid)
    } else {
        Err(hr_error(api, hr, "get cancellation id"))
    }
}

struct ListedCredential {
    credential_id: Vec<u8>,
    rp_id: Option<String>,
    user_id: Option<Vec<u8>>,
}

fn list_platform_credentials(
    api: &WebAuthn,
    rp_id: &str,
) -> Result<Vec<ListedCredential>, HelloError> {
    let mut bufs = NativeBuffers::new();
    let options = GetCredentialsOptions {
        version: 1,
        rp_id: bufs.add_wide(rp_id),
        browser_in_private_mode: 0,
    };
    let options_ptr = &options;
    let mut list: *const CredentialDetailsList = std::ptr::null();
    // SAFETY: options_ptr points to the live stack local and list is initialized.
    let hr = unsafe { (api.get_platform_credential_list)(options_ptr, &mut list) };
    if hr != S_OK && hr != NTE_NOT_FOUND {
        return Err(hr_error(api, hr, "enumerate platform credentials"));
    }
    let mut entries = Vec::new();
    if !list.is_null() {
        // SAFETY: a non-null list is a valid list until the free call.
        let details = unsafe { &*list };
        for index in 0..details.count {
            // SAFETY: index is within the array length declared by count.
            let entry_ptr = unsafe { *details.details.add(index as usize) };
            if entry_ptr.is_null() {
                continue;
            }
            // SAFETY: non-null entry pointer from the native list.
            let entry = unsafe { &*entry_ptr };
            let credential_id = if entry.cb_credential_id > 0 && !entry.pb_credential_id.is_null() {
                // SAFETY: count and pointer come from the native entry.
                unsafe {
                    std::slice::from_raw_parts(
                        entry.pb_credential_id,
                        entry.cb_credential_id as usize,
                    )
                }
                .to_vec()
            } else {
                Vec::new()
            };
            let entry_rp_id = if entry.rp_information.is_null() {
                None
            } else {
                // SAFETY: nested entity is valid while the list lives.
                wide_to_string(unsafe { (*entry.rp_information).id })
            };
            let entry_user_id = if entry.user_information.is_null() {
                None
            } else {
                // SAFETY: nested entity is valid while the list lives.
                let user = unsafe { *entry.user_information };
                if user.cb_id > 0 && !user.pb_id.is_null() {
                    // SAFETY: count and pointer come from the native entry.
                    Some(
                        unsafe { std::slice::from_raw_parts(user.pb_id, user.cb_id as usize) }
                            .to_vec(),
                    )
                } else {
                    None
                }
            };
            entries.push(ListedCredential {
                credential_id,
                rp_id: entry_rp_id,
                user_id: entry_user_id,
            });
        }
        // SAFETY: list was allocated by webauthn.dll and is freed here.
        unsafe { (api.free_platform_credential_list)(list) };
    }
    Ok(entries)
}

fn delete_credential(api: &WebAuthn, credential_id: &[u8]) -> Result<(), HelloError> {
    let cb = u32::try_from(credential_id.len())
        .map_err(|_| HelloError::Corrupt("credential ID is too long".into()))?;
    // SAFETY: the id slice is valid for cb bytes for the call duration.
    let hr = unsafe { (api.delete_platform_credential)(cb, credential_id.as_ptr()) };
    match hr {
        S_OK | NTE_NOT_FOUND => Ok(()),
        other => Err(hr_error(api, other, "delete platform credential")),
    }
}

fn delete_created_credential(
    api: &WebAuthn,
    rp_id: &str,
    user_id: &[u8; 32],
) -> Result<(), HelloError> {
    // Only the exact RP and user match is deleted, and no other credential is ever touched.
    let entries = list_platform_credentials(api, rp_id)?;
    for entry in entries.iter().filter(|entry| {
        entry.rp_id.as_deref() == Some(rp_id)
            && entry.user_id.as_deref() == Some(user_id.as_slice())
            && !entry.credential_id.is_empty()
    }) {
        let id = &entry.credential_id;
        delete_credential(api, id)?;
        let after = list_platform_credentials(api, rp_id)?;
        if after
            .iter()
            .any(|entry| entry.credential_id.as_slice() == id.as_slice())
        {
            return Err(HelloError::Platform(
                "own credential still listed after cleanup deletion".into(),
            ));
        }
    }
    Ok(())
}

fn read_attestation(
    attestation: &Attestation,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), HelloError> {
    if attestation.version < ATTESTATION_VERSION_MIN {
        return Err(HelloError::Corrupt(format!(
            "attestation version {} is below the PRF-requiring version {ATTESTATION_VERSION_MIN}",
            attestation.version
        )));
    }
    if attestation.used_transport & TRANSPORT_INTERNAL == 0 {
        return Err(HelloError::Unsupported(
            "make credential did not use the internal Windows Hello transport".into(),
        ));
    }
    if attestation.version >= 8 && attestation.transports & TRANSPORT_INTERNAL == 0 {
        return Err(HelloError::Unsupported(
            "attestation reports no internal Windows Hello transport".into(),
        ));
    }
    if attestation.prf_enabled == 0 {
        return Err(HelloError::Unsupported(
            "Windows Hello credential lacks PRF support".into(),
        ));
    }
    let credential_id =
        read_credential_id(attestation.pb_credential_id, attestation.cb_credential_id)?;
    check_authenticator_data(
        attestation.pb_authenticator_data,
        attestation.cb_authenticator_data,
    )?;
    let key = read_prf_key(attestation.hmac_secret, "make credential")?;
    Ok((credential_id, key))
}

fn read_assertion(
    assertion: &Assertion,
    requested_id: &[u8],
) -> Result<Zeroizing<[u8; 32]>, HelloError> {
    if assertion.version < ASSERTION_VERSION_MIN {
        return Err(HelloError::Corrupt(format!(
            "assertion version {} is below the PRF-requiring version {ASSERTION_VERSION_MIN}",
            assertion.version
        )));
    }
    if assertion.used_transport & TRANSPORT_INTERNAL == 0 {
        return Err(HelloError::Unsupported(
            "get assertion did not use the internal Windows Hello transport".into(),
        ));
    }
    let used_len = assertion.credential.cb_id;
    if used_len as usize != requested_id.len() || assertion.credential.pb_id.is_null() {
        return Err(HelloError::Corrupt(
            "assertion used a different credential id".into(),
        ));
    }
    // SAFETY: used_len equals requested_id.len() at this point.
    let used =
        unsafe { std::slice::from_raw_parts(assertion.credential.pb_id, requested_id.len()) };
    if used != requested_id {
        return Err(HelloError::Corrupt(
            "assertion used a different credential id".into(),
        ));
    }
    check_authenticator_data(
        assertion.pb_authenticator_data,
        assertion.cb_authenticator_data,
    )?;
    read_prf_key(assertion.hmac_secret, "get assertion")
}

fn read_credential_id(ptr: *const u8, len: u32) -> Result<Vec<u8>, HelloError> {
    let length = usize::try_from(len)
        .map_err(|_| HelloError::Corrupt("invalid credential ID length".into()))?;
    if length == 0 || length > MAX_CREDENTIAL_ID || ptr.is_null() {
        return Err(HelloError::Corrupt(format!(
            "credential ID length {len} cannot fit enrollment metadata"
        )));
    }
    // SAFETY: length is bounded by the local credential metadata capacity.
    Ok(unsafe { std::slice::from_raw_parts(ptr, length) }.to_vec())
}

fn check_authenticator_data(data: *const u8, len: u32) -> Result<(), HelloError> {
    if data.is_null() {
        return Err(HelloError::Corrupt(
            "authenticator data pointer is null".into(),
        ));
    }
    if len < AUTHENTICATOR_DATA_HEADER_LEN {
        return Err(HelloError::Corrupt(format!(
            "authenticator data length {len} is below the {AUTHENTICATOR_DATA_HEADER_LEN}-byte header"
        )));
    }
    // SAFETY: the native buffer has at least the fixed header length.
    let header =
        unsafe { std::slice::from_raw_parts(data, AUTHENTICATOR_DATA_HEADER_LEN as usize) };
    let flags = header[AUTHENTICATOR_DATA_FLAGS_OFFSET];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(HelloError::Corrupt(
            "authenticator data lacks the user presence bit".into(),
        ));
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(HelloError::Corrupt(
            "authenticator data lacks the user verification bit".into(),
        ));
    }
    Ok(())
}

fn read_prf_key(
    hmac_secret: *const HmacSalt,
    operation: &str,
) -> Result<Zeroizing<[u8; 32]>, HelloError> {
    if hmac_secret.is_null() {
        return Err(HelloError::Unsupported(format!(
            "{operation} enabled PRF but returned no hmac secret"
        )));
    }
    // SAFETY: a non-null pHmacSecret points at a valid native salt value.
    let salt = unsafe { &*hmac_secret };
    if salt.cb_first != HMAC_SECRET_LENGTH || salt.pb_first.is_null() {
        return Err(HelloError::Unsupported(format!(
            "{operation} returned an hmac secret of {} bytes instead of {HMAC_SECRET_LENGTH}",
            salt.cb_first
        )));
    }
    let mut key = Zeroizing::from([0u8; 32]);
    // SAFETY: cb_first was checked equal to HMAC_SECRET_LENGTH.
    key.as_mut().copy_from_slice(unsafe {
        std::slice::from_raw_parts(salt.pb_first, HMAC_SECRET_LENGTH as usize)
    });
    Ok(key)
}

fn build_client_data(
    bufs: &mut NativeBuffers,
    operation: &str,
    rp_id: &str,
) -> Result<ClientData, HelloError> {
    let mut challenge = [0u8; 32];
    fill(&mut challenge)
        .map_err(|error| HelloError::Platform(format!("challenge randomness failed. {error}")))?;
    let json = format!(
        "{{\"type\":\"webauthn.{operation}\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
        base64url(&challenge),
        json_escape(rp_id),
    );
    let len = json.len();
    debug_assert!(len <= u32::MAX as usize, "client data json fits in a DWORD");
    Ok(ClientData {
        version: 1,
        cb_json: len as u32,
        pb_json: bufs.add_bytes_owned(json.into_bytes()),
        hash_alg_id: bufs.add_wide("SHA-256"),
    })
}

fn operation_error(
    api: &WebAuthn,
    hr: i32,
    operation: &str,
    cancel: &HelloCancellation,
) -> HelloError {
    // The correlated flag wins because our own cancel() or the caller's
    // bounded watchdog may have driven the failure.
    if cancel.is_cancelled() {
        return HelloError::Cancelled;
    }
    match hr {
        NTE_USER_CANCELLED | ERROR_CANCELLED_HRESULT => HelloError::Cancelled,
        ERROR_TIMEOUT_HRESULT => HelloError::TimedOut,
        NTE_NOT_FOUND => HelloError::KeyLost,
        other => hr_error(api, other, operation),
    }
}

fn hr_error(api: &WebAuthn, hr: i32, operation: &str) -> HelloError {
    HelloError::Platform(format!(
        "{operation} failed with {} (0x{hr:08X})",
        error_name(api, hr)
    ))
}

fn error_name(api: &WebAuthn, hr: i32) -> String {
    // SAFETY: the call takes an HRESULT and returns a static native string.
    let ptr = unsafe { (api.get_error_name)(hr) };
    wide_to_string(ptr).unwrap_or_else(|| "unknown".into())
}

fn timeout_ms(timeout: Duration) -> u32 {
    // The native field is a DWORD of milliseconds, so durations beyond about
    // 49 days clamp to the field maximum.
    timeout
        .as_millis()
        .min(u32::MAX as u128)
        .try_into()
        .unwrap_or(u32::MAX)
}

// URL-safe base64 without padding, per the WebAuthn challenge encoding.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(input: &[u8]) -> String {
    // Every index is masked to 6 bits, so it is always in range.
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(BASE64URL[((n >> 18) & 63) as usize] as char);
        out.push(BASE64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL[(n & 63) as usize] as char);
        }
    }
    out
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn wide_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    // SAFETY: the pointer is a native null-terminated wide string owned by
    // the live native structure or by the webauthn.dll error table.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(ptr, len)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cancellation_starts_uncancelled_and_clones_share_state() {
        let cancel = HelloCancellation::new();
        let clone = cancel.clone();
        assert!(!cancel.is_cancelled());
        assert!(!clone.is_cancelled());
        cancel.cancel();
        assert!(cancel.is_cancelled());
        assert!(clone.is_cancelled());
        clone.cancel();
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn cancellation_cancel_before_any_operation_only_sets_the_flag() {
        let cancel = HelloCancellation::new();
        cancel.cancel();
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn base64url_matches_rfc4648_url_alphabet_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(b"\xfb\xff\xbf"), "-_-_");
    }

    #[test]
    fn json_escape_handles_quotes_backslash_and_controls() {
        assert_eq!(json_escape(r#"a"b\c"#), "a\\\"b\\\\c");
        assert_eq!(json_escape("x\ny"), "x\\ny");
        assert_eq!(json_escape("plain"), "plain");
    }

    #[test]
    fn attestation_without_prf_is_unsupported() {
        // SAFETY: every field in the FFI record is an integer or nullable pointer.
        let mut attestation: Attestation = unsafe { std::mem::zeroed() };
        attestation.version = ATTESTATION_VERSION_MIN;
        attestation.used_transport = TRANSPORT_INTERNAL;
        assert!(matches!(
            read_attestation(&attestation),
            Err(HelloError::Unsupported(_))
        ));
    }

    fn test_attestation(data: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), HelloError> {
        let credential_id = [9u8; 32];
        let prf = [13u8; 32];
        let salt = HmacSalt {
            cb_first: HMAC_SECRET_LENGTH,
            pb_first: prf.as_ptr(),
            cb_second: 0,
            pb_second: std::ptr::null(),
        };
        // SAFETY: every field in the FFI record is an integer or nullable pointer.
        let mut attestation: Attestation = unsafe { std::mem::zeroed() };
        attestation.version = 8;
        attestation.used_transport = TRANSPORT_INTERNAL;
        attestation.transports = TRANSPORT_INTERNAL;
        attestation.prf_enabled = 1;
        attestation.cb_credential_id = credential_id.len().try_into().unwrap();
        attestation.pb_credential_id = credential_id.as_ptr();
        attestation.cb_authenticator_data = data.len().try_into().unwrap();
        attestation.pb_authenticator_data = data.as_ptr();
        attestation.hmac_secret = &salt;
        read_attestation(&attestation)
    }

    fn test_assertion(data: &[u8]) -> Result<Zeroizing<[u8; 32]>, HelloError> {
        let credential_id = [9u8; 32];
        let prf = [13u8; 32];
        let salt = HmacSalt {
            cb_first: HMAC_SECRET_LENGTH,
            pb_first: prf.as_ptr(),
            cb_second: 0,
            pb_second: std::ptr::null(),
        };
        // SAFETY: every field in the FFI record is an integer or nullable pointer.
        let mut assertion: Assertion = unsafe { std::mem::zeroed() };
        assertion.version = 6;
        assertion.used_transport = TRANSPORT_INTERNAL;
        assertion.credential = Credential {
            version: 1,
            cb_id: credential_id.len().try_into().unwrap(),
            pb_id: credential_id.as_ptr(),
            credential_type: std::ptr::null(),
        };
        assertion.cb_authenticator_data = data.len().try_into().unwrap();
        assertion.pb_authenticator_data = data.as_ptr();
        assertion.hmac_secret = &salt;
        read_assertion(&assertion, &credential_id)
    }

    #[test]
    fn attestation_accepts_extended_authenticator_data() {
        let mut data = [0u8; 164];
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        let (credential_id, _) = test_attestation(&data).unwrap();
        assert_eq!(credential_id, [9u8; 32]);
    }

    #[test]
    fn assertion_accepts_extended_authenticator_data() {
        let mut data = [0u8; 75];
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        assert!(test_assertion(&data).is_ok());
    }

    #[test]
    fn authenticator_data_rejects_null_and_short_headers() {
        let mut short = [0u8; 36];
        short[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        for len in [0, short.len() as u32] {
            assert!(matches!(
                check_authenticator_data(short.as_ptr(), len),
                Err(HelloError::Corrupt(_))
            ));
        }
        for len in [AUTHENTICATOR_DATA_HEADER_LEN, 164] {
            assert!(matches!(
                check_authenticator_data(std::ptr::null(), len),
                Err(HelloError::Corrupt(_))
            ));
        }
        let mut minimum = [0u8; AUTHENTICATOR_DATA_HEADER_LEN as usize];
        minimum[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        assert!(check_authenticator_data(minimum.as_ptr(), AUTHENTICATOR_DATA_HEADER_LEN).is_ok());
    }

    #[test]
    fn attestation_and_assertion_require_both_user_flags() {
        let mut data = [0u8; 164];
        for (flags, missing) in [
            (FLAG_USER_PRESENT, "verification"),
            (FLAG_USER_VERIFIED, "presence"),
            (0, "presence"),
        ] {
            data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = flags;
            for result in [
                test_attestation(&data).map(|_| ()),
                test_assertion(&data).map(|_| ()),
            ] {
                assert!(matches!(
                    result,
                    Err(HelloError::Corrupt(reason)) if reason.contains(missing)
                ));
            }
        }
    }

    #[test]
    fn platform_credential_identifiers_can_exceed_64_bytes() {
        let identifier = [42u8; 128];
        assert_eq!(
            read_credential_id(
                identifier.as_ptr(),
                u32::try_from(identifier.len()).unwrap()
            )
            .unwrap(),
            identifier
        );
    }

    #[test]
    fn timeout_ms_clamps_to_the_dword_maximum() {
        assert_eq!(timeout_ms(Duration::from_millis(180_000)), 180_000);
        assert_eq!(
            timeout_ms(Duration::from_secs(u64::from(u32::MAX) + 1)),
            u32::MAX
        );
    }

    #[cfg(windows)]
    struct TestWindow {
        hwnd: usize,
    }

    #[cfg(windows)]
    impl HelloWindow for TestWindow {
        fn hwnd(&self) -> HWND {
            self.hwnd as HWND
        }
    }

    #[cfg(windows)]
    #[test]
    fn enroll_with_dead_owner_fails_before_any_prompt() {
        let owner = Arc::new(TestWindow { hwnd: 0 });
        let cancel = HelloCancellation::new();
        let error = match enroll(
            owner,
            "connetto-hello-native-test.invalid",
            &[7; 32],
            &[9; 32],
            &cancel,
            Duration::from_secs(1),
        ) {
            Ok(_) => panic!("dead owner unexpectedly enrolled a credential"),
            Err(error) => error,
        };
        assert!(matches!(error, HelloError::MissingOwner));
        assert!(!cancel.is_cancelled());
    }

    #[cfg(windows)]
    #[test]
    fn enroll_with_pre_cancelled_handle_fails_before_any_prompt() {
        let hwnd = create_hidden_window();
        let owner = Arc::new(TestWindow {
            hwnd: hwnd as usize,
        });
        let cancel = HelloCancellation::new();
        cancel.cancel();
        let error = match enroll(
            owner,
            "connetto-hello-native-test.invalid",
            &[7; 32],
            &[9; 32],
            &cancel,
            Duration::from_secs(1),
        ) {
            Ok(_) => panic!("pre-cancelled request unexpectedly enrolled a credential"),
            Err(error) => error,
        };
        assert!(matches!(error, HelloError::Cancelled));
        destroy_window(hwnd);
    }

    #[cfg(windows)]
    fn create_hidden_window() -> HWND {
        use windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW;
        let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
        // SAFETY: the class name is a terminated built-in Win32 window class.
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(
            !hwnd.is_null(),
            "static window creation failed on the test machine"
        );
        hwnd
    }

    #[cfg(windows)]
    fn destroy_window(hwnd: HWND) {
        use windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow;
        // SAFETY: hwnd is a live window created by the test.
        unsafe { DestroyWindow(hwnd) };
    }

    #[cfg(windows)]
    #[test]
    fn recover_created_for_unknown_rp_and_user_is_none() {
        let mut user = [0u8; 32];
        fill(&mut user).expect("test randomness available");
        let found = recover_created("connetto-hello-native-test.invalid", &user).unwrap();
        assert!(found.is_none());
    }
}
