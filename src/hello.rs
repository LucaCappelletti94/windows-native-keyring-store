use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "search")]
use crate::utils::cred_from_credential;
#[cfg(feature = "search")]
use keyring_core::Entry;
use keyring_core::{Error, Result};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CREDENTIALW, CredEnumerateW, CredFree,
};
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;
use zeroize::{Zeroize, Zeroizing};

use crate::hello_crypto::{PROTECTED_OVERHEAD, is_protected, open, seal};
use crate::hello_mutex::lock_target;
use crate::hello_native;
use crate::utils::{
    CredPersist, delete_credential, extract_attributes, extract_from_credential, extract_secret,
    save_credential, validate_secret, validate_target,
};

pub use crate::hello_native::{HelloCancellation, HelloWindow};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum HelloError {
    #[error("Windows Hello owner window is missing or no longer live")]
    MissingOwner,
    #[error("Windows Hello authentication was cancelled")]
    Cancelled,
    #[error("Windows Hello authentication timed out")]
    TimedOut,
    #[error("Windows Hello PRF is unsupported ({0})")]
    Unsupported(String),
    #[error("Windows Hello credential for this store was lost")]
    KeyLost,
    #[error("Windows Hello store is corrupt ({0})")]
    Corrupt(String),
    #[error("Windows Hello operation failed ({0})")]
    Platform(String),
    #[error("credential changed during migration ({0})")]
    Conflict(String),
    #[error("Windows Hello store is locked")]
    Locked,
}

impl From<HelloError> for Error {
    fn from(error: HelloError) -> Self {
        match error {
            HelloError::Corrupt(reason) => Error::BadStoreFormat(reason),
            HelloError::Unsupported(reason) => Error::NotSupportedByStore(reason),
            HelloError::Platform(_) | HelloError::Conflict(_) => {
                Error::PlatformFailure(Box::new(error))
            }
            _ => Error::NoStorageAccess(Box::new(error)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Locked,
    Unlocked,
    Lost,
}

struct Request {
    id: u64,
    cancellation: HelloCancellation,
    completed: Mutex<Option<std::result::Result<(), HelloError>>>,
    changed: Condvar,
}

impl Request {
    fn finish(&self, result: std::result::Result<(), HelloError>) {
        let mut completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *completed = Some(result);
        self.changed.notify_all();
    }

    fn wait(
        &self,
        timeout: Duration,
        caller: &HelloCancellation,
        owns_operation: bool,
    ) -> std::result::Result<(), HelloError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HelloError::TimedOut)?;
        let mut completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if caller.is_cancelled() {
                return Err(HelloError::Cancelled);
            }
            if let Some(result) = &*completed {
                return result.clone();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if owns_operation {
                    self.cancellation.cancel();
                }
                return Err(HelloError::TimedOut);
            }
            let (next, _) = self
                .changed
                .wait_timeout(completed, remaining.min(Duration::from_millis(50)))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            completed = next;
        }
    }
}

struct State {
    generation: u64,
    key: Option<Zeroizing<[u8; 32]>>,
    active: Option<Arc<Request>>,
    lost: bool,
}

pub(crate) struct Gate {
    prefix: String,
    rp_id: String,
    state: Mutex<State>,
}

const META_MAGIC: &[u8; 5] = b"HPRF1";
const MAX_WAIT: Duration = Duration::from_secs(240);
pub(crate) const MAX_CREDENTIAL_ID: usize = CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - 72;
const MAX_PROTECTED_PLAINTEXT: usize = CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - PROTECTED_OVERHEAD;

struct Metadata {
    salt: [u8; 32],
    user_id: [u8; 32],
    credential_id: Option<Vec<u8>>,
}

struct Snapshot {
    source: Zeroizing<Vec<u8>>,
    attributes: std::collections::HashMap<String, String>,
    modified: u64,
}

impl Gate {
    pub(crate) fn new(application: &str, store: &str) -> Result<Arc<Self>> {
        if application.is_empty() || store.is_empty() {
            return Err(Error::Invalid(
                "application/store".into(),
                "identifiers cannot be empty".into(),
            ));
        }
        let mut prefix = "keyring:hello-prf:1:".to_owned();
        for identifier in [application, store] {
            use std::fmt::Write;
            write!(prefix, "{:x}:", identifier.len()).expect("string formatting");
            append_hex(&mut prefix, identifier.as_bytes());
            prefix.push(':');
        }
        validate_target(&format!("{prefix}metadata"), "")?;
        let digest = Sha256::digest(prefix.as_bytes());
        let mut rp_id = String::with_capacity(64 + 1 + ".invalid".len());
        append_hex(&mut rp_id, &digest[..16]);
        rp_id.push('.');
        append_hex(&mut rp_id, &digest[16..]);
        rp_id.push_str(".invalid");
        Ok(Arc::new(Self {
            prefix,
            rp_id,
            state: Mutex::new(State {
                generation: 0,
                key: None,
                active: None,
                lost: false,
            }),
        }))
    }

    #[cfg(test)]
    pub(crate) fn install_test_key(&self, key: [u8; 32]) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .key = Some(Zeroizing::new(key));
    }

    pub(crate) fn id(&self) -> String {
        self.prefix.clone()
    }

    pub(crate) fn protection(&self) -> Protection {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.lost {
            Protection::Lost
        } else if state.key.is_some() {
            Protection::Unlocked
        } else {
            Protection::Locked
        }
    }

    pub(crate) fn scoped_target(&self, legacy: &str) -> Result<String> {
        let mut target =
            String::with_capacity(self.prefix.len() + 6 + legacy.len().saturating_mul(2));
        target.push_str(&self.prefix);
        target.push_str("entry:");
        append_hex(&mut target, legacy.as_bytes());
        validate_target(&target, "")?;
        Ok(target)
    }

    pub(crate) fn capability() -> std::result::Result<(), HelloError> {
        hello_native::available()
    }

    pub(crate) fn unlock(
        self: &Arc<Self>,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> std::result::Result<(), HelloError> {
        if owner.hwnd().is_null() || unsafe { IsWindow(owner.hwnd()) } == 0 {
            return Err(HelloError::MissingOwner);
        }
        let timeout = timeout.min(MAX_WAIT);
        if timeout.is_zero() {
            return Err(HelloError::TimedOut);
        }
        self.unlock_with(cancellation, timeout, move |gate, cancellation, timeout| {
            gate.perform_unlock(owner, cancellation, timeout)
        })
    }

    fn unlock_with<F>(
        self: &Arc<Self>,
        cancellation: &HelloCancellation,
        timeout: Duration,
        work: F,
    ) -> std::result::Result<(), HelloError>
    where
        F: FnOnce(
                &Gate,
                &HelloCancellation,
                Duration,
            ) -> std::result::Result<Zeroizing<[u8; 32]>, HelloError>
            + Send
            + 'static,
    {
        if cancellation.is_cancelled() {
            return Err(HelloError::Cancelled);
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.lost {
            return Err(HelloError::KeyLost);
        }
        if state.key.is_some() {
            return Ok(());
        }
        let request = match &state.active {
            Some(request) if request.id != state.generation => {
                let request = Arc::clone(request);
                drop(state);
                request.wait(timeout, cancellation, false)?;
                return Err(HelloError::Cancelled);
            }
            Some(request) => (Arc::clone(request), false),
            None => {
                state.generation = state.generation.wrapping_add(1);
                let request = Arc::new(Request {
                    id: state.generation,
                    cancellation: cancellation.clone(),
                    completed: Mutex::new(None),
                    changed: Condvar::new(),
                });
                state.active = Some(Arc::clone(&request));
                let gate = Arc::clone(self);
                let worker_request = Arc::clone(&request);
                std::thread::spawn(move || {
                    let result = work(&gate, &worker_request.cancellation, timeout);
                    let mut state = gate
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let outcome = if state.generation != worker_request.id
                        || worker_request.cancellation.is_cancelled()
                    {
                        Err(HelloError::Cancelled)
                    } else {
                        match result {
                            Ok(key) => {
                                state.key = Some(key);
                                Ok(())
                            }
                            Err(error) => {
                                if matches!(error, HelloError::KeyLost | HelloError::Corrupt(_)) {
                                    state.lost = true;
                                }
                                Err(error)
                            }
                        }
                    };
                    if state
                        .active
                        .as_ref()
                        .is_some_and(|request| request.id == worker_request.id)
                    {
                        state.active = None;
                    }
                    drop(state);
                    worker_request.finish(outcome);
                });
                (request, true)
            }
        };
        drop(state);
        request.0.wait(timeout, cancellation, request.1)
    }

    pub(crate) fn lock(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.generation = state.generation.wrapping_add(1);
        state.key = None;
        let request = state.active.as_ref().map(Arc::clone);
        drop(state);
        if let Some(request) = request {
            request.cancellation.cancel();
        }
    }

    fn perform_unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, HelloError> {
        let metadata_target = self.metadata_target();
        let _lock = lock_target(&metadata_target)?;
        let metadata = match read_raw(&metadata_target)? {
            Some(bytes) => Some(parse_metadata(&bytes)?),
            None => None,
        };
        match metadata {
            Some(mut metadata) => {
                if metadata.credential_id.is_none() {
                    if self.has_scoped_entries()? {
                        return Err(HelloError::KeyLost);
                    }
                    metadata.credential_id =
                        hello_native::recover_created(&self.rp_id, &metadata.user_id)?;
                    if let Some(ref id) = metadata.credential_id {
                        save_metadata(&metadata_target, &metadata)?;
                        return hello_native::assert_prf(
                            owner,
                            &self.rp_id,
                            id,
                            &metadata.salt,
                            cancellation,
                            timeout,
                        );
                    }
                    delete_credential(&metadata_target).map_err(platform)?;
                } else {
                    let id = metadata
                        .credential_id
                        .as_deref()
                        .ok_or(HelloError::KeyLost)?;
                    return hello_native::assert_prf(
                        owner,
                        &self.rp_id,
                        id,
                        &metadata.salt,
                        cancellation,
                        timeout,
                    );
                }
            }
            None if self.has_scoped_entries()? => return Err(HelloError::KeyLost),
            None => (),
        }
        let mut user_id = [0u8; 32];
        let mut salt = [0u8; 32];
        getrandom::fill(&mut user_id).map_err(|err| HelloError::Platform(err.to_string()))?;
        getrandom::fill(&mut salt).map_err(|err| HelloError::Platform(err.to_string()))?;
        let pending = Metadata {
            salt,
            user_id,
            credential_id: None,
        };
        save_metadata(&metadata_target, &pending)?;
        let created =
            hello_native::enroll(owner, &self.rp_id, &user_id, &salt, cancellation, timeout)?;
        let complete = Metadata {
            credential_id: Some(created.credential_id),
            ..pending
        };
        if let Err(error) = save_metadata(&metadata_target, &complete) {
            let id = complete
                .credential_id
                .as_deref()
                .expect("completed enrollment has an ID");
            hello_native::remove_exact(&self.rp_id, id)?;
            delete_credential(&metadata_target).map_err(platform)?;
            return Err(error);
        }
        Ok(created.key)
    }

    fn has_scoped_entries(&self) -> std::result::Result<bool, HelloError> {
        let pattern: Vec<u16> = format!("{}entry:*\0", self.prefix).encode_utf16().collect();
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        if unsafe { CredEnumerateW(pattern.as_ptr(), 0, &mut count, &mut entries) } == 0 {
            return match crate::utils::decode_error() {
                Error::NoEntry => Ok(false),
                error => Err(platform(error)),
            };
        }
        unsafe { CredFree(entries.cast()) };
        Ok(count != 0)
    }

    #[cfg(feature = "search")]
    pub(crate) fn search(
        self: &Arc<Self>,
        pattern: Option<&regex::Regex>,
        delimiters: &[String; 3],
    ) -> Result<Vec<Entry>> {
        let filter: Vec<u16> = format!("{}entry:*\0", self.prefix).encode_utf16().collect();
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut entries) } == 0 {
            return match crate::utils::decode_error() {
                Error::NoEntry => Ok(Vec::new()),
                error => Err(error),
            };
        }
        let native = unsafe {
            std::slice::from_raw_parts(
                entries,
                usize::try_from(count).expect("u32 fits usize on Windows"),
            )
        };
        let mut candidates = Vec::with_capacity(native.len());
        for credential in native {
            candidates.push(cred_from_credential(unsafe { &mut **credential }));
        }
        unsafe { CredFree(entries.cast()) };

        let spec = format!(
            "^{}(.*){}(.*){}$",
            regex::escape(&delimiters[0]),
            regex::escape(&delimiters[1]),
            regex::escape(&delimiters[2]),
        );
        let spec =
            regex::Regex::new(&spec).map_err(|error| Error::BadStoreFormat(error.to_string()))?;
        let mut result = Vec::new();
        for mut candidate in candidates {
            let suffix = candidate
                .target_name
                .strip_prefix(&self.prefix)
                .and_then(|suffix| suffix.strip_prefix("entry:"))
                .ok_or_else(|| Error::BadStoreFormat("entry escaped its scoped prefix".into()))?;
            let legacy =
                decode_hex(suffix).map_err(|error| Error::BadStoreFormat(error.to_string()))?;
            if pattern.is_some_and(|pattern| !pattern.is_match(&legacy)) {
                continue;
            }
            if let Some(captures) = spec.captures(&legacy) {
                candidate.specifiers = Some((captures[2].to_owned(), captures[1].to_owned()));
            }
            candidate.legacy_target = Some(legacy);
            candidate.hello = Some(Arc::clone(self));
            result.push(Entry::new_with_credential(Arc::new(candidate)));
        }
        Ok(result)
    }

    fn metadata_target(&self) -> String {
        format!("{}metadata", self.prefix)
    }

    fn with_key<T>(&self, action: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = state.key.as_ref().ok_or_else(|| {
            Error::from(if state.lost {
                HelloError::KeyLost
            } else {
                HelloError::Locked
            })
        })?;
        action(key)
    }

    pub(crate) fn get_secret(&self, target: &str, legacy: &str) -> Result<Vec<u8>> {
        self.with_key(|key| {
            let blob = match read_raw(target).map_err(Error::from)? {
                Some(blob) => blob,
                None => return self.migrate(target, legacy, key),
            };
            if !is_protected(&blob) {
                return Err(HelloError::Corrupt("scoped secret is unsealed".into()).into());
            }
            let mut secret = open(key, &self.prefix, target, &blob).map_err(Error::from)?;
            Ok(std::mem::take(&mut *secret))
        })
    }

    pub(crate) fn set_secret(
        &self,
        target: &str,
        legacy: &str,
        user: &str,
        secret: &[u8],
    ) -> Result<()> {
        validate_protected_plaintext(secret)?;
        self.with_key(|key| {
            match read_raw(target).map_err(Error::from)? {
                Some(blob) => {
                    if !is_protected(&blob) {
                        return Err(HelloError::Corrupt("scoped secret is unsealed".into()).into());
                    }
                    open(key, &self.prefix, target, &blob).map_err(Error::from)?;
                }
                None => match self.migrate(target, legacy, key) {
                    Ok(mut original) => original.zeroize(),
                    Err(Error::NoEntry) => (),
                    Err(error) => return Err(error),
                },
            }
            let attributes = match extract_from_credential(target, extract_attributes) {
                Ok(attributes) => Some(attributes),
                Err(Error::NoEntry) => None,
                Err(error) => return Err(error),
            };
            let username = attributes
                .as_ref()
                .map_or(user, |attrs| attrs["username"].as_str());
            let alias = attributes
                .as_ref()
                .map_or("", |attrs| attrs["target_alias"].as_str());
            let comment = attributes
                .as_ref()
                .map_or("", |attrs| attrs["comment"].as_str());
            let sealed = seal(key, &self.prefix, target, secret).map_err(Error::from)?;
            validate_secret(&sealed)?;
            save_credential(
                target,
                username,
                alias,
                comment,
                &sealed,
                &CredPersist::Local,
            )
        })
    }

    pub(crate) fn update_attributes(
        &self,
        target: &str,
        legacy: &str,
        user: &str,
        alias: &str,
        comment: &str,
    ) -> Result<()> {
        crate::utils::validate_attributes(user, alias, comment)?;
        self.with_key(|key| {
            if read_raw(target).map_err(Error::from)?.is_none() {
                let mut migrated = self.migrate(target, legacy, key)?;
                migrated.zeroize();
            }
            let blob = read_raw(target)
                .map_err(Error::from)?
                .ok_or(Error::NoEntry)?;
            if !is_protected(&blob) {
                return Err(HelloError::Corrupt("scoped secret is unsealed".into()).into());
            }
            open(key, &self.prefix, target, &blob).map_err(Error::from)?;
            save_credential(target, user, alias, comment, &blob, &CredPersist::Local)
        })
    }

    pub(crate) fn attributes(
        &self,
        target: &str,
        legacy: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        self.with_key(|key| {
            if read_raw(target).map_err(Error::from)?.is_none() {
                let mut migrated = self.migrate(target, legacy, key)?;
                migrated.zeroize();
            }
            let blob = read_raw(target)
                .map_err(Error::from)?
                .ok_or(Error::NoEntry)?;
            if !is_protected(&blob) {
                return Err(HelloError::Corrupt("scoped secret is unsealed".into()).into());
            }
            open(key, &self.prefix, target, &blob).map_err(Error::from)?;
            extract_from_credential(target, extract_attributes)
        })
    }

    pub(crate) fn delete(&self, target: &str, legacy: &str) -> Result<()> {
        self.with_key(|key| {
            let _source_lock = lock_target(legacy).map_err(Error::from)?;
            let _destination_lock = lock_target(target).map_err(Error::from)?;
            if read_raw(target).map_err(Error::from)?.is_none() {
                let mut migrated = self.migrate(target, legacy, key)?;
                migrated.zeroize();
            }
            if read_raw(legacy).map_err(Error::from)?.is_some() {
                return Err(HelloError::Conflict(legacy.into()).into());
            }
            delete_credential(target)
        })
    }

    fn migrate(&self, target: &str, legacy: &str, key: &[u8; 32]) -> Result<Vec<u8>> {
        let _source_lock = lock_target(legacy).map_err(Error::from)?;
        let _destination_lock = lock_target(target).map_err(Error::from)?;
        if let Some(blob) = read_raw(target).map_err(Error::from)? {
            if !is_protected(&blob) {
                return Err(HelloError::Corrupt("scoped secret is unsealed".into()).into());
            }
            let mut plain = open(key, &self.prefix, target, &blob).map_err(Error::from)?;
            return Ok(std::mem::take(&mut *plain));
        }
        let Snapshot {
            mut source,
            attributes,
            modified,
        } = snapshot(legacy)?;
        validate_protected_plaintext(&source)?;
        let sealed = seal(key, &self.prefix, target, &source).map_err(Error::from)?;
        validate_secret(&sealed)?;
        save_credential(
            target,
            &attributes["username"],
            &attributes["target_alias"],
            &attributes["comment"],
            &sealed,
            &CredPersist::Local,
        )?;
        let current = match snapshot(legacy) {
            Ok(current) => current,
            Err(Error::NoEntry) => return Err(HelloError::Conflict(legacy.into()).into()),
            Err(error) => return Err(error),
        };
        if current.source != source
            || current.attributes != attributes
            || current.modified != modified
        {
            return Err(HelloError::Conflict(legacy.into()).into());
        }
        match delete_credential(legacy) {
            Err(Error::NoEntry) => return Err(HelloError::Conflict(legacy.into()).into()),
            result => result?,
        }
        Ok(std::mem::take(&mut *source))
    }
}

fn snapshot(target: &str) -> Result<Snapshot> {
    extract_from_credential(target, |native: &CREDENTIALW| {
        let modified = (u64::from(native.LastWritten.dwHighDateTime) << 32)
            | u64::from(native.LastWritten.dwLowDateTime);
        Ok(Snapshot {
            source: Zeroizing::new(extract_secret(native)?),
            attributes: extract_attributes(native)?,
            modified,
        })
    })
}

fn read_raw(target: &str) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, HelloError> {
    match extract_from_credential(target, extract_secret) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(platform(error)),
    }
}

fn platform(error: Error) -> HelloError {
    HelloError::Platform(error.to_string())
}

fn validate_protected_plaintext(secret: &[u8]) -> Result<()> {
    if secret.len() > MAX_PROTECTED_PLAINTEXT {
        return Err(Error::TooLong(
            "secret".into(),
            u32::try_from(MAX_PROTECTED_PLAINTEXT).expect("Credential Manager bound fits u32"),
        ));
    }
    Ok(())
}

fn parse_metadata(blob: &[u8]) -> std::result::Result<Metadata, HelloError> {
    if blob.len() < 70 || &blob[..5] != META_MAGIC {
        return Err(HelloError::Corrupt("invalid enrollment record".into()));
    }
    let salt: [u8; 32] = blob[6..38]
        .try_into()
        .map_err(|_| HelloError::Corrupt("invalid salt".into()))?;
    let user_id: [u8; 32] = blob[38..70]
        .try_into()
        .map_err(|_| HelloError::Corrupt("invalid user ID".into()))?;
    let credential_id = match blob[5] {
        0 if blob.len() == 70 => None,
        1 if blob.len() >= 73 => {
            let length = usize::from(u16::from_le_bytes([blob[70], blob[71]]));
            if !(1..=MAX_CREDENTIAL_ID).contains(&length) || blob.len() != 72 + length {
                return Err(HelloError::Corrupt("invalid credential ID length".into()));
            }
            Some(blob[72..].to_vec())
        }
        _ => return Err(HelloError::Corrupt("invalid enrollment state".into())),
    };
    Ok(Metadata {
        salt,
        user_id,
        credential_id,
    })
}

fn save_metadata(target: &str, metadata: &Metadata) -> std::result::Result<(), HelloError> {
    let mut bytes = Vec::with_capacity(72 + metadata.credential_id.as_ref().map_or(0, Vec::len));
    bytes.extend_from_slice(META_MAGIC);
    bytes.push(u8::from(metadata.credential_id.is_some()));
    bytes.extend_from_slice(&metadata.salt);
    bytes.extend_from_slice(&metadata.user_id);
    if let Some(id) = &metadata.credential_id {
        let length = u16::try_from(id.len())
            .map_err(|_| HelloError::Corrupt("credential ID too long".into()))?;
        if length == 0 || usize::from(length) > MAX_CREDENTIAL_ID {
            return Err(HelloError::Corrupt("invalid credential ID length".into()));
        }
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(id);
    }
    save_credential(target, "", "", "", &bytes, &CredPersist::Local).map_err(platform)
}

#[cfg(feature = "search")]
fn decode_hex(encoded: &str) -> std::result::Result<String, HelloError> {
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(HelloError::Corrupt("invalid scoped target encoding".into()));
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    for pair in pairs {
        let high = digit(pair[0])
            .ok_or_else(|| HelloError::Corrupt("invalid scoped target encoding".into()))?;
        let low = digit(pair[1])
            .ok_or_else(|| HelloError::Corrupt("invalid scoped target encoding".into()))?;
        decoded.push((high << 4) | low);
    }
    String::from_utf8(decoded)
        .map_err(|_| HelloError::Corrupt("invalid scoped target UTF-8".into()))
}

fn append_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn relying_party_identifier_has_valid_dns_label_lengths() {
        let gate = Gate::new("application", "account").unwrap();
        assert!(
            gate.rp_id
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63)
        );
        assert!(gate.rp_id.ends_with(".invalid"));
    }

    #[test]
    fn enrollment_metadata_accepts_long_platform_credential_ids() {
        let identifier = [42u8; 128];
        let mut metadata = Vec::with_capacity(72 + identifier.len());
        metadata.extend_from_slice(META_MAGIC);
        metadata.push(1);
        metadata.extend_from_slice(&[7u8; 32]);
        metadata.extend_from_slice(&[8u8; 32]);
        metadata.extend_from_slice(&u16::try_from(identifier.len()).unwrap().to_le_bytes());
        metadata.extend_from_slice(&identifier);
        assert_eq!(
            parse_metadata(&metadata).unwrap().credential_id.as_deref(),
            Some(identifier.as_slice())
        );
    }

    #[test]
    fn oversized_plaintext_is_rejected_before_authentication() {
        let gate = Gate::new("length-test", "store").unwrap();
        let secret = vec![0u8; MAX_PROTECTED_PLAINTEXT + 1];
        assert!(matches!(
            gate.set_secret("scoped", "legacy", "user", &secret),
            Err(Error::TooLong(_, limit)) if limit as usize == MAX_PROTECTED_PLAINTEXT
        ));
    }

    #[test]
    fn locking_during_unlock_prevents_late_key_publication() {
        const REQUEST: u64 = 13;
        let gate = Gate::new("test", "concurrent-lock").unwrap();
        let cancellation = HelloCancellation::new();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            let result =
                worker_gate.unlock_with(&cancellation, Duration::from_secs(2), move |_, _, _| {
                    entered_tx.send(REQUEST).unwrap();
                    let released = release_rx
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| HelloError::TimedOut)?;
                    assert_eq!(released, REQUEST);
                    Ok(Zeroizing::new([9; 32]))
                });
            result_tx.send((REQUEST, result)).unwrap();
        });

        let entered = entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(entered, REQUEST);
        gate.lock();
        release_tx.send(REQUEST).unwrap();
        let (completed, result) = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(completed, REQUEST);
        assert!(matches!(result, Err(HelloError::Cancelled)));
        assert_eq!(gate.protection(), Protection::Locked);
        assert!(matches!(
            gate.get_secret("target", "legacy"),
            Err(Error::NoStorageAccess(_))
        ));
    }
    #[test]
    fn cancelling_an_inflight_unlock_keeps_the_store_locked() {
        const REQUEST: u64 = 29;
        let gate = Gate::new("test", "cancel-unlock").unwrap();
        let cancellation = HelloCancellation::new();
        let caller_cancel = cancellation.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker_gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            let result =
                worker_gate.unlock_with(&cancellation, Duration::from_secs(2), move |_, _, _| {
                    entered_tx.send(REQUEST).unwrap();
                    let released = release_rx
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| HelloError::TimedOut)?;
                    assert_eq!(released, REQUEST);
                    Ok(Zeroizing::new([3; 32]))
                });
            result_tx.send((REQUEST, result)).unwrap();
        });

        assert_eq!(
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            REQUEST
        );
        caller_cancel.cancel();
        let (completed, result) = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(completed, REQUEST);
        assert!(matches!(result, Err(HelloError::Cancelled)));
        release_tx.send(REQUEST).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
            .is_some()
        {
            assert!(
                Instant::now() < deadline,
                "cancelled worker failed to finish"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(gate.protection(), Protection::Locked);
    }
}
