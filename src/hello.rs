use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "search")]
use crate::cred::Cred;
#[cfg(feature = "search")]
use keyring_core::Entry;
use keyring_core::{Error, Result};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CREDENTIALW, CredEnumerateW, CredFree,
};
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;
use zeroize::Zeroizing;

use crate::hello_crypto::{PROTECTED_OVERHEAD, is_protected, open, seal};
use crate::hello_mutex::{lock_target, lock_target_with_timeout};
use crate::hello_native;
use crate::utils::{
    CredPersist, delete_credential, extract_attributes, extract_from_credential, extract_secret,
    hex, save_credential, validate_secret, validate_target,
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
    #[error("Windows Hello store discard is incomplete")]
    Discarding,
    #[error("Windows Hello store was discarded")]
    Discarded,
    #[error("legacy source deleted but scoped target deletion failed ({0})")]
    IncompleteDeletion(String),
}

impl From<HelloError> for Error {
    fn from(error: HelloError) -> Self {
        match error {
            HelloError::Corrupt(reason) => Error::BadStoreFormat(reason),
            HelloError::Unsupported(reason) => Error::NotSupportedByStore(reason),
            HelloError::Platform(_)
            | HelloError::Conflict(_)
            | HelloError::IncompleteDeletion(_) => Error::PlatformFailure(Box::new(error)),
            _ => Error::NoStorageAccess(Box::new(error)),
        }
    }
}

pub(crate) type HelloResult<T> = std::result::Result<T, HelloError>;

/// Recovers a poisoned guard, since no gate invariant depends on a panicking holder.
pub(crate) fn unpoison<T>(result: std::sync::LockResult<T>) -> T {
    result.unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Locked,
    Unlocked,
    Lost,
}

struct Request {
    cancellation: HelloCancellation,
    completed: Mutex<Option<HelloResult<()>>>,
    changed: Condvar,
}

impl Request {
    fn finish(&self, result: HelloResult<()>) {
        let mut completed = unpoison(self.completed.lock());
        *completed = Some(result);
        self.changed.notify_all();
    }

    fn wait(
        &self,
        timeout: Duration,
        caller: &HelloCancellation,
        owns_operation: bool,
    ) -> HelloResult<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HelloError::TimedOut)?;
        let mut completed = unpoison(self.completed.lock());
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
            let (next, _) = unpoison(
                self.changed
                    .wait_timeout(completed, remaining.min(Duration::from_millis(50))),
            );
            completed = next;
        }
    }
}

struct State {
    key: Option<Zeroizing<[u8; 32]>>,
    active: Option<Arc<Request>>,
    lost: bool,
}

impl State {
    /// Erases the key and cancels the pending request under the state lock, so it cannot publish.
    fn revoke(&mut self) -> Option<Arc<Request>> {
        self.key = None;
        let request = self.active.clone()?;
        request.cancellation.mark_cancelled();
        Some(request)
    }

    /// Publishes a finished request's outcome unless it was cancelled first.
    fn settle(
        &mut self,
        request: &Arc<Request>,
        result: HelloResult<Zeroizing<[u8; 32]>>,
    ) -> HelloResult<()> {
        if self
            .active
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, request))
        {
            self.active = None;
        }
        if request.cancellation.is_cancelled() {
            return Err(HelloError::Cancelled);
        }
        match result {
            Ok(key) => {
                self.key = Some(key);
                Ok(())
            }
            Err(error) => {
                if matches!(error, HelloError::KeyLost | HelloError::Corrupt(_)) {
                    self.lost = true;
                }
                Err(error)
            }
        }
    }
}

pub(crate) struct Gate {
    prefix: String,
    rp_id: String,
    generation: Option<[u8; 16]>,
    state: Mutex<State>,
}

const META_MAGIC: &[u8; 5] = b"HPRF1";
const CONTROL_MAGIC: &[u8; 5] = b"HCTL1";
const MAX_WAIT: Duration = Duration::from_secs(240);
pub(crate) const MAX_CREDENTIAL_ID: usize = CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - 72;
const MAX_PROTECTED_PLAINTEXT: usize = CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - PROTECTED_OVERHEAD;

struct Metadata {
    salt: [u8; 32],
    user_id: [u8; 32],
    credential_id: Option<Vec<u8>>,
}

#[derive(Clone, Copy)]
struct Control {
    discarding: bool,
    generation: [u8; 16],
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
            prefix += &format!("{:x}:{}:", identifier.len(), hex(identifier.as_bytes()));
        }
        validate_target(&format!("{prefix}metadata"), "")?;
        let generation = match read_control(&format!("{prefix}control")) {
            Ok(control) => control.map(|control| control.generation),
            // An unreadable record opens blocked, so only `discard` can proceed.
            Err(HelloError::Corrupt(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let digest = Sha256::digest(prefix.as_bytes());
        let rp_id = format!("{}.{}.invalid", hex(&digest[..16]), hex(&digest[16..]));
        Ok(Arc::new(Self {
            prefix,
            rp_id,
            generation,
            state: Mutex::new(State {
                key: None,
                active: None,
                lost: false,
            }),
        }))
    }

    #[cfg(test)]
    pub(crate) fn install_test_key(&self, key: [u8; 32]) {
        unpoison(self.state.lock()).key = Some(Zeroizing::new(key));
    }

    pub(crate) fn id(&self) -> String {
        self.prefix.clone()
    }

    pub(crate) fn protection(&self) -> Protection {
        let state = unpoison(self.state.lock());
        if state.lost {
            Protection::Lost
        } else if state.key.is_some() {
            Protection::Unlocked
        } else {
            Protection::Locked
        }
    }

    pub(crate) fn scoped_target(&self, legacy: &str) -> Result<String> {
        let target = format!("{}entry:{}", self.prefix, hex(legacy.as_bytes()));
        validate_target(&target, "")?;
        Ok(target)
    }

    fn legacy_target(&self, target: &str) -> Result<String> {
        let encoded = target
            .strip_prefix(&self.prefix)
            .and_then(|suffix| suffix.strip_prefix("entry:"))
            .ok_or_else(|| Error::BadStoreFormat("entry escaped its scoped prefix".into()))?;
        Ok(decode_hex(encoded)?)
    }

    pub(crate) fn unlock(
        self: &Arc<Self>,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> HelloResult<()> {
        // Refuse before metadata is touched, ahead of the native check at the prompt.
        // SAFETY: `IsWindow` accepts any handle value, including null or stale handles.
        if unsafe { IsWindow(owner.hwnd()) } == 0 {
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
    ) -> HelloResult<()>
    where
        F: FnOnce(&Gate, &HelloCancellation, Duration) -> HelloResult<Zeroizing<[u8; 32]>>
            + Send
            + 'static,
    {
        if cancellation.is_cancelled() {
            return Err(HelloError::Cancelled);
        }
        let mut state = unpoison(self.state.lock());
        if state.lost {
            return Err(HelloError::KeyLost);
        }
        if state.key.is_some() {
            return Ok(());
        }
        let request = match &state.active {
            Some(request) if request.cancellation.is_cancelled() => {
                let request = Arc::clone(request);
                drop(state);
                request.wait(timeout, cancellation, false)?;
                return Err(HelloError::Cancelled);
            }
            Some(request) => (Arc::clone(request), false),
            None => {
                let request = Arc::new(Request {
                    cancellation: cancellation.clone(),
                    completed: Mutex::new(None),
                    changed: Condvar::new(),
                });
                state.active = Some(Arc::clone(&request));
                let gate = Arc::clone(self);
                let worker_request = Arc::clone(&request);
                std::thread::spawn(move || {
                    let result = work(&gate, &worker_request.cancellation, timeout);
                    let outcome = unpoison(gate.state.lock()).settle(&worker_request, result);
                    worker_request.finish(outcome);
                });
                (request, true)
            }
        };
        drop(state);
        request.0.wait(timeout, cancellation, request.1)
    }

    pub(crate) fn lock(&self) {
        let request = unpoison(self.state.lock()).revoke();
        if let Some(request) = request {
            request.cancellation.abort_native();
        }
    }

    fn perform_unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> HelloResult<Zeroizing<[u8; 32]>> {
        let metadata_target = self.metadata_target();
        // Discard waits on this lease before removing enrollment state.
        let _lease = lock_target(&metadata_target)?;
        self.check_control()?;
        let key = self.open_or_enroll(&metadata_target, owner, cancellation, timeout)?;
        self.check_control()?;
        Ok(key)
    }

    fn open_or_enroll(
        &self,
        metadata_target: &str,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> HelloResult<Zeroizing<[u8; 32]>> {
        if let Some(bytes) = read_raw(metadata_target)? {
            let mut metadata = parse_metadata(&bytes)?;
            if metadata.credential_id.is_none() {
                if self.has_scoped_entries()? {
                    return Err(HelloError::KeyLost);
                }
                metadata.credential_id =
                    hello_native::recover_created(&self.rp_id, &metadata.user_id)?;
                match metadata.credential_id {
                    Some(_) => save_metadata(metadata_target, &metadata)?,
                    None => delete_credential(metadata_target).map_err(platform)?,
                }
            }
            if let Some(id) = &metadata.credential_id {
                return hello_native::assert_prf(
                    owner,
                    &self.rp_id,
                    id,
                    &metadata.salt,
                    cancellation,
                    timeout,
                );
            }
        } else if self.has_scoped_entries()? {
            return Err(HelloError::KeyLost);
        }
        let mut user_id = [0u8; 32];
        let mut salt = [0u8; 32];
        getrandom::fill(&mut user_id).map_err(platform)?;
        getrandom::fill(&mut salt).map_err(platform)?;
        let pending = Metadata {
            salt,
            user_id,
            credential_id: None,
        };
        save_metadata(metadata_target, &pending)?;
        let created =
            hello_native::enroll(owner, &self.rp_id, &user_id, &salt, cancellation, timeout)?;
        let complete = Metadata {
            credential_id: Some(created.credential_id),
            ..pending
        };
        if let Err(error) = save_metadata(metadata_target, &complete) {
            let id = complete
                .credential_id
                .as_deref()
                .expect("completed enrollment has an ID");
            hello_native::remove_exact(&self.rp_id, id)?;
            delete_credential(metadata_target).map_err(platform)?;
            return Err(error);
        }
        Ok(created.key)
    }

    fn scoped_targets(&self) -> HelloResult<Vec<String>> {
        let entry_prefix = format!("{}entry:", self.prefix);
        let filter: Vec<u16> = format!("{entry_prefix}*\0").encode_utf16().collect();
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        // SAFETY: `filter` is NUL-terminated and both out pointers are writable locals.
        if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut entries) } == 0 {
            return match crate::utils::decode_error() {
                Error::NoEntry => Ok(Vec::new()),
                error => Err(platform(error)),
            };
        }
        // SAFETY: on success `entries` holds `count` credential pointers owned until `CredFree`.
        let native = unsafe {
            std::slice::from_raw_parts(
                entries,
                usize::try_from(count).expect("u32 fits usize on Windows"),
            )
        };
        let targets: Vec<String> = native
            .iter()
            // SAFETY: every enumerated pointer refers to a credential that lives until `CredFree`.
            .map(|credential| crate::utils::target_name(unsafe { &**credential }))
            .collect();
        // SAFETY: `entries` came from the successful enumeration above and is freed exactly once.
        unsafe { CredFree(entries.cast()) };
        if targets
            .iter()
            .any(|target| !target.starts_with(&entry_prefix))
        {
            return Err(HelloError::Corrupt(
                "credential enumeration escaped the scoped prefix".into(),
            ));
        }
        Ok(targets)
    }

    fn has_scoped_entries(&self) -> HelloResult<bool> {
        Ok(!self.scoped_targets()?.is_empty())
    }

    #[cfg(feature = "search")]
    pub(crate) fn search(
        self: &Arc<Self>,
        pattern: Option<&regex::Regex>,
        delimiters: &[String; 3],
    ) -> Result<Vec<Entry>> {
        let spec = format!(
            "^{}(.*){}(.*){}$",
            regex::escape(&delimiters[0]),
            regex::escape(&delimiters[1]),
            regex::escape(&delimiters[2]),
        );
        let spec =
            regex::Regex::new(&spec).map_err(|error| Error::BadStoreFormat(error.to_string()))?;
        self.guarded(|| {
            let mut result = Vec::new();
            for target_name in self.scoped_targets()? {
                let legacy = self.legacy_target(&target_name)?;
                if pattern.is_some_and(|pattern| !pattern.is_match(&legacy)) {
                    continue;
                }
                let specifiers = spec
                    .captures(&legacy)
                    .map(|captures| (captures[2].to_owned(), captures[1].to_owned()));
                result.push(Entry::new_with_credential(Arc::new(Cred {
                    target_name,
                    specifiers,
                    persistence: CredPersist::Local,
                    hello: Some(Arc::clone(self)),
                })));
            }
            Ok(result)
        })
    }

    fn metadata_target(&self) -> String {
        format!("{}metadata", self.prefix)
    }

    fn control_target(&self) -> String {
        format!("{}control", self.prefix)
    }

    fn check_control(&self) -> HelloResult<()> {
        let control = match read_control(&self.control_target()) {
            Ok(control) => control,
            Err(HelloError::Corrupt(_)) => return Err(HelloError::Discarding),
            Err(error) => return Err(error),
        };
        match control {
            Some(control) if control.discarding => Err(HelloError::Discarding),
            Some(control) if Some(control.generation) == self.generation => Ok(()),
            None if self.generation.is_none() => Ok(()),
            _ => Err(HelloError::Discarded),
        }
    }

    // Discard writes its marker under the same lock, so a passed check holds for `action`.
    fn guarded<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        let _store = lock_target(&self.control_target())?;
        self.check_control()?;
        action()
    }

    fn with_key<T>(&self, action: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        self.guarded(|| {
            let state = unpoison(self.state.lock());
            let key = state.key.as_ref().ok_or_else(|| {
                Error::from(if state.lost {
                    HelloError::KeyLost
                } else {
                    HelloError::Locked
                })
            })?;
            action(key)
        })
    }

    pub(crate) fn get_secret(&self, target: &str) -> Result<Vec<u8>> {
        self.with_key(|key| Ok(std::mem::take(&mut *self.migrate(target, key)?)))
    }

    pub(crate) fn set_secret(&self, target: &str, user: &str, secret: &[u8]) -> Result<()> {
        validate_protected_plaintext(secret)?;
        self.with_key(|key| {
            match self.migrate(target, key) {
                Ok(_) | Err(Error::NoEntry) => (),
                Err(error) => return Err(error),
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
            let sealed = seal(key, &self.prefix, target, secret)?;
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
        user: &str,
        alias: &str,
        comment: &str,
    ) -> Result<()> {
        crate::utils::validate_attributes(user, alias, comment)?;
        self.with_key(|key| {
            let secret = self.migrate(target, key)?;
            let sealed = seal(key, &self.prefix, target, &secret)?;
            save_credential(target, user, alias, comment, &sealed, &CredPersist::Local)
        })
    }

    pub(crate) fn attributes(
        &self,
        target: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        self.with_key(|key| {
            self.migrate(target, key)?;
            extract_from_credential(target, extract_attributes)
        })
    }

    pub(crate) fn delete(&self, target: &str) -> Result<()> {
        let legacy = &self.legacy_target(target)?;
        self.guarded(|| {
            // Stores sharing a service and user also share this legacy source.
            let _source_lock = lock_target(legacy)?;
            let legacy_deleted = match delete_credential(legacy) {
                Ok(()) => true,
                Err(Error::NoEntry) => false,
                Err(error) => return Err(error),
            };
            match delete_credential(target) {
                Err(Error::NoEntry) if legacy_deleted => Ok(()),
                Err(error) if legacy_deleted => {
                    Err(HelloError::IncompleteDeletion(error.to_string()).into())
                }
                result => result,
            }
        })
    }

    pub(crate) fn discard(&self, timeout: Duration) -> HelloResult<()> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(HelloError::TimedOut)?;
        let remaining = || deadline.saturating_duration_since(Instant::now());
        let control_target = self.control_target();
        let marker = {
            let _store = lock_target_with_timeout(&control_target, remaining())?;
            let marker = match read_control(&control_target) {
                Ok(Some(control)) if control.discarding => control,
                Ok(Some(control)) if Some(control.generation) == self.generation => Control {
                    discarding: true,
                    ..control
                },
                Ok(None) if self.generation.is_none() => Control {
                    discarding: true,
                    generation: random_generation()?,
                },
                // An unreadable record is an interrupted discard that any handle may resume.
                Err(HelloError::Corrupt(_)) => Control {
                    discarding: true,
                    generation: random_generation()?,
                },
                Ok(_) => return Err(HelloError::Discarded),
                Err(error) => return Err(error),
            };
            save_control(&control_target, &marker)?;
            marker
        };
        self.lock();
        let metadata_target = self.metadata_target();
        let _lease = lock_target_with_timeout(&metadata_target, remaining())?;
        {
            let _store = lock_target_with_timeout(&control_target, remaining())?;
            match read_control(&control_target)? {
                Some(control) if control.discarding && control.generation == marker.generation => {}
                Some(control) if !control.discarding => return Ok(()),
                _ => return Err(HelloError::Discarding),
            }
        }
        self.remove_enrollment_credential(&metadata_target)?;
        for target in self.scoped_targets()? {
            delete_owned(&target)?;
        }
        delete_owned(&metadata_target)?;
        let _store = lock_target_with_timeout(&control_target, remaining())?;
        save_control(
            &control_target,
            &Control {
                discarding: false,
                generation: random_generation()?,
            },
        )
    }

    fn remove_enrollment_credential(&self, metadata_target: &str) -> HelloResult<()> {
        let Some(bytes) = read_raw(metadata_target)? else {
            return hello_native::remove_all_for_rp(&self.rp_id);
        };
        let metadata = match parse_metadata(&bytes) {
            Ok(metadata) => metadata,
            // The RP is derived from this store alone, so it still identifies its passkeys.
            Err(HelloError::Corrupt(_)) => return hello_native::remove_all_for_rp(&self.rp_id),
            Err(error) => return Err(error),
        };
        let credential_id = match metadata.credential_id {
            Some(id) => Some(id),
            None => hello_native::recover_created(&self.rp_id, &metadata.user_id)?,
        };
        match credential_id {
            Some(id) => hello_native::remove_exact(&self.rp_id, &id),
            None => Ok(()),
        }
    }

    /// Opens the scoped secret, first sealing and moving its exact legacy source if absent.
    fn migrate(&self, target: &str, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let legacy = &self.legacy_target(target)?;
        let _source_lock = lock_target(legacy)?;
        if let Some(blob) = read_raw(target)? {
            if !is_protected(&blob) {
                return Err(HelloError::Corrupt("scoped secret is unsealed".into()).into());
            }
            return Ok(open(key, &self.prefix, target, &blob)?);
        }
        let Snapshot {
            source,
            attributes,
            modified,
        } = snapshot(legacy)?;
        validate_protected_plaintext(&source)?;
        let sealed = seal(key, &self.prefix, target, &source)?;
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
        Ok(source)
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

fn read_raw(target: &str) -> HelloResult<Option<Zeroizing<Vec<u8>>>> {
    match extract_from_credential(target, extract_secret) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(platform(error)),
    }
}

fn platform(error: impl std::fmt::Display) -> HelloError {
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

fn parse_metadata(blob: &[u8]) -> HelloResult<Metadata> {
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

fn save_metadata(target: &str, metadata: &Metadata) -> HelloResult<()> {
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

fn read_control(target: &str) -> HelloResult<Option<Control>> {
    let Some(blob) = read_raw(target)? else {
        return Ok(None);
    };
    if blob.len() != 22 || &blob[..5] != CONTROL_MAGIC {
        return Err(HelloError::Corrupt("invalid store control record".into()));
    }
    let discarding = match blob[5] {
        0 => false,
        1 => true,
        _ => return Err(HelloError::Corrupt("invalid store control state".into())),
    };
    let generation = blob[6..]
        .try_into()
        .map_err(|_| HelloError::Corrupt("invalid store generation".into()))?;
    Ok(Some(Control {
        discarding,
        generation,
    }))
}

fn save_control(target: &str, control: &Control) -> HelloResult<()> {
    let mut bytes = Vec::with_capacity(22);
    bytes.extend_from_slice(CONTROL_MAGIC);
    bytes.push(u8::from(control.discarding));
    bytes.extend_from_slice(&control.generation);
    save_credential(target, "", "", "", &bytes, &CredPersist::Local).map_err(platform)
}

fn random_generation() -> HelloResult<[u8; 16]> {
    let mut generation = [0; 16];
    getrandom::fill(&mut generation).map_err(platform)?;
    Ok(generation)
}

fn delete_owned(target: &str) -> HelloResult<()> {
    match delete_credential(target) {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(error) => Err(platform(error)),
    }
}

fn decode_hex(encoded: &str) -> HelloResult<String> {
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
            gate.set_secret("scoped", "user", &secret),
            Err(Error::TooLong(_, limit)) if limit as usize == MAX_PROTECTED_PLAINTEXT
        ));
    }

    const REQUEST: u64 = 13;

    type Outcome = (u64, std::result::Result<(), HelloError>);

    /// Starts an unlock whose work blocks until `REQUEST` is sent on the returned sender.
    fn hold_unlock(
        gate: &Arc<Gate>,
        cancellation: HelloCancellation,
    ) -> (mpsc::Sender<u64>, mpsc::Receiver<Outcome>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let worker_gate = Arc::clone(gate);
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
        assert_eq!(
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            REQUEST
        );
        (release_tx, result_rx)
    }

    fn assert_cancelled(results: &mpsc::Receiver<Outcome>) {
        let (completed, result) = results.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(completed, REQUEST);
        assert!(matches!(result, Err(HelloError::Cancelled)));
    }

    fn refusal(gate: &Gate) -> Option<HelloError> {
        match gate.get_secret(&gate.scoped_target("legacy").unwrap()) {
            Err(Error::NoStorageAccess(reason)) => reason.downcast_ref::<HelloError>().cloned(),
            _ => None,
        }
    }

    #[test]
    fn locking_during_unlock_prevents_late_key_publication() {
        let gate = Gate::new("test", "concurrent-lock").unwrap();
        let (release, results) = hold_unlock(&gate, HelloCancellation::new());
        gate.lock();
        release.send(REQUEST).unwrap();
        assert_cancelled(&results);
        assert_eq!(gate.protection(), Protection::Locked);
        assert_eq!(refusal(&gate), Some(HelloError::Locked));
    }

    #[test]
    fn lock_revokes_a_finished_unlock_before_it_can_publish() {
        let gate = Gate::new("test", "lock-race").unwrap();
        let (release, results) = hold_unlock(&gate, HelloCancellation::new());
        let mut state = unpoison(gate.state.lock());
        let request = state.active.clone().unwrap();
        state.revoke();
        let published = state.settle(&request, Ok(Zeroizing::new([1; 32])));
        assert!(matches!(published, Err(HelloError::Cancelled)));
        assert!(state.key.is_none());
        drop(state);
        release.send(REQUEST).unwrap();
        assert_cancelled(&results);
        assert_eq!(gate.protection(), Protection::Locked);
    }

    #[test]
    fn cancelling_an_inflight_unlock_keeps_the_store_locked() {
        let gate = Gate::new("test", "cancel-unlock").unwrap();
        let cancellation = HelloCancellation::new();
        let (release, results) = hold_unlock(&gate, cancellation.clone());
        cancellation.cancel();
        assert_cancelled(&results);
        release.send(REQUEST).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while unpoison(gate.state.lock()).active.is_some() {
            assert!(
                Instant::now() < deadline,
                "cancelled worker failed to finish"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(gate.protection(), Protection::Locked);
    }

    #[test]
    fn discarding_during_unlock_never_publishes_a_key() {
        let gate = Gate::new("test", &format!("discard-unlock-{}", fastrand::u64(..))).unwrap();
        let (release, results) = hold_unlock(&gate, HelloCancellation::new());
        gate.discard(Duration::from_secs(2)).unwrap();
        release.send(REQUEST).unwrap();
        assert_cancelled(&results);
        assert_eq!(gate.protection(), Protection::Locked);
        let refused = refusal(&gate);
        crate::utils::delete_credential(&gate.control_target()).unwrap();
        assert_eq!(refused, Some(HelloError::Discarded));
    }
}
