//! Windows Hello support for sealed stores.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use keyring_core::api::{CredentialPersistence, CredentialStoreApi};
use keyring_core::{Entry, Result};
use sha2::{Digest, Sha256};
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;
use zeroize::Zeroizing;

use crate::hello_native::{self, MAX_CREDENTIAL_ID};
pub use crate::hello_native::{HelloCancellation, HelloWindow};
use crate::sealed::{
    Gate, Kind, Protection, SealError, SealResult, deadline, delete_owned, platform, read_raw,
    remaining, unpoison,
};
use crate::sealed_lock::{lock_target, lock_target_with_timeout};
use crate::utils::{CredPersist, hex, save_credential};

/// Check that Windows Hello can protect a sealed store on this machine, without prompting.
///
/// This needs WebAuthn API 9, a user-verifying platform authenticator, and exactly one
/// Windows Hello entry in the WebAuthn authenticator list. PRF support is only confirmed by
/// the first unlock.
///
/// # Errors
///
/// [`SealError::Unsupported`] when any requirement is missing, [`SealError::Locked`] when
/// Windows Hello is locked, [`SealError::Conflict`] when several Windows Hello authenticators
/// are listed, and [`SealError::Platform`] when WebAuthn fails.
pub fn capability() -> std::result::Result<(), SealError> {
    hello_native::available()
}

const META_MAGIC: &[u8; 5] = b"HPRF1";
const MAX_WAIT: Duration = Duration::from_secs(240);

/// The enrollment record, pending until its credential id is known.
struct Metadata {
    salt: [u8; 32],
    user_id: [u8; 32],
    credential_id: Option<Vec<u8>>,
}

/// One in-flight unlock that every concurrent caller of the same store joins.
struct Request {
    cancellation: HelloCancellation,
    completed: Mutex<Option<SealResult<()>>>,
    changed: Condvar,
}

impl Request {
    fn finish(&self, result: SealResult<()>) {
        *unpoison(self.completed.lock()) = Some(result);
        self.changed.notify_all();
    }

    fn wait(
        &self,
        timeout: Duration,
        caller: &HelloCancellation,
        owns_operation: bool,
    ) -> SealResult<()> {
        let deadline = deadline(timeout)?;
        let mut completed = unpoison(self.completed.lock());
        loop {
            if caller.is_cancelled() {
                return Err(SealError::Cancelled);
            }
            if let Some(result) = &*completed {
                return result.clone();
            }
            let left = remaining(deadline);
            if left.is_zero() {
                if owns_operation {
                    self.cancellation.cancel();
                }
                return Err(SealError::TimedOut);
            }
            let (next, _) = unpoison(
                self.changed
                    .wait_timeout(completed, left.min(Duration::from_millis(50))),
            );
            completed = next;
        }
    }
}

/// State shared by a `HelloStore` and its in-flight unlock worker.
struct Shared {
    gate: Arc<Gate>,
    rp_id: String,
    active: Mutex<Option<Arc<Request>>>,
}

/// A named store whose entries are sealed under a key from a Windows Hello passkey's PRF.
///
/// One Windows Hello approval in [`HelloStore::unlock`] opens every entry until
/// [`HelloStore::lock`]. The first unlock of an empty store enrolls the passkey.
pub struct HelloStore {
    id: String,
    shared: Arc<Shared>,
}

impl HelloStore {
    /// Create the store named `store` for `application`, starting locked.
    pub fn new(application: &str, store: &str) -> Result<Arc<Self>> {
        let gate = Gate::new(Kind::Hello, application, store)?;
        let id = gate.id();
        let digest = Sha256::digest(id.as_bytes());
        let rp_id = format!("{}.{}.invalid", hex(&digest[..16]), hex(&digest[16..]));
        Ok(Arc::new(Self {
            id,
            shared: Arc::new(Shared {
                gate,
                rp_id,
                active: Mutex::new(None),
            }),
        }))
    }

    /// Unlock with one Windows Hello approval anchored to `owner`, enrolling on first use.
    ///
    /// Concurrent callers share one request. `timeout` is capped at four minutes.
    ///
    /// # Errors
    ///
    /// [`SealError::MissingOwner`] before any prompt if `owner` is not a live window,
    /// [`SealError::Cancelled`] or [`SealError::TimedOut`] if the request ends early,
    /// [`SealError::KeyLost`] if the store's passkey is gone, and
    /// [`SealError::Unsupported`] if this machine cannot use Windows Hello PRF.
    pub fn unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> std::result::Result<(), SealError> {
        // Refuse before any record is touched, ahead of the native check at the prompt.
        // SAFETY: `IsWindow` accepts any handle value, including null or stale handles.
        if unsafe { IsWindow(owner.hwnd()) } == 0 {
            return Err(SealError::MissingOwner);
        }
        let timeout = timeout.min(MAX_WAIT);
        if timeout.is_zero() {
            return Err(SealError::TimedOut);
        }
        self.shared.unlock_with(
            cancellation,
            timeout,
            move |shared, cancellation, timeout| {
                shared.perform_unlock(owner, cancellation, timeout)
            },
        )
    }

    /// Erase the key and cancel any pending Windows Hello request.
    pub fn lock(&self) {
        self.shared.lock();
    }

    /// Delete this store's entries, enrollment and passkey, retiring every existing handle.
    ///
    /// No Windows Hello approval is needed.
    ///
    /// # Errors
    ///
    /// [`SealError::TimedOut`] if the store's locks are not free within `timeout`, and
    /// [`SealError::Discarded`] if this handle predates an earlier discard.
    pub fn discard(&self, timeout: Duration) -> std::result::Result<(), SealError> {
        let deadline = deadline(timeout)?;
        let gate = &self.shared.gate;
        let marker = gate.begin_discard(deadline)?;
        self.lock();
        let metadata = gate.metadata_target();
        // An unlock holds this lease for its whole ceremony, so the passkey is idle afterwards.
        let _lease = lock_target_with_timeout(&metadata, remaining(deadline))?;
        if !gate.confirm_discard(&marker, deadline)? {
            return Ok(());
        }
        self.shared.remove_enrollment_credential(&metadata)?;
        gate.delete_entries()?;
        delete_owned(&metadata)?;
        gate.finish_discard(&marker, deadline)
    }

    /// Report whether this store holds its key, or has lost its passkey.
    pub fn protection(&self) -> Protection {
        self.shared.gate.protection()
    }

    #[cfg(test)]
    pub(crate) fn install_test_key(&self, key: [u8; 32]) {
        self.shared.gate.install_key(key);
    }
}

impl Shared {
    fn lock(&self) {
        self.gate.lock();
        if let Some(request) = unpoison(self.active.lock()).as_ref() {
            request.cancellation.cancel();
        }
    }

    /// Runs `work` as the store's single request, or joins the one already running.
    fn unlock_with<F>(
        self: &Arc<Self>,
        cancellation: &HelloCancellation,
        timeout: Duration,
        work: F,
    ) -> SealResult<()>
    where
        F: FnOnce(&Shared, &HelloCancellation, Duration) -> SealResult<Zeroizing<[u8; 32]>>
            + Send
            + 'static,
    {
        if cancellation.is_cancelled() {
            return Err(SealError::Cancelled);
        }
        match self.gate.protection() {
            Protection::Unlocked => return Ok(()),
            Protection::Lost => return Err(SealError::KeyLost),
            Protection::Locked => {}
        }
        let mut active = unpoison(self.active.lock());
        let (request, owns) = match &*active {
            Some(request) if request.cancellation.is_cancelled() => {
                let request = Arc::clone(request);
                drop(active);
                request.wait(timeout, cancellation, false)?;
                return Err(SealError::Cancelled);
            }
            Some(request) => (Arc::clone(request), false),
            None => {
                let request = Arc::new(Request {
                    cancellation: cancellation.clone(),
                    completed: Mutex::new(None),
                    changed: Condvar::new(),
                });
                *active = Some(Arc::clone(&request));
                let epoch = self.gate.epoch();
                let shared = Arc::clone(self);
                let worker = Arc::clone(&request);
                std::thread::spawn(move || {
                    let result = work(&shared, &worker.cancellation, timeout);
                    let outcome = if worker.cancellation.is_cancelled() {
                        Err(SealError::Cancelled)
                    } else {
                        shared.gate.settle(epoch, result)
                    };
                    let mut active = unpoison(shared.active.lock());
                    if active
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &worker))
                    {
                        *active = None;
                    }
                    drop(active);
                    worker.finish(outcome);
                });
                (request, true)
            }
        };
        drop(active);
        request.wait(timeout, cancellation, owns)
    }

    fn perform_unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> SealResult<Zeroizing<[u8; 32]>> {
        let metadata_target = self.gate.metadata_target();
        // Discard waits on this lease before removing enrollment state.
        let _lease = lock_target(&metadata_target)?;
        self.gate.check_control()?;
        let key = self.open_or_enroll(&metadata_target, owner, cancellation, timeout)?;
        self.gate.check_control()?;
        Ok(key)
    }

    fn open_or_enroll(
        &self,
        metadata_target: &str,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> SealResult<Zeroizing<[u8; 32]>> {
        if let Some(bytes) = read_raw(metadata_target)? {
            let mut metadata = parse_metadata(&bytes)?;
            if metadata.credential_id.is_none() {
                if self.gate.has_scoped_entries()? {
                    return Err(SealError::KeyLost);
                }
                metadata.credential_id =
                    hello_native::recover_created(&self.rp_id, &metadata.user_id)?;
                match metadata.credential_id {
                    Some(_) => save_metadata(metadata_target, &metadata)?,
                    None => delete_owned(metadata_target)?,
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
        } else if self.gate.has_scoped_entries()? {
            return Err(SealError::KeyLost);
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
            if let Some(id) = &complete.credential_id {
                hello_native::remove_exact(&self.rp_id, id)?;
            }
            delete_owned(metadata_target)?;
            return Err(error);
        }
        Ok(created.key)
    }

    /// Removes the store's passkey, by its recorded id or else by the store's RP.
    fn remove_enrollment_credential(&self, metadata_target: &str) -> SealResult<()> {
        let Some(bytes) = read_raw(metadata_target)? else {
            return hello_native::remove_all_for_rp(&self.rp_id);
        };
        let metadata = match parse_metadata(&bytes) {
            Ok(metadata) => metadata,
            // The RP is derived from this store alone, so it still identifies its passkeys.
            Err(SealError::Corrupt(_)) => return hello_native::remove_all_for_rp(&self.rp_id),
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
}

impl Drop for HelloStore {
    fn drop(&mut self) {
        self.lock();
    }
}

impl std::fmt::Debug for HelloStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelloStore").field("id", &self.id).finish()
    }
}

impl CredentialStoreApi for HelloStore {
    fn vendor(&self) -> String {
        "Windows Hello PRF, https://crates.io/crates/windows-native-keyring-store".into()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        self.shared.gate.build(service, user, modifiers)
    }

    /// Search this store's entries, optionally by a `pattern` on their `{user}.{service}` name.
    #[cfg(feature = "search")]
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        self.shared.gate.search(spec)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

fn parse_metadata(blob: &[u8]) -> SealResult<Metadata> {
    if blob.len() < 70 || &blob[..5] != META_MAGIC {
        return Err(SealError::Corrupt("invalid enrollment record".into()));
    }
    let salt: [u8; 32] = blob[6..38]
        .try_into()
        .map_err(|_| SealError::Corrupt("invalid salt".into()))?;
    let user_id: [u8; 32] = blob[38..70]
        .try_into()
        .map_err(|_| SealError::Corrupt("invalid user ID".into()))?;
    let credential_id = match blob[5] {
        0 if blob.len() == 70 => None,
        1 if blob.len() >= 73 => {
            let length = usize::from(u16::from_le_bytes([blob[70], blob[71]]));
            if !(1..=MAX_CREDENTIAL_ID).contains(&length) || blob.len() != 72 + length {
                return Err(SealError::Corrupt("invalid credential ID length".into()));
            }
            Some(blob[72..].to_vec())
        }
        _ => return Err(SealError::Corrupt("invalid enrollment state".into())),
    };
    Ok(Metadata {
        salt,
        user_id,
        credential_id,
    })
}

fn save_metadata(target: &str, metadata: &Metadata) -> SealResult<()> {
    let mut bytes = Vec::with_capacity(72 + metadata.credential_id.as_ref().map_or(0, Vec::len));
    bytes.extend_from_slice(META_MAGIC);
    bytes.push(u8::from(metadata.credential_id.is_some()));
    bytes.extend_from_slice(&metadata.salt);
    bytes.extend_from_slice(&metadata.user_id);
    if let Some(id) = &metadata.credential_id {
        let length = u16::try_from(id.len())
            .map_err(|_| SealError::Corrupt("credential ID too long".into()))?;
        if length == 0 || usize::from(length) > MAX_CREDENTIAL_ID {
            return Err(SealError::Corrupt("invalid credential ID length".into()));
        }
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(id);
    }
    save_credential(target, "", "", "", &bytes, &CredPersist::Local).map_err(platform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::Error;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn relying_party_identifier_has_valid_dns_label_lengths() {
        let store = HelloStore::new("application", "account").unwrap();
        let rp_id = &store.shared.rp_id;
        assert!(
            rp_id
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63)
        );
        assert!(rp_id.ends_with(".invalid"));
    }

    #[test]
    fn enrollment_metadata_round_trips_long_platform_credential_ids() {
        let target = format!("keyring:hello-prf:test:{}", fastrand::u64(..));
        let metadata = Metadata {
            salt: [7; 32],
            user_id: [8; 32],
            credential_id: Some(vec![42; 128]),
        };
        save_metadata(&target, &metadata).unwrap();
        let read = parse_metadata(&read_raw(&target).unwrap().unwrap());
        delete_owned(&target).unwrap();
        let read = read.unwrap();
        assert_eq!(read.salt, [7; 32]);
        assert_eq!(read.user_id, [8; 32]);
        assert_eq!(read.credential_id, Some(vec![42; 128]));
    }

    #[test]
    fn malformed_enrollment_metadata_is_corrupt() {
        let mut pending = META_MAGIC.to_vec();
        pending.push(0);
        pending.extend([0; 64]);
        assert!(parse_metadata(&pending).is_ok());
        for blob in [
            &pending[..69],
            &[pending.as_slice(), &[0]].concat()[..],
            &[&b"XPRF1"[..], &pending[5..]].concat()[..],
            &[&pending[..5], &[2], &pending[6..]].concat()[..],
            &[&pending[..5], &[1], &pending[6..], &[0, 0, 0]].concat()[..],
        ] {
            assert!(matches!(parse_metadata(blob), Err(SealError::Corrupt(_))));
        }
    }

    const REQUEST: u64 = 13;

    type Outcome = (u64, SealResult<()>);

    /// Starts an unlock whose work blocks until `REQUEST` is sent on the returned sender.
    fn hold_unlock(
        store: &HelloStore,
        cancellation: HelloCancellation,
    ) -> (mpsc::Sender<u64>, mpsc::Receiver<Outcome>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let shared = Arc::clone(&store.shared);
        std::thread::spawn(move || {
            let result =
                shared.unlock_with(&cancellation, Duration::from_secs(2), move |_, _, _| {
                    entered_tx.send(REQUEST).unwrap();
                    let released = release_rx
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| SealError::TimedOut)?;
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
        assert_eq!(result, Err(SealError::Cancelled));
    }

    fn refusal(store: &HelloStore) -> Option<SealError> {
        let entry = store.build("service", "user", None).unwrap();
        match entry.get_secret() {
            Err(Error::NoStorageAccess(reason)) => reason.downcast_ref::<SealError>().cloned(),
            _ => None,
        }
    }

    fn wait_until_idle(store: &HelloStore) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while unpoison(store.shared.active.lock()).is_some() {
            assert!(Instant::now() < deadline, "unlock worker failed to finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn locking_during_unlock_prevents_late_key_publication() {
        let store = HelloStore::new("test", "concurrent-lock").unwrap();
        let (release, results) = hold_unlock(&store, HelloCancellation::new());
        store.lock();
        release.send(REQUEST).unwrap();
        assert_cancelled(&results);
        assert_eq!(store.protection(), Protection::Locked);
        assert_eq!(refusal(&store), Some(SealError::Locked));
    }

    #[test]
    fn a_request_that_finishes_after_lock_cannot_publish() {
        let store = HelloStore::new("test", "lock-race").unwrap();
        let epoch = store.shared.gate.epoch();
        store.shared.gate.lock();
        assert_eq!(
            store.shared.gate.settle(epoch, Ok(Zeroizing::new([1; 32]))),
            Err(SealError::Cancelled)
        );
        assert_eq!(store.protection(), Protection::Locked);
    }

    #[test]
    fn cancelling_an_inflight_unlock_keeps_the_store_locked() {
        let store = HelloStore::new("test", "cancel-unlock").unwrap();
        let cancellation = HelloCancellation::new();
        let (release, results) = hold_unlock(&store, cancellation.clone());
        cancellation.cancel();
        assert_cancelled(&results);
        release.send(REQUEST).unwrap();
        wait_until_idle(&store);
        assert_eq!(store.protection(), Protection::Locked);
    }

    #[test]
    fn a_second_caller_joins_the_request_in_flight() {
        let store = HelloStore::new("test", "join-unlock").unwrap();
        let (release, results) = hold_unlock(&store, HelloCancellation::new());
        let shared = Arc::clone(&store.shared);
        let joined = std::thread::spawn(move || {
            shared.unlock_with(
                &HelloCancellation::new(),
                Duration::from_secs(2),
                |_, _, _| panic!("a joining caller must not start a second request"),
            )
        });
        std::thread::sleep(Duration::from_millis(50));
        release.send(REQUEST).unwrap();
        assert_eq!(
            results.recv_timeout(Duration::from_secs(2)).unwrap().1,
            Ok(())
        );
        assert_eq!(joined.join().unwrap(), Ok(()));
        assert_eq!(store.protection(), Protection::Unlocked);
        store.lock();
    }

    #[test]
    fn a_lost_passkey_marks_the_store_lost() {
        let store = HelloStore::new("test", &format!("lost-{}", fastrand::u64(..))).unwrap();
        let result = store.shared.unlock_with(
            &HelloCancellation::new(),
            Duration::from_secs(2),
            |_, _, _| Err(SealError::KeyLost),
        );
        assert_eq!(result, Err(SealError::KeyLost));
        wait_until_idle(&store);
        assert_eq!(store.protection(), Protection::Lost);
        assert_eq!(refusal(&store), Some(SealError::KeyLost));
        let again = store.shared.unlock_with(
            &HelloCancellation::new(),
            Duration::from_secs(2),
            |_, _, _| panic!("a lost store must not start another request"),
        );
        assert_eq!(again, Err(SealError::KeyLost));
    }

    #[test]
    fn discarding_during_unlock_never_publishes_a_key() {
        let store =
            HelloStore::new("test", &format!("discard-unlock-{}", fastrand::u64(..))).unwrap();
        let (release, results) = hold_unlock(&store, HelloCancellation::new());
        let control = store.shared.gate.control_target();
        let discarded = store.discard(Duration::from_secs(5));
        release.send(REQUEST).unwrap();
        assert_cancelled(&results);
        let refused = refusal(&store);
        crate::utils::delete_credential(&control).unwrap();
        assert_eq!(discarded, Ok(()));
        assert_eq!(store.protection(), Protection::Locked);
        assert_eq!(refused, Some(SealError::Discarded));
    }
}
