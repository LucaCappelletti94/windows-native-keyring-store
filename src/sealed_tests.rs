use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use keyring_core::{Entry, Error, api::CredentialStoreApi};

use crate::sealed::{Protection, SealError};
use crate::utils::{delete_credential, extract_from_credential, extract_secret, save_credential};
use crate::{CredPersist, SealedStore, Store};

fn target_of(entry: &Entry) -> String {
    let cred = entry.as_any().downcast_ref::<crate::cred::Cred>();
    cred.unwrap().target_name.clone()
}

fn raw(target: &str) -> keyring_core::Result<Vec<u8>> {
    extract_from_credential(target, extract_secret)
}

fn write_raw(target: &str, bytes: &[u8]) {
    save_credential(target, "", "", "", bytes, &CredPersist::Local).unwrap();
}

/// A store with a fresh name whose records are deleted when the test ends.
struct Scope {
    application: String,
    name: String,
    store: Arc<SealedStore>,
    targets: Vec<String>,
}

impl Scope {
    fn new() -> Self {
        Self::named(format!("sealed-test-{}", fastrand::u64(..)), "store")
    }

    fn named(application: String, name: &str) -> Self {
        Self {
            store: SealedStore::new(&application, name).unwrap(),
            application,
            name: name.into(),
            targets: Vec::new(),
        }
    }

    fn sibling(&self, name: &str) -> Self {
        Self::named(self.application.clone(), name)
    }

    fn reopen(&self) -> Arc<SealedStore> {
        SealedStore::new(&self.application, &self.name).unwrap()
    }

    fn entry(&mut self, user: &str) -> Entry {
        let entry = self.store.build("service", user, None).unwrap();
        self.targets.push(target_of(&entry));
        entry
    }

    fn keycheck(&self) -> String {
        format!("{}keycheck", self.store.id())
    }

    fn control(&self) -> String {
        format!("{}control", self.store.id())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        for target in self
            .targets
            .iter()
            .chain([&self.keycheck(), &self.control()])
        {
            let _ = delete_credential(target);
        }
    }
}

fn refused_with<T>(result: keyring_core::Result<T>, expected: &SealError) -> bool {
    match result {
        Err(Error::NoStorageAccess(reason)) => reason.downcast_ref::<SealError>() == Some(expected),
        _ => false,
    }
}

#[test]
fn locked_store_refuses_secret_operations() {
    let mut scope = Scope::new();
    let entry = scope.entry("user");
    assert_eq!(scope.store.protection(), Protection::Locked);
    assert!(refused_with(entry.get_secret(), &SealError::Locked));
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &SealError::Locked
    ));
    assert!(refused_with(entry.get_attributes(), &SealError::Locked));
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
}

#[test]
fn targets_are_scoped_and_entries_require_local_persistence() {
    let first = SealedStore::new("an", "account").unwrap();
    let second = SealedStore::new("a", "naccount").unwrap();
    let first_target = target_of(&first.build("svc", "user", None).unwrap());
    assert_ne!(
        first_target,
        target_of(&second.build("svc", "user", None).unwrap())
    );
    assert!(first_target.starts_with(&first.id()));
    let reopened = SealedStore::new("an", "account").unwrap();
    assert_eq!(first.id(), reopened.id());
    assert_eq!(
        first_target,
        target_of(&reopened.build("svc", "user", None).unwrap())
    );
    for modifiers in [
        HashMap::from([("persistence", "Enterprise")]),
        HashMap::from([("persistence", "Session")]),
        HashMap::from([("target", "outside-namespace")]),
    ] {
        assert!(matches!(
            first.build("svc", "user", Some(&modifiers)),
            Err(Error::Invalid(_, _))
        ));
    }
    assert!(SealedStore::new("", "account").is_err());
    assert!(matches!(
        first.persistence(),
        keyring_core::api::CredentialPersistence::UntilDelete
    ));
}

#[test]
fn round_trip_stores_only_ciphertext_bound_to_the_store() {
    let mut scope = Scope::new();
    scope.store.unlock(&[3; 32]).unwrap();
    assert_eq!(scope.store.protection(), Protection::Unlocked);
    let entry = scope.entry("alice");
    entry.set_password("refresh-token").unwrap();
    assert_eq!(entry.get_password().unwrap(), "refresh-token");
    assert_eq!(entry.get_attributes().unwrap()["username"], "alice");

    let stored = raw(&target_of(&entry)).unwrap();
    assert!(crate::sealed_crypto::is_protected(&stored));
    let plain: Vec<u8> = "refresh-token"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(!stored.windows(plain.len()).any(|window| window == plain));

    scope.store.lock();
    assert!(refused_with(entry.get_password(), &SealError::Locked));
}

#[test]
fn wrong_key_leaves_the_store_locked_and_writes_nothing() {
    let mut scope = Scope::new();
    scope.store.unlock(&[5; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();
    let target = target_of(&entry);
    let (entry_before, keycheck_before) = (raw(&target).unwrap(), raw(&scope.keycheck()).unwrap());

    let other = scope.reopen();
    assert_eq!(other.unlock(&[6; 32]), Err(SealError::WrongKey));
    assert_eq!(other.protection(), Protection::Locked);
    assert_eq!(raw(&target).unwrap(), entry_before);
    assert_eq!(raw(&scope.keycheck()).unwrap(), keycheck_before);

    other.unlock(&[5; 32]).unwrap();
    let reopened = other.build("service", "user", None).unwrap();
    assert_eq!(reopened.get_secret().unwrap(), b"sealed");
}

#[test]
fn missing_or_unsealed_keycheck_with_entries_is_corrupt() {
    let mut scope = Scope::new();
    scope.store.unlock(&[8; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();

    delete_credential(&scope.keycheck()).unwrap();
    assert!(matches!(
        scope.store.unlock(&[8; 32]),
        Err(SealError::Corrupt(_))
    ));
    write_raw(&scope.keycheck(), b"plain");
    assert!(matches!(
        scope.store.unlock(&[8; 32]),
        Err(SealError::Corrupt(_))
    ));
    assert_eq!(scope.store.protection(), Protection::Locked);
    assert_eq!(raw(&scope.keycheck()).unwrap(), b"plain");
}

#[test]
fn tampered_ciphertext_never_returns_plaintext() {
    let mut scope = Scope::new();
    scope.store.unlock(&[41; 32]).unwrap();
    let entry = scope.entry("credential");
    entry.set_secret(b"sealed-token").unwrap();
    let target = target_of(&entry);

    let ordinary = Store::new()
        .unwrap()
        .build(
            "ignored",
            "ignored",
            Some(&HashMap::from([("target", target.as_str())])),
        )
        .unwrap();
    assert!(matches!(
        ordinary.get_password(),
        Err(Error::BadStoreFormat(_))
    ));

    let mut stored = raw(&target).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0x80;
    write_raw(&target, &stored);
    assert!(matches!(entry.get_secret(), Err(Error::BadStoreFormat(_))));
}

#[test]
fn writes_never_overwrite_an_unsealed_scoped_record() {
    let mut scope = Scope::new();
    scope.store.unlock(&[9; 32]).unwrap();
    let entry = scope.entry("user");
    let target = target_of(&entry);
    write_raw(&target, b"planted");
    assert!(matches!(
        entry.set_secret(b"replacement"),
        Err(Error::BadStoreFormat(_))
    ));
    assert!(matches!(entry.get_secret(), Err(Error::BadStoreFormat(_))));
    assert_eq!(raw(&target).unwrap(), b"planted");
}

#[test]
fn rewriting_a_secret_keeps_its_attributes() {
    let mut scope = Scope::new();
    scope.store.unlock(&[10; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"first").unwrap();
    entry
        .update_attributes(&HashMap::from([
            ("comment", "kept"),
            ("username", "renamed"),
        ]))
        .unwrap();
    entry.set_secret(b"second").unwrap();
    let attributes = entry.get_attributes().unwrap();
    assert_eq!(attributes["comment"], "kept");
    assert_eq!(attributes["username"], "renamed");
    assert_eq!(entry.get_secret().unwrap(), b"second");
}

#[test]
fn dropping_the_store_locks_retained_entries() {
    let mut scope = Scope::new();
    scope.store.unlock(&[71; 32]).unwrap();
    let entry = scope.entry("user");
    let reopened = scope.reopen();
    let store = std::mem::replace(&mut scope.store, reopened);
    drop(store);
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &SealError::Locked
    ));
}

#[test]
fn locked_delete_removes_the_entry_and_absent_entries_report_no_entry() {
    let mut scope = Scope::new();
    scope.store.unlock(&[44; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();
    entry.delete_credential().unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
}

#[test]
fn secrets_up_to_the_sealed_capacity_round_trip_and_larger_ones_are_refused() {
    // Credential Manager holds 2,560 bytes, and sealing adds 31.
    const CAPACITY: usize = 2560 - 31;
    let mut scope = Scope::new();
    scope.store.unlock(&[11; 32]).unwrap();
    let entry = scope.entry("user");
    let largest = vec![0x5A; CAPACITY];
    entry.set_secret(&largest).unwrap();
    assert_eq!(entry.get_secret().unwrap(), largest);
    assert!(matches!(
        entry.set_secret(&[0x5A; CAPACITY + 1]),
        Err(Error::TooLong(_, limit)) if limit as usize == CAPACITY
    ));
    assert_eq!(entry.get_secret().unwrap(), largest);
}

#[test]
fn seal_errors_map_to_keyring_error_kinds() {
    assert!(matches!(
        Error::from(SealError::Corrupt("record".into())),
        Error::BadStoreFormat(_)
    ));
    assert!(matches!(
        Error::from(SealError::Platform("service".into())),
        Error::PlatformFailure(_)
    ));
    for error in [
        SealError::Locked,
        SealError::WrongKey,
        SealError::TimedOut,
        SealError::Discarding,
        SealError::Discarded,
    ] {
        assert!(matches!(Error::from(error), Error::NoStorageAccess(_)));
    }
}

#[test]
fn the_store_lock_is_released_after_unlock() {
    let scope = Scope::new();
    scope.store.unlock(&[12; 32]).unwrap();
    let application = scope.application.clone();
    let unlocked = std::thread::spawn(move || {
        SealedStore::new(&application, "store")
            .unwrap()
            .unlock(&[12; 32])
    })
    .join()
    .unwrap();
    assert_eq!(unlocked, Ok(()));
}

#[test]
fn a_second_process_shares_the_store_and_its_locks() {
    const CHILD: &str = "SEALED_TESTS_CHILD";
    if let Ok(request) = std::env::var(CHILD) {
        let (held, application) = request.split_once(':').unwrap();
        let store = SealedStore::new(application, "store").unwrap();
        let probe = format!("{}probe", store.id());
        if held == "held" {
            let attempt = crate::sealed_lock::lock_target_with_timeout(
                &probe,
                std::time::Duration::from_millis(300),
            );
            assert!(matches!(attempt, Err(SealError::TimedOut)));
        } else {
            assert_eq!(store.unlock(&[14; 32]), Err(SealError::WrongKey));
            store.unlock(&[13; 32]).unwrap();
        }
        return;
    }
    let child = |request: String| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sealed_tests::a_second_process_shares_the_store_and_its_locks",
                "--test-threads",
                "1",
            ])
            .env(CHILD, request)
            .status()
            .unwrap()
            .success()
    };
    let scope = Scope::new();
    scope.store.unlock(&[13; 32]).unwrap();
    let probe = crate::sealed_lock::lock_target(&format!("{}probe", scope.store.id())).unwrap();
    assert!(child(format!("held:{}", scope.application)));
    drop(probe);
    assert!(child(format!("free:{}", scope.application)));
}

const DISCARD_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn discard_retires_every_handle_and_spares_a_sibling_store() {
    let mut scope = Scope::new();
    let mut sibling = scope.sibling("other");
    scope.store.unlock(&[21; 32]).unwrap();
    sibling.store.unlock(&[21; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"discarded").unwrap();
    let kept = sibling.entry("user");
    kept.set_secret(b"kept").unwrap();
    let second = scope.reopen();
    second.unlock(&[21; 32]).unwrap();
    let second_entry = second.build("service", "user", None).unwrap();

    scope.store.discard(DISCARD_TIMEOUT).unwrap();

    assert_eq!(scope.store.protection(), Protection::Locked);
    assert!(refused_with(entry.get_secret(), &SealError::Discarded));
    assert!(refused_with(
        second_entry.get_secret(),
        &SealError::Discarded
    ));
    assert!(refused_with(
        second_entry.delete_credential(),
        &SealError::Discarded
    ));
    assert_eq!(second.unlock(&[21; 32]), Err(SealError::Discarded));
    assert_eq!(
        scope.store.discard(DISCARD_TIMEOUT),
        Err(SealError::Discarded)
    );
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(raw(&scope.keycheck()), Err(Error::NoEntry)));
    assert_eq!(kept.get_secret().unwrap(), b"kept");

    let fresh = scope.reopen();
    fresh.unlock(&[22; 32]).unwrap();
    let reborn = fresh.build("service", "user", None).unwrap();
    assert!(matches!(reborn.get_secret(), Err(Error::NoEntry)));
    reborn.set_secret(b"second generation").unwrap();

    scope.reopen().discard(DISCARD_TIMEOUT).unwrap();
    assert!(refused_with(reborn.get_secret(), &SealError::Discarded));
}

#[test]
fn discard_waits_for_a_briefly_held_store_lock() {
    let scope = Scope::new();
    let control = scope.control();
    let (held, release) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let _lock = crate::sealed_lock::lock_target(&control).unwrap();
        held.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
    });
    release.recv().unwrap();
    assert_eq!(scope.store.discard(DISCARD_TIMEOUT), Ok(()));
    holder.join().unwrap();
}

#[test]
fn corrupt_control_record_blocks_the_store_until_discard() {
    let mut scope = Scope::new();
    scope.store.unlock(&[23; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    write_raw(&scope.control(), b"garbage");

    let blocked = scope.reopen();
    assert_eq!(blocked.unlock(&[23; 32]), Err(SealError::Discarding));
    assert!(refused_with(entry.get_secret(), &SealError::Discarding));
    blocked.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    scope.reopen().unlock(&[24; 32]).unwrap();
}

#[test]
fn an_interrupted_discard_blocks_until_any_handle_resumes_it() {
    let mut scope = Scope::new();
    scope.store.unlock(&[25; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    let mut marker = crate::sealed::CONTROL_MAGIC.to_vec();
    marker.push(1);
    marker.extend([7; 16]);
    write_raw(&scope.control(), &marker);

    assert!(refused_with(
        entry.set_secret(b"replacement"),
        &SealError::Discarding
    ));
    assert!(refused_with(
        entry.delete_credential(),
        &SealError::Discarding
    ));
    assert_eq!(scope.store.unlock(&[25; 32]), Err(SealError::Discarding));
    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(raw(&scope.keycheck()), Err(Error::NoEntry)));
    scope.reopen().unlock(&[26; 32]).unwrap();
}

#[test]
fn discard_gives_up_when_the_store_lock_stays_held() {
    let scope = Scope::new();
    let _held = crate::sealed_lock::lock_target(&scope.control()).unwrap();
    let store = Arc::clone(&scope.store);
    let result = std::thread::spawn(move || store.discard(Duration::from_millis(200)))
        .join()
        .unwrap();
    assert_eq!(result, Err(SealError::TimedOut));
}

#[test]
fn a_deleted_control_record_never_revives_a_retired_generation() {
    let mut scope = Scope::new();
    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    let current = scope.reopen();
    current.unlock(&[27; 32]).unwrap();
    let entry = current.build("service", "user", None).unwrap();
    scope.targets.push(target_of(&entry));
    delete_credential(&scope.control()).unwrap();

    assert!(refused_with(entry.get_secret(), &SealError::Discarded));
    assert_eq!(current.discard(DISCARD_TIMEOUT), Err(SealError::Discarded));
}
