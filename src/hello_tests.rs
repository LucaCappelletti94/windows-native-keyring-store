use std::collections::HashMap;

use keyring_core::{Error, api::CredentialStoreApi};

use crate::{HelloStore, Store, hello::HelloError};

fn target_of(entry: &keyring_core::Entry) -> String {
    let cred = entry.as_any().downcast_ref::<crate::cred::Cred>();
    cred.unwrap().target_name.clone()
}

fn legacy_entry(application: &str, user: &str) -> keyring_core::Entry {
    Store::new()
        .unwrap()
        .build(application, user, None)
        .unwrap()
}

struct ScopeCleanup {
    prefix: String,
    targets: Vec<String>,
}

impl ScopeCleanup {
    fn new(store: &HelloStore) -> Self {
        Self {
            prefix: store.id(),
            targets: Vec::new(),
        }
    }

    fn track(&mut self, entry: &keyring_core::Entry) -> String {
        let target = target_of(entry);
        self.targets.push(target.clone());
        target
    }
}

impl Drop for ScopeCleanup {
    fn drop(&mut self) {
        for target in &self.targets {
            let _ = crate::utils::delete_credential(target);
        }
        for suffix in ["metadata", "control"] {
            let _ = crate::utils::delete_credential(&format!("{}{suffix}", self.prefix));
        }
    }
}

#[test]
fn named_store_refuses_plaintext_operations_while_locked() {
    let store = HelloStore::new("app", "account").unwrap();
    let entry = store.build("service", "user", None).unwrap();
    for result in [entry.get_secret().map(drop), entry.set_secret(b"secret")] {
        let Err(Error::NoStorageAccess(reason)) = result else {
            panic!("locked store returned a secret operation result");
        };
        assert!(matches!(
            reason.downcast_ref::<HelloError>(),
            Some(HelloError::Locked)
        ));
    }
}

#[test]
fn named_store_scopes_targets_and_rejects_enterprise_persistence() {
    let first = HelloStore::new("an", "account").unwrap();
    let second = HelloStore::new("a", "naccount").unwrap();
    let first_entry = first.build("svc", "user", None).unwrap();
    let second_entry = second.build("svc", "user", None).unwrap();
    let first_target = target_of(&first_entry);
    assert_ne!(first_target, target_of(&second_entry));
    let reopened = HelloStore::new("an", "account").unwrap();
    assert_eq!(first.id(), reopened.id());
    let reopened_entry = reopened.build("svc", "user", None).unwrap();
    assert_eq!(first_target, target_of(&reopened_entry));
    assert!(matches!(
        first.build(
            "svc",
            "user",
            Some(&HashMap::from([("persistence", "Enterprise")]))
        ),
        Err(Error::Invalid(_, _))
    ));
    assert!(matches!(
        first.build(
            "svc",
            "user",
            Some(&HashMap::from([("target", "outside-namespace")]))
        ),
        Err(Error::Invalid(_, _))
    ));
}

struct MissingWindow;

impl crate::hello::HelloWindow for MissingWindow {
    fn hwnd(&self) -> windows_sys::Win32::Foundation::HWND {
        std::ptr::null_mut()
    }
}

#[test]
fn unlock_without_live_owner_fails_before_authentication() {
    let store = HelloStore::new("app", "missing-owner").unwrap();
    let result = store.unlock(
        std::sync::Arc::new(MissingWindow),
        &crate::hello::HelloCancellation::new(),
        std::time::Duration::from_secs(5),
    );
    assert!(matches!(result, Err(HelloError::MissingOwner)));
}

#[test]
fn migration_seals_exact_legacy_secret_before_returning_it() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("user-{}", fastrand::u64(..));
    let legacy = legacy_entry(&application, &user);
    legacy.set_password("refresh-token").unwrap();

    let protected_store = HelloStore::new(&application, "shared").unwrap();
    let protected = protected_store.build(&application, &user, None).unwrap();
    protected_store.install_test_key([17; 32]);
    assert_eq!(protected.get_password().unwrap(), "refresh-token");
    assert!(matches!(legacy.get_password(), Err(Error::NoEntry)));

    let stored =
        crate::utils::extract_from_credential(&target_of(&protected), crate::utils::extract_secret)
            .unwrap();
    assert!(crate::hello_crypto::is_protected(&stored));
    assert_ne!(stored, b"refresh-token");
    protected_store.lock();
    assert!(matches!(
        protected.get_password(),
        Err(Error::NoStorageAccess(_))
    ));
    protected_store.install_test_key([17; 32]);
    protected.delete_credential().unwrap();
}

#[test]
fn failed_migration_preserves_the_original_credential() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("user-{}", fastrand::u64(..));
    let legacy = legacy_entry(&application, &user);
    let original =
        vec![42; windows_sys::Win32::Security::Credentials::CRED_MAX_CREDENTIAL_BLOB_SIZE as usize];
    legacy.set_secret(&original).unwrap();

    let protected_store = HelloStore::new(&application, "shared").unwrap();
    let protected = protected_store.build(&application, &user, None).unwrap();
    protected_store.install_test_key([27; 32]);
    assert!(matches!(protected.get_secret(), Err(Error::TooLong(_, _))));
    assert_eq!(legacy.get_secret().unwrap(), original);
    assert!(matches!(
        crate::utils::extract_from_credential(&target_of(&protected), crate::utils::extract_secret),
        Err(Error::NoEntry)
    ));
    legacy.delete_credential().unwrap();
}

#[test]
fn locked_delete_removes_both_exact_sources_without_decrypting() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("user-{}", fastrand::u64(..));
    let store = HelloStore::new(&application, "shared").unwrap();
    let mut cleanup = ScopeCleanup::new(&store);
    store.install_test_key([44; 32]);
    let protected = store.build(&application, &user, None).unwrap();
    let scoped_target = cleanup.track(&protected);
    protected.set_secret(b"sealed").unwrap();
    store.lock();

    let legacy = legacy_entry(&application, &user);
    cleanup.track(&legacy);
    legacy.set_secret(b"independent").unwrap();
    protected.delete_credential().unwrap();
    assert!(matches!(legacy.get_secret(), Err(Error::NoEntry)));
    assert!(matches!(
        crate::utils::extract_from_credential(&scoped_target, crate::utils::extract_secret),
        Err(Error::NoEntry)
    ));
}

#[test]
fn deleting_a_legacy_entry_never_exposes_a_plaintext_source_afterwards() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("user-{}", fastrand::u64(..));
    let legacy = legacy_entry(&application, &user);
    legacy.set_secret(b"legacy").unwrap();

    let store = HelloStore::new(&application, "shared").unwrap();
    store.install_test_key([53; 32]);
    let protected = store.build(&application, &user, None).unwrap();
    protected.delete_credential().unwrap();
    assert!(matches!(legacy.get_secret(), Err(Error::NoEntry)));
    assert!(matches!(protected.get_secret(), Err(Error::NoEntry)));
}

#[test]
fn ordinary_store_public_construction_remains_available() {
    let plain = Store {
        id: "ordinary".into(),
        delimiters: [String::new(), ".".into(), String::new()],
        service_no_divider: false,
    };
    let entry = plain
        .build("service", &format!("test-{}", fastrand::u64(..)), None)
        .unwrap();
    entry.set_secret(b"ordinary entry").unwrap();
    assert_eq!(entry.get_secret().unwrap(), b"ordinary entry");
    entry.delete_credential().unwrap();
}

#[test]
fn tampered_scoped_ciphertext_never_returns_plaintext() {
    let application = format!("test-{}", fastrand::u64(..));
    let store = HelloStore::new(&application, "shared").unwrap();
    store.install_test_key([41; 32]);
    let entry = store.build(&application, "credential", None).unwrap();
    entry.set_secret(b"sealed-token").unwrap();

    let target = &target_of(&entry);
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
    let mut stored =
        crate::utils::extract_from_credential(target, crate::utils::extract_secret).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0x80;
    crate::utils::save_credential(
        target,
        "credential",
        "",
        "",
        &stored,
        &crate::CredPersist::Local,
    )
    .unwrap();
    assert!(matches!(entry.get_secret(), Err(Error::BadStoreFormat(_))));
    entry.delete_credential().unwrap();
}

#[test]
fn dropping_the_store_locks_retained_entries() {
    let store = HelloStore::new("test", &format!("drop-{}", fastrand::u64(..))).unwrap();
    store.install_test_key([71; 32]);
    let entry = store.build("service", "user", None).unwrap();
    drop(store);
    assert!(matches!(
        entry.set_secret(b"secret"),
        Err(Error::NoStorageAccess(_))
    ));
}

#[test]
fn migration_accepts_arbitrary_legacy_binary_secret() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("binary-{}", fastrand::u64(..));
    let ordinary = legacy_entry(&application, &user);
    let secret = [0xFF, 0xFF, 0x01, 0x02, 0x00];
    ordinary.set_secret(&secret).unwrap();

    let store = HelloStore::new(&application, "shared").unwrap();
    store.install_test_key([92; 32]);
    let protected = store.build(&application, &user, None).unwrap();
    assert!(matches!(
        protected.get_password(),
        Err(Error::BadStoreFormat(_))
    ));
    assert_eq!(protected.get_secret().unwrap(), secret);
    assert!(matches!(ordinary.get_secret(), Err(Error::NoEntry)));
    protected.delete_credential().unwrap();
}

#[test]
fn locked_delete_of_absent_entry_returns_no_entry() {
    let application = format!("delete-{}", fastrand::u64(..));
    let store = HelloStore::new(&application, "shared").unwrap();
    let entry = store.build(&application, "absent", None).unwrap();
    assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
}

#[test]
fn discard_retires_old_handles_and_preserves_another_named_store() {
    let application = format!("discard-{}", fastrand::u64(..));
    let first = HelloStore::new(&application, "first").unwrap();
    let second = HelloStore::new(&application, "second").unwrap();
    let mut first_cleanup = ScopeCleanup::new(&first);
    let mut second_cleanup = ScopeCleanup::new(&second);
    first.install_test_key([12; 32]);
    second.install_test_key([13; 32]);
    let old = first.build(&application, "item", None).unwrap();
    let neighbor = second.build(&application, "item", None).unwrap();
    let first_target = first_cleanup.track(&old);
    second_cleanup.track(&neighbor);
    old.set_secret(b"first").unwrap();
    neighbor.set_secret(b"second").unwrap();

    first.discard(std::time::Duration::from_secs(5)).unwrap();
    assert!(matches!(
        crate::utils::extract_from_credential(&first_target, crate::utils::extract_secret),
        Err(Error::NoEntry)
    ));
    assert_eq!(neighbor.get_secret().unwrap(), b"second");

    let fresh = HelloStore::new(&application, "first").unwrap();
    fresh.install_test_key([17; 32]);
    let replacement = fresh.build(&application, "item", None).unwrap();
    replacement.set_secret(b"replacement").unwrap();
    assert!(matches!(
        old.set_secret(b"stale"),
        Err(Error::NoStorageAccess(_))
    ));
    assert!(matches!(
        old.delete_credential(),
        Err(Error::NoStorageAccess(_))
    ));
    assert_eq!(replacement.get_secret().unwrap(), b"replacement");
}

fn write_raw(target: &str, bytes: &[u8]) {
    crate::utils::save_credential(target, "", "", "", bytes, &crate::CredPersist::Local).unwrap();
}

fn refused_with(result: keyring_core::Result<()>, expected: &HelloError) -> bool {
    matches!(
        result,
        Err(Error::NoStorageAccess(reason)) if reason.downcast_ref::<HelloError>() == Some(expected)
    )
}

#[test]
fn discard_recovers_from_corrupt_enrollment_metadata() {
    let application = format!("discard-{}", fastrand::u64(..));
    let store = HelloStore::new(&application, "metadata").unwrap();
    let mut cleanup = ScopeCleanup::new(&store);
    store.install_test_key([21; 32]);
    let entry = store.build(&application, "item", None).unwrap();
    let target = cleanup.track(&entry);
    entry.set_secret(b"sealed").unwrap();
    let metadata = format!("{}metadata", store.id());
    write_raw(&metadata, b"not enrollment metadata");

    store.discard(std::time::Duration::from_secs(5)).unwrap();
    for removed in [&target, &metadata] {
        assert!(matches!(
            crate::utils::extract_from_credential(removed, crate::utils::extract_secret),
            Err(Error::NoEntry)
        ));
    }
}

#[test]
fn corrupt_control_record_opens_blocked_until_discard() {
    let application = format!("discard-{}", fastrand::u64(..));
    let neighbor = HelloStore::new(&application, "neighbor").unwrap();
    let mut neighbor_cleanup = ScopeCleanup::new(&neighbor);
    neighbor.install_test_key([31; 32]);
    let kept = neighbor.build(&application, "item", None).unwrap();
    neighbor_cleanup.track(&kept);
    kept.set_secret(b"kept").unwrap();

    let mut cleanup = ScopeCleanup::new(&HelloStore::new(&application, "control").unwrap());
    write_raw(
        &format!("{}control", cleanup.prefix),
        b"not a control record",
    );
    let blocked = HelloStore::new(&application, "control").unwrap();
    blocked.install_test_key([32; 32]);
    let entry = blocked.build(&application, "item", None).unwrap();
    cleanup.track(&entry);
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &HelloError::Discarding
    ));
    assert!(refused_with(
        entry.delete_credential(),
        &HelloError::Discarding
    ));

    blocked.discard(std::time::Duration::from_secs(5)).unwrap();
    assert!(refused_with(
        entry.set_secret(b"stale"),
        &HelloError::Discarded
    ));
    let fresh = HelloStore::new(&application, "control").unwrap();
    fresh.install_test_key([33; 32]);
    let replacement = fresh.build(&application, "item", None).unwrap();
    replacement.set_secret(b"replacement").unwrap();
    assert_eq!(replacement.get_secret().unwrap(), b"replacement");
    assert_eq!(kept.get_secret().unwrap(), b"kept");
}
