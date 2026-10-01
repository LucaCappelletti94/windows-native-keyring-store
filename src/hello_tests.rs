use std::collections::HashMap;

use keyring_core::{Error, api::CredentialStoreApi};

use crate::{HelloStore, Store, hello::HelloError};

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
    let first_target = &first_entry
        .as_any()
        .downcast_ref::<crate::cred::Cred>()
        .unwrap()
        .target_name;
    let second_target = &second_entry
        .as_any()
        .downcast_ref::<crate::cred::Cred>()
        .unwrap()
        .target_name;
    assert_ne!(first_target, second_target);
    let reopened = HelloStore::new("an", "account").unwrap();
    assert_eq!(first.id(), reopened.id());
    let reopened_entry = reopened.build("svc", "user", None).unwrap();
    assert_eq!(
        first_target,
        &reopened_entry
            .as_any()
            .downcast_ref::<crate::cred::Cred>()
            .unwrap()
            .target_name
    );
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
    let ordinary = Store::new().unwrap();
    let legacy = ordinary.build(&application, &user, None).unwrap();
    legacy.set_password("refresh-token").unwrap();

    let protected_store = HelloStore::new(&application, "shared").unwrap();
    let protected = protected_store.build(&application, &user, None).unwrap();
    protected_store.install_test_key([17; 32]);
    assert_eq!(protected.get_password().unwrap(), "refresh-token");
    assert!(matches!(legacy.get_password(), Err(Error::NoEntry)));

    let target = &protected
        .as_any()
        .downcast_ref::<crate::cred::Cred>()
        .unwrap()
        .target_name;
    let stored =
        crate::utils::extract_from_credential(target, crate::utils::extract_secret).unwrap();
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
    let legacy = Store::new()
        .unwrap()
        .build(&application, &user, None)
        .unwrap();
    let original = vec![
        42;
        usize::try_from(
            windows_sys::Win32::Security::Credentials::CRED_MAX_CREDENTIAL_BLOB_SIZE
        )
        .unwrap()
    ];
    legacy.set_secret(&original).unwrap();

    let protected_store = HelloStore::new(&application, "shared").unwrap();
    let protected = protected_store.build(&application, &user, None).unwrap();
    protected_store.install_test_key([27; 32]);
    assert!(matches!(protected.get_secret(), Err(Error::TooLong(_, _))));
    assert!(matches!(
        protected.delete_credential(),
        Err(Error::TooLong(_, _))
    ));
    assert_eq!(legacy.get_secret().unwrap(), original);
    let target = &protected
        .as_any()
        .downcast_ref::<crate::cred::Cred>()
        .unwrap()
        .target_name;
    assert!(matches!(
        crate::utils::extract_from_credential(target, crate::utils::extract_secret),
        Err(Error::NoEntry)
    ));
    legacy.delete_credential().unwrap();
}

#[test]
fn deleting_a_scoped_entry_refuses_an_unmigrated_legacy_duplicate() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("user-{}", fastrand::u64(..));
    let store = HelloStore::new(&application, "shared").unwrap();
    store.install_test_key([44; 32]);
    let protected = store.build(&application, &user, None).unwrap();
    protected.set_secret(b"sealed").unwrap();

    let legacy = Store::new()
        .unwrap()
        .build(&application, &user, None)
        .unwrap();
    legacy.set_secret(b"independent").unwrap();
    assert!(matches!(
        protected.delete_credential(),
        Err(Error::PlatformFailure(reason)) if matches!(reason.downcast_ref::<HelloError>(), Some(HelloError::Conflict(_)))
    ));
    assert_eq!(protected.get_secret().unwrap(), b"sealed");
    assert_eq!(legacy.get_secret().unwrap(), b"independent");
    legacy.delete_credential().unwrap();
    protected.delete_credential().unwrap();
}

#[test]
fn deleting_a_legacy_entry_never_exposes_a_plaintext_source_afterwards() {
    let application = format!("test-{}", fastrand::u64(..));
    let user = format!("user-{}", fastrand::u64(..));
    let legacy = Store::new()
        .unwrap()
        .build(&application, &user, None)
        .unwrap();
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

    let target = &entry
        .as_any()
        .downcast_ref::<crate::cred::Cred>()
        .unwrap()
        .target_name;
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
    let ordinary = Store::new()
        .unwrap()
        .build(&application, &user, None)
        .unwrap();
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
