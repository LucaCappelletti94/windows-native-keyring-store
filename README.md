# Windows Native Keyring Store

[![build](https://github.com/open-source-cooperative/windows-native-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/windows-native-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/windows-native-keyring-store.svg?style=flat-square)](https://crates.io/crates/windows-native-keyring-store) [![docs.rs](https://docs.rs/windows-native-keyring-store/badge.svg)](https://docs.rs/windows-native-keyring-store)

Windows Credential Manager storage for the [`keyring-core`](https://crates.io/crates/keyring-core) ecosystem. See the [ordinary store example](examples/example.rs).

## Stores

`Store::new()` uses the exact `{user}.{service}` target with `Enterprise` persistence. `Store::new_with_configuration()` accepts `prefix`, `divider`, `suffix`, and `service_no_divider` options.

Ordinary credentials can also specify a `target` and `persistence` modifier. Their `username`, `target_alias`, and `comment` attributes can be updated.

`HelloStore::new(application, store)` creates a named, application-scoped Windows Hello PRF store implementing `CredentialStoreApi`. Each entry gets a scoped target with `Local` persistence.

An explicit `target` or any other persistence is rejected. Store names partition credentials within the Windows account and do not provide application-identity isolation.

The first `unlock` enrolls a credential with one Windows Hello approval. Later unlocks assert against that credential with one approval. Pass an `Arc<dyn HelloWindow>` that owns a **live GUI window** for the entire native operation.

Supply a fresh `HelloCancellation` for each request and a bounded timeout. `lock` cancels a pending request and erases the shared sealing key. Dropping the store also locks retained entry handles.

```rust
use keyring_core::api::CredentialStoreApi;
use std::{sync::Arc, time::Duration};
use windows_native_keyring_store::{HelloStore, hello::{HelloCancellation, HelloWindow}};

fn read_secret(window: Arc<dyn HelloWindow>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let store = HelloStore::new("example-app", "account")?;
    let entry = store.build("example-app", "alice", None)?;
    let cancellation = HelloCancellation::new();
    store.unlock(window, &cancellation, Duration::from_secs(60))?;
    let secret = entry.get_secret()?;
    store.lock();
    Ok(secret)
}
```

The gate requires Windows WebAuthn API `9` and explicitly selects Windows Hello for creation and assertion. `HelloStore::capability()` checks for the selectable authenticator. PRF support is verified during unlock.

Missing credentials or metadata beside protected entries return key loss or corruption without replacing the credential. Only public credential ID, random user ID, and salt metadata persist outside encrypted entries.

After an authenticated unlock, first access to an exact legacy `{user}.{service}` target seals the existing secret under its scoped target and persists it before deleting that source. Stop external legacy writers during migration.

Participating library writers share a named cross-process mutex and recheck the source before deletion. Windows has no compare-and-delete credential API, so a nonparticipating writer racing that final deletion can lose its update.

## Search and threading

The default `search` feature enables regular-expression credential search and requires `regex`. Disable default features if search is unnecessary. The named store searches only its scoped targets.

Concurrent operations on the same ordinary entry may not complete in initiation order. Coordinate application writes to a shared entry. Changing persistence immediately before a read may fail while Credential Manager is busy.

## License

Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your discretion. Contributions submitted without a separate agreement carry the same dual license.
