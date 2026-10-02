use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use keyring_core::api::{CredentialPersistence, CredentialStoreApi};
use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};

use crate::CredPersist;
use crate::cred::Cred;
use crate::hello::{Gate, HelloCancellation, HelloError, HelloWindow, Protection};

/// A named Windows Hello PRF store sharing one gate across all entries.
pub struct HelloStore {
    id: String,
    gate: Arc<Gate>,
}

impl HelloStore {
    /// Create a stable application/store-scoped credential namespace.
    pub fn new(application: &str, store: &str) -> Result<Arc<Self>> {
        let gate = Gate::new(application, store)?;
        Ok(Arc::new(Self {
            id: gate.id(),
            gate,
        }))
    }

    /// Unlock through a live owner and one cancellable Hello operation.
    pub fn unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> std::result::Result<(), HelloError> {
        self.gate.unlock(owner, cancellation, timeout)
    }

    /// Erase the shared sealing key and cancel any pending operation.
    pub fn lock(&self) {
        self.gate.lock();
    }

    /// Delete this store's entries, enrollment, and passkey, retiring every existing handle.
    pub fn discard(&self, timeout: Duration) -> std::result::Result<(), HelloError> {
        self.gate.discard(timeout)
    }

    /// Report whether this store has an unlocked or lost key.
    pub fn protection(&self) -> Protection {
        self.gate.protection()
    }

    /// Check for a selectable Hello authenticator without claiming PRF support.
    pub fn capability() -> std::result::Result<(), HelloError> {
        crate::hello_native::available()
    }
    #[cfg(test)]
    pub(crate) fn install_test_key(&self, key: [u8; 32]) {
        self.gate.install_test_key(key);
    }
}

impl Drop for HelloStore {
    fn drop(&mut self) {
        self.gate.lock();
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
        let modifiers = parse_attributes(&["target", "persistence"], modifiers)?;
        if modifiers.contains_key("target") {
            return Err(Error::Invalid(
                "target".into(),
                "Hello targets are derived from service and user".into(),
            ));
        }
        let persistence: CredPersist = modifiers
            .get("persistence")
            .map_or("Local", String::as_str)
            .parse()?;
        if persistence != CredPersist::Local {
            return Err(Error::Invalid(
                "persistence".into(),
                "Hello entries require Local persistence".into(),
            ));
        }
        let delimiters = [String::new(), ".".into(), String::new()];
        let mut cred =
            Cred::build_from_specifiers(None, &delimiters, false, service, user, persistence)?;
        cred.target_name = self.gate.scoped_target(&cred.target_name)?;
        cred.hello = Some(Arc::clone(&self.gate));
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }

    #[cfg(feature = "search")]
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(&["pattern"], Some(spec))?;
        let pattern = spec
            .get("pattern")
            .map(|pattern| {
                regex::Regex::new(pattern).map_err(|_| {
                    Error::Invalid(
                        pattern.to_string(),
                        "is not a valid regular expression".into(),
                    )
                })
            })
            .transpose()?;
        self.gate.search(
            pattern.as_ref(),
            &[String::new(), ".".into(), String::new()],
        )
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
