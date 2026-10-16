//! Drop secrets in the operating system's keychain: macOS Keychain Services,
//! Windows Credential Manager, or the Linux Secret Service, through `keyring`.
//!
//! Entries live under the service [`SERVICE`] with these accounts:
//!
//! | Account | Value |
//! |---|---|
//! | `drop/device-secret` | the device secp256k1 secret key, 32 bytes |
//! | `drop/recovery-secret` | the recovery secret, 32 bytes |
//! | `drop/file-key/<file id>` | a per-file FSWNENC2 input key, 32 bytes |
//!
//! Values are stored as raw bytes.  Nothing here logs or formats a secret: read
//! values are wrapped in `Zeroizing` immediately, and errors from the platform
//! are reduced to a typed variant without their attached data (keyring's own
//! errors can carry the raw secret bytes, so they are never passed through).

use super::FileId;
use std::fmt;
use wildbloom_envelope::{InputKey, KEY_BYTES};
use zeroize::Zeroizing;

/// The keychain service name: the app's bundle identifier.
pub const SERVICE: &str = "dev.forgesworn.wildbloom-node";
const DEVICE_SECRET: &str = "drop/device-secret";
const RECOVERY_SECRET: &str = "drop/recovery-secret";
const FILE_KEY_PREFIX: &str = "drop/file-key/";

/// Why the keychain could not be used.  No variant carries secret bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeychainError {
    /// Linux only: no Secret Service provider (or no D-Bus session) is running.
    /// The first-run copy asks the owner to install or start a keyring.  When
    /// `restart_needed` is true the store failed to start when the app did, and
    /// keyring caches that for the life of the process, so the app must be
    /// restarted after the keyring is started; otherwise a retry is enough.
    #[error("no Secret Service keyring is running on this computer")]
    SecretServiceMissing { restart_needed: bool },
    /// macOS and Windows: the platform keychain could not be initialised.
    /// keyring caches this for the process, so it also needs a restart.
    #[error("the system keychain is unavailable")]
    Unavailable,
    /// The keychain is locked or the owner refused access.
    #[error("the system keychain is locked or refused access")]
    Denied,
    /// A stored value is not the expected 32 bytes.
    #[error("a keychain entry is not in the expected format")]
    Corrupt,
    /// Any other platform failure, described without its attached data.
    #[error("the system keychain failed ({0})")]
    Platform(&'static str),
}

/// A secret store keyed by account name.  The OS keychain in production, an
/// in-memory map in tests.
pub trait SecretStore: Send + Sync {
    /// `Ok(None)` when there is no entry.
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>;
    fn write(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError>;
    /// Succeeds when the entry is already absent.
    fn remove(&self, account: &str) -> Result<(), KeychainError>;
}

/// The platform keychain through `keyring`'s default store for this OS.
pub struct OsKeychain {
    service: String,
}

impl OsKeychain {
    /// Initialises the platform store.  keyring tries once per process and
    /// caches the outcome, so any failure here needs an app restart: on Linux
    /// it is `SecretServiceMissing { restart_needed: true }` whatever the cause.
    /// A provider that goes away later surfaces on an operation instead, so
    /// first run should also call [`Self::probe`].
    pub fn new() -> Result<Self, KeychainError> {
        if keyring::Entry::store_status().is_err() {
            return Err(store_init_failure());
        }
        Ok(Self {
            service: SERVICE.to_string(),
        })
    }

    /// Reads a probe account to confirm the keychain is reachable and unlocked.
    pub fn probe(&self) -> Result<(), KeychainError> {
        self.read("drop/probe").map(|_| ())
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry, KeychainError> {
        keyring::Entry::new(&self.service, account).map_err(|e| classify(&e))
    }
}

impl SecretStore for OsKeychain {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        match self.entry(account)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(classify(&error)),
        }
    }

    fn write(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.entry(account)?
            .set_secret(secret)
            .map_err(|e| classify(&e))
    }

    fn remove(&self, account: &str) -> Result<(), KeychainError> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(classify(&error)),
        }
    }
}

/// Reduces a keyring error to a variant without its payload.  `BadEncoding`
/// and `BadDataFormat` carry the stored bytes, so nothing of the error is kept.
fn classify(error: &keyring::Error) -> KeychainError {
    use keyring::Error as E;
    match error {
        E::NoDefaultStore => store_init_failure(),
        E::PlatformFailure(inner) => {
            if names_missing_secret_service(&inner.to_string()) {
                missing_or(false, KeychainError::Platform("platform failure"))
            } else {
                KeychainError::Platform("platform failure")
            }
        }
        E::NoStorageAccess(_) => KeychainError::Denied,
        E::BadEncoding(_) | E::BadDataFormat(..) => KeychainError::Corrupt,
        E::NoEntry => KeychainError::Platform("missing entry"),
        E::BadStoreFormat(_) => KeychainError::Platform("store format"),
        E::TooLong(..) => KeychainError::Platform("attribute too long"),
        E::Invalid(..) => KeychainError::Platform("invalid attribute"),
        E::Ambiguous(_) => KeychainError::Platform("ambiguous entry"),
        E::NotSupportedByStore(_) => KeychainError::Platform("unsupported operation"),
        _ => KeychainError::Platform("unknown"),
    }
}

/// A store that failed to start, which keyring will not retry in this process.
fn store_init_failure() -> KeychainError {
    missing_or(true, KeychainError::Unavailable)
}

/// On Linux a store that cannot start, or a D-Bus failure naming the Secret
/// Service, means no provider is running.  Elsewhere it is the fallback.
fn missing_or(restart_needed: bool, fallback: KeychainError) -> KeychainError {
    if cfg!(target_os = "linux") {
        KeychainError::SecretServiceMissing { restart_needed }
    } else {
        fallback
    }
}

/// The messages `secret-service` and D-Bus give when no provider is running.
/// Platform error text never contains secret values.
fn names_missing_secret_service(message: &str) -> bool {
    [
        "no secret service provider or dbus session found",
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "The name org.freedesktop.secrets was not provided",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

/// Typed access to Drop's entries on any [`SecretStore`].
pub struct DropKeychain<S: SecretStore> {
    store: S,
}

impl<S: SecretStore> fmt::Debug for DropKeychain<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DropKeychain")
    }
}

impl<S: SecretStore> DropKeychain<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    fn read_32(&self, account: &str) -> Result<Option<Zeroizing<[u8; KEY_BYTES]>>, KeychainError> {
        let Some(bytes) = self.store.read(account)? else {
            return Ok(None);
        };
        let mut out = Zeroizing::new([0u8; KEY_BYTES]);
        if bytes.len() != KEY_BYTES {
            return Err(KeychainError::Corrupt);
        }
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    /// The device secp256k1 secret key bytes.
    pub fn device_secret(&self) -> Result<Option<Zeroizing<[u8; KEY_BYTES]>>, KeychainError> {
        self.read_32(DEVICE_SECRET)
    }

    pub fn set_device_secret(&self, secret: &[u8; KEY_BYTES]) -> Result<(), KeychainError> {
        self.store.write(DEVICE_SECRET, secret)
    }

    pub fn recovery_secret(&self) -> Result<Option<InputKey>, KeychainError> {
        Ok(self
            .read_32(RECOVERY_SECRET)?
            .map(|bytes| InputKey::from_bytes(*bytes)))
    }

    pub fn set_recovery_secret(&self, secret: &InputKey) -> Result<(), KeychainError> {
        self.store.write(RECOVERY_SECRET, secret.expose())
    }

    pub fn file_key(&self, id: &FileId) -> Result<Option<InputKey>, KeychainError> {
        Ok(self
            .read_32(&file_account(id))?
            .map(|bytes| InputKey::from_bytes(*bytes)))
    }

    pub fn set_file_key(&self, id: &FileId, key: &InputKey) -> Result<(), KeychainError> {
        self.store.write(&file_account(id), key.expose())
    }

    pub fn remove_file_key(&self, id: &FileId) -> Result<(), KeychainError> {
        self.store.remove(&file_account(id))
    }

    /// Removes only the device secret (rolling back an interrupted first run).
    pub fn remove_device_secret(&self) -> Result<(), KeychainError> {
        self.store.remove(DEVICE_SECRET)
    }

    /// Removes the device and recovery secrets (used when the owner resets Drop).
    pub fn remove_identity(&self) -> Result<(), KeychainError> {
        self.store.remove(DEVICE_SECRET)?;
        self.store.remove(RECOVERY_SECRET)
    }
}

fn file_account(id: &FileId) -> String {
    format!("{FILE_KEY_PREFIX}{id}")
}

/// An in-memory [`SecretStore`] for tests.
#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore {
    entries: std::sync::Mutex<std::collections::HashMap<String, Zeroizing<Vec<u8>>>>,
    pub fail_with: std::sync::Mutex<Option<KeychainError>>,
}

#[cfg(test)]
impl MemoryStore {
    fn check(&self) -> Result<(), KeychainError> {
        match self.fail_with.lock().unwrap().clone() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn accounts(&self) -> Vec<String> {
        let mut out: Vec<_> = self.entries.lock().unwrap().keys().cloned().collect();
        out.sort();
        out
    }
}

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        self.check()?;
        Ok(self.entries.lock().unwrap().get(account).cloned())
    }

    fn write(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.check()?;
        self.entries
            .lock()
            .unwrap()
            .insert(account.to_string(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn remove(&self, account: &str) -> Result<(), KeychainError> {
        self.check()?;
        self.entries.lock().unwrap().remove(account);
        Ok(())
    }
}

#[cfg(test)]
impl SecretStore for std::sync::Arc<MemoryStore> {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        (**self).read(account)
    }
    fn write(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        (**self).write(account, secret)
    }
    fn remove(&self, account: &str) -> Result<(), KeychainError> {
        (**self).remove(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn keychain() -> (Arc<MemoryStore>, DropKeychain<Arc<MemoryStore>>) {
        let store = Arc::new(MemoryStore::default());
        (store.clone(), DropKeychain::new(store))
    }

    #[test]
    fn stores_reads_and_removes_each_entry() {
        let (store, keychain) = keychain();
        assert!(keychain.device_secret().unwrap().is_none());
        assert!(keychain.recovery_secret().unwrap().is_none());
        let id = FileId::from_bytes([7; 16]);
        assert!(keychain.file_key(&id).unwrap().is_none());

        keychain.set_device_secret(&[1; 32]).unwrap();
        let recovery = InputKey::from_bytes([2; 32]);
        keychain.set_recovery_secret(&recovery).unwrap();
        let file_key = InputKey::from_bytes([3; 32]);
        keychain.set_file_key(&id, &file_key).unwrap();

        assert_eq!(*keychain.device_secret().unwrap().unwrap(), [1; 32]);
        assert_eq!(keychain.recovery_secret().unwrap().unwrap(), recovery);
        assert_eq!(keychain.file_key(&id).unwrap().unwrap(), file_key);
        assert_eq!(
            store.accounts(),
            vec![
                "drop/device-secret".to_string(),
                format!("drop/file-key/{}", "07".repeat(16)),
                "drop/recovery-secret".to_string(),
            ]
        );

        keychain.remove_file_key(&id).unwrap();
        keychain.remove_file_key(&id).unwrap();
        assert!(keychain.file_key(&id).unwrap().is_none());
        keychain.remove_identity().unwrap();
        assert!(store.accounts().is_empty());
    }

    #[test]
    fn a_wrong_length_entry_is_corrupt() {
        let (store, keychain) = keychain();
        store.write(RECOVERY_SECRET, &[0; 31]).unwrap();
        assert_eq!(keychain.recovery_secret(), Err(KeychainError::Corrupt));
    }

    #[test]
    fn store_errors_pass_through_typed() {
        let (store, keychain) = keychain();
        let missing = KeychainError::SecretServiceMissing {
            restart_needed: false,
        };
        *store.fail_with.lock().unwrap() = Some(missing.clone());
        assert_eq!(keychain.device_secret().unwrap_err(), missing);
    }

    #[test]
    fn keyring_errors_drop_their_payloads() {
        let secret = vec![0x5a; 32];
        let corrupt = classify(&keyring::Error::BadEncoding(secret.clone()));
        assert_eq!(corrupt, KeychainError::Corrupt);
        for text in [format!("{corrupt}"), format!("{corrupt:?}")] {
            assert!(!text.contains("90"), "{text}");
            assert!(!text.contains("5a"), "{text}");
        }
        let unavailable = classify(&keyring::Error::NoDefaultStore);
        if cfg!(target_os = "linux") {
            assert_eq!(
                unavailable,
                KeychainError::SecretServiceMissing {
                    restart_needed: true
                }
            );
        } else {
            assert_eq!(unavailable, KeychainError::Unavailable);
        }
        let denied = classify(&keyring::Error::NoStorageAccess(Box::new(
            std::io::Error::other("locked"),
        )));
        assert_eq!(denied, KeychainError::Denied);
    }

    #[test]
    fn any_store_start_failure_needs_a_restart_on_linux() {
        let failure = store_init_failure();
        if cfg!(target_os = "linux") {
            assert_eq!(
                failure,
                KeychainError::SecretServiceMissing {
                    restart_needed: true
                }
            );
        } else {
            assert_eq!(failure, KeychainError::Unavailable);
        }
        assert_eq!(classify(&keyring::Error::NoDefaultStore), failure);
    }

    #[test]
    fn recognises_a_missing_secret_service() {
        assert!(names_missing_secret_service(
            "zbus error: no secret service provider or dbus session found"
        ));
        assert!(names_missing_secret_service(
            "org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.secrets was not provided by any .service files"
        ));
        assert!(!names_missing_secret_service("SS Error: object locked"));
    }
}
