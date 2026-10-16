//! Drop's key material: the device keypair, the recovery secret, the recovery
//! identity and the encrypted key list.
//!
//! # API
//!
//! - [`DeviceKeys::generate`], [`DeviceKeys::load_or_create`]: the device's own
//!   secp256k1 keypair, which signs uploads without a prompt per file.  Its
//!   secret lives in the OS keychain.
//! - [`RecoverySecret::generate`]: 32 random bytes, shown once to the owner as
//!   `wbk1_` text ([`RecoverySecret::to_display`]) and accepted back by
//!   [`RecoverySecret::parse`] on restore.
//! - [`RecoverySecret::identity`]: the recovery identity keypair, derived as below.
//!   It is approved in the same grant as the device key and is the only key
//!   that uploads the key list.
//! - [`KeyList`]: the per-file keys and file metadata.  [`KeyList::seal`] makes
//!   an FSWNENC2 vault-mode envelope under the recovery secret (used directly as
//!   the FSWNENC2 input key) and [`KeyList::open`] reverses it on restore.
//!
//! # Recovery identity derivation
//!
//! ```text
//! okm = HKDF-SHA256(ikm  = recovery secret (32 bytes),
//!                   salt = "wildbloom-drop/v1"                               (UTF-8),
//!                   info = "wildbloom-drop/recovery-identity/secp256k1/v1"   (UTF-8),
//!                   L    = 32)
//! recovery identity secret key = okm, as a big-endian secp256k1 scalar
//! ```
//!
//! The derivation fails closed if `okm` is zero or not below the curve order
//! (probability about 2^-128); [`RecoverySecret::generate`] redraws in that case,
//! so every recovery secret it hands out has an identity.  The FSWNENC2 key
//! list envelope also uses the recovery secret as HKDF input, but with the
//! envelope's own `info` (`forgesworn-aes-256-gcm-chunked/v2`) and a fresh random
//! salt, so the two outputs are domain-separated.
//!
//! # Key list format, version 1
//!
//! The plaintext is canonical JSON (no whitespace, keys in this order, minimal
//! escaping, entries sorted by strictly ascending `id`):
//!
//! ```text
//! {"v":"wildbloom-drop-keys/1","files":[
//!   {"id":"<32 hex>","sha256":"<64 hex>","size":<envelope bytes>,"key":"wbk1_…",
//!    "name":"<sanitised name>","type":"<media type>","bytes":<plaintext bytes>,
//!    "added":<unix seconds>}, …]}
//! ```
//!
//! It is sealed as one FSWNENC2 envelope whose private metadata is
//! `wildbloom-drop-keys.json` / `application/json`.  The decoder checks the
//! version first and refuses any other `v` with [`KeyListError::UnsupportedVersion`],
//! then re-encodes and compares so that only the canonical form is accepted.
//! Local paths are deliberately absent.

use super::FileId;
use super::keychain::{DropKeychain, KeychainError, SecretStore};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use wildbloom_envelope::{InputKey, KEY_BYTES, KeyError, Limits, MIN_ENVELOPE_BYTES};
use zeroize::{Zeroize, Zeroizing};

/// HKDF salt for every Drop derivation from the recovery secret.
pub const RECOVERY_HKDF_SALT: &[u8] = b"wildbloom-drop/v1";
/// HKDF info for the recovery identity.
pub const RECOVERY_IDENTITY_INFO: &[u8] = b"wildbloom-drop/recovery-identity/secp256k1/v1";

/// The key list's version tag.
pub const KEY_LIST_VERSION: &str = "wildbloom-drop-keys/1";
/// The private name inside the key list envelope.
pub const KEY_LIST_NAME: &str = "wildbloom-drop-keys.json";
/// The private media type inside the key list envelope.
pub const KEY_LIST_MEDIA_TYPE: &str = "application/json";
/// The key list's own envelope limit: 64 MiB is tens of thousands of files.
pub const KEY_LIST_LIMITS: Limits = Limits::new(64 * 1024 * 1024);
/// JavaScript's largest exact integer, so other implementations read numbers exactly.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(transparent)]
    Keychain(#[from] KeychainError),
    #[error("the system random source failed")]
    Random,
    #[error("the stored device secret is not a valid secp256k1 key")]
    InvalidDeviceSecret,
    #[error("the recovery key is not a valid wbk1_ key")]
    RecoveryKeyEncoding,
    #[error("this recovery key has no valid recovery identity")]
    NoRecoveryIdentity,
}

impl From<KeyError> for DeviceError {
    fn from(_: KeyError) -> Self {
        Self::RecoveryKeyEncoding
    }
}

/// The device's secp256k1 keypair.  `Debug` shows only the public key.
pub struct DeviceKeys(nostr::prelude::Keys);

impl DeviceKeys {
    /// A fresh keypair from the OS random source.
    pub fn generate() -> Self {
        Self(nostr::prelude::Keys::generate())
    }

    pub fn from_secret(secret: &[u8; KEY_BYTES]) -> Result<Self, DeviceError> {
        let secret_key = nostr::prelude::SecretKey::from_slice(secret)
            .map_err(|_| DeviceError::InvalidDeviceSecret)?;
        Ok(Self(nostr::prelude::Keys::new(secret_key)))
    }

    /// Loads the device key from the keychain, creating and storing one if
    /// there is none yet.
    pub fn load_or_create<S: SecretStore>(keychain: &DropKeychain<S>) -> Result<Self, DeviceError> {
        if let Some(secret) = keychain.device_secret()? {
            return Self::from_secret(&secret);
        }
        let keys = Self::generate();
        keychain.set_device_secret(&keys.secret_bytes())?;
        Ok(keys)
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; KEY_BYTES]> {
        Zeroizing::new(self.0.secret_key().to_secret_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        self.0.public_key().to_hex()
    }

    /// For signing in later steps (BUD-11 uploads, NIP-98 requests).
    pub fn keys(&self) -> &nostr::prelude::Keys {
        &self.0
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKeys({})", self.public_key_hex())
    }
}

/// The recovery identity keypair.  `Debug` shows only the public key.
pub struct RecoveryIdentity(nostr::prelude::Keys);

impl RecoveryIdentity {
    pub fn public_key_hex(&self) -> String {
        self.0.public_key().to_hex()
    }

    pub fn keys(&self) -> &nostr::prelude::Keys {
        &self.0
    }
}

impl fmt::Debug for RecoveryIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryIdentity({})", self.public_key_hex())
    }
}

/// The 32-byte recovery secret.  Zeroised on drop; `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverySecret(InputKey);

impl RecoverySecret {
    /// 32 fresh random bytes with a valid recovery identity.
    pub fn generate() -> Result<Self, DeviceError> {
        // A redraw is needed with probability about 2^-128 per attempt.
        for _ in 0..4 {
            let key = InputKey::random().map_err(|_| DeviceError::Random)?;
            if let Ok(secret) = Self::from_input_key(key) {
                return Ok(secret);
            }
        }
        Err(DeviceError::Random)
    }

    /// Wraps existing bytes, refusing a secret with no recovery identity.
    pub fn from_input_key(key: InputKey) -> Result<Self, DeviceError> {
        derive_identity(&key)?;
        Ok(Self(key))
    }

    /// Parses the owner's `wbk1_` text on restore.
    pub fn parse(text: &str) -> Result<Self, DeviceError> {
        Self::from_input_key(InputKey::parse_wbk1(text.trim())?)
    }

    /// The `wbk1_` text shown once at first run and saved in the recovery file.
    pub fn to_display(&self) -> Zeroizing<String> {
        self.0.to_wbk1()
    }

    /// The FSWNENC2 input key for the key list (vault mode).
    pub fn input_key(&self) -> &InputKey {
        &self.0
    }

    pub fn identity(&self) -> RecoveryIdentity {
        derive_identity(&self.0).expect("checked when the secret was constructed")
    }

    /// Loads the recovery secret from the keychain, or generates and stores one.
    pub fn load_or_create<S: SecretStore>(keychain: &DropKeychain<S>) -> Result<Self, DeviceError> {
        if let Some(key) = keychain.recovery_secret()? {
            return Self::from_input_key(key);
        }
        let secret = Self::generate()?;
        keychain.set_recovery_secret(secret.input_key())?;
        Ok(secret)
    }
}

impl fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoverySecret(<redacted>)")
    }
}

fn derive_identity(secret: &InputKey) -> Result<RecoveryIdentity, DeviceError> {
    let hk = Hkdf::<Sha256>::new(Some(RECOVERY_HKDF_SALT), secret.expose());
    let mut okm = Zeroizing::new([0u8; KEY_BYTES]);
    hk.expand(RECOVERY_IDENTITY_INFO, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let secret_key = nostr::prelude::SecretKey::from_slice(okm.as_ref())
        .map_err(|_| DeviceError::NoRecoveryIdentity)?;
    Ok(RecoveryIdentity(nostr::prelude::Keys::new(secret_key)))
}

/// One file in the key list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyListEntry {
    pub id: FileId,
    /// SHA-256 of the stored envelope: its Blossom address.
    pub sha256: [u8; 32],
    /// Envelope bytes.
    pub size: u64,
    /// The per-file FSWNENC2 input key.  Redacted in `Debug`.
    pub key: InputKey,
    /// The sanitised display name (the envelope also carries it privately).
    pub name: String,
    pub media_type: String,
    /// Plaintext bytes.
    pub bytes: u64,
    /// When the file was added, in Unix seconds.
    pub added: u64,
}

/// The owner's per-file keys and metadata, restored with the recovery secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyList {
    entries: Vec<KeyListEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyListError {
    #[error("the key list version is not supported by this app")]
    UnsupportedVersion,
    #[error("the key list is not valid: {0}")]
    Malformed(&'static str),
    #[error("the envelope does not hold a key list")]
    NotAKeyList,
    #[error("two key list entries share an id")]
    DuplicateId,
    #[error("the key list envelope could not be opened: {0}")]
    Envelope(String),
}

impl From<wildbloom_envelope::Error> for KeyListError {
    fn from(error: wildbloom_envelope::Error) -> Self {
        // Envelope errors carry no secret material; keep the message only.
        Self::Envelope(error.to_string())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireList {
    v: String,
    files: Vec<WireEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    id: String,
    sha256: String,
    size: u64,
    key: String,
    name: String,
    #[serde(rename = "type")]
    media_type: String,
    bytes: u64,
    added: u64,
}

impl Drop for WireEntry {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Deserialize)]
struct VersionOnly {
    v: String,
}

impl KeyList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Entries in ascending id order.
    pub fn entries(&self) -> &[KeyListEntry] {
        &self.entries
    }

    pub fn get(&self, id: &FileId) -> Option<&KeyListEntry> {
        self.entries
            .binary_search_by(|e| e.id.cmp(id))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// Adds an entry after validating it; a repeated id is refused.
    pub fn insert(&mut self, entry: KeyListEntry) -> Result<(), KeyListError> {
        check_entry(&entry)?;
        match self.entries.binary_search_by(|e| e.id.cmp(&entry.id)) {
            Ok(_) => Err(KeyListError::DuplicateId),
            Err(at) => {
                self.entries.insert(at, entry);
                Ok(())
            }
        }
    }

    pub fn remove(&mut self, id: &FileId) -> Option<KeyListEntry> {
        let at = self.entries.binary_search_by(|e| e.id.cmp(id)).ok()?;
        Some(self.entries.remove(at))
    }

    /// The canonical version-1 plaintext.  Contains every key, so it is
    /// zeroised on drop.
    pub fn to_canonical_json(&self) -> Zeroizing<Vec<u8>> {
        let wire = WireList {
            v: KEY_LIST_VERSION.to_string(),
            files: self
                .entries
                .iter()
                .map(|e| WireEntry {
                    id: e.id.to_string(),
                    sha256: super::hex_lower(&e.sha256),
                    size: e.size,
                    key: e.key.to_wbk1().to_string(),
                    name: e.name.clone(),
                    media_type: e.media_type.clone(),
                    bytes: e.bytes,
                    added: e.added,
                })
                .collect(),
        };
        // Reserve generously so the buffer never reallocates and leaves an
        // unzeroised copy: an entry is under 1,700 bytes even with maximal
        // name and type.
        let mut out = Zeroizing::new(Vec::with_capacity(64 + wire.files.len() * 1_700));
        serde_json::to_writer(&mut *out, &wire).expect("serialising plain data cannot fail");
        out
    }

    /// Strict decode of version-1 plaintext.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, KeyListError> {
        let version: VersionOnly =
            serde_json::from_slice(bytes).map_err(|_| KeyListError::Malformed("shape"))?;
        if version.v != KEY_LIST_VERSION {
            return Err(KeyListError::UnsupportedVersion);
        }
        let wire: WireList =
            serde_json::from_slice(bytes).map_err(|_| KeyListError::Malformed("shape"))?;
        let mut entries = Vec::with_capacity(wire.files.len());
        for file in &wire.files {
            let entry = KeyListEntry {
                id: FileId::parse(&file.id).ok_or(KeyListError::Malformed("id"))?,
                sha256: super::parse_sha256(&file.sha256)
                    .ok_or(KeyListError::Malformed("sha256"))?,
                size: file.size,
                key: InputKey::parse_wbk1(&file.key).map_err(|_| KeyListError::Malformed("key"))?,
                name: file.name.clone(),
                media_type: file.media_type.clone(),
                bytes: file.bytes,
                added: file.added,
            };
            check_entry(&entry)?;
            if let Some(previous) = entries.last().map(|e: &KeyListEntry| e.id) {
                if previous == entry.id {
                    return Err(KeyListError::DuplicateId);
                }
                if previous > entry.id {
                    return Err(KeyListError::Malformed("order"));
                }
            }
            entries.push(entry);
        }
        let list = Self { entries };
        if list.to_canonical_json().as_slice() != bytes {
            return Err(KeyListError::Malformed("canonical form"));
        }
        Ok(list)
    }

    /// Seals the key list as an FSWNENC2 vault-mode envelope under the recovery
    /// secret.  The result is ciphertext, safe to upload.
    pub fn seal(&self, recovery: &RecoverySecret) -> Result<Vec<u8>, KeyListError> {
        let json = self.to_canonical_json();
        Ok(wildbloom_envelope::seal_bytes(
            recovery.input_key(),
            KEY_LIST_NAME,
            KEY_LIST_MEDIA_TYPE,
            &json,
            KEY_LIST_LIMITS,
        )?)
    }

    /// Opens a sealed key list on restore.
    pub fn open(recovery: &RecoverySecret, envelope: &[u8]) -> Result<Self, KeyListError> {
        let (metadata, json) =
            wildbloom_envelope::open_bytes(recovery.input_key(), envelope, KEY_LIST_LIMITS)?;
        if metadata.name != KEY_LIST_NAME || metadata.media_type != KEY_LIST_MEDIA_TYPE {
            return Err(KeyListError::NotAKeyList);
        }
        Self::from_canonical_json(&json)
    }
}

fn check_entry(entry: &KeyListEntry) -> Result<(), KeyListError> {
    if entry.name.is_empty() || wildbloom_envelope::sanitise_name(&entry.name) != entry.name {
        return Err(KeyListError::Malformed("name"));
    }
    if wildbloom_envelope::normalise_media_type(&entry.media_type)
        .ok()
        .as_deref()
        != Some(entry.media_type.as_str())
    {
        return Err(KeyListError::Malformed("type"));
    }
    if entry.size < MIN_ENVELOPE_BYTES || entry.size > MAX_SAFE_INTEGER || entry.bytes >= entry.size
    {
        return Err(KeyListError::Malformed("size"));
    }
    if entry.added == 0 || entry.added > MAX_SAFE_INTEGER {
        return Err(KeyListError::Malformed("added"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drop::keychain::MemoryStore;
    use std::sync::Arc;

    fn counting(from: u8) -> InputKey {
        InputKey::from_bytes(std::array::from_fn(|i| from.wrapping_add(i as u8)))
    }

    fn entry(id: u8, key: u8) -> KeyListEntry {
        KeyListEntry {
            id: FileId::from_bytes([id; 16]),
            sha256: [id; 32],
            size: 65_608,
            key: counting(key),
            name: format!("file-{id}.txt"),
            media_type: "text/plain".into(),
            bytes: 43,
            added: 1_900_000_000,
        }
    }

    fn list() -> KeyList {
        let mut list = KeyList::new();
        list.insert(entry(2, 0x20)).unwrap();
        list.insert(entry(1, 0x10)).unwrap();
        list
    }

    /// Synthetic recovery secret 0x00..0x1f: test material only.  The expected
    /// values were computed independently (RFC 5869 HKDF and secp256k1 scalar
    /// multiplication in a separate script), not read back from this code.
    #[test]
    fn recovery_identity_vector() {
        assert_eq!(RECOVERY_HKDF_SALT, b"wildbloom-drop/v1");
        assert_eq!(
            RECOVERY_IDENTITY_INFO,
            b"wildbloom-drop/recovery-identity/secp256k1/v1"
        );
        let secret = RecoverySecret::from_input_key(counting(0)).unwrap();
        let identity = secret.identity();
        assert_eq!(
            identity.keys().secret_key().to_secret_hex(),
            "83bce8b0494afd4fa28372bd72bcce12853bc5de0d80d26c6b7206f491bd8765"
        );
        assert_eq!(
            identity.public_key_hex(),
            "dc1fbd4e2105c9fafd35fcd3374f3e513d098227967ee1f8a703f246061613b0"
        );
        // Deterministic: the same secret always gives the same identity.
        let again = RecoverySecret::parse(&secret.to_display()).unwrap();
        assert_eq!(again.identity().public_key_hex(), identity.public_key_hex());
    }

    #[test]
    fn recovery_identity_is_independent_of_the_key_list_envelope_key() {
        // The identity secret must not equal the FSWNENC2 derivation of the same
        // input under any salt the identity uses.
        let secret = RecoverySecret::from_input_key(counting(0)).unwrap();
        let identity = secret.identity().keys().secret_key().to_secret_bytes();
        let envelope_key =
            wildbloom_envelope::derive_envelope_key(secret.input_key(), RECOVERY_HKDF_SALT);
        assert_ne!(identity, *envelope_key);
        assert_ne!(identity, *secret.input_key().expose());
    }

    #[test]
    fn different_secrets_give_different_identities() {
        let a = RecoverySecret::generate().unwrap();
        let b = RecoverySecret::generate().unwrap();
        assert_ne!(a, b);
        assert_ne!(a.identity().public_key_hex(), b.identity().public_key_hex());
        assert_eq!(a.to_display().len(), 48);
        assert!(a.to_display().starts_with("wbk1_"));
    }

    #[test]
    fn recovery_text_parses_strictly() {
        let secret = RecoverySecret::generate().unwrap();
        let text = secret.to_display();
        assert_eq!(RecoverySecret::parse(&text).unwrap(), secret);
        assert_eq!(
            RecoverySecret::parse(&format!("  {}\n", text.as_str())).unwrap(),
            secret
        );
        assert!(matches!(
            RecoverySecret::parse("wbk1_short"),
            Err(DeviceError::RecoveryKeyEncoding)
        ));
        assert!(matches!(
            RecoverySecret::parse(&text[5..]),
            Err(DeviceError::RecoveryKeyEncoding)
        ));
    }

    #[test]
    fn secret_types_never_print_secrets() {
        let secret = RecoverySecret::from_input_key(counting(0)).unwrap();
        assert_eq!(format!("{secret:?}"), "RecoverySecret(<redacted>)");
        let device = DeviceKeys::from_secret(&[0x11; 32]).unwrap();
        let text = format!("{device:?}");
        assert!(!text.contains(&"11".repeat(32)), "{text}");
        assert!(text.contains(&device.public_key_hex()));
        let listed = format!("{:?}", list());
        assert!(!listed.contains("wbk1_"), "{listed}");
    }

    #[test]
    fn device_keys_round_trip_through_the_keychain() {
        let store = Arc::new(MemoryStore::default());
        let keychain = DropKeychain::new(store.clone());
        let first = DeviceKeys::load_or_create(&keychain).unwrap();
        let second = DeviceKeys::load_or_create(&keychain).unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());
        assert_eq!(first.public_key_hex().len(), 64);
        assert!(matches!(
            DeviceKeys::from_secret(&[0; 32]),
            Err(DeviceError::InvalidDeviceSecret)
        ));

        let recovery = RecoverySecret::load_or_create(&keychain).unwrap();
        assert_eq!(RecoverySecret::load_or_create(&keychain).unwrap(), recovery);
        assert_eq!(store.accounts().len(), 2);
    }

    #[test]
    fn key_list_canonical_form_is_exact() {
        let json = list().to_canonical_json();
        let text = std::str::from_utf8(&json).unwrap();
        let k1 = counting(0x10).to_wbk1();
        let k2 = counting(0x20).to_wbk1();
        let expected = format!(
            concat!(
                r#"{{"v":"wildbloom-drop-keys/1","files":["#,
                r#"{{"id":"{id1}","sha256":"{h1}","size":65608,"key":"{k1}","name":"file-1.txt","type":"text/plain","bytes":43,"added":1900000000}},"#,
                r#"{{"id":"{id2}","sha256":"{h2}","size":65608,"key":"{k2}","name":"file-2.txt","type":"text/plain","bytes":43,"added":1900000000}}"#,
                r#"]}}"#
            ),
            id1 = "01".repeat(16),
            h1 = "01".repeat(32),
            k1 = k1.as_str(),
            id2 = "02".repeat(16),
            h2 = "02".repeat(32),
            k2 = k2.as_str(),
        );
        assert_eq!(text, expected);
        assert_eq!(KeyList::from_canonical_json(&json).unwrap(), list());
        assert_eq!(
            KeyList::from_canonical_json(br#"{"v":"wildbloom-drop-keys/1","files":[]}"#).unwrap(),
            KeyList::new()
        );
    }

    #[test]
    fn key_list_round_trips_sealed_under_the_recovery_secret() {
        let recovery = RecoverySecret::generate().unwrap();
        let sealed = list().seal(&recovery).unwrap();
        assert_eq!(&sealed[..8], wildbloom_envelope::MAGIC);
        let haystack = String::from_utf8_lossy(&sealed);
        assert!(!haystack.contains("wbk1_") && !haystack.contains("file-1"));
        assert_eq!(KeyList::open(&recovery, &sealed).unwrap(), list());
        // Each seal draws a fresh salt.
        assert_ne!(list().seal(&recovery).unwrap(), sealed);

        let wrong = RecoverySecret::generate().unwrap();
        assert!(matches!(
            KeyList::open(&wrong, &sealed),
            Err(KeyListError::Envelope(_))
        ));
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            KeyList::open(&recovery, &tampered),
            Err(KeyListError::Envelope(_))
        ));
    }

    #[test]
    fn an_envelope_that_is_not_a_key_list_is_refused() {
        let recovery = RecoverySecret::generate().unwrap();
        let json = list().to_canonical_json();
        let other = wildbloom_envelope::seal_bytes(
            recovery.input_key(),
            "photo.json",
            "application/json",
            &json,
            KEY_LIST_LIMITS,
        )
        .unwrap();
        assert_eq!(
            KeyList::open(&recovery, &other),
            Err(KeyListError::NotAKeyList)
        );
    }

    #[test]
    fn other_versions_are_refused_before_anything_else() {
        for v in ["wildbloom-drop-keys/2", "wildbloom-drop-keys/0", ""] {
            let json = format!(r#"{{"v":"{v}","files":[],"future":true}}"#);
            assert_eq!(
                KeyList::from_canonical_json(json.as_bytes()),
                Err(KeyListError::UnsupportedVersion),
                "{v}"
            );
        }
        assert_eq!(
            KeyList::from_canonical_json(br#"{"files":[]}"#),
            Err(KeyListError::Malformed("shape"))
        );
    }

    #[test]
    fn non_canonical_or_invalid_lists_are_refused() {
        let good = String::from_utf8(list().to_canonical_json().to_vec()).unwrap();
        let swapped = {
            let list = list();
            let (a, b) = (&list.entries()[0], &list.entries()[1]);
            let one = |e: &KeyListEntry| {
                format!(
                    r#"{{"id":"{}","sha256":"{}","size":65608,"key":"{}","name":"{}","type":"text/plain","bytes":43,"added":1900000000}}"#,
                    e.id,
                    crate::drop::hex_lower(&e.sha256),
                    e.key.to_wbk1().as_str(),
                    e.name
                )
            };
            format!(
                r#"{{"v":"wildbloom-drop-keys/1","files":[{},{}]}}"#,
                one(b),
                one(a)
            )
        };
        let duplicate = good.replace(&"02".repeat(16), &"01".repeat(16));
        let cases: Vec<(String, KeyListError)> = vec![
            (
                good.replace(r#"{"v""#, r#"{ "v""#),
                KeyListError::Malformed("canonical form"),
            ),
            (
                good.replacen(r#""files""#, r#""extra":1,"files""#, 1),
                KeyListError::Malformed("shape"),
            ),
            (
                good.replace("\"bytes\":43", "\"bytes\":43.0"),
                KeyListError::Malformed("shape"),
            ),
            (swapped, KeyListError::Malformed("order")),
            (duplicate, KeyListError::DuplicateId),
            (
                good.replacen("file-1.txt", ".file-1.txt", 1),
                KeyListError::Malformed("name"),
            ),
            (
                good.replacen("text/plain", "Text/Plain", 1),
                KeyListError::Malformed("type"),
            ),
            (
                good.replacen("\"size\":65608", "\"size\":43", 1),
                KeyListError::Malformed("size"),
            ),
            (
                good.replacen("\"added\":1900000000", "\"added\":0", 1),
                KeyListError::Malformed("added"),
            ),
            (
                good.replacen(&"01".repeat(32), &"0G".repeat(32), 1),
                KeyListError::Malformed("sha256"),
            ),
            (
                good.replacen("wbk1_", "wbk2_", 1),
                KeyListError::Malformed("key"),
            ),
        ];
        for (json, expected) in cases {
            assert_eq!(
                KeyList::from_canonical_json(json.as_bytes()),
                Err(expected.clone()),
                "{json}"
            );
        }
    }

    #[test]
    fn insert_validates_and_refuses_duplicates() {
        let mut list = list();
        assert_eq!(list.insert(entry(1, 0x30)), Err(KeyListError::DuplicateId));
        let mut bad = entry(3, 0x30);
        bad.name = "a/b".into();
        assert_eq!(list.insert(bad), Err(KeyListError::Malformed("name")));
        assert_eq!(
            list.get(&FileId::from_bytes([2; 16])).unwrap().key,
            counting(0x20)
        );
        assert!(list.remove(&FileId::from_bytes([2; 16])).is_some());
        assert_eq!(list.entries().len(), 1);
    }
}
