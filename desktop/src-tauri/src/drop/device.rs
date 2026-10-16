//! Drop's key material: the device keypair, the recovery secret, the recovery
//! identity and the encrypted key list.
//!
//! # API
//!
//! - [`identity_state`]: `Fresh` (first run), `Ready` (load) or `Partial` (an
//!   interrupted first run or a lost entry: restore or reset, never silently
//!   regenerate).
//! - [`FirstRunLock::acquire`] then [`create_first_run`]: makes the device key
//!   and the recovery secret once, under a file lock so two windows or two
//!   instances cannot race.  It refuses if either secret already exists.
//! - [`load_identity`], [`DeviceKeys::load`], [`RecoverySecret::load`]: a missing
//!   entry is [`DeviceError::RestoreNeeded`], never a new key.
//! - [`restore_identity`]: stores a recovery secret the owner typed back in and
//!   makes a device key if there is none, refusing a different stored secret.
//! - [`RecoverySecret::to_display`] / [`RecoverySecret::parse`]: the `wbk1_` text.
//! - [`RecoverySecret::identity`]: the recovery identity keypair, approved in the
//!   same grant as the device key and the only key that uploads the key list.
//! - [`KeyList`]: per-file keys and metadata, with tombstones for removed files.
//!   [`KeyList::seal`] bumps `seq` and seals; [`KeyList::open_newest`] opens
//!   every fetched copy, merges them by file id (so forks between two computers
//!   sharing one recovery secret both survive, and a tombstone keeps a removed
//!   file removed), and refuses a result older than the last seen locally.
//!
//! # Derivations from the recovery secret
//!
//! ```text
//! HKDF-SHA256(ikm = recovery secret (32 bytes), salt = "wildbloom-drop/v1", L = 32,
//!             info = "wildbloom-drop/recovery-identity/secp256k1/v1")
//!   -> recovery identity secret key (big-endian secp256k1 scalar)
//! HKDF-SHA256(ikm = recovery secret (32 bytes), salt = "wildbloom-drop/v1", L = 32,
//!             info = "wildbloom-drop/key-list-vault/v1")
//!   -> key list vault key, the FSWNENC2 input key for the key list
//! ```
//!
//! All strings are UTF-8 without a terminator.  The raw recovery secret is
//! therefore never an FSWNENC2 input key, so it never meets a salt read from an
//! envelope.  The identity derivation fails closed if the output is zero or not
//! below the curve order (probability about 2^-128);
//! [`RecoverySecret::generate`] redraws in that case.
//!
//! # Key list format, version 1
//!
//! The plaintext is canonical JSON (no whitespace, keys in this order, minimal
//! escaping, entries sorted by strictly ascending `id`):
//!
//! ```text
//! {"v":"wildbloom-drop-keys/1","seq":<1..2^53-1>,"files":[
//!   {"id":"<32 hex>","sha256":"<64 hex>","size":<envelope bytes>,"key":"wbk1_…",
//!    "name":"<sanitised name>","type":"<media type>","bytes":<plaintext bytes>,
//!    "added":<unix seconds>}, …],
//!  "removed":[{"id":"<32 hex>","at":<unix seconds>}, …]}
//! ```
//!
//! `removed` is sorted by strictly ascending `id` too, and no id may appear in
//! both arrays.  `seq` rises by one on every seal, so a node serving an older
//! copy is caught.
//! The list is sealed as one FSWNENC2 envelope under the key list vault key,
//! with private metadata `wildbloom-drop-keys.json` / `application/json`.  The
//! decoder checks `v` first and refuses any other value with
//! [`KeyListError::UnsupportedVersion`], then requires `seq` and re-encodes and
//! compares so that only the canonical form is accepted.  Local paths are
//! deliberately absent.

use super::FileId;
use super::keychain::{DropKeychain, KeychainError, SecretStore};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::Path;
use wildbloom_envelope::{InputKey, KEY_BYTES, KeyError, Limits, MIN_ENVELOPE_BYTES};
use zeroize::{Zeroize, Zeroizing};

/// HKDF salt for every Drop derivation from the recovery secret.
pub const RECOVERY_HKDF_SALT: &[u8] = b"wildbloom-drop/v1";
/// HKDF info for the recovery identity.
pub const RECOVERY_IDENTITY_INFO: &[u8] = b"wildbloom-drop/recovery-identity/secp256k1/v1";
/// HKDF info for the key list vault key.
pub const KEY_LIST_VAULT_INFO: &[u8] = b"wildbloom-drop/key-list-vault/v1";

/// The key list's version tag.
pub const KEY_LIST_VERSION: &str = "wildbloom-drop-keys/1";
/// The private name inside the key list envelope.
pub const KEY_LIST_NAME: &str = "wildbloom-drop-keys.json";
/// The private media type inside the key list envelope.
pub const KEY_LIST_MEDIA_TYPE: &str = "application/json";
/// The key list's own envelope limit: 64 MiB is tens of thousands of files.
pub const KEY_LIST_LIMITS: Limits = Limits::new(64 * 1024 * 1024);
/// The first-run lock file's name inside the lock directory.
pub const FIRST_RUN_LOCK_FILE: &str = "drop-first-run.lock";
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
    /// A secret Drop needs is not in the keychain.  The owner restores with
    /// their recovery key; a new key is never made in its place.
    #[error("Drop's keys are missing from this computer; restore with the recovery key")]
    RestoreNeeded,
    #[error("Drop is already set up on this computer")]
    AlreadyInitialised,
    #[error("a different recovery key is already stored on this computer")]
    DifferentRecoverySecret,
    #[error("Drop set-up is already running")]
    FirstRunInProgress,
    #[error("the first-run lock could not be created")]
    Lock(#[source] std::io::Error),
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

    /// The stored device key; [`DeviceError::RestoreNeeded`] if there is none.
    pub fn load<S: SecretStore>(keychain: &DropKeychain<S>) -> Result<Self, DeviceError> {
        let secret = keychain
            .device_secret()?
            .ok_or(DeviceError::RestoreNeeded)?;
        Self::from_secret(&secret)
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

    /// The stored recovery secret; [`DeviceError::RestoreNeeded`] if there is none.
    pub fn load<S: SecretStore>(keychain: &DropKeychain<S>) -> Result<Self, DeviceError> {
        Self::from_input_key(
            keychain
                .recovery_secret()?
                .ok_or(DeviceError::RestoreNeeded)?,
        )
    }

    /// The `wbk1_` text shown once at first run and saved in the recovery file.
    pub fn to_display(&self) -> Zeroizing<String> {
        self.0.to_wbk1()
    }

    /// The raw secret, for keychain storage only.  It is never an FSWNENC2 key.
    pub fn secret(&self) -> &InputKey {
        &self.0
    }

    pub fn identity(&self) -> RecoveryIdentity {
        derive_identity(&self.0).expect("checked when the secret was constructed")
    }

    /// The FSWNENC2 input key for the key list (vault mode).
    pub fn key_list_key(&self) -> InputKey {
        let okm = expand(&self.0, KEY_LIST_VAULT_INFO);
        InputKey::from_bytes(*okm)
    }
}

impl fmt::Debug for RecoverySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoverySecret(<redacted>)")
    }
}

fn expand(secret: &InputKey, info: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    let hk = Hkdf::<Sha256>::new(Some(RECOVERY_HKDF_SALT), secret.expose());
    let mut okm = Zeroizing::new([0u8; KEY_BYTES]);
    hk.expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

fn derive_identity(secret: &InputKey) -> Result<RecoveryIdentity, DeviceError> {
    let okm = expand(secret, RECOVERY_IDENTITY_INFO);
    let secret_key = nostr::prelude::SecretKey::from_slice(okm.as_ref())
        .map_err(|_| DeviceError::NoRecoveryIdentity)?;
    Ok(RecoveryIdentity(nostr::prelude::Keys::new(secret_key)))
}

/// What the keychain holds for Drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityState {
    /// Neither secret: first run.
    Fresh,
    /// Both secrets: load them.
    Ready,
    /// Only one: an interrupted first run or a lost entry.  Restore or reset.
    Partial,
}

pub fn identity_state<S: SecretStore>(
    keychain: &DropKeychain<S>,
) -> Result<IdentityState, DeviceError> {
    let device = keychain.device_secret()?.is_some();
    let recovery = keychain.recovery_secret()?.is_some();
    Ok(match (device, recovery) {
        (false, false) => IdentityState::Fresh,
        (true, true) => IdentityState::Ready,
        _ => IdentityState::Partial,
    })
}

/// An exclusive lock held for the whole of first run or restore.  The OS
/// releases it if the process dies, so it never goes stale.
#[derive(Debug)]
pub struct FirstRunLock {
    _file: File,
}

impl FirstRunLock {
    /// Takes the lock in `dir` (created private if missing), or
    /// [`DeviceError::FirstRunInProgress`] if another holder has it.
    pub fn acquire(dir: &Path) -> Result<Self, DeviceError> {
        wildbloom_private_state::private_directory(dir).map_err(DeviceError::Lock)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(dir.join(FIRST_RUN_LOCK_FILE))
            .map_err(DeviceError::Lock)?;
        wildbloom_private_state::check_file(&file).map_err(DeviceError::Lock)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| DeviceError::FirstRunInProgress)?;
        Ok(Self { _file: file })
    }
}

/// Drop's two long-lived secrets.
#[derive(Debug)]
pub struct DropIdentity {
    pub device: DeviceKeys,
    pub recovery: RecoverySecret,
}

/// Makes and stores the device key and recovery secret.  Refuses with
/// [`DeviceError::AlreadyInitialised`] if either is already stored, so an
/// existing recovery secret is never replaced.
pub fn create_first_run<S: SecretStore>(
    keychain: &DropKeychain<S>,
    _lock: &FirstRunLock,
) -> Result<DropIdentity, DeviceError> {
    if identity_state(keychain)? != IdentityState::Fresh {
        return Err(DeviceError::AlreadyInitialised);
    }
    let recovery = RecoverySecret::generate()?;
    let device = DeviceKeys::generate();
    keychain.set_device_secret(&device.secret_bytes())?;
    if let Err(error) = keychain.set_recovery_secret(recovery.secret()) {
        // Leave the keychain Fresh rather than Partial; nothing was shown yet.
        let _ = keychain.remove_device_secret();
        return Err(error.into());
    }
    Ok(DropIdentity { device, recovery })
}

/// Both stored secrets; [`DeviceError::RestoreNeeded`] if either is missing.
pub fn load_identity<S: SecretStore>(
    keychain: &DropKeychain<S>,
) -> Result<DropIdentity, DeviceError> {
    Ok(DropIdentity {
        device: DeviceKeys::load(keychain)?,
        recovery: RecoverySecret::load(keychain)?,
    })
}

/// Stores the recovery secret the owner typed back in and makes this
/// computer's device key if it has none.  A different stored recovery secret
/// is refused, never overwritten.
pub fn restore_identity<S: SecretStore>(
    keychain: &DropKeychain<S>,
    _lock: &FirstRunLock,
    recovery: RecoverySecret,
) -> Result<DropIdentity, DeviceError> {
    match keychain.recovery_secret()? {
        Some(stored) if stored != *recovery.secret() => {
            return Err(DeviceError::DifferentRecoverySecret);
        }
        Some(_) => {}
        None => keychain.set_recovery_secret(recovery.secret())?,
    }
    let device = match keychain.device_secret()? {
        Some(secret) => DeviceKeys::from_secret(&secret)?,
        None => {
            let device = DeviceKeys::generate();
            keychain.set_device_secret(&device.secret_bytes())?;
            device
        }
    };
    Ok(DropIdentity { device, recovery })
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

/// A removed file: its id and when it was removed, in Unix seconds.  Kept so
/// that merging with an older or forked copy cannot bring the file back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tombstone {
    pub id: FileId,
    pub at: u64,
}

/// The owner's per-file keys and metadata, restored with the recovery secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyList {
    /// 0 for a list never sealed; otherwise the `seq` of the last seal or open.
    seq: u64,
    entries: Vec<KeyListEntry>,
    removed: Vec<Tombstone>,
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
    #[error("no key list copy was offered")]
    NoCandidates,
    /// The newest copy offered is older than one this computer already saw.
    #[error("the newest key list offered (seq {newest}) is older than seq {last_seen}")]
    Rollback { last_seen: u64, newest: u64 },
    /// Two copies at the same `seq` hold different entries for one file id.
    #[error("two key list copies at seq {0} disagree about one file")]
    Conflict(u64),
    /// The id belongs to a removed file and cannot be added again.
    #[error("that file was removed from the key list")]
    Removed,
    #[error("the key list sequence number is exhausted")]
    SeqExhausted,
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
    seq: u64,
    files: Vec<WireEntry>,
    removed: Vec<WireTombstone>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireTombstone {
    id: String,
    at: u64,
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

    /// The `seq` of the last seal or open; 0 if never sealed.
    pub fn seq(&self) -> u64 {
        self.seq
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

    /// Removed files, in ascending id order.
    pub fn tombstones(&self) -> &[Tombstone] {
        &self.removed
    }

    fn tombstone_index(&self, id: &FileId) -> Result<usize, usize> {
        self.removed.binary_search_by(|t| t.id.cmp(id))
    }

    /// Adds an entry after validating it; a repeated or removed id is refused.
    pub fn insert(&mut self, entry: KeyListEntry) -> Result<(), KeyListError> {
        check_entry(&entry)?;
        if self.tombstone_index(&entry.id).is_ok() {
            return Err(KeyListError::Removed);
        }
        match self.entries.binary_search_by(|e| e.id.cmp(&entry.id)) {
            Ok(_) => Err(KeyListError::DuplicateId),
            Err(at) => {
                self.entries.insert(at, entry);
                Ok(())
            }
        }
    }

    /// Removes a file and records a tombstone at `removed_at` (Unix seconds),
    /// even if this copy never held the file (another computer's copy may).
    /// Returns the removed entry, if this copy had it.
    pub fn remove(
        &mut self,
        id: &FileId,
        removed_at: u64,
    ) -> Result<Option<KeyListEntry>, KeyListError> {
        if removed_at == 0 || removed_at > MAX_SAFE_INTEGER {
            return Err(KeyListError::Malformed("removed"));
        }
        match self.tombstone_index(id) {
            Ok(at) => {
                let stone = &mut self.removed[at];
                stone.at = stone.at.max(removed_at);
            }
            Err(at) => self.removed.insert(
                at,
                Tombstone {
                    id: *id,
                    at: removed_at,
                },
            ),
        }
        Ok(self
            .entries
            .binary_search_by(|e| e.id.cmp(id))
            .ok()
            .map(|at| self.entries.remove(at)))
    }

    /// The canonical version-1 plaintext at `seq`.  Contains every key, so it
    /// is zeroised on drop.
    fn canonical_json_at(&self, seq: u64) -> Zeroizing<Vec<u8>> {
        let wire = WireList {
            v: KEY_LIST_VERSION.to_string(),
            seq,
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
            removed: self
                .removed
                .iter()
                .map(|t| WireTombstone {
                    id: t.id.to_string(),
                    at: t.at,
                })
                .collect(),
        };
        // Reserve generously so the buffer never reallocates and leaves an
        // unzeroised copy: an entry is under 1,700 bytes even with maximal
        // name and type, and a tombstone under 64.
        let mut out = Zeroizing::new(Vec::with_capacity(
            128 + wire.files.len() * 1_700 + wire.removed.len() * 64,
        ));
        serde_json::to_writer(&mut *out, &wire).expect("serialising plain data cannot fail");
        out
    }

    /// The canonical plaintext at the current `seq`.
    pub fn to_canonical_json(&self) -> Zeroizing<Vec<u8>> {
        self.canonical_json_at(self.seq)
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
        if wire.seq == 0 || wire.seq > MAX_SAFE_INTEGER {
            return Err(KeyListError::Malformed("seq"));
        }
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
        let mut removed: Vec<Tombstone> = Vec::with_capacity(wire.removed.len());
        for stone in &wire.removed {
            let id = FileId::parse(&stone.id).ok_or(KeyListError::Malformed("removed"))?;
            if stone.at == 0
                || stone.at > MAX_SAFE_INTEGER
                || removed.last().is_some_and(|t| t.id >= id)
                || entries.binary_search_by(|e| e.id.cmp(&id)).is_ok()
            {
                return Err(KeyListError::Malformed("removed"));
            }
            removed.push(Tombstone { id, at: stone.at });
        }
        let list = Self {
            seq: wire.seq,
            entries,
            removed,
        };
        if list.to_canonical_json().as_slice() != bytes {
            return Err(KeyListError::Malformed("canonical form"));
        }
        Ok(list)
    }

    /// Seals the key list at `seq + 1` as an FSWNENC2 vault-mode envelope under
    /// the key list vault key, and advances `seq` only if sealing succeeded.
    /// The result is ciphertext, safe to upload.
    pub fn seal(&mut self, recovery: &RecoverySecret) -> Result<Vec<u8>, KeyListError> {
        let next = self
            .seq
            .checked_add(1)
            .filter(|n| *n <= MAX_SAFE_INTEGER)
            .ok_or(KeyListError::SeqExhausted)?;
        let json = self.canonical_json_at(next);
        let sealed = wildbloom_envelope::seal_bytes(
            &recovery.key_list_key(),
            KEY_LIST_NAME,
            KEY_LIST_MEDIA_TYPE,
            &json,
            KEY_LIST_LIMITS,
        )?;
        self.seq = next;
        Ok(sealed)
    }

    /// Opens one sealed key list.
    pub fn open(recovery: &RecoverySecret, envelope: &[u8]) -> Result<Self, KeyListError> {
        let (metadata, json) =
            wildbloom_envelope::open_bytes(&recovery.key_list_key(), envelope, KEY_LIST_LIMITS)?;
        if metadata.name != KEY_LIST_NAME || metadata.media_type != KEY_LIST_MEDIA_TYPE {
            return Err(KeyListError::NotAKeyList);
        }
        Self::from_canonical_json(&json)
    }

    /// Opens every candidate copy (for example one per node) and merges them
    /// with [`KeyList::merge`].  Copies that fail to open are skipped; if none
    /// opens, the first failure is returned.  A merged `seq` (the highest
    /// among the copies) below `last_seen`, the highest this computer has
    /// sealed or opened (0 if none), is a [`KeyListError::Rollback`].  The
    /// result is independent of candidate order.
    pub fn open_newest(
        recovery: &RecoverySecret,
        candidates: &[&[u8]],
        last_seen: u64,
    ) -> Result<Self, KeyListError> {
        let mut opened = Vec::with_capacity(candidates.len());
        let mut first_error = None;
        for candidate in candidates {
            match Self::open(recovery, candidate) {
                Ok(list) => opened.push(list),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if opened.is_empty() {
            return Err(first_error.unwrap_or(KeyListError::NoCandidates));
        }
        let merged = Self::merge(opened)?;
        if merged.seq < last_seen {
            return Err(KeyListError::Rollback {
                last_seen,
                newest: merged.seq,
            });
        }
        Ok(merged)
    }

    /// Merges copies by file id, so a fork between two computers keeps both
    /// sides' additions:
    ///
    /// - tombstones are unioned, keeping the latest `at` per id, and remove
    ///   that id's entry from every copy, so nothing removed comes back;
    /// - each remaining id takes its entry from the highest-`seq` copy that
    ///   holds it, and two copies at that `seq` holding different entries for
    ///   it are a [`KeyListError::Conflict`] (entries never change once added);
    /// - the result's `seq` is the highest among the copies, so its next seal
    ///   is one above every copy.
    ///
    /// The result does not depend on the order of `lists`.
    pub fn merge(lists: Vec<Self>) -> Result<Self, KeyListError> {
        use std::collections::BTreeMap;
        let seq = lists
            .iter()
            .map(|l| l.seq)
            .max()
            .ok_or(KeyListError::NoCandidates)?;
        let mut removed: BTreeMap<FileId, u64> = BTreeMap::new();
        for stone in lists.iter().flat_map(|l| l.removed.iter()) {
            let at = removed.entry(stone.id).or_insert(stone.at);
            *at = (*at).max(stone.at);
        }
        // Per id: the highest seq holding it and that seq's entry.
        let mut chosen: BTreeMap<FileId, (u64, KeyListEntry)> = BTreeMap::new();
        let mut disputed: BTreeMap<FileId, u64> = BTreeMap::new();
        for list in &lists {
            for entry in &list.entries {
                if removed.contains_key(&entry.id) {
                    continue;
                }
                match chosen.get(&entry.id) {
                    Some((best, _)) if *best > list.seq => {}
                    Some((best, existing)) if *best == list.seq => {
                        if existing != entry {
                            disputed.insert(entry.id, list.seq);
                        }
                    }
                    _ => {
                        disputed.remove(&entry.id);
                        chosen.insert(entry.id, (list.seq, entry.clone()));
                    }
                }
            }
        }
        if let Some(seq) = disputed.values().max() {
            return Err(KeyListError::Conflict(*seq));
        }
        Ok(Self {
            seq,
            entries: chosen.into_values().map(|(_, entry)| entry).collect(),
            removed: removed
                .into_iter()
                .map(|(id, at)| Tombstone { id, at })
                .collect(),
        })
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

    /// Two entries at seq 7.
    fn list() -> KeyList {
        let mut list = KeyList::new();
        list.insert(entry(2, 0x20)).unwrap();
        list.insert(entry(1, 0x10)).unwrap();
        list.seq = 7;
        list
    }

    fn keychain() -> (Arc<MemoryStore>, DropKeychain<Arc<MemoryStore>>) {
        let store = Arc::new(MemoryStore::default());
        (store.clone(), DropKeychain::new(store))
    }

    /// Synthetic recovery secret 0x00..0x1f: test material only.  The expected
    /// values were computed independently (RFC 5869 HKDF and secp256k1 scalar
    /// multiplication in a separate script), not read back from this code.
    #[test]
    fn recovery_derivation_vectors() {
        assert_eq!(RECOVERY_HKDF_SALT, b"wildbloom-drop/v1");
        assert_eq!(
            RECOVERY_IDENTITY_INFO,
            b"wildbloom-drop/recovery-identity/secp256k1/v1"
        );
        assert_eq!(KEY_LIST_VAULT_INFO, b"wildbloom-drop/key-list-vault/v1");
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
        assert_eq!(
            secret.key_list_key(),
            InputKey::from_bytes(std::array::from_fn(|i| {
                u8::from_str_radix(
                    &"e3d4547d81ac74018709cc8432a1452981499b1c4929c384caf82a3ed6253abb"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            }))
        );
        // Deterministic: the same secret always gives the same outputs.
        let again = RecoverySecret::parse(&secret.to_display()).unwrap();
        assert_eq!(again.identity().public_key_hex(), identity.public_key_hex());
        assert_eq!(again.key_list_key(), secret.key_list_key());
    }

    #[test]
    fn the_three_keys_are_distinct() {
        let secret = RecoverySecret::from_input_key(counting(0)).unwrap();
        let identity = secret.identity().keys().secret_key().to_secret_bytes();
        let vault = *secret.key_list_key().expose();
        let raw = *secret.secret().expose();
        assert_ne!(identity, vault);
        assert_ne!(identity, raw);
        assert_ne!(vault, raw);
    }

    #[test]
    fn the_key_list_is_not_sealed_under_the_raw_secret() {
        let recovery = RecoverySecret::from_input_key(counting(0)).unwrap();
        let sealed = list().seal(&recovery).unwrap();
        assert!(
            wildbloom_envelope::open_bytes(recovery.secret(), &sealed, KEY_LIST_LIMITS).is_err()
        );
        assert!(
            wildbloom_envelope::open_bytes(&recovery.key_list_key(), &sealed, KEY_LIST_LIMITS)
                .is_ok()
        );
    }

    #[test]
    fn different_secrets_give_different_identities() {
        let a = RecoverySecret::generate().unwrap();
        let b = RecoverySecret::generate().unwrap();
        assert_ne!(a, b);
        assert_ne!(a.identity().public_key_hex(), b.identity().public_key_hex());
        assert_ne!(a.key_list_key(), b.key_list_key());
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
    fn first_run_creates_once_and_load_never_regenerates() {
        let lock_dir = tempfile::tempdir().unwrap();
        let (store, keychain) = keychain();
        assert_eq!(identity_state(&keychain).unwrap(), IdentityState::Fresh);
        assert!(matches!(
            load_identity(&keychain),
            Err(DeviceError::RestoreNeeded)
        ));
        assert!(store.accounts().is_empty(), "load must not create");

        let lock = FirstRunLock::acquire(&lock_dir.path().join("locks")).unwrap();
        let created = create_first_run(&keychain, &lock).unwrap();
        assert_eq!(identity_state(&keychain).unwrap(), IdentityState::Ready);
        assert!(matches!(
            create_first_run(&keychain, &lock),
            Err(DeviceError::AlreadyInitialised)
        ));
        let loaded = load_identity(&keychain).unwrap();
        assert_eq!(loaded.recovery, created.recovery);
        assert_eq!(
            loaded.device.public_key_hex(),
            created.device.public_key_hex()
        );
        assert!(matches!(
            DeviceKeys::from_secret(&[0; 32]),
            Err(DeviceError::InvalidDeviceSecret)
        ));
    }

    #[test]
    fn a_lost_entry_is_partial_and_needs_restore() {
        let lock_dir = tempfile::tempdir().unwrap();
        let (_, keychain) = keychain();
        let lock = FirstRunLock::acquire(&lock_dir.path().join("locks")).unwrap();
        let created = create_first_run(&keychain, &lock).unwrap();

        keychain.remove_device_secret().unwrap();
        assert_eq!(identity_state(&keychain).unwrap(), IdentityState::Partial);
        assert!(matches!(
            DeviceKeys::load(&keychain),
            Err(DeviceError::RestoreNeeded)
        ));
        assert!(matches!(
            create_first_run(&keychain, &lock),
            Err(DeviceError::AlreadyInitialised)
        ));
        // Restoring with the same recovery key makes a new device key and keeps
        // the recovery secret.
        let restored = restore_identity(&keychain, &lock, created.recovery.clone()).unwrap();
        assert_eq!(restored.recovery, created.recovery);
        assert_ne!(
            restored.device.public_key_hex(),
            created.device.public_key_hex()
        );
        assert_eq!(identity_state(&keychain).unwrap(), IdentityState::Ready);

        // A different recovery key is refused, never overwritten.
        let other = RecoverySecret::generate().unwrap();
        assert!(matches!(
            restore_identity(&keychain, &lock, other),
            Err(DeviceError::DifferentRecoverySecret)
        ));
        assert_eq!(RecoverySecret::load(&keychain).unwrap(), created.recovery);
    }

    #[test]
    fn a_failed_recovery_write_leaves_the_keychain_fresh() {
        struct FailRecovery(MemoryStore);
        impl SecretStore for FailRecovery {
            fn read(&self, a: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
                self.0.read(a)
            }
            fn write(&self, a: &str, s: &[u8]) -> Result<(), KeychainError> {
                if a.contains("recovery") {
                    return Err(KeychainError::Denied);
                }
                self.0.write(a, s)
            }
            fn remove(&self, a: &str) -> Result<(), KeychainError> {
                self.0.remove(a)
            }
        }
        let lock_dir = tempfile::tempdir().unwrap();
        let keychain = DropKeychain::new(FailRecovery(MemoryStore::default()));
        let lock = FirstRunLock::acquire(&lock_dir.path().join("locks")).unwrap();
        assert!(matches!(
            create_first_run(&keychain, &lock),
            Err(DeviceError::Keychain(KeychainError::Denied))
        ));
        assert_eq!(identity_state(&keychain).unwrap(), IdentityState::Fresh);
    }

    #[test]
    fn first_run_is_single_flight() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("locks");
        let held = FirstRunLock::acquire(&dir).unwrap();
        assert!(matches!(
            FirstRunLock::acquire(&dir),
            Err(DeviceError::FirstRunInProgress)
        ));
        // From another thread too.
        let path = dir.clone();
        let other = std::thread::spawn(move || FirstRunLock::acquire(&path).map(|_| ()))
            .join()
            .unwrap();
        assert!(matches!(other, Err(DeviceError::FirstRunInProgress)));
        drop(held);
        assert!(FirstRunLock::acquire(&dir).is_ok());
    }

    #[test]
    fn key_list_canonical_form_is_exact() {
        let json = list().to_canonical_json();
        let text = std::str::from_utf8(&json).unwrap();
        let k1 = counting(0x10).to_wbk1();
        let k2 = counting(0x20).to_wbk1();
        let expected = format!(
            concat!(
                r#"{{"v":"wildbloom-drop-keys/1","seq":7,"files":["#,
                r#"{{"id":"{id1}","sha256":"{h1}","size":65608,"key":"{k1}","name":"file-1.txt","type":"text/plain","bytes":43,"added":1900000000}},"#,
                r#"{{"id":"{id2}","sha256":"{h2}","size":65608,"key":"{k2}","name":"file-2.txt","type":"text/plain","bytes":43,"added":1900000000}}"#,
                r#"],"removed":[]}}"#
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
        let empty = KeyList::from_canonical_json(
            br#"{"v":"wildbloom-drop-keys/1","seq":1,"files":[],"removed":[]}"#,
        )
        .unwrap();
        assert_eq!(empty.seq(), 1);
        assert!(empty.entries().is_empty());
    }

    #[test]
    fn seq_is_required_and_bounded() {
        for json in [
            r#"{"v":"wildbloom-drop-keys/1","files":[],"removed":[]}"#,
            r#"{"v":"wildbloom-drop-keys/1","seq":"1","files":[],"removed":[]}"#,
            r#"{"v":"wildbloom-drop-keys/1","seq":-1,"files":[],"removed":[]}"#,
            r#"{"v":"wildbloom-drop-keys/1","seq":1,"files":[]}"#,
        ] {
            assert_eq!(
                KeyList::from_canonical_json(json.as_bytes()),
                Err(KeyListError::Malformed("shape")),
                "{json}"
            );
        }
        for json in [
            r#"{"v":"wildbloom-drop-keys/1","seq":0,"files":[],"removed":[]}"#,
            r#"{"v":"wildbloom-drop-keys/1","seq":9007199254740992,"files":[],"removed":[]}"#,
        ] {
            assert_eq!(
                KeyList::from_canonical_json(json.as_bytes()),
                Err(KeyListError::Malformed("seq")),
                "{json}"
            );
        }
        assert_eq!(
            KeyList::from_canonical_json(
                br#"{"v":"wildbloom-drop-keys/1","files":[],"seq":1,"removed":[]}"#
            ),
            Err(KeyListError::Malformed("canonical form"))
        );
    }

    #[test]
    fn sealing_advances_seq_and_round_trips() {
        let recovery = RecoverySecret::generate().unwrap();
        let mut list = list();
        let first = list.seal(&recovery).unwrap();
        assert_eq!(list.seq(), 8);
        assert_eq!(&first[..8], wildbloom_envelope::MAGIC);
        let haystack = String::from_utf8_lossy(&first);
        assert!(!haystack.contains("wbk1_") && !haystack.contains("file-1"));
        let opened = KeyList::open(&recovery, &first).unwrap();
        assert_eq!(opened, list);
        let second = list.seal(&recovery).unwrap();
        assert_eq!(list.seq(), 9);
        assert_ne!(second, first);

        let mut exhausted = KeyList::new();
        exhausted.seq = MAX_SAFE_INTEGER;
        assert_eq!(exhausted.seal(&recovery), Err(KeyListError::SeqExhausted));
        assert_eq!(exhausted.seq(), MAX_SAFE_INTEGER);

        let wrong = RecoverySecret::generate().unwrap();
        assert!(matches!(
            KeyList::open(&wrong, &first),
            Err(KeyListError::Envelope(_))
        ));
        let mut tampered = first.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            KeyList::open(&recovery, &tampered),
            Err(KeyListError::Envelope(_))
        ));
    }

    /// A list at `seq` holding entries for `ids`.
    fn at(seq: u64, ids: &[u8]) -> KeyList {
        let mut list = KeyList::new();
        for id in ids {
            list.insert(entry(*id, *id * 0x10)).unwrap();
        }
        list.seq = seq;
        list
    }

    fn ids(list: &KeyList) -> Vec<u8> {
        list.entries().iter().map(|e| e.sha256[0]).collect()
    }

    #[test]
    fn open_newest_is_independent_of_candidate_order() {
        let recovery = RecoverySecret::generate().unwrap();
        let seal_at = |list: KeyList| {
            let mut list = list;
            list.seq -= 1;
            list.seal(&recovery).unwrap()
        };
        // A5 and B5' forked from one seq-4 list; C6 is A's next seal.
        let a5 = seal_at(at(5, &[1, 2]));
        let b5 = seal_at(at(5, &[1, 3]));
        let c6 = seal_at(at(6, &[1, 2, 4]));
        let garbage = vec![0u8; 100];
        let orders: [[&[u8]; 4]; 4] = [
            [&a5, &b5, &c6, &garbage],
            [&c6, &b5, &a5, &garbage],
            [&b5, &garbage, &a5, &c6],
            [&garbage, &c6, &a5, &b5],
        ];
        for order in orders {
            let merged = KeyList::open_newest(&recovery, &order, 0).unwrap();
            assert_eq!(merged.seq(), 6);
            assert_eq!(ids(&merged), vec![1, 2, 3, 4]);
        }
        // The next seal is one above every copy.
        let mut merged = KeyList::open_newest(&recovery, &[&a5, &b5, &c6], 6).unwrap();
        merged.seal(&recovery).unwrap();
        assert_eq!(merged.seq(), 7);
    }

    #[test]
    fn open_newest_refuses_rollback_and_empty_input() {
        let recovery = RecoverySecret::generate().unwrap();
        let mut list = list();
        let old = list.seal(&recovery).unwrap(); // seq 8
        list.insert(entry(3, 0x30)).unwrap();
        let new = list.seal(&recovery).unwrap(); // seq 9
        assert_eq!(
            KeyList::open_newest(&recovery, &[&new, &new], 9)
                .unwrap()
                .seq(),
            9
        );
        // A node that only serves the old copy is caught.
        assert_eq!(
            KeyList::open_newest(&recovery, &[&old], 9),
            Err(KeyListError::Rollback {
                last_seen: 9,
                newest: 8
            })
        );
        assert_eq!(
            KeyList::open_newest(&recovery, &[], 0),
            Err(KeyListError::NoCandidates)
        );
        assert!(matches!(
            KeyList::open_newest(&recovery, &[&[0u8; 100][..]], 0),
            Err(KeyListError::Envelope(_))
        ));
    }

    #[test]
    fn merge_conflicts_only_at_the_deciding_seq() {
        let mut altered = at(6, &[1]);
        altered.entries[0].key = counting(0x99);
        let conflicting = || vec![at(6, &[1, 2]), altered.clone(), at(5, &[3])];
        assert_eq!(
            KeyList::merge(conflicting()),
            Err(KeyListError::Conflict(6))
        );
        let mut reversed = conflicting();
        reversed.reverse();
        assert_eq!(KeyList::merge(reversed), Err(KeyListError::Conflict(6)));

        // A disagreement at seq 5 is settled by a seq-6 copy of that file, in
        // any order.
        let mut altered5 = altered.clone();
        altered5.seq = 5;
        for lists in [
            vec![at(5, &[1]), altered5.clone(), at(6, &[1])],
            vec![at(6, &[1]), at(5, &[1]), altered5.clone()],
        ] {
            let merged = KeyList::merge(lists).unwrap();
            assert_eq!(merged.entries()[0], entry(1, 0x10));
        }
    }

    #[test]
    fn a_fork_merge_keeps_both_sides_and_respects_tombstones() {
        let recovery = RecoverySecret::generate().unwrap();
        let mut base = at(4, &[1, 2]);
        let shared = base.seal(&recovery).unwrap(); // seq 5 on both computers
        let mut x = KeyList::open(&recovery, &shared).unwrap();
        let mut y = KeyList::open(&recovery, &shared).unwrap();
        // Computer X removes file 2; computer Y adds file 3.  Both seal seq 6.
        x.remove(&FileId::from_bytes([2; 16]), 1_900_000_500)
            .unwrap();
        y.insert(entry(3, 0x30)).unwrap();
        let x6 = x.seal(&recovery).unwrap();
        let y6 = y.seal(&recovery).unwrap();
        for order in [[&x6, &y6, &shared], [&shared, &y6, &x6]] {
            let order: Vec<&[u8]> = order.iter().map(|v| v.as_slice()).collect();
            let merged = KeyList::open_newest(&recovery, &order, 6).unwrap();
            assert_eq!(merged.seq(), 6);
            // Y's addition survives; X's removal is not undone by Y's copy.
            assert_eq!(ids(&merged), vec![1, 3]);
            assert_eq!(
                merged.tombstones(),
                &[Tombstone {
                    id: FileId::from_bytes([2; 16]),
                    at: 1_900_000_500
                }]
            );
            // The merge round-trips, tombstone included, at seq 7.
            let mut merged = merged;
            let sealed = merged.seal(&recovery).unwrap();
            let reopened = KeyList::open(&recovery, &sealed).unwrap();
            assert_eq!(reopened.seq(), 7);
            assert_eq!(reopened, merged);
        }
    }

    #[test]
    fn tombstones_are_validated_on_decode() {
        let mut list = at(3, &[1]);
        list.remove(&FileId::from_bytes([5; 16]), 1_900_000_000)
            .unwrap();
        let good = String::from_utf8(list.to_canonical_json().to_vec()).unwrap();
        assert!(good.ends_with(&format!(
            r#""removed":[{{"id":"{}","at":1900000000}}]}}"#,
            "05".repeat(16)
        )));
        assert_eq!(KeyList::from_canonical_json(good.as_bytes()).unwrap(), list);
        let in_both = good.replace(&"05".repeat(16), &"01".repeat(16));
        let zero = good.replace("\"at\":1900000000", "\"at\":0");
        let unsorted = good.replace(
            r#""removed":["#,
            &format!(r#""removed":[{{"id":"{}","at":1}},"#, "09".repeat(16)),
        );
        let duplicate = good.replace(
            r#""removed":["#,
            &format!(r#""removed":[{{"id":"{}","at":1}},"#, "05".repeat(16)),
        );
        for json in [in_both, zero, unsorted, duplicate] {
            assert_eq!(
                KeyList::from_canonical_json(json.as_bytes()),
                Err(KeyListError::Malformed("removed")),
                "{json}"
            );
        }
    }

    #[test]
    fn an_envelope_that_is_not_a_key_list_is_refused() {
        let recovery = RecoverySecret::generate().unwrap();
        let json = list().to_canonical_json();
        let other = wildbloom_envelope::seal_bytes(
            &recovery.key_list_key(),
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
            KeyList::from_canonical_json(br#"{"seq":1,"files":[]}"#),
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
                r#"{{"v":"wildbloom-drop-keys/1","seq":7,"files":[{},{}],"removed":[]}}"#,
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
        let two = FileId::from_bytes([2; 16]);
        assert!(list.remove(&two, 1_900_000_100).unwrap().is_some());
        assert_eq!(list.entries().len(), 1);
        // A removed id cannot come back, and a second removal keeps the later time.
        assert_eq!(list.insert(entry(2, 0x20)), Err(KeyListError::Removed));
        assert!(list.remove(&two, 1_900_000_050).unwrap().is_none());
        assert_eq!(
            list.tombstones(),
            &[Tombstone {
                id: two,
                at: 1_900_000_100
            }]
        );
        assert_eq!(
            list.remove(&two, 0),
            Err(KeyListError::Malformed("removed"))
        );
    }
}
