//! The Drop engine: everything behind the IPC commands, independent of Tauri
//! so the headless integration test drives exactly what the app runs.
//!
//! The Tauri layer supplies a [`Host`] (events, the local node, dialogs) and a
//! secret store factory.  Background work (encryption, mirroring, checks, the
//! key list, sharing and the watched folder) runs on the given tokio runtime.

use super::client::{self, NodeEndpoint, NodeError};
use super::device::{
    self, DeviceError, DropIdentity, FirstRunLock, IdentityState, KeyList, KeyListEntry,
    RecoverySecret,
};
use super::envelope::{self, SHARE_MAX_PLAINTEXT_BYTES, TempDirLock};
use super::index::{self, FileRecord, Index, local, online};
use super::keychain::{DropKeychain, KeychainError, SecretStore};
use super::types::*;
use super::{FileId, hex_lower};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use zeroize::Zeroizing;

/// The default per-blob limit of a Wildbloom Node; its health endpoint does
/// not publish the configured one.  Envelopes up to this size are still
/// opened, whatever [`EngineConfig::online_blob_limit`] says.
pub const DEFAULT_NODE_BLOB_LIMIT: u64 = 1024 * 1024 * 1024;
/// The online node's per-blob limit the app assumes: the shelter limit.
pub const ONLINE_BLOB_LIMIT: u64 = 256 * 1024 * 1024;
/// How long an approval lasts.
pub const APPROVAL_SECONDS: u64 = 365 * 86_400;
/// The grant ceiling when the node's quota is unknown.
pub const DEFAULT_GRANT_BYTES: u64 = 5_000_000_000;
/// Foregather context for Drop shares (design question Q17).
pub const PAIRING_NAMESPACE: &str = "wildbloom.drop";
pub const PAIRING_PURPOSE: &str = "share";

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The local node as the host sees it.
#[derive(Clone, Debug)]
pub struct LocalNode {
    /// `"ok"` (ready or starting), `"stopped"` or `"error"`.
    pub state: &'static str,
    /// Where to reach it, once it listens.
    pub endpoint: Option<NodeEndpoint>,
}

/// What the engine needs from the app around it.
pub trait Host: Send + Sync + 'static {
    fn emit_file(&self, row: &FileRow);
    fn emit_removed(&self, id: &str);
    fn emit_status(&self, status: &DropStatus, line: &super::status::StatusLine);
    fn emit_share(&self, state: &ShareState);
    fn local_node(&self) -> LocalNode;
    /// The Drop keys changed: restart the local node so it trusts them.
    fn trust_changed(&self);
    fn node_settings_exist(&self) -> bool;
    /// Design question Q10: write direct, loopback-only node settings and
    /// start the node, when no settings exist yet.
    fn ensure_node_settings(&self) -> Result<(), String>;
    /// A native save dialog; `None` if cancelled.
    fn pick_save_path(&self, suggested_name: &str) -> Option<PathBuf>;
    /// A native multi-file open dialog; empty if cancelled.
    fn pick_files(&self) -> Vec<PathBuf>;
    /// Reveal a folder in the file manager.
    fn open_folder(&self, path: &Path);
    /// Moves a file to the system Trash or Recycle Bin.  Never deletes it.
    fn trash(&self, path: &Path) -> std::io::Result<()>;
    /// Opens a file with the system's default app.
    fn open_path(&self, path: &Path);
    /// Shows a file selected in Finder, Explorer or the file manager.
    fn reveal_path(&self, path: &Path);
}

/// Configuration that differs between the app and the tests.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Private Drop state: the index, sealed key list, outbox and locks.
    pub data_dir: PathBuf,
    /// Private temp directory for envelopes and plaintext in transit.
    pub temp_dir: PathBuf,
    /// The optional inbox folder, `~/Wildbloom`.
    pub watch_dir: PathBuf,
    /// How the watched folder is shown, for example `~/Wildbloom`.
    pub watch_display: String,
    /// The recipient page base, `https://wildbloom.forgesworn.dev/get/`.
    pub get_base: String,
    /// The pairing relay API base; `None` derives `<online origin>pair/v1/`.
    pub relay_base: Option<String>,
    /// Loopback HTTP for nodes, the relay and links: tests only.
    pub allow_loopback_http: bool,
    pub signer_timeout: Duration,
    pub computer_name: String,
    /// How often the watched folder is scanned.
    pub watch_interval: Duration,
    /// The largest envelope the online node takes.  Drops whose envelope
    /// would be larger are refused before encryption rather than failing
    /// online with 413.
    pub online_blob_limit: u64,
    /// How often the online node's key list copies are checked for changes
    /// made on the owner's other computers.
    pub pull_interval: Duration,
}

/// A [`SecretStore`] behind an `Arc<dyn …>`, so the OS keychain and the test
/// store share one engine type.
#[derive(Clone)]
pub struct DynStore(pub Arc<dyn SecretStore>);

impl SecretStore for DynStore {
    fn read(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        self.0.read(account)
    }
    fn write(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.0.write(account, secret)
    }
    fn remove(&self, account: &str) -> Result<(), KeychainError> {
        self.0.remove(account)
    }
}

pub type StoreFactory = Box<dyn Fn() -> Result<Arc<dyn SecretStore>, KeychainError> + Send + Sync>;

pub(crate) struct OnlineRuntime {
    pub reachable: bool,
    pub failed_checks: u32,
    pub quota: Option<u64>,
    pub full: bool,
}

pub struct Engine {
    pub(crate) cfg: EngineConfig,
    pub(crate) host: Arc<dyn Host>,
    pub(crate) http: reqwest::Client,
    pub(crate) rt: Handle,
    pub(crate) index: Index,
    store_factory: StoreFactory,
    keychain: Mutex<Option<Arc<DropKeychain<DynStore>>>>,
    identity: Mutex<Option<Arc<DropIdentity>>>,
    _temp_lock: TempDirLock,
    pub(crate) keylist: tokio::sync::Mutex<Option<KeyList>>,
    pub(crate) keysync: tokio::sync::Mutex<()>,
    pub(crate) keysync_wake: Notify,
    pub(crate) encrypt_queue: tokio::sync::Mutex<()>,
    pub(crate) progress: Mutex<HashMap<String, (u8, Instant)>>,
    pub(crate) online_rt: Mutex<OnlineRuntime>,
    pub(crate) wake: Notify,
    pub(crate) approval: Mutex<super::approve::ApprovalRuntime>,
    pub(crate) shares: Mutex<HashMap<String, super::share::ShareSession>>,
    /// One share flow per file at a time.
    pub(crate) share_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub(crate) watch_wake: Notify,
    pub(crate) deletes_wake: Notify,
    /// Rows removed while still being encrypted: their key and outbox file
    /// must not be kept.
    pub(crate) removed_ids: Mutex<std::collections::HashSet<String>>,
    /// Held for writing while restore may replace the recovery secret, and
    /// for reading by every add, so no file is keyed under a secret that is
    /// about to change.
    pub(crate) setup_lock: tokio::sync::RwLock<()>,
    /// Online key list copies (by SHA-256) already merged, or found unusable,
    /// in this process.  Cleared when the key list is reset.
    pub(crate) pulled: Mutex<std::collections::HashSet<String>>,
    /// Runs a key list pull now.
    pub(crate) pull_wake: Notify,
    /// Held by the folder pass for its whole run, and by a removal that
    /// touches the folder.  Lock order: `keysync`, then `folder_lock`, then
    /// `keylist`.  The folder pass never takes `keysync`, so `apply_key_list`
    /// (which holds `keysync` and removes rows) cannot deadlock against it.
    pub(crate) folder_lock: tokio::sync::Mutex<()>,
    /// `off`, `on`, `unavailable` or `too_many`, as the last pass found it.
    pub(crate) folder_state: Mutex<&'static str>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Engine")
    }
}

pub(crate) fn keychain_error(error: &KeychainError) -> CommandError {
    CommandError::with_message("keychain_unavailable", error.to_string())
}

pub(crate) fn internal(message: impl Into<String>) -> CommandError {
    CommandError::with_message("internal", message)
}

fn index_error(error: index::IndexError) -> CommandError {
    internal(error.to_string())
}

pub(crate) trait OrInternal<T> {
    fn or_internal(self) -> CommandResult<T>;
}

impl<T> OrInternal<T> for Result<T, index::IndexError> {
    fn or_internal(self) -> CommandResult<T> {
        self.map_err(index_error)
    }
}

/// Settings keys in the index.
pub(crate) mod kv {
    pub const ONLINE_URL: &str = "online_url";
    pub const FIRST_RUN_STEP: &str = "first_run_step";
    pub const FIRST_RUN_DONE: &str = "first_run_done";
    pub const RESTORE_PENDING: &str = "restore_pending";
    pub const APPROVAL_BY: &str = "approval_by";
    pub const APPROVAL_UNTIL: &str = "approval_until";
    pub const APPROVAL_LIMIT: &str = "approval_limit";
    pub const APPROVAL_REVOKED: &str = "approval_revoked";
    pub const RECOVERY_SAVED_AT: &str = "recovery_saved_at";
    pub const RECOVERY_CONFIRMED: &str = "recovery_confirmed";
    pub const LAST_SEEN_SEQ: &str = "key_list_last_seen_seq";
    pub const KEY_LIST_LOCAL_SHA: &str = "key_list_local_sha256";
    pub const KEY_LIST_ONLINE_SHA: &str = "key_list_online_sha256";
    /// The Wildbloom folder mirror is on (with [`FOLDER_ID`]).
    pub const WATCH_ENABLED: &str = "watch_enabled";
    /// The random id in the folder's marker file, set when the folder is
    /// turned on.
    pub const FOLDER_ID: &str = "folder_id";
    pub const LAST_CHECK: &str = "last_copy_check";
    /// A sealed key list has not reached every node it should be on.
    pub const KEY_LIST_PENDING: &str = "key_list_pending";
    /// The key list could not be opened or sealed; shown in the status line.
    pub const KEY_LIST_FAILED: &str = "key_list_failed";
}

impl Engine {
    /// Takes the temp directory lock, sweeps stale temp files (binding rule:
    /// before any Drop operation), opens the index and the keychain.
    pub fn new(
        cfg: EngineConfig,
        host: Arc<dyn Host>,
        store_factory: StoreFactory,
        rt: Handle,
    ) -> Result<Arc<Self>, String> {
        // Frozen into every entry this computer adds, so cleaned once here.
        let mut cfg = cfg;
        cfg.computer_name = super::path::computer_origin(&cfg.computer_name);
        wildbloom_private_state::private_directory(&cfg.data_dir)
            .map_err(|_| "the Drop data directory is not private".to_string())?;
        let temp_lock = TempDirLock::acquire(&cfg.temp_dir).map_err(|e| e.to_string())?;
        let report = envelope::sweep_stale_temp_files(&temp_lock).map_err(|e| e.to_string())?;
        if report.removed > 0 || !report.failed.is_empty() {
            eprintln!(
                "Wildbloom Drop: removed {} stale temp files ({} could not be removed)",
                report.removed,
                report.failed.len()
            );
        }
        let outbox = cfg.data_dir.join("outbox");
        wildbloom_private_state::private_directory(&outbox)
            .map_err(|_| "the Drop outbox is not private".to_string())?;
        let index = Index::open(&cfg.data_dir).map_err(|e| e.to_string())?;
        let engine = Arc::new(Self {
            cfg,
            host,
            http: client::http_client(),
            rt,
            index,
            store_factory,
            keychain: Mutex::new(None),
            identity: Mutex::new(None),
            _temp_lock: temp_lock,
            keylist: tokio::sync::Mutex::new(None),
            keysync: tokio::sync::Mutex::new(()),
            keysync_wake: Notify::new(),
            encrypt_queue: tokio::sync::Mutex::new(()),
            progress: Mutex::new(HashMap::new()),
            online_rt: Mutex::new(OnlineRuntime {
                reachable: true,
                failed_checks: 0,
                quota: None,
                full: false,
            }),
            wake: Notify::new(),
            approval: Mutex::new(super::approve::ApprovalRuntime::default()),
            shares: Mutex::new(HashMap::new()),
            share_locks: Mutex::new(HashMap::new()),
            watch_wake: Notify::new(),
            deletes_wake: Notify::new(),
            removed_ids: Mutex::new(std::collections::HashSet::new()),
            setup_lock: tokio::sync::RwLock::new(()),
            pulled: Mutex::new(std::collections::HashSet::new()),
            pull_wake: Notify::new(),
            folder_lock: tokio::sync::Mutex::new(()),
            folder_state: Mutex::new("off"),
        });
        let _ = engine.keychain();
        Ok(engine)
    }

    /// Starts the background workers.  Safe to call once.
    pub fn start(self: &Arc<Self>) {
        // An install from before the mirror kept `watch_enabled` for the
        // inbox folder.  The mirror moves and removes files, so the owner
        // opts in again through its confirmation.  Links are kept for the
        // enable-time rule that adopts inbox files in place.
        if self.index.get_bool(kv::WATCH_ENABLED).unwrap_or(false)
            && self.index.get(kv::FOLDER_ID).ok().flatten().is_none()
        {
            let _ = self.index.set_bool(kv::WATCH_ENABLED, false);
        }
        self.refresh_folder_state();
        // Rows left mid-step by a previous run.
        if let Ok(files) = self.index.files() {
            for file in files {
                if file.local == local::ENCRYPTING && file.watch_path.is_some() && self.mirror_on()
                {
                    self.forget_cut_off_import(&file);
                } else if file.local == local::ENCRYPTING {
                    // The original was not fully encrypted; its id is never
                    // reused, so the row shows that it must be added again.
                    let _ = self.index.set_local(&file.id, local::UNREADABLE);
                } else if file.local == local::RESTORING {
                    // A copy back that was cut off: offer Copy back again.
                    let _ = self.index.set_local(&file.id, local::MISSING);
                } else if file.online == online::COPYING {
                    let _ = self.index.set_online(&file.id, online::QUEUED);
                }
            }
        }
        self.sweep_orphan_outbox();
        // The index and keychain are the durable record of the key list.
        self.keysync_wake.notify_one();
        self.spawn_workers();
    }

    /// A folder import cut off mid-encryption is forgotten, so the pass takes
    /// its file in again.  An edit's link goes back to the version it was
    /// replacing (with a size that cannot match), so it is taken in again as
    /// an edit of that version.  It was never in the key list.
    fn forget_cut_off_import(&self, file: &FileRecord) {
        if let Some(prev) = file.prev.as_deref()
            && let Ok(Some(old)) = self.index.file(prev)
            && old.watch_path.is_none()
        {
            let _ = self.index.set_link(
                prev,
                file.watch_path.clone().map(|path| (path, u64::MAX, 0)),
            );
        }
        if let (Some(id), Ok(keychain)) = (FileId::parse(&file.id), self.keychain()) {
            let _ = keychain.remove_file_key(&id);
        }
        let _ = std::fs::remove_file(self.outbox_path(&file.id));
        let _ = self.index.delete_file(&file.id);
    }

    /// Envelopes in the outbox whose row is gone (removed while encrypting,
    /// or before a crash) are deleted.  Their keys were removed with the row.
    fn sweep_orphan_outbox(&self) {
        let Ok(entries) = std::fs::read_dir(self.cfg.data_dir.join("outbox")) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".fswn")) else {
                continue;
            };
            let keep = self
                .index
                .file(id)
                .ok()
                .flatten()
                .is_some_and(|f| f.local == local::PENDING);
            if !keep {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Whether `id` was removed while its encryption was running.
    pub(crate) fn was_removed(&self, id: &str) -> bool {
        self.removed_ids
            .lock()
            .map(|r| r.contains(id))
            .unwrap_or(true)
            || self.index.file(id).ok().flatten().is_none()
    }

    // ------------------------------------------------------------ keychain

    /// The keychain, opening it on first use.  Every failure is reported as
    /// `keychain_unavailable`.
    pub(crate) fn keychain(&self) -> CommandResult<Arc<DropKeychain<DynStore>>> {
        let mut slot = self.keychain.lock().map_err(|_| internal("lock"))?;
        if let Some(keychain) = slot.as_ref() {
            return Ok(keychain.clone());
        }
        let store = (self.store_factory)().map_err(|e| keychain_error(&e))?;
        let keychain = Arc::new(DropKeychain::new(DynStore(store)));
        *slot = Some(keychain.clone());
        Ok(keychain)
    }

    fn keychain_ok(&self) -> bool {
        match self.keychain() {
            Ok(keychain) => device::identity_state(&keychain).is_ok(),
            Err(_) => false,
        }
    }

    fn recheck_keychain(&self) {
        if let Ok(mut slot) = self.keychain.lock() {
            *slot = None;
        }
        if let Ok(mut identity) = self.identity.lock() {
            *identity = None;
        }
        let _ = self.keychain();
    }

    pub(crate) fn identity_state(&self) -> CommandResult<IdentityState> {
        let keychain = self.keychain()?;
        device::identity_state(&keychain).map_err(|e| device_error(&e))
    }

    /// The loaded device key and recovery secret.  Never creates them.
    pub(crate) fn identity(&self) -> CommandResult<Arc<DropIdentity>> {
        if let Some(identity) = self.identity.lock().map_err(|_| internal("lock"))?.as_ref() {
            return Ok(identity.clone());
        }
        let keychain = self.keychain()?;
        let identity = Arc::new(device::load_identity(&keychain).map_err(|e| device_error(&e))?);
        *self.identity.lock().map_err(|_| internal("lock"))? = Some(identity.clone());
        Ok(identity)
    }

    fn set_identity(&self, identity: DropIdentity) -> Arc<DropIdentity> {
        let identity = Arc::new(identity);
        if let Ok(mut slot) = self.identity.lock() {
            *slot = Some(identity.clone());
        }
        identity
    }

    /// The public keys the local node must trust: the device key and the
    /// recovery identity.  Empty before first run.
    pub fn local_trusted_keys(&self) -> Vec<String> {
        match self.identity() {
            Ok(identity) => vec![
                identity.device.public_key_hex(),
                identity.recovery.identity().public_key_hex(),
            ],
            Err(_) => Vec::new(),
        }
    }

    fn first_run_lock(&self) -> CommandResult<FirstRunLock> {
        FirstRunLock::acquire(&self.cfg.data_dir.join("locks")).map_err(|e| match e {
            DeviceError::FirstRunInProgress => CommandError::code("busy"),
            other => internal(other.to_string()),
        })
    }

    // --------------------------------------------------------------- nodes

    pub(crate) fn online_endpoint(&self) -> Option<NodeEndpoint> {
        let url = self.index.get(kv::ONLINE_URL).ok().flatten()?;
        NodeEndpoint::parse(&url, self.cfg.allow_loopback_http).ok()
    }

    pub(crate) fn local_endpoint(&self) -> Option<NodeEndpoint> {
        let node = self.host.local_node();
        if node.state != "ok" {
            return None;
        }
        node.endpoint
    }

    /// The local node is listening: run pending uploads and the key list now,
    /// and pick up other computers' changes that waited for it.
    pub fn local_node_ready(&self) {
        self.wake.notify_one();
        if self.index.get_bool(kv::KEY_LIST_PENDING).unwrap_or(false) {
            self.keysync_wake.notify_one();
        }
        self.pull_wake.notify_one();
    }

    pub(crate) fn approval_active(&self) -> bool {
        let now = now();
        !self.index.get_bool(kv::APPROVAL_REVOKED).unwrap_or(false)
            && self.index.get(kv::APPROVAL_BY).ok().flatten().is_some()
            && self
                .index
                .get_u64(kv::APPROVAL_UNTIL)
                .ok()
                .flatten()
                .is_some_and(|until| until > now)
    }

    /// The online node, only while this computer may write to it.
    pub(crate) fn writable_online(&self) -> Option<NodeEndpoint> {
        if !self.approval_active() {
            return None;
        }
        self.online_endpoint()
    }

    pub(crate) fn drop_max_bytes(&self) -> u64 {
        envelope::drop_limits(self.cfg.online_blob_limit).max_source_bytes()
    }

    // ------------------------------------------------------------- folder

    /// Whether the Wildbloom folder mirror is on: turned on, with a folder id.
    pub(crate) fn mirror_on(&self) -> bool {
        self.index.get_bool(kv::WATCH_ENABLED).unwrap_or(false)
            && self.index.get(kv::FOLDER_ID).ok().flatten().is_some()
    }

    /// Whether the folder is there now: its root is a real folder whose
    /// marker holds this install's folder id.
    pub(crate) fn folder_available(&self) -> bool {
        let id = self
            .index
            .get(kv::FOLDER_ID)
            .ok()
            .flatten()
            .unwrap_or_default();
        super::folder::available(&self.cfg.watch_dir, &id)
    }

    /// `off`, `on`, `unavailable` or `too_many`.
    pub(crate) fn folder_state(&self) -> &'static str {
        if !self.mirror_on() {
            "off"
        } else if !self.folder_available() {
            "unavailable"
        } else if matches!(self.folder_state.lock().map(|s| *s), Ok("too_many")) {
            "too_many"
        } else {
            "on"
        }
    }

    /// Records the folder state; emits the status when it changed.
    pub(crate) fn set_folder_state(&self, state: &'static str) {
        let changed = match self.folder_state.lock() {
            Ok(mut slot) => std::mem::replace(&mut *slot, state) != state,
            Err(_) => false,
        };
        if changed {
            self.emit_status();
        }
    }

    fn refresh_folder_state(&self) {
        let state = if !self.mirror_on() {
            "off"
        } else if self.folder_available() {
            "on"
        } else {
            "unavailable"
        };
        if let Ok(mut slot) = self.folder_state.lock() {
            *slot = state;
        }
    }

    // -------------------------------------------------------------- status

    pub fn first_run(&self) -> Option<FirstRun> {
        let done = self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false);
        let node_settings_exist = self.host.node_settings_exist();
        if !self.keychain_ok() {
            if done {
                return None;
            }
            return Some(FirstRun {
                step: "keychain",
                node_settings_exist,
            });
        }
        if done {
            return None;
        }
        let step = match self.index.get(kv::FIRST_RUN_STEP).ok().flatten().as_deref() {
            Some("approve") => "approve",
            Some("recovery") => "recovery",
            _ => "node",
        };
        Some(FirstRun {
            step,
            node_settings_exist,
        })
    }

    pub fn status(&self) -> DropStatus {
        let online_url = self.index.get(kv::ONLINE_URL).ok().flatten();
        let endpoint = self.online_endpoint();
        let runtime = self
            .online_rt
            .lock()
            .map(|r| (r.reachable, r.failed_checks, r.quota, r.full));
        let (reachable, failed_checks, quota, full) = runtime.unwrap_or((false, 0, None, false));
        let approval_limit = self.index.get_u64(kv::APPROVAL_LIMIT).ok().flatten();
        let used = self.index.online_used_bytes().unwrap_or(0);
        let limit = approval_limit.or(quota).unwrap_or(0);
        let online = OnlineStatus {
            configured: online_url.is_some(),
            url: endpoint
                .as_ref()
                .map(|e| e.origin().trim_end_matches('/').to_owned())
                .unwrap_or_default(),
            host: endpoint
                .as_ref()
                .map(NodeEndpoint::host)
                .unwrap_or_default(),
            reachable,
            failed_checks,
            used_bytes: used,
            limit_bytes: limit,
            full: full || (limit > 0 && used >= limit),
        };
        let device_npub = self
            .identity()
            .ok()
            .map(|i| npub(&i.device.public_key_hex()));
        let by = self.index.get(kv::APPROVAL_BY).ok().flatten();
        let until = self.index.get_u64(kv::APPROVAL_UNTIL).ok().flatten();
        let approval = match (&by, until) {
            (Some(by), Some(until)) => ApprovalSummary {
                state: if self.approval_active() {
                    "active"
                } else {
                    "expired"
                },
                by_npub: Some(npub(by)),
                device_npub,
                until: Some(until),
                limit_bytes: approval_limit,
            },
            _ => ApprovalSummary {
                state: "none",
                by_npub: None,
                device_npub,
                until: None,
                limit_bytes: None,
            },
        };
        let recovery = RecoveryStatus {
            key_list: if self.key_list_failed() {
                "failed"
            } else {
                "ok"
            },
            saved_at: self.index.get_u64(kv::RECOVERY_SAVED_AT).ok().flatten(),
            confirmed: self
                .index
                .get(kv::RECOVERY_CONFIRMED)
                .ok()
                .flatten()
                .is_none_or(|v| v == "1"),
        };
        DropStatus {
            first_run: self.first_run(),
            node: self.host.local_node().state,
            keychain: if self.keychain_ok() {
                "ok"
            } else {
                "unavailable"
            },
            online,
            approval,
            recovery,
            watch_folder: WatchFolderStatus {
                enabled: self.mirror_on(),
                path: self.cfg.watch_display.clone(),
                state: self.folder_state(),
            },
            limits: LimitsStatus {
                drop_max_bytes: self.drop_max_bytes(),
                share_max_bytes: SHARE_MAX_PLAINTEXT_BYTES,
            },
            browser_approval: false,
        }
    }

    pub fn snapshot(&self) -> DropSnapshot {
        DropSnapshot {
            status: self.status(),
            files: self.rows(),
        }
    }

    pub fn rows(&self) -> Vec<FileRow> {
        let shares: HashMap<String, index::ShareRecord> = self
            .index
            .shares()
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.file_id.clone(), s))
            .collect();
        self.index
            .files()
            .unwrap_or_default()
            .iter()
            .map(|f| self.row_for(f, shares.get(&f.id)))
            .collect()
    }

    fn row_for(&self, file: &FileRecord, share: Option<&index::ShareRecord>) -> FileRow {
        let progress = self
            .progress
            .lock()
            .ok()
            .and_then(|p| p.get(&file.id).map(|(v, _)| *v));
        let now = now();
        let mut shared_until = None;
        let mut sharing_ended = None;
        let state: &'static str = match (file.local.as_str(), file.online.as_str()) {
            (local::NOT_KEPT, _) => "not_kept",
            (local::RESTORING, _) => "restoring",
            (local::ENCRYPTING | local::PENDING, _) => "encrypting",
            (local::UNREADABLE, _) => "unreadable",
            (_, online::NONE) => "no_online",
            (_, online::QUEUED) => "queued",
            (_, online::COPYING) => "copying",
            (_, online::WAITING) => "waiting",
            (_, online::FAILED) => "failed",
            (_, online::MISSING) => "missing_online",
            (_, online::FULL) => "online_full",
            (local::MISSING, _) => "missing_local",
            _ => match share.map(|s| s.state.as_str()) {
                Some(index::share::SENT) => {
                    shared_until = share.and_then(|s| s.delete_at);
                    "shared"
                }
                Some(index::share::STOP_PENDING) => "stop_pending",
                // Shown until the record is swept a day after it was marked.
                Some(index::share::OWNER_ONLY) => "share_owner_only",
                // A replaced shared copy stranded on the node, for a day.
                _ if self
                    .index
                    .stranded_at(&file.id)
                    .ok()
                    .flatten()
                    .is_some_and(|at| now.saturating_sub(at) < 86_400) =>
                {
                    "share_owner_only"
                }
                Some(index::share::ENDED)
                    if share
                        .and_then(|s| s.ended_at)
                        .is_some_and(|at| now.saturating_sub(at) < 86_400) =>
                {
                    sharing_ended = share.and_then(|s| s.ended_at);
                    "sharing_ended"
                }
                _ => "two_copies",
            },
        };
        let progress = match state {
            "encrypting" | "copying" | "restoring" => progress.or(Some(0)),
            _ => None,
        };
        FileRow {
            id: file.id.clone(),
            name: file.name.clone(),
            bytes: file.bytes,
            added: file.added,
            state,
            progress,
            shared_until,
            sharing_ended,
            not_kept: (state == "not_kept").then_some(match file.note.as_deref() {
                Some("too_big") => "too_big",
                Some("too_long") => "too_long",
                Some("too_deep") => "too_deep",
                _ => "name",
            }),
            folder: self.row_folder(file),
            // A "Not kept" row has a file there too (Show in Finder finds
            // it), but nothing Wildbloom keeps.
            in_watch_folder: file.watch_path.is_some() && state != "not_kept",
        }
    }

    /// The row's folder relative to the Wildbloom folder, for display: where
    /// its file is, or (with the mirror on) where its entry path puts it.
    fn row_folder(&self, file: &FileRecord) -> Option<String> {
        let rel: Vec<String> = match &file.watch_path {
            Some(path) => super::folder::relative(&self.cfg.watch_dir, Path::new(path))?,
            None if self.mirror_on() => file.path.split('/').map(str::to_owned).collect(),
            None => return None,
        };
        (rel.len() > 1).then(|| rel[..rel.len() - 1].join("/"))
    }

    pub(crate) fn emit_row(&self, id: &str) {
        let Ok(Some(file)) = self.index.file(id) else {
            return;
        };
        let share = self.index.share(id).ok().flatten();
        self.host.emit_file(&self.row_for(&file, share.as_ref()));
    }

    /// Records progress and emits at most four row updates a second.
    pub(crate) fn set_progress(&self, id: &str, percent: u8) {
        let emit = {
            let Ok(mut progress) = self.progress.lock() else {
                return;
            };
            let now = Instant::now();
            let previous = progress.get(id).copied();
            match previous {
                Some((last, at))
                    if last == percent
                        || (now.duration_since(at) < Duration::from_millis(250)
                            && percent < 100) =>
                {
                    progress.insert(id.to_owned(), (percent, at));
                    false
                }
                _ => {
                    progress.insert(id.to_owned(), (percent, now));
                    true
                }
            }
        };
        if emit {
            self.emit_row(id);
        }
    }

    pub(crate) fn clear_progress(&self, id: &str) {
        if let Ok(mut progress) = self.progress.lock() {
            progress.remove(id);
        }
    }

    pub fn emit_status(&self) {
        let status = self.status();
        let line = super::status::resolve(&status, &self.rows(), now());
        self.host.emit_status(&status, &line);
    }

    pub fn status_line(&self) -> super::status::StatusLine {
        super::status::resolve(&self.status(), &self.rows(), now())
    }

    pub async fn drop_status(self: &Arc<Self>, recheck: Option<&str>) -> DropSnapshot {
        match recheck {
            Some("keychain") => self.recheck_keychain(),
            Some("keylist") => self.sync_key_list_reporting().await,
            Some("online") => {
                self.check_online().await;
                self.wake.notify_one();
            }
            _ => {}
        }
        self.snapshot()
    }

    pub fn platform_info(&self) -> PlatformInfo {
        PlatformInfo {
            os: match std::env::consts::OS {
                "macos" => "macos",
                "windows" => "windows",
                _ => "linux",
            },
            desktop: if cfg!(target_os = "linux") {
                std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default()
            } else {
                String::new()
            },
            computer_name: self.cfg.computer_name.clone(),
        }
    }

    // ---------------------------------------------------------- first run

    pub async fn check_online_node(&self, url: &str) -> CommandResult<NodeCheck> {
        let node = NodeEndpoint::parse(url, self.cfg.allow_loopback_http)
            .map_err(|_| CommandError::with_host("not_a_node", host_of(url)))?;
        match client::health(&self.http, &node).await {
            Ok(health) => {
                if let Ok(mut rt) = self.online_rt.lock() {
                    rt.quota = Some(health.quota_bytes);
                }
                Ok(NodeCheck {
                    ok: true,
                    host: node.host(),
                    used_bytes: health.bytes,
                    limit_bytes: health.quota_bytes,
                })
            }
            Err(NodeError::Tls) => Err(CommandError::with_host("tls", node.host())),
            Err(NodeError::Unreachable) => Err(CommandError::with_host("no_answer", node.host())),
            Err(_) => Err(CommandError::with_host("not_a_node", node.host())),
        }
    }

    /// Makes the device key and recovery secret if this is a fresh computer.
    /// A partial set (one secret lost) is never repaired by regenerating.
    fn ensure_identity(&self) -> CommandResult<()> {
        match self.identity_state()? {
            IdentityState::Ready => {
                self.identity()?;
                Ok(())
            }
            IdentityState::Partial => Err(CommandError::with_message(
                "restore_needed",
                "Drop's keys are incomplete on this computer; restore with the recovery key.",
            )),
            IdentityState::Fresh => {
                let lock = self.first_run_lock()?;
                let keychain = self.keychain()?;
                let identity =
                    device::create_first_run(&keychain, &lock).map_err(|e| device_error(&e))?;
                self.set_identity(identity);
                self.host.trust_changed();
                Ok(())
            }
        }
    }

    pub async fn set_online_node(self: &Arc<Self>, url: Option<&str>) -> CommandResult<()> {
        let first = !self.index.get_bool(kv::FIRST_RUN_DONE).or_internal()?;
        if first && !self.host.node_settings_exist() {
            self.host
                .ensure_node_settings()
                .map_err(|e| CommandError::with_message("node", e))?;
        }
        self.ensure_identity()?;
        let previous = self.index.get(kv::ONLINE_URL).or_internal()?;
        match url {
            Some(url) => {
                let node = NodeEndpoint::parse(url, self.cfg.allow_loopback_http)
                    .map_err(|_| CommandError::with_host("not_a_node", host_of(url)))?;
                let origin = node.origin().to_owned();
                if previous.as_deref() != Some(origin.as_str()) {
                    self.end_shares_before_node_change().await?;
                    self.index.set(kv::ONLINE_URL, &origin).or_internal()?;
                    self.forget_approval()?;
                    self.requeue_all_online()?;
                    if let Ok(mut rt) = self.online_rt.lock() {
                        rt.failed_checks = 0;
                        rt.reachable = true;
                        rt.full = false;
                    }
                }
                if first {
                    self.index
                        .set(kv::FIRST_RUN_STEP, "approve")
                        .or_internal()?;
                }
            }
            None => {
                if previous.is_some() {
                    self.end_shares_before_node_change().await?;
                }
                self.index.unset(kv::ONLINE_URL).or_internal()?;
                self.forget_approval()?;
                for file in self.index.files().or_internal()? {
                    self.index
                        .set_online(&file.id, online::NONE)
                        .or_internal()?;
                }
                if first {
                    self.index
                        .set(kv::FIRST_RUN_STEP, "recovery")
                        .or_internal()?;
                }
            }
        }
        self.emit_status();
        for file in self.index.files().or_internal()? {
            self.emit_row(&file.id);
        }
        self.wake.notify_one();
        Ok(())
    }

    fn forget_approval(&self) -> CommandResult<()> {
        for key in [
            kv::APPROVAL_BY,
            kv::APPROVAL_UNTIL,
            kv::APPROVAL_LIMIT,
            kv::APPROVAL_REVOKED,
        ] {
            self.index.unset(key).or_internal()?;
        }
        Ok(())
    }

    fn requeue_all_online(&self) -> CommandResult<()> {
        for file in self.index.files().or_internal()? {
            if file.local != local::UNREADABLE && file.local != local::NOT_KEPT {
                self.index
                    .set_online(&file.id, online::QUEUED)
                    .or_internal()?;
                self.index.set_backoff(&file.id, 0, 0).or_internal()?;
            }
        }
        Ok(())
    }

    pub fn recovery_key_for_display(&self) -> CommandResult<RecoveryKeyDisplay> {
        let identity = self.identity()?;
        Ok(RecoveryKeyDisplay {
            key: identity.recovery.to_display().to_string(),
        })
    }

    pub fn save_recovery_file(&self, path: Option<PathBuf>) -> CommandResult<SavedRecoveryFile> {
        let identity = self.identity()?;
        let path = match path {
            Some(path) => path,
            None => self
                .host
                .pick_save_path("Wildbloom recovery key.txt")
                .ok_or(CommandError::code("cancelled"))?,
        };
        let online = self
            .online_endpoint()
            .map(|e| e.origin().trim_end_matches('/').to_owned())
            .unwrap_or_else(|| "not set up".into());
        let text = Zeroizing::new(format!(
            "Wildbloom recovery key\nCreated {} on {}\n\n{}\n\nOnline node: {}\n\nUse this to restore your Wildbloom Drop files on a new computer:\nopen Wildbloom Drop, choose \"Restore from a recovery key\" and enter it.\nKeep this file somewhere safe and private.\n",
            super::status::full_date(now()),
            self.cfg.computer_name,
            identity.recovery.to_display().as_str(),
            online,
        ));
        write_private_file(&path, text.as_bytes())
            .map_err(|_| CommandError::with_message("save_failed", "Couldn't save the file."))?;
        self.index
            .set_u64(kv::RECOVERY_SAVED_AT, now())
            .or_internal()?;
        self.emit_status();
        Ok(SavedRecoveryFile {
            filename: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        })
    }

    pub fn confirm_recovery_saved(self: &Arc<Self>) -> CommandResult<()> {
        self.identity()?;
        if self
            .index
            .get(kv::RECOVERY_SAVED_AT)
            .or_internal()?
            .is_none()
        {
            self.index
                .set_u64(kv::RECOVERY_SAVED_AT, now())
                .or_internal()?;
        }
        self.index
            .set_bool(kv::RECOVERY_CONFIRMED, true)
            .or_internal()?;
        self.index
            .set_bool(kv::FIRST_RUN_DONE, true)
            .or_internal()?;
        self.index.unset(kv::FIRST_RUN_STEP).or_internal()?;
        self.emit_status();
        self.keysync_wake.notify_one();
        self.watch_wake.notify_one();
        Ok(())
    }

    /// Turns the Wildbloom folder mirror on or off.
    ///
    /// - On (from off): writes the marker with a new folder id.  Files kept
    ///   through the earlier inbox folder are linked in place when they sit
    ///   at the root under their own name, unchanged; one in a subfolder is
    ///   taken in again at its real path, replacing its old entry once kept.
    ///   Every other link is cleared, so files already in the folder are
    ///   linked by content or taken in as new.
    /// - On again (the folder or its marker was lost): if the marker is back,
    ///   nothing changes.  Otherwise every link is cleared and a new marker
    ///   written, so no deletion is ever inferred against a folder that was
    ///   recreated empty.
    /// - Off: every link is cleared; the files stay as the owner's own.
    pub async fn set_watch_folder(self: &Arc<Self>, enabled: bool) -> CommandResult<()> {
        let was_on = self.mirror_on();
        if enabled && was_on && self.folder_available() {
            self.refresh_folder_state();
            self.emit_status();
            self.watch_wake.notify_one();
            self.pull_wake.notify_one();
            return Ok(());
        }
        let _folder = self.folder_lock.lock().await;
        if enabled {
            let id = FileId::random()
                .map_err(|_| internal("random"))?
                .to_string();
            super::folder::write_marker(&self.cfg.watch_dir, &id).map_err(|_| {
                CommandError::with_message("watch_folder", "Couldn't create the Wildbloom folder.")
            })?;
            if was_on {
                self.clear_folder_links()?;
            } else {
                self.adopt_inbox_links().await?;
            }
            self.index.set(kv::FOLDER_ID, &id).or_internal()?;
        } else {
            self.clear_folder_links()?;
            self.index.unset(kv::FOLDER_ID).or_internal()?;
        }
        self.index
            .set_bool(kv::WATCH_ENABLED, enabled)
            .or_internal()?;
        self.refresh_folder_state();
        drop(_folder);
        self.emit_status();
        for file in self.index.files().or_internal()? {
            self.emit_row(&file.id);
        }
        self.watch_wake.notify_one();
        self.pull_wake.notify_one();
        Ok(())
    }

    /// Clears every link and drops "Not kept" rows.  The caller holds the
    /// folder lock.
    fn clear_folder_links(&self) -> CommandResult<()> {
        for file in self.index.files().or_internal()? {
            if file.local == local::NOT_KEPT {
                self.index.delete_file(&file.id).or_internal()?;
                self.host.emit_removed(&file.id);
            } else if file.watch_path.is_some() {
                self.index.set_link(&file.id, None).or_internal()?;
            }
        }
        Ok(())
    }

    /// The enable-time rule for files kept through the earlier inbox folder
    /// (spec 2.7).  The caller holds the folder lock.
    async fn adopt_inbox_links(self: &Arc<Self>) -> CommandResult<()> {
        use super::folder::Stat;
        let root = self.cfg.watch_dir.clone();
        for file in self.index.files().or_internal()? {
            let Some(link) = file.watch_path.clone() else {
                continue;
            };
            if file.local == local::NOT_KEPT {
                self.index.delete_file(&file.id).or_internal()?;
                self.host.emit_removed(&file.id);
                continue;
            }
            let path = PathBuf::from(&link);
            let unchanged = matches!(
                super::folder::stat_path(&root, &path),
                Stat::Present(meta) if super::folder::matches(&meta, file.watch_size, file.watch_mtime)
            );
            let legacy = file.path == file.name
                && file.sha256.is_some()
                && file.local != local::UNREADABLE
                && file.local != local::ENCRYPTING;
            let rel = super::folder::relative_nfc(&root, &path);
            match rel {
                Some(rel) if unchanged && legacy => {
                    if super::path::fold(&rel) == super::path::fold(&file.path) {
                        // At the root under its own name: linked in place.
                        continue;
                    }
                    self.index.set_link(&file.id, None).or_internal()?;
                    let Ok(meta) = std::fs::symlink_metadata(&path) else {
                        continue;
                    };
                    if super::watch::not_kept_reason(&rel, false, meta.len(), self.drop_max_bytes())
                        .is_some()
                    {
                        continue;
                    }
                    let hash_path = path.clone();
                    let Ok(Ok(hash)) =
                        tokio::task::spawn_blocking(move || sha256_file(&hash_path)).await
                    else {
                        continue;
                    };
                    // Re-encrypted at its real path; the inbox entry is
                    // removed once the new one is kept.
                    let _ = self
                        .import_folder_file(path, rel, &meta, hash, Some(file.id.clone()))
                        .await;
                }
                _ => self.index.set_link(&file.id, None).or_internal()?,
            }
        }
        Ok(())
    }

    /// Opens a row's file in the Wildbloom folder with its default app.
    pub fn open_file(&self, id: &str) -> CommandResult<()> {
        let path = self.folder_file(id)?;
        self.host.open_path(&path);
        Ok(())
    }

    /// Shows a row's file in Finder, Explorer or the file manager.
    pub fn reveal_file(&self, id: &str) -> CommandResult<()> {
        let path = self.folder_file(id)?;
        self.host.reveal_path(&path);
        Ok(())
    }

    /// The row's file in the folder, if it is there now (a "Not kept" row
    /// counts).
    fn folder_file(&self, id: &str) -> CommandResult<PathBuf> {
        let file = self
            .index
            .file(id)
            .or_internal()?
            .ok_or(CommandError::code("not_found"))?;
        let path = file
            .watch_path
            .map(PathBuf::from)
            .ok_or(CommandError::code("not_in_folder"))?;
        match super::folder::stat_path(&self.cfg.watch_dir, &path) {
            super::folder::Stat::Present(_) => Ok(path),
            _ => Err(CommandError::code("not_in_folder")),
        }
    }

    pub fn open_watch_folder(&self) -> CommandResult<()> {
        std::fs::create_dir_all(&self.cfg.watch_dir).map_err(|_| {
            CommandError::with_message("watch_folder", "Couldn't open the Wildbloom folder.")
        })?;
        self.host.open_folder(&self.cfg.watch_dir);
        Ok(())
    }

    // --------------------------------------------------------------- files

    pub async fn pick_files(self: &Arc<Self>) -> CommandResult<AddResult> {
        let host = self.host.clone();
        let paths = tokio::task::spawn_blocking(move || host.pick_files())
            .await
            .unwrap_or_default();
        self.add_paths(paths).await
    }

    /// Classifies, de-duplicates and queues each path from the window.
    /// While the Wildbloom folder mirror is on, each file gets a free path at
    /// the folder's root, and the folder pass places it once encrypted.
    pub async fn add_paths(self: &Arc<Self>, paths: Vec<PathBuf>) -> CommandResult<AddResult> {
        let mut result = AddResult::default();
        if paths.is_empty() {
            return Ok(result);
        }
        let _setup = self.setup_lock.read().await;
        self.identity()?;
        let limit = self.drop_max_bytes();
        let mirror = self.mirror_on();
        for path in paths {
            let name = wildbloom_envelope::sanitise_name(
                &path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            );
            let meta = match std::fs::metadata(&path) {
                Ok(meta) => meta,
                Err(_) => {
                    result.refused.push(refused(&name, "unreadable", None));
                    continue;
                }
            };
            if meta.is_dir() {
                result.refused.push(refused(&name, "folder", None));
                continue;
            }
            if !meta.is_file() || meta.len() == 0 {
                result.refused.push(refused(&name, "unreadable", None));
                continue;
            }
            if meta.len() > limit {
                result.refused.push(refused(&name, "too_big", Some(limit)));
                continue;
            }
            let hash_path = path.clone();
            let plain = match tokio::task::spawn_blocking(move || sha256_file(&hash_path)).await {
                Ok(Ok(hash)) => hash,
                _ => {
                    result.refused.push(refused(&name, "unreadable", None));
                    continue;
                }
            };
            if let Some(existing) = self.index.file_by_plain_sha256(&plain).or_internal()? {
                result.duplicates.push(Duplicate {
                    name,
                    id: existing.id,
                });
                continue;
            }
            // A version 1 entry (its path is its name) while the mirror is
            // off; a free root path, `plain` and `from` while it is on.
            let fields = if mirror {
                NewFields {
                    path: self.free_root_path(&name)?,
                    prev: None,
                    origin: self.cfg.computer_name.clone(),
                    entry_plain: plain.clone(),
                }
            } else {
                NewFields {
                    path: name.clone(),
                    prev: None,
                    origin: String::new(),
                    entry_plain: String::new(),
                }
            };
            let id = self.queue_new_file(path, name, meta.len(), plain, fields, None)?;
            result.added.push(id);
        }
        self.emit_status();
        Ok(result)
    }

    /// Inserts a row for a new file and starts its encryption.
    fn queue_new_file(
        self: &Arc<Self>,
        source: PathBuf,
        name: String,
        bytes: u64,
        plain: String,
        fields: NewFields,
        link: Option<(String, u64, i64)>,
    ) -> CommandResult<String> {
        // Every entry must pass the key list's own checks, or every other
        // computer would refuse the whole list.
        if !(fields.path == name || super::path::valid_path(&fields.path))
            || !super::device::valid_from(&fields.origin)
        {
            return Err(internal("not a valid entry path"));
        }
        let id = FileId::random()
            .map_err(|_| internal("random"))?
            .to_string();
        let record = FileRecord {
            id: id.clone(),
            name: name.clone(),
            media_type: guess_media_type(&name).to_owned(),
            bytes,
            added: now(),
            plain_sha256: plain,
            sha256: None,
            size: None,
            local: local::ENCRYPTING.into(),
            online: if self.online_endpoint().is_some() {
                online::QUEUED.into()
            } else {
                online::NONE.into()
            },
            attempts: 0,
            next_attempt: 0,
            watch_path: link.as_ref().map(|(path, _, _)| path.clone()),
            watch_size: link.as_ref().map(|(_, size, _)| *size),
            watch_mtime: link.as_ref().map(|(_, _, mtime)| *mtime),
            path: fields.path,
            prev: fields.prev,
            origin: fields.origin,
            entry_plain: fields.entry_plain,
            note: None,
        };
        self.index.insert_file(&record).or_internal()?;
        self.set_progress(&id, 0);
        let engine = self.clone();
        let task_id = id.clone();
        self.rt
            .spawn(async move { engine.encrypt_and_keep(task_id, source).await });
        Ok(id)
    }

    /// Takes in a file found in the Wildbloom folder at `rel` (its entry
    /// path, NFC): a new entry with a fresh key, linked to the file, with no
    /// content de-duplication (the same bytes at two paths are two files).
    /// An edit names the version it replaces as `prev` and keeps its path.
    pub(crate) async fn import_folder_file(
        self: &Arc<Self>,
        source: PathBuf,
        rel: String,
        meta: &std::fs::Metadata,
        plain: String,
        prev: Option<String>,
    ) -> CommandResult<String> {
        let _setup = self.setup_lock.read().await;
        self.identity()?;
        // The envelope's own name for the file, which the entry carries and
        // reconcile rebuilds from the row: they must be equal.
        let name = wildbloom_envelope::sanitise_name(
            &source
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        let link = (
            source.to_string_lossy().into_owned(),
            meta.len(),
            super::folder::mtime_of(meta),
        );
        let fields = NewFields {
            path: rel,
            prev,
            origin: self.cfg.computer_name.clone(),
            entry_plain: plain.clone(),
        };
        let id = self.queue_new_file(source, name, meta.len(), plain, fields, Some(link))?;
        self.emit_status();
        Ok(id)
    }

    /// A root path no row and no file in the folder has yet: the name, or
    /// `"{stem} 2{ext}"` and so on, compared by folded key.
    fn free_root_path(&self, name: &str) -> CommandResult<String> {
        let base = super::path::safe_component(name);
        let mut taken = std::collections::HashSet::new();
        for file in self.index.files().or_internal()? {
            let parts: Vec<&str> = file.path.split('/').collect();
            for n in 1..=parts.len() {
                taken.insert(super::path::fold(&parts[..n].join("/")));
            }
        }
        for n in 1..10_000u32 {
            let candidate = if n == 1 {
                base.clone()
            } else {
                super::folder::numbered(&base, n)
            };
            let on_disk = std::fs::symlink_metadata(self.cfg.watch_dir.join(&candidate)).is_ok();
            if !on_disk && !taken.contains(&super::path::fold(&candidate)) {
                return Ok(candidate);
            }
        }
        Err(internal("no free name"))
    }

    /// Encrypts one new file under a fresh key (its id is never reused for
    /// another encryption), stores the key, records it in the key list and
    /// puts the envelope on the local node.
    async fn encrypt_and_keep(self: Arc<Self>, id: String, source: PathBuf) {
        let _turn = self.encrypt_queue.lock().await;
        let Ok(Some(record)) = self.index.file(&id) else {
            return;
        };
        let Some(file_id) = FileId::parse(&id) else {
            return;
        };
        let engine = self.clone();
        let temp_dir = self.cfg.temp_dir.clone();
        let media_type = record.media_type.clone();
        let limits = envelope::drop_limits(DEFAULT_NODE_BLOB_LIMIT);
        let progress_id = id.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            envelope::encrypt_new_file(
                &source,
                &media_type,
                limits,
                &temp_dir,
                &mut |done, total| {
                    if engine.was_removed(&progress_id) {
                        return ControlFlow::Break(());
                    }
                    let percent = (done.saturating_mul(100) / total.max(1)).min(99) as u8;
                    engine.set_progress(&progress_id, percent);
                    ControlFlow::Continue(())
                },
            )
        })
        .await;
        if self.was_removed(&id) {
            // Removed while encrypting: the envelope (a temp file) drops here
            // and no key is ever stored.
            self.clear_progress(&id);
            return;
        }
        let encrypted = match outcome {
            Ok(Ok(encrypted)) => encrypted,
            _ => {
                let _ = self.index.set_local(&id, local::UNREADABLE);
                self.clear_progress(&id);
                self.emit_row(&id);
                self.emit_status();
                return;
            }
        };
        let keychain = match self.keychain() {
            Ok(keychain) => keychain,
            Err(_) => {
                let _ = self.index.set_local(&id, local::UNREADABLE);
                self.emit_row(&id);
                self.emit_status();
                return;
            }
        };
        if keychain.set_file_key(&file_id, &encrypted.key).is_err() {
            let _ = self.index.set_local(&id, local::UNREADABLE);
            self.emit_row(&id);
            self.emit_status();
            return;
        }
        let sha = hex_lower(&encrypted.sealed.sha256);
        let size = encrypted.sealed.envelope_bytes;
        let outbox = self.outbox_path(&id);
        if encrypted.file.persist(&outbox).is_err() {
            let _ = keychain.remove_file_key(&file_id);
            let _ = self.index.set_local(&id, local::UNREADABLE);
            self.emit_row(&id);
            return;
        }
        if self.was_removed(&id) {
            // Removed between the check above and storing the key.
            let _ = keychain.remove_file_key(&file_id);
            let _ = std::fs::remove_file(&outbox);
            self.clear_progress(&id);
            return;
        }
        let _ = self.index.set_envelope(&id, &sha, size);
        let _ = self
            .index
            .set_media_type(&id, &encrypted.sealed.metadata.media_type);
        let _ = self.index.set_local(&id, local::PENDING);
        {
            let mut keylist = self.keylist.lock().await;
            let _ = self.load_key_list(&mut keylist);
            if let Some(list) = keylist.as_mut() {
                let _ = list.insert(KeyListEntry {
                    id: file_id,
                    sha256: encrypted.sealed.sha256,
                    size,
                    key: encrypted.key.clone(),
                    name: encrypted.sealed.metadata.name.clone(),
                    media_type: encrypted.sealed.metadata.media_type.clone(),
                    bytes: encrypted.sealed.metadata.size,
                    added: record.added,
                    // The frozen row fields, exactly as reconcile rebuilds them.
                    path: if record.path == record.name {
                        encrypted.sealed.metadata.name.clone()
                    } else {
                        record.path.clone()
                    },
                    prev: record.prev.as_deref().and_then(FileId::parse),
                    plain: super::parse_sha256(&record.entry_plain),
                    from: record.origin.clone(),
                });
            }
        }
        drop(_turn);
        self.keysync_wake.notify_one();
        self.upload_local(&id).await;
        self.wake.notify_one();
    }

    pub(crate) fn outbox_path(&self, id: &str) -> PathBuf {
        self.cfg.data_dir.join("outbox").join(format!("{id}.fswn"))
    }

    /// Puts a pending envelope from the outbox on the local node.
    pub(crate) async fn upload_local(self: &Arc<Self>, id: &str) -> bool {
        let Ok(Some(record)) = self.index.file(id) else {
            return false;
        };
        let (Some(sha), Some(size)) = (record.sha256.clone(), record.size) else {
            return false;
        };
        let Some(node) = self.local_endpoint() else {
            return false;
        };
        let Ok(identity) = self.identity() else {
            return false;
        };
        let outbox = self.outbox_path(id);
        let engine = self.clone();
        let progress_id = id.to_owned();
        let body = match client::file_body(&outbox, move |sent| {
            let percent = 99u64.min(sent.saturating_mul(100) / size.max(1)) as u8;
            engine.set_progress(&progress_id, percent);
        })
        .await
        {
            Ok(body) => body,
            Err(_) => return false,
        };
        match client::upload(&self.http, &node, identity.device.keys(), &sha, size, body).await {
            Ok(()) => {
                let _ = self.index.set_local(id, local::OK);
                let _ = std::fs::remove_file(&outbox);
                self.clear_progress(id);
                self.emit_row(id);
                self.emit_status();
                if self.online_endpoint().is_none() {
                    self.complete_edit(id).await;
                }
                true
            }
            Err(_) => false,
        }
    }

    pub fn retry(self: &Arc<Self>, id: Option<&str>) -> CommandResult<()> {
        for file in self.index.files().or_internal()? {
            if id.is_some_and(|id| id != file.id) {
                continue;
            }
            if matches!(
                file.online.as_str(),
                online::FAILED | online::MISSING | online::WAITING | online::FULL
            ) {
                self.index
                    .set_online(&file.id, online::QUEUED)
                    .or_internal()?;
                self.index.set_backoff(&file.id, 0, 0).or_internal()?;
                self.emit_row(&file.id);
            }
        }
        if let Ok(mut rt) = self.online_rt.lock() {
            rt.full = false;
        }
        self.emit_status();
        self.wake.notify_one();
        Ok(())
    }

    pub fn copy_back(self: &Arc<Self>, id: &str) -> CommandResult<()> {
        let file = self
            .index
            .file(id)
            .or_internal()?
            .ok_or(CommandError::code("not_found"))?;
        if file.local != local::MISSING {
            return Ok(());
        }
        self.index.set_local(id, local::RESTORING).or_internal()?;
        self.emit_row(id);
        let engine = self.clone();
        let id = id.to_owned();
        self.rt.spawn(async move {
            let ok = engine.copy_online_to_local(&id).await;
            let _ = engine
                .index
                .set_local(&id, if ok { local::OK } else { local::MISSING });
            engine.clear_progress(&id);
            engine.emit_row(&id);
            engine.emit_status();
        });
        Ok(())
    }

    /// Streams a blob from the online node into the local node.
    pub(crate) async fn copy_online_to_local(self: &Arc<Self>, id: &str) -> bool {
        let Ok(Some(file)) = self.index.file(id) else {
            return false;
        };
        let (Some(sha), Some(size)) = (file.sha256.clone(), file.size) else {
            return false;
        };
        let (Some(from), Some(to), Ok(identity)) = (
            self.online_endpoint(),
            self.local_endpoint(),
            self.identity(),
        ) else {
            return false;
        };
        let engine = self.clone();
        let progress_id = id.to_owned();
        let body = match client::relay_body(&self.http, &from, &sha, size, move |sent| {
            let percent = 99u64.min(sent.saturating_mul(100) / size.max(1)) as u8;
            engine.set_progress(&progress_id, percent);
        })
        .await
        {
            Ok(body) => body,
            Err(_) => return false,
        };
        client::upload(&self.http, &to, identity.device.keys(), &sha, size, body)
            .await
            .is_ok()
    }

    pub async fn save_copy(
        self: &Arc<Self>,
        id: &str,
        path: Option<PathBuf>,
    ) -> CommandResult<SavedCopy> {
        let file = self
            .index
            .file(id)
            .or_internal()?
            .ok_or(CommandError::code("not_found"))?;
        let path = match path {
            Some(path) => path,
            None => {
                let host = self.host.clone();
                let name = file.name.clone();
                tokio::task::spawn_blocking(move || host.pick_save_path(&name))
                    .await
                    .ok()
                    .flatten()
                    .ok_or(CommandError::code("cancelled"))?
            }
        };
        let plain = self.decrypt_to_temp(&file).await?;
        let target = path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            // A copy, not a rename: the temp directory is private app data.
            std::fs::copy(plain.path(), &target)?;
            drop(plain);
            Ok(())
        })
        .await
        .map_err(|_| internal("save"))?
        .map_err(|_| CommandError::with_message("save_failed", "Couldn't save the copy."))?;
        Ok(SavedCopy {
            folder: path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        })
    }

    /// Fetches a kept envelope (local first, then online) and decrypts it into
    /// a private temp file, released only once every record authenticated.
    pub(crate) async fn decrypt_to_temp(
        self: &Arc<Self>,
        file: &FileRecord,
    ) -> CommandResult<tempfile::NamedTempFile> {
        let (Some(sha), Some(size)) = (file.sha256.clone(), file.size) else {
            return Err(CommandError::code("not_ready"));
        };
        let file_id = FileId::parse(&file.id).ok_or(internal("id"))?;
        let key = self
            .keychain()?
            .file_key(&file_id)
            .map_err(|e| keychain_error(&e))?
            .ok_or(CommandError::code("missing_key"))?;
        let envelope = tempfile::Builder::new()
            .prefix(".wildbloom-")
            .suffix(".part")
            .tempfile_in(&self.cfg.temp_dir)
            .map_err(|_| internal("temp"))?;
        let outbox = self.outbox_path(&file.id);
        let mut fetched = false;
        if outbox.is_file() {
            fetched = std::fs::copy(&outbox, envelope.path()).is_ok();
        }
        for node in [self.local_endpoint(), self.online_endpoint()]
            .into_iter()
            .flatten()
        {
            if fetched {
                break;
            }
            fetched = client::download_to_file(
                &self.http,
                &node,
                &sha,
                size,
                envelope.path(),
                &mut |_| {},
            )
            .await
            .is_ok();
        }
        if !fetched {
            return Err(CommandError::code("node_unreachable"));
        }
        let temp_dir = self.cfg.temp_dir.clone();
        let limits = envelope::drop_limits(DEFAULT_NODE_BLOB_LIMIT);
        tokio::task::spawn_blocking(move || {
            let result = envelope::decrypt_to_private_temp(
                &key,
                envelope.path(),
                limits,
                &temp_dir,
                &mut |_, _| ControlFlow::Continue(()),
            );
            drop(envelope);
            result
        })
        .await
        .map_err(|_| internal("decrypt"))?
        .map(|(_, plain)| plain)
        .map_err(|_| CommandError::code("unreadable"))
    }

    /// Remove in the window: deletes both copies, any shared copy and the
    /// key, and tells the other computers through the key list.  While the
    /// Wildbloom folder mirror is on, its file there goes to the Trash.
    pub async fn remove(self: &Arc<Self>, id: &str) -> CommandResult<()> {
        self.remove_row(id, RemoveHow::Window).await?;
        self.run_pending_deletes().await;
        Ok(())
    }

    /// Removes one row: its own copies (deletions a node cannot take now are
    /// queued against the node that holds the copy), any shared copy, the key
    /// and the row, with a tombstone written before the key goes.
    ///
    /// While the mirror is on, a removal in the window or from another
    /// computer first moves the row's unchanged file in the folder to the
    /// Trash (never deleting it).  A file changed here and not yet taken in
    /// is left alone and unlinked, so it is taken in as new and the change
    /// wins.  If the file cannot be moved, nothing is removed and the error
    /// says so (a remote removal is retried on the next pull).
    ///
    /// Online deletions go only to nodes where this computer's device key
    /// claims the copy (`online_copies`).  BUD-12 deletion is self-only: a
    /// node answers 403 to a delete of another computer's copy, which would
    /// be retried for ever while the approval is active.  The computer that
    /// put it there deletes its own claim when the tombstone reaches it.
    ///
    /// The caller runs the queued deletions.
    pub(crate) async fn remove_row(
        self: &Arc<Self>,
        id: &str,
        how: RemoveHow,
    ) -> CommandResult<()> {
        let mut file = self
            .index
            .file(id)
            .or_internal()?
            .ok_or(CommandError::code("not_found"))?;
        let _folder = if matches!(how, RemoveHow::Window | RemoveHow::Remote { .. })
            && file.watch_path.is_some()
            && file.local != local::NOT_KEPT
            && self.mirror_on()
        {
            let guard = self.folder_lock.lock().await;
            // The folder pass may have moved the link while this waited.
            file = self
                .index
                .file(id)
                .or_internal()?
                .ok_or(CommandError::code("not_found"))?;
            self.remove_folder_file(&file)?;
            Some(guard)
        } else {
            None
        };
        // An encryption still running for this row sees the flag and keeps
        // neither its key nor its envelope.
        if let Ok(mut removed) = self.removed_ids.lock() {
            removed.insert(id.to_owned());
        }
        self.cancel_share_session(id).await;
        // A remote removal keeps the tombstone's own time, so the key list's
        // content does not change here.
        let at = match how {
            RemoveHow::Remote { at } => at,
            RemoveHow::Window | RemoveHow::FromFolder | RemoveHow::Superseded => now(),
        };
        if let Some(sha) = &file.sha256 {
            self.index
                .queue_delete("local", sha, "device", 0)
                .or_internal()?;
            // Every node this computer put a copy on, including one used
            // before the online node was changed.
            for origin in self.index.online_copies(id).or_internal()? {
                self.index
                    .queue_delete(&origin, sha, "device", 0)
                    .or_internal()?;
            }
        }
        if let Some(share) = self.index.share(id).or_internal()?
            && matches!(
                share.state.as_str(),
                index::share::OPEN | index::share::SENT | index::share::STOP_PENDING
            )
        {
            self.index
                .queue_delete(&share.origin, &share.sha256, "device", 0)
                .or_internal()?;
            if let Some(share_id) = FileId::parse(&share.share_id) {
                let _ = self.keychain()?.remove_file_key(&share_id);
            }
        }
        if let Some(file_id) = FileId::parse(id) {
            // The tombstone is durable before the key goes, so no rebuilt key
            // list can bring the file back.
            self.index.add_tombstone(id, at).or_internal()?;
            self.keychain()?
                .remove_file_key(&file_id)
                .map_err(|e| keychain_error(&e))?;
            let mut keylist = self.keylist.lock().await;
            if let Some(list) = keylist.as_mut() {
                let _ = list.remove(&file_id, at);
            }
        }
        let _ = std::fs::remove_file(self.outbox_path(id));
        self.index.delete_file(id).or_internal()?;
        self.clear_progress(id);
        self.host.emit_removed(id);
        self.emit_status();
        drop(_folder);
        // A remote removal came from the key list; publishing it again would
        // only re-seal the same content.
        if !matches!(how, RemoveHow::Remote { .. }) {
            self.keysync_wake.notify_one();
        }
        Ok(())
    }

    /// The folder side of a removal in the window or from another computer.
    /// The caller holds the folder lock.
    fn remove_folder_file(&self, file: &FileRecord) -> CommandResult<()> {
        use super::folder::Stat;
        let Some(path) = file.watch_path.as_deref().map(PathBuf::from) else {
            return Ok(());
        };
        if !self.folder_available() {
            // Removed now, its file would be taken in again when the folder
            // is back.  A remote removal waits; the owner is told why.
            return Err(CommandError::with_message(
                "folder_unavailable",
                "Your Wildbloom folder can't be found, so files in it can't be removed now.",
            ));
        }
        let root = &self.cfg.watch_dir;
        let Some(rel) = super::folder::relative(root, &path) else {
            self.index.set_link(&file.id, None).or_internal()?;
            return Ok(());
        };
        match super::folder::stat_under(root, &rel) {
            Stat::Present(meta)
                if super::folder::matches(&meta, file.watch_size, file.watch_mtime) =>
            {
                if !self.move_to_trash(&rel) {
                    return Err(CommandError::with_message(
                        "trash_failed",
                        "Couldn't move the file in your Wildbloom folder to the Trash.",
                    ));
                }
                if let Some(parent) = path.parent() {
                    super::folder::sweep_empty(root, &[parent.to_path_buf()].into_iter().collect());
                }
            }
            // Changed here and not taken in yet: the change is kept and will
            // be taken in as a new file.  Unreadable or a link: left alone.
            Stat::Present(_) | Stat::Unknown => {
                self.index.set_link(&file.id, None).or_internal()?;
            }
            Stat::Missing => {}
        }
        Ok(())
    }

    /// Moves the folder file at `rel` to the Trash, or to the hidden
    /// fallback folder.  Never deletes it.
    pub(crate) fn move_to_trash(&self, rel: &[String]) -> bool {
        let (year, month, day) = super::status::ymd(now());
        let date = format!("{year:04}-{month:02}-{day:02}");
        let host = self.host.clone();
        super::folder::remove_to_trash(&self.cfg.watch_dir, rel, &date, &move |path| {
            host.trash(path)
        })
    }

    /// An edit is complete once its new version is safely kept (online, or
    /// locally when no online node is set): the version it replaces is then
    /// removed as superseded, which publishes its tombstone.
    pub(crate) async fn complete_edit(self: &Arc<Self>, id: &str) {
        let Ok(Some(file)) = self.index.file(id) else {
            return;
        };
        let Some(prev) = file.prev else {
            return;
        };
        if matches!(self.index.file(&prev), Ok(Some(_)))
            && self.remove_row(&prev, RemoveHow::Superseded).await.is_ok()
        {
            self.deletes_wake.notify_one();
        }
    }

    /// Sends every queued deletion that is due to the node it was queued for.
    pub(crate) async fn run_pending_deletes(self: &Arc<Self>) {
        let Ok(deletes) = self.index.pending_deletes() else {
            return;
        };
        let Ok(identity) = self.identity() else {
            return;
        };
        let now = now();
        for delete in deletes {
            if delete.not_before > now {
                continue;
            }
            let node = match delete.node.as_str() {
                "local" => self.local_endpoint(),
                origin => NodeEndpoint::parse(origin, self.cfg.allow_loopback_http).ok(),
            };
            let Some(node) = node else { continue };
            let recovery;
            let keys = match delete.signer.as_str() {
                "recovery" => {
                    recovery = identity.recovery.identity();
                    recovery.keys().clone()
                }
                _ => identity.device.keys().clone(),
            };
            match client::delete(&self.http, &node, &keys, &delete.sha256).await {
                Ok(()) => {
                    let _ = self.index.finish_delete(&delete);
                }
                // The approval for this node has ended: its claims moved to
                // the node's owner, and this key can never delete them.  Stop
                // retrying, and tell the owner a shared copy needs them.
                // Refused: only the node's own answer that this computer's
                // approval there has ended (its claims then belong to the
                // owner) stops the retries.  Any other refusal is retried.
                Err(NodeError::Unauthorised) if delete.node != "local" => {
                    let ended = matches!(
                        client::grant_status(&self.http, &node, identity.device.keys()).await,
                        Ok(Some(status)) if status.state != "active"
                    );
                    if ended {
                        let _ = self.index.finish_delete(&delete);
                        self.mark_owner_only(&delete);
                    }
                }
                Err(_) => {}
            }
        }
    }

    /// A shared copy this computer can no longer delete: its share record, or
    /// for a replaced copy the file the deletion was queued for, says so.
    fn mark_owner_only(&self, delete: &index::PendingDelete) {
        let mut marked = false;
        for share in self.index.shares().unwrap_or_default() {
            if share.sha256 == delete.sha256 && share.state != index::share::ENDED {
                let mut record = share.clone();
                record.state = index::share::OWNER_ONLY.into();
                record.ended_at = Some(now());
                let _ = self.index.put_share(&record);
                self.emit_row(&share.file_id);
                marked = true;
            }
        }
        if !marked
            && let Some(file_id) = &delete.file_id
            && self.index.file(file_id).ok().flatten().is_some()
        {
            let _ = self
                .index
                .add_stranded(file_id, &delete.sha256, &delete.node, now());
            self.emit_row(file_id);
        }
    }

    /// The recovery secret, for the key list and restore.
    pub(crate) fn recovery(&self) -> CommandResult<RecoverySecret> {
        Ok(self.identity()?.recovery.clone())
    }

    pub(crate) fn identity_after_restore(&self, identity: DropIdentity) {
        self.set_identity(identity);
    }
}

/// The local node's friend grant expiry for the Drop keys: 2100-01-01 UTC.
/// It is a constant because the node keys friend claims by a grant id built
/// from it; a grant id that changed (a new expiry, or a switch between owner
/// and friend tiers when Tor or a public URL is turned on or off) would leave
/// earlier local copies as unprotected guest claims the node may evict.
pub const LOCAL_FRIEND_GRANT_EXPIRY: u64 = 4_102_444_800;

/// The `wildbloomd` arguments that let the Drop device key and recovery
/// identity write to the local node: the same friend grant whatever the
/// transport, so their claims keep one tier and grant across restarts.  A key
/// equal to the configured owner is left as the owner.
pub fn local_node_trust_args(
    keys: &[String],
    owner: Option<&str>,
    quota_bytes: u64,
) -> Vec<String> {
    keys.iter()
        .filter(|key| owner != Some(key.as_str()))
        .flat_map(|key| {
            [
                "--friend-grant".to_owned(),
                format!("{key}:{quota_bytes}:{LOCAL_FRIEND_GRANT_EXPIRY}"),
            ]
        })
        .collect()
}

/// The frozen key list entry fields of a new row.
pub(crate) struct NewFields {
    pub path: String,
    pub prev: Option<String>,
    pub origin: String,
    pub entry_plain: String,
}

/// Why a row is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoveHow {
    /// The owner chose Remove in the window.
    Window,
    /// Its file was deleted from the Wildbloom folder (inferred by the
    /// folder pass).  There is nothing left in the folder to move.
    FromFolder,
    /// A newer version or an identical entry replaces it.  Its tombstone is
    /// new, so it is published.
    Superseded,
    /// Another computer removed it; `at` is the tombstone's own time.
    Remote { at: u64 },
}

pub(crate) fn device_error(error: &DeviceError) -> CommandError {
    match error {
        DeviceError::Keychain(e) => keychain_error(e),
        DeviceError::RestoreNeeded => {
            CommandError::with_message("restore_needed", error.to_string())
        }
        DeviceError::RecoveryKeyEncoding | DeviceError::NoRecoveryIdentity => {
            CommandError::code("bad_key")
        }
        other => internal(other.to_string()),
    }
}

fn refused(name: &str, reason: &'static str, limit: Option<u64>) -> Refused {
    Refused {
        name: name.to_owned(),
        reason,
        limit_bytes: limit,
    }
}

pub(crate) fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(port) => format!("{h}:{port}"),
                None => h.to_owned(),
            })
        })
        // Never echo input that is not an address back into the UI.
        .unwrap_or_else(|| "that address".to_owned())
}

/// `npub1…` for a 64-hex public key; the hex itself if it does not parse.
pub fn npub(hex: &str) -> String {
    use nostr::prelude::ToBech32 as _;
    nostr::prelude::PublicKey::from_hex(hex)
        .ok()
        .and_then(|pk| pk.to_bech32().ok())
        .unwrap_or_else(|| hex.to_owned())
}

pub(crate) fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    // `mode` applies only when the file is created; an existing file is
    // made private before anything is written to it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// A media type from the file name's extension, for the private metadata the
/// recipient's browser uses when saving.  Unknown types are left empty
/// (`application/octet-stream`).
pub(crate) fn guess_media_type(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "md" => "text/markdown",
        "json" => "application/json",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_local_trust_grant_is_one_constant_friend_grant() {
        let keys = vec!["aa".repeat(32), "bb".repeat(32)];
        let args = local_node_trust_args(&keys, None, 1000);
        assert_eq!(
            args,
            [
                "--friend-grant".to_owned(),
                format!("{}:1000:4102444800", "aa".repeat(32)),
                "--friend-grant".to_owned(),
                format!("{}:1000:4102444800", "bb".repeat(32)),
            ]
        );
        // Never --allow-pubkey, whatever the node's transport: the function
        // takes no mode, so toggling Tor or a public URL cannot change it.
        assert!(args.iter().all(|a| a != "--allow-pubkey"));
        assert_eq!(local_node_trust_args(&keys, None, 1000), args, "stable");
        // A key that is already the owner stays the owner.
        assert_eq!(local_node_trust_args(&keys, Some(&keys[0]), 1000).len(), 2);
        // 2100-01-01T00:00:00Z.
        assert_eq!(
            super::super::status::full_date(LOCAL_FRIEND_GRANT_EXPIRY),
            "1 January 2100"
        );
    }
}
