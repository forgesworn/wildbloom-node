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
/// not publish the configured one.
pub const DEFAULT_NODE_BLOB_LIMIT: u64 = 1024 * 1024 * 1024;
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
    pub const WATCH_ENABLED: &str = "watch_enabled";
    pub const LAST_CHECK: &str = "last_copy_check";
    /// A sealed key list has not reached every node it should be on.
    pub const KEY_LIST_PENDING: &str = "key_list_pending";
    /// The key list could not be opened or sealed; shown in the status line.
    pub const KEY_LIST_FAILED: &str = "key_list_failed";
    pub const LOCAL_FRIEND_EXPIRY: &str = "local_friend_expiry";
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
        });
        let _ = engine.keychain();
        Ok(engine)
    }

    /// Starts the background workers.  Safe to call once.
    pub fn start(self: &Arc<Self>) {
        // Rows left mid-step by a previous run.
        if let Ok(files) = self.index.files() {
            for file in files {
                if file.local == local::ENCRYPTING {
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

    /// The fixed expiry of the local node's friend grant for the Drop keys
    /// (ten years from first use), so its grant identity never changes.
    pub fn local_friend_expiry(&self) -> u64 {
        if let Ok(Some(expiry)) = self.index.get_u64(kv::LOCAL_FRIEND_EXPIRY) {
            return expiry;
        }
        let expiry = now() + 10 * 366 * 86_400;
        let _ = self.index.set_u64(kv::LOCAL_FRIEND_EXPIRY, expiry);
        expiry
    }

    /// The local node is listening: run pending uploads and the key list now.
    pub fn local_node_ready(&self) {
        self.wake.notify_one();
        if self.index.get_bool(kv::KEY_LIST_PENDING).unwrap_or(false) {
            self.keysync_wake.notify_one();
        }
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
        envelope::drop_limits(DEFAULT_NODE_BLOB_LIMIT).max_source_bytes()
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
                enabled: self.index.get_bool(kv::WATCH_ENABLED).unwrap_or(false),
                path: self.cfg.watch_display.clone(),
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
            in_watch_folder: file.watch_path.is_some(),
        }
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
            if file.local != local::UNREADABLE {
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

    pub fn set_watch_folder(self: &Arc<Self>, enabled: bool) -> CommandResult<()> {
        if enabled {
            std::fs::create_dir_all(&self.cfg.watch_dir).map_err(|_| {
                CommandError::with_message("watch_folder", "Couldn't create the Wildbloom folder.")
            })?;
        }
        self.index
            .set_bool(kv::WATCH_ENABLED, enabled)
            .or_internal()?;
        self.emit_status();
        self.watch_wake.notify_one();
        Ok(())
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
        self.add_paths(paths, None).await
    }

    /// Classifies, de-duplicates and queues each path.  `watched` marks a file
    /// taken in from the watched folder, with its size and mtime.
    pub async fn add_paths(
        self: &Arc<Self>,
        paths: Vec<PathBuf>,
        watched: Option<(u64, i64)>,
    ) -> CommandResult<AddResult> {
        let mut result = AddResult::default();
        if paths.is_empty() {
            return Ok(result);
        }
        let _setup = self.setup_lock.read().await;
        self.identity()?;
        let limit = self.drop_max_bytes();
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
            let id = FileId::random()
                .map_err(|_| internal("random"))?
                .to_string();
            let record = FileRecord {
                id: id.clone(),
                name: name.clone(),
                media_type: guess_media_type(&name).to_owned(),
                bytes: meta.len(),
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
                watch_path: watched.map(|_| path.to_string_lossy().into_owned()),
                watch_size: watched.map(|(size, _)| size),
                watch_mtime: watched.map(|(_, mtime)| mtime),
            };
            self.index.insert_file(&record).or_internal()?;
            self.set_progress(&id, 0);
            result.added.push(id.clone());
            let engine = self.clone();
            self.rt
                .spawn(async move { engine.encrypt_and_keep(id, path).await });
        }
        self.emit_status();
        Ok(result)
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

    /// Deletes both copies, any shared copy and the key.  The original file is
    /// never touched.  Deletions a node cannot take now are queued against
    /// the node that holds the copy.
    pub async fn remove(self: &Arc<Self>, id: &str) -> CommandResult<()> {
        let file = self
            .index
            .file(id)
            .or_internal()?
            .ok_or(CommandError::code("not_found"))?;
        // An encryption still running for this row sees the flag and keeps
        // neither its key nor its envelope.
        if let Ok(mut removed) = self.removed_ids.lock() {
            removed.insert(id.to_owned());
        }
        self.cancel_share_session(id).await;
        let at = now();
        if let Some(sha) = &file.sha256 {
            self.index
                .queue_delete("local", sha, "device", 0)
                .or_internal()?;
            if file.online != online::NONE
                && let Some(online) = self.online_endpoint()
            {
                self.index
                    .queue_delete(online.origin(), sha, "device", 0)
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
        self.keysync_wake.notify_one();
        self.run_pending_deletes().await;
        Ok(())
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
                Err(NodeError::Unauthorised) if delete.node != "local" => {
                    let current = self
                        .online_endpoint()
                        .is_some_and(|online| online.origin() == delete.node);
                    if current && self.approval_active() {
                        continue;
                    }
                    let _ = self.index.finish_delete(&delete);
                    self.mark_owner_only(&delete.sha256);
                }
                Err(_) => {}
            }
        }
    }

    /// A shared copy this computer can no longer delete.
    fn mark_owner_only(&self, sha256: &str) {
        for share in self.index.shares().unwrap_or_default() {
            if share.sha256 == sha256 && share.state != index::share::ENDED {
                let mut record = share.clone();
                record.state = index::share::OWNER_ONLY.into();
                record.ended_at = Some(now());
                let _ = self.index.put_share(&record);
                self.emit_row(&share.file_id);
            }
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
