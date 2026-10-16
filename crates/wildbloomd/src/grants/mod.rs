//! Owner-authorised device grants and the owner-delegated claim lifecycle.
//!
//! The core has owner, friend, paid and guest tiers but no "delegated by an
//! owner" tier, so this shell composes one from public core APIs:
//!
//! * While a grant is active its device and recovery keys are core friend
//!   grants, so the byte ceiling, streaming limits and concurrency stay
//!   core-enforced.  The core grant never lapses on its own (a far-future
//!   sentinel); this module owns the real expiry.  That stops a node which was
//!   down across the expiry from having the core reap the claims at start-up.
//! * When a key's authority ends (expiry, revocation, or its owner leaving the
//!   configured owner set) every claim it holds is moved to an owner-tier
//!   claim for the issuing owner, and only then is the key removed from the
//!   core's trusted set.  The owner can list or delete those claims with
//!   ordinary BUD-12 requests, and refusal of further writes is core-enforced.
//! * Between the real expiry and that sweep, a gate in front of the core
//!   router refuses writes from ended keys.
//! * Each move is recorded.  If the same key is granted again, its moved
//!   claims are handed back (so a recovery identity can list its key list
//!   after a lost device was revoked), unless the owner deleted them first.
use crate::grants::event::{Action, Authorised, EventError, GrantTerms};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path as AxumPath, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::spawn_blocking;
use wildbloom_core::{
    AppState, ClaimSpec, FriendGrant, RetentionTier, Store, StoreError, store::UploadStart,
};

pub mod event;
pub mod issuer;
#[cfg(test)]
mod tests;

/// Core-side expiry of a delegated friend grant: never.  See the module docs.
pub const CORE_GRANT_SENTINEL: u64 = i64::MAX as u64;
pub const DATABASE_FILE: &str = "device-grants.sqlite3";
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const LIST_PAGE: usize = 100;
/// Bounds the claims one key can have collected in memory during a sweep.
const MAX_SWEEP_CLAIMS: usize = 1_000_000;

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    })
}

pub struct GrantsConfig {
    pub owners: Vec<String>,
    pub server_names: Vec<String>,
    /// Public origin with a trailing slash, used for exact NIP-98 URLs.
    pub origin: String,
    pub cli_friend_grants: Vec<FriendGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantRow {
    device: String,
    recovery: String,
    issuer: String,
    byte_limit: u64,
    until: u64,
    granted_at: u64,
    last_event_at: u64,
    revoked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    issuer: String,
    byte_limit: u64,
}

#[derive(Debug, Default)]
struct Snapshot {
    grants: BTreeMap<String, GrantRow>,
    /// Keys currently registered in the core as delegated friend grants.
    members: BTreeMap<String, Member>,
}

impl Snapshot {
    fn grant_active(&self, row: &GrantRow, owners: &BTreeSet<String>, now: u64) -> bool {
        row.revoked_at.is_none() && row.until > now && owners.contains(&row.issuer)
    }

    fn key_active(&self, key: &str, owners: &BTreeSet<String>, now: u64) -> bool {
        self.grants.values().any(|row| {
            (row.device == key || row.recovery == key) && self.grant_active(row, owners, now)
        })
    }

    fn knows(&self, key: &str) -> bool {
        self.members.contains_key(key)
            || self
                .grants
                .values()
                .any(|row| row.device == key || row.recovery == key)
    }

    /// The ceiling a key should carry in the core: the device's own grant, or
    /// for a recovery identity the largest active grant that names it.
    fn active_limit(&self, key: &str, owners: &BTreeSet<String>, now: u64) -> Option<u64> {
        self.grants
            .values()
            .filter(|row| {
                (row.device == key || row.recovery == key) && self.grant_active(row, owners, now)
            })
            .map(|row| row.byte_limit)
            .max()
    }
}

#[derive(Clone)]
pub struct Grants {
    inner: Arc<Inner>,
}

struct Inner {
    db: Mutex<Connection>,
    owners: BTreeSet<String>,
    server_names: Vec<String>,
    origin: String,
    cli_friend_grants: Vec<FriendGrant>,
    clock: Clock,
    snapshot: RwLock<Arc<Snapshot>>,
    /// Delegated writes hold a read guard for their whole request; a sweep
    /// takes the write guard so no delegated write is in flight while claims
    /// are copied and the key leaves the core's trusted set.
    sweep_lock: tokio::sync::RwLock<()>,
    /// Serialises grant, revoke and sweep decisions.
    updates: tokio::sync::Mutex<()>,
    app: OnceLock<AppState>,
}

#[derive(Debug, thiserror::Error)]
pub enum GrantsError {
    #[error("device grant database failed")]
    Database(#[from] rusqlite::Error),
    #[error("device grant state I/O failed")]
    Io(#[from] std::io::Error),
    #[error("device grant database has an unsupported schema version {0}")]
    Schema(i64),
    #[error(
        "a persisted device or recovery key is now also a configured owner or friend; remove the conflicting --allow-pubkey or --friend-grant"
    )]
    Conflict,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: &'static str,
}

impl ApiError {
    fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
    fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn unauthorised(message: &'static str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    fn forbidden(message: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }
    fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "device grant state is unavailable",
        )
    }
}

impl From<EventError> for ApiError {
    fn from(error: EventError) -> Self {
        match error {
            EventError::Invalid => Self::bad_request("invalid device grant event"),
            EventError::Unauthorised => Self::unauthorised("device grant event is not authorised"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response();
        no_store(&mut response);
        if let Ok(value) = HeaderValue::from_str(self.message) {
            response.headers_mut().insert("x-reason", value);
        }
        response
    }
}

fn no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GrantStatus {
    pub device: String,
    pub recovery: String,
    pub bytes: u64,
    pub until: u64,
    pub state: &'static str,
}

impl Grants {
    pub fn database_path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join(DATABASE_FILE)
    }

    pub fn open(data_dir: &Path, config: GrantsConfig, clock: Clock) -> Result<Self, GrantsError> {
        let path = Self::database_path(data_dir);
        create_private_file(&path)?;
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        initialise(&connection)?;
        let grants = Self {
            inner: Arc::new(Inner {
                db: Mutex::new(connection),
                owners: config.owners.into_iter().collect(),
                server_names: config.server_names,
                origin: config.origin,
                cli_friend_grants: config.cli_friend_grants,
                clock,
                snapshot: RwLock::new(Arc::new(Snapshot::default())),
                sweep_lock: tokio::sync::RwLock::new(()),
                updates: tokio::sync::Mutex::new(()),
                app: OnceLock::new(),
            }),
        };
        grants.reload()?;
        let snapshot = grants.snapshot();
        let cli_keys = grants
            .inner
            .cli_friend_grants
            .iter()
            .map(|grant| grant.pubkey.as_str())
            .collect::<BTreeSet<_>>();
        if snapshot
            .members
            .keys()
            .any(|key| grants.inner.owners.contains(key) || cli_keys.contains(key.as_str()))
        {
            return Err(GrantsError::Conflict);
        }
        Ok(grants)
    }

    /// CLI friend grants plus every delegated key the core must currently
    /// hold.  Supply this as `BlossomConfig::friend_grants`.
    pub fn core_friend_grants(&self) -> Vec<FriendGrant> {
        let snapshot = self.snapshot();
        self.inner
            .cli_friend_grants
            .iter()
            .cloned()
            .chain(snapshot.members.iter().map(|(key, member)| FriendGrant {
                pubkey: key.clone(),
                byte_limit: member.byte_limit,
                expires_at: CORE_GRANT_SENTINEL,
                grant_id: core_grant_id(key),
                issuer: Some(member.issuer.clone()),
            }))
            .collect()
    }

    /// Every delegated key this node has recorded, for services that must not
    /// treat them as public identities.
    pub fn known_keys(&self) -> Vec<String> {
        let snapshot = self.snapshot();
        let mut keys = snapshot.members.keys().cloned().collect::<BTreeSet<_>>();
        for row in snapshot.grants.values() {
            keys.insert(row.device.clone());
            keys.insert(row.recovery.clone());
        }
        keys.into_iter().collect()
    }

    /// Attach the running core.  Call once, before serving.
    pub fn attach(&self, state: AppState) {
        let _ = self.inner.app.set(state);
    }

    pub fn spawn_maintenance(&self) -> tokio::task::JoinHandle<()> {
        let grants = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(SWEEP_INTERVAL);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                if let Err(error) = grants.sweep_ended().await {
                    tracing::warn!(reason = %error, "device grant sweep will retry");
                }
                grants.prune_used_events();
            }
        })
    }

    /// Owner-signed grant, revocation and status routes.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/grants/v1", post(post_grant))
            .route("/grants/v1/{device}", get(get_grant).delete(delete_grant))
            .with_state(self.clone())
            .layer(cors(&[Method::GET, Method::POST, Method::DELETE]))
    }

    fn now(&self) -> u64 {
        (self.inner.clock)()
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        self.inner
            .snapshot
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn app(&self) -> Result<&AppState, ApiError> {
        self.inner.app.get().ok_or_else(ApiError::unavailable)
    }

    fn reload(&self) -> Result<(), GrantsError> {
        let next = {
            let db = self.inner.db.lock().map_err(|_| poisoned())?;
            read_snapshot(&db)?
        };
        if let Ok(mut guard) = self.inner.snapshot.write() {
            *guard = Arc::new(next);
        }
        Ok(())
    }

    pub fn is_active(&self, key: &str) -> bool {
        self.snapshot()
            .key_active(key, &self.inner.owners, self.now())
    }

    pub fn is_active_device(&self, key: &str) -> bool {
        let snapshot = self.snapshot();
        snapshot
            .grants
            .get(key)
            .is_some_and(|row| snapshot.grant_active(row, &self.inner.owners, self.now()))
    }

    /// Record a single-use event id; `false` means it was already used.
    pub(crate) fn consume_event(&self, event_id: &str, expires_at: u64) -> Result<bool, ApiError> {
        let db = self.inner.db.lock().map_err(|_| ApiError::unavailable())?;
        let inserted = db
            .execute(
                "INSERT OR IGNORE INTO used_events (event_id, expires_at) VALUES (?1, ?2)",
                params![event_id, as_i64(expires_at)?],
            )
            .map_err(|_| ApiError::unavailable())?;
        Ok(inserted == 1)
    }

    fn prune_used_events(&self) {
        let now = self.now();
        if let Ok(db) = self.inner.db.lock() {
            let _ = db.execute(
                "DELETE FROM used_events WHERE expires_at < ?1",
                [i64::try_from(now).unwrap_or(i64::MAX)],
            );
        }
    }

    async fn apply_grant(&self, body: &[u8]) -> Result<(StatusCode, GrantStatus), ApiError> {
        let _update = self.inner.updates.lock().await;
        let now = self.now();
        let authorised = event::verify(body, &self.inner.owners, &self.inner.server_names, now)?;
        let Action::Grant(terms) = authorised.action.clone() else {
            return Err(ApiError::bad_request("expected a grant event"));
        };
        let snapshot = self.snapshot();
        self.check_grant_conflicts(&snapshot, &authorised, &terms)?;
        let previous = snapshot.grants.get(&terms.device).cloned();
        let previous_members = [&terms.device, &terms.recovery]
            .into_iter()
            .map(|key| (key.clone(), snapshot.members.get(key).cloned()))
            .collect::<Vec<_>>();
        let row = GrantRow {
            device: terms.device.clone(),
            recovery: terms.recovery.clone(),
            issuer: authorised.owner.clone(),
            byte_limit: terms.byte_limit,
            until: terms.until,
            granted_at: authorised.created_at,
            last_event_at: authorised.created_at,
            revoked_at: None,
        };
        // The recovery identity's core ceiling is the largest active grant
        // that names it, including this one.
        let mut projected = snapshot.grants.clone();
        projected.insert(row.device.clone(), row.clone());
        let projected = Snapshot {
            grants: projected,
            members: BTreeMap::new(),
        };
        let recovery_limit = projected
            .active_limit(&terms.recovery, &self.inner.owners, now)
            .unwrap_or(terms.byte_limit);
        {
            let mut db = self.inner.db.lock().map_err(|_| ApiError::unavailable())?;
            let tx = db.transaction().map_err(|_| ApiError::unavailable())?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO used_events (event_id, expires_at) VALUES (?1, ?2)",
                    params![authorised.event_id, as_i64(authorised.expires_at)?],
                )
                .map_err(|_| ApiError::unavailable())?;
            if inserted != 1 {
                return Err(ApiError::conflict("device grant event was already used"));
            }
            write_grant(&tx, &row).map_err(|_| ApiError::unavailable())?;
            write_member(&tx, &terms.device, &authorised.owner, terms.byte_limit)
                .map_err(|_| ApiError::unavailable())?;
            write_member(&tx, &terms.recovery, &authorised.owner, recovery_limit)
                .map_err(|_| ApiError::unavailable())?;
            tx.commit().map_err(|_| ApiError::unavailable())?;
        }
        self.reload().map_err(|_| ApiError::unavailable())?;
        if let Err(error) = self.push_core_policy().await {
            tracing::error!(reason = %error, "core refused the device grant policy; reverting");
            self.revert(&terms.device, previous, previous_members)?;
            let _ = self.push_core_policy().await;
            return Err(ApiError::unavailable());
        }
        for (key, before) in [&terms.device, &terms.recovery].into_iter().zip([
            snapshot.members.get(&terms.device),
            snapshot.members.get(&terms.recovery),
        ]) {
            if before.is_none() {
                self.restore_moved_claims(key).await;
            }
        }
        // A replacement can leave an earlier recovery identity unreferenced.
        self.sweep_locked().await.ok();
        tracing::info!(device = %terms.device, "accepted an owner-signed device grant");
        let status = if previous.is_some() {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        };
        Ok((status, self.status_of(&row)))
    }

    fn check_grant_conflicts(
        &self,
        snapshot: &Snapshot,
        authorised: &Authorised,
        terms: &GrantTerms,
    ) -> Result<(), ApiError> {
        let cli = self
            .inner
            .cli_friend_grants
            .iter()
            .map(|grant| grant.pubkey.as_str())
            .collect::<BTreeSet<_>>();
        for key in [&terms.device, &terms.recovery] {
            if self.inner.owners.contains(key) || cli.contains(key.as_str()) {
                return Err(ApiError::conflict(
                    "a delegated key cannot be an owner or friend key",
                ));
            }
            if snapshot
                .members
                .get(key)
                .is_some_and(|member| member.issuer != authorised.owner)
            {
                return Err(ApiError::conflict(
                    "this key is still delegated by another owner",
                ));
            }
        }
        for row in snapshot.grants.values() {
            if row.device == terms.device {
                continue;
            }
            if row.recovery == terms.device || row.device == terms.recovery {
                return Err(ApiError::conflict(
                    "a key cannot be both a device and a recovery identity",
                ));
            }
            if row.recovery == terms.recovery && row.issuer != authorised.owner {
                return Err(ApiError::conflict(
                    "this recovery identity belongs to another owner",
                ));
            }
        }
        if let Some(row) = snapshot.grants.get(&terms.device)
            && authorised.created_at <= row.last_event_at
        {
            return Err(ApiError::conflict(
                "a newer event for this device was already accepted",
            ));
        }
        Ok(())
    }

    fn revert(
        &self,
        device: &str,
        previous: Option<GrantRow>,
        members: Vec<(String, Option<Member>)>,
    ) -> Result<(), ApiError> {
        {
            let mut db = self.inner.db.lock().map_err(|_| ApiError::unavailable())?;
            let tx = db.transaction().map_err(|_| ApiError::unavailable())?;
            match previous {
                Some(row) => write_grant(&tx, &row),
                None => tx
                    .execute("DELETE FROM device_grants WHERE device = ?1", [device])
                    .map(|_| ()),
            }
            .map_err(|_| ApiError::unavailable())?;
            for (key, member) in members {
                match member {
                    Some(member) => write_member(&tx, &key, &member.issuer, member.byte_limit),
                    None => tx
                        .execute("DELETE FROM core_members WHERE pubkey = ?1", [&key])
                        .map(|_| ()),
                }
                .map_err(|_| ApiError::unavailable())?;
            }
            tx.commit().map_err(|_| ApiError::unavailable())?;
        }
        self.reload().map_err(|_| ApiError::unavailable())
    }

    async fn apply_revoke(
        &self,
        device: &str,
        headers: &HeaderMap,
    ) -> Result<GrantStatus, ApiError> {
        let _update = self.inner.updates.lock().await;
        let now = self.now();
        let header = single_authorization(headers)?;
        let bytes = event::decode_header(header)
            .ok_or_else(|| ApiError::bad_request("invalid device grant event"))?;
        let authorised = event::verify(&bytes, &self.inner.owners, &self.inner.server_names, now)?;
        let Action::Revoke { device: named } = &authorised.action else {
            return Err(ApiError::bad_request("expected a revoke event"));
        };
        if named != device {
            return Err(ApiError::bad_request(
                "revoke event names a different device",
            ));
        }
        let snapshot = self.snapshot();
        let mut row = snapshot
            .grants
            .get(device)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "unknown device"))?;
        if authorised.created_at <= row.last_event_at {
            return Err(ApiError::conflict(
                "a newer event for this device was already accepted",
            ));
        }
        row.revoked_at = Some(now);
        row.last_event_at = authorised.created_at;
        {
            let mut db = self.inner.db.lock().map_err(|_| ApiError::unavailable())?;
            let tx = db.transaction().map_err(|_| ApiError::unavailable())?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO used_events (event_id, expires_at) VALUES (?1, ?2)",
                    params![authorised.event_id, as_i64(authorised.expires_at)?],
                )
                .map_err(|_| ApiError::unavailable())?;
            if inserted != 1 {
                return Err(ApiError::conflict("device grant event was already used"));
            }
            write_grant(&tx, &row).map_err(|_| ApiError::unavailable())?;
            tx.commit().map_err(|_| ApiError::unavailable())?;
        }
        self.reload().map_err(|_| ApiError::unavailable())?;
        tracing::info!(device = %device, "revoked a device grant");
        if let Err(error) = self.sweep_locked().await {
            tracing::warn!(reason = %error, "device grant sweep will retry");
        }
        Ok(self.status_of(&row))
    }

    fn status_of(&self, row: &GrantRow) -> GrantStatus {
        let now = self.now();
        let state = if row.revoked_at.is_some() {
            "revoked"
        } else if !self.inner.owners.contains(&row.issuer) {
            "withdrawn"
        } else if row.until <= now {
            "expired"
        } else {
            "active"
        };
        GrantStatus {
            device: row.device.clone(),
            recovery: row.recovery.clone(),
            bytes: row.byte_limit,
            until: row.until,
            state,
        }
    }

    async fn push_core_policy(&self) -> Result<(), wildbloom_core::BlossomConfigError> {
        let Some(app) = self.inner.app.get() else {
            return Ok(());
        };
        app.set_friend_grants(self.core_friend_grants()).await
    }

    /// Move ended keys' claims to their owner and remove them from the core.
    pub async fn sweep_ended(&self) -> Result<(), String> {
        let _update = self.inner.updates.lock().await;
        self.sweep_locked().await
    }

    async fn sweep_locked(&self) -> Result<(), String> {
        let now = self.now();
        let snapshot = self.snapshot();
        let ended = snapshot
            .members
            .iter()
            .filter(|(key, _)| !snapshot.key_active(key, &self.inner.owners, now))
            .map(|(key, member)| (key.clone(), member.clone()))
            .collect::<Vec<_>>();
        // Keep surviving recovery ceilings in step with the grants naming them.
        let mut adjusted = Vec::new();
        for (key, member) in &snapshot.members {
            if let Some(limit) = snapshot.active_limit(key, &self.inner.owners, now)
                && limit != member.byte_limit
            {
                adjusted.push((key.clone(), member.issuer.clone(), limit));
            }
        }
        if ended.is_empty() && adjusted.is_empty() {
            return Ok(());
        }
        let Some(app) = self.inner.app.get() else {
            return Ok(());
        };
        let _sweep = self.inner.sweep_lock.write().await;
        let mut transferred = Vec::new();
        for (key, member) in ended {
            let grants = self.clone();
            let store = app.store().clone();
            let moving = key.clone();
            let result =
                spawn_blocking(move || grants.transfer_blocking(&store, &moving, &member.issuer))
                    .await
                    .unwrap_or_else(|_| Err("claim move task failed".to_owned()));
            match result {
                Ok(count) => {
                    tracing::info!(
                        claims = count,
                        "moved an ended delegated key's claims to its owner"
                    );
                    transferred.push(key);
                }
                Err(error) => {
                    tracing::warn!(reason = %error, "could not copy delegated claims to the owner yet");
                }
            }
        }
        let previous = self.snapshot();
        {
            let mut db = self
                .inner
                .db
                .lock()
                .map_err(|_| "database lock".to_owned())?;
            let tx = db.transaction().map_err(|_| "database".to_owned())?;
            for key in &transferred {
                tx.execute("DELETE FROM core_members WHERE pubkey = ?1", [key])
                    .map_err(|_| "database".to_owned())?;
            }
            for (key, issuer, limit) in &adjusted {
                write_member(&tx, key, issuer, *limit).map_err(|_| "database".to_owned())?;
            }
            tx.commit().map_err(|_| "database".to_owned())?;
        }
        self.reload().map_err(|_| "database".to_owned())?;
        if let Err(error) = self.push_core_policy().await {
            // Put the members back so the next pass retries the removal; the
            // copies already made are idempotent.
            if let Ok(db) = self.inner.db.lock() {
                for key in &transferred {
                    if let Some(member) = previous.members.get(key) {
                        let _ = write_member(&db, key, &member.issuer, member.byte_limit);
                    }
                }
            }
            let _ = self.reload();
            return Err(format!("core refused the reduced delegated set: {error}"));
        }
        Ok(())
    }

    /// Give a re-activated key back the claims an earlier sweep moved to its
    /// owner.  The owner's copy is removed again unless the owner held that
    /// blob independently; if the owner deleted their copy in the meantime,
    /// that deletion wins and the key does not get the claim back.
    async fn restore_moved_claims(&self, key: &str) {
        let Ok(app) = self.app() else {
            return;
        };
        let Some(member) = self.snapshot().members.get(key).cloned() else {
            return;
        };
        let grants = self.clone();
        let store = app.store().clone();
        let key = key.to_owned();
        let result = spawn_blocking(move || grants.restore_blocking(&store, &key, &member)).await;
        match result {
            Ok(Ok((restored, kept))) if restored + kept > 0 => {
                tracing::info!(
                    restored,
                    kept,
                    "restored moved claims to a re-activated delegated key"
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(reason = %error, "could not restore moved delegated claims")
            }
            Err(_) => tracing::warn!("delegated claim restore task failed"),
        }
    }

    fn restore_blocking(
        &self,
        store: &Store,
        key: &str,
        member: &Member,
    ) -> Result<(u64, u64), String> {
        let records = {
            let db = self
                .inner
                .db
                .lock()
                .map_err(|_| "database lock".to_owned())?;
            read_moved(&db, key).map_err(|_| "database".to_owned())?
        };
        let (mut restored, mut kept) = (0_u64, 0_u64);
        for record in records {
            // Claims moved to a different owner stay with that owner.
            if record.owner != member.issuer {
                kept += 1;
                continue;
            }
            let spec = ClaimSpec {
                signer_pubkey: key.to_owned(),
                retention_tier: RetentionTier::Friend,
                declared_type: record.declared_type.clone(),
                grant_id: Some(core_grant_id(key)),
                claim_expires_at: Some(CORE_GRANT_SENTINEL),
                byte_limit: Some(member.byte_limit),
                class: record.class.clone(),
            };
            match store.begin_claimed_mirror(&record.hash, record.size, spec) {
                Ok(UploadStart::Existing(_)) => {}
                // The blob is gone (the reservation is cancelled on drop).
                Ok(UploadStart::Reserved(_))
                | Err(
                    StoreError::MissingBlob | StoreError::Tombstoned | StoreError::LengthMismatch,
                ) => {
                    self.forget_moved(key, &record.hash)?;
                    continue;
                }
                // Over the new ceiling: the owner keeps holding it.
                Err(StoreError::FriendLimitExceeded) => {
                    kept += 1;
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            }
            let others = {
                let db = self
                    .inner
                    .db
                    .lock()
                    .map_err(|_| "database lock".to_owned())?;
                count_moved_for(&db, &record.hash, &record.owner, key)
                    .map_err(|_| "database".to_owned())?
            };
            if !record.independent && others == 0 {
                match store.delete_claim(&record.hash, &record.owner) {
                    Ok(_) | Err(StoreError::MissingBlob) => {}
                    Err(StoreError::NotClaimant) => {
                        // The owner deleted their copy while holding it.
                        let _ = store.delete_claim(&record.hash, key);
                        self.forget_moved(key, &record.hash)?;
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            self.forget_moved(key, &record.hash)?;
            restored += 1;
        }
        Ok((restored, kept))
    }

    fn forget_moved(&self, key: &str, hash: &str) -> Result<(), String> {
        let db = self
            .inner
            .db
            .lock()
            .map_err(|_| "database lock".to_owned())?;
        db.execute(
            "DELETE FROM moved_claims WHERE pubkey = ?1 AND hash = ?2",
            params![key, hash],
        )
        .map(|_| ())
        .map_err(|_| "database".to_owned())
    }

    /// Move every claim `key` holds under its delegated grant to an
    /// owner-tier claim for `owner`, recording each move.
    fn transfer_blocking(&self, store: &Store, key: &str, owner: &str) -> Result<u64, String> {
        let claims =
            collect_claims(store, key, Some(&core_grant_id(key))).map_err(|e| e.to_string())?;
        if claims.is_empty() {
            return Ok(0);
        }
        let owner_hashes = collect_claims(store, owner, None)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|claim| claim.sha256)
            .collect::<BTreeSet<_>>();
        let mut moved = 0_u64;
        for claim in claims {
            let independent = owner_hashes.contains(&claim.sha256) && {
                let db = self
                    .inner
                    .db
                    .lock()
                    .map_err(|_| "database lock".to_owned())?;
                owner_holds_independently(&db, &claim.sha256, owner)
                    .map_err(|_| "database".to_owned())?
            };
            let declared = declared_type(&claim.content_type);
            let spec = ClaimSpec {
                signer_pubkey: owner.to_owned(),
                retention_tier: RetentionTier::Owner,
                declared_type: declared.clone(),
                grant_id: None,
                claim_expires_at: None,
                byte_limit: None,
                class: claim.class.clone(),
            };
            // A mirror-style claim never lifts an operator tombstone.
            match store.begin_claimed_mirror(&claim.sha256, claim.size, spec) {
                Ok(UploadStart::Existing(_)) => {}
                Ok(UploadStart::Reserved(_))
                | Err(
                    StoreError::MissingBlob | StoreError::Tombstoned | StoreError::LengthMismatch,
                ) => {
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            }
            // The owner claim now protects the blob, so removing the key's
            // claim can never orphan it.
            match store.delete_claim(&claim.sha256, key) {
                Ok(_) | Err(StoreError::NotClaimant | StoreError::MissingBlob) => {}
                Err(error) => return Err(error.to_string()),
            }
            let db = self
                .inner
                .db
                .lock()
                .map_err(|_| "database lock".to_owned())?;
            db.execute(
                "INSERT INTO moved_claims (pubkey, hash, owner, size, declared_type, class, independent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(pubkey, hash) DO UPDATE SET owner = excluded.owner,
                    size = excluded.size, declared_type = excluded.declared_type,
                    class = excluded.class, independent = excluded.independent",
                params![
                    key,
                    claim.sha256,
                    owner,
                    i64::try_from(claim.size).unwrap_or(i64::MAX),
                    declared,
                    claim.class,
                    independent,
                ],
            )
            .map_err(|_| "database".to_owned())?;
            moved += 1;
        }
        Ok(moved)
    }
}

/// Every claim of `key` (optionally only those under its delegated grant).
fn collect_claims(
    store: &Store,
    key: &str,
    grant_id: Option<&str>,
) -> Result<Vec<wildbloom_core::ClaimMetadata>, StoreError> {
    let mut claims = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = match grant_id {
            Some(grant_id) => {
                store.list_claims_for_grant(key, grant_id, cursor.as_deref(), LIST_PAGE)?
            }
            None => store.list_claims(key, cursor.as_deref(), LIST_PAGE)?,
        };
        let done = page.len() < LIST_PAGE;
        cursor = page.last().map(|claim| claim.sha256.clone());
        claims.extend(page);
        if done || claims.len() >= MAX_SWEEP_CLAIMS {
            return Ok(claims);
        }
    }
}

struct MovedClaim {
    hash: String,
    owner: String,
    size: u64,
    declared_type: String,
    class: Option<String>,
    independent: bool,
}

fn read_moved(connection: &Connection, key: &str) -> rusqlite::Result<Vec<MovedClaim>> {
    let mut statement = connection.prepare(
        "SELECT hash, owner, size, declared_type, class, independent
         FROM moved_claims WHERE pubkey = ?1 ORDER BY hash",
    )?;
    let rows = statement.query_map([key], |row| {
        Ok(MovedClaim {
            hash: row.get(0)?,
            owner: row.get(1)?,
            size: row_u64(row, 2)?,
            declared_type: row.get(3)?,
            class: row.get(4)?,
            independent: row.get(5)?,
        })
    })?;
    rows.collect()
}

fn count_moved_for(
    connection: &Connection,
    hash: &str,
    owner: &str,
    except: &str,
) -> rusqlite::Result<i64> {
    connection.query_row(
        "SELECT COUNT(*) FROM moved_claims WHERE hash = ?1 AND owner = ?2 AND pubkey != ?3",
        params![hash, owner, except],
        |row| row.get(0),
    )
}

/// The owner claims `hash` in its own right unless every existing owner
/// claim for it came from a recorded move.
fn owner_holds_independently(
    connection: &Connection,
    hash: &str,
    owner: &str,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT NOT EXISTS (SELECT 1 FROM moved_claims WHERE hash = ?1 AND owner = ?2)
             OR EXISTS (SELECT 1 FROM moved_claims WHERE hash = ?1 AND owner = ?2 AND independent)",
        params![hash, owner],
        |row| row.get(0),
    )
}

fn declared_type(value: &str) -> String {
    if value.is_empty() || value.len() > 255 {
        "application/octet-stream".to_owned()
    } else {
        value.to_owned()
    }
}

pub fn core_grant_id(key: &str) -> String {
    format!("wildbloom-delegated:{key}")
}

fn poisoned() -> GrantsError {
    GrantsError::Io(std::io::Error::other("device grant state lock poisoned"))
}

fn as_i64(value: u64) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::bad_request("integer out of range"))
}

fn create_private_file(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    wildbloom_private_state::check_file(&file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "device grant database requires mode 0600",
            ));
        }
    }
    Ok(())
}

fn initialise(connection: &Connection) -> Result<(), GrantsError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > 1 {
        return Err(GrantsError::Schema(version));
    }
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS device_grants (
            device TEXT PRIMARY KEY NOT NULL,
            recovery TEXT NOT NULL,
            issuer TEXT NOT NULL,
            byte_limit INTEGER NOT NULL CHECK (byte_limit > 0),
            until INTEGER NOT NULL,
            granted_at INTEGER NOT NULL,
            last_event_at INTEGER NOT NULL,
            revoked_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS core_members (
            pubkey TEXT PRIMARY KEY NOT NULL,
            issuer TEXT NOT NULL,
            byte_limit INTEGER NOT NULL CHECK (byte_limit > 0)
         );
         CREATE TABLE IF NOT EXISTS moved_claims (
            pubkey TEXT NOT NULL,
            hash TEXT NOT NULL,
            owner TEXT NOT NULL,
            size INTEGER NOT NULL CHECK (size >= 0),
            declared_type TEXT NOT NULL,
            class TEXT,
            independent INTEGER NOT NULL,
            PRIMARY KEY (pubkey, hash)
         );
         CREATE INDEX IF NOT EXISTS moved_claims_hash ON moved_claims(hash, owner);
         CREATE TABLE IF NOT EXISTS used_events (
            event_id TEXT PRIMARY KEY NOT NULL,
            expires_at INTEGER NOT NULL
         );
         PRAGMA user_version = 1;
         COMMIT;",
    )?;
    Ok(())
}

fn read_snapshot(connection: &Connection) -> rusqlite::Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    let mut statement = connection.prepare(
        "SELECT device, recovery, issuer, byte_limit, until, granted_at, last_event_at, revoked_at
         FROM device_grants",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(GrantRow {
            device: row.get(0)?,
            recovery: row.get(1)?,
            issuer: row.get(2)?,
            byte_limit: row_u64(row, 3)?,
            until: row_u64(row, 4)?,
            granted_at: row_u64(row, 5)?,
            last_event_at: row_u64(row, 6)?,
            revoked_at: row
                .get::<_, Option<i64>>(7)?
                .map(|value| u64::try_from(value).unwrap_or(0)),
        })
    })?;
    for row in rows {
        let row = row?;
        snapshot.grants.insert(row.device.clone(), row);
    }
    let mut statement =
        connection.prepare("SELECT pubkey, issuer, byte_limit FROM core_members")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            Member {
                issuer: row.get(1)?,
                byte_limit: row_u64(row, 2)?,
            },
        ))
    })?;
    for row in rows {
        let (key, member) = row?;
        snapshot.members.insert(key, member);
    }
    Ok(snapshot)
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn write_grant(connection: &Connection, row: &GrantRow) -> rusqlite::Result<()> {
    let int = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    connection.execute(
        "INSERT INTO device_grants
            (device, recovery, issuer, byte_limit, until, granted_at, last_event_at, revoked_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(device) DO UPDATE SET
            recovery = excluded.recovery, issuer = excluded.issuer,
            byte_limit = excluded.byte_limit, until = excluded.until,
            granted_at = excluded.granted_at, last_event_at = excluded.last_event_at,
            revoked_at = excluded.revoked_at",
        params![
            row.device,
            row.recovery,
            row.issuer,
            int(row.byte_limit),
            int(row.until),
            int(row.granted_at),
            int(row.last_event_at),
            row.revoked_at.map(int),
        ],
    )?;
    Ok(())
}

fn write_member(
    connection: &Connection,
    key: &str,
    issuer: &str,
    byte_limit: u64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO core_members (pubkey, issuer, byte_limit) VALUES (?1, ?2, ?3)
         ON CONFLICT(pubkey) DO UPDATE SET issuer = excluded.issuer, byte_limit = excluded.byte_limit",
        params![key, issuer, i64::try_from(byte_limit).unwrap_or(i64::MAX)],
    )?;
    Ok(())
}

fn single_authorization(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or_else(|| ApiError::unauthorised("missing authorisation"))?;
    if values.next().is_some() {
        return Err(ApiError::bad_request("duplicate authorisation headers"));
    }
    value
        .to_str()
        .map_err(|_| ApiError::bad_request("invalid authorisation header"))
}

pub(crate) fn cors(methods: &[Method]) -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(methods.to_vec())
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}

async fn post_grant(State(grants): State<Grants>, request: Request<Body>) -> Response {
    let result = async {
        if request.uri().query().is_some() {
            return Err(ApiError::bad_request("queries are not accepted"));
        }
        let body = to_bytes(request.into_body(), event::MAX_EVENT_BYTES)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "event is too large"))?;
        grants.apply_grant(&body).await
    }
    .await;
    match result {
        Ok((status, body)) => {
            let mut response = (status, Json(body)).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn delete_grant(
    State(grants): State<Grants>,
    AxumPath(device): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if !event::is_canonical_key(&device) {
        return ApiError::bad_request("invalid device public key").into_response();
    }
    match grants.apply_revoke(&device, &headers).await {
        Ok(status) => {
            let mut response = Json(status).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn get_grant(
    State(grants): State<Grants>,
    AxumPath(device): AxumPath<String>,
    request: Request<Body>,
) -> Response {
    let result = (|| {
        if !event::is_canonical_key(&device) {
            return Err(ApiError::bad_request("invalid device public key"));
        }
        if request.uri().query().is_some() {
            return Err(ApiError::bad_request("queries are not accepted"));
        }
        let header = single_authorization(request.headers())?;
        let principal = wildbloom_checkout::authenticate(
            header,
            &format!("{}grants/v1/{device}", grants.inner.origin),
            "GET",
            b"",
            grants.now(),
        )
        .map_err(|_| ApiError::unauthorised("status request is not authorised"))?;
        let snapshot = grants.snapshot();
        let row = snapshot.grants.get(&device);
        let requester = principal.pubkey();
        let allowed = grants.inner.owners.contains(requester)
            || row.is_some_and(|row| row.device == requester || row.recovery == requester);
        if !allowed {
            return Err(ApiError::forbidden("status request is not authorised"));
        }
        let row = row.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "unknown device"))?;
        Ok(grants.status_of(row))
    })();
    match result {
        Ok(status) => {
            let mut response = Json(status).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

fn is_core_write(method: &Method, path: &str) -> bool {
    match *method {
        Method::PUT => path == "/upload" || path == "/mirror",
        Method::HEAD => path == "/upload",
        Method::DELETE => true,
        _ => false,
    }
}

/// Layer for the core Blossom router: refuses writes from a delegated key
/// whose grant has ended, and holds the sweep read guard for active ones.
pub async fn gate(State(grants): State<Grants>, request: Request, next: Next) -> Response {
    if !is_core_write(request.method(), request.uri().path()) {
        return next.run(request).await;
    }
    let Some(signer) = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(event::signer_of_header)
    else {
        // Undecodable or unsigned: the core applies the same checks and refuses.
        return next.run(request).await;
    };
    if !grants.snapshot().knows(&signer) {
        return next.run(request).await;
    }
    let _guard = grants.inner.sweep_lock.read().await;
    if !grants.is_active(&signer) {
        return ApiError::forbidden("the delegated storage grant has ended").into_response();
    }
    next.run(request).await
}

/// Stops background maintenance when dropped.
pub struct Maintenance(pub tokio::task::JoinHandle<()>);

impl Drop for Maintenance {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Convenience used by the binary: does a database exist for this node?
pub fn has_database(data_dir: &Path) -> bool {
    Grants::database_path(data_dir).exists()
}

impl std::fmt::Debug for Grants {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Grants")
    }
}
