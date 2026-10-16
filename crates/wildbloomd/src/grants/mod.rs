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
//! * A gate in front of the core router refuses every non-read request from a
//!   delegated key whose grant has ended, the moment it ends.
//! * The maintenance sweep then waits (briefly, per key) for that key's
//!   in-flight writes, moves its friend claims to owner-tier claims for the
//!   issuing owner, records each move, and only then removes the key from the
//!   core's trusted set.  Refusal is then core-enforced too.
//! * While a key is active again under the same owner, each sweep hands its
//!   recorded moves back beside the owner's claim.
//! * At start-up, claims of delegated keys that an older binary demoted to
//!   guest are re-adopted.
use crate::grants::event::{Action, Authorised, EventError, GrantTerms};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path as AxumPath, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use db::{GrantRow, Member, Rows};
use futures_util::StreamExt;
use rusqlite::Connection;
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::Notify, task::spawn_blocking, time::Instant};
use wildbloom_core::{AppState, FriendGrant};

mod claims;
mod db;
pub mod event;
pub mod issuer;
#[cfg(test)]
mod tests;

/// Core-side expiry of a delegated friend grant: never.  See the module docs.
pub const CORE_GRANT_SENTINEL: u64 = i64::MAX as u64;
pub const DATABASE_FILE: &str = "device-grants.sqlite3";
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// Longest a sweep waits for one pass's ended keys to finish in-flight writes;
/// a key still busy is retried on the next pass.
const IN_FLIGHT_WAIT: Duration = Duration::from_secs(5);
/// A delegated write body must keep arriving and must finish in bounded time.
pub const WRITE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const WRITE_TOTAL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

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
    /// Keys that may never be delegated, such as the service announcement key.
    pub reserved_keys: Vec<String>,
}

type Snapshot = Rows;

impl Rows {
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

    fn last_event_at(&self, device: &str) -> Option<u64> {
        let row = self.grants.get(device).map(|row| row.last_event_at);
        let marker = self.markers.get(device).copied();
        row.max(marker)
    }
}

#[derive(Clone)]
pub struct Grants {
    inner: Arc<Inner>,
}

struct Inner {
    db: Mutex<Connection>,
    owners: BTreeSet<String>,
    reserved: BTreeSet<String>,
    server_names: Vec<String>,
    origin: String,
    cli_friend_grants: Vec<FriendGrant>,
    clock: Clock,
    snapshot: RwLock<Arc<Snapshot>>,
    /// In-flight write count per delegated key, for the sweep to wait on.
    in_flight: Mutex<HashMap<String, usize>>,
    in_flight_changed: Notify,
    /// Wakes maintenance after a grant or revocation is committed.
    wake: Notify,
    /// Serialises grant, revoke and sweep state changes (never held while
    /// verifying signatures or streaming a body).
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
        "a persisted device or recovery key is now also a configured owner, friend or service key; remove the conflicting configuration"
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    pub state: &'static str,
}

/// Decrements a key's in-flight count when a delegated write finishes.
struct InFlight {
    grants: Grants,
    key: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.grants.inner.in_flight.lock()
            && let Some(count) = counts.get_mut(&self.key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.key);
            }
        }
        self.grants.inner.in_flight_changed.notify_waiters();
    }
}

fn db_error<E>(_: E) -> String {
    "device grant database".to_owned()
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
        let version = db::initialise(&connection)?;
        if version != 1 {
            return Err(GrantsError::Schema(version));
        }
        let grants = Self {
            inner: Arc::new(Inner {
                db: Mutex::new(connection),
                owners: config.owners.into_iter().collect(),
                reserved: config.reserved_keys.into_iter().collect(),
                server_names: config.server_names,
                origin: config.origin,
                cli_friend_grants: config.cli_friend_grants,
                clock,
                snapshot: RwLock::new(Arc::new(Snapshot::default())),
                in_flight: Mutex::new(HashMap::new()),
                in_flight_changed: Notify::new(),
                wake: Notify::new(),
                updates: tokio::sync::Mutex::new(()),
                app: OnceLock::new(),
            }),
        };
        grants.reload()?;
        // Any key this node ever delegated stays subject to the gate, so it
        // cannot also be configured as an owner, friend or service key.
        let cli_keys = grants.cli_keys();
        if grants.known_keys().iter().any(|key| {
            grants.inner.owners.contains(key)
                || cli_keys.contains(key)
                || grants.inner.reserved.contains(key)
        }) {
            return Err(GrantsError::Conflict);
        }
        Ok(grants)
    }

    fn cli_keys(&self) -> BTreeSet<String> {
        self.inner
            .cli_friend_grants
            .iter()
            .map(|grant| grant.pubkey.clone())
            .collect()
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

    /// Every delegated key this node has recorded.
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

    /// Re-adopt demoted delegated claims, then run one sweep.
    pub async fn startup(&self) -> Result<(), String> {
        let _update = self.inner.updates.lock().await;
        let Some(app) = self.inner.app.get() else {
            return Ok(());
        };
        let snapshot = self.snapshot();
        for (key, member) in &snapshot.members {
            let store = app.store().clone();
            let (key, member) = (key.clone(), member.clone());
            let result =
                spawn_blocking(move || claims::adopt(&store, &key, &member, &core_grant_id(&key)))
                    .await
                    .unwrap_or_else(|_| Err("claim adoption task failed".to_owned()));
            match result {
                Ok((0, 0)) => {}
                Ok((adopted, refused)) => tracing::warn!(
                    adopted,
                    refused,
                    "re-adopted delegated claims that an earlier binary had demoted"
                ),
                Err(error) => {
                    tracing::warn!(reason = %error, "could not re-adopt delegated claims")
                }
            }
        }
        self.sweep_locked().await
    }

    pub fn spawn_maintenance(&self) -> tokio::task::JoinHandle<()> {
        let grants = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(SWEEP_INTERVAL);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = timer.tick() => {}
                    () = grants.inner.wake.notified() => {}
                }
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

    fn reload(&self) -> Result<(), GrantsError> {
        let next = {
            let db = self.inner.db.lock().map_err(|_| poisoned())?;
            db::read_rows(&db)?
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
        db::consume_event(&db, event_id, expires_at).map_err(|_| ApiError::unavailable())
    }

    fn prune_used_events(&self) {
        let now = self.now();
        if let Ok(db) = self.inner.db.lock() {
            let _ = db::prune_used_events(&db, now);
        }
    }

    /// Count a delegated write as in flight if its key is active.  The count
    /// is taken before the check, so a sweep that sees zero in flight after a
    /// key ended cannot race a write that saw the key active.
    fn begin_write(&self, key: &str) -> Option<InFlight> {
        if let Ok(mut counts) = self.inner.in_flight.lock() {
            *counts.entry(key.to_owned()).or_default() += 1;
        }
        let flight = InFlight {
            grants: self.clone(),
            key: key.to_owned(),
        };
        self.is_active(key).then_some(flight)
    }

    fn in_flight(&self, key: &str) -> usize {
        self.inner
            .in_flight
            .lock()
            .map(|counts| counts.get(key).copied().unwrap_or(0))
            .unwrap_or(usize::MAX)
    }

    async fn wait_idle(&self, key: &str, deadline: Instant) -> bool {
        loop {
            let notified = self.inner.in_flight_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight(key) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.in_flight(key) == 0;
            }
        }
    }

    async fn apply_grant(&self, body: &[u8]) -> Result<(StatusCode, GrantStatus), ApiError> {
        // Signature and structure first, outside the state lock.
        let now = self.now();
        let authorised = event::verify(body, &self.inner.owners, &self.inner.server_names, now)?;
        let Action::Grant(terms) = authorised.action.clone() else {
            return Err(ApiError::bad_request("expected a grant event"));
        };
        let _update = self.inner.updates.lock().await;
        let now = self.now();
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
        let mut projected = Snapshot {
            grants: snapshot.grants.clone(),
            ..Snapshot::default()
        };
        projected.grants.insert(row.device.clone(), row.clone());
        let recovery_limit = projected
            .active_limit(&terms.recovery, &self.inner.owners, now)
            .unwrap_or(terms.byte_limit);
        {
            let mut db = self.inner.db.lock().map_err(|_| ApiError::unavailable())?;
            let tx = db.transaction().map_err(|_| ApiError::unavailable())?;
            if !db::consume_event(&tx, &authorised.event_id, authorised.expires_at)
                .map_err(|_| ApiError::unavailable())?
            {
                return Err(ApiError::conflict("device grant event was already used"));
            }
            db::write_grant(&tx, &row).map_err(|_| ApiError::unavailable())?;
            db::write_member(&tx, &terms.device, &authorised.owner, terms.byte_limit)
                .map_err(|_| ApiError::unavailable())?;
            db::write_member(&tx, &terms.recovery, &authorised.owner, recovery_limit)
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
        // Restoring moved claims and sweeping a replaced recovery identity
        // happen in maintenance, not on this request.
        self.inner.wake.notify_one();
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
        let cli = self.cli_keys();
        for key in [&terms.device, &terms.recovery] {
            if self.inner.owners.contains(key)
                || cli.contains(key)
                || self.inner.reserved.contains(key)
            {
                return Err(ApiError::conflict(
                    "a delegated key cannot be an owner, friend or service key",
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
        if snapshot
            .last_event_at(&terms.device)
            .is_some_and(|last| authorised.created_at <= last)
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
                Some(row) => db::write_grant(&tx, &row),
                None => db::delete_grant(&tx, device),
            }
            .map_err(|_| ApiError::unavailable())?;
            for (key, member) in members {
                match member {
                    Some(member) => db::write_member(&tx, &key, &member.issuer, member.byte_limit),
                    None => db::delete_member(&tx, &key),
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
        let _update = self.inner.updates.lock().await;
        let now = self.now();
        let snapshot = self.snapshot();
        if snapshot
            .last_event_at(device)
            .is_some_and(|last| authorised.created_at <= last)
        {
            return Err(ApiError::conflict(
                "a newer event for this device was already accepted",
            ));
        }
        let row = snapshot.grants.get(device).cloned().map(|mut row| {
            row.revoked_at = Some(now);
            row.last_event_at = authorised.created_at;
            row
        });
        {
            let mut db = self.inner.db.lock().map_err(|_| ApiError::unavailable())?;
            let tx = db.transaction().map_err(|_| ApiError::unavailable())?;
            if !db::consume_event(&tx, &authorised.event_id, authorised.expires_at)
                .map_err(|_| ApiError::unavailable())?
            {
                return Err(ApiError::conflict("device grant event was already used"));
            }
            match &row {
                Some(row) => db::write_grant(&tx, row),
                // Pre-emptive revocation: an older grant posted later must not land.
                None => db::write_marker(&tx, device, authorised.created_at),
            }
            .map_err(|_| ApiError::unavailable())?;
            tx.commit().map_err(|_| ApiError::unavailable())?;
        }
        self.reload().map_err(|_| ApiError::unavailable())?;
        // The gate refuses the key from here on; the claim move runs in
        // maintenance so a slow in-flight upload cannot delay this reply.
        self.inner.wake.notify_one();
        tracing::info!(device = %device, "revoked a device grant");
        Ok(match row {
            Some(row) => self.status_of(&row),
            None => GrantStatus {
                device: device.to_owned(),
                recovery: None,
                bytes: None,
                until: None,
                state: "revoked",
            },
        })
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
            recovery: Some(row.recovery.clone()),
            bytes: Some(row.byte_limit),
            until: Some(row.until),
            state,
        }
    }

    async fn push_core_policy(&self) -> Result<(), wildbloom_core::BlossomConfigError> {
        let Some(app) = self.inner.app.get() else {
            return Ok(());
        };
        app.set_friend_grants(self.core_friend_grants()).await
    }

    /// One maintenance pass: hand back moved claims to active keys, keep
    /// recovery ceilings current, and move ended keys' claims to their owner.
    pub async fn sweep_ended(&self) -> Result<(), String> {
        let _update = self.inner.updates.lock().await;
        self.sweep_locked().await
    }

    async fn sweep_locked(&self) -> Result<(), String> {
        let Some(app) = self.inner.app.get() else {
            return Ok(());
        };
        let now = self.now();
        let snapshot = self.snapshot();

        // Retry restores every pass: this also covers a crash after a grant
        // was committed and claims over a ceiling that has since grown.
        let moved_keys = {
            let db = self.inner.db.lock().map_err(db_error)?;
            db::moved_keys(&db).map_err(db_error)?
        };
        for key in moved_keys {
            let Some(member) = snapshot.members.get(&key).cloned() else {
                continue;
            };
            if !snapshot.key_active(&key, &self.inner.owners, now) {
                continue;
            }
            let grants = self.clone();
            let store = app.store().clone();
            let result = spawn_blocking(move || {
                claims::restore(
                    &store,
                    &grants.inner.db,
                    &key,
                    &member,
                    &core_grant_id(&key),
                )
            })
            .await
            .unwrap_or_else(|_| Err("claim restore task failed".to_owned()));
            match result {
                Ok((restored, _)) if restored > 0 => {
                    tracing::info!(restored, "handed moved claims back to a delegated key");
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(reason = %error, "could not hand moved claims back"),
            }
        }

        let mut adjusted = Vec::new();
        for (key, member) in &snapshot.members {
            if let Some(limit) = snapshot.active_limit(key, &self.inner.owners, now)
                && limit != member.byte_limit
            {
                adjusted.push((key.clone(), member.issuer.clone(), limit));
            }
        }
        let ended = snapshot
            .members
            .iter()
            .filter(|(key, _)| !snapshot.key_active(key, &self.inner.owners, now))
            .map(|(key, member)| (key.clone(), member.clone()))
            .collect::<Vec<_>>();
        let deadline = Instant::now() + IN_FLIGHT_WAIT;
        let mut transferred = Vec::new();
        for (key, member) in ended {
            if !self.wait_idle(&key, deadline).await {
                tracing::info!(
                    "an ended delegated key still has a write in flight; retrying later"
                );
                continue;
            }
            let grants = self.clone();
            let store = app.store().clone();
            let moving = key.clone();
            let result = spawn_blocking(move || {
                claims::transfer(
                    &store,
                    &grants.inner.db,
                    &moving,
                    &member.issuer,
                    &core_grant_id(&moving),
                )
            })
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
                    tracing::warn!(reason = %error, "could not move delegated claims to the owner yet");
                }
            }
        }
        if transferred.is_empty() && adjusted.is_empty() {
            return Ok(());
        }
        {
            let mut db = self.inner.db.lock().map_err(db_error)?;
            let tx = db.transaction().map_err(db_error)?;
            for key in &transferred {
                db::delete_member(&tx, key).map_err(db_error)?;
            }
            for (key, issuer, limit) in &adjusted {
                db::write_member(&tx, key, issuer, *limit).map_err(db_error)?;
            }
            tx.commit().map_err(db_error)?;
        }
        self.reload().map_err(db_error)?;
        if let Err(error) = self.push_core_policy().await {
            // Put the members back so the next pass retries; moves already
            // made are recorded and idempotent.
            if let Ok(db) = self.inner.db.lock() {
                for key in &transferred {
                    if let Some(member) = snapshot.members.get(key) {
                        let _ = db::write_member(&db, key, &member.issuer, member.byte_limit);
                    }
                }
            }
            let _ = self.reload();
            return Err(format!("core refused the reduced delegated set: {error}"));
        }
        Ok(())
    }
}

pub fn core_grant_id(key: &str) -> String {
    format!("wildbloom-delegated:{key}")
}

fn poisoned() -> GrantsError {
    GrantsError::Io(std::io::Error::other("device grant state lock poisoned"))
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

fn json_ok(status: StatusCode, body: GrantStatus) -> Response {
    let mut response = (status, Json(body)).into_response();
    no_store(&mut response);
    response
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
        Ok((status, body)) => json_ok(status, body),
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
        Ok(status) => json_ok(StatusCode::OK, status),
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
        Ok(status) => json_ok(StatusCode::OK, status),
        Err(error) => error.into_response(),
    }
}

/// Requests the gate lets through for an ended key: reads only.  `HEAD
/// /upload` is BUD-06 write preflight, so it is not a read.
fn is_read(method: &Method, path: &str) -> bool {
    match *method {
        Method::GET | Method::OPTIONS => true,
        Method::HEAD => path != "/upload",
        _ => false,
    }
}

/// Bound a delegated write body: it must keep arriving and finish in time.
fn bounded_body(body: Body) -> Body {
    let deadline = Instant::now() + WRITE_TOTAL_TIMEOUT;
    let stream =
        futures_util::stream::unfold(Some(body.into_data_stream()), move |state| async move {
            let mut stream = state?;
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(WRITE_IDLE_TIMEOUT);
            match tokio::time::timeout(wait, stream.next()).await {
                Ok(Some(Ok(bytes))) => Some((Ok::<Bytes, std::io::Error>(bytes), Some(stream))),
                Ok(Some(Err(_))) => {
                    Some((Err(std::io::Error::other("upload stream failed")), None))
                }
                Ok(None) => None,
                Err(_) => Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "delegated write body timed out",
                    )),
                    None,
                )),
            }
        });
    Body::from_stream(stream)
}

/// Layer for the core Blossom router.  A delegated key whose grant has ended
/// can only read; an active one's writes are counted in flight and bounded.
pub async fn gate(State(grants): State<Grants>, request: Request, next: Next) -> Response {
    if is_read(request.method(), request.uri().path()) {
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
    let Some(_flight) = grants.begin_write(&signer) else {
        return ApiError::forbidden("the delegated storage grant has ended").into_response();
    };
    let (parts, body) = request.into_parts();
    next.run(Request::from_parts(parts, bounded_body(body)))
        .await
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

#[cfg(test)]
impl Grants {
    pub(crate) fn snapshot_members(&self) -> std::collections::BTreeMap<String, u64> {
        self.snapshot()
            .members
            .iter()
            .map(|(key, member)| (key.clone(), member.byte_limit))
            .collect()
    }
}
