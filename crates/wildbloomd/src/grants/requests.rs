//! Opt-in request grants: a currently granted device lets a fresh key upload
//! one file's bytes for at most 24 hours, so a person the owner asks can send
//! a file to the owner's Drop without an owner signature per request.
//!
//! * `POST /request/v1/upload-grants` takes a device-signed NIP-98 request in
//!   the pairing issuer's profile.  Every limit is checked before the event id
//!   is spent.
//! * While active, the key is a core friend grant whose ceiling is the grant's
//!   `bytes`, with the far-future core sentinel used for delegated keys, so the
//!   ceiling, streaming limits and deduplication charging stay core-enforced.
//!   The gate lets it upload, preflight and delete its own claims; reads pass
//!   as for any signer.  Everything else is refused.
//! * A grant ends at `until`, on `DELETE` by the device that made it, or when
//!   that device's grant ends.  The gate refuses its writes at once.  The sweep
//!   then deletes every claim the key holds (other signers' claims on the same
//!   blob keep it) and only then drops the key from the core's trusted set.
//!   Unlike delegated claims, nothing moves to the owner: these are a
//!   stranger's transient bytes the owner never took in.
//! * Records live in `request-grants.sqlite3`, apart from device grants, and
//!   are kept after a grant ends, so a key is never granted twice.
use super::{
    ApiError, CORE_GRANT_SENTINEL, Grants, GrantsError, InFlight, core_grant_id, cors,
    create_private_file, event::is_canonical_key, no_store,
};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Path as AxumPath, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{delete, post},
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{task::spawn_blocking, time::Instant};
use wildbloom_core::{ClaimSpec, FriendGrant, RetentionTier, Store, StoreError};

pub const DATABASE_FILE: &str = "request-grants.sqlite3";
pub const ISSUE_PATH: &str = "request/v1/upload-grants";
/// The largest envelope the browser makes (`MAX_PROTOTYPE_TRANSFER_BYTES`).
pub const MAX_GRANT_BYTES: u64 = 270_532_608;
/// Longest a request grant may last.
pub const MAX_GRANT_SECONDS: u64 = 24 * 60 * 60;
/// Request grants one device may hold open at once.
pub const MAX_OPEN_PER_DEVICE: usize = 3;
/// Request grants one device may be issued within any rolling window.
pub const RATE_LIMIT: usize = 10;
pub const RATE_WINDOW: u64 = 60 * 60;
pub const MAX_BODY_BYTES: usize = 1024;
/// NIP-98 freshness in the checkout profile is 60 s old or 30 s ahead.
const REPLAY_WINDOW: u64 = 120;
const SCHEMA_VERSION: i64 = 1;
/// A hash no blob has, so the room check never meets a stored blob.
const PROBE_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Error codes in the `error` member.  Clients match on these exact strings.
mod code {
    pub const NOT_SUPPORTED: &str = "not_supported";
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const INVALID_PUBKEY: &str = "invalid_pubkey";
    pub const INVALID_BYTES: &str = "invalid_bytes";
    pub const INVALID_UNTIL: &str = "invalid_until";
    pub const BODY_TOO_LARGE: &str = "body_too_large";
    pub const UNAUTHORISED: &str = "unauthorised";
    pub const NOT_A_DEVICE: &str = "not_a_device";
    pub const NOT_YOURS: &str = "not_yours";
    pub const UNKNOWN_REQUEST: &str = "unknown_request";
    pub const KEY_IN_USE: &str = "key_in_use";
    pub const REPLAYED: &str = "replayed";
    pub const NO_ROOM: &str = "no_room";
    pub const TOO_MANY_OPEN: &str = "too_many_open";
    pub const TOO_MANY_REQUESTS: &str = "too_many_requests";
    pub const UNAVAILABLE: &str = "unavailable";
    pub const REQUEST_ENDED: &str = "request_ended";
    pub const UPLOAD_ONLY: &str = "upload_only";
}

fn bad(code: &'static str) -> ApiError {
    ApiError::bad_request(code)
}

fn unavailable() -> ApiError {
    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, code::UNAVAILABLE)
}

pub fn has_database(data_dir: &Path) -> bool {
    database_path(data_dir).exists()
}

fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DATABASE_FILE)
}

/// The core grant id of a request key, distinct from delegated keys' ids.
pub fn request_grant_id(key: &str) -> String {
    format!("wildbloom-request:{key}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RequestRow {
    pub pubkey: String,
    pub device: String,
    pub bytes: u64,
    pub until: u64,
    pub issued_at: u64,
    /// Set by `DELETE`, by the device's revocation, or once the sweep has
    /// seen the grant end.  An end is never undone.
    pub ended_at: Option<u64>,
    /// Every claim was deleted and the key left the core's trusted set.
    pub cleaned_at: Option<u64>,
}

type Rows = BTreeMap<String, RequestRow>;

pub(super) struct Requests {
    db: Mutex<Connection>,
    rows: RwLock<Arc<Rows>>,
}

fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn row_opt(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    Ok(row
        .get::<_, Option<i64>>(index)?
        .map(|value| u64::try_from(value).unwrap_or(0)))
}

impl Requests {
    fn open(data_dir: &Path) -> Result<Self, GrantsError> {
        let path = database_path(data_dir);
        create_private_file(&path)?;
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(GrantsError::RequestSchema(version));
        }
        connection.execute_batch(&format!(
            "PRAGMA journal_mode = WAL;
             BEGIN;
             CREATE TABLE IF NOT EXISTS request_grants (
                pubkey TEXT PRIMARY KEY NOT NULL,
                device TEXT NOT NULL,
                bytes INTEGER NOT NULL CHECK (bytes > 0),
                until INTEGER NOT NULL,
                issued_at INTEGER NOT NULL,
                ended_at INTEGER,
                cleaned_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS request_grants_device
                ON request_grants(device, issued_at);
             PRAGMA user_version = {SCHEMA_VERSION};
             COMMIT;"
        ))?;
        let requests = Self {
            db: Mutex::new(connection),
            rows: RwLock::new(Arc::default()),
        };
        requests.reload()?;
        Ok(requests)
    }

    fn reload(&self) -> Result<(), GrantsError> {
        let next = {
            let db = self.db.lock().map_err(|_| super::poisoned())?;
            let mut statement = db.prepare(
                "SELECT pubkey, device, bytes, until, issued_at, ended_at, cleaned_at
                 FROM request_grants",
            )?;
            let mut rows = Rows::new();
            for row in statement.query_map([], |row| {
                Ok(RequestRow {
                    pubkey: row.get(0)?,
                    device: row.get(1)?,
                    bytes: row_u64(row, 2)?,
                    until: row_u64(row, 3)?,
                    issued_at: row_u64(row, 4)?,
                    ended_at: row_opt(row, 5)?,
                    cleaned_at: row_opt(row, 6)?,
                })
            })? {
                let row = row?;
                rows.insert(row.pubkey.clone(), row);
            }
            rows
        };
        if let Ok(mut guard) = self.rows.write() {
            *guard = Arc::new(next);
        }
        Ok(())
    }

    pub(super) fn rows(&self) -> Arc<Rows> {
        self.rows
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub(super) fn knows(&self, key: &str) -> bool {
        self.rows().contains_key(key)
    }

    fn write(&self, sql: &str, args: impl rusqlite::Params) -> Result<(), GrantsError> {
        {
            let db = self.db.lock().map_err(|_| super::poisoned())?;
            db.execute(sql, args)?;
        }
        self.reload()
    }

    fn insert(&self, row: &RequestRow) -> Result<(), GrantsError> {
        self.write(
            "INSERT INTO request_grants (pubkey, device, bytes, until, issued_at, ended_at, cleaned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            params![
                row.pubkey,
                row.device,
                int(row.bytes),
                int(row.until),
                int(row.issued_at)
            ],
        )
    }

    fn end(&self, pubkey: &str, now: u64) -> Result<(), GrantsError> {
        self.write(
            "UPDATE request_grants SET ended_at = ?2 WHERE pubkey = ?1 AND ended_at IS NULL",
            params![pubkey, int(now)],
        )
    }

    /// End every open request grant a device made, as its grant is revoked.
    pub(super) fn end_device(&self, device: &str, now: u64) -> Result<(), GrantsError> {
        self.write(
            "UPDATE request_grants SET ended_at = ?2 WHERE device = ?1 AND ended_at IS NULL",
            params![device, int(now)],
        )
    }

    fn set_cleaned(&self, keys: &[String], now: Option<u64>) -> Result<(), GrantsError> {
        {
            let mut db = self.db.lock().map_err(|_| super::poisoned())?;
            let tx = db.transaction()?;
            for key in keys {
                tx.execute(
                    "UPDATE request_grants SET cleaned_at = ?2, ended_at = COALESCE(ended_at, ?3)
                     WHERE pubkey = ?1",
                    params![key, now.map(int), now.map(int)],
                )?;
            }
            tx.commit()?;
        }
        self.reload()
    }
}

/// The issue request body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueBody {
    pubkey: String,
    bytes: u64,
    until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Terms {
    pub pubkey: String,
    pub bytes: u64,
    pub until: u64,
}

/// Strict parse of an issue body: one JSON object with exactly `pubkey`,
/// `bytes` and `until` (any order or whitespace, no duplicates).
pub fn parse_issue(body: &[u8], now: u64) -> Result<Terms, ApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            code::BODY_TOO_LARGE,
        ));
    }
    // An object only: the derived struct would also take an array.
    if body.trim_ascii_start().first() != Some(&b'{') {
        return Err(bad(code::INVALID_REQUEST));
    }
    let raw: IssueBody = serde_json::from_slice(body).map_err(|_| bad(code::INVALID_REQUEST))?;
    // `from_hex` only decodes; `xonly` checks the point is on the curve.
    let on_curve = nostr::prelude::PublicKey::from_hex(&raw.pubkey)
        .and_then(|key| key.xonly())
        .is_ok();
    if !is_canonical_key(&raw.pubkey) || !on_curve {
        return Err(bad(code::INVALID_PUBKEY));
    }
    if raw.bytes == 0 || raw.bytes > MAX_GRANT_BYTES {
        return Err(bad(code::INVALID_BYTES));
    }
    if raw.until <= now || raw.until > now.saturating_add(MAX_GRANT_SECONDS) {
        return Err(bad(code::INVALID_UNTIL));
    }
    Ok(Terms {
        pubkey: raw.pubkey,
        bytes: raw.bytes,
        until: raw.until,
    })
}

#[derive(Serialize)]
struct Ended {
    pubkey: String,
    state: &'static str,
}

/// Why the store refused an issue.
enum StoreRefusal {
    KeyInUse,
    NoRoom,
    Failed,
}

/// Blocking store checks for an issue: the key must hold no claim and no
/// paid allowance (so the end-of-grant deletion only ever removes what this
/// grant let in), and the device must have room for `bytes` more within its
/// ceiling less its open request grants, under the node's quota and per-blob
/// limit.  The room check uses the core's own accounting, in-flight
/// reservations included.  It is a check, not a reservation.
fn store_checks(
    store: &Store,
    key: &str,
    device: &str,
    ceiling: u64,
    open_bytes: u64,
    bytes: u64,
) -> Result<(), StoreRefusal> {
    let holds = !store
        .list_claims(key, None, 1)
        .map_err(|_| StoreRefusal::Failed)?
        .is_empty();
    let paid = store
        .paid_claim(key, "application/octet-stream", None)
        .map_err(|_| StoreRefusal::Failed)?
        .is_some();
    if holds || paid {
        return Err(StoreRefusal::KeyInUse);
    }
    let Some(limit) = ceiling.checked_sub(open_bytes).filter(|limit| *limit > 0) else {
        return Err(StoreRefusal::NoRoom);
    };
    let spec = ClaimSpec {
        signer_pubkey: device.to_owned(),
        retention_tier: RetentionTier::Friend,
        declared_type: "application/octet-stream".to_owned(),
        grant_id: Some(core_grant_id(device)),
        claim_expires_at: Some(CORE_GRANT_SENTINEL),
        byte_limit: Some(limit),
        class: None,
    };
    match store.check_claimed_upload(PROBE_HASH, bytes, &spec) {
        Ok(()) => Ok(()),
        Err(
            StoreError::FriendLimitExceeded
            | StoreError::QuotaExceeded
            | StoreError::BlobTooLarge { .. },
        ) => Err(StoreRefusal::NoRoom),
        Err(_) => Err(StoreRefusal::Failed),
    }
}

fn authorization(headers: &HeaderMap) -> Result<&str, ApiError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or_else(|| ApiError::unauthorised(code::UNAUTHORISED))?;
    if values.next().is_some() {
        return Err(bad(code::INVALID_REQUEST));
    }
    value.to_str().map_err(|_| bad(code::INVALID_REQUEST))
}

impl Grants {
    /// Open (or create) the request grant records.  Call once, after
    /// [`Grants::open`] and before [`Grants::core_friend_grants`].
    pub fn open_requests(&self, data_dir: &Path) -> Result<(), GrantsError> {
        let requests = Requests::open(data_dir)?;
        // A recorded request key stays subject to the gate and the sweep, so
        // it can never also be configured or delegated in another role.
        let snapshot = self.snapshot();
        let cli = self.cli_keys();
        if requests.rows().keys().any(|key| {
            self.inner.owners.contains(key)
                || cli.contains(key)
                || self.inner.reserved.contains(key)
                || snapshot.knows(key)
                || snapshot.markers.contains_key(key)
        }) {
            return Err(GrantsError::RequestConflict);
        }
        let _ = self.inner.requests.set(requests);
        Ok(())
    }

    pub(super) fn requests(&self) -> Option<&Requests> {
        self.inner.requests.get()
    }

    /// The device-signed issue and end routes.
    pub fn request_router(&self) -> Router {
        Router::new()
            .route(&format!("/{ISSUE_PATH}"), post(issue))
            .route(&format!("/{ISSUE_PATH}/{{pubkey}}"), delete(end))
            .with_state(self.clone())
            .layer(cors(&[Method::POST, Method::DELETE]))
    }

    fn request_active(&self, row: &RequestRow, now: u64) -> bool {
        row.ended_at.is_none()
            && row.cleaned_at.is_none()
            && row.until > now
            && self.is_active_device(&row.device)
    }

    pub fn is_active_request(&self, key: &str) -> bool {
        let now = self.now();
        self.requests()
            .and_then(|requests| requests.rows().get(key).cloned())
            .is_some_and(|row| self.request_active(&row, now))
    }

    /// Request keys the core must currently hold as friend grants.
    pub(super) fn request_friend_grants(&self) -> Vec<FriendGrant> {
        let Some(requests) = self.requests() else {
            return Vec::new();
        };
        requests
            .rows()
            .values()
            .filter(|row| row.cleaned_at.is_none())
            .map(|row| FriendGrant {
                pubkey: row.pubkey.clone(),
                byte_limit: row.bytes,
                expires_at: CORE_GRANT_SENTINEL,
                grant_id: request_grant_id(&row.pubkey),
                issuer: Some(row.device.clone()),
            })
            .collect()
    }

    /// Whether a key was ever recorded in any role, so it cannot become a
    /// request key.
    fn key_seen(&self, key: &str, caller: &str) -> bool {
        let snapshot = self.snapshot();
        key == caller
            || self.inner.owners.contains(key)
            || self.cli_keys().contains(key)
            || self.inner.reserved.contains(key)
            || snapshot.knows(key)
            || snapshot.markers.contains_key(key)
            || self.requests().is_some_and(|requests| requests.knows(key))
    }

    async fn issue_request(&self, request: Request<Body>) -> Result<Terms, ApiError> {
        let Some(requests) = self.requests() else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, code::NOT_SUPPORTED));
        };
        if request.uri().query().is_some() {
            return Err(bad(code::INVALID_REQUEST));
        }
        let header = authorization(request.headers())?.to_owned();
        let body = to_bytes(request.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, code::BODY_TOO_LARGE))?;
        let now = self.now();
        let principal = wildbloom_checkout::authenticate(
            &header,
            &format!("{}{ISSUE_PATH}", self.inner.origin),
            "POST",
            &body,
            now,
        )
        .map_err(|_| ApiError::unauthorised(code::UNAUTHORISED))?;
        let device = principal.pubkey().to_owned();
        // Owners, recovery identities, request keys and ended devices are
        // never active devices.
        if !self.is_active_device(&device) {
            return Err(ApiError::forbidden(code::NOT_A_DEVICE));
        }
        let terms = parse_issue(&body, now)?;

        let update = self.inner.updates.lock().await;
        let now = self.now();
        if !self.is_active_device(&device) {
            return Err(ApiError::forbidden(code::NOT_A_DEVICE));
        }
        if self.key_seen(&terms.pubkey, &device) {
            return Err(ApiError::conflict(code::KEY_IN_USE));
        }
        let rows = requests.rows();
        let mine = rows.values().filter(|row| row.device == device);
        let open = mine
            .clone()
            .filter(|row| self.request_active(row, now))
            .collect::<Vec<_>>();
        if open.len() >= MAX_OPEN_PER_DEVICE {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                code::TOO_MANY_OPEN,
            ));
        }
        if mine
            .filter(|row| now.saturating_sub(row.issued_at) < RATE_WINDOW)
            .count()
            >= RATE_LIMIT
        {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                code::TOO_MANY_REQUESTS,
            ));
        }
        let open_bytes = open
            .iter()
            .fold(0_u64, |total, row| total.saturating_add(row.bytes));
        let ceiling = self
            .snapshot()
            .grants
            .get(&device)
            .map(|row| row.byte_limit)
            .ok_or_else(|| ApiError::forbidden(code::NOT_A_DEVICE))?;
        let app = self.inner.app.get().ok_or_else(unavailable)?;
        let store = app.store().clone();
        let (key, checked_device, bytes) = (terms.pubkey.clone(), device.clone(), terms.bytes);
        let verdict = spawn_blocking(move || {
            store_checks(&store, &key, &checked_device, ceiling, open_bytes, bytes)
        })
        .await
        .map_err(|_| unavailable())?;
        match verdict {
            Ok(()) => {}
            Err(StoreRefusal::KeyInUse) => return Err(ApiError::conflict(code::KEY_IN_USE)),
            Err(StoreRefusal::NoRoom) => return Err(ApiError::conflict(code::NO_ROOM)),
            Err(StoreRefusal::Failed) => return Err(unavailable()),
        }
        // Every limit passed: only now is the event id spent.
        if !self
            .consume_event(principal.event_id(), now.saturating_add(REPLAY_WINDOW))
            .map_err(|_| unavailable())?
        {
            return Err(ApiError::conflict(code::REPLAYED));
        }
        let row = RequestRow {
            pubkey: terms.pubkey.clone(),
            device,
            bytes: terms.bytes,
            until: terms.until,
            issued_at: now,
            ended_at: None,
            cleaned_at: None,
        };
        requests.insert(&row).map_err(|_| unavailable())?;
        // The core push waits for in-flight core writes to drain, so it runs
        // outside the state lock, as for device grants.
        drop(update);
        if let Err(error) = self.push_core_policy().await {
            tracing::error!(reason = %error, "core refused the request grant policy; ending it");
            // The key stays recorded and ended, so the gate refuses it and
            // the sweep removes it from the core again.
            let _update = self.inner.updates.lock().await;
            let _ = requests.end(&row.pubkey, self.now());
            drop(_update);
            self.inner.wake.notify_one();
            return Err(unavailable());
        }
        tracing::info!(
            bytes = row.bytes,
            until = row.until,
            "issued a request grant"
        );
        Ok(terms)
    }

    async fn end_request(&self, pubkey: &str, request: Request<Body>) -> Result<Ended, ApiError> {
        let Some(requests) = self.requests() else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, code::NOT_SUPPORTED));
        };
        if !is_canonical_key(pubkey) {
            return Err(bad(code::INVALID_PUBKEY));
        }
        if request.uri().query().is_some() {
            return Err(bad(code::INVALID_REQUEST));
        }
        let header = authorization(request.headers())?.to_owned();
        let body = to_bytes(request.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, code::BODY_TOO_LARGE))?;
        let principal = wildbloom_checkout::authenticate(
            &header,
            &format!("{}{ISSUE_PATH}/{pubkey}", self.inner.origin),
            "DELETE",
            &body,
            self.now(),
        )
        .map_err(|_| ApiError::unauthorised(code::UNAUTHORISED))?;
        let row = requests
            .rows()
            .get(pubkey)
            .cloned()
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, code::UNKNOWN_REQUEST))?;
        // Only the device that made it; ending only reduces authority, so a
        // device whose own grant has ended may still end its requests.
        if row.device != principal.pubkey() {
            return Err(ApiError::forbidden(code::NOT_YOURS));
        }
        {
            let _update = self.inner.updates.lock().await;
            let now = self.now();
            if !self
                .consume_event(principal.event_id(), now.saturating_add(REPLAY_WINDOW))
                .map_err(|_| unavailable())?
            {
                return Err(ApiError::conflict(code::REPLAYED));
            }
            requests.end(pubkey, now).map_err(|_| unavailable())?;
        }
        self.inner.wake.notify_one();
        tracing::info!("ended a request grant");
        Ok(Ended {
            pubkey: pubkey.to_owned(),
            state: "ended",
        })
    }

    /// Count a request key's write as in flight if its grant is active.
    pub(super) fn begin_request_write(&self, key: &str) -> Option<InFlight> {
        self.begin_write_if(key, |grants| grants.is_active_request(key))
    }

    /// The request part of a sweep: delete every claim of each ended request
    /// key whose writes have finished.  Returns the keys cleaned on this pass,
    /// already marked, for the caller's core push.
    pub(super) async fn sweep_requests_locked(&self) -> Result<Vec<String>, String> {
        let (Some(requests), Some(app)) = (self.requests(), self.inner.app.get()) else {
            return Ok(Vec::new());
        };
        let now = self.now();
        let ended = requests
            .rows()
            .values()
            .filter(|row| row.cleaned_at.is_none() && !self.request_active(row, now))
            .map(|row| row.pubkey.clone())
            .collect::<Vec<_>>();
        let deadline = Instant::now() + self.in_flight_wait();
        let mut cleaned = Vec::new();
        for key in ended {
            if !self.wait_idle(&key, deadline).await {
                tracing::info!("an ended request key still has a write in flight; retrying later");
                continue;
            }
            let store = app.store().clone();
            let removing = key.clone();
            let result = spawn_blocking(move || super::claims::remove_all(&store, &removing))
                .await
                .unwrap_or_else(|_| Err("request claim removal task failed".to_owned()));
            match result {
                Ok(claims) => {
                    tracing::info!(claims, "deleted an ended request grant's claims");
                    cleaned.push(key);
                }
                Err(error) => {
                    tracing::warn!(reason = %error, "could not delete request grant claims yet");
                }
            }
        }
        if !cleaned.is_empty() {
            requests
                .set_cleaned(&cleaned, Some(now))
                .map_err(|_| "request grant database".to_owned())?;
        }
        Ok(cleaned)
    }

    /// Put cleaned keys back after the core refused the reduced set, so the
    /// next pass retries.  Their ends stay recorded.
    pub(super) fn unclean_requests(&self, keys: &[String]) {
        if let Some(requests) = self.requests()
            && !keys.is_empty()
        {
            let _ = requests.set_cleaned(keys, None);
        }
    }
}

async fn issue(State(grants): State<Grants>, request: Request<Body>) -> Response {
    match grants.issue_request(request).await {
        Ok(terms) => {
            let mut response = (StatusCode::CREATED, Json(terms)).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

async fn end(
    State(grants): State<Grants>,
    AxumPath(pubkey): AxumPath<String>,
    request: Request<Body>,
) -> Response {
    match grants.end_request(&pubkey, request).await {
        Ok(ended) => {
            let mut response = (StatusCode::OK, Json(ended)).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}

/// The gate for a request key's non-read requests: while its grant is active
/// it may upload, preflight and delete its own claims, with the delegated
/// body pacing.  `PUT /mirror` and everything else are refused.
pub(super) async fn gate(grants: &Grants, signer: &str, request: Request, next: Next) -> Response {
    let Some(_flight) = grants.begin_request_write(signer) else {
        return ApiError::forbidden(code::REQUEST_ENDED).into_response();
    };
    let method = request.method();
    let path = request.uri().path();
    let allowed = (path == "/upload" && (method == Method::PUT || method == Method::HEAD))
        || (method == Method::DELETE && super::blob_hash(path).is_some());
    if !allowed {
        return ApiError::forbidden(code::UPLOAD_ONLY).into_response();
    }
    let (parts, body) = request.into_parts();
    next.run(Request::from_parts(parts, super::bounded_body(body)))
        .await
}
