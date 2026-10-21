//! Group mode: a closed storage node for the devices of one or more groups.
//!
//! A group is one enrolled keeper key and one room id (`docs/GROUP-GRANTS.md`).
//! Keeper-signed kind 27541 grants name the device keys that may use the node.
//! Group keys ride the core friend-grant machinery (a core grant id per group
//! and the far-future sentinel expiry that device grants use); the real expiry
//! and scopes are enforced by a gate in front of the core router.
use super::{
    CORE_GRANT_SENTINEL, Grants, GrantsError, cors,
    event::is_canonical_key,
    group_db::{self, Floor, GroupGrantRow, GroupId, GroupKey, GroupRows},
    group_event::{self, Body, FUTURE_SKEW, GroupEvent, Refusal, Scope},
};
use axum::{
    Json, Router,
    body::{Body as HttpBody, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use rusqlite::Connection;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use wildbloom_core::FriendGrant;

/// Posts to the event route allowed in any one minute, across all callers:
/// every request over Tor arrives from loopback, so a per-address limit
/// would mean nothing.
const EVENTS_PER_MINUTE: usize = 120;

const GROUP_DATABASE_FILE: &str = "group-grants.sqlite3";

/// One keeper the node owner serves, from `--group-keeper`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    pub keeper: String,
    /// Bytes the node owner allows this keeper's groups to hold, per group.
    pub ceiling: u64,
    /// Room ids the owner expects.  Empty means any room of this keeper.
    pub rooms: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct GroupConfig {
    pub enrolments: Vec<Enrolment>,
    /// Simultaneous group upload streams.
    pub max_concurrent_writes: usize,
}

pub(super) struct GroupState {
    pub db: Mutex<Connection>,
    pub enrolments: BTreeMap<String, Enrolment>,
    /// The node's own host names, lower case, as a grant's `server` names them.
    pub hosts: BTreeSet<String>,
    pub snapshot: RwLock<Arc<GroupRows>>,
    /// Serialises grant, revocation and reset commits.  Never held while
    /// verifying a signature, serving a request or waiting for the core.
    pub updates: tokio::sync::Mutex<()>,
    /// Clock seconds of recent posts to the event route.
    pub posts: Mutex<VecDeque<u64>>,
    /// Blobs each group holds, built from the store's claims on first use
    /// and kept current by the gate.  An absent entry is rebuilt, never
    /// guessed.
    pub holdings: Mutex<HashMap<GroupId, Arc<Mutex<Option<Holdings>>>>>,
    /// Bytes of group uploads that have been admitted and not yet committed.
    pub reserved: Mutex<HashMap<GroupId, u64>>,
    pub writes: Arc<tokio::sync::Semaphore>,
}

/// The distinct blobs one group holds, with their sizes: a blob counts once
/// against the group ceiling however many of its keys claim it.
#[derive(Debug, Default)]
pub(super) struct Holdings {
    blobs: HashMap<String, u64>,
    total: u64,
}

impl Holdings {
    pub fn contains(&self, hash: &str) -> bool {
        self.blobs.contains_key(hash)
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn insert(&mut self, hash: &str, size: u64) {
        if let Some(old) = self.blobs.insert(hash.to_owned(), size) {
            self.total = self.total.saturating_sub(old);
        }
        self.total = self.total.saturating_add(size);
    }

    pub fn remove(&mut self, hash: &str) {
        if let Some(old) = self.blobs.remove(hash) {
            self.total = self.total.saturating_sub(old);
        }
    }
}

/// A host name as a grant or token names it: bare, or the host of an
/// `http(s)` origin.
pub(super) fn host_of(value: &str) -> Option<String> {
    let value = value.to_ascii_lowercase();
    if group_event::is_host_name(&value) {
        return Some(value);
    }
    let url = url::Url::parse(&value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    url.host_str().map(str::to_owned)
}

/// The core grant id shared by every key of one group.
pub fn core_group_grant_id(keeper: &str, room: &str) -> String {
    format!("wildbloom-group:{keeper}:{room}")
}

impl Grants {
    pub fn group_database_path(data_dir: &Path) -> PathBuf {
        data_dir.join(GROUP_DATABASE_FILE)
    }

    /// Turn on group mode: open the private state file and validate the
    /// enrolments against every other kind of key this node knows.  Call once,
    /// before `core_friend_grants` is read for the core configuration.
    pub fn enable_group(&self, data_dir: &Path, config: GroupConfig) -> Result<(), GrantsError> {
        if config.enrolments.is_empty() {
            return Err(GrantsError::Group("group mode needs at least one keeper"));
        }
        let mut enrolments = BTreeMap::new();
        for enrolment in config.enrolments {
            if !is_canonical_key(&enrolment.keeper)
                || enrolment.ceiling == 0
                || enrolment.ceiling > i64::MAX as u64
                || enrolment.rooms.iter().any(|room| !is_canonical_key(room))
                || enrolments
                    .insert(enrolment.keeper.clone(), enrolment)
                    .is_some()
            {
                return Err(GrantsError::Group(
                    "a group keeper must be unique, with a 64 hex key and a positive ceiling",
                ));
            }
        }
        let path = Self::group_database_path(data_dir);
        super::create_private_file(&path)?;
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let version = group_db::initialise(&connection)?;
        if version != group_db::SCHEMA_VERSION {
            return Err(GrantsError::Schema(version));
        }
        let rows = group_db::read_rows(&connection)?;
        // A keeper is an authority, never a user: it cannot also be an owner,
        // friend, device grant, recovery, service or group device key.
        let others = self.other_authority_keys();
        if enrolments
            .keys()
            .any(|keeper| others.contains(keeper) || rows.keys.contains_key(keeper))
            || rows
                .keys
                .keys()
                .any(|key| others.contains(key) || enrolments.contains_key(key))
        {
            return Err(GrantsError::Conflict);
        }
        let state = GroupState {
            db: Mutex::new(connection),
            enrolments,
            hosts: self
                .inner
                .server_names
                .iter()
                .filter_map(|name| host_of(name))
                .collect(),
            snapshot: RwLock::new(Arc::new(rows)),
            updates: tokio::sync::Mutex::new(()),
            posts: Mutex::new(VecDeque::new()),
            holdings: Mutex::new(HashMap::new()),
            reserved: Mutex::new(HashMap::new()),
            writes: Arc::new(tokio::sync::Semaphore::new(
                config.max_concurrent_writes.max(1),
            )),
        };
        self.inner
            .group
            .set(state)
            .map_err(|_| GrantsError::Group("group mode is already enabled"))
    }

    /// Owner, CLI friend, service and device-grant device or recovery keys.
    fn other_authority_keys(&self) -> BTreeSet<String> {
        let mut keys = self.inner.owners.clone();
        keys.extend(self.inner.reserved.iter().cloned());
        keys.extend(self.cli_keys());
        keys.extend(self.known_keys());
        keys
    }

    fn group_snapshot(&self) -> Option<Arc<GroupRows>> {
        let state = self.inner.group.get()?;
        state.snapshot.read().ok().map(|guard| guard.clone())
    }

    /// Whether a device grant may not take this key: it is an enrolled keeper
    /// or already a group device.
    pub(super) fn group_claims_key(&self, key: &str) -> bool {
        let Some(state) = self.inner.group.get() else {
            return false;
        };
        state.enrolments.contains_key(key)
            || self
                .group_snapshot()
                .is_some_and(|rows| rows.keys.contains_key(key))
    }

    /// Core friend grants for group keys that hold or may make claims: every
    /// key that ever had an `upload` grant, with its group's core grant id.
    /// Ended keys stay in the set so the core never demotes their claims;
    /// the gate refuses them.
    pub(super) fn group_friend_grants(&self) -> Vec<FriendGrant> {
        let Some(rows) = self.group_snapshot() else {
            return Vec::new();
        };
        rows.keys
            .iter()
            .filter_map(|(device, key)| {
                Some(FriendGrant {
                    pubkey: device.clone(),
                    byte_limit: key.byte_limit?,
                    expires_at: CORE_GRANT_SENTINEL,
                    grant_id: core_group_grant_id(&key.keeper, &key.room),
                    issuer: Some(key.keeper.clone()),
                })
            })
            .collect()
    }
}

/// A grant event the node recorded, or already held exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    pub created: bool,
    pub state: &'static str,
}

struct Plan {
    accepted: Accepted,
    grant: Option<GroupGrantRow>,
    floor: Option<(GroupId, Floor)>,
    key: Option<(String, GroupKey)>,
}

impl Plan {
    fn unchanged(state: &'static str) -> Self {
        Self {
            accepted: Accepted {
                created: false,
                state,
            },
            grant: None,
            floor: None,
            key: None,
        }
    }
}

/// What a failed core push must put back.
struct Previous {
    grant: Option<GroupGrantRow>,
    key: Option<GroupKey>,
}

impl Grants {
    pub fn group_enabled(&self) -> bool {
        self.inner.group.get().is_some()
    }

    pub(super) fn group_state(&self) -> Result<&GroupState, Refusal> {
        self.inner.group.get().ok_or_else(Refusal::unavailable)
    }

    fn reload_group(&self, state: &GroupState) -> Result<(), Refusal> {
        let next = {
            let db = state.db.lock().map_err(|_| Refusal::unavailable())?;
            group_db::read_rows(&db).map_err(|_| Refusal::unavailable())?
        };
        if let Ok(mut guard) = state.snapshot.write() {
            *guard = Arc::new(next);
        }
        Ok(())
    }

    /// A route-wide limit on posted events, on the node's own clock.
    fn allow_group_post(&self, state: &GroupState) -> Result<(), Refusal> {
        let now = self.now();
        let mut posts = state.posts.lock().map_err(|_| Refusal::unavailable())?;
        while posts
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= 60)
        {
            posts.pop_front();
        }
        if posts.len() >= EVENTS_PER_MINUTE {
            return Err(Refusal::new(StatusCode::TOO_MANY_REQUESTS, "rate"));
        }
        posts.push_back(now);
        Ok(())
    }

    /// Submit one kind 27541 event.  Rules 1 to 7 of section 4.4 need no
    /// state and run before the database is touched; rules 8 to 11 run
    /// against the node's state under the update lock.
    pub async fn post_group_event(&self, body: &[u8]) -> Result<Accepted, Refusal> {
        let state = self.group_state()?;
        self.allow_group_post(state)?;
        let event = group_event::parse(body)?;
        // 5: a keeper the node owner enrolled, for a room they expect.
        state
            .enrolments
            .get(&event.keeper)
            .filter(|enrolment| {
                enrolment.rooms.is_empty() || enrolment.rooms.contains(event.room())
            })
            .ok_or(Refusal::forbidden("keeper"))?;
        // 6 and 7: this node, and an event neither from the future nor over.
        if !state.hosts.contains(event.server()) {
            return Err(Refusal::forbidden("server"));
        }
        let now = self.now();
        if event.created_at > now.saturating_add(FUTURE_SKEW) {
            return Err(Refusal::forbidden("future"));
        }
        if event.expiration <= now {
            return Err(Refusal::forbidden("expired"));
        }

        let update = state.updates.lock().await;
        let now = self.now();
        let rows = self.group_snapshot().ok_or_else(Refusal::unavailable)?;
        let plan = self.evaluate_group_event(state, &rows, &event, now)?;
        if plan.grant.is_none() && plan.floor.is_none() {
            return Ok(plan.accepted);
        }
        let previous = Previous {
            grant: plan.grant.as_ref().and_then(|row| {
                rows.grants
                    .get(&(row.keeper.clone(), row.grant_id.clone()))
                    .cloned()
            }),
            key: plan
                .key
                .as_ref()
                .and_then(|(device, _)| rows.keys.get(device).cloned()),
        };
        let before = self.group_friend_grants();
        {
            let mut db = state.db.lock().map_err(|_| Refusal::unavailable())?;
            let tx = db.transaction().map_err(|_| Refusal::unavailable())?;
            if let Some(row) = &plan.grant {
                group_db::write_grant(&tx, row).map_err(|_| Refusal::unavailable())?;
            }
            if let Some((group, floor)) = &plan.floor {
                group_db::write_floor(&tx, group, floor).map_err(|_| Refusal::unavailable())?;
            }
            if let Some((device, key)) = &plan.key {
                group_db::write_key(&tx, device, key).map_err(|_| Refusal::unavailable())?;
            }
            tx.commit().map_err(|_| Refusal::unavailable())?;
        }
        self.reload_group(state)?;
        drop(update);
        // Revocations, resets and expiry never change the core's friend set,
        // so they never wait on a core push; only a new upload key or a new
        // ceiling does.  The push waits for in-flight core writes, so it runs
        // outside the update lock.
        if before != self.group_friend_grants()
            && let Err(error) = self.push_core_policy().await
        {
            tracing::error!(reason = %error, "core refused the group friend set; reverting");
            let _update = state.updates.lock().await;
            if let Some(row) = &plan.grant
                && self
                    .group_snapshot()
                    .and_then(|rows| {
                        rows.grants
                            .get(&(row.keeper.clone(), row.grant_id.clone()))
                            .cloned()
                    })
                    .as_ref()
                    == Some(row)
            {
                self.revert_group(state, row, previous, plan.key.as_ref())?;
            }
            drop(_update);
            let _ = self.push_core_policy().await;
            return Err(Refusal::unavailable());
        }
        Ok(plan.accepted)
    }

    fn revert_group(
        &self,
        state: &GroupState,
        written: &GroupGrantRow,
        previous: Previous,
        key: Option<&(String, GroupKey)>,
    ) -> Result<(), Refusal> {
        {
            let mut db = state.db.lock().map_err(|_| Refusal::unavailable())?;
            let tx = db.transaction().map_err(|_| Refusal::unavailable())?;
            match previous.grant {
                Some(row) => group_db::write_grant(&tx, &row),
                None => {
                    group_db::delete_grant(&tx, &(written.keeper.clone(), written.grant_id.clone()))
                }
            }
            .map_err(|_| Refusal::unavailable())?;
            if let Some((device, _)) = key {
                match previous.key {
                    Some(key) => group_db::write_key(&tx, device, &key),
                    None => group_db::delete_key(&tx, device),
                }
                .map_err(|_| Refusal::unavailable())?;
            }
            tx.commit().map_err(|_| Refusal::unavailable())?;
        }
        self.reload_group(state)
    }

    fn group_key_conflict(
        &self,
        state: &GroupState,
        rows: &GroupRows,
        group: &GroupId,
        device: &str,
    ) -> bool {
        self.other_authority_keys().contains(device)
            || state.enrolments.contains_key(device)
            || rows
                .keys
                .get(device)
                .is_some_and(|key| (&key.keeper, &key.room) != (&group.0, &group.1))
            || rows
                .rows_for(device)
                .any(|row| (&row.keeper, &row.room) != (&group.0, &group.1))
    }

    /// Rules 8 to 11 of section 4.4, and the state each outcome writes.
    fn evaluate_group_event(
        &self,
        state: &GroupState,
        rows: &GroupRows,
        event: &GroupEvent,
        now: u64,
    ) -> Result<Plan, Refusal> {
        let group = (event.keeper.clone(), event.room().to_owned());
        let enrolled = |keeper: &str| state.enrolments.contains_key(keeper);
        let (grant_id, device, server, scopes, bytes, revoked) = match &event.body {
            Body::Reset { .. } => {
                if let Some(floor) = rows.floors.get(&group) {
                    if floor.event_id == event.id {
                        return Ok(Plan::unchanged("reset"));
                    }
                    if event.created_at <= floor.created_at {
                        return Err(Refusal::conflict("stale"));
                    }
                }
                return Ok(Plan {
                    accepted: Accepted {
                        created: true,
                        state: "reset",
                    },
                    grant: None,
                    floor: Some((
                        group,
                        Floor {
                            created_at: event.created_at,
                            expires_at: event.created_at.saturating_add(group_db::FLOOR_RETENTION),
                            event_id: event.id.clone(),
                        },
                    )),
                    key: None,
                });
            }
            Body::Grant {
                grant_id,
                device,
                server,
                scopes,
                bytes,
                revoked,
                ..
            } => (grant_id, device, server, *scopes, *bytes, *revoked),
        };
        // 8: a device is one kind of key, in one group.
        if self.group_key_conflict(state, rows, &group, device) {
            return Err(Refusal::conflict("key-conflict"));
        }
        // 9: nothing at or before a reset lands again.
        if rows
            .floors
            .get(&group)
            .is_some_and(|floor| event.created_at <= floor.created_at)
        {
            return Err(Refusal::conflict("floor"));
        }
        // 10: one id, one room, device and node; strictly newer; revoked is final.
        let existing = rows.grants.get(&(event.keeper.clone(), grant_id.clone()));
        if let Some(row) = existing {
            if row.event_id == event.id {
                return Ok(Plan::unchanged(if row.active {
                    "active"
                } else {
                    "revoked"
                }));
            }
            if (&row.room, &row.device, &row.server) != (&group.1, device, server) {
                return Err(Refusal::conflict("scope-changed"));
            }
            if event.created_at <= row.created_at {
                return Err(Refusal::conflict("stale"));
            }
            if !row.active && !revoked {
                return Err(Refusal::conflict("revoked"));
            }
        }
        // 11: one active grant per device in a group.
        if !revoked
            && rows.rows_for(device).any(|other| {
                other.grant_id != *grant_id
                    && (&other.keeper, &other.room) == (&group.0, &group.1)
                    && rows.is_active(other, enrolled, now)
            })
        {
            return Err(Refusal::conflict("scope-taken"));
        }
        let row = GroupGrantRow {
            keeper: event.keeper.clone(),
            grant_id: grant_id.clone(),
            room: group.1.clone(),
            device: device.clone(),
            server: server.clone(),
            scopes,
            bytes,
            active: !revoked,
            created_at: event.created_at,
            expiration: event.expiration,
            retain_until: existing.map_or(event.expiration, |row| {
                row.retain_until.max(event.expiration)
            }),
            revoked_at: revoked.then(|| {
                existing
                    .and_then(|row| row.revoked_at)
                    .unwrap_or(event.created_at)
            }),
            event_id: event.id.clone(),
        };
        // A key joins its group on its first active grant and keeps the
        // ceiling of the newest one that carried an upload scope.
        let known = rows.keys.get(device);
        let key = (!revoked)
            .then(|| GroupKey {
                keeper: group.0.clone(),
                room: group.1.clone(),
                byte_limit: bytes.or(known.and_then(|key| key.byte_limit)),
            })
            .filter(|key| known != Some(key))
            .map(|key| (device.clone(), key));
        Ok(Plan {
            accepted: Accepted {
                created: true,
                state: if revoked { "revoked" } else { "active" },
            },
            grant: Some(row),
            floor: None,
            key,
        })
    }

    /// `POST /groups/v1/events`.  The signature is the authority, so the
    /// route needs no `Authorization` and anyone may post.
    pub fn group_router(&self) -> Router {
        Router::new()
            .route("/groups/v1/events", post(post_event))
            .with_state(self.clone())
            .layer(cors(&[Method::POST]))
    }
}

async fn post_event(State(grants): State<Grants>, request: Request<HttpBody>) -> Response {
    let body = match to_bytes(request.into_body(), group_event::MAX_EVENT_BYTES).await {
        Ok(body) => body,
        Err(_) => return Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "too-large").into_response(),
    };
    match grants.post_group_event(&body).await {
        Ok(accepted) => {
            let mut response = (
                if accepted.created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                Json(serde_json::json!({ "state": accepted.state })),
            )
                .into_response();
            let headers = response.headers_mut();
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            headers.insert(
                "x-reason",
                HeaderValue::from_static(if accepted.created {
                    "accepted"
                } else {
                    "unchanged"
                }),
            );
            response
        }
        Err(refusal) => refusal.into_response(),
    }
}

impl Grants {
    /// Forget what no event or token could still need (see `group_db::prune`).
    pub(super) fn prune_group(&self, now: u64) {
        if let Some(state) = self.inner.group.get()
            && let Ok(db) = state.db.lock()
        {
            let _ = group_db::prune(&db, now);
        }
    }
}

#[cfg(test)]
impl Grants {
    /// Whether `key` holds an active grant with the scope bit, right now.
    pub(crate) fn group_granted(&self, key: &str, scope: u8) -> bool {
        let Some(state) = self.inner.group.get() else {
            return false;
        };
        let enrolled = |keeper: &str| state.enrolments.contains_key(keeper);
        self.group_snapshot()
            .and_then(|rows| {
                rows.active_for(key, &enrolled, self.now())
                    .map(|row| row.scopes & scope != 0)
            })
            .unwrap_or(false)
    }
}

/// An active grant, as the gate needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ActiveGrant {
    pub scopes: u8,
    pub bytes: Option<u64>,
}

impl ActiveGrant {
    pub fn allows(&self, scope: Scope) -> bool {
        self.scopes & scope.bit() != 0
    }
}

/// Who a token's signer is to this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Who {
    /// A device of a group, with its grant while one is active.
    Member {
        group: GroupId,
        active: Option<ActiveGrant>,
    },
    /// An owner, CLI friend, service or device-grant key: the core's own
    /// rules apply to it, and it reads only what it holds itself.
    Authority,
    /// Anyone else.
    Stranger,
}

/// Admitted upload bytes, released when dropped.
pub(super) struct Reservation {
    grants: Grants,
    group: GroupId,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(state) = self.grants.inner.group.get()
            && let Ok(mut reserved) = state.reserved.lock()
            && let Some(held) = reserved.get_mut(&self.group)
        {
            *held = held.saturating_sub(self.bytes);
            if *held == 0 {
                reserved.remove(&self.group);
            }
        }
    }
}

impl Grants {
    fn enrolled_keeper(&self) -> impl Fn(&str) -> bool + '_ {
        move |keeper| {
            self.inner
                .group
                .get()
                .is_some_and(|state| state.enrolments.contains_key(keeper))
        }
    }

    /// The ceiling the node owner set for the keeper's groups.
    pub(super) fn group_ceiling(&self, keeper: &str) -> Option<u64> {
        self.inner
            .group
            .get()?
            .enrolments
            .get(keeper)
            .map(|enrolment| enrolment.ceiling)
    }

    fn is_other_authority(&self, key: &str) -> bool {
        self.inner.owners.contains(key)
            || self.inner.reserved.contains(key)
            || self
                .inner
                .cli_friend_grants
                .iter()
                .any(|grant| grant.pubkey == key)
            || self.snapshot().knows(key)
    }

    /// Who `signer` is, and which grant is active for it, right now.
    pub(super) fn group_who(&self, signer: &str) -> Who {
        let now = self.now();
        let enrolled = self.enrolled_keeper();
        if let Some(rows) = self.group_snapshot()
            && let Some(group) = rows.group_of(signer)
        {
            let active = rows
                .active_for(signer, &enrolled, now)
                .map(|row| ActiveGrant {
                    scopes: row.scopes,
                    bytes: row.bytes,
                });
            return Who::Member { group, active };
        }
        if self.is_other_authority(signer) {
            Who::Authority
        } else {
            Who::Stranger
        }
    }

    /// Whether `signer` ended a grant with `scope` less than seven days ago.
    pub(super) fn group_in_grace(&self, signer: &str, scope: Scope) -> bool {
        self.group_snapshot().is_some_and(|rows| {
            rows.in_grace(signer, scope.bit(), &self.enrolled_keeper(), self.now())
        })
    }

    /// Every device key of `group`.
    pub(super) fn group_devices(&self, group: &GroupId) -> Vec<String> {
        self.group_snapshot()
            .map(|rows| rows.devices_of(group))
            .unwrap_or_default()
    }

    /// Run `f` on what `group` holds.  Blocking: it may walk the store's
    /// claims for every key of the group the first time it is used.
    pub(super) fn with_holdings<R>(
        &self,
        group: &GroupId,
        f: impl FnOnce(&mut Holdings) -> R,
    ) -> Result<R, Refusal> {
        let state = self.group_state()?;
        let store = self
            .inner
            .app
            .get()
            .ok_or_else(Refusal::unavailable)?
            .store()
            .clone();
        let cell = state
            .holdings
            .lock()
            .map_err(|_| Refusal::unavailable())?
            .entry(group.clone())
            .or_default()
            .clone();
        let mut cell = cell.lock().map_err(|_| Refusal::unavailable())?;
        if cell.is_none() {
            let grant_id = core_group_grant_id(&group.0, &group.1);
            let mut holdings = Holdings::default();
            for device in self.group_devices(group) {
                super::claims::each_claim(&store, &device, Some(&grant_id), |claim| {
                    holdings.insert(&claim.sha256, claim.size);
                })
                .map_err(|_| Refusal::unavailable())?;
            }
            *cell = Some(holdings);
        }
        Ok(f(cell.as_mut().expect("holdings were just built")))
    }

    /// Admit `need` more bytes into `group` or say the group is full.  The
    /// bytes count against the ceiling until the reservation is dropped, so
    /// concurrent uploads cannot jointly pass it.  Blocking.
    pub(super) fn reserve_group_bytes(
        &self,
        group: &GroupId,
        ceiling: u64,
        need: u64,
    ) -> Result<Option<Reservation>, Refusal> {
        let state = self.group_state()?;
        let mut reserved = state.reserved.lock().map_err(|_| Refusal::unavailable())?;
        let total = self.with_holdings(group, |holdings| holdings.total())?;
        let current = reserved.get(group).copied().unwrap_or(0);
        if need > 0 && total.saturating_add(current).saturating_add(need) > ceiling {
            return Ok(None);
        }
        if need > 0 {
            *reserved.entry(group.clone()).or_default() += need;
        }
        Ok(Some(Reservation {
            grants: self.clone(),
            group: group.clone(),
            bytes: need,
        }))
    }

    /// Spend a delete token id.  `false` when it was spent already.
    pub(super) fn spend_group_token(
        &self,
        token_id: &str,
        expires_at: u64,
    ) -> Result<bool, Refusal> {
        let state = self.group_state()?;
        let db = state.db.lock().map_err(|_| Refusal::unavailable())?;
        group_db::spend_token(&db, token_id, expires_at).map_err(|_| Refusal::unavailable())
    }

    pub(super) fn group_writes(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        self.inner.group.get().map(|state| state.writes.clone())
    }
}
