//! Group mode: a closed storage node for the devices of one or more groups.
//!
//! A group is one enrolled keeper key and one room id (`docs/GROUP-GRANTS.md`).
//! Keeper-signed kind 27541 grants name the device keys that may use the node.
//! Group keys ride the core friend-grant machinery (a core grant id per group
//! and the far-future sentinel expiry that device grants use); the real expiry
//! and scopes are enforced by a gate in front of the core router.
use super::{
    CORE_GRANT_SENTINEL, Grants, GrantsError,
    event::is_canonical_key,
    group_db::{self, GroupRows},
};
use rusqlite::Connection;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use wildbloom_core::FriendGrant;

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
}

pub(super) struct GroupState {
    #[allow(dead_code)] // read by the event route and the gate
    pub db: Mutex<Connection>,
    pub enrolments: BTreeMap<String, Enrolment>,
    pub snapshot: RwLock<Arc<GroupRows>>,
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
            snapshot: RwLock::new(Arc::new(rows)),
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
