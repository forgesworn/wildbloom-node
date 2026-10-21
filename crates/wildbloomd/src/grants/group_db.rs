//! Private SQLite state for group grants (`group-grants.sqlite3`).
//!
//! Separate from the device grant database so that group mode can be turned
//! on and off without touching device grants.  It holds grant rows by keeper
//! and grant id, reset floors, the key to group map and the spent delete
//! token ids.  Back it up with the store: a lost file forgets revocations.
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

pub(super) const SCHEMA_VERSION: i64 = 1;

/// A device's grant id at a node: the keeper that signed it and the id.
pub(super) type GrantId = (String, String);
/// One group at a node: an enrolled keeper and a room id.
pub(super) type GroupId = (String, String);

/// What a removed device may still do, and for how long: delete its own
/// claims for seven days after its grant ended (decision O4).
pub(super) const SELF_DELETE_GRACE: u64 = 7 * 24 * 60 * 60;
/// How long a reset floor is kept after its `created_at`: no event the
/// floor could refuse can still be unexpired after that.
pub(super) const FLOOR_RETENTION: u64 = super::group_event::MAX_GRANT_SECONDS;

/// A device key's group at this node.  A key joins the group of the first
/// active grant that names it and stays there: its claims belong to the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupKey {
    pub keeper: String,
    pub room: String,
    /// The core friend ceiling for the key: the `bytes` of the newest active
    /// grant with an `upload` scope.  `None` while the key never had one.
    pub byte_limit: Option<u64>,
}

/// The newest accepted event for one grant id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GroupGrantRow {
    pub keeper: String,
    pub grant_id: String,
    pub room: String,
    pub device: String,
    pub server: String,
    pub scopes: u8,
    pub bytes: Option<u64>,
    /// `false` once revoked: terminal for the id.
    pub active: bool,
    /// `created_at` of the newest accepted event.
    pub created_at: u64,
    /// `expiration` of the newest accepted event: the end of the grant.
    pub expiration: u64,
    /// The latest `expiration` any accepted event for the id carried.
    pub retain_until: u64,
    /// `created_at` of the first revocation.
    pub revoked_at: Option<u64>,
    pub event_id: String,
}

/// A reset: every grant of the room that is not newer ended at `created_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Floor {
    pub created_at: u64,
    pub expires_at: u64,
    pub event_id: String,
}

#[derive(Debug, Default)]
pub(super) struct GroupRows {
    pub grants: BTreeMap<GrantId, GroupGrantRow>,
    pub floors: BTreeMap<GroupId, Floor>,
    pub keys: BTreeMap<String, GroupKey>,
    by_device: BTreeMap<String, Vec<GrantId>>,
}

fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn optional_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    match row.get::<_, Option<i64>>(index)? {
        Some(_) => Ok(Some(row_u64(row, index)?)),
        None => Ok(None),
    }
}

impl GroupRows {
    fn index(&mut self) {
        self.by_device.clear();
        for (id, row) in &self.grants {
            self.by_device
                .entry(row.device.clone())
                .or_default()
                .push(id.clone());
        }
    }

    pub fn rows_for<'a>(&'a self, device: &str) -> impl Iterator<Item = &'a GroupGrantRow> {
        self.by_device
            .get(device)
            .into_iter()
            .flatten()
            .filter_map(|id| self.grants.get(id))
    }

    fn covered(&self, row: &GroupGrantRow) -> bool {
        self.floors
            .get(&(row.keeper.clone(), row.room.clone()))
            .is_some_and(|floor| row.created_at <= floor.created_at)
    }

    /// Active: the newest event says `active`, `expiration` is ahead, it is
    /// newer than any reset floor, and its keeper is still enrolled.
    pub fn is_active(
        &self,
        row: &GroupGrantRow,
        enrolled: impl Fn(&str) -> bool,
        now: u64,
    ) -> bool {
        row.active && row.expiration > now && !self.covered(row) && enrolled(&row.keeper)
    }

    /// The first of: revocation, covering reset, expiration.  `None` while
    /// the grant is still running.
    pub fn ended_at(&self, row: &GroupGrantRow, now: u64) -> Option<u64> {
        let floor = self
            .floors
            .get(&(row.keeper.clone(), row.room.clone()))
            .filter(|floor| row.created_at <= floor.created_at)
            .map(|floor| floor.created_at);
        let expired = (row.expiration <= now).then_some(row.expiration);
        [row.revoked_at, floor, expired].into_iter().flatten().min()
    }

    /// The one active grant at this node that names `device`.
    pub fn active_for<'a>(
        &'a self,
        device: &str,
        enrolled: &impl Fn(&str) -> bool,
        now: u64,
    ) -> Option<&'a GroupGrantRow> {
        self.rows_for(device)
            .find(|row| self.is_active(row, enrolled, now))
    }

    /// Whether `device` ended a grant with `scope` less than seven days ago.
    pub fn in_grace(
        &self,
        device: &str,
        scope: u8,
        enrolled: &impl Fn(&str) -> bool,
        now: u64,
    ) -> bool {
        self.rows_for(device).any(|row| {
            row.scopes & scope != 0
                && enrolled(&row.keeper)
                && self
                    .ended_at(row, now)
                    .is_some_and(|end| now < end.saturating_add(SELF_DELETE_GRACE))
        })
    }
}

const TABLES: &str = "
     CREATE TABLE IF NOT EXISTS group_grants (
        keeper TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        room TEXT NOT NULL,
        device TEXT NOT NULL,
        server TEXT NOT NULL,
        scopes INTEGER NOT NULL,
        bytes INTEGER CHECK (bytes IS NULL OR bytes > 0),
        active INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expiration INTEGER NOT NULL,
        retain_until INTEGER NOT NULL,
        revoked_at INTEGER,
        event_id TEXT NOT NULL,
        PRIMARY KEY (keeper, grant_id)
     );
     CREATE INDEX IF NOT EXISTS group_grants_device ON group_grants(device);
     CREATE TABLE IF NOT EXISTS group_floors (
        keeper TEXT NOT NULL,
        room TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        event_id TEXT NOT NULL,
        PRIMARY KEY (keeper, room)
     );
     CREATE TABLE IF NOT EXISTS group_keys (
        device TEXT PRIMARY KEY NOT NULL,
        keeper TEXT NOT NULL,
        room TEXT NOT NULL,
        byte_limit INTEGER CHECK (byte_limit IS NULL OR byte_limit > 0)
     );
     CREATE TABLE IF NOT EXISTS used_events (
        event_id TEXT PRIMARY KEY NOT NULL,
        expires_at INTEGER NOT NULL
     );";

/// Create the schema.  Returns the resulting version, or the unsupported
/// version found.
pub(super) fn initialise(connection: &Connection) -> rusqlite::Result<i64> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Ok(version);
    }
    connection.execute_batch("PRAGMA journal_mode = WAL;")?;
    let tx = connection.unchecked_transaction()?;
    tx.execute_batch(TABLES)?;
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    tx.commit()?;
    Ok(SCHEMA_VERSION)
}

pub(super) fn read_rows(connection: &Connection) -> rusqlite::Result<GroupRows> {
    let mut rows = GroupRows::default();
    let mut statement = connection.prepare(
        "SELECT keeper, grant_id, room, device, server, scopes, bytes, active, created_at,
                expiration, retain_until, revoked_at, event_id
         FROM group_grants",
    )?;
    for row in statement.query_map([], |row| {
        Ok(GroupGrantRow {
            keeper: row.get(0)?,
            grant_id: row.get(1)?,
            room: row.get(2)?,
            device: row.get(3)?,
            server: row.get(4)?,
            scopes: u8::try_from(row_u64(row, 5)?)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, 0))?,
            bytes: optional_u64(row, 6)?,
            active: row.get(7)?,
            created_at: row_u64(row, 8)?,
            expiration: row_u64(row, 9)?,
            retain_until: row_u64(row, 10)?,
            revoked_at: optional_u64(row, 11)?,
            event_id: row.get(12)?,
        })
    })? {
        let row = row?;
        rows.grants
            .insert((row.keeper.clone(), row.grant_id.clone()), row);
    }
    rows.index();
    let mut statement = connection
        .prepare("SELECT keeper, room, created_at, expires_at, event_id FROM group_floors")?;
    for row in statement.query_map([], |row| {
        Ok((
            (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
            Floor {
                created_at: row_u64(row, 2)?,
                expires_at: row_u64(row, 3)?,
                event_id: row.get(4)?,
            },
        ))
    })? {
        let (id, floor) = row?;
        rows.floors.insert(id, floor);
    }
    let mut statement =
        connection.prepare("SELECT device, keeper, room, byte_limit FROM group_keys")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            GroupKey {
                keeper: row.get(1)?,
                room: row.get(2)?,
                byte_limit: optional_u64(row, 3)?,
            },
        ))
    })? {
        let (device, key) = row?;
        rows.keys.insert(device, key);
    }
    Ok(rows)
}

pub(super) fn write_grant(connection: &Connection, row: &GroupGrantRow) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO group_grants
            (keeper, grant_id, room, device, server, scopes, bytes, active, created_at,
             expiration, retain_until, revoked_at, event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(keeper, grant_id) DO UPDATE SET
            scopes = excluded.scopes, bytes = excluded.bytes, active = excluded.active,
            created_at = excluded.created_at, expiration = excluded.expiration,
            retain_until = excluded.retain_until, revoked_at = excluded.revoked_at,
            event_id = excluded.event_id",
        params![
            row.keeper,
            row.grant_id,
            row.room,
            row.device,
            row.server,
            row.scopes,
            row.bytes.map(int),
            row.active,
            int(row.created_at),
            int(row.expiration),
            int(row.retain_until),
            row.revoked_at.map(int),
            row.event_id,
        ],
    )?;
    Ok(())
}

pub(super) fn write_floor(
    connection: &Connection,
    group: &GroupId,
    floor: &Floor,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO group_floors (keeper, room, created_at, expires_at, event_id)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(keeper, room) DO UPDATE SET created_at = excluded.created_at,
            expires_at = excluded.expires_at, event_id = excluded.event_id",
        params![
            group.0,
            group.1,
            int(floor.created_at),
            int(floor.expires_at),
            floor.event_id
        ],
    )?;
    Ok(())
}

pub(super) fn write_key(
    connection: &Connection,
    device: &str,
    key: &GroupKey,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO group_keys (device, keeper, room, byte_limit) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(device) DO UPDATE SET byte_limit = excluded.byte_limit",
        params![device, key.keeper, key.room, key.byte_limit.map(int)],
    )?;
    Ok(())
}

/// Drop what no event or token could still need: a grant id once every
/// version and the seven-day delete grace have passed, a floor 90 days after
/// its reset, a spent token id once the token has expired.  Device to group
/// membership is never pruned: a key's claims stay with its group.
pub(super) fn prune(connection: &Connection, now: u64) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM group_grants WHERE retain_until < ?1",
        [int(now.saturating_sub(SELF_DELETE_GRACE))],
    )?;
    connection.execute("DELETE FROM group_floors WHERE expires_at < ?1", [int(now)])?;
    connection.execute("DELETE FROM used_events WHERE expires_at < ?1", [int(now)])?;
    Ok(())
}

impl GroupRows {
    /// The group a device key belongs to at this node: where its first
    /// active grant put it, or where a retained grant row names it.
    pub fn group_of(&self, device: &str) -> Option<GroupId> {
        self.keys
            .get(device)
            .map(|key| (key.keeper.clone(), key.room.clone()))
            .or_else(|| {
                self.rows_for(device)
                    .next()
                    .map(|row| (row.keeper.clone(), row.room.clone()))
            })
    }

    /// Every device key of one group.
    pub fn devices_of(&self, group: &GroupId) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(_, key)| (&key.keeper, &key.room) == (&group.0, &group.1))
            .map(|(device, _)| device.clone())
            .collect()
    }
}

/// Record a single-use token id; `false` when it was already spent.
pub(super) fn spend_token(
    connection: &Connection,
    token_id: &str,
    expires_at: u64,
) -> rusqlite::Result<bool> {
    super::db::consume_event(connection, token_id, expires_at)
}
