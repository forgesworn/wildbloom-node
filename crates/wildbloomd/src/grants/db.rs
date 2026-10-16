//! Private SQLite state for device grants.  Never shared with the core store.
use rusqlite::{Connection, params};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GrantRow {
    pub device: String,
    pub recovery: String,
    pub issuer: String,
    pub byte_limit: u64,
    pub until: u64,
    pub granted_at: u64,
    pub last_event_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Member {
    pub issuer: String,
    pub byte_limit: u64,
}

#[derive(Debug, Clone)]
pub(super) struct MovedClaim {
    pub hash: String,
    pub owner: String,
    pub size: u64,
    pub declared_type: String,
    pub class: Option<String>,
}

#[derive(Debug, Default)]
pub(super) struct Rows {
    pub grants: BTreeMap<String, GrantRow>,
    pub members: BTreeMap<String, Member>,
    /// `created_at` of revocations for devices that had no grant yet.
    pub markers: BTreeMap<String, u64>,
}

fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

pub(super) fn initialise(connection: &Connection) -> rusqlite::Result<i64> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > 1 {
        return Ok(version);
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
         CREATE TABLE IF NOT EXISTS revocation_markers (
            device TEXT PRIMARY KEY NOT NULL,
            last_event_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS moved_claims (
            pubkey TEXT NOT NULL,
            hash TEXT NOT NULL,
            owner TEXT NOT NULL,
            size INTEGER NOT NULL CHECK (size >= 0),
            declared_type TEXT NOT NULL,
            class TEXT,
            PRIMARY KEY (pubkey, hash)
         );
         CREATE TABLE IF NOT EXISTS used_events (
            event_id TEXT PRIMARY KEY NOT NULL,
            expires_at INTEGER NOT NULL
         );
         PRAGMA user_version = 1;
         COMMIT;",
    )?;
    Ok(1)
}

pub(super) fn read_rows(connection: &Connection) -> rusqlite::Result<Rows> {
    let mut rows = Rows::default();
    let mut statement = connection.prepare(
        "SELECT device, recovery, issuer, byte_limit, until, granted_at, last_event_at, revoked_at
         FROM device_grants",
    )?;
    for row in statement.query_map([], |row| {
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
    })? {
        let row = row?;
        rows.grants.insert(row.device.clone(), row);
    }
    let mut statement =
        connection.prepare("SELECT pubkey, issuer, byte_limit FROM core_members")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            Member {
                issuer: row.get(1)?,
                byte_limit: row_u64(row, 2)?,
            },
        ))
    })? {
        let (key, member) = row?;
        rows.members.insert(key, member);
    }
    let mut statement =
        connection.prepare("SELECT device, last_event_at FROM revocation_markers")?;
    for row in statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row_u64(row, 1)?)))? {
        let (device, at) = row?;
        rows.markers.insert(device, at);
    }
    Ok(rows)
}

pub(super) fn write_grant(connection: &Connection, row: &GrantRow) -> rusqlite::Result<()> {
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

pub(super) fn delete_grant(connection: &Connection, device: &str) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM device_grants WHERE device = ?1", [device])?;
    Ok(())
}

pub(super) fn write_member(
    connection: &Connection,
    key: &str,
    issuer: &str,
    byte_limit: u64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO core_members (pubkey, issuer, byte_limit) VALUES (?1, ?2, ?3)
         ON CONFLICT(pubkey) DO UPDATE SET issuer = excluded.issuer, byte_limit = excluded.byte_limit",
        params![key, issuer, int(byte_limit)],
    )?;
    Ok(())
}

pub(super) fn delete_member(connection: &Connection, key: &str) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM core_members WHERE pubkey = ?1", [key])?;
    Ok(())
}

pub(super) fn write_marker(
    connection: &Connection,
    device: &str,
    last_event_at: u64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO revocation_markers (device, last_event_at) VALUES (?1, ?2)
         ON CONFLICT(device) DO UPDATE SET last_event_at = excluded.last_event_at",
        params![device, int(last_event_at)],
    )?;
    Ok(())
}

/// Insert a single-use event id; `false` when it was already used.
pub(super) fn consume_event(
    connection: &Connection,
    event_id: &str,
    expires_at: u64,
) -> rusqlite::Result<bool> {
    Ok(connection.execute(
        "INSERT OR IGNORE INTO used_events (event_id, expires_at) VALUES (?1, ?2)",
        params![event_id, int(expires_at)],
    )? == 1)
}

pub(super) fn prune_used_events(connection: &Connection, now: u64) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM used_events WHERE expires_at < ?1", [int(now)])?;
    Ok(())
}

pub(super) fn record_move(
    connection: &Connection,
    key: &str,
    claim: &MovedClaim,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO moved_claims (pubkey, hash, owner, size, declared_type, class)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(pubkey, hash) DO UPDATE SET owner = excluded.owner, size = excluded.size,
            declared_type = excluded.declared_type, class = excluded.class",
        params![
            key,
            claim.hash,
            claim.owner,
            int(claim.size),
            claim.declared_type,
            claim.class
        ],
    )?;
    Ok(())
}

pub(super) fn forget_move(connection: &Connection, key: &str, hash: &str) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM moved_claims WHERE pubkey = ?1 AND hash = ?2",
        params![key, hash],
    )?;
    Ok(())
}

/// One page of a key's recorded moves, in hash order after `after`.
pub(super) fn moved_page(
    connection: &Connection,
    key: &str,
    after: &str,
    limit: usize,
) -> rusqlite::Result<Vec<MovedClaim>> {
    let mut statement = connection.prepare(
        "SELECT hash, owner, size, declared_type, class FROM moved_claims
         WHERE pubkey = ?1 AND hash > ?2 ORDER BY hash LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![key, after, i64::try_from(limit).unwrap_or(i64::MAX)],
        |row| {
            Ok(MovedClaim {
                hash: row.get(0)?,
                owner: row.get(1)?,
                size: row_u64(row, 2)?,
                declared_type: row.get(3)?,
                class: row.get(4)?,
            })
        },
    )?;
    rows.collect()
}

pub(super) fn moved_keys(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare("SELECT DISTINCT pubkey FROM moved_claims")?;
    let rows = statement.query_map([], |row| row.get(0))?;
    rows.collect()
}
