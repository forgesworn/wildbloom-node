//! Private SQLite state for device grants.  Never shared with the core store.
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;

pub(super) const SCHEMA_VERSION: i64 = 2;

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
    /// When the key last joined the core's trusted set.  Claims it made while
    /// a member are newer than this; older guest claims predate the grant.
    pub since: u64,
}

#[derive(Debug, Clone)]
pub(super) struct MovedClaim {
    pub hash: String,
    pub owner: String,
    pub size: u64,
    pub declared_type: String,
    pub class: Option<String>,
    /// The owner already claimed the blob before the move.
    pub independent: bool,
    /// The owner wrote the blob itself around or after the move.
    pub adopted: bool,
    pub moved_at: u64,
}

impl MovedClaim {
    /// The owner claim exists only because of the move, so it may be dropped
    /// when the key takes the blob back or deletes it.
    pub fn owner_claim_is_ours(&self) -> bool {
        !self.independent && !self.adopted
    }
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

const TABLES: &str = "
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
        byte_limit INTEGER NOT NULL CHECK (byte_limit > 0),
        since INTEGER NOT NULL DEFAULT 0
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
        independent INTEGER NOT NULL,
        adopted INTEGER NOT NULL,
        moved_at INTEGER NOT NULL,
        PRIMARY KEY (pubkey, hash)
     );
     CREATE INDEX IF NOT EXISTS moved_claims_owner ON moved_claims(owner, hash);
     CREATE TABLE IF NOT EXISTS owner_writes (
        owner TEXT NOT NULL,
        hash TEXT NOT NULL,
        at INTEGER NOT NULL,
        PRIMARY KEY (owner, hash)
     );
     CREATE TABLE IF NOT EXISTS used_events (
        event_id TEXT PRIMARY KEY NOT NULL,
        expires_at INTEGER NOT NULL
     );";

/// Create or migrate the schema.  Returns the resulting version, or the
/// unsupported version found, and whether recorded moves were discarded.
pub(super) fn initialise(connection: &Connection) -> rusqlite::Result<(i64, bool)> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Ok((version, false));
    }
    connection.execute_batch("PRAGMA journal_mode = WAL;")?;
    let mut discarded = false;
    let tx = connection.unchecked_transaction()?;
    if version == 1 {
        // Unreleased preview layouts.  Their move records cannot be trusted
        // to carry the ownership flags, so they are dropped: the owner keeps
        // those claims, and they are simply not handed back.
        discarded = tx
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE name = 'moved_claims')
                    AND EXISTS (SELECT 1 FROM moved_claims)",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);
        tx.execute_batch("DROP TABLE IF EXISTS moved_claims;")?;
        let has_since: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM pragma_table_info('core_members') WHERE name = 'since')",
            [],
            |row| row.get(0),
        )?;
        if !has_since {
            tx.execute_batch(
                "ALTER TABLE core_members ADD COLUMN since INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
    }
    tx.execute_batch(TABLES)?;
    tx.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
    tx.commit()?;
    Ok((SCHEMA_VERSION, discarded))
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
        connection.prepare("SELECT pubkey, issuer, byte_limit, since FROM core_members")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            Member {
                issuer: row.get(1)?,
                byte_limit: row_u64(row, 2)?,
                since: row_u64(row, 3)?,
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

/// Insert or update a member.  `since` is set only when the key joins.
pub(super) fn write_member(
    connection: &Connection,
    key: &str,
    member: &Member,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO core_members (pubkey, issuer, byte_limit, since) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(pubkey) DO UPDATE SET issuer = excluded.issuer, byte_limit = excluded.byte_limit",
        params![key, member.issuer, int(member.byte_limit), int(member.since)],
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

pub(super) fn prune(
    connection: &Connection,
    now: u64,
    owner_write_window: u64,
) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM used_events WHERE expires_at < ?1", [int(now)])?;
    connection.execute(
        "DELETE FROM owner_writes WHERE at < ?1",
        [int(now.saturating_sub(owner_write_window))],
    )?;
    Ok(())
}

/// Record that an owner is writing `hash` itself.  A move recorded later
/// within the window, or already recorded, then never drops that claim.
pub(super) fn mark_owner_write(
    connection: &Connection,
    owner: &str,
    hash: &str,
    now: u64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO owner_writes (owner, hash, at) VALUES (?1, ?2, ?3)
         ON CONFLICT(owner, hash) DO UPDATE SET at = excluded.at",
        params![owner, hash, int(now)],
    )?;
    connection.execute(
        "UPDATE moved_claims SET adopted = 1 WHERE owner = ?1 AND hash = ?2",
        params![owner, hash],
    )?;
    Ok(())
}

pub(super) fn recent_owner_write(
    connection: &Connection,
    owner: &str,
    hash: &str,
    since: u64,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM owner_writes WHERE owner = ?1 AND hash = ?2 AND at >= ?3)",
        params![owner, hash, int(since)],
        |row| row.get(0),
    )
}

fn moved_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MovedClaim> {
    Ok(MovedClaim {
        hash: row.get(0)?,
        owner: row.get(1)?,
        size: row_u64(row, 2)?,
        declared_type: row.get(3)?,
        class: row.get(4)?,
        independent: row.get(5)?,
        adopted: row.get(6)?,
        moved_at: row_u64(row, 7)?,
    })
}

const MOVED_COLUMNS: &str =
    "hash, owner, size, declared_type, class, independent, adopted, moved_at";

pub(super) fn moved_row(
    connection: &Connection,
    key: &str,
    hash: &str,
) -> rusqlite::Result<Option<MovedClaim>> {
    connection
        .query_row(
            &format!("SELECT {MOVED_COLUMNS} FROM moved_claims WHERE pubkey = ?1 AND hash = ?2"),
            params![key, hash],
            moved_from_row,
        )
        .optional()
}

/// Record a move before it happens; an existing record keeps its flags.
pub(super) fn insert_move(
    connection: &Connection,
    key: &str,
    claim: &MovedClaim,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO moved_claims
            (pubkey, hash, owner, size, declared_type, class, independent, adopted, moved_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            key,
            claim.hash,
            claim.owner,
            int(claim.size),
            claim.declared_type,
            claim.class,
            claim.independent,
            claim.adopted,
            int(claim.moved_at)
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

/// One page of a key's recorded moves to `owner`, in hash order after
/// `after`.  Moves to any other owner are parked and never read here.
pub(super) fn moved_page(
    connection: &Connection,
    key: &str,
    owner: &str,
    after: &str,
    limit: usize,
) -> rusqlite::Result<Vec<MovedClaim>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {MOVED_COLUMNS} FROM moved_claims
         WHERE pubkey = ?1 AND owner = ?2 AND hash > ?3 ORDER BY hash LIMIT ?4"
    ))?;
    let rows = statement.query_map(
        params![key, owner, after, i64::try_from(limit).unwrap_or(i64::MAX)],
        moved_from_row,
    )?;
    rows.collect()
}
