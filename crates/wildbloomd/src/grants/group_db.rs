//! Private SQLite state for group grants (`group-grants.sqlite3`).
//!
//! Separate from the device grant database so that group mode can be turned
//! on and off without touching device grants.  It holds grant rows by keeper
//! and grant id, reset floors, the key to group map and the spent delete
//! token ids.  Back it up with the store: a lost file forgets revocations.
use rusqlite::Connection;
use std::collections::BTreeMap;

pub(super) const SCHEMA_VERSION: i64 = 1;

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

#[derive(Debug, Default)]
pub(super) struct GroupRows {
    pub keys: BTreeMap<String, GroupKey>,
}

#[cfg(test)]
fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

const TABLES: &str = "
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
    let mut statement =
        connection.prepare("SELECT device, keeper, room, byte_limit FROM group_keys")?;
    for row in statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            GroupKey {
                keeper: row.get(1)?,
                room: row.get(2)?,
                byte_limit: match row.get::<_, Option<i64>>(3)? {
                    Some(_) => Some(row_u64(row, 3)?),
                    None => None,
                },
            },
        ))
    })? {
        let (device, key) = row?;
        rows.keys.insert(device, key);
    }
    Ok(rows)
}

#[cfg(test)]
pub(super) fn write_key(
    connection: &Connection,
    device: &str,
    key: &GroupKey,
) -> rusqlite::Result<()> {
    use rusqlite::params;
    connection.execute(
        "INSERT INTO group_keys (device, keeper, room, byte_limit) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(device) DO UPDATE SET byte_limit = excluded.byte_limit",
        params![device, key.keeper, key.room, key.byte_limit.map(int)],
    )?;
    Ok(())
}
