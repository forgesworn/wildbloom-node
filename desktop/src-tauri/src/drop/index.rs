//! The private SQLite file index: one row per kept file, the shared copies,
//! deletions waiting for a node, and small settings.  It holds no secret: keys
//! live in the OS keychain and in the sealed key list.  The database file sits
//! in a private directory and is itself private (0600 on Unix).

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

/// Where a file's local (this computer) copy is.
pub mod local {
    /// Being encrypted from the original.
    pub const ENCRYPTING: &str = "encrypting";
    /// Encrypted into the outbox; not yet on the local node.
    pub const PENDING: &str = "pending";
    pub const OK: &str = "ok";
    /// A check found it gone from the local node.
    pub const MISSING: &str = "missing";
    /// Being copied back from the online node (restore or Copy back).
    pub const RESTORING: &str = "restoring";
    /// The original could not be read or encrypted.
    pub const UNREADABLE: &str = "unreadable";
    /// A folder file that cannot be kept (too big, or an unusable name or
    /// path).  It has no key and no envelope and is never in the key list;
    /// `note` says why.
    pub const NOT_KEPT: &str = "not_kept";
}

/// Where a file's online copy is.
pub mod online {
    /// No online node is set up.
    pub const NONE: &str = "none";
    pub const QUEUED: &str = "queued";
    pub const COPYING: &str = "copying";
    pub const OK: &str = "ok";
    /// Waiting for the online node (unreachable, or approval not active).
    pub const WAITING: &str = "waiting";
    pub const FAILED: &str = "failed";
    /// A check found it gone or the wrong size.
    pub const MISSING: &str = "missing";
    pub const FULL: &str = "full";
}

/// A shared copy's lifecycle.
pub mod share {
    /// Uploaded for an open Share sheet; nothing sent yet.
    pub const OPEN: &str = "open";
    pub const SENT: &str = "sent";
    /// Stop sharing (or the 24 h deletion) is waiting for the online node.
    pub const STOP_PENDING: &str = "stop_pending";
    /// Deleted; the row shows "sharing ended" for 24 hours.
    pub const ENDED: &str = "ended";
    /// The approval ended before the copy could be deleted: the node moved
    /// it to its owner, so only the owner can remove it now.
    pub const OWNER_ONLY: &str = "owner_only";
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRecord {
    pub id: String,
    pub name: String,
    pub media_type: String,
    pub bytes: u64,
    pub added: u64,
    pub plain_sha256: String,
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub local: String,
    pub online: String,
    pub attempts: u32,
    pub next_attempt: u64,
    /// The link to a file on disk: the absolute path as it really is, and the
    /// size and nanosecond mtime last seen or written.
    pub watch_path: Option<String>,
    pub watch_size: Option<u64>,
    pub watch_mtime: Option<i64>,
    /// The key list entry's relative path, frozen when the row is inserted;
    /// equal to `name` for a version 1 entry.
    pub path: String,
    /// The entry's `prev` (32 hex), frozen.
    pub prev: Option<String>,
    /// The entry's `from` (the computer name), frozen; empty if unknown.
    pub origin: String,
    /// The entry's `plain` (64 hex), frozen; empty if unknown.  Unlike
    /// `plain_sha256`, which is learned for duplicate detection, it never
    /// changes.
    pub entry_plain: String,
    /// Why a `not_kept` row is not kept.
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareRecord {
    pub file_id: String,
    /// The shared copy's own id: its key is the keychain's file key for it.
    pub share_id: String,
    /// The online node origin the shared copy was uploaded to.
    pub origin: String,
    pub sha256: String,
    pub size: u64,
    pub state: String,
    pub sent_at: Option<u64>,
    pub delete_at: Option<u64>,
    pub ended_at: Option<u64>,
    /// When the recipient's page confirmed the download, if it did.
    pub downloaded_at: Option<u64>,
}

/// A deletion still owed to a node.  `node` is `local` or the online node's
/// origin at the time the deletion was queued (never "whatever is configured
/// now").  `signer` is `device` or `recovery`.  It is not sent before
/// `not_before` (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDelete {
    pub node: String,
    pub sha256: String,
    pub signer: String,
    pub not_before: u64,
    /// The file a shared copy belonged to, so a copy only the node's owner can
    /// remove is shown on that file's row.
    pub file_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("the Drop file index failed: {0}")]
    Sql(String),
    #[error("the Drop file index directory is not private")]
    Private,
    /// An index written by another version of this app's schema.  Drop
    /// refuses it rather than guessing at missing node origins.
    #[error(
        "the Drop file index has schema version {0}, but this app needs version {SCHEMA_VERSION}; move the drop folder in the app data directory aside to start again"
    )]
    Version(i64),
}

/// The schema this build reads and writes.  Version 1 (test builds only)
/// lacked node origins on deletions and shares, so it is refused.  Versions 2
/// to 4 are migrated in place (see `MIGRATE_2_TO_3`, `MIGRATE_3_TO_4` and
/// `MIGRATE_4_TO_5`).
pub const SCHEMA_VERSION: i64 = 5;

impl From<rusqlite::Error> for IndexError {
    fn from(error: rusqlite::Error) -> Self {
        // SQLite messages describe the statement, never the bound values.
        Self::Sql(error.to_string())
    }
}

pub struct Index {
    db: Mutex<Connection>,
}

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Index")
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  media_type TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  added INTEGER NOT NULL,
  plain_sha256 TEXT NOT NULL,
  sha256 TEXT,
  size INTEGER,
  local TEXT NOT NULL,
  online TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL DEFAULT 0,
  watch_path TEXT,
  watch_size INTEGER,
  watch_mtime INTEGER,
  path TEXT NOT NULL DEFAULT '',
  prev TEXT,
  origin TEXT NOT NULL DEFAULT '',
  entry_plain TEXT NOT NULL DEFAULT '',
  note TEXT
);
CREATE INDEX IF NOT EXISTS files_plain ON files(plain_sha256);
CREATE TABLE IF NOT EXISTS shares (
  file_id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  state TEXT NOT NULL,
  sent_at INTEGER,
  delete_at INTEGER,
  ended_at INTEGER,
  downloaded_at INTEGER
);
CREATE TABLE IF NOT EXISTS deletes (
  node TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  signer TEXT NOT NULL,
  not_before INTEGER NOT NULL DEFAULT 0,
  file_id TEXT,
  PRIMARY KEY (node, sha256, signer)
);
CREATE TABLE IF NOT EXISTS online_copies (
  file_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  PRIMARY KEY (file_id, origin)
);
CREATE TABLE IF NOT EXISTS stranded (
  file_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  origin TEXT NOT NULL,
  at INTEGER NOT NULL,
  PRIMARY KEY (file_id, sha256)
);
CREATE TABLE IF NOT EXISTS removed (
  id TEXT PRIMARY KEY,
  at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS watch_seen (
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  PRIMARY KEY (path, size, mtime)
);
CREATE TABLE IF NOT EXISTS kv (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS held (
  id TEXT PRIMARY KEY,
  at INTEGER NOT NULL
);
";

/// Schema 2 to 3, in one transaction: the frozen key list entry fields
/// (`path` is the name for every existing row, which is how a version 1
/// entry reads), a `note` for rows that are not kept, and the online copies
/// that Remove used to infer for rows this computer uploaded before it
/// recorded them.  Rows restored from the key list (`restored:` plain hash)
/// claim nothing until they upload, so they are not backfilled.
const MIGRATE_2_TO_3: &str = "
ALTER TABLE files ADD COLUMN path TEXT NOT NULL DEFAULT '';
ALTER TABLE files ADD COLUMN prev TEXT;
ALTER TABLE files ADD COLUMN origin TEXT NOT NULL DEFAULT '';
ALTER TABLE files ADD COLUMN entry_plain TEXT NOT NULL DEFAULT '';
ALTER TABLE files ADD COLUMN note TEXT;
UPDATE files SET path = name;
INSERT OR IGNORE INTO online_copies (file_id, origin)
  SELECT id, (SELECT value FROM kv WHERE key = 'online_url') FROM files
  WHERE online = 'ok' AND plain_sha256 NOT LIKE 'restored:%'
    AND (SELECT value FROM kv WHERE key = 'online_url') IS NOT NULL;
PRAGMA user_version = 3;
";

/// Schema 3 to 4, in one transaction: when a shared copy's recipient
/// confirmed the download.  Existing shares have no confirmation.
const MIGRATE_3_TO_4: &str = "
ALTER TABLE shares ADD COLUMN downloaded_at INTEGER;
PRAGMA user_version = 4;
";

/// Schema 4 to 5, in one transaction: rows whose deletion from the Wildbloom
/// folder is held back until the owner chooses (the mass-removal brake).  The
/// version matters as much as the table: a schema 4 build would see a held
/// row as a linked file that is missing and remove it everywhere, so it must
/// refuse this index instead.
const MIGRATE_4_TO_5: &str = "
CREATE TABLE held (id TEXT PRIMARY KEY, at INTEGER NOT NULL);
PRAGMA user_version = 5;
";

const SHARE_COLUMNS: &str =
    "file_id, share_id, origin, sha256, size, state, sent_at, delete_at, ended_at, downloaded_at";

const FILE_COLUMNS: &str = "id, name, media_type, bytes, added, plain_sha256, sha256, size, local, online, attempts, next_attempt, watch_path, watch_size, watch_mtime, path, prev, origin, entry_plain, note";

fn file_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FileRecord> {
    Ok(FileRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        media_type: row.get(2)?,
        bytes: row.get::<_, i64>(3)? as u64,
        added: row.get::<_, i64>(4)? as u64,
        plain_sha256: row.get(5)?,
        sha256: row.get(6)?,
        size: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        local: row.get(8)?,
        online: row.get(9)?,
        attempts: row.get::<_, i64>(10)? as u32,
        next_attempt: row.get::<_, i64>(11)? as u64,
        watch_path: row.get(12)?,
        watch_size: row.get::<_, Option<i64>>(13)?.map(|v| v as u64),
        watch_mtime: row.get(14)?,
        path: row.get(15)?,
        prev: row.get(16)?,
        origin: row.get(17)?,
        entry_plain: row.get(18)?,
        note: row.get(19)?,
    })
}

fn share_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShareRecord> {
    Ok(ShareRecord {
        file_id: row.get(0)?,
        share_id: row.get(1)?,
        origin: row.get(2)?,
        sha256: row.get(3)?,
        size: row.get::<_, i64>(4)? as u64,
        state: row.get(5)?,
        sent_at: row.get::<_, Option<i64>>(6)?.map(|v| v as u64),
        delete_at: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        ended_at: row.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        downloaded_at: row.get::<_, Option<i64>>(9)?.map(|v| v as u64),
    })
}

fn int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Index {
    /// Opens (creating if missing) `drop-index.sqlite` in the private `dir`.
    pub fn open(dir: &Path) -> Result<Self, IndexError> {
        wildbloom_private_state::private_directory(dir).map_err(|_| IndexError::Private)?;
        let path = dir.join("drop-index.sqlite");
        let mut db = Connection::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| IndexError::Private)?;
        }
        db.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA foreign_keys = ON;")?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                let tables: i64 = db.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
                    [],
                    |r| r.get(0),
                )?;
                if tables > 0 {
                    return Err(IndexError::Version(0));
                }
                db.execute_batch(SCHEMA)?;
                db.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
            }
            2..=4 => {
                let migration = db.transaction()?;
                if version <= 2 {
                    migration.execute_batch(MIGRATE_2_TO_3)?;
                }
                if version <= 3 {
                    migration.execute_batch(MIGRATE_3_TO_4)?;
                }
                migration.execute_batch(MIGRATE_4_TO_5)?;
                migration.commit()?;
                db.execute_batch(SCHEMA)?;
            }
            SCHEMA_VERSION => db.execute_batch(SCHEMA)?,
            other => return Err(IndexError::Version(other)),
        }
        Ok(Self { db: Mutex::new(db) })
    }

    fn with<T>(
        &self,
        work: impl FnOnce(&Connection) -> rusqlite::Result<T>,
    ) -> Result<T, IndexError> {
        let db = self
            .db
            .lock()
            .map_err(|_| IndexError::Sql("lock poisoned".into()))?;
        Ok(work(&db)?)
    }

    // ---------------------------------------------------------------- kv

    pub fn get(&self, key: &str) -> Result<Option<String>, IndexError> {
        self.with(|db| {
            db.query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
                .optional()
        })
    }

    pub fn get_u64(&self, key: &str) -> Result<Option<u64>, IndexError> {
        Ok(self.get(key)?.and_then(|v| v.parse().ok()))
    }

    pub fn get_bool(&self, key: &str) -> Result<bool, IndexError> {
        Ok(self.get(key)?.as_deref() == Some("1"))
    }

    pub fn set(&self, key: &str, value: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .map(|_| ())
        })
    }

    pub fn set_u64(&self, key: &str, value: u64) -> Result<(), IndexError> {
        self.set(key, &value.to_string())
    }

    pub fn set_bool(&self, key: &str, value: bool) -> Result<(), IndexError> {
        self.set(key, if value { "1" } else { "0" })
    }

    pub fn unset(&self, key: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute("DELETE FROM kv WHERE key = ?1", [key])
                .map(|_| ())
        })
    }

    // ------------------------------------------------------------- files

    pub fn insert_file(&self, file: &FileRecord) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                &format!("INSERT INTO files ({FILE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)"),
                params![
                    file.id,
                    file.name,
                    file.media_type,
                    int(file.bytes),
                    int(file.added),
                    file.plain_sha256,
                    file.sha256,
                    file.size.map(int),
                    file.local,
                    file.online,
                    file.attempts,
                    int(file.next_attempt),
                    file.watch_path,
                    file.watch_size.map(int),
                    file.watch_mtime,
                    file.path,
                    file.prev,
                    file.origin,
                    file.entry_plain,
                    file.note,
                ],
            )
            .map(|_| ())
        })
    }

    pub fn file(&self, id: &str) -> Result<Option<FileRecord>, IndexError> {
        self.with(|db| {
            db.query_row(
                &format!("SELECT {FILE_COLUMNS} FROM files WHERE id = ?1"),
                [id],
                file_from_row,
            )
            .optional()
        })
    }

    /// Every row, newest first.
    pub fn files(&self) -> Result<Vec<FileRecord>, IndexError> {
        self.with(|db| {
            let mut statement = db.prepare(&format!(
                "SELECT {FILE_COLUMNS} FROM files ORDER BY added DESC, id"
            ))?;
            statement
                .query_map([], file_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    pub fn file_by_plain_sha256(&self, sha256: &str) -> Result<Option<FileRecord>, IndexError> {
        self.with(|db| {
            db.query_row(
                &format!("SELECT {FILE_COLUMNS} FROM files WHERE plain_sha256 = ?1 LIMIT 1"),
                [sha256],
                file_from_row,
            )
            .optional()
        })
    }

    pub fn set_envelope(&self, id: &str, sha256: &str, size: u64) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "UPDATE files SET sha256 = ?2, size = ?3 WHERE id = ?1",
                params![id, sha256, int(size)],
            )
            .map(|_| ())
        })
    }

    pub fn set_media_type(&self, id: &str, media_type: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "UPDATE files SET media_type = ?2 WHERE id = ?1",
                params![id, media_type],
            )
            .map(|_| ())
        })
    }

    pub fn set_local(&self, id: &str, state: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "UPDATE files SET local = ?2 WHERE id = ?1",
                params![id, state],
            )
            .map(|_| ())
        })
    }

    pub fn set_online(&self, id: &str, state: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "UPDATE files SET online = ?2 WHERE id = ?1",
                params![id, state],
            )
            .map(|_| ())
        })
    }

    /// Records a failed online attempt and when the next one may run.
    pub fn set_backoff(
        &self,
        id: &str,
        attempts: u32,
        next_attempt: u64,
    ) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "UPDATE files SET attempts = ?2, next_attempt = ?3 WHERE id = ?1",
                params![id, attempts, int(next_attempt)],
            )
            .map(|_| ())
        })
    }

    /// Sets or clears the link to a file on disk: (absolute path, size,
    /// nanosecond mtime).
    pub fn set_link(&self, id: &str, link: Option<(String, u64, i64)>) -> Result<(), IndexError> {
        let (path, size, mtime) = match link {
            Some((path, size, mtime)) => (Some(path), Some(int(size)), Some(mtime)),
            None => (None, None, None),
        };
        self.with(|db| {
            db.execute(
                "UPDATE files SET watch_path = ?2, watch_size = ?3, watch_mtime = ?4 WHERE id = ?1",
                params![id, path, size, mtime],
            )
            .map(|_| ())
        })
    }

    /// The learned plaintext hash used to spot duplicates.
    pub fn set_plain_sha256(&self, id: &str, sha256: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "UPDATE files SET plain_sha256 = ?2 WHERE id = ?1",
                params![id, sha256],
            )
            .map(|_| ())
        })
    }

    /// Every row linked to a file on disk.
    pub fn linked_files(&self) -> Result<Vec<FileRecord>, IndexError> {
        self.with(|db| {
            let mut statement = db.prepare(&format!(
                "SELECT {FILE_COLUMNS} FROM files WHERE watch_path IS NOT NULL ORDER BY added DESC, id"
            ))?;
            statement
                .query_map([], file_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    pub fn delete_file(&self, id: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute("DELETE FROM shares WHERE file_id = ?1", [id])?;
            db.execute("DELETE FROM online_copies WHERE file_id = ?1", [id])?;
            db.execute("DELETE FROM stranded WHERE file_id = ?1", [id])?;
            db.execute("DELETE FROM held WHERE id = ?1", [id])?;
            db.execute("DELETE FROM files WHERE id = ?1", [id])
                .map(|_| ())
        })
    }

    /// Bytes this computer has stored on the online node (its own copies and
    /// shared copies), for the footer and settings.  A file counts only when
    /// this computer's device key claims it (an `online_copies` row): a file
    /// another computer put online is not charged to this one.
    pub fn online_used_bytes(&self) -> Result<u64, IndexError> {
        self.with(|db| {
            let files: i64 = db.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM files WHERE online = 'ok'
                 AND EXISTS (SELECT 1 FROM online_copies WHERE online_copies.file_id = files.id)",
                [],
                |r| r.get(0),
            )?;
            let shares: i64 = db.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM shares WHERE state IN ('open', 'sent', 'stop_pending')",
                [],
                |r| r.get(0),
            )?;
            Ok((files.max(0) + shares.max(0)) as u64)
        })
    }

    // ------------------------------------------------------------ shares

    pub fn share(&self, file_id: &str) -> Result<Option<ShareRecord>, IndexError> {
        self.with(|db| {
            db.query_row(
                &format!("SELECT {SHARE_COLUMNS} FROM shares WHERE file_id = ?1"),
                [file_id],
                share_from_row,
            )
            .optional()
        })
    }

    pub fn shares(&self) -> Result<Vec<ShareRecord>, IndexError> {
        self.with(|db| {
            let mut statement = db.prepare(&format!("SELECT {SHARE_COLUMNS} FROM shares"))?;
            statement
                .query_map([], share_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    pub fn put_share(&self, share: &ShareRecord) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                &format!("INSERT INTO shares ({SHARE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(file_id) DO UPDATE SET share_id = excluded.share_id, origin = excluded.origin, sha256 = excluded.sha256, size = excluded.size, state = excluded.state,
                 sent_at = excluded.sent_at, delete_at = excluded.delete_at, ended_at = excluded.ended_at, downloaded_at = excluded.downloaded_at"),
                params![
                    share.file_id,
                    share.share_id,
                    share.origin,
                    share.sha256,
                    int(share.size),
                    share.state,
                    share.sent_at.map(int),
                    share.delete_at.map(int),
                    share.ended_at.map(int),
                    share.downloaded_at.map(int),
                ],
            )
            .map(|_| ())
        })
    }

    pub fn delete_share(&self, file_id: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute("DELETE FROM shares WHERE file_id = ?1", [file_id])
                .map(|_| ())
        })
    }

    // ----------------------------------------------------------- deletes

    /// Queues a deletion on `node` (`local` or an online origin) that may be
    /// sent from `not_before` on.
    pub fn queue_delete(
        &self,
        node: &str,
        sha256: &str,
        signer: &str,
        not_before: u64,
    ) -> Result<(), IndexError> {
        self.queue_share_delete(node, sha256, signer, not_before, None)
    }

    /// As [`Self::queue_delete`], for a shared copy of `file_id`.
    pub fn queue_share_delete(
        &self,
        node: &str,
        sha256: &str,
        signer: &str,
        not_before: u64,
        file_id: Option<&str>,
    ) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT INTO deletes (node, sha256, signer, not_before, file_id) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(node, sha256, signer) DO UPDATE SET not_before = MIN(not_before, excluded.not_before),
                 file_id = COALESCE(excluded.file_id, file_id)",
                params![node, sha256, signer, int(not_before), file_id],
            )
            .map(|_| ())
        })
    }

    // ------------------------------------------------------ online copies

    /// Records that this computer's device key holds a copy of `file_id` on
    /// the online node at `origin`, so Remove reaches it after a node change.
    pub fn add_online_copy(&self, file_id: &str, origin: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT OR IGNORE INTO online_copies (file_id, origin) VALUES (?1, ?2)",
                params![file_id, origin],
            )
            .map(|_| ())
        })
    }

    pub fn online_copies(&self, file_id: &str) -> Result<Vec<String>, IndexError> {
        self.with(|db| {
            let mut statement =
                db.prepare("SELECT origin FROM online_copies WHERE file_id = ?1 ORDER BY origin")?;
            statement
                .query_map([file_id], |r| r.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    /// A shared copy of `file_id` that only the node's owner can now remove.
    pub fn add_stranded(
        &self,
        file_id: &str,
        sha256: &str,
        origin: &str,
        at: u64,
    ) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT OR REPLACE INTO stranded (file_id, sha256, origin, at) VALUES (?1, ?2, ?3, ?4)",
                params![file_id, sha256, origin, int(at)],
            )
            .map(|_| ())
        })
    }

    /// When the newest stranded copy of `file_id` was marked, if any.
    pub fn stranded_at(&self, file_id: &str) -> Result<Option<u64>, IndexError> {
        self.with(|db| {
            db.query_row(
                "SELECT MAX(at) FROM stranded WHERE file_id = ?1",
                [file_id],
                |r| r.get::<_, Option<i64>>(0),
            )
            .map(|v| v.map(|v| v.max(0) as u64))
        })
    }

    pub fn pending_deletes(&self) -> Result<Vec<PendingDelete>, IndexError> {
        self.with(|db| {
            let mut statement =
                db.prepare("SELECT node, sha256, signer, not_before, file_id FROM deletes")?;
            statement
                .query_map([], |r| {
                    Ok(PendingDelete {
                        node: r.get(0)?,
                        sha256: r.get(1)?,
                        signer: r.get(2)?,
                        not_before: r.get::<_, i64>(3)?.max(0) as u64,
                        file_id: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    pub fn finish_delete(&self, delete: &PendingDelete) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "DELETE FROM deletes WHERE node = ?1 AND sha256 = ?2 AND signer = ?3",
                params![delete.node, delete.sha256, delete.signer],
            )
            .map(|_| ())
        })
    }

    // -------------------------------------------------------- tombstones

    /// Records a removed file, so a key list rebuilt from the index keeps it
    /// removed even if the in-memory list was never loaded.
    pub fn add_tombstone(&self, id: &str, at: u64) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT INTO removed (id, at) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET at = MAX(at, excluded.at)",
                params![id, int(at)],
            )
            .map(|_| ())
        })
    }

    pub fn has_tombstone(&self, id: &str) -> Result<bool, IndexError> {
        self.with(|db| {
            db.query_row("SELECT 1 FROM removed WHERE id = ?1", [id], |_| Ok(()))
                .optional()
                .map(|v| v.is_some())
        })
    }

    pub fn tombstones(&self) -> Result<Vec<(String, u64)>, IndexError> {
        self.with(|db| {
            let mut statement = db.prepare("SELECT id, at FROM removed")?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get::<_, i64>(1)?.max(0) as u64)))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    /// Clears every tombstone (used when an unfinished set-up takes a
    /// different recovery key, whose key list starts empty).
    pub fn clear_tombstones(&self) -> Result<(), IndexError> {
        self.with(|db| db.execute("DELETE FROM removed", []).map(|_| ()))
    }

    // ------------------------------------------------------ held removals

    /// Holds back the deletion of each of `ids` from the Wildbloom folder
    /// until the owner chooses (the mass-removal brake).  One transaction, so
    /// a crash leaves all or none of them held.
    pub fn hold(&self, ids: &[String], at: u64) -> Result<(), IndexError> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| IndexError::Sql("lock poisoned".into()))?;
        let batch = db.transaction()?;
        for id in ids {
            batch.execute(
                "INSERT OR IGNORE INTO held (id, at) VALUES (?1, ?2)",
                params![id, int(at)],
            )?;
        }
        batch.commit()?;
        Ok(())
    }

    /// Every held row id.
    pub fn held(&self) -> Result<std::collections::HashSet<String>, IndexError> {
        self.with(|db| {
            let mut statement = db.prepare("SELECT id FROM held")?;
            statement
                .query_map([], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()
        })
    }

    pub fn is_held(&self, id: &str) -> Result<bool, IndexError> {
        self.with(|db| {
            db.query_row("SELECT 1 FROM held WHERE id = ?1", [id], |_| Ok(()))
                .optional()
                .map(|v| v.is_some())
        })
    }

    /// Ends one row's hold; the row stays.
    pub fn release_hold(&self, id: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute("DELETE FROM held WHERE id = ?1", [id])
                .map(|_| ())
        })
    }

    /// Ends every hold (the folder's links were cleared).
    pub fn clear_holds(&self) -> Result<(), IndexError> {
        self.with(|db| db.execute("DELETE FROM held", []).map(|_| ()))
    }

    // ------------------------------------------------------- watch folder

    /// Whether this exact version (path, size, mtime) of a watched file was
    /// already taken in, so a restart does not add it twice.
    pub fn watch_seen(&self, path: &str, size: u64, mtime: i64) -> Result<bool, IndexError> {
        self.with(|db| {
            db.query_row(
                "SELECT 1 FROM watch_seen WHERE path = ?1 AND size = ?2 AND mtime = ?3",
                params![path, int(size), mtime],
                |_| Ok(()),
            )
            .optional()
            .map(|v| v.is_some())
        })
    }

    pub fn mark_watch_seen(&self, path: &str, size: u64, mtime: i64) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT OR IGNORE INTO watch_seen (path, size, mtime) VALUES (?1, ?2, ?3)",
                params![path, int(size), mtime],
            )
            .map(|_| ())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_schemas_are_refused_and_new_ones_versioned() {
        let dir = tempfile::tempdir().unwrap();
        let drop = dir.path().join("drop");
        drop_index_at(&drop);
        let db = Connection::open(drop.join("drop-index.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        db.execute_batch("PRAGMA user_version = 1;").unwrap();
        drop_connection(db);
        assert!(matches!(Index::open(&drop), Err(IndexError::Version(1))));
        // Tables without a version are not silently adopted either.
        let bare = dir.path().join("bare");
        wildbloom_private_state::private_directory(&bare).unwrap();
        Connection::open(bare.join("drop-index.sqlite"))
            .unwrap()
            .execute_batch("CREATE TABLE files (id TEXT);")
            .unwrap();
        assert!(matches!(Index::open(&bare), Err(IndexError::Version(0))));
    }

    /// The version 2 schema as the installed build created it.
    const SCHEMA_2: &str = "
CREATE TABLE files (id TEXT PRIMARY KEY, name TEXT NOT NULL, media_type TEXT NOT NULL,
  bytes INTEGER NOT NULL, added INTEGER NOT NULL, plain_sha256 TEXT NOT NULL, sha256 TEXT,
  size INTEGER, local TEXT NOT NULL, online TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt INTEGER NOT NULL DEFAULT 0, watch_path TEXT, watch_size INTEGER, watch_mtime INTEGER);
CREATE INDEX files_plain ON files(plain_sha256);
CREATE TABLE shares (file_id TEXT PRIMARY KEY, share_id TEXT NOT NULL, origin TEXT NOT NULL,
  sha256 TEXT NOT NULL, size INTEGER NOT NULL, state TEXT NOT NULL, sent_at INTEGER,
  delete_at INTEGER, ended_at INTEGER);
CREATE TABLE deletes (node TEXT NOT NULL, sha256 TEXT NOT NULL, signer TEXT NOT NULL,
  not_before INTEGER NOT NULL DEFAULT 0, file_id TEXT, PRIMARY KEY (node, sha256, signer));
CREATE TABLE online_copies (file_id TEXT NOT NULL, origin TEXT NOT NULL, PRIMARY KEY (file_id, origin));
CREATE TABLE stranded (file_id TEXT NOT NULL, sha256 TEXT NOT NULL, origin TEXT NOT NULL,
  at INTEGER NOT NULL, PRIMARY KEY (file_id, sha256));
CREATE TABLE removed (id TEXT PRIMARY KEY, at INTEGER NOT NULL);
CREATE TABLE watch_seen (path TEXT NOT NULL, size INTEGER NOT NULL, mtime INTEGER NOT NULL,
  PRIMARY KEY (path, size, mtime));
CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
PRAGMA user_version = 2;
";

    fn version_2_index(dir: &Path, online_url: Option<&str>) {
        wildbloom_private_state::private_directory(dir).unwrap();
        let db = Connection::open(dir.join("drop-index.sqlite")).unwrap();
        db.execute_batch(SCHEMA_2).unwrap();
        for (id, plain, online) in [
            ("a", "aa".repeat(32), "ok"),
            ("r", "restored:r".to_string(), "ok"),
            ("q", "cc".repeat(32), "queued"),
        ] {
            db.execute(
                "INSERT INTO files (id, name, media_type, bytes, added, plain_sha256, sha256, size, local, online, watch_path, watch_size, watch_mtime)
                 VALUES (?1, ?2, 'text/plain', 12, 1900000000, ?3, ?4, 65608, 'ok', ?5, ?6, 12, 7)",
                params![id, format!("{id}.txt"), plain, "bb".repeat(32), online, (id == "a").then_some("/w/a.txt")],
            )
            .unwrap();
        }
        if let Some(url) = online_url {
            db.execute(
                "INSERT INTO kv (key, value) VALUES ('online_url', ?1)",
                [url],
            )
            .unwrap();
        }
        db.execute(
            "INSERT INTO kv (key, value) VALUES ('watch_enabled', '1')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn version_2_migrates_to_the_current_schema() {
        let dir = tempfile::tempdir().unwrap();
        let drop = dir.path().join("drop");
        let node = "https://storage.example/";
        version_2_index(&drop, Some(node));
        let index = Index::open(&drop).unwrap();
        drop_connection_of(index);
        let db = Connection::open(drop.join("drop-index.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        drop_connection(db);
        let index = Index::open(&drop).unwrap();
        for id in ["a", "r", "q"] {
            let file = index.file(id).unwrap().unwrap();
            assert_eq!(file.path, format!("{id}.txt"), "path = name");
            assert_eq!(file.prev, None);
            assert_eq!(file.origin, "");
            assert_eq!(file.entry_plain, "");
            assert_eq!(file.note, None);
        }
        assert_eq!(
            index.file("a").unwrap().unwrap().watch_path.as_deref(),
            Some("/w/a.txt")
        );
        // Only the uploaded row is backfilled: not the restored or queued one.
        assert_eq!(index.online_copies("a").unwrap(), vec![node.to_string()]);
        assert!(index.online_copies("r").unwrap().is_empty());
        assert!(index.online_copies("q").unwrap().is_empty());
        assert_eq!(index.online_used_bytes().unwrap(), 65_608);
        // The inbox setting is kept: this build still means the same by it.
        assert!(index.get_bool("watch_enabled").unwrap());
        // Reopening a migrated index changes nothing.
        drop_connection_of(index);
        let index = Index::open(&drop).unwrap();
        assert_eq!(index.files().unwrap().len(), 3);

        // With no online node there is nothing to backfill.
        let bare = dir.path().join("bare");
        version_2_index(&bare, None);
        let index = Index::open(&bare).unwrap();
        assert!(index.online_copies("a").unwrap().is_empty());

        // Version 1 and anything newer than 5 are refused.
        for (name, version) in [("one", 1), ("six", 6)] {
            let other = dir.path().join(name);
            version_2_index(&other, None);
            Connection::open(other.join("drop-index.sqlite"))
                .unwrap()
                .execute_batch(&format!("PRAGMA user_version = {version};"))
                .unwrap();
            assert!(matches!(Index::open(&other), Err(IndexError::Version(v)) if v == version));
        }
    }

    /// A version 3 index (as the previous build left it) with a sent share
    /// from before downloads were confirmed.
    fn version_3_index(dir: &Path) {
        version_2_index(dir, Some("https://storage.example/"));
        let db = Connection::open(dir.join("drop-index.sqlite")).unwrap();
        db.execute_batch(MIGRATE_2_TO_3).unwrap();
        db.execute(
            "INSERT INTO shares (file_id, share_id, origin, sha256, size, state, sent_at, delete_at, ended_at)
             VALUES ('a', ?1, 'https://storage.example/', ?2, 70000, 'sent', 10, 86410, NULL)",
            params!["dd".repeat(16), "cc".repeat(32)],
        )
        .unwrap();
    }

    #[test]
    fn version_3_migrates_to_4_without_download_times() {
        let dir = tempfile::tempdir().unwrap();
        let drop = dir.path().join("drop");
        version_3_index(&drop);
        let index = Index::open(&drop).unwrap();
        let share = index.share("a").unwrap().unwrap();
        assert_eq!(share.state, share::SENT);
        assert_eq!((share.sent_at, share.delete_at), (Some(10), Some(86_410)));
        assert_eq!(share.downloaded_at, None, "no old share was confirmed");
        // The files and settings are untouched.
        assert_eq!(index.files().unwrap().len(), 3);
        assert!(index.get_bool("watch_enabled").unwrap());
        // The new column round-trips, and a replacing record clears it.
        index
            .put_share(&ShareRecord {
                downloaded_at: Some(500),
                ..share.clone()
            })
            .unwrap();
        assert_eq!(index.share("a").unwrap().unwrap().downloaded_at, Some(500));
        drop_connection_of(index);
        let db = Connection::open(drop.join("drop-index.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        drop_connection(db);
        // Reopening a migrated index changes nothing.
        let index = Index::open(&drop).unwrap();
        assert_eq!(index.shares().unwrap()[0].downloaded_at, Some(500));
        index.put_share(&share).unwrap();
        assert_eq!(index.share("a").unwrap().unwrap().downloaded_at, None);
    }

    #[test]
    fn version_4_migrates_to_5_with_nothing_held() {
        let dir = tempfile::tempdir().unwrap();
        let drop = dir.path().join("drop");
        // A version 4 index, as 0.3.8 left it: no `held` table.
        version_3_index(&drop);
        let db = Connection::open(drop.join("drop-index.sqlite")).unwrap();
        db.execute_batch(MIGRATE_3_TO_4).unwrap();
        let tables: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'held'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
        drop_connection(db);
        let index = Index::open(&drop).unwrap();
        assert!(index.held().unwrap().is_empty(), "nothing is held");
        assert_eq!(index.files().unwrap().len(), 3);
        assert_eq!(index.shares().unwrap().len(), 1);
        assert!(index.get_bool("watch_enabled").unwrap());
        index.hold(&["a".into()], 7).unwrap();
        drop_connection_of(index);
        let db = Connection::open(drop.join("drop-index.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 5);
        drop_connection(db);
        // Reopening keeps the hold.
        let index = Index::open(&drop).unwrap();
        assert!(index.is_held("a").unwrap());
    }

    #[test]
    fn holds_round_trip_and_go_with_their_row() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("drop")).unwrap();
        for id in ["a", "b", "c"] {
            index.insert_file(&record(id)).unwrap();
        }
        index.hold(&["a".into(), "b".into()], 10).unwrap();
        // Holding again changes nothing.
        index.hold(&["a".into()], 20).unwrap();
        assert_eq!(
            index.held().unwrap(),
            ["a", "b"].map(String::from).into_iter().collect()
        );
        assert!(index.is_held("a").unwrap());
        assert!(!index.is_held("c").unwrap());
        index.release_hold("a").unwrap();
        assert!(!index.is_held("a").unwrap());
        assert!(index.file("a").unwrap().is_some(), "the row stays");
        // A removed row takes its hold with it.
        index.delete_file("b").unwrap();
        assert!(index.held().unwrap().is_empty());
        index.hold(&["c".into()], 30).unwrap();
        index.clear_holds().unwrap();
        assert!(index.held().unwrap().is_empty());
        assert!(index.file("c").unwrap().is_some());
    }

    fn drop_connection_of(index: Index) {
        drop(index);
    }

    fn drop_index_at(dir: &Path) {
        Index::open(dir).unwrap();
        // Reopening a current index is fine.
        Index::open(dir).unwrap();
    }

    fn drop_connection(db: Connection) {
        drop(db);
    }

    fn record(id: &str) -> FileRecord {
        FileRecord {
            id: id.into(),
            name: "notes.txt".into(),
            media_type: "text/plain".into(),
            bytes: 12,
            added: 1_900_000_000,
            plain_sha256: "aa".repeat(32),
            sha256: None,
            size: None,
            local: local::ENCRYPTING.into(),
            online: online::QUEUED.into(),
            attempts: 0,
            next_attempt: 0,
            watch_path: None,
            watch_size: None,
            watch_mtime: None,
            path: "notes.txt".into(),
            prev: None,
            origin: String::new(),
            entry_plain: String::new(),
            note: None,
        }
    }

    #[test]
    fn rows_shares_deletes_and_settings_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("drop")).unwrap();
        index.insert_file(&record("a")).unwrap();
        index.set_envelope("a", &"bb".repeat(32), 65_608).unwrap();
        index.set_local("a", local::OK).unwrap();
        index.set_online("a", online::OK).unwrap();
        // Online but not claimed by this computer: not charged to it.
        assert_eq!(index.online_used_bytes().unwrap(), 0);
        index
            .add_online_copy("a", "https://storage.example/")
            .unwrap();
        let file = index.file("a").unwrap().unwrap();
        assert_eq!(file.size, Some(65_608));
        assert_eq!(file.local, "ok");
        assert_eq!(file, {
            let mut expected = record("a");
            expected.sha256 = Some("bb".repeat(32));
            expected.size = Some(65_608);
            expected.local = local::OK.into();
            expected.online = online::OK.into();
            expected
        });
        assert_eq!(
            index
                .file_by_plain_sha256(&"aa".repeat(32))
                .unwrap()
                .unwrap()
                .id,
            "a"
        );
        assert_eq!(index.online_used_bytes().unwrap(), 65_608);

        index
            .put_share(&ShareRecord {
                file_id: "a".into(),
                share_id: "dd".repeat(16),
                origin: "https://storage.example/".into(),
                sha256: "cc".repeat(32),
                size: 70_000,
                state: share::SENT.into(),
                sent_at: Some(1),
                delete_at: Some(2),
                ended_at: None,
                downloaded_at: Some(3),
            })
            .unwrap();
        assert_eq!(index.share("a").unwrap().unwrap().downloaded_at, Some(3));
        assert_eq!(index.online_used_bytes().unwrap(), 135_608);
        let node = "https://storage.example/";
        index
            .queue_delete(node, &"cc".repeat(32), "device", 50)
            .unwrap();
        index
            .queue_delete(node, &"cc".repeat(32), "device", 9)
            .unwrap();
        let deletes = index.pending_deletes().unwrap();
        assert_eq!(deletes.len(), 1);
        assert_eq!((deletes[0].node.as_str(), deletes[0].not_before), (node, 9));
        index.add_online_copy("a", node).unwrap();
        index.add_online_copy("a", node).unwrap();
        assert_eq!(index.online_copies("a").unwrap(), vec![node.to_string()]);
        index.add_stranded("a", &"ee".repeat(32), node, 77).unwrap();
        assert_eq!(index.stranded_at("a").unwrap(), Some(77));
        index.add_tombstone("b", 5).unwrap();
        index.add_tombstone("b", 3).unwrap();
        assert_eq!(index.tombstones().unwrap(), vec![("b".to_string(), 5)]);

        index.set_u64("last_seen_seq", 7).unwrap();
        assert_eq!(index.get_u64("last_seen_seq").unwrap(), Some(7));
        index.set_bool("watch", true).unwrap();
        assert!(index.get_bool("watch").unwrap());

        assert!(index.has_tombstone("b").unwrap());
        assert!(!index.has_tombstone("a").unwrap());

        assert!(index.linked_files().unwrap().is_empty());
        index
            .set_link("a", Some(("/w/Docs/a.txt".into(), 12, 1_900_000_000_123)))
            .unwrap();
        index.set_plain_sha256("a", &"cd".repeat(32)).unwrap();
        let linked = index.linked_files().unwrap();
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].watch_path.as_deref(), Some("/w/Docs/a.txt"));
        assert_eq!(linked[0].watch_size, Some(12));
        assert_eq!(linked[0].watch_mtime, Some(1_900_000_000_123));
        assert_eq!(linked[0].plain_sha256, "cd".repeat(32));
        index.set_link("a", None).unwrap();
        assert!(index.linked_files().unwrap().is_empty());

        assert!(!index.watch_seen("/w/a.txt", 3, 9).unwrap());
        index.mark_watch_seen("/w/a.txt", 3, 9).unwrap();
        assert!(index.watch_seen("/w/a.txt", 3, 9).unwrap());

        index.delete_file("a").unwrap();
        assert!(index.file("a").unwrap().is_none());
        assert!(index.online_copies("a").unwrap().is_empty());
        assert_eq!(index.stranded_at("a").unwrap(), None);
        assert!(index.share("a").unwrap().is_none());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("drop/drop-index.sqlite"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
