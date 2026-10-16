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
    pub watch_path: Option<String>,
    pub watch_size: Option<u64>,
    pub watch_mtime: Option<i64>,
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
}

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("the Drop file index failed: {0}")]
    Sql(String),
    #[error("the Drop file index directory is not private")]
    Private,
}

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
  watch_mtime INTEGER
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
  ended_at INTEGER
);
CREATE TABLE IF NOT EXISTS deletes (
  node TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  signer TEXT NOT NULL,
  not_before INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node, sha256, signer)
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
PRAGMA user_version = 1;
";

const FILE_COLUMNS: &str = "id, name, media_type, bytes, added, plain_sha256, sha256, size, local, online, attempts, next_attempt, watch_path, watch_size, watch_mtime";

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
        let db = Connection::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| IndexError::Private)?;
        }
        db.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA foreign_keys = ON;")?;
        db.execute_batch(SCHEMA)?;
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
                &format!("INSERT INTO files ({FILE_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"),
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

    pub fn delete_file(&self, id: &str) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute("DELETE FROM shares WHERE file_id = ?1", [id])?;
            db.execute("DELETE FROM files WHERE id = ?1", [id])
                .map(|_| ())
        })
    }

    /// Bytes this computer has stored on the online node (its own copies and
    /// shared copies), for the footer and settings.
    pub fn online_used_bytes(&self) -> Result<u64, IndexError> {
        self.with(|db| {
            let files: i64 = db.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM files WHERE online = 'ok'",
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
                "SELECT file_id, share_id, origin, sha256, size, state, sent_at, delete_at, ended_at FROM shares WHERE file_id = ?1",
                [file_id],
                share_from_row,
            )
            .optional()
        })
    }

    pub fn shares(&self) -> Result<Vec<ShareRecord>, IndexError> {
        self.with(|db| {
            let mut statement = db.prepare(
                "SELECT file_id, share_id, origin, sha256, size, state, sent_at, delete_at, ended_at FROM shares",
            )?;
            statement
                .query_map([], share_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    pub fn put_share(&self, share: &ShareRecord) -> Result<(), IndexError> {
        self.with(|db| {
            db.execute(
                "INSERT INTO shares (file_id, share_id, origin, sha256, size, state, sent_at, delete_at, ended_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(file_id) DO UPDATE SET share_id = excluded.share_id, origin = excluded.origin, sha256 = excluded.sha256, size = excluded.size, state = excluded.state,
                 sent_at = excluded.sent_at, delete_at = excluded.delete_at, ended_at = excluded.ended_at",
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
        self.with(|db| {
            db.execute(
                "INSERT INTO deletes (node, sha256, signer, not_before) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(node, sha256, signer) DO UPDATE SET not_before = MIN(not_before, excluded.not_before)",
                params![node, sha256, signer, int(not_before)],
            )
            .map(|_| ())
        })
    }

    pub fn pending_deletes(&self) -> Result<Vec<PendingDelete>, IndexError> {
        self.with(|db| {
            let mut statement =
                db.prepare("SELECT node, sha256, signer, not_before FROM deletes")?;
            statement
                .query_map([], |r| {
                    Ok(PendingDelete {
                        node: r.get(0)?,
                        sha256: r.get(1)?,
                        signer: r.get(2)?,
                        not_before: r.get::<_, i64>(3)?.max(0) as u64,
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
        let file = index.file("a").unwrap().unwrap();
        assert_eq!(file.size, Some(65_608));
        assert_eq!(file.local, "ok");
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
            })
            .unwrap();
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
        index.add_tombstone("b", 5).unwrap();
        index.add_tombstone("b", 3).unwrap();
        assert_eq!(index.tombstones().unwrap(), vec![("b".to_string(), 5)]);

        index.set_u64("last_seen_seq", 7).unwrap();
        assert_eq!(index.get_u64("last_seen_seq").unwrap(), Some(7));
        index.set_bool("watch", true).unwrap();
        assert!(index.get_bool("watch").unwrap());

        assert!(!index.watch_seen("/w/a.txt", 3, 9).unwrap());
        index.mark_watch_seen("/w/a.txt", 3, 9).unwrap();
        assert!(index.watch_seen("/w/a.txt", 3, 9).unwrap());

        index.delete_file("a").unwrap();
        assert!(index.file("a").unwrap().is_none());
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
