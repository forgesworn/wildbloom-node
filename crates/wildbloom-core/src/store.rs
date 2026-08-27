use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub root: PathBuf,
    pub quota_bytes: u64,
    pub max_blob_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Store {
    config: StoreConfig,
    database_path: PathBuf,
    _lock: Arc<File>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BlobMetadata {
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub content_type: String,
    pub uploaded: u64,
}

#[derive(Debug)]
pub enum UploadStart {
    Existing(BlobMetadata),
    Reserved(UploadReservation),
}

#[derive(Debug)]
pub struct UploadReservation {
    store: Store,
    id: String,
    expected_hash: String,
    expected_size: u64,
    owner_pubkey: String,
    content_type: String,
    temp_path: PathBuf,
    completed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StoreStats {
    pub blobs: u64,
    pub bytes: u64,
    pub reserved_bytes: u64,
    pub quota_bytes: u64,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid SHA-256 digest")]
    InvalidHash,
    #[error("blob size {size} exceeds the per-blob limit of {limit} bytes")]
    BlobTooLarge { size: u64, limit: u64 },
    #[error("the configured storage quota is full")]
    QuotaExceeded,
    #[error("content length does not match the stored blob")]
    LengthMismatch,
    #[error("received bytes do not match the authorised SHA-256 digest")]
    HashMismatch,
    #[error("upload reservation no longer exists")]
    MissingReservation,
    #[error("stored blob is missing from disk")]
    MissingBlob,
    #[error("another Wildbloom process is already using this data directory")]
    AlreadyOpen,
    #[error("integer is outside the supported storage range")]
    IntegerRange,
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage database failed: {0}")]
    Database(#[from] rusqlite::Error),
}

impl Store {
    pub fn open(config: StoreConfig) -> Result<Self, StoreError> {
        if config.quota_bytes > i64::MAX as u64 || config.max_blob_bytes > i64::MAX as u64 {
            return Err(StoreError::IntegerRange);
        }

        create_private_dir(&config.root)?;
        create_private_dir(&config.root.join("blobs"))?;
        create_private_dir(&config.root.join("tmp"))?;

        let lock_path = config.root.join("wildbloom.lock");
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        set_private_file_permissions(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                StoreError::AlreadyOpen
            } else {
                StoreError::Io(error)
            }
        })?;

        let database_path = config.root.join("wildbloom.sqlite3");
        let store = Self {
            config,
            database_path,
            _lock: Arc::new(lock),
        };
        store.initialise_database()?;
        store.clear_interrupted_uploads()?;
        Ok(store)
    }

    pub fn config(&self) -> &StoreConfig {
        &self.config
    }

    pub fn begin_upload(
        &self,
        expected_hash: &str,
        expected_size: u64,
        owner_pubkey: &str,
        content_type: &str,
    ) -> Result<UploadStart, StoreError> {
        validate_hash(expected_hash)?;
        if expected_size > self.config.max_blob_bytes {
            return Err(StoreError::BlobTooLarge {
                size: expected_size,
                limit: self.config.max_blob_bytes,
            });
        }

        let expected_size_i64 =
            i64::try_from(expected_size).map_err(|_| StoreError::IntegerRange)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(metadata) = query_blob(&transaction, expected_hash)? {
            if metadata.size != expected_size {
                return Err(StoreError::LengthMismatch);
            }
            transaction.execute(
                "INSERT OR IGNORE INTO owners (owner_pubkey, hash, created_at) VALUES (?1, ?2, ?3)",
                params![owner_pubkey, expected_hash, unix_time()?],
            )?;
            transaction.commit()?;
            return Ok(UploadStart::Existing(metadata));
        }

        let used: i64 = transaction.query_row(
            "SELECT COALESCE((SELECT SUM(size) FROM blobs), 0) + \
                    COALESCE((SELECT SUM(size) FROM reservations), 0)",
            [],
            |row| row.get(0),
        )?;
        let quota = i64::try_from(self.config.quota_bytes).map_err(|_| StoreError::IntegerRange)?;
        if used > quota.saturating_sub(expected_size_i64) {
            return Err(StoreError::QuotaExceeded);
        }

        let id = Uuid::new_v4().simple().to_string();
        transaction.execute(
            "INSERT INTO reservations (id, hash, size, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, expected_hash, expected_size_i64, unix_time()?],
        )?;
        transaction.commit()?;

        Ok(UploadStart::Reserved(UploadReservation {
            store: self.clone(),
            temp_path: self.config.root.join("tmp").join(format!("{id}.part")),
            id,
            expected_hash: expected_hash.to_owned(),
            expected_size,
            owner_pubkey: owner_pubkey.to_owned(),
            content_type: content_type.to_owned(),
            completed: false,
        }))
    }

    pub fn get(&self, hash: &str) -> Result<Option<BlobMetadata>, StoreError> {
        validate_hash(hash)?;
        let connection = self.connection()?;
        let metadata = query_blob(&connection, hash)?;
        if metadata.is_some() && !self.blob_path(hash).is_file() {
            return Err(StoreError::MissingBlob);
        }
        Ok(metadata)
    }

    pub fn blob_path(&self, hash: &str) -> PathBuf {
        self.config.root.join("blobs").join(&hash[..2]).join(hash)
    }

    pub fn stats(&self) -> Result<StoreStats, StoreError> {
        let connection = self.connection()?;
        let (blobs, bytes): (i64, i64) = connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM blobs",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let reserved: i64 = connection.query_row(
            "SELECT COALESCE(SUM(size), 0) FROM reservations",
            [],
            |row| row.get(0),
        )?;
        Ok(StoreStats {
            blobs: u64::try_from(blobs).map_err(|_| StoreError::IntegerRange)?,
            bytes: u64::try_from(bytes).map_err(|_| StoreError::IntegerRange)?,
            reserved_bytes: u64::try_from(reserved).map_err(|_| StoreError::IntegerRange)?,
            quota_bytes: self.config.quota_bytes,
        })
    }

    fn connection(&self) -> Result<Connection, StoreError> {
        let connection = Connection::open(&self.database_path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        Ok(connection)
    }

    fn initialise_database(&self) -> Result<(), StoreError> {
        let connection = self.connection()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS blobs (
                hash TEXT PRIMARY KEY NOT NULL,
                size INTEGER NOT NULL CHECK (size >= 0),
                content_type TEXT NOT NULL,
                created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS owners (
                owner_pubkey TEXT NOT NULL,
                hash TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_pubkey, hash)
             );
             CREATE TABLE IF NOT EXISTS reservations (
                id TEXT PRIMARY KEY NOT NULL,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL CHECK (size >= 0),
                created_at INTEGER NOT NULL
             );",
        )?;
        set_private_file_permissions(&self.database_path)?;
        Ok(())
    }

    fn clear_interrupted_uploads(&self) -> Result<(), StoreError> {
        let connection = self.connection()?;
        connection.execute("DELETE FROM reservations", [])?;
        for entry in fs::read_dir(self.config.root.join("tmp"))? {
            let path = entry?.path();
            if path.is_file() {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

impl UploadReservation {
    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    pub fn expected_hash(&self) -> &str {
        &self.expected_hash
    }

    pub fn commit(
        mut self,
        actual_hash: &str,
        actual_size: u64,
    ) -> Result<BlobMetadata, StoreError> {
        if actual_hash != self.expected_hash {
            return Err(StoreError::HashMismatch);
        }
        if actual_size != self.expected_size {
            return Err(StoreError::LengthMismatch);
        }

        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = transaction
            .query_row(
                "SELECT 1 FROM reservations WHERE id = ?1",
                [&self.id],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !exists {
            return Err(StoreError::MissingReservation);
        }

        let uploaded = unix_time()?;
        let uploaded_unsigned = u64::try_from(uploaded).map_err(|_| StoreError::IntegerRange)?;
        let metadata = if let Some(metadata) = query_blob(&transaction, &self.expected_hash)? {
            fs::remove_file(&self.temp_path)?;
            metadata
        } else {
            let destination = self.store.blob_path(&self.expected_hash);
            let parent = destination.parent().ok_or(StoreError::InvalidHash)?;
            create_private_dir(parent)?;
            fs::rename(&self.temp_path, &destination)?;
            set_private_file_permissions(&destination)?;
            transaction.execute(
                "INSERT INTO blobs (hash, size, content_type, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    self.expected_hash,
                    i64::try_from(self.expected_size).map_err(|_| StoreError::IntegerRange)?,
                    self.content_type,
                    uploaded
                ],
            )?;
            BlobMetadata {
                sha256: self.expected_hash.clone(),
                size: self.expected_size,
                content_type: self.content_type.clone(),
                uploaded: uploaded_unsigned,
            }
        };

        transaction.execute(
            "INSERT OR IGNORE INTO owners (owner_pubkey, hash, created_at) VALUES (?1, ?2, ?3)",
            params![self.owner_pubkey, self.expected_hash, uploaded],
        )?;
        transaction.execute("DELETE FROM reservations WHERE id = ?1", [&self.id])?;
        transaction.commit()?;
        self.completed = true;
        Ok(metadata)
    }

    fn cancel(&self) {
        if let Ok(connection) = self.store.connection() {
            let _ = connection.execute("DELETE FROM reservations WHERE id = ?1", [&self.id]);
        }
        let _ = fs::remove_file(&self.temp_path);
    }
}

impl Drop for UploadReservation {
    fn drop(&mut self) {
        if !self.completed {
            self.cancel();
        }
    }
}

fn query_blob(connection: &Connection, hash: &str) -> Result<Option<BlobMetadata>, StoreError> {
    let metadata = connection
        .query_row(
            "SELECT hash, size, content_type, created_at FROM blobs WHERE hash = ?1",
            [hash],
            |row| {
                let size: i64 = row.get(1)?;
                let uploaded: i64 = row.get(3)?;
                Ok((
                    row.get::<_, String>(0)?,
                    size,
                    row.get::<_, String>(2)?,
                    uploaded,
                ))
            },
        )
        .optional()?
        .map(
            |(sha256, size, content_type, uploaded)| -> Result<BlobMetadata, StoreError> {
                Ok(BlobMetadata {
                    sha256,
                    size: u64::try_from(size).map_err(|_| StoreError::IntegerRange)?,
                    content_type,
                    uploaded: u64::try_from(uploaded).map_err(|_| StoreError::IntegerRange)?,
                })
            },
        )
        .transpose()?;
    Ok(metadata)
}

fn validate_hash(hash: &str) -> Result<(), StoreError> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::InvalidHash);
    }
    if hash.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(StoreError::InvalidHash);
    }
    Ok(())
}

fn unix_time() -> Result<i64, StoreError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| StoreError::Io(std::io::Error::other(error)))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| StoreError::IntegerRange)
}

fn create_private_dir(path: &Path) -> Result<(), StoreError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_store(quota: u64, max_blob: u64) -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(StoreConfig {
            root: directory.path().join("data"),
            quota_bytes: quota,
            max_blob_bytes: max_blob,
        })
        .unwrap();
        (directory, store)
    }

    #[test]
    fn reserves_commits_and_deduplicates_blobs() {
        let (_directory, store) = test_store(100, 100);
        let hash = "a".repeat(64);
        let UploadStart::Reserved(reservation) = store
            .begin_upload(&hash, 5, "01".repeat(32).as_str(), "text/plain")
            .unwrap()
        else {
            panic!("first upload must reserve space");
        };
        fs::File::create(reservation.temp_path())
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        let metadata = reservation.commit(&hash, 5).unwrap();
        assert_eq!(metadata.size, 5);
        assert!(store.blob_path(&hash).is_file());

        let existing = store
            .begin_upload(
                &hash,
                5,
                "02".repeat(32).as_str(),
                "application/octet-stream",
            )
            .unwrap();
        assert!(matches!(existing, UploadStart::Existing(_)));
        assert_eq!(store.stats().unwrap().bytes, 5);
    }

    #[test]
    fn reservations_enforce_quota_before_bytes_are_written() {
        let (_directory, store) = test_store(7, 7);
        let _first = store
            .begin_upload(&"a".repeat(64), 5, "01", "text/plain")
            .unwrap();
        let second = store.begin_upload(&"b".repeat(64), 3, "02", "text/plain");
        assert!(matches!(second, Err(StoreError::QuotaExceeded)));
    }

    #[test]
    fn dropped_reservations_return_quota() {
        let (_directory, store) = test_store(5, 5);
        let reservation = store
            .begin_upload(&"a".repeat(64), 5, "01", "text/plain")
            .unwrap();
        drop(reservation);
        assert_eq!(store.stats().unwrap().reserved_bytes, 0);
        assert!(
            store
                .begin_upload(&"b".repeat(64), 5, "02", "text/plain")
                .is_ok()
        );
    }

    #[test]
    fn rejects_non_canonical_hashes_and_oversized_blobs() {
        let (_directory, store) = test_store(100, 4);
        assert!(matches!(
            store.begin_upload(&"A".repeat(64), 1, "01", "text/plain"),
            Err(StoreError::InvalidHash)
        ));
        assert!(matches!(
            store.begin_upload(&"a".repeat(64), 5, "01", "text/plain"),
            Err(StoreError::BlobTooLarge { .. })
        ));
    }

    #[test]
    fn refuses_concurrent_processes_using_the_same_directory() {
        let (_directory, store) = test_store(100, 100);
        let second = Store::open(store.config().clone());
        assert!(matches!(second, Err(StoreError::AlreadyOpen)));
    }
}
