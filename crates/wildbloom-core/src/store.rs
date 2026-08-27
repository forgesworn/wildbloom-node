use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
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

#[derive(Debug)]
pub struct RepairReservation {
    store: Store,
    expected_hash: String,
    expected_size: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    OwnerRemoved,
    BlobDeleted,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IntegrityReport {
    pub checked: u64,
    pub healthy: u64,
    pub missing: Vec<String>,
    pub corrupted: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepairCandidate {
    pub sha256: String,
    pub size: u64,
    pub sources: Vec<String>,
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
    #[error("the signing public key does not own this blob")]
    NotOwner,
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
            if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
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

    pub fn check_upload(&self, expected_hash: &str, expected_size: u64) -> Result<(), StoreError> {
        validate_hash(expected_hash)?;
        if expected_size > self.config.max_blob_bytes {
            return Err(StoreError::BlobTooLarge {
                size: expected_size,
                limit: self.config.max_blob_bytes,
            });
        }
        let expected_size_i64 =
            i64::try_from(expected_size).map_err(|_| StoreError::IntegerRange)?;
        let connection = self.connection()?;
        if let Some(metadata) = query_blob(&connection, expected_hash)? {
            return if metadata.size == expected_size {
                Ok(())
            } else {
                Err(StoreError::LengthMismatch)
            };
        }
        let used: i64 = connection.query_row(
            "SELECT COALESCE((SELECT SUM(size) FROM blobs), 0) + \
                    COALESCE((SELECT SUM(size) FROM reservations), 0)",
            [],
            |row| row.get(0),
        )?;
        let quota = i64::try_from(self.config.quota_bytes).map_err(|_| StoreError::IntegerRange)?;
        if used > quota.saturating_sub(expected_size_i64) {
            return Err(StoreError::QuotaExceeded);
        }
        Ok(())
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

    pub fn delete_owned(
        &self,
        hash: &str,
        owner_pubkey: &str,
    ) -> Result<DeleteOutcome, StoreError> {
        validate_hash(hash)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if query_blob(&transaction, hash)?.is_none() {
            return Err(StoreError::MissingBlob);
        }
        let owns_blob = transaction
            .query_row(
                "SELECT 1 FROM owners WHERE owner_pubkey = ?1 AND hash = ?2",
                params![owner_pubkey, hash],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !owns_blob {
            return Err(StoreError::NotOwner);
        }

        transaction.execute(
            "DELETE FROM owners WHERE owner_pubkey = ?1 AND hash = ?2",
            params![owner_pubkey, hash],
        )?;
        let remaining_owners: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM owners WHERE hash = ?1",
            [hash],
            |row| row.get(0),
        )?;
        if remaining_owners > 0 {
            transaction.commit()?;
            return Ok(DeleteOutcome::OwnerRemoved);
        }

        let blob_path = self.blob_path(hash);
        if !blob_path.is_file() {
            return Err(StoreError::MissingBlob);
        }
        let tombstone = self
            .config
            .root
            .join("tmp")
            .join(format!("{}.delete", Uuid::new_v4().simple()));
        fs::rename(&blob_path, &tombstone)?;
        transaction.execute("DELETE FROM blobs WHERE hash = ?1", [hash])?;
        if let Err(error) = transaction.commit() {
            fs::rename(&tombstone, &blob_path)?;
            return Err(StoreError::Database(error));
        }
        if let Err(error) = fs::remove_file(&tombstone) {
            tracing::warn!(reason = %error, path = %tombstone.display(), "left a deleted blob tombstone for startup cleanup");
        }
        Ok(DeleteOutcome::BlobDeleted)
    }

    pub fn verify_integrity(&self) -> Result<IntegrityReport, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT hash, size FROM blobs ORDER BY hash")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut checked = 0_u64;
        let mut healthy = 0_u64;
        let mut missing = Vec::new();
        let mut corrupted = Vec::new();
        for row in rows {
            let (hash, expected_size) = row?;
            checked = checked.checked_add(1).ok_or(StoreError::IntegerRange)?;
            let path = self.blob_path(&hash);
            let mut file = match File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(hash);
                    continue;
                }
                Err(error) => return Err(StoreError::Io(error)),
            };
            let metadata = file.metadata()?;
            if i64::try_from(metadata.len()).map_err(|_| StoreError::IntegerRange)? != expected_size
            {
                corrupted.push(hash);
                continue;
            }
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            if hex::encode(hasher.finalize()) == hash {
                healthy = healthy.checked_add(1).ok_or(StoreError::IntegerRange)?;
            } else {
                corrupted.push(hash);
            }
        }
        Ok(IntegrityReport {
            checked,
            healthy,
            missing,
            corrupted,
        })
    }

    pub fn record_repair_source(&self, hash: &str, source_url: &str) -> Result<(), StoreError> {
        validate_hash(hash)?;
        let connection = self.connection()?;
        if query_blob(&connection, hash)?.is_none() {
            return Err(StoreError::MissingBlob);
        }
        connection.execute(
            "INSERT OR IGNORE INTO repair_sources (hash, source_url, created_at) VALUES (?1, ?2, ?3)",
            params![hash, source_url, unix_time()?],
        )?;
        Ok(())
    }

    pub fn repair_candidates(&self) -> Result<Vec<RepairCandidate>, StoreError> {
        let integrity = self.verify_integrity()?;
        let broken = integrity
            .missing
            .into_iter()
            .chain(integrity.corrupted)
            .collect::<Vec<_>>();
        let connection = self.connection()?;
        let mut candidates = Vec::with_capacity(broken.len());
        for hash in broken {
            let size: i64 =
                connection.query_row("SELECT size FROM blobs WHERE hash = ?1", [&hash], |row| {
                    row.get(0)
                })?;
            let mut statement = connection.prepare(
                "SELECT source_url FROM repair_sources WHERE hash = ?1 ORDER BY created_at DESC",
            )?;
            let sources = statement
                .query_map([&hash], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            candidates.push(RepairCandidate {
                sha256: hash,
                size: u64::try_from(size).map_err(|_| StoreError::IntegerRange)?,
                sources,
            });
        }
        Ok(candidates)
    }

    pub fn begin_repair(&self, hash: &str) -> Result<RepairReservation, StoreError> {
        validate_hash(hash)?;
        let connection = self.connection()?;
        let metadata = query_blob(&connection, hash)?.ok_or(StoreError::MissingBlob)?;
        let id = Uuid::new_v4().simple().to_string();
        Ok(RepairReservation {
            store: self.clone(),
            expected_hash: hash.to_owned(),
            expected_size: metadata.size,
            temp_path: self.config.root.join("tmp").join(format!("{id}.repair")),
            completed: false,
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
             );
             CREATE TABLE IF NOT EXISTS repair_sources (
                hash TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
                source_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (hash, source_url)
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

impl RepairReservation {
    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub fn expected_size(&self) -> u64 {
        self.expected_size
    }

    pub fn commit(mut self, actual_hash: &str, actual_size: u64) -> Result<(), StoreError> {
        if actual_hash != self.expected_hash {
            return Err(StoreError::HashMismatch);
        }
        if actual_size != self.expected_size {
            return Err(StoreError::LengthMismatch);
        }
        let mut connection = self.store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata =
            query_blob(&transaction, &self.expected_hash)?.ok_or(StoreError::MissingBlob)?;
        if metadata.size != self.expected_size {
            return Err(StoreError::LengthMismatch);
        }

        let destination = self.store.blob_path(&self.expected_hash);
        let backup = self
            .store
            .config
            .root
            .join("tmp")
            .join(format!("{}.corrupt", Uuid::new_v4().simple()));
        let had_destination = destination.exists();
        if had_destination {
            fs::rename(&destination, &backup)?;
        }
        if let Err(error) = fs::rename(&self.temp_path, &destination) {
            if had_destination {
                let _ = fs::rename(&backup, &destination);
            }
            return Err(StoreError::Io(error));
        }
        if let Err(error) = set_private_file_permissions(&destination) {
            let _ = fs::remove_file(&destination);
            if had_destination {
                let _ = fs::rename(&backup, &destination);
            }
            return Err(error);
        }
        if let Err(error) = transaction.commit() {
            let _ = fs::remove_file(&destination);
            if had_destination {
                let _ = fs::rename(&backup, &destination);
            }
            return Err(StoreError::Database(error));
        }
        if had_destination {
            let _ = fs::remove_file(backup);
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for RepairReservation {
    fn drop(&mut self) {
        if !self.completed {
            let _ = fs::remove_file(&self.temp_path);
        }
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

    #[test]
    fn deletion_removes_only_the_signers_ownership_until_the_last_owner() {
        let (_directory, store) = test_store(100, 100);
        let hash = "a".repeat(64);
        let UploadStart::Reserved(reservation) =
            store.begin_upload(&hash, 5, "01", "text/plain").unwrap()
        else {
            panic!("first upload must reserve space");
        };
        fs::File::create(reservation.temp_path())
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        reservation.commit(&hash, 5).unwrap();
        assert!(matches!(
            store.begin_upload(&hash, 5, "02", "text/plain").unwrap(),
            UploadStart::Existing(_)
        ));

        assert!(matches!(
            store.delete_owned(&hash, "03"),
            Err(StoreError::NotOwner)
        ));
        assert_eq!(
            store.delete_owned(&hash, "01").unwrap(),
            DeleteOutcome::OwnerRemoved
        );
        assert!(store.blob_path(&hash).is_file());
        assert_eq!(
            store.delete_owned(&hash, "02").unwrap(),
            DeleteOutcome::BlobDeleted
        );
        assert!(!store.blob_path(&hash).exists());
        assert_eq!(store.stats().unwrap().blobs, 0);
    }

    #[test]
    fn integrity_scan_distinguishes_healthy_missing_and_corrupt_blobs() {
        let (_directory, store) = test_store(100, 100);
        for (byte, owner) in [(b'a', "01"), (b'b', "02"), (b'c', "03")] {
            let bytes = [byte; 5];
            let hash = hex::encode(Sha256::digest(bytes));
            let UploadStart::Reserved(reservation) = store
                .begin_upload(&hash, bytes.len() as u64, owner, "application/octet-stream")
                .unwrap()
            else {
                panic!("new blob must reserve space");
            };
            fs::File::create(reservation.temp_path())
                .unwrap()
                .write_all(&bytes)
                .unwrap();
            reservation.commit(&hash, bytes.len() as u64).unwrap();
        }
        let missing_hash = hex::encode(Sha256::digest([b'b'; 5]));
        store
            .record_repair_source(&missing_hash, "https://one.example/blob")
            .unwrap();
        fs::remove_file(store.blob_path(&missing_hash)).unwrap();
        let corrupt_hash = hex::encode(Sha256::digest([b'c'; 5]));
        store
            .record_repair_source(&corrupt_hash, "https://two.example/blob")
            .unwrap();
        fs::write(store.blob_path(&corrupt_hash), [b'x'; 5]).unwrap();

        let report = store.verify_integrity().unwrap();
        assert_eq!(report.checked, 3);
        assert_eq!(report.healthy, 1);
        assert_eq!(report.missing, vec![missing_hash.clone()]);
        assert_eq!(report.corrupted, vec![corrupt_hash.clone()]);

        let candidates = store.repair_candidates().unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].sources, vec!["https://one.example/blob"]);
        assert_eq!(candidates[1].sources, vec!["https://two.example/blob"]);

        for (hash, byte) in [(&corrupt_hash, b'c'), (&missing_hash, b'b')] {
            let repair = store.begin_repair(hash).unwrap();
            fs::write(repair.temp_path(), [byte; 5]).unwrap();
            repair.commit(hash, 5).unwrap();
        }
        let repaired = store.verify_integrity().unwrap();
        assert_eq!(repaired.checked, 3);
        assert_eq!(repaired.healthy, 3);
        assert!(repaired.missing.is_empty());
        assert!(repaired.corrupted.is_empty());
    }

    #[test]
    fn deletion_wins_if_it_finishes_before_a_repair_commit() {
        let (_directory, store) = test_store(100, 100);
        let bytes = b"hello";
        let hash = hex::encode(Sha256::digest(bytes));
        let UploadStart::Reserved(upload) = store
            .begin_upload(&hash, bytes.len() as u64, "01", "text/plain")
            .unwrap()
        else {
            panic!("new blob must reserve space");
        };
        fs::write(upload.temp_path(), bytes).unwrap();
        upload.commit(&hash, bytes.len() as u64).unwrap();

        let repair = store.begin_repair(&hash).unwrap();
        fs::write(repair.temp_path(), bytes).unwrap();
        assert_eq!(
            store.delete_owned(&hash, "01").unwrap(),
            DeleteOutcome::BlobDeleted
        );
        assert!(matches!(
            repair.commit(&hash, bytes.len() as u64),
            Err(StoreError::MissingBlob)
        ));
        assert!(!store.blob_path(&hash).exists());
    }
}
