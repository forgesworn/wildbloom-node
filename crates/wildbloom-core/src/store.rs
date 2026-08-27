use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
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

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum RetentionTier {
    Guest,
    Friend,
    Owner,
}

impl RetentionTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Guest => "guest",
            Self::Friend => "friend",
            Self::Owner => "owner",
        }
    }

    fn from_database(value: &str) -> Result<Self, StoreError> {
        match value {
            "guest" => Ok(Self::Guest),
            "friend" => Ok(Self::Friend),
            "owner" => Ok(Self::Owner),
            _ => Err(StoreError::InvalidTier),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClaimSpec {
    pub signer_pubkey: String,
    pub retention_tier: RetentionTier,
    pub declared_type: String,
    pub grant_id: Option<String>,
    pub claim_expires_at: Option<u64>,
    pub byte_limit: Option<u64>,
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
    #[serde(skip)]
    pub retention_tier: RetentionTier,
    #[serde(skip)]
    pub opaque: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ClaimMetadata {
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub content_type: String,
    pub uploaded: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EvictionRecord {
    pub sha256: String,
    pub size: u64,
    pub retention_tier: RetentionTier,
    pub reason: &'static str,
    pub evicted_at: u64,
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
    claim: ClaimSpec,
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

#[derive(Debug)]
struct PendingEviction {
    original_path: PathBuf,
    tombstone_path: PathBuf,
    record: EvictionRecord,
}

#[derive(Debug, Default)]
struct PendingEvictions {
    items: Vec<PendingEviction>,
    committed: bool,
}

impl PendingEvictions {
    fn bytes_i64(&self) -> i64 {
        self.items
            .iter()
            .map(|item| i64::try_from(item.record.size).unwrap_or(i64::MAX))
            .fold(0_i64, i64::saturating_add)
    }

    fn commit(mut self) {
        self.committed = true;
        for item in &self.items {
            if let Err(error) = fs::remove_file(&item.tombstone_path) {
                tracing::warn!(reason = %error, path = %item.tombstone_path.display(), "left an evicted blob tombstone for startup cleanup");
            }
            tracing::info!(
                hash = %item.record.sha256,
                size = item.record.size,
                tier = %item.record.retention_tier.as_str(),
                reason = item.record.reason,
                evicted_at = item.record.evicted_at,
                "evicted best-effort blob"
            );
        }
    }
}

impl Drop for PendingEvictions {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for item in self.items.iter().rev() {
            if item.tombstone_path.exists()
                && let Err(error) = fs::rename(&item.tombstone_path, &item.original_path)
            {
                tracing::error!(reason = %error, path = %item.original_path.display(), "failed to restore a rolled-back eviction");
            }
        }
    }
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
    ClaimRemoved,
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
    #[error("the friend grant byte ceiling is exhausted")]
    FriendLimitExceeded,
    #[error("content length does not match the stored blob")]
    LengthMismatch,
    #[error("received bytes do not match the authorised SHA-256 digest")]
    HashMismatch,
    #[error("upload reservation no longer exists")]
    MissingReservation,
    #[error("stored blob is missing from disk")]
    MissingBlob,
    #[error("the signing public key does not claim this blob")]
    NotClaimant,
    #[error("stored claim has an invalid retention tier")]
    InvalidTier,
    #[error("the listing cursor is not an active claim for this signer")]
    InvalidCursor,
    #[error("the listing limit must be between 1 and 100")]
    InvalidListLimit,
    #[error("the storage quota is too small for valid watermarks")]
    InvalidWatermarks,
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
        if config.quota_bytes < 2 {
            return Err(StoreError::InvalidWatermarks);
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
        store.reap_expired_claims()?;
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
        self.begin_claimed_upload(
            expected_hash,
            expected_size,
            ClaimSpec {
                signer_pubkey: owner_pubkey.to_owned(),
                retention_tier: RetentionTier::Owner,
                declared_type: content_type.to_owned(),
                grant_id: None,
                claim_expires_at: None,
                byte_limit: None,
            },
        )
    }

    pub fn begin_claimed_upload(
        &self,
        expected_hash: &str,
        expected_size: u64,
        claim: ClaimSpec,
    ) -> Result<UploadStart, StoreError> {
        validate_hash(expected_hash)?;
        validate_claim(&claim)?;
        self.reap_expired_claims()?;
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
        let now = unix_time()?;

        if let Some((_, stored_size, _)) = query_blob_row(&transaction, expected_hash)? {
            if stored_size != expected_size {
                return Err(StoreError::LengthMismatch);
            }
            enforce_friend_limit(&transaction, &claim, expected_hash, expected_size, now)?;
            upsert_claim(&transaction, expected_hash, &claim, now)?;
            let metadata =
                query_blob(&transaction, expected_hash)?.ok_or(StoreError::MissingBlob)?;
            transaction.commit()?;
            return Ok(UploadStart::Existing(metadata));
        }

        enforce_friend_limit(&transaction, &claim, expected_hash, expected_size, now)?;
        let mut used: i64 = transaction.query_row(
            "SELECT COALESCE((SELECT SUM(size) FROM blobs), 0) + \
                    COALESCE((SELECT SUM(size) FROM reservations), 0)",
            [],
            |row| row.get(0),
        )?;
        let quota = i64::try_from(self.config.quota_bytes).map_err(|_| StoreError::IntegerRange)?;
        let (low, high) = self.watermarks()?;
        let low = i64::try_from(low).map_err(|_| StoreError::IntegerRange)?;
        let high = i64::try_from(high).map_err(|_| StoreError::IntegerRange)?;
        let predicted_free = quota.saturating_sub(used.saturating_add(expected_size_i64));
        let mut evictions = PendingEvictions::default();
        match claim.retention_tier {
            RetentionTier::Guest => {
                if predicted_free < high {
                    return Err(StoreError::QuotaExceeded);
                }
            }
            RetentionTier::Owner | RetentionTier::Friend => {
                let must_free = used
                    .saturating_add(expected_size_i64)
                    .saturating_sub(quota)
                    .max(if predicted_free < low {
                        high.saturating_sub(predicted_free)
                    } else {
                        0
                    });
                if must_free > 0 {
                    evictions = self.evict_guests(&transaction, must_free, now)?;
                    used = used.saturating_sub(evictions.bytes_i64());
                }
                if used > quota.saturating_sub(expected_size_i64) {
                    return Err(StoreError::QuotaExceeded);
                }
            }
        }

        let id = Uuid::new_v4().simple().to_string();
        transaction.execute(
            "INSERT INTO reservations
             (id, hash, size, retention_tier, signer_pubkey, declared_type,
              grant_id, claim_expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                expected_hash,
                expected_size_i64,
                claim.retention_tier.as_str(),
                claim.signer_pubkey,
                claim.declared_type,
                claim.grant_id,
                claim
                    .claim_expires_at
                    .map(i64::try_from)
                    .transpose()
                    .map_err(|_| StoreError::IntegerRange)?,
                now
            ],
        )?;
        transaction.commit()?;
        evictions.commit();

        Ok(UploadStart::Reserved(UploadReservation {
            store: self.clone(),
            temp_path: self.config.root.join("tmp").join(format!("{id}.part")),
            id,
            expected_hash: expected_hash.to_owned(),
            expected_size,
            claim,
            completed: false,
        }))
    }

    pub fn check_upload(&self, expected_hash: &str, expected_size: u64) -> Result<(), StoreError> {
        self.check_claimed_upload(
            expected_hash,
            expected_size,
            &ClaimSpec {
                signer_pubkey: String::new(),
                retention_tier: RetentionTier::Owner,
                declared_type: "application/octet-stream".to_owned(),
                grant_id: None,
                claim_expires_at: None,
                byte_limit: None,
            },
        )
    }

    pub fn check_claimed_upload(
        &self,
        expected_hash: &str,
        expected_size: u64,
        claim: &ClaimSpec,
    ) -> Result<(), StoreError> {
        validate_hash(expected_hash)?;
        validate_claim(claim)?;
        if expected_size > self.config.max_blob_bytes {
            return Err(StoreError::BlobTooLarge {
                size: expected_size,
                limit: self.config.max_blob_bytes,
            });
        }
        let expected_size_i64 =
            i64::try_from(expected_size).map_err(|_| StoreError::IntegerRange)?;
        let connection = self.connection()?;
        let now = unix_time()?;
        if let Some((_, stored_size, _)) = query_blob_row(&connection, expected_hash)? {
            if stored_size != expected_size {
                return Err(StoreError::LengthMismatch);
            }
            enforce_friend_limit(&connection, claim, expected_hash, expected_size, now)?;
            return Ok(());
        }
        enforce_friend_limit(&connection, claim, expected_hash, expected_size, now)?;
        let used: i64 = connection.query_row(
            "SELECT COALESCE((SELECT SUM(size) FROM blobs), 0) + \
                    COALESCE((SELECT SUM(size) FROM reservations), 0)",
            [],
            |row| row.get(0),
        )?;
        let quota = i64::try_from(self.config.quota_bytes).map_err(|_| StoreError::IntegerRange)?;
        let (_, high) = self.watermarks()?;
        match claim.retention_tier {
            RetentionTier::Guest => {
                let high = i64::try_from(high).map_err(|_| StoreError::IntegerRange)?;
                if quota.saturating_sub(used.saturating_add(expected_size_i64)) < high {
                    return Err(StoreError::QuotaExceeded);
                }
            }
            RetentionTier::Owner | RetentionTier::Friend => {
                let evictable: i64 = connection.query_row(
                    "SELECT COALESCE(SUM(b.size), 0)
                     FROM blobs b
                     WHERE NOT EXISTS (
                       SELECT 1 FROM claims c
                       WHERE c.hash = b.hash
                         AND (c.claim_expires_at IS NULL OR c.claim_expires_at > ?1)
                         AND c.retention_tier IN ('owner', 'friend')
                     )",
                    [now],
                    |row| row.get(0),
                )?;
                if used.saturating_sub(evictable) > quota.saturating_sub(expected_size_i64) {
                    return Err(StoreError::QuotaExceeded);
                }
            }
        }
        Ok(())
    }

    fn watermarks(&self) -> Result<(u64, u64), StoreError> {
        let low = self.config.quota_bytes / 10;
        let high = (self.config.quota_bytes / 5)
            .max(low.saturating_add(1))
            .min(self.config.quota_bytes.saturating_sub(1));
        if low >= high || high >= self.config.quota_bytes {
            return Err(StoreError::InvalidWatermarks);
        }
        Ok((low, high))
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

    pub fn list_claims(
        &self,
        signer_pubkey: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ClaimMetadata>, StoreError> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::InvalidListLimit);
        }
        if let Some(cursor) = cursor {
            validate_hash(cursor)?;
        }
        let connection = self.connection()?;
        let now = unix_time()?;
        let cursor_position = match cursor {
            Some(cursor) => Some(
                connection
                    .query_row(
                        "SELECT created_at FROM claims
                         WHERE signer_pubkey = ?1 AND hash = ?2
                           AND (claim_expires_at IS NULL OR claim_expires_at > ?3)",
                        params![signer_pubkey, cursor, now],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .ok_or(StoreError::InvalidCursor)?,
            ),
            None => None,
        };
        let mut statement = connection.prepare(
            "SELECT c.hash, c.created_at
             FROM claims c
             WHERE c.signer_pubkey = ?1
               AND (c.claim_expires_at IS NULL OR c.claim_expires_at > ?2)
               AND (?3 IS NULL OR c.created_at < ?3 OR (c.created_at = ?3 AND c.hash > ?4))
             ORDER BY c.created_at DESC, c.hash ASC
             LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                signer_pubkey,
                now,
                cursor_position,
                cursor.unwrap_or(""),
                i64::try_from(limit).map_err(|_| StoreError::IntegerRange)?
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut claims = Vec::new();
        for row in rows {
            let (hash, uploaded) = row?;
            let metadata = query_blob(&connection, &hash)?.ok_or(StoreError::MissingBlob)?;
            claims.push(ClaimMetadata {
                sha256: hash,
                size: metadata.size,
                content_type: metadata.content_type,
                uploaded: u64::try_from(uploaded).map_err(|_| StoreError::IntegerRange)?,
            });
        }
        Ok(claims)
    }

    pub fn delete_owned(
        &self,
        hash: &str,
        owner_pubkey: &str,
    ) -> Result<DeleteOutcome, StoreError> {
        self.delete_claim(hash, owner_pubkey)
    }

    pub fn delete_claim(
        &self,
        hash: &str,
        signer_pubkey: &str,
    ) -> Result<DeleteOutcome, StoreError> {
        validate_hash(hash)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if query_blob(&transaction, hash)?.is_none() {
            return Err(StoreError::MissingBlob);
        }
        let claims_blob = transaction
            .query_row(
                "SELECT 1 FROM claims WHERE signer_pubkey = ?1 AND hash = ?2",
                params![signer_pubkey, hash],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !claims_blob {
            return Err(StoreError::NotClaimant);
        }

        transaction.execute(
            "DELETE FROM claims WHERE signer_pubkey = ?1 AND hash = ?2",
            params![signer_pubkey, hash],
        )?;
        let remaining_claims: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM claims
             WHERE hash = ?1 AND (claim_expires_at IS NULL OR claim_expires_at > ?2)",
            params![hash, unix_time()?],
            |row| row.get(0),
        )?;
        if remaining_claims > 0 {
            transaction.commit()?;
            return Ok(DeleteOutcome::ClaimRemoved);
        }

        let blob_path = self.blob_path(hash);
        if !blob_path.is_file() {
            return Err(StoreError::MissingBlob);
        }
        let tombstone = self
            .config
            .root
            .join("tmp")
            .join(format!("{hash}.{}.delete", Uuid::new_v4().simple()));
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
        self.reap_expired_claims()?;
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

    pub fn reap_expired_claims(&self) -> Result<u64, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = unix_time()?;
        transaction.execute(
            "DELETE FROM claims WHERE claim_expires_at IS NOT NULL AND claim_expires_at <= ?1",
            [now],
        )?;
        let mut statement = transaction.prepare(
            "SELECT b.hash, b.size FROM blobs b
             WHERE NOT EXISTS (SELECT 1 FROM claims c WHERE c.hash = b.hash)
             ORDER BY b.created_at ASC, b.hash ASC",
        )?;
        let orphaned = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut removed = PendingEvictions::default();
        for (hash, size) in orphaned {
            let original_path = self.blob_path(&hash);
            if !original_path.is_file() {
                return Err(StoreError::MissingBlob);
            }
            let tombstone_path = self
                .config
                .root
                .join("tmp")
                .join(format!("{hash}.{}.evict", Uuid::new_v4().simple()));
            fs::rename(&original_path, &tombstone_path)?;
            removed.items.push(PendingEviction {
                original_path,
                tombstone_path,
                record: EvictionRecord {
                    sha256: hash.clone(),
                    size: u64::try_from(size).map_err(|_| StoreError::IntegerRange)?,
                    retention_tier: RetentionTier::Guest,
                    reason: "all claims expired",
                    evicted_at: u64::try_from(now).map_err(|_| StoreError::IntegerRange)?,
                },
            });
            transaction.execute("DELETE FROM blobs WHERE hash = ?1", [&hash])?;
        }
        let count = u64::try_from(removed.items.len()).map_err(|_| StoreError::IntegerRange)?;
        transaction.commit()?;
        removed.commit();
        Ok(count)
    }

    pub fn reconcile_claim_policy(
        &self,
        owner_pubkeys: &BTreeSet<String>,
        active_friend_grants: &BTreeSet<(String, String)>,
    ) -> Result<u64, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = transaction.prepare(
            "SELECT signer_pubkey, hash, retention_tier, grant_id
             FROM claims WHERE retention_tier IN ('owner', 'friend')",
        )?;
        let claims = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut demoted = 0_u64;
        for (signer, hash, tier, grant_id) in claims {
            let permitted = match RetentionTier::from_database(&tier)? {
                RetentionTier::Owner => owner_pubkeys.contains(&signer),
                RetentionTier::Friend => grant_id.is_some_and(|grant_id| {
                    active_friend_grants.contains(&(signer.clone(), grant_id))
                }),
                RetentionTier::Guest => true,
            };
            if !permitted {
                transaction.execute(
                    "UPDATE claims SET retention_tier = 'guest', grant_id = NULL,
                     claim_expires_at = NULL WHERE signer_pubkey = ?1 AND hash = ?2",
                    params![signer, hash],
                )?;
                demoted = demoted.checked_add(1).ok_or(StoreError::IntegerRange)?;
            }
        }
        transaction.commit()?;
        Ok(demoted)
    }

    fn evict_guests(
        &self,
        transaction: &Connection,
        bytes_to_free: i64,
        now: i64,
    ) -> Result<PendingEvictions, StoreError> {
        let mut statement = transaction.prepare(
            "SELECT b.hash, b.size
             FROM blobs b
             WHERE NOT EXISTS (
               SELECT 1 FROM claims c
               WHERE c.hash = b.hash
                 AND (c.claim_expires_at IS NULL OR c.claim_expires_at > ?1)
                 AND c.retention_tier IN ('owner', 'friend')
             )
             ORDER BY b.created_at ASC, b.hash ASC",
        )?;
        let candidates = statement
            .query_map([now], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);

        let mut evictions = PendingEvictions::default();
        let mut freed = 0_i64;
        for (hash, size) in candidates {
            if freed >= bytes_to_free {
                break;
            }
            let original_path = self.blob_path(&hash);
            if !original_path.is_file() {
                return Err(StoreError::MissingBlob);
            }
            let tombstone_path = self
                .config
                .root
                .join("tmp")
                .join(format!("{hash}.{}.evict", Uuid::new_v4().simple()));
            fs::rename(&original_path, &tombstone_path)?;
            let record = EvictionRecord {
                sha256: hash.clone(),
                size: u64::try_from(size).map_err(|_| StoreError::IntegerRange)?,
                retention_tier: RetentionTier::Guest,
                reason: "storage watermark",
                evicted_at: u64::try_from(now).map_err(|_| StoreError::IntegerRange)?,
            };
            evictions.items.push(PendingEviction {
                original_path,
                tombstone_path,
                record,
            });
            transaction.execute("DELETE FROM blobs WHERE hash = ?1", [&hash])?;
            freed = freed.saturating_add(size);
        }
        Ok(evictions)
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
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS blobs (
                hash TEXT PRIMARY KEY NOT NULL,
                size INTEGER NOT NULL CHECK (size >= 0),
                content_type TEXT NOT NULL,
                created_at INTEGER NOT NULL
             );
             -- `owners` is the 0.2 schema.  Creating it when absent makes the
             -- migration idempotent for both fresh and existing stores.
             CREATE TABLE IF NOT EXISTS owners (
                owner_pubkey TEXT NOT NULL,
                hash TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (owner_pubkey, hash)
             );
             CREATE TABLE IF NOT EXISTS claims (
                hash TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
                signer_pubkey TEXT NOT NULL,
                retention_tier TEXT NOT NULL
                    CHECK (retention_tier IN ('owner', 'friend', 'guest')),
                declared_type TEXT NOT NULL,
                grant_id TEXT,
                claim_expires_at INTEGER,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (signer_pubkey, hash)
             );
             INSERT OR IGNORE INTO claims
                (hash, signer_pubkey, retention_tier, declared_type,
                 grant_id, claim_expires_at, created_at)
             SELECT o.hash, o.owner_pubkey, 'owner', b.content_type,
                    NULL, NULL, o.created_at
             FROM owners o JOIN blobs b ON b.hash = o.hash;
             DROP TABLE owners;
             -- Reservations never survive a clean start, so replacing the
             -- old table is safer than attempting a partial column migration.
             DROP TABLE IF EXISTS reservations;
             CREATE TABLE reservations (
                id TEXT PRIMARY KEY NOT NULL,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL CHECK (size >= 0),
                retention_tier TEXT NOT NULL
                    CHECK (retention_tier IN ('owner', 'friend', 'guest')),
                signer_pubkey TEXT NOT NULL,
                declared_type TEXT NOT NULL,
                grant_id TEXT,
                claim_expires_at INTEGER,
                created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS repair_sources (
                hash TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
                source_url TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (hash, source_url)
             );
             CREATE INDEX IF NOT EXISTS claims_hash_active
                ON claims(hash, retention_tier, claim_expires_at);
             CREATE INDEX IF NOT EXISTS claims_signer_list
                ON claims(signer_pubkey, created_at DESC, hash);
             CREATE INDEX IF NOT EXISTS reservations_signer
                ON reservations(signer_pubkey, retention_tier);
             PRAGMA user_version = 2;
             COMMIT;",
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
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                let hash = name
                    .split('.')
                    .next()
                    .filter(|hash| validate_hash(hash).is_ok());
                let recoverable = name.ends_with(".delete")
                    || name.ends_with(".evict")
                    || name.ends_with(".corrupt");
                if recoverable
                    && let Some(hash) = hash
                    && query_blob_row(&connection, hash)?.is_some()
                    && !self.blob_path(hash).exists()
                {
                    let destination = self.blob_path(hash);
                    let parent = destination.parent().ok_or(StoreError::InvalidHash)?;
                    create_private_dir(parent)?;
                    fs::rename(&path, &destination)?;
                    set_private_file_permissions(&destination)?;
                    tracing::warn!(
                        hash,
                        "restored a blob after an interrupted file transaction"
                    );
                } else {
                    fs::remove_file(path)?;
                }
            }
        }
        for prefix in fs::read_dir(self.config.root.join("blobs"))? {
            let prefix = prefix?.path();
            if !prefix.is_dir() {
                continue;
            }
            for entry in fs::read_dir(prefix)? {
                let path = entry?.path();
                let Some(hash) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if path.is_file()
                    && validate_hash(hash).is_ok()
                    && query_blob_row(&connection, hash)?.is_none()
                {
                    fs::remove_file(&path)?;
                    tracing::warn!(
                        hash,
                        "removed an unindexed blob left by an interrupted commit"
                    );
                }
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
        let backup = self.store.config.root.join("tmp").join(format!(
            "{}.{}.corrupt",
            self.expected_hash,
            Uuid::new_v4().simple()
        ));
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
        if let Some((_, stored_size, _)) = query_blob_row(&transaction, &self.expected_hash)? {
            if stored_size != self.expected_size {
                return Err(StoreError::LengthMismatch);
            }
            fs::remove_file(&self.temp_path)?;
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
                    self.claim.declared_type,
                    uploaded
                ],
            )?;
        }

        upsert_claim(&transaction, &self.expected_hash, &self.claim, uploaded)?;
        let metadata =
            query_blob(&transaction, &self.expected_hash)?.ok_or(StoreError::MissingBlob)?;
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

fn validate_claim(claim: &ClaimSpec) -> Result<(), StoreError> {
    if claim.declared_type.is_empty() || claim.declared_type.len() > 255 {
        return Err(StoreError::InvalidTier);
    }
    if claim
        .claim_expires_at
        .is_some_and(|expires| expires > i64::MAX as u64)
        || claim
            .byte_limit
            .is_some_and(|limit| limit > i64::MAX as u64)
    {
        return Err(StoreError::IntegerRange);
    }
    let valid = match claim.retention_tier {
        RetentionTier::Owner | RetentionTier::Guest => {
            claim.grant_id.is_none()
                && claim.claim_expires_at.is_none()
                && claim.byte_limit.is_none()
        }
        RetentionTier::Friend => {
            claim
                .grant_id
                .as_deref()
                .is_some_and(|grant| !grant.is_empty() && grant.len() <= 255)
                && claim.claim_expires_at.is_some()
                && claim.byte_limit.is_some_and(|limit| limit > 0)
        }
    };
    valid.then_some(()).ok_or(StoreError::InvalidTier)
}

fn enforce_friend_limit(
    connection: &Connection,
    claim: &ClaimSpec,
    expected_hash: &str,
    expected_size: u64,
    now: i64,
) -> Result<(), StoreError> {
    if claim.retention_tier != RetentionTier::Friend {
        return Ok(());
    }
    let expires_at = claim.claim_expires_at.ok_or(StoreError::InvalidTier)?;
    if expires_at <= u64::try_from(now).map_err(|_| StoreError::IntegerRange)? {
        return Err(StoreError::FriendLimitExceeded);
    }
    let already_claimed = connection
        .query_row(
            "SELECT 1 FROM claims
             WHERE signer_pubkey = ?1 AND hash = ?2
               AND retention_tier = 'friend'
               AND (claim_expires_at IS NULL OR claim_expires_at > ?3)",
            params![claim.signer_pubkey, expected_hash, now],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    let claimed: i64 = connection.query_row(
        "SELECT COALESCE(SUM(b.size), 0)
         FROM claims c JOIN blobs b ON b.hash = c.hash
         WHERE c.signer_pubkey = ?1 AND c.retention_tier = 'friend'
           AND (c.claim_expires_at IS NULL OR c.claim_expires_at > ?2)",
        params![claim.signer_pubkey, now],
        |row| row.get(0),
    )?;
    let reserved: i64 = connection.query_row(
        "SELECT COALESCE(SUM(size), 0) FROM reservations
         WHERE signer_pubkey = ?1 AND retention_tier = 'friend'",
        [&claim.signer_pubkey],
        |row| row.get(0),
    )?;
    let added = if already_claimed {
        0
    } else {
        i64::try_from(expected_size).map_err(|_| StoreError::IntegerRange)?
    };
    let limit = i64::try_from(claim.byte_limit.ok_or(StoreError::InvalidTier)?)
        .map_err(|_| StoreError::IntegerRange)?;
    if claimed.saturating_add(reserved).saturating_add(added) > limit {
        return Err(StoreError::FriendLimitExceeded);
    }
    Ok(())
}

fn upsert_claim(
    connection: &Connection,
    hash: &str,
    claim: &ClaimSpec,
    created_at: i64,
) -> Result<(), StoreError> {
    connection.execute(
        "INSERT INTO claims
         (hash, signer_pubkey, retention_tier, declared_type,
          grant_id, claim_expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(signer_pubkey, hash) DO UPDATE SET
           retention_tier = excluded.retention_tier,
           declared_type = excluded.declared_type,
           grant_id = excluded.grant_id,
           claim_expires_at = excluded.claim_expires_at,
           created_at = excluded.created_at",
        params![
            hash,
            claim.signer_pubkey,
            claim.retention_tier.as_str(),
            claim.declared_type,
            claim.grant_id,
            claim
                .claim_expires_at
                .map(i64::try_from)
                .transpose()
                .map_err(|_| StoreError::IntegerRange)?,
            created_at
        ],
    )?;
    Ok(())
}

fn query_blob(connection: &Connection, hash: &str) -> Result<Option<BlobMetadata>, StoreError> {
    let basic = query_blob_row(connection, hash)?;
    let Some((sha256, size, uploaded)) = basic else {
        return Ok(None);
    };
    let now = unix_time()?;
    let mut statement = connection.prepare(
        "SELECT retention_tier, declared_type FROM claims
         WHERE hash = ?1 AND (claim_expires_at IS NULL OR claim_expires_at > ?2)",
    )?;
    let rows = statement
        .query_map(params![hash, now], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut effective_tier = RetentionTier::Guest;
    let mut owner_types = BTreeSet::new();
    for (tier, declared_type) in rows {
        let tier = RetentionTier::from_database(&tier)?;
        effective_tier = effective_tier.max(tier);
        if tier == RetentionTier::Owner {
            owner_types.insert(declared_type);
        }
    }
    let owner_type = (effective_tier == RetentionTier::Owner && owner_types.len() == 1)
        .then(|| owner_types.into_iter().next())
        .flatten();
    let opaque = owner_type.is_none();
    Ok(Some(BlobMetadata {
        sha256,
        size,
        content_type: owner_type.unwrap_or_else(|| "application/octet-stream".to_owned()),
        uploaded,
        retention_tier: effective_tier,
        opaque,
    }))
}

fn query_blob_row(
    connection: &Connection,
    hash: &str,
) -> Result<Option<(String, u64, u64)>, StoreError> {
    connection
        .query_row(
            "SELECT hash, size, created_at FROM blobs WHERE hash = ?1",
            [hash],
            |row| {
                let size: i64 = row.get(1)?;
                let uploaded: i64 = row.get(2)?;
                Ok((row.get::<_, String>(0)?, size, uploaded))
            },
        )
        .optional()?
        .map(|(sha256, size, uploaded)| {
            Ok((
                sha256,
                u64::try_from(size).map_err(|_| StoreError::IntegerRange)?,
                u64::try_from(uploaded).map_err(|_| StoreError::IntegerRange)?,
            ))
        })
        .transpose()
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

    fn owner_claim(signer: &str, declared_type: &str) -> ClaimSpec {
        ClaimSpec {
            signer_pubkey: signer.to_owned(),
            retention_tier: RetentionTier::Owner,
            declared_type: declared_type.to_owned(),
            grant_id: None,
            claim_expires_at: None,
            byte_limit: None,
        }
    }

    fn guest_claim(signer: &str) -> ClaimSpec {
        ClaimSpec {
            signer_pubkey: signer.to_owned(),
            retention_tier: RetentionTier::Guest,
            declared_type: "text/html".to_owned(),
            grant_id: None,
            claim_expires_at: None,
            byte_limit: None,
        }
    }

    fn friend_claim(signer: &str, byte_limit: u64, expires_at: u64) -> ClaimSpec {
        ClaimSpec {
            signer_pubkey: signer.to_owned(),
            retention_tier: RetentionTier::Friend,
            declared_type: "image/png".to_owned(),
            grant_id: Some(format!("grant-{signer}")),
            claim_expires_at: Some(expires_at),
            byte_limit: Some(byte_limit),
        }
    }

    fn store_claim(store: &Store, bytes: &[u8], claim: ClaimSpec) -> String {
        let hash = hex::encode(Sha256::digest(bytes));
        match store
            .begin_claimed_upload(&hash, bytes.len() as u64, claim)
            .unwrap()
        {
            UploadStart::Existing(_) => {}
            UploadStart::Reserved(reservation) => {
                fs::write(reservation.temp_path(), bytes).unwrap();
                reservation.commit(&hash, bytes.len() as u64).unwrap();
            }
        }
        hash
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
            Err(StoreError::NotClaimant)
        ));
        assert_eq!(
            store.delete_owned(&hash, "01").unwrap(),
            DeleteOutcome::ClaimRemoved
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

    #[test]
    fn guest_admission_preserves_the_high_watermark_and_owner_evicts_only_guests() {
        let (_directory, store) = test_store(100, 100);
        let held_hash = hex::encode(Sha256::digest([b'h'; 70]));
        let held = store
            .begin_claimed_upload(&held_hash, 70, guest_claim("held-guest"))
            .unwrap();
        let concurrent_rejected = store.begin_claimed_upload(
            &hex::encode(Sha256::digest([b'x'; 11])),
            11,
            guest_claim("other-guest"),
        );
        assert!(matches!(
            concurrent_rejected,
            Err(StoreError::QuotaExceeded)
        ));
        drop(held);

        let oldest_guest = store_claim(&store, &[b'a'; 30], guest_claim("oldest-guest"));
        let newer_guest = store_claim(&store, &[b'g'; 40], guest_claim("newer-guest"));
        let connection = store.connection().unwrap();
        connection
            .execute(
                "UPDATE blobs SET created_at = 1 WHERE hash = ?1",
                [&oldest_guest],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE blobs SET created_at = 2 WHERE hash = ?1",
                [&newer_guest],
            )
            .unwrap();
        drop(connection);

        let owner_bytes = [b'o'; 25];
        let owner_hash = hex::encode(Sha256::digest(owner_bytes));
        let UploadStart::Reserved(owner) = store
            .begin_claimed_upload(
                &owner_hash,
                owner_bytes.len() as u64,
                owner_claim("owner", "audio/mpeg"),
            )
            .unwrap()
        else {
            panic!("owner bytes must reserve after guest eviction");
        };
        assert!(!store.blob_path(&oldest_guest).exists());
        assert!(store.blob_path(&newer_guest).is_file());
        fs::write(owner.temp_path(), owner_bytes).unwrap();
        owner.commit(&owner_hash, owner_bytes.len() as u64).unwrap();
        assert_eq!(store.stats().unwrap().bytes, 65);
        assert_eq!(
            store.get(&owner_hash).unwrap().unwrap().retention_tier,
            RetentionTier::Owner
        );
    }

    #[test]
    fn protected_claims_are_never_automatic_eviction_candidates() {
        let (_directory, store) = test_store(100, 100);
        let expires = u64::try_from(unix_time().unwrap()).unwrap() + 3600;
        let friend_hash = store_claim(&store, &[b'f'; 80], friend_claim("friend", 100, expires));
        let result = store.begin_claimed_upload(
            &hex::encode(Sha256::digest([b'o'; 30])),
            30,
            owner_claim("owner", "text/plain"),
        );
        assert!(matches!(result, Err(StoreError::QuotaExceeded)));
        assert!(store.blob_path(&friend_hash).is_file());
        assert_eq!(
            store.get(&friend_hash).unwrap().unwrap().retention_tier,
            RetentionTier::Friend
        );
    }

    #[test]
    fn friend_ceiling_counts_logical_claims_across_dedup_restart_and_expiry() {
        let (directory, store) = test_store(100, 100);
        let now = u64::try_from(unix_time().unwrap()).unwrap();
        let held_hash = hex::encode(Sha256::digest([b'h'; 6]));
        let held = store
            .begin_claimed_upload(
                &held_hash,
                6,
                friend_claim("concurrent-friend", 10, now + 3600),
            )
            .unwrap();
        assert!(matches!(
            store.begin_claimed_upload(
                &hex::encode(Sha256::digest([b'j'; 5])),
                5,
                friend_claim("concurrent-friend", 10, now + 3600)
            ),
            Err(StoreError::FriendLimitExceeded)
        ));
        drop(held);

        let shared = [b's'; 6];
        let hash = store_claim(&store, &shared, owner_claim("owner", "text/plain"));
        assert!(matches!(
            store
                .begin_claimed_upload(&hash, 6, friend_claim("friend", 10, now + 3600))
                .unwrap(),
            UploadStart::Existing(_)
        ));
        assert!(matches!(
            store.begin_claimed_upload(
                &hex::encode(Sha256::digest([b'n'; 5])),
                5,
                friend_claim("friend", 10, now + 3600)
            ),
            Err(StoreError::FriendLimitExceeded)
        ));

        let config = store.config().clone();
        drop(store);
        let reopened = Store::open(config).unwrap();
        assert!(matches!(
            reopened.begin_claimed_upload(
                &hex::encode(Sha256::digest([b'r'; 5])),
                5,
                friend_claim("friend", 10, now + 3600)
            ),
            Err(StoreError::FriendLimitExceeded)
        ));
        reopened
            .connection()
            .unwrap()
            .execute(
                "UPDATE claims SET claim_expires_at = ?1
                 WHERE signer_pubkey = 'friend' AND hash = ?2",
                params![i64::try_from(now.saturating_sub(1)).unwrap(), hash],
            )
            .unwrap();
        assert!(
            reopened
                .begin_claimed_upload(
                    &hex::encode(Sha256::digest([b'e'; 5])),
                    5,
                    friend_claim("friend", 10, now + 7200)
                )
                .is_ok()
        );
        drop(reopened);
        drop(directory);
    }

    #[test]
    fn effective_tier_is_strongest_and_ambiguous_owner_types_are_opaque() {
        let (_directory, store) = test_store(100, 100);
        let now = u64::try_from(unix_time().unwrap()).unwrap();
        let bytes = b"same physical bytes";
        let hash = store_claim(&store, bytes, friend_claim("friend", 100, now + 3600));
        let friend_view = store.get(&hash).unwrap().unwrap();
        assert_eq!(friend_view.retention_tier, RetentionTier::Friend);
        assert!(friend_view.opaque);
        assert_eq!(friend_view.content_type, "application/octet-stream");

        store_claim(&store, bytes, owner_claim("owner-a", "audio/mpeg"));
        let owner_view = store.get(&hash).unwrap().unwrap();
        assert_eq!(owner_view.retention_tier, RetentionTier::Owner);
        assert!(!owner_view.opaque);
        assert_eq!(owner_view.content_type, "audio/mpeg");

        store_claim(&store, bytes, owner_claim("owner-b", "image/png"));
        let ambiguous = store.get(&hash).unwrap().unwrap();
        assert!(ambiguous.opaque);
        assert_eq!(ambiguous.content_type, "application/octet-stream");
        assert_eq!(
            store.delete_claim(&hash, "owner-b").unwrap(),
            DeleteOutcome::ClaimRemoved
        );
        assert_eq!(
            store.get(&hash).unwrap().unwrap().content_type,
            "audio/mpeg"
        );
    }

    #[test]
    fn list_is_bounded_cursor_paginated_and_signer_scoped() {
        let (_directory, store) = test_store(100, 100);
        let first = store_claim(&store, b"first", owner_claim("owner", "text/plain"));
        let second = store_claim(&store, b"second", owner_claim("owner", "text/plain"));
        store_claim(&store, b"someone else", owner_claim("other", "text/plain"));

        let page = store.list_claims("owner", None, 1).unwrap();
        assert_eq!(page.len(), 1);
        assert!([first.clone(), second.clone()].contains(&page[0].sha256));
        let next = store
            .list_claims("owner", Some(&page[0].sha256), 10)
            .unwrap();
        assert_eq!(next.len(), 1);
        assert_ne!(next[0].sha256, page[0].sha256);
        assert!(matches!(
            store.list_claims("other", Some(&page[0].sha256), 10),
            Err(StoreError::InvalidCursor)
        ));
        assert!(matches!(
            store.list_claims("owner", None, 101),
            Err(StoreError::InvalidListLimit)
        ));
    }

    #[test]
    fn existing_owner_schema_migrates_to_claims_without_moving_blob_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("data");
        fs::create_dir_all(root.join("blobs").join("aa")).unwrap();
        fs::create_dir_all(root.join("tmp")).unwrap();
        let hash = "a".repeat(64);
        fs::write(root.join("blobs").join("aa").join(&hash), b"hello").unwrap();
        let database = Connection::open(root.join("wildbloom.sqlite3")).unwrap();
        database
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE blobs (
                   hash TEXT PRIMARY KEY NOT NULL, size INTEGER NOT NULL,
                   content_type TEXT NOT NULL, created_at INTEGER NOT NULL
                 );
                 CREATE TABLE owners (
                   owner_pubkey TEXT NOT NULL,
                   hash TEXT NOT NULL REFERENCES blobs(hash) ON DELETE CASCADE,
                   created_at INTEGER NOT NULL,
                   PRIMARY KEY (owner_pubkey, hash)
                 );
                 CREATE TABLE reservations (
                   id TEXT PRIMARY KEY NOT NULL, hash TEXT NOT NULL,
                   size INTEGER NOT NULL, created_at INTEGER NOT NULL
                 );",
            )
            .unwrap();
        database
            .execute("INSERT INTO blobs VALUES (?1, 5, 'text/plain', 1)", [&hash])
            .unwrap();
        database
            .execute("INSERT INTO owners VALUES ('owner', ?1, 1)", [&hash])
            .unwrap();
        drop(database);

        let store = Store::open(StoreConfig {
            root,
            quota_bytes: 100,
            max_blob_bytes: 100,
        })
        .unwrap();
        let metadata = store.get(&hash).unwrap().unwrap();
        assert_eq!(metadata.retention_tier, RetentionTier::Owner);
        assert_eq!(metadata.content_type, "text/plain");
        assert!(!metadata.opaque);
    }

    #[test]
    fn startup_restores_indexed_tombstones_and_removes_unindexed_blob_files() {
        let (_directory, store) = test_store(100, 100);
        let hash = store_claim(&store, b"indexed", owner_claim("owner", "text/plain"));
        let original = store.blob_path(&hash);
        let tombstone = store
            .config
            .root
            .join("tmp")
            .join(format!("{hash}.interrupted.delete"));
        fs::rename(&original, &tombstone).unwrap();
        let unindexed_hash = hex::encode(Sha256::digest(b"unindexed"));
        let unindexed = store.blob_path(&unindexed_hash);
        create_private_dir(unindexed.parent().unwrap()).unwrap();
        fs::write(&unindexed, b"unindexed").unwrap();
        let config = store.config().clone();
        drop(store);

        let reopened = Store::open(config).unwrap();
        assert!(reopened.blob_path(&hash).is_file());
        assert!(!tombstone.exists());
        assert!(!unindexed.exists());
        assert_eq!(
            reopened.get(&hash).unwrap().unwrap().content_type,
            "text/plain"
        );
    }

    #[test]
    fn removed_operator_grants_demote_claims_without_deleting_bytes() {
        let (_directory, store) = test_store(100, 100);
        let owner_hash = store_claim(&store, b"former owner", owner_claim("owner", "text/plain"));
        let now = u64::try_from(unix_time().unwrap()).unwrap();
        let friend_hash = store_claim(
            &store,
            b"former friend",
            friend_claim("friend", 100, now + 3600),
        );
        assert_eq!(
            store
                .reconcile_claim_policy(&BTreeSet::new(), &BTreeSet::new())
                .unwrap(),
            2
        );
        for hash in [owner_hash, friend_hash] {
            let metadata = store.get(&hash).unwrap().unwrap();
            assert_eq!(metadata.retention_tier, RetentionTier::Guest);
            assert!(metadata.opaque);
            assert!(store.blob_path(&hash).is_file());
        }
    }
}
