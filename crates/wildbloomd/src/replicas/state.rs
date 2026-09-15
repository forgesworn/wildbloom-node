use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::{
    policy::{VerifiedPolicy, canonical_hex, identifier},
    transport::{NetworkFailure, Profile},
};

pub const MAX_STATE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("replica state directory must be a private, ordinary directory")]
    Directory,
    #[error("another coordinator already owns this replica state directory")]
    Locked,
    #[error("replica state I/O failed")]
    Io,
    #[error("replica state is corrupt or uses an unsupported schema")]
    Schema,
    #[error("replica state belongs to a different owner or policy")]
    Identity,
    #[error("policy revision is older than or conflicts with the accepted policy")]
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Observation {
    Verified { at: u64 },
    Failed { reason: NetworkFailure },
    AwaitingAuthorisation,
    SignerUnavailable,
    Acknowledged,
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub requested_at: u64,
    pub event_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u8,
    pub owner: String,
    pub policy_id: String,
    pub revision: u64,
    pub event_id: String,
    pub profile: Profile,
    pub observed_at: Option<u64>,
    pub cursor: usize,
    pub repair_cursors: BTreeMap<String, usize>,
    pub observations: BTreeMap<String, BTreeMap<String, Observation>>,
    pub pending: BTreeMap<String, Pending>,
}

pub struct StateDirectory {
    root: PathBuf,
    // Keep the advisory lock alive for the full coordinator lifetime.
    _lock: File,
    pub snapshot: Option<Snapshot>,
}

pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, StateError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| StateError::Io)?;
    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(StateError::Schema);
    }
    let file = File::open(path).map_err(|_| StateError::Io)?;
    if !file.metadata().map_err(|_| StateError::Io)?.is_file() {
        return Err(StateError::Schema);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StateError::Io)?;
    if bytes.len() > limit {
        return Err(StateError::Schema);
    }
    Ok(bytes)
}

pub fn private_directory(path: &Path) -> Result<(), StateError> {
    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).map_err(|_| StateError::Io)?;
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| StateError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(StateError::Directory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StateError::Directory);
        }
    }
    Ok(())
}

pub fn write_private(root: &Path, name: &str, bytes: &[u8]) -> Result<(), StateError> {
    let destination = root.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&destination)
        && !metadata.file_type().is_file()
    {
        return Err(StateError::Io);
    }
    let mut temp = tempfile::NamedTempFile::new_in(root).map_err(|_| StateError::Io)?;
    temp.write_all(bytes).map_err(|_| StateError::Io)?;
    temp.as_file().sync_all().map_err(|_| StateError::Io)?;
    temp.persist(destination).map_err(|_| StateError::Io)?;
    #[cfg(unix)]
    {
        File::open(root)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| StateError::Io)?;
    }
    Ok(())
}

impl StateDirectory {
    pub fn open(root: &Path) -> Result<Self, StateError> {
        private_directory(root)?;
        let lock_path = root.join("coordinator.lock");
        if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
            && !metadata.file_type().is_file()
        {
            return Err(StateError::Io);
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path).map_err(|_| StateError::Io)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| StateError::Locked)?;
        private_directory(&root.join("pending"))?;
        let path = root.join("state.json");
        let snapshot = if path.try_exists().map_err(|_| StateError::Io)?
            || std::fs::symlink_metadata(&path).is_ok()
        {
            let snapshot: Snapshot = serde_json::from_slice(&read_bounded(&path, MAX_STATE_BYTES)?)
                .map_err(|_| StateError::Schema)?;
            if snapshot.version != 1
                || snapshot.revision == 0
                || !canonical_hex(&snapshot.owner, 32)
                || !canonical_hex(&snapshot.event_id, 32)
                || !identifier(&snapshot.policy_id)
                || snapshot.cursor >= 128
                || snapshot.pending.len() > 2048
                || snapshot.observations.len() > 128
                || snapshot.repair_cursors.len() > 128
                || snapshot
                    .repair_cursors
                    .iter()
                    .any(|(hash, cursor)| !canonical_hex(hash, 32) || *cursor >= 256)
                || snapshot.pending.iter().any(|(key, pending)| {
                    let Some((hash, target)) = key.split_once(':') else {
                        return true;
                    };
                    !canonical_hex(hash, 32)
                        || !identifier(target)
                        || pending.requested_at == 0
                        || !canonical_hex(&pending.event_id, 32)
                })
                || snapshot.observations.iter().any(|(hash, targets)| {
                    !canonical_hex(hash, 32)
                        || targets.len() > 16
                        || targets.keys().any(|id| !identifier(id))
                })
            {
                return Err(StateError::Schema);
            }
            Some(snapshot)
        } else {
            None
        };
        Ok(Self {
            root: root.to_owned(),
            _lock: lock,
            snapshot,
        })
    }

    pub fn accept(&mut self, policy: &VerifiedPolicy) -> Result<(), StateError> {
        if let Some(state) = &self.snapshot {
            if state.owner != policy.owner || state.policy_id != policy.policy.id {
                return Err(StateError::Identity);
            }
            if state.revision > policy.policy.revision
                || (state.revision == policy.policy.revision && state.event_id != policy.event_id)
            {
                return Err(StateError::Rollback);
            }
            if state.event_id == policy.event_id {
                return Ok(());
            }
        }
        self.snapshot = Some(Snapshot {
            version: 1,
            owner: policy.owner.clone(),
            policy_id: policy.policy.id.clone(),
            revision: policy.policy.revision,
            event_id: policy.event_id.clone(),
            profile: policy.policy.profile,
            observed_at: None,
            cursor: 0,
            repair_cursors: BTreeMap::new(),
            observations: BTreeMap::new(),
            pending: BTreeMap::new(),
        });
        // Commit rollback protection before any operation or queue cleanup.
        self.save()?;
        self.clear_pending_files()?;
        Ok(())
    }

    pub fn save(&self) -> Result<(), StateError> {
        let bytes = serde_json::to_vec_pretty(self.snapshot.as_ref().ok_or(StateError::Schema)?)
            .map_err(|_| StateError::Schema)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StateError::Schema);
        }
        write_private(&self.root, "state.json", &bytes)
    }

    pub fn invalidate(&mut self) -> Result<(), StateError> {
        if let Some(snapshot) = &mut self.snapshot {
            snapshot.observations.clear();
            snapshot.observed_at = None;
            snapshot.pending.clear();
            self.save()?;
        }
        self.clear_pending_files()
    }

    pub fn pending_path(&self, event_id: &str, signed: bool) -> PathBuf {
        self.root.join("pending").join(format!(
            "{}-{event_id}.json",
            if signed { "signed" } else { "request" }
        ))
    }

    pub fn write_request(&self, event_id: &str, json: &[u8]) -> Result<(), StateError> {
        if !super::policy::canonical_hex(event_id, 32) {
            return Err(StateError::Schema);
        }
        write_private(
            &self.root.join("pending"),
            &format!("request-{event_id}.json"),
            json,
        )
    }

    pub fn remove_request(&self, event_id: &str) -> Result<(), StateError> {
        if !super::policy::canonical_hex(event_id, 32) {
            return Err(StateError::Schema);
        }
        for signed in [false, true] {
            let path = self.pending_path(event_id, signed);
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(StateError::Io),
            }
        }
        Ok(())
    }

    fn clear_pending_files(&self) -> Result<(), StateError> {
        self.reconcile_pending_files(&[])
    }

    pub fn reconcile_pending_files(&self, keep: &[String]) -> Result<(), StateError> {
        for entry in std::fs::read_dir(self.root.join("pending")).map_err(|_| StateError::Io)? {
            let entry = entry.map_err(|_| StateError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let id = name
                .strip_prefix("request-")
                .or_else(|| name.strip_prefix("signed-"))
                .and_then(|name| name.strip_suffix(".json"));
            if id.is_some_and(|id| {
                super::policy::canonical_hex(id, 32) && !keep.iter().any(|kept| kept == id)
            }) {
                std::fs::remove_file(entry.path()).map_err(|_| StateError::Io)?;
            }
        }
        Ok(())
    }
}
