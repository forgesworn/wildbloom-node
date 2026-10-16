//! The encrypted key list (design question Q4): sealed under a key derived
//! from the recovery secret, uploaded by the recovery identity to both nodes
//! after changes, and read back on a new computer to restore.
//!
//! The last `seq` this computer sealed or opened is kept in the index and
//! passed to `open_newest`, so a node serving an older list is refused.  The
//! sealed (ciphertext) copy is also kept locally, so a restart does not need
//! the network to know the current list.

use super::client::{self, NodeEndpoint};
use super::device::{self, KeyList, KeyListError, RecoverySecret};
use super::engine::{
    Engine, OrInternal as _, device_error, host_of, internal, kv, write_private_file,
};
use super::index::{FileRecord, local, online};
use super::types::{CommandError, CommandResult, RestoreResult};
use super::{FileId, hex_lower};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

/// A sealed key list is far below this; it bounds what a node can make us read.
const MAX_KEY_LIST_ENVELOPE: usize = 80 * 1024 * 1024;

impl Engine {
    fn sealed_key_list_path(&self) -> PathBuf {
        self.cfg.data_dir.join("key-list.fswn")
    }

    /// Loads the key list into `slot` if it is not loaded yet: the local sealed
    /// copy, checked against the last seen `seq`, or an empty list on a
    /// computer that never sealed one.
    pub(crate) fn load_key_list(&self, slot: &mut Option<KeyList>) -> CommandResult<()> {
        if slot.is_some() {
            return Ok(());
        }
        let recovery = self.recovery()?;
        let last_seen = self
            .index
            .get_u64(kv::LAST_SEEN_SEQ)
            .or_internal()?
            .unwrap_or(0);
        let list = match std::fs::read(self.sealed_key_list_path()) {
            Ok(bytes) => KeyList::open_newest(&recovery, &[&bytes], last_seen)
                .map_err(|e| internal(e.to_string()))?,
            Err(_) if last_seen == 0 => KeyList::new(),
            // The local copy is gone; the next sync merges the nodes' copies,
            // which must be at least `last_seen`.
            Err(_) => KeyList::new(),
        };
        *slot = Some(list);
        Ok(())
    }

    /// Seals the current key list and puts it on both nodes, merging any
    /// copies the online node holds first (another computer with the same
    /// recovery key may have added files).  Previous copies are deleted once
    /// the new one is stored.
    pub(crate) async fn sync_key_list(self: &Arc<Self>) -> CommandResult<()> {
        let _turn = self.keysync.lock().await;
        let identity = self.identity()?;
        let recovery = identity.recovery.clone();
        let recovery_keys = recovery.identity().keys().clone();
        let mut slot = self.keylist.lock().await;
        self.load_key_list(&mut slot)?;
        let mut list = slot.clone().expect("loaded above");
        let last_seen = self
            .index
            .get_u64(kv::LAST_SEEN_SEQ)
            .or_internal()?
            .unwrap_or(0);
        let online = self.writable_online();
        let mut merged_away = Vec::new();
        if let Some(node) = &online
            && let Ok(listed) = client::list(&self.http, node, &recovery_keys).await
        {
            let mut copies = vec![list.clone()];
            for entry in listed {
                let Ok(bytes) =
                    client::download_bytes(&self.http, node, &entry.sha256, MAX_KEY_LIST_ENVELOPE)
                        .await
                else {
                    continue;
                };
                if let Ok(copy) = KeyList::open(&recovery, &bytes) {
                    copies.push(copy);
                    merged_away.push(entry.sha256);
                }
            }
            match KeyList::merge(copies) {
                Ok(merged) if merged.seq() >= last_seen => list = merged,
                // A conflicting or rolled-back set is not merged; this
                // computer's own list is still sealed and kept.
                _ => merged_away.clear(),
            }
        }
        if list.seq() < last_seen {
            // Without the nodes' copies the next seal could be older than one
            // already published; wait until the online node can be read.
            return Ok(());
        }
        let sealed = list.seal(&recovery).map_err(|e| internal(e.to_string()))?;
        write_private_file(&self.sealed_key_list_path(), &sealed)
            .map_err(|_| internal("could not keep the key list"))?;
        self.index
            .set_u64(kv::LAST_SEEN_SEQ, list.seq())
            .or_internal()?;
        *slot = Some(list);
        drop(slot);
        let sha = hex_lower(&Sha256::digest(&sealed));
        let size = sealed.len() as u64;
        let mut stored = Vec::new();
        if let Some(node) = self.local_endpoint() {
            let ok = client::upload(
                &self.http,
                &node,
                &recovery_keys,
                &sha,
                size,
                sealed.clone().into(),
            )
            .await
            .is_ok();
            stored.push(("local", kv::KEY_LIST_LOCAL_SHA, ok));
        }
        if let Some(node) = &online {
            let ok = client::upload(
                &self.http,
                node,
                &recovery_keys,
                &sha,
                size,
                sealed.clone().into(),
            )
            .await
            .is_ok();
            stored.push(("online", kv::KEY_LIST_ONLINE_SHA, ok));
        }
        for (node, key, ok) in stored {
            if !ok {
                continue;
            }
            if let Some(previous) = self.index.get(key).or_internal()?
                && previous != sha
            {
                self.index
                    .queue_delete(node, &previous, "recovery")
                    .or_internal()?;
            }
            self.index.set(key, &sha).or_internal()?;
            if node == "online" {
                for old in &merged_away {
                    if *old != sha {
                        self.index
                            .queue_delete("online", old, "recovery")
                            .or_internal()?;
                    }
                }
            }
        }
        self.run_pending_deletes().await;
        Ok(())
    }

    // ----------------------------------------------------------- restore

    /// `restore`: checks the key and the node, stores the recovery secret and
    /// makes this computer's device key, then waits for approval.
    pub async fn restore(
        self: &Arc<Self>,
        recovery_key: Option<&str>,
        recovery_file: Option<PathBuf>,
        url: Option<&str>,
    ) -> CommandResult<RestoreResult> {
        let (key_text, file_url) = match (recovery_key, recovery_file) {
            (Some(key), None) => (key.trim().to_owned(), None),
            (None, Some(path)) => read_recovery_file(&path)?,
            _ => return Err(CommandError::code("bad_key")),
        };
        let recovery =
            RecoverySecret::parse(&key_text).map_err(|_| CommandError::code("bad_key"))?;
        let url = url
            .map(str::to_owned)
            .or(file_url)
            .ok_or(CommandError::code("not_a_node"))?;
        let check = self.check_online_node(&url).await?;
        if !self.host.node_settings_exist() {
            self.host
                .ensure_node_settings()
                .map_err(|e| CommandError::with_message("node", e))?;
        }
        let keychain = self.keychain()?;
        let first = !self.index.get_bool(kv::FIRST_RUN_DONE).or_internal()?;
        let lock = {
            let dir = self.cfg.data_dir.join("locks");
            device::FirstRunLock::acquire(&dir).map_err(|e| device_error(&e))?
        };
        // An unfinished set-up with no files may switch to the typed key; a
        // computer with files keeps its recovery secret.
        if let Ok(Some(stored)) = keychain.recovery_secret()
            && stored != *recovery.secret()
        {
            if first && self.index.files().or_internal()?.is_empty() {
                keychain
                    .set_recovery_secret(recovery.secret())
                    .map_err(|e| super::engine::keychain_error(&e))?;
            } else {
                return Err(CommandError::with_host("wrong_key", host_of(&url)));
            }
        }
        let identity =
            device::restore_identity(&keychain, &lock, recovery).map_err(|e| device_error(&e))?;
        drop(lock);
        self.identity_after_restore(identity);
        *self.keylist.lock().await = None;
        let node = NodeEndpoint::parse(&url, self.cfg.allow_loopback_http)
            .map_err(|_| CommandError::with_host("not_a_node", host_of(&url)))?;
        if self.index.get(kv::ONLINE_URL).or_internal()?.as_deref() != Some(node.origin()) {
            self.index
                .set(kv::ONLINE_URL, node.origin())
                .or_internal()?;
        }
        for key in [kv::APPROVAL_BY, kv::APPROVAL_UNTIL, kv::APPROVAL_LIMIT] {
            self.index.unset(key).or_internal()?;
        }
        self.index
            .set_bool(kv::RESTORE_PENDING, true)
            .or_internal()?;
        if first {
            self.index
                .set(kv::FIRST_RUN_STEP, "approve")
                .or_internal()?;
        }
        self.host.trust_changed();
        self.emit_status();
        Ok(RestoreResult {
            next: "approve",
            host: Some(check.host),
        })
    }

    /// After approval: read the key list from the online node, recreate the
    /// rows and copy every file back to this computer.
    pub(crate) async fn restore_after_approval(self: &Arc<Self>) -> Result<(), &'static str> {
        let identity = self.identity().map_err(|_| "wrong_key")?;
        let recovery = identity.recovery.clone();
        let recovery_keys = recovery.identity().keys().clone();
        let node = self.writable_online().ok_or("no_files")?;
        let listed = client::list(&self.http, &node, &recovery_keys)
            .await
            .map_err(|_| "no_files")?;
        if listed.is_empty() {
            return Err("no_files");
        }
        let mut candidates = Vec::new();
        for entry in &listed {
            if let Ok(bytes) =
                client::download_bytes(&self.http, &node, &entry.sha256, MAX_KEY_LIST_ENVELOPE)
                    .await
            {
                candidates.push(bytes);
            }
        }
        let last_seen = self
            .index
            .get_u64(kv::LAST_SEEN_SEQ)
            .ok()
            .flatten()
            .unwrap_or(0);
        let refs: Vec<&[u8]> = candidates.iter().map(Vec::as_slice).collect();
        let list = match KeyList::open_newest(&recovery, &refs, last_seen) {
            Ok(list) => list,
            Err(KeyListError::NoCandidates) => return Err("no_files"),
            Err(_) => return Err("wrong_key"),
        };
        let keychain = self.keychain().map_err(|_| "wrong_key")?;
        let mut restored = Vec::new();
        for entry in list.entries() {
            let id = entry.id.to_string();
            if self.index.file(&id).ok().flatten().is_some() {
                continue;
            }
            if keychain.set_file_key(&entry.id, &entry.key).is_err() {
                continue;
            }
            let record = FileRecord {
                id: id.clone(),
                name: entry.name.clone(),
                media_type: entry.media_type.clone(),
                bytes: entry.bytes,
                added: entry.added,
                // Restored rows are not matched as duplicates of new drops.
                plain_sha256: format!("restored:{id}"),
                sha256: Some(hex_lower(&entry.sha256)),
                size: Some(entry.size),
                local: local::RESTORING.into(),
                online: online::OK.into(),
                attempts: 0,
                next_attempt: 0,
                watch_path: None,
                watch_size: None,
                watch_mtime: None,
            };
            if self.index.insert_file(&record).is_ok() {
                self.set_progress(&id, 0);
                restored.push(id);
            }
        }
        let _ = self.index.set_u64(kv::LAST_SEEN_SEQ, list.seq());
        *self.keylist.lock().await = Some(list);
        let _ = self.index.set_bool(kv::RESTORE_PENDING, false);
        let _ = self.index.set_bool(kv::FIRST_RUN_DONE, true);
        let _ = self.index.unset(kv::FIRST_RUN_STEP);
        // The owner typed the key in, so it exists somewhere; saving it again
        // is still offered (status priority 10).
        let _ = self.index.set_bool(kv::RECOVERY_CONFIRMED, false);
        self.emit_status();
        let engine = self.clone();
        self.rt.spawn(async move {
            for id in restored {
                let ok = engine.copy_online_to_local(&id).await;
                let _ = engine
                    .index
                    .set_local(&id, if ok { local::OK } else { local::MISSING });
                // This computer's device key also claims the online copy, so
                // Remove here can delete it (BUD-12 deletion is self-only).
                if ok {
                    let _ = engine.index.set_online(&id, online::QUEUED);
                }
                engine.clear_progress(&id);
                engine.emit_row(&id);
            }
            engine.emit_status();
            engine.wake.notify_one();
            engine.keysync_wake.notify_one();
        });
        Ok(())
    }
}

/// The key and online node address from a recovery file (section 9.2).
fn read_recovery_file(path: &std::path::Path) -> CommandResult<(String, Option<String>)> {
    use std::io::Read as _;
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(64 * 1024).read_to_string(&mut text))
        .map_err(|_| CommandError::code("bad_key"))?;
    let text = zeroize::Zeroizing::new(text);
    let key = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(wildbloom_envelope::WBK1_PREFIX))
        .ok_or(CommandError::code("bad_key"))?
        .to_owned();
    let url = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("Online node:"))
        .map(|rest| rest.trim().to_owned())
        .filter(|rest| rest.starts_with("http"));
    Ok((key, url))
}

#[allow(dead_code)]
fn file_id(id: &str) -> Option<FileId> {
    FileId::parse(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_recovery_file_format() {
        let dir = tempfile::tempdir().unwrap();
        let secret = RecoverySecret::generate().unwrap();
        let path = dir.path().join("Wildbloom recovery key.txt");
        std::fs::write(
            &path,
            format!(
                "Wildbloom recovery key\nCreated 1 January 2026 on Test\n\n{}\n\nOnline node: https://storage.example\n\nUse this…\n",
                secret.to_display().as_str()
            ),
        )
        .unwrap();
        let (key, url) = read_recovery_file(&path).unwrap();
        assert_eq!(RecoverySecret::parse(&key).unwrap(), secret);
        assert_eq!(url.as_deref(), Some("https://storage.example"));
        std::fs::write(&path, "nothing here").unwrap();
        assert_eq!(read_recovery_file(&path).unwrap_err().code, "bad_key");
    }
}
