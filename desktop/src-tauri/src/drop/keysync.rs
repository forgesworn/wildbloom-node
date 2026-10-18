//! The encrypted key list (design question Q4): sealed under a key derived
//! from the recovery secret, uploaded by the recovery identity to both nodes
//! after changes, and read back on a new computer to restore.
//!
//! The last `seq` this computer sealed or opened is kept in the index and
//! passed to `open_newest`, so a node serving an older list is refused.  The
//! sealed (ciphertext) copy is also kept locally, so a restart does not need
//! the network to know the current list.

use super::client::{self, NodeEndpoint, NodeError};
use super::device::{self, KeyList, KeyListEntry, KeyListError, RecoverySecret};
use super::engine::{
    Engine, OrInternal as _, RemoveHow, device_error, host_of, internal, kv, write_private_file,
};
use super::index::{FileRecord, local, online};
use super::types::{CommandError, CommandResult, RestoreResult};
use super::{FileId, hex_lower};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

/// A sealed key list is far below this; it bounds what a node can make us read.
const MAX_KEY_LIST_ENVELOPE: usize = 80 * 1024 * 1024;
/// Key list copies opened per pull, so a node offering many cannot stall one.
const PULL_BATCH: usize = 16;

impl Engine {
    fn sealed_key_list_path(&self) -> PathBuf {
        self.cfg.data_dir.join("key-list.fswn")
    }

    /// Loads the key list into `slot` if it is not loaded yet: the local sealed
    /// copy, checked against the last seen `seq`, or an empty list on a
    /// computer that never sealed one.  Either way the list is then
    /// reconciled with the index, so nothing the index and keychain know about
    /// can be missing from it.  A local copy that cannot be opened (or is older
    /// than one already seen) is an error: the caller marks the key list as
    /// failed and the next sync rebuilds it from the nodes' copies.
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
        let mut list = match std::fs::read(self.sealed_key_list_path()) {
            Ok(bytes) => KeyList::open_newest(&recovery, &[&bytes], last_seen)
                .map_err(|e| internal(e.to_string()))?,
            // Never sealed here, or the local copy is gone: the next sync
            // merges the nodes' copies, which must be at least `last_seen`.
            Err(_) => KeyList::new(),
        };
        self.reconcile_key_list(&mut list)?;
        *slot = Some(list);
        Ok(())
    }

    /// Adds every kept file the index has an envelope and a keychain key for,
    /// and applies every recorded removal.  The index and the keychain are the
    /// durable record; the in-memory list is never the only copy of an entry.
    /// Entry fields come from the row's frozen columns, never recomputed, so a
    /// rebuilt entry is identical to the one first sealed (a differing copy at
    /// one `seq` would make every merge fail).
    pub(crate) fn reconcile_key_list(&self, list: &mut KeyList) -> CommandResult<()> {
        for (id, at) in self.index.tombstones().or_internal()? {
            if let Some(file_id) = FileId::parse(&id) {
                let _ = list.remove(&file_id, at.max(1));
            }
        }
        let keychain = self.keychain()?;
        for file in self.index.files().or_internal()? {
            if matches!(
                file.local.as_str(),
                local::UNREADABLE | local::ENCRYPTING | local::NOT_KEPT
            ) {
                continue;
            }
            let (Some(sha), Some(size), Some(file_id)) = (
                file.sha256.as_deref().and_then(super::parse_sha256),
                file.size,
                FileId::parse(&file.id),
            ) else {
                continue;
            };
            if list.get(&file_id).is_some() || list.tombstones().iter().any(|t| t.id == file_id) {
                continue;
            }
            let Some(key) = keychain
                .file_key(&file_id)
                .map_err(|e| super::engine::keychain_error(&e))?
            else {
                continue;
            };
            let media_type =
                wildbloom_envelope::normalise_media_type(&file.media_type).unwrap_or_default();
            let _ = list.insert(KeyListEntry {
                id: file_id,
                sha256: sha,
                size,
                key,
                name: file.name.clone(),
                media_type,
                bytes: file.bytes,
                added: file.added,
                path: entry_path(&file),
                prev: file.prev.as_deref().and_then(FileId::parse),
                plain: super::parse_sha256(&file.entry_plain),
                from: file.origin.clone(),
            });
        }
        Ok(())
    }

    /// Seals `list`, keeps the sealed copy and its `seq` locally.
    fn seal_locally(
        &self,
        list: &mut KeyList,
        recovery: &RecoverySecret,
    ) -> CommandResult<Vec<u8>> {
        let sealed = list.seal(recovery).map_err(|e| internal(e.to_string()))?;
        write_private_file(&self.sealed_key_list_path(), &sealed)
            .map_err(|_| internal("could not keep the key list"))?;
        self.index
            .set_u64(kv::LAST_SEEN_SEQ, list.seq())
            .or_internal()?;
        self.index
            .set_bool(kv::KEY_LIST_FAILED, false)
            .or_internal()?;
        Ok(sealed)
    }

    /// The key list problem shown in the status line, if any.
    pub(crate) fn key_list_failed(&self) -> bool {
        self.index.get_bool(kv::KEY_LIST_FAILED).unwrap_or(false)
    }

    /// Runs one sync and records whether it left the key list failed.
    pub(crate) async fn sync_key_list_reporting(self: &Arc<Self>) {
        let result = self.sync_key_list().await;
        if result.is_err() {
            let _ = self.index.set_bool(kv::KEY_LIST_FAILED, true);
            let _ = self.index.set_bool(kv::KEY_LIST_PENDING, true);
        }
        self.emit_status();
    }

    /// Reconciles the key list with the index, seals it locally first (before
    /// any network work), merges any copies the online node holds (another
    /// computer with the same recovery key may have added files), and puts the
    /// result on both nodes.  Previous copies are deleted once the new one is
    /// stored.
    pub(crate) async fn sync_key_list(self: &Arc<Self>) -> CommandResult<()> {
        let _turn = self.keysync.lock().await;
        let identity = self.identity()?;
        let recovery = identity.recovery.clone();
        let recovery_keys = recovery.identity().keys().clone();
        let mut slot = self.keylist.lock().await;
        let mut list = match self.load_key_list(&mut slot) {
            Ok(()) => slot.clone().expect("loaded above"),
            // An unreadable local copy: rebuild from the index and let the
            // nodes' copies supply the sequence number.
            Err(_) => {
                self.index
                    .set_bool(kv::KEY_LIST_FAILED, true)
                    .or_internal()?;
                let mut fresh = KeyList::new();
                self.reconcile_key_list(&mut fresh)?;
                fresh
            }
        };
        self.reconcile_key_list(&mut list)?;
        let last_seen = self
            .index
            .get_u64(kv::LAST_SEEN_SEQ)
            .or_internal()?
            .unwrap_or(0);
        // 1. Durable on this computer before anything touches the network.
        let mut sealed = None;
        if list.seq() >= last_seen {
            sealed = Some(self.seal_locally(&mut list, &recovery)?);
            *slot = Some(list.clone());
        }
        // 2. Merge the online node's copies.
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
                Ok(merged) if merged.seq() >= last_seen && merged != list => {
                    list = merged;
                    sealed = None;
                }
                Ok(merged) if merged.seq() >= last_seen => {}
                // A conflicting or rolled-back set is not merged; this
                // computer's own list is still sealed and kept.
                _ => merged_away.clear(),
            }
        }
        if list.seq() < last_seen {
            // Without the nodes' copies the next seal could be older than one
            // already published; the entries stay in the index and keychain
            // and are reconciled in on the next attempt.
            self.index
                .set_bool(kv::KEY_LIST_PENDING, true)
                .or_internal()?;
            self.index
                .set_bool(kv::KEY_LIST_FAILED, true)
                .or_internal()?;
            return Ok(());
        }
        let sealed = match sealed {
            Some(sealed) => sealed,
            None => self.seal_locally(&mut list, &recovery)?,
        };
        let applied = list.clone();
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
            stored.push(("local".to_owned(), kv::KEY_LIST_LOCAL_SHA, ok));
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
            stored.push((node.origin().to_owned(), kv::KEY_LIST_ONLINE_SHA, ok));
        }
        // Retried on the next mirror pass, when a node comes back or the
        // local node finishes starting.
        let complete = self.local_endpoint().is_some()
            && stored.iter().all(|(_, _, ok)| *ok)
            && stored.len() == 1 + usize::from(online.is_some());
        self.index
            .set_bool(kv::KEY_LIST_PENDING, !complete)
            .or_internal()?;
        for (node, key, ok) in stored {
            if !ok {
                continue;
            }
            // `<node>|<sha256>`: a previous copy is deleted where it was put.
            if let Some(previous) = self.index.get(key).or_internal()?
                && let Some((previous_node, previous_sha)) = previous.split_once('|')
                && previous_sha != sha
            {
                self.index
                    .queue_delete(previous_node, previous_sha, "recovery", 0)
                    .or_internal()?;
            }
            self.index
                .set(key, &format!("{node}|{sha}"))
                .or_internal()?;
            if key == kv::KEY_LIST_ONLINE_SHA {
                for old in &merged_away {
                    if *old != sha {
                        self.index
                            .queue_delete(&node, old, "recovery", 0)
                            .or_internal()?;
                    }
                }
            }
        }
        self.run_pending_deletes().await;
        // Other computers' additions and removals merged in above reach the
        // rows here too.
        self.apply_key_list(&applied).await;
        Ok(())
    }

    // -------------------------------------------------------------- pull

    /// Runs one pull and updates the status.
    pub(crate) async fn pull_key_list_reporting(self: &Arc<Self>) {
        let _ = self.pull_key_list().await;
        self.emit_status();
    }

    /// Reads the online node's key list copies that this computer has not
    /// merged yet, merges them into the current list and applies the result
    /// to the rows.  It needs no active approval (listing and reading are not
    /// writes), and it seals and uploads nothing itself:
    ///
    /// - when the merge adds nothing, nothing changes;
    /// - when the merge equals the newest copy read, that copy is adopted as
    ///   this computer's sealed list and `seq`;
    /// - otherwise this computer holds something the newest copy lacks, and
    ///   the key list sync is woken once to publish the merge.
    ///
    /// Contents are compared without `seq`, so two computers never re-seal
    /// each other's lists in turn.  Merging always includes the current list,
    /// so an old or withheld copy can neither bring a removed file back nor
    /// lower `seq`.
    pub(crate) async fn pull_key_list(self: &Arc<Self>) -> CommandResult<()> {
        if !self.index.get_bool(kv::FIRST_RUN_DONE).or_internal()?
            || self.index.get_bool(kv::RESTORE_PENDING).or_internal()?
        {
            return Ok(());
        }
        let Ok(identity) = self.identity() else {
            return Ok(());
        };
        let Some(node) = self.online_endpoint() else {
            return Ok(());
        };
        let recovery = identity.recovery.clone();
        let recovery_keys = recovery.identity().keys().clone();
        let _turn = self.keysync.lock().await;
        // Reachability is reported by the health checks.
        let Ok(listed) = client::list(&self.http, &node, &recovery_keys).await else {
            return Ok(());
        };
        let own = self
            .index
            .get(kv::KEY_LIST_ONLINE_SHA)
            .or_internal()?
            .and_then(|value| {
                let (origin, sha) = value.split_once('|')?;
                (origin == node.origin()).then(|| sha.to_owned())
            });
        let candidates: Vec<String> = {
            let pulled = self.pulled.lock().map_err(|_| internal("lock"))?;
            listed
                .into_iter()
                .map(|l| l.sha256)
                .filter(|sha| Some(sha) != own.as_ref() && !pulled.contains(sha))
                .take(PULL_BATCH)
                .collect()
        };
        let mut opened: Vec<(String, KeyList, Vec<u8>)> = Vec::new();
        for sha in candidates {
            match client::download_bytes(&self.http, &node, &sha, MAX_KEY_LIST_ENVELOPE).await {
                Ok(sealed) => match KeyList::open(&recovery, &sealed) {
                    Ok(list) => opened.push((sha, list, sealed)),
                    // Not ours, damaged or not a key list: never retried.
                    Err(_) => self.mark_pulled(&sha),
                },
                // Retried on the next pull.
                Err(error) if error.transient() || error == NodeError::Tls => {}
                Err(_) => self.mark_pulled(&sha),
            }
        }
        let mut slot = self.keylist.lock().await;
        if self.load_key_list(&mut slot).is_err() {
            // The next sync rebuilds the list from the index and the nodes.
            self.index
                .set_bool(kv::KEY_LIST_FAILED, true)
                .or_internal()?;
            self.keysync_wake.notify_one();
            return Ok(());
        }
        let current = slot.clone().expect("loaded above");
        let mut snapshot = current.clone();
        if let Some(newest) = opened.iter().max_by_key(|(_, list, _)| list.seq()) {
            let mut lists = vec![current.clone()];
            lists.extend(opened.iter().map(|(_, list, _)| list.clone()));
            let Ok(merged) = KeyList::merge(lists) else {
                // Copies from the owner's computers cannot really conflict
                // (ids are random and entries never change).  The copies are
                // not marked, so "Try again" re-reads them.
                self.index
                    .set_bool(kv::KEY_LIST_FAILED, true)
                    .or_internal()?;
                return Ok(());
            };
            if !merged.same_content(&current) {
                let (_, newest_list, newest_sealed) = newest;
                let last_seen = self
                    .index
                    .get_u64(kv::LAST_SEEN_SEQ)
                    .or_internal()?
                    .unwrap_or(0);
                let adopt = merged.same_content(newest_list);
                if adopt && newest_list.seq() > last_seen {
                    // Adopt: the newest copy already says everything.
                    if write_private_file(&self.sealed_key_list_path(), newest_sealed).is_ok() {
                        self.index
                            .set_u64(kv::LAST_SEEN_SEQ, newest_list.seq())
                            .or_internal()?;
                    } else {
                        self.index
                            .set_bool(kv::KEY_LIST_PENDING, true)
                            .or_internal()?;
                        self.keysync_wake.notify_one();
                    }
                } else if !adopt {
                    // Publish once: this computer adds something.
                    self.index
                        .set_bool(kv::KEY_LIST_PENDING, true)
                        .or_internal()?;
                    self.keysync_wake.notify_one();
                }
                *slot = Some(merged.clone());
                snapshot = merged;
            }
            for (sha, _, _) in &opened {
                self.mark_pulled(sha);
            }
        }
        drop(slot);
        // Always, so additions deferred by an earlier pull are retried.
        self.apply_key_list(&snapshot).await;
        Ok(())
    }

    fn mark_pulled(&self, sha: &str) {
        if let Ok(mut pulled) = self.pulled.lock() {
            pulled.insert(sha.to_owned());
        }
    }

    /// Brings the rows in line with `list`.  Runs under the key list sync
    /// lock, once set-up is done and no restore is waiting.
    ///
    /// - A tombstone whose row exists removes the row: this computer's own
    ///   copies and claims, the key and the row.
    /// - An entry with no row, no tombstone here and an online copy that is
    ///   really there gets a row and is copied to the local node.  The
    ///   online copy is never claimed or uploaded by this computer: no
    ///   `queued` state, so the other computer's approval is not charged
    ///   twice.  An entry whose online copy is not there yet waits for the
    ///   next pull.
    pub(crate) async fn apply_key_list(self: &Arc<Self>, list: &KeyList) {
        if !self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false)
            || self.index.get_bool(kv::RESTORE_PENDING).unwrap_or(true)
        {
            return;
        }
        let mut removed = false;
        // A row linked to a file in a folder that is not there now waits:
        // its file must go to the Trash, not be taken in again later.  The
        // tombstone stays in the list, so reconcile never re-adds it.
        let folder_paused = self.mirror_on() && self.folder_state() != "on";
        for stone in list.tombstones() {
            let id = stone.id.to_string();
            let Ok(Some(row)) = self.index.file(&id) else {
                continue;
            };
            if folder_paused && row.watch_path.is_some() && row.local != local::NOT_KEPT {
                continue;
            }
            if self
                .remove_row(&id, RemoveHow::Remote { at: stone.at })
                .await
                .is_ok()
            {
                removed = true;
            }
        }
        if removed {
            self.run_pending_deletes().await;
        }
        let (Some(node), Some(_)) = (self.online_endpoint(), self.local_endpoint()) else {
            return;
        };
        let Ok(keychain) = self.keychain() else {
            return;
        };
        let mut adopted = Vec::new();
        for entry in list.entries() {
            let id = entry.id.to_string();
            let removed_here = self
                .removed_ids
                .lock()
                .map(|r| r.contains(&id))
                .unwrap_or(true);
            if removed_here
                || !matches!(self.index.file(&id), Ok(None))
                || self.index.has_tombstone(&id).unwrap_or(true)
            {
                continue;
            }
            let sha = hex_lower(&entry.sha256);
            if !matches!(
                client::head(&self.http, &node, &sha).await,
                Ok(Some(size)) if size == entry.size
            ) {
                continue;
            }
            if keychain.set_file_key(&entry.id, &entry.key).is_err() {
                continue;
            }
            if self.index.insert_file(&row_for_entry(entry)).is_ok() {
                self.set_progress(&id, 0);
                adopted.push((id, sha));
            }
        }
        if adopted.is_empty() {
            return;
        }
        self.emit_status();
        let engine = self.clone();
        self.rt.spawn(async move {
            for (id, sha) in adopted {
                let ok = engine.copy_online_to_local(&id).await;
                if matches!(engine.index.file(&id), Ok(Some(_))) {
                    // Never `queued`: the online copy is the other computer's.
                    let _ = engine
                        .index
                        .set_local(&id, if ok { local::OK } else { local::MISSING });
                } else if ok {
                    // Removed while it was being copied: the copy that just
                    // landed goes too.
                    let _ = engine.index.queue_delete("local", &sha, "device", 0);
                    engine.deletes_wake.notify_one();
                }
                engine.clear_progress(&id);
                engine.emit_row(&id);
            }
            engine.emit_status();
            engine.watch_wake.notify_one();
        });
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
        // No drop may start while the recovery secret can still change.
        let _setup = self.setup_lock.write().await;
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
                // Nothing of the old secret may outlive it: an approval in
                // flight names its recovery identity, and the old key list
                // state would be checked against the wrong list.
                self.cancel_approval()?;
                keychain
                    .set_recovery_secret(recovery.secret())
                    .map_err(|e| super::engine::keychain_error(&e))?;
                for key in [
                    kv::LAST_SEEN_SEQ,
                    kv::KEY_LIST_LOCAL_SHA,
                    kv::KEY_LIST_ONLINE_SHA,
                    kv::KEY_LIST_PENDING,
                    kv::KEY_LIST_FAILED,
                ] {
                    self.index.unset(key).or_internal()?;
                }
                self.index.clear_tombstones().or_internal()?;
                match std::fs::remove_file(self.sealed_key_list_path()) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(internal("could not clear the old key list")),
                }
            } else {
                return Err(CommandError::with_host("wrong_key", host_of(&url)));
            }
        }
        let identity =
            device::restore_identity(&keychain, &lock, recovery).map_err(|e| device_error(&e))?;
        drop(lock);
        self.identity_after_restore(identity);
        *self.keylist.lock().await = None;
        if let Ok(mut pulled) = self.pulled.lock() {
            pulled.clear();
        }
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
            let record = row_for_entry(entry);
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

/// The path a row's entry carries: its frozen `path`, or its name for a row
/// from before the column existed.
pub(crate) fn entry_path(file: &FileRecord) -> String {
    if file.path.is_empty() {
        file.name.clone()
    } else {
        file.path.clone()
    }
}

/// A row for an entry this computer did not add (restore or another
/// computer's addition): being copied back here, with the online copy
/// already there, and the entry's own fields frozen.
fn row_for_entry(entry: &KeyListEntry) -> FileRecord {
    let id = entry.id.to_string();
    FileRecord {
        id: id.clone(),
        name: entry.name.clone(),
        media_type: entry.media_type.clone(),
        bytes: entry.bytes,
        added: entry.added,
        // Without a known plaintext hash, never matched as a duplicate.
        plain_sha256: entry
            .plain
            .map(|plain| hex_lower(&plain))
            .unwrap_or_else(|| format!("restored:{id}")),
        sha256: Some(hex_lower(&entry.sha256)),
        size: Some(entry.size),
        local: local::RESTORING.into(),
        online: online::OK.into(),
        attempts: 0,
        next_attempt: 0,
        watch_path: None,
        watch_size: None,
        watch_mtime: None,
        path: entry.path.clone(),
        prev: entry.prev.map(|prev| prev.to_string()),
        origin: entry.from.clone(),
        entry_plain: entry
            .plain
            .map(|plain| hex_lower(&plain))
            .unwrap_or_default(),
        note: None,
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
