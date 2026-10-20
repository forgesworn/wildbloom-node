//! Sharing (design questions Q5 to Q7, Q11, Q12).  Every share is a separate
//! copy under a fresh key, uploaded by the device key to the online node.  A
//! one-use Foregather live session ([`super::pairing`]) carries the
//! `wildbloom-share/1` descriptor inside a transfer-v1 invitation once both
//! sides have compared words; the recipient's receipt proves only that it
//! decrypted the descriptor.
//!
//! After the receipt the flow keeps listening, until the same session
//! deadline, for one `foregather-transfer-reply/1` reply: the recipient's page
//! sends `{"v":1,"event":"downloaded"}` once it has saved the file.  The relay
//! can withhold that reply but cannot forge it, so only an authenticated reply
//! that matches exactly counts; a missing one changes nothing.
//!
//! The access words, the link, the share key and every relay capability stay
//! in memory (the key also in the keychain while the copy exists) and are
//! never logged.

use super::client::{self, NodeEndpoint};
use super::descriptor::ShareDescriptor;
use super::engine::{
    DEFAULT_NODE_BLOB_LIMIT, Engine, OrInternal as _, PAIRING_PURPOSE, internal, kv, now,
};
use super::envelope::{SHARE_LIMITS, SHARE_MAX_PLAINTEXT_BYTES};
use super::index::{self, Index, IndexError, ShareRecord};
use super::pairing::{self, Ended, Live, LiveTransport as _, RelaySlot, VerifySlot};
use super::types::{CommandError, CommandResult, ShareState, SharingSettings};
use super::{FileId, hex_lower, parse_sha256};
use foregather_kit::live::{Channel, PairingSecret, Session};
use foregather_kit::transfer::Transfer;
use rand_core::OsRng;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wildbloom_envelope::InputKey;

/// How long a sent copy stays by default (Q12).
pub const DEFAULT_SHARE_EXPIRY_SECONDS: u64 = 24 * 60 * 60;
/// The expiry choices in the settings: an hour, a day and a week.
pub const SHARE_EXPIRY_CHOICES: [u64; 3] = [60 * 60, 24 * 60 * 60, 7 * 24 * 60 * 60];
/// How long an ended share's record stays, so its row shows "sharing ended"
/// for a day whatever the expiry was.
const ENDED_RECORD_SECONDS: u64 = 24 * 60 * 60;
/// The recipient's one reply is its packet sequence 1, after the receipt.
const REPLY_KIND: &str = "packet-1";
/// The reply may take as long as the download; a slower poll is enough.
const REPLY_POLL: Duration = Duration::from_secs(1);

/// The sharing settings (`share_after_download`, `share_expiry_seconds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharingPolicy {
    /// Keep the shared copy until its expiry after a confirmed download,
    /// rather than deleting it at once (the default).
    pub keep_after_download: bool,
    pub expiry_seconds: u64,
}

impl SharingPolicy {
    pub const DEFAULT: Self = Self {
        keep_after_download: false,
        expiry_seconds: DEFAULT_SHARE_EXPIRY_SECONDS,
    };

    /// The stored settings; a missing or unusable value reads as its default.
    pub fn load(index: &Index) -> Self {
        let keep_after_download = index
            .get(kv::SHARE_AFTER_DOWNLOAD)
            .ok()
            .flatten()
            .as_deref()
            == Some("keep");
        let expiry_seconds = index
            .get_u64(kv::SHARE_EXPIRY_SECONDS)
            .ok()
            .flatten()
            .filter(|s| SHARE_EXPIRY_CHOICES.contains(s))
            .unwrap_or(DEFAULT_SHARE_EXPIRY_SECONDS);
        Self {
            keep_after_download,
            expiry_seconds,
        }
    }

    /// Exactly `delete` or `keep`, and exactly one of the expiry choices.
    pub fn parse(after_download: &str, expiry_seconds: Option<u64>) -> CommandResult<Self> {
        let keep_after_download = match after_download {
            "delete" => false,
            "keep" => true,
            _ => return Err(CommandError::code("bad_setting")),
        };
        let expiry_seconds = expiry_seconds
            .filter(|s| SHARE_EXPIRY_CHOICES.contains(s))
            .ok_or(CommandError::code("bad_setting"))?;
        Ok(Self {
            keep_after_download,
            expiry_seconds,
        })
    }

    pub fn save(&self, index: &Index) -> Result<(), IndexError> {
        index.set(kv::SHARE_AFTER_DOWNLOAD, self.after_download())?;
        index.set_u64(kv::SHARE_EXPIRY_SECONDS, self.expiry_seconds)
    }

    pub fn after_download(&self) -> &'static str {
        if self.keep_after_download {
            "keep"
        } else {
            "delete"
        }
    }

    pub fn settings(&self) -> SharingSettings {
        SharingSettings {
            after_download: self.after_download(),
            expiry_seconds: self.expiry_seconds,
        }
    }
}

/// The recipient page's reply, `{"v":1,"event":"downloaded"}`, read strictly:
/// a JSON object with exactly these two members (no duplicates), `v` the
/// integer 1.  Anything else is no confirmation.
fn is_downloaded_reply(bytes: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        v: u64,
        event: String,
    }
    // An object only: the struct would also take the array `[1,"downloaded"]`.
    bytes.trim_ascii_start().first() == Some(&b'{')
        && serde_json::from_slice::<Reply>(bytes)
            .is_ok_and(|reply| reply.v == 1 && reply.event == "downloaded")
}

/// A shared copy being made: its key is in the keychain and its blob may be
/// on the online node, but no share record names it yet.  An aborted flow
/// deletes both.
struct PendingCopy {
    share_id: FileId,
    sha256: String,
    origin: String,
}

type PendingSlot = Arc<Mutex<Option<PendingCopy>>>;

pub(crate) struct ShareSession {
    generation: u64,
    task: tokio::task::JoinHandle<()>,
    verify: VerifySlot,
    relay: RelaySlot,
    pending: PendingSlot,
    /// Sent: the task only listens for the download confirmation now.
    sent: Arc<AtomicBool>,
}

/// What a stopped flow leaves to clean up.
struct Leftovers {
    relay: RelaySlot,
    pending: PendingSlot,
}

struct ShareCopy {
    share_id: FileId,
    key: InputKey,
    sha256: String,
    size: u64,
}

/// A sent share: the confirmed channel and transfer stay for the reply.
struct Sent {
    delete_at: u64,
    policy: SharingPolicy,
    channel: Channel,
    transfer: Transfer,
}

impl Sent {
    /// Whether the recipient's packet is its authenticated `downloaded`
    /// reply to this transfer.
    fn confirms_download(&mut self, packet: Vec<u8>) -> bool {
        let Ok(packet) = String::from_utf8(packet) else {
            return false;
        };
        let Ok(clear) = self.channel.open(&packet, now()) else {
            return false;
        };
        self.transfer
            .read_reply(&clear)
            .is_ok_and(|reply| is_downloaded_reply(&reply))
    }
}

impl Engine {
    /// `share_start` (`again = false`) and `share_again` (`again = true`, which
    /// reuses the existing shared copy when it is still there).
    pub fn share_start(self: &Arc<Self>, id: &str, again: bool) -> CommandResult<ShareState> {
        let file = self
            .index
            .file(id)
            .or_internal()?
            .ok_or(CommandError::code("not_found"))?;
        if file.bytes > SHARE_MAX_PLAINTEXT_BYTES {
            return Err(CommandError::code("too_big"));
        }
        if self.writable_online().is_none() {
            return Err(CommandError::code("node_unreachable"));
        }
        if let Some(leftovers) = self.stop_share_task(id) {
            let engine = self.clone();
            self.rt
                .spawn(async move { engine.clean_up(leftovers).await });
        }
        let generation = self.next_pairing_generation();
        let verify = Arc::new(Mutex::new(None));
        let slot: RelaySlot = Arc::new(Mutex::new(None));
        let pending: PendingSlot = Arc::new(Mutex::new(None));
        let sent = Arc::new(AtomicBool::new(false));
        let engine = self.clone();
        let task_id = id.to_owned();
        let task_verify = verify.clone();
        let task_slot = slot.clone();
        let task_pending = pending.clone();
        let task_sent = sent.clone();
        let lock = self.share_lock(id);
        let task = self.rt.spawn(async move {
            // One flow per file: a replaced flow's clean-up and this one
            // never interleave their records.
            let _turn = lock.lock().await;
            // Every path ends in a state the sheet can show; nothing that
            // fails part-way leaves it waiting.  The relay session is deleted
            // after the download confirmation or at the deadline.
            let state = engine
                .run_share(
                    &task_id,
                    again,
                    generation,
                    task_verify,
                    task_slot.clone(),
                    task_pending,
                    &task_sent,
                )
                .await
                .unwrap_or_else(|| ShareState::new(&task_id, "relay_unreachable"));
            engine.emit_share_if_current(&task_id, generation, state);
            engine.delete_relay_session(&task_slot).await;
        });
        self.shares.lock().map_err(|_| internal("lock"))?.insert(
            id.to_owned(),
            ShareSession {
                generation,
                task,
                verify,
                relay: slot,
                pending,
                sent,
            },
        );
        let mut state = ShareState::new(id, "preparing");
        state.progress = Some(0);
        Ok(state)
    }

    /// Whether a Share sheet's pairing is still running.  A sent share that
    /// only listens for its download confirmation does not count: its link
    /// has done its job.
    pub fn share_open(&self) -> bool {
        self.shares
            .lock()
            .map(|s| {
                s.values().any(|session| {
                    !session.task.is_finished() && !session.sent.load(Ordering::Relaxed)
                })
            })
            .unwrap_or(false)
    }

    /// `set_sharing`: strict, and read when a file is sent, so a share
    /// already sent keeps the policy and expiry it was sent with.
    pub fn set_sharing(
        &self,
        after_download: &str,
        expiry_seconds: Option<u64>,
    ) -> CommandResult<()> {
        SharingPolicy::parse(after_download, expiry_seconds)?
            .save(&self.index)
            .or_internal()?;
        self.emit_status();
        Ok(())
    }

    fn emit_share_if_current(&self, id: &str, generation: u64, state: ShareState) {
        let current = self
            .shares
            .lock()
            .ok()
            .and_then(|s| s.get(id).map(|s| s.generation))
            == Some(generation);
        if current {
            self.host.emit_share(&state);
        }
    }

    fn emit_share(&self, state: ShareState) {
        self.host.emit_share(&state);
    }

    fn share_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.share_locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.entry(id.to_owned()).or_default().clone()
    }

    /// Stops a running flow.  The shared copy it already recorded is left
    /// alone; what it had not recorded yet comes back as leftovers.
    fn stop_share_task(&self, id: &str) -> Option<Leftovers> {
        let session = self.shares.lock().ok()?.remove(id)?;
        session.task.abort();
        Some(Leftovers {
            relay: session.relay,
            pending: session.pending,
        })
    }

    /// Ends a stopped flow's relay session, and deletes a shared copy it was
    /// still making (its key and, if uploaded, its blob).
    async fn clean_up(self: &Arc<Self>, leftovers: Leftovers) {
        self.delete_relay_session(&leftovers.relay).await;
        let pending = leftovers.pending.lock().ok().and_then(|mut p| p.take());
        let Some(pending) = pending else { return };
        if let Ok(keychain) = self.keychain() {
            let _ = keychain.remove_file_key(&pending.share_id);
        }
        let deleted = match (
            NodeEndpoint::parse(&pending.origin, self.cfg.allow_loopback_http),
            self.identity(),
        ) {
            (Ok(node), Ok(identity)) => {
                client::delete(&self.http, &node, identity.device.keys(), &pending.sha256)
                    .await
                    .is_ok()
            }
            _ => false,
        };
        if !deleted {
            let _ = self
                .index
                .queue_delete(&pending.origin, &pending.sha256, "device", 0);
        }
    }

    /// Used by Remove: ends the pairing; the recorded copy is deleted by the
    /// caller.
    pub(crate) async fn cancel_share_session(self: &Arc<Self>, id: &str) {
        if let Some(leftovers) = self.stop_share_task(id) {
            self.clean_up(leftovers).await;
        }
    }

    /// Before the online node changes: end every live share on the old node
    /// (deleted there now, or queued against that node).
    pub(crate) async fn end_shares_before_node_change(self: &Arc<Self>) -> CommandResult<()> {
        for share in self.index.shares().or_internal()? {
            self.cancel_share_session(&share.file_id).await;
            if matches!(
                share.state.as_str(),
                index::share::OPEN | index::share::SENT | index::share::STOP_PENDING
            ) {
                self.delete_share_copy(&share, true).await;
            }
        }
        Ok(())
    }

    pub fn share_verify(&self, id: &str, matches: bool) -> CommandResult<Option<ShareState>> {
        let sender = self
            .shares
            .lock()
            .map_err(|_| internal("lock"))?
            .get(id)
            .and_then(|s| s.verify.lock().ok().and_then(|mut v| v.take()));
        let Some(sender) = sender else {
            return Ok(None);
        };
        let _ = sender.send(matches);
        Ok(Some(ShareState::new(
            id,
            if matches { "sending" } else { "mismatch" },
        )))
    }

    /// The sheet closed: end the live session, and delete the shared copy if
    /// nothing was ever sent with it.
    pub async fn share_cancel(self: &Arc<Self>, id: &str) -> CommandResult<()> {
        if let Some(leftovers) = self.stop_share_task(id) {
            self.clean_up(leftovers).await;
        }
        if let Some(share) = self.index.share(id).or_internal()?
            && share.state == index::share::OPEN
        {
            self.delete_share_copy(&share, false).await;
        }
        Ok(())
    }

    /// Stop sharing: delete the shared copy now, or as soon as the online node
    /// can be reached (the row shows `stop_pending` until then).
    pub async fn stop_sharing(self: &Arc<Self>, id: &str) -> CommandResult<()> {
        self.cancel_share_session(id).await;
        if let Some(share) = self.index.share(id).or_internal()?
            && matches!(
                share.state.as_str(),
                index::share::OPEN | index::share::SENT | index::share::STOP_PENDING
            )
        {
            self.delete_share_copy(&share, true).await;
        }
        self.emit_row(id);
        self.emit_status();
        Ok(())
    }

    /// Deletes a shared copy.  `keep_record` leaves an `ended` record so the
    /// row shows "sharing ended" for a day.  Returns whether the online node
    /// deleted it now (otherwise the deletion is queued).
    async fn delete_share_copy(self: &Arc<Self>, share: &ShareRecord, keep_record: bool) -> bool {
        // Deleted on the node the copy was uploaded to, whatever is set up now.
        let deleted = match (
            NodeEndpoint::parse(&share.origin, self.cfg.allow_loopback_http),
            self.identity(),
        ) {
            (Ok(node), Ok(identity)) => {
                client::delete(&self.http, &node, identity.device.keys(), &share.sha256)
                    .await
                    .is_ok()
            }
            _ => false,
        };
        if !deleted {
            let _ = self.index.queue_share_delete(
                &share.origin,
                &share.sha256,
                "device",
                0,
                Some(&share.file_id),
            );
        }
        if let (Some(share_id), Ok(keychain)) = (FileId::parse(&share.share_id), self.keychain()) {
            let _ = keychain.remove_file_key(&share_id);
        }
        if keep_record {
            let mut record = share.clone();
            if deleted {
                record.state = index::share::ENDED.into();
                record.ended_at = Some(now());
            } else {
                record.state = index::share::STOP_PENDING.into();
            }
            let _ = self.index.put_share(&record);
        } else {
            let _ = self.index.delete_share(&share.file_id);
        }
        self.emit_row(&share.file_id);
        deleted
    }

    /// The recipient confirmed the download of the copy `sha256`: record when,
    /// then delete the shared copy now or keep it until its deletion time, as
    /// the share's policy says.  `None` if the record no longer names that
    /// sent copy.
    pub(crate) async fn record_download(
        self: &Arc<Self>,
        id: &str,
        sha256: &str,
        at: u64,
        policy: SharingPolicy,
    ) -> Option<ShareState> {
        let mut share = self.index.share(id).ok().flatten()?;
        if share.sha256 != sha256 || share.state != index::share::SENT {
            return None;
        }
        share.downloaded_at = Some(at);
        // Recorded before the deletion, so the time is kept even if the
        // deletion is cut off.
        self.index.put_share(&share).ok()?;
        let mut state = ShareState::new(id, "downloaded");
        state.downloaded_at = Some(at);
        if policy.keep_after_download {
            state.copy = Some("kept");
            state.delete_at = share.delete_at;
            self.emit_row(id);
        } else {
            let deleted = self.delete_share_copy(&share, true).await;
            state.copy = Some(if deleted { "deleted" } else { "deleting" });
            self.emit_status();
        }
        Some(state)
    }

    /// Q12: delete sent copies at their deletion time, settle pending stops
    /// and clear "sharing ended" after a day.
    pub(crate) async fn sweep_shares(self: &Arc<Self>) {
        let now = now();
        let pending: Vec<String> = self
            .index
            .pending_deletes()
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.sha256)
            .collect();
        for share in self.index.shares().unwrap_or_default() {
            match share.state.as_str() {
                index::share::SENT if share.delete_at.is_some_and(|at| at <= now) => {
                    self.delete_share_copy(&share, true).await;
                }
                index::share::STOP_PENDING if !pending.contains(&share.sha256) => {
                    let mut record = share.clone();
                    record.state = index::share::ENDED.into();
                    record.ended_at = Some(now);
                    let _ = self.index.put_share(&record);
                    self.emit_row(&share.file_id);
                }
                index::share::ENDED | index::share::OWNER_ONLY
                    if share
                        .ended_at
                        .is_some_and(|at| now.saturating_sub(at) >= ENDED_RECORD_SECONDS) =>
                {
                    let _ = self.index.delete_share(&share.file_id);
                    self.emit_row(&share.file_id);
                }
                _ => {}
            }
        }
    }

    /// A sheet open when the app stopped never sent anything: delete its copy.
    pub(crate) async fn recover_open_shares(self: &Arc<Self>) {
        for share in self.index.shares().unwrap_or_default() {
            if share.state == index::share::OPEN {
                self.delete_share_copy(&share, false).await;
            }
        }
    }

    /// The existing shared copy, if it was never sent and is still on this
    /// node.  A sent copy is never reused: its recipient was told when it is
    /// deleted, and a new send must not move that time.
    async fn reusable_copy(self: &Arc<Self>, id: &str, node: &NodeEndpoint) -> Option<ShareCopy> {
        let share = self.index.share(id).ok().flatten()?;
        if share.state != index::share::OPEN || share.origin != node.origin() {
            return None;
        }
        let share_id = FileId::parse(&share.share_id)?;
        let key = self.keychain().ok()?.file_key(&share_id).ok().flatten()?;
        match client::head(&self.http, node, &share.sha256).await {
            Ok(Some(size)) if size == share.size => Some(ShareCopy {
                share_id,
                key,
                sha256: share.sha256,
                size: share.size,
            }),
            _ => None,
        }
    }

    /// Q5: a fresh copy of the file under a fresh key, uploaded to the online
    /// node.  Progress runs 0 to 100 across decrypt, encrypt and upload.
    async fn make_share_copy(
        self: &Arc<Self>,
        id: &str,
        node: &NodeEndpoint,
        progress: Arc<dyn Fn(u8) + Send + Sync>,
        pending: &PendingSlot,
    ) -> Result<ShareCopy, Ended> {
        let file = self.index.file(id).ok().flatten().ok_or(Ended::Node)?;
        let identity = self.identity().map_err(|_| Ended::Node)?;
        progress(5);
        let plain = self.decrypt_to_temp(&file).await.map_err(|_| Ended::Node)?;
        progress(30);
        let share_id = FileId::random().map_err(|_| Ended::Node)?;
        let key = InputKey::random().map_err(|_| Ended::Node)?;
        let temp_dir = self.cfg.temp_dir.clone();
        let name = file.name.clone();
        let media_type = file.media_type.clone();
        let encrypt_key = key.clone();
        let encrypt_progress = progress.clone();
        let sealed = tokio::task::spawn_blocking(move || {
            let result = wildbloom_envelope::encrypt_file_to_private_temp(
                &encrypt_key,
                plain.path(),
                &name,
                &media_type,
                SHARE_LIMITS,
                &temp_dir,
                &mut |done, total| {
                    encrypt_progress(30 + (done.saturating_mul(30) / total.max(1)) as u8);
                    ControlFlow::Continue(())
                },
            );
            // The plaintext copy is removed as soon as it is encrypted.
            drop(plain);
            result
        })
        .await
        .map_err(|_| Ended::Node)?
        .map_err(|_| Ended::Node)?;
        let (sealed, envelope) = sealed;
        let sha256 = hex_lower(&sealed.sha256);
        let size = sealed.envelope_bytes;
        let keychain = self.keychain().map_err(|_| Ended::Node)?;
        // Recorded before the key is stored, so an abort from here on is
        // cleaned up.
        if let Ok(mut slot) = pending.lock() {
            *slot = Some(PendingCopy {
                share_id,
                sha256: sha256.clone(),
                origin: node.origin().to_owned(),
            });
        }
        keychain
            .set_file_key(&share_id, &key)
            .map_err(|_| Ended::Node)?;
        let upload_progress = progress.clone();
        let body = client::file_body(envelope.path(), move |sent| {
            upload_progress(60 + (sent.saturating_mul(39) / size.max(1)).min(39) as u8);
        })
        .await
        .map_err(|_| Ended::Node)?;
        if client::upload(
            &self.http,
            node,
            identity.device.keys(),
            &sha256,
            size,
            body,
        )
        .await
        .is_err()
        {
            let _ = keychain.remove_file_key(&share_id);
            if let Ok(mut slot) = pending.lock() {
                *slot = None;
            }
            return Err(Ended::Node);
        }
        drop(envelope);
        Ok(ShareCopy {
            share_id,
            key,
            sha256,
            size,
        })
    }

    /// One share sheet's whole lifecycle.  Returns the final state to emit.
    #[allow(clippy::too_many_arguments)]
    async fn run_share(
        self: &Arc<Self>,
        id: &str,
        again: bool,
        generation: u64,
        verify: VerifySlot,
        slot: RelaySlot,
        pending: PendingSlot,
        sent_flag: &AtomicBool,
    ) -> Option<ShareState> {
        let ended = |reason: Ended| Some(ShareState::new(id, reason.state()));
        let (Some(node), Ok(identity), Ok(Some(file))) =
            (self.writable_online(), self.identity(), self.index.file(id))
        else {
            return ended(Ended::Node);
        };
        let previous = self.index.share(id).ok().flatten();

        // 1. The shared copy.
        let reused = if again {
            self.reusable_copy(id, &node).await
        } else {
            None
        };
        let fresh = reused.is_none();
        let copy = match reused {
            Some(copy) => copy,
            None => {
                let engine = self.clone();
                let progress_id = id.to_owned();
                let last = Arc::new(Mutex::new(0u8));
                let progress: Arc<dyn Fn(u8) + Send + Sync> = Arc::new(move |p: u8| {
                    let mut last = last.lock().unwrap_or_else(|e| e.into_inner());
                    if p >= last.saturating_add(5) || p >= 99 {
                        *last = p;
                        let mut state = ShareState::new(&progress_id, "preparing");
                        state.progress = Some(p.min(100));
                        engine.emit_share(state);
                    }
                });
                match self.make_share_copy(id, &node, progress, &pending).await {
                    Ok(copy) => copy,
                    Err(reason) => return ended(reason),
                }
            }
        };
        if fresh {
            // One shared copy per file in the index: a new copy replaces an
            // older one.  An unsent one goes now; a sent one keeps the
            // deletion time its recipient was told.
            if let Some(old) = previous.filter(|p| {
                p.sha256 != copy.sha256
                    && matches!(
                        p.state.as_str(),
                        index::share::SENT | index::share::OPEN | index::share::STOP_PENDING
                    )
            }) {
                let not_before = if old.state == index::share::SENT {
                    old.delete_at.unwrap_or(0)
                } else {
                    0
                };
                let _ = self.index.queue_share_delete(
                    &old.origin,
                    &old.sha256,
                    "device",
                    not_before,
                    Some(id),
                );
                if let (Some(old_id), Ok(keychain)) =
                    (FileId::parse(&old.share_id), self.keychain())
                {
                    let _ = keychain.remove_file_key(&old_id);
                }
            }
            let _ = self.index.put_share(&ShareRecord {
                file_id: id.to_owned(),
                share_id: copy.share_id.to_string(),
                origin: node.origin().to_owned(),
                sha256: copy.sha256.clone(),
                size: copy.size,
                state: index::share::OPEN.into(),
                sent_at: None,
                delete_at: None,
                ended_at: None,
                downloaded_at: None,
            });
        }
        // The record names the copy now; it is no longer an orphan.
        if let Ok(mut slot) = pending.lock() {
            *slot = None;
        }
        let mut state = ShareState::new(id, "preparing");
        state.progress = Some(100);
        self.emit_share(state);

        // 2. A one-use creation grant from the online node's issuer, then a
        //    fresh session, words and locator on the relay.
        let (live, session, secret) = match self
            .open_pairing(
                &node,
                identity.device.keys(),
                PAIRING_PURPOSE,
                &self.cfg.get_base,
                &slot,
            )
            .await
        {
            Ok(opened) => opened,
            Err(reason) => return ended(reason),
        };
        let announce = |name: &'static str, check: Option<Vec<String>>| {
            let mut state = ShareState::new(id, name);
            state.link = Some(live.link.clone());
            state.words = Some(live.words.clone());
            state.expires_at = Some(live.expires_at);
            state.check_words = check;
            self.emit_share(state);
        };
        announce("ready", None);

        // 3. Pairing, words, send and receipt, all inside the 600 s window.
        let deadline = live.deadline();
        let flow = self.pair_and_send(
            id, &file, &copy, &node, &live, session, secret, &verify, &announce,
        );
        let mut sent = match tokio::time::timeout_at(deadline, flow).await {
            Err(_) => return ended(Ended::Expired),
            Ok(Err(reason)) => return ended(reason),
            Ok(Ok(sent)) => sent,
        };
        sent_flag.store(true, Ordering::Relaxed);
        let (delete_at, after_download) = (sent.delete_at, sent.policy.after_download());
        let sent_state = |awaiting: bool| {
            let mut state = ShareState::new(id, "sent");
            state.delete_at = Some(delete_at);
            state.awaiting_download = Some(awaiting);
            state.after_download = Some(after_download);
            state
        };
        self.emit_share_if_current(id, generation, sent_state(true));

        // 4. The recipient's one reply, until the same deadline.  Its slot is
        //    write-once, so the first packet there is the only one.
        let confirmed = match tokio::time::timeout_at(deadline, wait_for_reply(&live)).await {
            Ok(Some(packet)) => sent.confirms_download(packet),
            _ => false,
        };
        if !confirmed {
            return Some(sent_state(false));
        }
        self.delete_relay_session(&slot).await;
        match self
            .record_download(id, &copy.sha256, now(), sent.policy)
            .await
        {
            Some(state) => Some(state),
            None => Some(sent_state(false)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn pair_and_send(
        self: &Arc<Self>,
        id: &str,
        file: &index::FileRecord,
        copy: &ShareCopy,
        node: &NodeEndpoint,
        live: &Live,
        session: Session,
        secret: PairingSecret,
        verify: &VerifySlot,
        announce: &(dyn Fn(&'static str, Option<Vec<String>>) + Sync),
    ) -> Result<Sent, Ended> {
        let mut channel = pairing::pair(live, session, secret, verify, announce).await?;
        self.emit_share(ShareState::new(id, "sending"));
        // The settings as they are when the file is sent.
        let policy = SharingPolicy::load(&self.index);
        let sent_at = now();
        let delete_at = sent_at + policy.expiry_seconds;
        let sha = parse_sha256(&copy.sha256).ok_or(Ended::Node)?;
        let descriptor = ShareDescriptor::build(
            node.origin(),
            &sha,
            copy.size,
            &copy.key,
            &file.name,
            file.bytes,
            delete_at,
        )
        .map_err(|_| Ended::Node)?;
        let transfer = Transfer::create(&descriptor.to_canonical_json(), &mut OsRng)
            .map_err(|_| Ended::Relay)?;
        let packet = zeroize::Zeroizing::new(
            channel
                .seal(&transfer.encode(), now())
                .map_err(|_| Ended::Relay)?,
        );
        live.send("packet-0", packet.as_bytes())
            .await
            .map_err(|_| Ended::Relay)?;
        let reply = pairing::wait_for(live, "packet-0").await?;
        let reply = String::from_utf8(reply).map_err(|_| Ended::Relay)?;
        let clear = channel.open(&reply, now()).map_err(|_| Ended::Relay)?;
        transfer.acknowledged(&clear).map_err(|_| Ended::Relay)?;
        let _ = self.index.put_share(&ShareRecord {
            file_id: id.to_owned(),
            share_id: copy.share_id.to_string(),
            origin: node.origin().to_owned(),
            sha256: copy.sha256.clone(),
            size: copy.size,
            state: index::share::SENT.into(),
            sent_at: Some(sent_at),
            delete_at: Some(delete_at),
            ended_at: None,
            downloaded_at: None,
        });
        self.emit_row(id);
        Ok(Sent {
            delete_at,
            policy,
            channel,
            transfer,
        })
    }
}

/// Polls for the recipient's reply until it is there or the relay refuses.
/// A transient failure only means "not yet": a missing reply is never read
/// as anything.
async fn wait_for_reply(live: &Live) -> Option<Vec<u8>> {
    loop {
        match live.poll(REPLY_KIND).await {
            Ok(Some(bytes)) => return Some(bytes),
            Ok(None) => {}
            Err(error) if error.transient() => {}
            Err(_) => return None,
        }
        tokio::time::sleep(REPLY_POLL).await;
    }
}

#[allow(dead_code)]
const _: u64 = DEFAULT_NODE_BLOB_LIMIT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drop::engine::{
        EngineConfig, Host, LocalNode, ONLINE_BLOB_LIMIT, PAIRING_NAMESPACE,
    };
    use crate::drop::index::{FileRecord, local, online};
    use crate::drop::keychain::{MemoryStore, SecretStore};
    use crate::drop::pairing::PAIRING_LIFETIME;
    use crate::drop::status::StatusLine;
    use crate::drop::types::{DropStatus, FileRow};
    use foregather_kit::Namespace;
    use foregather_kit::live::{PairingGate, Role};
    use std::path::{Path, PathBuf};

    #[test]
    fn only_the_exact_downloaded_reply_confirms() {
        assert!(is_downloaded_reply(br#"{"v":1,"event":"downloaded"}"#));
        // Member order and JSON whitespace do not matter.
        assert!(is_downloaded_reply(
            b" {\"event\": \"downloaded\",\n \"v\": 1} "
        ));
        for wrong_version in [
            br#"{"v":2,"event":"downloaded"}"#.as_slice(),
            br#"{"v":0,"event":"downloaded"}"#,
            br#"{"v":-1,"event":"downloaded"}"#,
            br#"{"v":1.0,"event":"downloaded"}"#,
            br#"{"v":"1","event":"downloaded"}"#,
            br#"{"v":true,"event":"downloaded"}"#,
            br#"{"event":"downloaded"}"#,
        ] {
            assert!(
                !is_downloaded_reply(wrong_version),
                "{}",
                String::from_utf8_lossy(wrong_version)
            );
        }
        for unknown_event in [
            br#"{"v":1,"event":"opened"}"#.as_slice(),
            br#"{"v":1,"event":"Downloaded"}"#,
            br#"{"v":1,"event":"downloaded "}"#,
            br#"{"v":1,"event":null}"#,
            br#"{"v":1}"#,
        ] {
            assert!(
                !is_downloaded_reply(unknown_event),
                "{}",
                String::from_utf8_lossy(unknown_event)
            );
        }
        for junk in [
            b"".as_slice(),
            b"downloaded",
            b"null",
            b"{}",
            b"\xff\xfe{",
            br#"[1,"downloaded"]"#,
            br#""{\"v\":1,\"event\":\"downloaded\"}""#,
            br#"{"v":1,"event":"downloaded"}x"#,
            br#"{"v":1,"event":"downloaded"}{"v":1,"event":"downloaded"}"#,
            br#"{"v":1,"event":"downloaded","at":1900000000}"#,
            br#"{"v":1,"v":1,"event":"downloaded"}"#,
            br#"{"v":1,"event":"downloaded","event":"downloaded"}"#,
            br#"{"v":1,"event":"downloaded""#,
        ] {
            assert!(
                !is_downloaded_reply(junk),
                "{}",
                String::from_utf8_lossy(junk)
            );
        }
    }

    /// Both ends of a confirmed live channel, in process, and the inviter's
    /// sent transfer with the recipient's receipt already read.
    fn sent_with_recipient() -> (Sent, Channel, Transfer) {
        let now = now();
        let session = Session::generate(
            Namespace::parse(PAIRING_NAMESPACE).unwrap(),
            Namespace::parse(PAIRING_PURPOSE).unwrap(),
            PAIRING_LIFETIME,
            now,
            &mut OsRng,
        )
        .unwrap();
        let secret = PairingSecret::generate(4, &mut OsRng).unwrap();
        let words = PairingSecret::parse(secret.expose_words()).unwrap();
        let inviter = PairingGate::new(session.clone(), secret, 1, now)
            .unwrap()
            .start(Role::Inviter, now, &mut OsRng)
            .unwrap();
        let recipient = PairingGate::new(session, words, 1, now)
            .unwrap()
            .start(Role::Recipient, now, &mut OsRng)
            .unwrap();
        let (inviter_hello, recipient_hello) = (inviter.hello(), recipient.hello());
        let inviter = inviter.finish(&recipient_hello, now).unwrap();
        let recipient = recipient.finish(&inviter_hello, now).unwrap();
        let (inviter_proof, recipient_proof) = (
            inviter.confirmation().unwrap(),
            recipient.confirmation().unwrap(),
        );
        let mut channel = inviter.confirm(&recipient_proof, now).unwrap();
        let mut theirs = recipient.confirm(&inviter_proof, now).unwrap();
        let transfer = Transfer::create(b"{\"descriptor\":true}", &mut OsRng).unwrap();
        let packet = channel.seal(&transfer.encode(), now).unwrap();
        let received = Transfer::parse(&theirs.open(&packet, now).unwrap()).unwrap();
        let receipt = theirs.seal(&received.receipt(), now).unwrap();
        transfer
            .acknowledged(&channel.open(&receipt, now).unwrap())
            .unwrap();
        let sent = Sent {
            delete_at: now + DEFAULT_SHARE_EXPIRY_SECONDS,
            policy: SharingPolicy::DEFAULT,
            channel,
            transfer,
        };
        (sent, theirs, received)
    }

    #[test]
    fn the_reply_counts_only_through_the_channel_and_for_this_transfer() {
        let downloaded = br#"{"v":1,"event":"downloaded"}"#;
        // The recipient's page: its reply at packet sequence 1.
        let (mut sent, mut theirs, received) = sent_with_recipient();
        let reply = theirs
            .seal(&received.reply(downloaded).unwrap(), now())
            .unwrap();
        assert!(sent.confirms_download(reply.into_bytes()));

        // Another reply than "downloaded" is no confirmation.
        let (mut sent, mut theirs, received) = sent_with_recipient();
        let reply = theirs
            .seal(
                &received.reply(br#"{"v":1,"event":"opened"}"#).unwrap(),
                now(),
            )
            .unwrap();
        assert!(!sent.confirms_download(reply.into_bytes()));

        // The relay cannot forge one: bytes it made up, a reply sealed in
        // another session, or a reply bound to another transfer.
        let (mut sent, _, _) = sent_with_recipient();
        assert!(!sent.confirms_download(downloaded.to_vec()));
        let (_, mut other, other_received) = sent_with_recipient();
        let foreign = other
            .seal(&other_received.reply(downloaded).unwrap(), now())
            .unwrap();
        assert!(!sent.confirms_download(foreign.into_bytes()));
        let (mut sent, mut theirs, _) = sent_with_recipient();
        let elsewhere = Transfer::create(b"{\"descriptor\":true}", &mut OsRng).unwrap();
        let rebound = theirs
            .seal(&elsewhere.reply(downloaded).unwrap(), now())
            .unwrap();
        assert!(!sent.confirms_download(rebound.into_bytes()));

        // A second receipt is not a reply.
        let (mut sent, mut theirs, received) = sent_with_recipient();
        let receipt = theirs.seal(&received.receipt(), now()).unwrap();
        assert!(!sent.confirms_download(receipt.into_bytes()));
        assert!(!sent.confirms_download(vec![0xff, 0xfe]));
    }

    #[test]
    fn sharing_settings_default_validate_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let index = Index::open(&dir.path().join("drop")).unwrap();
        assert_eq!(SharingPolicy::load(&index), SharingPolicy::DEFAULT);
        assert_eq!(
            serde_json::to_value(SharingPolicy::load(&index).settings()).unwrap(),
            serde_json::json!({ "afterDownload": "delete", "expirySeconds": 86_400 })
        );
        for (after, expiry) in [("delete", 3_600), ("keep", 86_400), ("keep", 604_800)] {
            let policy = SharingPolicy::parse(after, Some(expiry)).unwrap();
            policy.save(&index).unwrap();
            assert_eq!(SharingPolicy::load(&index), policy);
            assert_eq!(policy.settings().after_download, after);
            assert_eq!(policy.settings().expiry_seconds, expiry);
        }
        for (after, expiry) in [
            ("Keep", Some(3_600)),
            ("", Some(3_600)),
            ("deleted", Some(3_600)),
            ("delete", Some(0)),
            ("delete", Some(86_401)),
            ("keep", Some(1_209_600)),
            // Not an integer (the command passes `as_u64`).
            ("keep", None),
        ] {
            assert_eq!(
                SharingPolicy::parse(after, expiry).unwrap_err().code,
                "bad_setting",
                "{after} {expiry:?}"
            );
        }
        // A rejected value changes nothing stored.
        assert_eq!(
            SharingPolicy::load(&index),
            SharingPolicy::parse("keep", Some(604_800)).unwrap()
        );
        // Stored values this build does not know read as the defaults.
        index.set(kv::SHARE_AFTER_DOWNLOAD, "maybe").unwrap();
        index.set(kv::SHARE_EXPIRY_SECONDS, "5").unwrap();
        assert_eq!(SharingPolicy::load(&index), SharingPolicy::DEFAULT);
        index.set(kv::SHARE_EXPIRY_SECONDS, "soon").unwrap();
        assert_eq!(SharingPolicy::load(&index), SharingPolicy::DEFAULT);
    }

    #[derive(Default)]
    struct Recorder {
        rows: Mutex<Vec<FileRow>>,
        shares: Mutex<Vec<ShareState>>,
        statuses: Mutex<Vec<DropStatus>>,
    }

    impl Host for Recorder {
        fn emit_file(&self, row: &FileRow) {
            self.rows.lock().unwrap().push(row.clone());
        }
        fn emit_removed(&self, _: &str) {}
        fn emit_status(&self, status: &DropStatus, _: &StatusLine) {
            self.statuses.lock().unwrap().push(status.clone());
        }
        fn emit_share(&self, state: &ShareState) {
            self.shares.lock().unwrap().push(state.clone());
        }
        fn local_node(&self) -> LocalNode {
            LocalNode {
                state: "stopped",
                endpoint: None,
            }
        }
        fn trust_changed(&self) {}
        fn node_settings_exist(&self) -> bool {
            false
        }
        fn ensure_node_settings(&self) -> Result<(), String> {
            Ok(())
        }
        fn pick_save_path(&self, _: &str) -> Option<PathBuf> {
            None
        }
        fn pick_files(&self) -> Vec<PathBuf> {
            Vec::new()
        }
        fn open_folder(&self, _: &Path) {}
        fn trash(&self, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn open_path(&self, _: &Path) {}
        fn reveal_path(&self, _: &Path) {}
    }

    /// An engine with no device key and its workers not started: a deletion
    /// it sends cannot reach the online node, so it is queued.
    fn engine(dir: &Path) -> (Arc<Engine>, Arc<Recorder>) {
        let host = Arc::new(Recorder::default());
        let store = Arc::new(MemoryStore::default());
        let config = EngineConfig {
            data_dir: dir.join("drop"),
            temp_dir: dir.join("drop-temp"),
            watch_dir: dir.join("Wildbloom"),
            watch_display: "~/Wildbloom".into(),
            get_base: "http://127.0.0.1:5472/get/".into(),
            send_base: "http://127.0.0.1:5472/send/".into(),
            received_dir: dir.join("Downloads").join("Wildbloom Received"),
            received_display: "~/Downloads/Wildbloom Received".into(),
            relay_base: None,
            allow_loopback_http: true,
            signer_timeout: Duration::from_secs(1),
            computer_name: "Desk".into(),
            watch_interval: Duration::from_secs(60),
            online_blob_limit: ONLINE_BLOB_LIMIT,
            pull_interval: Duration::from_secs(60),
        };
        let engine = Engine::new(
            config,
            host.clone(),
            Box::new(move || Ok(store.clone() as Arc<dyn SecretStore>)),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        (engine, host)
    }

    const ORIGIN: &str = "https://storage.example/";

    fn kept_file(id: &str) -> FileRecord {
        FileRecord {
            id: id.into(),
            name: "brief.pdf".into(),
            media_type: "application/pdf".into(),
            bytes: 12,
            added: 1_900_000_000,
            plain_sha256: "aa".repeat(32),
            sha256: Some("bb".repeat(32)),
            size: Some(65_608),
            local: local::OK.into(),
            online: online::OK.into(),
            attempts: 0,
            next_attempt: 0,
            watch_path: None,
            watch_size: None,
            watch_mtime: None,
            path: "brief.pdf".into(),
            prev: None,
            origin: String::new(),
            entry_plain: String::new(),
            note: None,
        }
    }

    fn sent_share(id: &str, sha256: &str, delete_at: u64) -> ShareRecord {
        ShareRecord {
            file_id: id.into(),
            share_id: "dd".repeat(16),
            origin: ORIGIN.into(),
            sha256: sha256.into(),
            size: 70_000,
            state: index::share::SENT.into(),
            sent_at: Some(delete_at - DEFAULT_SHARE_EXPIRY_SECONDS),
            delete_at: Some(delete_at),
            ended_at: None,
            downloaded_at: None,
        }
    }

    fn last_row(host: &Recorder) -> FileRow {
        host.rows.lock().unwrap().last().cloned().unwrap()
    }

    #[tokio::test]
    async fn a_confirmed_download_keeps_or_deletes_the_shared_copy() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, host) = engine(dir.path());
        engine.index.insert_file(&kept_file("a")).unwrap();
        let delete_at = now() + 3_600;
        let first = "cc".repeat(32);
        engine
            .index
            .put_share(&sent_share("a", &first, delete_at))
            .unwrap();

        // A confirmation for another copy than the one recorded changes
        // nothing.
        let keep = SharingPolicy {
            keep_after_download: true,
            ..SharingPolicy::DEFAULT
        };
        assert!(
            engine
                .record_download("a", &"ee".repeat(32), 1_000, keep)
                .await
                .is_none()
        );
        assert_eq!(
            engine.index.share("a").unwrap().unwrap().downloaded_at,
            None
        );

        // Keep: the copy stays until its deletion time, now marked downloaded.
        let state = engine
            .record_download("a", &first, 1_000, keep)
            .await
            .unwrap();
        assert_eq!(state.state, "downloaded");
        assert_eq!(state.copy, Some("kept"));
        assert_eq!(state.downloaded_at, Some(1_000));
        assert_eq!(state.delete_at, Some(delete_at));
        assert_eq!(
            serde_json::to_value(&state).unwrap(),
            serde_json::json!({ "id": "a", "state": "downloaded", "deleteAt": delete_at,
                                "downloadedAt": 1_000, "copy": "kept" })
        );
        let share = engine.index.share("a").unwrap().unwrap();
        assert_eq!(share.state, index::share::SENT);
        assert_eq!(
            (share.delete_at, share.downloaded_at),
            (Some(delete_at), Some(1_000))
        );
        assert!(engine.index.pending_deletes().unwrap().is_empty());
        let row = last_row(&host);
        assert_eq!(row.state, "shared");
        assert_eq!(
            (row.shared_until, row.downloaded_at),
            (Some(delete_at), Some(1_000))
        );
        assert_eq!(
            serde_json::to_value(&row).unwrap()["downloadedAt"],
            serde_json::json!(1_000)
        );

        // Delete (the default), with the online node out of reach: the
        // deletion is queued and the row shows it is being deleted.
        let second = "ff".repeat(32);
        engine
            .index
            .put_share(&sent_share("a", &second, delete_at))
            .unwrap();
        let statuses = host.statuses.lock().unwrap().len();
        let state = engine
            .record_download("a", &second, 2_000, SharingPolicy::DEFAULT)
            .await
            .unwrap();
        assert_eq!(state.copy, Some("deleting"));
        assert_eq!(state.downloaded_at, Some(2_000));
        assert_eq!(state.delete_at, None);
        let share = engine.index.share("a").unwrap().unwrap();
        assert_eq!(share.state, index::share::STOP_PENDING);
        assert_eq!(share.downloaded_at, Some(2_000));
        let pending = engine.index.pending_deletes().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            (
                pending[0].node.as_str(),
                pending[0].sha256.as_str(),
                pending[0].file_id.as_deref()
            ),
            (ORIGIN, second.as_str(), Some("a"))
        );
        let row = last_row(&host);
        assert_eq!(
            (row.state, row.downloaded_at),
            ("stop_pending", Some(2_000))
        );
        assert!(
            host.statuses.lock().unwrap().len() > statuses,
            "status sent"
        );

        // Once the queued deletion is done the share ends, keeping the time.
        engine.index.finish_delete(&pending[0]).unwrap();
        engine.sweep_shares().await;
        let share = engine.index.share("a").unwrap().unwrap();
        assert_eq!(share.state, index::share::ENDED);
        assert_eq!(share.downloaded_at, Some(2_000));
        let row = last_row(&host);
        assert_eq!(row.state, "sharing_ended");
        assert_eq!(row.downloaded_at, Some(2_000));
        assert!(row.sharing_ended.is_some());

        // An ended share is not confirmed again.
        assert!(
            engine
                .record_download("a", &second, 3_000, SharingPolicy::DEFAULT)
                .await
                .is_none()
        );
        assert_eq!(
            engine.index.share("a").unwrap().unwrap().downloaded_at,
            Some(2_000)
        );
    }

    #[tokio::test]
    async fn set_sharing_is_strict_and_shows_in_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, host) = engine(dir.path());
        assert_eq!(
            engine.status().sharing,
            SharingSettings {
                after_download: "delete",
                expiry_seconds: 86_400
            }
        );
        assert_eq!(
            engine.set_sharing("never", Some(3_600)).unwrap_err().code,
            "bad_setting"
        );
        assert_eq!(
            engine.set_sharing("keep", Some(7)).unwrap_err().code,
            "bad_setting"
        );
        assert!(host.statuses.lock().unwrap().is_empty());
        engine.set_sharing("keep", Some(604_800)).unwrap();
        let expected = SharingSettings {
            after_download: "keep",
            expiry_seconds: 604_800,
        };
        assert_eq!(engine.status().sharing, expected);
        assert_eq!(
            host.statuses.lock().unwrap().last().unwrap().sharing,
            expected
        );
        assert_eq!(
            serde_json::to_value(engine.status()).unwrap()["sharing"],
            serde_json::json!({ "afterDownload": "keep", "expirySeconds": 604_800 })
        );
    }

    #[tokio::test]
    async fn a_sent_share_that_only_listens_is_not_an_open_sheet() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _host) = engine(dir.path());
        let sent = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(std::future::pending::<()>());
        engine.shares.lock().unwrap().insert(
            "a".into(),
            ShareSession {
                generation: 1,
                task,
                verify: Arc::new(Mutex::new(None)),
                relay: Arc::new(Mutex::new(None)),
                pending: Arc::new(Mutex::new(None)),
                sent: sent.clone(),
            },
        );
        assert!(engine.share_open(), "pairing");
        sent.store(true, Ordering::Relaxed);
        assert!(!engine.share_open(), "listening for the download");
        // Stop sharing still ends the listening task.
        let leftovers = engine.stop_share_task("a");
        assert!(leftovers.is_some());
        assert!(engine.shares.lock().unwrap().is_empty());
    }
}
