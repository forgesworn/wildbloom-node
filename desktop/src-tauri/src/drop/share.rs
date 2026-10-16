//! Sharing (design questions Q5 to Q7, Q11, Q12).  Every share is a separate
//! copy under a fresh key, uploaded by the device key to the online node.  A
//! one-use Foregather live session carries the `wildbloom-share/1` descriptor
//! inside a transfer-v1 invitation once both sides have compared words; the
//! recipient's receipt proves only that it decrypted the descriptor.
//!
//! The access words, the link, the share key and every relay capability stay
//! in memory (the key also in the keychain while the copy exists) and are
//! never logged.

use super::client::{self, NodeEndpoint};
use super::descriptor::ShareDescriptor;
use super::engine::{
    DEFAULT_NODE_BLOB_LIMIT, Engine, OrInternal as _, PAIRING_NAMESPACE, PAIRING_PURPOSE, internal,
    now,
};
use super::envelope::{SHARE_LIMITS, SHARE_MAX_PLAINTEXT_BYTES};
use super::index::{self, ShareRecord};
use super::relay::{self, Capability, InviterSession, Relay};
use super::types::{CommandError, CommandResult, ShareState};
use super::{FileId, hex_lower, parse_sha256};
use foregather_kit::Namespace;
use foregather_kit::handoff::PublicRoom;
use foregather_kit::live::{PairingGate, PairingSecret, Role, Session};
use foregather_kit::transfer::Transfer;
use rand_core::OsRng;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use wildbloom_envelope::InputKey;

/// How long the shared copy stays after it was sent (Q12).
pub const SHARE_KEEP_SECONDS: u64 = 24 * 60 * 60;
/// The live session lifetime, the documented maximum (Q6).
pub const PAIRING_LIFETIME: u64 = 600;
/// One attempt (Q6): the relay's hello and proof slots are write-once.
const PAIRING_ATTEMPTS: u8 = 1;
const POLL: Duration = Duration::from_millis(250);

type RelaySlot = Arc<Mutex<Option<(Relay, Arc<InviterSession>)>>>;

pub(crate) struct ShareSession {
    generation: u64,
    task: tokio::task::JoinHandle<()>,
    verify: Arc<Mutex<Option<oneshot::Sender<bool>>>>,
    relay: RelaySlot,
}

/// What a pairing ended in, short of `sent`.
enum Ended {
    Expired,
    WrongWords,
    Mismatch,
    Relay,
    Node,
    Cancelled,
}

impl Ended {
    fn state(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::WrongWords => "wrong_words",
            Self::Mismatch => "mismatch",
            Self::Relay | Self::Cancelled => "relay_unreachable",
            Self::Node => "node_unreachable",
        }
    }
}

struct ShareCopy {
    share_id: FileId,
    key: InputKey,
    sha256: String,
    size: u64,
}

impl Engine {
    fn relay_base(&self, online: &NodeEndpoint) -> String {
        self.cfg
            .relay_base
            .clone()
            .unwrap_or_else(|| format!("{}pair/v1/", online.origin()))
    }

    fn next_share_generation(&self) -> u64 {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

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
        self.stop_share_task(id);
        let generation = self.next_share_generation();
        let verify = Arc::new(Mutex::new(None));
        let slot: RelaySlot = Arc::new(Mutex::new(None));
        let engine = self.clone();
        let task_id = id.to_owned();
        let task_verify = verify.clone();
        let task_slot = slot.clone();
        let task = self.rt.spawn(async move {
            let state = engine
                .run_share(&task_id, again, task_verify, task_slot.clone())
                .await;
            if let Some(state) = state {
                engine.emit_share_if_current(&task_id, generation, state);
            }
            engine.delete_relay_session(&task_slot).await;
        });
        self.shares.lock().map_err(|_| internal("lock"))?.insert(
            id.to_owned(),
            ShareSession {
                generation,
                task,
                verify,
                relay: slot,
            },
        );
        let mut state = ShareState::new(id, "preparing");
        state.progress = Some(0);
        Ok(state)
    }

    /// Whether a Share sheet's pairing is still running.
    pub fn share_open(&self) -> bool {
        self.shares
            .lock()
            .map(|s| s.values().any(|session| !session.task.is_finished()))
            .unwrap_or(false)
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

    /// Stops a running pairing without touching the shared copy.
    fn stop_share_task(&self, id: &str) -> Option<RelaySlot> {
        let session = self.shares.lock().ok()?.remove(id)?;
        session.task.abort();
        Some(session.relay)
    }

    async fn delete_relay_session(&self, slot: &RelaySlot) {
        let taken = slot.lock().ok().and_then(|mut s| s.take());
        if let Some((relay, session)) = taken {
            let _ = relay.delete(&session).await;
        }
    }

    /// Used by Remove: ends the pairing; the copy is deleted by the caller.
    pub(crate) async fn cancel_share_session(&self, id: &str) {
        if let Some(slot) = self.stop_share_task(id) {
            self.delete_relay_session(&slot).await;
        }
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
        if let Some(slot) = self.stop_share_task(id) {
            self.delete_relay_session(&slot).await;
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
            && share.state != index::share::ENDED
        {
            self.delete_share_copy(&share, true).await;
        }
        self.emit_row(id);
        self.emit_status();
        Ok(())
    }

    /// Deletes a shared copy.  `keep_record` leaves an `ended` record so the
    /// row shows "sharing ended" for a day.
    async fn delete_share_copy(self: &Arc<Self>, share: &ShareRecord, keep_record: bool) {
        let deleted = match (self.online_endpoint(), self.identity()) {
            (Some(node), Ok(identity)) => {
                client::delete(&self.http, &node, identity.device.keys(), &share.sha256)
                    .await
                    .is_ok()
            }
            _ => false,
        };
        if !deleted {
            let _ = self.index.queue_delete("online", &share.sha256, "device");
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
    }

    /// Q12: delete sent copies after 24 hours, settle pending stops and clear
    /// "sharing ended" after a day.
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
                index::share::ENDED
                    if share
                        .ended_at
                        .is_some_and(|at| now.saturating_sub(at) >= SHARE_KEEP_SECONDS) =>
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

    /// The existing shared copy, if `again` allows reuse and it still exists.
    async fn reusable_copy(self: &Arc<Self>, id: &str, node: &NodeEndpoint) -> Option<ShareCopy> {
        let share = self.index.share(id).ok().flatten()?;
        if !matches!(
            share.state.as_str(),
            index::share::OPEN | index::share::SENT
        ) {
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
    async fn run_share(
        self: &Arc<Self>,
        id: &str,
        again: bool,
        verify: Arc<Mutex<Option<oneshot::Sender<bool>>>>,
        slot: RelaySlot,
    ) -> Option<ShareState> {
        let ended = |reason: Ended| Some(ShareState::new(id, reason.state()));
        let node = self.writable_online()?;
        let identity = self.identity().ok()?;
        let file = self.index.file(id).ok().flatten()?;
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
                match self.make_share_copy(id, &node, progress).await {
                    Ok(copy) => copy,
                    Err(reason) => return ended(reason),
                }
            }
        };
        if fresh {
            // One shared copy per file: a new copy replaces an older one,
            // which is deleted now (its link may not have been used yet, but
            // the index tracks only the current copy).
            if let Some(old) = previous.filter(|p| {
                p.sha256 != copy.sha256
                    && (p.state == index::share::SENT || p.state == index::share::OPEN)
            }) {
                let _ = self.index.queue_delete("online", &old.sha256, "device");
                if let (Some(old_id), Ok(keychain)) =
                    (FileId::parse(&old.share_id), self.keychain())
                {
                    let _ = keychain.remove_file_key(&old_id);
                }
            }
            let _ = self.index.put_share(&ShareRecord {
                file_id: id.to_owned(),
                share_id: copy.share_id.to_string(),
                sha256: copy.sha256.clone(),
                size: copy.size,
                state: index::share::OPEN.into(),
                sent_at: None,
                delete_at: None,
                ended_at: None,
            });
        }
        let mut state = ShareState::new(id, "preparing");
        state.progress = Some(100);
        self.emit_share(state);

        // 2. A one-use creation grant from the online node's issuer, then a
        //    fresh session, words and locator on the relay.
        let grant = match client::live_grant(&self.http, &node, identity.device.keys()).await {
            Ok(grant) => grant,
            Err(client::NodeError::Unreachable) => return ended(Ended::Relay),
            Err(_) => return ended(Ended::Relay),
        };
        let relay = Relay::new(
            &self.relay_base(&node),
            self.cfg.allow_loopback_http,
            self.http.clone(),
        )
        .ok()?;
        let grant = Capability::from_grant(&grant.token).ok()?;
        let issued = now();
        let session = Session::generate(
            Namespace::parse(PAIRING_NAMESPACE).ok()?,
            Namespace::parse(PAIRING_PURPOSE).ok()?,
            PAIRING_LIFETIME,
            issued,
            &mut OsRng,
        )
        .ok()?;
        let secret = PairingSecret::generate(4, &mut OsRng).ok()?;
        let words: Vec<String> = secret
            .expose_words()
            .split(' ')
            .map(str::to_owned)
            .collect();
        let inviter = match relay.allocate(&session, &grant).await {
            Ok(inviter) => Arc::new(inviter),
            Err(_) => return ended(Ended::Relay),
        };
        if let Ok(mut slot) = slot.lock() {
            *slot = Some((relay.clone(), inviter.clone()));
        }
        let link = PublicRoom {
            session: session.clone(),
            secret_format: "words".into(),
        }
        .link(
            &self.cfg.get_base,
            self.cfg.allow_loopback_http,
            PAIRING_NAMESPACE,
            PAIRING_PURPOSE,
            issued,
        )
        .ok()?;
        let expires_at = session.expires;
        let announce = |name: &'static str, check: Option<Vec<String>>| {
            let mut state = ShareState::new(id, name);
            state.link = Some(link.clone());
            state.words = Some(words.clone());
            state.expires_at = Some(expires_at);
            state.check_words = check;
            self.emit_share(state);
        };
        announce("ready", None);

        // 3. Pairing, words, send and receipt, all inside the 600 s window.
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(expires_at.saturating_sub(now()));
        let flow = self.pair_and_send(
            id, &file, &copy, &node, &relay, &inviter, session, secret, verify, &announce,
        );
        match tokio::time::timeout_at(deadline, flow).await {
            Err(_) => ended(Ended::Expired),
            Ok(Err(reason)) => ended(reason),
            Ok(Ok(delete_at)) => {
                let mut state = ShareState::new(id, "sent");
                state.delete_at = Some(delete_at);
                Some(state)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn pair_and_send(
        self: &Arc<Self>,
        id: &str,
        file: &index::FileRecord,
        copy: &ShareCopy,
        node: &NodeEndpoint,
        relay: &Relay,
        inviter: &InviterSession,
        session: Session,
        secret: PairingSecret,
        verify: Arc<Mutex<Option<oneshot::Sender<bool>>>>,
        announce: &(dyn Fn(&'static str, Option<Vec<String>>) + Sync),
    ) -> Result<u64, Ended> {
        let mut gate = PairingGate::new(session, secret, PAIRING_ATTEMPTS, now())
            .map_err(|_| Ended::Expired)?;
        let exchange = gate
            .start(Role::Inviter, now(), &mut OsRng)
            .map_err(|_| Ended::Expired)?;
        drop(gate);
        relay
            .send(inviter, "hello", &relay::public_message(&exchange.hello()))
            .await
            .map_err(|_| Ended::Relay)?;
        let peer_hello = self.wait_for(relay, inviter, "hello").await?;
        announce("opened", None);
        let peer_hello = relay::parse_public_message(&peer_hello).map_err(|_| Ended::WrongWords)?;
        let pending = exchange
            .finish(&peer_hello, now())
            .map_err(|_| Ended::WrongWords)?;
        let proof = pending.confirmation().map_err(|_| Ended::WrongWords)?;
        relay
            .send(inviter, "proof", &relay::public_message(&proof))
            .await
            .map_err(|_| Ended::Relay)?;
        let peer_proof = self.wait_for(relay, inviter, "proof").await?;
        let peer_proof = relay::parse_public_message(&peer_proof).map_err(|_| Ended::WrongWords)?;
        let mut channel = pending
            .confirm(&peer_proof, now())
            .map_err(|_| Ended::WrongWords)?;
        let check: Vec<String> = channel
            .verification_words(3, now())
            .map_err(|_| Ended::WrongWords)?
            .split(' ')
            .map(str::to_owned)
            .collect();
        let (sender, receiver) = oneshot::channel();
        if let Ok(mut slot) = verify.lock() {
            *slot = Some(sender);
        }
        announce("check", Some(check));
        match receiver.await {
            Ok(true) => {}
            Ok(false) => return Err(Ended::Mismatch),
            Err(_) => return Err(Ended::Cancelled),
        }
        self.emit_share(ShareState::new(id, "sending"));
        let sent_at = now();
        let delete_at = sent_at + SHARE_KEEP_SECONDS;
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
        relay
            .send(inviter, "packet-0", packet.as_bytes())
            .await
            .map_err(|_| Ended::Relay)?;
        let reply = self.wait_for(relay, inviter, "packet-0").await?;
        let reply = String::from_utf8(reply).map_err(|_| Ended::Relay)?;
        let clear = channel.open(&reply, now()).map_err(|_| Ended::Relay)?;
        transfer.acknowledged(&clear).map_err(|_| Ended::Relay)?;
        let _ = self.index.put_share(&ShareRecord {
            file_id: id.to_owned(),
            share_id: copy.share_id.to_string(),
            sha256: copy.sha256.clone(),
            size: copy.size,
            state: index::share::SENT.into(),
            sent_at: Some(sent_at),
            delete_at: Some(delete_at),
            ended_at: None,
        });
        self.emit_row(id);
        Ok(delete_at)
    }

    async fn wait_for(
        &self,
        relay: &Relay,
        inviter: &InviterSession,
        kind: &str,
    ) -> Result<Vec<u8>, Ended> {
        loop {
            match relay.poll(inviter, kind).await {
                Ok(Some(bytes)) => return Ok(bytes),
                Ok(None) => tokio::time::sleep(POLL).await,
                Err(_) => return Err(Ended::Relay),
            }
        }
    }
}

#[allow(dead_code)]
const _: u64 = DEFAULT_NODE_BLOB_LIMIT;
