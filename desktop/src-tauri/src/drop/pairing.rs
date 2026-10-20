//! The live pairing Share and Receive both use (design questions Q6 and
//! Q17): a one-use Foregather creation grant from the online node's issuer,
//! a fresh live session under namespace `wildbloom.drop` with the caller's
//! purpose, four words and a link, the PAKE with one attempt, and three check
//! words the owner confirms.  What travels on the confirmed channel after
//! that is the caller's: Share sends one transfer-v1 invitation, Receive runs
//! the `foregather-exchange/1` profile.
//!
//! The words, the link, the confirmed channel and every relay capability
//! stay in memory and are never logged.

use super::client::{self, NodeEndpoint};
use super::engine::{Engine, PAIRING_NAMESPACE, now};
use super::relay::{self, Capability, InviterSession, Relay, RelayError};
use foregather_kit::Namespace;
use foregather_kit::handoff::PublicRoom;
use foregather_kit::live::{Channel, PairingGate, PairingSecret, Role, Session};
use nostr::prelude::Keys;
use rand_core::OsRng;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

/// The live session lifetime, the documented maximum (Q6).
pub const PAIRING_LIFETIME: u64 = 600;
/// One attempt (Q6): the relay's hello and proof slots are write-once.
pub(crate) const PAIRING_ATTEMPTS: u8 = 1;
/// How often an inviter polls for the other side's next message.
pub(crate) const POLL: Duration = Duration::from_millis(250);

/// The relay session a running flow made, so a stopped flow can delete it.
pub(crate) type RelaySlot = Arc<Mutex<Option<(Relay, Arc<InviterSession>)>>>;
/// Where the owner's answer to the check words goes.
pub(crate) type VerifySlot = Arc<Mutex<Option<oneshot::Sender<bool>>>>;

/// The inviter's side of one live session on the relay: write its own
/// message slots, read the other side's, and delete the session.  [`Live`]
/// is the relay over HTTP; tests put an in-memory relay behind it.
pub(crate) trait LiveTransport: Send + Sync {
    /// Write-once `PUT` of the inviter's `kind` slot.
    fn send(&self, kind: &str, value: &[u8])
    -> impl Future<Output = Result<(), RelayError>> + Send;
    /// One read of the other side's `kind` slot: `None` while it is empty.
    fn poll(&self, kind: &str) -> impl Future<Output = Result<Option<Vec<u8>>, RelayError>> + Send;
    /// Ends the session on the relay.
    fn delete(&self) -> impl Future<Output = Result<(), RelayError>> + Send;
}

/// What a pairing ended in, short of a confirmed channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    Expired,
    WrongWords,
    Mismatch,
    Relay,
    Node,
    Cancelled,
}

impl Ended {
    pub(crate) fn state(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::WrongWords => "wrong_words",
            Self::Mismatch => "mismatch",
            Self::Relay | Self::Cancelled => "relay_unreachable",
            Self::Node => "node_unreachable",
        }
    }
}

/// A live session on the relay: what the owner sends and reads out, and
/// what the flow polls.
pub(crate) struct Live {
    pub relay: Relay,
    pub inviter: Arc<InviterSession>,
    pub link: String,
    pub words: Vec<String>,
    /// When the session ends; the whole exchange must finish by then.
    pub expires_at: u64,
}

impl Live {
    /// The session deadline as a tokio instant.
    pub fn deadline(&self) -> tokio::time::Instant {
        deadline_at(self.expires_at)
    }
}

/// `expires_at` (Unix seconds) as a tokio instant.
pub(crate) fn deadline_at(expires_at: u64) -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(expires_at.saturating_sub(now()))
}

impl Drop for Live {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.link);
        for word in &mut self.words {
            zeroize::Zeroize::zeroize(word);
        }
    }
}

impl LiveTransport for Live {
    async fn send(&self, kind: &str, value: &[u8]) -> Result<(), RelayError> {
        self.relay.send(&self.inviter, kind, value).await
    }

    async fn poll(&self, kind: &str) -> Result<Option<Vec<u8>>, RelayError> {
        self.relay.poll(&self.inviter, kind).await
    }

    async fn delete(&self) -> Result<(), RelayError> {
        self.relay.delete(&self.inviter).await
    }
}

impl Engine {
    pub(crate) fn relay_base(&self, online: &NodeEndpoint) -> String {
        self.cfg
            .relay_base
            .clone()
            .unwrap_or_else(|| format!("{}pair/v1/", online.origin()))
    }

    pub(crate) fn next_pairing_generation(&self) -> u64 {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// A one-use creation grant from the online node's issuer, then a fresh
    /// session for `purpose`, four words and the link under `link_base`.  The
    /// relay session goes in `slot` at once, so a stopped flow deletes it.
    pub(crate) async fn open_pairing(
        &self,
        node: &NodeEndpoint,
        device: &Keys,
        purpose: &str,
        link_base: &str,
        slot: &RelaySlot,
    ) -> Result<(Live, Session, PairingSecret), Ended> {
        let grant = client::live_grant(&self.http, node, device)
            .await
            .map_err(|_| Ended::Relay)?;
        let relay = Relay::new(
            &self.relay_base(node),
            self.cfg.allow_loopback_http,
            self.http.clone(),
        )
        .map_err(|_| Ended::Relay)?;
        let grant = Capability::from_grant(&grant.token).map_err(|_| Ended::Relay)?;
        let issued = now();
        let session = Session::generate(
            Namespace::parse(PAIRING_NAMESPACE).map_err(|_| Ended::Relay)?,
            Namespace::parse(purpose).map_err(|_| Ended::Relay)?,
            PAIRING_LIFETIME,
            issued,
            &mut OsRng,
        )
        .map_err(|_| Ended::Relay)?;
        let secret = PairingSecret::generate(4, &mut OsRng).map_err(|_| Ended::Relay)?;
        let words: Vec<String> = secret
            .expose_words()
            .split(' ')
            .map(str::to_owned)
            .collect();
        let inviter = match relay.allocate(&session, &grant).await {
            Ok(inviter) => Arc::new(inviter),
            Err(_) => return Err(Ended::Relay),
        };
        if let Ok(mut slot) = slot.lock() {
            *slot = Some((relay.clone(), inviter.clone()));
        }
        let link = PublicRoom {
            session: session.clone(),
            secret_format: "words".into(),
        }
        .link(
            link_base,
            self.cfg.allow_loopback_http,
            PAIRING_NAMESPACE,
            purpose,
            issued,
        )
        .map_err(|_| Ended::Relay)?;
        let expires_at = session.expires;
        Ok((
            Live {
                relay,
                inviter,
                link,
                words,
                expires_at,
            },
            session,
            secret,
        ))
    }

    pub(crate) async fn delete_relay_session(&self, slot: &RelaySlot) {
        let taken = slot.lock().ok().and_then(|mut s| s.take());
        if let Some((relay, session)) = taken {
            let _ = relay.delete(&session).await;
        }
    }
}

/// The PAKE (one attempt) and the three check words, then the owner's
/// answer through `verify`.  `announce` gets `opened` once the other side's
/// hello arrives and `check` with the words.  Returns the confirmed channel,
/// which has sealed and opened nothing, once the owner says they match.
pub(crate) async fn pair<T: LiveTransport>(
    transport: &T,
    session: Session,
    secret: PairingSecret,
    verify: &VerifySlot,
    announce: &(dyn Fn(&'static str, Option<Vec<String>>) + Sync),
) -> Result<Channel, Ended> {
    let mut gate =
        PairingGate::new(session, secret, PAIRING_ATTEMPTS, now()).map_err(|_| Ended::Expired)?;
    let exchange = gate
        .start(Role::Inviter, now(), &mut OsRng)
        .map_err(|_| Ended::Expired)?;
    drop(gate);
    transport
        .send("hello", &relay::public_message(&exchange.hello()))
        .await
        .map_err(|_| Ended::Relay)?;
    let peer_hello = wait_for(transport, "hello").await?;
    announce("opened", None);
    let peer_hello = relay::parse_public_message(&peer_hello).map_err(|_| Ended::WrongWords)?;
    let pending = exchange
        .finish(&peer_hello, now())
        .map_err(|_| Ended::WrongWords)?;
    let proof = pending.confirmation().map_err(|_| Ended::WrongWords)?;
    transport
        .send("proof", &relay::public_message(&proof))
        .await
        .map_err(|_| Ended::Relay)?;
    let peer_proof = wait_for(transport, "proof").await?;
    let peer_proof = relay::parse_public_message(&peer_proof).map_err(|_| Ended::WrongWords)?;
    let channel = pending
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
        Ok(true) => Ok(channel),
        Ok(false) => Err(Ended::Mismatch),
        Err(_) => Err(Ended::Cancelled),
    }
}

/// Polls the other side's `kind` slot until it is filled or the relay
/// refuses.
pub(crate) async fn wait_for<T: LiveTransport>(
    transport: &T,
    kind: &str,
) -> Result<Vec<u8>, Ended> {
    loop {
        match transport.poll(kind).await {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => tokio::time::sleep(POLL).await,
            Err(_) => return Err(Ended::Relay),
        }
    }
}
