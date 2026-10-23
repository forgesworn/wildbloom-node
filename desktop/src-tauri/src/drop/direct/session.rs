//! One "Receive a file" session, from an open live session to a kept file
//! (`docs/PROTOCOL.md`, "Session" to "Reconnection and the deadline").  Drop
//! is the inviter and makes the WebRTC offer.  The order:
//!
//! 1. Show the link and words; run the PAKE; show the three check words and
//!    wait for the owner's yes or no.
//! 2. Only on yes, switch the confirmed channel to `foregather-exchange/1`
//!    and send `invite` (`dir:"to-drop"`, `hide`, `ice` = the page's ICE entry
//!    from the node, or the built-in STUN default, a fresh 16-byte `id`, `max`
//!    250,000,000).
//! 3. Read `manifest` and ask the owner.  `decline` ends it there: no
//!    connection was made and nothing was allocated on a TURN server.
//! 4. On accept, open the hidden window, make the connection from Drop's own
//!    ICE entry (relay-only when hiding), send `accept` with the offer, read
//!    `answer`, keep its key here and hand only the SDP to the window.
//! 5. While the data flows, answer an ICE failure (or a long disconnection)
//!    with `restart`, at most five times and only before the deadline, each
//!    at the index after the page's last message.
//!
//! Cancellation and the deadline end every wait before the transfer; once
//! the data channel is up it may outlive the session, and the deadline then
//! only ends restarts.  Every way out closes the window, deletes what the
//! sink held (unless kept), tells the page `stop` if it still can, and
//! deletes the relay session.  This module knows nothing of Tauri: the
//! engine supplies a [`DirectHost`], and the tests a fake one.

use super::awake::Awake;
use super::messages::{
    self, Context, MAX_FILE_BYTES, MESSAGES_PER_SIDE, Manifest, Message, RESTARTS, Side, StopReason,
};
use super::sink::{Kept, Sink, SinkError};
use super::{PeerOp, PeerReport, PeerRequest, PeerState, ReceiveState, SinkEvent};
use crate::drop::client::TurnCredentials;
use crate::drop::engine::now;
use crate::drop::pairing::{self, Ended, LiveTransport, VerifySlot};
use crate::drop::relay::RelayError;
use foregather_kit::exchange::ExchangeChannel;
use foregather_kit::live::{PairingSecret, Session};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep_until, timeout_at};

/// What a session needs from around it.
pub trait DirectHost: Send + Sync + 'static {
    /// A new sheet state, for the Drop window.
    fn emit(&self, state: &ReceiveState);
    /// Opens the hidden peer window.  `false` if it cannot be made.
    fn open_peer(&self) -> bool;
    /// A request to the hidden window, over its request channel.
    fn peer(&self, request: &PeerRequest);
    /// Destroys the hidden window.
    fn close_peer(&self);
    /// Keeps the computer from idle-sleeping while the guard lives.
    fn keep_awake(&self) -> Awake;
}

/// The session's clocks.  Tests shorten them.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// How often the page's next exchange message is polled for.
    pub poll: Duration,
    /// How long the hidden window has to answer a request.
    pub reply: Duration,
    /// How long the first connection may take after the answer.
    pub connect: Duration,
    /// How long a failed connection has to come back.
    pub reconnect: Duration,
    /// How long a connection may stay `disconnected` before Drop restarts
    /// ICE (`failed` restarts at once).
    pub restart_after: Duration,
    /// How long a last frame has to leave before the window closes.
    pub flush: Duration,
    /// How long the page has to read a last `stop` or `decline` before the
    /// relay session is deleted.
    pub linger: Duration,
    /// How long a closed data channel waits for the page's `stop`: a page
    /// that is closed says so on the exchange, but its channel may close
    /// first.
    pub stop_grace: Duration,
    /// How long a connected peer may send nothing before the transfer is
    /// given up as lost.
    pub stall: Duration,
}

/// How long a connected transfer may go without a new byte before Drop ends
/// it as lost, so a peer that stops sending cannot hold Drop (and the Mac
/// awake) indefinitely.  A reconnection is timed by its own clocks instead.
pub const STALL: Duration = Duration::from_secs(90);

impl Timing {
    pub const DEFAULT: Self = Self {
        poll: pairing::POLL,
        reply: Duration::from_secs(20),
        connect: Duration::from_secs(90),
        reconnect: Duration::from_secs(45),
        restart_after: Duration::from_secs(8),
        flush: Duration::from_secs(1),
        linger: Duration::from_secs(2),
        stop_grace: Duration::from_secs(3),
        stall: STALL,
    };
}

/// An allocated live session and what the invitation needs.
pub struct Opened<T> {
    pub transport: T,
    pub session: Session,
    pub secret: PairingSecret,
    pub link: String,
    pub words: Vec<String>,
    pub expires_at: u64,
    pub turn: TurnCredentials,
    pub hide: bool,
}

/// Drop's private temp directory and the Received folder.
#[derive(Clone, Debug)]
pub struct Dirs {
    pub temp: PathBuf,
    pub received: PathBuf,
    /// The bytes free on the volume holding a path ([`free_space`]; tests
    /// supply their own).
    pub space: fn(&Path) -> Option<u64>,
}

/// Room kept free beyond twice the envelope before a file is accepted.
pub const SPACE_MARGIN: u64 = 64 * 1024 * 1024;

/// The bytes available to Drop on the volume holding `path`, or on its
/// nearest existing ancestor (the Received folder may not exist yet).
/// `None` when it cannot be read.
pub fn free_space(path: &Path) -> Option<u64> {
    let existing = path.ancestors().find(|p| p.exists())?;
    fs2::available_space(existing).ok()
}

/// How the sink's file ended: kept, or stopped before it could be.  One
/// lock decides between the two, so the ending the owner is shown is always
/// what is on disk.
#[derive(Default)]
struct Ending {
    /// The session is ending without a kept file: nothing may be placed.
    cancelled: bool,
    kept: Option<Kept>,
}

/// Where [`SinkSlot::end`] waits for a test.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pause {
    /// Verified, before the ending's lock.
    BeforeLock,
    /// Holding the ending's lock, before the file is placed.
    InLock,
}

/// The sink, shared by the session and the sink commands.
pub struct SinkSlot {
    sink: Mutex<Option<Sink>>,
    ending: Mutex<Ending>,
    events: mpsc::UnboundedSender<SinkEvent>,
    /// When the last write arrived, for the stall timer.
    last_write: Mutex<Option<Instant>>,
    #[cfg(test)]
    pause: Mutex<Option<PauseHook>>,
}

/// Where to pause, the signal that it has, and the wait to go on.
#[cfg(test)]
type PauseHook = (
    Pause,
    std::sync::mpsc::SyncSender<()>,
    std::sync::mpsc::Receiver<()>,
);

impl SinkSlot {
    fn install(&self, sink: Sink) {
        if let Ok(mut slot) = self.sink.lock() {
            *slot = Some(sink);
        }
    }

    /// Takes the sink if it belongs to `transfer`.
    fn take(&self, transfer: &str) -> Option<Sink> {
        let mut slot = self.sink.lock().ok()?;
        if slot.as_ref().is_some_and(|s| s.transfer() == transfer) {
            slot.take()
        } else {
            None
        }
    }

    /// `direct_sink_write`: blocking file I/O, so callers run it off the
    /// async threads.  A refused write deletes the temp file at once.
    pub fn write(&self, transfer: &str, offset: u64, bytes: &[u8]) -> Result<(), SinkError> {
        let mut slot = self
            .sink
            .lock()
            .map_err(|_| SinkError::Failed("the sink is unavailable"))?;
        let Some(sink) = slot.as_mut().filter(|s| s.transfer() == transfer) else {
            return Err(SinkError::Failed("no transfer is receiving"));
        };
        match sink.write(offset, bytes) {
            Ok(ack) => {
                if let Ok(mut last) = self.last_write.lock() {
                    *last = Some(Instant::now());
                }
                if let Some(acked) = ack {
                    let _ = self.events.send(SinkEvent::Progress { acked });
                }
                Ok(())
            }
            Err(error) => {
                *slot = None;
                let _ = self.events.send(SinkEvent::Failed(error));
                Err(error)
            }
        }
    }

    /// `direct_sink_end`: verifies and keeps the file, or deletes it.
    /// Blocking.  The file is placed only while holding the ending's lock and
    /// only if the session has not ended without it ([`SinkSlot::cancel`]).
    pub fn end(&self, transfer: &str, sha256: [u8; 32], size: u64) -> Result<Kept, SinkError> {
        let Some(sink) = self.take(transfer) else {
            return Err(SinkError::Failed("no transfer is receiving"));
        };
        let _ = self.events.send(SinkEvent::Verifying);
        let verified = match sink.verify(sha256, size) {
            Ok(verified) => verified,
            Err(error) => {
                let _ = self.events.send(SinkEvent::Failed(error));
                return Err(error);
            }
        };
        #[cfg(test)]
        self.paused(Pause::BeforeLock);
        let Ok(mut ending) = self.ending.lock() else {
            return Err(SinkError::Failed("the sink is unavailable"));
        };
        #[cfg(test)]
        self.paused(Pause::InLock);
        if ending.cancelled {
            // Stopped first: the plaintext goes with `verified`.
            return Err(SinkError::Failed("the transfer was stopped"));
        }
        match verified.keep() {
            Ok(kept) => {
                ending.kept = Some(kept.clone());
                let _ = self.events.send(SinkEvent::Kept(kept.clone()));
                Ok(kept)
            }
            Err(error) => {
                let _ = self.events.send(SinkEvent::Failed(error));
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn paused(&self, at: Pause) {
        let hook = self.pause.lock().ok().and_then(|mut p| {
            if p.as_ref().is_some_and(|(want, ..)| *want == at) {
                p.take()
            } else {
                None
            }
        });
        if let Some((_, paused, go)) = hook {
            let _ = paused.send(());
            let _ = go.recv();
        }
    }

    /// Makes the next [`SinkSlot::end`] stop at `at`: it signals the first
    /// returned receiver and waits on the sender.
    #[cfg(test)]
    pub(crate) fn pause_at(
        &self,
        at: Pause,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (paused, paused_rx) = std::sync::mpsc::sync_channel(1);
        let (go, go_rx) = std::sync::mpsc::sync_channel(1);
        *self.pause.lock().unwrap() = Some((at, paused, go_rx));
        (paused_rx, go)
    }

    /// `direct_sink_abort`: deletes what the sink holds.  Safe to repeat.
    pub fn abort(&self, transfer: &str) {
        drop(self.take(transfer));
    }

    /// The session is ending.  Returns the kept file if one was placed;
    /// otherwise no file will be, and what the sink holds is deleted.  Waits
    /// for an end that is placing its file.  Blocking.
    fn cancel(&self) -> Option<Kept> {
        let kept = {
            let mut ending = self.ending.lock().ok()?;
            if ending.kept.is_none() {
                ending.cancelled = true;
            }
            ending.kept.clone()
        };
        let sink = self.sink.lock().ok().and_then(|mut s| s.take());
        drop(sink);
        kept
    }

    /// The file this session kept, if it kept one.
    pub fn kept(&self) -> Option<Kept> {
        self.ending.lock().ok().and_then(|e| e.kept.clone())
    }

    /// When the last write arrived.
    fn last_write(&self) -> Option<Instant> {
        self.last_write.lock().ok().and_then(|l| *l)
    }

    pub fn holds(&self) -> bool {
        self.sink.lock().is_ok_and(|s| s.is_some())
    }
}

/// What the commands use to reach a running session.
pub struct Controls {
    pub verify: VerifySlot,
    consent: Mutex<Option<oneshot::Sender<bool>>>,
    cancel: watch::Sender<bool>,
    reports: mpsc::UnboundedSender<PeerReport>,
    transfer: Mutex<Option<String>>,
    /// The final state has gone out.  The task may still be tidying up (a
    /// last word to the page, the relay session's deletion), but a new
    /// receive may start.
    finished: AtomicBool,
    pub sink: SinkSlot,
}

impl Controls {
    /// The owner's answer to the check words.  `false` if nothing waits for
    /// one.
    pub fn verify(&self, matches: bool) -> bool {
        let sender = self.verify.lock().ok().and_then(|mut v| v.take());
        sender.is_some_and(|s| s.send(matches).is_ok())
    }

    /// The owner's answer to the file.  `false` if nothing waits for one.
    pub fn consent(&self, accept: bool) -> bool {
        let sender = self.consent.lock().ok().and_then(|mut c| c.take());
        sender.is_some_and(|s| s.send(accept).is_ok())
    }

    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }

    pub fn cancelled(&self) -> bool {
        *self.cancel.borrow()
    }

    pub fn finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }

    /// Marks the final state as sent, just before it is emitted.
    pub fn mark_finished(&self) {
        self.finished.store(true, Ordering::SeqCst);
    }

    /// A receiver that sees the cancel, for waits outside the session.
    pub fn watch_cancel(&self) -> watch::Receiver<bool> {
        self.cancel.subscribe()
    }

    /// The transfer's `id`, once the invitation has it.
    pub fn transfer(&self) -> Option<String> {
        self.transfer.lock().ok().and_then(|t| t.clone())
    }

    /// Passes on a report from the hidden window.  One about another
    /// transfer is dropped (`false`).
    pub fn report(&self, report: PeerReport) -> bool {
        let current = self.transfer();
        let ours = match report.transfer() {
            None => true,
            Some(transfer) => current.as_deref() == Some(transfer),
        };
        ours && self.reports.send(report).is_ok()
    }
}

/// The session's ends of the control channels.
pub struct Inputs {
    cancel: watch::Receiver<bool>,
    reports: mpsc::UnboundedReceiver<PeerReport>,
    sink_events: mpsc::UnboundedReceiver<SinkEvent>,
}

pub fn controls() -> (Arc<Controls>, Inputs) {
    let (cancel, cancel_rx) = watch::channel(false);
    let (reports, reports_rx) = mpsc::unbounded_channel();
    let (events, events_rx) = mpsc::unbounded_channel();
    let controls = Arc::new(Controls {
        verify: Arc::new(Mutex::new(None)),
        consent: Mutex::new(None),
        cancel,
        reports,
        transfer: Mutex::new(None),
        finished: AtomicBool::new(false),
        sink: SinkSlot {
            sink: Mutex::new(None),
            ending: Mutex::new(Ending::default()),
            events,
            last_write: Mutex::new(None),
            #[cfg(test)]
            pause: Mutex::new(None),
        },
    });
    (
        controls,
        Inputs {
            cancel: cancel_rx,
            reports: reports_rx,
            sink_events: events_rx,
        },
    )
}

/// How a session ended.
#[derive(Debug)]
enum End {
    Kept(Kept),
    Declined,
    /// The owner stopped it.
    Cancelled,
    /// The page stopped it or was closed.
    PeerCancelled,
    Failed {
        reason: &'static str,
        /// The `stop` to send on the exchange, if it can still be sent.
        tell: Option<StopReason>,
        /// The STOP frame the window sends if its transfer still runs.
        frame: Option<u8>,
    },
}

impl End {
    /// A failure this end found: the page is told, and the window sends
    /// STOP 2.
    fn failed(reason: &'static str) -> Self {
        Self::Failed {
            reason,
            tell: Some(StopReason::Failed),
            frame: Some(2),
        }
    }

    /// A failure the page already knows of, or that it cannot be told.
    fn quiet(reason: &'static str) -> Self {
        Self::Failed {
            reason,
            tell: None,
            frame: None,
        }
    }

    fn peer_stop(reason: StopReason) -> Self {
        match reason {
            StopReason::Cancelled => Self::PeerCancelled,
            StopReason::Unsupported => Self::quiet("unsupported"),
            StopReason::Failed => Self::quiet("peer_failed"),
        }
    }

    /// The window's frame logic ended with `outcome`.
    fn transfer(outcome: &str, kept: Option<Kept>) -> Self {
        let told = |reason| Self::Failed {
            reason,
            tell: Some(StopReason::Failed),
            frame: None,
        };
        match outcome {
            "kept" => kept.map_or(Self::failed("webview"), Self::Kept),
            "cancelled" => Self::Cancelled,
            "peer-cancelled" => Self::PeerCancelled,
            "peer-failed" => Self::quiet("peer_failed"),
            "peer-storage" => Self::quiet("peer_storage"),
            "protocol" => told("protocol"),
            "closed" => told("lost"),
            "verification" => told("verification"),
            "storage" => told("storage"),
            _ => Self::failed("webview"),
        }
    }
}

/// A webview reply the session waits for.
enum Reply {
    Done,
    Offer(String),
}

/// A restart in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    None,
    /// Waiting for the window's restart offer.
    Offer {
        seq: u64,
        by: Instant,
    },
    /// `restart` went out at this index; waiting for the page's answer.
    Answer {
        index: usize,
    },
    /// Waiting for the window to apply the restart answer.
    Apply {
        seq: u64,
        by: Instant,
    },
}

/// What woke the transfer loop.
enum Wake {
    Cancel,
    Sink(Option<SinkEvent>),
    Report(Option<PeerReport>),
    Packet(usize, Result<Vec<u8>, RelayError>),
    Timer,
    Deadline,
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    let _ = cancel.wait_for(|c| *c).await;
}

/// Polls the page's `kind` slot until it is filled.  Transient relay
/// failures only mean "not yet".
async fn wait_packet<T: LiveTransport>(
    transport: &T,
    kind: &str,
    poll: Duration,
) -> Result<Vec<u8>, RelayError> {
    loop {
        match transport.poll(kind).await {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => tokio::time::sleep(poll).await,
            Err(error) if error.transient() => tokio::time::sleep(poll).await,
            Err(error) => return Err(error),
        }
    }
}

/// 16 fresh random bytes as canonical unpadded base64url.
fn fresh_id() -> Option<String> {
    use base64::Engine as _;
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

struct Run<T, H> {
    transport: T,
    host: Arc<H>,
    controls: Arc<Controls>,
    cancel: watch::Receiver<bool>,
    reports: mpsc::UnboundedReceiver<PeerReport>,
    sink_events: mpsc::UnboundedReceiver<SinkEvent>,
    timing: Timing,
    dirs: Dirs,
    deadline: Instant,
    expires_at: u64,
    hide: bool,
    /// The ICE configuration holds a TURN URL.  Without one the two ends can
    /// only meet directly, and a failure to connect says so.
    relay_offered: bool,
    id: String,
    exchange: Option<ExchangeChannel>,
    /// The page can still be read: the relay has not failed.
    exchange_alive: bool,
    /// A sealed message whose upload was cut off; re-sent before a stop.
    unsent: Option<(u8, String)>,
    /// A `stop` went either way, so nothing more is sent.
    stopped: bool,
    /// The last thing written was a `stop` or `decline` the page should read.
    told: bool,
    seq: u64,
    peer_open: bool,
    manifest: Option<Manifest>,
    total: u64,
    acked: u64,
    channel_open: bool,
    connected: bool,
    ever_connected: bool,
    reconnecting: bool,
    connect_by: Option<Instant>,
    failed_since: Option<Instant>,
    disconnected_since: Option<Instant>,
    pending: Pending,
    restarts: usize,
    /// The data is flowing: restarts may start.
    in_transfer: bool,
    /// The file is being verified: no more bytes are due.
    verifying: bool,
    /// When the data channel opened or the connection last came up: the
    /// stall timer runs from here or the last write, whichever is later.
    flowing_since: Option<Instant>,
    kept_at: Option<(Instant, Kept)>,
    awake: Option<Awake>,
}

/// Runs one session to its end and returns the final state, which has
/// already been emitted.
pub async fn run<T: LiveTransport + 'static, H: DirectHost>(
    opened: Opened<T>,
    host: Arc<H>,
    controls: Arc<Controls>,
    inputs: Inputs,
    dirs: Dirs,
    timing: Timing,
) -> ReceiveState {
    let Opened {
        transport,
        session,
        secret,
        mut link,
        mut words,
        expires_at,
        turn,
        hide,
    } = opened;
    let mut run = Run {
        transport,
        host,
        controls,
        cancel: inputs.cancel,
        reports: inputs.reports,
        sink_events: inputs.sink_events,
        timing,
        dirs,
        deadline: pairing::deadline_at(expires_at),
        expires_at,
        hide,
        relay_offered: false,
        id: String::new(),
        exchange: None,
        exchange_alive: true,
        unsent: None,
        stopped: false,
        told: false,
        seq: 0,
        peer_open: false,
        manifest: None,
        total: 0,
        acked: 0,
        channel_open: false,
        connected: false,
        ever_connected: false,
        reconnecting: false,
        connect_by: None,
        failed_since: None,
        disconnected_since: None,
        pending: Pending::None,
        restarts: 0,
        in_transfer: false,
        verifying: false,
        flowing_since: None,
        kept_at: None,
        awake: None,
    };
    let end = match run.drive(session, secret, &link, &words, turn).await {
        Ok(end) | Err(end) => end,
    };
    zeroize::Zeroize::zeroize(&mut link);
    for word in &mut words {
        zeroize::Zeroize::zeroize(word);
    }
    run.finish(end).await
}

impl<T: LiveTransport, H: DirectHost> Run<T, H> {
    fn emit(&self, state: &ReceiveState) {
        self.host.emit(state);
    }

    /// A state that names the file.
    fn file_state(&self, name: &'static str) -> ReceiveState {
        let mut state = ReceiveState::new(name);
        if let Some(manifest) = &self.manifest {
            state.name = Some(manifest.name.clone());
            state.size = Some(manifest.size);
            state.media_type = Some(manifest.media_type.clone());
        }
        state
    }

    fn emit_progress(&self) {
        let mut state = self.file_state(if self.channel_open {
            "receiving"
        } else {
            "connecting"
        });
        state.hidden = Some(self.hide);
        state.reconnecting = Some(self.reconnecting);
        if self.channel_open {
            state.acknowledged = Some(self.acked);
            state.total = Some(self.total);
        }
        self.emit(&state);
    }

    fn request(&mut self, op: PeerOp) -> u64 {
        self.seq += 1;
        self.host.peer(&PeerRequest {
            transfer: self.id.clone(),
            seq: self.seq,
            op,
        });
        self.seq
    }

    async fn drive(
        &mut self,
        session: Session,
        secret: PairingSecret,
        link: &str,
        words: &[String],
        turn: TurnCredentials,
    ) -> Result<End, End> {
        // 1. The link and words, the PAKE and the check words.
        let host = self.host.clone();
        let expires_at = self.expires_at;
        let announce = |name: &'static str, check: Option<Vec<String>>| {
            let mut state = ReceiveState::new(name);
            state.link = Some(link.to_owned());
            state.words = Some(words.to_vec());
            state.expires_at = Some(expires_at);
            state.check_words = check;
            host.emit(&state);
        };
        announce("waiting", None);
        let verify = self.controls.verify.clone();
        let paired = tokio::select! {
            biased;
            _ = cancelled(&mut self.cancel) => return Err(End::Cancelled),
            _ = sleep_until(self.deadline) => return Err(End::quiet("expired")),
            paired = pairing::pair(&self.transport, session, secret, &verify, &announce) => paired,
        };
        let channel = match paired {
            Ok(channel) => channel,
            Err(Ended::Cancelled) => return Err(End::Cancelled),
            Err(ended) => return Err(End::quiet(ended.state())),
        };
        self.exchange = Some(ExchangeChannel::new(channel).map_err(|_| End::quiet("protocol"))?);

        // 2. The invitation, with the page's own ICE entry.
        let TurnCredentials { own, peer, .. } = turn;
        self.relay_offered = own.has_turn();
        self.id = fresh_id().ok_or(End::quiet("protocol"))?;
        if let Ok(mut transfer) = self.controls.transfer.lock() {
            *transfer = Some(self.id.clone());
        }
        let invite = Message::Invite {
            hide: self.hide,
            ice: vec![peer],
            id: self.id.clone(),
            max: MAX_FILE_BYTES,
        };
        self.send(&invite, true).await?;
        drop(invite);
        self.emit(&ReceiveState::new("waiting_file"));

        // 3. The manifest, and the owner's answer.
        let manifest = match self.read(Some(MAX_FILE_BYTES), true).await? {
            Message::Manifest(manifest) => manifest,
            Message::Stop { reason } => return Err(End::peer_stop(reason)),
            _ => return Err(self.refuse("protocol").await),
        };
        self.total = match messages::envelope_bytes(&manifest) {
            Some(total) => total,
            None => return Err(self.refuse("protocol").await),
        };
        self.manifest = Some(manifest.clone());
        // The envelope and the plaintext both pass through temp files before
        // the file is placed: ask only if there is room for both and more.
        if !self.has_room() {
            return Err(End::Failed {
                reason: "storage",
                tell: Some(StopReason::Failed),
                frame: None,
            });
        }
        self.emit(&self.file_state("consent"));
        let (answer, chosen) = oneshot::channel();
        if let Ok(mut slot) = self.controls.consent.lock() {
            *slot = Some(answer);
        }
        let accepted = tokio::select! {
            biased;
            _ = cancelled(&mut self.cancel) => return Err(End::Cancelled),
            _ = sleep_until(self.deadline) => return Err(End::quiet("expired")),
            chosen = chosen => chosen,
        };
        match accepted {
            Ok(true) => {}
            Ok(false) => {
                if self.send(&Message::Decline, true).await.is_ok() {
                    self.stopped = true;
                    self.told = true;
                }
                return Ok(End::Declined);
            }
            Err(_) => return Err(End::Cancelled),
        }

        // 4. The connection: Drop's own ICE entry, relay-only when hiding.
        self.awake = Some(self.host.keep_awake());
        self.emit_progress();
        if !self.host.open_peer() {
            return Err(End::failed("webview"));
        }
        self.peer_open = true;
        self.await_ready().await?;
        let seq = self.request(PeerOp::Create {
            ice_servers: vec![own],
            relay_only: self.hide,
            envelope_bytes: self.total,
            size: manifest.size,
        });
        self.reply(seq, true).await?;
        let seq = self.request(PeerOp::Offer);
        let Reply::Offer(offer) = self.reply(seq, true).await? else {
            return Err(End::failed("webview"));
        };
        if messages::check_sdp(&offer).is_err() {
            return Err(End::failed("webview"));
        }
        self.send(&Message::Accept { sdp: offer }, true).await?;
        let (key, sdp) = match self.read(None, true).await? {
            Message::Answer { key, sdp } => (key, sdp),
            Message::Stop { reason } => return Err(End::peer_stop(reason)),
            _ => return Err(self.refuse("protocol").await),
        };
        // The key stays here: the sink holds it, the window never sees it.
        let sink = Sink::create(
            &self.dirs.temp,
            &self.dirs.received,
            &self.id,
            key,
            manifest,
        )
        .map_err(|error| End::Failed {
            reason: error.reason(),
            tell: Some(StopReason::Failed),
            frame: Some(error.stop_code()),
        })?;
        self.controls.sink.install(sink);
        let seq = self.request(PeerOp::Answer { sdp });
        // The data channel may outlive the session from here on.
        self.connect_by = Some(Instant::now() + self.timing.connect);
        self.reply(seq, false).await?;

        // 5. The transfer.
        self.transfer().await
    }

    /// Whether the temp directory's volume and the Received folder's both
    /// have twice the envelope free and [`SPACE_MARGIN`] besides.  A volume
    /// whose free space cannot be read does not refuse the file; a write
    /// that runs out of room still ends it as `storage`.
    fn has_room(&self) -> bool {
        let need = self.total.saturating_mul(2).saturating_add(SPACE_MARGIN);
        [&self.dirs.temp, &self.dirs.received]
            .into_iter()
            .filter_map(|dir| (self.dirs.space)(dir))
            .all(|free| free >= need)
    }

    /// Refuses the page's last message: `stop` with `failed`, if it can
    /// still be sent.
    async fn refuse(&mut self, reason: &'static str) -> End {
        self.tell(StopReason::Failed).await;
        End::Failed {
            reason,
            tell: None,
            frame: Some(2),
        }
    }

    /// Seals and sends the next message.  An upload cut off by a cancel is
    /// kept, so the stop that follows can go after it.
    async fn send(&mut self, message: &Message, deadline: bool) -> Result<u8, End> {
        let bytes = zeroize::Zeroizing::new(
            messages::encode(message).map_err(|_| End::failed("protocol"))?,
        );
        let exchange = self.exchange.as_mut().ok_or(End::quiet("protocol"))?;
        if exchange.sent() >= MESSAGES_PER_SIDE {
            return Err(End::failed("protocol"));
        }
        let (index, packet) = exchange
            .seal(&bytes, now())
            .map_err(|_| End::quiet("expired"))?;
        self.unsent = Some((index, packet));
        self.flush_unsent(deadline).await?;
        Ok(index)
    }

    async fn flush_unsent(&mut self, deadline: bool) -> Result<(), End> {
        let Some((index, packet)) = self.unsent.as_ref() else {
            return Ok(());
        };
        let kind = format!("packet-{index}");
        let sent = tokio::select! {
            biased;
            _ = cancelled(&mut self.cancel) => return Err(End::Cancelled),
            _ = sleep_until(self.deadline), if deadline => return Err(End::quiet("expired")),
            sent = self.transport.send(&kind, packet.as_bytes()) => sent,
        };
        match sent {
            Ok(()) => {
                self.unsent = None;
                Ok(())
            }
            Err(_) => Err(End::quiet("relay_unreachable")),
        }
    }

    /// Reads the page's next message.  One that is not allowed is answered
    /// with `stop` and ends the session.
    async fn read(&mut self, max: Option<u64>, deadline: bool) -> Result<Message, End> {
        let index = self
            .exchange
            .as_ref()
            .ok_or(End::quiet("protocol"))?
            .received();
        let kind = format!("packet-{index}");
        let bytes = tokio::select! {
            biased;
            _ = cancelled(&mut self.cancel) => return Err(End::Cancelled),
            _ = sleep_until(self.deadline), if deadline => return Err(End::quiet("expired")),
            bytes = wait_packet(&self.transport, &kind, self.timing.poll) => bytes,
        };
        let bytes = bytes.map_err(|_| End::quiet("relay_unreachable"))?;
        self.open(index, bytes, max).await
    }

    async fn open(
        &mut self,
        index: usize,
        bytes: Vec<u8>,
        max: Option<u64>,
    ) -> Result<Message, End> {
        let expired = now() >= self.expires_at;
        let opened = String::from_utf8(bytes)
            .ok()
            .zip(self.exchange.as_mut())
            .and_then(|(packet, exchange)| exchange.open(&packet, now()).ok());
        let Some(clear) = opened else {
            return Err(if expired {
                End::quiet("expired")
            } else {
                // The relay changed the packet, or the page framed it for
                // another profile.
                End::failed("protocol")
            });
        };
        let context = Context {
            from: Side::Page,
            index,
            ice_allowlist: &[],
            max,
        };
        match messages::decode(&clear, &context) {
            Ok(message) => {
                if matches!(message, Message::Stop { .. }) {
                    self.stopped = true;
                }
                Ok(message)
            }
            Err(refusal) => {
                self.tell(refusal.stop).await;
                let reason = if refusal.detail == messages::TOO_BIG {
                    "too_big"
                } else if refusal.stop == StopReason::Unsupported {
                    "unsupported"
                } else {
                    "protocol"
                };
                Err(End::Failed {
                    reason,
                    tell: None,
                    frame: Some(2),
                })
            }
        }
    }

    /// Best effort and at most once: `stop` in place of Drop's next message,
    /// after any message a cancel cut off.  Never after a `stop` either way,
    /// after the deadline or past index 7.
    async fn tell(&mut self, reason: StopReason) {
        if self.stopped || now() >= self.expires_at {
            return;
        }
        let Some(exchange) = self.exchange.as_mut() else {
            return;
        };
        // A message a cancel cut off already holds its index.
        if exchange.sent() >= MESSAGES_PER_SIDE {
            return;
        }
        self.stopped = true;
        let Ok(bytes) = messages::encode(&Message::Stop { reason }) else {
            return;
        };
        let limit = Instant::now() + Duration::from_secs(5);
        if let Some((index, packet)) = self.unsent.take() {
            let sent = timeout_at(
                limit,
                self.transport
                    .send(&format!("packet-{index}"), packet.as_bytes()),
            )
            .await;
            if !matches!(sent, Ok(Ok(()))) {
                return;
            }
        }
        let Ok((index, packet)) = exchange.seal(&bytes, now()) else {
            return;
        };
        let sent = timeout_at(
            limit,
            self.transport
                .send(&format!("packet-{index}"), packet.as_bytes()),
        )
        .await;
        self.told = matches!(sent, Ok(Ok(())));
    }

    /// Waits for the hidden window's page to load.
    async fn await_ready(&mut self) -> Result<(), End> {
        let by = Instant::now() + self.timing.reply;
        loop {
            let report = tokio::select! {
                biased;
                _ = cancelled(&mut self.cancel) => return Err(End::Cancelled),
                _ = sleep_until(self.deadline) => return Err(End::quiet("expired")),
                _ = sleep_until(by) => return Err(End::failed("webview")),
                report = self.reports.recv() => report,
            };
            match report {
                Some(PeerReport::Ready) => return Ok(()),
                Some(other) => {
                    if let Some(end) = self.note(other) {
                        return Err(end);
                    }
                }
                None => return Err(End::failed("webview")),
            }
        }
    }

    /// Waits for the window's reply to request `seq`, noting anything else
    /// it reports meanwhile.
    async fn reply(&mut self, seq: u64, deadline: bool) -> Result<Reply, End> {
        let by = Instant::now() + self.timing.reply;
        loop {
            let report = tokio::select! {
                biased;
                _ = cancelled(&mut self.cancel) => return Err(End::Cancelled),
                _ = sleep_until(self.deadline), if deadline => return Err(End::quiet("expired")),
                _ = sleep_until(by) => return Err(End::failed("webview")),
                report = self.reports.recv() => report,
            };
            match report {
                Some(PeerReport::Done { seq: done, .. }) if done == seq => return Ok(Reply::Done),
                Some(PeerReport::Offer {
                    seq: offer, sdp, ..
                }) if offer == seq => {
                    return Ok(Reply::Offer(sdp));
                }
                Some(PeerReport::Error {
                    seq: failed,
                    reason,
                    ..
                }) if failed == seq => {
                    return Err(End::failed(if reason == "no-relay" {
                        "no_relay"
                    } else {
                        "webview"
                    }));
                }
                Some(other) => {
                    if let Some(end) = self.note(other) {
                        return Err(end);
                    }
                }
                None => return Err(End::failed("webview")),
            }
        }
    }

    /// Records a report that is not the reply being waited for.  Returns
    /// the end it brings, if any.
    fn note(&mut self, report: PeerReport) -> Option<End> {
        match report {
            PeerReport::State { state, .. } => self.on_state(state),
            PeerReport::Channel { .. } => {
                if !self.channel_open {
                    self.channel_open = true;
                    self.flowing_since = Some(Instant::now());
                    self.emit_progress();
                }
                None
            }
            PeerReport::Ended { outcome, .. } => {
                Some(End::transfer(&outcome, self.controls.sink.kept()))
            }
            PeerReport::Ready
            | PeerReport::Done { .. }
            | PeerReport::Offer { .. }
            | PeerReport::Error { .. } => None,
        }
    }

    /// Why a connection that never came up ended: `connect_direct` when no
    /// relay was on offer, because some networks do not allow a direct one.
    fn connect_reason(&self) -> &'static str {
        if self.relay_offered {
            "connect"
        } else {
            "connect_direct"
        }
    }

    fn give_up(&self) -> End {
        End::failed(if self.ever_connected {
            "lost"
        } else {
            self.connect_reason()
        })
    }

    /// Whether a restart may go out now: one at a time, at most five, before
    /// the deadline, while the page can still be read, and only once the
    /// page's message at the last index Drop used has been read.
    fn can_restart(&self) -> bool {
        let Some(exchange) = self.exchange.as_ref() else {
            return false;
        };
        self.pending == Pending::None
            && self.restarts < RESTARTS
            && Instant::now() < self.deadline
            && now() < self.expires_at
            && !self.stopped
            && self.exchange_alive
            && self.unsent.is_none()
            && exchange.sent() == exchange.received()
            && exchange.sent() <= 1 + RESTARTS
    }

    fn start_restart(&mut self) {
        self.restarts += 1;
        let seq = self.request(PeerOp::Restart);
        self.pending = Pending::Offer {
            seq,
            by: Instant::now() + self.timing.reply,
        };
    }

    /// A failed connection with no restart under way is restarted now, or
    /// given up when no restart is possible.
    fn restart_or_give_up(&mut self) -> Option<End> {
        if !self.in_transfer || self.failed_since.is_none() || self.pending != Pending::None {
            return None;
        }
        if self.can_restart() {
            self.start_restart();
            None
        } else {
            Some(self.give_up())
        }
    }

    fn on_state(&mut self, state: PeerState) -> Option<End> {
        match state {
            PeerState::Connected => {
                self.connected = true;
                self.ever_connected = true;
                if self.channel_open {
                    self.flowing_since = Some(Instant::now());
                }
                self.connect_by = None;
                self.failed_since = None;
                self.disconnected_since = None;
                if self.reconnecting {
                    self.reconnecting = false;
                    self.emit_progress();
                }
                None
            }
            PeerState::Disconnected => {
                self.connected = false;
                self.disconnected_since.get_or_insert_with(Instant::now);
                if self.ever_connected && !self.reconnecting {
                    self.reconnecting = true;
                    self.emit_progress();
                }
                None
            }
            PeerState::Failed => {
                self.connected = false;
                self.failed_since.get_or_insert_with(Instant::now);
                self.disconnected_since = None;
                if self.ever_connected && !self.reconnecting {
                    self.reconnecting = true;
                    self.emit_progress();
                }
                self.restart_or_give_up()
            }
            PeerState::New | PeerState::Connecting | PeerState::Closed => None,
        }
    }

    /// When a connected transfer that has stopped receiving bytes is given
    /// up, if the stall timer runs now.
    fn stall_at(&self) -> Option<Instant> {
        if !self.channel_open
            || !self.connected
            || self.reconnecting
            || self.verifying
            || self.kept_at.is_some()
        {
            return None;
        }
        let since = self.flowing_since?;
        let since = self
            .controls
            .sink
            .last_write()
            .map_or(since, |w| w.max(since));
        Some(since + self.timing.stall)
    }

    /// The earliest clock the transfer loop waits on.
    fn next_timer(&self) -> Option<Instant> {
        let pending = match self.pending {
            Pending::Offer { by, .. } | Pending::Apply { by, .. } => Some(by),
            _ => None,
        };
        [
            self.kept_at.as_ref().map(|(at, _)| *at + self.timing.flush),
            self.connect_by,
            self.failed_since.map(|at| at + self.timing.reconnect),
            self.disconnected_since
                .map(|at| at + self.timing.restart_after),
            pending,
            self.stall_at(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    async fn transfer(&mut self) -> Result<End, End> {
        // A failure noted before the loop is acted on now.
        self.in_transfer = true;
        if let Some(end) = self.restart_or_give_up() {
            return Err(end);
        }
        loop {
            let before_deadline = Instant::now() < self.deadline;
            let index = self.exchange.as_ref().map_or(0, |e| e.received());
            let readable = before_deadline
                && !self.stopped
                && self.exchange_alive
                && self.exchange.is_some()
                && index < MESSAGES_PER_SIDE;
            let kind = format!("packet-{index}");
            let timer = self.next_timer();
            let wake = tokio::select! {
                biased;
                _ = cancelled(&mut self.cancel) => Wake::Cancel,
                event = self.sink_events.recv() => Wake::Sink(event),
                report = self.reports.recv() => Wake::Report(report),
                bytes = wait_packet(&self.transport, &kind, self.timing.poll), if readable => {
                    Wake::Packet(index, bytes)
                }
                _ = sleep_until(timer.unwrap_or(self.deadline)), if timer.is_some() => Wake::Timer,
                _ = sleep_until(self.deadline), if before_deadline => Wake::Deadline,
            };
            let end = match wake {
                Wake::Cancel => Some(End::Cancelled),
                Wake::Sink(Some(event)) => self.on_sink(event),
                Wake::Sink(None) | Wake::Report(None) => Some(End::failed("webview")),
                Wake::Report(Some(report)) => self.on_report(report).await,
                Wake::Packet(index, bytes) => self.on_packet(index, bytes).await,
                Wake::Timer => self.on_timer(),
                Wake::Deadline => self.on_deadline(),
            };
            if let Some(end) = end {
                return Ok(end);
            }
        }
    }

    fn on_sink(&mut self, event: SinkEvent) -> Option<End> {
        match event {
            SinkEvent::Progress { acked } => {
                self.acked = acked;
                self.emit_progress();
                None
            }
            SinkEvent::Verifying => {
                self.verifying = true;
                self.emit(&self.file_state("verifying"));
                None
            }
            // KEPT goes out when the end command returns; give it a moment
            // to leave before the window closes.
            SinkEvent::Kept(kept) => {
                self.kept_at = Some((Instant::now(), kept));
                None
            }
            SinkEvent::Failed(error) => Some(End::Failed {
                reason: error.reason(),
                tell: Some(StopReason::Failed),
                frame: Some(error.stop_code()),
            }),
        }
    }

    async fn on_report(&mut self, report: PeerReport) -> Option<End> {
        match report {
            PeerReport::Done { seq, .. } => {
                if matches!(self.pending, Pending::Apply { seq: s, .. } if s == seq) {
                    self.pending = Pending::None;
                }
                None
            }
            PeerReport::Offer { seq, sdp, .. } => {
                if !matches!(self.pending, Pending::Offer { seq: s, .. } if s == seq) {
                    return None;
                }
                if messages::check_sdp(&sdp).is_err() {
                    return Some(End::failed("webview"));
                }
                if !self.can_send_restart() {
                    self.pending = Pending::None;
                    return self.restart_or_give_up();
                }
                match self.send(&Message::Restart { sdp }, true).await {
                    Ok(index) => {
                        self.pending = Pending::Answer {
                            index: usize::from(index),
                        };
                        None
                    }
                    Err(End::Cancelled) => Some(End::Cancelled),
                    Err(_) => {
                        // The relay or the deadline: no more restarts.
                        self.exchange_alive = false;
                        self.pending = Pending::None;
                        self.restart_or_give_up()
                    }
                }
            }
            PeerReport::Error { seq, .. } => {
                let ours = match self.pending {
                    Pending::Offer { seq: s, .. } | Pending::Apply { seq: s, .. } => s == seq,
                    _ => false,
                };
                if ours {
                    self.pending = Pending::None;
                    return self.restart_or_give_up();
                }
                None
            }
            // The channel closed before the frame logic finished.  A page that
            // was closed sends `stop` as it goes; look for it before calling
            // the connection lost.
            PeerReport::Ended { outcome, .. }
                if outcome == "closed" && self.controls.sink.kept().is_none() =>
            {
                Some(self.channel_closed().await)
            }
            other => self.note(other),
        }
    }

    /// The window's data channel closed mid-transfer.  If the page's next
    /// message, read within `stop_grace`, is its `stop`, the page ended it
    /// ("They closed the page"); otherwise the connection was lost.
    async fn channel_closed(&mut self) -> End {
        let lost = End::Failed {
            reason: "lost",
            tell: Some(StopReason::Failed),
            frame: None,
        };
        let index = self.exchange.as_ref().map_or(0, |e| e.received());
        if self.stopped
            || !self.exchange_alive
            || self.exchange.is_none()
            || index >= MESSAGES_PER_SIDE
        {
            return lost;
        }
        let by = (Instant::now() + self.timing.stop_grace).min(self.deadline);
        let kind = format!("packet-{index}");
        let bytes = tokio::select! {
            biased;
            _ = cancelled(&mut self.cancel) => return End::Cancelled,
            _ = sleep_until(by) => return lost,
            bytes = wait_packet(&self.transport, &kind, self.timing.poll) => bytes,
        };
        let Ok(bytes) = bytes else {
            self.exchange_alive = false;
            return lost;
        };
        let before = self.exchange.as_ref().map(ExchangeChannel::received);
        match self.open(index, bytes, None).await {
            Ok(Message::Stop { reason }) => End::peer_stop(reason),
            // Anything else (a restart answer) cannot bring the channel back.
            Ok(_) => lost,
            // Not from the page: the channel closed all the same.
            Err(_) if self.exchange.as_ref().map(ExchangeChannel::received) == before => {
                self.exchange_alive = false;
                lost
            }
            Err(end) => end,
        }
    }

    /// The window's restart offer can still go out.
    fn can_send_restart(&self) -> bool {
        Instant::now() < self.deadline
            && now() < self.expires_at
            && !self.stopped
            && self.exchange_alive
            && self
                .exchange
                .as_ref()
                .is_some_and(|e| e.sent() == e.received() && e.sent() <= 1 + RESTARTS)
    }

    async fn on_packet(&mut self, index: usize, bytes: Result<Vec<u8>, RelayError>) -> Option<End> {
        let Ok(bytes) = bytes else {
            // The relay is gone: the transfer goes on without restarts.
            self.exchange_alive = false;
            if matches!(self.pending, Pending::Answer { .. }) {
                self.pending = Pending::None;
            }
            return self.restart_or_give_up();
        };
        let before = self.exchange.as_ref().map(ExchangeChannel::received);
        match self.open(index, bytes, None).await {
            // A packet that did not authenticate changes nothing in the
            // exchange: the relay (or someone at it) wrote it, not the page.
            // It cannot end a transfer the page is still sending; the
            // exchange is given up instead, so the transfer goes on without
            // restarts, as when the relay is gone.
            Err(_) if self.exchange.as_ref().map(ExchangeChannel::received) == before => {
                self.exchange_alive = false;
                if matches!(self.pending, Pending::Answer { .. }) {
                    self.pending = Pending::None;
                }
                self.restart_or_give_up()
            }
            Err(end) => Some(end),
            Ok(Message::Stop { reason }) => Some(End::peer_stop(reason)),
            Ok(Message::RestartAnswer { sdp }) if self.pending == Pending::Answer { index } => {
                let seq = self.request(PeerOp::Answer { sdp });
                self.pending = Pending::Apply {
                    seq,
                    by: Instant::now() + self.timing.reply,
                };
                None
            }
            // A restart answer nobody asked for, or at the wrong index.
            Ok(_) => Some(self.refuse("protocol").await),
        }
    }

    fn on_timer(&mut self) -> Option<End> {
        let at = Instant::now();
        if let Some((kept_at, kept)) = &self.kept_at
            && at >= *kept_at + self.timing.flush
        {
            return Some(End::Kept(kept.clone()));
        }
        if self.connect_by.is_some_and(|by| at >= by) {
            return Some(End::failed(self.connect_reason()));
        }
        if self.stall_at().is_some_and(|by| at >= by) {
            return Some(End::failed("lost"));
        }
        if self
            .failed_since
            .is_some_and(|since| at >= since + self.timing.reconnect)
        {
            return Some(self.give_up());
        }
        if self
            .disconnected_since
            .is_some_and(|since| at >= since + self.timing.restart_after)
        {
            self.disconnected_since = None;
            if self.can_restart() {
                self.start_restart();
            }
        }
        if let Pending::Offer { by, .. } | Pending::Apply { by, .. } = self.pending
            && at >= by
        {
            self.pending = Pending::None;
            return self.restart_or_give_up();
        }
        None
    }

    /// The session deadline: no restart can start or finish from here on.
    fn on_deadline(&mut self) -> Option<End> {
        if matches!(self.pending, Pending::Offer { .. } | Pending::Answer { .. }) {
            self.pending = Pending::None;
        }
        self.restart_or_give_up()
    }

    /// Every way out: the window closes (sending STOP first when this end
    /// stopped it), the sink's files go unless kept, the page is told, the
    /// final state is emitted and the relay session is deleted.
    async fn finish(&mut self, end: End) -> ReceiveState {
        // One decision, under the sink's lock: a file kept while the session
        // was ending stays kept (waiting for one being placed), and
        // otherwise no file can be placed from here on.
        let end = match end {
            End::Kept(kept) => End::Kept(kept),
            end => {
                let controls = self.controls.clone();
                match tokio::task::spawn_blocking(move || controls.sink.cancel()).await {
                    Ok(Some(kept)) => End::Kept(kept),
                    _ => end,
                }
            }
        };
        let (tell, frame) = match &end {
            End::Cancelled => (Some(StopReason::Cancelled), Some(1)),
            End::Failed { tell, frame, .. } => (*tell, *frame),
            _ => (None, None),
        };
        if self.peer_open {
            let seq = self.request(PeerOp::Close { stop: frame });
            let by = Instant::now() + self.timing.flush;
            loop {
                match timeout_at(by, self.reports.recv()).await {
                    Ok(Some(PeerReport::Done { seq: done, .. })) if done == seq => break,
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
            self.host.close_peer();
            self.peer_open = false;
        }
        if let Some(reason) = tell {
            self.tell(reason).await;
        }
        self.awake = None;
        let state = self.final_state(end);
        self.controls.mark_finished();
        self.emit(&state);
        // The page reads a last `stop` or `decline` before the session goes.
        if self.told {
            tokio::time::sleep(self.timing.linger).await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), self.transport.delete()).await;
        state
    }

    fn final_state(&self, end: End) -> ReceiveState {
        match end {
            End::Kept(kept) => {
                let mut state = self.file_state("kept");
                state.name = Some(kept.name);
                state.id = Some(self.id.clone());
                state.path = Some(kept.path.display().to_string());
                state
            }
            End::Declined => self.file_state("declined"),
            End::Cancelled => {
                let mut state = self.file_state("cancelled");
                state.by = Some("you");
                state
            }
            End::PeerCancelled => {
                let mut state = self.file_state("cancelled");
                state.by = Some("them");
                state
            }
            End::Failed { reason, .. } => {
                let mut state = self.file_state("failed");
                state.reason = Some(reason);
                state
            }
        }
    }
}

#[cfg(test)]
mod tests;
