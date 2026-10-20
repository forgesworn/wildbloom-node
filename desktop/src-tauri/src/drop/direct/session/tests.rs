//! Whole sessions against the Foregather kit's own `PairingGate` and
//! `ExchangeChannel`: an in-memory relay, a fake phone that pairs as the
//! recipient and speaks `wildbloom-direct/1`, and a fake webview that answers
//! the session's requests and feeds the sink real FSWNENC2 envelopes.  Keys,
//! servers and credentials are synthetic.

use super::*;
use crate::drop::direct::messages::IceServer;
use crate::drop::direct::sink::tests::{sealed, sha};
use crate::drop::relay;
use foregather_kit::Namespace;
use foregather_kit::live::{PairingGate, Role};
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use wildbloom_envelope::InputKey;

const TIMING: Timing = Timing {
    poll: Duration::from_millis(10),
    reply: Duration::from_secs(2),
    connect: Duration::from_secs(3),
    reconnect: Duration::from_secs(2),
    restart_after: Duration::from_millis(200),
    flush: Duration::from_millis(50),
    linger: Duration::from_millis(20),
    stop_grace: Duration::from_millis(500),
};

const DROP_SDP: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:dr0p\r\na=fingerprint:sha-256 10:11:12:13\r\na=setup:actpass\r\n";
const PAGE_SDP: &str = "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:pAg3\r\na=fingerprint:sha-256 40:41:42:43\r\na=setup:active\r\n";

fn restart_sdp(n: usize) -> String {
    DROP_SDP.replace("dr0p", &format!("dr{n}p"))
}

// ------------------------------------------------------- the in-memory relay

#[derive(Default)]
struct Relay {
    slots: Mutex<HashMap<String, Vec<u8>>>,
    deleted: AtomicBool,
}

#[derive(Clone)]
struct Inviter(Arc<Relay>);

impl LiveTransport for Inviter {
    async fn send(&self, kind: &str, value: &[u8]) -> Result<(), RelayError> {
        if self.0.deleted.load(Ordering::SeqCst) {
            return Err(RelayError::Http(404));
        }
        let mut slots = self.0.slots.lock().unwrap();
        let key = format!("inviter/{kind}");
        match slots.get(&key) {
            Some(old) if old != value => Err(RelayError::Http(409)),
            Some(_) => Ok(()),
            None => {
                slots.insert(key, value.to_vec());
                Ok(())
            }
        }
    }

    async fn poll(&self, kind: &str) -> Result<Option<Vec<u8>>, RelayError> {
        if self.0.deleted.load(Ordering::SeqCst) {
            return Err(RelayError::Http(404));
        }
        Ok(self
            .0
            .slots
            .lock()
            .unwrap()
            .get(&format!("recipient/{kind}"))
            .cloned())
    }

    async fn delete(&self) -> Result<(), RelayError> {
        self.0.deleted.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// ------------------------------------------------------------- the phone

struct Phone {
    relay: Arc<Relay>,
    session: Session,
    words: String,
    exchange: Option<ExchangeChannel>,
    allowlist: Vec<String>,
}

impl Phone {
    fn put(&self, kind: &str, bytes: &[u8]) {
        self.relay
            .slots
            .lock()
            .unwrap()
            .insert(format!("recipient/{kind}"), bytes.to_vec());
    }

    fn peek(&self, kind: &str) -> Option<Vec<u8>> {
        self.relay
            .slots
            .lock()
            .unwrap()
            .get(&format!("inviter/{kind}"))
            .cloned()
    }

    async fn get(&self, kind: &str) -> Vec<u8> {
        let by = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(bytes) = self.peek(kind) {
                return bytes;
            }
            assert!(Instant::now() < by, "Drop never wrote {kind}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The recipient's side of the PAKE.  Returns the check words.
    async fn pair_with(&mut self, words: &str) -> Option<String> {
        let secret = PairingSecret::parse(words).unwrap();
        let mut gate = PairingGate::new(self.session.clone(), secret, 1, now()).unwrap();
        let exchange = gate.start(Role::Recipient, now(), &mut OsRng).unwrap();
        self.put("hello", &relay::public_message(&exchange.hello()));
        let theirs = relay::parse_public_message(&self.get("hello").await).unwrap();
        let pending = exchange.finish(&theirs, now()).ok()?;
        self.put(
            "proof",
            &relay::public_message(&pending.confirmation().unwrap()),
        );
        let proof = relay::parse_public_message(&self.get("proof").await).unwrap();
        let channel = pending.confirm(&proof, now()).ok()?;
        let check = channel.verification_words(3, now()).unwrap();
        self.exchange = Some(ExchangeChannel::new(channel).unwrap());
        Some(check)
    }

    /// Pairs with the wrong words: the hello and, if it can, the proof.
    /// Never waits for Drop's proof, which wrong words may stop it sending.
    async fn pair_wrong(&mut self, words: &str) {
        let secret = PairingSecret::parse(words).unwrap();
        let mut gate = PairingGate::new(self.session.clone(), secret, 1, now()).unwrap();
        let exchange = gate.start(Role::Recipient, now(), &mut OsRng).unwrap();
        self.put("hello", &relay::public_message(&exchange.hello()));
        let theirs = relay::parse_public_message(&self.get("hello").await).unwrap();
        if let Ok(pending) = exchange.finish(&theirs, now())
            && let Ok(proof) = pending.confirmation()
        {
            self.put("proof", &relay::public_message(&proof));
        }
    }

    async fn pair(&mut self) -> String {
        let words = self.words.clone();
        self.pair_with(&words).await.expect("the words match")
    }

    fn index(&self) -> usize {
        self.exchange.as_ref().unwrap().received()
    }

    /// Drop's next message.
    async fn read(&mut self) -> Message {
        let index = self.index();
        let packet = self.get(&format!("packet-{index}")).await;
        let clear = self
            .exchange
            .as_mut()
            .unwrap()
            .open(std::str::from_utf8(&packet).unwrap(), now())
            .unwrap();
        let allow: Vec<&str> = self.allowlist.iter().map(String::as_str).collect();
        messages::decode(
            &clear,
            &Context {
                from: Side::Drop,
                index,
                ice_allowlist: &allow,
                max: None,
            },
        )
        .unwrap_or_else(|r| panic!("Drop sent a refused message at {index}: {r:?}"))
    }

    /// Whether Drop wrote its message at `index` within a moment.
    async fn wrote(&self, index: usize) -> bool {
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.peek(&format!("packet-{index}")).is_some()
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        let (index, packet) = self.exchange.as_mut().unwrap().seal(bytes, now()).unwrap();
        self.put(&format!("packet-{index}"), packet.as_bytes());
    }

    fn send(&mut self, message: &Message) {
        let bytes = messages::encode(message).unwrap();
        self.send_bytes(&bytes);
    }
}

// --------------------------------------------------------- the host

struct FakeHost {
    states: Mutex<Vec<ReceiveState>>,
    requests: mpsc::UnboundedSender<PeerRequest>,
    log: Mutex<Vec<PeerRequest>>,
    opened: AtomicUsize,
    closed: AtomicUsize,
    awake: AtomicUsize,
    can_open: bool,
}

impl DirectHost for FakeHost {
    fn emit(&self, state: &ReceiveState) {
        self.states.lock().unwrap().push(state.clone());
    }
    fn open_peer(&self) -> bool {
        if self.can_open {
            self.opened.fetch_add(1, Ordering::SeqCst);
        }
        self.can_open
    }
    fn peer(&self, request: &PeerRequest) {
        self.log.lock().unwrap().push(request.clone());
        let _ = self.requests.send(request.clone());
    }
    fn close_peer(&self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
    fn keep_awake(&self) -> Awake {
        self.awake.fetch_add(1, Ordering::SeqCst);
        Awake::none()
    }
}

// ------------------------------------------------------------ the webview

struct Web {
    controls: Arc<Controls>,
    requests: mpsc::UnboundedReceiver<PeerRequest>,
}

impl Web {
    async fn next(&mut self) -> PeerRequest {
        tokio::time::timeout(Duration::from_secs(10), self.requests.recv())
            .await
            .expect("a request in time")
            .expect("the session is running")
    }

    /// No request arrives within a moment.
    async fn quiet(&mut self) -> bool {
        tokio::time::timeout(Duration::from_millis(400), self.requests.recv())
            .await
            .is_err()
    }

    fn transfer(&self) -> String {
        self.controls.transfer().unwrap()
    }

    fn report(&self, report: PeerReport) {
        self.controls.report(report);
    }

    fn ready(&self) {
        self.report(PeerReport::Ready);
    }

    fn done(&self, request: &PeerRequest) {
        self.report(PeerReport::Done {
            transfer: self.transfer(),
            seq: request.seq,
        });
    }

    fn offer(&self, request: &PeerRequest, sdp: &str) {
        self.report(PeerReport::Offer {
            transfer: self.transfer(),
            seq: request.seq,
            sdp: sdp.into(),
        });
    }

    fn state(&self, state: PeerState) {
        self.report(PeerReport::State {
            transfer: self.transfer(),
            state,
        });
    }

    fn channel(&self) {
        self.report(PeerReport::Channel {
            transfer: self.transfer(),
        });
    }

    fn ended(&self, outcome: &str) {
        self.report(PeerReport::Ended {
            transfer: self.transfer(),
            outcome: outcome.into(),
        });
    }

    fn write(&self, envelope: &[u8], upto: usize) -> Result<(), SinkError> {
        let transfer = self.transfer();
        for (i, part) in envelope[..upto].chunks(65_527).enumerate() {
            self.controls
                .sink
                .write(&transfer, (i * 65_527) as u64, part)?;
        }
        Ok(())
    }

    fn end(&self, plain: &[u8]) -> Result<Kept, SinkError> {
        self.controls
            .sink
            .end(&self.transfer(), sha(plain), plain.len() as u64)
    }
}

// --------------------------------------------------------- the harness

fn credential(label: &str) -> IceServer {
    IceServer {
        credential: format!("{}=", "A".repeat(27)),
        urls: vec![
            "turn:turn.example.net:3478?transport=udp".into(),
            "turns:turn.example.net:5349?transport=tcp".into(),
        ],
        username: format!("1800003600:{label}"),
    }
}

fn turn() -> TurnCredentials {
    TurnCredentials {
        expires: 1_800_003_600,
        own: credential("b3duLWxhYmVs"),
        peer: credential("cGVlci1sYWJlbA"),
    }
}

struct Harness {
    relay: Arc<Relay>,
    host: Arc<FakeHost>,
    controls: Arc<Controls>,
    web: Web,
    phone: Phone,
    task: tokio::task::JoinHandle<ReceiveState>,
    temp: PathBuf,
    received: PathBuf,
    _dir: tempfile::TempDir,
}

fn start(lifetime: u64) -> Harness {
    start_with(lifetime, true)
}

fn start_with(lifetime: u64, can_open: bool) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let temp = dir.path().join("drop-temp");
    let received = dir.path().join("Downloads").join("Wildbloom Received");
    let relay = Arc::new(Relay::default());
    let session = Session::generate(
        Namespace::parse("wildbloom.drop").unwrap(),
        Namespace::parse(super::super::PURPOSE).unwrap(),
        lifetime,
        now(),
        &mut OsRng,
    )
    .unwrap();
    let secret = PairingSecret::generate(4, &mut OsRng).unwrap();
    let words = secret.expose_words().to_owned();
    let (requests, requests_rx) = mpsc::unbounded_channel();
    let host = Arc::new(FakeHost {
        states: Mutex::new(Vec::new()),
        requests,
        log: Mutex::new(Vec::new()),
        opened: AtomicUsize::new(0),
        closed: AtomicUsize::new(0),
        awake: AtomicUsize::new(0),
        can_open,
    });
    let (controls, inputs) = controls();
    let opened = Opened {
        transport: Inviter(relay.clone()),
        session: session.clone(),
        secret,
        link: "https://wildbloom.example.invalid/send/#synthetic".into(),
        words: words.split(' ').map(str::to_owned).collect(),
        expires_at: session.expires,
        turn: turn(),
        hide: true,
    };
    let dirs = Dirs {
        temp: temp.clone(),
        received: received.clone(),
    };
    let task = tokio::spawn(run(
        opened,
        host.clone(),
        controls.clone(),
        inputs,
        dirs,
        TIMING,
    ));
    let allowlist = turn().peer.urls.clone();
    Harness {
        relay: relay.clone(),
        host,
        controls: controls.clone(),
        web: Web {
            controls,
            requests: requests_rx,
        },
        phone: Phone {
            relay,
            session,
            words,
            exchange: None,
            allowlist,
        },
        task,
        temp,
        received,
        _dir: dir,
    }
}

/// A file the phone will send, sealed under a fresh key.
struct File {
    key: InputKey,
    plain: Vec<u8>,
    manifest: Manifest,
    envelope: Vec<u8>,
}

fn file(name: &str, size: usize) -> File {
    let key = InputKey::random().unwrap();
    let plain: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
    let (manifest, envelope) = sealed(&key, name, &plain);
    File {
        key,
        plain,
        manifest,
        envelope,
    }
}

impl Harness {
    fn names(&self) -> Vec<&'static str> {
        self.host
            .states
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.state)
            .collect()
    }

    async fn until(&self, name: &str) -> ReceiveState {
        let by = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(state) = self
                .host
                .states
                .lock()
                .unwrap()
                .iter()
                .find(|s| s.state == name)
            {
                return state.clone();
            }
            assert!(Instant::now() < by, "no {name} state: {:?}", self.names());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The phone pairs, the owner confirms the words, the phone reads the
    /// invitation.
    async fn paired(&mut self) -> Message {
        let words = self.phone.pair().await;
        let check = self.until("check").await;
        assert_eq!(check.check_words.as_ref().unwrap().join(" "), words);
        assert!(self.controls.verify(true));
        self.phone.read().await
    }

    /// Up to the owner being asked about `file`.
    async fn offered(&mut self, file: &File) {
        self.paired().await;
        self.until("waiting_file").await;
        self.phone.send(&Message::Manifest(file.manifest.clone()));
        let consent = self.until("consent").await;
        assert_eq!(consent.name.as_deref(), Some(file.manifest.name.as_str()));
        assert_eq!(consent.size, Some(file.manifest.size));
    }

    /// The owner accepts; the window loads and makes the connection.
    async fn accepted(&mut self, file: &File) {
        self.offered(file).await;
        assert!(self.controls.consent(true));
        self.web.ready();
        let create = self.web.next().await;
        assert_eq!(
            create.op,
            PeerOp::Create {
                ice_servers: vec![turn().own],
                relay_only: true,
                envelope_bytes: file.envelope.len() as u64,
                size: file.manifest.size,
            }
        );
        self.web.done(&create);
        let offer = self.web.next().await;
        assert_eq!(offer.op, PeerOp::Offer);
        self.web.offer(&offer, DROP_SDP);
        assert_eq!(
            self.phone.read().await,
            Message::Accept {
                sdp: DROP_SDP.into()
            }
        );
    }

    /// The page answers, the window applies it and the channel opens.
    async fn connected(&mut self, file: &File) {
        self.accepted(file).await;
        self.phone.send(&Message::Answer {
            key: file.key.clone(),
            sdp: PAGE_SDP.into(),
        });
        let answer = self.web.next().await;
        assert_eq!(
            answer.op,
            PeerOp::Answer {
                sdp: PAGE_SDP.into()
            }
        );
        self.web.done(&answer);
        self.web.state(PeerState::Connecting);
        self.web.state(PeerState::Connected);
        self.web.channel();
        self.until("receiving").await;
    }

    /// The final state, after checking what every way out must leave.
    async fn end(&mut self) -> ReceiveState {
        let state = tokio::time::timeout(Duration::from_secs(15), &mut self.task)
            .await
            .expect("the session ends")
            .unwrap();
        assert!(
            self.relay.deleted.load(Ordering::SeqCst),
            "relay session deleted"
        );
        assert_eq!(
            self.host.opened.load(Ordering::SeqCst),
            self.host.closed.load(Ordering::SeqCst),
            "every window opened was closed"
        );
        if state.state != "kept" {
            assert!(temp_is_empty(&self.temp), "temp files left");
            assert!(!self.controls.sink.holds());
            assert!(
                !self.received.exists() || std::fs::read_dir(&self.received).unwrap().count() == 0,
                "nothing received"
            );
        }
        assert_eq!(self.host.states.lock().unwrap().last(), Some(&state));
        state
    }

    /// The close request the window gets at the end, answered.
    async fn closed(&mut self) -> Option<u8> {
        let close = self.web.next().await;
        let PeerOp::Close { stop } = close.op else {
            panic!("expected close, got {close:?}");
        };
        self.web.done(&close);
        stop
    }
}

fn temp_is_empty(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).map_or(true, |entries| {
        entries
            .flatten()
            .all(|e| e.file_name() == ".wildbloom-temp.lock")
    })
}

fn stop(reason: StopReason) -> Message {
    Message::Stop { reason }
}

// ----------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_arrives_is_verified_and_kept() {
    let mut h = start(600);
    let f = file("Café holiday.mp4", 2_300_000);
    let words = h.until("waiting").await;
    assert_eq!(words.words.as_ref().unwrap().len(), 4);
    assert!(words.link.as_deref().unwrap().starts_with("https://"));
    let invite = {
        let words = h.phone.pair().await;
        h.until("opened").await;
        let check = h.until("check").await;
        assert_eq!(check.check_words.as_ref().unwrap().join(" "), words);
        h.controls.verify(true);
        h.phone.read().await
    };
    // The page's own credential, and only that, travels in the invitation.
    let Message::Invite { hide, ice, id, max } = invite else {
        panic!("not an invitation");
    };
    assert!(hide);
    assert_eq!(ice, vec![turn().peer]);
    assert_eq!(max, 250_000_000);
    assert!(messages::canonical_id(&id));
    assert_eq!(h.controls.transfer().as_deref(), Some(id.as_str()));
    h.until("waiting_file").await;
    h.phone.send(&Message::Manifest(f.manifest.clone()));
    h.until("consent").await;
    h.controls.consent(true);
    h.web.ready();
    let create = h.web.next().await;
    h.web.done(&create);
    let offer = h.web.next().await;
    h.web.offer(&offer, DROP_SDP);
    assert!(matches!(h.phone.read().await, Message::Accept { .. }));
    h.phone.send(&Message::Answer {
        key: f.key.clone(),
        sdp: PAGE_SDP.into(),
    });
    let answer = h.web.next().await;
    h.web.done(&answer);
    h.web.state(PeerState::Connected);
    h.web.channel();
    let half = f.envelope.len() / 2;
    h.web.write(&f.envelope, half).unwrap();
    // Progress shows acknowledged bytes, never more than were written.
    let progress = h.until("receiving").await;
    assert_eq!(progress.total, Some(f.envelope.len() as u64));
    let rest = &f.envelope[..];
    let transfer = h.web.transfer();
    let mut offset = half;
    for part in rest[half..].chunks(65_527) {
        h.controls
            .sink
            .write(&transfer, offset as u64, part)
            .unwrap();
        offset += part.len();
    }
    let kept = h.web.end(&f.plain).unwrap();
    h.web.ended("kept");
    assert_eq!(h.closed().await, None);
    let state = h.end().await;
    assert_eq!(state.state, "kept");
    assert_eq!(state.name.as_deref(), Some("Café holiday.mp4"));
    assert_eq!(state.id.as_deref(), Some(id.as_str()));
    assert_eq!(std::fs::read(&kept.path).unwrap(), f.plain);
    assert_eq!(kept.path, h.received.join("Café holiday.mp4"));
    assert!(temp_is_empty(&h.temp));
    // The states the sheet saw, in order.
    let names = h.names();
    let order = [
        "waiting",
        "opened",
        "check",
        "waiting_file",
        "consent",
        "connecting",
        "receiving",
        "verifying",
        "kept",
    ];
    let mut at = 0;
    for name in names {
        if at < order.len() && name == order[at] {
            at += 1;
        }
    }
    assert_eq!(at, order.len(), "{:?}", h.names());
    let acked: Vec<u64> = h
        .host
        .states
        .lock()
        .unwrap()
        .iter()
        .filter_map(|s| s.acknowledged)
        .collect();
    assert!(acked.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(acked.last(), Some(&(f.envelope.len() as u64)));
    // The key never reached the window; Drop's own credential did.
    let key = f.key.to_wbk1();
    for request in h.host.log.lock().unwrap().iter() {
        let text = serde_json::to_string(request).unwrap();
        assert!(!text.contains(key.as_str()), "key in {request:?}");
        assert!(
            !text.contains("cGVlci1sYWJlbA"),
            "the page's credential in {request:?}"
        );
    }
    assert_eq!(h.host.awake.load(Ordering::SeqCst), 1);
    // Nothing more went on the exchange after the answer.
    assert!(!h.phone.wrote(2).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_file_opens_no_connection() {
    let mut h = start(600);
    let f = file("a.txt", 10);
    h.offered(&f).await;
    assert!(h.controls.consent(false));
    assert_eq!(h.phone.read().await, Message::Decline);
    let state = h.end().await;
    assert_eq!(state.state, "declined");
    assert_eq!(state.name.as_deref(), Some("a.txt"));
    assert_eq!(h.host.opened.load(Ordering::SeqCst), 0);
    assert!(h.host.log.lock().unwrap().is_empty());
    assert_eq!(h.host.awake.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_words_end_the_session() {
    let mut h = start(600);
    let other = PairingSecret::generate(4, &mut OsRng).unwrap();
    h.phone.pair_wrong(other.expose_words()).await;
    let state = h.end().await;
    assert_eq!(state.state, "failed");
    assert_eq!(state.reason, Some("wrong_words"));
    assert!(!h.names().contains(&"check"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_words_that_do_not_match_end_the_session() {
    let mut h = start(600);
    h.phone.pair().await;
    h.until("check").await;
    assert!(h.controls.verify(false));
    let state = h.end().await;
    assert_eq!(state.reason, Some("mismatch"));
    // No invitation went out.
    assert!(h.phone.peek("packet-0").is_none());
}

/// Each stage a person can cancel at, with what the page must then see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_at_each_stage() {
    // Waiting for the page to open the link.
    let mut h = start(600);
    h.until("waiting").await;
    h.controls.cancel();
    let state = h.end().await;
    assert_eq!((state.state, state.by), ("cancelled", Some("you")));

    // At the check words.
    let mut h = start(600);
    h.phone.pair().await;
    h.until("check").await;
    h.controls.cancel();
    assert_eq!(h.end().await.by, Some("you"));
    assert!(h.phone.peek("packet-0").is_none());

    // Waiting for their file: the page reads stop in place of message 1.
    let mut h = start(600);
    h.paired().await;
    h.until("waiting_file").await;
    h.controls.cancel();
    assert_eq!(h.phone.read().await, stop(StopReason::Cancelled));
    assert_eq!(h.end().await.state, "cancelled");

    // At the consent question.
    let mut h = start(600);
    let f = file("a.txt", 10);
    h.offered(&f).await;
    h.controls.cancel();
    assert_eq!(h.phone.read().await, stop(StopReason::Cancelled));
    let state = h.end().await;
    assert_eq!(state.name.as_deref(), Some("a.txt"));
    assert_eq!(h.host.opened.load(Ordering::SeqCst), 0);

    // While the window makes the connection: STOP 1 to the window.
    let mut h = start(600);
    h.offered(&f).await;
    h.controls.consent(true);
    h.web.ready();
    let create = h.web.next().await;
    assert!(matches!(create.op, PeerOp::Create { .. }));
    h.controls.cancel();
    assert_eq!(h.closed().await, Some(1));
    assert_eq!(h.phone.read().await, stop(StopReason::Cancelled));
    assert_eq!(h.end().await.by, Some("you"));

    // Waiting for the page's answer.
    let mut h = start(600);
    h.accepted(&f).await;
    h.controls.cancel();
    assert_eq!(h.closed().await, Some(1));
    assert_eq!(h.phone.read().await, stop(StopReason::Cancelled));
    assert_eq!(h.end().await.state, "cancelled");

    // Mid-transfer: the partial envelope goes.
    let mut h = start(600);
    let f = file("b.bin", 3_000_000);
    h.connected(&f).await;
    h.web.write(&f.envelope, 1_500_000).unwrap();
    assert!(h.controls.sink.holds());
    h.controls.cancel();
    assert_eq!(h.closed().await, Some(1));
    assert_eq!(h.phone.read().await, stop(StopReason::Cancelled));
    let state = h.end().await;
    assert_eq!((state.state, state.by), ("cancelled", Some("you")));
    // A write after the end is refused.
    assert!(h.web.write(&f.envelope, 1000).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_page_stopping_ends_it_as_theirs() {
    let mut h = start(600);
    let f = file("a.bin", 200_000);
    h.connected(&f).await;
    h.web.write(&f.envelope, 100_000).unwrap();
    h.phone.send(&stop(StopReason::Cancelled));
    assert_eq!(h.closed().await, None);
    let state = h.end().await;
    assert_eq!((state.state, state.by), ("cancelled", Some("them")));
    // Drop sends nothing after the page's stop.
    assert!(!h.phone.wrote(2).await);

    // A stop in place of the manifest.
    let mut h = start(600);
    h.paired().await;
    h.phone.send(&stop(StopReason::Unsupported));
    let state = h.end().await;
    assert_eq!(state.reason, Some("unsupported"));
    assert!(!h.phone.wrote(1).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_page_is_theirs_whichever_arrives_first() {
    // The page's stop arrives, then its channel closes.
    let mut h = start(600);
    let f = file("a.bin", 200_000);
    h.connected(&f).await;
    h.web.write(&f.envelope, 100_000).unwrap();
    h.phone.send(&stop(StopReason::Cancelled));
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.web.ended("closed");
    assert_eq!(h.closed().await, None);
    let state = h.end().await;
    assert_eq!((state.state, state.by), ("cancelled", Some("them")));
    assert!(!h.phone.wrote(2).await, "nothing answers the page's stop");

    // The channel closes first; the page's stop follows within the grace.
    let mut h = start(600);
    let f = file("a.bin", 200_000);
    h.connected(&f).await;
    h.web.write(&f.envelope, 100_000).unwrap();
    h.web.ended("closed");
    tokio::time::sleep(TIMING.stop_grace / 5).await;
    assert!(
        !h.task.is_finished(),
        "a closed channel waits for the page's stop"
    );
    h.phone.send(&stop(StopReason::Cancelled));
    assert_eq!(h.closed().await, None);
    let state = h.end().await;
    assert_eq!((state.state, state.by), ("cancelled", Some("them")));
    assert!(!h.phone.wrote(2).await, "nothing answers the page's stop");

    // The channel closes and the page says nothing: the connection was lost,
    // and the page is told.
    let mut h = start(600);
    let f = file("a.bin", 200_000);
    h.connected(&f).await;
    h.web.write(&f.envelope, 100_000).unwrap();
    let closed_at = Instant::now();
    h.web.ended("closed");
    assert_eq!(h.closed().await, None);
    assert!(closed_at.elapsed() >= TIMING.stop_grace);
    let state = h.end().await;
    assert_eq!((state.state, state.reason), ("failed", Some("lost")));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_event_at_an_index_is_a_protocol_failure() {
    // An answer in the manifest's place.
    let mut h = start(600);
    let f = file("a.txt", 10);
    h.paired().await;
    h.phone.send(&Message::Answer {
        key: f.key.clone(),
        sdp: PAGE_SDP.into(),
    });
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.end().await.reason, Some("protocol"));

    // A restart answer nobody asked for.
    let mut h = start(600);
    h.connected(&f).await;
    h.phone.send(&Message::RestartAnswer {
        sdp: PAGE_SDP.into(),
    });
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.end().await.reason, Some("protocol"));

    // Text that is not canonical JSON, and a newer version.
    let mut h = start(600);
    h.paired().await;
    h.phone
        .send_bytes(br#"{"event": "manifest","name":"a.txt","size":1,"type":"text/plain","v":1}"#);
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.end().await.reason, Some("protocol"));
    let mut h = start(600);
    h.paired().await;
    h.phone
        .send_bytes(br#"{"event":"manifest","name":"a.txt","size":1,"type":"text/plain","v":2}"#);
    assert_eq!(h.phone.read().await, stop(StopReason::Unsupported));
    assert_eq!(h.end().await.reason, Some("unsupported"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_manifests_are_refused() {
    let names = [
        format!(
            r#"{{"event":"manifest","name":"{}","size":1,"type":"text/plain","v":1}}"#,
            "a".repeat(181)
        ),
        format!(
            r#"{{"event":"manifest","name":"a.txt","size":1,"type":"{}","v":1}}"#,
            "t".repeat(256)
        ),
    ];
    for text in names {
        let mut h = start(600);
        h.paired().await;
        h.phone.send_bytes(text.as_bytes());
        assert_eq!(h.phone.read().await, stop(StopReason::Failed));
        assert_eq!(h.end().await.reason, Some("protocol"));
        assert!(!h.names().contains(&"consent"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_above_max_is_unsupported() {
    let mut h = start(600);
    h.paired().await;
    h.phone.send(&Message::Manifest(Manifest {
        name: "big.bin".into(),
        size: 250_000_001,
        media_type: "application/octet-stream".into(),
    }));
    assert_eq!(h.phone.read().await, stop(StopReason::Unsupported));
    let state = h.end().await;
    assert_eq!(state.reason, Some("too_big"));
    assert!(!h.names().contains(&"consent"));
}

/// One ICE restart: the window's failure, its restart offer, the page's
/// answer at the same index, applied, and back to connected.
async fn restart(h: &mut Harness, n: usize) {
    h.web.state(PeerState::Failed);
    let request = h.web.next().await;
    assert_eq!(request.op, PeerOp::Restart, "restart {n}");
    h.web.offer(&request, &restart_sdp(n));
    let index = h.phone.index();
    assert_eq!(
        h.phone.read().await,
        Message::Restart {
            sdp: restart_sdp(n)
        }
    );
    assert_eq!(index, n + 1, "restart {n} goes at index {}", n + 1);
    h.phone.send(&Message::RestartAnswer {
        sdp: PAGE_SDP.into(),
    });
    let apply = h.web.next().await;
    assert_eq!(
        apply.op,
        PeerOp::Answer {
            sdp: PAGE_SDP.into()
        }
    );
    h.web.done(&apply);
    h.web.state(PeerState::Connected);
    // The sheet said it was reconnecting, and then that it is not.
    let by = Instant::now() + Duration::from_secs(5);
    loop {
        let last = h
            .host
            .states
            .lock()
            .unwrap()
            .last()
            .and_then(|s| s.reconnecting);
        if last == Some(false) {
            break;
        }
        assert!(Instant::now() < by, "restart {n} never settled");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn five_restarts_and_no_sixth() {
    let mut h = start(600);
    let f = file("a.bin", 300_000);
    h.connected(&f).await;
    for n in 1..=5 {
        restart(&mut h, n).await;
    }
    let reconnecting: Vec<bool> = h
        .host
        .states
        .lock()
        .unwrap()
        .iter()
        .filter_map(|s| s.reconnecting)
        .collect();
    assert_eq!(reconnecting.iter().filter(|r| **r).count(), 5);
    // The data still arrives on the same connection after five restarts.
    h.web.write(&f.envelope, f.envelope.len()).unwrap();
    // A sixth failure is not restarted: the transfer has failed.
    h.web.state(PeerState::Failed);
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.phone.index(), 8);
    let state = h.end().await;
    assert_eq!(state.reason, Some("lost"));
    let restarts = h
        .host
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.op == PeerOp::Restart)
        .count();
    assert_eq!(restarts, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_five_restarts_only_a_stop_may_follow() {
    let mut h = start(600);
    let f = file("a.bin", 1000);
    h.connected(&f).await;
    for n in 1..=5 {
        restart(&mut h, n).await;
    }
    // The page's message at index 7 can only be a stop.
    h.phone.send(&Message::RestartAnswer {
        sdp: PAGE_SDP.into(),
    });
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.end().await.reason, Some("protocol"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_disconnection_restarts_and_a_short_one_does_not() {
    let mut h = start(600);
    let f = file("a.bin", 1000);
    h.connected(&f).await;
    // A blip shorter than the restart wait recovers by itself.
    h.web.state(PeerState::Disconnected);
    tokio::time::sleep(TIMING.restart_after / 4).await;
    h.web.state(PeerState::Connected);
    assert!(h.web.quiet().await);
    // A longer one is restarted.
    h.web.state(PeerState::Disconnected);
    let request = h.web.next().await;
    assert_eq!(request.op, PeerOp::Restart);
    h.controls.cancel();
    assert_eq!(h.closed().await, Some(1));
    h.end().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_deadline_ends_every_wait_before_the_transfer() {
    // Nobody opens the link.
    let mut h = start(2);
    let state = h.end().await;
    assert_eq!(state.reason, Some("expired"));

    // The owner never answers the consent question.
    let mut h = start(4);
    let f = file("a.txt", 10);
    h.offered(&f).await;
    let state = h.end().await;
    assert_eq!(state.reason, Some("expired"));
    assert_eq!(state.name.as_deref(), Some("a.txt"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_transfer_outlives_the_deadline_but_restarts_do_not() {
    let mut h = start(4);
    let f = file("a.bin", 500_000);
    h.connected(&f).await;
    let expires = h.phone.session.expires;
    while now() < expires + 1 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Still receiving after the session's end.
    h.web.write(&f.envelope, f.envelope.len()).unwrap();
    // An ICE failure now ends it: no restart is possible.
    h.web.state(PeerState::Failed);
    assert_eq!(h.closed().await, Some(2));
    let state = h.end().await;
    assert_eq!(state.reason, Some("lost"));
    assert!(
        !h.host
            .log
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.op == PeerOp::Restart)
    );

    // Without a failure the file is kept after the deadline.
    let mut h = start(4);
    h.connected(&f).await;
    while now() < h.phone.session.expires + 1 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    h.web.write(&f.envelope, f.envelope.len()).unwrap();
    h.web.end(&f.plain).unwrap();
    h.web.ended("kept");
    h.closed().await;
    assert_eq!(h.end().await.state, "kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_that_never_comes_up_is_given_up() {
    let mut h = start(600);
    let f = file("a.bin", 1000);
    h.accepted(&f).await;
    h.phone.send(&Message::Answer {
        key: f.key.clone(),
        sdp: PAGE_SDP.into(),
    });
    let answer = h.web.next().await;
    h.web.done(&answer);
    // Never connected within the connect wait.
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.end().await.reason, Some("connect"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_envelope_is_refused_and_deleted() {
    let mut h = start(600);
    let f = file("a.bin", 200_000);
    h.connected(&f).await;
    let mut tampered = f.envelope.clone();
    tampered[70_000] ^= 1;
    h.web.write(&tampered, tampered.len()).unwrap();
    let refused = h.web.end(&f.plain).unwrap_err();
    assert_eq!(refused.stop_code(), 2);
    h.web.ended("verification");
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    let state = h.end().await;
    assert_eq!(state.reason, Some("verification"));
    assert!(h.names().contains(&"verifying"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_out_of_order_write_is_refused_at_once() {
    let mut h = start(600);
    let f = file("a.bin", 200_000);
    h.connected(&f).await;
    let transfer = h.web.transfer();
    h.controls
        .sink
        .write(&transfer, 0, &f.envelope[..1000])
        .unwrap();
    assert_eq!(
        h.controls
            .sink
            .write(&transfer, 2000, &f.envelope[2000..3000]),
        Err(SinkError::Failed("a gap or an overlap"))
    );
    // The partial file went with the refusal.
    assert!(!h.controls.sink.holds());
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.end().await.reason, Some("verification"));
    // A write for another transfer is refused.
    assert!(h.controls.sink.write("other", 0, &[1]).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_window_that_cannot_open_fails_the_session_and_tells_the_page() {
    let mut h = start_with(600, false);
    let f = file("a.txt", 10);
    h.offered(&f).await;
    h.controls.consent(true);
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    let state = h.end().await;
    assert_eq!(state.reason, Some("webview"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hiding_with_no_relay_and_a_silent_window_fail_clearly() {
    let mut h = start(600);
    let f = file("a.txt", 10);
    h.offered(&f).await;
    h.controls.consent(true);
    h.web.ready();
    let create = h.web.next().await;
    h.web.report(PeerReport::Error {
        transfer: h.web.transfer(),
        seq: create.seq,
        reason: "no-relay".into(),
    });
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.phone.read().await, stop(StopReason::Failed));
    assert_eq!(h.end().await.reason, Some("no_relay"));

    // The window never loads.
    let mut h = start(600);
    h.offered(&f).await;
    h.controls.consent(true);
    assert_eq!(h.closed().await, Some(2));
    assert_eq!(h.end().await.reason, Some("webview"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_for_another_transfer_are_ignored() {
    let mut h = start(600);
    let f = file("a.bin", 1000);
    h.connected(&f).await;
    assert!(!h.controls.report(PeerReport::Ended {
        transfer: "AAAAAAAAAAAAAAAAAAAAAA".into(),
        outcome: "peer-cancelled".into(),
    }));
    h.web.write(&f.envelope, f.envelope.len()).unwrap();
    h.web.end(&f.plain).unwrap();
    // Without the window's report, KEPT is given a moment and then it ends.
    h.closed().await;
    assert_eq!(h.end().await.state, "kept");
}
