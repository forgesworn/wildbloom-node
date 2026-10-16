//! Headless end-to-end test of Drop with synthetic keys and loopback services:
//! a local wildbloomd, an "online" wildbloomd with device grants and the
//! pairing issuer, a Foregather live relay, an in-process Nostr relay and an
//! in-process NIP-46 signer.  The recipient is the Foregather Rust kit.
//!
//! Ignored by default.  Run with the three binaries in one directory:
//!
//! ```text
//! WILDBLOOM_E2E_BIN_DIR=/path/to/bin cargo test drop_end_to_end -- --ignored --nocapture
//! ```
//!
//! `bin` holds `wildbloomd-local` (this repository's daemon),
//! `wildbloomd-grants` (a daemon with `--device-grants` and
//! `--pairing-issuer`) and `foregather-server` (with live mode).

use super::client::{self, NodeEndpoint};
use super::descriptor::ShareDescriptor;
use super::engine::{Engine, EngineConfig, Host, LocalNode, PAIRING_NAMESPACE, PAIRING_PURPOSE};
use super::keychain::{MemoryStore, SecretStore};
use super::status::StatusLine;
use super::types::*;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use foregather_kit::handoff::PublicRoom;
use foregather_kit::live::{PairingGate, PairingSecret, Role};
use foregather_kit::transfer::Transfer;
use futures_util::{SinkExt as _, StreamExt as _};
use nostr::prelude::Keys;
use nostr_connect::prelude::{
    NostrConnectKeys, NostrConnectRemoteSigner, NostrConnectRequest, NostrConnectSignerActions,
};
use rand_core::OsRng;
use serde_json::Value;
use std::collections::HashMap;
use std::net::TcpListener as StdListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_port(port: u16, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "{what} did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// wildbloomd's default quota, which the app passes for a default install.
const LOCAL_QUOTA: u64 = 10 * 1024 * 1024 * 1024;

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// --------------------------------------------------------------- relay

/// A minimal in-memory Nostr relay: REQ, EVENT, CLOSE with kind, `#p` and
/// `since` filters, for NIP-46 only.
async fn nostr_relay() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (events, _) = tokio::sync::broadcast::channel::<Value>(256);
    let stored: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let events = events.clone();
            let stored = stored.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = ws.split();
                let mut live = events.subscribe();
                let mut subs: HashMap<String, Vec<Value>> = HashMap::new();
                loop {
                    tokio::select! {
                        message = source.next() => {
                            let Some(Ok(message)) = message else { return };
                            let Ok(text) = message.into_text() else { continue };
                            let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(&text) else { continue };
                            match parts.first().and_then(Value::as_str) {
                                Some("REQ") => {
                                    let id = parts[1].as_str().unwrap_or_default().to_owned();
                                    let filters: Vec<Value> = parts[2..].to_vec();
                                    let past: Vec<Value> = stored
                                        .lock()
                                        .unwrap()
                                        .iter()
                                        .filter(|e| filters.iter().any(|f| matches(f, e) && f.get("limit") != Some(&Value::from(0))))
                                        .cloned()
                                        .collect();
                                    for event in past {
                                        let _ = sink.send(serde_json::json!(["EVENT", id, event]).to_string().into()).await;
                                    }
                                    let _ = sink.send(serde_json::json!(["EOSE", id]).to_string().into()).await;
                                    subs.insert(id, filters);
                                }
                                Some("CLOSE") => {
                                    subs.remove(parts[1].as_str().unwrap_or_default());
                                }
                                Some("EVENT") => {
                                    let event = parts[1].clone();
                                    let id = event["id"].clone();
                                    stored.lock().unwrap().push(event.clone());
                                    let _ = events.send(event);
                                    let _ = sink.send(serde_json::json!(["OK", id, true, ""]).to_string().into()).await;
                                }
                                _ => {}
                            }
                        }
                        event = live.recv() => {
                            let Ok(event) = event else { continue };
                            for (id, filters) in &subs {
                                if filters.iter().any(|f| matches(f, &event)) {
                                    let _ = sink.send(serde_json::json!(["EVENT", id, event]).to_string().into()).await;
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

fn matches(filter: &Value, event: &Value) -> bool {
    if let Some(kinds) = filter.get("kinds").and_then(Value::as_array)
        && !kinds.contains(&event["kind"])
    {
        return false;
    }
    if let Some(since) = filter.get("since").and_then(Value::as_u64)
        && event["created_at"].as_u64().unwrap_or(0) < since
    {
        return false;
    }
    if let Some(wanted) = filter.get("#p").and_then(Value::as_array) {
        let tagged = event["tags"]
            .as_array()
            .is_some_and(|tags| tags.iter().any(|t| t[0] == "p" && wanted.contains(&t[1])));
        if !tagged {
            return false;
        }
    }
    true
}

// -------------------------------------------------------------- signer

#[derive(Clone, Default)]
struct Counts {
    total: Arc<AtomicUsize>,
    sign: Arc<AtomicUsize>,
}

impl NostrConnectSignerActions for Counts {
    fn approve(&self, _: &nostr::prelude::PublicKey, request: &NostrConnectRequest) -> bool {
        self.total.fetch_add(1, Ordering::SeqCst);
        if matches!(request, NostrConnectRequest::SignEvent(_)) {
            self.sign.fetch_add(1, Ordering::SeqCst);
        }
        true
    }
}

// ---------------------------------------------------------------- host

struct TestHost {
    bin: PathBuf,
    work: PathBuf,
    name: &'static str,
    engine: OnceLock<Weak<Engine>>,
    local: Mutex<Option<(Proc, u16)>>,
    shares: Mutex<Vec<ShareState>>,
    settings: Mutex<bool>,
}

impl TestHost {
    fn restart_local(&self) {
        let keys = self
            .engine
            .get()
            .and_then(Weak::upgrade)
            .map(|e| e.local_trusted_keys())
            .unwrap_or_default();
        let mut slot = self.local.lock().unwrap();
        let port = slot.as_ref().map_or_else(free_port, |(_, port)| *port);
        *slot = None;
        let mut command = Command::new(self.bin.join("wildbloomd-local"));
        command
            .args(["--no-tor", "--repair-interval", "0", "--bind"])
            .arg(format!("127.0.0.1:{port}"))
            .arg("--public-url")
            .arg(format!("http://localhost:{port}/"))
            .arg("--data-dir")
            .arg(self.work.join(format!("{}-local-node", self.name)));
        // Exactly what the app passes in every transport mode.
        command.args(super::engine::local_node_trust_args(
            &keys,
            None,
            LOCAL_QUOTA,
        ));
        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for_port(port, "local node");
        *slot = Some((Proc(child), port));
    }
}

impl Host for TestHost {
    fn emit_file(&self, _: &FileRow) {}
    fn emit_removed(&self, _: &str) {}
    fn emit_status(&self, _: &DropStatus, _: &StatusLine) {}
    fn emit_share(&self, state: &ShareState) {
        self.shares.lock().unwrap().push(state.clone());
    }
    fn local_node(&self) -> LocalNode {
        let port = self.local.lock().unwrap().as_ref().map(|(_, port)| *port);
        LocalNode {
            state: if port.is_some() { "ok" } else { "stopped" },
            endpoint: port.map(|port| {
                NodeEndpoint::with_server(
                    url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
                    "localhost".into(),
                )
            }),
        }
    }
    fn trust_changed(&self) {
        if *self.settings.lock().unwrap() {
            self.restart_local();
        }
    }
    fn node_settings_exist(&self) -> bool {
        *self.settings.lock().unwrap()
    }
    fn ensure_node_settings(&self) -> Result<(), String> {
        *self.settings.lock().unwrap() = true;
        self.restart_local();
        Ok(())
    }
    fn pick_save_path(&self, _: &str) -> Option<PathBuf> {
        None
    }
    fn pick_files(&self) -> Vec<PathBuf> {
        Vec::new()
    }
    fn open_folder(&self, _: &Path) {}
}

fn engine_for(
    host: &Arc<TestHost>,
    store: &Arc<MemoryStore>,
    relay_api: &str,
    watch_dir: &Path,
) -> Arc<Engine> {
    let base = host.work.join(host.name);
    let config = EngineConfig {
        data_dir: base.join("drop"),
        temp_dir: base.join("drop-temp"),
        watch_dir: watch_dir.to_path_buf(),
        watch_display: "~/Wildbloom".into(),
        get_base: "http://127.0.0.1:5472/get/".into(),
        relay_base: Some(relay_api.to_owned()),
        allow_loopback_http: true,
        signer_timeout: Duration::from_secs(30),
        computer_name: "Test computer".into(),
        watch_interval: Duration::from_millis(500),
    };
    let store = store.clone();
    let engine = Engine::new(
        config,
        host.clone(),
        Box::new(move || Ok(store.clone() as Arc<dyn SecretStore>)),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    let _ = host.engine.set(Arc::downgrade(&engine));
    engine.start();
    engine
}

async fn until<T>(what: &str, seconds: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn approve(engine: &Arc<Engine>, bunker: &str) {
    engine.approve_device(Some(bunker), false).unwrap();
    let engine = engine.clone();
    let status = until("approval", 90, || {
        let status = engine.approval_status().unwrap();
        (status.state != "waiting").then_some(status)
    })
    .await;
    assert_eq!(status.state, "approved", "{status:?}");
}

fn row(engine: &Engine, id: &str) -> Option<FileRow> {
    engine.rows().into_iter().find(|r| r.id == id)
}

/// A recipient through the relay HTTP API, as the browser kit does it.
struct Recipient {
    http: reqwest::Client,
    api: String,
    locator: String,
    capability: String,
}

impl Recipient {
    async fn claim(api: &str, locator: &str) -> Self {
        let capability = URL_SAFE_NO_PAD.encode(rand_bytes());
        let http = reqwest::Client::new();
        let response = http
            .post(format!("{api}live-sessions/{locator}/claim"))
            .bearer_auth(&capability)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "claim {}",
            response.status()
        );
        Self {
            http,
            api: api.to_owned(),
            locator: locator.to_owned(),
            capability,
        }
    }

    async fn put(&self, kind: &str, body: String) {
        let response = self
            .http
            .put(format!(
                "{}live-sessions/{}/messages/recipient/{kind}",
                self.api, self.locator
            ))
            .bearer_auth(&self.capability)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "put {kind} {}",
            response.status()
        );
    }

    async fn get(&self, kind: &str) -> String {
        loop {
            let response = self
                .http
                .get(format!(
                    "{}live-sessions/{}/messages/inviter/{kind}",
                    self.api, self.locator
                ))
                .bearer_auth(&self.capability)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                return response.text().await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

fn rand_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

fn file_key_entries(store: &MemoryStore) -> usize {
    store
        .accounts()
        .iter()
        .filter(|a| a.starts_with("drop/file-key/"))
        .count()
}

/// The loopback services every journey needs.
struct Services {
    bin: PathBuf,
    _work: tempfile::TempDir,
    work_path: PathBuf,
    bunker: String,
    counts: Counts,
    relay_api: String,
    fg_port: u16,
    online_url: String,
    online: NodeEndpoint,
    http: reqwest::Client,
    _procs: Vec<Proc>,
}

async fn services() -> Option<Services> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let Some(bin) = std::env::var_os("WILDBLOOM_E2E_BIN_DIR").map(PathBuf::from) else {
        eprintln!("skipped: WILDBLOOM_E2E_BIN_DIR is not set");
        return None;
    };
    let work = tempfile::tempdir().unwrap();
    let work_path = work.path().to_path_buf();

    // Synthetic owner and signer keys, the Nostr relay and the NIP-46 signer.
    let owner = Keys::generate();
    let signer_keys = Keys::generate();
    let relay_port = nostr_relay().await;
    let relay_url = format!("ws://127.0.0.1:{relay_port}");
    let counts = Counts::default();
    let signer = NostrConnectRemoteSigner::new(
        NostrConnectKeys::new(signer_keys.clone(), owner.clone()),
        [relay_url.as_str()],
        Some("synthetic-connect-secret".into()),
        None,
    )
    .unwrap();
    let bunker = signer.bunker_uri().to_string();
    let serve_counts = counts.clone();
    tokio::spawn(async move {
        let _ = signer.serve(serve_counts).await;
    });
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // The Foregather live relay and the online node with the issuer.
    let fg_port = free_port();
    let operator_token = URL_SAFE_NO_PAD.encode(rand_bytes());
    let foregather = Proc(
        Command::new(bin.join("foregather-server"))
            .env("FOREGATHER_CREATE_TOKEN", &operator_token)
            .env("FOREGATHER_DB", work_path.join("foregather.sqlite"))
            .env("FOREGATHER_BIND", format!("127.0.0.1:{fg_port}"))
            .env("FOREGATHER_ENABLE_LIVE", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_port(fg_port, "foregather relay");
    let relay_api = format!("http://127.0.0.1:{fg_port}/v1/");
    let token_file = work_path.join("operator-token");
    super::engine::write_private_file(&token_file, operator_token.as_bytes()).unwrap();
    let online_port = free_port();
    let online_url = format!("http://localhost:{online_port}/");
    let online_node = Proc(
        Command::new(bin.join("wildbloomd-grants"))
            .args([
                "--no-tor",
                "--repair-interval",
                "0",
                "--device-grants",
                "--pairing-issuer",
            ])
            .arg("--bind")
            .arg(format!("127.0.0.1:{online_port}"))
            .arg("--public-url")
            .arg(&online_url)
            .arg("--allow-pubkey")
            .arg(owner.public_key().to_hex())
            .arg("--data-dir")
            .arg(work_path.join("online-node"))
            .arg("--pairing-relay-url")
            .arg(format!("http://127.0.0.1:{fg_port}/"))
            .arg("--pairing-operator-token-file")
            .arg(&token_file)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for_port(online_port, "online node");
    let online = NodeEndpoint::parse(&online_url, true).unwrap();
    let http = reqwest::Client::new();

    Some(Services {
        bin,
        _work: work,
        work_path,
        bunker,
        counts,
        relay_api,
        fg_port,
        online_url,
        online,
        http,
        _procs: vec![foregather, online_node],
    })
}

/// A first-run engine, approved through the synthetic signer, with its
/// recovery key confirmed.  Returns the engine, host, store and recovery key.
async fn approved_engine(
    svc: &Services,
    name: &'static str,
    watch_dir: &Path,
) -> (Arc<Engine>, Arc<TestHost>, Arc<MemoryStore>, String) {
    let store = Arc::new(MemoryStore::default());
    let host = Arc::new(TestHost {
        bin: svc.bin.clone(),
        work: svc.work_path.clone(),
        name,
        engine: OnceLock::new(),
        local: Mutex::new(None),
        shares: Mutex::new(Vec::new()),
        settings: Mutex::new(false),
    });
    let engine = engine_for(&host, &store, &svc.relay_api, watch_dir);
    assert_eq!(engine.first_run().unwrap().step, "node");
    let check = engine.check_online_node(&svc.online_url).await.unwrap();
    assert!(check.ok && check.limit_bytes > 0);
    engine.set_online_node(Some(&svc.online_url)).await.unwrap();
    assert_eq!(engine.first_run().unwrap().step, "approve");
    assert!(
        host.local_node().endpoint.is_some(),
        "Q10 started the local node"
    );
    approve(&engine, &svc.bunker).await;
    assert_eq!(engine.first_run().unwrap().step, "recovery");
    let recovery_key = engine.recovery_key_for_display().unwrap().key.clone();
    engine.confirm_recovery_saved().unwrap();
    assert!(engine.first_run().is_none());
    (engine, host, store, recovery_key)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs WILDBLOOM_E2E_BIN_DIR with wildbloomd-local, wildbloomd-grants and foregather-server"]
async fn drop_end_to_end() {
    let Some(svc) = services().await else {
        return;
    };
    let Services {
        bin,
        work_path,
        bunker,
        counts,
        relay_api,
        online_url,
        online,
        http,
        ..
    } = &svc;
    let (bin, work_path, bunker, relay_api, online_url, online, http) = (
        bin.clone(),
        work_path.clone(),
        bunker.clone(),
        relay_api.clone(),
        online_url.clone(),
        online.clone(),
        http.clone(),
    );
    let report = |step: &str| eprintln!("e2e: {step}");

    // ---------------------------------------------------- first run (D1-D3)
    let watch_dir = work_path.join("home/Wildbloom");
    let (engine, host, store, recovery_key) = approved_engine(&svc, "first", &watch_dir).await;
    let signer_requests_after_approval = counts.total.load(Ordering::SeqCst);
    assert_eq!(counts.sign.load(Ordering::SeqCst), 1, "one signature");
    report(&format!(
        "approved with {} signer requests ({} signature)",
        signer_requests_after_approval,
        counts.sign.load(Ordering::SeqCst)
    ));

    // ------------------------------------------------- add a file, 2 copies
    let originals = work_path.join("originals");
    std::fs::create_dir_all(&originals).unwrap();
    let source = originals.join("holiday photos.bin");
    let plain: Vec<u8> = (0..3_000_000u32).map(|i| (i * 7 + 3) as u8).collect();
    std::fs::write(&source, &plain).unwrap();
    let source_mtime = std::fs::metadata(&source).unwrap().modified().unwrap();
    let added = engine.add_paths(vec![source.clone()], None).await.unwrap();
    assert_eq!(added.added.len(), 1, "{added:?}");
    let id = added.added[0].clone();
    let dup = engine.add_paths(vec![source.clone()], None).await.unwrap();
    assert_eq!(dup.duplicates.len(), 1, "same plaintext is a duplicate");
    let check_engine = engine.clone();
    until("2 copies", 60, || {
        row(&check_engine, &id).filter(|r| r.state == "two_copies")
    })
    .await;
    let record = engine.index.file(&id).unwrap().unwrap();
    let sha = record.sha256.clone().unwrap();
    let local = host.local_node().endpoint.unwrap();
    let local_head = client::head(&http, &local, &sha).await.unwrap();
    let online_head = client::head(&http, &online, &sha).await.unwrap();
    assert_eq!(local_head, record.size);
    assert_eq!(online_head, record.size);
    assert_eq!(file_key_entries(&store), 1, "one per-file keychain entry");
    assert_eq!(
        counts.total.load(Ordering::SeqCst),
        signer_requests_after_approval,
        "no signer request after approval"
    );
    assert_eq!(std::fs::read(&source).unwrap(), plain, "original untouched");
    assert_eq!(
        std::fs::metadata(&source).unwrap().modified().unwrap(),
        source_mtime
    );
    report(&format!(
        "2 copies verified by HEAD on both nodes ({} bytes)",
        record.size.unwrap()
    ));
    // The local copy is a friend-grant claim that survives node restarts:
    // the app passes one constant grant in every transport mode, so a Tor or
    // public-URL toggle (each a restart with the same Drop arguments) never
    // changes its grant or demotes it to a guest claim.
    let device_keys = engine.identity().unwrap().device.keys().clone();
    for _ in 0..2 {
        host.restart_local();
        let listed = client::list(&http, &local, &device_keys).await.unwrap();
        assert!(
            listed.iter().any(|l| l.sha256 == sha),
            "the local copy is still this grant's claim after a restart"
        );
        assert_eq!(
            client::head(&http, &local, &sha).await.unwrap(),
            record.size
        );
    }
    report("local copy kept its friend-grant claim across node restarts");
    // The key list reaches both nodes.
    let key_engine = engine.clone();
    until("key list on the online node", 30, || {
        key_engine
            .index
            .get(super::engine::kv::KEY_LIST_ONLINE_SHA)
            .unwrap()
    })
    .await;

    // ---------------------------------------------------------------- share
    let first = engine.share_start(&id, false).unwrap();
    assert_eq!(first.state, "preparing");
    let ready = until("share link", 60, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "ready")
            .cloned()
    })
    .await;
    let link = ready.link.clone().unwrap();
    let words = ready.words.clone().unwrap();
    assert_eq!(words.len(), 4);
    assert!(link.starts_with("http://127.0.0.1:5472/get/#"));
    report("share link and four words ready");
    // The recipient: parse the link, claim, pair with the words.
    let now = super::engine::now();
    let room = PublicRoom::parse_link(
        &link,
        "http://127.0.0.1:5472/get/",
        true,
        PAIRING_NAMESPACE,
        PAIRING_PURPOSE,
        now,
    )
    .unwrap();
    let recipient = Recipient::claim(&relay_api, &room.session.locator).await;
    let secret = PairingSecret::parse(&words.join(" ")).unwrap();
    let mut gate = PairingGate::new(room.session.clone(), secret, 1, now).unwrap();
    let exchange = gate.start(Role::Recipient, now, &mut OsRng).unwrap();
    recipient
        .put("hello", serde_json::to_string(&exchange.hello()).unwrap())
        .await;
    let inviter_hello: String = serde_json::from_str(&recipient.get("hello").await).unwrap();
    let pending = exchange.finish(&inviter_hello, now).unwrap();
    recipient
        .put(
            "proof",
            serde_json::to_string(&pending.confirmation().unwrap()).unwrap(),
        )
        .await;
    let inviter_proof: String = serde_json::from_str(&recipient.get("proof").await).unwrap();
    let mut channel = pending.confirm(&inviter_proof, now).unwrap();
    let their_words: Vec<String> = channel
        .verification_words(3, now)
        .unwrap()
        .split(' ')
        .map(str::to_owned)
        .collect();
    let check_state = until("check words", 30, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "check")
            .cloned()
    })
    .await;
    assert_eq!(check_state.check_words.clone().unwrap(), their_words);
    assert!(
        host.shares
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.state == "opened")
    );
    let next = engine.share_verify(&id, true).unwrap().unwrap();
    assert_eq!(next.state, "sending");
    let packet = recipient.get("packet-0").await;
    let clear = channel.open(&packet, super::engine::now()).unwrap();
    let transfer = Transfer::parse(&clear).unwrap();
    let descriptor = ShareDescriptor::parse(transfer.payload()).unwrap();
    let receipt = channel
        .seal(&transfer.receipt(), super::engine::now())
        .unwrap();
    recipient.put("packet-0", receipt).await;
    let sent = until("sent", 30, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "sent")
            .cloned()
    })
    .await;
    assert!(sent.delete_at.unwrap() > super::engine::now() + 86_000);
    assert_eq!(descriptor.name(), "holiday photos.bin");
    assert_eq!(descriptor.bytes(), plain.len() as u64);
    assert_ne!(descriptor.sha256(), sha, "a separate share copy");
    // The recipient downloads and decrypts the shared copy.
    let bytes = http
        .get(descriptor.url())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(bytes.len() as u64, descriptor.size());
    let (metadata, opened) = wildbloom_envelope::open_bytes(
        descriptor.key(),
        &bytes,
        wildbloom_envelope::Limits::BROWSER,
    )
    .unwrap();
    assert_eq!(metadata.name, "holiday photos.bin");
    assert_eq!(&*opened, &plain, "recipient bytes equal the source");
    assert_eq!(row(&engine, &id).unwrap().state, "shared");
    report("recipient paired, received the receipt-confirmed descriptor and decrypted the file");

    // ---------------------------------------------------- stop sharing (33)
    engine.stop_sharing(&id).await.unwrap();
    assert_eq!(
        client::head(&http, &online, descriptor.sha256())
            .await
            .unwrap(),
        None,
        "shared copy deleted"
    );
    assert_eq!(
        client::head(&http, &online, &sha).await.unwrap(),
        record.size,
        "owner copy kept"
    );
    assert_eq!(row(&engine, &id).unwrap().state, "sharing_ended");
    assert_eq!(file_key_entries(&store), 1, "share key removed");
    report("stop sharing deleted the share blob and kept the owner copy");

    // Wrong words end the link (S9); closing the sheet deletes a copy that
    // was never sent.
    host.shares.lock().unwrap().clear();
    engine.share_start(&id, true).unwrap();
    let ready = until("second share link", 60, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "ready")
            .cloned()
    })
    .await;
    let now = super::engine::now();
    let room = PublicRoom::parse_link(
        ready.link.as_deref().unwrap(),
        "http://127.0.0.1:5472/get/",
        true,
        PAIRING_NAMESPACE,
        PAIRING_PURPOSE,
        now,
    )
    .unwrap();
    let intruder = Recipient::claim(&relay_api, &room.session.locator).await;
    let guess = PairingSecret::generate(4, &mut OsRng).unwrap();
    let mut gate = PairingGate::new(room.session.clone(), guess, 1, now).unwrap();
    let exchange = gate.start(Role::Recipient, now, &mut OsRng).unwrap();
    intruder
        .put("hello", serde_json::to_string(&exchange.hello()).unwrap())
        .await;
    let inviter_hello: String = serde_json::from_str(&intruder.get("hello").await).unwrap();
    let pending = exchange.finish(&inviter_hello, now).unwrap();
    intruder
        .put(
            "proof",
            serde_json::to_string(&pending.confirmation().unwrap()).unwrap(),
        )
        .await;
    until("wrong words", 30, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "wrong_words")
            .cloned()
    })
    .await;
    assert!(
        host.shares
            .lock()
            .unwrap()
            .iter()
            .all(|s| s.state != "sent")
    );
    let unsent = engine.index.share(&id).unwrap().unwrap();
    assert_eq!(unsent.state, "open");
    assert_eq!(
        client::head(&http, &online, &unsent.sha256).await.unwrap(),
        Some(unsent.size)
    );
    engine.share_cancel(&id).await.unwrap();
    assert_eq!(
        client::head(&http, &online, &unsent.sha256).await.unwrap(),
        None
    );
    assert!(engine.index.share(&id).unwrap().is_none());
    assert_eq!(file_key_entries(&store), 1);
    report("wrong words ended the link; closing the sheet deleted the unsent copy");

    // ------------------------------------------------- watched folder (32)
    engine.set_watch_folder(true).unwrap();
    std::fs::write(watch_dir.join("ignored.part"), b"partial").unwrap();
    let watched = watch_dir.join("scan.bin");
    let rows_before = engine.rows().len();
    {
        use std::io::Write as _;
        let mut file = std::fs::File::create(&watched).unwrap();
        for i in 0..50u32 {
            let chunk: Vec<u8> = (0..1_000_000u32).map(|j| (i * 31 + j) as u8).collect();
            file.write_all(&chunk).unwrap();
            file.flush().unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(
                engine.rows().len(),
                rows_before,
                "no row while the file is still being written"
            );
        }
    }
    let watched_sha = super::engine::sha256_file(&watched).unwrap();
    let watched_mtime = std::fs::metadata(&watched).unwrap().modified().unwrap();
    let watch_engine = engine.clone();
    let watched_row = until("watched file kept", 90, || {
        watch_engine
            .rows()
            .into_iter()
            .find(|r| r.name == "scan.bin" && r.state == "two_copies")
    })
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(engine.rows().len(), rows_before + 1, "exactly one row");
    assert!(engine.rows().iter().all(|r| r.name != "ignored.part"));
    assert!(watched_row.in_watch_folder);
    assert_eq!(super::engine::sha256_file(&watched).unwrap(), watched_sha);
    assert_eq!(
        std::fs::metadata(&watched).unwrap().modified().unwrap(),
        watched_mtime
    );
    report("watched folder: one row after writing stopped, original unchanged, .part ignored");

    // --------------------------------------------------------- remove (34)
    let sealed_before = engine
        .index
        .get(super::engine::kv::KEY_LIST_ONLINE_SHA)
        .unwrap();
    let watched_record = engine.index.file(&watched_row.id).unwrap().unwrap();
    let watched_blob = watched_record.sha256.clone().unwrap();
    assert_eq!(file_key_entries(&store), 2);
    engine.remove(&watched_row.id).await.unwrap();
    assert_eq!(
        client::head(&http, &local, &watched_blob).await.unwrap(),
        None
    );
    assert_eq!(
        client::head(&http, &online, &watched_blob).await.unwrap(),
        None
    );
    assert_eq!(file_key_entries(&store), 1, "its keychain entry is gone");
    assert_eq!(super::engine::sha256_file(&watched).unwrap(), watched_sha);
    report("remove deleted both copies and the key; the original is untouched");

    // Remove while still encrypting (M3): no key and no outbox file survive.
    let big = originals.join("large scan.bin");
    std::fs::write(&big, vec![7u8; 60_000_000]).unwrap();
    let keys_before = file_key_entries(&store);
    let early = engine
        .add_paths(vec![big.clone()], None)
        .await
        .unwrap()
        .added[0]
        .clone();
    engine.remove(&early).await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        file_key_entries(&store),
        keys_before,
        "no key kept for a removed row"
    );
    assert!(engine.index.file(&early).unwrap().is_none());
    let outbox: Vec<_> = std::fs::read_dir(work_path.join("first/drop/outbox"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert!(outbox.is_empty(), "no outbox envelope kept: {outbox:?}");
    report("remove during encryption kept neither a key nor an envelope");
    // Let the key list carry the removal.
    let key_engine = engine.clone();
    until("key list after removal", 30, || {
        let now = key_engine
            .index
            .get(super::engine::kv::KEY_LIST_ONLINE_SHA)
            .unwrap();
        (now != sealed_before).then_some(())
    })
    .await;
    engine.set_watch_folder(false).unwrap();
    // Only the current key list is kept on each node.
    let identity = engine.identity().unwrap();
    let recovery_keys = identity.recovery.identity().keys().clone();
    let lists = client::list(&http, &online, &recovery_keys).await.unwrap();
    assert_eq!(lists.len(), 1, "stale key lists are deleted: {lists:?}");
    let lists = client::list(&http, &local, &recovery_keys).await.unwrap();
    assert_eq!(
        lists.len(),
        1,
        "stale local key lists are deleted: {lists:?}"
    );

    // ---------------------------------------- restore on a fresh computer
    let store2 = Arc::new(MemoryStore::default());
    let host2 = Arc::new(TestHost {
        bin: bin.clone(),
        work: work_path.clone(),
        name: "second",
        engine: OnceLock::new(),
        local: Mutex::new(None),
        shares: Mutex::new(Vec::new()),
        settings: Mutex::new(false),
    });
    let engine2 = engine_for(
        &host2,
        &store2,
        &relay_api,
        &work_path.join("home2/Wildbloom"),
    );
    assert_eq!(engine2.first_run().unwrap().step, "node");
    let restored = engine2
        .restore(Some(&recovery_key), None, Some(&online_url))
        .await
        .unwrap();
    assert_eq!(restored.next, "approve");
    approve(&engine2, &bunker).await;
    assert!(engine2.first_run().is_none());
    let restore_engine = engine2.clone();
    let rows = until("restored rows", 60, || {
        let rows = restore_engine.rows();
        (!rows.is_empty() && rows.iter().all(|r| r.state == "two_copies")).then_some(rows)
    })
    .await;
    assert_eq!(rows.len(), 1, "the removed file stays removed: {rows:?}");
    assert_eq!(rows[0].id, id);
    assert_eq!(rows[0].name, "holiday photos.bin");
    let out = work_path.join("restored copy.bin");
    engine2.save_copy(&id, Some(out.clone())).await.unwrap();
    assert_eq!(
        std::fs::read(&out).unwrap(),
        plain,
        "restored bytes equal the source"
    );
    assert_eq!(file_key_entries(&store2), 1);
    assert!(!engine2.status().recovery.confirmed);
    report("restore on a fresh app data dir recovered the file from the key list");

    // Changing the online node first ends live shares on the old node (M2).
    host2.shares.lock().unwrap().clear();
    engine2.share_start(&id, false).unwrap();
    until("share link on the restored computer", 60, || {
        host2
            .shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "ready")
            .cloned()
    })
    .await;
    let live = engine2.index.share(&id).unwrap().unwrap();
    assert_eq!(live.origin, online.origin());
    assert_eq!(
        client::head(&http, &online, &live.sha256).await.unwrap(),
        Some(live.size)
    );
    let elsewhere = format!("http://localhost:{}/", free_port());
    engine2.set_online_node(Some(&elsewhere)).await.unwrap();
    assert_eq!(
        client::head(&http, &online, &live.sha256).await.unwrap(),
        None,
        "the live share was deleted on the old node before the change"
    );
    assert!(engine2.index.pending_deletes().unwrap().is_empty());
    report("changing the online node deleted the live share on the old node first");

    // Remove after the node change still reaches the copy on the old node.
    let device2 = engine2.identity().unwrap().device.keys().clone();
    let restored_sha = engine2.index.file(&id).unwrap().unwrap().sha256.unwrap();
    let before = client::list(&http, &online, &device2).await.unwrap();
    assert!(
        before.iter().any(|l| l.sha256 == restored_sha),
        "this computer claimed the restored copy"
    );
    engine2.remove(&id).await.unwrap();
    let after = client::list(&http, &online, &device2).await.unwrap();
    assert!(
        after.iter().all(|l| l.sha256 != restored_sha),
        "Remove deleted this computer's copy on the old node"
    );
    report("remove after a node change deleted the copy on the old node");
}

/// Waits for a JSON file the browser driver writes into the hand-off folder.
async fn handoff_file(dir: &Path, name: &str, seconds: u64) -> Value {
    let path = dir.join(name);
    until(name, seconds, || {
        std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    })
    .await
}

/// The owner side of a share to the real recipient page, driven in Chromium
/// by `desktop/tests/drop-get-journey.mjs`.  The two talk through files in
/// `WILDBLOOM_E2E_HANDOFF`: this test writes `share.json` (the link and words
/// the owner would send and read out) and checks what the page saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs WILDBLOOM_E2E_BIN_DIR, WILDBLOOM_E2E_HANDOFF and the browser driver"]
async fn drop_share_to_the_get_page() {
    let Some(handoff) = std::env::var_os("WILDBLOOM_E2E_HANDOFF").map(PathBuf::from) else {
        eprintln!("skipped: WILDBLOOM_E2E_HANDOFF is not set");
        return;
    };
    let Some(svc) = services().await else {
        return;
    };
    let watch_dir = svc.work_path.join("home/Wildbloom");
    let (engine, host, _store, _key) = approved_engine(&svc, "get", &watch_dir).await;
    let source = svc.work_path.join("Quarterly report.pdf");
    let plain: Vec<u8> = (0..1_500_000u32).map(|i| (i * 13 + 5) as u8).collect();
    std::fs::write(&source, &plain).unwrap();
    let id = engine.add_paths(vec![source], None).await.unwrap().added[0].clone();
    let check_engine = engine.clone();
    until("2 copies", 60, || {
        row(&check_engine, &id).filter(|r| r.state == "two_copies")
    })
    .await;
    engine.share_start(&id, false).unwrap();
    let ready = until("share link", 60, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "ready")
            .cloned()
    })
    .await;
    let expected = super::hex_lower(&<sha2::Sha256 as sha2::Digest>::digest(&plain));
    std::fs::write(
        handoff.join("share.json"),
        serde_json::json!({
            "link": ready.link,
            "words": ready.words.clone().unwrap().join(" "),
            "relayUpstream": format!("http://127.0.0.1:{}", svc.fg_port),
            "name": "Quarterly report.pdf",
            "bytes": plain.len(),
        })
        .to_string(),
    )
    .unwrap();
    eprintln!("e2e-get: link and words handed to the browser driver");
    let check = until("check words", 120, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "check")
            .cloned()
    })
    .await;
    let seen = handoff_file(&handoff, "recipient-words.json", 60).await;
    assert_eq!(
        seen["words"].as_str().unwrap(),
        check.check_words.clone().unwrap().join(" "),
        "the page and the owner show the same three words"
    );
    engine.share_verify(&id, true).unwrap();
    until("sent", 60, || {
        host.shares
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.state == "sent")
            .cloned()
    })
    .await;
    eprintln!("e2e-get: receipt received from the page");
    let downloaded = handoff_file(&handoff, "downloaded.json", 120).await;
    assert_eq!(downloaded["sha256"].as_str().unwrap(), expected);
    assert_eq!(downloaded["bytes"].as_u64().unwrap(), plain.len() as u64);
    assert_eq!(downloaded["name"].as_str().unwrap(), "Quarterly report.pdf");
    eprintln!("e2e-get: the page saved the exact bytes");
    let share = engine.index.share(&id).unwrap().unwrap();
    engine.stop_sharing(&id).await.unwrap();
    assert_eq!(
        client::head(&svc.http, &svc.online, &share.sha256)
            .await
            .unwrap(),
        None
    );
    std::fs::write(handoff.join("stopped.json"), "{}").unwrap();
    eprintln!("e2e-get: stop sharing deleted the shared copy");
}
