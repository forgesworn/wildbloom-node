//! The engine side of "Receive a file": the commands behind the sheet, the
//! hidden window's reports and sink, the setting, and "Add to Wildbloom".
//! One receive runs at a time.  It runs on the engine's runtime, so closing
//! the Drop window (which only hides it) never ends it; quitting does.

use super::awake::Awake;
use super::received;
use super::session::{self, Controls, DirectHost, Dirs, Opened, Timing};
use super::sink::SinkError;
use super::{
    AddedToWildbloom, PURPOSE, PeerReport, PeerRequest, ReceiveState, ReceivingSettings,
    messages::{MAX_FILE_BYTES, default_stun},
};
use crate::drop::client::{self, NodeEndpoint, TurnError};
use crate::drop::engine::{Engine, internal};
use crate::drop::pairing::{Live, RelaySlot};
use crate::drop::types::{CommandError, CommandResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The ICE configuration for one receive from the issuer's answer.  A node
/// with no issuer (404) gives the built-in STUN entry for both ends.
/// `expires` is not read in a direct send, which lasts at most the session's
/// own ten minutes.  Hiding means relay-only ICE, which needs a TURN URL, so
/// it is refused here, before any pairing link exists.
fn ice_for_receive(
    answer: Result<client::TurnCredentials, TurnError>,
    hide: bool,
) -> Result<client::TurnCredentials, &'static str> {
    let turn = match answer {
        Ok(turn) => turn,
        Err(TurnError::NotOffered) => client::TurnCredentials {
            expires: 0,
            own: default_stun(),
            peer: default_stun(),
        },
        Err(TurnError::Unreachable) => return Err("node_unreachable"),
        Err(TurnError::Limited) => return Err("turn_limit"),
        Err(TurnError::Refused(_) | TurnError::Invalid) => return Err("turn_refused"),
    };
    if hide && !turn.own.has_turn() {
        return Err("no_relay");
    }
    Ok(turn)
}

/// The receiving setting in the index: `on` turns hiding on; anything else
/// (and nothing) is the default, off.  Hiding needs a TURN server, which a
/// default install has none of.
pub(crate) const HIDE_ADDRESS: &str = "receive_hide_address";

struct Running {
    generation: u64,
    task: tokio::task::JoinHandle<()>,
    controls: Arc<Controls>,
}

/// The engine's receive state.
#[derive(Default)]
pub struct DirectState {
    running: Mutex<Option<Running>>,
    /// Files kept in this run, by transfer id, for Add to Wildbloom and Show.
    received: Mutex<HashMap<String, PathBuf>>,
    /// The sheet's last state, for a window that loads mid-transfer.
    last: Mutex<Option<(u64, ReceiveState)>>,
}

impl std::fmt::Debug for DirectState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DirectState")
    }
}

/// The engine as a session's surroundings.
struct EngineHost {
    engine: Arc<Engine>,
    generation: u64,
}

impl DirectHost for EngineHost {
    fn emit(&self, state: &ReceiveState) {
        // A receive that has been replaced says nothing more.
        let current = self
            .engine
            .direct
            .running
            .lock()
            .ok()
            .and_then(|r| r.as_ref().map(|r| r.generation))
            == Some(self.generation);
        if !current {
            return;
        }
        let mut state = state.clone();
        if state.state == "kept" {
            self.engine.decorate_kept(&mut state);
        }
        if let Ok(mut last) = self.engine.direct.last.lock() {
            *last = Some((self.generation, state.clone()));
        }
        self.engine.host.emit_receive(&state);
    }

    fn open_peer(&self) -> bool {
        self.engine.host.open_peer_window()
    }

    fn peer(&self, request: &PeerRequest) {
        self.engine.host.peer_request(request);
    }

    fn close_peer(&self) {
        self.engine.host.close_peer_window();
    }

    fn keep_awake(&self) -> Awake {
        self.engine.host.keep_awake()
    }
}

fn sink_error(error: SinkError) -> CommandError {
    match error {
        SinkError::Storage => CommandError::code("sink_storage"),
        SinkError::Failed(detail) => CommandError::with_message("sink_failed", detail),
    }
}

/// `dir` shown as the owner knows it: `~/…` under the home folder, except on
/// Windows.
pub(crate) fn display_path(path: &Path, home: Option<&Path>) -> String {
    if !cfg!(windows)
        && let Some(rest) = home.and_then(|home| path.strip_prefix(home).ok())
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

impl Engine {
    /// Hiding Drop's address (relay-only ICE) is off unless turned on.
    pub fn receive_hide_address(&self) -> bool {
        self.index.get(HIDE_ADDRESS).ok().flatten().as_deref() == Some("on")
    }

    pub fn receiving_settings(&self) -> ReceivingSettings {
        ReceivingSettings {
            hide_address: self.receive_hide_address(),
            folder: self.cfg.received_display.clone(),
            max_bytes: MAX_FILE_BYTES,
        }
    }

    /// `set_receiving`: read when the next receive starts.
    pub fn set_receiving(&self, hide_address: bool) -> CommandResult<()> {
        self.index
            .set(HIDE_ADDRESS, if hide_address { "on" } else { "off" })
            .map_err(|e| internal(e.to_string()))?;
        self.emit_status();
        Ok(())
    }

    /// The running session's controls while its task runs, including the
    /// moments after its final state while it closes the window and tidies
    /// up: the hidden window's commands still reach it.
    fn running_controls(&self) -> Option<Arc<Controls>> {
        self.direct
            .running
            .lock()
            .ok()?
            .as_ref()
            .filter(|r| !r.task.is_finished())
            .map(|r| r.controls.clone())
    }

    /// The running session's controls until its final state has gone out.
    fn open_controls(&self) -> Option<Arc<Controls>> {
        self.running_controls().filter(|c| !c.finished())
    }

    /// Whether a receive is under way (for the quit confirmation).
    pub fn receive_open(&self) -> bool {
        self.open_controls().is_some()
    }

    /// `receive_start`: a new receive.  Rejects `busy` while one runs and
    /// `node_unreachable` without an online node this computer may use.
    pub fn receive_start(self: &Arc<Self>) -> CommandResult<ReceiveState> {
        let mut running = self.direct.running.lock().map_err(|_| internal("lock"))?;
        // A receive whose final state has gone out may still be tidying up;
        // it does not hold up a new one.
        if running
            .as_ref()
            .is_some_and(|r| !r.task.is_finished() && !r.controls.finished())
        {
            return Err(CommandError::code("busy"));
        }
        let node = self
            .writable_online()
            .ok_or(CommandError::code("node_unreachable"))?;
        let generation = self.next_pairing_generation();
        let (controls, inputs) = session::controls();
        let engine = self.clone();
        let task_controls = controls.clone();
        let task = self.rt.spawn(async move {
            engine
                .run_receive(node, generation, task_controls, inputs)
                .await;
        });
        *running = Some(Running {
            generation,
            task,
            controls,
        });
        let state = ReceiveState::new("preparing");
        if let Ok(mut last) = self.direct.last.lock() {
            *last = Some((generation, state.clone()));
        }
        Ok(state)
    }

    async fn run_receive(
        self: Arc<Self>,
        node: NodeEndpoint,
        generation: u64,
        controls: Arc<Controls>,
        inputs: session::Inputs,
    ) {
        let host = Arc::new(EngineHost {
            engine: self.clone(),
            generation,
        });
        host.emit(&ReceiveState::new("preparing"));
        let slot: RelaySlot = Arc::new(Mutex::new(None));
        let mut cancel = controls.watch_cancel();
        let opened = tokio::select! {
            biased;
            _ = cancel.wait_for(|c| *c) => Err(None),
            opened = self.open_receive(&node, &slot) => opened.map_err(Some),
        };
        match opened {
            Ok(opened) => {
                let dirs = Dirs {
                    temp: self.cfg.temp_dir.clone(),
                    received: self.cfg.received_dir.clone(),
                    space: session::free_space,
                };
                session::run(opened, host, controls, inputs, dirs, Timing::DEFAULT).await;
                // The session deleted it; forget it without a second request.
                if let Ok(mut slot) = slot.lock() {
                    slot.take();
                }
            }
            Err(reason) => {
                // Anything allocated before a cancel or a failure goes.
                self.delete_relay_session(&slot).await;
                let mut state = ReceiveState::new("cancelled");
                state.by = Some("you");
                controls.mark_finished();
                host.emit(&match reason {
                    None => state,
                    Some(reason) => ReceiveState::failed(reason),
                });
            }
        }
    }

    /// Drop's and the page's ICE configuration, then a live session for
    /// purpose `send` under the send page's link.  The configuration comes
    /// first, so a node that refuses it, or a person who hides their address
    /// where there is no TURN server to hide behind, fails before any link
    /// is shown.  A node with no issuer (404) gives the built-in STUN default.
    async fn open_receive(
        &self,
        node: &NodeEndpoint,
        slot: &RelaySlot,
    ) -> Result<Opened<Live>, &'static str> {
        let identity = self.identity().map_err(|_| "node_unreachable")?;
        let hide = self.receive_hide_address();
        let answer = client::turn_credentials(&self.http, node, identity.device.keys()).await;
        let turn = ice_for_receive(answer, hide)?;
        let (live, session, secret) = self
            .open_pairing(
                node,
                identity.device.keys(),
                PURPOSE,
                &self.cfg.send_base,
                slot,
            )
            .await
            .map_err(|ended| ended.state())?;
        Ok(Opened {
            link: live.link.clone(),
            words: live.words.clone(),
            expires_at: live.expires_at,
            transport: live,
            session,
            secret,
            turn,
            hide,
        })
    }

    /// The sheet's current state; `idle` when nothing has run.
    pub fn receive_state(&self) -> ReceiveState {
        self.direct
            .last
            .lock()
            .ok()
            .and_then(|last| last.as_ref().map(|(_, state)| state.clone()))
            .unwrap_or_else(|| ReceiveState::new("idle"))
    }

    /// The owner's answer to the check words.  Nothing happens if none is
    /// awaited.
    pub fn receive_verify(&self, matches: bool) {
        if let Some(controls) = self.open_controls() {
            controls.verify(matches);
        }
    }

    /// The owner's answer to the file.  Nothing happens if none is awaited.
    pub fn receive_consent(&self, accept: bool) {
        if let Some(controls) = self.open_controls() {
            controls.consent(accept);
        }
    }

    /// Ends the receive at any stage.  A kept file stays kept.
    pub fn receive_cancel(&self) {
        if let Some(controls) = self.open_controls() {
            controls.cancel();
        }
    }

    /// Quitting: ends a running receive and waits briefly for it to tidy up.
    pub async fn stop_receiving(&self) {
        let task = {
            let Ok(mut running) = self.direct.running.lock() else {
                return;
            };
            running.take().map(|r| {
                r.controls.cancel();
                r.task
            })
        };
        if let Some(task) = task {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
        }
    }

    /// A report from the hidden window.  One for another transfer, or with
    /// no receive running, is dropped.
    pub fn direct_peer_report(&self, report: PeerReport) {
        if let Some(controls) = self.running_controls() {
            controls.report(report);
        }
    }

    /// `direct_sink_write`: the next envelope bytes at `offset`.
    pub async fn direct_sink_write(
        &self,
        transfer: String,
        offset: u64,
        bytes: Vec<u8>,
    ) -> CommandResult<()> {
        let controls = self
            .running_controls()
            .ok_or(CommandError::code("sink_failed"))?;
        tokio::task::spawn_blocking(move || controls.sink.write(&transfer, offset, &bytes))
            .await
            .map_err(|_| CommandError::code("sink_failed"))?
            .map_err(sink_error)
    }

    /// `direct_sink_end`: verify and keep.  Resolves when the file is kept,
    /// so the window then sends KEPT.
    pub async fn direct_sink_end(
        &self,
        transfer: String,
        sha256: &str,
        size: u64,
    ) -> CommandResult<()> {
        let sha256 = crate::drop::parse_sha256(sha256).ok_or(CommandError::code("sink_failed"))?;
        let controls = self
            .running_controls()
            .ok_or(CommandError::code("sink_failed"))?;
        let id = transfer.clone();
        let kept = tokio::task::spawn_blocking(move || controls.sink.end(&transfer, sha256, size))
            .await
            .map_err(|_| CommandError::code("sink_failed"))?
            .map_err(sink_error)?;
        if let Ok(mut received) = self.direct.received.lock() {
            received.insert(id, kept.path);
        }
        Ok(())
    }

    /// `direct_sink_abort`: deletes what the sink holds.
    pub async fn direct_sink_abort(&self, transfer: String) {
        if let Some(controls) = self.running_controls() {
            let _ = tokio::task::spawn_blocking(move || controls.sink.abort(&transfer)).await;
        }
    }

    /// The kept state as the sheet shows it: where the file is, the folder,
    /// and whether Add to Wildbloom can run.
    fn decorate_kept(&self, state: &mut ReceiveState) {
        if let (Some(id), Some(path)) = (state.id.clone(), state.path.clone()) {
            let path = PathBuf::from(path);
            if let Ok(mut received) = self.direct.received.lock() {
                received.entry(id).or_insert_with(|| path.clone());
            }
            state.path = Some(format!(
                "{}{}{}",
                self.cfg.received_display,
                std::path::MAIN_SEPARATOR,
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ));
        }
        state.folder = Some(self.cfg.received_display.clone());
        state.can_add = Some(self.mirror_on() && self.folder_available());
    }

    fn received_path(&self, id: &str) -> CommandResult<PathBuf> {
        let path = self
            .direct
            .received
            .lock()
            .map_err(|_| internal("lock"))?
            .get(id)
            .cloned()
            .ok_or(CommandError::code("not_found"))?;
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_file()) {
            return Err(CommandError::code("not_found"));
        }
        Ok(path)
    }

    /// `receive_reveal`: shows a received file in Finder, Explorer or the
    /// file manager.
    pub fn receive_reveal(&self, id: &str) -> CommandResult<()> {
        let path = self.received_path(id)?;
        self.host.reveal_path(&path);
        Ok(())
    }

    /// `reveal_received_folder`: the Received folder in Finder, Explorer or
    /// the file manager, made first when nothing has arrived yet.
    pub fn reveal_received_folder(&self) -> CommandResult<()> {
        std::fs::create_dir_all(&self.cfg.received_dir).map_err(|_| {
            CommandError::with_message("received_folder", "Couldn't open the Received folder.")
        })?;
        self.host.reveal_path(&self.cfg.received_dir);
        Ok(())
    }

    /// `receive_add_to_wildbloom`: moves a received file into the Wildbloom
    /// folder under the same no-replace naming, where the folder mirror takes
    /// it in as the owner's own file.  Refused while the folder is off or
    /// missing, and for a file the mirror would never take in (empty, or a
    /// name it ignores).
    pub async fn receive_add_to_wildbloom(&self, id: &str) -> CommandResult<AddedToWildbloom> {
        let path = self.received_path(id)?;
        if !self.mirror_on() {
            return Err(CommandError::code("folder_off"));
        }
        if !self.folder_available() {
            return Err(CommandError::code("folder_unavailable"));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_owned)
            .ok_or(CommandError::code("not_found"))?;
        let empty = std::fs::metadata(&path).is_ok_and(|m| m.len() == 0);
        if empty || crate::drop::watch::ignored(&name) {
            return Err(CommandError::code("cannot_sync"));
        }
        let placed = {
            let _folder = self.folder_lock.lock().await;
            let root = self.cfg.watch_dir.clone();
            tokio::task::spawn_blocking(move || received::place(&path, &root, &name))
                .await
                .map_err(|_| internal("move"))?
                .map_err(|_| CommandError::code("move_failed"))?
        };
        let (new_path, new_name) = placed;
        if let Ok(mut received) = self.direct.received.lock() {
            received.insert(id.to_owned(), new_path);
        }
        self.watch_wake.notify_one();
        Ok(AddedToWildbloom {
            name: new_name,
            folder: self.cfg.watch_display.clone(),
        })
    }

    /// Start-up: staging files a killed process left in the Received folder.
    pub(crate) fn sweep_received(&self) {
        received::sweep(&self.cfg.received_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drop::direct::messages::IceServer;
    use crate::drop::engine::{EngineConfig, Host, LocalNode, ONLINE_BLOB_LIMIT, kv};
    use crate::drop::keychain::{MemoryStore, SecretStore};
    use crate::drop::status::StatusLine;
    use crate::drop::types::{DropStatus, FileRow, ShareState};
    use std::time::Duration;

    #[derive(Default)]
    struct Recorder {
        receives: Mutex<Vec<ReceiveState>>,
        statuses: Mutex<Vec<DropStatus>>,
        revealed: Mutex<Vec<PathBuf>>,
    }

    impl Host for Recorder {
        fn emit_file(&self, _: &FileRow) {}
        fn emit_removed(&self, _: &str) {}
        fn emit_status(&self, status: &DropStatus, _: &StatusLine) {
            self.statuses.lock().unwrap().push(status.clone());
        }
        fn emit_share(&self, _: &ShareState) {}
        fn emit_receive(&self, state: &ReceiveState) {
            self.receives.lock().unwrap().push(state.clone());
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
        fn reveal_path(&self, path: &Path) {
            self.revealed.lock().unwrap().push(path.to_path_buf());
        }
    }

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

    #[test]
    fn a_node_without_an_issuer_gives_the_built_in_stun_entry() {
        let turn = ice_for_receive(Err(TurnError::NotOffered), false).unwrap();
        assert_eq!(turn.own, default_stun());
        assert_eq!(turn.peer, default_stun());
        assert_eq!(turn.own.urls, vec!["stun:stun.cloudflare.com:3478"]);
        assert!(!turn.own.has_turn());
    }

    /// Hiding with nothing to hide behind ends before a pairing link is made:
    /// `open_receive` returns this error before it reaches `open_pairing`.
    #[test]
    fn hiding_without_a_turn_url_is_refused_before_any_link() {
        assert_eq!(
            ice_for_receive(Err(TurnError::NotOffered), true).unwrap_err(),
            "no_relay"
        );
        let stun_only = client::TurnCredentials {
            expires: 1_800_003_600,
            own: default_stun(),
            peer: default_stun(),
        };
        assert_eq!(
            ice_for_receive(Ok(stun_only.clone()), true).unwrap_err(),
            "no_relay"
        );
        assert!(ice_for_receive(Ok(stun_only), false).is_ok());
        let relay = |label: &str| IceServer {
            credential: "Y3JlZA".into(),
            urls: vec!["turn:turn.example.net:3478?transport=udp".into()],
            username: format!("1800003600:{label}"),
        };
        let with_turn = client::TurnCredentials {
            expires: 1_800_003_600,
            own: relay("b3du"),
            peer: relay("cGVlcg"),
        };
        assert!(ice_for_receive(Ok(with_turn), true).is_ok());
    }

    #[test]
    fn the_other_issuer_failures_keep_their_codes() {
        for (error, code) in [
            (TurnError::Unreachable, "node_unreachable"),
            (TurnError::Limited, "turn_limit"),
            (TurnError::Refused(403), "turn_refused"),
            (TurnError::Invalid, "turn_refused"),
        ] {
            assert_eq!(ice_for_receive(Err(error), false).unwrap_err(), code);
        }
    }

    #[tokio::test]
    async fn hiding_defaults_off_persists_and_shows_in_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, host) = engine(dir.path());
        assert!(!engine.receive_hide_address());
        assert_eq!(
            serde_json::to_value(engine.status()).unwrap()["receiving"],
            serde_json::json!({ "hideAddress": false, "folder": "~/Downloads/Wildbloom Received",
                                "maxBytes": 250_000_000 })
        );
        engine.set_receiving(true).unwrap();
        assert!(engine.receive_hide_address());
        assert!(
            host.statuses
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .receiving
                .hide_address
        );
        engine.set_receiving(false).unwrap();
        assert!(!engine.status().receiving.hide_address);
        // An unknown stored value reads as the default.
        engine.index.set(HIDE_ADDRESS, "maybe").unwrap();
        assert!(!engine.receive_hide_address());
        // A stored `off` from an earlier version stays off.
        engine.index.set(HIDE_ADDRESS, "off").unwrap();
        assert!(!engine.receive_hide_address());
    }

    #[tokio::test]
    async fn starting_needs_an_online_node_and_nothing_else_answers_without_a_receive() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _host) = engine(dir.path());
        assert_eq!(engine.receive_state().state, "idle");
        assert_eq!(engine.receive_start().unwrap_err().code, "node_unreachable");
        // Without a receive these are quiet no-ops or clear refusals.
        engine.receive_verify(true);
        engine.receive_consent(true);
        engine.receive_cancel();
        engine.direct_peer_report(PeerReport::Ready);
        assert_eq!(
            engine
                .direct_sink_write("t".into(), 0, vec![1])
                .await
                .unwrap_err()
                .code,
            "sink_failed"
        );
        assert_eq!(
            engine
                .direct_sink_end("t".into(), &"ab".repeat(32), 1)
                .await
                .unwrap_err()
                .code,
            "sink_failed"
        );
        assert_eq!(engine.receive_reveal("t").unwrap_err().code, "not_found");
        assert_eq!(
            engine.receive_add_to_wildbloom("t").await.unwrap_err().code,
            "not_found"
        );
        assert!(!engine.receive_open());
    }

    /// Turns the folder mirror on over `dir`'s Wildbloom folder.
    fn folder_on(engine: &Engine) {
        let id = "f".repeat(32);
        crate::drop::folder::write_marker(&engine.cfg.watch_dir, &id).unwrap();
        engine.index.set(kv::FOLDER_ID, &id).unwrap();
        engine.index.set_bool(kv::WATCH_ENABLED, true).unwrap();
    }

    fn receive(engine: &Engine, id: &str, name: &str, bytes: &[u8]) -> PathBuf {
        let dir = &engine.cfg.received_dir;
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        engine
            .direct
            .received
            .lock()
            .unwrap()
            .insert(id.into(), path.clone());
        path
    }

    #[tokio::test]
    async fn add_to_wildbloom_moves_without_replacing() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, host) = engine(dir.path());
        let path = receive(&engine, "a", "holiday.mp4", b"film");
        // The folder is off.
        assert_eq!(
            engine.receive_add_to_wildbloom("a").await.unwrap_err().code,
            "folder_off"
        );
        folder_on(&engine);
        // The folder has gone missing.
        std::fs::rename(&engine.cfg.watch_dir, dir.path().join("moved")).unwrap();
        assert_eq!(
            engine.receive_add_to_wildbloom("a").await.unwrap_err().code,
            "folder_unavailable"
        );
        std::fs::rename(dir.path().join("moved"), &engine.cfg.watch_dir).unwrap();
        std::fs::write(engine.cfg.watch_dir.join("holiday.mp4"), b"older").unwrap();
        let added = engine.receive_add_to_wildbloom("a").await.unwrap();
        assert_eq!(added.name, "holiday (2).mp4");
        assert_eq!(added.folder, "~/Wildbloom");
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(engine.cfg.watch_dir.join("holiday (2).mp4")).unwrap(),
            b"film"
        );
        assert_eq!(
            std::fs::read(engine.cfg.watch_dir.join("holiday.mp4")).unwrap(),
            b"older"
        );
        // Show follows the file to its new place.
        engine.receive_reveal("a").unwrap();
        assert_eq!(
            host.revealed.lock().unwrap().last().unwrap(),
            &engine.cfg.watch_dir.join("holiday (2).mp4")
        );
        // A file the mirror would never take in is refused.
        receive(&engine, "b", "empty.txt", b"");
        assert_eq!(
            engine.receive_add_to_wildbloom("b").await.unwrap_err().code,
            "cannot_sync"
        );
        receive(&engine, "c", "film.part", b"x");
        assert_eq!(
            engine.receive_add_to_wildbloom("c").await.unwrap_err().code,
            "cannot_sync"
        );
        // A received file that has gone is not found.
        let gone = receive(&engine, "d", "gone.txt", b"x");
        std::fs::remove_file(gone).unwrap();
        assert_eq!(
            engine.receive_add_to_wildbloom("d").await.unwrap_err().code,
            "not_found"
        );
    }

    #[tokio::test]
    async fn kept_states_show_the_received_folder_and_whether_add_can_run() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _host) = engine(dir.path());
        let mut state = ReceiveState::new("kept");
        state.id = Some("AAECAwQFBgcICQoLDA0ODw".into());
        state.path = Some(
            engine
                .cfg
                .received_dir
                .join("a (2).txt")
                .display()
                .to_string(),
        );
        engine.decorate_kept(&mut state);
        assert_eq!(
            state.path.as_deref(),
            Some(
                format!(
                    "~/Downloads/Wildbloom Received{}a (2).txt",
                    std::path::MAIN_SEPARATOR
                )
                .as_str()
            )
        );
        assert_eq!(
            state.folder.as_deref(),
            Some("~/Downloads/Wildbloom Received")
        );
        assert_eq!(state.can_add, Some(false));
        folder_on(&engine);
        engine.decorate_kept(&mut state);
        assert_eq!(state.can_add, Some(true));
        assert!(
            engine
                .direct
                .received
                .lock()
                .unwrap()
                .contains_key("AAECAwQFBgcICQoLDA0ODw")
        );
    }

    #[tokio::test]
    async fn a_receive_that_has_ended_does_not_hold_up_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, host) = engine(dir.path());
        // A session still tidying up after its final state.
        let (controls, _inputs) = session::controls();
        let task = tokio::spawn(std::future::pending::<()>());
        *engine.direct.running.lock().unwrap() = Some(Running {
            generation: 7,
            task,
            controls: controls.clone(),
        });
        assert!(engine.receive_open());
        assert_eq!(engine.receive_start().unwrap_err().code, "busy");
        controls.mark_finished();
        assert!(!engine.receive_open());
        // Past the busy check: here there is no online node.
        assert_eq!(engine.receive_start().unwrap_err().code, "node_unreachable");
        // The hidden window's reports still reach it while it tidies up.
        assert!(engine.running_controls().is_some());
        // An older receive's states are not shown once another is current.
        let old = EngineHost {
            engine: engine.clone(),
            generation: 6,
        };
        old.emit(&ReceiveState::failed("lost"));
        assert!(host.receives.lock().unwrap().is_empty());
        assert_eq!(engine.receive_state().state, "idle");
        let current = EngineHost {
            engine: engine.clone(),
            generation: 7,
        };
        current.emit(&ReceiveState::failed("lost"));
        assert_eq!(host.receives.lock().unwrap().len(), 1);
        assert_eq!(engine.receive_state().reason, Some("lost"));
    }

    #[tokio::test]
    async fn the_received_folder_is_made_and_shown() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = tempfile::tempdir().unwrap();
        // A folder that cannot be made: a file stands where Downloads would be.
        std::fs::write(blocked.path().join("Downloads"), b"in the way").unwrap();
        let (fresh, fresh_host) = engine(dir.path());
        let (stuck, stuck_host) = engine(blocked.path());
        assert!(!fresh.cfg.received_dir.exists());
        fresh.reveal_received_folder().unwrap();
        assert!(fresh.cfg.received_dir.is_dir());
        assert_eq!(
            fresh_host.revealed.lock().unwrap().last(),
            Some(&fresh.cfg.received_dir)
        );
        // Again, with the folder there: shown again, nothing else changes.
        fresh.reveal_received_folder().unwrap();
        assert_eq!(fresh_host.revealed.lock().unwrap().len(), 2);
        // Refused, and nothing is shown.
        assert_eq!(
            stuck.reveal_received_folder().unwrap_err().code,
            "received_folder"
        );
        assert!(stuck_host.revealed.lock().unwrap().is_empty());
    }

    #[test]
    fn display_paths_use_a_tilde_under_home() {
        let home = Path::new("/home/someone");
        let path = home.join("Downloads").join("Wildbloom Received");
        if cfg!(windows) {
            assert_eq!(display_path(&path, Some(home)), path.display().to_string());
        } else {
            assert_eq!(
                display_path(&path, Some(home)),
                "~/Downloads/Wildbloom Received"
            );
            assert_eq!(display_path(Path::new("/srv/in"), Some(home)), "/srv/in");
        }
    }
}
