//! The Tauri side of Drop: the commands in `ui/DROP-IPC.md`, and the host the
//! engine emits events through.  Commands are async so keychain access and
//! dialogs never run on the main thread.

use super::client::NodeEndpoint;
use super::direct::awake::Awake;
use super::direct::{
    AddedToWildbloom, PEER_PAGE, PEER_WINDOW, PeerReport, PeerRequest, ReceiveState,
};
use super::engine::{Engine, Host, LocalNode};
use super::status::{StatusLine, Tone};
use super::types::*;
use crate::{NodeManager, Settings, Transport};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tauri::{AppHandle, Emitter, Manager, State, Wry};
use tauri_plugin_dialog::DialogExt as _;

/// The engine, filled in during set-up.
#[derive(Default)]
pub struct DropSlot(pub OnceLock<Arc<Engine>>);

/// The hidden direct-send window's request channel.  The window attaches it
/// with `direct_peer_attach` before it reports `ready`; every request goes
/// through it, so requests reach that one webview and no other.  The window
/// has no event permission at all, so it hears none of the app's events.
#[derive(Default)]
pub struct PeerChannel(std::sync::Mutex<Option<tauri::ipc::Channel<PeerRequest>>>);

impl PeerChannel {
    fn set(&self, channel: Option<tauri::ipc::Channel<PeerRequest>>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = channel;
    }

    fn attached(&self) -> bool {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Sends one request; dropped when no window is attached, which cannot
    /// happen while a session runs, since Rust sends nothing before `ready`
    /// and `ready` is refused until the channel is attached.
    fn send(&self, request: &PeerRequest) {
        let channel = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(channel) = channel {
            let _ = channel.send(request.clone());
        }
    }
}

/// Paths the operating system handed over in a native drop on the Drop
/// window.  `add_paths` accepts only these, so the webview cannot name an
/// arbitrary file for Drop to read and copy.
#[derive(Default)]
pub struct NativeDrops(std::sync::Mutex<Vec<(PathBuf, std::time::Instant)>>);

/// How long a dropped path stays acceptable to `add_paths`.
const DROP_WINDOW_SECONDS: u64 = 60;

impl NativeDrops {
    pub fn record(&self, paths: &[PathBuf]) {
        let mut recent = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        recent.retain(|(_, at)| now.duration_since(*at).as_secs() < DROP_WINDOW_SECONDS);
        recent.extend(paths.iter().map(|p| (p.clone(), now)));
    }

    /// Splits `paths` into those from a recent native drop (taken, so each
    /// drop is used once) and the rest.
    fn take(&self, paths: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let mut recent = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        recent.retain(|(_, at)| now.duration_since(*at).as_secs() < DROP_WINDOW_SECONDS);
        let (mut ok, mut refused) = (Vec::new(), Vec::new());
        for path in paths {
            if let Some(at) = recent.iter().position(|(p, _)| *p == path) {
                recent.swap_remove(at);
                ok.push(path);
            } else {
                refused.push(path);
            }
        }
        (ok, refused)
    }
}

/// Tray items that follow the status line.
pub struct TrayItems {
    pub status: tauri::menu::MenuItem<Wry>,
    pub folder: tauri::menu::MenuItem<Wry>,
    pub tray: tauri::tray::TrayIcon<Wry>,
}

fn engine(slot: &State<'_, DropSlot>) -> CommandResult<Arc<Engine>> {
    slot.0
        .get()
        .cloned()
        .ok_or_else(|| CommandError::with_message("starting", "Wildbloom Drop is starting."))
}

pub struct TauriHost {
    pub app: AppHandle,
    pub manager: Arc<NodeManager>,
}

impl TauriHost {
    fn update_tray(&self, status: &DropStatus, line: &StatusLine) {
        let Some(items) = self.app.try_state::<TrayItems>() else {
            return;
        };
        let _ = items.status.set_text(&line.text);
        let _ = items.folder.set_enabled(status.watch_folder.enabled);
        let tip = format!("Wildbloom Node: {}", line.text);
        let _ = items.tray.set_tooltip(Some(&tip));
        let title = match line.tone {
            Tone::Normal => None,
            Tone::Busy => Some("\u{2191}"),
            Tone::Attention => Some("!"),
        };
        // macOS shows a short title beside the icon; elsewhere it is ignored.
        #[cfg(target_os = "macos")]
        let _ = items.tray.set_title(title);
        #[cfg(not(target_os = "macos"))]
        let _ = title;
    }
}

/// The windows that show the folder's files and status.  File rows and the
/// status carry the owner's and device's npubs, the node URL, the folder
/// path and file names, so they go only to the windows that listen for them
/// (the Drop window, and the node window for the status), never as a
/// broadcast that reaches the hidden direct-send window.
const FILE_WINDOWS: [&str; 1] = ["drop"];
const STATUS_WINDOWS: [&str; 2] = ["drop", "main"];

impl TauriHost {
    fn forget_peer_channel(&self) {
        if let Some(channel) = self.app.try_state::<PeerChannel>() {
            channel.set(None);
        }
    }
}

impl Host for TauriHost {
    fn emit_file(&self, row: &FileRow) {
        for window in FILE_WINDOWS {
            let _ = self.app.emit_to(window, "drop://file", row);
        }
    }

    fn emit_removed(&self, id: &str) {
        let row = RemovedRow {
            id: id.to_owned(),
            removed: true,
        };
        for window in FILE_WINDOWS {
            let _ = self.app.emit_to(window, "drop://file", &row);
        }
    }

    fn emit_status(&self, status: &DropStatus, line: &StatusLine) {
        for window in STATUS_WINDOWS {
            let _ = self.app.emit_to(window, "drop://status", status);
        }
        self.update_tray(status, line);
    }

    fn emit_share(&self, state: &ShareState) {
        // Links and words only ever go to the Drop window.
        let _ = self.app.emit_to("drop", "share://state", state);
    }

    fn local_node(&self) -> LocalNode {
        let Ok(status) = self.manager.status.read() else {
            return LocalNode {
                state: "error",
                endpoint: None,
            };
        };
        let state = match status.phase {
            "ready" | "starting" => "ok",
            "error" => "error",
            _ => "stopped",
        };
        let endpoint = match (status.phase, status.local_port, &status.public_url) {
            ("ready", Some(port), Some(public)) => {
                let server = url::Url::parse(public)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned));
                match (
                    url::Url::parse(&format!("http://127.0.0.1:{port}/")),
                    server,
                ) {
                    (Ok(base), Some(server)) => Some(NodeEndpoint::with_server(base, server)),
                    _ => None,
                }
            }
            _ => None,
        };
        LocalNode { state, endpoint }
    }

    fn trust_changed(&self) {
        if !self.node_settings_exist() {
            return;
        }
        let app = self.app.clone();
        let manager = self.manager.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = crate::start_runtime(app, manager.clone()).await {
                let generation = manager.status.read().map(|s| s.generation).unwrap_or(0);
                crate::set_error(&manager, generation, error);
            }
        });
    }

    fn node_settings_exist(&self) -> bool {
        crate::settings_path(&self.app).is_ok_and(|path| path.is_file())
    }

    fn ensure_node_settings(&self) -> Result<(), String> {
        if self.node_settings_exist() {
            return Ok(());
        }
        // Q10: direct mode with no public URL binds to loopback and starts no
        // Tor.  Mirroring is a push from this computer, so nothing needs to
        // reach the local node.
        let settings = Settings {
            transport: Transport::Direct,
            direct_public_url: None,
            ..Settings::default()
        };
        crate::write_settings(&self.app, &settings)?;
        self.trust_changed();
        Ok(())
    }

    fn pick_save_path(&self, suggested_name: &str) -> Option<PathBuf> {
        self.app
            .dialog()
            .file()
            .set_file_name(suggested_name)
            .blocking_save_file()
            .and_then(|path| path.into_path().ok())
    }

    fn pick_files(&self) -> Vec<PathBuf> {
        self.app
            .dialog()
            .file()
            .blocking_pick_files()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|path| path.into_path().ok())
            .collect()
    }

    fn open_folder(&self, path: &Path) {
        let program = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(windows) {
            "explorer"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(program).arg(path).spawn();
    }

    fn trash(&self, path: &Path) -> std::io::Result<()> {
        #[allow(unused_mut)]
        let mut context = trash::TrashContext::default();
        // The Finder method goes through AppleScript and asks for Automation
        // permission; NSFileManager does not.
        #[cfg(target_os = "macos")]
        {
            use trash::macos::{DeleteMethod, TrashContextExtMacos as _};
            context.set_delete_method(DeleteMethod::NsFileManager);
        }
        // The error text names the path, so it is not passed on.
        context
            .delete(path)
            .map_err(|_| std::io::Error::other("could not move the file to the Trash"))
    }

    fn open_path(&self, path: &Path) {
        // Each program takes the path as its own argument; no shell runs.
        let program = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(windows) {
            "explorer"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(program).arg(path).spawn();
    }

    fn reveal_path(&self, path: &Path) {
        let mut command = if cfg!(target_os = "macos") {
            let mut command = std::process::Command::new("open");
            command.arg("-R").arg(path);
            command
        } else if cfg!(windows) {
            let mut command = std::process::Command::new("explorer");
            command.arg("/select,").arg(path);
            command
        } else {
            // No portable "select this file"; open its folder instead.
            let mut command = std::process::Command::new("xdg-open");
            command.arg(path.parent().unwrap_or(path));
            command
        };
        let _ = command.spawn();
    }

    fn emit_receive(&self, state: &ReceiveState) {
        // Links and words only ever go to the Drop window.
        let _ = self.app.emit_to(DROP_WINDOW, "receive://state", state);
    }

    fn open_peer_window(&self) -> bool {
        // One transfer at a time: a window left from an earlier one goes,
        // and so does its channel.
        self.forget_peer_channel();
        if let Some(old) = self.app.get_webview_window(PEER_WINDOW) {
            let _ = old.destroy();
        }
        tauri::WebviewWindowBuilder::new(
            &self.app,
            PEER_WINDOW,
            tauri::WebviewUrl::App(PEER_PAGE.into()),
        )
        .title("Wildbloom Drop connection")
        .visible(false)
        .focused(false)
        .skip_taskbar(true)
        .build()
        .is_ok()
    }

    fn peer_request(&self, request: &PeerRequest) {
        // Through the window's own channel, never an event: an event sent
        // to one window still reaches any window listening for every target.
        if let Some(channel) = self.app.try_state::<PeerChannel>() {
            channel.send(request);
        }
    }

    fn close_peer_window(&self) {
        self.forget_peer_channel();
        if let Some(window) = self.app.get_webview_window(PEER_WINDOW) {
            let _ = window.destroy();
        }
    }

    fn keep_awake(&self) -> Awake {
        Awake::hold()
    }
}

/// The Drop window's label.
const DROP_WINDOW: &str = "drop";

/// Each receive command answers only the window that owns it, as the
/// capability files already require.
fn only(webview: &tauri::Webview, label: &str) -> CommandResult<()> {
    if webview.label() == label {
        Ok(())
    } else {
        Err(CommandError::code("wrong_window"))
    }
}

// ------------------------------------------------------------- commands

#[tauri::command]
pub async fn platform_info(slot: State<'_, DropSlot>) -> CommandResult<PlatformInfo> {
    Ok(engine(&slot)?.platform_info())
}

#[tauri::command]
pub async fn drop_status(
    slot: State<'_, DropSlot>,
    recheck: Option<String>,
) -> CommandResult<DropSnapshot> {
    Ok(engine(&slot)?.drop_status(recheck.as_deref()).await)
}

#[tauri::command]
pub async fn add_paths(
    slot: State<'_, DropSlot>,
    drops: State<'_, NativeDrops>,
    paths: Vec<String>,
) -> CommandResult<AddResult> {
    let (mut dropped, mut refused) = drops.take(paths.into_iter().map(PathBuf::from).collect());
    if !refused.is_empty() {
        // The page's drop event can race the window event that records it.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let (late, still) = drops.take(refused);
        dropped.extend(late);
        refused = still;
    }
    let mut result = engine(&slot)?.add_paths(dropped).await?;
    for path in refused {
        result.refused.push(Refused {
            name: wildbloom_envelope::sanitise_name(
                &path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
            reason: "unreadable",
            limit_bytes: None,
        });
    }
    Ok(result)
}

#[tauri::command]
pub async fn pick_files(slot: State<'_, DropSlot>) -> CommandResult<AddResult> {
    engine(&slot)?.pick_files().await
}

#[tauri::command]
pub async fn retry(slot: State<'_, DropSlot>, id: Option<String>) -> CommandResult<()> {
    engine(&slot)?.retry(id.as_deref())
}

#[tauri::command]
pub async fn copy_back(slot: State<'_, DropSlot>, id: String) -> CommandResult<()> {
    engine(&slot)?.copy_back(&id)
}

#[tauri::command]
pub async fn save_copy(slot: State<'_, DropSlot>, id: String) -> CommandResult<Option<SavedCopy>> {
    // The save dialog is always Rust's: the webview never names a path.
    match engine(&slot)?.save_copy(&id, None).await {
        Err(error) if error.code == "cancelled" => Ok(None),
        other => other.map(Some),
    }
}

#[tauri::command]
pub async fn remove(slot: State<'_, DropSlot>, id: String) -> CommandResult<()> {
    engine(&slot)?.remove(&id).await
}

/// The owner's choice for deletions from the Wildbloom folder that the
/// mass-removal brake held back: `remove` or `put_back`, for these rows.
#[tauri::command]
pub async fn resolve_held_removals(
    slot: State<'_, DropSlot>,
    ids: Vec<String>,
    choice: String,
) -> CommandResult<HeldResolved> {
    engine(&slot)?.resolve_held_removals(&ids, &choice).await
}

#[tauri::command]
pub async fn check_online_node(slot: State<'_, DropSlot>, url: String) -> CommandResult<NodeCheck> {
    engine(&slot)?.check_online_node(&url).await
}

#[tauri::command]
pub async fn set_online_node(slot: State<'_, DropSlot>, url: Option<String>) -> CommandResult<()> {
    engine(&slot)?.set_online_node(url.as_deref()).await
}

#[tauri::command]
pub async fn approve_device(
    slot: State<'_, DropSlot>,
    bunker_url: Option<String>,
    browser: Option<bool>,
) -> CommandResult<()> {
    engine(&slot)?.approve_device(bunker_url.as_deref(), browser.unwrap_or(false))
}

#[tauri::command]
pub async fn renew_approval(
    slot: State<'_, DropSlot>,
    bunker_url: Option<String>,
    browser: Option<bool>,
) -> CommandResult<()> {
    engine(&slot)?.approve_device(bunker_url.as_deref(), browser.unwrap_or(false))
}

#[tauri::command]
pub async fn approval_status(slot: State<'_, DropSlot>) -> CommandResult<ApprovalStatus> {
    engine(&slot)?.approval_status()
}

#[tauri::command]
pub async fn cancel_approval(slot: State<'_, DropSlot>) -> CommandResult<()> {
    engine(&slot)?.cancel_approval()
}

#[tauri::command]
pub async fn recovery_key_for_display(
    slot: State<'_, DropSlot>,
) -> CommandResult<RecoveryKeyDisplay> {
    engine(&slot)?.recovery_key_for_display()
}

#[tauri::command]
pub async fn save_recovery_file(
    slot: State<'_, DropSlot>,
) -> CommandResult<Option<SavedRecoveryFile>> {
    let engine = engine(&slot)?;
    match tokio::task::spawn_blocking(move || engine.save_recovery_file(None))
        .await
        .map_err(|_| CommandError::code("internal"))?
    {
        Err(error) if error.code == "cancelled" => Ok(None),
        other => other.map(Some),
    }
}

/// From the node window: open a Drop flow (`recovery`, to save the
/// recovery key again) in the Drop window, which alone may read the key.
#[tauri::command]
pub async fn open_drop_flow(app: AppHandle, flow: String) -> CommandResult<()> {
    if flow != "recovery" {
        return Err(CommandError::code("bad_flow"));
    }
    if let Some(window) = app.get_webview_window("drop") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    app.emit_to("drop", "drop://open-flow", OpenFlow { flow: "recovery" })
        .map_err(|_| CommandError::code("internal"))
}

#[tauri::command]
pub async fn confirm_recovery_saved(slot: State<'_, DropSlot>) -> CommandResult<()> {
    engine(&slot)?.confirm_recovery_saved()
}

#[tauri::command]
pub async fn restore(
    slot: State<'_, DropSlot>,
    recovery_key: Option<String>,
    recovery_file: Option<String>,
    url: Option<String>,
) -> CommandResult<RestoreResult> {
    let key = recovery_key.map(zeroize::Zeroizing::new);
    engine(&slot)?
        .restore(
            key.as_deref().map(String::as_str),
            recovery_file.map(PathBuf::from),
            url.as_deref(),
        )
        .await
}

#[tauri::command]
pub async fn set_watch_folder(slot: State<'_, DropSlot>, enabled: bool) -> CommandResult<()> {
    engine(&slot)?.set_watch_folder(enabled).await
}

/// From the node window's settings: what happens to a shared copy after a
/// confirmed download, and how long a sent copy stays.  `expirySeconds` is
/// taken as any JSON value so that a non-integer is the typed `bad_setting`
/// rejection rather than an argument error.
#[tauri::command]
pub async fn set_sharing(
    slot: State<'_, DropSlot>,
    after_download: String,
    expiry_seconds: serde_json::Value,
) -> CommandResult<()> {
    engine(&slot)?.set_sharing(&after_download, expiry_seconds.as_u64())
}

#[tauri::command]
pub async fn open_file(slot: State<'_, DropSlot>, id: String) -> CommandResult<()> {
    engine(&slot)?.open_file(&id)
}

#[tauri::command]
pub async fn reveal_file(slot: State<'_, DropSlot>, id: String) -> CommandResult<()> {
    engine(&slot)?.reveal_file(&id)
}

#[tauri::command]
pub async fn open_watch_folder(slot: State<'_, DropSlot>) -> CommandResult<()> {
    engine(&slot)?.open_watch_folder()
}

#[tauri::command]
pub async fn share_start(slot: State<'_, DropSlot>, id: String) -> CommandResult<ShareState> {
    engine(&slot)?.share_start(&id, false)
}

#[tauri::command]
pub async fn share_again(slot: State<'_, DropSlot>, id: String) -> CommandResult<ShareState> {
    engine(&slot)?.share_start(&id, true)
}

#[tauri::command]
pub async fn share_verify(
    slot: State<'_, DropSlot>,
    id: String,
    matches: bool,
) -> CommandResult<Option<ShareState>> {
    engine(&slot)?.share_verify(&id, matches)
}

#[tauri::command]
pub async fn share_cancel(slot: State<'_, DropSlot>, id: String) -> CommandResult<()> {
    engine(&slot)?.share_cancel(&id).await
}

#[tauri::command]
pub async fn stop_sharing(slot: State<'_, DropSlot>, id: String) -> CommandResult<()> {
    engine(&slot)?.stop_sharing(&id).await
}

// ----------------------------------------------------------- receiving

#[tauri::command]
pub async fn receive_start(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
) -> CommandResult<ReceiveState> {
    only(&webview, DROP_WINDOW)?;
    engine(&slot)?.receive_start()
}

#[tauri::command]
pub async fn receive_state(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
) -> CommandResult<ReceiveState> {
    only(&webview, DROP_WINDOW)?;
    Ok(engine(&slot)?.receive_state())
}

#[tauri::command]
pub async fn receive_verify(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    matches: bool,
) -> CommandResult<()> {
    only(&webview, DROP_WINDOW)?;
    engine(&slot)?.receive_verify(matches);
    Ok(())
}

#[tauri::command]
pub async fn receive_consent(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    accept: bool,
) -> CommandResult<()> {
    only(&webview, DROP_WINDOW)?;
    engine(&slot)?.receive_consent(accept);
    Ok(())
}

#[tauri::command]
pub async fn receive_cancel(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
) -> CommandResult<()> {
    only(&webview, DROP_WINDOW)?;
    engine(&slot)?.receive_cancel();
    Ok(())
}

#[tauri::command]
pub async fn receive_add_to_wildbloom(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    id: String,
) -> CommandResult<AddedToWildbloom> {
    only(&webview, DROP_WINDOW)?;
    engine(&slot)?.receive_add_to_wildbloom(&id).await
}

#[tauri::command]
pub async fn receive_reveal(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    id: String,
) -> CommandResult<()> {
    only(&webview, DROP_WINDOW)?;
    engine(&slot)?.receive_reveal(&id)
}

/// From the node window's settings: hide this computer's address behind the
/// relay when receiving (the default).
#[tauri::command]
pub async fn set_receiving(slot: State<'_, DropSlot>, hide_address: bool) -> CommandResult<()> {
    engine(&slot)?.set_receiving(hide_address)
}

/// From the node window's settings: shows the Received folder, making it
/// first when nothing has arrived yet.
#[tauri::command]
pub async fn reveal_received_folder(slot: State<'_, DropSlot>) -> CommandResult<()> {
    engine(&slot)?.reveal_received_folder()
}

/// From the hidden window, once at start-up and before `ready`: the channel
/// its requests arrive on.  Replaces any earlier one.
#[tauri::command]
pub async fn direct_peer_attach(
    peer: State<'_, PeerChannel>,
    webview: tauri::Webview,
    channel: tauri::ipc::Channel<PeerRequest>,
) -> CommandResult<()> {
    only(&webview, PEER_WINDOW)?;
    peer.set(Some(channel));
    Ok(())
}

/// From the hidden window: replies, state changes and the transfer's end.
/// `ready` is refused `{ code: "no_channel" }` until the window has attached
/// its channel, so Rust never sends a request with nowhere to go.
#[tauri::command]
pub async fn direct_peer_report(
    slot: State<'_, DropSlot>,
    peer: State<'_, PeerChannel>,
    webview: tauri::Webview,
    report: PeerReport,
) -> CommandResult<()> {
    only(&webview, PEER_WINDOW)?;
    if report == PeerReport::Ready && !peer.attached() {
        return Err(CommandError::code("no_channel"));
    }
    engine(&slot)?.direct_peer_report(report);
    Ok(())
}

/// From the hidden window: one DATA frame's bytes as the raw request body,
/// with the transfer in `Wildbloom-Transfer` and the envelope offset in
/// `Wildbloom-Offset`.  Resolves once they are written; the window sends the
/// ACK only then.
#[tauri::command]
pub async fn direct_sink_write(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    request: tauri::ipc::Request<'_>,
) -> CommandResult<()> {
    only(&webview, PEER_WINDOW)?;
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err(CommandError::code("sink_failed"));
    };
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let (Some(transfer), Some(offset)) = (
        header("wildbloom-transfer"),
        header("wildbloom-offset").and_then(|v| v.parse::<u64>().ok()),
    ) else {
        return Err(CommandError::code("sink_failed"));
    };
    engine(&slot)?
        .direct_sink_write(transfer, offset, bytes.clone())
        .await
}

/// From the hidden window: END's SHA-256 (lower-case hex) and size.
/// Resolves once the file is verified and kept (send KEPT); rejects
/// `sink_failed` (send STOP 2) or `sink_storage` (send STOP 3).
#[tauri::command]
pub async fn direct_sink_end(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    transfer: String,
    sha256: String,
    size: u64,
) -> CommandResult<()> {
    only(&webview, PEER_WINDOW)?;
    engine(&slot)?
        .direct_sink_end(transfer, &sha256, size)
        .await
}

/// From the hidden window: delete what the sink holds.  Safe to repeat.
#[tauri::command]
pub async fn direct_sink_abort(
    slot: State<'_, DropSlot>,
    webview: tauri::Webview,
    transfer: String,
) -> CommandResult<()> {
    only(&webview, PEER_WINDOW)?;
    engine(&slot)?.direct_sink_abort(transfer).await;
    Ok(())
}

/// What a drag over the Drop window carries, for the overlay copy.
pub fn drag_info(paths: &[PathBuf], drop_max_bytes: u64) -> DragInfo {
    let mut info = DragInfo {
        files: 0,
        folders: 0,
        too_big: 0,
    };
    for path in paths {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_dir() => info.folders += 1,
            Ok(meta) => {
                info.files += 1;
                if meta.len() > drop_max_bytes {
                    info.too_big += 1;
                }
            }
            Err(_) => info.files += 1,
        }
    }
    info
}

/// The computer's name for the recovery file.
pub fn computer_name() -> String {
    #[cfg(target_os = "macos")]
    if let Ok(output) = std::process::Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
        && output.status.success()
    {
        let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !name.is_empty() {
            return name;
        }
    }
    if let Ok(name) = std::env::var("COMPUTERNAME") {
        return name;
    }
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this computer".into())
}

#[cfg(test)]
mod tests {
    use super::super::direct::PeerOp;
    use super::*;
    use std::sync::Mutex;
    use tauri::ipc::{Channel, InvokeResponseBody};

    fn request(seq: u64) -> PeerRequest {
        PeerRequest {
            transfer: "t".into(),
            seq,
            op: PeerOp::Offer,
        }
    }

    fn recording() -> (Channel<PeerRequest>, Arc<Mutex<Vec<serde_json::Value>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        let channel = Channel::new(move |body| {
            let InvokeResponseBody::Json(json) = body else {
                panic!("a request is JSON");
            };
            into.lock()
                .unwrap()
                .push(serde_json::from_str(&json).unwrap());
            Ok(())
        });
        (channel, seen)
    }

    #[test]
    fn requests_go_only_through_the_attached_channel() {
        let peer = PeerChannel::default();
        assert!(!peer.attached());
        peer.send(&request(1)); // nowhere to go: dropped

        let (first, first_seen) = recording();
        peer.set(Some(first));
        assert!(peer.attached());
        peer.send(&request(2));
        assert_eq!(
            *first_seen.lock().unwrap(),
            [serde_json::json!({ "transfer": "t", "seq": 2, "op": "offer" })]
        );

        // A later attach replaces the earlier channel.
        let (second, second_seen) = recording();
        peer.set(Some(second));
        peer.send(&request(3));
        assert_eq!(first_seen.lock().unwrap().len(), 1);
        assert_eq!(second_seen.lock().unwrap().len(), 1);

        // Closing the window forgets it.
        peer.set(None);
        assert!(!peer.attached());
        peer.send(&request(4));
        assert_eq!(second_seen.lock().unwrap().len(), 1);
    }

    /// Every capability that reaches the hidden direct-send window, and what
    /// it grants.  The window faces a stranger's phone, so it must hear none
    /// of the app's events and may call only its own commands.
    #[test]
    fn the_direct_window_has_no_event_permission() {
        let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
        let mut granted = Vec::new();
        for entry in std::fs::read_dir(folder).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let file = std::fs::read_to_string(&path).unwrap();
            let capability: serde_json::Value = serde_json::from_str(&file).unwrap();
            let windows = capability["windows"].as_array().unwrap();
            if windows
                .iter()
                .any(|w| w == PEER_WINDOW || w.as_str().is_some_and(|w| w.contains('*')))
            {
                for permission in capability["permissions"].as_array().unwrap() {
                    let id = permission
                        .as_str()
                        .or_else(|| permission["identifier"].as_str())
                        .unwrap();
                    granted.push(id.to_owned());
                }
            }
        }
        granted.sort();
        assert_eq!(
            granted,
            [
                "allow-direct-peer-attach",
                "allow-direct-peer-report",
                "allow-direct-sink-abort",
                "allow-direct-sink-end",
                "allow-direct-sink-write",
            ]
        );
    }
}
