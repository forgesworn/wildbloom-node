//! The Tauri side of Drop: the commands in `ui/DROP-IPC.md`, and the host the
//! engine emits events through.  Commands are async so keychain access and
//! dialogs never run on the main thread.

use super::client::NodeEndpoint;
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

impl Host for TauriHost {
    fn emit_file(&self, row: &FileRow) {
        let _ = self.app.emit("drop://file", row);
    }

    fn emit_removed(&self, id: &str) {
        let _ = self.app.emit(
            "drop://file",
            RemovedRow {
                id: id.to_owned(),
                removed: true,
            },
        );
    }

    fn emit_status(&self, status: &DropStatus, line: &StatusLine) {
        let _ = self.app.emit("drop://status", status);
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
    let mut result = engine(&slot)?.add_paths(dropped, None).await?;
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
    engine(&slot)?.set_watch_folder(enabled)
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
