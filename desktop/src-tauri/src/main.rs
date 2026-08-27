use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tauri::{
    AppHandle, Manager, State, WindowEvent,
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as _};
use tauri_plugin_shell::{
    ShellExt as _,
    process::{CommandChild, CommandEvent},
};
use tauri_plugin_updater::UpdaterExt as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Settings {
    allowed_pubkey: Option<String>,
    quota_gib: u64,
    start_at_login: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allowed_pubkey: None,
            quota_gib: 10,
            start_at_login: false,
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeStatus {
    generation: u64,
    phase: &'static str,
    detail: String,
    onion_url: Option<String>,
    local_port: Option<u16>,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            generation: 0,
            phase: "starting",
            detail: "Preparing the private Tor service.".into(),
            onion_url: None,
            local_port: None,
        }
    }
}

#[derive(Debug, Default)]
struct Children {
    tor: Option<CommandChild>,
    node: Option<CommandChild>,
}

#[derive(Debug)]
struct NodeManager {
    children: Mutex<Children>,
    status: RwLock<RuntimeStatus>,
    operation: tokio::sync::Mutex<()>,
}

impl Default for NodeManager {
    fn default() -> Self {
        Self {
            children: Mutex::new(Children::default()),
            status: RwLock::new(RuntimeStatus::default()),
            operation: tokio::sync::Mutex::new(()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    storage: HealthStorage,
}

#[derive(Debug, Deserialize)]
struct HealthStorage {
    blobs: u64,
    bytes: u64,
    quota_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StorageStatus {
    blobs: u64,
    bytes: u64,
    quota_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeStatus {
    phase: &'static str,
    phase_label: &'static str,
    detail: String,
    onion_url: Option<String>,
    storage: Option<StorageStatus>,
    settings: Settings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateStatus {
    available: bool,
    version: Option<String>,
}

#[tauri::command]
async fn node_status(
    app: AppHandle,
    manager: State<'_, Arc<NodeManager>>,
) -> Result<NodeStatus, String> {
    let current = manager
        .status
        .read()
        .map_err(|_| "node status lock failed")?
        .clone();
    let settings = read_settings(&app)?;
    let storage = if current.phase == "ready" {
        match current.local_port {
            Some(port) => fetch_health(port).await.ok(),
            None => None,
        }
    } else {
        None
    };
    Ok(NodeStatus {
        phase: current.phase,
        phase_label: phase_label(current.phase),
        detail: current.detail,
        onion_url: current.onion_url,
        storage,
        settings,
    })
}

#[tauri::command]
async fn save_settings(
    app: AppHandle,
    manager: State<'_, Arc<NodeManager>>,
    settings: Settings,
) -> Result<(), String> {
    validate_settings(&settings)?;
    write_settings(&app, &settings)?;
    let autostart = app.autolaunch();
    if settings.start_at_login {
        autostart.enable().map_err(|error| error.to_string())?;
    } else {
        autostart.disable().map_err(|error| error.to_string())?;
    }
    start_runtime(app, manager.inner().clone()).await
}

#[tauri::command]
async fn restart_node(app: AppHandle, manager: State<'_, Arc<NodeManager>>) -> Result<(), String> {
    start_runtime(app, manager.inner().clone()).await
}

#[tauri::command]
async fn check_for_update(app: AppHandle) -> Result<UpdateStatus, String> {
    let update = app
        .updater()
        .map_err(|error| format!("could not initialise the signed updater: {error}"))?
        .check()
        .await
        .map_err(|error| format!("could not check for a signed update: {error}"))?;
    Ok(UpdateStatus {
        version: update.as_ref().map(|available| available.version.clone()),
        available: update.is_some(),
    })
}

#[tauri::command]
async fn install_update(app: AppHandle) -> Result<(), String> {
    let updater = app
        .updater()
        .map_err(|error| format!("could not initialise the signed updater: {error}"))?;
    let update = updater
        .check()
        .await
        .map_err(|error| format!("could not check for a signed update: {error}"))?
        .ok_or("Wildbloom Node is already up to date")?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| format!("could not install the signed update: {error}"))?;
    app.restart();
}

async fn start_runtime(app: AppHandle, manager: Arc<NodeManager>) -> Result<(), String> {
    let _operation = manager.operation.lock().await;
    stop_children(&manager);
    let settings = read_settings(&app)?;
    validate_settings(&settings)?;
    let generation = {
        let mut status = manager
            .status
            .write()
            .map_err(|_| "node status lock failed")?;
        status.generation = status.generation.saturating_add(1);
        status.phase = "starting";
        status.detail = "Bootstrapping a private Tor service.".into();
        status.onion_url = None;
        status.local_port = None;
        status.generation
    };
    let data_dir = node_data_dir(&app)?;
    let tor_root = data_dir.join("tor");
    let tor_data = tor_root.join("client");
    let onion_dir = tor_root.join("onion-service");
    let torrc = tor_root.join("torrc");
    create_private_dir(&tor_root)?;
    create_private_dir(&tor_data)?;
    create_private_dir(&onion_dir)?;
    fs::write(
        &torrc,
        b"# This Tor instance is managed by Wildbloom Node.\n",
    )
    .map_err(|error| format!("could not write the private Tor configuration: {error}"))?;
    set_private_file(&torrc)?;
    let node_port = free_port()?;
    let socks_port = free_port()?;
    let target = format!("127.0.0.1:{node_port}");
    let tor_runtime = app
        .path()
        .resource_dir()
        .map_err(|error| format!("could not locate the bundled Tor runtime: {error}"))?
        .join("tor-runtime");
    let tor_path = bundled_tor_path(&tor_runtime)?;
    let tor_command = app.shell().command(tor_path).args([
        "-f".into(),
        torrc.into_os_string(),
        "--DataDirectory".into(),
        tor_data.into_os_string(),
        "--GeoIPFile".into(),
        tor_runtime.join("data/geoip").into_os_string(),
        "--GeoIPv6File".into(),
        tor_runtime.join("data/geoip6").into_os_string(),
        "--SocksPort".into(),
        format!("127.0.0.1:{socks_port}").into(),
        "--ORPort".into(),
        "0".into(),
        "--ExitRelay".into(),
        "0".into(),
        "--ExitPolicy".into(),
        "reject *:*".into(),
        "--PublishServerDescriptor".into(),
        "0".into(),
        "--__OwningControllerProcess".into(),
        std::process::id().to_string().into(),
        "--HiddenServiceDir".into(),
        onion_dir.clone().into_os_string(),
        "--HiddenServiceVersion".into(),
        "3".into(),
        "--HiddenServicePort".into(),
        format!("80 {target}").into(),
        "--Log".into(),
        "notice stdout".into(),
    ]);
    let (mut events, tor_child) = tor_command
        .spawn()
        .map_err(|error| format!("could not start bundled Tor: {error}"))?;
    manager
        .children
        .lock()
        .map_err(|_| "child process lock failed")?
        .tor = Some(tor_child);
    set_phase(
        &manager,
        generation,
        "starting",
        "The bundled Tor process is running and bootstrapping.",
        None,
        None,
    );

    let event_app = app.clone();
    let event_manager = manager.clone();
    tauri::async_runtime::spawn(async move {
        let mut node_started = false;
        while let Some(event) = events.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes);
                    let bootstrap = tor_bootstrap_percent(&line);
                    if !node_started && bootstrap == Some(100) {
                        node_started = true;
                        if let Err(error) = start_node_sidecar(
                            &event_app,
                            event_manager.clone(),
                            &settings,
                            generation,
                            node_port,
                            socks_port,
                            &onion_dir,
                        )
                        .await
                        {
                            set_error(&event_manager, generation, error);
                        }
                    } else if !node_started && let Some(percent) = bootstrap {
                        let detail = format!("The bundled Tor process is {percent}% bootstrapped.");
                        set_phase(
                            &event_manager,
                            generation,
                            "starting",
                            &detail,
                            None,
                            None,
                        );
                    }
                }
                CommandEvent::Error(error) => set_error(
                    &event_manager,
                    generation,
                    format!("Tor output failed: {error}"),
                ),
                CommandEvent::Terminated(payload) => {
                    if generation_is_current(&event_manager, generation) {
                        set_error(
                            &event_manager,
                            generation,
                            format!("Tor stopped unexpectedly with code {:?}.", payload.code),
                        );
                    }
                    break;
                }
                _ => {}
            }
        }
    });

    let timeout_manager = manager.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(300)).await;
        let still_starting = timeout_manager
            .status
            .read()
            .is_ok_and(|status| status.generation == generation && status.phase == "starting");
        if still_starting {
            set_error(
                &timeout_manager,
                generation,
                "Tor did not finish bootstrapping within five minutes.".into(),
            );
            stop_children(&timeout_manager);
        }
    });
    Ok(())
}

async fn start_node_sidecar(
    app: &AppHandle,
    manager: Arc<NodeManager>,
    settings: &Settings,
    generation: u64,
    node_port: u16,
    socks_port: u16,
    onion_dir: &Path,
) -> Result<(), String> {
    if !generation_is_current(&manager, generation) {
        return Ok(());
    }
    let hostname = wait_for_onion_hostname(onion_dir).await?;
    let data_dir = node_data_dir(app)?;
    let quota_bytes = settings
        .quota_gib
        .checked_mul(1024 * 1024 * 1024)
        .ok_or("storage quota is too large")?;
    let mut arguments = vec![
        "--bind".into(),
        format!("127.0.0.1:{node_port}").into(),
        "--data-dir".into(),
        data_dir.into_os_string(),
        "--quota-bytes".into(),
        quota_bytes.to_string().into(),
        "--public-url".into(),
        format!("http://{hostname}/").into(),
        "--server-name".into(),
        hostname.clone().into(),
        "--no-tor".into(),
        "--mirror-proxy".into(),
        format!("socks5h://127.0.0.1:{socks_port}").into(),
        "--repair-interval".into(),
        "3600".into(),
    ];
    if let Some(pubkey) = &settings.allowed_pubkey {
        arguments.push("--allow-pubkey".into());
        arguments.push(pubkey.into());
    }
    let (mut events, node_child) = app
        .shell()
        .sidecar("wildbloomd")
        .map_err(|error| format!("bundled Wildbloom daemon is unavailable: {error}"))?
        .args(arguments)
        .spawn()
        .map_err(|error| format!("could not start Wildbloom Node: {error}"))?;
    manager
        .children
        .lock()
        .map_err(|_| "child process lock failed")?
        .node = Some(node_child);
    set_phase(
        &manager,
        generation,
        "starting",
        "Tor is ready.  Starting the Blossom service.",
        Some(format!("http://{hostname}/")),
        Some(node_port),
    );

    let node_manager = manager.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes) => {
                    let line = String::from_utf8_lossy(&bytes);
                    if line.contains("Wildbloom Node is ready") {
                        set_phase(
                            &node_manager,
                            generation,
                            "ready",
                            "The onion service is online and storage repair is active.",
                            Some(format!("http://{hostname}/")),
                            Some(node_port),
                        );
                    }
                }
                CommandEvent::Error(error) => set_error(
                    &node_manager,
                    generation,
                    format!("Wildbloom output failed: {error}"),
                ),
                CommandEvent::Terminated(payload) => {
                    if generation_is_current(&node_manager, generation) {
                        set_error(
                            &node_manager,
                            generation,
                            format!(
                                "Wildbloom Node stopped unexpectedly with code {:?}.",
                                payload.code
                            ),
                        );
                    }
                    break;
                }
                _ => {}
            }
        }
    });
    Ok(())
}

async fn fetch_health(port: u16) -> Result<StorageStatus, String> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .map_err(|error| error.to_string())?
        .get(format!("http://127.0.0.1:{port}/healthz"))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!("health endpoint returned {}", response.status()));
    }
    let health = response
        .json::<HealthResponse>()
        .await
        .map_err(|error| error.to_string())?;
    Ok(StorageStatus {
        blobs: health.storage.blobs,
        bytes: health.storage.bytes,
        quota_bytes: health.storage.quota_bytes,
    })
}

async fn wait_for_onion_hostname(onion_dir: &Path) -> Result<String, String> {
    let hostname_path = onion_dir.join("hostname");
    for _ in 0..120 {
        if let Ok(hostname) = fs::read_to_string(&hostname_path) {
            let hostname = hostname.trim().to_ascii_lowercase();
            if valid_v3_onion(&hostname) {
                return Ok(hostname);
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err("Tor did not create a valid v3 onion identity".into())
}

fn stop_children(manager: &NodeManager) {
    if let Ok(mut children) = manager.children.lock() {
        if let Some(child) = children.node.take() {
            let _ = child.kill();
        }
        if let Some(child) = children.tor.take() {
            let _ = child.kill();
        }
    }
}

fn generation_is_current(manager: &NodeManager, generation: u64) -> bool {
    manager
        .status
        .read()
        .is_ok_and(|status| status.generation == generation)
}

fn set_phase(
    manager: &NodeManager,
    generation: u64,
    phase: &'static str,
    detail: &str,
    onion_url: Option<String>,
    local_port: Option<u16>,
) {
    if let Ok(mut status) = manager.status.write()
        && status.generation == generation
    {
        status.phase = phase;
        status.detail = detail.into();
        status.onion_url = onion_url;
        status.local_port = local_port;
        eprintln!("Wildbloom Node runtime phase: {phase}: {detail}");
    }
}

fn set_error(manager: &NodeManager, generation: u64, detail: String) {
    set_phase(manager, generation, "error", &detail, None, None);
}

fn phase_label(phase: &str) -> &'static str {
    match phase {
        "ready" => "Online",
        "error" => "Needs attention",
        "stopped" => "Stopped",
        _ => "Starting",
    }
}

fn validate_settings(settings: &Settings) -> Result<(), String> {
    if let Some(pubkey) = &settings.allowed_pubkey
        && (pubkey.len() != 64
            || !pubkey
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err("the Nostr public key must be 64 lower-case hexadecimal characters".into());
    }
    if !(1..=16_384).contains(&settings.quota_gib) {
        return Err("the storage quota must be between 1 GiB and 16 TiB".into());
    }
    Ok(())
}

fn read_settings(app: &AppHandle) -> Result<Settings, String> {
    let path = settings_path(app)?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| format!("settings are invalid; inspect or remove {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(error) => Err(format!("could not read settings: {error}")),
    }
}

fn write_settings(app: &AppHandle, settings: &Settings) -> Result<(), String> {
    let path = settings_path(app)?;
    let parent = path.parent().ok_or("settings path has no parent")?;
    create_private_dir(parent)?;
    let temporary = parent.join("settings.json.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec_pretty(settings).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("could not write settings: {error}"))?;
    set_private_file(&temporary)?;
    fs::rename(&temporary, &path)
        .map_err(|error| format!("could not replace settings: {error}"))?;
    set_private_file(&path)
}

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|path| path.join("settings.json"))
        .map_err(|error| error.to_string())
}

fn node_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|path| path.join("node"))
        .map_err(|error| error.to_string())
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn set_private_file(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn valid_v3_onion(hostname: &str) -> bool {
    hostname.strip_suffix(".onion").is_some_and(|service| {
        service.len() == 56
            && service
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    })
}

fn tor_bootstrap_percent(line: &str) -> Option<u8> {
    let remainder = line.split_once("Bootstrapped ")?.1;
    let digits = remainder.split_once('%')?.0;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u8>().ok().filter(|percent| *percent <= 100)
}

fn bundled_tor_path(runtime: &Path) -> Result<PathBuf, String> {
    #[cfg(windows)]
    let path = runtime.join("tor/tor.exe");
    #[cfg(not(windows))]
    let path = runtime.join("tor/tor");

    if !path.is_file() {
        return Err(format!(
            "the verified Tor runtime is incomplete: {} is missing",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path
            .metadata()
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err(format!(
                "the bundled Tor executable is not executable: {}",
                path.display()
            ));
        }
    }
    Ok(path)
}

fn free_port() -> Result<u16, String> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show Wildbloom Node", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    let mut tray = TrayIconBuilder::new()
        .tooltip("Wildbloom Node")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => app.exit(0),
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn main() {
    let manager = Arc::new(NodeManager::default());
    let managed = manager.clone();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(
            |app, _arguments, _cwd| {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            },
        ))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(managed)
        .invoke_handler(tauri::generate_handler![
            node_status,
            save_settings,
            restart_node,
            check_for_update,
            install_update
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            build_tray(app)?;
            let handle = app.handle().clone();
            let manager = app.state::<Arc<NodeManager>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = start_runtime(handle, manager.clone()).await {
                    let generation = manager
                        .status
                        .read()
                        .map(|status| status.generation)
                        .unwrap_or(0);
                    set_error(&manager, generation, error);
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build Wildbloom Node");
    app.run(move |_app, event| {
        if matches!(
            event,
            tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
        ) {
            stop_children(&manager);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_writer_public_keys() {
        let mut settings = Settings::default();
        assert!(validate_settings(&settings).is_ok());

        settings.allowed_pubkey = Some("a".repeat(64));
        assert!(validate_settings(&settings).is_ok());
        settings.allowed_pubkey = Some("A".repeat(64));
        assert!(validate_settings(&settings).is_err());
        settings.allowed_pubkey = Some("a".repeat(63));
        assert!(validate_settings(&settings).is_err());
    }

    #[test]
    fn recognises_only_canonical_v3_onion_hostnames() {
        assert!(valid_v3_onion(&format!("{}.onion", "a".repeat(56))));
        assert!(valid_v3_onion(&format!("{}.onion", "2".repeat(56))));
        assert!(!valid_v3_onion(&format!("{}.onion", "1".repeat(56))));
        assert!(!valid_v3_onion(&format!("{}.example", "a".repeat(56))));
    }

    #[test]
    fn reads_only_bounded_tor_bootstrap_notices() {
        assert_eq!(
            tor_bootstrap_percent("Aug 27 10:00:00 [notice] Bootstrapped 5% (conn): Connecting"),
            Some(5)
        );
        assert_eq!(
            tor_bootstrap_percent("Aug 27 10:00:01 [notice] Bootstrapped 100% (done): Done"),
            Some(100)
        );
        assert_eq!(tor_bootstrap_percent("Bootstrapped 101%"), None);
        assert_eq!(tor_bootstrap_percent("Bootstrapped nope%"), None);
        assert_eq!(tor_bootstrap_percent("unrelated output"), None);
    }
}
