//! Owner-side pool supervision. This is separate from the local storage node.
//! Receipt inspection is local; only explicit check/start commands contact nodes.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_shell::ShellExt as _;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::oneshot,
};

const RECEIPT_LIMIT: usize = 128 * 1024;
const OUTPUT_LIMIT: usize = 256 * 1024;
const MAX_POOLS: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Inspection {
    receipt_id: String,
    owner: String,
    manifest: Manifest,
    storage_verified: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Manifest {
    mode: String,
    profile: String,
    payload: Payload,
    required: usize,
    total: usize,
    copies: u8,
    parts: Vec<Part>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Payload {
    sha256: String,
    size: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Part {
    index: usize,
    size: u64,
    targets: Vec<Target>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Target {
    id: String,
    origin: String,
    failure_group: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Report {
    receipt_id: String,
    observed_at: u64,
    verified_groups: Vec<usize>,
    recoverable: bool,
    protected: bool,
    reconstructed: bool,
    uploads_attempted: usize,
    reserved_transfer_bytes: u64,
    nodes: Vec<NodeReport>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
struct NodeReport {
    id: String,
    part_index: usize,
    state: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct PoolStatus {
    inspection: Inspection,
    phase: String,
    detail: String,
    expires_at: Option<u64>,
    started_at: Option<u64>,
    report: Option<Report>,
    work_dir: String,
}
struct Active {
    id: String,
    stop: Option<oneshot::Sender<()>>,
    done: oneshot::Receiver<()>,
}
#[derive(Default)]
pub struct PoolManager {
    entries: Mutex<BTreeMap<String, PoolStatus>>,
    active: tokio::sync::Mutex<Option<Active>>,
    operation: tokio::sync::Mutex<()>,
    load_error: Mutex<Option<String>>,
}
#[derive(Serialize)]
pub struct PoolList {
    pools: Vec<PoolStatus>,
    error: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSettings {
    receipt_id: String,
    check_only: bool,
    allow_reconstruction: bool,
    signer: String,
    signer_arguments: Vec<String>,
    proxy: Option<String>,
    expires_at: u64,
    interval: u64,
    transfer_budget_bytes: u64,
    max_work_bytes: u64,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
fn root(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|p| p.join("owner-pools"))
        .map_err(|_| "Could not locate owner pool storage.".into())
}
fn private_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| "Could not create private pool directory.")?;
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "Could not inspect pool directory.")?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("Pool state must use ordinary private directories.".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("Pool directory is not private (0700 required).".into());
        }
    }
    Ok(())
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "Could not read pool state.")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        return Err("Invalid or oversized pool state.".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| "Could not open pool state.")?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read pool state.")?;
    if bytes.len() > limit {
        return Err("Oversized pool state.".into());
    }
    Ok(bytes)
}
fn daemon(app: &AppHandle) -> Result<Command, String> {
    // Use Tauri's bundled sidecar resolver; never resolve a daemon through PATH.
    let command: std::process::Command = app
        .shell()
        .sidecar("wildbloomd")
        .map_err(|_| "The bundled daemon is missing.")?
        .into();
    let mut command = Command::from(command);
    command.kill_on_drop(true).stderr(Stdio::null());
    Ok(command)
}
async fn inspect(
    mut command: Command,
    path: &Path,
    owner: &str,
    id: &str,
) -> Result<Inspection, String> {
    if !hex(owner) || !hex(id) {
        return Err(
            "Receipt ID and owner must be lowercase hexadecimal public identifiers.".into(),
        );
    }
    let mut child = command
        .args(["replicas", "pool-inspect", "--receipt"])
        .arg(path)
        .args(["--owner", owner, "--receipt-id", id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "Could not start receipt verification.")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Receipt verifier output unavailable.")?;
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let mut output = Vec::new();
        stdout
            .take(OUTPUT_LIMIT as u64 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| "Could not read receipt verification.")?;
        if output.len() > OUTPUT_LIMIT {
            return Err("Receipt verification exceeded its limit.");
        }
        if !child
            .wait()
            .await
            .map_err(|_| "Receipt verifier stopped unexpectedly.")?
            .success()
        {
            return Err("Receipt signature, owner, placement or transport is invalid.");
        }
        let parsed: Inspection =
            serde_json::from_slice(&output).map_err(|_| "Invalid receipt verifier result.")?;
        if parsed.receipt_id != id || parsed.owner != owner || parsed.storage_verified {
            return Err("Receipt verifier identity mismatch.");
        }
        Ok(parsed)
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        other => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(match other {
                Ok(Err(e)) => e,
                _ => "Receipt verification timed out.",
            }
            .into())
        }
    }
}
fn identifiers(bytes: &[u8]) -> Result<(String, String), String> {
    let event: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "Receipt must be signed JSON.")?;
    let id = event["id"]
        .as_str()
        .filter(|v| hex(v))
        .ok_or("Receipt has no canonical event ID.")?;
    let owner = event["pubkey"]
        .as_str()
        .filter(|v| hex(v))
        .ok_or("Receipt has no canonical author.")?;
    Ok((id.into(), owner.into()))
}
fn status(inspection: Inspection, path: &Path) -> PoolStatus {
    PoolStatus {
        inspection,
        phase: "stopped".into(),
        detail: "Receipt verified locally. Storage has not been checked in this session.".into(),
        expires_at: None,
        started_at: None,
        report: None,
        work_dir: path.join("work").to_string_lossy().into(),
    }
}
pub async fn load(app: AppHandle, manager: Arc<PoolManager>) {
    let _operation = manager.operation.lock().await;
    let result = async {
        let root = root(&app)?;
        private_dir(&root)?;
        let mut entries = BTreeMap::new();
        for entry in fs::read_dir(&root).map_err(|_| "Could not list saved pools.")? {
            let entry = entry.map_err(|_| "Could not read saved pool directory.")?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if !hex(&id) {
                continue;
            }
            if entries.len() >= MAX_POOLS {
                return Err("Too many saved pools; maximum 16.".to_owned());
            }
            private_dir(&entry.path())?;
            let path = entry.path().join("receipt.json");
            if !path.exists() {
                continue;
            }
            let bytes = read(&path, RECEIPT_LIMIT)?;
            let (actual_id, owner) = identifiers(&bytes)?;
            if actual_id != id {
                return Err("A saved pool receipt has changed identity.".to_owned());
            }
            let inspected = inspect(daemon(&app)?, &path, &owner, &id).await?;
            entries.insert(id, status(inspected, &entry.path()));
        }
        *manager
            .entries
            .lock()
            .map_err(|_| "Pool state lock failed.")? = entries;
        Ok::<_, String>(())
    }
    .await;
    if let Err(error) = result
        && let Ok(mut target) = manager.load_error.lock()
    {
        *target = Some(error);
    }
}
#[tauri::command]
pub fn open_pool_client(app: AppHandle) -> Result<(), String> {
    #[allow(deprecated)]
    app.shell()
        .open("https://wildbloom.forgesworn.dev/#client", None)
        .map_err(|_| "Could not open the browser client.".into())
}
#[tauri::command]
pub async fn import_pool(
    app: AppHandle,
    manager: State<'_, Arc<PoolManager>>,
    receipt: String,
    owner: String,
) -> Result<Inspection, String> {
    let _operation = manager.operation.lock().await;
    if receipt.len() > RECEIPT_LIMIT {
        return Err("Receipt exceeds 128 KiB.".into());
    }
    let (id, author) = identifiers(receipt.as_bytes())?;
    if owner != author {
        return Err("The receipt author does not match the owner you entered.".into());
    }
    if manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?
        .len()
        >= MAX_POOLS
    {
        return Err("At most 16 receipts can be managed. Remove a stopped receipt first.".into());
    }
    let root = root(&app)?;
    private_dir(&root)?;
    let mut file =
        tempfile::NamedTempFile::new_in(&root).map_err(|_| "Could not stage private receipt.")?;
    file.write_all(receipt.as_bytes())
        .map_err(|_| "Could not stage receipt.")?;
    file.as_file()
        .sync_all()
        .map_err(|_| "Could not save receipt.")?;
    let inspected = inspect(daemon(&app)?, file.path(), &owner, &id).await?;
    if manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?
        .contains_key(&id)
    {
        return Err("This receipt is already imported.".into());
    }
    let directory = root.join(&id);
    private_dir(&directory)?;
    file.persist_noclobber(directory.join("receipt.json"))
        .map_err(|_| "A saved receipt already exists; it will not be overwritten.")?;
    manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?
        .insert(id, status(inspected.clone(), &directory));
    Ok(inspected)
}
fn valid_report(report: &Report, inspection: &Inspection, started: Option<u64>) -> bool {
    report.receipt_id == inspection.receipt_id
        && report.observed_at <= now()
        && started.is_none_or(|s| report.observed_at >= s)
        && report.verified_groups.len() == inspection.manifest.total
        && report.verified_groups.iter().all(|v| *v <= 16)
        && report.nodes.len() <= 16
        && report.nodes.iter().all(|node| {
            inspection
                .manifest
                .parts
                .iter()
                .any(|p| p.index == node.part_index && p.targets.iter().any(|n| n.id == node.id))
                && ["verified", "unavailable", "not_checked"].contains(&node.state.as_str())
        })
}
#[tauri::command]
pub async fn pool_status(
    app: AppHandle,
    manager: State<'_, Arc<PoolManager>>,
) -> Result<PoolList, String> {
    let mut entries = manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?;
    for (id, entry) in entries.iter_mut() {
        if entry.started_at.is_some() {
            let path = root(&app)?.join(id).join("work/pool-report.json");
            if let Ok(bytes) = read(&path, OUTPUT_LIMIT)
                && let Ok(report) = serde_json::from_slice::<Report>(&bytes)
                && valid_report(&report, &entry.inspection, entry.started_at)
            {
                entry.report = Some(report);
            }
        }
    }
    Ok(PoolList {
        pools: entries.values().cloned().collect(),
        error: manager
            .load_error
            .lock()
            .map_err(|_| "Pool state lock failed.")?
            .clone(),
    })
}
fn validate_run(settings: &RunSettings, inspection: &Inspection, clock: u64) -> Result<(), String> {
    if settings.receipt_id != inspection.receipt_id || !hex(&settings.receipt_id) {
        return Err("Select a verified receipt.".into());
    }
    if settings.expires_at <= clock || settings.expires_at - clock > 365 * 86400 {
        return Err("Authority must expire within the next year.".into());
    }
    if !(5..=86400).contains(&settings.interval)
        || !(1..=32 * 1024 * 1024 * 1024).contains(&settings.transfer_budget_bytes)
        || !(1..=32 * 1024 * 1024 * 1024).contains(&settings.max_work_bytes)
    {
        return Err("Choose valid bounded interval and budgets (maximum 32 GiB each).".into());
    }
    if !settings.check_only
        && (!settings.allow_reconstruction
            || !Path::new(&settings.signer).is_absolute()
            || !Path::new(&settings.signer).is_file())
    {
        return Err("Repair requires explicit reconstruction consent and an absolute external signer executable path.".into());
    }
    if settings.signer_arguments.len() > 16
        || settings
            .signer_arguments
            .iter()
            .any(|a| a.len() > 4096 || a.contains('\0'))
    {
        return Err("Signer arguments exceed their limits.".into());
    }
    match (&*inspection.manifest.profile, &settings.proxy) {
        ("direct", None) => {}
        ("tor", Some(proxy)) => {
            let url = reqwest::Url::parse(proxy)
                .map_err(|_| "Tor requires an explicit loopback SOCKS5h proxy.")?;
            if url.scheme() != "socks5h"
                || url.host_str() != Some("127.0.0.1")
                || url.port().is_none_or(|p| p == 0)
                || !url.username().is_empty()
                || url.password().is_some()
                || !["", "/"].contains(&url.path())
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(
                    "Use socks5h://127.0.0.1:PORT for Tor; no remote DNS fallback is permitted."
                        .into(),
                );
            }
        }
        _ => {
            return Err(
                "Direct pools require no proxy; Tor pools require a loopback SOCKS5h proxy.".into(),
            );
        }
    }
    Ok(())
}
fn arguments(
    settings: &RunSettings,
    inspection: &Inspection,
    directory: &Path,
) -> Vec<std::ffi::OsString> {
    let mut args = vec![
        "replicas".into(),
        "pool-repair".into(),
        "--receipt".into(),
        directory.join("receipt.json").into_os_string(),
        "--receipt-id".into(),
        settings.receipt_id.clone().into(),
        "--owner".into(),
        inspection.owner.clone().into(),
        "--work-dir".into(),
        directory.join("work").into_os_string(),
        "--stop-on-stdin".into(),
        "--expires-at".into(),
        settings.expires_at.to_string().into(),
        "--interval".into(),
        settings.interval.to_string().into(),
        "--transfer-budget-bytes".into(),
        settings.transfer_budget_bytes.to_string().into(),
        "--max-work-bytes".into(),
        settings.max_work_bytes.to_string().into(),
    ];
    if settings.check_only {
        args.push("--check-only".into());
    } else {
        args.extend([
            "--allow-reconstruction".into(),
            "--signer".into(),
            settings.signer.clone().into(),
        ]);
        for arg in &settings.signer_arguments {
            args.push(format!("--signer-arg={arg}").into());
        }
    }
    if let Some(proxy) = &settings.proxy {
        args.extend(["--proxy".into(), proxy.into()]);
    }
    args
}
fn require_stopped(slot: &mut Option<Active>, selected: Option<&str>) -> Result<(), String> {
    if let Some(active) = slot.as_mut()
        && selected.is_none_or(|id| id == active.id)
    {
        if matches!(
            active.done.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ) {
            return Err("Stop the active pool check or repair first.".into());
        }
        // Consuming a completed receiver also retires its slot. Quit must never
        // poll that receiver again after a receipt was removed.
        *slot = None;
    }
    Ok(())
}
#[tauri::command]
pub async fn start_pool(
    app: AppHandle,
    manager: State<'_, Arc<PoolManager>>,
    settings: RunSettings,
) -> Result<(), String> {
    let _operation = manager.operation.lock().await;
    let mut active = manager.active.lock().await;
    require_stopped(&mut active, None)?;
    let inspection = manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?
        .get(&settings.receipt_id)
        .ok_or("Import this receipt first.")?
        .inspection
        .clone();
    validate_run(&settings, &inspection, now())?;
    let directory = root(&app)?.join(&settings.receipt_id);
    private_dir(&directory)?;
    let verified = inspect(
        daemon(&app)?,
        &directory.join("receipt.json"),
        &inspection.owner,
        &settings.receipt_id,
    )
    .await?;
    private_dir(&directory.join("work"))?;
    // Remove only this receipt's old observation so a new run never presents stale success.
    let old_report = directory.join("work/pool-report.json");
    if old_report.exists() {
        read(&old_report, OUTPUT_LIMIT)?;
        fs::remove_file(old_report).map_err(|_| "Could not clear previous observation.")?;
    }
    let started_at = now();
    let mut child = daemon(&app)?
        .args(arguments(&settings, &verified, &directory))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|_| "Could not start owner pool process.")?;
    let mut input = child
        .stdin
        .take()
        .ok_or("Owner process lifetime pipe unavailable.")?;
    let id = settings.receipt_id.clone();
    let (stop, mut stopped) = oneshot::channel();
    let (finished, done) = oneshot::channel();
    *active = Some(Active {
        id: id.clone(),
        stop: Some(stop),
        done,
    });
    {
        let mut entries = manager
            .entries
            .lock()
            .map_err(|_| "Pool state lock failed.")?;
        let entry = entries.get_mut(&id).ok_or("Pool disappeared.")?;
        entry.phase = if settings.check_only {
            "checking"
        } else {
            "repairing"
        }
        .into();
        entry.detail = if settings.check_only {
            "Reading and verifying approved nodes. No signing or uploads."
        } else {
            "Owner repair is running. Closing the window keeps it running; quitting stops it."
        }
        .into();
        entry.started_at = Some(started_at);
        entry.expires_at = Some(settings.expires_at);
        entry.report = None;
    }
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn(async move {
        let outcome = tokio::select! {
            result = child.wait() => result.ok().map(|s| s.success()),
            _ = &mut stopped => {
                let _ = input.write_all(b"stop\n").await;
                drop(input);
                if tokio::time::timeout(Duration::from_secs(5), child.wait()).await.is_err() { let _ = child.kill().await; let _ = child.wait().await; }
                None
            }
        };
        if let Ok(mut entries) = manager.entries.lock()
            && let Some(entry) = entries.get_mut(&id)
        {
            entry.phase = if outcome == Some(false) {
                "attention"
            } else {
                "stopped"
            }
            .into();
            entry.detail = match outcome {
                Some(true) if settings.check_only => "Read-only check finished. See the observation time and verified parts below.",
                Some(true) => "Owner repair stopped.",
                Some(false) => "Process stopped: protection is incomplete, authority expired, or configuration needs attention. Check the last observation, budgets, signer and proxy. After an abrupt stop, inspect the private work folder for pool-pass leftovers before retrying.",
                None => "Stopped. No further checks or repair will run until you start again.",
            }.into();
        }
        let _ = finished.send(());
    });
    Ok(())
}
#[tauri::command]
pub async fn stop_pool(manager: State<'_, Arc<PoolManager>>) -> Result<(), String> {
    manager.stop().await
}
impl PoolManager {
    pub async fn stop(&self) -> Result<(), String> {
        let _operation = self.operation.lock().await;
        let mut slot = self.active.lock().await;
        if let Some(active) = slot.as_mut() {
            if let Some(stop) = active.stop.take() {
                let _ = stop.send(());
            }
            if tokio::time::timeout(Duration::from_secs(7), &mut active.done)
                .await
                .is_err()
            {
                return Err(
                    "Stop is still pending. No other pool process can start until this one exits."
                        .into(),
                );
            }
        }
        *slot = None;
        Ok(())
    }
}
#[tauri::command]
pub async fn remove_pool(
    app: AppHandle,
    manager: State<'_, Arc<PoolManager>>,
    receipt_id: String,
) -> Result<(), String> {
    let _operation = manager.operation.lock().await;
    if !hex(&receipt_id) {
        return Err("Invalid receipt ID.".into());
    }
    {
        let mut slot = manager.active.lock().await;
        require_stopped(&mut slot, Some(&receipt_id))?;
    }
    if !manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?
        .contains_key(&receipt_id)
    {
        return Err("Unknown receipt.".into());
    }
    // Preserve the work directory, reports and crash leftovers for deliberate operator review.
    fs::remove_file(root(&app)?.join(&receipt_id).join("receipt.json"))
        .map_err(|_| "Could not remove local receipt.")?;
    manager
        .entries
        .lock()
        .map_err(|_| "Pool state lock failed.")?
        .remove(&receipt_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inspection() -> Inspection {
        serde_json::from_value(serde_json::json!({"receipt_id":"a".repeat(64),"owner":"b".repeat(64),"storage_verified":false,"manifest":{"mode":"replicas","profile":"direct","payload":{"sha256":"c".repeat(64),"size":1024},"required":1,"total":1,"copies":2,"parts":[{"index":0,"size":1024,"targets":[{"id":"a","origin":"https://a.example/","failure_group":"a"},{"id":"b","origin":"https://b.example/","failure_group":"b"}]}]}})).unwrap()
    }
    fn settings() -> RunSettings {
        RunSettings {
            receipt_id: "a".repeat(64),
            check_only: true,
            allow_reconstruction: false,
            signer: String::new(),
            signer_arguments: vec![],
            proxy: None,
            expires_at: 200,
            interval: 300,
            transfer_budget_bytes: 1024,
            max_work_bytes: 1024,
        }
    }
    #[tokio::test]
    async fn completed_receipt_removal_retires_supervision_before_quit() {
        let manager = PoolManager::default();
        let (stop, _stopped) = oneshot::channel();
        let (finished, done) = oneshot::channel();
        let mut slot = Some(Active {
            id: "a".repeat(64),
            stop: Some(stop),
            done,
        });
        assert!(require_stopped(&mut slot, Some(&"a".repeat(64))).is_err());
        assert!(slot.is_some());
        finished.send(()).unwrap();
        require_stopped(&mut slot, Some(&"a".repeat(64))).unwrap();
        assert!(slot.is_none());
        *manager.active.lock().await = slot;
        manager.stop().await.unwrap();
        manager.stop().await.unwrap();
    }
    #[test]
    fn bounded_authority_transport_and_reconstruction_are_separate() {
        let mut s = settings();
        let mut i = inspection();
        assert!(validate_run(&s, &i, 100).is_ok());
        s.expires_at = 100;
        assert!(validate_run(&s, &i, 100).is_err());
        s.expires_at = 200;
        s.check_only = false;
        assert!(validate_run(&s, &i, 100).is_err());
        let executable = tempfile::NamedTempFile::new().unwrap();
        s.signer = executable.path().to_string_lossy().into();
        s.allow_reconstruction = true;
        assert!(validate_run(&s, &i, 100).is_ok());
        s.transfer_budget_bytes = 33 * 1024 * 1024 * 1024;
        assert!(validate_run(&s, &i, 100).is_err());
        s.transfer_budget_bytes = 1024;
        s.proxy = Some("socks5h://127.0.0.1:9050".into());
        assert!(validate_run(&s, &i, 100).is_err());
        i.manifest.profile = "tor".into();
        assert!(validate_run(&s, &i, 100).is_ok());
        for proxy in [
            "socks5://127.0.0.1:9050",
            "socks5h://remote.example:9050",
            "socks5h://user@127.0.0.1:9050",
            "socks5h://127.0.0.1:9050/path",
        ] {
            s.proxy = Some(proxy.into());
            assert!(validate_run(&s, &i, 100).is_err());
        }
    }
    #[test]
    fn read_only_arguments_never_grant_signing_or_reconstruction() {
        let mut s = settings();
        s.signer = "/unused/path".into();
        s.signer_arguments = vec!["$(must remain literal)".into()];
        let args = arguments(&s, &inspection(), Path::new("/private/pool"));
        assert!(args.contains(&"--check-only".into()));
        assert!(args.contains(&"--stop-on-stdin".into()));
        assert!(!args.contains(&"--signer".into()));
        assert!(!args.contains(&"--allow-reconstruction".into()));
        s.check_only = false;
        let args = arguments(&s, &inspection(), Path::new("/private/pool"));
        assert!(args.contains(&"--signer-arg=$(must remain literal)".into()));
    }
    #[test]
    fn private_state_refuses_symlinks_and_oversized_reads() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        private_dir(&root).unwrap();
        let file = root.join("file");
        fs::write(&file, b"1234").unwrap();
        assert!(read(&file, 3).is_err());
        assert_eq!(read(&file, 4).unwrap(), b"1234");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            symlink(&file, root.join("link")).unwrap();
            assert!(read(&root.join("link"), 4).is_err());
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(private_dir(&root).is_err());
        }
    }
    #[test]
    fn reports_cannot_belong_to_another_receipt_or_precede_this_run() {
        let i = inspection();
        let mut r = Report {
            receipt_id: i.receipt_id.clone(),
            observed_at: now(),
            verified_groups: vec![2],
            recoverable: true,
            protected: true,
            reconstructed: false,
            uploads_attempted: 0,
            reserved_transfer_bytes: 2048,
            nodes: vec![],
        };
        assert!(valid_report(&r, &i, Some(r.observed_at)));
        assert!(!valid_report(&r, &i, Some(r.observed_at + 1)));
        r.receipt_id = "b".repeat(64);
        assert!(!valid_report(&r, &i, None));
    }
}
