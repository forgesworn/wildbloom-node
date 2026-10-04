//! Real daemon acceptance for the desktop's read-only and lifetime contracts.
use axum::{
    Router,
    routing::{get, put},
};
use nostr::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncWriteExt, process::Command};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn daemon() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wildbloomd"));
    c.kill_on_drop(true).stderr(Stdio::null());
    c
}
async fn fixture() -> (
    tempfile::TempDir,
    Event,
    Arc<AtomicUsize>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let temp = tempfile::tempdir().unwrap();
    let payload = b"synthetic encrypted fixture";
    let hash = hex::encode(Sha256::digest(payload));
    let uploads = Arc::new(AtomicUsize::new(0));
    let mut origins = Vec::new();
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let writes = uploads.clone();
        let app = Router::new()
            .route(
                &format!("/{hash}"),
                get(move || async { payload.as_slice() }),
            )
            .route(
                "/upload",
                put(move || async move {
                    writes.fetch_add(1, Ordering::SeqCst);
                    "untrusted acknowledgement"
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        origins.push(format!("http://{}/", listener.local_addr().unwrap()));
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
    }
    let keys = Keys::generate();
    let manifest = json!({"type":"wildbloom.pool","version":1,"mode":"replicas","profile":"direct","payload":{"sha256":hash,"size":payload.len(),"encryption":"forgesworn-aes-256-gcm-chunked-v2"},"required":1,"total":1,"copies":2,"parts":[{"index":0,"sha256":hash,"size":payload.len(),"targets":origins.iter().enumerate().map(|(i,origin)|json!({"id":format!("node-{i}"),"origin":origin,"failure_group":format!("site-{i}"),"weight":1})).collect::<Vec<_>>()}]});
    let event = EventBuilder::new(Kind::from(30078), manifest.to_string())
        .tag(Tag::identifier(format!("wildbloom.pool.v1:{hash}")))
        .finalize(&keys)
        .unwrap();
    std::fs::write(temp.path().join("receipt.json"), event.as_json()).unwrap();
    (temp, event, uploads, tasks)
}
fn repair(temp: &tempfile::TempDir, event: &Event) -> Command {
    let mut c = daemon();
    c.args(["replicas", "pool-repair", "--receipt"])
        .arg(temp.path().join("receipt.json"))
        .args([
            "--receipt-id",
            &event.id.to_hex(),
            "--owner",
            &event.pubkey.to_hex(),
            "--work-dir",
        ])
        .arg(temp.path().join("work"))
        .args([
            "--expires-at",
            &(now() + 60).to_string(),
            "--permit-loopback-development",
        ]);
    c
}
async fn bounded(mut command: Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn inspection_is_local_and_read_only_checks_report_loss_without_signing_or_uploads() {
    let (temp, event, uploads, tasks) = fixture().await;
    let mut inspect = daemon();
    inspect
        .args(["replicas", "pool-inspect", "--receipt"])
        .arg(temp.path().join("receipt.json"))
        .args([
            "--receipt-id",
            &event.id.to_hex(),
            "--owner",
            &event.pubkey.to_hex(),
            "--permit-loopback-development",
        ]);
    let output = bounded(inspect).await;
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["storage_verified"], false);
    assert!(!temp.path().join("work").exists());
    let mut command = repair(&temp, &event);
    command.arg("--check-only");
    let output = bounded(command).await;
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["protected"], true);
    assert_eq!(report["reconstructed"], false);
    assert_eq!(report["uploads_attempted"], 0);
    assert_eq!(report["verified_groups"], json!([2]));
    assert_eq!(report["nodes"][0]["state"], "verified");
    tasks[1].abort();
    tokio::task::yield_now().await;
    let mut command = repair(&temp, &event);
    command.arg("--check-only");
    let output = bounded(command).await;
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["protected"], false);
    assert_eq!(report["recoverable"], true);
    assert_eq!(report["nodes"][1]["state"], "unavailable");
    assert_eq!(uploads.load(Ordering::SeqCst), 0);
    tasks[0].abort();
}
#[tokio::test]
async fn supervisor_pipe_stops_resident_repair_and_releases_private_work() {
    let (temp, event, uploads, tasks) = fixture().await;
    let mut command = repair(&temp, &event);
    command
        .args(["--allow-reconstruction", "--stop-on-stdin", "--signer"])
        .arg(temp.path().join("unused-signer"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    let report = temp.path().join("work/pool-report.json");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !report.exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    input.write_all(b"stop\n").await.unwrap();
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(
        !std::fs::read_dir(temp.path().join("work"))
            .unwrap()
            .any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("pool-pass-"))
    );
    let mut command = repair(&temp, &event);
    command.arg("--check-only");
    assert!(bounded(command).await.status.success());
    // Closing stdin, as happens on abrupt parent loss, follows the same graceful path.
    let mut command = repair(&temp, &event);
    command
        .args(["--check-only", "--stop-on-stdin"])
        .stdin(Stdio::piped());
    let mut child = command.spawn().unwrap();
    drop(child.stdin.take());
    assert!(
        tokio::time::timeout(Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert_eq!(uploads.load(Ordering::SeqCst), 0);
    for task in tasks {
        task.abort();
    }
}
