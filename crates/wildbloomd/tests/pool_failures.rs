//! Process-level fault injection. All stores/keys are disposable, all sockets
//! loopback. A stalled HTTP body proves the kill/expiry occurs during I/O.
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Response, StatusCode},
    routing::{get, put},
};
use futures_util::stream::{self, StreamExt};
use nostr::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::process::Command;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
struct Fixture {
    root: tempfile::TempDir,
    event: Event,
    stall: Arc<AtomicBool>,
    reads: Arc<AtomicUsize>,
    uploads: Arc<AtomicUsize>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let payload = b"synthetic ciphertext for interruption tests";
        let hash = hex::encode(Sha256::digest(payload));
        let stall = Arc::new(AtomicBool::new(true));
        let reads = Arc::new(AtomicUsize::new(0));
        let uploads = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        let mut targets = Vec::new();
        for i in 0..2 {
            let stalled = stall.clone();
            let read_count = reads.clone();
            let write_count = uploads.clone();
            let app = Router::new()
                .route(
                    &format!("/{hash}"),
                    get(move || async move {
                        read_count.fetch_add(1, Ordering::SeqCst);
                        let body = if stalled.load(Ordering::SeqCst) {
                            Body::from_stream(
                                stream::once(async {
                                    Ok::<_, std::io::Error>(Bytes::from_static(&payload[..8]))
                                })
                                .chain(stream::pending()),
                            )
                        } else {
                            Body::from(payload.as_slice())
                        };
                        Response::builder()
                            .header("content-length", payload.len())
                            .body(body)
                            .unwrap()
                    }),
                )
                .route(
                    "/upload",
                    put(move || async move {
                        write_count.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INSUFFICIENT_STORAGE
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            targets.push(json!({"id":format!("node-{i}"),"origin":format!("http://{}/",listener.local_addr().unwrap()),"failure_group":format!("site-{i}"),"weight":1}));
            tasks.push(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
        }
        let keys = Keys::generate();
        let manifest = json!({"type":"wildbloom.pool","version":1,"mode":"replicas","profile":"direct","payload":{"sha256":hash,"size":payload.len(),"encryption":"forgesworn-aes-256-gcm-chunked-v2"},"required":1,"total":1,"copies":2,"parts":[{"index":0,"sha256":hash,"size":payload.len(),"targets":targets}]});
        let event = EventBuilder::new(Kind::from(30078), manifest.to_string())
            .tag(Tag::identifier(format!("wildbloom.pool.v1:{hash}")))
            .finalize(&keys)
            .unwrap();
        std::fs::write(root.path().join("receipt.json"), event.as_json()).unwrap();
        Self {
            root,
            event,
            stall,
            reads,
            uploads,
            tasks,
        }
    }
    fn work(&self) -> PathBuf {
        self.root.path().join("work")
    }
    fn command(&self, expiry: u64) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_wildbloomd"));
        c.kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(["replicas", "pool-repair", "--receipt"])
            .arg(self.root.path().join("receipt.json"))
            .args([
                "--receipt-id",
                &self.event.id.to_hex(),
                "--owner",
                &self.event.pubkey.to_hex(),
                "--work-dir",
            ])
            .arg(self.work())
            .args([
                "--expires-at",
                &expiry.to_string(),
                "--permit-loopback-development",
            ]);
        c
    }
    fn passes(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.work())
            .unwrap()
            .map(Result::unwrap)
            .filter(|e| e.file_name().to_string_lossy().starts_with("pool-pass-"))
            .map(|e| e.path())
            .collect()
    }
    async fn partial_download(&self) -> PathBuf {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if self.work().exists() {
                    for dir in self.passes() {
                        for file in std::fs::read_dir(dir).unwrap().map(Result::unwrap) {
                            // Directory-entry metadata can lag an open writer
                            // on Windows. Observe the actual bytes through a
                            // new file handle before injecting the failure.
                            if std::fs::read(file.path()).is_ok_and(|bytes| bytes.len() == 8) {
                                return file.path();
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("partial bytes must reach private scratch storage")
    }
    async fn healthy_restart(&self) {
        self.stall.store(false, Ordering::SeqCst);
        let mut c = self.command(now() + 60);
        c.arg("--check-only");
        let output = bounded(c).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["protected"], true);
        assert_eq!(report["uploads_attempted"], 0);
        assert!(self.passes().is_empty());
        assert_eq!(self.uploads.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn bounded(mut c: Command) -> std::process::Output {
    tokio::time::timeout(Duration::from_secs(10), c.output())
        .await
        .expect("bounded daemon")
        .unwrap()
}

#[tokio::test]
async fn hard_kill_releases_lock_preserves_partial_files_and_requires_review() {
    let f = Fixture::new().await;
    let mut c = f.command(now() + 60);
    c.args(["--allow-reconstruction", "--signer"])
        .arg(f.root.path().join("unused-signer"));
    let mut child = c.spawn().unwrap();
    let partial = f.partial_download().await;
    let bytes = std::fs::read(&partial).unwrap();
    let passes = f.passes();
    assert_eq!(passes.len(), 1);
    let mut concurrent = f.command(now() + 60);
    concurrent.arg("--check-only");
    let output = bounded(concurrent).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("another coordinator"));
    child.kill().await.unwrap(); // SIGKILL / TerminateProcess, no graceful destructors.
    assert!(!child.wait().await.unwrap().success());
    let reads = f.reads.load(Ordering::SeqCst);
    let mut restart = f.command(now() + 60);
    restart.arg("--check-only");
    let output = bounded(restart).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("review and remove stale pool-pass"));
    assert_eq!(f.reads.load(Ordering::SeqCst), reads);
    assert_eq!(std::fs::read(&partial).unwrap(), bytes);
    assert_eq!(f.passes(), passes);
    assert!(!f.work().join("pool-report.json").exists());
    // The test owns this exact directory. Model the documented operator review,
    // never delete by a broad glob or touch any real profile.
    std::fs::remove_dir_all(&passes[0]).unwrap();
    f.healthy_restart().await;
}

#[tokio::test]
async fn expiry_cancels_stalled_download_cleans_scratch_and_does_not_renew() {
    let f = Fixture::new().await;
    let expiry = now() + 5;
    let mut c = f.command(expiry);
    c.args(["--allow-reconstruction", "--signer"])
        .arg(f.root.path().join("unused-signer"));
    let child = c.spawn().unwrap();
    f.partial_download().await;
    let output = tokio::time::timeout(Duration::from_secs(8), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("owner pool repair authority expired")
    );
    assert!(f.passes().is_empty());
    assert!(!f.work().join("pool-report.json").exists());
    let reads = f.reads.load(Ordering::SeqCst);
    let mut c = f.command(expiry);
    c.arg("--check-only");
    let output = bounded(c).await;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("owner pool repair authority expired")
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), reads);
    f.healthy_restart().await;
}

#[tokio::test]
async fn unavailable_work_directory_refuses_without_network_and_can_be_retried() {
    let f = Fixture::new().await;
    std::fs::write(f.work(), b"synthetic unrelated file").unwrap();
    let mut c = f.command(now() + 60);
    c.arg("--check-only");
    let output = bounded(c).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("private, ordinary directory"));
    assert_eq!(f.reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read(f.work()).unwrap(),
        b"synthetic unrelated file"
    );
    std::fs::remove_file(f.work()).unwrap();
    f.healthy_restart().await;
}
