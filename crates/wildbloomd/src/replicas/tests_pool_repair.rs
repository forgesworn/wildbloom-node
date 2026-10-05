//! Real HTTP and disk fault tests for the production repair pass. Only the
//! external signer is replaced with a synthetic in-process key.
use super::*;
use crate::replicas::{signer::SignerError, transport::Profile};
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::{get, put},
};
use futures_util::future::BoxFuture;
use nostr::prelude::{Event, EventBuilder, FinalizeEvent, Keys};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
struct NodeState {
    bytes: Vec<u8>,
    reject_upload: bool,
    false_ack: bool,
    // Remove the local destination after a successful GET request, before the
    // client opens it. This simulates unavailable scratch storage without
    // filling or changing permissions on the developer's filesystem.
    break_scratch: Option<PathBuf>,
}
struct Fixture {
    _root: tempfile::TempDir,
    args: RepairArgs,
    receipt: Vec<u8>,
    manifest: pool::Manifest,
    original: Vec<Vec<u8>>,
    nodes: Vec<Arc<Mutex<NodeState>>>,
    reads: Arc<AtomicUsize>,
    uploads: Arc<AtomicUsize>,
    signer: TestSigner,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
struct TestSigner {
    keys: Keys,
    calls: AtomicUsize,
    delay_until: Option<u64>,
}
impl Signer for TestSigner {
    fn sign<'a>(
        &'a self,
        request: &'a UnsignedEvent,
    ) -> BoxFuture<'a, Result<Vec<u8>, SignerError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(deadline) = self.delay_until {
                tokio::time::timeout(Duration::from_secs(10), async {
                    while SystemClock.now() < deadline {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap();
            }
            Ok(request
                .clone()
                .finalize(&self.keys)
                .unwrap()
                .as_json()
                .into_bytes())
        })
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
// Independent 2-of-4 vector: rows [1,0], [0,1], [3,2], [2,3].
fn twice(byte: u8) -> u8 {
    (byte << 1) ^ if byte & 128 != 0 { 0x1d } else { 0 }
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut payload = b"FSWNENC2".to_vec();
        payload.extend((0..1001).map(|i| (i % 251) as u8));
        let size = payload.len().div_ceil(2);
        let a = payload[..size].to_vec();
        let mut b = payload[size..].to_vec();
        b.resize(size, 0);
        let original = vec![
            a.clone(),
            b.clone(),
            a.iter()
                .zip(&b)
                .map(|(a, b)| twice(*a) ^ a ^ twice(*b))
                .collect(),
            a.iter()
                .zip(&b)
                .map(|(a, b)| twice(*a) ^ twice(*b) ^ b)
                .collect(),
        ];
        let reads = Arc::new(AtomicUsize::new(0));
        let uploads = Arc::new(AtomicUsize::new(0));
        let keys = Keys::generate();
        let mut nodes = Vec::new();
        let mut tasks = Vec::new();
        let mut parts = Vec::new();
        for (index, bytes) in original.iter().enumerate() {
            let state = Arc::new(Mutex::new(NodeState {
                bytes: bytes.clone(),
                ..Default::default()
            }));
            let read_state = state.clone();
            let read_count = reads.clone();
            let write_state = state.clone();
            let write_count = uploads.clone();
            let expected = bytes.clone();
            let owner = keys.public_key();
            let app = Router::new()
                .route(
                    &format!("/{}", hash(bytes)),
                    get(move || async move {
                        read_count.fetch_add(1, Ordering::SeqCst);
                        let mut state = read_state.lock().unwrap();
                        if let Some(work) = state.break_scratch.take() {
                            for pass in std::fs::read_dir(work).unwrap().map(Result::unwrap) {
                                if pass.file_name().to_string_lossy().starts_with("pool-pass-") {
                                    // On Unix an open NamedTempFile can be unlinked.
                                    // The replacement directory makes the subsequent
                                    // open fail with EISDIR, even when run as root.
                                    for file in
                                        std::fs::read_dir(pass.path()).unwrap().map(Result::unwrap)
                                    {
                                        std::fs::remove_file(file.path()).unwrap();
                                        std::fs::create_dir(file.path()).unwrap();
                                    }
                                }
                            }
                        }
                        state.bytes.clone()
                    }),
                )
                .route(
                    "/upload",
                    put(move |headers: HeaderMap, body: Bytes| async move {
                        write_count.fetch_add(1, Ordering::SeqCst);
                        let auth = headers["authorization"]
                            .to_str()
                            .unwrap()
                            .strip_prefix("Nostr ")
                            .unwrap();
                        let event = Event::from_json(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(auth)
                                .unwrap(),
                        )
                        .unwrap();
                        event.verify().unwrap();
                        assert_eq!(event.pubkey, owner);
                        assert_eq!(event.kind, Kind::from(24242));
                        let tags: Vec<_> =
                            event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
                        assert!(tags.contains(&vec!["x".into(), hash(&expected)]));
                        assert!(tags.contains(&vec!["t".into(), "upload".into()]));
                        assert!(tags.contains(&vec!["server".into(), "127.0.0.1".into()]));
                        let expiry = tags.iter().find(|t| t[0] == "expiration").unwrap()[1]
                            .parse::<u64>()
                            .unwrap();
                        assert!(expiry > SystemClock.now());
                        assert_eq!(headers["x-sha-256"], hash(&expected));
                        assert_eq!(body.as_ref(), expected);
                        let mut state = write_state.lock().unwrap();
                        if state.reject_upload {
                            return StatusCode::INSUFFICIENT_STORAGE;
                        }
                        if !state.false_ack {
                            state.bytes = body.to_vec();
                        }
                        StatusCode::CREATED
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}/", listener.local_addr().unwrap());
            tasks.push(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
            parts.push(json!({"index":index,"sha256":hash(bytes),"size":size,"targets":[{"id":format!("node-{index}"),"origin":origin,"failure_group":format!("site-{index}"),"weight":1}]}));
            nodes.push(state);
        }
        let manifest = json!({"type":"wildbloom.pool","version":1,"mode":"erasure","profile":"direct","payload":{"sha256":hash(&payload),"size":payload.len(),"encryption":"forgesworn-aes-256-gcm-chunked-v2"},"required":2,"total":4,"copies":1,"parts":parts});
        let event = EventBuilder::new(Kind::from(30078), manifest.to_string())
            .tag(Tag::identifier(format!(
                "wildbloom.pool.v1:{}",
                hash(&payload)
            )))
            .finalize(&keys)
            .unwrap();
        let receipt = event.as_json().into_bytes();
        let receipt_path = root.path().join("receipt.json");
        std::fs::write(&receipt_path, &receipt).unwrap();
        let work_dir = root.path().join("work");
        state::private_directory(&work_dir).unwrap();
        let args = RepairArgs {
            receipt: receipt_path,
            receipt_id: event.id.to_hex(),
            owner: keys.public_key().to_hex(),
            work_dir,
            allow_reconstruction: true,
            check_only: false,
            stop_on_stdin: false,
            expires_at: SystemClock.now() + 60,
            signer: Some(root.path().join("unused-signer")),
            signer_arg: vec![],
            signer_timeout: 5,
            proxy: None,
            permit_loopback_development: true,
            once: true,
            interval: 5,
            transfer_budget_bytes: 1024 * 1024,
            max_work_bytes: 1024 * 1024,
        };
        // Exercise the real receipt validator, too.
        let (manifest, _) = pool::receipt(
            &receipt,
            &args.owner,
            &args.receipt_id,
            SystemClock.now(),
            true,
        )
        .unwrap();
        Self {
            _root: root,
            args,
            receipt,
            manifest,
            original,
            nodes,
            reads,
            uploads,
            signer: TestSigner {
                keys,
                calls: AtomicUsize::new(0),
                delay_until: None,
            },
            tasks,
        }
    }
    async fn pass(&self) -> Result<Report, Error> {
        let guard = Guard {
            args: &self.args,
            bytes: &self.receipt,
        };
        let transport = HttpTransport::new(Profile::LoopbackDevelopment, None, true).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            pass(&guard, &self.manifest, &transport, &self.signer),
        )
        .await
        .expect("bounded repair pass");
        assert!(
            !std::fs::read_dir(&self.args.work_dir).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("pool-pass-")),
            "temporary parts must be removed on success or failure"
        );
        result
    }
    fn damage_data(&self) {
        self.nodes[0].lock().unwrap().bytes[0] ^= 1; // Correct length, wrong hash.
        self.nodes[1].lock().unwrap().bytes.truncate(1); // Wrong length.
    }
    fn assert_original(&self) {
        for (node, expected) in self.nodes.iter().zip(&self.original) {
            assert_eq!(&node.lock().unwrap().bytes, expected);
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::test]
async fn corrupted_parts_are_rejected_and_rebuilt_from_verified_parity() {
    let f = Fixture::new().await;
    f.damage_data();
    let report = f.pass().await.unwrap();
    assert!(report.protected && report.recoverable && report.reconstructed);
    assert_eq!(report.uploads_attempted, 2);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 2);
    assert_eq!(report.verified_groups, vec![1; 4]);
    f.assert_original();
    let report = f.pass().await.unwrap();
    assert!(report.protected && !report.reconstructed);
    assert_eq!(report.uploads_attempted, 0);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn corruption_below_threshold_never_signs_or_uploads() {
    let f = Fixture::new().await;
    f.damage_data();
    f.nodes[2].lock().unwrap().bytes[0] ^= 1;
    let report = f.pass().await.unwrap();
    assert!(!report.protected && !report.recoverable && !report.reconstructed);
    assert_eq!(report.verified_groups, vec![0, 0, 0, 1]);
    assert_eq!(report.uploads_attempted, 0);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.uploads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn full_target_and_false_ack_remain_degraded_until_verified_retry() {
    let f = Fixture::new().await;
    f.damage_data();
    f.nodes[0].lock().unwrap().reject_upload = true;
    f.nodes[1].lock().unwrap().false_ack = true;
    let report = f.pass().await.unwrap();
    assert!(!report.protected && report.recoverable && report.reconstructed);
    assert_eq!(report.verified_groups, vec![0, 0, 1, 1]);
    assert_eq!(report.uploads_attempted, 2);
    f.nodes[0].lock().unwrap().reject_upload = false;
    f.nodes[1].lock().unwrap().false_ack = false;
    assert!(f.pass().await.unwrap().protected);
    assert_eq!(f.uploads.load(Ordering::SeqCst), 4);
    f.assert_original();
}

#[tokio::test]
async fn disk_budget_refuses_before_network_and_retries_after_correction() {
    let mut f = Fixture::new().await;
    f.args.max_work_bytes = 1;
    assert_eq!(
        f.pass().await.err().unwrap().to_string(),
        "pool layout exceeds temporary disk budget"
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 0);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    f.args.max_work_bytes = 1024 * 1024;
    assert!(f.pass().await.unwrap().protected);
}

#[cfg(unix)]
#[tokio::test]
async fn unavailable_local_download_storage_stops_without_blame_or_uploads() {
    let f = Fixture::new().await;
    f.nodes[0].lock().unwrap().break_scratch = Some(f.args.work_dir.clone());
    assert_eq!(
        f.pass().await.err().unwrap().to_string(),
        "could not write owner repair temporary storage"
    );
    assert_eq!(f.reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.uploads.load(Ordering::SeqCst), 0);
    assert!(f.pass().await.unwrap().protected);
}

#[tokio::test]
async fn signature_return_after_authority_expiry_never_uploads() {
    let mut f = Fixture::new().await;
    f.damage_data();
    f.args.expires_at = SystemClock.now() + 2;
    f.signer.delay_until = Some(f.args.expires_at);
    assert_eq!(
        f.pass().await.err().unwrap().to_string(),
        "owner pool repair authority expired"
    );
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.uploads.load(Ordering::SeqCst), 0);
    // No implicit renewal: a second attempt still refuses before more I/O.
    let reads = f.reads.load(Ordering::SeqCst);
    assert!(f.pass().await.is_err());
    assert_eq!(f.reads.load(Ordering::SeqCst), reads);
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), 1);
}
