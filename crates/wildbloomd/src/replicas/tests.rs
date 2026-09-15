use super::{engine::*, policy::*, signer::*, state::*, transport::*, *};
use futures_util::future::BoxFuture;
use nostr::prelude::{FinalizeEvent, Keys, UnsignedEvent};
use std::{
    collections::BTreeSet,
    sync::{
        Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

const NOW: u64 = 1_800_000_000;
const LIMITS: Limits = Limits {
    verification_bytes: 1000,
    mirrors: 4,
};

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn policy() -> Policy {
    Policy {
        policy_type: "wildbloom.replica-policy".into(),
        version: 1,
        id: "synthetic-test".into(),
        revision: 1,
        expires_at: NOW + 3600,
        profile: Profile::LoopbackDevelopment,
        desired_groups: 2,
        targets: (1..=3)
            .map(|n| Target {
                id: format!("node-{n}"),
                origin: format!("http://127.0.0.1:{}/", 4000 + n),
                failure_group: format!("group-{n}"),
                retention: Retention::Owner,
            })
            .collect(),
        blobs: vec![Blob {
            sha256: "ab".repeat(32),
            size: 10,
        }],
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
    state_path: PathBuf,
    keys: Keys,
    clock: TestClock,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let f = Self {
            path: root.path().join("policy.json"),
            state_path: root.path().join("state"),
            _root: root,
            keys: Keys::generate(),
            clock: TestClock(AtomicU64::new(NOW)),
        };
        f.write(policy());
        f
    }
    fn write(&self, policy: Policy) {
        let event = policy_template(policy, &self.keys.public_key().to_hex(), NOW)
            .unwrap()
            .finalize(&self.keys)
            .unwrap();
        std::fs::write(&self.path, serde_json::to_vec(&event).unwrap()).unwrap();
    }
    fn load(&self) -> VerifiedPolicy {
        load_policy(
            &self.path,
            &self.keys.public_key().to_hex(),
            self.clock.now(),
        )
        .unwrap()
    }
    async fn pass(
        &self,
        state: &mut StateDirectory,
        net: &dyn Transport,
        signer: Option<&dyn Signer>,
        limits: Limits,
    ) -> Result<Report, Error> {
        let policy = self.load();
        run_pass(
            &Guard {
                path: &self.path,
                expected: &policy,
                clock: &self.clock,
            },
            state,
            net,
            signer,
            limits,
        )
        .await
    }
}

struct TestSigner {
    keys: Keys,
    calls: AtomicUsize,
    change: bool,
    after_sign: Option<Box<dyn Fn() + Send + Sync>>,
}
impl TestSigner {
    fn new(keys: &Keys) -> Self {
        Self {
            keys: keys.clone(),
            calls: AtomicUsize::new(0),
            change: false,
            after_sign: None,
        }
    }
}
impl Signer for TestSigner {
    fn sign<'a>(
        &'a self,
        request: &'a UnsignedEvent,
    ) -> BoxFuture<'a, Result<Vec<u8>, SignerError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut request = request.clone();
            if self.change {
                request.content.push_str(" changed");
            }
            if let Some(hook) = &self.after_sign {
                hook();
            }
            Ok(serde_json::to_vec(&request.finalize(&self.keys).unwrap()).unwrap())
        })
    }
}

#[tokio::test]
async fn policy_removed_while_signer_runs_cannot_authorise_a_write() {
    let f = Fixture::new();
    let path = f.path.clone();
    let mut signer = TestSigner::new(&f.keys);
    signer.after_sign = Some(Box::new(move || {
        std::fs::remove_file(&path).unwrap();
    }));
    let net = TestNet::new(&["node-1"]);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    assert!(
        f.pass(&mut state, &net, Some(&signer), LIMITS)
            .await
            .is_err()
    );
    assert_eq!(net.mirrors.load(Ordering::SeqCst), 0);
    assert!(state.snapshot.as_ref().unwrap().pending.is_empty());
}

#[tokio::test]
async fn signed_return_wakes_the_default_interval_before_its_authorisation_expires() {
    let f = Fixture::new();
    let net = TestNet::new(&["node-1"]);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    f.pass(&mut state, &net, None, LIMITS).await.unwrap();
    let id = state
        .snapshot
        .as_ref()
        .unwrap()
        .pending
        .values()
        .next()
        .unwrap()
        .event_id
        .clone();
    std::fs::write(
        state.pending_path(&id, true),
        b"invalid signed return still needs examination",
    )
    .unwrap();
    tokio::time::timeout(
        Duration::from_millis(100),
        wait_for_work(&state, Duration::from_secs(300)),
    )
    .await
    .unwrap();
}

#[test]
fn interrupted_temporary_write_keeps_the_committed_revision_and_unknown_state_refuses() {
    let f = Fixture::new();
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    state.accept(&f.load()).unwrap();
    drop(state);
    std::fs::write(f.state_path.join(".tmp-interrupted"), b"{\"revision\":999,").unwrap();
    let state = StateDirectory::open(&f.state_path).unwrap();
    assert_eq!(state.snapshot.as_ref().unwrap().revision, 1);
    drop(state);
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(f.state_path.join("state.json")).unwrap()).unwrap();
    json["version"] = 2.into();
    std::fs::write(
        f.state_path.join("state.json"),
        serde_json::to_vec(&json).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        StateDirectory::open(&f.state_path),
        Err(StateError::Schema)
    ));
}

#[test]
fn same_second_requests_bind_the_policy_revision_and_exact_configured_destination() {
    let f = Fixture::new();
    let first = f.load();
    let request = repair_template(
        &first,
        &first.policy.blobs[0],
        &first.policy.targets[0],
        NOW,
    )
    .unwrap();
    let returned = serde_json::to_vec(&request.clone().finalize(&f.keys).unwrap()).unwrap();
    let another_target = repair_template(
        &first,
        &first.policy.blobs[0],
        &first.policy.targets[1],
        NOW,
    )
    .unwrap();
    assert!(verify_return(&returned, &another_target, NOW).is_err());
    let mut updated = policy();
    updated.revision = 2;
    f.write(updated);
    let updated = f.load();
    let new_request = repair_template(
        &updated,
        &updated.policy.blobs[0],
        &updated.policy.targets[0],
        NOW,
    )
    .unwrap();
    assert!(verify_return(&returned, &new_request, NOW).is_err());
}

struct TestNet {
    present: Mutex<BTreeSet<String>>,
    verifies: AtomicUsize,
    mirrors: AtomicUsize,
    false_ack: bool,
    refused: BTreeSet<String>,
    before_reply: Option<Box<dyn Fn() + Send + Sync>>,
}
impl TestNet {
    fn new(nodes: &[&str]) -> Self {
        Self {
            present: Mutex::new(nodes.iter().map(|v| (*v).to_owned()).collect()),
            verifies: AtomicUsize::new(0),
            mirrors: AtomicUsize::new(0),
            false_ack: false,
            refused: BTreeSet::new(),
            before_reply: None,
        }
    }
}
impl Transport for TestNet {
    fn verify<'a>(
        &'a self,
        target: &'a Target,
        _: &'a Blob,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async move {
            self.verifies.fetch_add(1, Ordering::SeqCst);
            if let Some(hook) = &self.before_reply {
                hook();
            }
            if self.present.lock().unwrap().contains(&target.id) {
                Ok(())
            } else {
                Err(NetworkFailure::Unavailable)
            }
        })
    }
    fn mirror<'a>(
        &'a self,
        target: &'a Target,
        _: &'a Target,
        blob: &'a Blob,
        header: &'a str,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async move {
            self.mirrors.fetch_add(1, Ordering::SeqCst);
            let host = Url::parse(&target.origin)
                .unwrap()
                .host_str()
                .unwrap()
                .to_owned();
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header.strip_prefix("Nostr ").unwrap())
                .unwrap();
            let event = nostr::prelude::Event::from_json(bytes).unwrap();
            assert!(
                wildbloom_core::auth::AuthPolicy::new([host])
                    .with_allowed_pubkeys([event.pubkey.to_hex()])
                    .verify_upload(Some(header), &blob.sha256, NOW)
                    .is_ok()
            );
            if self.refused.contains(&target.id) {
                return Err(NetworkFailure::Refused);
            }
            if !self.false_ack {
                self.present.lock().unwrap().insert(target.id.clone());
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn restores_floor_rechecks_after_restart_and_uses_another_destination() {
    let f = Fixture::new();
    let signer = TestSigner::new(&f.keys);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let net = TestNet::new(&["node-1"]);
    assert_eq!(
        f.pass(&mut state, &net, Some(&signer), LIMITS)
            .await
            .unwrap()
            .blobs[0]
            .verified_configured_groups,
        2
    );
    assert_eq!(net.verifies.load(Ordering::SeqCst), 4);
    drop(state);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let mut net = TestNet::new(&["node-2"]);
    net.refused.insert("node-1".into());
    let report = f
        .pass(&mut state, &net, Some(&signer), LIMITS)
        .await
        .unwrap();
    assert_eq!(report.blobs[0].verified_configured_groups, 2);
    assert!(matches!(
        report.blobs[0].observations["node-1"],
        Observation::Failed { .. }
    ));
    assert!(matches!(
        report.blobs[0].observations["node-3"],
        Observation::Verified { .. }
    ));
    let empty = TestNet::new(&[]);
    assert_eq!(
        f.pass(&mut state, &empty, Some(&signer), LIMITS)
            .await
            .unwrap()
            .blobs[0]
            .verified_configured_groups,
        0
    );
    assert_eq!(empty.mirrors.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn acknowledgements_and_modified_signed_returns_never_count() {
    let f = Fixture::new();
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let mut net = TestNet::new(&["node-1"]);
    net.false_ack = true;
    let mut signer = TestSigner::new(&f.keys);
    assert_eq!(
        f.pass(&mut state, &net, Some(&signer), LIMITS)
            .await
            .unwrap()
            .blobs[0]
            .verified_configured_groups,
        1
    );
    let writes = net.mirrors.load(Ordering::SeqCst);
    signer.change = true;
    let report = f
        .pass(&mut state, &net, Some(&signer), LIMITS)
        .await
        .unwrap();
    assert_eq!(net.mirrors.load(Ordering::SeqCst), writes);
    assert!(matches!(
        report.blobs[0].observations["node-2"],
        Observation::SignerUnavailable
    ));
    let persisted = std::fs::read_to_string(f.state_path.join("state.json")).unwrap();
    assert!(!persisted.contains("\"sig\"") && !persisted.contains("Nostr "));
}

#[tokio::test]
async fn manual_handoff_is_stable_across_restart_and_consumes_only_exact_return() {
    let f = Fixture::new();
    let net = TestNet::new(&["node-1"]);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let report = f.pass(&mut state, &net, None, LIMITS).await.unwrap();
    assert_eq!(report.pending_event_ids.len(), 2);
    let id = state.snapshot.as_ref().unwrap().pending[&format!("{}:node-2", "ab".repeat(32))]
        .event_id
        .clone();
    let request: UnsignedEvent =
        serde_json::from_slice(&std::fs::read(state.pending_path(&id, false)).unwrap()).unwrap();
    drop(state);
    f.clock.0.store(NOW + 10, Ordering::SeqCst);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let again = f.pass(&mut state, &net, None, LIMITS).await.unwrap();
    assert_eq!(again.pending_event_ids, report.pending_event_ids);
    std::fs::write(
        state.pending_path(&id, true),
        serde_json::to_vec(&request.finalize(&f.keys).unwrap()).unwrap(),
    )
    .unwrap();
    let report = f.pass(&mut state, &net, None, LIMITS).await.unwrap();
    assert_eq!(report.blobs[0].verified_configured_groups, 2);
    assert!(!state.pending_path(&id, true).exists() && !state.pending_path(&id, false).exists());
    f.clock.0.store(NOW + 121, Ordering::SeqCst);
    f.pass(&mut state, &net, None, LIMITS).await.unwrap();
    assert!(state.snapshot.as_ref().unwrap().pending.is_empty());
}

#[tokio::test]
async fn policy_change_during_network_invalidates_observation_and_prevents_signing() {
    let f = Fixture::new();
    let signer = TestSigner::new(&f.keys);
    let mut net = TestNet::new(&["node-1"]);
    let path = f.path.clone();
    net.before_reply = Some(Box::new(move || {
        let _ = std::fs::remove_file(&path);
    }));
    let policy = f.load();
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    assert!(
        run_pass(
            &Guard {
                path: &f.path,
                expected: &policy,
                clock: &f.clock
            },
            &mut state,
            &net,
            Some(&signer),
            LIMITS
        )
        .await
        .is_err()
    );
    assert_eq!(net.verifies.load(Ordering::SeqCst), 1);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
    assert!(state.snapshot.as_ref().unwrap().observations.is_empty());
}

#[tokio::test]
async fn stop_replay_and_small_budget_perform_no_network_work() {
    let f = Fixture::new();
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let net = TestNet::new(&["node-1"]);
    let signer = TestSigner::new(&f.keys);
    assert!(
        f.pass(
            &mut state,
            &net,
            Some(&signer),
            Limits {
                verification_bytes: 69,
                mirrors: 4
            }
        )
        .await
        .is_err()
    );
    let mut stop = policy();
    stop.revision = 2;
    stop.desired_groups = 0;
    f.write(stop);
    assert!(
        f.pass(&mut state, &net, Some(&signer), LIMITS)
            .await
            .unwrap()
            .stopped
    );
    drop(state);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    f.write(policy());
    assert!(matches!(
        f.pass(&mut state, &net, Some(&signer), LIMITS).await,
        Err(Error::State(StateError::Rollback))
    ));
    assert_eq!(net.verifies.load(Ordering::SeqCst), 0);
    assert_eq!(signer.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn shared_groups_and_friend_sources_do_not_inflate_owned_floor() {
    let f = Fixture::new();
    let mut p = policy();
    p.targets[0].retention = Retention::Friend;
    p.targets[1].failure_group = "shared".into();
    p.targets[2].failure_group = "shared".into();
    assert!(p.validate().is_err());
    p.desired_groups = 1;
    f.write(p);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let signer = TestSigner::new(&f.keys);
    let report = f
        .pass(
            &mut state,
            &TestNet::new(&["node-1"]),
            Some(&signer),
            LIMITS,
        )
        .await
        .unwrap();
    assert_eq!(report.blobs[0].verified_configured_groups, 1);
    assert_eq!(report.mirror_attempts, 1);
}

#[tokio::test]
async fn rotating_cursor_eventually_checks_every_blob_under_a_small_budget() {
    let f = Fixture::new();
    let mut p = policy();
    p.blobs.push(Blob {
        sha256: "cd".repeat(32),
        size: 10,
    });
    f.write(p);
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    let net = TestNet::new(&["node-1", "node-2"]);
    let limits = Limits {
        verification_bytes: 70,
        mirrors: 4,
    };
    let first = f.pass(&mut state, &net, None, limits).await.unwrap();
    assert_eq!(first.blobs[0].verified_configured_groups, 2);
    assert_eq!(first.blobs[1].verified_configured_groups, 0);
    let second = f.pass(&mut state, &net, None, limits).await.unwrap();
    assert_eq!(second.blobs[0].verified_configured_groups, 0);
    assert_eq!(second.blobs[1].verified_configured_groups, 2);
    assert_eq!(net.verifies.load(Ordering::SeqCst), 6);
}

#[test]
fn strict_signature_schema_expiry_and_profile_validation() {
    let f = Fixture::new();
    let owner = f.keys.public_key().to_hex();
    let bytes = std::fs::read(&f.path).unwrap();
    assert!(verify_policy(&bytes, &Keys::generate().public_key().to_hex(), NOW).is_err());
    assert!(verify_policy(&bytes, &owner, NOW + 3600).is_err());
    assert!(verify_policy(&bytes, &owner, NOW - 31).is_err());
    for field in ["sig", "id", "content"] {
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json[field] = "00".into();
        assert!(verify_policy(&serde_json::to_vec(&json).unwrap(), &owner, NOW).is_err());
    }
    let duplicate = format!(
        "{{\"kind\":30078,{}",
        std::str::from_utf8(&bytes).unwrap().trim_start_matches('{')
    );
    assert!(verify_policy(duplicate.as_bytes(), &owner, NOW).is_err());
    let mut p = policy();
    p.targets[0].origin = "http://localhost:4001/".into();
    assert!(p.validate().is_err());
    p.targets[0].origin = "http://127.0.0.1:4001/path".into();
    assert!(p.validate().is_err());
    p.targets[0].origin = "http://127.0.0.1:4001/".into();
    p.blobs[0].size = MAX_BLOB_BYTES + 1;
    assert!(p.validate().is_err());
    assert!(verify_policy(&vec![b' '; MAX_POLICY_BYTES + 1], &owner, NOW).is_err());
}

#[test]
fn state_lock_rollback_identity_and_corruption_survive_restart() {
    let f = Fixture::new();
    let mut state = StateDirectory::open(&f.state_path).unwrap();
    assert!(matches!(
        StateDirectory::open(&f.state_path),
        Err(StateError::Locked)
    ));
    state.accept(&f.load()).unwrap();
    let mut changed = policy();
    changed.expires_at += 1;
    f.write(changed);
    assert!(matches!(state.accept(&f.load()), Err(StateError::Rollback)));
    let mut changed = policy();
    changed.id = "other".into();
    changed.revision = 2;
    f.write(changed);
    assert!(matches!(state.accept(&f.load()), Err(StateError::Identity)));
    drop(state);
    std::fs::write(f.state_path.join("state.json"), b"{}").unwrap();
    assert!(matches!(
        StateDirectory::open(&f.state_path),
        Err(StateError::Schema)
    ));
}

#[cfg(unix)]
#[test]
fn dangling_state_symlink_cannot_reset_rollback_protection() {
    let f = Fixture::new();
    drop(StateDirectory::open(&f.state_path).unwrap());
    std::os::unix::fs::symlink(f.state_path.join("absent"), f.state_path.join("state.json"))
        .unwrap();
    assert!(StateDirectory::open(&f.state_path).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn local_signer_process_handles_exact_return_failure_oversize_and_timeout() {
    let f = Fixture::new();
    let p = f.load();
    let request = repair_template(&p, &p.policy.blobs[0], &p.policy.targets[1], NOW).unwrap();
    let signed_path = f._root.path().join("synthetic-signed.json");
    std::fs::write(
        &signed_path,
        serde_json::to_vec(&request.clone().finalize(&f.keys).unwrap()).unwrap(),
    )
    .unwrap();
    let mut signer = CommandSigner {
        executable: "/bin/sh".into(),
        arguments: vec![
            "-c".into(),
            "cat >/dev/null; cat \"$1\"".into(),
            "fixture".into(),
            signed_path.to_str().unwrap().into(),
        ],
        timeout: Duration::from_secs(2),
    };
    let returned = signer.sign(&request).await.unwrap();
    assert!(verify_return(&returned, &request, NOW).is_ok());
    assert!(verify_return(&returned, &request, NOW + 120).is_err());
    for script in [
        "exit 1",
        "cat >/dev/null; head -c 16385 /dev/zero",
        "exec sleep 3",
    ] {
        signer.arguments = vec!["-c".into(), script.into()];
        signer.timeout = Duration::from_millis(50);
        assert!(signer.sign(&request).await.is_err());
    }
    signer.executable = "relative-helper".into();
    assert!(signer.sign(&request).await.is_err());
}
