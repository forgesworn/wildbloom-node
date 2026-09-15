use super::{
    engine::{Clock, load_policy},
    enrol::{self, Config, InventoryRow, TargetSpec},
    policy::PolicyError,
    signer::{Signer, SignerError},
    state::{Observation, Snapshot},
    transport::Profile,
    *,
};
use futures_util::future::BoxFuture;
use nostr::prelude::{FinalizeEvent, Keys, UnsignedEvent};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct KeySigner {
    keys: Keys,
    calls: AtomicUsize,
    tamper: bool,
}
impl Signer for KeySigner {
    fn sign<'a>(
        &'a self,
        request: &'a UnsignedEvent,
    ) -> BoxFuture<'a, Result<Vec<u8>, SignerError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut request = request.clone();
            if self.tamper {
                let mut policy: serde_json::Value = serde_json::from_str(&request.content).unwrap();
                policy["desired_groups"] = serde_json::json!(1);
                request = UnsignedEvent::new(
                    request.pubkey,
                    request.created_at,
                    request.kind,
                    request.tags.clone(),
                    policy.to_string(),
                );
            }
            Ok(serde_json::to_vec(&request.finalize(&self.keys).unwrap()).unwrap())
        })
    }
}

struct Fixture {
    root: tempfile::TempDir,
    keys: Keys,
    signer: KeySigner,
    clock: TestClock,
}

fn hash(n: u64) -> String {
    format!("{n:064x}")
}

fn row(n: u64) -> InventoryRow {
    InventoryRow {
        sha256: hash(n),
        size: 100 + n,
        content_type: Some("application/vnd.test".into()),
        uploaded: Some(1_000 + n),
    }
}

impl Fixture {
    fn new() -> Self {
        let keys = Keys::generate();
        Self {
            root: tempfile::tempdir().unwrap(),
            signer: KeySigner {
                keys: keys.clone(),
                calls: AtomicUsize::new(0),
                tamper: false,
            },
            keys,
            clock: TestClock(AtomicU64::new(NOW)),
        }
    }
    fn owner(&self) -> String {
        self.keys.public_key().to_hex()
    }
    fn config(&self) -> Config {
        Config {
            root: self.root.path().to_owned(),
            state_root: None,
            owner: Some(self.owner()),
            owner_file: None,
            signer: "/synthetic/signer".into(),
            signer_args: Vec::new(),
            signer_timeout_secs: 30,
            policy_prefix: "synthetic".into(),
            profile: Profile::LoopbackDevelopment,
            source: TargetSpec {
                id: "source".into(),
                origin: "http://127.0.0.1:4001/".into(),
            },
            archives: vec![
                TargetSpec {
                    id: "archive-one".into(),
                    origin: "http://127.0.0.1:4002/".into(),
                },
                TargetSpec {
                    id: "archive-two".into(),
                    origin: "http://127.0.0.1:4003/".into(),
                },
            ],
            accept_types: Some(vec!["application/vnd.test".into()]),
            policy_ttl_days: 30,
            renew_below_days: 7,
            intake_grace_days: 7,
        }
    }
    async fn enrol(&self, rows: &[InventoryRow]) -> enrol::Report {
        self.enrol_with(&self.config(), rows, false).await.unwrap()
    }
    async fn enrol_with(
        &self,
        config: &Config,
        rows: &[InventoryRow],
        dry_run: bool,
    ) -> Result<enrol::Report, Error> {
        enrol::run(config, rows, Some(&self.signer), &self.clock, dry_run).await
    }
    fn signed_ids(report: &enrol::Report) -> Vec<&str> {
        report.signed.iter().map(|s| s.id.as_str()).collect()
    }
    fn latest_event(&self, id: &str) -> String {
        std::fs::read_to_string(self.root.path().join("state/policy-history.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .rfind(|record| record["id"] == id)
            .unwrap()["event"]
            .as_str()
            .unwrap()
            .to_owned()
    }
    /// What the intake coordinator writes after a pass over `event`.
    fn intake_state(&self, event: &str, verified: &[(u64, &[&str])]) {
        let mut observations = BTreeMap::new();
        for (n, on) in verified {
            let mut targets = BTreeMap::new();
            for id in ["archive-one", "archive-two"] {
                targets.insert(
                    id.to_owned(),
                    if on.contains(&id) {
                        Observation::Verified { at: NOW }
                    } else {
                        Observation::Deferred
                    },
                );
            }
            observations.insert(hash(*n), targets);
        }
        let snapshot = Snapshot {
            version: 1,
            owner: self.owner(),
            policy_id: "synthetic-intake".into(),
            revision: 1,
            event_id: event.to_owned(),
            profile: Profile::LoopbackDevelopment,
            observed_at: Some(NOW),
            cursor: 0,
            repair_cursors: BTreeMap::new(),
            observations,
            pending: BTreeMap::new(),
        };
        let dir = self.root.path().join("coordinators/synthetic-intake");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("state.json"),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
    }
    fn signed_policy(&self, id: &str) -> Policy {
        load_policy(
            &self.root.path().join(format!("policies/signed-{id}.json")),
            &self.owner(),
            self.clock.now(),
        )
        .unwrap()
        .policy
    }
    fn lines(&self, name: &str) -> usize {
        std::fs::read_to_string(self.root.path().join("state").join(name))
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }
}

use super::policy::Policy;

fn rows(range: std::ops::Range<u64>) -> Vec<InventoryRow> {
    range.map(row).collect()
}

#[tokio::test]
async fn first_run_enrols_everything_into_one_intake_policy_the_coordinator_accepts() {
    let f = Fixture::new();
    let report = f.enrol(&rows(1..7)).await;
    assert_eq!(report.new.len(), 6);
    assert_eq!(report.ledger.intake, 6);
    assert_eq!(Fixture::signed_ids(&report), ["synthetic-intake"]);
    let policy = f.signed_policy("synthetic-intake");
    assert_eq!(policy.blobs.len(), 6);
    assert_eq!(policy.desired_groups, 2);
    assert_eq!(policy.targets[0].retention, super::policy::Retention::Guest);
    assert!(Path::new(&f.root.path().join("coordinators/synthetic-intake")).is_dir());
}

#[tokio::test]
async fn unchanged_input_and_dry_runs_sign_and_write_nothing() {
    let f = Fixture::new();
    f.enrol(&rows(1..7)).await;
    let calls = f.signer.calls.load(Ordering::SeqCst);
    let again = f.enrol(&rows(1..7)).await;
    assert!(again.signed.is_empty());
    assert_eq!(again.unchanged, ["synthetic-intake"]);
    let dry = f.enrol_with(&f.config(), &rows(1..9), true).await.unwrap();
    assert!(dry.dry_run && dry.signed.iter().all(|s| s.dry_run && s.event.is_none()));
    assert_eq!(f.signer.calls.load(Ordering::SeqCst), calls);
    assert_eq!(f.lines("ledger.jsonl"), 6);
}

#[tokio::test]
async fn coordinator_state_is_trusted_only_for_an_event_this_enrolment_signed() {
    let f = Fixture::new();
    f.enrol(&rows(1..7)).await;
    f.intake_state(&"ab".repeat(32), &[(1, &["archive-one", "archive-two"])]);
    let report = f.enrol(&rows(1..7)).await;
    assert!(!report.intake_state_trusted);
    assert!(report.archived.is_empty() && report.signed.is_empty());
}

#[tokio::test]
async fn verified_blobs_move_to_prefix_chunks_and_partial_copies_wait_for_grace() {
    let f = Fixture::new();
    let inventory: Vec<InventoryRow> = [0x11_u64, 0x12, 0x21, 0x31]
        .into_iter()
        .map(|n| InventoryRow {
            sha256: format!("{n:x}{}", "0".repeat(62)),
            ..row(n)
        })
        .collect();
    let first = f.enrol(&inventory).await;
    let event = first.signed[0].event.clone().unwrap();
    let both: &[&str] = &["archive-one", "archive-two"];
    let only_one: &[&str] = &["archive-one"];
    let hash_of = |row: &InventoryRow| row.sha256.clone();
    // Observations keyed by the real inventory hashes.
    let mut observations = BTreeMap::new();
    for (row, on) in inventory.iter().zip([both, both, both, only_one]) {
        let mut targets = BTreeMap::new();
        for id in ["archive-one", "archive-two"] {
            targets.insert(
                id.to_owned(),
                if on.contains(&id) {
                    Observation::Verified { at: NOW }
                } else {
                    Observation::Deferred
                },
            );
        }
        observations.insert(hash_of(row), targets);
    }
    let dir = f.root.path().join("coordinators/synthetic-intake");
    let snapshot = Snapshot {
        version: 1,
        owner: f.owner(),
        policy_id: "synthetic-intake".into(),
        revision: 1,
        event_id: event,
        profile: Profile::LoopbackDevelopment,
        observed_at: Some(NOW),
        cursor: 0,
        repair_cursors: BTreeMap::new(),
        observations,
        pending: BTreeMap::new(),
    };
    std::fs::write(
        dir.join("state.json"),
        serde_json::to_vec(&snapshot).unwrap(),
    )
    .unwrap();

    let report = f.enrol(&inventory).await;
    assert!(report.intake_state_trusted);
    assert_eq!(report.archived.len(), 3);
    assert_eq!(report.ledger.intake, 1);
    assert_eq!(
        Fixture::signed_ids(&report),
        [
            "synthetic-archive-1",
            "synthetic-archive-2",
            "synthetic-intake"
        ]
    );
    assert_eq!(f.signed_policy("synthetic-archive-1").blobs.len(), 2);
    assert!(
        f.signed_policy("synthetic-archive-1")
            .targets
            .iter()
            .all(|t| t.id != "source")
    );
    let settled = f.enrol(&inventory).await;
    assert!(
        settled.signed.is_empty(),
        "stale but trusted state must not churn"
    );

    // Past the grace period the partial copy is archived for archive-to-archive repair.
    f.clock.0.store(NOW + 8 * DAY, Ordering::SeqCst);
    let aged = f.enrol(&inventory).await;
    assert_eq!(aged.archived.len(), 1);
    assert_eq!(aged.archived[0].verified_on, ["archive-one"]);
}

#[tokio::test]
async fn a_new_blob_touches_intake_first_and_then_exactly_one_chunk() {
    let f = Fixture::new();
    let first = f.enrol(&rows(1..3)).await;
    f.intake_state(
        first.signed[0].event.as_deref().unwrap(),
        &[
            (1, &["archive-one", "archive-two"]),
            (2, &["archive-one", "archive-two"]),
        ],
    );
    f.enrol(&rows(1..3)).await;
    let arrived = f.enrol(&rows(1..4)).await;
    assert_eq!(arrived.new, [hash(3)]);
    assert_eq!(Fixture::signed_ids(&arrived), ["synthetic-intake"]);
    f.intake_state(
        &f.latest_event("synthetic-intake"),
        &[(3, &["archive-one", "archive-two"])],
    );
    let moved = f.enrol(&rows(1..4)).await;
    assert_eq!(
        Fixture::signed_ids(&moved),
        ["synthetic-archive-0", "synthetic-intake"]
    );
}

#[tokio::test]
async fn the_ledger_outlives_the_source_and_reports_an_uncopied_loss_once() {
    let f = Fixture::new();
    let first = f.enrol(&rows(1..4)).await;
    f.intake_state(
        first.signed[0].event.as_deref().unwrap(),
        &[(1, &["archive-one", "archive-two"])],
    );
    f.enrol(&rows(1..4)).await;
    let forgotten = f.enrol(&rows(2..4)).await;
    assert!(forgotten.lost.is_empty() && forgotten.signed.is_empty());
    assert_eq!(forgotten.ledger.archived, 1);
    let lost = f.enrol(&rows(3..4)).await;
    assert_eq!(lost.lost, [hash(2)]);
    assert!(f.enrol(&rows(3..4)).await.lost.is_empty());
}

#[tokio::test]
async fn foreign_types_are_counted_and_malformed_inventories_are_refused() {
    let f = Fixture::new();
    let mut inventory = rows(1..3);
    inventory.push(InventoryRow {
        content_type: Some("image/png".into()),
        ..row(9)
    });
    inventory.push(InventoryRow {
        content_type: None,
        ..row(8)
    });
    let report = f.enrol(&inventory).await;
    assert_eq!((report.foreign_types, report.new.len()), (2, 2));

    let mut changed = rows(1..3);
    changed[0].size += 1;
    assert!(matches!(
        f.enrol_with(&f.config(), &changed, false).await,
        Err(Error::Enrol(_))
    ));
    assert!(enrol::parse_inventory(b"  \n").is_err());
    assert!(enrol::parse_inventory(b"[]").unwrap().is_empty());
}

#[tokio::test]
async fn policies_near_expiry_are_renewed_with_a_new_revision_then_settle() {
    let f = Fixture::new();
    f.enrol(&rows(1..3)).await;
    f.clock.0.store(NOW + 24 * DAY, Ordering::SeqCst);
    let renewed = f.enrol(&rows(1..3)).await;
    assert_eq!(renewed.signed.len(), 1);
    assert_eq!(renewed.signed[0].why, "renewing expiry");
    assert_eq!(renewed.signed[0].revision, 2);
    assert!(f.enrol(&rows(1..3)).await.signed.is_empty());
}

#[tokio::test]
async fn intake_is_capped_and_a_full_prefix_splits_with_a_stop_revision() {
    let f = Fixture::new();
    let inventory: Vec<InventoryRow> = (0..130_u64)
        .map(|n| InventoryRow {
            sha256: format!("a{:x}{:062x}", n % 16, n),
            ..row(n)
        })
        .collect();
    let first = f.enrol(&inventory).await;
    assert_eq!(first.signed[0].blobs, 128);
    assert_eq!(first.ledger.intake, 130);
    let in_first = f.signed_policy("synthetic-intake").blobs;
    let verify = |f: &Fixture, hashes: &[String]| {
        let mut observations = BTreeMap::new();
        for h in hashes {
            let mut targets = BTreeMap::new();
            for id in ["archive-one", "archive-two"] {
                targets.insert(id.to_owned(), Observation::Verified { at: NOW });
            }
            observations.insert(h.clone(), targets);
        }
        let snapshot = Snapshot {
            version: 1,
            owner: f.owner(),
            policy_id: "synthetic-intake".into(),
            revision: 1,
            event_id: f.latest_event("synthetic-intake"),
            profile: Profile::LoopbackDevelopment,
            observed_at: Some(NOW),
            cursor: 0,
            repair_cursors: BTreeMap::new(),
            observations,
            pending: BTreeMap::new(),
        };
        std::fs::write(
            f.root
                .path()
                .join("coordinators/synthetic-intake/state.json"),
            serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
    };
    verify(
        &f,
        &in_first
            .iter()
            .map(|b| b.sha256.clone())
            .collect::<Vec<_>>(),
    );
    let chunked = f.enrol(&inventory).await;
    assert_eq!(
        Fixture::signed_ids(&chunked),
        ["synthetic-archive-a", "synthetic-intake"]
    );
    let rest: Vec<String> = inventory
        .iter()
        .map(|r| r.sha256.clone())
        .filter(|h| !in_first.iter().any(|b| &b.sha256 == h))
        .collect();
    verify(&f, &rest);
    let split = f.enrol(&inventory).await;
    let stop = split
        .signed
        .iter()
        .find(|s| s.id == "synthetic-archive-a")
        .unwrap();
    assert_eq!((stop.desired_groups, stop.blobs), (0, 0));
    let chunks: Vec<_> = split
        .signed
        .iter()
        .filter(|s| s.id.len() == "synthetic-archive-a0".len())
        .collect();
    assert!(chunks.len() > 1 && chunks.iter().all(|s| s.blobs <= 128));
    assert_eq!(chunks.iter().map(|s| s.blobs).sum::<usize>(), 130);
    let intake = split
        .signed
        .iter()
        .find(|s| s.id == "synthetic-intake")
        .unwrap();
    assert_eq!(intake.desired_groups, 0);
    assert!(f.enrol(&inventory).await.signed.is_empty());
}

#[tokio::test]
async fn a_signer_that_returns_different_content_is_refused_and_nothing_is_written() {
    let mut f = Fixture::new();
    f.signer.tamper = true;
    let result = f.enrol_with(&f.config(), &rows(1..3), false).await;
    assert!(matches!(
        result,
        Err(Error::Enrol(_)) | Err(Error::Policy(PolicyError::Schema))
    ));
    assert!(
        !f.root
            .path()
            .join("policies/signed-synthetic-intake.json")
            .exists()
    );
    assert_eq!(f.lines("policy-history.jsonl"), 0);
}

#[tokio::test]
async fn configuration_mistakes_are_refused_before_any_write() {
    let f = Fixture::new();
    let mut config = f.config();
    config.archives[1].id = "source".into();
    assert!(matches!(
        f.enrol_with(&config, &rows(1..2), false).await,
        Err(Error::Configuration(_))
    ));
    let mut config = f.config();
    config.owner_file = Some("/synthetic/owner".into());
    assert!(f.enrol_with(&config, &rows(1..2), false).await.is_err());
    assert!(
        enrol::run(&f.config(), &rows(1..2), None, &f.clock, false)
            .await
            .is_err()
    );
}

#[test]
fn fingerprints_use_sorted_keys_without_whitespace() {
    // Pinned against JSON.stringify with recursively sorted keys, so a policy
    // history written by another enrolment tool for the same root matches.
    let value = serde_json::json!({"b": 1, "a": [{"y": "x", "c": 2}], "_": null});
    let expected = r#"{"_":null,"a":[{"c":2,"y":"x"}],"b":1}"#;
    let targets = serde_json::json!([{
        "id": "archive-one", "origin": "http://127.0.0.1:4002/",
        "failure_group": "archive-one", "retention": "owner"
    }]);
    assert_eq!(super::enrol::canonical_for_tests(&value), expected);
    assert_eq!(
        super::enrol::canonical_for_tests(&targets),
        r#"[{"failure_group":"archive-one","id":"archive-one","origin":"http://127.0.0.1:4002/","retention":"owner"}]"#
    );
}
