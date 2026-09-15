use super::{
    directory::{self, Runner, Settings, TransportFactory},
    engine::{Clock, Limits},
    policy::{Blob, Policy, Retention, Target, VerifiedPolicy, policy_template},
    state::StateDirectory,
    transport::{NetworkFailure, Profile, Transport},
};
use futures_util::future::BoxFuture;
use nostr::prelude::{FinalizeEvent, Keys};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
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

#[derive(Clone, Default)]
struct Net {
    verifies: Arc<AtomicUsize>,
}
impl Transport for Net {
    fn verify<'a>(
        &'a self,
        _: &'a Target,
        _: &'a Blob,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
    fn mirror<'a>(
        &'a self,
        _: &'a Target,
        _: &'a Target,
        _: &'a Blob,
        _: &'a str,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async { Ok(()) })
    }
}

fn policy(id: &str, revision: u64, desired_groups: u8) -> Policy {
    Policy {
        policy_type: "wildbloom.replica-policy".into(),
        version: 1,
        id: id.into(),
        revision,
        expires_at: NOW + 30 * 86_400,
        profile: Profile::LoopbackDevelopment,
        desired_groups,
        targets: (1..=2)
            .map(|n| Target {
                id: format!("node-{n}"),
                origin: format!("http://127.0.0.1:{}/", 4000 + n),
                failure_group: format!("group-{n}"),
                retention: Retention::Owner,
            })
            .collect(),
        blobs: if desired_groups == 0 {
            Vec::new()
        } else {
            vec![Blob {
                sha256: "cd".repeat(32),
                size: 10,
            }]
        },
    }
}

struct Fixture {
    root: tempfile::TempDir,
    keys: Keys,
    clock: TestClock,
    net: Net,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("policies")).unwrap();
        Self {
            root,
            keys: Keys::generate(),
            clock: TestClock(AtomicU64::new(NOW)),
            net: Net::default(),
        }
    }
    fn write(&self, file_id: &str, policy: Policy) {
        let event = policy_template(policy, &self.keys.public_key().to_hex(), NOW)
            .unwrap()
            .finalize(&self.keys)
            .unwrap();
        std::fs::write(
            self.root
                .path()
                .join(format!("policies/signed-{file_id}.json")),
            serde_json::to_vec(&event).unwrap(),
        )
        .unwrap();
    }
    fn runner<'a>(
        &self,
        factory: &'a TransportFactory<'a>,
        intervals: Vec<(String, u64)>,
    ) -> Runner<'a> {
        Runner::new(Settings {
            policy_dir: self.root.path().join("policies"),
            state_root: self.root.path().join("coordinators"),
            owner: self.keys.public_key().to_hex(),
            limits: LIMITS,
            default_interval: 300,
            intervals,
            transport: factory,
        })
        .unwrap()
    }
    fn advance(&self, secs: u64) {
        self.clock.0.fetch_add(secs, Ordering::SeqCst);
    }
}

fn lines(out: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn a_policy_added_after_startup_is_picked_up_on_the_next_cycle() {
    let f = Fixture::new();
    let net = f.net.clone();
    let factory = move |_: &VerifiedPolicy| Ok(Box::new(net.clone()) as Box<dyn Transport>);
    let mut runner = f.runner(&factory, Vec::new());
    f.write("first", policy("first", 1, 2));
    let mut out = Vec::new();
    let cycle = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!((cycle.passes, cycle.failures), (1, 0));

    f.write("second", policy("second", 1, 2));
    f.advance(1);
    let mut out = Vec::new();
    let cycle = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!(cycle.passes, 1, "only the new policy is due");
    assert_eq!(lines(&out)[0]["policy_id"], "second");
    assert!(
        f.root
            .path()
            .join("coordinators/second/state.json")
            .is_file()
    );
}

#[tokio::test]
async fn a_stopped_policy_is_not_rerun_until_a_new_signed_revision_appears() {
    let f = Fixture::new();
    let net = f.net.clone();
    let factory = move |_: &VerifiedPolicy| Ok(Box::new(net.clone()) as Box<dyn Transport>);
    let mut runner = f.runner(&factory, Vec::new());
    f.write("intake", policy("intake", 1, 0));
    let mut out = Vec::new();
    runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!(lines(&out)[0]["stopped"], true);

    f.advance(10_000);
    let mut out = Vec::new();
    let idle = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!((idle.passes, out.len()), (0, 0));

    f.write("intake", policy("intake", 2, 2));
    f.advance(301);
    let mut out = Vec::new();
    let resumed = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!(resumed.passes, 1);
    assert_eq!(lines(&out)[0]["stopped"], false);
    assert!(f.net.verifies.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn a_bad_policy_is_reported_and_backed_off_while_others_keep_running() {
    let f = Fixture::new();
    let net = f.net.clone();
    let factory = move |_: &VerifiedPolicy| Ok(Box::new(net.clone()) as Box<dyn Transport>);
    let mut runner = f.runner(&factory, Vec::new());
    f.write("good", policy("good", 1, 2));
    std::fs::write(
        f.root.path().join("policies/signed-broken.json"),
        b"not an event",
    )
    .unwrap();
    f.write("misnamed", policy("somebody-else", 1, 2));

    let mut out = Vec::new();
    let cycle = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!((cycle.passes, cycle.failures), (1, 2));
    let errors: Vec<_> = lines(&out)
        .into_iter()
        .filter(|line| line.get("error").is_some())
        .map(|line| line["policy_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(errors, ["broken", "misnamed"]);

    f.advance(30);
    let mut out = Vec::new();
    let early = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!(early.failures, 0, "failed policies wait out their backoff");
}

#[tokio::test]
async fn a_policy_whose_state_is_already_locked_is_skipped_not_fatal() {
    let f = Fixture::new();
    let net = f.net.clone();
    let factory = move |_: &VerifiedPolicy| Ok(Box::new(net.clone()) as Box<dyn Transport>);
    let _held = StateDirectory::open(&f.root.path().join("coordinators/taken")).unwrap();
    let mut runner = f.runner(&factory, Vec::new());
    f.write("taken", policy("taken", 1, 2));
    f.write("free", policy("free", 1, 2));
    let mut out = Vec::new();
    let cycle = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!((cycle.passes, cycle.failures), (1, 1));
}

#[tokio::test]
async fn interval_overrides_pick_the_longest_matching_prefix() {
    let f = Fixture::new();
    let net = f.net.clone();
    let factory = move |_: &VerifiedPolicy| Ok(Box::new(net.clone()) as Box<dyn Transport>);
    let mut runner = f.runner(
        &factory,
        vec![("chunk-".into(), 21_600), ("chunk-hot".into(), 60)],
    );
    f.write("chunk-cold", policy("chunk-cold", 1, 2));
    f.write("chunk-hot", policy("chunk-hot", 1, 2));
    runner
        .cycle(&f.clock, None, &mut Vec::new(), false)
        .await
        .unwrap();
    f.advance(61);
    let mut out = Vec::new();
    let cycle = runner.cycle(&f.clock, None, &mut out, false).await.unwrap();
    assert_eq!(cycle.passes, 1);
    assert_eq!(lines(&out)[0]["policy_id"], "chunk-hot");
    assert!(runner.sleep_for(&f.clock) <= directory::RESCAN_SECS);
}

#[test]
fn interval_arguments_are_validated() {
    assert_eq!(
        directory::parse_interval("chunk-=900").unwrap(),
        ("chunk-".to_owned(), 900)
    );
    for bad in [
        "",
        "=900",
        "Chunk=900",
        "chunk",
        "chunk=4",
        "chunk=86401",
        "chunk=x",
    ] {
        assert!(directory::parse_interval(bad).is_err(), "{bad}");
    }
}
