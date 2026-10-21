//! Group mode tests.  Synthetic keys, hosts and hashes only.
use super::{
    Enrolment, Grants, GrantsConfig, GrantsError, GroupConfig,
    group::core_group_grant_id,
    group_db::{self, GroupKey},
};
use nostr::prelude::Keys;
use std::{collections::BTreeSet, path::Path, sync::Arc};

const SERVER: &str = "grove.example.net";

fn keys(n: u64) -> String {
    Keys::parse(&format!("{n:064x}"))
        .unwrap()
        .public_key()
        .to_hex()
}

fn open(root: &Path, owners: &[u64], friends: &[u64], reserved: &[u64]) -> Grants {
    std::fs::create_dir_all(root).unwrap();
    Grants::open(
        root,
        GrantsConfig {
            owners: owners.iter().map(|n| keys(*n)).collect(),
            server_names: vec![SERVER.into()],
            origin: format!("https://{SERVER}/"),
            cli_friend_grants: friends
                .iter()
                .map(|n| wildbloom_core::FriendGrant {
                    pubkey: keys(*n),
                    byte_limit: 1024,
                    expires_at: 4_000_000_000,
                    grant_id: format!("local:{n}"),
                    issuer: None,
                })
                .collect(),
            reserved_keys: reserved.iter().map(|n| keys(*n)).collect(),
        },
        Arc::new(|| 1_800_000_000),
    )
    .unwrap()
}

fn enrol(keeper: u64, ceiling: u64) -> Enrolment {
    Enrolment {
        keeper: keys(keeper),
        ceiling,
        rooms: BTreeSet::new(),
    }
}

fn config(enrolments: Vec<Enrolment>) -> GroupConfig {
    GroupConfig { enrolments }
}

#[test]
fn the_state_file_is_private_and_a_group_keys_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let grants = open(&root, &[1], &[], &[]);
    grants
        .enable_group(&root, config(vec![enrol(10, 1 << 30)]))
        .unwrap();
    let path = Grants::group_database_path(&root);
    assert_eq!(path.file_name().unwrap(), "group-grants.sqlite3");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(grants.group_friend_grants().is_empty());
    {
        let state = grants.inner.group.get().unwrap();
        let db = state.db.lock().unwrap();
        group_db::write_key(
            &db,
            &keys(20),
            &GroupKey {
                keeper: keys(10),
                room: "a".repeat(64),
                byte_limit: Some(4096),
            },
        )
        .unwrap();
        group_db::write_key(
            &db,
            &keys(21),
            &GroupKey {
                keeper: keys(10),
                room: "a".repeat(64),
                byte_limit: None,
            },
        )
        .unwrap();
    }
    drop(grants);

    let grants = open(&root, &[1], &[], &[]);
    grants
        .enable_group(&root, config(vec![enrol(10, 1 << 30)]))
        .unwrap();
    // Only a key that ever had an upload grant is a core friend; a read-only
    // member is a group key but holds no claims.
    let friends = grants.core_friend_grants();
    assert_eq!(friends.len(), 1);
    assert_eq!(friends[0].pubkey, keys(20));
    assert_eq!(friends[0].byte_limit, 4096);
    assert_eq!(friends[0].expires_at, super::CORE_GRANT_SENTINEL);
    assert_eq!(
        friends[0].grant_id,
        core_group_grant_id(&keys(10), &"a".repeat(64))
    );
    assert_eq!(friends[0].issuer, Some(keys(10)));
    assert!(grants.group_claims_key(&keys(21)));
    assert!(grants.group_claims_key(&keys(10)));
    assert!(!grants.group_claims_key(&keys(1)));
}

#[test]
fn a_keeper_cannot_also_be_an_owner_friend_service_or_group_key() {
    for (owners, friends, reserved) in [
        (vec![10], vec![], vec![]),
        (vec![1], vec![10], vec![]),
        (vec![1], vec![], vec![10]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let grants = open(&root, &owners, &friends, &reserved);
        assert!(matches!(
            grants.enable_group(&root, config(vec![enrol(10, 1024)])),
            Err(GrantsError::Conflict)
        ));
    }
    // A persisted group device that is now an owner stops the node starting.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let grants = open(&root, &[1], &[], &[]);
    grants
        .enable_group(&root, config(vec![enrol(10, 1024)]))
        .unwrap();
    {
        let state = grants.inner.group.get().unwrap();
        let db = state.db.lock().unwrap();
        group_db::write_key(
            &db,
            &keys(1),
            &GroupKey {
                keeper: keys(10),
                room: "a".repeat(64),
                byte_limit: None,
            },
        )
        .unwrap();
    }
    drop(grants);
    let grants = open(&root, &[1], &[], &[]);
    assert!(matches!(
        grants.enable_group(&root, config(vec![enrol(10, 1024)])),
        Err(GrantsError::Conflict)
    ));
}

#[test]
fn enrolments_are_validated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let grants = open(&root, &[1], &[], &[]);
    for bad in [
        config(vec![]),
        config(vec![enrol(10, 0)]),
        config(vec![enrol(10, u64::MAX)]),
        config(vec![enrol(10, 1), enrol(10, 2)]),
        config(vec![Enrolment {
            keeper: "AB".repeat(32),
            ceiling: 1,
            rooms: BTreeSet::new(),
        }]),
        config(vec![Enrolment {
            keeper: keys(10),
            ceiling: 1,
            rooms: BTreeSet::from(["short".to_owned()]),
        }]),
    ] {
        assert!(matches!(
            grants.enable_group(&root, bad),
            Err(GrantsError::Group(_))
        ));
    }
    grants
        .enable_group(&root, config(vec![enrol(10, 1)]))
        .unwrap();
    assert!(matches!(
        grants.enable_group(&root, config(vec![enrol(11, 1)])),
        Err(GrantsError::Group(_))
    ));
}

// ---------------------------------------------------------------------------
// The shared vectors (`vectors/group-grants-v1.json`).
// ---------------------------------------------------------------------------
use super::{gate, group_event::Scope};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
    middleware::from_fn_with_state,
};
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;
use wildbloom_core::{AppState, BlossomConfig, ServerMetadata, Store, StoreConfig, router};

const VECTORS: &str = include_str!("../../../../vectors/group-grants-v1.json");
const MIB: u64 = 1024 * 1024;

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

/// A node on its own directory, clock and store.  The clock is absolute and
/// set by each vector step, so the same node can sit at any time of day.
struct VectorNode {
    _dir: tempfile::TempDir,
    grants: Grants,
    app: Router,
    clock: Arc<AtomicU64>,
}

impl VectorNode {
    async fn new(vectors: &Value) -> Self {
        Self::open_at(vectors, tempfile::tempdir().unwrap()).await
    }

    /// Stop the node and start it again on the same directory and clock.
    async fn restart(self, vectors: &Value) -> Self {
        let Self {
            _dir, grants, app, ..
        } = self;
        drop(app);
        drop(grants);
        Self::open_at(vectors, _dir).await
    }

    async fn open_at(vectors: &Value, dir: tempfile::TempDir) -> Self {
        let root = dir.path().join("data");
        let node = &vectors["node"];
        let owners = node["owners"]
            .as_array()
            .unwrap()
            .iter()
            .map(|owner| owner.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let server = node["servers"][0].as_str().unwrap().to_owned();
        let clock = Arc::new(AtomicU64::new(vectors["time"]["t0"].as_u64().unwrap()));
        std::fs::create_dir_all(&root).unwrap();
        let store = Store::open(StoreConfig {
            root: root.clone(),
            quota_bytes: 64 * MIB,
            max_blob_bytes: 8 * MIB,
        })
        .unwrap();
        let source = clock.clone();
        let grants = Grants::open(
            &root,
            GrantsConfig {
                owners: owners.clone(),
                server_names: vec![server.clone()],
                origin: format!("https://{server}/"),
                cli_friend_grants: Vec::new(),
                reserved_keys: Vec::new(),
            },
            Arc::new(move || source.load(Ordering::SeqCst)),
        )
        .unwrap();
        grants
            .enable_group(
                &root,
                GroupConfig {
                    enrolments: node["enrolments"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|enrolment| Enrolment {
                            keeper: enrolment["keeper"].as_str().unwrap().to_owned(),
                            ceiling: enrolment["ceiling"].as_u64().unwrap(),
                            rooms: BTreeSet::new(),
                        })
                        .collect(),
                },
            )
            .unwrap();
        let state = AppState::new(
            store,
            BlossomConfig {
                server_metadata: ServerMetadata::default(),
                public_base_url: format!("https://{server}/").parse().unwrap(),
                accepted_server_names: vec![server],
                allowed_pubkeys: owners,
                friend_grants: grants.core_friend_grants(),
                open_shelter: false,
                max_concurrent_writes: 4,
                mirror_proxy: None,
            },
        )
        .unwrap();
        grants.attach(state.clone());
        grants.startup().await.unwrap();
        let app = router(state)
            .layer(from_fn_with_state(grants.clone(), gate))
            .merge(grants.group_router());
        Self {
            _dir: dir,
            grants,
            app,
            clock,
        }
    }

    fn set_now(&self, now: u64) {
        self.clock.store(now, Ordering::SeqCst);
    }

    /// POST one event.  Returns the status, the `X-Reason` and the `state`.
    async fn post(&self, event: &Value) -> (StatusCode, String, Option<String>) {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/groups/v1/events")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(event).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let reason = response
            .headers()
            .get("x-reason")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "no-store",
            "event responses are never cached"
        );
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        let state = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|body| body["state"].as_str().map(str::to_owned));
        (status, reason, state)
    }

    fn granted(&self, key: &str, scope: &str) -> bool {
        let bit = match scope {
            "upload" => Scope::Upload,
            "get" => Scope::Get,
            "delete" => Scope::Delete,
            "purge" => Scope::Purge,
            "turn" => Scope::Turn,
            "relay-read" => Scope::RelayRead,
            _ => Scope::RelayWrite,
        }
        .bit();
        self.grants.group_granted(key, bit)
    }
}

async fn expect_post(node: &VectorNode, name: &str, event: &Value, expect: &Value) {
    let (status, reason, state) = node.post(event).await;
    assert_eq!(
        status.as_u16(),
        expect["status"].as_u64().unwrap() as u16,
        "{name}: status (reason {reason})"
    );
    assert_eq!(reason, expect["reason"].as_str().unwrap(), "{name}: reason");
    if let Some(expected) = expect["state"].as_str() {
        assert_eq!(state.as_deref(), Some(expected), "{name}: state");
    }
}

#[tokio::test]
async fn every_grant_event_vector_gets_its_status_reason_and_state() {
    let vectors = vectors();
    let cases = vectors["grantEvents"].as_array().unwrap();
    assert_eq!(cases.len(), 37);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        // Each case runs on a fresh node, at its own time.
        let node = VectorNode::new(&vectors).await;
        node.set_now(case["now"].as_u64().unwrap());
        expect_post(&node, name, &case["event"], &case["expect"]).await;
    }
}

/// Runs one ordered sequence.  Request steps need the read gate, so they are
/// handed to `request` and the sequences that have them are skipped until it
/// exists.
async fn run_sequence(vectors: &Value, sequence: &Value, with_requests: bool) -> bool {
    let name = sequence["name"].as_str().unwrap();
    let steps = sequence["steps"].as_array().unwrap();
    if !with_requests && steps.iter().any(|step| step.get("request").is_some()) {
        return false;
    }
    let node = VectorNode::new(vectors).await;
    for (index, step) in steps.iter().enumerate() {
        node.set_now(step["now"].as_u64().unwrap());
        let label = format!("{name} step {index}");
        if let Some(event) = step.get("post") {
            expect_post(&node, &label, event, &step["expect"]).await;
        } else if let Some(check) = step.get("check") {
            let granted = node.granted(
                check["key"].as_str().unwrap(),
                check["scope"].as_str().unwrap(),
            );
            assert_eq!(
                granted,
                step["expect"]["granted"].as_bool().unwrap(),
                "{label}: granted"
            );
        } else {
            panic!("{label}: unknown step");
        }
    }
    true
}

#[tokio::test]
async fn the_sequence_vectors_without_requests_pass_in_order() {
    let vectors = vectors();
    let mut ran = 0;
    for sequence in vectors["sequences"].as_array().unwrap() {
        ran += usize::from(run_sequence(&vectors, sequence, false).await);
    }
    assert_eq!(ran, 8);
}

fn case<'a>(vectors: &'a Value, group: &str, name: &str) -> &'a Value {
    vectors[group]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

fn step_post(sequence: &Value, index: usize) -> &Value {
    &sequence["steps"][index]["post"]
}

#[tokio::test]
async fn an_oversized_body_is_refused_and_the_route_is_limited_as_a_whole() {
    let vectors = vectors();
    let node = VectorNode::new(&vectors).await;
    let response = node
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/groups/v1/events")
                .body(Body::from(vec![b' '; 16 * 1024 + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.headers().get("x-reason").unwrap(), "too-large");

    // Every post counts, whoever sent it and whatever it held.
    let mut limited = None;
    for _ in 0..200 {
        let (status, reason, _) = node.post(&Value::Null).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = Some(reason);
            break;
        }
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(limited.as_deref(), Some("rate"));
    // The window is a minute of the node's clock.
    node.set_now(vectors["time"]["t0"].as_u64().unwrap() + 61);
    let (status, _, _) = node.post(&Value::Null).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn grant_rows_floors_and_revocations_survive_a_restart() {
    let vectors = vectors();
    let reset = case(&vectors, "sequences", "reset-and-regrant");
    let revoke = case(&vectors, "sequences", "renew-revoke-readmit");
    let alice = vectors["keys"]["alicePhone"]["pubkey"].as_str().unwrap();
    let bob = vectors["keys"]["bobLaptop"]["pubkey"].as_str().unwrap();

    let node = VectorNode::new(&vectors).await;
    // Two grants, then a reset that ends both.
    for index in [0, 1, 2] {
        node.set_now(reset["steps"][index]["now"].as_u64().unwrap());
        let (status, ..) = node.post(step_post(reset, index)).await;
        assert!(status.is_success());
    }
    assert!(!node.granted(alice, "get") && !node.granted(bob, "get"));

    let node = node.restart(&vectors).await;
    node.set_now(reset["steps"][5]["now"].as_u64().unwrap());
    // The floor is remembered: the old id cannot land again at the floor.
    expect_post(
        &node,
        "floor after restart",
        step_post(reset, 5),
        &reset["steps"][5]["expect"],
    )
    .await;
    assert!(!node.granted(alice, "get"));
    // A newer renewal lands, and its group key is a core friend again.
    node.set_now(reset["steps"][6]["now"].as_u64().unwrap());
    expect_post(
        &node,
        "renewal after restart",
        step_post(reset, 6),
        &reset["steps"][6]["expect"],
    )
    .await;
    assert!(node.granted(alice, "get"));
    assert_eq!(node.grants.core_friend_grants().len(), 1);

    // A revocation survives too, so a replayed grant stays refused.
    drop(node);
    let node = VectorNode::new(&vectors).await;
    for index in [0, 5] {
        node.set_now(revoke["steps"][index]["now"].as_u64().unwrap());
        let (status, ..) = node.post(step_post(revoke, index)).await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let node = node.restart(&vectors).await;
    node.set_now(revoke["steps"][8]["now"].as_u64().unwrap());
    assert!(!node.granted(alice, "get"));
    expect_post(
        &node,
        "renewal of a revoked id after restart",
        step_post(revoke, 8),
        &revoke["steps"][8]["expect"],
    )
    .await;
}

#[tokio::test]
async fn a_key_cannot_be_both_a_device_grant_and_a_group_key() {
    use super::event::DEVICE_GRANT_KIND;
    use nostr::prelude::{EventBuilder, FinalizeEvent, Kind, Tag, Timestamp};

    let vectors = vectors();
    let node = VectorNode::new(&vectors).await;
    let owner = Keys::parse(vectors["keys"]["nodeOwner"]["secret"].as_str().unwrap()).unwrap();
    let alice = vectors["keys"]["alicePhone"]["pubkey"].as_str().unwrap();
    let now = vectors["time"]["t0"].as_u64().unwrap();
    let device_grant = |device: &str, recovery: &str| {
        let tags = [
            ["t", "grant"],
            ["device", device],
            ["recovery", recovery],
            ["bytes", "1048576"],
            ["until", &(now + 86_400).to_string()],
            ["server", "grove.example.net"],
            ["expiration", &(now + 300).to_string()],
        ]
        .into_iter()
        .map(|tag| Tag::parse(tag).unwrap())
        .collect::<Vec<_>>();
        EventBuilder::new(Kind::Custom(DEVICE_GRANT_KIND), "Approve this device")
            .tags(tags)
            .custom_created_at(Timestamp::from(now))
            .finalize(&owner)
            .unwrap()
    };
    let spare = keys(500);
    let spare_recovery = keys(501);

    // A group device cannot become a device grant, and a device grant's key
    // cannot become a group device.
    let (status, ..) = node
        .post(&case(&vectors, "grantEvents", "good-grant")["event"])
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let refused = node
        .grants
        .apply_grant(
            serde_json::to_string(&device_grant(alice, &spare_recovery))
                .unwrap()
                .as_bytes(),
        )
        .await;
    assert_eq!(refused.unwrap_err().status, StatusCode::CONFLICT);
    let refused = node
        .grants
        .apply_grant(
            serde_json::to_string(&device_grant(&spare, alice))
                .unwrap()
                .as_bytes(),
        )
        .await;
    assert_eq!(refused.unwrap_err().status, StatusCode::CONFLICT);
    node.grants
        .apply_grant(
            serde_json::to_string(&device_grant(&keys(502), &keys(503)))
                .unwrap()
                .as_bytes(),
        )
        .await
        .unwrap();

    // Bob, a device-grant device, is refused as a group device (rule 8).
    let bob = vectors["keys"]["bobLaptop"]["pubkey"].as_str().unwrap();
    node.grants
        .apply_grant(
            serde_json::to_string(&device_grant(bob, &keys(504)))
                .unwrap()
                .as_bytes(),
        )
        .await
        .unwrap();
    let (status, reason, _) = node
        .post(&case(&vectors, "grantEvents", "good-grant-get-only")["event"])
        .await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::CONFLICT, "key-conflict")
    );
}
