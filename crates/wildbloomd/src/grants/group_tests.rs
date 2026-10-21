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
    GroupConfig {
        enrolments,
        max_concurrent_writes: 4,
    }
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
use super::{gate, group_event::Scope, group_gate};
use axum::body::Bytes;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::from_fn_with_state,
};
use futures_util::{StreamExt, future::BoxFuture};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tower::ServiceExt;
use wildbloom_core::{
    AppState, BlobFetcher, BlossomConfig, FetchError, FetchPath, FetchRequest, FetchedBlob,
    ServerMetadata, Store, StoreConfig, router,
};

/// Overrides for the tests that fill a node or a group.
#[derive(Default, Clone)]
struct Limits {
    quota: Option<u64>,
    ceiling: Option<u64>,
    /// A `--friend-grant` key, to try the core's own upload route.
    friend: Option<String>,
    /// What the node's mirror source serves, whatever it is asked for.
    source: Option<Vec<u8>>,
    /// Holds the mirror source until released.
    source_gate: Option<Arc<tokio::sync::Notify>>,
    /// The per-blob limit, default 8 MiB.
    max_blob: Option<u64>,
    /// The friend key's byte limit, default 1 MiB.
    friend_bytes: Option<u64>,
}

/// A mirror source that serves the same bytes for every hash it is asked for.
struct FakeSource(Vec<u8>, Option<Arc<tokio::sync::Notify>>);

impl BlobFetcher for FakeSource {
    fn fetch(&self, _request: FetchRequest) -> BoxFuture<'_, Result<FetchedBlob, FetchError>> {
        let bytes = self.0.clone();
        let gate = self.1.clone();
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.notified().await;
            }
            Ok(FetchedBlob {
                path: FetchPath::Https,
                size: bytes.len() as u64,
                content_type: None,
                body: futures_util::stream::once(async move { Ok(Bytes::from(bytes)) }).boxed(),
            })
        })
    }
}

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
    store: Store,
    owner: String,
}

impl VectorNode {
    async fn new(vectors: &Value) -> Self {
        Self::open_at(vectors, tempfile::tempdir().unwrap(), Limits::default()).await
    }

    async fn limited(vectors: &Value, limits: Limits) -> Self {
        Self::open_at(vectors, tempfile::tempdir().unwrap(), limits).await
    }

    /// Stop the node and start it again on the same directory and clock.
    async fn restart(self, vectors: &Value) -> Self {
        let Self {
            _dir,
            grants,
            app,
            store,
            ..
        } = self;
        drop(app);
        drop(grants);
        drop(store);
        Self::open_at(vectors, _dir, Limits::default()).await
    }

    async fn open_at(vectors: &Value, dir: tempfile::TempDir, limits: Limits) -> Self {
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
            quota_bytes: limits.quota.unwrap_or(64 * MIB),
            max_blob_bytes: limits.max_blob.unwrap_or(8 * MIB),
        })
        .unwrap();
        let held_store = store.clone();
        let owner = owners[0].clone();
        let source = clock.clone();
        let grants = Grants::open(
            &root,
            GrantsConfig {
                owners: owners.clone(),
                server_names: vec![server.clone()],
                origin: format!("https://{server}/"),
                cli_friend_grants: limits
                    .friend
                    .iter()
                    .map(|key| wildbloom_core::FriendGrant {
                        pubkey: key.clone(),
                        byte_limit: limits.friend_bytes.unwrap_or(MIB),
                        expires_at: 4_000_000_000,
                        grant_id: "local:friend".into(),
                        issuer: None,
                    })
                    .collect(),
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
                            ceiling: limits
                                .ceiling
                                .unwrap_or_else(|| enrolment["ceiling"].as_u64().unwrap()),
                            rooms: BTreeSet::new(),
                        })
                        .collect(),
                    max_concurrent_writes: 4,
                },
            )
            .unwrap();
        let config = BlossomConfig {
            server_metadata: ServerMetadata::default(),
            public_base_url: format!("https://{server}/").parse().unwrap(),
            accepted_server_names: vec![server],
            allowed_pubkeys: owners,
            friend_grants: grants.core_friend_grants(),
            open_shelter: false,
            max_concurrent_writes: 4,
            mirror_proxy: None,
        };
        let state = match limits.source {
            Some(bytes) => AppState::with_fetcher(
                store,
                config,
                Arc::new(FakeSource(bytes, limits.source_gate.clone())),
            ),
            None => AppState::new(store, config),
        }
        .unwrap();
        grants.attach(state.clone());
        grants.startup().await.unwrap();
        let app = router(state)
            .layer(from_fn_with_state(grants.clone(), gate))
            .layer(from_fn_with_state(grants.clone(), group_gate))
            .merge(grants.group_router());
        Self {
            _dir: dir,
            grants,
            app,
            clock,
            store: held_store,
            owner,
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

    /// Send one vector request and return the status, `X-Reason` and headers.
    async fn request(&self, vectors: &Value, request: &Value) -> (StatusCode, String, HeaderMap) {
        let mut builder = Request::builder()
            .method(request["method"].as_str().unwrap())
            .uri(request["path"].as_str().unwrap());
        for pair in request["headers"].as_array().unwrap() {
            builder = builder.header(pair[0].as_str().unwrap(), pair[1].as_str().unwrap());
        }
        let body = request
            .get("body")
            .and_then(Value::as_str)
            .map(|name| {
                vectors["blobs"][name]["text"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            })
            .unwrap_or_default();
        let response = self
            .app
            .clone()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let reason = headers
            .get("x-reason")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        // Drain the body so a streamed read finishes.
        let _ = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, reason, headers)
    }

    /// The node owner's own write.  Its HTTP path is the core's, which reads
    /// the machine clock, so a vector clock in 2027 cannot drive it: the
    /// owner's blob goes in through the store, as the owner's claim.
    fn owner_upload(&self, vectors: &Value, name: &str) {
        let text = vectors["blobs"][name]["text"].as_str().unwrap();
        let hash = vectors["blobs"][name]["sha256"].as_str().unwrap();
        let started = self
            .store
            .begin_upload(
                hash,
                text.len() as u64,
                &self.owner,
                "application/octet-stream",
            )
            .unwrap();
        let wildbloom_core::store::UploadStart::Reserved(reservation) = started else {
            panic!("the owner's blob was already stored");
        };
        std::fs::write(reservation.temp_path(), text).unwrap();
        reservation.commit(hash, text.len() as u64).unwrap();
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

/// The signer of a vector request's token, to spot the node owner's.
fn token_signer(request: &Value) -> Option<String> {
    use base64::Engine as _;
    let header = request["headers"]
        .as_array()?
        .iter()
        .find(|pair| pair[0] == "Authorization")?[1]
        .as_str()?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header.strip_prefix("Nostr ")?.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice::<Value>(&bytes).ok()?["pubkey"]
        .as_str()
        .map(str::to_owned)
}

async fn expect_request(node: &VectorNode, vectors: &Value, name: &str, step: &Value) {
    let request = &step["request"];
    let expect = &step["expect"];
    if token_signer(request).as_deref() == Some(node.owner.as_str()) {
        assert_eq!(
            expect["status"], 201,
            "{name}: only owner uploads are direct"
        );
        node.owner_upload(vectors, request["body"].as_str().unwrap());
        return;
    }
    let (status, reason, _) = node.request(vectors, request).await;
    assert_eq!(
        status.as_u16(),
        expect["status"].as_u64().unwrap() as u16,
        "{name}: status (reason {reason})"
    );
    if !status.is_success() {
        assert_eq!(reason, expect["reason"].as_str().unwrap(), "{name}: reason");
    }
}

/// Apply ordered steps to a node: post, request or check, each at its own time.
async fn run_steps(node: &VectorNode, vectors: &Value, name: &str, steps: &Value) {
    for (index, step) in steps.as_array().unwrap().iter().enumerate() {
        node.set_now(step["now"].as_u64().unwrap());
        let label = format!("{name} step {index}");
        if let Some(event) = step.get("post") {
            expect_post(node, &label, event, &step["expect"]).await;
        } else if step.get("request").is_some() {
            expect_request(node, vectors, &label, step).await;
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
}

#[tokio::test]
async fn every_sequence_vector_passes_in_order() {
    let vectors = vectors();
    let sequences = vectors["sequences"].as_array().unwrap();
    assert_eq!(sequences.len(), 10);
    for sequence in sequences {
        let node = VectorNode::new(&vectors).await;
        let name = sequence["name"].as_str().unwrap();
        run_steps(&node, &vectors, name, &sequence["steps"]).await;
    }
}

#[tokio::test]
async fn every_request_vector_passes_after_the_fixture() {
    let vectors = vectors();
    let cases = vectors["requests"].as_array().unwrap();
    assert_eq!(cases.len(), 39);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        // Each case starts again from the fixture on a fresh node.
        let node = VectorNode::new(&vectors).await;
        run_steps(
            &node,
            &vectors,
            "fixture",
            &vectors["requestFixture"]["steps"],
        )
        .await;
        node.set_now(case["now"].as_u64().unwrap());
        expect_request(&node, &vectors, name, case).await;
    }
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
async fn an_oversized_body_is_refused() {
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
}

/// A keeper's revocation of a grant, as the review's run sent it.
fn revocation(vectors: &Value, at: u64) -> Value {
    sign(
        &secret(vectors, "authorityA"),
        27_541,
        &[
            ("t", "grant".to_owned()),
            ("grant", "a683be7ffdc9a5cdab418a1d3dd3a9dd".to_owned()),
            (
                "d",
                vectors["rooms"]["a"]["roomId"].as_str().unwrap().to_owned(),
            ),
            ("device", pubkey(vectors, "alicePhone")),
            ("server", "grove.example.net".to_owned()),
            ("scope", "upload".to_owned()),
            ("scope", "get".to_owned()),
            ("scope", "delete".to_owned()),
            ("bytes", "1073741824".to_owned()),
            ("status", "revoked".to_owned()),
            ("expiration", "1802592000".to_owned()),
        ],
        "",
        at,
    )
}

#[tokio::test]
async fn junk_cannot_stop_a_revocation_and_replays_cost_nothing() {
    let vectors = vectors();
    let (hash, _) = blob(&vectors, "blob1");
    let now = 1_800_000_000;
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    assert_eq!(
        get(&node, &vectors, "alicePhone", &hash, now + 100).await.0,
        StatusCode::OK
    );
    // The review's run: 120 posts of nothing, then a real revocation.
    for _ in 0..700 {
        let (status, ..) = node.post(&serde_json::json!({})).await;
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::TOO_MANY_REQUESTS);
    }
    // Junk has a budget of its own, and has used it up...
    let (status, reason, _) = node.post(&serde_json::json!({})).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "rate")
    );
    // ...but it was never the keeper's.
    node.set_now(now + 101);
    assert_eq!(
        node.post(&revocation(&vectors, now + 101)).await.0,
        StatusCode::CREATED
    );
    let (status, reason, _) = get(&node, &vectors, "alicePhone", &hash, now + 101).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::FORBIDDEN, "not-granted")
    );

    // A replay of an event the node holds is free, however often it comes.
    let held = &case(&vectors, "grantEvents", "good-grant-get-only")["event"];
    node.set_now(now + 102);
    for _ in 0..300 {
        assert_eq!(node.post(held).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn the_keepers_grant_budget_never_stops_a_revocation_or_a_reset() {
    let vectors = vectors();
    let now = 1_800_000_000;
    let node = VectorNode::new(&vectors).await;
    node.set_now(now);
    // 120 new grants a minute from enrolled keepers; the 121st waits.
    for n in 0..120 {
        let device = keys(1_000 + n);
        let event = grant_for(
            &vectors,
            "authorityA",
            "a",
            &format!("{n:032x}"),
            &device,
            &["get"],
            None,
            now,
            86_400,
        );
        assert_eq!(node.post(&event).await.0, StatusCode::CREATED, "{n}");
    }
    let extra = grant_for(
        &vectors,
        "authorityA",
        "a",
        &format!("{:032x}", 999),
        &keys(2_000),
        &["get"],
        None,
        now,
        86_400,
    );
    let (status, reason, _) = node.post(&extra).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "rate")
    );
    // The budget is each keeper's own: keeper B is not held up by keeper A.
    let other = grant(
        &vectors,
        "authorityB",
        "b",
        "99999999999999999999999999999999",
        "carolPhone",
        &["get"],
        None,
        now,
        86_400,
    );
    assert_eq!(node.post(&other).await.0, StatusCode::CREATED);
    // A revocation and a reset still land, and the budget refills.
    node.set_now(now + 1);
    assert_eq!(
        node.post(&revocation(&vectors, now + 1)).await.0,
        StatusCode::CREATED
    );
    let reset = sign(
        &secret(&vectors, "authorityA"),
        27_541,
        &[
            ("t", "reset".to_owned()),
            (
                "d",
                vectors["rooms"]["a"]["roomId"].as_str().unwrap().to_owned(),
            ),
            ("server", "grove.example.net".to_owned()),
            ("expiration", "1807776000".to_owned()),
        ],
        "",
        now + 2,
    );
    node.set_now(now + 2);
    assert_eq!(node.post(&reset).await.0, StatusCode::CREATED);
    node.set_now(now + 61);
    let fresh = grant_for(
        &vectors,
        "authorityA",
        "a",
        &format!("{:032x}", 998),
        &keys(2_001),
        &["get"],
        None,
        now + 61,
        86_400,
    );
    assert_eq!(node.post(&fresh).await.0, StatusCode::CREATED);
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

// ---------------------------------------------------------------------------
// Behaviour the vectors do not reach: caching, immediacy, ceilings, owners.
// ---------------------------------------------------------------------------
use nostr::prelude::{EventBuilder, FinalizeEvent, Kind, Tag, Timestamp};

fn secret(vectors: &Value, name: &str) -> Keys {
    Keys::parse(vectors["keys"][name]["secret"].as_str().unwrap()).unwrap()
}

fn pubkey(vectors: &Value, name: &str) -> String {
    vectors["keys"][name]["pubkey"].as_str().unwrap().to_owned()
}

fn blob(vectors: &Value, name: &str) -> (String, String) {
    (
        vectors["blobs"][name]["sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
        vectors["blobs"][name]["text"].as_str().unwrap().to_owned(),
    )
}

fn sign(signer: &Keys, kind: u16, tags: &[(&str, String)], content: &str, at: u64) -> Value {
    let tags = tags
        .iter()
        .map(|(name, value)| Tag::parse([*name, value.as_str()]).unwrap())
        .collect::<Vec<_>>();
    let event = EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .custom_created_at(Timestamp::from(at))
        .finalize(signer)
        .unwrap();
    serde_json::to_value(event).unwrap()
}

/// A grant a test signs itself, for ceilings and timings the vectors lack.
#[allow(clippy::too_many_arguments)]
fn grant(
    vectors: &Value,
    keeper: &str,
    room: &str,
    grant_id: &str,
    device: &str,
    scopes: &[&str],
    bytes: Option<u64>,
    at: u64,
    lifetime: u64,
) -> Value {
    grant_for(
        vectors,
        keeper,
        room,
        grant_id,
        &pubkey(vectors, device),
        scopes,
        bytes,
        at,
        lifetime,
    )
}

/// The same for any device key.
#[allow(clippy::too_many_arguments)]
fn grant_for(
    vectors: &Value,
    keeper: &str,
    room: &str,
    grant_id: &str,
    device: &str,
    scopes: &[&str],
    bytes: Option<u64>,
    at: u64,
    lifetime: u64,
) -> Value {
    let mut tags = vec![
        ("t", "grant".to_owned()),
        ("grant", grant_id.to_owned()),
        (
            "d",
            vectors["rooms"][room]["roomId"]
                .as_str()
                .unwrap()
                .to_owned(),
        ),
        ("device", device.to_owned()),
        ("server", "grove.example.net".to_owned()),
    ];
    tags.extend(scopes.iter().map(|scope| ("scope", (*scope).to_owned())));
    if let Some(bytes) = bytes {
        tags.push(("bytes", bytes.to_string()));
    }
    tags.push(("status", "active".to_owned()));
    tags.push(("expiration", (at + lifetime).to_string()));
    sign(&secret(vectors, keeper), 27_541, &tags, "", at)
}

/// A BUD-11 token a test signs, valid for a minute around `now`.
fn token(vectors: &Value, who: &str, verb: &str, hash: &str, now: u64) -> String {
    token_by(&secret(vectors, who), verb, hash, now)
}

fn token_by(signer: &Keys, verb: &str, hash: &str, now: u64) -> String {
    use base64::Engine as _;
    let tags = [
        ("t", verb.to_owned()),
        ("expiration", (now + 59).to_string()),
        ("server", "grove.example.net".to_owned()),
        ("x", hash.to_owned()),
    ];
    let event = sign(signer, 24_242, &tags, "group-grants/1 synthetic", now - 1);
    format!(
        "Nostr {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&event).unwrap())
    )
}

fn request(method: &str, path: &str, headers: &[(&str, String)], body: Option<&str>) -> Value {
    serde_json::json!({
        "method": method,
        "path": path,
        "headers": headers.iter().map(|(k, v)| serde_json::json!([k, v])).collect::<Vec<_>>(),
        "body": body,
    })
}

async fn get(
    node: &VectorNode,
    vectors: &Value,
    who: &str,
    hash: &str,
    now: u64,
) -> (StatusCode, String, HeaderMap) {
    node.set_now(now);
    let headers = [("Authorization", token(vectors, who, "get", hash, now))];
    node.request(
        vectors,
        &request("GET", &format!("/{hash}"), &headers, None),
    )
    .await
}

async fn upload(
    node: &VectorNode,
    vectors: &Value,
    who: &str,
    name: &str,
    now: u64,
) -> (StatusCode, String, HeaderMap) {
    node.set_now(now);
    let (hash, text) = blob(vectors, name);
    let headers = [
        ("Authorization", token(vectors, who, "upload", &hash, now)),
        ("X-SHA-256", hash.clone()),
        ("Content-Length", text.len().to_string()),
    ];
    node.request(vectors, &request("PUT", "/upload", &headers, Some(name)))
        .await
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect()
}

async fn fixture(node: &VectorNode, vectors: &Value) {
    run_steps(
        node,
        vectors,
        "fixture",
        &vectors["requestFixture"]["steps"],
    )
    .await;
}

#[tokio::test]
async fn unauthenticated_reads_are_refused_alike_and_no_group_read_is_cacheable() {
    let vectors = vectors();
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    node.set_now(1_800_003_600);
    let (stored, _) = blob(&vectors, "blob1");
    let (missing, _) = blob(&vectors, "blob4");

    // No token: the same 401 and the same bytes whether or not the hash is
    // stored, for GET, HEAD and a range read; nothing can tell them apart.
    let mut bodies = Vec::new();
    for hash in [&stored, &missing, &"0".repeat(64), &"not-a-hash".to_owned()] {
        for (method, range) in [("GET", None), ("HEAD", None), ("GET", Some("bytes=0-3"))] {
            let mut headers = Vec::new();
            if let Some(range) = range {
                headers.push(("Range", range.to_owned()));
            }
            let response = node
                .app
                .clone()
                .oneshot({
                    let mut builder = Request::builder().method(method).uri(format!("/{hash}"));
                    for (name, value) in &headers {
                        builder = builder.header(*name, value);
                    }
                    builder.body(Body::empty()).unwrap()
                })
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {hash}"
            );
            assert_eq!(
                response.headers().get("cache-control").unwrap(),
                "private, no-store"
            );
            assert!(
                header(response.headers(), "vary")
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case("authorization"))
            );
            bodies.push(to_bytes(response.into_body(), 1 << 16).await.unwrap());
        }
    }
    // HEAD carries no body; every GET answer is the same bytes.
    let gets = bodies
        .iter()
        .filter(|body| !body.is_empty())
        .collect::<BTreeSet<_>>();
    assert_eq!(gets.len(), 1);

    // Authenticated answers, ranges and refusals are all private too, and a
    // conditional request is never answered 304.
    let tail = node
        .request(&vectors, &vectors["requests"][0]["request"])
        .await;
    assert_eq!(tail.0, StatusCode::OK);
    for (status, who, hash, range, extra) in [
        (StatusCode::OK, "alicePhone", &stored, None, None),
        (
            StatusCode::PARTIAL_CONTENT,
            "alicePhone",
            &stored,
            Some("bytes=0-3"),
            None,
        ),
        (
            StatusCode::OK,
            "alicePhone",
            &stored,
            None,
            Some(("If-None-Match", format!("\"{stored}\""))),
        ),
        (StatusCode::NOT_FOUND, "alicePhone", &missing, None, None),
        (StatusCode::FORBIDDEN, "stranger", &stored, None, None),
    ] {
        node.set_now(1_800_003_600);
        let mut headers = vec![(
            "Authorization",
            token(&vectors, who, "get", hash, 1_800_003_600),
        )];
        headers.extend(range.map(|range| ("Range", range.to_owned())));
        headers.extend(extra);
        let (got, reason, response) = node
            .request(
                &vectors,
                &request("GET", &format!("/{hash}"), &headers, None),
            )
            .await;
        assert_eq!(got, status, "{who} {range:?} {reason}");
        assert_eq!(header(&response, "cache-control"), ["private, no-store"]);
        assert!(
            header(&response, "vary")
                .iter()
                .any(|value| value.eq_ignore_ascii_case("authorization")),
            "{status}"
        );
    }
}

#[tokio::test]
async fn a_revoked_reset_or_expired_key_is_refused_on_its_very_next_request() {
    let vectors = vectors();
    let (hash, _) = blob(&vectors, "blob1");
    let now = 1_800_000_000;
    let room_a = vectors["rooms"]["a"]["roomId"].as_str().unwrap().to_owned();

    // Revocation.
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    assert_eq!(
        get(&node, &vectors, "alicePhone", &hash, now + 100).await.0,
        StatusCode::OK
    );
    let revoke = sign(
        &secret(&vectors, "authorityA"),
        27_541,
        &[
            ("t", "grant".to_owned()),
            ("grant", "a683be7ffdc9a5cdab418a1d3dd3a9dd".to_owned()),
            ("d", room_a.clone()),
            ("device", pubkey(&vectors, "alicePhone")),
            ("server", "grove.example.net".to_owned()),
            ("scope", "upload".to_owned()),
            ("scope", "get".to_owned()),
            ("scope", "delete".to_owned()),
            ("bytes", "1073741824".to_owned()),
            ("status", "revoked".to_owned()),
            ("expiration", "1802592000".to_owned()),
        ],
        "",
        now + 101,
    );
    node.set_now(now + 101);
    assert_eq!(node.post(&revoke).await.0, StatusCode::CREATED);
    let (status, reason, _) = get(&node, &vectors, "alicePhone", &hash, now + 101).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::FORBIDDEN, "not-granted")
    );

    // Reset ends every grant of the room, bob's included.
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    assert_eq!(
        get(&node, &vectors, "bobLaptop", &hash, now + 100).await.0,
        StatusCode::OK
    );
    let reset = sign(
        &secret(&vectors, "authorityA"),
        27_541,
        &[
            ("t", "reset".to_owned()),
            ("d", room_a),
            ("server", "grove.example.net".to_owned()),
            ("expiration", "1807776000".to_owned()),
        ],
        "",
        now + 101,
    );
    node.set_now(now + 101);
    assert_eq!(node.post(&reset).await.0, StatusCode::CREATED);
    for who in ["alicePhone", "bobLaptop", "coordinatorA"] {
        let (status, reason, _) = get(&node, &vectors, who, &hash, now + 101).await;
        assert_eq!(
            (status, reason.as_str()),
            (StatusCode::FORBIDDEN, "not-granted"),
            "{who}"
        );
    }
    // The other group is untouched.
    let (other, _) = blob(&vectors, "blob2");
    assert_eq!(
        get(&node, &vectors, "carolPhone", &other, now + 101)
            .await
            .0,
        StatusCode::OK
    );

    // Expiry: one second before the grant ends it works, at the second it does not.
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    assert_eq!(
        get(&node, &vectors, "alicePhone", &hash, 1_802_591_998)
            .await
            .0,
        StatusCode::OK
    );
    let (status, ..) = get(&node, &vectors, "alicePhone", &hash, 1_802_592_000).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_device_and_group_ceilings_hold_and_a_full_node_refuses_without_evicting() {
    let vectors = vectors();
    let now = 1_800_000_000;
    // A group ceiling of 40 bytes holds one 31-byte blob and no second.
    let node = VectorNode::limited(
        &vectors,
        Limits {
            ceiling: Some(40),
            ..Limits::default()
        },
    )
    .await;
    node.set_now(now);
    for (keeper, device, id) in [(
        "authorityA",
        "alicePhone",
        "11111111111111111111111111111111",
    )] {
        let event = grant(
            &vectors,
            keeper,
            "a",
            id,
            device,
            &["upload", "get", "delete"],
            Some(1 << 20),
            now,
            86_400,
        );
        assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    }
    let event = grant(
        &vectors,
        "authorityA",
        "a",
        "22222222222222222222222222222222",
        "bobLaptop",
        &["upload", "get"],
        Some(1 << 20),
        now,
        86_400,
    );
    assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    assert_eq!(
        upload(&node, &vectors, "alicePhone", "blob1", now + 10)
            .await
            .0,
        StatusCode::CREATED
    );
    let (status, reason, _) = upload(&node, &vectors, "alicePhone", "blob4", now + 11).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::INSUFFICIENT_STORAGE, "group-full")
    );
    // The ceiling counts a blob once, so another member's copy of it is free.
    assert_eq!(
        upload(&node, &vectors, "bobLaptop", "blob1", now + 12)
            .await
            .0,
        StatusCode::OK
    );
    // A preflight says the same before any byte is sent.
    let (hash4, text4) = blob(&vectors, "blob4");
    node.set_now(now + 13);
    let preflight = node
        .request(
            &vectors,
            &request(
                "HEAD",
                "/upload",
                &[
                    (
                        "Authorization",
                        token(&vectors, "alicePhone", "upload", &hash4, now + 13),
                    ),
                    ("X-SHA-256", hash4.clone()),
                    ("X-Content-Length", text4.len().to_string()),
                    ("X-Content-Type", "application/octet-stream".to_owned()),
                ],
                None,
            ),
        )
        .await;
    assert_eq!(preflight.0, StatusCode::INSUFFICIENT_STORAGE);
    // Nothing was evicted or lost.
    let (hash1, _) = blob(&vectors, "blob1");
    assert_eq!(
        get(&node, &vectors, "bobLaptop", &hash1, now + 14).await.0,
        StatusCode::OK
    );

    // A device ceiling of 40 bytes: one blob.
    let node = VectorNode::new(&vectors).await;
    node.set_now(now);
    let event = grant(
        &vectors,
        "authorityA",
        "a",
        "33333333333333333333333333333333",
        "alicePhone",
        &["upload", "get"],
        Some(40),
        now,
        86_400,
    );
    assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    assert_eq!(
        upload(&node, &vectors, "alicePhone", "blob1", now + 10)
            .await
            .0,
        StatusCode::CREATED
    );
    let (status, reason, _) = upload(&node, &vectors, "alicePhone", "blob4", now + 11).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::INSUFFICIENT_STORAGE, "device-full")
    );

    // A full node: the quota holds two 31-byte blobs; the third is refused
    // and the first two are still there.
    let node = VectorNode::limited(
        &vectors,
        Limits {
            quota: Some(64),
            ..Limits::default()
        },
    )
    .await;
    node.set_now(now);
    let event = grant(
        &vectors,
        "authorityA",
        "a",
        "44444444444444444444444444444444",
        "alicePhone",
        &["upload", "get"],
        Some(1 << 20),
        now,
        86_400,
    );
    assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    for (name, status) in [
        ("blob1", StatusCode::CREATED),
        ("blob2", StatusCode::CREATED),
    ] {
        assert_eq!(
            upload(&node, &vectors, "alicePhone", name, now + 10)
                .await
                .0,
            status
        );
    }
    let (status, reason, _) = upload(&node, &vectors, "alicePhone", "blob3", now + 11).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::INSUFFICIENT_STORAGE, "node-full")
    );
    for name in ["blob1", "blob2"] {
        let (hash, _) = blob(&vectors, name);
        assert_eq!(
            get(&node, &vectors, "alicePhone", &hash, now + 12).await.0,
            StatusCode::OK,
            "{name}"
        );
    }
}

#[tokio::test]
async fn another_member_still_reads_what_an_expired_member_uploaded() {
    let vectors = vectors();
    let now = 1_800_000_000;
    let node = VectorNode::new(&vectors).await;
    node.set_now(now);
    let alice = grant(
        &vectors,
        "authorityA",
        "a",
        "55555555555555555555555555555555",
        "alicePhone",
        &["upload", "get"],
        Some(1 << 20),
        now,
        1_000,
    );
    let bob = grant(
        &vectors,
        "authorityA",
        "a",
        "66666666666666666666666666666666",
        "bobLaptop",
        &["get"],
        None,
        now,
        100_000,
    );
    assert_eq!(node.post(&alice).await.0, StatusCode::CREATED);
    assert_eq!(node.post(&bob).await.0, StatusCode::CREATED);
    assert_eq!(
        upload(&node, &vectors, "alicePhone", "blob1", now + 10)
            .await
            .0,
        StatusCode::CREATED
    );
    let (hash, _) = blob(&vectors, "blob1");
    // Alice's grant ends by expiry; her claim, and what the group holds, stay.
    let (status, ..) = get(&node, &vectors, "alicePhone", &hash, now + 1_000).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        get(&node, &vectors, "bobLaptop", &hash, now + 1_000)
            .await
            .0,
        StatusCode::OK
    );
    // And across a restart, the claim is still the group's.
    let node = node.restart(&vectors).await;
    assert_eq!(
        get(&node, &vectors, "bobLaptop", &hash, now + 1_001)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        get(&node, &vectors, "alicePhone", &hash, now + 1_001)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn owners_and_strangers_get_no_open_reads_and_the_core_still_judges_owner_writes() {
    let vectors = vectors();
    let now = 1_800_003_600;
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    let (owner_blob, _) = blob(&vectors, "blob3");
    let (group_blob, _) = blob(&vectors, "blob1");
    // The owner needs a token like anyone, and sees only what it holds.
    let plain = node
        .request(
            &vectors,
            &request("GET", &format!("/{owner_blob}"), &[], None),
        )
        .await;
    assert_eq!(plain.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        get(&node, &vectors, "nodeOwner", &owner_blob, now).await.0,
        StatusCode::OK
    );
    let (status, reason, _) = get(&node, &vectors, "nodeOwner", &group_blob, now).await;
    assert_eq!((status, reason.as_str()), (StatusCode::NOT_FOUND, "absent"));
    // Keepers are not users.
    let (status, reason, _) = get(&node, &vectors, "authorityA", &group_blob, now).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::FORBIDDEN, "not-granted")
    );
    // The unauthenticated server information and health routes still answer.
    for path in ["/", "/healthz"] {
        let (status, ..) = node
            .request(&vectors, &request("GET", path, &[], None))
            .await;
        assert_eq!(status, StatusCode::OK, "{path}");
    }
    // Lists are self-only and need an upload grant: a read-only member and a
    // stranger are refused before the core is asked.
    for who in ["bobLaptop", "stranger"] {
        node.set_now(now);
        let pubkey = pubkey(&vectors, who);
        let headers = [("Authorization", {
            use base64::Engine as _;
            let event = sign(
                &secret(&vectors, who),
                24_242,
                &[
                    ("t", "list".to_owned()),
                    ("expiration", (now + 59).to_string()),
                    ("server", "grove.example.net".to_owned()),
                ],
                "group-grants/1 synthetic list",
                now - 1,
            );
            format!(
                "Nostr {}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&event).unwrap())
            )
        })];
        let (status, reason, _) = node
            .request(
                &vectors,
                &request("GET", &format!("/list/{pubkey}"), &headers, None),
            )
            .await;
        assert_eq!(
            (status, reason.as_str()),
            (StatusCode::FORBIDDEN, "not-granted"),
            "{who}"
        );
    }
}

#[tokio::test]
async fn mirrors_need_an_upload_grant_and_preflights_allow_range() {
    let vectors = vectors();
    let now = 1_800_003_600;
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    let (hash, _) = blob(&vectors, "blob4");
    for (who, reason) in [("bobLaptop", "not-granted"), ("stranger", "not-granted")] {
        node.set_now(now);
        let body = serde_json::json!({ "url": format!("https://source.example.net/{hash}") });
        let headers = [("Authorization", token(&vectors, who, "upload", &hash, now))];
        let mut mirror = request("PUT", "/mirror", &headers, None);
        mirror["bodyText"] = body;
        let response = node
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/mirror")
                    .header("Authorization", &headers[0].1)
                    .header("content-type", "application/json")
                    .body(Body::from(mirror["bodyText"].to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{who}");
        assert_eq!(response.headers().get("x-reason").unwrap(), reason);
    }
    // A member with an upload grant reaches the core, which has no fetcher here.
    node.set_now(now);
    let response = node
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mirror")
                .header(
                    "Authorization",
                    token(&vectors, "alicePhone", "upload", &hash, now),
                )
                .body(Body::from(
                    serde_json::json!({ "url": format!("https://source.example.net/{hash}") })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get("x-reason").unwrap(),
        "mirroring is disabled"
    );
    // CORS preflight reveals nothing and allows Authorization, Range, X-SHA-256.
    let response = node
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(format!("/{hash}"))
                .header("origin", "https://app.example.net")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "authorization, range")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    let allowed = header(response.headers(), "access-control-allow-headers").join(",");
    for name in ["authorization", "range", "x-sha-256"] {
        assert!(allowed.contains(name), "{allowed}");
    }
    assert_eq!(
        header(response.headers(), "access-control-allow-origin"),
        ["*"]
    );
    // A simple cross-origin read carries exactly one allow-origin header.
    let (_, _, headers) = {
        node.set_now(now);
        let (hash1, _) = blob(&vectors, "blob1");
        node.request(
            &vectors,
            &request(
                "GET",
                &format!("/{hash1}"),
                &[
                    (
                        "Authorization",
                        token(&vectors, "alicePhone", "get", &hash1, now),
                    ),
                    ("Origin", "https://app.example.net".to_owned()),
                ],
                None,
            ),
        )
        .await
    };
    assert_eq!(header(&headers, "access-control-allow-origin").len(), 1);
}

#[tokio::test]
async fn with_group_mode_off_the_gate_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    let grants = open(&root, &[1], &[], &[]);
    let store = Store::open(StoreConfig {
        root: root.clone(),
        quota_bytes: 64 * MIB,
        max_blob_bytes: 8 * MIB,
    })
    .unwrap();
    let hash = "a".repeat(64);
    let state = AppState::new(
        store.clone(),
        BlossomConfig {
            server_metadata: ServerMetadata::default(),
            public_base_url: format!("https://{SERVER}/").parse().unwrap(),
            accepted_server_names: vec![SERVER.into()],
            allowed_pubkeys: vec![keys(1)],
            friend_grants: grants.core_friend_grants(),
            open_shelter: false,
            max_concurrent_writes: 4,
            mirror_proxy: None,
        },
    )
    .unwrap();
    grants.attach(state.clone());
    let app = router(state).layer(from_fn_with_state(grants.clone(), group_gate));
    // An unknown blob is a plain 404 from the core, not a 401 from the gate.
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/{hash}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(!grants.group_enabled());
}

#[tokio::test]
async fn a_spent_delete_token_stays_spent_across_a_restart() {
    let vectors = vectors();
    let sequence = case(&vectors, "sequences", "delete-replay-and-grace");
    let steps = sequence["steps"].as_array().unwrap();
    let node = VectorNode::new(&vectors).await;
    // Grant, two uploads, the delete, its replay and the re-upload.
    run_steps(
        &node,
        &vectors,
        "before",
        &Value::Array(steps[..6].to_vec()),
    )
    .await;
    let node = node.restart(&vectors).await;
    // The claim is back, the token was spent before the restart.
    run_steps(
        &node,
        &vectors,
        "after",
        &Value::Array(steps[6..7].to_vec()),
    )
    .await;
    assert_eq!(steps[6]["expect"]["reason"], "spent");
    // The revocation and the seven-day grace behave the same afterwards.
    run_steps(&node, &vectors, "grace", &Value::Array(steps[7..].to_vec())).await;
}

// ---------------------------------------------------------------------------
// The independent review's findings.
// ---------------------------------------------------------------------------

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A raw upload: the hash and length a client claims, and the bytes it sends.
async fn put_raw(
    node: &VectorNode,
    signer: &Keys,
    hash: &str,
    length: usize,
    body: Vec<u8>,
    now: u64,
) -> (StatusCode, String, HeaderMap) {
    node.set_now(now);
    let response = node
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/upload")
                .header("Authorization", token_by(signer, "upload", hash, now))
                .header("X-SHA-256", hash)
                .header("Content-Length", length.to_string())
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let headers = response.headers().clone();
    let reason = headers
        .get("x-reason")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let status = response.status();
    let _ = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, reason, headers)
}

fn holds(node: &VectorNode, key: &str, hash: &str) -> bool {
    super::claims::holds_claim(&node.store, key, hash).unwrap()
}

#[tokio::test]
async fn a_hash_and_a_length_are_not_enough_to_be_handed_a_blob() {
    let vectors = vectors();
    let now = 1_800_000_060;
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    let alice = secret(&vectors, "alicePhone");
    let alice_key = pubkey(&vectors, "alicePhone");
    let (owner_blob, owner_text) = blob(&vectors, "blob3");
    let (other_group, _) = blob(&vectors, "blob2");

    // The review's run: the owner's hash and size, and nothing but zeros.
    for hash in [&owner_blob, &other_group] {
        let (status, reason, _) = put_raw(
            &node,
            &alice,
            hash,
            owner_text.len(),
            vec![0; owner_text.len()],
            now,
        )
        .await;
        assert_eq!(
            (status, reason.as_str()),
            (StatusCode::BAD_REQUEST, "bad-request")
        );
        assert!(!holds(&node, &alice_key, hash), "no claim was made");
        let (status, reason, _) = get(&node, &vectors, "alicePhone", hash, now + 1).await;
        assert_eq!((status, reason.as_str()), (StatusCode::NOT_FOUND, "absent"));
    }
    // Too few, too many or wrong bytes are all refused the same way.
    for body in [
        vec![],
        vec![1; owner_text.len() + 1],
        vec![7; owner_text.len()],
    ] {
        let length = owner_text.len();
        let (status, ..) = put_raw(&node, &alice, &owner_blob, length, body, now + 2).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(!holds(&node, &alice_key, &owner_blob));

    // The real bytes prove the blob: 201 for a group that did not hold it,
    // and from then on the group may read it.
    let (status, ..) = put_raw(
        &node,
        &alice,
        &owner_blob,
        owner_text.len(),
        owner_text.clone().into_bytes(),
        now + 3,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        get(&node, &vectors, "alicePhone", &owner_blob, now + 4)
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        get(&node, &vectors, "bobLaptop", &owner_blob, now + 4)
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn no_upload_or_preflight_hints_that_a_blob_is_stored_elsewhere() {
    let vectors = vectors();
    let now = 1_800_000_060;
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    let alice = secret(&vectors, "alicePhone");
    let (stored, text) = blob(&vectors, "blob3");
    let (unknown, _) = blob(&vectors, "blob4");

    // A wrong length gets the same answer for a stored hash and an unknown one.
    let wrong = |hash: String| {
        let (node, alice) = (&node, &alice);
        async move {
            let (status, reason, _) = put_raw(node, alice, &hash, 5, vec![1; 5], now).await;
            (status, reason)
        }
    };
    assert_eq!(wrong(stored.clone()).await, wrong(unknown.clone()).await);
    // So does a preflight, with the right length or a wrong one.
    for length in [text.len(), 5, text.len() + 100] {
        let mut answers = Vec::new();
        for hash in [&stored, &unknown] {
            node.set_now(now);
            let (status, reason, _) = node
                .request(
                    &vectors,
                    &request(
                        "HEAD",
                        "/upload",
                        &[
                            ("Authorization", token_by(&alice, "upload", hash, now)),
                            ("X-SHA-256", hash.clone()),
                            ("X-Content-Length", length.to_string()),
                            ("X-Content-Type", "application/octet-stream".to_owned()),
                        ],
                        None,
                    ),
                )
                .await;
            answers.push((status, reason));
        }
        assert_eq!(answers[0], answers[1], "length {length}");
    }
}

#[tokio::test]
async fn the_core_upload_route_and_mirrors_also_need_the_bytes() {
    let vectors = vectors();
    let (hash4, text4) = blob(&vectors, "blob4");
    let (owner_blob, owner_text) = blob(&vectors, "blob3");
    let friend = Keys::generate();
    // The core checks tokens on the machine clock, so this node keeps it.
    let node = VectorNode::limited(
        &vectors,
        Limits {
            friend: Some(friend.public_key().to_hex()),
            source: Some(text4.clone().into_bytes()),
            ..Limits::default()
        },
    )
    .await;
    let now = real_now();
    node.set_now(now);
    let alice_key = pubkey(&vectors, "alicePhone");
    let event = grant(
        &vectors,
        "authorityA",
        "a",
        "77777777777777777777777777777777",
        "alicePhone",
        &["upload", "get"],
        Some(1 << 20),
        now,
        86_400,
    );
    assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    node.owner_upload(&vectors, "blob3");
    assert_eq!(
        upload(&node, &vectors, "alicePhone", "blob1", now).await.0,
        StatusCode::CREATED
    );
    let (group_blob, _) = blob(&vectors, "blob1");
    let friend_key = friend.public_key().to_hex();

    // A friend key: zeros for the owner's or a group's hash are refused, and
    // it gets no claim and cannot read.
    for hash in [&owner_blob, &group_blob] {
        let (status, ..) = put_raw(
            &node,
            &friend,
            hash,
            owner_text.len(),
            vec![0; owner_text.len()],
            now,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!holds(&node, &friend_key, hash));
        node.set_now(now);
        let (status, ..) = node
            .request(
                &vectors,
                &request(
                    "GET",
                    &format!("/{hash}"),
                    &[("Authorization", token_by(&friend, "get", hash, now))],
                    None,
                ),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    // With the real bytes it holds its own claim, as a re-upload always did.
    let (status, ..) = put_raw(
        &node,
        &friend,
        &owner_blob,
        owner_text.len(),
        owner_text.clone().into_bytes(),
        now,
    )
    .await;
    assert!(status.is_success(), "{status}");
    assert!(holds(&node, &friend_key, &owner_blob));

    // A mirror of a blob the group does not hold, from a source that serves
    // other bytes: the core would call the existing blob a success and drop
    // what it fetched, so the gate takes the claim back.
    let mirror = |hash: String| {
        let (node, alice) = (&node, secret(&vectors, "alicePhone"));
        async move {
            node.set_now(now);
            let response = node
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/mirror")
                        .header("Authorization", token_by(&alice, "upload", &hash, now))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({ "url": format!("https://source.example.net/{hash}") })
                                .to_string(),
                        ))
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
            (status, reason)
        }
    };
    let (status, reason) = mirror(group_blob.clone()).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::OK, ""),
        "held already"
    );
    let (status, reason) = mirror(owner_blob.clone()).await;
    assert_eq!(
        (status, reason.as_str()),
        (
            StatusCode::CONFLICT,
            "mirror origin returned the wrong blob"
        )
    );
    assert!(!holds(&node, &alice_key, &owner_blob));
    assert_eq!(
        get(&node, &vectors, "alicePhone", &owner_blob, now).await.0,
        StatusCode::NOT_FOUND
    );
    // A blob nobody holds is fetched, checked and kept: that mirror is real.
    let (status, _) = mirror(hash4.clone()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        get(&node, &vectors, "alicePhone", &hash4, now).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn gate_answers_carry_the_core_cors_headers_and_health_says_little() {
    let vectors = vectors();
    let now = 1_800_000_060;
    let node = VectorNode::new(&vectors).await;
    fixture(&node, &vectors).await;
    let (hash, text) = blob(&vectors, "blob1");
    let (fresh, fresh_text) = blob(&vectors, "blob4");
    node.set_now(now);
    let origin = ("Origin", "https://app.example.net".to_owned());
    let mut answers = Vec::new();
    // 401, 403, 404, 200 (read), 201 (upload), preflight, delete and a refusal.
    answers.push(
        node.request(
            &vectors,
            &request(
                "GET",
                &format!("/{hash}"),
                std::slice::from_ref(&origin),
                None,
            ),
        )
        .await,
    );
    for (who, target) in [("stranger", &hash), ("alicePhone", &fresh)] {
        let headers = [
            ("Authorization", token(&vectors, who, "get", target, now)),
            origin.clone(),
        ];
        answers.push(
            node.request(
                &vectors,
                &request("GET", &format!("/{target}"), &headers, None),
            )
            .await,
        );
    }
    let headers = [
        (
            "Authorization",
            token(&vectors, "alicePhone", "get", &hash, now),
        ),
        origin.clone(),
    ];
    answers.push(
        node.request(
            &vectors,
            &request("GET", &format!("/{hash}"), &headers, None),
        )
        .await,
    );
    let headers = [
        (
            "Authorization",
            token(&vectors, "alicePhone", "upload", &fresh, now),
        ),
        ("X-SHA-256", fresh.clone()),
        ("Content-Length", fresh_text.len().to_string()),
        origin.clone(),
    ];
    answers.push(
        node.request(
            &vectors,
            &request("PUT", "/upload", &headers, Some("blob4")),
        )
        .await,
    );
    let headers = [
        (
            "Authorization",
            token(&vectors, "alicePhone", "upload", &hash, now),
        ),
        ("X-SHA-256", hash.clone()),
        ("X-Content-Length", text.len().to_string()),
        ("X-Content-Type", "application/octet-stream".to_owned()),
        origin.clone(),
    ];
    answers.push(
        node.request(&vectors, &request("HEAD", "/upload", &headers, None))
            .await,
    );
    let headers = [
        (
            "Authorization",
            token(&vectors, "alicePhone", "delete", &fresh, now),
        ),
        origin.clone(),
    ];
    answers.push(
        node.request(
            &vectors,
            &request("DELETE", &format!("/{fresh}"), &headers, None),
        )
        .await,
    );
    let headers = [
        (
            "Authorization",
            token(&vectors, "bobLaptop", "delete", &hash, now),
        ),
        origin.clone(),
    ];
    answers.push(
        node.request(
            &vectors,
            &request("DELETE", &format!("/{hash}"), &headers, None),
        )
        .await,
    );
    let statuses = answers
        .iter()
        .map(|(status, ..)| status.as_u16())
        .collect::<Vec<_>>();
    assert_eq!(statuses, [401, 403, 404, 200, 201, 200, 200, 403]);
    for (status, _, headers) in &answers {
        assert_eq!(
            header(headers, "access-control-allow-origin"),
            ["*"],
            "{status}"
        );
        let exposed = header(headers, "access-control-expose-headers").join(",");
        assert!(
            exposed.contains("x-reason") && exposed.contains("content-range"),
            "{status}: {exposed}"
        );
    }

    // Liveness only, and nothing cacheable, on the two public routes.
    for path in ["/", "/healthz"] {
        let response = node
            .app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()["cache-control"],
            "private, no-store",
            "{path}"
        );
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        if path == "/healthz" {
            assert_eq!(text, r#"{"status":"ok"}"#);
        }
    }

    // A HEAD of a list is judged like a GET of one.
    node.set_now(now);
    let stranger = pubkey(&vectors, "stranger");
    let headers = [(
        "Authorization",
        token(&vectors, "stranger", "list", &hash, now),
    )];
    let (status, reason, _) = node
        .request(
            &vectors,
            &request("HEAD", &format!("/list/{stranger}"), &headers, None),
        )
        .await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::FORBIDDEN, "not-granted")
    );
}

#[tokio::test]
async fn a_preflight_counts_the_bytes_other_uploads_have_in_flight() {
    let vectors = vectors();
    let now = 1_800_000_000;
    let node = VectorNode::limited(
        &vectors,
        Limits {
            ceiling: Some(40),
            ..Limits::default()
        },
    )
    .await;
    node.set_now(now);
    let event = grant(
        &vectors,
        "authorityA",
        "a",
        "88888888888888888888888888888888",
        "alicePhone",
        &["upload", "get"],
        Some(1 << 20),
        now,
        86_400,
    );
    assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    let (hash, text) = blob(&vectors, "blob4");
    let preflight = || async {
        node.set_now(now + 5);
        node.request(
            &vectors,
            &request(
                "HEAD",
                "/upload",
                &[
                    (
                        "Authorization",
                        token(&vectors, "alicePhone", "upload", &hash, now + 5),
                    ),
                    ("X-SHA-256", hash.clone()),
                    ("X-Content-Length", text.len().to_string()),
                    ("X-Content-Type", "application/octet-stream".to_owned()),
                ],
                None,
            ),
        )
        .await
        .0
    };
    assert_eq!(preflight().await, StatusCode::OK);
    let group = (
        pubkey(&vectors, "authorityA"),
        vectors["rooms"]["a"]["roomId"].as_str().unwrap().to_owned(),
    );
    // Another device's upload is part way through and holds 31 of the 40.
    let admitted = node
        .grants
        .reserve_group_bytes(&group, 40, 31)
        .unwrap()
        .unwrap();
    assert_eq!(preflight().await, StatusCode::INSUFFICIENT_STORAGE);
    drop(admitted);
    assert_eq!(preflight().await, StatusCode::OK);
}

#[tokio::test]
async fn a_grant_the_core_will_not_take_is_not_recorded_or_admitted() {
    let vectors = vectors();
    let node = VectorNode::new(&vectors).await;
    node.set_now(1_800_000_000);
    let event = case(&vectors, "grantEvents", "good-grant")["event"].clone();
    let alice = pubkey(&vectors, "alicePhone");
    node.grants
        .inner
        .fail_push
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (status, reason, _) = node.post(&event).await;
    assert_eq!(
        (status, reason.as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    assert!(!node.granted(&alice, "get"), "the gate never saw the key");
    assert!(node.grants.core_friend_grants().is_empty());
    // The keeper retries and it lands, as a new grant rather than a replay.
    let (status, reason, _) = node.post(&event).await;
    assert_eq!((status, reason.as_str()), (StatusCode::CREATED, "accepted"));
    assert!(node.granted(&alice, "get"));
    assert_eq!(node.grants.core_friend_grants().len(), 1);
}

/// What a request answered, for comparing two hashes: status and reason.
type Answer = (StatusCode, String);

#[tokio::test]
async fn a_stored_hash_and_an_unknown_one_get_the_same_answer_at_every_length() {
    let vectors = vectors();
    let node = VectorNode::limited(
        &vectors,
        Limits {
            ceiling: Some(10 * MIB),
            max_blob: Some(MIB),
            ..Limits::default()
        },
    )
    .await;
    let now = 1_800_000_000;
    node.set_now(now);
    // The review's table: a device with 512 KiB, a 1 MiB blob limit.
    let event = grant(
        &vectors,
        "authorityA",
        "a",
        "abababababababababababababababab",
        "alicePhone",
        &["upload", "get"],
        Some(524_288),
        now,
        86_400,
    );
    assert_eq!(node.post(&event).await.0, StatusCode::CREATED);
    let carol = grant(
        &vectors,
        "authorityB",
        "b",
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "carolPhone",
        &["upload", "get"],
        Some(1 << 20),
        now,
        86_400,
    );
    assert_eq!(node.post(&carol).await.0, StatusCode::CREATED);
    assert_eq!(
        upload(&node, &vectors, "carolPhone", "blob2", now + 1)
            .await
            .0,
        StatusCode::CREATED
    );
    let alice = secret(&vectors, "alicePhone");
    let (stored, _) = blob(&vectors, "blob2");
    let (unknown, _) = blob(&vectors, "blob4");

    for length in [0_usize, 7, 31, 524_289, 600_000, 1_048_576, 1_048_577] {
        let mut puts: Vec<Answer> = Vec::new();
        let mut heads: Vec<Answer> = Vec::new();
        for hash in [&stored, &unknown] {
            let (status, reason, _) =
                put_raw(&node, &alice, hash, length, vec![0; length], now + 2).await;
            puts.push((status, reason));
            node.set_now(now + 2);
            let (status, reason, _) = node
                .request(
                    &vectors,
                    &request(
                        "HEAD",
                        "/upload",
                        &[
                            ("Authorization", token_by(&alice, "upload", hash, now + 2)),
                            ("X-SHA-256", hash.clone()),
                            ("X-Content-Length", length.to_string()),
                            ("X-Content-Type", "application/octet-stream".to_owned()),
                        ],
                        None,
                    ),
                )
                .await;
            heads.push((status, reason));
        }
        assert_eq!(puts[0], puts[1], "PUT of {length} bytes");
        assert_eq!(heads[0], heads[1], "HEAD of {length} bytes");
        if length == 600_000 {
            assert_eq!(puts[0].0, StatusCode::INSUFFICIENT_STORAGE);
            assert_eq!(heads[0].0, StatusCode::INSUFFICIENT_STORAGE);
        }
        if length == 1_048_577 {
            assert_eq!(puts[0].0, StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
}

#[tokio::test]
async fn an_owner_delegated_key_is_judged_before_a_byte_is_read_too() {
    let vectors = vectors();
    let friend = Keys::generate();
    let node = VectorNode::limited(
        &vectors,
        Limits {
            friend: Some(friend.public_key().to_hex()),
            friend_bytes: Some(100_000),
            max_blob: Some(MIB),
            ..Limits::default()
        },
    )
    .await;
    let now = real_now();
    node.set_now(now);
    node.owner_upload(&vectors, "blob3");
    let (stored, _) = blob(&vectors, "blob3");
    let (unknown, _) = blob(&vectors, "blob4");
    for length in [7_usize, 31, 600_000, 1_048_577] {
        let mut answers: Vec<Answer> = Vec::new();
        for hash in [&stored, &unknown] {
            let (status, reason, _) =
                put_raw(&node, &friend, hash, length, vec![0; length], now).await;
            answers.push((status, reason));
        }
        assert_eq!(answers[0], answers[1], "{length} bytes");
        if length == 600_000 {
            assert_eq!(answers[0].0, StatusCode::INSUFFICIENT_STORAGE);
        }
        if length == 1_048_577 {
            assert_eq!(answers[0].0, StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
}

#[tokio::test]
async fn a_revocation_never_waits_on_a_core_push_or_a_write_in_flight() {
    let vectors = vectors();
    let node = Arc::new(VectorNode::new(&vectors).await);
    let now = real_now();
    node.set_now(now);
    // Keeper B has a member whose grant its keeper will revoke.
    let carol = grant(
        &vectors,
        "authorityB",
        "b",
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "carolPhone",
        &["get"],
        None,
        now,
        86_400,
    );
    assert_eq!(node.post(&carol).await.0, StatusCode::CREATED);

    // An owner upload that starts and then stalls, holding a core write slot.
    let body = vec![0_u8; 1_000];
    let hash = hex::encode(Sha256::digest(&body));
    let owner = secret(&vectors, "nodeOwner");
    let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(4);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|chunk| (Ok::<Bytes, std::io::Error>(chunk), receiver))
    });
    let upload = {
        let node = node.clone();
        let request = Request::builder()
            .method("PUT")
            .uri("/upload")
            .header("Authorization", token_by(&owner, "upload", &hash, now))
            .header("X-SHA-256", &hash)
            .header("Content-Length", "1000")
            .body(Body::from_stream(stream))
            .unwrap();
        tokio::spawn(async move { node.app.clone().oneshot(request).await.unwrap().status() })
    };
    sender.send(Bytes::from(vec![0; 10])).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A new upload key from keeper A has to be pushed to the core, which waits
    // for that write.
    let alice = grant(
        &vectors,
        "authorityA",
        "a",
        "efefefefefefefefefefefefefefefef",
        "alicePhone",
        &["upload", "get"],
        Some(1 << 20),
        now,
        86_400,
    );
    let pending = {
        let node = node.clone();
        tokio::spawn(async move { node.post(&alice).await.0 })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!pending.is_finished(), "the push is waiting on the write");

    // Keeper B's revocation is accepted promptly all the same.
    node.set_now(now + 1);
    let revoke = sign(
        &secret(&vectors, "authorityB"),
        27_541,
        &[
            ("t", "grant".to_owned()),
            ("grant", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_owned()),
            (
                "d",
                vectors["rooms"]["b"]["roomId"].as_str().unwrap().to_owned(),
            ),
            ("device", pubkey(&vectors, "carolPhone")),
            ("server", "grove.example.net".to_owned()),
            ("scope", "get".to_owned()),
            ("status", "revoked".to_owned()),
            ("expiration", (now + 86_400).to_string()),
        ],
        "",
        now + 1,
    );
    let (status, ..) = tokio::time::timeout(Duration::from_secs(2), node.post(&revoke))
        .await
        .expect("the revocation did not wait for the push");
    assert_eq!(status, StatusCode::CREATED);
    assert!(!node.granted(&pubkey(&vectors, "carolPhone"), "get"));
    assert!(!pending.is_finished());

    // Let the write finish: the push, and so the grant, follow.
    sender.send(Bytes::from(vec![0; 990])).await.unwrap();
    drop(sender);
    assert_eq!(upload.await.unwrap(), StatusCode::CREATED);
    assert_eq!(pending.await.unwrap(), StatusCode::CREATED);
    assert!(node.granted(&pubkey(&vectors, "alicePhone"), "upload"));
}

#[tokio::test]
async fn an_owner_delegated_key_cannot_read_a_claim_a_mirror_has_not_proven() {
    let vectors = vectors();
    let (_, text4) = blob(&vectors, "blob4");
    let (owner_blob, _) = blob(&vectors, "blob3");
    let friend = Keys::generate();
    let friend_key = friend.public_key().to_hex();
    let release = Arc::new(tokio::sync::Notify::new());
    let node = Arc::new(
        VectorNode::limited(
            &vectors,
            Limits {
                friend: Some(friend_key.clone()),
                source: Some(text4.into_bytes()),
                source_gate: Some(release.clone()),
                ..Limits::default()
            },
        )
        .await,
    );
    let now = real_now();
    node.set_now(now);
    node.owner_upload(&vectors, "blob3");

    // The key is marked before the core is asked, and the mark outlives the
    // take-back; the mirror itself answers as a fresh wrong-bytes one does.
    let mirror = {
        let node = node.clone();
        let (friend, hash) = (friend.clone(), owner_blob.clone());
        tokio::spawn(async move {
            let response = node
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri("/mirror")
                        .header("Authorization", token_by(&friend, "upload", &hash, now))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::json!({ "url": format!("https://source.example.net/{hash}") })
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            let reason = response
                .headers()
                .get("x-reason")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            (response.status(), reason)
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(node.grants.is_unproven(&friend_key, &owner_blob));
    release.notify_one();
    let (status, reason) = mirror.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reason, "mirror origin returned the wrong blob");
    assert!(!node.grants.is_unproven(&friend_key, &owner_blob));
    assert!(!holds(&node, &friend_key, &owner_blob));

    // While a key's claim is unproven it reads nothing, even with the claim in place.
    let (status, ..) = put_raw(
        &node,
        &friend,
        &owner_blob,
        31,
        blob(&vectors, "blob3").1.into_bytes(),
        now,
    )
    .await;
    assert!(status.is_success());
    let read = || async {
        node.request(
            &vectors,
            &request(
                "GET",
                &format!("/{owner_blob}"),
                &[("Authorization", token_by(&friend, "get", &owner_blob, now))],
                None,
            ),
        )
        .await
        .0
    };
    assert_eq!(read().await, StatusCode::OK);
    let mark = node.grants.mark_unproven(&friend_key, &owner_blob).unwrap();
    assert_eq!(read().await, StatusCode::NOT_FOUND);
    drop(mark);
    assert_eq!(read().await, StatusCode::OK);
}

#[tokio::test]
async fn the_event_route_exposes_x_reason_to_browsers() {
    let vectors = vectors();
    let node = VectorNode::new(&vectors).await;
    node.set_now(1_800_000_000);
    let event = case(&vectors, "grantEvents", "good-grant")["event"].clone();
    let response = node
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/groups/v1/events")
                .header("origin", "https://app.example.net")
                .body(Body::from(serde_json::to_vec(&event).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        header(response.headers(), "access-control-allow-origin"),
        ["*"]
    );
    assert!(
        header(response.headers(), "access-control-expose-headers")
            .join(",")
            .contains("x-reason")
    );
}
