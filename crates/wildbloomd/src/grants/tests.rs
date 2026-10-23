//! Device grant, delegated claim, pairing issuer and TURN credential issuer
//! tests.  Synthetic keys, hashes, domains and secrets only; Foregather is a
//! local stand-in router.
use super::{
    Grants, GrantsConfig,
    event::{DEVICE_GRANT_KIND, MAX_GRANT_SECONDS},
    gate,
    issuer::{Issuer, OperatorToken},
    turn::{TurnIssuer, TurnSecret},
};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    http::{Method, Request, StatusCode, header},
    middleware::from_fn_with_state,
    routing::post,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
use wildbloom_core::{AppState, BlossomConfig, ServerMetadata, Store, StoreConfig, router};

const SERVER: &str = "node.example";
const ORIGIN: &str = "https://node.example/";
const MIB: u64 = 1024 * 1024;

fn real_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn keys(n: u64) -> Keys {
    Keys::parse(&format!("{n:064x}")).unwrap()
}

fn hex(keys: &Keys) -> String {
    keys.public_key().to_hex()
}

struct Node {
    grants: Grants,
    state: AppState,
    app: Router,
    offset: Arc<AtomicI64>,
}

impl Node {
    fn now(&self) -> u64 {
        real_now().saturating_add_signed(self.offset.load(Ordering::SeqCst))
    }

    fn advance(&self, seconds: i64) {
        self.offset.fetch_add(seconds, Ordering::SeqCst);
    }

    async fn sweep(&self) {
        self.grants.sweep_ended().await.unwrap();
    }

    async fn call(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

async fn node_at(root: PathBuf, offset: Arc<AtomicI64>) -> Node {
    node_with(root, offset, &[1], Vec::new()).await
}

async fn node_with(
    root: PathBuf,
    offset: Arc<AtomicI64>,
    owners: &[u64],
    friends: Vec<wildbloom_core::FriendGrant>,
) -> Node {
    let owners = owners.iter().map(|n| hex(&keys(*n))).collect::<Vec<_>>();
    let store = Store::open(StoreConfig {
        root: root.clone(),
        quota_bytes: 64 * MIB,
        max_blob_bytes: 8 * MIB,
    })
    .unwrap();
    let clock_offset = offset.clone();
    let grants = Grants::open(
        &root,
        GrantsConfig {
            owners: owners.clone(),
            server_names: vec![SERVER.into()],
            origin: ORIGIN.into(),
            cli_friend_grants: friends,
            reserved_keys: vec![hex(&keys(99))],
        },
        Arc::new(move || real_now().saturating_add_signed(clock_offset.load(Ordering::SeqCst))),
    )
    .unwrap();
    let state = AppState::new(
        store,
        BlossomConfig {
            server_metadata: ServerMetadata::default(),
            public_base_url: ORIGIN.parse().unwrap(),
            accepted_server_names: vec![SERVER.into()],
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
    let app = router(state.clone())
        .layer(from_fn_with_state(grants.clone(), gate))
        .merge(grants.router());
    Node {
        grants,
        state,
        app,
        offset,
    }
}

async fn node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let node = node_at(dir.path().join("data"), Arc::new(AtomicI64::new(0))).await;
    (dir, node)
}

fn signed(signer: &Keys, kind: u16, tags: Vec<Vec<String>>, created_at: u64) -> String {
    let tags = tags
        .into_iter()
        .map(|tag| Tag::parse(tag).unwrap())
        .collect::<Vec<_>>();
    let event = EventBuilder::new(Kind::Custom(kind), "Approve this device")
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .finalize(signer)
        .unwrap();
    serde_json::to_string(&event).unwrap()
}

fn tag(name: &str, value: impl ToString) -> Vec<String> {
    vec![name.to_owned(), value.to_string()]
}

struct Grant {
    device: u64,
    recovery: u64,
    bytes: u64,
    until_in: u64,
}

fn grant_tags(grant: &Grant, now: u64) -> Vec<Vec<String>> {
    vec![
        tag("t", "grant"),
        tag("device", hex(&keys(grant.device))),
        tag("recovery", hex(&keys(grant.recovery))),
        tag("bytes", grant.bytes),
        tag("until", now + grant.until_in),
        tag("server", SERVER),
        tag("expiration", now + 300),
    ]
}

fn grant_event(signer: &Keys, grant: &Grant, now: u64) -> String {
    signed(signer, DEVICE_GRANT_KIND, grant_tags(grant, now), now)
}

fn post_grant(body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/grants/v1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn revoke_request(signer: &Keys, device: &Keys, created_at: u64) -> Request<Body> {
    let event = signed(
        signer,
        DEVICE_GRANT_KIND,
        vec![
            tag("t", "revoke"),
            tag("device", hex(device)),
            tag("server", SERVER),
            tag("expiration", created_at + 300),
        ],
        created_at,
    );
    Request::builder()
        .method(Method::DELETE)
        .uri(format!("/grants/v1/{}", hex(device)))
        .header(
            header::AUTHORIZATION,
            format!("Nostr {}", URL_SAFE_NO_PAD.encode(event)),
        )
        .body(Body::empty())
        .unwrap()
}

fn bud11(signer: &Keys, verb: &str, hash: Option<&str>) -> String {
    let now = real_now();
    let mut tags = vec![
        tag("t", verb),
        tag("server", SERVER),
        tag("expiration", now + 60),
    ];
    if let Some(hash) = hash {
        tags.push(tag("x", hash));
    }
    let tags = tags
        .into_iter()
        .map(|tag| Tag::parse(tag).unwrap())
        .collect::<Vec<_>>();
    let event = EventBuilder::new(Kind::Custom(24_242), "Authorise blob request")
        .tags(tags)
        .custom_created_at(Timestamp::from(now))
        .finalize(signer)
        .unwrap();
    format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
    )
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn upload(node: &Node, signer: &Keys, bytes: &[u8]) -> StatusCode {
    let hash = sha(bytes);
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/upload")
        .header(header::CONTENT_LENGTH, bytes.len())
        .header("x-sha-256", &hash)
        .header(header::AUTHORIZATION, bud11(signer, "upload", Some(&hash)))
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    node.call(request).await.0
}

async fn delete(node: &Node, signer: &Keys, hash: &str) -> StatusCode {
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/{hash}"))
        .header(header::AUTHORIZATION, bud11(signer, "delete", Some(hash)))
        .body(Body::empty())
        .unwrap();
    node.call(request).await.0
}

async fn list(node: &Node, signer: &Keys) -> Vec<String> {
    let request = Request::builder()
        .uri(format!("/list/{}", hex(signer)))
        .header(header::AUTHORIZATION, bud11(signer, "list", None))
        .body(Body::empty())
        .unwrap();
    let (status, body) = node.call(request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body.as_array()
        .unwrap()
        .iter()
        .map(|item| item["sha256"].as_str().unwrap().to_owned())
        .collect()
}

async fn get_status(node: &Node, path: &str) -> StatusCode {
    let request = Request::builder().uri(path).body(Body::empty()).unwrap();
    node.call(request).await.0
}

fn nip98(signer: &Keys, url: &str, method: &str, body: &[u8], created_at: u64) -> String {
    let mut tags = vec![tag("u", url), tag("method", method)];
    if method == "POST" {
        tags.push(tag("payload", sha(body)));
    }
    let tags = tags
        .into_iter()
        .map(|tag| Tag::parse(tag).unwrap())
        .collect::<Vec<_>>();
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::from(created_at))
        .finalize(signer)
        .unwrap();
    format!(
        "Nostr {}",
        STANDARD.encode(serde_json::to_vec(&event).unwrap())
    )
}

fn standard_grant() -> Grant {
    Grant {
        device: 10,
        recovery: 11,
        bytes: MIB,
        until_in: 3600,
    }
}

#[tokio::test]
async fn owner_grant_allows_device_and_recovery_writes_and_revocation_stops_them() {
    let (_dir, node) = node().await;
    let (owner, device, recovery) = (keys(1), keys(10), keys(11));
    assert_eq!(
        upload(&node, &device, b"before grant").await,
        StatusCode::UNAUTHORIZED
    );

    let (status, body) = node
        .call(post_grant(grant_event(
            &owner,
            &standard_grant(),
            node.now(),
        )))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["state"], "active");
    assert_eq!(body["device"], hex(&device));
    assert_eq!(body["recovery"], hex(&recovery));

    assert_eq!(
        upload(&node, &device, b"device file").await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &recovery, b"key list").await,
        StatusCode::CREATED
    );
    assert_eq!(list(&node, &device).await, vec![sha(b"device file")]);
    assert_eq!(list(&node, &recovery).await, vec![sha(b"key list")]);
    // BUD-12 self-only delete works for a delegated key.
    assert_eq!(
        upload(&node, &device, b"shared copy").await,
        StatusCode::CREATED
    );
    assert_eq!(
        delete(&node, &device, &sha(b"shared copy")).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"shared copy"))).await,
        StatusCode::NOT_FOUND
    );

    let (status, body) = node
        .call(revoke_request(&owner, &device, node.now() + 1))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "revoked");
    assert_eq!(
        upload(&node, &device, b"after revoke").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        upload(&node, &recovery, b"after revoke").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        delete(&node, &device, &sha(b"device file")).await,
        StatusCode::FORBIDDEN
    );
    // Existing claims are kept, moved to the owner by the next sweep, and
    // the owner can delete them.
    node.sweep().await;
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"device file"))).await,
        StatusCode::OK
    );
    let mut owned = list(&node, &owner).await;
    owned.sort();
    let mut expected = vec![sha(b"device file"), sha(b"key list")];
    expected.sort();
    assert_eq!(owned, expected);
    assert!(list(&node, &device).await.is_empty());
    assert_eq!(
        delete(&node, &owner, &sha(b"device file")).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"device file"))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn grant_events_from_non_owners_or_for_other_servers_are_refused() {
    let (_dir, node) = node().await;
    let now = node.now();
    let stranger = keys(2);
    let (status, _) = node
        .call(post_grant(grant_event(&stranger, &standard_grant(), now)))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut tags = grant_tags(&standard_grant(), now);
    tags[5] = tag("server", "other.example");
    let (status, _) = node
        .call(post_grant(signed(&keys(1), DEVICE_GRANT_KIND, tags, now)))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A tampered body no longer matches its signature.
    let tampered = grant_event(&keys(1), &standard_grant(), now).replace(
        &format!("\"{}\"", 1024 * 1024),
        &format!("\"{}\"", 2 * 1024 * 1024),
    );
    let (status, _) = node.call(post_grant(tampered)).await;
    assert!(matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST
    ));
    assert_eq!(
        upload(&node, &keys(10), b"no grant").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn stale_future_long_lived_and_replayed_events_are_refused() {
    let (_dir, node) = node().await;
    let owner = keys(1);
    let now = node.now();
    let grant = standard_grant();

    // Expired: its NIP-40 expiration has passed.
    let mut tags = grant_tags(&grant, now - 1000);
    tags[4] = tag("until", now + 3600);
    let (status, _) = node
        .call(post_grant(signed(
            &owner,
            DEVICE_GRANT_KIND,
            tags,
            now - 1000,
        )))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // From the future.
    let (status, _) = node
        .call(post_grant(grant_event(&owner, &grant, now + 120)))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Event lifetime longer than ten minutes.
    let mut tags = grant_tags(&grant, now);
    tags[6] = tag("expiration", now + 3600);
    let (status, _) = node
        .call(post_grant(signed(&owner, DEVICE_GRANT_KIND, tags, now)))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Replayed body.
    let event = grant_event(&owner, &grant, now);
    assert_eq!(
        node.call(post_grant(event.clone())).await.0,
        StatusCode::CREATED
    );
    assert_eq!(node.call(post_grant(event)).await.0, StatusCode::CONFLICT);

    // An older, never-submitted grant cannot undo a later revocation.
    let older = grant_event(
        &owner,
        &Grant {
            bytes: 2 * MIB,
            ..standard_grant()
        },
        now - 5,
    );
    assert_eq!(
        node.call(revoke_request(&owner, &keys(10), now + 1))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(node.call(post_grant(older)).await.0, StatusCode::CONFLICT);
    // The same revoke event cannot be replayed either.
    assert_eq!(
        node.call(revoke_request(&owner, &keys(10), now + 1))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        upload(&node, &keys(10), b"still revoked").await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn malformed_grant_events_are_refused() {
    let (_dir, node) = node().await;
    let owner = keys(1);
    let now = node.now();
    let base = grant_tags(&standard_grant(), now);
    let mut cases: Vec<Vec<Vec<String>>> = Vec::new();
    let mut duplicate = base.clone();
    duplicate.push(tag("device", hex(&keys(12))));
    cases.push(duplicate);
    let mut unknown = base.clone();
    unknown.push(tag("class", "x"));
    cases.push(unknown);
    let mut same = base.clone();
    same[2] = tag("recovery", hex(&keys(10)));
    cases.push(same);
    let mut zero = base.clone();
    zero[3] = tag("bytes", "0");
    cases.push(zero);
    let mut padded = base.clone();
    padded[3] = tag("bytes", "01024");
    cases.push(padded);
    let mut past = base.clone();
    past[4] = tag("until", now - 1);
    cases.push(past);
    let mut far = base.clone();
    far[4] = tag("until", now + MAX_GRANT_SECONDS + 60);
    cases.push(far);
    let mut upper = base.clone();
    upper[1] = tag("device", hex(&keys(10)).to_uppercase());
    cases.push(upper);
    let mut missing = base.clone();
    missing.remove(2);
    cases.push(missing);
    for tags in cases {
        let (status, _) = node
            .call(post_grant(signed(
                &owner,
                DEVICE_GRANT_KIND,
                tags.clone(),
                now,
            )))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{tags:?}");
    }
    let (status, _) = node
        .call(post_grant(signed(&owner, 24_242, base, now)))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // An owner key cannot be delegated to itself.
    let (status, _) = node
        .call(post_grant(grant_event(
            &owner,
            &Grant {
                device: 1,
                ..standard_grant()
            },
            now,
        )))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn byte_ceiling_is_enforced_per_delegated_key() {
    let (_dir, node) = node().await;
    let grant = Grant {
        bytes: 16,
        ..standard_grant()
    };
    assert_eq!(
        node.call(post_grant(grant_event(&keys(1), &grant, node.now())))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &keys(10), b"0123456789").await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &keys(10), b"abcdefghij").await,
        StatusCode::INSUFFICIENT_STORAGE
    );
    assert_eq!(
        upload(&node, &keys(11), b"abcdefghij").await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn expiry_stops_new_writes_but_keeps_stored_claims_at_owner_retention() {
    let dir = tempfile::tempdir().unwrap();
    let offset = Arc::new(AtomicI64::new(0));
    let node = node_at(dir.path().join("data"), offset.clone()).await;
    let (owner, device) = (keys(1), keys(10));
    let grant = Grant {
        until_in: 100,
        ..standard_grant()
    };
    assert_eq!(
        node.call(post_grant(grant_event(&owner, &grant, node.now())))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &device, b"kept file").await,
        StatusCode::CREATED
    );

    node.advance(200);
    // The gate refuses before the sweep has run.
    assert_eq!(
        upload(&node, &device, b"late file").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        delete(&node, &device, &sha(b"kept file")).await,
        StatusCode::FORBIDDEN
    );
    let late = sha(b"late file");
    let preflight = Request::builder()
        .method(Method::HEAD)
        .uri("/upload")
        .header("x-sha-256", &late)
        .header("x-content-length", "9")
        .header("x-content-type", "application/octet-stream")
        .header(header::AUTHORIZATION, bud11(&device, "upload", Some(&late)))
        .body(Body::empty())
        .unwrap();
    assert_eq!(node.call(preflight).await.0, StatusCode::FORBIDDEN);
    let mirror = Request::builder()
        .method(Method::PUT)
        .uri("/mirror")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, bud11(&device, "upload", Some(&late)))
        .body(Body::from(
            json!({ "url": format!("https://source.example/{late}") }).to_string(),
        ))
        .unwrap();
    assert_eq!(node.call(mirror).await.0, StatusCode::FORBIDDEN);
    node.grants.sweep_ended().await.unwrap();
    assert_eq!(
        upload(&node, &device, b"late file").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(list(&node, &owner).await, vec![sha(b"kept file")]);
    let status_url = format!("{ORIGIN}grants/v1/{}", hex(&device));
    let request = Request::builder()
        .uri(format!("/grants/v1/{}", hex(&device)))
        .header(
            header::AUTHORIZATION,
            nip98(&device, &status_url, "GET", b"", node.now()),
        )
        .body(Body::empty())
        .unwrap();
    let (status, body) = node.call(request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "expired");

    // The owner-tier claim survives a restart and a full quota of new writes
    // never evicts it.
    drop(node);
    let node = node_at(dir.path().join("data"), offset).await;
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"kept file"))).await,
        StatusCode::OK
    );
    assert_eq!(list(&node, &owner).await, vec![sha(b"kept file")]);
    assert_eq!(
        upload(&node, &device, b"after restart").await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_node_down_across_expiry_keeps_claims_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let offset = Arc::new(AtomicI64::new(0));
    let node = node_at(dir.path().join("data"), offset.clone()).await;
    let grant = Grant {
        until_in: 100,
        ..standard_grant()
    };
    assert_eq!(
        node.call(post_grant(grant_event(&keys(1), &grant, node.now())))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &keys(10), b"offline expiry").await,
        StatusCode::CREATED
    );
    drop(node);
    offset.fetch_add(500, Ordering::SeqCst);
    let node = node_at(dir.path().join("data"), offset).await;
    assert_eq!(list(&node, &keys(1)).await, vec![sha(b"offline expiry")]);
    assert_eq!(
        upload(&node, &keys(10), b"refused").await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn regranting_a_recovery_identity_restores_its_key_list() {
    let (_dir, node) = node().await;
    let (owner, recovery) = (keys(1), keys(11));
    let now = node.now();
    assert_eq!(
        node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &recovery, b"encrypted key list").await,
        StatusCode::CREATED
    );
    assert_eq!(
        node.call(revoke_request(&owner, &keys(10), now + 1))
            .await
            .0,
        StatusCode::OK
    );
    node.sweep().await;
    assert!(list(&node, &recovery).await.is_empty());
    assert_eq!(list(&node, &owner).await, vec![sha(b"encrypted key list")]);

    // A new computer is approved with the same recovery identity.
    let replacement = Grant {
        device: 20,
        ..standard_grant()
    };
    assert_eq!(
        node.call(post_grant(grant_event(&owner, &replacement, now + 2)))
            .await
            .0,
        StatusCode::CREATED
    );
    node.sweep().await;
    assert_eq!(
        list(&node, &recovery).await,
        vec![sha(b"encrypted key list")]
    );
    // The owner claim the move created is dropped again, so the recovery
    // identity's delete really removes the blob.
    assert!(list(&node, &owner).await.is_empty());
    assert_eq!(
        delete(&node, &recovery, &sha(b"encrypted key list")).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"encrypted key list"))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn an_owner_deletion_while_holding_moved_claims_wins_over_a_regrant() {
    let (_dir, node) = node().await;
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    assert_eq!(
        upload(&node, &device, b"owner removes").await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&owner, &device, now + 1)).await;
    node.sweep().await;
    assert_eq!(
        delete(&node, &owner, &sha(b"owner removes")).await,
        StatusCode::OK
    );
    assert_eq!(
        node.call(post_grant(grant_event(&owner, &standard_grant(), now + 2)))
            .await
            .0,
        StatusCode::OK
    );
    node.sweep().await;
    assert!(list(&node, &device).await.is_empty());
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"owner removes"))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn key_role_conflicts_are_refused() {
    let (_dir, node) = node().await;
    let owner = keys(1);
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    // The first grant's recovery identity cannot become a device, and its
    // device cannot become someone's recovery identity.
    for grant in [
        Grant {
            device: 11,
            recovery: 30,
            ..standard_grant()
        },
        Grant {
            device: 31,
            recovery: 10,
            ..standard_grant()
        },
    ] {
        assert_eq!(
            node.call(post_grant(grant_event(&owner, &grant, now)))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
}

fn status_request(signer: &Keys, device: &Keys, created_at: u64) -> Request<Body> {
    let url = format!("{ORIGIN}grants/v1/{}", hex(device));
    Request::builder()
        .uri(format!("/grants/v1/{}", hex(device)))
        .header(
            header::AUTHORIZATION,
            nip98(signer, &url, "GET", b"", created_at),
        )
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn status_is_visible_only_to_the_device_its_recovery_identity_and_owners() {
    let (_dir, node) = node().await;
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    for signer in [keys(1), keys(10), keys(11)] {
        let (status, body) = node.call(status_request(&signer, &keys(10), now)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "active");
    }
    assert_eq!(
        node.call(status_request(&keys(2), &keys(10), now)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        node.call(status_request(&keys(10), &keys(10), now - 600))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

struct Relay {
    url: String,
    calls: Arc<AtomicU32>,
    seen: Arc<Mutex<Vec<(String, Value)>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

const OPERATOR_TOKEN_BYTES: [u8; 32] = [7; 32];

async fn relay(status: StatusCode) -> Relay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicU32::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (counter, recorded) = (calls.clone(), seen.clone());
    let app = Router::new().route(
        "/v1/creation-grants",
        post(
            move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let counter = counter.clone();
                let recorded = recorded.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let auth = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    recorded.lock().unwrap().push((auth, body.clone()));
                    let response = json!({
                        "id": "AAAAAAAAAAAAAAAAAAAAAA",
                        "token": URL_SAFE_NO_PAD.encode([9_u8; 32]),
                        "resource": body["resource"],
                        "expires": body["expires"],
                        "remaining": body["max_uses"],
                        "max_invitation_lifetime": body["max_invitation_lifetime"],
                    });
                    (status, Json(response))
                }
            },
        ),
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Relay {
        url,
        calls,
        seen,
        task,
    }
}

fn issuer_app(node: &Node, relay: &Relay) -> Router {
    let token = OperatorToken::parse(&URL_SAFE_NO_PAD.encode(OPERATOR_TOKEN_BYTES)).unwrap();
    Issuer::new(node.grants.clone(), &relay.url.parse().unwrap(), token)
        .unwrap()
        .router()
}

fn issue_request(signer: &Keys, created_at: u64, body: &[u8]) -> Request<Body> {
    let url = format!("{ORIGIN}pairing/v1/live-grants");
    Request::builder()
        .method(Method::POST)
        .uri("/pairing/v1/live-grants")
        .header(
            header::AUTHORIZATION,
            nip98(signer, &url, "POST", body, created_at),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}

async fn call(app: &Router, request: Request<Body>) -> (StatusCode, Value, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        text,
    )
}

#[tokio::test]
async fn issuer_returns_a_one_use_live_grant_to_a_granted_device() {
    let (_dir, node) = node().await;
    let relay = relay(StatusCode::CREATED).await;
    let app = issuer_app(&node, &relay);
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;

    let (status, body, text) = call(&app, issue_request(&keys(10), now, b"")).await;
    assert_eq!(status, StatusCode::CREATED, "{text}");
    assert_eq!(body["resource"], "live");
    assert_eq!(body["remaining"], 1);
    assert_eq!(body["max_invitation_lifetime"], 600);
    assert_eq!(body["token"], URL_SAFE_NO_PAD.encode([9_u8; 32]));
    assert!(body.get("id").is_none());
    let operator = URL_SAFE_NO_PAD.encode(OPERATOR_TOKEN_BYTES);
    assert!(!text.contains(&operator));
    let seen = relay.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, format!("Bearer {operator}"));
    let request = &seen[0].1;
    assert_eq!(request["resource"], "live");
    assert_eq!(request["max_uses"], 1);
    assert_eq!(request["max_invitation_lifetime"], 600);
    assert_eq!(request.as_object().unwrap().len(), 4);
}

#[tokio::test]
async fn issuer_refuses_unauthorised_requests_without_calling_the_relay() {
    let (_dir, node) = node().await;
    let relay = relay(StatusCode::CREATED).await;
    let app = issuer_app(&node, &relay);
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;

    // Unknown device, the recovery identity, the owner, a stale event, a
    // wrong URL and a non-empty body.
    assert_eq!(
        call(&app, issue_request(&keys(2), now, b"")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, issue_request(&keys(11), now, b"")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, issue_request(&keys(1), now, b"")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, issue_request(&keys(10), now - 600, b"")).await.0,
        StatusCode::UNAUTHORIZED
    );
    let wrong_url = Request::builder()
        .method(Method::POST)
        .uri("/pairing/v1/live-grants")
        .header(
            header::AUTHORIZATION,
            nip98(
                &keys(10),
                "https://other.example/pairing/v1/live-grants",
                "POST",
                b"",
                now,
            ),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, wrong_url).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        call(&app, issue_request(&keys(10), now, b"{}")).await.0,
        StatusCode::BAD_REQUEST
    );
    let missing = Request::builder()
        .method(Method::POST)
        .uri("/pairing/v1/live-grants")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, missing).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);

    // A replayed NIP-98 event is refused after one use.
    let created = now + 1;
    let first = issue_request(&keys(10), created, b"");
    let replay = issue_request(&keys(10), created, b"");
    assert_eq!(call(&app, first).await.0, StatusCode::CREATED);
    assert_eq!(call(&app, replay).await.0, StatusCode::CONFLICT);
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);

    // An expired or revoked device grant cannot obtain more grants.
    node.call(revoke_request(&keys(1), &keys(10), now + 2))
        .await;
    assert_eq!(
        call(&app, issue_request(&keys(10), now + 3, b"")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(relay.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn issuer_redacts_relay_failures() {
    let (_dir, node) = node().await;
    let relay = relay(StatusCode::UNAUTHORIZED).await;
    let app = issuer_app(&node, &relay);
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    let (status, _, text) = call(&app, issue_request(&keys(10), now, b"")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(!text.contains(&URL_SAFE_NO_PAD.encode([9_u8; 32])));
    assert!(!text.contains(&URL_SAFE_NO_PAD.encode(OPERATOR_TOKEN_BYTES)));
}

#[test]
fn operator_tokens_are_canonical_and_redacted() {
    let encoded = URL_SAFE_NO_PAD.encode(OPERATOR_TOKEN_BYTES);
    let token = OperatorToken::parse(&format!("{encoded}\n")).unwrap();
    assert!(!format!("{token:?}").contains(&encoded));
    assert!(OperatorToken::parse(&format!("{encoded}=")).is_err());
    assert!(OperatorToken::parse(&URL_SAFE_NO_PAD.encode([1_u8; 16])).is_err());
    assert!(OperatorToken::parse("not base64!").is_err());
    assert!(super::issuer::relay_api_url(&"http://relay.example/".parse().unwrap()).is_err());
    assert!(super::issuer::relay_api_url(&"https://relay.example/v1".parse().unwrap()).is_err());
    assert_eq!(
        super::issuer::relay_api_url(&"http://127.0.0.1:8787/".parse().unwrap())
            .unwrap()
            .as_str(),
        "http://127.0.0.1:8787/v1/creation-grants"
    );
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn tokens_and_authorisation_events_never_reach_the_logs() {
    // A process-wide subscriber: per-thread defaults race with other tests
    // over tracing's callsite interest cache.  Every concurrently running
    // test in this binary therefore also logs into the capture.
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let (_dir, node) = node().await;
    let relay = relay(StatusCode::CREATED).await;
    let app = issuer_app(&node, &relay);
    let now = node.now();
    let grant = grant_event(&keys(1), &standard_grant(), now);
    let grant_sig = serde_json::from_str::<Value>(&grant).unwrap()["sig"]
        .as_str()
        .unwrap()
        .to_owned();
    node.call(post_grant(grant)).await;
    let issue = issue_request(&keys(10), now, b"");
    let issue_header = issue
        .headers()
        .get(header::AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let (status, _, _) = call(&app, issue).await;
    assert_eq!(status, StatusCode::CREATED);
    let upload_header = bud11(&keys(10), "upload", Some(&sha(b"logged?")));
    upload(&node, &keys(10), b"logged?").await;
    let turn = turn_request(&keys(10), now, b"");
    let turn_header = turn
        .headers()
        .get(header::AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let (status, turn_body, _) = call(&turn_app(&node), turn).await;
    assert_eq!(status, StatusCode::CREATED);
    node.call(revoke_request(&keys(1), &keys(10), now + 1))
        .await;
    upload(&node, &keys(10), b"refused").await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("accepted an owner-signed device grant"),
        "{logs}"
    );
    assert!(
        logs.contains("issued a pair of ICE configurations"),
        "{logs}"
    );
    let mut secrets = vec![
        URL_SAFE_NO_PAD.encode(OPERATOR_TOKEN_BYTES),
        URL_SAFE_NO_PAD.encode([9_u8; 32]),
        grant_sig,
        issue_header.trim_start_matches("Nostr ").to_owned(),
        upload_header.trim_start_matches("Nostr ").to_owned(),
        TURN_SECRET.to_owned(),
        turn_header.trim_start_matches("Nostr ").to_owned(),
    ];
    for side in ["own", "peer"] {
        for member in ["credential", "username"] {
            secrets.push(turn_body[side][member].as_str().unwrap().to_owned());
        }
    }
    for secret in secrets {
        assert!(!logs.contains(&secret), "a secret value reached the logs");
    }
}

#[tokio::test]
async fn a_former_delegated_key_cannot_be_reconfigured_as_a_friend() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let node = node_at(root.clone(), Arc::new(AtomicI64::new(0))).await;
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    node.call(revoke_request(&keys(1), &keys(10), now + 1))
        .await;
    drop(node);
    let reopened = Grants::open(
        &root,
        GrantsConfig {
            owners: vec![hex(&keys(1))],
            server_names: vec![SERVER.into()],
            origin: ORIGIN.into(),
            reserved_keys: Vec::new(),
            cli_friend_grants: vec![wildbloom_core::FriendGrant {
                pubkey: hex(&keys(10)),
                byte_limit: MIB,
                expires_at: now + 3600,
                grant_id: "local".into(),
                issuer: None,
            }],
        },
        super::system_clock(),
    );
    assert!(matches!(reopened, Err(super::GrantsError::Conflict)));
}

#[tokio::test]
async fn delegated_core_grants_never_expire_in_the_core() {
    // The real expiry must stay in the shell: if the core grant carried it,
    // the core would reap the claims at the next store open after it passed.
    let dir = tempfile::tempdir().unwrap();
    let offset = Arc::new(AtomicI64::new(0));
    let node = node_at(dir.path().join("data"), offset.clone()).await;
    let grant = Grant {
        until_in: 2,
        ..standard_grant()
    };
    assert_eq!(
        node.call(post_grant(grant_event(&keys(1), &grant, node.now())))
            .await
            .0,
        StatusCode::CREATED
    );
    for core_grant in node.grants.core_friend_grants() {
        assert_eq!(core_grant.expires_at, super::CORE_GRANT_SENTINEL);
    }
    assert_eq!(
        upload(&node, &keys(10), b"outlives the real expiry").await,
        StatusCode::CREATED
    );
    drop(node);
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let node = node_at(dir.path().join("data"), offset).await;
    assert_eq!(
        list(&node, &keys(1)).await,
        vec![sha(b"outlives the real expiry")]
    );
}

#[tokio::test]
async fn issuer_budget_is_a_sliding_window_checked_before_replay() {
    let (_dir, node) = node().await;
    let relay = relay(StatusCode::CREATED).await;
    let app = issuer_app(&node, &relay);
    let long = Grant {
        until_in: 3 * 3600,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&keys(1), &long, node.now())))
        .await;
    let issue = |created_at: u64| issue_request(&keys(10), created_at, b"");
    let half = super::issuer::RATE_LIMIT as u64 / 2;
    // Half the budget at t0, the other half 3590 s later.
    let t0 = node.now();
    for age in 0..half {
        assert_eq!(call(&app, issue(t0 - age)).await.0, StatusCode::CREATED);
    }
    node.advance(3590);
    let t1 = node.now();
    for age in 0..half {
        assert_eq!(call(&app, issue(t1 - age)).await.0, StatusCode::CREATED);
    }
    // Over budget: refused, and its event id is not spent.
    let refused_at = t1 - 20;
    assert_eq!(
        call(&app, issue(refused_at)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Eleven seconds on, the t0 half has left the window but the refused
    // event is still fresh: it is accepted, proving it was not consumed.
    node.advance(11);
    let t2 = node.now();
    assert_eq!(call(&app, issue(refused_at)).await.0, StatusCode::CREATED);
    // A fixed window reset at t0 + 3600 would now allow a whole budget; a
    // sliding one still counts the t1 half and the accepted retry.
    for ahead in 1..half {
        assert_eq!(call(&app, issue(t2 + ahead)).await.0, StatusCode::CREATED);
    }
    assert_eq!(
        call(&app, issue(t2 + half)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        relay.calls.load(Ordering::SeqCst),
        3 * super::issuer::RATE_LIMIT / 2
    );
}

#[tokio::test]
async fn moved_claims_return_only_to_a_regrant_by_the_same_owner() {
    let dir = tempfile::tempdir().unwrap();
    let node = node_with(
        dir.path().join("data"),
        Arc::new(AtomicI64::new(0)),
        &[1, 2],
        Vec::new(),
    )
    .await;
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    assert_eq!(
        upload(&node, &keys(10), b"first owner's file").await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&keys(1), &keys(10), now + 1))
        .await;
    node.sweep().await;
    assert_eq!(
        node.call(post_grant(grant_event(
            &keys(2),
            &standard_grant(),
            now + 2
        )))
        .await
        .0,
        StatusCode::OK
    );
    node.sweep().await;
    assert!(list(&node, &keys(10)).await.is_empty());
    assert_eq!(
        list(&node, &keys(1)).await,
        vec![sha(b"first owner's file")]
    );
}

#[tokio::test]
async fn recovery_ceiling_follows_the_largest_active_grant() {
    let (_dir, node) = node().await;
    let now = node.now();
    let small = Grant {
        bytes: 16,
        ..standard_grant()
    };
    let large = Grant {
        device: 20,
        bytes: 64,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&keys(1), &small, now)))
        .await;
    node.call(post_grant(grant_event(&keys(1), &large, now)))
        .await;
    assert_eq!(node.grants.snapshot_members()[&hex(&keys(11))], 64);
    assert_eq!(
        upload(&node, &keys(11), &[7_u8; 40]).await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&keys(1), &keys(20), now + 1))
        .await;
    node.sweep().await;
    assert_eq!(node.grants.snapshot_members()[&hex(&keys(11))], 16);
    assert_eq!(
        upload(&node, &keys(11), b"over the smaller ceiling").await,
        StatusCode::INSUFFICIENT_STORAGE
    );
}

#[tokio::test]
async fn removing_the_issuing_owner_withdraws_its_device_grants() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let offset = Arc::new(AtomicI64::new(0));
    let node = node_with(root.clone(), offset.clone(), &[1, 2], Vec::new()).await;
    let now = node.now();
    node.call(post_grant(grant_event(&keys(2), &standard_grant(), now)))
        .await;
    assert_eq!(
        upload(&node, &keys(10), b"withdrawn owner's file").await,
        StatusCode::CREATED
    );
    drop(node);
    let node = node_with(root, offset, &[1], Vec::new()).await;
    let (status, body) = node
        .call(status_request(&keys(10), &keys(10), node.now()))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "withdrawn");
    assert_eq!(
        upload(&node, &keys(10), b"refused").await,
        StatusCode::FORBIDDEN
    );
    assert!(node.grants.snapshot_members().is_empty());
    // The bytes are still stored, now under the former owner like any of
    // that owner's other claims.
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"withdrawn owner's file"))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_regrant_never_deletes_an_owner_claim() {
    let (_dir, node) = node().await;
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    assert_eq!(
        upload(&node, &device, b"owner re-uploads").await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&owner, &device, now + 1)).await;
    node.sweep().await;
    // The owner deletes the moved copy, then uploads the same bytes itself.
    assert_eq!(
        delete(&node, &owner, &sha(b"owner re-uploads")).await,
        StatusCode::OK
    );
    assert_eq!(
        upload(&node, &owner, b"owner re-uploads").await,
        StatusCode::CREATED
    );
    node.call(post_grant(grant_event(&owner, &standard_grant(), now + 2)))
        .await;
    node.sweep().await;
    assert_eq!(list(&node, &device).await, vec![sha(b"owner re-uploads")]);
    assert_eq!(list(&node, &owner).await, vec![sha(b"owner re-uploads")]);
    assert_eq!(
        delete(&node, &device, &sha(b"owner re-uploads")).await,
        StatusCode::OK
    );
    assert_eq!(list(&node, &owner).await, vec![sha(b"owner re-uploads")]);
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"owner re-uploads"))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn startup_re_adopts_claims_an_older_binary_demoted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let offset = Arc::new(AtomicI64::new(0));
    let node = node_at(root.clone(), offset.clone()).await;
    node.call(post_grant(grant_event(
        &keys(1),
        &standard_grant(),
        node.now(),
    )))
    .await;
    assert_eq!(
        upload(&node, &keys(10), b"survives a rollback").await,
        StatusCode::CREATED
    );
    drop(node);
    {
        // A binary without device grants: its reconcile demotes the claim.
        let store = Store::open(StoreConfig {
            root: root.clone(),
            quota_bytes: 64 * MIB,
            max_blob_bytes: 8 * MIB,
        })
        .unwrap();
        let _old = AppState::new(
            store.clone(),
            BlossomConfig {
                server_metadata: ServerMetadata::default(),
                public_base_url: ORIGIN.parse().unwrap(),
                accepted_server_names: vec![SERVER.into()],
                allowed_pubkeys: vec![hex(&keys(1))],
                friend_grants: Vec::new(),
                open_shelter: false,
                max_concurrent_writes: 4,
                mirror_proxy: None,
            },
        )
        .unwrap();
        assert!(
            store
                .list_claims_for_grant(
                    &hex(&keys(10)),
                    &super::core_grant_id(&hex(&keys(10))),
                    None,
                    10
                )
                .unwrap()
                .is_empty()
        );
    }
    let node = node_at(root, offset).await;
    assert_eq!(
        list(&node, &keys(10)).await,
        vec![sha(b"survives a rollback")]
    );
    node.advance(7200);
    node.sweep().await;
    assert_eq!(
        list(&node, &keys(1)).await,
        vec![sha(b"survives a rollback")]
    );
}

#[tokio::test]
async fn restores_over_the_ceiling_are_retried_on_later_sweeps() {
    let (_dir, node) = node().await;
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    let files: [&[u8]; 2] = [b"first ten.", b"second ten"];
    for file in files {
        assert_eq!(upload(&node, &device, file).await, StatusCode::CREATED);
    }
    node.call(revoke_request(&owner, &device, now + 1)).await;
    node.sweep().await;
    let small = Grant {
        bytes: 16,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&owner, &small, now + 2)))
        .await;
    node.sweep().await;
    let first = list(&node, &device).await;
    assert_eq!(first.len(), 1);
    assert_eq!(delete(&node, &device, &first[0]).await, StatusCode::OK);
    node.sweep().await;
    let second = list(&node, &device).await;
    assert_eq!(second.len(), 1);
    assert_ne!(first, second);
}

#[tokio::test]
async fn paid_claims_of_a_delegated_key_are_not_moved_to_the_owner() {
    let (_dir, node) = node().await;
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    let store = node.state.store();
    store
        .reserve_paid_sale(&wildbloom_core::PaidSale {
            order_id: "order-1".into(),
            signer_pubkey: hex(&device),
            capacity_bytes: MIB,
            duration_seconds: 3600,
            grace_seconds: 0,
            hold_expires_at: real_now() + 600,
            renews: None,
        })
        .unwrap();
    store.activate_paid_sale("order-1").unwrap();
    assert_eq!(
        upload(&node, &device, b"paid for separately").await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&owner, &device, now + 1)).await;
    node.sweep().await;
    assert!(list(&node, &owner).await.is_empty());
    assert_eq!(
        list(&node, &device).await,
        vec![sha(b"paid for separately")]
    );
}

#[tokio::test]
async fn a_revocation_before_any_grant_blocks_older_grants() {
    let (_dir, node) = node().await;
    let now = node.now();
    let (status, body) = node
        .call(revoke_request(&keys(1), &keys(10), now + 5))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "revoked");
    assert_eq!(
        node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        node.call(post_grant(grant_event(
            &keys(1),
            &standard_grant(),
            now + 6
        )))
        .await
        .0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn service_keys_cannot_be_delegated_and_ended_keys_cannot_use_other_methods() {
    let (_dir, node) = node().await;
    let now = node.now();
    let service = Grant {
        device: 99,
        ..standard_grant()
    };
    assert_eq!(
        node.call(post_grant(grant_event(&keys(1), &service, now)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    node.call(revoke_request(&keys(1), &keys(10), now + 1))
        .await;
    let hash = sha(b"x");
    let request = Request::builder()
        .method(Method::PATCH)
        .uri("/upload")
        .header(
            header::AUTHORIZATION,
            bud11(&keys(10), "upload", Some(&hash)),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(node.call(request).await.0, StatusCode::FORBIDDEN);
}

fn held_upload(signer: &Keys, bytes: &[u8]) -> (Request<Body>, tokio::sync::mpsc::Sender<Bytes>) {
    let hash = sha(bytes);
    let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(4);
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|chunk| (Ok::<Bytes, std::io::Error>(chunk), receiver))
    });
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/upload")
        .header(header::CONTENT_LENGTH, bytes.len())
        .header("x-sha-256", &hash)
        .header(header::AUTHORIZATION, bud11(signer, "upload", Some(&hash)))
        .body(Body::from_stream(stream))
        .unwrap();
    (request, sender)
}

async fn wait_for_in_flight(node: &Node, key: &Keys, count: usize) {
    for _ in 0..200 {
        if node.grants.in_flight_count(&hex(key)) == count {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("in-flight count never reached {count}");
}

#[tokio::test]
async fn a_held_upload_neither_delays_revocation_nor_loses_its_claim() {
    let (_dir, node) = node().await;
    node.grants
        .set_in_flight_wait(std::time::Duration::from_secs(2));
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    // A second computer keeps the recovery identity active, so only the
    // revoked device leaves the core.  (Removing a key from the core waits
    // for every in-flight core write, including this held one.)
    let other = Grant {
        device: 20,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&owner, &other, now)))
        .await;
    let body = b"an upload held open across revocation".to_vec();
    let (request, sender) = held_upload(&device, &body);
    sender
        .send(Bytes::copy_from_slice(&body[..10]))
        .await
        .unwrap();
    let app = node.app.clone();
    let upload = tokio::spawn(async move { app.oneshot(request).await.unwrap().status() });
    wait_for_in_flight(&node, &device, 1).await;

    // Revocation is committed and answered without waiting for the upload.
    let (status, _) = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        node.call(revoke_request(&owner, &device, now + 1)),
    )
    .await
    .expect("revocation must reply without waiting for in-flight writes");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        upload_status(&node, &device, b"new write").await,
        StatusCode::FORBIDDEN
    );
    // The sweep waits, then skips the busy key rather than moving early.
    node.sweep().await;
    assert!(node.grants.snapshot_members().contains_key(&hex(&device)));

    sender
        .send(Bytes::copy_from_slice(&body[10..]))
        .await
        .unwrap();
    drop(sender);
    assert_eq!(upload.await.unwrap(), StatusCode::CREATED);
    wait_for_in_flight(&node, &device, 0).await;
    node.sweep().await;
    assert!(!node.grants.snapshot_members().contains_key(&hex(&device)));
    assert_eq!(list(&node, &owner).await, vec![sha(&body)]);
}

async fn upload_status(node: &Node, signer: &Keys, bytes: &[u8]) -> StatusCode {
    upload(node, signer, bytes).await
}

#[tokio::test]
async fn a_stalled_delegated_body_times_out() {
    let (_dir, node) = node().await;
    let device = keys(10);
    node.call(post_grant(grant_event(
        &keys(1),
        &standard_grant(),
        node.now(),
    )))
    .await;
    let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = polled.clone();
    let hash = sha(b"never arrives");
    let stream = futures_util::stream::unfold((), move |()| {
        flag.store(true, Ordering::SeqCst);
        std::future::pending::<Option<(Result<Bytes, std::io::Error>, ())>>()
    });
    let request = Request::builder()
        .method(Method::PUT)
        .uri("/upload")
        .header(header::CONTENT_LENGTH, 13)
        .header("x-sha-256", &hash)
        .header(header::AUTHORIZATION, bud11(&device, "upload", Some(&hash)))
        .body(Body::from_stream(stream))
        .unwrap();
    let app = node.app.clone();
    let upload = tokio::spawn(async move { app.oneshot(request).await.unwrap().status() });
    for _ in 0..200 {
        if polled.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        polled.load(Ordering::SeqCst),
        "the core never read the body"
    );
    tokio::time::pause();
    tokio::time::advance(super::WRITE_IDLE_TIMEOUT + std::time::Duration::from_secs(1)).await;
    tokio::time::resume();
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), upload)
        .await
        .expect("a stalled delegated body must time out")
        .unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    wait_for_in_flight(&node, &device, 0).await;
}

#[tokio::test]
async fn a_device_delete_after_a_lapse_removes_the_blob() {
    let (_dir, node) = node().await;
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    assert_eq!(
        upload(&node, &device, b"shared copy one").await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &device, b"shared copy two!").await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&owner, &device, now + 1)).await;
    node.sweep().await;
    // Re-granted with a ceiling that fits only one of them.
    let small = Grant {
        bytes: 15,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&owner, &small, now + 2)))
        .await;
    node.sweep().await;
    // Handed back: the owner claim the move made is gone, so stop sharing
    // really deletes the bytes.
    assert_eq!(list(&node, &device).await, vec![sha(b"shared copy one")]);
    assert_eq!(
        delete(&node, &device, &sha(b"shared copy one")).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"shared copy one"))).await,
        StatusCode::NOT_FOUND
    );
    // Not yet handed back (over the ceiling when last tried): the device's
    // delete still releases the owner claim the move created.
    let (status, body) = node
        .call(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/{}", sha(b"shared copy two!")))
                .header(
                    header::AUTHORIZATION,
                    bud11(&device, "delete", Some(&sha(b"shared copy two!"))),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"shared copy two!"))).await,
        StatusCode::NOT_FOUND
    );
    assert!(list(&node, &owner).await.is_empty());
}

#[tokio::test]
async fn owner_claims_held_before_the_move_are_never_dropped() {
    let (_dir, node) = node().await;
    let (owner, device) = (keys(1), keys(10));
    let now = node.now();
    assert_eq!(
        upload(&node, &owner, b"owner had it first").await,
        StatusCode::CREATED
    );
    node.call(post_grant(grant_event(&owner, &standard_grant(), now)))
        .await;
    assert_eq!(
        upload(&node, &device, b"owner had it first").await,
        StatusCode::OK
    );
    node.call(revoke_request(&owner, &device, now + 1)).await;
    node.sweep().await;
    node.call(post_grant(grant_event(&owner, &standard_grant(), now + 2)))
        .await;
    node.sweep().await;
    assert_eq!(list(&node, &device).await, vec![sha(b"owner had it first")]);
    assert_eq!(
        delete(&node, &device, &sha(b"owner had it first")).await,
        StatusCode::OK
    );
    assert_eq!(list(&node, &owner).await, vec![sha(b"owner had it first")]);
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"owner had it first"))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_preview_grant_database_is_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    std::fs::create_dir_all(&root).unwrap();
    {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(root.join(super::DATABASE_FILE)).unwrap();
    }
    let connection = rusqlite::Connection::open(root.join(super::DATABASE_FILE)).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE core_members (pubkey TEXT PRIMARY KEY NOT NULL, issuer TEXT NOT NULL,
                byte_limit INTEGER NOT NULL CHECK (byte_limit > 0));
             CREATE TABLE moved_claims (pubkey TEXT NOT NULL, hash TEXT NOT NULL,
                owner TEXT NOT NULL, size INTEGER NOT NULL, declared_type TEXT NOT NULL,
                class TEXT, independent INTEGER NOT NULL, PRIMARY KEY (pubkey, hash));
             INSERT INTO moved_claims VALUES ('a', 'b', 'c', 1, 'x', NULL, 0);
             PRAGMA user_version = 1;",
        )
        .unwrap();
    drop(connection);
    let node = node_at(root.clone(), Arc::new(AtomicI64::new(0))).await;
    // The migrated database records moves with the current layout.
    node.call(post_grant(grant_event(
        &keys(1),
        &standard_grant(),
        node.now(),
    )))
    .await;
    assert_eq!(
        upload(&node, &keys(10), b"after migration").await,
        StatusCode::CREATED
    );
    node.call(revoke_request(&keys(1), &keys(10), node.now() + 1))
        .await;
    node.sweep().await;
    assert_eq!(list(&node, &keys(1)).await, vec![sha(b"after migration")]);
    drop(node);
    let connection = rusqlite::Connection::open(root.join(super::DATABASE_FILE)).unwrap();
    connection
        .execute_batch("PRAGMA user_version = 3;")
        .unwrap();
    drop(connection);
    let reopened = Grants::open(
        &root,
        GrantsConfig {
            owners: vec![hex(&keys(1))],
            server_names: vec![SERVER.into()],
            origin: ORIGIN.into(),
            cli_friend_grants: Vec::new(),
            reserved_keys: Vec::new(),
        },
        super::system_clock(),
    );
    assert!(matches!(reopened, Err(super::GrantsError::Schema(3))));
}

#[tokio::test]
async fn re_adoption_leaves_guest_claims_from_before_the_grant() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let offset = Arc::new(AtomicI64::new(0));
    {
        // A guest mirror-style claim made by the key before it was granted.
        let store = Store::open(StoreConfig {
            root: root.clone(),
            quota_bytes: 64 * MIB,
            max_blob_bytes: 8 * MIB,
        })
        .unwrap();
        let owner_spec = wildbloom_core::ClaimSpec {
            signer_pubkey: hex(&keys(1)),
            retention_tier: wildbloom_core::RetentionTier::Owner,
            declared_type: "application/octet-stream".into(),
            grant_id: None,
            claim_expires_at: None,
            byte_limit: None,
            class: None,
        };
        let bytes = b"guest before grant";
        let hash = sha(bytes);
        if let wildbloom_core::store::UploadStart::Reserved(reservation) = store
            .begin_claimed_upload(&hash, bytes.len() as u64, owner_spec)
            .unwrap()
        {
            std::fs::write(reservation.temp_path(), bytes).unwrap();
            reservation.commit(&hash, bytes.len() as u64).unwrap();
        }
        let guest = wildbloom_core::ClaimSpec {
            signer_pubkey: hex(&keys(10)),
            retention_tier: wildbloom_core::RetentionTier::Guest,
            declared_type: "application/octet-stream".into(),
            grant_id: None,
            claim_expires_at: None,
            byte_limit: None,
            class: None,
        };
        store
            .begin_claimed_mirror(&hash, bytes.len() as u64, guest)
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let node = node_at(root.clone(), offset.clone()).await;
    node.call(post_grant(grant_event(
        &keys(1),
        &standard_grant(),
        node.now(),
    )))
    .await;
    drop(node);
    let node = node_at(root, offset).await;
    assert!(list(&node, &keys(10)).await.is_empty());
}

#[tokio::test]
async fn a_hand_back_keeps_an_owner_claim_another_keys_move_relies_on() {
    let (_dir, node) = node().await;
    let owner = keys(1);
    let now = node.now();
    // Two computers, each with its own recovery identity, hold the same blob.
    let (a, b) = (
        Grant {
            device: 10,
            recovery: 11,
            ..standard_grant()
        },
        Grant {
            device: 20,
            recovery: 21,
            ..standard_grant()
        },
    );
    node.call(post_grant(grant_event(&owner, &a, now))).await;
    node.call(post_grant(grant_event(&owner, &b, now))).await;
    let blob: &[u8] = b"held by two devices";
    for device in [10, 20] {
        let status = upload(&node, &keys(device), blob).await;
        assert!(status.is_success(), "{status}");
    }
    node.call(revoke_request(&owner, &keys(10), now + 1)).await;
    node.call(revoke_request(&owner, &keys(20), now + 1)).await;
    node.sweep().await;
    assert_eq!(list(&node, &owner).await, vec![sha(blob)]);
    // The key the sweep moved first is the one whose move created the owner
    // claim; hand that one back first.
    let (first, second) = if hex(&keys(10)) < hex(&keys(20)) {
        ((10, a), (20, b))
    } else {
        ((20, b), (10, a))
    };
    node.call(post_grant(grant_event(&owner, &first.1, now + 2)))
        .await;
    node.sweep().await;
    assert_eq!(list(&node, &keys(first.0)).await, vec![sha(blob)]);
    // The other key's move still relies on the owner claim.
    assert_eq!(list(&node, &owner).await, vec![sha(blob)]);
    assert_eq!(
        delete(&node, &keys(first.0), &sha(blob)).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&node, &format!("/{}", sha(blob))).await,
        StatusCode::OK
    );
    // Once the second key takes it back, the move-created owner claim goes
    // and that key's delete removes the bytes.
    node.call(post_grant(grant_event(&owner, &second.1, now + 2)))
        .await;
    node.sweep().await;
    assert!(list(&node, &owner).await.is_empty());
    assert_eq!(
        delete(&node, &keys(second.0), &sha(blob)).await,
        StatusCode::OK
    );
    assert_eq!(
        get_status(&node, &format!("/{}", sha(blob))).await,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn migrated_preview_members_join_at_the_migration_time() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE core_members (pubkey TEXT PRIMARY KEY NOT NULL, issuer TEXT NOT NULL,
                byte_limit INTEGER NOT NULL CHECK (byte_limit > 0));
             INSERT INTO core_members VALUES ('k', 'o', 10);
             PRAGMA user_version = 1;",
        )
        .unwrap();
    assert_eq!(
        super::db::initialise(&connection, 12_345).unwrap(),
        (2, false)
    );
    let rows = super::db::read_rows(&connection).unwrap();
    assert_eq!(rows.members["k"].since, 12_345);
}

const TURN_SECRET: &str = "synthetic-wildbloom-turn-secret-0001";
const TURN_URLS: [&str; 3] = [
    "stun:turn.example.net:3478",
    "turn:turn.example.net:3478?transport=udp",
    "turns:turn.example.net:5349?transport=tcp",
];

fn turn_app(node: &Node) -> Router {
    let urls = super::turn::ice_urls(&TURN_URLS.map(str::to_owned)).unwrap();
    TurnIssuer::new(
        node.grants.clone(),
        urls,
        Some(TurnSecret::parse(TURN_SECRET).unwrap()),
    )
    .router()
}

fn turn_request_signed(authorization: String, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/turn/v1/credentials")
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn turn_request(signer: &Keys, created_at: u64, body: &[u8]) -> Request<Body> {
    let url = format!("{ORIGIN}turn/v1/credentials");
    turn_request_signed(nip98(signer, &url, "POST", body, created_at), body)
}

/// The verified event id inside a NIP-98 `Authorization` header.
fn nip98_event_id(request: &Request<Body>) -> String {
    let header = request.headers()[header::AUTHORIZATION].to_str().unwrap();
    let event = STANDARD
        .decode(header.trim_start_matches("Nostr "))
        .unwrap();
    serde_json::from_slice::<Value>(&event).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Check one returned ICE entry and return its random label.
fn turn_label(entry: &Value, expires: u64) -> String {
    let object = entry.as_object().unwrap();
    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        ["credential", "urls", "username"]
    );
    assert_eq!(entry["urls"], json!(TURN_URLS));
    let username = entry["username"].as_str().unwrap();
    let (timestamp, label) = username.split_once(':').unwrap();
    assert_eq!(timestamp, expires.to_string());
    assert_eq!(URL_SAFE_NO_PAD.decode(label).unwrap().len(), 16);
    assert_eq!(label.len(), 22);
    let credential = entry["credential"].as_str().unwrap();
    assert_eq!(credential.len(), 28);
    assert_eq!(STANDARD.decode(credential).unwrap().len(), 20);
    assert_eq!(
        TurnSecret::parse(TURN_SECRET)
            .unwrap()
            .credential(username)
            .unwrap(),
        credential
    );
    for value in [username, credential] {
        assert!((1..=256).contains(&value.len()));
        assert!(!value.chars().any(char::is_control));
    }
    label.to_owned()
}

#[tokio::test]
async fn turn_issuer_returns_two_fresh_credentials_to_a_granted_device() {
    let (_dir, node) = node().await;
    let app = turn_app(&node);
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;

    let mut labels = Vec::new();
    for created_at in [now, now + 1] {
        let request = turn_request(&keys(10), created_at, b"");
        let event_id = nip98_event_id(&request);
        let before = node.now();
        let response = app.clone().oneshot(request).await.unwrap();
        let after = node.now();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        let body = serde_json::from_slice::<Value>(&bytes).unwrap();
        assert_eq!(
            body.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["expires", "own", "peer"]
        );
        let expires = body["expires"].as_u64().unwrap();
        assert!(
            (before + super::turn::CREDENTIAL_TTL..=after + super::turn::CREDENTIAL_TTL)
                .contains(&expires)
        );
        assert_eq!(super::turn::CREDENTIAL_TTL, 900);
        let own = turn_label(&body["own"], expires);
        let peer = turn_label(&body["peer"], expires);
        // Exactly these bytes: canonical member order and no other members.
        let entry = |side: &str| {
            format!(
                r#"{{"credential":"{}","urls":{},"username":"{}"}}"#,
                body[side]["credential"].as_str().unwrap(),
                serde_json::to_string(&TURN_URLS).unwrap(),
                body[side]["username"].as_str().unwrap(),
            )
        };
        assert_eq!(
            text,
            format!(
                r#"{{"expires":{expires},"own":{},"peer":{}}}"#,
                entry("own"),
                entry("peer")
            )
        );
        // Nothing in the response names the device, the request or the secret.
        for private in [hex(&keys(10)), event_id, TURN_SECRET.to_owned()] {
            assert!(!text.contains(&private));
        }
        labels.extend([own, peer]);
    }
    let distinct = labels.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), labels.len());
}

#[tokio::test]
async fn a_stun_only_issuer_needs_no_secret_and_hands_out_empty_credentials() {
    let (_dir, node) = node().await;
    let urls = vec!["stun:stun.example.net:3478".to_owned()];
    let urls = super::turn::ice_urls(&urls).unwrap();
    assert!(!super::turn::has_turn_url(&urls));
    let app = TurnIssuer::new(node.grants.clone(), urls, None).router();
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    let response = app
        .oneshot(turn_request(&keys(10), now, b""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let body = serde_json::from_slice::<Value>(&bytes).unwrap();
    let expires = body["expires"].as_u64().unwrap();
    let entry = r#"{"credential":"","urls":["stun:stun.example.net:3478"],"username":""}"#;
    assert_eq!(
        text,
        format!(r#"{{"expires":{expires},"own":{entry},"peer":{entry}}}"#)
    );
}

#[tokio::test]
async fn a_turn_issuer_without_its_secret_is_unavailable_rather_than_unsigned() {
    let (_dir, node) = node().await;
    let urls = super::turn::ice_urls(&TURN_URLS.map(str::to_owned)).unwrap();
    let app = TurnIssuer::new(node.grants.clone(), urls, None).router();
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    let response = app
        .oneshot(turn_request(&keys(10), now, b""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn turn_issuer_refuses_unauthorised_requests() {
    let (_dir, node) = node().await;
    let app = turn_app(&node);
    let now = node.now();
    node.call(post_grant(grant_event(&keys(1), &standard_grant(), now)))
        .await;
    let url = format!("{ORIGIN}turn/v1/credentials");

    // Unknown device, the recovery identity and the owner.
    for signer in [keys(2), keys(11), keys(1)] {
        assert_eq!(
            call(&app, turn_request(&signer, now, b"")).await.0,
            StatusCode::FORBIDDEN
        );
    }
    // A stale event, a wrong URL, method or payload, a body, a query and no
    // authorisation at all.
    assert_eq!(
        call(&app, turn_request(&keys(10), now - 61, b"")).await.0,
        StatusCode::UNAUTHORIZED
    );
    for (wrong_url, method, payload) in [
        (
            "https://other.example/turn/v1/credentials",
            "POST",
            &b""[..],
        ),
        (
            "https://node.example/pairing/v1/live-grants",
            "POST",
            &b""[..],
        ),
        (url.as_str(), "GET", &b""[..]),
        (url.as_str(), "POST", &b"x"[..]),
    ] {
        let request = turn_request_signed(nip98(&keys(10), wrong_url, method, payload, now), b"");
        assert_eq!(call(&app, request).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        call(&app, turn_request(&keys(10), now, b"{}")).await.0,
        StatusCode::BAD_REQUEST
    );
    let query = Request::builder()
        .method(Method::POST)
        .uri("/turn/v1/credentials?x=1")
        .header(
            header::AUTHORIZATION,
            nip98(&keys(10), &url, "POST", b"", now),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, query).await.0, StatusCode::BAD_REQUEST);
    let missing = Request::builder()
        .method(Method::POST)
        .uri("/turn/v1/credentials")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(&app, missing).await.0, StatusCode::UNAUTHORIZED);

    // A replayed NIP-98 event is refused after one use, with the response
    // redacted like the pairing issuer's.
    let first = turn_request(&keys(10), now + 1, b"");
    let replay = turn_request(&keys(10), now + 1, b"");
    assert_eq!(call(&app, first).await.0, StatusCode::CREATED);
    let (status, body, text) = call(&app, replay).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"error": "TURN credential request was already used"})
    );
    assert!(!text.contains(TURN_SECRET));

    // A revoked device grant obtains nothing more.
    node.call(revoke_request(&keys(1), &keys(10), now + 2))
        .await;
    assert_eq!(
        call(&app, turn_request(&keys(10), now + 3, b"")).await.0,
        StatusCode::FORBIDDEN
    );

    // Nor does an expired one.
    let brief = Grant {
        device: 20,
        recovery: 21,
        until_in: 5,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&keys(1), &brief, now)))
        .await;
    assert_eq!(
        call(&app, turn_request(&keys(20), now, b"")).await.0,
        StatusCode::CREATED
    );
    node.advance(10);
    assert_eq!(
        call(&app, turn_request(&keys(20), node.now(), b"")).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn turn_budget_is_its_own_and_a_refusal_spends_no_event_id() {
    let (_dir, node) = node().await;
    let relay = relay(StatusCode::CREATED).await;
    let pairing = issuer_app(&node, &relay);
    let app = turn_app(&node);
    let long = Grant {
        until_in: 3 * 3600,
        ..standard_grant()
    };
    node.call(post_grant(grant_event(&keys(1), &long, node.now())))
        .await;
    let t0 = node.now();
    let limit = u64::from(super::turn::RATE_LIMIT);
    assert_eq!(limit, 30);
    for age in 0..limit {
        assert_eq!(
            call(&app, turn_request(&keys(10), t0 - age, b"")).await.0,
            StatusCode::CREATED
        );
    }
    // Over budget: refused, and its event id is still unspent.
    let refused = turn_request(&keys(10), t0 - limit, b"");
    let refused_id = nip98_event_id(&refused);
    let (status, body, _) = call(&app, refused).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, json!({"error": "TURN credential budget is spent"}));
    assert!(
        node.grants.consume_event(&refused_id, t0 + 3600).unwrap(),
        "a refused request spent its event id"
    );
    // The pairing budget is separate and untouched.
    assert_eq!(
        call(&pairing, issue_request(&keys(10), t0, b"")).await.0,
        StatusCode::CREATED
    );
    // A second device has a budget of its own.
    let other = Grant {
        device: 20,
        recovery: 21,
        ..long
    };
    node.call(post_grant(grant_event(&keys(1), &other, t0)))
        .await;
    assert_eq!(
        call(&app, turn_request(&keys(20), t0, b"")).await.0,
        StatusCode::CREATED
    );
    // An hour later the budget has rolled over.
    node.advance(3600);
    assert_eq!(
        call(&app, turn_request(&keys(10), node.now(), b"")).await.0,
        StatusCode::CREATED
    );
}
