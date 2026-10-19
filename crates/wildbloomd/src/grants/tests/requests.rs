//! Request grant tests: issuing, upload enforcement, end-of-grant deletion and
//! the shared `vectors/wildbloom-request-v1.json`.  Synthetic keys, hashes and
//! domains only.
use super::*;
use crate::grants::requests::{MAX_OPEN_PER_DEVICE, RATE_LIMIT, has_database, parse_issue};
use serde::{Deserialize, Serialize};

const ISSUE_URL: &str = "https://node.example/request/v1/upload-grants";

/// A fresh request key, as Drop would make one.
fn request_key(n: u64) -> Keys {
    keys(1000 + n)
}

fn issue_body(key: &Keys, bytes: u64, until: u64) -> Vec<u8> {
    json!({ "pubkey": hex(key), "bytes": bytes, "until": until })
        .to_string()
        .into_bytes()
}

fn issue_with(signer: &Keys, body: &[u8], created_at: u64) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/request/v1/upload-grants")
        .header(
            header::AUTHORIZATION,
            nip98(signer, ISSUE_URL, "POST", body, created_at),
        )
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn end_with(signer: &Keys, key: &str, created_at: u64) -> Request<Body> {
    let url = format!("{ISSUE_URL}/{key}");
    Request::builder()
        .method(Method::DELETE)
        .uri(format!("/request/v1/upload-grants/{key}"))
        .header(
            header::AUTHORIZATION,
            nip98(signer, &url, "DELETE", b"", created_at),
        )
        .body(Body::empty())
        .unwrap()
}

async fn request_node_at(root: PathBuf, offset: Arc<AtomicI64>) -> Node {
    node_built(root, offset, &[1], Vec::new(), true).await
}

async fn request_node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let node = request_node_at(dir.path().join("data"), Arc::new(AtomicI64::new(0))).await;
    (dir, node)
}

async fn grant_device(node: &Node, grant: &Grant) {
    let (status, body) = node
        .call(post_grant(grant_event(&keys(1), grant, node.now())))
        .await;
    assert!(status.is_success(), "{body}");
}

/// Ask for a request grant for `key`, ending `until_in` seconds from now.
async fn issue(
    node: &Node,
    device: &Keys,
    key: &Keys,
    bytes: u64,
    until_in: u64,
) -> (StatusCode, Value) {
    let now = node.now();
    node.call(issue_with(
        device,
        &issue_body(key, bytes, now + until_in),
        now,
    ))
    .await
}

async fn end(node: &Node, device: &Keys, key: &Keys) -> (StatusCode, Value) {
    node.call(end_with(device, &hex(key), node.now())).await
}

fn error(body: &Value) -> &str {
    body["error"].as_str().unwrap_or_default()
}

fn preflight(signer: &Keys, bytes: &[u8]) -> Request<Body> {
    let hash = sha(bytes);
    Request::builder()
        .method(Method::HEAD)
        .uri("/upload")
        .header("x-sha-256", &hash)
        .header("x-content-length", bytes.len().to_string())
        .header("x-content-type", "application/octet-stream")
        .header(header::AUTHORIZATION, bud11(signer, "upload", Some(&hash)))
        .body(Body::empty())
        .unwrap()
}

fn mirror(signer: &Keys, bytes: &[u8]) -> Request<Body> {
    let hash = sha(bytes);
    Request::builder()
        .method(Method::PUT)
        .uri("/mirror")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, bud11(signer, "upload", Some(&hash)))
        .body(Body::from(
            json!({ "url": format!("https://source.example/{hash}") }).to_string(),
        ))
        .unwrap()
}

fn in_core(node: &Node, key: &Keys) -> bool {
    node.grants
        .core_friend_grants()
        .iter()
        .any(|grant| grant.pubkey == hex(key))
}

fn device_grant(bytes: u64) -> Grant {
    Grant {
        bytes,
        until_in: 3 * 3600,
        ..standard_grant()
    }
}

#[tokio::test]
async fn a_granted_device_issues_a_request_its_key_can_use_within_the_ceiling() {
    let (_dir, node) = request_node().await;
    let (device, key) = (keys(10), request_key(1));
    grant_device(&node, &device_grant(MIB)).await;
    let until = node.now() + 600;
    let (status, body) = node
        .call(issue_with(
            &device,
            &issue_body(&key, 65_536, until),
            node.now(),
        ))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        body,
        json!({ "pubkey": hex(&key), "bytes": 65_536, "until": until })
    );
    assert!(in_core(&node, &key));

    // Upload, preflight, dedup, list and delete its own claims.
    assert_eq!(
        upload(&node, &key, b"from the phone").await,
        StatusCode::CREATED
    );
    assert_eq!(upload(&node, &key, b"from the phone").await, StatusCode::OK);
    assert_eq!(node.call(preflight(&key, b"x")).await.0, StatusCode::OK);
    assert_eq!(list(&node, &key).await, vec![sha(b"from the phone")]);
    // Over the grant's ceiling: refused by the core.
    let large = vec![7_u8; 65_530];
    assert_eq!(
        upload(&node, &key, &large).await,
        StatusCode::INSUFFICIENT_STORAGE
    );
    // Mirroring is never allowed.
    let (status, body) = node.call(mirror(&key, b"elsewhere")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error(&body), "upload_only");
    // A key nobody granted is refused by the core.
    assert_eq!(
        upload(&node, &request_key(99), b"stranger").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        delete(&node, &key, &sha(b"from the phone")).await,
        StatusCode::OK
    );
    assert!(list(&node, &key).await.is_empty());
    // The device's own grant is untouched by the request.
    assert_eq!(
        upload(&node, &device, b"device file").await,
        StatusCode::CREATED
    );
    // The grant status route does not treat a request key as a device.
    assert_eq!(
        node.call(status_request(&key, &device, node.now())).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn only_an_active_device_may_issue_and_every_nip98_rule_holds() {
    let (_dir, node) = request_node().await;
    let device = keys(10);
    grant_device(&node, &device_grant(MIB)).await;
    let now = node.now();
    assert_eq!(
        issue(&node, &device, &request_key(1), 1000, 600).await.0,
        StatusCode::CREATED
    );

    // The owner, the recovery identity, an unknown key and a request key.
    for caller in [keys(1), keys(11), keys(2), request_key(1)] {
        let (status, body) = issue(&node, &caller, &request_key(2), 1000, 600).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(error(&body), "not_a_device");
    }
    let body = issue_body(&request_key(2), 1000, now + 600);
    // Stale, wrong URL, wrong method tag, payload over another body, missing.
    let stale = issue_with(&device, &body, now - 600);
    let wrong_url = Request::builder()
        .method(Method::POST)
        .uri("/request/v1/upload-grants")
        .header(
            header::AUTHORIZATION,
            nip98(
                &device,
                "https://other.example/request/v1/upload-grants",
                "POST",
                &body,
                now,
            ),
        )
        .body(Body::from(body.clone()))
        .unwrap();
    let wrong_method = Request::builder()
        .method(Method::POST)
        .uri("/request/v1/upload-grants")
        .header(
            header::AUTHORIZATION,
            nip98(&device, ISSUE_URL, "GET", b"", now),
        )
        .body(Body::from(body.clone()))
        .unwrap();
    let other_body = Request::builder()
        .method(Method::POST)
        .uri("/request/v1/upload-grants")
        .header(
            header::AUTHORIZATION,
            nip98(&device, ISSUE_URL, "POST", b"{}", now),
        )
        .body(Body::from(body.clone()))
        .unwrap();
    let missing = Request::builder()
        .method(Method::POST)
        .uri("/request/v1/upload-grants")
        .body(Body::from(body.clone()))
        .unwrap();
    for request in [stale, wrong_url, wrong_method, other_body, missing] {
        let (status, body) = node.call(request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(error(&body), "unauthorised");
    }
    let query = Request::builder()
        .method(Method::POST)
        .uri("/request/v1/upload-grants?x=1")
        .header(
            header::AUTHORIZATION,
            nip98(&device, ISSUE_URL, "POST", &body, now),
        )
        .body(Body::from(body.clone()))
        .unwrap();
    assert_eq!(node.call(query).await.0, StatusCode::BAD_REQUEST);
    let oversized = vec![b' '; 2048];
    let (status, body) = node.call(issue_with(&device, &oversized, now)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&body), "body_too_large");

    // A replay is single use: the key it names is now taken.
    let body = issue_body(&request_key(3), 1000, now + 600);
    assert_eq!(
        node.call(issue_with(&device, &body, now)).await.0,
        StatusCode::CREATED
    );
    let (status, reply) = node.call(issue_with(&device, &body, now)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error(&reply), "key_in_use");

    // A revoked device cannot issue.
    node.call(revoke_request(&keys(1), &device, now + 1)).await;
    let (status, body) = issue(&node, &device, &request_key(4), 1000, 600).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error(&body), "not_a_device");
}

#[tokio::test]
async fn a_device_holds_at_most_three_open_requests_and_ten_an_hour() {
    let (_dir, node) = request_node().await;
    let device = keys(10);
    grant_device(&node, &device_grant(8 * MIB)).await;
    for n in 1..=MAX_OPEN_PER_DEVICE as u64 {
        assert_eq!(
            issue(&node, &device, &request_key(n), 1000, 600).await.0,
            StatusCode::CREATED
        );
    }
    let (status, body) = issue(&node, &device, &request_key(4), 1000, 600).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error(&body), "too_many_open");
    // Ending one frees an open slot; the refusal above recorded nothing.
    assert_eq!(end(&node, &device, &request_key(1)).await.0, StatusCode::OK);
    assert_eq!(
        issue(&node, &device, &request_key(4), 1000, 600).await.0,
        StatusCode::CREATED
    );
    // Keep ending to stay under the open limit until ten were issued.
    let mut issued = MAX_OPEN_PER_DEVICE + 1;
    let mut key = 4;
    while issued < RATE_LIMIT {
        assert_eq!(
            end(&node, &device, &request_key(key - 2)).await.0,
            StatusCode::OK
        );
        key += 1;
        assert_eq!(
            issue(&node, &device, &request_key(key), 1000, 600).await.0,
            StatusCode::CREATED
        );
        issued += 1;
    }
    assert_eq!(
        end(&node, &device, &request_key(key - 2)).await.0,
        StatusCode::OK
    );
    let (status, body) = issue(&node, &device, &request_key(50), 1000, 600).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error(&body), "too_many_requests");
    // The window slides: an hour on, the device may ask again.
    node.advance(3600);
    assert_eq!(
        issue(&node, &device, &request_key(50), 1000, 600).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn a_request_needs_room_in_the_device_ceiling_and_a_refusal_spends_nothing() {
    let (_dir, node) = request_node().await;
    let device = keys(10);
    grant_device(&node, &device_grant(200_000)).await;
    let mine = vec![1_u8; 150_000];
    assert_eq!(upload(&node, &device, &mine).await, StatusCode::CREATED);
    let now = node.now();
    let body = issue_body(&request_key(1), 100_000, now + 600);
    let (status, reply) = node.call(issue_with(&device, &body, now)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(reply, json!({ "error": "no_room" }));
    // Freeing the device's space lets the identical signed request through,
    // so the refusal did not spend its event id.
    assert_eq!(delete(&node, &device, &sha(&mine)).await, StatusCode::OK);
    assert_eq!(
        node.call(issue_with(&device, &body, now)).await.0,
        StatusCode::CREATED
    );
    // An open request's bytes count against the device until it ends.
    let (status, reply) = issue(&node, &device, &request_key(2), 150_000, 600).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error(&reply), "no_room");
    assert_eq!(end(&node, &device, &request_key(1)).await.0, StatusCode::OK);
    assert_eq!(
        issue(&node, &device, &request_key(2), 150_000, 600).await.0,
        StatusCode::CREATED
    );

    // Larger than the node accepts for one blob: no room either.
    let big = Grant {
        device: 20,
        recovery: 21,
        bytes: 32 * MIB,
        until_in: 3600,
    };
    grant_device(&node, &big).await;
    let (status, reply) = issue(&node, &keys(20), &request_key(3), 8 * MIB + 1, 600).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error(&reply), "no_room");
    assert_eq!(
        issue(&node, &keys(20), &request_key(3), 8 * MIB, 600)
            .await
            .0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn a_request_key_must_never_have_been_seen() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let offset = Arc::new(AtomicI64::new(0));
    // A former friend whose claims were demoted to guest when its grant left
    // the configuration: unknown to the grant records, but it holds claims.
    let former = keys(60);
    let friend = wildbloom_core::FriendGrant {
        pubkey: hex(&former),
        byte_limit: MIB,
        expires_at: real_now() + 3600,
        grant_id: "local".into(),
        issuer: None,
    };
    let node = node_built(root.clone(), offset.clone(), &[1], vec![friend], false).await;
    assert_eq!(
        upload(&node, &former, b"old friend file").await,
        StatusCode::CREATED
    );
    drop(node);
    let node = request_node_at(root, offset).await;
    let device = keys(10);
    grant_device(&node, &device_grant(MIB)).await;
    grant_device(
        &node,
        &Grant {
            device: 20,
            recovery: 21,
            ..device_grant(MIB)
        },
    )
    .await;
    assert_eq!(
        issue(&node, &device, &request_key(1), 1000, 600).await.0,
        StatusCode::CREATED
    );
    // Owner, itself, its recovery identity, another device and recovery
    // identity, the service key, an existing request key, a claim holder.
    for taken in [
        keys(1),
        keys(10),
        keys(11),
        keys(20),
        keys(21),
        keys(99),
        request_key(1),
        former,
    ] {
        let (status, body) = issue(&node, &device, &taken, 1000, 600).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(error(&body), "key_in_use");
    }
    // Nor can a recorded request key become a device or recovery identity.
    for grant in [
        Grant {
            device: 1001,
            recovery: 30,
            ..standard_grant()
        },
        Grant {
            device: 31,
            recovery: 1001,
            ..standard_grant()
        },
    ] {
        let (status, _) = node
            .call(post_grant(grant_event(&keys(1), &grant, node.now())))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
}

#[tokio::test]
async fn an_expired_request_is_refused_at_once_and_its_claims_are_deleted() {
    let (_dir, node) = request_node().await;
    let (owner, device, key) = (keys(1), keys(10), request_key(1));
    grant_device(&node, &device_grant(MIB)).await;
    assert_eq!(
        issue(&node, &device, &key, 65_536, 100).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &key, b"only the request").await,
        StatusCode::CREATED
    );
    // The owner already holds this blob; the request key gets its own claim.
    assert_eq!(
        upload(&node, &owner, b"shared bytes").await,
        StatusCode::CREATED
    );
    assert_eq!(upload(&node, &key, b"shared bytes").await, StatusCode::OK);

    node.advance(200);
    // The gate refuses before any sweep.
    for request in [
        Request::builder()
            .method(Method::PUT)
            .uri("/upload")
            .header(header::CONTENT_LENGTH, 4)
            .header("x-sha-256", sha(b"late"))
            .header(
                header::AUTHORIZATION,
                bud11(&key, "upload", Some(&sha(b"late"))),
            )
            .body(Body::from(&b"late"[..]))
            .unwrap(),
        preflight(&key, b"late"),
        mirror(&key, b"late"),
    ] {
        let head = request.method() == Method::HEAD;
        let (status, body) = node.call(request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // A HEAD response has no body to carry the code.
        if !head {
            assert_eq!(error(&body), "request_ended");
        }
    }
    assert_eq!(
        delete(&node, &key, &sha(b"only the request")).await,
        StatusCode::FORBIDDEN
    );
    // Reads still pass until the sweep deletes the bytes.
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"only the request"))).await,
        StatusCode::OK
    );
    node.sweep().await;
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"only the request"))).await,
        StatusCode::NOT_FOUND
    );
    // Another key's claim on the same blob is kept; nothing moved to the owner.
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"shared bytes"))).await,
        StatusCode::OK
    );
    assert_eq!(list(&node, &owner).await, vec![sha(b"shared bytes")]);
    assert!(list(&node, &key).await.is_empty());
    assert!(!in_core(&node, &key));
    // Its device can still end it; the end is idempotent.
    let (status, body) = end(&node, &device, &key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "pubkey": hex(&key), "state": "ended" }));
}

#[tokio::test]
async fn the_device_ends_its_request_and_only_its_own() {
    let (_dir, node) = request_node().await;
    let (device, key) = (keys(10), request_key(1));
    grant_device(&node, &device_grant(MIB)).await;
    grant_device(
        &node,
        &Grant {
            device: 20,
            recovery: 21,
            ..device_grant(MIB)
        },
    )
    .await;
    assert_eq!(
        issue(&node, &device, &key, 65_536, 3600).await.0,
        StatusCode::CREATED
    );
    assert_eq!(upload(&node, &key, b"arrived").await, StatusCode::CREATED);

    let (status, body) = end(&node, &keys(20), &key).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error(&body), "not_yours");
    let (status, body) = end(&node, &device, &request_key(9)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error(&body), "unknown_request");
    let (status, _) = node.call(end_with(&device, "not-a-key", node.now())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let now = node.now();
    let (status, body) = node.call(end_with(&device, &hex(&key), now)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "pubkey": hex(&key), "state": "ended" }));
    let (status, body) = node.call(end_with(&device, &hex(&key), now)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error(&body), "replayed");
    let (status, body) = node.call(mirror(&key, b"x")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error(&body), "request_ended");
    assert_eq!(
        upload(&node, &key, b"too late").await,
        StatusCode::FORBIDDEN
    );
    node.sweep().await;
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"arrived"))).await,
        StatusCode::NOT_FOUND
    );
    assert!(!in_core(&node, &key));
}

#[tokio::test]
async fn revoking_the_device_ends_its_requests_for_good() {
    let (_dir, node) = request_node().await;
    let (owner, device, key) = (keys(1), keys(10), request_key(1));
    let grant = device_grant(MIB);
    grant_device(&node, &grant).await;
    assert_eq!(
        issue(&node, &device, &key, 65_536, 3600).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &key, b"before revoke").await,
        StatusCode::CREATED
    );
    let now = node.now();
    assert_eq!(
        node.call(revoke_request(&owner, &device, now + 1)).await.0,
        StatusCode::OK
    );
    assert_eq!(
        upload(&node, &key, b"after revoke").await,
        StatusCode::FORBIDDEN
    );
    // Approving the same computer again does not bring the request back.
    assert!(
        node.call(post_grant(grant_event(&owner, &grant, now + 2)))
            .await
            .0
            .is_success()
    );
    assert_eq!(
        upload(&node, &key, b"after regrant").await,
        StatusCode::FORBIDDEN
    );
    node.sweep().await;
    assert_eq!(
        get_status(&node, &format!("/{}", sha(b"before revoke"))).await,
        StatusCode::NOT_FOUND
    );
    assert!(!in_core(&node, &key));
}

#[tokio::test]
async fn a_cut_off_upload_leaves_nothing_and_the_sweep_waits_for_a_held_one() {
    let (_dir, node) = request_node().await;
    node.grants
        .set_in_flight_wait(std::time::Duration::from_millis(200));
    let (device, key) = (keys(10), request_key(1));
    grant_device(&node, &device_grant(MIB)).await;
    assert_eq!(
        issue(&node, &device, &key, 65_536, 3600).await.0,
        StatusCode::CREATED
    );

    // Half the body, then the connection goes: no claim, no bytes.
    let body = b"a file the network dropped halfway".to_vec();
    let (request, sender) = held_upload(&key, &body);
    sender
        .send(Bytes::copy_from_slice(&body[..10]))
        .await
        .unwrap();
    let app = node.app.clone();
    let upload = tokio::spawn(async move { app.oneshot(request).await.unwrap().status() });
    wait_for_in_flight(&node, &key, 1).await;
    drop(sender);
    let status = upload.await.unwrap();
    assert!(!status.is_success(), "{status}");
    wait_for_in_flight(&node, &key, 0).await;
    assert!(list(&node, &key).await.is_empty());
    assert_eq!(
        get_status(&node, &format!("/{}", sha(&body))).await,
        StatusCode::NOT_FOUND
    );

    // An upload admitted while active and still arriving when the grant
    // ends: the sweep skips the busy key, then deletes what it wrote.
    let body = b"held open across the end".to_vec();
    let (request, sender) = held_upload(&key, &body);
    sender
        .send(Bytes::copy_from_slice(&body[..5]))
        .await
        .unwrap();
    let app = node.app.clone();
    let upload = tokio::spawn(async move { app.oneshot(request).await.unwrap().status() });
    wait_for_in_flight(&node, &key, 1).await;
    assert_eq!(end(&node, &device, &key).await.0, StatusCode::OK);
    node.sweep().await;
    assert!(in_core(&node, &key));
    sender
        .send(Bytes::copy_from_slice(&body[5..]))
        .await
        .unwrap();
    drop(sender);
    assert_eq!(upload.await.unwrap(), StatusCode::CREATED);
    node.sweep().await;
    assert!(!in_core(&node, &key));
    assert_eq!(
        get_status(&node, &format!("/{}", sha(&body))).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_request_outlives_a_restart_and_still_ends_on_time() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let offset = Arc::new(AtomicI64::new(0));
    let node = request_node_at(root.clone(), offset.clone()).await;
    let (device, key) = (keys(10), request_key(1));
    grant_device(&node, &device_grant(MIB)).await;
    assert_eq!(
        issue(&node, &device, &key, 65_536, 300).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        upload(&node, &key, b"before restart").await,
        StatusCode::CREATED
    );
    drop(node);

    let node = request_node_at(root.clone(), offset.clone()).await;
    assert_eq!(
        upload(&node, &key, b"after restart").await,
        StatusCode::CREATED
    );
    assert_eq!(list(&node, &key).await.len(), 2);
    drop(node);

    // Down across the end, and back with the routes turned off: the records
    // still drive the gate and the start-up sweep deletes the claims.
    offset.fetch_add(400, Ordering::SeqCst);
    let node = node_at(root.clone(), offset).await;
    assert!(has_database(&root));
    for bytes in [&b"before restart"[..], b"after restart"] {
        assert_eq!(
            get_status(&node, &format!("/{}", sha(bytes))).await,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(upload(&node, &key, b"refused").await, StatusCode::FORBIDDEN);
    let (status, _) = issue(&node, &device, &request_key(2), 1000, 600).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn start_up_refuses_a_recorded_request_key_in_another_role() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let node = request_node_at(root.clone(), Arc::new(AtomicI64::new(0))).await;
    grant_device(&node, &device_grant(MIB)).await;
    assert_eq!(
        issue(&node, &keys(10), &request_key(1), 1000, 600).await.0,
        StatusCode::CREATED
    );
    drop(node);
    for (owners, friends) in [
        (vec![hex(&keys(1)), hex(&request_key(1))], Vec::new()),
        (
            vec![hex(&keys(1))],
            vec![wildbloom_core::FriendGrant {
                pubkey: hex(&request_key(1)),
                byte_limit: MIB,
                expires_at: real_now() + 3600,
                grant_id: "local".into(),
                issuer: None,
            }],
        ),
    ] {
        let grants = Grants::open(
            &root,
            GrantsConfig {
                owners,
                server_names: vec![SERVER.into()],
                origin: ORIGIN.into(),
                cli_friend_grants: friends,
                reserved_keys: Vec::new(),
            },
            super::super::system_clock(),
        )
        .unwrap();
        assert!(matches!(
            grants.open_requests(&root),
            Err(super::super::GrantsError::RequestConflict)
        ));
    }
}

#[tokio::test]
async fn without_the_flag_the_routes_answer_404_and_nothing_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("data");
    let node = node_at(root.clone(), Arc::new(AtomicI64::new(0))).await;
    grant_device(&node, &device_grant(MIB)).await;
    let (status, _) = issue(&node, &keys(10), &request_key(1), 1000, 600).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = end(&node, &keys(10), &request_key(1)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!has_database(&root));
}

#[tokio::test]
async fn the_pairing_issuer_refuses_a_request_key() {
    let (_dir, node) = request_node().await;
    let relay = relay(StatusCode::CREATED).await;
    let app = issuer_app(&node, &relay);
    grant_device(&node, &device_grant(MIB)).await;
    let key = request_key(1);
    assert_eq!(
        issue(&node, &keys(10), &key, 1000, 600).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&app, issue_request(&key, node.now(), b"")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(relay.calls.load(Ordering::SeqCst), 0);
    // A request key cannot ask for another request grant either.
    let (status, body) = issue(&node, &key, &request_key(2), 1000, 600).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(error(&body), "not_a_device");
}

fn put_upload(signer: &Keys, bytes: &[u8]) -> Request<Body> {
    let hash = sha(bytes);
    Request::builder()
        .method(Method::PUT)
        .uri("/upload")
        .header(header::CONTENT_LENGTH, bytes.len())
        .header("x-sha-256", &hash)
        .header(header::AUTHORIZATION, bud11(signer, "upload", Some(&hash)))
        .body(Body::from(bytes.to_vec()))
        .unwrap()
}

/// Send as a browser on the `/send` page would, with an `Origin`.
async fn from_page(node: &Node, mut request: Request<Body>) -> axum::response::Response {
    request.headers_mut().insert(
        header::ORIGIN,
        header::HeaderValue::from_static("https://send.example"),
    );
    node.app.clone().oneshot(request).await.unwrap()
}

fn header_value(response: &axum::response::Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The CORS headers of an actual (non-preflight) response.
fn cors_of(response: &axum::response::Response) -> (Option<String>, Option<String>, Vec<String>) {
    (
        header_value(response, header::ACCESS_CONTROL_ALLOW_ORIGIN),
        header_value(response, header::ACCESS_CONTROL_EXPOSE_HEADERS),
        response
            .headers()
            .get_all(header::VARY)
            .iter()
            .filter_map(|value| value.to_str().ok().map(str::to_owned))
            .collect(),
    )
}

#[tokio::test]
async fn gate_refusals_carry_the_core_cors_headers_and_preflight_is_unchanged() {
    let (_dir, node) = request_node().await;
    grant_device(&node, &device_grant(MIB)).await;
    let short = Grant {
        device: 20,
        recovery: 21,
        bytes: MIB,
        until_in: 100,
    };
    grant_device(&node, &short).await;
    let key = request_key(1);
    assert_eq!(
        issue(&node, &keys(10), &key, 65_536, 100).await.0,
        StatusCode::CREATED
    );

    // A refusal the core makes itself, for comparison.
    let core = from_page(&node, put_upload(&request_key(99), b"stranger")).await;
    assert_eq!(core.status(), StatusCode::UNAUTHORIZED);
    let expected = cors_of(&core);
    assert_eq!(expected.0.as_deref(), Some("*"));
    assert!(
        expected
            .1
            .as_deref()
            .is_some_and(|names| names.split(',').any(|name| name == "x-reason"))
    );

    let check = |response: axum::response::Response, reason: &str| {
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{reason}");
        assert_eq!(cors_of(&response), expected, "{reason}");
        assert_eq!(
            header_value(&response, header::HeaderName::from_static("x-reason")).as_deref(),
            Some(reason)
        );
    };
    check(
        from_page(&node, mirror(&key, b"elsewhere")).await,
        "upload_only",
    );
    node.advance(200);
    check(
        from_page(&node, put_upload(&key, b"late")).await,
        "request_ended",
    );
    // A refused preflight has no body: the browser reads the code from X-Reason.
    check(
        from_page(&node, preflight(&key, b"late")).await,
        "request_ended",
    );
    // The delegated-key refusal is answered by the gate too.
    check(
        from_page(&node, put_upload(&keys(20), b"late device file")).await,
        "the delegated storage grant has ended",
    );

    // CORS preflight is a read: it passes the gate and the core answers it.
    let options = Request::builder()
        .method(Method::OPTIONS)
        .uri("/upload")
        .header(header::ORIGIN, "https://send.example")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization,content-type,x-sha-256",
        )
        .body(Body::empty())
        .unwrap();
    let response = node.app.clone().oneshot(options).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_value(&response, header::ACCESS_CONTROL_ALLOW_ORIGIN).as_deref(),
        Some("*")
    );
    let methods = header_value(&response, header::ACCESS_CONTROL_ALLOW_METHODS).unwrap();
    assert!(
        methods.split(',').any(|method| method == "PUT"),
        "{methods}"
    );
    let headers = header_value(&response, header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap();
    for name in ["authorization", "content-type", "x-sha-256"] {
        assert!(
            headers.split(',').any(|allowed| allowed == name),
            "{headers}"
        );
    }
}

// Shared vectors.

#[derive(Deserialize)]
struct Vectors {
    now: u64,
    invitation: Section<InvitationValid, InvitationInvalid>,
    reply: Section<ReplyValid, ReplyInvalid>,
    #[serde(rename = "uploadGrant")]
    upload_grant: Section<GrantValid, GrantInvalid>,
}

#[derive(Deserialize)]
struct Section<V, I> {
    valid: Vec<V>,
    invalid: Vec<I>,
}

#[derive(Deserialize)]
struct InvitationValid {
    name: String,
    invitation: String,
    pubkey: String,
    #[serde(rename = "serverTag")]
    server_tag: String,
}

#[derive(Deserialize)]
struct InvitationInvalid {
    name: String,
    reason: String,
    invitation: String,
}

#[derive(Deserialize)]
struct ReplyValid {
    name: String,
    reply: String,
    sha256: String,
    size: u64,
}

#[derive(Deserialize)]
struct ReplyInvalid {
    name: String,
    reply: String,
}

#[derive(Deserialize)]
struct GrantValid {
    name: String,
    body: String,
}

#[derive(Deserialize)]
struct GrantInvalid {
    name: String,
    status: u16,
    error: String,
    body: String,
}

fn vectors() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/wildbloom-request-v1.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The invitation, in its canonical key order.  The node never reads one;
/// this is the executable form of the PROTOCOL.md rules that Drop's
/// `RequestDescriptor` and the `/send` page's parser must both match.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    v: String,
    node: String,
    signer: String,
    key: String,
    size: u64,
    bytes: u64,
    files: u64,
    until: u64,
}

fn check_node(text: &str) -> Option<String> {
    let url = url::Url::parse(text).ok()?;
    let host = url.host()?;
    let loopback = match &host {
        url::Host::Domain(name) => *name == "localhost",
        url::Host::Ipv4(ip) => ip.octets() == [127, 0, 0, 1],
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    let onion =
        matches!(&host, url::Host::Domain(name) if name.trim_end_matches('.').ends_with(".onion"));
    let scheme = url.scheme() == "https" || url.scheme() == "http" && loopback;
    (url.as_str() == text
        && scheme
        && !onion
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/")
        .then(|| url.host_str().map(str::to_owned))
        .flatten()
}

/// Returns the request public key and BUD-11 server tag, or the rule broken.
fn check_invitation(payload: &[u8], now: u64) -> Result<(String, String), &'static str> {
    if payload.is_empty() || payload.len() > 16_364 {
        return Err("length");
    }
    if payload.trim_ascii_start().first() != Some(&b'{') {
        return Err("shape");
    }
    let wire: Invitation = serde_json::from_slice(payload).map_err(|_| "shape")?;
    if wire.v != "wildbloom-request/1" {
        return Err("version");
    }
    let server = check_node(&wire.node).ok_or("node")?;
    if !super::super::event::is_canonical_key(&wire.signer) {
        return Err("signer");
    }
    let signer = Keys::parse(&wire.signer).map_err(|_| "signer")?;
    wildbloom_envelope::InputKey::parse_wbk1(&wire.key).map_err(|_| "key")?;
    if !(wildbloom_envelope::MIN_ENVELOPE_BYTES..=270_532_608).contains(&wire.size) {
        return Err("size");
    }
    if wire.bytes == 0 || wire.bytes >= wire.size || wire.bytes > 250_000_000 {
        return Err("bytes");
    }
    if wire.files != 1 {
        return Err("files");
    }
    if wire.until <= now || wire.until > now + 86_400 || wire.until > MAX_SAFE_INTEGER {
        return Err("until");
    }
    if serde_json::to_vec(&wire).unwrap() != payload {
        return Err("canonical");
    }
    Ok((signer.public_key().to_hex(), server))
}

/// The optional reply, read strictly as Share's downloaded reply is.
fn read_reply(bytes: &[u8]) -> Option<(String, u64)> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        v: u64,
        event: String,
        sha256: String,
        size: u64,
    }
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }
    let reply: Reply = serde_json::from_slice(bytes).ok()?;
    (reply.v == 1
        && reply.event == "sending"
        && super::super::event::is_canonical_key(&reply.sha256)
        && (1..=MAX_SAFE_INTEGER).contains(&reply.size))
    .then_some((reply.sha256, reply.size))
}

#[test]
fn invitation_vectors_follow_the_documented_rules() {
    let vectors = vectors();
    assert!(!vectors.invitation.valid.is_empty());
    for case in &vectors.invitation.valid {
        let (pubkey, server) = check_invitation(case.invitation.as_bytes(), vectors.now)
            .unwrap_or_else(|reason| panic!("{}: refused for {reason}", case.name));
        assert_eq!(pubkey, case.pubkey, "{}", case.name);
        assert_eq!(server, case.server_tag, "{}", case.name);
    }
    for case in &vectors.invitation.invalid {
        assert_eq!(
            check_invitation(case.invitation.as_bytes(), vectors.now).err(),
            Some(case.reason.as_str()),
            "{}",
            case.name
        );
    }
}

#[test]
fn reply_vectors_are_read_strictly() {
    let vectors = vectors();
    for case in &vectors.reply.valid {
        assert_eq!(
            read_reply(case.reply.as_bytes()),
            Some((case.sha256.clone(), case.size)),
            "{}",
            case.name
        );
    }
    for case in &vectors.reply.invalid {
        assert_eq!(read_reply(case.reply.as_bytes()), None, "{}", case.name);
    }
}

#[tokio::test]
async fn upload_grant_vectors_match_the_route() {
    let vectors = vectors();
    for case in &vectors.upload_grant.valid {
        let terms = parse_issue(case.body.as_bytes(), vectors.now)
            .unwrap_or_else(|_| panic!("{}", case.name));
        let expected: Value = serde_json::from_str(&case.body).unwrap();
        assert_eq!(
            serde_json::to_value(&terms).unwrap(),
            expected,
            "{}",
            case.name
        );
    }
    // Every refusal through the real route, on a node whose clock reads `now`.
    let dir = tempfile::tempdir().unwrap();
    let node = node_clocked(
        dir.path().join("data"),
        Arc::new(AtomicI64::new(0)),
        &[1],
        Vec::new(),
        true,
        Some(vectors.now),
    )
    .await;
    grant_device(&node, &device_grant(MIB)).await;
    for case in &vectors.upload_grant.invalid {
        let request = issue_with(&keys(10), case.body.as_bytes(), node.now());
        let (status, body) = node.call(request).await;
        assert_eq!(status.as_u16(), case.status, "{}: {body}", case.name);
        assert_eq!(error(&body), case.error, "{}", case.name);
    }
}
