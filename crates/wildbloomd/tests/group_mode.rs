//! Start-up behaviour of `wildbloomd --group-mode`, through the real binary.
//! Synthetic keys only.
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_wildbloomd");
const KEEPER: &str = "ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

fn run(extra: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("temporary directory");
    Command::new(BIN)
        .args(["--no-tor", "--data-dir"])
        .arg(dir.path().join("data"))
        .args(["--bind", "127.0.0.1:0"])
        .args(extra)
        .env_remove("WILDBLOOM_OPEN_SHELTER")
        .output()
        .expect("run wildbloomd")
}

fn refused(extra: &[&str], needle: &str) {
    let output = run(extra);
    assert!(!output.status.success(), "{extra:?} must not start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(needle), "{extra:?}: {stderr}");
}

#[test]
fn group_mode_refuses_to_start_beside_the_guest_tier_discovery_and_paid_profiles() {
    let keeper = format!("{KEEPER}:1048576");
    let base = ["--group-mode", "--group-keeper", keeper.as_str()];
    for (flag, value, needle) in [
        ("--open-shelter", None, "--open-shelter"),
        (
            "--service-profile",
            Some("/nonexistent/profile.json"),
            "--service-profile",
        ),
        (
            "--checkout-profile",
            Some("/nonexistent/checkout.json"),
            "--checkout-profile",
        ),
    ] {
        let mut args = base.to_vec();
        args.push(flag);
        args.extend(value);
        refused(&args, needle);
    }
    refused(&["--group-mode"], "at least one --group-keeper");
    refused(&["--group-keeper", keeper.as_str()], "--group-mode");
}

// ---------------------------------------------------------------------------
// A running group node: grants over HTTP, authenticated reads, and a restart.
// ---------------------------------------------------------------------------
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    net::TcpStream,
    process::{Child, Command as AsyncCommand},
};

const HOST: &str = "localhost";

struct Daemon {
    child: Child,
    port: u16,
}

impl Daemon {
    async fn start(directory: &Path, keeper: &str, extra: &[&str]) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut child = AsyncCommand::new(BIN)
            .args(["--no-tor", "--repair-interval", "0"])
            .args(["--bind", &format!("127.0.0.1:{port}")])
            .args(["--public-url", &format!("http://{HOST}:{port}/")])
            .args(["--server-name", HOST])
            .args([
                "--group-mode",
                "--group-keeper",
                &format!("{keeper}:1048576"),
            ])
            .args(["--max-blob-bytes", "1048576"])
            .args(extra)
            .arg("--data-dir")
            .arg(directory)
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                assert!(child.try_wait().unwrap().is_none(), "the group node exited");
                if TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                    .await
                    .is_ok()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("readiness");
        Self { child, port }
    }

    async fn stop(mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

fn now() -> u64 {
    Timestamp::now().as_secs()
}

fn sign(signer: &Keys, kind: u16, tags: &[[&str; 2]], content: &str) -> Vec<u8> {
    let tags = tags.iter().map(|tag| Tag::parse(*tag).unwrap());
    let event = EventBuilder::new(Kind::from(kind), content)
        .tags(tags)
        .custom_created_at(Timestamp::from(now() - 1))
        .finalize(signer)
        .unwrap();
    serde_json::to_vec(&event).unwrap()
}

fn grant_event(
    keeper: &Keys,
    id: &str,
    room: &str,
    device: &Keys,
    scopes: &[&str],
    bytes: Option<u64>,
    status: &str,
) -> Vec<u8> {
    let device = device.public_key().to_hex();
    let bytes = bytes.map(|bytes| bytes.to_string());
    let expiration = (now() + 86_400).to_string();
    let mut tags = vec![
        ["t", "grant"],
        ["grant", id],
        ["d", room],
        ["device", device.as_str()],
        ["server", HOST],
    ];
    tags.extend(scopes.iter().map(|scope| ["scope", *scope]));
    if let Some(bytes) = &bytes {
        tags.push(["bytes", bytes.as_str()]);
    }
    tags.push(["status", status]);
    tags.push(["expiration", expiration.as_str()]);
    sign(keeper, 27_541, &tags, "")
}

fn token(signer: &Keys, verb: &str, hash: &str, lifetime: u64) -> String {
    let expiration = (now() + lifetime).to_string();
    let event = sign(
        signer,
        24_242,
        &[
            ["t", verb],
            ["x", hash],
            ["server", HOST],
            ["expiration", &expiration],
        ],
        "synthetic group node test",
    );
    format!("Nostr {}", URL_SAFE_NO_PAD.encode(event))
}

#[tokio::test]
async fn a_running_group_node_serves_only_its_group_and_remembers_across_a_restart() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (keeper, alice, bob, stranger) = (
        Keys::generate(),
        Keys::generate(),
        Keys::generate(),
        Keys::generate(),
    );
    let room = "7a".repeat(32);
    let bytes = b"synthetic group node blob".to_vec();
    let hash = hex::encode(Sha256::digest(&bytes));
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let post = |daemon: &Daemon, body: Vec<u8>| {
        let request = client.post(daemon.url("/groups/v1/events")).body(body);
        async move { request.send().await.unwrap().status().as_u16() }
    };
    let get = |daemon: &Daemon, who: &Keys, hash: &str| {
        let request = client
            .get(daemon.url(&format!("/{hash}")))
            .header("authorization", token(who, "get", hash, 60));
        async move { request.send().await.unwrap() }
    };
    let alice_id = "a1".repeat(16);
    let bob_id = "b2".repeat(16);

    let node = Daemon::start(&data, &keeper.public_key().to_hex(), &[]).await;
    assert_eq!(
        post(
            &node,
            grant_event(
                &keeper,
                &alice_id,
                &room,
                &alice,
                &["upload", "get", "delete"],
                Some(1 << 20),
                "active"
            )
        )
        .await,
        201
    );
    assert_eq!(
        post(
            &node,
            grant_event(&keeper, &bob_id, &room, &bob, &["get"], None, "active")
        )
        .await,
        201
    );

    // Alice uploads; the reply is a descriptor.
    let upload = client
        .put(node.url("/upload"))
        .header("x-sha-256", &hash)
        .header("authorization", token(&alice, "upload", &hash, 60))
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status().as_u16(), 201);

    // Nobody reads without a token, and the answer is private.
    let open = client
        .get(node.url(&format!("/{hash}")))
        .send()
        .await
        .unwrap();
    assert_eq!(open.status().as_u16(), 401);
    assert_eq!(open.headers()["cache-control"], "private, no-store");
    let missing = client
        .get(node.url(&format!("/{}", "0".repeat(64))))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 401);
    assert_eq!(get(&node, &stranger, &hash).await.status().as_u16(), 403);
    let read = get(&node, &bob, &hash).await;
    assert_eq!(read.status().as_u16(), 200);
    assert_eq!(read.headers()["cache-control"], "private, no-store");
    assert_eq!(read.bytes().await.unwrap().to_vec(), bytes);
    assert_eq!(
        client
            .get(node.url("/healthz"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );

    // A restart keeps the grants and the group's claim.
    node.stop().await;
    let node = Daemon::start(&data, &keeper.public_key().to_hex(), &[]).await;
    assert_eq!(get(&node, &bob, &hash).await.status().as_u16(), 200);
    assert_eq!(get(&node, &alice, &hash).await.status().as_u16(), 200);

    // Revoking bob takes effect on his next request, and sticks after a restart
    // even when his old grant is posted again.  A revocation must be strictly
    // newer than the grant it ends, so the keeper signs a second later.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        post(
            &node,
            grant_event(&keeper, &bob_id, &room, &bob, &["get"], None, "revoked")
        )
        .await,
        201
    );
    assert_eq!(get(&node, &bob, &hash).await.status().as_u16(), 403);
    node.stop().await;
    let node = Daemon::start(&data, &keeper.public_key().to_hex(), &[]).await;
    assert_eq!(get(&node, &bob, &hash).await.status().as_u16(), 403);
    assert_eq!(
        post(
            &node,
            grant_event(&keeper, &bob_id, &room, &bob, &["get"], None, "active")
        )
        .await,
        409
    );

    // A delete token is spent once, even across a restart.
    let delete = token(&alice, "delete", &hash, 3600);
    let send_delete = |node: &Daemon| {
        let request = client
            .delete(node.url(&format!("/{hash}")))
            .header("authorization", &delete);
        async move { request.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(send_delete(&node).await, 200);
    assert_eq!(send_delete(&node).await, 404);
    assert_eq!(
        client
            .put(node.url("/upload"))
            .header("x-sha-256", &hash)
            .header("authorization", token(&alice, "upload", &hash, 60))
            .body(bytes.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        201
    );
    node.stop().await;
    let node = Daemon::start(&data, &keeper.public_key().to_hex(), &[]).await;
    assert_eq!(send_delete(&node).await, 409);
    assert_eq!(get(&node, &alice, &hash).await.status().as_u16(), 200);
    node.stop().await;
}
