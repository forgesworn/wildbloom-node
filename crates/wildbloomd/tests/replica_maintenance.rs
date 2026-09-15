//! Real Blossom daemons and coordinator processes through a controlled local
//! SOCKS fixture. This exercises Tor-profile routing, not the real Tor network
//! or physical independence. No public endpoint or real signing key is used.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp, UnsignedEvent};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::Mutex,
};

const BIN: &str = env!("CARGO_BIN_EXE_wildbloomd");

fn onion(index: u8) -> String {
    let public = [index; 32];
    let checksum = Sha3_256::digest([b".onion checksum".as_slice(), &public, &[3]].concat());
    let encoded = [public.as_slice(), &checksum[..2], &[3]].concat();
    let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::new();
    for position in 0..56 {
        let mut value = 0;
        for bit in 0..5 {
            let offset = position * 5 + bit;
            value = (value << 1) | ((encoded[offset / 8] >> (7 - offset % 8)) & 1);
        }
        output.push(alphabet[value as usize] as char);
    }
    format!("{output}.onion")
}

struct Socks {
    url: String,
    hosts: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Socks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn socks(routes: BTreeMap<String, u16>) -> Socks {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("socks5h://{}", listener.local_addr().unwrap());
    let routes = Arc::new(routes);
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let recorded = hosts.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    let routes = routes.clone(); let recorded = recorded.clone();
                    connections.spawn(async move {
                        let _ = tokio::time::timeout(Duration::from_secs(30), async {
                            let mut greeting = [0; 2]; stream.read_exact(&mut greeting).await?;
                            if greeting[0] != 5 { return Ok::<_, std::io::Error>(()); }
                            let mut methods = vec![0; greeting[1] as usize]; stream.read_exact(&mut methods).await?;
                            stream.write_all(&[5, 0]).await?;
                            let mut request = [0; 5]; stream.read_exact(&mut request).await?;
                            if request[..4] != [5, 1, 0, 3] { return Ok(()); }
                            let mut host = vec![0; request[4] as usize]; stream.read_exact(&mut host).await?;
                            let host = String::from_utf8(host).unwrap();
                            let mut port = [0; 2]; stream.read_exact(&mut port).await?;
                            recorded.lock().await.push(host.clone());
                            let Some(destination) = routes.get(&host).filter(|_| u16::from_be_bytes(port) == 80) else {
                                stream.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await?; return Ok(());
                            };
                            match TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, *destination)).await {
                                Ok(mut upstream) => {
                                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                                    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                                }
                                Err(_) => { stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?; }
                            }
                            Ok(())
                        }).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {},
            }
        }
    });
    Socks { url, hosts, task }
}

struct Node {
    child: Child,
    directory: PathBuf,
    port: u16,
    host: String,
}
impl Node {
    async fn start(
        directory: PathBuf,
        port: u16,
        host: String,
        proxy: &str,
        owner: &str,
        quota: u64,
    ) -> Self {
        let mut child = Command::new(BIN)
            .args([
                "--no-tor",
                "--repair-interval",
                "0",
                "--bind",
                &format!("127.0.0.1:{port}"),
                "--public-url",
                &format!("http://{host}/"),
                "--server-name",
                &host,
                "--mirror-proxy",
                proxy,
                "--allow-pubkey",
                owner,
                "--quota-bytes",
                &quota.to_string(),
                "--max-blob-bytes",
                "2097152",
            ])
            .arg("--data-dir")
            .arg(&directory)
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if child.try_wait().unwrap().is_some() {
                    let mut reason = String::new();
                    child
                        .stderr
                        .take()
                        .unwrap()
                        .take(8192)
                        .read_to_string(&mut reason)
                        .await
                        .unwrap();
                    panic!("fixture node exited before readiness: {reason}");
                }
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
        .expect("fixture node readiness timeout");
        Self {
            child,
            directory,
            port,
            host,
        }
    }
    async fn stop(&mut self) {
        self.child.kill().await.unwrap();
        self.child.wait().await.unwrap();
    }
    fn blob(&self, hash: &str) -> PathBuf {
        self.directory.join("blobs").join(&hash[..2]).join(hash)
    }
}

async fn coordinator(policy: &Path, state: &Path, owner: &str, proxy: &str) -> Value {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new(BIN)
            .args([
                "replicas", "run", "--once", "--owner", owner, "--proxy", proxy,
            ])
            .arg("--policy")
            .arg(policy)
            .arg("--state-dir")
            .arg(state)
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("coordinator deadline")
    .unwrap();
    assert!(
        output.status.success(),
        "coordinator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("bounded JSON report");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\"sig\""));
    report
}

fn sign_pending(state: &Path, keys: &Keys) -> usize {
    let mut count = 0;
    for entry in std::fs::read_dir(state.join("pending")).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let Some(id) = name
            .strip_prefix("request-")
            .and_then(|v| v.strip_suffix(".json"))
        else {
            continue;
        };
        let request: UnsignedEvent =
            serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
        assert_eq!(request.compute_id().to_hex(), id);
        assert_eq!(request.pubkey, keys.public_key());
        let signed = request.finalize(keys).unwrap();
        std::fs::write(
            state.join("pending").join(format!("signed-{id}.json")),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        count += 1;
    }
    count
}

async fn maintain(policy: &Path, state: &Path, keys: &Keys, proxy: &str) -> Value {
    for _ in 0..5 {
        let report = coordinator(policy, state, &keys.public_key().to_hex(), proxy).await;
        if report["blobs"][0]["verified_configured_groups"] == 2 {
            return report;
        }
        assert!(
            sign_pending(state, keys) > 0,
            "deficit has no repair authorisation request"
        );
    }
    panic!("replica floor was not restored within the bounded manual signing passes");
}

async fn upload(client: &reqwest::Client, node: &Node, keys: &Keys, bytes: Vec<u8>) -> String {
    let hash = hex::encode(Sha256::digest(&bytes));
    let now = Timestamp::now().as_secs();
    let auth = EventBuilder::new(Kind::from(24242), "Synthetic replica acceptance upload")
        .tags([
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", &hash]).unwrap(),
            Tag::parse(["server", &node.host]).unwrap(),
            Tag::parse(["expiration", &(now + 120).to_string()]).unwrap(),
        ])
        .finalize(keys)
        .unwrap();
    let response = client
        .put(format!("http://127.0.0.1:{}/upload", node.port))
        .header("x-sha-256", &hash)
        .header(
            "authorization",
            format!(
                "Nostr {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&auth).unwrap())
            ),
        )
        .header("content-type", "application/octet-stream")
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 201);
    hash
}

#[tokio::test]
async fn real_nodes_restore_a_floor_after_loss_corruption_and_restart() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let keys = Keys::generate();
    let owner = keys.public_key().to_hex();
    let hosts = (1..=5).map(onion).collect::<Vec<_>>();
    let mut ports = Vec::new();
    for _ in 0..5 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(listener.local_addr().unwrap().port());
    }
    let proxy = socks(hosts.iter().cloned().zip(ports.iter().copied()).collect()).await;
    let mut nodes = Vec::new();
    for n in 0..5 {
        nodes.push(
            Node::start(
                root.path().join(format!("node-{n}")),
                ports[n],
                hosts[n].clone(),
                &proxy.url,
                &owner,
                if n == 3 {
                    2 * 1024 * 1024
                } else {
                    8 * 1024 * 1024
                },
            )
            .await,
        );
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let bytes = (0..1_048_607).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    let hash = upload(&client, &nodes[0], &keys, bytes.clone()).await;
    upload(&client, &nodes[3], &keys, vec![7; 2 * 1024 * 1024]).await;
    let now = Timestamp::now().as_secs();
    let content = json!({ "type": "wildbloom.replica-policy", "version": 1, "id": "process-acceptance", "revision": 1,
        "expires_at": now + 3600, "profile": "tor-only", "desired_groups": 2,
        "targets": hosts.iter().enumerate().map(|(n, host)| json!({"id": format!("node-{}", n + 1), "origin": format!("http://{host}/"), "failure_group": format!("configured-{}", n + 1), "retention": "owner"})).collect::<Vec<_>>(),
        "blobs": [{"sha256": hash, "size": bytes.len()}] });
    let content_path = root.path().join("content.json");
    std::fs::write(&content_path, serde_json::to_vec(&content).unwrap()).unwrap();
    let template = Command::new(BIN)
        .args(["replicas", "template", "--owner", &owner])
        .arg("--content")
        .arg(&content_path)
        .output()
        .await
        .unwrap();
    assert!(template.status.success());
    let unsigned: UnsignedEvent = serde_json::from_slice(&template.stdout).unwrap();
    let signed_policy = unsigned.finalize(&keys).unwrap();
    let policy_path = root.path().join("policy.json");
    std::fs::write(&policy_path, serde_json::to_vec(&signed_policy).unwrap()).unwrap();
    let state = root.path().join("coordinator");
    let first = maintain(&policy_path, &state, &keys, &proxy.url).await;
    assert_eq!(
        first["blobs"][0]["observations"]["node-2"]["state"],
        "verified"
    );
    nodes[0].stop().await;
    nodes[1].stop().await;
    nodes[1] = Node::start(
        nodes[1].directory.clone(),
        nodes[1].port,
        nodes[1].host.clone(),
        &proxy.url,
        &owner,
        8 * 1024 * 1024,
    )
    .await;
    let after_loss = maintain(&policy_path, &state, &keys, &proxy.url).await;
    assert_eq!(
        after_loss["blobs"][0]["observations"]["node-3"]["state"],
        "verified"
    );
    std::fs::write(nodes[2].blob(&hash), vec![0; bytes.len()]).unwrap();
    let after_corruption = maintain(&policy_path, &state, &keys, &proxy.url).await;
    assert_eq!(
        after_corruption["blobs"][0]["observations"]["node-3"]["reason"],
        "invalid_bytes"
    );
    assert_eq!(
        after_corruption["blobs"][0]["observations"]["node-5"]["state"],
        "verified"
    );
    assert!(
        !nodes[3].blob(&hash).exists(),
        "quota-limited node must not hold a copy"
    );
    nodes[1].stop().await;
    nodes[2].stop().await;
    nodes[4].stop().await;
    nodes[4] = Node::start(
        nodes[4].directory.clone(),
        nodes[4].port,
        nodes[4].host.clone(),
        &proxy.url,
        &owner,
        8 * 1024 * 1024,
    )
    .await;
    nodes[0] = Node::start(
        root.path().join("replacement"),
        ports[0],
        hosts[0].clone(),
        &proxy.url,
        &owner,
        8 * 1024 * 1024,
    )
    .await;
    let recovered = maintain(&policy_path, &state, &keys, &proxy.url).await;
    assert_eq!(
        recovered["blobs"][0]["observations"]["node-1"]["state"],
        "verified"
    );
    let returned = client
        .get(format!("http://127.0.0.1:{}/{hash}", ports[0]))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(returned.as_ref(), bytes);
    let mut stopped_content = content;
    stopped_content["revision"] = 2.into();
    stopped_content["desired_groups"] = 0.into();
    std::fs::write(&content_path, serde_json::to_vec(&stopped_content).unwrap()).unwrap();
    let template = Command::new(BIN)
        .args(["replicas", "template", "--owner", &owner])
        .arg("--content")
        .arg(&content_path)
        .output()
        .await
        .unwrap();
    assert!(template.status.success());
    let request: UnsignedEvent = serde_json::from_slice(&template.stdout).unwrap();
    std::fs::write(
        &policy_path,
        serde_json::to_vec(&request.finalize(&keys).unwrap()).unwrap(),
    )
    .unwrap();
    let stopped = Command::new(BIN)
        .args(["replicas", "run", "--once", "--owner", &owner])
        .arg("--policy")
        .arg(&policy_path)
        .arg("--state-dir")
        .arg(&state)
        .output()
        .await
        .unwrap();
    assert!(
        stopped.status.success(),
        "signed stop policy needs no live transport"
    );
    let stopped: Value = serde_json::from_slice(&stopped.stdout).unwrap();
    assert_eq!(stopped["stopped"], true);
    let persisted: Value =
        serde_json::from_slice(&std::fs::read(state.join("state.json")).unwrap()).unwrap();
    assert_eq!(persisted["revision"], 2);
    assert_eq!(std::fs::read_dir(state.join("pending")).unwrap().count(), 0);
    let seen = proxy.hosts.lock().await;
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|host| hosts.contains(host)));
    eprintln!(
        "Replica acceptance: 5 loopback Node stores, {} exact bytes, original stopped, corrupt and quota-limited targets refused, restarted source and fresh replacement verified; all SOCKS destinations explicitly configured. This is not real Tor or physical independence.",
        bytes.len()
    );
}
