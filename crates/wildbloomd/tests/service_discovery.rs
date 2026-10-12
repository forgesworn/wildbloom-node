//! Real daemon free-shelter discovery and mirroring via a controlled SOCKS fixture.
//! No real Tor, public relay, operator credentials or independently hosted machine.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
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
        profile: Option<&Path>,
    ) -> Self {
        let mut command = Command::new(BIN);
        command
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
            .kill_on_drop(true);
        if let Some(profile) = profile {
            command
                .arg("--open-shelter")
                .arg("--service-profile")
                .arg(profile);
        }
        let mut child = command.spawn().unwrap();
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
}

fn authorisation(keys: &Keys, host: &str, hash: &str) -> String {
    let event = EventBuilder::new(Kind::from(24242), "Synthetic storage discovery acceptance")
        .tags([
            Tag::parse(["t", "upload"]).unwrap(),
            Tag::parse(["x", hash]).unwrap(),
            Tag::parse(["server", host]).unwrap(),
            Tag::parse([
                "expiration",
                &(Timestamp::now().as_secs() + 120).to_string(),
            ])
            .unwrap(),
        ])
        .finalize(keys)
        .unwrap();
    format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
    )
}
#[tokio::test]
async fn discovered_shelter_mirrors_only_and_reports_full_after_restart() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let ports = (0..2)
        .map(|_| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        })
        .collect::<Vec<_>>();
    let hosts = [onion(1), onion(2)];
    let proxy = socks(hosts.iter().cloned().zip(ports.iter().copied()).collect()).await;
    let owner = Keys::parse(&hex::encode([1; 32])).unwrap();
    let guest = Keys::parse(&hex::encode([2; 32])).unwrap();
    let service_key = Keys::parse(&hex::encode([3; 32])).unwrap();
    let profile = root.path().join("service-profile.json");
    std::fs::write(&profile, serde_json::to_vec(&json!({"service_pubkey":service_key.public_key().to_hex(),
        "identifier":"synthetic-shelter","name":"Synthetic shelter","about":"Loopback acceptance only",
        "origins":[format!("http://{}/",hosts[1])],"browser_origins":["https://app.example"],"announcement":null})).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut source = Node::start(
        root.path().join("source"),
        ports[0],
        hosts[0].clone(),
        &proxy.url,
        &owner.public_key().to_hex(),
        1000,
        None,
    )
    .await;
    let mut shelter = Node::start(
        root.path().join("shelter"),
        ports[1],
        hosts[1].clone(),
        &proxy.url,
        &owner.public_key().to_hex(),
        1000,
        Some(&profile),
    )
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!("http://127.0.0.1:{}/services/v1", source.port))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    let description: Value = client
        .get(format!("http://127.0.0.1:{}/services/v1", shelter.port))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(description["services"][0]["availability"], "accepting");
    assert_eq!(description["checkout"], Value::Null);
    assert_eq!(
        description["service_pubkey"],
        service_key.public_key().to_hex()
    );
    // Synthetic opaque bytes: this test verifies storage and authorisation, not browser encryption.
    let bytes = vec![37u8; 800];
    let hash = hex::encode(Sha256::digest(&bytes));
    let upload = client
        .put(format!("http://127.0.0.1:{}/upload", source.port))
        .header("x-sha-256", &hash)
        .header("authorization", authorisation(&owner, &source.host, &hash))
        .header("content-type", "application/octet-stream")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status().as_u16(), 201);
    let denied = client
        .put(format!("http://127.0.0.1:{}/upload", shelter.port))
        .header("x-sha-256", &hash)
        .header("authorization", authorisation(&guest, &shelter.host, &hash))
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status().as_u16(), 401);
    let mirrored = client
        .put(format!("http://127.0.0.1:{}/mirror", shelter.port))
        .header("authorization", authorisation(&guest, &shelter.host, &hash))
        .json(&json!({"url":format!("http://{}/{hash}",source.host)}))
        .send()
        .await
        .unwrap();
    assert_eq!(mirrored.status().as_u16(), 201);
    let current: Value = client
        .get(format!("http://127.0.0.1:{}/services/v1", shelter.port))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(current["services"][0]["availability"], "full");
    let saved = client
        .get(format!("http://127.0.0.1:{}/{hash}", shelter.port))
        .send()
        .await
        .unwrap();
    assert_eq!(saved.headers()["content-type"], "application/octet-stream");
    assert_eq!(saved.bytes().await.unwrap().as_ref(), bytes);
    shelter.stop().await;
    shelter = Node::start(
        shelter.directory.clone(),
        shelter.port,
        shelter.host.clone(),
        &proxy.url,
        &owner.public_key().to_hex(),
        1000,
        Some(&profile),
    )
    .await;
    let reopened: Value = client
        .get(format!("http://127.0.0.1:{}/services/v1", shelter.port))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reopened["services"][0]["availability"], "full");
    let seen = proxy.hosts.lock().await;
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|host| hosts.contains(host)));
    drop(seen);
    source.stop().await;
    shelter.stop().await;
}
