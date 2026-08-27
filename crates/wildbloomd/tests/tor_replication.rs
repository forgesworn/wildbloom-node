use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use std::{
    net::TcpListener,
    process::Stdio,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::{
    process::Child,
    time::{sleep, timeout},
};

/// Seconds each managed Tor may take to bootstrap.  Defaults to 900; raise it
/// with `WILDBLOOM_TEST_TOR_TIMEOUT` on days when directory fetches stall.
fn tor_bootstrap_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("WILDBLOOM_TEST_TOR_TIMEOUT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(900),
    )
}

fn ready_timeout() -> Duration {
    tor_bootstrap_timeout() + Duration::from_secs(30)
}

#[tokio::test]
#[ignore = "requires a real Tor executable; run with WILDBLOOM_TEST_TOR_BIN=/path/to/tor"]
async fn two_nodes_replicate_repair_and_preserve_the_onion_identity() {
    let tor = std::env::var("WILDBLOOM_TEST_TOR_BIN")
        .expect("set WILDBLOOM_TEST_TOR_BIN to an audited Tor executable");
    let keys = Keys::parse(&format!("{:064x}", 1)).unwrap();
    let pubkey = keys.public_key().to_hex();
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let first_port = free_port();
    let second_port = free_port();
    let mut first = start_node(&tor, &first_dir, first_port, &pubkey).await;
    let mut second = start_node(&tor, &second_dir, second_port, &pubkey).await;
    let first_onion = wait_for_node(&first_dir, first_port).await;
    let second_onion = wait_for_node(&second_dir, second_port).await;

    let bytes = b"wildbloom automatic repair acceptance";
    let hash = hex::encode(Sha256::digest(bytes));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .unwrap();
    let upload = client
        .put(format!("http://127.0.0.1:{first_port}/upload"))
        .header("content-type", "text/plain")
        .header("x-sha-256", &hash)
        .header(
            "authorization",
            authorization(&keys, "upload", &hash, &first_onion),
        )
        .body(bytes.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::CREATED);

    let source = format!("http://{first_onion}/{hash}.txt");
    let mirrored =
        mirror_until_reachable(&client, second_port, &keys, &hash, &second_onion, &source).await;
    assert_eq!(mirrored.status(), StatusCode::CREATED);

    let second_blob = second_dir.path().join("blobs").join(&hash[..2]).join(&hash);
    std::fs::remove_file(&second_blob).unwrap();
    wait_for_blob(&client, second_port, &hash, bytes).await;

    stop_node(&mut first).await;
    let retained = client
        .get(format!("http://127.0.0.1:{second_port}/{hash}"))
        .send()
        .await
        .unwrap();
    assert_eq!(retained.status(), StatusCode::OK);
    assert_eq!(retained.bytes().await.unwrap(), bytes.as_slice());

    stop_node(&mut second).await;
    let mut restarted = start_node(&tor, &second_dir, second_port, &pubkey).await;
    assert_eq!(wait_for_node(&second_dir, second_port).await, second_onion);
    stop_node(&mut restarted).await;
}

async fn stop_node(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id().expect("node process must still be running");
        let status = tokio::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .await
            .unwrap();
        assert!(status.success());
    }
    #[cfg(windows)]
    child.start_kill().unwrap();

    let status = timeout(Duration::from_secs(20), child.wait())
        .await
        .expect("node did not stop cleanly")
        .unwrap();
    assert!(status.success());
}

async fn start_node(tor: &str, directory: &TempDir, port: u16, pubkey: &str) -> Child {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_wildbloomd"))
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--data-dir")
        .arg(directory.path())
        .arg("--tor-bin")
        .arg(tor)
        .arg("--tor-timeout")
        .arg(tor_bootstrap_timeout().as_secs().to_string())
        .arg("--allow-pubkey")
        .arg(pubkey)
        .arg("--repair-interval")
        .arg("1")
        .env("RUST_LOG", "info")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

async fn wait_for_node(directory: &TempDir, port: u16) -> String {
    let hostname = directory.path().join("tor/onion-service/hostname");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    for _ in 0..(ready_timeout().as_secs() * 4) {
        if let Ok(onion) = std::fs::read_to_string(&hostname)
            && let Ok(response) = client
                .get(format!("http://127.0.0.1:{port}/healthz"))
                .send()
                .await
            && response.status() == StatusCode::OK
        {
            return onion.trim().to_owned();
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("node did not become ready at {}", hostname.display());
}

/// A freshly published onion service can take minutes to become reachable
/// through another client's circuits.  Keep asking until the origin answers or
/// the budget runs out.  Every refused attempt must leave nothing behind, which
/// the final repair and retention checks would expose.
async fn mirror_until_reachable(
    client: &reqwest::Client,
    port: u16,
    keys: &Keys,
    hash: &str,
    server: &str,
    source: &str,
) -> reqwest::Response {
    let deadline = Instant::now() + ready_timeout();
    loop {
        let response = client
            .put(format!("http://127.0.0.1:{port}/mirror"))
            .header("content-type", "application/json")
            .header("authorization", authorization(keys, "upload", hash, server))
            .json(&serde_json::json!({ "url": source }))
            .send()
            .await
            .unwrap();
        if response.status() != StatusCode::BAD_GATEWAY || Instant::now() >= deadline {
            return response;
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn wait_for_blob(client: &reqwest::Client, port: u16, hash: &str, expected: &[u8]) {
    for _ in 0..120 {
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{port}/{hash}"))
            .send()
            .await
            && response.status() == StatusCode::OK
            && let Ok(bytes) = response.bytes().await
            && bytes.as_ref() == expected
        {
            return;
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("the replica was not repaired");
}

fn authorization(keys: &Keys, operation: &str, hash: &str, server: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let tags = [
        vec!["t", operation],
        vec!["x", hash],
        vec!["server", server],
    ]
    .into_iter()
    .map(|tag| Tag::parse(tag).unwrap())
    .chain(std::iter::once(
        Tag::parse(["expiration", &(now + 120).to_string()]).unwrap(),
    ));
    let event = EventBuilder::new(Kind::Custom(24_242), format!("Authorise {operation}"))
        .tags(tags)
        .custom_created_at(Timestamp::from(now))
        .finalize(keys)
        .unwrap();
    format!(
        "Nostr {}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
    )
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
