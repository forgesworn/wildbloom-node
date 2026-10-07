//! Fresh full-read audits, not a proof of continuous retention or dedicated disk.
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncReadExt;
use wildbloom_core::Store;

const DOMAIN: &[u8] = b"wildbloom.storage-proof.v1\n";
#[derive(Clone)]
struct ProofState {
    store: Store,
    origin: String,
    active: Arc<tokio::sync::Semaphore>,
    rate: Arc<Mutex<(Instant, u32)>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    sha256: String,
    nonce: String,
}
#[derive(Serialize)]
struct Proof {
    version: u8,
    sha256: String,
    nonce: String,
    size: u64,
    digest: String,
}

pub fn router(store: Store, origin: String) -> Router {
    Router::new()
        .route("/storage/v1/proof", post(prove))
        .with_state(ProofState {
            store,
            origin,
            active: Arc::new(tokio::sync::Semaphore::new(1)),
            rate: Arc::new(Mutex::new((Instant::now(), 0))),
        })
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::POST])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
async fn prove(State(state): State<ProofState>, request: Request<Body>) -> Response {
    let result = tokio::time::timeout(Duration::from_secs(300), execute(state, request)).await;
    let mut response = match result {
        Ok(Ok(proof)) => axum::Json(proof).into_response(),
        Ok(Err(code)) => (code, "Storage audit unavailable").into_response(),
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "Storage audit timed out").into_response(),
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
async fn execute(state: ProofState, request: Request<Body>) -> Result<Proof, StatusCode> {
    let _permit = state
        .active
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let (parts, body) = request.into_parts();
    if parts.uri.query().is_some()
        || parts.headers.get_all(header::AUTHORIZATION).iter().count() != 1
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let body = tokio::time::timeout(Duration::from_secs(10), to_bytes(body, 1024))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let authorization = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs();
    wildbloom_checkout::authenticate(
        authorization,
        &format!("{}storage/v1/proof", state.origin),
        "POST",
        &body,
        now,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let challenge: Challenge =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !hash(&challenge.sha256) || !hash(&challenge.nonce) {
        return Err(StatusCode::BAD_REQUEST);
    }
    {
        let mut rate = state
            .rate
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if rate.0.elapsed() >= Duration::from_secs(60) {
            *rate = (Instant::now(), 0);
        }
        if rate.1 >= 6 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        rate.1 += 1;
    }
    let metadata = state
        .store
        .get(&challenge.sha256)
        .map_err(|_| StatusCode::NOT_FOUND)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let path = state.store.blob_path(&challenge.sha256);
    let file_metadata = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if !file_metadata.is_file() || file_metadata.len() != metadata.size {
        return Err(StatusCode::CONFLICT);
    }
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let mut proof = Sha256::new();
    proof.update(DOMAIN);
    proof.update(hex::decode(&challenge.nonce).map_err(|_| StatusCode::BAD_REQUEST)?);
    proof.update(metadata.size.to_be_bytes());
    let mut content = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut size = 0u64;
    loop {
        let count = file
            .read(&mut buffer)
            .await
            .map_err(|_| StatusCode::CONFLICT)?;
        if count == 0 {
            break;
        }
        size = size.checked_add(count as u64).ok_or(StatusCode::CONFLICT)?;
        if size > metadata.size {
            return Err(StatusCode::CONFLICT);
        }
        proof.update(&buffer[..count]);
        content.update(&buffer[..count]);
    }
    if size != metadata.size || hex::encode(content.finalize()) != challenge.sha256 {
        return Err(StatusCode::CONFLICT);
    }
    Ok(Proof {
        version: 1,
        sha256: challenge.sha256,
        nonce: challenge.nonce,
        size,
        digest: hex::encode(proof.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    use wildbloom_core::{StoreConfig, store::UploadStart};

    fn fixture(bytes: &[u8]) -> (tempfile::TempDir, ProofState, String) {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(StoreConfig {
            root: root.path().join("store"),
            quota_bytes: 1_000_000,
            max_blob_bytes: 1_000_000,
        })
        .unwrap();
        let hash = hex::encode(Sha256::digest(bytes));
        let keys = Keys::parse(&hex::encode([42; 32])).unwrap();
        let UploadStart::Reserved(upload) = store
            .begin_upload(
                &hash,
                bytes.len() as u64,
                &keys.public_key().to_hex(),
                "application/octet-stream",
            )
            .unwrap()
        else {
            panic!("new fixture")
        };
        std::fs::write(upload.temp_path(), bytes).unwrap();
        upload.commit(&hash, bytes.len() as u64).unwrap();
        (
            root,
            ProofState {
                store,
                origin: "https://node.example/".into(),
                active: Arc::new(tokio::sync::Semaphore::new(1)),
                rate: Arc::new(Mutex::new((Instant::now(), 0))),
            },
            hash,
        )
    }
    fn request(hash: &str, nonce: &str, signed_body: Option<&[u8]>) -> Request<Body> {
        let body = serde_json::to_vec(&serde_json::json!({"sha256":hash,"nonce":nonce})).unwrap();
        let keys = Keys::parse(&hex::encode([42; 32])).unwrap();
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags([
                Tag::parse(["u", "https://node.example/storage/v1/proof"]).unwrap(),
                Tag::parse(["method", "POST"]).unwrap(),
                Tag::parse([
                    "payload",
                    &hex::encode(Sha256::digest(signed_body.unwrap_or(&body))),
                ])
                .unwrap(),
            ])
            .finalize(&keys)
            .unwrap();
        Request::builder()
            .method("POST")
            .uri("/storage/v1/proof")
            .header(
                header::AUTHORIZATION,
                format!(
                    "Nostr {}",
                    STANDARD.encode(serde_json::to_vec(&event).unwrap())
                ),
            )
            .body(Body::from(body))
            .unwrap()
    }
    #[tokio::test]
    async fn full_read_matches_independent_vector_and_binds_fresh_nonce() {
        let bytes = b"synthetic encrypted shard\0";
        let (_root, state, hash) = fixture(bytes);
        let nonce = "00".repeat(32);
        let proof = execute(state.clone(), request(&hash, &nonce, None))
            .await
            .unwrap();
        assert_eq!(proof.size, bytes.len() as u64);
        // Shared with the browser's independent node:crypto vector.
        assert_eq!(
            proof.digest,
            "246639ec47ca6f3a6898766ae343c25199396d89e684c58aa019eb85933a29d2"
        );
        let next = execute(state, request(&hash, &"01".repeat(32), None))
            .await
            .unwrap();
        assert_ne!(next.digest, proof.digest);
    }
    #[tokio::test]
    async fn authentication_and_input_errors_never_scan_a_blob() {
        let (_root, state, hash) = fixture(b"data");
        assert!(matches!(
            execute(state.clone(), request(&hash, &"00".repeat(32), Some(b"{}"))).await,
            Err(StatusCode::UNAUTHORIZED)
        ));
        for nonce in ["bad".to_owned(), "AB".repeat(32)] {
            assert!(matches!(
                execute(state.clone(), request(&hash, &nonce, None)).await,
                Err(StatusCode::BAD_REQUEST)
            ));
        }
        let mut no_auth = request(&hash, &"00".repeat(32), None);
        no_auth.headers_mut().remove(header::AUTHORIZATION);
        assert!(execute(state.clone(), no_auth).await.is_err());
        assert_eq!(state.rate.lock().unwrap().1, 0);
        let mut query = request(&hash, &"00".repeat(32), None);
        *query.uri_mut() = "/storage/v1/proof?nonce=ignored".parse().unwrap();
        assert!(matches!(
            execute(state.clone(), query).await,
            Err(StatusCode::BAD_REQUEST)
        ));
        let mut oversized = request(&hash, &"00".repeat(32), None);
        *oversized.body_mut() = Body::from(vec![0u8; 1025]);
        assert!(matches!(
            execute(state, oversized).await,
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        ));
    }
    #[tokio::test]
    async fn missing_and_corrupt_storage_cannot_produce_a_proof() {
        let (_root, state, hash) = fixture(b"data");
        let nonce = "00".repeat(32);
        assert!(matches!(
            execute(state.clone(), request(&"ff".repeat(32), &nonce, None)).await,
            Err(StatusCode::NOT_FOUND)
        ));
        std::fs::write(state.store.blob_path(&hash), b"xxxx").unwrap();
        assert!(matches!(
            execute(state.clone(), request(&hash, &nonce, None)).await,
            Err(StatusCode::CONFLICT)
        ));
        std::fs::write(state.store.blob_path(&hash), b"shorter?").unwrap();
        assert!(matches!(
            execute(state, request(&hash, &nonce, None)).await,
            Err(StatusCode::CONFLICT)
        ));
    }
    #[tokio::test]
    async fn admission_is_bounded_and_audit_responses_are_never_cacheable() {
        let (_root, state, hash) = fixture(b"data");
        let nonce = "00".repeat(32);
        let permit = state.active.acquire().await.unwrap();
        assert!(matches!(
            execute(state.clone(), request(&hash, &nonce, None)).await,
            Err(StatusCode::TOO_MANY_REQUESTS)
        ));
        drop(permit);
        for _ in 0..6 {
            assert!(
                execute(state.clone(), request(&hash, &nonce, None))
                    .await
                    .is_ok()
            );
        }
        let response = prove(State(state.clone()), request(&hash, &nonce, None)).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        *state.rate.lock().unwrap() = (Instant::now() - Duration::from_secs(61), 6);
        assert_eq!(
            prove(State(state), request(&hash, &nonce, None))
                .await
                .status(),
            StatusCode::OK
        );
    }
}
