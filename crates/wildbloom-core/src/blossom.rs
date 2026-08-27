use crate::{
    auth::{AuthError, AuthPolicy},
    store::{BlobMetadata, Store, StoreError, StoreStats, UploadStart},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State, rejection::JsonRejection},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{
            ACCEPT_RANGES, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE,
            CONTENT_TYPE, ETAG, RANGE,
        },
    },
    response::{IntoResponse, Response},
    routing::{get, put},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::SeekFrom,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    task::spawn_blocking,
};
use tokio_util::io::ReaderStream;
use tower_http::cors::{Any, CorsLayer};
use url::Url;

static X_SHA_256: HeaderName = HeaderName::from_static("x-sha-256");

#[derive(Debug, Clone)]
pub struct BlossomConfig {
    pub public_base_url: Url,
    pub accepted_server_names: Vec<String>,
    /// A loopback `socks5h://` proxy enables onion-only BUD-04 mirroring.
    pub mirror_proxy: Option<Url>,
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<InnerState>,
}

struct InnerState {
    store: Store,
    public_base_url: Url,
    auth: AuthPolicy,
    mirror_client: Option<reqwest::Client>,
}

#[derive(Debug, thiserror::Error)]
pub enum BlossomConfigError {
    #[error("mirror proxy must be a loopback socks5h URL")]
    UnsafeMirrorProxy,
    #[error("failed to configure the mirror client: {0}")]
    MirrorClient(#[from] reqwest::Error),
}

#[derive(Debug, Serialize)]
struct ServerInfo {
    name: &'static str,
    software: &'static str,
    version: &'static str,
    blossom: [&'static str; 4],
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    storage: StoreStats,
}

#[derive(Debug, Serialize)]
struct BlobDescriptor {
    url: String,
    sha256: String,
    size: u64,
    #[serde(rename = "type")]
    content_type: String,
    uploaded: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorRequest {
    url: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: &'static str,
    range_size: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
}

impl AppState {
    pub fn new(store: Store, config: BlossomConfig) -> Result<Self, BlossomConfigError> {
        let auth = AuthPolicy::new(config.accepted_server_names);
        let mirror_client = config.mirror_proxy.map(build_mirror_client).transpose()?;
        Ok(Self {
            inner: Arc::new(InnerState {
                store,
                public_base_url: config.public_base_url,
                auth,
                mirror_client,
            }),
        })
    }

    pub fn store(&self) -> &Store {
        &self.inner.store
    }
}

pub fn router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::HEAD, Method::PUT, Method::OPTIONS])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            CONTENT_LENGTH,
            X_SHA_256.clone(),
        ])
        .expose_headers([
            CONTENT_LENGTH,
            CONTENT_RANGE,
            CONTENT_TYPE,
            ETAG,
            ACCEPT_RANGES,
        ]);

    Router::new()
        .route("/", get(server_info))
        .route("/healthz", get(health))
        .route("/upload", put(upload))
        .route("/mirror", put(mirror))
        .route("/{blob}", get(get_blob).head(head_blob))
        .layer(cors)
        .with_state(state)
}

async fn server_info() -> Json<ServerInfo> {
    Json(ServerInfo {
        name: "Wildbloom Node",
        software: "https://github.com/forgesworn/wildbloom-node",
        version: env!("CARGO_PKG_VERSION"),
        blossom: ["BUD-01", "BUD-02", "BUD-04", "BUD-11"],
    })
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    let store = state.inner.store.clone();
    let storage = spawn_blocking(move || store.stats())
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::from_store)?;
    Ok(Json(HealthResponse {
        status: "ok",
        storage,
    }))
}

async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let expected_hash = header_str(&headers, &X_SHA_256, "missing X-SHA-256 header")?;
    if !is_canonical_hash(expected_hash) {
        return Err(ApiError::bad_request("invalid X-SHA-256 header"));
    }
    let expected_hash = expected_hash.to_owned();
    let expected_size = header_str(&headers, &CONTENT_LENGTH, "missing Content-Length header")?
        .parse::<u64>()
        .map_err(|_| ApiError::bad_request("invalid Content-Length header"))?;
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .unwrap_or("application/octet-stream")
        .to_owned();
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let verified = state
        .inner
        .auth
        .verify_upload(authorization, &expected_hash, unix_time())
        .map_err(ApiError::from_auth)?;

    let store = state.inner.store.clone();
    let begin_hash = expected_hash.clone();
    let owner = verified.owner_pubkey;
    let begin_content_type = content_type.clone();
    let started = spawn_blocking(move || {
        store.begin_upload(&begin_hash, expected_size, &owner, &begin_content_type)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_store)?;

    match started {
        UploadStart::Existing(metadata) => {
            let descriptor = descriptor(&state, metadata);
            Ok((StatusCode::OK, Json(descriptor)).into_response())
        }
        UploadStart::Reserved(reservation) => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                options.mode(0o600);
            }
            let mut file = options
                .open(reservation.temp_path())
                .await
                .map_err(|_| ApiError::internal())?;
            let mut stream = body.into_data_stream();
            let mut hasher = Sha256::new();
            let mut received = 0_u64;

            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| ApiError::bad_request("upload stream failed"))?;
                let chunk_len =
                    u64::try_from(chunk.len()).map_err(|_| ApiError::payload_too_large())?;
                received = received
                    .checked_add(chunk_len)
                    .ok_or_else(ApiError::payload_too_large)?;
                if received > reservation.expected_size() {
                    return Err(ApiError::bad_request("body exceeds Content-Length"));
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|_| ApiError::internal())?;
            }
            if received != reservation.expected_size() {
                return Err(ApiError::bad_request("body does not match Content-Length"));
            }
            file.flush().await.map_err(|_| ApiError::internal())?;
            file.sync_all().await.map_err(|_| ApiError::internal())?;
            drop(file);

            let actual_hash = hex::encode(hasher.finalize());
            let metadata = spawn_blocking(move || reservation.commit(&actual_hash, received))
                .await
                .map_err(|_| ApiError::internal())?
                .map_err(ApiError::from_store)?;
            let descriptor = descriptor(&state, metadata);
            Ok((StatusCode::CREATED, Json(descriptor)).into_response())
        }
    }
}

async fn mirror(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<MirrorRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let client = state
        .inner
        .mirror_client
        .as_ref()
        .ok_or_else(|| ApiError::forbidden("mirroring is disabled"))?;
    let Json(payload) = payload.map_err(|_| ApiError::bad_request("invalid mirror request"))?;
    if payload.url.len() > 2048 {
        return Err(ApiError::bad_request("mirror URL is too long"));
    }
    let source =
        Url::parse(&payload.url).map_err(|_| ApiError::bad_request("invalid mirror URL"))?;
    let expected_hash = mirror_hash_from_url(&source)
        .ok_or_else(|| ApiError::forbidden("mirror source is not permitted"))?
        .to_owned();
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let verified = state
        .inner
        .auth
        .verify_upload(authorization, &expected_hash, unix_time())
        .map_err(ApiError::from_auth)?;

    let response = client
        .get(source)
        .send()
        .await
        .map_err(|error| ApiError::bad_gateway(error, "mirror origin could not be reached"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(ApiError::bad_gateway_status(response.status()));
    }
    let expected_size = response
        .content_length()
        .ok_or_else(|| ApiError::bad_gateway_message("mirror origin omitted Content-Length"))?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .unwrap_or("application/octet-stream")
        .to_owned();

    let store = state.inner.store.clone();
    let begin_hash = expected_hash.clone();
    let owner = verified.owner_pubkey;
    let begin_content_type = content_type.clone();
    let started = spawn_blocking(move || {
        store.begin_upload(&begin_hash, expected_size, &owner, &begin_content_type)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_store)?;

    match started {
        UploadStart::Existing(metadata) => {
            let descriptor = descriptor(&state, metadata);
            Ok((StatusCode::OK, Json(descriptor)).into_response())
        }
        UploadStart::Reserved(reservation) => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options
                .open(reservation.temp_path())
                .await
                .map_err(|_| ApiError::internal())?;
            let mut stream = response.bytes_stream();
            let mut hasher = Sha256::new();
            let mut received = 0_u64;

            while let Some(chunk) = stream.next().await {
                let chunk = chunk
                    .map_err(|error| ApiError::bad_gateway(error, "mirror origin stream failed"))?;
                let chunk_len =
                    u64::try_from(chunk.len()).map_err(|_| ApiError::payload_too_large())?;
                received = received
                    .checked_add(chunk_len)
                    .ok_or_else(ApiError::payload_too_large)?;
                if received > reservation.expected_size() {
                    return Err(ApiError::bad_gateway_message(
                        "mirror origin exceeded Content-Length",
                    ));
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|_| ApiError::internal())?;
            }
            if received != reservation.expected_size() {
                return Err(ApiError::bad_gateway_message(
                    "mirror origin did not match Content-Length",
                ));
            }
            file.flush().await.map_err(|_| ApiError::internal())?;
            file.sync_all().await.map_err(|_| ApiError::internal())?;
            drop(file);

            let actual_hash = hex::encode(hasher.finalize());
            if actual_hash != expected_hash {
                return Err(ApiError::conflict("mirror origin returned the wrong blob"));
            }
            let metadata = spawn_blocking(move || reservation.commit(&actual_hash, received))
                .await
                .map_err(|_| ApiError::internal())?
                .map_err(ApiError::from_store)?;
            let descriptor = descriptor(&state, metadata);
            Ok((StatusCode::CREATED, Json(descriptor)).into_response())
        }
    }
}

async fn get_blob(
    State(state): State<AppState>,
    AxumPath(blob): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    serve_blob(state, blob, headers, false).await
}

async fn head_blob(
    State(state): State<AppState>,
    AxumPath(blob): AxumPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    serve_blob(state, blob, headers, true).await
}

async fn serve_blob(
    state: AppState,
    blob: String,
    headers: HeaderMap,
    head_only: bool,
) -> Result<Response, ApiError> {
    let hash = hash_from_path(&blob).ok_or_else(|| ApiError::not_found("blob not found"))?;
    let store = state.inner.store.clone();
    let lookup_hash = hash.to_owned();
    let metadata = spawn_blocking(move || store.get(&lookup_hash))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::from_store)?
        .ok_or_else(|| ApiError::not_found("blob not found"))?;

    let range = match headers.get(RANGE) {
        Some(value) => Some(
            parse_range(
                value
                    .to_str()
                    .map_err(|_| ApiError::range_not_satisfiable(metadata.size))?,
                metadata.size,
            )
            .ok_or_else(|| ApiError::range_not_satisfiable(metadata.size))?,
        ),
        None => None,
    };
    let (start, end, status) = range
        .map(|(start, end)| (start, end, StatusCode::PARTIAL_CONTENT))
        .unwrap_or_else(|| (0, metadata.size.saturating_sub(1), StatusCode::OK));
    let response_size = if metadata.size == 0 {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    };

    let body = if head_only || response_size == 0 {
        Body::empty()
    } else {
        let mut file = File::open(state.inner.store.blob_path(hash))
            .await
            .map_err(|_| ApiError::internal())?;
        file.seek(SeekFrom::Start(start))
            .await
            .map_err(|_| ApiError::internal())?;
        Body::from_stream(ReaderStream::new(file.take(response_size)))
    };

    let mut response = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, metadata.content_type)
        .header(CONTENT_LENGTH, response_size)
        .header(ACCEPT_RANGES, "bytes")
        .header(CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(ETAG, format!("\"{}\"", metadata.sha256));
    if status == StatusCode::PARTIAL_CONTENT {
        response = response.header(
            CONTENT_RANGE,
            format!("bytes {start}-{end}/{}", metadata.size),
        );
    }
    response.body(body).map_err(|_| ApiError::internal())
}

fn build_mirror_client(proxy_url: Url) -> Result<reqwest::Client, BlossomConfigError> {
    if proxy_url.scheme() != "socks5h"
        || !proxy_url.username().is_empty()
        || proxy_url.password().is_some()
        || !matches!(proxy_url.path(), "" | "/")
        || proxy_url.query().is_some()
        || proxy_url.fragment().is_some()
        || !proxy_url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
        || proxy_url.port().is_none()
    {
        return Err(BlossomConfigError::UnsafeMirrorProxy);
    }
    let proxy = reqwest::Proxy::all(proxy_url.as_str())?;
    Ok(reqwest::Client::builder()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(10 * 60))
        .user_agent(concat!("wildbloom-node/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

fn mirror_hash_from_url(url: &Url) -> Option<&str> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?;
    let onion = host.ends_with(".onion");
    if (!onion && url.scheme() != "https") || !is_safe_mirror_host(host, onion) {
        return None;
    }
    let blob = url.path_segments()?.next_back()?;
    hash_from_path(blob)
}

fn is_safe_mirror_host(host: &str, onion: bool) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return false;
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if onion && (labels.len() != 2 || labels[0].len() != 56) {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn descriptor(state: &AppState, metadata: BlobMetadata) -> BlobDescriptor {
    let extension = extension_for(&metadata.content_type);
    let url = format!(
        "{}/{}.{}",
        state.inner.public_base_url.as_str().trim_end_matches('/'),
        metadata.sha256,
        extension
    );
    BlobDescriptor {
        url,
        sha256: metadata.sha256,
        size: metadata.size,
        content_type: metadata.content_type,
        uploaded: metadata.uploaded,
    }
}

fn hash_from_path(path: &str) -> Option<&str> {
    let (hash, suffix) = if path.len() == 64 {
        (path, None)
    } else {
        let (hash, suffix) = path.split_once('.')?;
        (hash, Some(suffix))
    };
    if suffix.is_some_and(str::is_empty) || !is_canonical_hash(hash) {
        return None;
    }
    Some(hash)
}

fn is_canonical_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !hash.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    if size == 0 || !value.starts_with("bytes=") || value.contains(',') {
        return None;
    }
    let (start, end) = value.strip_prefix("bytes=")?.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<u64>().ok()?;
        if suffix == 0 {
            return None;
        }
        let suffix = suffix.min(size);
        return Some((size - suffix, size - 1));
    }
    let start = start.parse::<u64>().ok()?;
    if start >= size {
        return None;
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().ok()?.min(size - 1)
    };
    (start <= end).then_some((start, end))
}

fn extension_for(content_type: &str) -> &'static str {
    match content_type.split(';').next().unwrap_or_default().trim() {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/avif" => "avif",
        "audio/mpeg" => "mp3",
        "audio/ogg" => "ogg",
        "audio/wav" => "wav",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "application/json" => "json",
        "text/markdown" => "md",
        "text/plain" => "txt",
        _ => "bin",
    }
}

fn header_str<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
    missing_message: &'static str,
) -> Result<&'a str, ApiError> {
    headers
        .get(name)
        .ok_or_else(|| ApiError::bad_request(missing_message))?
        .to_str()
        .map_err(|_| ApiError::bad_request(missing_message))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl ApiError {
    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
            range_size: None,
        }
    }

    fn not_found(message: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
            range_size: None,
        }
    }

    fn forbidden(message: &'static str) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message,
            range_size: None,
        }
    }

    fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message,
            range_size: None,
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: "upload is too large",
            range_size: None,
        }
    }

    fn range_not_satisfiable(size: u64) -> Self {
        tracing::debug!(size, "rejected invalid byte range");
        Self {
            status: StatusCode::RANGE_NOT_SATISFIABLE,
            message: "range not satisfiable",
            range_size: Some(size),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal storage error",
            range_size: None,
        }
    }

    fn bad_gateway(error: reqwest::Error, message: &'static str) -> Self {
        tracing::warn!(reason = %error, "failed to fetch Blossom mirror origin");
        Self::bad_gateway_message(message)
    }

    fn bad_gateway_status(status: reqwest::StatusCode) -> Self {
        tracing::debug!(%status, "Blossom mirror origin returned an unusable status");
        Self::bad_gateway_message("mirror origin returned an unusable response")
    }

    fn bad_gateway_message(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message,
            range_size: None,
        }
    }

    fn from_auth(error: AuthError) -> Self {
        tracing::debug!(reason = %error, "rejected Blossom authorisation");
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid Blossom authorisation",
            range_size: None,
        }
    }

    fn from_store(error: StoreError) -> Self {
        match error {
            StoreError::BlobTooLarge { .. } => Self::payload_too_large(),
            StoreError::QuotaExceeded => Self {
                status: StatusCode::INSUFFICIENT_STORAGE,
                message: "storage quota is full",
                range_size: None,
            },
            StoreError::InvalidHash | StoreError::LengthMismatch | StoreError::HashMismatch => {
                Self::bad_request("upload does not match its declared metadata")
            }
            StoreError::MissingBlob => Self::not_found("blob not found"),
            error => {
                tracing::error!(reason = %error, "Blossom storage operation failed");
                Self::internal()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response();
        if let Some(size) = self.range_size
            && let Ok(value) = HeaderValue::from_str(&format!("bytes */{size}"))
        {
            response.headers_mut().insert(CONTENT_RANGE, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use http_body_util::BodyExt;
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
    use tower::ServiceExt;

    fn upload_authorization(hash: &str, created_at: u64) -> String {
        let keys = Keys::parse(&format!("{:064x}", 1)).unwrap();
        let tags = [
            vec!["t", "upload"],
            vec!["x", hash],
            vec!["server", "node.example"],
        ]
        .into_iter()
        .map(|tag| Tag::parse(tag).unwrap())
        .chain(std::iter::once(
            Tag::parse(["expiration", &(created_at + 120).to_string()]).unwrap(),
        ));
        let event = EventBuilder::new(Kind::Custom(24_242), "Upload blob")
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .finalize(&keys)
            .unwrap();
        format!(
            "Nostr {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
        )
    }

    #[test]
    fn parses_single_byte_ranges() {
        assert_eq!(parse_range("bytes=0-4", 10), Some((0, 4)));
        assert_eq!(parse_range("bytes=5-", 10), Some((5, 9)));
        assert_eq!(parse_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_range("bytes=9-20", 10), Some((9, 9)));
        assert_eq!(parse_range("bytes=10-", 10), None);
        assert_eq!(parse_range("bytes=1-2,4-5", 10), None);
    }

    #[test]
    fn accepts_hashes_with_optional_extensions() {
        let hash = "a".repeat(64);
        assert_eq!(hash_from_path(&hash), Some(hash.as_str()));
        assert_eq!(hash_from_path(&format!("{hash}.webp")), Some(hash.as_str()));
        assert_eq!(hash_from_path(&format!("{hash}.")), None);
        assert_eq!(hash_from_path(&"A".repeat(64)), None);
    }

    #[test]
    fn mirror_policy_accepts_hash_addressed_onions_and_public_https() {
        let hash = "a".repeat(64);
        let onion = Url::parse(&format!("http://{}.onion/{hash}.bin", "b".repeat(56))).unwrap();
        assert_eq!(mirror_hash_from_url(&onion), Some(hash.as_str()));
        let public = Url::parse(&format!("https://blossom.example/{hash}.bin")).unwrap();
        assert_eq!(mirror_hash_from_url(&public), Some(hash.as_str()));
        assert!(
            mirror_hash_from_url(
                &Url::parse(&format!("http://blossom.example/{hash}.bin")).unwrap()
            )
            .is_none()
        );
        assert!(mirror_hash_from_url(&Url::parse("http://127.0.0.1/private").unwrap()).is_none());
        assert!(
            mirror_hash_from_url(
                &Url::parse(&format!(
                    "http://{}.onion/{hash}.bin?swap=1",
                    "b".repeat(56)
                ))
                .unwrap()
            )
            .is_none()
        );
        assert!(
            mirror_hash_from_url(
                &Url::parse(&format!("http://user@{}.onion/{hash}.bin", "b".repeat(56))).unwrap()
            )
            .is_none()
        );
    }

    #[test]
    fn mirror_proxy_must_be_loopback_socks5h() {
        let loopback = Url::parse("socks5h://127.0.0.1:39050").unwrap();
        assert!(
            build_mirror_client(loopback.clone()).is_ok(),
            "rejected {loopback:?}"
        );
        assert!(matches!(
            build_mirror_client(Url::parse("http://127.0.0.1:39050").unwrap()),
            Err(BlossomConfigError::UnsafeMirrorProxy)
        ));
        assert!(matches!(
            build_mirror_client(Url::parse("socks5h://192.0.2.1:39050").unwrap()),
            Err(BlossomConfigError::UnsafeMirrorProxy)
        ));
    }

    #[tokio::test]
    async fn signed_upload_round_trips_and_supports_ranges() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(crate::store::StoreConfig {
            root: directory.path().join("data"),
            quota_bytes: 1024,
            max_blob_bytes: 1024,
        })
        .unwrap();
        let app = router(
            AppState::new(
                store,
                BlossomConfig {
                    public_base_url: Url::parse("http://node.example/").unwrap(),
                    accepted_server_names: vec!["node.example".into()],
                    mirror_proxy: None,
                },
            )
            .unwrap(),
        );
        let bytes = b"hello wildbloom";
        let hash = hex::encode(Sha256::digest(bytes));
        let now = unix_time();
        let upload = Request::builder()
            .method(Method::PUT)
            .uri("/upload")
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, bytes.len())
            .header(&X_SHA_256, &hash)
            .header(AUTHORIZATION, upload_authorization(&hash, now))
            .body(Body::from(bytes.as_slice()))
            .unwrap();
        let response = app.clone().oneshot(upload).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let descriptor: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(descriptor["sha256"], hash);
        assert_eq!(descriptor["url"], format!("http://node.example/{hash}.txt"));

        let download = Request::builder()
            .uri(format!("/{hash}.txt"))
            .header(RANGE, "bytes=6-14")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(download).await.unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[CONTENT_RANGE], "bytes 6-14/15");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            &bytes[6..15]
        );
    }
}
