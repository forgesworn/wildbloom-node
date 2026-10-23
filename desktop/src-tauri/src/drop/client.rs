//! HTTP to Wildbloom nodes: BUD-11 signed Blossom requests (upload, delete,
//! list), unsigned reads (HEAD, GET, health), NIP-98 requests (grant status,
//! pairing creation grants) and the owner's grant event.
//!
//! Authorisation headers are bearer material.  They are built, sent and
//! dropped here, and never logged, formatted into errors or returned.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use futures_util::StreamExt as _;
use nostr::prelude::{EventBuilder, FinalizeEvent as _, Keys, Kind, Tag, Timestamp};
use reqwest::{Body, Client, StatusCode, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt as _;
use url::{Host, Url};

/// BUD-11's authorisation kind.
pub const BLOSSOM_AUTH_KIND: u16 = 24_242;
/// The node accepts at most five minutes between `created_at` and expiry.
const BLOSSOM_AUTH_LIFETIME: u64 = 300;
/// The media type every envelope is stored as.
pub const ENVELOPE_MEDIA_TYPE: &str = wildbloom_envelope::MEDIA_TYPE;

/// A node origin and the exact server name its BUD-11 events must carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEndpoint {
    base: Url,
    server: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("the address is not a valid node origin")]
    Invalid,
    #[error("the address must use https")]
    NotHttps,
}

impl NodeEndpoint {
    /// An HTTPS origin (plain HTTP only for loopback when allowed) with no
    /// credentials, query or fragment.  A path is refused: nodes are origins.
    pub fn parse(text: &str, allow_loopback_http: bool) -> Result<Self, EndpointError> {
        let mut url = Url::parse(text.trim()).map_err(|_| EndpointError::Invalid)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            return Err(EndpointError::Invalid);
        }
        let host = url.host().ok_or(EndpointError::Invalid)?.to_owned();
        let loopback = match &host {
            Host::Domain(name) => *name == "localhost",
            Host::Ipv4(ip) => ip.is_loopback(),
            Host::Ipv6(ip) => ip.is_loopback(),
        };
        match url.scheme() {
            "https" => {}
            "http" if allow_loopback_http && loopback => {}
            "http" => return Err(EndpointError::NotHttps),
            _ => return Err(EndpointError::Invalid),
        }
        url.set_path("/");
        let server = url.host_str().ok_or(EndpointError::Invalid)?.to_owned();
        Ok(Self { base: url, server })
    }

    /// A node reached at `base` that names itself `server` in BUD-11 events
    /// (the local node listens on 127.0.0.1 but is named `localhost`).
    pub fn with_server(base: Url, server: String) -> Self {
        Self { base, server }
    }

    pub fn origin(&self) -> &str {
        self.base.as_str()
    }

    pub fn host(&self) -> String {
        match self.base.port() {
            Some(port) => format!("{}:{port}", self.base.host_str().unwrap_or_default()),
            None => self.base.host_str().unwrap_or_default().to_owned(),
        }
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

/// What went wrong talking to a node.  No variant carries a header or body.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    #[error("the node did not answer")]
    Unreachable,
    #[error("a secure connection could not be made")]
    Tls,
    #[error("the node refused the signature")]
    Unauthorised,
    #[error("the node's space is full")]
    Full,
    #[error("the blob is larger than the node accepts")]
    TooLarge,
    #[error("the blob is not on the node")]
    NotFound,
    #[error("the node returned something unexpected")]
    Invalid,
    #[error("the bytes did not match their address")]
    Mismatch,
    #[error("the node answered HTTP {0}")]
    Http(u16),
    #[error("local file error")]
    Io,
    #[error("the operation was cancelled")]
    Cancelled,
}

impl NodeError {
    pub fn from_reqwest(error: &reqwest::Error) -> Self {
        if is_tls(error) {
            Self::Tls
        } else {
            Self::Unreachable
        }
    }

    fn from_status(status: StatusCode) -> Self {
        match status.as_u16() {
            401 | 403 => Self::Unauthorised,
            404 => Self::NotFound,
            413 => Self::TooLarge,
            507 => Self::Full,
            code => Self::Http(code),
        }
    }

    /// Worth retrying later without the owner doing anything.
    pub fn transient(&self) -> bool {
        matches!(self, Self::Unreachable | Self::Http(500..=599))
    }
}

fn is_tls(error: &reqwest::Error) -> bool {
    let mut source: Option<&dyn std::error::Error> = Some(error);
    while let Some(current) = source {
        let text = current.to_string().to_ascii_lowercase();
        if text.contains("certificate") || text.contains("tls") || text.contains("handshake") {
            return true;
        }
        source = current.source();
    }
    false
}

/// The longest a node may go without sending a byte: the wait for response
/// headers on reads, and the gap between body chunks on every transfer.  It
/// is applied per chunk, never across a whole request, so a slow but steady
/// transfer always completes.  (A client-wide reqwest read timeout is not
/// used: it starts at send and an upload's progress does not reset it.)
pub const READ_TIMEOUT: Duration = Duration::from_secs(60);

static STALL_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(READ_TIMEOUT.as_millis() as u64);

fn stall() -> Duration {
    Duration::from_millis(STALL_MS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Tests shorten the stall timeout to exercise it.
#[cfg(test)]
pub(crate) fn set_stall_for_tests(timeout: Duration) {
    STALL_MS.store(
        timeout.as_millis() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Sends a read request, waiting at most the stall timeout for its headers.
async fn send_read(request: reqwest::RequestBuilder) -> Result<reqwest::Response, NodeError> {
    match tokio::time::timeout(stall(), request.send()).await {
        Err(_) => Err(NodeError::Unreachable),
        Ok(result) => result.map_err(|e| NodeError::from_reqwest(&e)),
    }
}

/// The next body chunk, or `Unreachable` if none arrives within the stall
/// timeout.
async fn next_chunk<S>(stream: &mut S) -> Result<Option<bytes::Bytes>, NodeError>
where
    S: futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Unpin,
{
    match tokio::time::timeout(stall(), stream.next()).await {
        Err(_) | Ok(Some(Err(_))) => Err(NodeError::Unreachable),
        Ok(None) => Ok(None),
        Ok(Some(Ok(chunk))) => Ok(Some(chunk)),
    }
}

/// How long an upload of `size` bytes may take in all: ten minutes plus one
/// second per 16 KiB, so a stalled receiver cannot hold a body open forever.
pub fn upload_deadline(size: u64) -> Duration {
    Duration::from_secs(600 + size / (16 * 1024))
}

/// The HTTP client every Drop request uses: no ambient proxy, no redirects,
/// bounded connect time and no referrer.
pub fn http_client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("wildbloom-drop/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("the HTTP client configuration is static")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn tag(parts: &[&str]) -> Tag {
    Tag::parse(parts.iter().copied()).expect("static tag shapes are valid")
}

/// A BUD-11 `Authorization` value for `verb` over `hashes` on `server`.
pub fn blossom_auth(keys: &Keys, verb: &str, hashes: &[&str], server: &str) -> String {
    let created = now();
    let expiration = (created + BLOSSOM_AUTH_LIFETIME).to_string();
    let mut tags = vec![tag(&["t", verb])];
    for hash in hashes {
        tags.push(tag(&["x", hash]));
    }
    tags.push(tag(&["server", server]));
    tags.push(tag(&["expiration", &expiration]));
    let content = match verb {
        "upload" => "Keep an encrypted Wildbloom Drop copy",
        "delete" => "Remove a Wildbloom Drop copy",
        "list" => "List Wildbloom Drop copies",
        _ => "Wildbloom Drop",
    };
    let event = EventBuilder::new(Kind::Custom(BLOSSOM_AUTH_KIND), content)
        .tags(tags)
        .custom_created_at(Timestamp::from(created))
        .finalize(keys)
        .expect("signing with local keys cannot fail");
    format!("Nostr {}", URL_SAFE_NO_PAD.encode(event.as_json()))
}

/// A NIP-98 `Authorization` value in the checkout profile: exact `u` and
/// `method`, a `payload` digest for POST, empty content, standard base64.
pub fn http_auth(keys: &Keys, url: &str, method: &str, body: &[u8]) -> String {
    let mut tags = vec![tag(&["u", url]), tag(&["method", method])];
    if method == "POST" {
        let digest = super::hex_lower(&Sha256::digest(body));
        tags.push(tag(&["payload", &digest]));
    }
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::from(now()))
        .finalize(keys)
        .expect("signing with local keys cannot fail");
    format!("Nostr {}", STANDARD.encode(event.as_json()))
}

#[derive(Debug, Deserialize)]
struct Health {
    storage: HealthStorage,
}

#[derive(Debug, Deserialize)]
struct HealthStorage {
    #[allow(dead_code)]
    blobs: u64,
    bytes: u64,
    quota_bytes: u64,
}

/// What a node's health endpoint says about its storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeHealth {
    pub bytes: u64,
    pub quota_bytes: u64,
}

/// `Unreachable`/`Tls` when nothing answered, `Invalid` when something
/// answered that is not a Wildbloom Node.
pub async fn health(http: &Client, node: &NodeEndpoint) -> Result<NodeHealth, NodeError> {
    let response = http
        .get(node.url("healthz"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    if response.status() != StatusCode::OK {
        return Err(NodeError::Invalid);
    }
    let bytes = read_bounded(response, 16 * 1024).await?;
    let health: Health = serde_json::from_slice(&bytes).map_err(|_| NodeError::Invalid)?;
    Ok(NodeHealth {
        bytes: health.storage.bytes,
        quota_bytes: health.storage.quota_bytes,
    })
}

async fn read_bounded(response: reqwest::Response, max: usize) -> Result<Vec<u8>, NodeError> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(NodeError::Invalid);
    }
    let mut out = Vec::new();
    let mut stream = Box::pin(response.bytes_stream());
    while let Some(chunk) = next_chunk(&mut stream).await? {
        if out.len() + chunk.len() > max {
            return Err(NodeError::Invalid);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// `PUT /upload` (BUD-02 + BUD-11) of exactly `size` bytes addressed `sha256`.
pub async fn upload(
    http: &Client,
    node: &NodeEndpoint,
    keys: &Keys,
    sha256: &str,
    size: u64,
    body: Body,
) -> Result<(), NodeError> {
    let auth = blossom_auth(keys, "upload", &[sha256], node.server());
    let response = http
        .put(node.url("upload"))
        .header(header::AUTHORIZATION, auth)
        .header("X-SHA-256", sha256)
        .header(header::CONTENT_LENGTH, size)
        .header(header::CONTENT_TYPE, ENVELOPE_MEDIA_TYPE)
        .timeout(upload_deadline(size))
        .body(body)
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    match response.status() {
        StatusCode::OK | StatusCode::CREATED => Ok(()),
        status => Err(NodeError::from_status(status)),
    }
}

/// `HEAD /<sha256>`: the stored size, or `None` for 404.
pub async fn head(
    http: &Client,
    node: &NodeEndpoint,
    sha256: &str,
) -> Result<Option<u64>, NodeError> {
    let response = http
        .head(node.url(sha256))
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    match response.status() {
        StatusCode::OK => response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .map(Some)
            .ok_or(NodeError::Invalid),
        StatusCode::NOT_FOUND => Ok(None),
        status => Err(NodeError::from_status(status)),
    }
}

/// `DELETE /<sha256>` (BUD-12): removes this signer's claim.  Already gone
/// counts as done.
pub async fn delete(
    http: &Client,
    node: &NodeEndpoint,
    keys: &Keys,
    sha256: &str,
) -> Result<(), NodeError> {
    let auth = blossom_auth(keys, "delete", &[sha256], node.server());
    let response = http
        .delete(node.url(sha256))
        .header(header::AUTHORIZATION, auth)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    match response.status() {
        StatusCode::OK | StatusCode::NO_CONTENT | StatusCode::NOT_FOUND => Ok(()),
        status => Err(NodeError::from_status(status)),
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Listed {
    pub sha256: String,
    pub size: u64,
}

/// `GET /list/<pubkey>` (BUD-12): every active claim of the signing key.
pub async fn list(
    http: &Client,
    node: &NodeEndpoint,
    keys: &Keys,
) -> Result<Vec<Listed>, NodeError> {
    let pubkey = keys.public_key().to_hex();
    let mut out: Vec<Listed> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..1000 {
        let mut url = node.url(&format!("list/{pubkey}?limit=100"));
        if let Some(cursor) = &cursor {
            url.push_str(&format!("&cursor={cursor}"));
        }
        let auth = blossom_auth(keys, "list", &[], node.server());
        let response = http
            .get(url)
            .header(header::AUTHORIZATION, auth)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| NodeError::from_reqwest(&e))?;
        if response.status() != StatusCode::OK {
            return Err(NodeError::from_status(response.status()));
        }
        let page: Vec<Listed> = serde_json::from_slice(&read_bounded(response, 1024 * 1024).await?)
            .map_err(|_| NodeError::Invalid)?;
        if page
            .iter()
            .any(|entry| super::parse_sha256(&entry.sha256).is_none())
        {
            return Err(NodeError::Invalid);
        }
        let done = page.len() < 100;
        cursor = page.last().map(|entry| entry.sha256.clone());
        out.extend(page);
        if done || cursor.is_none() {
            return Ok(out);
        }
    }
    Err(NodeError::Invalid)
}

/// Streams `/<sha256>` into `dest`, checking the exact size and SHA-256 of
/// what arrived.  `progress(received)` is called as bytes arrive.
pub async fn download_to_file(
    http: &Client,
    node: &NodeEndpoint,
    sha256: &str,
    size: u64,
    dest: &Path,
    progress: &mut (dyn FnMut(u64) + Send),
) -> Result<(), NodeError> {
    let response = send_read(http.get(node.url(sha256))).await?;
    if response.status() != StatusCode::OK {
        return Err(NodeError::from_status(response.status()));
    }
    if response.content_length().is_some_and(|n| n != size) {
        return Err(NodeError::Mismatch);
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(dest)
        .await
        .map_err(|_| NodeError::Io)?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let mut stream = Box::pin(response.bytes_stream());
    while let Some(chunk) = next_chunk(&mut stream).await? {
        received += chunk.len() as u64;
        if received > size {
            return Err(NodeError::Mismatch);
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|_| NodeError::Io)?;
        progress(received);
    }
    file.flush().await.map_err(|_| NodeError::Io)?;
    file.sync_all().await.map_err(|_| NodeError::Io)?;
    if received != size || super::hex_lower(&hasher.finalize()) != sha256 {
        return Err(NodeError::Mismatch);
    }
    Ok(())
}

/// Fetches a small blob (a key list) into memory, checking its SHA-256.
pub async fn download_bytes(
    http: &Client,
    node: &NodeEndpoint,
    sha256: &str,
    max: usize,
) -> Result<Vec<u8>, NodeError> {
    let response = send_read(http.get(node.url(sha256))).await?;
    if response.status() != StatusCode::OK {
        return Err(NodeError::from_status(response.status()));
    }
    let bytes = read_bounded(response, max).await?;
    if super::hex_lower(&Sha256::digest(&bytes)) != sha256 {
        return Err(NodeError::Mismatch);
    }
    Ok(bytes)
}

/// A file as an upload body that reports bytes as they are read.
pub async fn file_body(
    path: &Path,
    mut progress: impl FnMut(u64) + Send + 'static,
) -> Result<Body, NodeError> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| NodeError::Io)?;
    let mut sent = 0u64;
    // A local disk read that stalls fails the upload rather than hanging it.
    let stream = tokio_stream_from(file).map(move |chunk| {
        if let Ok(bytes) = &chunk {
            sent += bytes.len() as u64;
            progress(sent);
        }
        chunk
    });
    Ok(Body::wrap_stream(stream))
}

/// A GET response from another node as an upload body, so a copy between
/// nodes never lands on disk.  The receiving node hashes every byte.
pub async fn relay_body(
    http: &Client,
    from: &NodeEndpoint,
    sha256: &str,
    size: u64,
    mut progress: impl FnMut(u64) + Send + 'static,
) -> Result<Body, NodeError> {
    let response = send_read(http.get(from.url(sha256))).await?;
    if response.status() != StatusCode::OK {
        return Err(NodeError::from_status(response.status()));
    }
    if response.content_length().is_some_and(|n| n != size) {
        return Err(NodeError::Mismatch);
    }
    // A source that stops sending ends the upload (each chunk must arrive
    // within the stall timeout); a steady one may take as long as it needs.
    let source = Box::pin(response.bytes_stream());
    let stream = futures_util::stream::unfold(Some((source, 0u64)), |state| async move {
        let (mut source, sent) = state?;
        match next_chunk(&mut source).await {
            Ok(None) => None,
            Ok(Some(chunk)) => {
                let sent = sent + chunk.len() as u64;
                Some(((Ok(chunk), sent), Some((source, sent))))
            }
            Err(_) => Some((
                (
                    Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
                    sent,
                ),
                None,
            )),
        }
    })
    .map(move |(item, sent): (std::io::Result<bytes::Bytes>, u64)| {
        progress(sent);
        item
    });
    Ok(Body::wrap_stream(stream))
}

fn tokio_stream_from(
    file: tokio::fs::File,
) -> impl futures_util::Stream<Item = std::io::Result<bytes::Bytes>> + Send {
    futures_util::stream::unfold(Some(file), |state| async move {
        use tokio::io::AsyncReadExt as _;
        let mut file = state?;
        let mut buffer = vec![0u8; 256 * 1024];
        let read = tokio::time::timeout(stall(), file.read(&mut buffer))
            .await
            .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        match read {
            Ok(0) => None,
            Ok(n) => {
                buffer.truncate(n);
                Some((Ok(bytes::Bytes::from(buffer)), Some(file)))
            }
            Err(error) => Some((Err(error), None)),
        }
    })
}

// ------------------------------------------------------------ grants

/// The node's answer to a grant, revoke or status request.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GrantStatus {
    pub device: String,
    #[serde(default)]
    pub recovery: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    pub state: String,
}

/// Why the online node did not take a grant.  `reason` is the node's own
/// short `x-reason` text, which never carries request material.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("the node did not answer")]
    Unreachable,
    /// 401: a bad signature or a signer that is not an owner.
    #[error("the node does not recognise the signer as its owner")]
    NotOwner { reason: Option<String> },
    #[error("the node refused the approval")]
    Refused { status: u16, reason: Option<String> },
    #[error("the node returned something unexpected")]
    Invalid,
}

fn reason(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get("x-reason")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(200).collect())
}

/// `POST /grants/v1` with one owner-signed kind 27540 grant event.
pub async fn post_grant(
    http: &Client,
    node: &NodeEndpoint,
    event_json: &str,
) -> Result<GrantStatus, GrantError> {
    let response = http
        .post(node.url("grants/v1"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(event_json.to_owned())
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|_| GrantError::Unreachable)?;
    let status = response.status();
    if status == StatusCode::OK || status == StatusCode::CREATED {
        let bytes = read_bounded(response, 16 * 1024)
            .await
            .map_err(|_| GrantError::Invalid)?;
        return serde_json::from_slice(&bytes).map_err(|_| GrantError::Invalid);
    }
    let reason = reason(&response);
    if status == StatusCode::UNAUTHORIZED {
        return Err(GrantError::NotOwner { reason });
    }
    Err(GrantError::Refused {
        status: status.as_u16(),
        reason,
    })
}

/// `GET /grants/v1/<device>` with a NIP-98 event from the device.  `None`
/// when the node has no grant for it (403 or 404).
pub async fn grant_status(
    http: &Client,
    node: &NodeEndpoint,
    device: &Keys,
) -> Result<Option<GrantStatus>, NodeError> {
    let url = node.url(&format!("grants/v1/{}", device.public_key().to_hex()));
    let auth = http_auth(device, &url, "GET", b"");
    let response = http
        .get(&url)
        .header(header::AUTHORIZATION, auth)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    match response.status() {
        StatusCode::OK => {
            let bytes = read_bounded(response, 16 * 1024).await?;
            serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| NodeError::Invalid)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(None),
        status => Err(NodeError::from_status(status)),
    }
}

/// A one-use Foregather `live` creation grant.  `Debug` hides the token.
#[derive(Clone, Deserialize)]
pub struct LiveGrant {
    pub token: String,
    pub resource: String,
    pub expires: u64,
    pub remaining: u32,
    pub max_invitation_lifetime: u64,
}

impl std::fmt::Debug for LiveGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LiveGrant([redacted])")
    }
}

impl Drop for LiveGrant {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

/// `POST /pairing/v1/live-grants`: the device asks the online node's issuer
/// for a creation grant on the pairing relay.
pub async fn live_grant(
    http: &Client,
    node: &NodeEndpoint,
    device: &Keys,
) -> Result<LiveGrant, NodeError> {
    let url = node.url("pairing/v1/live-grants");
    let auth = http_auth(device, &url, "POST", b"");
    let response = http
        .post(&url)
        .header(header::AUTHORIZATION, auth)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    if response.status() != StatusCode::CREATED {
        return Err(NodeError::from_status(response.status()));
    }
    let bytes = read_bounded(response, 4096).await?;
    let grant: LiveGrant = serde_json::from_slice(&bytes).map_err(|_| NodeError::Invalid)?;
    if grant.resource != "live" || grant.remaining < 1 || grant.max_invitation_lifetime < 600 {
        return Err(NodeError::Invalid);
    }
    Ok(grant)
}

/// The ICE configuration from the node's issuer, on the same servers for
/// both ends: TURN REST credentials, or `stun:` URLs with no credential.
/// `own` is for this computer and `peer` for the verified person at the other
/// end of a direct send.  `Debug` hides the usernames and credentials.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnCredentials {
    pub expires: u64,
    pub own: super::direct::messages::IceServer,
    pub peer: super::direct::messages::IceServer,
}

/// Why the node gave no ICE configuration.  No variant carries a header or
/// body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TurnError {
    #[error("the node did not answer")]
    Unreachable,
    /// 404: the node does not run the issuer, so Drop uses its built-in STUN
    /// default.
    #[error("the node does not issue an ICE configuration")]
    NotOffered,
    /// 429: this computer has asked too often in the last hour.
    #[error("too many requests for TURN credentials this hour")]
    Limited,
    /// Any other refusal, such as 403 without an active device grant.
    #[error("the node refused TURN credentials (HTTP {0})")]
    Refused(u16),
    #[error("the node returned something unexpected")]
    Invalid,
}

/// Reads the issuer's reply: exactly `{"expires","own","peer"}`, each entry
/// exactly an `ice` server that passes the `ice` rules: TURN credentials, or
/// `stun:` URLs with an empty username and credential.
pub fn parse_turn_credentials(bytes: &[u8]) -> Result<TurnCredentials, TurnError> {
    // Objects only: a derived struct would also take the array form.
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| TurnError::Invalid)?;
    let objects = value.as_object().is_some_and(|reply| {
        ["own", "peer"]
            .iter()
            .all(|name| reply.get(*name).is_some_and(serde_json::Value::is_object))
    });
    if !objects {
        return Err(TurnError::Invalid);
    }
    // Read from the bytes, not the value, so a duplicate member is refused.
    let credentials: TurnCredentials =
        serde_json::from_slice(bytes).map_err(|_| TurnError::Invalid)?;
    if credentials.expires == 0 || !credentials.own.well_formed() || !credentials.peer.well_formed()
    {
        return Err(TurnError::Invalid);
    }
    Ok(credentials)
}

/// `POST /turn/v1/credentials` with the device's NIP-98, as [`live_grant`]
/// does.
pub async fn turn_credentials(
    http: &Client,
    node: &NodeEndpoint,
    device: &Keys,
) -> Result<TurnCredentials, TurnError> {
    let url = node.url("turn/v1/credentials");
    let auth = http_auth(device, &url, "POST", b"");
    let response = http
        .post(&url)
        .header(header::AUTHORIZATION, auth)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .map_err(|_| TurnError::Unreachable)?;
    match response.status() {
        StatusCode::CREATED => {}
        StatusCode::NOT_FOUND => return Err(TurnError::NotOffered),
        StatusCode::TOO_MANY_REQUESTS => return Err(TurnError::Limited),
        status => return Err(TurnError::Refused(status.as_u16())),
    }
    let bytes = read_bounded(response, 8192)
        .await
        .map_err(|_| TurnError::Invalid)?;
    parse_turn_credentials(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_https_origins_unless_loopback_is_allowed() {
        let node = NodeEndpoint::parse("https://storage.example", false).unwrap();
        assert_eq!(node.origin(), "https://storage.example/");
        assert_eq!(node.server(), "storage.example");
        assert_eq!(node.url("upload"), "https://storage.example/upload");
        assert_eq!(
            NodeEndpoint::parse("http://storage.example/", true),
            Err(EndpointError::NotHttps)
        );
        assert_eq!(
            NodeEndpoint::parse("http://localhost:3742/", false),
            Err(EndpointError::NotHttps)
        );
        let local = NodeEndpoint::parse("http://localhost:3742/", true).unwrap();
        assert_eq!(local.server(), "localhost");
        assert_eq!(local.host(), "localhost:3742");
        for bad in [
            "https://user@storage.example/",
            "https://storage.example/path",
            "https://storage.example/?q",
            "ftp://storage.example/",
            "storage.example",
        ] {
            assert!(NodeEndpoint::parse(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn blossom_auth_is_scoped_and_short_lived() {
        let keys = Keys::generate();
        let header = blossom_auth(&keys, "upload", &[&"ab".repeat(32)], "storage.example");
        let json = URL_SAFE_NO_PAD
            .decode(header.strip_prefix("Nostr ").unwrap())
            .unwrap();
        let event: nostr::prelude::Event = serde_json::from_slice(&json).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::Custom(24_242));
        let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert!(tags.contains(&vec!["t".into(), "upload".into()]));
        assert!(tags.contains(&vec!["x".into(), "ab".repeat(32)]));
        assert!(tags.contains(&vec!["server".into(), "storage.example".into()]));
        let expiration: u64 = tags.iter().find(|t| t[0] == "expiration").unwrap()[1]
            .parse()
            .unwrap();
        assert_eq!(
            expiration - event.created_at.as_secs(),
            BLOSSOM_AUTH_LIFETIME
        );
        assert!(!event.content.trim().is_empty());
    }

    // ------------------------------------------------ stall regression tests

    use tokio::io::AsyncReadExt as _;

    /// The stall timeout the transfer tests use.
    const STALL: Duration = Duration::from_millis(400);

    /// Reads one HTTP/1.1 request head and its `Content-Length` body.
    async fn read_request(socket: &mut tokio::net::TcpStream) -> usize {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map_or(0, |v| v.trim().parse().unwrap());
        let mut body = vec![0u8; length];
        socket.read_exact(&mut body).await.unwrap();
        length
    }

    /// A one-request server; `serve` writes the response.
    async fn server<F, Fut>(serve: F) -> NodeEndpoint
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            serve(socket).await;
        });
        NodeEndpoint::parse(&format!("http://127.0.0.1:{port}/"), true).unwrap()
    }

    /// `n` chunks of `size` bytes, one every `every`.
    fn steady(n: u32, size: usize, every: Duration) -> Body {
        Body::wrap_stream(futures_util::stream::unfold(0u32, move |i| async move {
            if i >= n {
                return None;
            }
            tokio::time::sleep(every).await;
            Some((
                Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'x'; size])),
                i + 1,
            ))
        }))
    }

    #[tokio::test]
    async fn a_steady_upload_longer_than_the_stall_timeout_succeeds() {
        set_stall_for_tests(STALL);
        let node = server(|mut socket| async move {
            assert_eq!(read_request(&mut socket).await, 8 * 1024);
            socket
                .write_all(b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
        })
        .await;
        // Eight chunks 250 ms apart: two seconds in all, five stall timeouts.
        let started = std::time::Instant::now();
        let result = upload(
            &http_client(),
            &node,
            &Keys::generate(),
            &"ab".repeat(32),
            8 * 1024,
            steady(8, 1024, Duration::from_millis(250)),
        )
        .await;
        assert_eq!(result, Ok(()));
        assert!(started.elapsed() > STALL * 4);
    }

    #[tokio::test]
    async fn a_steady_download_longer_than_the_stall_timeout_succeeds() {
        set_stall_for_tests(STALL);
        let chunk = vec![b'y'; 1000];
        let sha = crate::drop::hex_lower(&Sha256::digest(chunk.repeat(6)));
        let node = server(move |mut socket| async move {
            read_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6000\r\n\r\n")
                .await
                .unwrap();
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(250)).await;
                socket.write_all(&chunk).await.unwrap();
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("blob");
        std::fs::write(&dest, b"").unwrap();
        let result = download_to_file(&http_client(), &node, &sha, 6000, &dest, &mut |_| {}).await;
        assert_eq!(result, Ok(()));
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), 6000);
    }

    #[tokio::test]
    async fn a_stalled_download_fails_within_the_stall_timeout() {
        set_stall_for_tests(STALL);
        let node = server(|mut socket| async move {
            read_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6000\r\n\r\nyyyy")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("blob");
        std::fs::write(&dest, b"").unwrap();
        let started = std::time::Instant::now();
        let result = download_to_file(
            &http_client(),
            &node,
            &"ab".repeat(32),
            6000,
            &dest,
            &mut |_| {},
        )
        .await;
        assert_eq!(result, Err(NodeError::Unreachable));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_stalled_relay_source_fails_the_upload() {
        set_stall_for_tests(STALL);
        let source = server(|mut socket| async move {
            read_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6000\r\n\r\nzzzz")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;
        // The destination reads whatever arrives and never answers early.
        let destination = server(|mut socket| async move {
            let mut sink = vec![0u8; 65_536];
            while socket.read(&mut sink).await.is_ok_and(|n| n > 0) {}
        })
        .await;
        let http = http_client();
        let started = std::time::Instant::now();
        let body = relay_body(&http, &source, &"ab".repeat(32), 6000, |_| {})
            .await
            .unwrap();
        let result = upload(
            &http,
            &destination,
            &Keys::generate(),
            &"ab".repeat(32),
            6000,
            body,
        )
        .await;
        assert!(result.is_err(), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn uploads_have_a_size_bound_deadline() {
        assert_eq!(upload_deadline(0), Duration::from_secs(600));
        assert_eq!(
            upload_deadline(1024 * 1024 * 1024),
            Duration::from_secs(600 + 65_536)
        );
    }

    #[test]
    fn http_auth_follows_the_checkout_profile() {
        let keys = Keys::generate();
        let header = http_auth(
            &keys,
            "https://storage.example/pairing/v1/live-grants",
            "POST",
            b"",
        );
        let json = STANDARD
            .decode(header.strip_prefix("Nostr ").unwrap())
            .unwrap();
        let event: nostr::prelude::Event = serde_json::from_slice(&json).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::HttpAuth);
        assert!(event.content.is_empty());
        let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
        assert!(tags.contains(&vec![
            "payload".into(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
        ]));
        let get = http_auth(&keys, "https://storage.example/grants/v1/x", "GET", b"");
        let json = STANDARD
            .decode(get.strip_prefix("Nostr ").unwrap())
            .unwrap();
        let event: nostr::prelude::Event = serde_json::from_slice(&json).unwrap();
        assert!(event.tags.iter().all(|t| t.as_slice()[0] != "payload"));
    }

    // ------------------------------------------------- TURN credentials

    /// The issuer's documented example, with synthetic values.
    fn turn_reply() -> serde_json::Value {
        let entry = |label: &str| {
            serde_json::json!({
                "credential": format!("{}=", "A".repeat(27)),
                "urls": ["turn:turn.example.net:3478?transport=udp", "turns:turn.example.net:5349?transport=tcp"],
                "username": format!("1800003600:{label}"),
            })
        };
        serde_json::json!({
            "expires": 1_800_003_600u64,
            "own": entry("b3duLWxhYmVsLXN5bnRoZXRpYw"),
            "peer": entry("cGVlci1sYWJlbC1zeW50aGV0aWM"),
        })
    }

    #[test]
    fn turn_credentials_parse_exactly() {
        let good = turn_reply();
        let parsed = parse_turn_credentials(good.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.expires, 1_800_003_600);
        assert_eq!(parsed.own.username, "1800003600:b3duLWxhYmVsLXN5bnRoZXRpYw");
        assert_eq!(
            parsed.peer.username,
            "1800003600:cGVlci1sYWJlbC1zeW50aGV0aWM"
        );
        assert_eq!(parsed.own.urls.len(), 2);
        // Debug never shows a credential or username.
        let shown = format!("{parsed:?}");
        assert!(
            !shown.contains("AAAA") && !shown.contains("b3duLWxh"),
            "{shown}"
        );

        type Change = fn(&mut serde_json::Value);
        let mutate = |change: Change| {
            let mut value = turn_reply();
            change(&mut value);
            parse_turn_credentials(value.to_string().as_bytes())
        };
        let refused: Vec<(&str, Change)> = vec![
            ("extra member", |v| v["note"] = "x".into()),
            ("missing peer", |v| {
                v.as_object_mut().unwrap().remove("peer");
            }),
            ("extra entry member", |v| v["own"]["ttl"] = 1.into()),
            ("STUN-only server with a credential", |v| {
                v["peer"]["urls"] = serde_json::json!(["stun:turn.example.net:3478"])
            }),
            ("STUN-only server with a username only", |v| {
                v["own"]["urls"] = serde_json::json!(["stun:turn.example.net:3478"]);
                v["own"]["credential"] = "".into();
            }),
            ("TURN server with an empty username", |v| {
                v["own"]["username"] = "".into()
            }),
            ("five URLs", |v| {
                v["own"]["urls"] =
                    serde_json::json!(["turn:a", "turn:b", "turn:c", "turn:d", "turn:e"])
            }),
            ("no URLs", |v| v["own"]["urls"] = serde_json::json!([])),
            ("bad scheme", |v| {
                v["own"]["urls"] = serde_json::json!(["https://turn.example.net/"])
            }),
            ("space in URL", |v| {
                v["own"]["urls"] = serde_json::json!(["turn:turn.example.net :3478"])
            }),
            ("long URL", |v| {
                v["own"]["urls"] = serde_json::json!([format!("turn:{}", "a".repeat(252))])
            }),
            ("empty credential", |v| v["peer"]["credential"] = "".into()),
            ("long username", |v| {
                v["peer"]["username"] = "u".repeat(257).into()
            }),
            ("control in username", |v| {
                v["peer"]["username"] = "a\u{7}b".into()
            }),
            ("string expiry", |v| v["expires"] = "1800003600".into()),
            ("zero expiry", |v| v["expires"] = 0.into()),
            ("array entry", |v| {
                v["own"] = serde_json::json!(["c", ["turn:turn.example.net"], "u"])
            }),
        ];
        for (name, change) in refused {
            assert_eq!(mutate(change), Err(TurnError::Invalid), "{name}");
        }
        let text = turn_reply().to_string();
        let duplicated = text.replacen("\"expires\"", "\"expires\":1,\"expires\"", 1);
        assert_eq!(
            parse_turn_credentials(duplicated.as_bytes()),
            Err(TurnError::Invalid)
        );
        assert_eq!(parse_turn_credentials(b"[]"), Err(TurnError::Invalid));
        assert_eq!(parse_turn_credentials(b""), Err(TurnError::Invalid));
    }

    /// A STUN-only reply, as a node with only `--turn-url stun:...` sends.
    #[test]
    fn a_stun_only_reply_parses_when_it_carries_no_credential() {
        let entry = serde_json::json!({
            "credential": "",
            "urls": ["stun:stun.example.net:3478"],
            "username": "",
        });
        let reply = serde_json::json!({"expires": 1_800_003_600u64, "own": entry, "peer": entry});
        let parsed = parse_turn_credentials(reply.to_string().as_bytes()).unwrap();
        assert!(!parsed.own.has_turn() && !parsed.peer.has_turn());
        assert!(parsed.own.username.is_empty() && parsed.own.credential.is_empty());
    }

    /// A server that answers one request with `status` and `body`.
    async fn answering(status: &'static str, body: String) -> NodeEndpoint {
        server(move |mut socket| async move {
            let head = {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap();
                    head.push(byte[0]);
                }
                String::from_utf8(head).unwrap()
            };
            assert!(head.starts_with("POST /turn/v1/credentials HTTP/1.1"), "{head}");
            assert!(head.to_ascii_lowercase().contains("authorization: nostr "));
            let reply = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
        })
        .await
    }

    #[tokio::test]
    async fn turn_credentials_come_from_the_issuer_route() {
        let keys = Keys::generate();
        let http = http_client();
        let node = answering("201 Created", turn_reply().to_string()).await;
        let credentials = turn_credentials(&http, &node, &keys).await.unwrap();
        assert_eq!(credentials.expires, 1_800_003_600);
        for (status, expected) in [
            ("404 Not Found", TurnError::NotOffered),
            ("429 Too Many Requests", TurnError::Limited),
            ("403 Forbidden", TurnError::Refused(403)),
            ("503 Service Unavailable", TurnError::Refused(503)),
            ("200 OK", TurnError::Refused(200)),
        ] {
            let node = answering(status, "{}".into()).await;
            assert_eq!(
                turn_credentials(&http, &node, &keys).await,
                Err(expected),
                "{status}"
            );
        }
        let node = answering("201 Created", "{\"expires\":1}".into()).await;
        assert_eq!(
            turn_credentials(&http, &node, &keys).await,
            Err(TurnError::Invalid)
        );
        // Nothing listening.
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            NodeEndpoint::parse(&format!("http://127.0.0.1:{port}/"), true).unwrap()
        };
        assert_eq!(
            turn_credentials(&http, &closed, &keys).await,
            Err(TurnError::Unreachable)
        );
    }
}
