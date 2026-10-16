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
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| NodeError::Unreachable)?;
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
    let response = http
        .get(node.url(sha256))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
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
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| NodeError::Unreachable)?;
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
    let response = http
        .get(node.url(sha256))
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
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
    let response = http
        .get(from.url(sha256))
        .send()
        .await
        .map_err(|e| NodeError::from_reqwest(&e))?;
    if response.status() != StatusCode::OK {
        return Err(NodeError::from_status(response.status()));
    }
    if response.content_length().is_some_and(|n| n != size) {
        return Err(NodeError::Mismatch);
    }
    let mut sent = 0u64;
    let stream = response.bytes_stream().map(move |chunk| {
        if let Ok(bytes) = &chunk {
            sent += bytes.len() as u64;
            progress(sent);
        }
        chunk
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
        match file.read(&mut buffer).await {
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
}
