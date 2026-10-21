//! Keeper-signed group grant events (kind 27541), rules 1 to 4 of
//! `docs/GROUP-GRANTS.md` section 4.4: size and strict NIP-01 shape, kind,
//! content and tags, lifetime, then the id and BIP-340 signature.
//!
//! Every authority tag appears exactly once with exactly one value (`scope`
//! may repeat, once per distinct scope), unknown tags are refused, and a
//! tag a reader could disagree about makes the whole event malformed.
use super::event::is_canonical_key;
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use nostr::prelude::Event;
use serde::Deserialize;
use std::collections::BTreeMap;

pub const GROUP_KIND: u16 = 27_541;
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
const MAX_TAGS: usize = 16;
/// Longest a grant (or reset) may live after its `created_at`: 90 days.
pub const MAX_GRANT_SECONDS: u64 = 90 * 24 * 60 * 60;
/// How far ahead of the node clock an event or token `created_at` may be.
pub const FUTURE_SKEW: u64 = 30;

/// What a grant lets a device do.  The bit values are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Upload = 1,
    Get = 2,
    Delete = 4,
    Purge = 8,
    Turn = 16,
    RelayRead = 32,
    RelayWrite = 64,
}

impl Scope {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "upload" => Self::Upload,
            "get" => Self::Get,
            "delete" => Self::Delete,
            "purge" => Self::Purge,
            "turn" => Self::Turn,
            "relay-read" => Self::RelayRead,
            "relay-write" => Self::RelayWrite,
            _ => return None,
        })
    }

    pub fn bit(self) -> u8 {
        self as u8
    }
}

/// Why a request was refused: an HTTP status and the reason name the vectors
/// and the wire (`X-Reason`) use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    pub status: StatusCode,
    pub reason: &'static str,
}

impl Refusal {
    pub const fn new(status: StatusCode, reason: &'static str) -> Self {
        Self { status, reason }
    }
    pub const fn bad(reason: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason)
    }
    pub const fn malformed() -> Self {
        Self::bad("malformed")
    }
    pub const fn forbidden(reason: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, reason)
    }
    pub const fn conflict(reason: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, reason)
    }
    pub const fn unavailable() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({ "error": self.reason })),
        )
            .into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert("x-reason", HeaderValue::from_static(self.reason));
        response
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Grant {
        grant_id: String,
        room: String,
        device: String,
        server: String,
        scopes: u8,
        bytes: Option<u64>,
        revoked: bool,
    },
    Reset {
        room: String,
        server: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEvent {
    pub id: String,
    pub keeper: String,
    pub created_at: u64,
    pub expiration: u64,
    pub body: Body,
}

impl GroupEvent {
    pub fn room(&self) -> &str {
        match &self.body {
            Body::Grant { room, .. } | Body::Reset { room, .. } => room,
        }
    }

    pub fn server(&self) -> &str {
        match &self.body {
            Body::Grant { server, .. } | Body::Reset { server, .. } => server,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Canonical unsigned decimal: digits only, no sign, no leading zero.
fn decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

/// A lower-case host name: no scheme, port, path or user information.
pub fn is_host_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// Rules 1 to 4: everything that needs no node state.  A refusal here is
/// `malformed` (400), `lifetime` (400) or `signature` (401), in that order.
pub fn parse(bytes: &[u8]) -> Result<GroupEvent, Refusal> {
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(Refusal::new(StatusCode::PAYLOAD_TOO_LARGE, "too-large"));
    }
    // A strict structural parse first: duplicate or unknown fields fail here,
    // so the signed values below cannot differ from what a reviewer reads.
    let raw: RawEvent = serde_json::from_slice(bytes).map_err(|_| Refusal::malformed())?;
    if raw.kind != GROUP_KIND
        || !raw.content.is_empty()
        || !is_hex(&raw.id, 64)
        || !is_canonical_key(&raw.pubkey)
        || !is_hex(&raw.sig, 128)
    {
        return Err(Refusal::malformed());
    }
    let (body, expiration) = tags(&raw)?;
    if expiration <= raw.created_at || expiration - raw.created_at > MAX_GRANT_SECONDS {
        return Err(Refusal::bad("lifetime"));
    }
    let event: Event = serde_json::from_slice(bytes).map_err(|_| Refusal::malformed())?;
    event
        .verify()
        .map_err(|_| Refusal::new(StatusCode::UNAUTHORIZED, "signature"))?;
    if event.pubkey.to_hex() != raw.pubkey || event.id.to_hex() != raw.id {
        return Err(Refusal::new(StatusCode::UNAUTHORIZED, "signature"));
    }
    Ok(GroupEvent {
        id: raw.id,
        keeper: raw.pubkey,
        created_at: raw.created_at,
        expiration,
        body,
    })
}

fn tags(raw: &RawEvent) -> Result<(Body, u64), Refusal> {
    if raw.tags.len() > MAX_TAGS {
        return Err(Refusal::malformed());
    }
    let mut singles: BTreeMap<&str, &str> = BTreeMap::new();
    let mut scopes: Vec<&str> = Vec::new();
    for tag in &raw.tags {
        let [name, value] = tag.as_slice() else {
            return Err(Refusal::malformed());
        };
        match name.as_str() {
            "scope" => scopes.push(value),
            "t" | "grant" | "d" | "device" | "server" | "bytes" | "status" | "expiration" => {
                if singles.insert(name, value).is_some() {
                    return Err(Refusal::malformed());
                }
            }
            _ => return Err(Refusal::malformed()),
        }
    }
    let verb = *singles.get("t").ok_or_else(Refusal::malformed)?;
    let required: &[&str] = match verb {
        "grant" => &[
            "t",
            "grant",
            "d",
            "device",
            "server",
            "status",
            "expiration",
        ],
        "reset" => &["t", "d", "server", "expiration"],
        _ => return Err(Refusal::malformed()),
    };
    let optional = usize::from(singles.contains_key("bytes"));
    if singles.len() != required.len() + if verb == "grant" { optional } else { 0 }
        || required.iter().any(|name| !singles.contains_key(name))
    {
        return Err(Refusal::malformed());
    }
    let room = singles["d"];
    let server = singles["server"];
    let expiration = decimal(singles["expiration"]).ok_or_else(Refusal::malformed)?;
    if !is_canonical_key(room) || !is_host_name(server) {
        return Err(Refusal::malformed());
    }
    if verb == "reset" {
        if !scopes.is_empty() {
            return Err(Refusal::malformed());
        }
        return Ok((
            Body::Reset {
                room: room.to_owned(),
                server: server.to_owned(),
            },
            expiration,
        ));
    }

    let (grant_id, device) = (singles["grant"], singles["device"]);
    if !is_hex(grant_id, 32) || !is_canonical_key(device) || device == raw.pubkey {
        return Err(Refusal::malformed());
    }
    let revoked = match singles["status"] {
        "active" => false,
        "revoked" => true,
        _ => return Err(Refusal::malformed()),
    };
    if scopes.is_empty() || scopes.len() > 7 {
        return Err(Refusal::malformed());
    }
    let mut mask = 0_u8;
    for value in scopes {
        let bit = Scope::parse(value).ok_or_else(Refusal::malformed)?.bit();
        if mask & bit != 0 {
            return Err(Refusal::malformed());
        }
        mask |= bit;
    }
    // A byte ceiling goes with an `upload` scope, and only with one.
    let bytes = match (mask & Scope::Upload.bit() != 0, singles.get("bytes")) {
        (true, Some(value)) => Some(
            decimal(value)
                .filter(|bytes| (1..=i64::MAX as u64).contains(bytes))
                .ok_or_else(Refusal::malformed)?,
        ),
        (false, None) => None,
        _ => return Err(Refusal::malformed()),
    };
    Ok((
        Body::Grant {
            grant_id: grant_id.to_owned(),
            room: room.to_owned(),
            device: device.to_owned(),
            server: server.to_owned(),
            scopes: mask,
            bytes,
            revoked,
        },
        expiration,
    ))
}
