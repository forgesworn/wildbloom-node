//! Owner-signed device grant and revocation events (kind 27540).
//!
//! Every authority tag appears exactly once with exactly one value, unknown
//! tags are refused, and the event's own validity window comes from a NIP-40
//! `expiration` tag.  The grant's lifetime is a separate `until` tag.
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use nostr::prelude::Event;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Ephemeral range, so a relay that is handed one does not store it.  Not a
/// registered NIP kind and away from Blossom's 24242 and NIP-46's 24133.
pub const DEVICE_GRANT_KIND: u16 = 27_540;
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
/// Upper bound on `expiration - created_at`.  Long enough for a remote signer
/// prompt, short enough that a captured event soon becomes useless.
pub const MAX_EVENT_LIFETIME: u64 = 10 * 60;
pub const FUTURE_SKEW: u64 = 30;
/// Longest grant an owner may sign in one event; renewal issues a new event.
pub const MAX_GRANT_SECONDS: u64 = 2 * 366 * 24 * 60 * 60;
const MAX_CONTENT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantTerms {
    pub device: String,
    pub recovery: String,
    pub byte_limit: u64,
    pub until: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Grant(GrantTerms),
    Revoke { device: String },
}

#[derive(Debug, Clone)]
pub struct Authorised {
    pub owner: String,
    pub event_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    /// Malformed JSON, kind, tags or values.
    Invalid,
    /// Bad signature, wrong signer, wrong server or outside its time window.
    Unauthorised,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct RawEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

/// Decode a `Nostr <base64>` header with the same lenient alphabets the core
/// accepts for BUD-11.
pub fn decode_header(header: &str) -> Option<Vec<u8>> {
    let encoded = header.strip_prefix("Nostr ")?;
    if encoded.is_empty() || encoded.len() > MAX_EVENT_BYTES * 2 {
        return None;
    }
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| URL_SAFE.decode(encoded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .ok()?;
    (bytes.len() <= MAX_EVENT_BYTES).then_some(bytes)
}

/// The verified signer of a BUD-11 `Authorization` header, or `None` when it
/// cannot be decoded or its signature fails.  Callers only use this to decide
/// whether to refuse early; the core still performs full verification.
pub fn signer_of_header(header: &str) -> Option<String> {
    let bytes = decode_header(header)?;
    let event: Event = serde_json::from_slice(&bytes).ok()?;
    event.verify().ok()?;
    Some(event.pubkey.to_hex())
}

pub fn verify(
    bytes: &[u8],
    owners: &BTreeSet<String>,
    server_names: &[String],
    now: u64,
) -> Result<Authorised, EventError> {
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(EventError::Invalid);
    }
    // A strict structural parse first: duplicate or unknown fields fail here,
    // so the signed values below cannot differ from what a reviewer reads.
    let raw: RawEvent = serde_json::from_slice(bytes).map_err(|_| EventError::Invalid)?;
    if raw.kind != DEVICE_GRANT_KIND || raw.content.len() > MAX_CONTENT_BYTES {
        return Err(EventError::Invalid);
    }
    let tags = singleton_tags(&raw.tags)?;
    let verb = tags.get("t").ok_or(EventError::Invalid)?;
    let allowed: &[&str] = match *verb {
        "grant" => &[
            "t",
            "device",
            "recovery",
            "bytes",
            "until",
            "server",
            "expiration",
        ],
        "revoke" => &["t", "device", "server", "expiration"],
        _ => return Err(EventError::Invalid),
    };
    if tags.len() != allowed.len() || allowed.iter().any(|name| !tags.contains_key(name)) {
        return Err(EventError::Invalid);
    }
    let device = canonical_key(tags["device"])?;
    let expires_at = decimal(tags["expiration"])?;
    let action = if *verb == "grant" {
        let recovery = canonical_key(tags["recovery"])?;
        let byte_limit = decimal(tags["bytes"])?;
        let until = decimal(tags["until"])?;
        if recovery == device || byte_limit == 0 || byte_limit > i64::MAX as u64 {
            return Err(EventError::Invalid);
        }
        Action::Grant(GrantTerms {
            device,
            recovery,
            byte_limit,
            until,
        })
    } else {
        Action::Revoke { device }
    };

    let event: Event = serde_json::from_slice(bytes).map_err(|_| EventError::Invalid)?;
    event.verify().map_err(|_| EventError::Unauthorised)?;
    let owner = event.pubkey.to_hex();
    if owner != raw.pubkey || !owners.contains(&owner) {
        return Err(EventError::Unauthorised);
    }
    let server = tags["server"];
    if !server_names
        .iter()
        .any(|accepted| accepted.to_ascii_lowercase() == server)
    {
        return Err(EventError::Unauthorised);
    }
    let created_at = raw.created_at;
    if created_at > now.saturating_add(FUTURE_SKEW)
        || expires_at <= now
        || expires_at < created_at
        || expires_at - created_at > MAX_EVENT_LIFETIME
    {
        return Err(EventError::Unauthorised);
    }
    if let Action::Grant(terms) = &action
        && (terms.until <= now
            || terms.until <= created_at
            || terms.until > now.saturating_add(MAX_GRANT_SECONDS))
    {
        return Err(EventError::Invalid);
    }
    Ok(Authorised {
        owner,
        event_id: event.id.to_hex(),
        created_at,
        expires_at,
        action,
    })
}

fn singleton_tags(tags: &[Vec<String>]) -> Result<BTreeMap<&str, &str>, EventError> {
    if tags.len() > 16 {
        return Err(EventError::Invalid);
    }
    let mut map = BTreeMap::new();
    for tag in tags {
        let [name, value] = tag.as_slice() else {
            return Err(EventError::Invalid);
        };
        if map.insert(name.as_str(), value.as_str()).is_some() {
            return Err(EventError::Invalid);
        }
    }
    Ok(map)
}

pub fn is_canonical_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_key(value: &str) -> Result<String, EventError> {
    is_canonical_key(value)
        .then(|| value.to_owned())
        .ok_or(EventError::Invalid)
}

/// Canonical unsigned decimal: digits only, no sign, no leading zero.
fn decimal(value: &str) -> Result<u64, EventError> {
    if value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(EventError::Invalid);
    }
    value.parse().map_err(|_| EventError::Invalid)
}
