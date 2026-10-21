//! BUD-11 tokens for a group node (`docs/GROUP-GRANTS.md` section 6.1).
//!
//! Group mode verifies every token itself, on the node's own clock and in the
//! order section 6.7 lists, so the reason a client sees is the first thing
//! wrong with its token.  The core would refuse a delete token that lives
//! longer than five minutes and has no verifier for `get` at all.
use super::{
    event::{FUTURE_SKEW, decode_header, is_canonical_key},
    group::host_of,
    group_event::Refusal,
};
use axum::http::{HeaderMap, StatusCode, header};
use nostr::prelude::Event;
use serde::Deserialize;
use std::collections::BTreeSet;

const BLOSSOM_AUTH_KIND: u16 = 24_242;
const MAX_CONTENT_BYTES: usize = 1024;
/// Most `x` or `server` tags a token may carry, as in the core.
const MAX_SCOPED_TAGS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verb {
    Get,
    Upload,
    Delete,
    List,
}

impl Verb {
    fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Upload => "upload",
            Self::Delete => "delete",
            Self::List => "list",
        }
    }

    /// Longest a token may live.  Delete tokens are single use and live as
    /// long as a client's retry journal keeps a signed delete (a week and a
    /// second).
    fn longest(self) -> u64 {
        match self {
            Self::Delete => 604_801,
            _ => 300,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Token {
    pub signer: String,
    pub event_id: String,
    pub expiration: u64,
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

const fn unauthorised(reason: &'static str) -> Refusal {
    Refusal::new(StatusCode::UNAUTHORIZED, reason)
}

/// The tags named `name`, each of exactly one value.
fn scoped<'a>(raw: &'a RawEvent, name: &str) -> Result<Vec<&'a str>, Refusal> {
    let tags = raw
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|first| first == name))
        .collect::<Vec<_>>();
    if tags.len() > MAX_SCOPED_TAGS || tags.iter().any(|tag| tag.len() != 2) {
        return Err(unauthorised("event"));
    }
    Ok(tags.into_iter().map(|tag| tag[1].as_str()).collect())
}

fn singleton<'a>(raw: &'a RawEvent, name: &str) -> Result<&'a str, Refusal> {
    match scoped(raw, name)?.as_slice() {
        [only] => Ok(only),
        _ => Err(unauthorised("event")),
    }
}

/// Check a request's one `Authorization` header as a token for `verb`.
///
/// `hash` is the blob the request names; `None` skips the `x` check (listing,
/// which names no blob, and a request whose blob cannot be read).  The checks
/// run in order: header, encoding, event, signature, verb, server, hash,
/// future, expired, lifetime.
pub(super) fn verify(
    headers: &HeaderMap,
    verb: Verb,
    hash: Option<&str>,
    hosts: &BTreeSet<String>,
    now: u64,
) -> Result<Token, Refusal> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(unauthorised("missing"))?;
    if values.next().is_some() {
        return Err(unauthorised("missing"));
    }
    let bytes = value
        .to_str()
        .ok()
        .and_then(decode_header)
        .ok_or(unauthorised("encoding"))?;
    let raw: RawEvent = serde_json::from_slice(&bytes).map_err(|_| unauthorised("event"))?;
    if raw.kind != BLOSSOM_AUTH_KIND
        || raw.content.len() > MAX_CONTENT_BYTES
        || raw.content.trim().is_empty()
    {
        return Err(unauthorised("event"));
    }
    let expiration = singleton(&raw, "expiration")?
        .parse::<u64>()
        .map_err(|_| unauthorised("event"))?;
    let verb_tag = singleton(&raw, "t")?;
    let hashes = scoped(&raw, "x")?;
    let servers = scoped(&raw, "server")?;
    let event: Event = serde_json::from_slice(&bytes).map_err(|_| unauthorised("event"))?;
    event.verify().map_err(|_| unauthorised("signature"))?;
    if verb_tag != verb.name() {
        return Err(unauthorised("verb"));
    }
    if !servers
        .iter()
        .filter_map(|server| host_of(server))
        .any(|host| hosts.contains(&host))
    {
        return Err(unauthorised("server"));
    }
    if let Some(hash) = hash
        && (hashes.is_empty()
            || hashes.iter().any(|x| !is_canonical_key(x))
            || !hashes.contains(&hash))
    {
        return Err(unauthorised("hash"));
    }
    if raw.created_at > now.saturating_add(FUTURE_SKEW) {
        return Err(unauthorised("future"));
    }
    if expiration <= now {
        return Err(unauthorised("expired"));
    }
    if expiration < raw.created_at || expiration - raw.created_at > verb.longest() {
        return Err(unauthorised("lifetime"));
    }
    Ok(Token {
        signer: event.pubkey.to_hex(),
        event_id: event.id.to_hex(),
        expiration,
    })
}
