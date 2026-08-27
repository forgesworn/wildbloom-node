use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nostr::prelude::Event;
use serde::Deserialize;
use std::{collections::BTreeSet, time::Duration};
use thiserror::Error;

const BLOSSOM_AUTH_KIND: u16 = 24_242;
const MAX_AUTH_BYTES: usize = 16 * 1024;
const MAX_CONTENT_BYTES: usize = 1024;

#[derive(Debug, Clone)]
pub struct AuthPolicy {
    accepted_servers: BTreeSet<String>,
    max_event_lifetime: Duration,
    future_clock_skew: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpload {
    pub owner_pubkey: String,
    pub event_id: String,
    pub expires_at: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing Blossom authorisation")]
    Missing,
    #[error("invalid Blossom authorisation encoding")]
    Encoding,
    #[error("invalid Nostr authorisation event")]
    InvalidEvent,
    #[error("invalid Nostr authorisation signature")]
    InvalidSignature,
    #[error("authorisation event must be kind 24242")]
    WrongKind,
    #[error("authorisation event is from the future")]
    FutureEvent,
    #[error("authorisation event has expired")]
    Expired,
    #[error("authorisation lifetime is too long")]
    LifetimeTooLong,
    #[error("authorisation is not scoped to this upload")]
    WrongVerb,
    #[error("authorisation is not scoped to this blob")]
    WrongHash,
    #[error("authorisation is not scoped to this server")]
    WrongServer,
    #[error("authorisation event contains ambiguous security tags")]
    AmbiguousTags,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    #[serde(rename = "sig")]
    _sig: String,
}

impl AuthPolicy {
    pub fn new<I, S>(servers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            accepted_servers: servers
                .into_iter()
                .map(Into::into)
                .map(|server| server.to_ascii_lowercase())
                .collect(),
            max_event_lifetime: Duration::from_secs(5 * 60),
            future_clock_skew: Duration::from_secs(30),
        }
    }

    pub fn with_max_event_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_event_lifetime = lifetime;
        self
    }

    pub fn verify_upload(
        &self,
        authorization: Option<&str>,
        expected_hash: &str,
        now: u64,
    ) -> Result<VerifiedUpload, AuthError> {
        let authorization = authorization.ok_or(AuthError::Missing)?;
        let encoded = authorization
            .strip_prefix("Nostr ")
            .ok_or(AuthError::Encoding)?;
        if encoded.is_empty() || encoded.len() > MAX_AUTH_BYTES * 2 || encoded.contains('=') {
            return Err(AuthError::Encoding);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| AuthError::Encoding)?;
        if bytes.len() > MAX_AUTH_BYTES {
            return Err(AuthError::Encoding);
        }

        let raw: RawEvent = serde_json::from_slice(&bytes).map_err(|_| AuthError::InvalidEvent)?;
        if raw.content.len() > MAX_CONTENT_BYTES {
            return Err(AuthError::InvalidEvent);
        }
        let event: Event = serde_json::from_slice(&bytes).map_err(|_| AuthError::InvalidEvent)?;
        event.verify().map_err(|_| AuthError::InvalidSignature)?;

        if raw.kind != BLOSSOM_AUTH_KIND {
            return Err(AuthError::WrongKind);
        }
        if raw.created_at > now.saturating_add(self.future_clock_skew.as_secs()) {
            return Err(AuthError::FutureEvent);
        }

        let verb = unique_singleton_tag(&raw.tags, "t")?;
        if verb != "upload" {
            return Err(AuthError::WrongVerb);
        }
        let hashes = scoped_tags(&raw.tags, "x")?;
        if hashes.is_empty()
            || hashes.iter().any(|hash| !is_canonical_hash(hash))
            || !hashes.contains(&expected_hash)
        {
            return Err(AuthError::WrongHash);
        }
        let servers = scoped_tags(&raw.tags, "server")?;
        if servers.is_empty()
            || servers.iter().any(|server| !is_domain_name(server))
            || self.accepted_servers.is_empty()
            || !servers
                .iter()
                .any(|server| self.accepted_servers.contains(*server))
        {
            return Err(AuthError::WrongServer);
        }
        let expires_at = unique_singleton_tag(&raw.tags, "expiration")?
            .parse::<u64>()
            .map_err(|_| AuthError::AmbiguousTags)?;
        if expires_at <= now {
            return Err(AuthError::Expired);
        }
        if expires_at < raw.created_at
            || expires_at.saturating_sub(raw.created_at) > self.max_event_lifetime.as_secs()
        {
            return Err(AuthError::LifetimeTooLong);
        }

        Ok(VerifiedUpload {
            owner_pubkey: raw.pubkey,
            event_id: raw.id,
            expires_at,
        })
    }
}

fn unique_singleton_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Result<&'a str, AuthError> {
    let matches = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|kind| kind == name))
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].len() != 2 {
        return Err(AuthError::AmbiguousTags);
    }
    Ok(matches[0][1].as_str())
}

fn scoped_tags<'a>(tags: &'a [Vec<String>], name: &str) -> Result<Vec<&'a str>, AuthError> {
    let matches = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|kind| kind == name))
        .collect::<Vec<_>>();
    if matches.len() > 32 || matches.iter().any(|tag| tag.len() != 2) {
        return Err(AuthError::AmbiguousTags);
    }
    Ok(matches.iter().map(|tag| tag[1].as_str()).collect())
}

fn is_canonical_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_domain_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value.split('.').all(|label| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};

    fn header(tags: Vec<Vec<String>>, created_at: u64) -> String {
        let keys = Keys::parse(&format!("{:064x}", 1)).unwrap();
        let tags = tags
            .into_iter()
            .map(|tag| Tag::parse(tag).unwrap())
            .collect::<Vec<_>>();
        let event = EventBuilder::new(Kind::Custom(BLOSSOM_AUTH_KIND), "Upload blob")
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .finalize(&keys)
            .unwrap();
        let json = serde_json::to_vec(&event).unwrap();
        format!("Nostr {}", URL_SAFE_NO_PAD.encode(json))
    }

    fn valid_tags(hash: &str, expiration: u64) -> Vec<Vec<String>> {
        vec![
            vec!["t".into(), "upload".into()],
            vec!["x".into(), hash.into()],
            vec!["server".into(), "node.example".into()],
            vec!["expiration".into(), expiration.to_string()],
        ]
    }

    #[test]
    fn accepts_a_valid_exactly_scoped_upload() {
        let hash = "a".repeat(64);
        let auth = header(valid_tags(&hash, 1_120), 1_000);
        let verified = AuthPolicy::new(["node.example"])
            .verify_upload(Some(&auth), &hash, 1_010)
            .unwrap();
        assert_eq!(verified.expires_at, 1_120);
        assert_eq!(verified.owner_pubkey.len(), 64);
    }

    #[test]
    fn rejects_wrong_hash_server_and_verb() {
        let hash = "a".repeat(64);
        let policy = AuthPolicy::new(["node.example"]);

        let wrong_hash = header(valid_tags(&"b".repeat(64), 1_120), 1_000);
        assert_eq!(
            policy.verify_upload(Some(&wrong_hash), &hash, 1_010),
            Err(AuthError::WrongHash)
        );

        let mut tags = valid_tags(&hash, 1_120);
        tags[2][1] = "attacker.example".into();
        assert_eq!(
            policy.verify_upload(Some(&header(tags, 1_000)), &hash, 1_010),
            Err(AuthError::WrongServer)
        );

        let mut tags = valid_tags(&hash, 1_120);
        tags[0][1] = "delete".into();
        assert_eq!(
            policy.verify_upload(Some(&header(tags, 1_000)), &hash, 1_010),
            Err(AuthError::WrongVerb)
        );
    }

    #[test]
    fn rejects_expired_long_lived_and_ambiguous_singleton_events() {
        let hash = "a".repeat(64);
        let policy = AuthPolicy::new(["node.example"]);

        let expired = header(valid_tags(&hash, 1_009), 1_000);
        assert_eq!(
            policy.verify_upload(Some(&expired), &hash, 1_010),
            Err(AuthError::Expired)
        );

        let long_lived = header(valid_tags(&hash, 1_400), 1_000);
        assert_eq!(
            policy.verify_upload(Some(&long_lived), &hash, 1_010),
            Err(AuthError::LifetimeTooLong)
        );

        let mut tags = valid_tags(&hash, 1_120);
        tags.push(vec!["t".into(), "upload".into()]);
        assert_eq!(
            policy.verify_upload(Some(&header(tags, 1_000)), &hash, 1_010),
            Err(AuthError::AmbiguousTags)
        );
    }

    #[test]
    fn accepts_standard_multi_server_and_multi_hash_scope() {
        let hash = "a".repeat(64);
        let mut tags = valid_tags(&hash, 1_120);
        tags.push(vec!["server".into(), "second.example".into()]);
        tags.push(vec!["x".into(), "b".repeat(64)]);
        assert!(
            AuthPolicy::new(["node.example"])
                .verify_upload(Some(&header(tags, 1_000)), &hash, 1_010)
                .is_ok()
        );
    }

    #[test]
    fn rejects_tampered_signatures() {
        let hash = "a".repeat(64);
        let auth = header(valid_tags(&hash, 1_120), 1_000);
        let encoded = auth.strip_prefix("Nostr ").unwrap();
        let mut event: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        event["content"] = "Tampered".into();
        let tampered = format!(
            "Nostr {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&event).unwrap())
        );
        assert_eq!(
            AuthPolicy::new(["node.example"]).verify_upload(Some(&tampered), &hash, 1_010),
            Err(AuthError::InvalidSignature)
        );
    }
}
