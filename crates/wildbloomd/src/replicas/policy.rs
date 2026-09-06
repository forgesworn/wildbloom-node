use nostr::prelude::{Event, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

use super::transport::Profile;

pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_EVENT_BYTES: usize = 16 * 1024;
pub const MAX_BLOB_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy or signed event exceeds its size limit")]
    Size,
    #[error("invalid signed event or policy schema")]
    Schema,
    #[error("invalid event ID, signature or expected author")]
    Signature,
    #[error("policy is expired or dated in the future")]
    Time,
    #[error("policy has invalid targets, groups or blob bounds")]
    Bounds,
    #[error("policy origin is unsafe for the selected transport")]
    Origin,
    #[error("signed event does not match the exact pending request")]
    ChangedRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(rename = "type")]
    pub policy_type: String,
    pub version: u8,
    pub id: String,
    pub revision: u64,
    pub expires_at: u64,
    pub profile: Profile,
    pub desired_groups: u8,
    pub targets: Vec<Target>,
    pub blobs: Vec<Blob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub origin: String,
    pub failure_group: String,
    pub retention: Retention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Retention {
    Owner,
    Friend,
    Guest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub sha256: String,
    pub size: u64,
}

pub struct VerifiedPolicy {
    pub policy: Policy,
    pub event_id: String,
    pub owner: String,
}

// Parsing this separately refuses duplicate or unknown event fields before
// the Nostr library sees them. Errors never quote the supplied event.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

pub fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

pub fn signed_event(bytes: &[u8], owner: &str, limit: usize) -> Result<Event, PolicyError> {
    if bytes.len() > limit {
        return Err(PolicyError::Size);
    }
    let raw: StrictEvent = serde_json::from_slice(bytes).map_err(|_| PolicyError::Schema)?;
    if !canonical_hex(&raw.id, 32)
        || !canonical_hex(&raw.pubkey, 32)
        || !canonical_hex(&raw.sig, 64)
        || raw.pubkey != owner
    {
        return Err(PolicyError::Signature);
    }
    if raw.content.len() > 128 * 1024
        || raw.tags.len() > 8
        || raw
            .tags
            .iter()
            .any(|tag| tag.len() > 3 || tag.iter().any(|part| part.len() > 256))
    {
        return Err(PolicyError::Bounds);
    }
    let event = Event::from_json(bytes).map_err(|_| PolicyError::Schema)?;
    event.verify().map_err(|_| PolicyError::Signature)?;
    if event.kind.as_u16() != raw.kind || event.created_at.as_secs() != raw.created_at {
        return Err(PolicyError::Schema);
    }
    Ok(event)
}

impl Policy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.policy_type != "wildbloom.replica-policy"
            || self.version != 1
            || !identifier(&self.id)
            || self.revision == 0
            || self.expires_at == 0
            || self.targets.len() > 16
            || self.blobs.len() > 128
        {
            return Err(PolicyError::Bounds);
        }
        let mut ids = BTreeSet::new();
        let mut origins = BTreeSet::new();
        let mut groups = BTreeSet::new();
        for target in &self.targets {
            if !identifier(&target.id)
                || !identifier(&target.failure_group)
                || !ids.insert(&target.id)
                || !origins.insert(&target.origin)
            {
                return Err(PolicyError::Bounds);
            }
            let url = Url::parse(&target.origin).map_err(|_| PolicyError::Origin)?;
            if url.as_str() != target.origin || !self.profile.accepts(&url) {
                return Err(PolicyError::Origin);
            }
            if target.retention == Retention::Owner {
                groups.insert(&target.failure_group);
            }
        }
        let mut hashes = BTreeSet::new();
        for blob in &self.blobs {
            if !canonical_hex(&blob.sha256, 32)
                || blob.size == 0
                || blob.size > MAX_BLOB_BYTES
                || !hashes.insert(&blob.sha256)
            {
                return Err(PolicyError::Bounds);
            }
        }
        if usize::from(self.desired_groups) > groups.len()
            || (self.desired_groups > 0 && self.blobs.is_empty())
        {
            return Err(PolicyError::Bounds);
        }
        Ok(())
    }
}

pub fn policy_template(
    policy: Policy,
    owner: &str,
    now: u64,
) -> Result<UnsignedEvent, PolicyError> {
    policy.validate()?;
    if policy.expires_at <= now {
        return Err(PolicyError::Time);
    }
    if !canonical_hex(owner, 32) {
        return Err(PolicyError::Signature);
    }
    let public_key = PublicKey::from_hex(owner).map_err(|_| PolicyError::Signature)?;
    let tags = vec![
        Tag::parse([
            "d".to_owned(),
            format!("wildbloom.replica-policy.v1:{}", policy.id),
        ])
        .map_err(|_| PolicyError::Schema)?,
        Tag::parse(["expiration".to_owned(), policy.expires_at.to_string()])
            .map_err(|_| PolicyError::Schema)?,
    ];
    let content = serde_json::to_string(&policy).map_err(|_| PolicyError::Schema)?;
    Ok(UnsignedEvent::new(
        public_key,
        Timestamp::from_secs(now),
        Kind::from(30078),
        tags,
        content,
    ))
}

pub fn verify_policy(bytes: &[u8], owner: &str, now: u64) -> Result<VerifiedPolicy, PolicyError> {
    let event = signed_event(bytes, owner, MAX_POLICY_BYTES)?;
    if event.kind.as_u16() != 30078 {
        return Err(PolicyError::Schema);
    }
    let policy: Policy = serde_json::from_str(&event.content).map_err(|_| PolicyError::Schema)?;
    policy.validate()?;
    if policy.expires_at <= now
        || event.created_at.as_secs() > now.saturating_add(30)
        || event.created_at.as_secs() >= policy.expires_at
    {
        return Err(PolicyError::Time);
    }
    let expected = policy_template(policy.clone(), owner, event.created_at.as_secs())?;
    if event.tags != expected.tags || event.content != expected.content {
        return Err(PolicyError::Schema);
    }
    Ok(VerifiedPolicy {
        policy,
        owner: owner.to_owned(),
        event_id: event.id.to_hex(),
    })
}

pub fn repair_template(
    policy: &VerifiedPolicy,
    blob: &Blob,
    target: &Target,
    now: u64,
) -> Result<UnsignedEvent, PolicyError> {
    let origin = Url::parse(&target.origin).map_err(|_| PolicyError::Origin)?;
    let server = origin.host_str().ok_or(PolicyError::Origin)?;
    let tags = [
        vec!["t".to_owned(), "upload".to_owned()],
        vec!["x".to_owned(), blob.sha256.clone()],
        vec!["server".to_owned(), server.to_owned()],
        vec![
            "expiration".to_owned(),
            now.saturating_add(120)
                .min(policy.policy.expires_at)
                .to_string(),
        ],
    ]
    .into_iter()
    .map(Tag::parse)
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| PolicyError::Schema)?;
    let key = PublicKey::from_hex(&policy.owner).map_err(|_| PolicyError::Signature)?;
    Ok(UnsignedEvent::new(
        key,
        Timestamp::from_secs(now.saturating_sub(1)),
        Kind::from(24242),
        tags,
        format!(
            "Mirror one configured blob; policy event {}; destination {}",
            policy.event_id, target.origin
        ),
    ))
}

pub fn verify_return(
    bytes: &[u8],
    request: &UnsignedEvent,
    now: u64,
) -> Result<Event, PolicyError> {
    let event = signed_event(bytes, &request.pubkey.to_hex(), MAX_EVENT_BYTES)?;
    if event.id != request.compute_id() {
        return Err(PolicyError::ChangedRequest);
    }
    let origin_tag = request
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().is_some_and(|t| t == "server"))
        .and_then(|tag| tag.as_slice().get(1))
        .ok_or(PolicyError::Schema)?;
    let hash = request
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().is_some_and(|t| t == "x"))
        .and_then(|tag| tag.as_slice().get(1))
        .ok_or(PolicyError::Schema)?;
    use base64::Engine as _;
    let header = format!(
        "Nostr {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    wildbloom_core::auth::AuthPolicy::new([origin_tag.clone()])
        .with_allowed_pubkeys([request.pubkey.to_hex()])
        .verify_upload(Some(&header), hash, now)
        .map_err(|_| PolicyError::Time)?;
    Ok(event)
}
