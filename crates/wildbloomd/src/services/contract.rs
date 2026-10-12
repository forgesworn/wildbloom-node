//! The public storage profile shared with 402-announce. No I/O or private keys.
use nostr::prelude::{Event, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr};
use url::Url;
use wildbloom_checkout::{Issuer, Network, Offer, Rail};

use super::Error;

pub const PROFILE: &str = "forgesworn-storage-service-v1";
pub const MAX_BYTES: usize = 65_536;
const SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Description {
    pub profile: String,
    pub service_pubkey: String,
    pub identifier: String,
    pub name: String,
    pub about: String,
    pub origins: Vec<String>,
    pub max_blob_bytes: u64,
    pub observed_at: u64,
    pub expires_at: u64,
    pub state: ListingState,
    pub checkout: Option<Payment>,
    pub services: Vec<Service>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ListingState {
    Published,
    Withdrawn,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Availability {
    Accepting,
    Full,
    Paused,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    pub protocol: String,
    pub origin: String,
    pub network: Network,
    pub rails: Vec<Rail>,
    pub issuers: Vec<Issuer>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Service {
    #[serde(rename = "free-mirror")]
    Free {
        id: String,
        revision: u64,
        availability: Availability,
        operation: String,
        authorisation: String,
        retention: String,
        eviction_policy: String,
    },
    #[serde(rename = "paid-storage")]
    Paid {
        id: String,
        revision: u64,
        availability: Availability,
        capacity_bytes: u64,
        duration_seconds: u64,
        grace_seconds: u64,
        price_msat: u64,
        delivery_bytes: u64,
        delivery_policy: String,
        retention_policy: String,
        refund_policy: String,
    },
}
impl Service {
    pub fn id(&self) -> &str {
        match self {
            Self::Free { id, .. } | Self::Paid { id, .. } => id,
        }
    }
    pub fn availability(&self) -> Availability {
        match self {
            Self::Free { availability, .. } | Self::Paid { availability, .. } => *availability,
        }
    }
    pub fn pause(&mut self) {
        match self {
            Self::Free { availability, .. } | Self::Paid { availability, .. } => {
                *availability = Availability::Paused
            }
        }
    }
    pub fn paid(offer: &Offer, availability: Availability) -> Self {
        Self::Paid {
            id: offer.id.clone(),
            revision: offer.revision.into(),
            availability,
            capacity_bytes: offer.capacity_bytes,
            duration_seconds: offer.duration_seconds,
            grace_seconds: offer.grace_seconds,
            price_msat: offer.price_msat,
            delivery_bytes: offer.delivery_bytes,
            delivery_policy: offer.delivery_policy.clone(),
            retention_policy: offer.retention_policy.clone(),
            refund_policy: offer.refund_policy.clone(),
        }
    }
}
pub fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub fn text(value: &str, max: usize, multiline: bool) -> bool {
    !value.trim().is_empty()
        && value.encode_utf16().count() <= max
        && !value
            .chars()
            .any(|c| (c <= '\u{1f}' || c == '\u{7f}') && !(multiline && matches!(c, '\n' | '\t')))
}
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && matches!(o[1], 18 | 19))
                || (o[0] == 192 && o[1] == 88 && o[2] == 99))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(ip));
            }
            let s = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || s[0] & 0xfe00 == 0xfc00
                || s[0] & 0xffc0 == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0)
                || (s[0] == 0 && s[1..6].iter().all(|n| *n == 0)))
        }
    }
}
pub fn endpoint(value: &str, origin: bool, https_only: bool) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error)?;
    let host = url.host_str().ok_or(Error)?;
    if !text(value, 2048, false)
        || url.as_str() != value
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (origin && url.path() != "/")
        || url.port() == Some(0)
    {
        return Err(Error);
    }
    if host.ends_with(".onion") {
        if https_only
            || !matches!(url.scheme(), "http" | "https")
            || !crate::replicas::transport::valid_onion(host)
        {
            return Err(Error);
        }
    } else {
        if url.scheme() != "https"
            || host.ends_with('.')
            || host == "localhost"
            || host.ends_with(".localhost")
        {
            return Err(Error);
        }
        match url.host().ok_or(Error)? {
            url::Host::Ipv4(ip) if !public_ip(ip.into()) => return Err(Error),
            url::Host::Ipv6(ip) if !public_ip(ip.into()) => return Err(Error),
            url::Host::Domain(host) if !host.contains('.') => return Err(Error),
            _ => {}
        }
    }
    Ok(url)
}
impl Description {
    pub fn validate(&self) -> Result<(), Error> {
        let key = PublicKey::from_hex(&self.service_pubkey).map_err(|_| Error)?;
        if self.profile != PROFILE
            || key.to_hex() != self.service_pubkey
            || !id(&self.identifier)
            || !text(&self.name, 256, false)
            || !text(&self.about, 4096, false)
            || self.origins.is_empty()
            || self.origins.len() > 10
            || self.max_blob_bytes == 0
            || self.max_blob_bytes > SAFE
            || self.observed_at > SAFE
            || self.expires_at > SAFE
            || self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > 86400
            || self.services.is_empty()
            || self.services.len() > 32
        {
            return Err(Error);
        }
        let mut origins = BTreeSet::new();
        for origin in &self.origins {
            endpoint(origin, true, false)?;
            if !origins.insert(origin) {
                return Err(Error);
            }
        }
        let mut ids = BTreeSet::new();
        let mut free = 0;
        let mut paid = false;
        for service in &self.services {
            if !id(service.id())
                || !ids.insert(service.id())
                || (self.state == ListingState::Withdrawn
                    && service.availability() != Availability::Paused)
            {
                return Err(Error);
            }
            match service {
                Service::Free {
                    revision,
                    operation,
                    authorisation,
                    retention,
                    eviction_policy,
                    ..
                } => {
                    free += 1;
                    if *revision == 0
                        || *revision > SAFE
                        || free > 1
                        || operation != "mirror"
                        || authorisation != "bud-11"
                        || retention != "best-effort"
                        || !text(eviction_policy, 2048, true)
                    {
                        return Err(Error);
                    }
                }
                Service::Paid {
                    revision,
                    capacity_bytes,
                    duration_seconds,
                    grace_seconds,
                    price_msat,
                    delivery_bytes,
                    delivery_policy,
                    retention_policy,
                    refund_policy,
                    ..
                } => {
                    paid = true;
                    if [
                        revision,
                        capacity_bytes,
                        duration_seconds,
                        price_msat,
                        delivery_bytes,
                    ]
                    .iter()
                    .any(|n| **n == 0 || **n > SAFE)
                        || *grace_seconds > SAFE
                        || price_msat % 1000 != 0
                        || [delivery_policy, retention_policy, refund_policy]
                            .iter()
                            .any(|s| !text(s, 2048, true))
                    {
                        return Err(Error);
                    }
                }
            }
        }
        if paid != self.checkout.is_some() {
            return Err(Error);
        }
        if let Some(p) = &self.checkout {
            endpoint(&p.origin, true, true)?;
            if p.protocol != "wildbloom-checkout-v1"
                || !origins.contains(&p.origin)
                || p.rails.is_empty()
                || p.rails.len() > 2
                || (p.rails.len() == 2 && p.rails[0] == p.rails[1])
                || p.issuers.len() > 32
                || (p.rails.contains(&Rail::Lnurlcash)
                    && (p.network != Network::Bitcoin || p.issuers.is_empty()))
                || (!p.rails.contains(&Rail::Lnurlcash) && !p.issuers.is_empty())
            {
                return Err(Error);
            }
            let mut ids = BTreeSet::new();
            for issuer in &p.issuers {
                let note = endpoint(&issuer.note_endpoint, false, true)?;
                let callback = endpoint(&issuer.callback, false, true)?;
                if !id(&issuer.id)
                    || !ids.insert(&issuer.id)
                    || note.origin() != callback.origin()
                    || issuer.mint_pubkey.len() != 66
                    || !(issuer.mint_pubkey.starts_with("02")
                        || issuer.mint_pubkey.starts_with("03"))
                    || !issuer
                        .mint_pubkey
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(Error);
                }
            }
        }
        if serde_json::to_vec(self).map_err(|_| Error)?.len() > 60000 {
            return Err(Error);
        }
        Ok(())
    }
    pub fn capabilities(&self) -> Vec<Value> {
        self.services.iter().map(|s| match s {
            Service::Free { id, eviction_policy, .. } => json!({"name":id,"description":format!("Signed mirrors only; best-effort, evictable shelter. {eviction_policy}"),"endpoint":"/mirror"}),
            Service::Paid { id, capacity_bytes, duration_seconds, grace_seconds, delivery_bytes, retention_policy, .. } =>
                json!({"name":id,"description":format!("{capacity_bytes} ciphertext bytes for {duration_seconds} seconds; {grace_seconds} seconds grace; {delivery_bytes} delivery bytes. {retention_policy}"),"endpoint":"/checkout/v1/offers"}),
        }).collect()
    }
    pub fn template(&self, created_at: u64) -> Result<UnsignedEvent, Error> {
        self.validate()?;
        if created_at < self.observed_at
            || created_at - self.observed_at > 300
            || created_at >= self.expires_at
        {
            return Err(Error);
        }
        let mut tags = vec![
            vec!["d".into(), self.identifier.clone()],
            vec!["name".into(), self.name.clone()],
        ];
        tags.extend(self.origins.iter().map(|o| vec!["url".into(), o.clone()]));
        tags.extend([
            vec!["about".into(), self.about.clone()],
            vec!["source".into(), "self".into()],
            vec![
                "status".into(),
                if self.state == ListingState::Withdrawn {
                    "stale"
                } else {
                    "active"
                }
                .into(),
            ],
            vec!["expiration".into(), self.expires_at.to_string()],
            vec!["t".into(), "storage".into()],
            vec!["t".into(), "wildbloom".into()],
            vec!["t".into(), PROFILE.into()],
        ]);
        if let Some(payment) = &self.checkout {
            for rail in &payment.rails {
                let mut tag = vec![
                    "pmi".into(),
                    "wildbloom-checkout".into(),
                    match rail {
                        Rail::Lightning => "lightning",
                        Rail::Lnurlcash => "lnurlcash",
                    }
                    .into(),
                    match payment.network {
                        Network::Bitcoin => "bitcoin",
                        Network::Testnet => "testnet",
                        Network::Regtest => "regtest",
                    }
                    .into(),
                ];
                if *rail == Rail::Lnurlcash {
                    let mut seen = BTreeSet::new();
                    for issuer in &payment.issuers {
                        let host = endpoint(&issuer.note_endpoint, false, true)?
                            .host_str()
                            .ok_or(Error)?
                            .to_owned();
                        if seen.insert(host.clone()) {
                            tag.push(host);
                        }
                    }
                }
                tags.push(tag);
            }
        }
        for service in &self.services {
            let price = match service {
                Service::Paid { price_msat, .. } => price_msat / 1000,
                _ => 0,
            };
            tags.push(vec![
                "price".into(),
                service.id().into(),
                price.to_string(),
                "sats".into(),
            ]);
        }
        let tags = tags
            .into_iter()
            .map(Tag::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error)?;
        let content = json!({"storage": self, "capabilities": self.capabilities()}).to_string();
        let event = UnsignedEvent::new(
            PublicKey::from_hex(&self.service_pubkey).map_err(|_| Error)?,
            Timestamp::from(created_at),
            Kind::from(31402),
            tags,
            content,
        );
        let mut envelope = serde_json::to_value(&event).map_err(|_| Error)?;
        envelope["id"] = json!("0".repeat(64));
        envelope["sig"] = json!("0".repeat(128));
        if serde_json::to_vec(&envelope).map_err(|_| Error)?.len() > MAX_BYTES {
            return Err(Error);
        }
        Ok(event)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Content {
    storage: Description,
    capabilities: Vec<Value>,
}
/// Verify foreign contract fixtures, preserving expired records for replacement watermarks.
pub fn parse_event(bytes: &[u8], now: u64) -> Result<(Event, Description), Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error);
    }
    let event: Event = serde_json::from_slice(bytes).map_err(|_| Error)?;
    event.verify().map_err(|_| Error)?;
    if event.kind != Kind::from(31402) || event.created_at.as_secs() > now.saturating_add(30) {
        return Err(Error);
    }
    let content: Content = serde_json::from_str(&event.content).map_err(|_| Error)?;
    let expected = content.storage.template(event.created_at.as_secs())?;
    if event.pubkey != expected.pubkey || content.capabilities != content.storage.capabilities() {
        return Err(Error);
    }
    let sorted = |tags: &nostr::prelude::Tags| {
        let mut t = tags
            .iter()
            .map(|t| t.as_slice().to_vec())
            .collect::<Vec<_>>();
        t.sort();
        t
    };
    if sorted(&event.tags) != sorted(&expected.tags) {
        return Err(Error);
    }
    Ok((event, content.storage))
}
pub fn accept_signature(bytes: &[u8], request: &UnsignedEvent, now: u64) -> Result<Event, Error> {
    let (event, description) = parse_event(bytes, now)?;
    if event.id != request.compute_id() || description.expires_at <= now {
        return Err(Error);
    }
    Ok(event)
}
