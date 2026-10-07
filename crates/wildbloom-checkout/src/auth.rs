use crate::{Error, digest};
use base64::Engine;
use nostr::prelude::{Event, Kind};

/// Constructible only through NIP-98 signature verification.
#[derive(Debug, Clone)]
pub struct Principal {
    pub(crate) pubkey: String,
}
impl Principal {
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }
}

/// Checkout's strict NIP-98 profile. Exact strings are checked before crypto;
/// body hashes are mandatory for POST, even for an empty body. Repeated signed
/// requests are safe only because every mutation is idempotent by order ID.
pub fn authenticate(
    header: &str,
    url: &str,
    method: &str,
    body: &[u8],
    now: u64,
) -> Result<Principal, Error> {
    if header.len() > 12_000 || body.len() > 16_384 || !matches!(method, "GET" | "POST") {
        return Err(Error::Unauthorised);
    }
    let encoded = header.strip_prefix("Nostr ").ok_or(Error::Unauthorised)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Error::Unauthorised)?;
    if decoded.len() > 8192 {
        return Err(Error::Unauthorised);
    }
    let event = Event::from_json(decoded).map_err(|_| Error::Unauthorised)?;
    let created = event.created_at.as_secs();
    if event.kind != Kind::HttpAuth
        || !event.content.is_empty()
        || created > now.saturating_add(30)
        || now > created.saturating_add(60)
    {
        return Err(Error::Unauthorised);
    }
    let tag = |name: &str| -> Result<Option<&str>, Error> {
        let tags: Vec<_> = event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().is_some_and(|v| v == name))
            .collect();
        match tags.as_slice() {
            [] => Ok(None),
            [t] if t.as_slice().len() == 2 => Ok(Some(t.as_slice()[1].as_str())),
            _ => Err(Error::Unauthorised),
        }
    };
    if tag("u")? != Some(url) || tag("method")? != Some(method) {
        return Err(Error::Unauthorised);
    }
    let expected = digest(body);
    if method == "POST" && tag("payload")? != Some(expected.as_str()) {
        return Err(Error::Unauthorised);
    }
    if method == "GET" && (!body.is_empty() || tag("payload")?.is_some()) {
        return Err(Error::Unauthorised);
    }
    event.verify().map_err(|_| Error::Unauthorised)?;
    Ok(Principal {
        pubkey: event.pubkey.to_hex(),
    })
}
