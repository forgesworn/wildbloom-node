//! The Foregather live relay over HTTP, mirroring the browser kit's
//! `createLiveRelayClient` (allocate, send, receive, delete) for the inviter.
//!
//! Capabilities (the creation grant, inviter and delete tokens) travel only in
//! `Authorization: Bearer`, never in a path, query, log or error.  Responses
//! are bounded to 24 KiB, redirects are refused and reads retry a transient
//! failure at most twice, as the browser transport does.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::StreamExt as _;
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

const MAX_BODY: usize = 24 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    #[error("the pairing relay did not answer")]
    Unreachable,
    #[error("the pairing relay answered HTTP {0}")]
    Http(u16),
    #[error("the pairing relay returned something unexpected")]
    Invalid,
}

impl RelayError {
    pub(crate) fn transient(&self) -> bool {
        matches!(
            self,
            Self::Unreachable | Self::Http(408 | 429 | 502 | 503 | 504)
        )
    }
}

/// A canonical 32-byte unpadded base64url capability.  Never printed.
#[derive(Clone)]
pub struct Capability(Zeroizing<String>);

impl Capability {
    fn parse(value: &str) -> Result<Self, RelayError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| RelayError::Invalid)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err(RelayError::Invalid);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    pub fn from_grant(token: &str) -> Result<Self, RelayError> {
        Self::parse(token)
    }

    fn bearer(&self) -> Result<header::HeaderValue, RelayError> {
        let mut value = header::HeaderValue::from_str(&format!("Bearer {}", self.0.as_str()))
            .map_err(|_| RelayError::Invalid)?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Capability([redacted])")
    }
}

#[derive(Serialize)]
struct AllocateRequest<'a> {
    session: &'a foregather_kit::live::Session,
    secret_format: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocatedRoom {
    session: foregather_kit::live::Session,
    secret_format: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    room: AllocatedRoom,
    #[allow(dead_code)]
    room_code: String,
    inviter_token: String,
    delete_token: String,
}

/// An allocated live session: where it is and the inviter's capabilities.
#[derive(Debug)]
pub struct InviterSession {
    pub locator: String,
    inviter: Capability,
    delete: Capability,
}

/// One relay API base such as `https://relay.example/pair/v1/`.
#[derive(Clone, Debug)]
pub struct Relay {
    base: Url,
    http: Client,
}

impl Relay {
    /// HTTPS (or loopback HTTP when allowed) base ending in `/`.
    pub fn new(base: &str, allow_loopback_http: bool, http: Client) -> Result<Self, RelayError> {
        let url = Url::parse(base).map_err(|_| RelayError::Invalid)?;
        let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.as_str() != base
            || !url.path().ends_with('/')
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !(url.scheme() == "https"
                || allow_loopback_http && url.scheme() == "http" && loopback)
        {
            return Err(RelayError::Invalid);
        }
        Ok(Self { base: url, http })
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        capability: &Capability,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, Vec<u8>), RelayError> {
        let url = self.base.join(path).map_err(|_| RelayError::Invalid)?;
        let mut request = self
            .http
            .request(method, url)
            .header(header::ACCEPT, "application/json")
            .header(header::AUTHORIZATION, capability.bearer()?)
            .timeout(REQUEST_TIMEOUT);
        if let Some(body) = body {
            if body.len() > MAX_BODY {
                return Err(RelayError::Invalid);
            }
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = request.send().await.map_err(|_| RelayError::Unreachable)?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY as u64)
        {
            return Err(RelayError::Invalid);
        }
        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| RelayError::Unreachable)?;
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err(RelayError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }

    /// `POST live-sessions` with the public room and a creation grant.
    pub async fn allocate(
        &self,
        session: &foregather_kit::live::Session,
        grant: &Capability,
    ) -> Result<InviterSession, RelayError> {
        let body = serde_json::to_vec(&AllocateRequest {
            session,
            secret_format: "words",
        })
        .map_err(|_| RelayError::Invalid)?;
        let (status, bytes) = self
            .request(reqwest::Method::POST, "live-sessions", grant, Some(body))
            .await?;
        if status != StatusCode::CREATED && status != StatusCode::OK {
            return Err(RelayError::Http(status.as_u16()));
        }
        let allocation: Allocation =
            serde_json::from_slice(&bytes).map_err(|_| RelayError::Invalid)?;
        let returned = &allocation.room.session;
        if allocation.room.secret_format != "words"
            || returned.locator != session.locator
            || returned.profile != session.profile
            || returned.namespace != session.namespace
            || returned.purpose != session.purpose
            || returned.issued != session.issued
            || returned.expires != session.expires
        {
            return Err(RelayError::Invalid);
        }
        Ok(InviterSession {
            locator: session.locator.clone(),
            inviter: Capability::parse(&allocation.inviter_token)?,
            delete: Capability::parse(&allocation.delete_token)?,
        })
    }

    /// Write-once `PUT`; an uncertain write is retried with identical bytes.
    pub async fn send(
        &self,
        session: &InviterSession,
        kind: &str,
        value: &[u8],
    ) -> Result<(), RelayError> {
        let path = format!("live-sessions/{}/messages/inviter/{kind}", session.locator);
        let mut attempt = 0;
        loop {
            match self
                .request(
                    reqwest::Method::PUT,
                    &path,
                    &session.inviter,
                    Some(value.to_vec()),
                )
                .await
            {
                Ok((status, _)) if status.is_success() => return Ok(()),
                Ok((status, _)) => {
                    let error = RelayError::Http(status.as_u16());
                    if attempt >= 2 || !error.transient() {
                        return Err(error);
                    }
                }
                Err(error) if attempt < 2 && error.transient() => {}
                Err(error) => return Err(error),
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
        }
    }

    /// One poll of the recipient's `kind` message: `None` while absent.
    pub async fn poll(
        &self,
        session: &InviterSession,
        kind: &str,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let path = format!(
            "live-sessions/{}/messages/recipient/{kind}",
            session.locator
        );
        let mut attempt = 0;
        loop {
            let result = self
                .request(reqwest::Method::GET, &path, &session.inviter, None)
                .await;
            match result {
                Ok((StatusCode::OK, bytes)) => return Ok(Some(bytes)),
                Ok((StatusCode::NOT_FOUND, _)) => return Ok(None),
                Ok((status, _)) => {
                    let error = RelayError::Http(status.as_u16());
                    if attempt >= 2 || !error.transient() {
                        return Err(error);
                    }
                }
                Err(error) if attempt < 2 && error.transient() => {}
                Err(error) => return Err(error),
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
        }
    }

    /// `DELETE live-sessions/<locator>` with the deletion capability.
    pub async fn delete(&self, session: &InviterSession) -> Result<(), RelayError> {
        let path = format!("live-sessions/{}", session.locator);
        let (status, _) = self
            .request(reqwest::Method::DELETE, &path, &session.delete, None)
            .await?;
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(RelayError::Http(status.as_u16()))
        }
    }
}

/// A hello or proof as the relay stores it: a JSON string.
pub fn public_message(value: &str) -> Vec<u8> {
    serde_json::to_vec(value).expect("a string always serialises")
}

/// Reads a hello or proof back out of its JSON string.
pub fn parse_public_message(bytes: &[u8]) -> Result<String, RelayError> {
    serde_json::from_slice::<String>(bytes).map_err(|_| RelayError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bases_and_capabilities_are_strict() {
        let http = Client::new();
        assert!(Relay::new("https://relay.example/pair/v1/", false, http.clone()).is_ok());
        assert!(Relay::new("https://relay.example/pair/v1", false, http.clone()).is_err());
        assert!(Relay::new("http://relay.example/v1/", true, http.clone()).is_err());
        assert!(Relay::new("http://127.0.0.1:8787/v1/", false, http.clone()).is_err());
        assert!(Relay::new("http://127.0.0.1:8787/v1/", true, http).is_ok());
        let token = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert!(Capability::parse(&token).is_ok());
        assert!(Capability::parse(&format!("{token}=")).is_err());
        assert!(Capability::parse(&URL_SAFE_NO_PAD.encode([7u8; 31])).is_err());
        assert_eq!(
            format!("{:?}", Capability::parse(&token).unwrap()),
            "Capability([redacted])"
        );
        assert_eq!(public_message("abc"), b"\"abc\"");
        assert_eq!(parse_public_message(b"\"abc\"").unwrap(), "abc");
    }
}
