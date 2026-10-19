//! Opt-in pairing issuer: a currently granted device exchanges one fresh
//! NIP-98 request for a one-use Foregather `live` creation grant.
//!
//! The NIP-98 profile, device check and budget are the shared
//! [`DeviceAuth`] gate, with a budget of its own.  The operator token reaches
//! Foregather only in this module's outbound `Authorization` header.  It is
//! never logged, echoed or returned.
use super::{
    ApiError, Grants, cors,
    device_auth::{DeviceAuth, Refusals},
    no_store,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};
use url::Url;

pub const ISSUER_PATH: &str = "pairing/v1/live-grants";
/// Environment form of the operator token.  Child processes never inherit it;
/// prefer `--pairing-operator-token-file`.
pub const TOKEN_ENV: &str = "WILDBLOOM_PAIRING_OPERATOR_TOKEN";
/// Foregather's maximum live session lifetime.
pub const MAX_INVITATION_LIFETIME: u64 = 600;
/// A creation grant only needs to cover the allocation that follows it.
pub const GRANT_TTL: u64 = 300;
/// Per-device issuance budget within any rolling hour.
pub const RATE_LIMIT: u32 = 30;
const MAX_UPSTREAM_BYTES: usize = 4096;
static REFUSALS: Refusals = Refusals {
    unauthorised: "pairing request is not authorised",
    spent: "pairing request budget is spent",
    replayed: "pairing request was already used",
};

/// The Foregather operator creation token.  Debug output is redacted.
#[derive(Clone)]
pub struct OperatorToken(Arc<str>);

impl std::fmt::Debug for OperatorToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OperatorToken([redacted])")
    }
}

impl OperatorToken {
    /// Accepts only Foregather's canonical form: 32 bytes as unpadded base64url.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let value = value.trim_matches(|c: char| c.is_ascii_whitespace());
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| "the pairing operator token must be canonical unpadded base64url")?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
            return Err("the pairing operator token must encode exactly 32 bytes");
        }
        Ok(Self(Arc::from(value)))
    }

    pub fn from_file(path: &Path) -> Result<Self, &'static str> {
        let bytes = wildbloom_checkout::read_private_file(path).map_err(
            |_| "the pairing operator token file must be an absolute, private (0600) regular file",
        )?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "the pairing operator token file is not UTF-8")?;
        Self::parse(text)
    }

    fn bearer(&self) -> Result<HeaderValue, ApiError> {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.0))
            .map_err(|_| ApiError::unavailable())?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// Validate the Foregather API base: HTTPS, or plain HTTP only to loopback.
pub fn relay_api_url(url: &Url) -> Result<Url, &'static str> {
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain == "localhost",
        None => false,
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(
            "--pairing-relay-url must be an HTTPS (or loopback HTTP) base URL ending in / without credentials, query or fragment",
        );
    }
    url.join("v1/creation-grants")
        .map_err(|_| "--pairing-relay-url cannot be joined")
}

#[derive(Clone)]
pub struct Issuer {
    auth: DeviceAuth,
    endpoint: Url,
    token: OperatorToken,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct UpstreamRequest {
    resource: &'static str,
    expires: u64,
    max_uses: u32,
    max_invitation_lifetime: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct UpstreamGrant {
    id: String,
    token: String,
    resource: String,
    expires: u64,
    remaining: u32,
    max_invitation_lifetime: u64,
}

#[derive(Serialize)]
pub struct LiveGrant {
    pub token: String,
    pub resource: &'static str,
    pub expires: u64,
    pub remaining: u32,
    pub max_invitation_lifetime: u64,
}

impl Issuer {
    pub fn new(
        grants: Grants,
        relay_url: &Url,
        token: OperatorToken,
    ) -> Result<Self, &'static str> {
        let endpoint = relay_api_url(relay_url)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .user_agent(concat!(
                "wildbloom-node-pairing/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(|_| "could not build the pairing issuer HTTP client")?;
        Ok(Self {
            auth: DeviceAuth::new(grants, ISSUER_PATH, RATE_LIMIT, &REFUSALS),
            endpoint,
            token,
            client,
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(&format!("/{ISSUER_PATH}"), post(issue))
            .with_state(self.clone())
            .layer(cors(&[Method::POST]))
    }

    async fn request_grant(&self) -> Result<LiveGrant, ApiError> {
        let expires = self.auth.now().saturating_add(GRANT_TTL);
        let body = serde_json::to_vec(&UpstreamRequest {
            resource: "live",
            expires,
            max_uses: 1,
            max_invitation_lifetime: MAX_INVITATION_LIFETIME,
        })
        .map_err(|_| ApiError::unavailable())?;
        let upstream_failure = || {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "the pairing relay refused the grant",
            )
        };
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header(header::AUTHORIZATION, self.token.bearer()?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| {
                tracing::warn!("pairing relay is unreachable");
                ApiError::new(StatusCode::BAD_GATEWAY, "the pairing relay is unreachable")
            })?;
        let status = response.status();
        if status != reqwest::StatusCode::CREATED && status != reqwest::StatusCode::OK {
            tracing::warn!(
                status = status.as_u16(),
                "pairing relay refused a creation grant"
            );
            return Err(match status.as_u16() {
                429 | 503 | 507 => ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the pairing relay is at capacity",
                ),
                _ => upstream_failure(),
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| upstream_failure())? {
            if bytes.len() + chunk.len() > MAX_UPSTREAM_BYTES {
                return Err(upstream_failure());
            }
            bytes.extend_from_slice(&chunk);
        }
        let grant: UpstreamGrant =
            serde_json::from_slice(&bytes).map_err(|_| upstream_failure())?;
        let token_ok = URL_SAFE_NO_PAD.decode(&grant.token).is_ok_and(|decoded| {
            decoded.len() == 32 && URL_SAFE_NO_PAD.encode(&decoded) == grant.token
        });
        if !token_ok
            || grant.resource != "live"
            || grant.remaining != 1
            || grant.max_invitation_lifetime != MAX_INVITATION_LIFETIME
            || grant.expires != expires
        {
            tracing::warn!("pairing relay returned an unexpected creation grant");
            return Err(upstream_failure());
        }
        Ok(LiveGrant {
            token: grant.token,
            resource: "live",
            expires: grant.expires,
            remaining: grant.remaining,
            max_invitation_lifetime: grant.max_invitation_lifetime,
        })
    }
}

async fn issue(State(issuer): State<Issuer>, request: Request<Body>) -> Response {
    let result = async {
        issuer.auth.authorise(request).await?;
        issuer.request_grant().await
    }
    .await;
    match result {
        Ok(grant) => {
            tracing::info!("issued a one-use pairing creation grant");
            let mut response = (StatusCode::CREATED, Json(grant)).into_response();
            no_store(&mut response);
            response
        }
        Err(error) => error.into_response(),
    }
}
