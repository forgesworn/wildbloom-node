//! Transport-neutral blob fetching.
//!
//! The Blossom router and the store decide *whether* a blob may be mirrored or
//! repaired, and they verify every byte that arrives.  A [`BlobFetcher`]
//! decides only *how* the bytes travel: through Tor, plain HTTPS, loopback or
//! a future native lane.  A fetcher never sees authorisation events,
//! retention tiers or the owner's Nostr identity, and it never writes to
//! storage.  Transport success therefore never promotes a claim and never
//! proves durable custody.

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, future::BoxFuture, stream::BoxStream};
use std::{fmt, time::Duration};
use url::Url;

/// One request for the bytes of a content-addressed blob.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// Source already accepted by the router's mirror policy.
    pub source: Url,
    /// Lower-case hexadecimal SHA-256 the router expects.  A hint for
    /// hash-addressed transports; the router still verifies the digest.
    pub sha256: String,
    /// Exact size the router expects when it already knows it, as it does
    /// during repair.  A hint; the router still enforces the exact length.
    pub expected_size: Option<u64>,
}

/// Which kind of path carried a fetched blob.
///
/// Recorded on every successful mirror and repair so that evidence states the
/// transport that was actually used rather than inferring it from the fact
/// that a fetch succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchPath {
    /// A Tor circuit, whether to an onion service or a public HTTPS origin.
    Tor,
    /// Ordinary HTTPS on the open internet.
    Https,
    /// A direct peer-to-peer path.
    Direct,
    /// An opaque relay carried the bytes.
    Relayed,
    /// Loopback, used by tests and local shells.
    Loopback,
}

impl fmt::Display for FetchPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Tor => "tor",
            Self::Https => "https",
            Self::Direct => "direct",
            Self::Relayed => "relayed",
            Self::Loopback => "loopback",
        })
    }
}

/// A fetched blob whose bytes are still streaming.
pub struct FetchedBlob {
    /// The path that is carrying the bytes.
    pub path: FetchPath,
    /// Size the source declared.  The router rejects any stream that does
    /// not deliver exactly this many bytes.
    pub size: u64,
    /// Media type the source declared, unfiltered.
    pub content_type: Option<String>,
    /// The bytes, delivered in bounded chunks.  Never buffered whole.
    pub body: BoxStream<'static, Result<Bytes, FetchError>>,
}

impl fmt::Debug for FetchedBlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchedBlob")
            .field("path", &self.path)
            .field("size", &self.size)
            .field("content_type", &self.content_type)
            .finish_non_exhaustive()
    }
}

/// Why a fetch did not produce a usable stream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError {
    #[error("the configured fetcher does not support this source")]
    UnsupportedSource,
    #[error("mirror origin could not be reached: {0}")]
    Unreachable(String),
    #[error("mirror origin returned status {0}")]
    UnusableStatus(u16),
    #[error("mirror origin omitted Content-Length")]
    MissingLength,
    #[error("mirror origin stream failed: {0}")]
    Stream(String),
}

/// A way to obtain the bytes of one blob from a source the router has
/// already accepted.
///
/// Implementations own the network path and nothing else.  They must return
/// a bounded stream rather than a buffered body, must not follow redirects
/// to sources the router has not vetted, and must report the [`FetchPath`]
/// they actually used.
pub trait BlobFetcher: Send + Sync + 'static {
    /// Starts fetching `request`.  Returns once the source has accepted the
    /// request and declared a size; the bytes themselves arrive through
    /// [`FetchedBlob::body`].
    fn fetch(&self, request: FetchRequest) -> BoxFuture<'_, Result<FetchedBlob, FetchError>>;
}

/// Why a fetcher could not be configured.
#[derive(Debug, thiserror::Error)]
pub enum FetchConfigError {
    #[error("mirror proxy must be a loopback socks5h URL")]
    UnsafeProxy,
    #[error("failed to configure the mirror client: {0}")]
    Client(#[from] reqwest::Error),
}

/// HTTP fetcher that speaks only through a loopback `socks5h://` proxy.
///
/// This is how the node reaches onion services and public HTTPS origins
/// through Tor without resolving names locally.  It is the only adapter the
/// node ships today and the default behaviour when a managed Tor process is
/// running.
#[derive(Debug, Clone)]
pub struct TorHttpFetcher {
    client: reqwest::Client,
}

impl TorHttpFetcher {
    /// Builds a fetcher over `proxy_url`, which must be a bare loopback
    /// `socks5h://` address with a port and no credentials, path, query or
    /// fragment.
    pub fn new(proxy_url: Url) -> Result<Self, FetchConfigError> {
        if proxy_url.scheme() != "socks5h"
            || !proxy_url.username().is_empty()
            || proxy_url.password().is_some()
            || !matches!(proxy_url.path(), "" | "/")
            || proxy_url.query().is_some()
            || proxy_url.fragment().is_some()
            || !proxy_url
                .host_str()
                .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback())
            || proxy_url.port().is_none()
        {
            return Err(FetchConfigError::UnsafeProxy);
        }
        let proxy = reqwest::Proxy::all(proxy_url.as_str())?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(10 * 60))
            .user_agent(concat!("wildbloom-node/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client })
    }
}

impl BlobFetcher for TorHttpFetcher {
    fn fetch(&self, request: FetchRequest) -> BoxFuture<'_, Result<FetchedBlob, FetchError>> {
        Box::pin(async move {
            if !matches!(request.source.scheme(), "http" | "https") {
                return Err(FetchError::UnsupportedSource);
            }
            let response = self
                .client
                .get(request.source)
                .send()
                .await
                .map_err(|error| FetchError::Unreachable(error.to_string()))?;
            let status = response.status();
            if status != reqwest::StatusCode::OK {
                return Err(FetchError::UnusableStatus(status.as_u16()));
            }
            let size = response.content_length().ok_or(FetchError::MissingLength)?;
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = response
                .bytes_stream()
                .map_err(|error| FetchError::Stream(error.to_string()))
                .boxed();
            Ok(FetchedBlob {
                path: FetchPath::Tor,
                size,
                content_type,
                body,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_fetcher_requires_a_loopback_socks5h_proxy() {
        let loopback = Url::parse("socks5h://127.0.0.1:39050").unwrap();
        assert!(
            TorHttpFetcher::new(loopback.clone()).is_ok(),
            "loopback socks5h must be accepted"
        );
        assert!(matches!(
            TorHttpFetcher::new(Url::parse("http://127.0.0.1:39050").unwrap()),
            Err(FetchConfigError::UnsafeProxy)
        ));
        assert!(matches!(
            TorHttpFetcher::new(Url::parse("socks5h://192.0.2.1:39050").unwrap()),
            Err(FetchConfigError::UnsafeProxy)
        ));
        assert!(matches!(
            TorHttpFetcher::new(Url::parse("socks5h://user@127.0.0.1:39050").unwrap()),
            Err(FetchConfigError::UnsafeProxy)
        ));
        assert!(matches!(
            TorHttpFetcher::new(Url::parse("socks5h://127.0.0.1:39050/path").unwrap()),
            Err(FetchConfigError::UnsafeProxy)
        ));
    }

    #[tokio::test]
    async fn tor_fetcher_refuses_sources_that_are_not_http() {
        let fetcher =
            TorHttpFetcher::new(Url::parse("socks5h://127.0.0.1:39050").unwrap()).unwrap();
        let result = fetcher
            .fetch(FetchRequest {
                source: Url::parse("ftp://origin.example/blob").unwrap(),
                sha256: "a".repeat(64),
                expected_size: None,
            })
            .await;
        assert!(matches!(result, Err(FetchError::UnsupportedSource)));
    }

    #[test]
    fn fetch_paths_have_stable_labels() {
        assert_eq!(FetchPath::Tor.to_string(), "tor");
        assert_eq!(FetchPath::Https.to_string(), "https");
        assert_eq!(FetchPath::Direct.to_string(), "direct");
        assert_eq!(FetchPath::Relayed.to_string(), "relayed");
        assert_eq!(FetchPath::Loopback.to_string(), "loopback");
    }
}
