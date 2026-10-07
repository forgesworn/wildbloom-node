//! Explicit operator destination pins: no ambient proxy, DNS or redirects.
use crate::{Error, NoteTransport, SensitiveUrl, TransportFailure};
use reqwest::{Client, Response};
use std::{net::SocketAddr, time::Duration};
use url::Url;

/// A hostname and its operator-approved socket addresses. TLS still verifies the
/// URL hostname. Changing DNS requires an explicit configuration refresh.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub origin: String,
    pub addresses: Vec<SocketAddr>,
    pub allow_loopback_http: bool,
}
#[derive(Clone)]
pub(crate) struct PinnedClient {
    pub(crate) client: Client,
    origin: Url,
}
impl PinnedClient {
    pub(crate) fn new(pin: Destination) -> Result<Self, Error> {
        let origin = Url::parse(&pin.origin).map_err(|_| Error::Invalid)?;
        let host = origin.host_str().ok_or(Error::Invalid)?;
        if origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || host.ends_with(".onion")
            || pin.addresses.is_empty()
            || pin.addresses.len() > 16
        {
            return Err(Error::Invalid);
        }
        let port = origin.port_or_known_default().ok_or(Error::Invalid)?;
        if pin
            .addresses
            .iter()
            .any(|a| a.port() != port || a.ip().is_unspecified() || a.ip().is_multicast())
        {
            return Err(Error::Invalid);
        }
        if origin.scheme() != "https"
            && !(origin.scheme() == "http"
                && pin.allow_loopback_http
                && pin.addresses.iter().all(|a| a.ip().is_loopback()))
        {
            return Err(Error::Invalid);
        }
        // Literal IP URLs bypass the resolver, so require the same literal pin.
        let literal = match origin.host() {
            Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
            _ => None,
        };
        if literal.is_some_and(|ip| pin.addresses.iter().any(|a| a.ip() != ip)) {
            return Err(Error::Invalid);
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(12))
            .referer(false)
            .resolve_to_addrs(host, &pin.addresses)
            .build()
            .map_err(|_| Error::Invalid)?;
        Ok(Self { client, origin })
    }
    pub(crate) fn url(&self, value: &str) -> Result<Url, TransportFailure> {
        let url = Url::parse(value).map_err(|_| TransportFailure)?;
        if url.origin() != self.origin.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportFailure);
        }
        Ok(url)
    }
    pub(crate) fn path(&self, path: &str) -> Result<Url, TransportFailure> {
        self.origin.join(path).map_err(|_| TransportFailure)
    }
}
pub(crate) async fn bounded(mut response: Response) -> Result<Vec<u8>, TransportFailure> {
    const MAX: usize = 65536;
    if !response.status().is_success()
        || response.content_length().is_some_and(|n| n > MAX as u64)
        || response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
    {
        return Err(TransportFailure);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| TransportFailure)? {
        if chunk.len() > MAX - body.len() {
            return Err(TransportFailure);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
/// Only the configured issuer note endpoint can be fetched; queries contain
/// assets and are deliberately never included in errors or Debug output.
pub struct HttpNoteTransport {
    endpoints: Vec<(Url, PinnedClient)>,
}
impl HttpNoteTransport {
    pub fn new(endpoints: Vec<(String, Destination)>) -> Result<Self, Error> {
        if endpoints.is_empty() || endpoints.len() > 32 {
            return Err(Error::Invalid);
        }
        let endpoints = endpoints
            .into_iter()
            .map(|(endpoint, pin)| {
                let client = PinnedClient::new(pin)?;
                let url = client.url(&endpoint).map_err(|_| Error::Invalid)?;
                if url.query().is_some() {
                    return Err(Error::Invalid);
                }
                Ok((url, client))
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self { endpoints })
    }
}
#[async_trait::async_trait]
impl NoteTransport for HttpNoteTransport {
    async fn get(&self, sensitive: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure> {
        let url = Url::parse(sensitive.expose()).map_err(|_| TransportFailure)?;
        let (_, client) = self
            .endpoints
            .iter()
            .find(|(endpoint, _)| {
                endpoint.origin() == url.origin() && endpoint.path() == url.path()
            })
            .ok_or(TransportFailure)?;
        let url = client.url(sensitive.expose())?;
        bounded(
            client
                .client
                .get(url)
                .send()
                .await
                .map_err(|_| TransportFailure)?,
        )
        .await
    }
}
