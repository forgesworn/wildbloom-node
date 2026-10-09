//! Explicit operator destination pins: no ambient proxy, DNS or redirects.
use crate::{Error, NoteTransport, RefundTransport, SensitiveUrl, TransportFailure};
use reqwest::{Client, Response};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
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

/// HTTPS-only customer refund transport. The first request to an origin resolves
/// it once, rejects local/special-use addresses and pins that exact address set
/// for the rest of the command. Redirects and ambient proxies remain disabled.
pub struct HttpRefundTransport {
    allow_loopback_http: bool,
    clients: tokio::sync::Mutex<HashMap<String, PinnedClient>>,
}
impl HttpRefundTransport {
    pub fn new(allow_loopback_http: bool) -> Self {
        Self {
            allow_loopback_http,
            clients: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
    async fn client(&self, url: &Url) -> Result<PinnedClient, TransportFailure> {
        let host = url.host_str().ok_or(TransportFailure)?;
        let port = url.port_or_known_default().ok_or(TransportFailure)?;
        let loopback_name = host.eq_ignore_ascii_case("localhost");
        if !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || host.ends_with(".onion")
            || (url.scheme() != "https"
                && !(url.scheme() == "http" && self.allow_loopback_http && loopback_name))
        {
            return Err(TransportFailure);
        }
        // Literal public IP destinations have no hostname identity to pin.
        if host.parse::<IpAddr>().is_ok() && !(self.allow_loopback_http && is_loopback(host)) {
            return Err(TransportFailure);
        }
        let origin = format!("{}://{}:{}/", url.scheme(), host, port);
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(&origin) {
            return Ok(client.clone());
        }
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| TransportFailure)?
            .filter(|address| {
                if self.allow_loopback_http && loopback_name {
                    address.ip().is_loopback()
                } else {
                    public_ip(address.ip())
                }
            })
            .take(17)
            .collect();
        if addresses.is_empty() || addresses.len() > 16 {
            return Err(TransportFailure);
        }
        let client = PinnedClient::new(Destination {
            origin: origin.clone(),
            addresses,
            allow_loopback_http: self.allow_loopback_http && loopback_name,
        })
        .map_err(|_| TransportFailure)?;
        clients.insert(origin, client.clone());
        Ok(client)
    }
}
fn is_loopback(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(mapped));
            }
            let s = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x0064 && s[1] == 0xff9b)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                || (s[0] == 0x2001 && s[1] == 0)
                || (s[0] == 0x2001 && s[1] == 2)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || s[0] == 0x2002)
        }
    }
}
#[async_trait::async_trait]
impl RefundTransport for HttpRefundTransport {
    async fn get(&self, sensitive: &SensitiveUrl) -> Result<Vec<u8>, TransportFailure> {
        let url = Url::parse(sensitive.expose()).map_err(|_| TransportFailure)?;
        let client = self.client(&url).await?;
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

#[cfg(test)]
mod refund_tests {
    use super::public_ip;
    use std::net::IpAddr;

    #[test]
    fn refund_dns_filter_refuses_private_special_and_transition_addresses() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "100::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(!public_ip(value.parse::<IpAddr>().unwrap()), "{value}");
        }
        for value in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_ip(value.parse::<IpAddr>().unwrap()), "{value}");
        }
    }
}
