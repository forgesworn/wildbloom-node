use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use url::Url;

use super::policy::{Blob, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    DirectHttps,
    TorOnly,
    LoopbackDevelopment,
}

impl Profile {
    pub fn accepts(self, url: &Url) -> bool {
        if url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port() == Some(0)
        {
            return false;
        }
        let Some(host) = url.host_str() else {
            return false;
        };
        match self {
            Self::DirectHttps => {
                url.scheme() == "https"
                    && valid_domain(host)
                    && !host.ends_with(".onion")
                    && host.parse::<IpAddr>().is_err()
            }
            Self::TorOnly => matches!(url.scheme(), "http" | "https") && valid_onion(host),
            // IPv4 only: current BUD-11 hostname scoping has no bare IPv6 form.
            Self::LoopbackDevelopment => {
                url.scheme() == "http" && host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
            }
        }
    }
}

fn valid_domain(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_onion(host: &str) -> bool {
    let Some(label) = host.strip_suffix(".onion") else {
        return false;
    };
    if label.len() != 56 {
        return false;
    }
    let mut decoded = Vec::with_capacity(35);
    let mut accumulator = 0_u32;
    let mut bits = 0;
    for byte in label.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return false,
        };
        accumulator = ((accumulator << 5) | u32::from(value)) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
        }
    }
    if decoded.len() != 35 || bits != 0 || decoded[34] != 3 {
        return false;
    }
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(&decoded[..32]);
    hasher.update([3]);
    decoded[32..34] == hasher.finalize()[..2]
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFailure {
    Unreachable,
    Unavailable,
    InvalidBytes,
    InvalidResponse,
    Refused,
}

// Errors deliberately contain no URL, bearer event, response text or file data.
pub trait Transport: Send + Sync {
    fn verify<'a>(
        &'a self,
        target: &'a Target,
        blob: &'a Blob,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>>;
    fn mirror<'a>(
        &'a self,
        target: &'a Target,
        source: &'a Target,
        blob: &'a Blob,
        authorization: &'a str,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>>;
}

// A signed stop policy must be recordable without configuring any network
// adapter, including when a formerly selected Tor listener is absent.
pub struct DisabledTransport;
impl Transport for DisabledTransport {
    fn verify<'a>(
        &'a self,
        _: &'a Target,
        _: &'a Blob,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async { Err(NetworkFailure::Refused) })
    }
    fn mirror<'a>(
        &'a self,
        _: &'a Target,
        _: &'a Target,
        _: &'a Blob,
        _: &'a str,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async { Err(NetworkFailure::Refused) })
    }
}

pub struct HttpTransport {
    client: reqwest::Client,
    profile: Profile,
}

impl HttpTransport {
    pub fn new(
        profile: Profile,
        proxy: Option<&Url>,
        permit_loopback: bool,
    ) -> Result<Self, &'static str> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(600))
            .user_agent(concat!(
                "wildbloom-node-replicas/",
                env!("CARGO_PKG_VERSION")
            ));
        match profile {
            Profile::DirectHttps if proxy.is_none() => {
                builder = builder.https_only(true).dns_resolver(PublicResolver);
            }
            Profile::TorOnly => {
                let proxy =
                    proxy.ok_or("Tor-only maintenance needs an explicit loopback socks5h proxy")?;
                // socks5h is a non-special URL scheme: the URL parser may
                // represent a numeric host as a domain. Parse the literal here.
                let loopback = proxy
                    .host_str()
                    .and_then(|host| {
                        host.trim_start_matches('[')
                            .trim_end_matches(']')
                            .parse::<IpAddr>()
                            .ok()
                    })
                    .is_some_and(|ip| ip.is_loopback());
                if proxy.scheme() != "socks5h"
                    || !loopback
                    || proxy.port().is_none()
                    || proxy.port() == Some(0)
                    || proxy.path() != "/" && !proxy.path().is_empty()
                    || !proxy.username().is_empty()
                    || proxy.password().is_some()
                    || proxy.query().is_some()
                    || proxy.fragment().is_some()
                {
                    return Err("Tor-only maintenance needs a bare loopback socks5h proxy");
                }
                builder = builder
                    .proxy(reqwest::Proxy::all(proxy.as_str()).map_err(|_| "invalid Tor proxy")?);
            }
            Profile::LoopbackDevelopment if permit_loopback && proxy.is_none() => {}
            _ => {
                return Err(
                    "selected transport conflicts with the supplied proxy or development consent",
                );
            }
        }
        Ok(Self {
            client: builder
                .build()
                .map_err(|_| "could not configure replica client")?,
            profile,
        })
    }

    fn origin(&self, target: &Target) -> Result<Url, NetworkFailure> {
        let origin = Url::parse(&target.origin).map_err(|_| NetworkFailure::Refused)?;
        if !self.profile.accepts(&origin) {
            return Err(NetworkFailure::Refused);
        }
        Ok(origin)
    }
}

impl Transport for HttpTransport {
    fn verify<'a>(
        &'a self,
        target: &'a Target,
        blob: &'a Blob,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async move {
            let url = self
                .origin(target)?
                .join(&blob.sha256)
                .map_err(|_| NetworkFailure::Refused)?;
            let mut response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|_| NetworkFailure::Unreachable)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(NetworkFailure::Unavailable);
            }
            if response.content_length() != Some(blob.size) {
                return Err(NetworkFailure::InvalidBytes);
            }
            let mut hasher = Sha256::new();
            let mut received = 0_u64;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| NetworkFailure::InvalidBytes)?
            {
                received = received
                    .checked_add(chunk.len() as u64)
                    .ok_or(NetworkFailure::InvalidBytes)?;
                if received > blob.size {
                    return Err(NetworkFailure::InvalidBytes);
                }
                hasher.update(&chunk);
            }
            if received != blob.size || hex::encode(hasher.finalize()) != blob.sha256 {
                return Err(NetworkFailure::InvalidBytes);
            }
            Ok(())
        })
    }

    fn mirror<'a>(
        &'a self,
        target: &'a Target,
        source: &'a Target,
        blob: &'a Blob,
        authorization: &'a str,
    ) -> BoxFuture<'a, Result<(), NetworkFailure>> {
        Box::pin(async move {
            let endpoint = self
                .origin(target)?
                .join("mirror")
                .map_err(|_| NetworkFailure::Refused)?;
            let source = self
                .origin(source)?
                .join(&blob.sha256)
                .map_err(|_| NetworkFailure::Refused)?;
            let mut header = reqwest::header::HeaderValue::from_str(authorization)
                .map_err(|_| NetworkFailure::Refused)?;
            header.set_sensitive(true);
            let mut response = self
                .client
                .put(endpoint)
                .header(reqwest::header::AUTHORIZATION, header)
                .json(&serde_json::json!({ "url": source.as_str() }))
                .send()
                .await
                .map_err(|_| NetworkFailure::Unreachable)?;
            if !matches!(response.status().as_u16(), 200 | 201) {
                return Err(NetworkFailure::Refused);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| NetworkFailure::InvalidResponse)?
            {
                if body.len().saturating_add(chunk.len()) > 16 * 1024 {
                    return Err(NetworkFailure::InvalidResponse);
                }
                body.extend_from_slice(&chunk);
            }
            #[derive(Deserialize)]
            struct Descriptor {
                url: String,
                sha256: String,
                size: u64,
                #[serde(rename = "type")]
                media_type: String,
                uploaded: u64,
            }
            let descriptor: Descriptor =
                serde_json::from_slice(&body).map_err(|_| NetworkFailure::InvalidResponse)?;
            // Never follow a descriptor URL. Read back from the operator's exact target.
            let descriptor_url =
                Url::parse(&descriptor.url).map_err(|_| NetworkFailure::InvalidResponse)?;
            if descriptor.sha256 != blob.sha256
                || descriptor.size != blob.size
                || descriptor.url.len() > 2048
                || descriptor.media_type.len() > 255
                || descriptor.uploaded == 0
                || !matches!(descriptor_url.scheme(), "http" | "https")
                || descriptor_url.host_str().is_none()
                || !descriptor_url.username().is_empty()
                || descriptor_url.password().is_some()
            {
                return Err(NetworkFailure::InvalidResponse);
            }
            Ok(())
        })
    }
}

#[derive(Debug)]
struct PublicResolver;

impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|address| public_ip(address.ip()))
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "no permitted public address",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19 || b == 51 && c == 100))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => public_ipv6(ip),
    }
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_ip(IpAddr::V4(v4));
    }
    let s = ip.segments();
    // Conservative globally routed unicast subset: exclude special-use,
    // transition, documentation and benchmarking assignments.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
        && s[0] != 0x2002
        && !(s[0] == 0x3fff && s[1] < 0x1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn profiles_refuse_cross_transport_origins_and_implicit_proxies() {
        for origin in [
            "http://example.com/",
            "https://127.0.0.1/",
            "https://user@example.com/",
            "https://example.com/a",
            "https://example.com/?x=1",
            "https://example.com/#x",
            "https://example.com:0/",
        ] {
            assert!(
                !Profile::DirectHttps.accepts(&Url::parse(origin).unwrap()),
                "{origin}"
            );
        }
        assert!(
            Profile::DirectHttps.accepts(&Url::parse("https://storage.example.com:8443/").unwrap())
        );
        assert!(!Profile::TorOnly.accepts(&Url::parse("https://storage.example.com/").unwrap()));
        assert!(
            !Profile::TorOnly
                .accepts(&Url::parse(&format!("http://{}.onion/", "a".repeat(56))).unwrap())
        );
        assert!(!Profile::LoopbackDevelopment.accepts(&Url::parse("http://localhost/").unwrap()));
        assert!(HttpTransport::new(Profile::LoopbackDevelopment, None, false).is_err());
        assert!(HttpTransport::new(Profile::TorOnly, None, false).is_err());
        for proxy in [
            "socks5://127.0.0.1:9050",
            "socks5h://localhost:9050",
            "socks5h://192.168.1.1:9050",
            "socks5h://u:p@127.0.0.1:9050",
            "socks5h://127.0.0.1:9050/path",
        ] {
            assert!(
                HttpTransport::new(Profile::TorOnly, Some(&Url::parse(proxy).unwrap()), false)
                    .is_err()
            );
        }
        let proxy = Url::parse("socks5h://127.0.0.1:9050").unwrap();
        assert!(HttpTransport::new(Profile::TorOnly, Some(&proxy), false).is_ok());
        assert!(HttpTransport::new(Profile::DirectHttps, Some(&proxy), false).is_err());
    }

    #[test]
    fn dns_filter_refuses_private_special_transition_and_mapped_addresses() {
        // IANA special-purpose registries, checked 6 September 2026. A
        // conservative subset deliberately also excludes special anycast.
        for address in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.0.1",
            "192.0.0.10",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::7f00:1",
            "2001::1",
            "2001:20::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(address.parse().unwrap()), "{address}");
        }
    }

    async fn response_target(response: Vec<u8>) -> (Target, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target {
            id: "fixture".into(),
            origin: format!("http://{}/", listener.local_addr().unwrap()),
            failure_group: "fixture".into(),
            retention: super::super::policy::Retention::Owner,
        };
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut part = [0; 1024];
                let received = stream.read(&mut part).await.unwrap();
                if received == 0 {
                    return;
                }
                request.extend_from_slice(&part[..received]);
                assert!(request.len() <= 8192);
            }
            let _ = stream.write_all(&response).await;
        });
        (target, task)
    }

    #[tokio::test]
    async fn complete_response_bytes_are_required_and_redirects_are_not_followed() {
        let bytes = b"synthetic bytes";
        let blob = Blob {
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let client = HttpTransport::new(Profile::LoopbackDevelopment, None, true).unwrap();
        for (status, length, body, expected) in [
            (200, bytes.len(), bytes.as_slice(), Ok(())),
            (
                200,
                bytes.len(),
                b"synthetic bytex".as_slice(),
                Err(NetworkFailure::InvalidBytes),
            ),
            (
                200,
                bytes.len(),
                b"short".as_slice(),
                Err(NetworkFailure::InvalidBytes),
            ),
            (
                200,
                bytes.len() + 1,
                bytes.as_slice(),
                Err(NetworkFailure::InvalidBytes),
            ),
            (404, 0, b"".as_slice(), Err(NetworkFailure::Unavailable)),
            (302, 0, b"".as_slice(), Err(NetworkFailure::Unavailable)),
        ] {
            let trap = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut response = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {length}\r\nConnection: close\r\nLocation: http://{}/\r\n\r\n", trap.local_addr().unwrap()).into_bytes();
            response.extend_from_slice(body);
            let (target, server) = response_target(response).await;
            assert_eq!(client.verify(&target, &blob).await, expected);
            server.await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(10), trap.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn mirror_descriptor_is_bounded_and_never_followed() {
        let blob = Blob {
            sha256: "ab".repeat(32),
            size: 10,
        };
        let client = HttpTransport::new(Profile::LoopbackDevelopment, None, true).unwrap();
        for body in [b"{}".to_vec(), vec![b' '; 16385], serde_json::to_vec(&serde_json::json!({ "url": "http://127.0.0.1:1/private", "sha256": "cd".repeat(32), "size": 10, "type": "application/octet-stream", "uploaded": 1 })).unwrap()] {
            let mut response = format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes(); response.extend(body);
            let (target, server) = response_target(response).await;
            assert_eq!(client.mirror(&target, &target, &blob, "Nostr synthetic").await, Err(NetworkFailure::InvalidResponse));
            server.await.unwrap();
        }
    }
}
