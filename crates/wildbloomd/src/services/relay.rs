//! One bounded NIP-01 publication per explicitly configured destination.
use super::{Announcement, Error, contract};
use futures_util::{SinkExt, StreamExt};
use nostr::prelude::Event;
use serde::Deserialize;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use url::Url;

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Direct,
    TorOnly,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub url: String,
    /// Direct mode requires operator approved public sockets. Tor mode requires none.
    #[serde(default)]
    pub addresses: Vec<SocketAddr>,
}
fn relay_url(value: &str, transport: Transport) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error)?;
    if !contract::text(value, 2048, false)
        || url.as_str() != value
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(Error);
    }
    let host = url.host_str().ok_or(Error)?;
    let onion = host.ends_with(".onion");
    if onion {
        if transport != Transport::TorOnly
            || !crate::replicas::transport::valid_onion(host)
            || !matches!(url.scheme(), "ws" | "wss")
        {
            return Err(Error);
        }
    } else {
        if url.scheme() != "wss" {
            return Err(Error);
        }
        let mut https = url.clone();
        https.set_scheme("https").map_err(|_| Error)?;
        contract::endpoint(https.as_str(), false, true)?;
    }
    Ok(url)
}
pub fn proxy_address(proxy: &Url) -> Result<SocketAddr, Error> {
    if proxy.scheme() != "socks5h"
        || !proxy.username().is_empty()
        || proxy.password().is_some()
        || !matches!(proxy.path(), "" | "/")
        || proxy.query().is_some()
        || proxy.fragment().is_some()
    {
        return Err(Error);
    }
    let host = proxy.host().ok_or(Error)?;
    let ip = match host {
        url::Host::Ipv4(ip) => ip.into(),
        url::Host::Ipv6(ip) => ip.into(),
        url::Host::Domain(host) => host.parse::<std::net::IpAddr>().map_err(|_| Error)?,
    };
    let address = SocketAddr::new(ip, proxy.port().ok_or(Error)?);
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(Error);
    }
    Ok(address)
}
pub fn validate(a: &Announcement, proxy: Option<&Url>, no_tor: bool) -> Result<(), Error> {
    if a.relays.is_empty() || a.relays.len() > 8 {
        return Err(Error);
    }
    match a.transport {
        Transport::Direct if !no_tor || proxy.is_some() => return Err(Error),
        Transport::TorOnly => {
            proxy_address(proxy.ok_or(Error)?)?;
        }
        _ => {}
    }
    let mut seen = std::collections::BTreeSet::new();
    for destination in &a.relays {
        let url = relay_url(&destination.url, a.transport)?;
        if !seen.insert(&destination.url) {
            return Err(Error);
        }
        match a.transport {
            Transport::TorOnly if !destination.addresses.is_empty() => return Err(Error),
            Transport::Direct => {
                if destination.addresses.is_empty() || destination.addresses.len() > 16 {
                    return Err(Error);
                }
                for address in &destination.addresses {
                    if address.port() != url.port_or_known_default().ok_or(Error)?
                        || !crate::replicas::transport::public_ip(address.ip())
                    {
                        return Err(Error);
                    }
                    let literal: Option<std::net::IpAddr> = match url.host() {
                        Some(url::Host::Ipv4(ip)) => Some(ip.into()),
                        Some(url::Host::Ipv6(ip)) => Some(ip.into()),
                        _ => None,
                    };
                    if literal.is_some_and(|ip| ip != address.ip()) {
                        return Err(Error);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
async fn socks(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream, Error> {
    if host.is_empty() || host.len() > 255 {
        return Err(Error);
    }
    let mut stream = TcpStream::connect(proxy).await.map_err(|_| Error)?;
    stream.write_all(&[5, 1, 0]).await.map_err(|_| Error)?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await.map_err(|_| Error)?;
    if reply != [5, 0] {
        return Err(Error);
    }
    // DOMAIN form deliberately passes DNS to Tor. There is no direct fallback.
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(|_| Error)?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| Error)?;
    if header[..3] != [5, 0, 0] {
        return Err(Error);
    }
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await.map_err(|_| Error)? as usize,
        _ => return Err(Error),
    };
    let mut ignored = vec![0; length + 2];
    stream.read_exact(&mut ignored).await.map_err(|_| Error)?;
    Ok(stream)
}
fn acknowledged(value: &serde_json::Value, id: &str) -> Option<bool> {
    let a = value.as_array()?;
    if a.len() != 4 || a[0] != "OK" || a[1] != id || !a[3].is_string() {
        return None;
    }
    a[2].as_bool()
}
pub async fn publish(
    destination: &Destination,
    transport: Transport,
    proxy: Option<&Url>,
    event: &Event,
) -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let url = relay_url(&destination.url, transport)?;
        let stream = match transport {
            Transport::TorOnly => {
                socks(
                    proxy_address(proxy.ok_or(Error)?)?,
                    url.host_str().ok_or(Error)?,
                    url.port_or_known_default().ok_or(Error)?,
                )
                .await?
            }
            Transport::Direct => {
                let mut connected = None;
                for address in &destination.addresses {
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(address))
                            .await
                    {
                        connected = Some(stream);
                        break;
                    }
                }
                connected.ok_or(Error)?
            }
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = WebSocketConfig::default()
            .max_message_size(Some(contract::MAX_BYTES))
            .max_frame_size(Some(contract::MAX_BYTES));
        // Supplying a connected stream preserves direct pins / socks5h and TLS host verification.
        // This handshake does not follow redirects or implement relay AUTH.
        let (mut socket, _) =
            client_async_tls_with_config(url.as_str(), stream, Some(config), None)
                .await
                .map_err(|_| Error)?;
        socket
            .send(Message::Text(
                serde_json::json!(["EVENT", event]).to_string().into(),
            ))
            .await
            .map_err(|_| Error)?;
        for _ in 0..32 {
            match socket.next().await.ok_or(Error)?.map_err(|_| Error)? {
                Message::Text(text) => {
                    if let Ok(value) = serde_json::from_str(&text) {
                        match acknowledged(&value, &event.id.to_hex()) {
                            Some(true) => {
                                let _ = socket.close(None).await;
                                return Ok(());
                            }
                            Some(false) => return Err(Error),
                            _ => {}
                        }
                    }
                }
                Message::Close(_) => return Err(Error),
                _ => {}
            }
        }
        Err(Error)
    })
    .await
    .map_err(|_| Error)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acknowledgement_requires_exact_id_and_boolean() {
        assert_eq!(
            acknowledged(&serde_json::json!(["OK", "event", true, ""]), "event"),
            Some(true)
        );
        for v in [
            serde_json::json!(["OK", "other", true, ""]),
            serde_json::json!(["OK", "event", "true", ""]),
            serde_json::json!(["NOTICE", "saved"]),
        ] {
            assert_eq!(acknowledged(&v, "event"), None);
        }
        assert_eq!(
            acknowledged(
                &serde_json::json!(["OK", "event", false, "refused"]),
                "event"
            ),
            Some(false)
        );
    }
    #[tokio::test]
    async fn socks_uses_remote_domain_and_fails_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            let mut domain = vec![0; request[4] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"relay.example");
            assert_eq!(stream.read_u16().await.unwrap(), 443);
            stream
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        assert!(socks(address, "relay.example", 443).await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_publication_requires_positive_acknowledgement_over_the_proxy() {
        use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind};
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/storage-v1/free-onion.json"
        ))
        .unwrap();
        let origin = Url::parse(fixture["description"]["origins"][0].as_str().unwrap()).unwrap();
        let relay = format!("ws://{}/", origin.host_str().unwrap());
        let event = EventBuilder::new(Kind::from(31402), "synthetic only")
            .finalize(&Keys::parse(&hex::encode([1; 32])).unwrap())
            .unwrap();
        for reply in ["accepted", "refused", "wrong-id", "oversized"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy =
                Url::parse(&format!("socks5h://{}", listener.local_addr().unwrap())).unwrap();
            let expected = event.id.to_hex();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 5];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..4], &[5, 1, 0, 3]);
                let mut host = vec![0; header[4] as usize];
                stream.read_exact(&mut host).await.unwrap();
                assert!(String::from_utf8(host).unwrap().ends_with(".onion"));
                assert_eq!(stream.read_u16().await.unwrap(), 80);
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                    .await
                    .unwrap();
                let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                let text = ws.next().await.unwrap().unwrap().into_text().unwrap();
                let v: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(v[0], "EVENT");
                assert_eq!(v[1]["id"], expected);
                let event: Event = serde_json::from_value(v[1].clone()).unwrap();
                event.verify().unwrap();
                let message = match reply {
                    "accepted" => serde_json::json!(["OK", expected, true, ""]).to_string(),
                    "refused" => serde_json::json!(["OK", expected, false, "refused"]).to_string(),
                    "wrong-id" => serde_json::json!(["OK", "0".repeat(64), true, ""]).to_string(),
                    _ => "x".repeat(65537),
                };
                ws.send(Message::Text(message.into())).await.unwrap();
                let _ = ws.close(None).await;
            });
            assert_eq!(
                publish(
                    &Destination {
                        url: relay.clone(),
                        addresses: vec![]
                    },
                    Transport::TorOnly,
                    Some(&proxy),
                    &event
                )
                .await
                .is_ok(),
                reply == "accepted",
                "{reply}"
            );
            server.await.unwrap();
        }
    }
}
