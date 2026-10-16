//! The `wildbloom-share/1` share descriptor, carried inside the transfer-v1
//! invitation and validated strictly by the recipient page.
//!
//! Canonical JSON, keys in exactly this order and no whitespace:
//!
//! ```text
//! {"v":"wildbloom-share/1","url":"https://<online node>/<sha256>","sha256":"<64 hex>",
//!  "size":<ciphertext bytes>,"key":"wbk1_…","name":"<sanitised name>",
//!  "bytes":<plaintext bytes>,"expires":<unix seconds>}
//! ```
//!
//! The validator mirrors `parseShareDescriptor` in the wildbloom client and is
//! stricter in four places, so anything built here is accepted there:
//! the bytes must be canonical; `key` must decode canonically to 32 bytes; `size`
//! must be at least one envelope and larger than `bytes`; and `bytes` is capped
//! at Q13's 250 MB share limit rather than 256 MiB.  Like the client, it accepts
//! plain HTTP only for `localhost`, `127.0.0.1` and `[::1]` (local development).

use super::envelope::SHARE_MAX_PLAINTEXT_BYTES;
use serde::{Deserialize, Serialize};
use std::fmt;
use url::{Host, Url};
use wildbloom_envelope::{InputKey, MIN_ENVELOPE_BYTES, sanitise_name};
use zeroize::{Zeroize, Zeroizing};

pub const SHARE_DESCRIPTOR_VERSION: &str = "wildbloom-share/1";
/// The pairing frame limit for the descriptor bytes.
pub const SHARE_DESCRIPTOR_MAX_BYTES: usize = 16_364;
/// The recipient page's plaintext ceiling (`MAX_PROTOTYPE_FILE_BYTES`).
pub const MAX_PROTOTYPE_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// The recipient page's ciphertext ceiling (`MAX_PROTOTYPE_TRANSFER_BYTES`).
pub const MAX_PROTOTYPE_TRANSFER_BYTES: u64 = MAX_PROTOTYPE_FILE_BYTES + 2 * 1024 * 1024;
/// JavaScript's largest exact integer.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Why a descriptor was refused.  `TooLarge` is kept apart because the
/// recipient page words it differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DescriptorError {
    #[error("the share details are invalid: {0}")]
    Invalid(&'static str),
    #[error("the shared file is larger than the recipient page accepts")]
    TooLarge,
}

use DescriptorError::Invalid;

/// A validated share descriptor.  Holds the share key, so `Debug` redacts it
/// and the canonical bytes are zeroised on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareDescriptor {
    url: String,
    sha256: String,
    size: u64,
    key: InputKey,
    name: String,
    bytes: u64,
    expires: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: String,
    url: String,
    sha256: String,
    size: u64,
    key: String,
    name: String,
    bytes: u64,
    expires: u64,
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ShareDescriptor {
    /// Builds a descriptor for a shared copy uploaded to `server` (an origin,
    /// optionally with a path prefix).  `name` is sanitised here; `bytes` over
    /// the Q13 share cap is [`DescriptorError::TooLarge`].
    pub fn build(
        server: &str,
        sha256: &[u8; 32],
        size: u64,
        key: &InputKey,
        name: &str,
        bytes: u64,
        expires: u64,
    ) -> Result<Self, DescriptorError> {
        let sha256 = super::hex_lower(sha256);
        let mut url = Url::parse(server).map_err(|_| Invalid("server"))?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(Invalid("server"));
        }
        url.path_segments_mut()
            .map_err(|_| Invalid("server"))?
            .pop_if_empty()
            .push(&sha256);
        let descriptor = Self {
            url: url.into(),
            sha256,
            size,
            key: key.clone(),
            name: sanitise_name(name),
            bytes,
            expires,
        };
        // Build only what the validator accepts, including the size limit.
        Self::parse(&descriptor.to_canonical_json())
    }

    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn key(&self) -> &InputKey {
        &self.key
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// The canonical bytes for the invitation.  They contain the share key.
    pub fn to_canonical_json(&self) -> Zeroizing<Vec<u8>> {
        let wire = Wire {
            v: SHARE_DESCRIPTOR_VERSION.to_string(),
            url: self.url.clone(),
            sha256: self.sha256.clone(),
            size: self.size,
            key: self.key.to_wbk1().to_string(),
            name: self.name.clone(),
            bytes: self.bytes,
            expires: self.expires,
        };
        // Reserve past the frame limit so the buffer never reallocates.
        let mut out = Zeroizing::new(Vec::with_capacity(SHARE_DESCRIPTOR_MAX_BYTES + 1024));
        serde_json::to_writer(&mut *out, &wire).expect("serialising plain data cannot fail");
        out
    }

    /// Strict validation of untrusted descriptor bytes.  Never fetches anything.
    pub fn parse(payload: &[u8]) -> Result<Self, DescriptorError> {
        if payload.is_empty() || payload.len() > SHARE_DESCRIPTOR_MAX_BYTES {
            return Err(Invalid("size"));
        }
        std::str::from_utf8(payload).map_err(|_| Invalid("utf-8"))?;
        let wire: Wire = serde_json::from_slice(payload).map_err(|_| Invalid("shape"))?;
        if wire.v != SHARE_DESCRIPTOR_VERSION {
            return Err(Invalid("version"));
        }
        if super::parse_sha256(&wire.sha256).is_none() {
            return Err(Invalid("sha256"));
        }
        check_url(&wire.url, &wire.sha256)?;
        let key = InputKey::parse_wbk1(&wire.key).map_err(|_| Invalid("key"))?;
        if wire.name.is_empty() || sanitise_name(&wire.name) != wire.name {
            return Err(Invalid("name"));
        }
        for count in [wire.size, wire.bytes, wire.expires] {
            if count == 0 || count > MAX_SAFE_INTEGER {
                return Err(Invalid("number"));
            }
        }
        if wire.size < MIN_ENVELOPE_BYTES || wire.bytes >= wire.size {
            return Err(Invalid("size"));
        }
        let descriptor = Self {
            url: wire.url.clone(),
            sha256: wire.sha256.clone(),
            size: wire.size,
            key,
            name: wire.name.clone(),
            bytes: wire.bytes,
            expires: wire.expires,
        };
        if descriptor.to_canonical_json().as_slice() != payload {
            return Err(Invalid("canonical form"));
        }
        if wire.size > MAX_PROTOTYPE_TRANSFER_BYTES || wire.bytes > SHARE_MAX_PLAINTEXT_BYTES {
            return Err(DescriptorError::TooLarge);
        }
        Ok(descriptor)
    }
}

impl fmt::Debug for ShareDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShareDescriptor")
            .field("url", &self.url)
            .field("size", &self.size)
            .field("key", &"<redacted>")
            .field("name", &self.name)
            .field("bytes", &self.bytes)
            .field("expires", &self.expires)
            .finish()
    }
}

/// HTTPS (or loopback HTTP), no credentials, query or fragment, not an onion
/// address, already in WHATWG serialised form, and ending in `/<sha256>`.
fn check_url(text: &str, sha256: &str) -> Result<(), DescriptorError> {
    let url = Url::parse(text).map_err(|_| Invalid("url"))?;
    if url.as_str() != text {
        return Err(Invalid("url"));
    }
    let host = url.host().ok_or(Invalid("url"))?;
    let loopback = match &host {
        Host::Domain(name) => *name == "localhost",
        Host::Ipv4(ip) => ip.octets() == [127, 0, 0, 1],
        Host::Ipv6(ip) => ip.is_loopback(),
    };
    if let Host::Domain(name) = &host
        && name.trim_end_matches('.').ends_with(".onion")
    {
        return Err(Invalid("url"));
    }
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(Invalid("url")),
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Invalid("url"));
    }
    if url.path().rsplit('/').next() != Some(sha256) {
        return Err(Invalid("url"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    // The cases below are ported from the wildbloom client's
    // `tests/share-descriptor.test.ts` (the recipient page's validator), so the
    // two implementations agree on what is accepted.
    const HASH: &str = "abababababababababababababababababababababababababababababababab";

    fn key() -> String {
        format!("wbk1_{}", "A".repeat(43))
    }

    fn descriptor(overrides: Value) -> Value {
        let mut base = json!({
            "v": "wildbloom-share/1",
            "url": format!("https://storage.example/{HASH}"),
            "sha256": HASH,
            "size": 65_608,
            "key": key(),
            "name": "holiday-photos.zip",
            "bytes": 43,
            "expires": 1_900_000_000u64,
        });
        if let (Value::Object(base), Value::Object(extra)) = (&mut base, overrides) {
            for (k, v) in extra {
                base.insert(k, v);
            }
        }
        base
    }

    /// `serde_json` keeps insertion order only with `preserve_order`, so emit
    /// the documented key order by hand, as `JSON.stringify` does in the TS test.
    fn encode(value: &Value) -> Vec<u8> {
        let Value::Object(map) = value else {
            return serde_json::to_vec(value).unwrap();
        };
        let order = [
            "v", "url", "sha256", "size", "key", "name", "bytes", "expires",
        ];
        let mut parts: Vec<String> = order
            .iter()
            .filter_map(|k| map.get(*k).map(|v| format!("{}:{}", json!(k), v)))
            .collect();
        for (k, v) in map {
            if !order.contains(&k.as_str()) {
                parts.push(format!("{}:{}", json!(k), v));
            }
        }
        format!("{{{}}}", parts.join(",")).into_bytes()
    }

    fn reason(value: &Value) -> Option<DescriptorError> {
        ShareDescriptor::parse(&encode(value)).err()
    }

    #[test]
    fn accepts_the_exact_documented_shape() {
        let bytes = encode(&descriptor(json!({})));
        let parsed = ShareDescriptor::parse(&bytes).unwrap();
        assert_eq!(parsed.name(), "holiday-photos.zip");
        assert_eq!((parsed.bytes(), parsed.size()), (43, 65_608));
        assert_eq!(parsed.sha256(), HASH);
        assert_eq!(parsed.to_canonical_json().as_slice(), bytes.as_slice());
    }

    #[test]
    fn accepts_plain_http_only_for_loopback() {
        for url in [
            format!("http://127.0.0.1:9000/{HASH}"),
            format!("http://localhost/{HASH}"),
            format!("http://[::1]:8080/{HASH}"),
        ] {
            assert_eq!(reason(&descriptor(json!({ "url": url }))), None, "{url}");
        }
        let url = format!("http://storage.example/{HASH}");
        assert_eq!(
            reason(&descriptor(json!({ "url": url }))),
            Some(Invalid("url"))
        );
    }

    #[test]
    fn rejects_every_ported_invalid_case() {
        let cd = "cd".repeat(32);
        let onion = format!("https://{}.onion/{HASH}", "a".repeat(56));
        let cases: Vec<(&str, Value)> = vec![
            ("an extra field", json!({ "extra": 1 })),
            ("a wrong version", json!({ "v": "wildbloom-share/2" })),
            (
                "an upper-case hash",
                json!({ "sha256": HASH.to_uppercase() }),
            ),
            ("a short hash", json!({ "sha256": "ab" })),
            (
                "a URL not ending in the hash",
                json!({ "url": format!("https://storage.example/{cd}") }),
            ),
            (
                "a URL with an extension",
                json!({ "url": format!("https://storage.example/{HASH}.bin") }),
            ),
            (
                "a URL with a query",
                json!({ "url": format!("https://storage.example/{HASH}?token=1") }),
            ),
            (
                "a URL with a fragment",
                json!({ "url": format!("https://storage.example/{HASH}#x") }),
            ),
            (
                "a URL with credentials",
                json!({ "url": format!("https://user:pass@storage.example/{HASH}") }),
            ),
            (
                "a non-canonical URL",
                json!({ "url": format!("HTTPS://Storage.Example/{HASH}") }),
            ),
            ("an onion address", json!({ "url": onion })),
            ("a key without the prefix", json!({ "key": "A".repeat(48) })),
            ("a short key", json!({ "key": "wbk1_short" })),
            ("an empty name", json!({ "name": "" })),
            ("a name with a path", json!({ "name": "../secret.txt" })),
            ("an unsanitised name", json!({ "name": "bad:name?.txt" })),
            ("a zero size", json!({ "size": 0 })),
            ("a fractional size", json!({ "size": 1.5 })),
            ("a string size", json!({ "size": "10" })),
            ("a zero plaintext size", json!({ "bytes": 0 })),
            ("a missing expiry", json!({ "expires": 0 })),
            ("a string expiry", json!({ "expires": "soon" })),
        ];
        for (label, overrides) in cases {
            assert!(
                matches!(reason(&descriptor(overrides)), Some(Invalid(_))),
                "{label}"
            );
        }
    }

    #[test]
    fn rejects_arrays_scalars_malformed_json_and_invalid_utf8() {
        for value in [json!([]), json!("text"), json!(null)] {
            assert!(matches!(reason(&value), Some(Invalid(_))));
        }
        for payload in [&b"{not json"[..], &[0xffu8, 0xfe][..], &[][..]] {
            assert!(matches!(ShareDescriptor::parse(payload), Err(Invalid(_))));
        }
    }

    #[test]
    fn rejects_a_payload_over_the_frame_limit_before_parsing() {
        let payload = vec![b' '; SHARE_DESCRIPTOR_MAX_BYTES + 1];
        assert_eq!(ShareDescriptor::parse(&payload), Err(Invalid("size")));
    }

    #[test]
    fn reports_an_oversize_share_separately() {
        let over_transfer = descriptor(json!({ "size": MAX_PROTOTYPE_TRANSFER_BYTES + 1 }));
        assert_eq!(reason(&over_transfer), Some(DescriptorError::TooLarge));
        let over_file = descriptor(
            json!({ "bytes": MAX_PROTOTYPE_FILE_BYTES + 1, "size": MAX_PROTOTYPE_TRANSFER_BYTES }),
        );
        assert_eq!(reason(&over_file), Some(DescriptorError::TooLarge));
        // Deliberately stricter than the TS validator, which accepts 256 MiB
        // here: Q13 caps a share at 250 MB of plaintext.
        let at_ts_limit = descriptor(
            json!({ "size": MAX_PROTOTYPE_TRANSFER_BYTES, "bytes": MAX_PROTOTYPE_FILE_BYTES }),
        );
        assert_eq!(reason(&at_ts_limit), Some(DescriptorError::TooLarge));
        let at_q13 = descriptor(
            json!({ "size": MAX_PROTOTYPE_TRANSFER_BYTES, "bytes": SHARE_MAX_PLAINTEXT_BYTES }),
        );
        assert_eq!(reason(&at_q13), None);
    }

    #[test]
    fn rejects_rust_only_stricter_cases() {
        let reordered = format!(
            r#"{{"url":"https://storage.example/{HASH}","v":"wildbloom-share/1","sha256":"{HASH}","size":65608,"key":"{}","name":"n","bytes":43,"expires":1}}"#,
            key()
        );
        assert_eq!(
            ShareDescriptor::parse(reordered.as_bytes()),
            Err(Invalid("canonical form"))
        );
        let spaced = String::from_utf8(encode(&descriptor(json!({}))))
            .unwrap()
            .replace(",", ", ");
        assert_eq!(
            ShareDescriptor::parse(spaced.as_bytes()),
            Err(Invalid("canonical form"))
        );
        // The final base64url character carries two spare bits that must be zero.
        let loose_key = format!("wbk1_{}B", "A".repeat(42));
        assert_eq!(
            reason(&descriptor(json!({ "key": loose_key }))),
            Some(Invalid("key"))
        );
        assert_eq!(
            reason(&descriptor(json!({ "size": 16, "bytes": 15 }))),
            Some(Invalid("size"))
        );
        assert_eq!(
            reason(&descriptor(json!({ "bytes": 65_608 }))),
            Some(Invalid("size"))
        );
        assert_eq!(
            reason(&descriptor(json!({ "expires": 1u64 << 53 }))),
            Some(Invalid("number"))
        );
        let trailing_slash = format!("https://storage.example/{HASH}/");
        assert_eq!(
            reason(&descriptor(json!({ "url": trailing_slash }))),
            Some(Invalid("url"))
        );
        let empty_query = format!("https://storage.example/{HASH}?");
        assert_eq!(
            reason(&descriptor(json!({ "url": empty_query }))),
            Some(Invalid("url"))
        );
        let root_dot_onion = format!("https://{}.onion./{HASH}", "a".repeat(56));
        assert_eq!(
            reason(&descriptor(json!({ "url": root_dot_onion }))),
            Some(Invalid("url"))
        );
        let ftp = format!("ftp://storage.example/{HASH}");
        assert_eq!(
            reason(&descriptor(json!({ "url": ftp }))),
            Some(Invalid("url"))
        );
    }

    #[test]
    fn builds_canonical_descriptors_that_parse_back() {
        let hash = [0xab; 32];
        let share_key = InputKey::from_bytes([7; 32]);
        let built = ShareDescriptor::build(
            "https://storage.example",
            &hash,
            65_608,
            &share_key,
            "Holiday: photos?.zip",
            43,
            1_900_000_000,
        )
        .unwrap();
        assert_eq!(built.url(), format!("https://storage.example/{HASH}"));
        assert_eq!(built.name(), "Holiday_ photos_.zip");
        let json = built.to_canonical_json();
        let expected = format!(
            r#"{{"v":"wildbloom-share/1","url":"https://storage.example/{HASH}","sha256":"{HASH}","size":65608,"key":"{}","name":"Holiday_ photos_.zip","bytes":43,"expires":1900000000}}"#,
            share_key.to_wbk1().as_str()
        );
        assert_eq!(std::str::from_utf8(&json).unwrap(), expected);
        assert_eq!(ShareDescriptor::parse(&json).unwrap(), built);
        // The JSON shape the TS validator checks: exactly the eight keys.
        let value: Value = serde_json::from_slice(&json).unwrap();
        let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys.join(","), "bytes,expires,key,name,sha256,size,url,v");
    }

    #[test]
    fn build_keeps_a_server_path_prefix_and_refuses_bad_servers() {
        let hash = [0xab; 32];
        let k = InputKey::from_bytes([7; 32]);
        let build = |server: &str| {
            ShareDescriptor::build(server, &hash, 65_608, &k, "f", 43, 1_900_000_000)
        };
        assert_eq!(
            build("https://storage.example/blossom/").unwrap().url(),
            format!("https://storage.example/blossom/{HASH}")
        );
        assert_eq!(
            build("http://127.0.0.1:3000").unwrap().url(),
            format!("http://127.0.0.1:3000/{HASH}")
        );
        for bad in [
            "http://storage.example",
            "https://user@storage.example",
            "https://storage.example/?x=1",
            "https://storage.example/#f",
            "not a url",
            "mailto:owner@storage.example",
        ] {
            assert!(matches!(build(bad), Err(Invalid(_))), "{bad}");
        }
    }

    #[test]
    fn build_enforces_the_share_cap() {
        let hash = [0xab; 32];
        let k = InputKey::from_bytes([7; 32]);
        let over = ShareDescriptor::build(
            "https://storage.example",
            &hash,
            MAX_PROTOTYPE_TRANSFER_BYTES,
            &k,
            "f",
            SHARE_MAX_PLAINTEXT_BYTES + 1,
            1_900_000_000,
        );
        assert_eq!(over, Err(DescriptorError::TooLarge));
    }

    #[test]
    fn debug_redacts_the_key() {
        let built = ShareDescriptor::parse(&encode(&descriptor(json!({})))).unwrap();
        let text = format!("{built:?}");
        assert!(!text.contains("wbk1_"), "{text}");
    }
}
