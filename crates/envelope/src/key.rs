//! Input keys and their `wbk1_` text form.

use crate::{Error, HKDF_INFO, KEY_BYTES};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

/// The text prefix of an encoded 32-byte key.
pub const WBK1_PREFIX: &str = "wbk1_";
/// `wbk1_` plus 43 unpadded base64url characters.
const WBK1_LEN: usize = 5 + 43;

/// A 32-byte FSWNENC2 input key: a fresh per-file key, or a long-lived vault
/// key such as a recovery secret.  Zeroised on drop; `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct InputKey(Zeroizing<[u8; KEY_BYTES]>);

/// Why a `wbk1_` string was refused.  Carries no key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("the key is not wbk1_ followed by canonical unpadded base64url for 32 bytes")]
    Encoding,
}

impl InputKey {
    /// 32 fresh bytes from the operating system's random source.
    pub fn random() -> Result<Self, Error> {
        let mut key = Zeroizing::new([0u8; KEY_BYTES]);
        getrandom::fill(key.as_mut()).map_err(|_| Error::Random)?;
        Ok(Self(key))
    }

    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw key.  Callers must not copy it anywhere that outlives use.
    pub fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    /// `wbk1_` followed by canonical unpadded base64url.
    pub fn to_wbk1(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(WBK1_LEN));
        out.push_str(WBK1_PREFIX);
        URL_SAFE_NO_PAD.encode_string(self.0.as_ref(), &mut out);
        out
    }

    /// Parses a `wbk1_` key, re-encoding and comparing so that alternate final
    /// characters which decode to the same 256 bits are refused.
    pub fn parse_wbk1(text: &str) -> Result<Self, KeyError> {
        let body = text
            .strip_prefix(WBK1_PREFIX)
            .filter(|_| text.len() == WBK1_LEN)
            .ok_or(KeyError::Encoding)?;
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| KeyError::Encoding)?,
        );
        let bytes: [u8; KEY_BYTES] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::Encoding)?;
        let key = Self::from_bytes(bytes);
        if key.to_wbk1().as_str() != text {
            return Err(KeyError::Encoding);
        }
        Ok(key)
    }
}

impl fmt::Debug for InputKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InputKey(<redacted>)")
    }
}

/// `HKDF-SHA256(ikm = input_key, salt = header salt, info = HKDF_INFO, L = 32)`.
pub fn derive_envelope_key(input_key: &InputKey, salt: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key.expose());
    let mut out = Zeroizing::new([0u8; KEY_BYTES]);
    hk.expand(HKDF_INFO, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counting(from: u8) -> InputKey {
        InputKey::from_bytes(std::array::from_fn(|i| from.wrapping_add(i as u8)))
    }

    #[test]
    fn encodes_the_published_recovery_key() {
        // ENCRYPTION.md's one-record vector key 000102...1f.
        assert_eq!(
            counting(0).to_wbk1().as_str(),
            "wbk1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        );
        let parsed =
            InputKey::parse_wbk1("wbk1_ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8").unwrap();
        assert_eq!(parsed, counting(0x20));
    }

    #[test]
    fn refuses_non_canonical_and_malformed_keys() {
        let good = counting(0).to_wbk1();
        assert!(InputKey::parse_wbk1(&good).is_ok());
        // The last character carries 2 spare bits that must be zero; "9" sets one.
        let mut alternate = good.to_string();
        alternate.pop();
        alternate.push('9');
        assert!(InputKey::parse_wbk1(&alternate).is_err());
        for bad in [
            "",
            "wbk1_",
            "wbk1_short",
            &good[5..],
            &format!("{}=", good.as_str()),
            &format!("WBK1_{}", &good[5..]),
            &good.replace('_', "/"),
            &format!("wbk2_{}", &good[5..]),
        ] {
            assert!(InputKey::parse_wbk1(bad).is_err(), "{bad:?}");
        }
        assert!(InputKey::parse_wbk1(&format!("wbk1_{}", "A".repeat(43))).is_ok());
    }

    #[test]
    fn debug_never_prints_the_key() {
        let text = format!("{:?}", counting(0x41));
        assert_eq!(text, "InputKey(<redacted>)");
    }

    #[test]
    fn random_keys_differ() {
        assert_ne!(InputKey::random().unwrap(), InputKey::random().unwrap());
    }
}
