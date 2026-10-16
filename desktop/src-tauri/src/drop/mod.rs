//! Wildbloom Drop: desktop encryption and key handling.
//!
//! This step provides the internal Rust API only.  Tauri commands, the grant
//! event, NIP-46, mirroring, sharing, the watcher and the UI are later steps
//! and call into these modules:
//!
//! - [`envelope`]: streaming FSWNENC2 to private temp files, via the shared
//!   `wildbloom-envelope` crate.  `encrypt_new_file` mints a fresh per-file key;
//!   `drop_limits` and `SHARE_LIMITS` carry the Q13 size caps.
//! - [`keychain`]: the OS keychain behind the `SecretStore` trait.  `DropKeychain`
//!   holds the device secret, the recovery secret and per-file keys.  A missing
//!   Linux Secret Service is the typed `KeychainError::SecretServiceMissing`.
//! - [`device`]: the device keypair, the `wbk1_` recovery secret, the
//!   HKDF-derived recovery identity, and the versioned key list sealed in FSWNENC2
//!   vault mode under the recovery secret.
//! - [`descriptor`]: the `wildbloom-share/1` share descriptor builder and strict
//!   validator.
//!
//! Secrets are zeroised on drop where the types allow it, and no `Debug` or
//! error value in these modules carries key bytes.

// Nothing outside this module calls it until the commands land in a later step.
#![allow(dead_code)]

pub mod descriptor;
pub mod device;
pub mod envelope;
pub mod keychain;

use std::fmt;

/// A Drop file entry's identifier: 16 random bytes as 32 lower-case hex
/// characters.  Not secret; it names keychain entries and key list rows.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId([u8; 16]);

impl FileId {
    pub fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Strict parse: exactly 32 lower-case hex characters.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId({self})")
    }
}

/// Lower-case hex for public digests.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Strict 64-character lower-case hex SHA-256.
pub(crate) fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_ids_round_trip_strictly() {
        let id = FileId::random().unwrap();
        assert_eq!(FileId::parse(&id.to_string()), Some(id));
        assert_ne!(FileId::random().unwrap(), id);
        assert!(FileId::parse(&"A".repeat(32)).is_none());
        assert!(FileId::parse(&"a".repeat(31)).is_none());
        assert!(FileId::parse("").is_none());
        assert_eq!(FileId::from_bytes([0xab; 16]).to_string(), "ab".repeat(16));
    }

    #[test]
    fn sha256_hex_is_strict_lower_case() {
        let hash = [0xcd; 32];
        assert_eq!(parse_sha256(&hex_lower(&hash)), Some(hash));
        assert!(parse_sha256(&"CD".repeat(32)).is_none());
        assert!(parse_sha256(&"cd".repeat(31)).is_none());
    }
}
