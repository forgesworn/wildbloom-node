//! Streaming `FSWNENC2` envelope (`forgesworn-aes-256-gcm-chunked-v2`).
//!
//! This is the one Rust FSWNENC2 codec in Wildbloom Node, shared by `wildbloomd`
//! and the desktop.  It is extracted from the frame module of `stash-rs` 0.6.1
//! (`forgesworn/stash-rs`, `src/frame.rs`), keeping its primitives (header, HKDF,
//! nonce, AAD, canonical metadata and padding bucket) and restructuring the record
//! loop to stream through `Read` and `Write` instead of whole-blob buffers.  The
//! normative specification is `docs/FSWNENC2.md` and `docs/ENCRYPTION.md` in
//! `forgesworn/wildbloom`; the frozen vectors in `tests/fixtures` are copied
//! byte for byte from that repository.
//!
//! ```text
//! header  = "FSWNENC2" | u32 BE chunk size (1 MiB) | u32 BE record count | 8-byte nonce prefix | 32-byte salt
//! key     = HKDF-SHA256(ikm = input key, salt = header salt, info = HKDF_INFO, L = 32)
//! record  = AES-256-GCM(nonce = prefix | u32 BE counter, aad = header | u32 BE counter)
//! logical = u32 BE metadata length | {"name","size","type"} | source | random padding
//! ```
//!
//! Per-file mode and vault mode are the same bytes: only the input key differs
//! (a fresh [`InputKey`] per file, or a long-lived key such as a recovery
//! secret).  The fresh per-envelope salt is what keeps a reused vault key
//! nonce-safe, so no production path here can fix the salt.
//!
//! # Conformance and scope
//!
//! This crate writes and reads `FSWNENC2` only, and is therefore **not** a
//! fully conformant decoder in the sense of `ENCRYPTION.md`, which requires
//! reading `FSWNENC1` and legacy `WBLMENC1` as well.  Both are refused with
//! [`Error::Magic`]; nothing Wildbloom Node writes uses them.  A caller that
//! must open historical envelopes needs a different reader.
//!
//! Decryption never returns plaintext before every record has authenticated and
//! every semantic check has passed: the file helper deletes its private temp
//! file on any error or panic, and the byte helper returns nothing.  A hard kill
//! skips that cleanup, so callers take a [`TempDirLock`] on the temp directory
//! at start-up, hold it for the life of the process, and run
//! [`sweep_stale_temp_files`] with it.  That directory must be local, private
//! app data: not a synced or backed-up folder, and not a network file system.

mod key;
mod name;
mod stream;
mod temp;
#[cfg(test)]
mod tests;

pub use key::{InputKey, KeyError, WBK1_PREFIX, derive_envelope_key};
pub use name::{normalise_media_type, sanitise_name};
pub use stream::{
    Progress, Sealed, decrypt_file_to_private_temp, encrypt, encrypt_file_to_private_temp,
    envelope_bytes, open_bytes, seal_bytes,
};
pub use temp::{SweepReport, TempDirLock, sweep_stale_temp_files};

use serde::{Deserialize, Serialize};

/// The envelope magic and version field, authenticated in every record's AAD.
pub const MAGIC: &[u8; 8] = b"FSWNENC2";
/// The media type an envelope is written and served as.
pub const MEDIA_TYPE: &str = "application/vnd.forgesworn.encrypted";
/// The legacy media type, recognised on read only.
pub const LEGACY_MEDIA_TYPE: &str = "application/vnd.wildbloom.encrypted";
/// The scheme name the shared specification gives this construction.
pub const SCHEME: &str = "forgesworn-aes-256-gcm-chunked-v2";
/// The HKDF `info` label: exactly 33 UTF-8 bytes, no NUL.  Part of the format.
pub const HKDF_INFO: &[u8] = b"forgesworn-aes-256-gcm-chunked/v2";
/// Clear header bytes: magic 8, chunk size 4, record count 4, nonce prefix 8, salt 32.
pub const HEADER_BYTES: usize = 56;
/// Random nonce prefix bytes at header offset 16.
pub const NONCE_PREFIX_BYTES: usize = 8;
/// Key-derivation salt bytes at header offset 24.  Public, never secret.
pub const SALT_BYTES: usize = 32;
/// Plaintext bytes in one authenticated record.
pub const CHUNK_BYTES: usize = 1024 * 1024;
/// GCM tag bytes appended to every record.
pub const TAG_BYTES: usize = 16;
/// The smallest padding bucket.
pub const MIN_PADDING_BUCKET: usize = 64 * 1024;
/// The ceiling on the canonical metadata JSON.
pub const MAX_METADATA_BYTES: usize = 4096;
/// Input keys are 32 bytes.
pub const KEY_BYTES: usize = 32;
/// The smallest possible envelope: one 64 KiB record.
pub const MIN_ENVELOPE_BYTES: u64 = (HEADER_BYTES + MIN_PADDING_BUCKET + TAG_BYTES) as u64;

/// The private metadata inside the first record.  Field order is load-bearing:
/// serialisation must produce `{"name":…,"size":…,"type":…}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// The sanitised source name (see [`sanitise_name`]).
    pub name: String,
    /// The exact source byte count, before padding.
    pub size: u64,
    /// The lower-cased source media type (see [`normalise_media_type`]).
    #[serde(rename = "type")]
    pub media_type: String,
}

/// The largest source a caller will encrypt or accept.  The record ceiling is
/// derived from it, as `ENCRYPTION.md` requires, so a caller never hard-codes a
/// record count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    max_source_bytes: u64,
}

impl Limits {
    /// Wildbloom's browser client and recipient page: 256 MiB sources, 257 records.
    pub const BROWSER: Self = Self::new(256 * 1024 * 1024);

    /// A ceiling of `max_source_bytes` plaintext bytes.
    pub const fn new(max_source_bytes: u64) -> Self {
        Self { max_source_bytes }
    }

    pub const fn max_source_bytes(self) -> u64 {
        self.max_source_bytes
    }

    /// `ceil((max source + 4 + max metadata) / 1 MiB)`, the most records an
    /// envelope within this limit can need.
    pub fn max_records(self) -> u32 {
        let logical = self
            .max_source_bytes
            .saturating_add(4 + MAX_METADATA_BYTES as u64);
        u32::try_from(logical.div_ceil(CHUNK_BYTES as u64)).unwrap_or(u32::MAX)
    }
}

/// Why an envelope could not be written or read.  No variant carries key or
/// plaintext bytes, so errors are safe to log.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("envelope I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("private state directory or file is not private")]
    PrivateState(#[source] std::io::Error),
    #[error("the system random source failed")]
    Random,
    #[error("the operation was cancelled")]
    Cancelled,
    #[error("another process holds this temp directory")]
    TempDirInUse,
    #[error("the source changed size while it was being encrypted")]
    SourceChanged,
    #[error("the source is larger than this envelope limit allows")]
    TooLarge,
    #[error("the media type is invalid")]
    MediaType,
    #[error("the metadata is larger than {MAX_METADATA_BYTES} bytes")]
    MetadataTooLarge,
    #[error("the envelope magic is not FSWNENC2")]
    Magic,
    #[error("the envelope header is out of range")]
    Header,
    #[error("the envelope length is inconsistent with its header")]
    Length,
    #[error("an envelope record failed authentication (wrong key, or modified)")]
    Authentication,
    #[error("the envelope metadata is not canonical: {0}")]
    Metadata(&'static str),
    #[error("the envelope padding does not match its declared size")]
    Padding,
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    #[test]
    fn browser_limit_matches_the_published_record_cap() {
        // ENCRYPTION.md: ceil((256 MiB + 4 + 4096) / 1 MiB) = 257.
        assert_eq!(Limits::BROWSER.max_records(), 257);
        assert_eq!(Limits::new(0).max_records(), 1);
        assert_eq!(Limits::new(u64::MAX).max_records(), u32::MAX);
    }
}
