//! Drop's use of the shared FSWNENC2 codec: fresh per-file keys, private temp
//! files and the Q13 size caps.  All cryptography lives in `wildbloom-envelope`.

use std::path::Path;
use tempfile::NamedTempFile;
use wildbloom_envelope::{InputKey, Limits, Metadata, Progress, Sealed};

pub use wildbloom_envelope::Error as EnvelopeError;

/// Q13: a shared copy carries at most 250 MB (decimal) of plaintext, which stays
/// under the recipient page's 256 MiB after padding.
pub const SHARE_MAX_PLAINTEXT_BYTES: u64 = 250_000_000;
/// Limits for shared copies.
pub const SHARE_LIMITS: Limits = Limits::new(SHARE_MAX_PLAINTEXT_BYTES);

/// A worst-case name and type for sizing: 180 three-byte UTF-16 units and 255
/// more, the most metadata bytes a sanitised name and valid type can take.
fn worst_case_metadata() -> (String, String) {
    ("\u{4e00}".repeat(180), "\u{4e00}".repeat(255))
}

/// Q13 drop cap: the largest plaintext whose envelope, with any metadata, fits
/// within the online node's per-blob limit.
pub fn drop_limits(node_blob_limit: u64) -> Limits {
    let (name, media_type) = worst_case_metadata();
    let fits = |source: u64| {
        wildbloom_envelope::envelope_bytes(&name, &media_type, source)
            .is_ok_and(|bytes| bytes <= node_blob_limit)
    };
    if !fits(0) {
        // Not even an empty file fits; refuse everything.
        return Limits::new(0);
    }
    let (mut fits_up_to, mut too_big) = (0u64, node_blob_limit.saturating_add(1));
    while too_big - fits_up_to > 1 {
        let middle = fits_up_to + (too_big - fits_up_to) / 2;
        if fits(middle) {
            fits_up_to = middle;
        } else {
            too_big = middle;
        }
    }
    Limits::new(fits_up_to)
}

/// One encrypted drop: the fresh per-file key, what was sealed, and the private
/// temp file holding the envelope (deleted when dropped unless persisted).
pub struct EncryptedFile {
    pub key: InputKey,
    pub sealed: Sealed,
    pub file: NamedTempFile,
}

/// Encrypts the file at `source` under a fresh random key into a private temp
/// file in `temp_dir`.  The stored name is the sanitised final path component.
pub fn encrypt_new_file(
    source: &Path,
    media_type: &str,
    limits: Limits,
    temp_dir: &Path,
    progress: Progress<'_>,
) -> Result<EncryptedFile, EnvelopeError> {
    let name = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let key = InputKey::random()?;
    let (sealed, file) = wildbloom_envelope::encrypt_file_to_private_temp(
        &key, source, &name, media_type, limits, temp_dir, progress,
    )?;
    Ok(EncryptedFile { key, sealed, file })
}

/// Decrypts an envelope into a private temp file, released only after every
/// record authenticates.
pub fn decrypt_to_private_temp(
    key: &InputKey,
    envelope: &Path,
    limits: Limits,
    temp_dir: &Path,
    progress: Progress<'_>,
) -> Result<(Metadata, NamedTempFile), EnvelopeError> {
    wildbloom_envelope::decrypt_file_to_private_temp(key, envelope, limits, temp_dir, progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::ControlFlow;

    fn go() -> impl FnMut(u64, u64) -> ControlFlow<()> {
        |_, _| ControlFlow::Continue(())
    }

    #[test]
    fn drop_cap_is_the_node_limit_less_padding() {
        let gib = 1024 * 1024 * 1024;
        let limits = drop_limits(gib);
        let (name, media_type) = worst_case_metadata();
        let max = limits.max_source_bytes();
        let at = wildbloom_envelope::envelope_bytes(&name, &media_type, max).unwrap();
        let over = wildbloom_envelope::envelope_bytes(&name, &media_type, max + 1).unwrap();
        assert!(at <= gib && over > gib, "{max} {at} {over}");
        // 1 GiB less the header, one 1 MiB record of tags and metadata headroom.
        assert!(max > gib - 2 * 1024 * 1024);
        assert_eq!(drop_limits(1000).max_source_bytes(), 0);
    }

    #[test]
    fn share_cap_fits_the_recipient_page() {
        let (name, media_type) = worst_case_metadata();
        let envelope =
            wildbloom_envelope::envelope_bytes(&name, &media_type, SHARE_MAX_PLAINTEXT_BYTES)
                .unwrap();
        assert!(envelope <= super::super::descriptor::MAX_PROTOTYPE_TRANSFER_BYTES);
        assert!(SHARE_LIMITS.max_records() <= Limits::BROWSER.max_records());
    }

    #[test]
    fn a_new_file_gets_a_fresh_key_and_round_trips() {
        let work = tempfile::tempdir().unwrap();
        let source = work.path().join("Holiday Photos.zip");
        std::fs::write(&source, b"synthetic bytes").unwrap();
        let temp = work.path().join("private");
        let a =
            encrypt_new_file(&source, "application/zip", SHARE_LIMITS, &temp, &mut go()).unwrap();
        let b =
            encrypt_new_file(&source, "application/zip", SHARE_LIMITS, &temp, &mut go()).unwrap();
        assert_ne!(a.key, b.key);
        assert_ne!(a.sealed.sha256, b.sealed.sha256);
        assert_eq!(a.sealed.metadata.name, "Holiday Photos.zip");
        let (metadata, plain) =
            decrypt_to_private_temp(&a.key, a.file.path(), SHARE_LIMITS, &temp, &mut go()).unwrap();
        assert_eq!(metadata.size, 15);
        assert_eq!(std::fs::read(plain.path()).unwrap(), b"synthetic bytes");
        assert!(matches!(
            decrypt_to_private_temp(&b.key, a.file.path(), SHARE_LIMITS, &temp, &mut go()),
            Err(EnvelopeError::Authentication)
        ));
    }
}
