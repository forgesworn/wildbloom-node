//! Where a direct send's envelope lands.  The hidden webview runs the frame
//! logic and hands each DATA frame's bytes here, in order, through a raw
//! binary IPC command; it sends the ACK only after the write returns.  The
//! bytes go to a private temp file in Drop's own temp directory
//! (`.wildbloom-*.part`, so the start-up sweep deletes what a crash leaves),
//! never under `~/Wildbloom`.
//!
//! On END the sink checks, in the protocol's order: exactly E bytes arrived;
//! the envelope opens with the key and every record authenticates, with the
//! record count and padding matching the header (all in `wildbloom-envelope`);
//! the metadata equals the manifest exactly; the plaintext's size and SHA-256
//! equal END.  Only then is the file moved into the Received folder, and the
//! webview sends KEPT.  Any failure deletes both temp files (the envelope and
//! the plaintext) and the webview sends STOP 2, or STOP 3 when there is no
//! room.  Nothing is visible to the owner before the file is kept.
//!
//! The key stays here: it never reaches the webview.

use super::frames;
use super::messages::{MAX_FILE_BYTES, Manifest};
use super::received;
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write as _};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use wildbloom_envelope::{InputKey, Limits};

/// Why the sink refused the file.  The webview sends STOP with
/// [`SinkError::stop_code`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    /// The bytes or the file are not what was promised (STOP 2).
    #[error("the file is not the one that was offered: {0}")]
    Failed(&'static str),
    /// There is no room to keep the file (STOP 3).
    #[error("there is no room to keep the file")]
    Storage,
}

impl SinkError {
    pub fn stop_code(self) -> u8 {
        match self {
            Self::Failed(_) => frames::StopCode::Failed as u8,
            Self::Storage => frames::StopCode::Storage as u8,
        }
    }

    /// The failed state's reason.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Failed(_) => "verification",
            Self::Storage => "storage",
        }
    }
}

/// A full disk or quota is "no room"; any other I/O failure is a failure.
pub(crate) fn io_error(error: &std::io::Error, what: &'static str) -> SinkError {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded | ErrorKind::FileTooLarge => {
            SinkError::Storage
        }
        _ => SinkError::Failed(what),
    }
}

/// A kept file: where it is and the name it took there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub path: PathBuf,
    pub name: String,
}

/// One transfer's envelope on its way in.  Dropping it deletes the temp
/// file, so every way out but a kept file leaves nothing behind.
pub struct Sink {
    transfer: String,
    key: InputKey,
    manifest: Manifest,
    total: u64,
    envelope: NamedTempFile,
    written: u64,
    acked: u64,
    broken: bool,
    temp_dir: PathBuf,
    received_dir: PathBuf,
    #[cfg(test)]
    pub(crate) fail_writes_after: Option<(u64, std::io::ErrorKind)>,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sink")
            .field("total", &self.total)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

/// A new private temp file in Drop's temp directory, named so the start-up
/// sweep (`wildbloom_envelope::sweep_stale_temp_files`) removes it after a
/// crash.
pub(crate) fn private_temp(temp_dir: &Path) -> std::io::Result<NamedTempFile> {
    wildbloom_private_state::private_directory(temp_dir)?;
    let file = tempfile::Builder::new()
        .prefix(".wildbloom-")
        .suffix(".part")
        .tempfile_in(temp_dir)?;
    wildbloom_private_state::check_file(file.as_file())?;
    Ok(file)
}

impl Sink {
    /// A sink for `manifest`'s envelope, sealed under `key`.
    pub fn create(
        temp_dir: &Path,
        received_dir: &Path,
        transfer: &str,
        key: InputKey,
        manifest: Manifest,
    ) -> Result<Self, SinkError> {
        if manifest.size > MAX_FILE_BYTES {
            return Err(SinkError::Failed("larger than the limit"));
        }
        let total = super::messages::envelope_bytes(&manifest)
            .ok_or(SinkError::Failed("the manifest cannot be sealed"))?;
        let envelope = private_temp(temp_dir).map_err(|e| io_error(&e, "temp file"))?;
        Ok(Self {
            transfer: transfer.to_owned(),
            key,
            manifest,
            total,
            envelope,
            written: 0,
            acked: 0,
            broken: false,
            temp_dir: temp_dir.to_path_buf(),
            received_dir: received_dir.to_path_buf(),
            #[cfg(test)]
            fail_writes_after: None,
        })
    }

    pub fn transfer(&self) -> &str {
        &self.transfer
    }

    /// E, the envelope length the manifest implies.
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    /// Writes the next envelope bytes, which must start exactly where the
    /// last write ended and stay within E.  Returns the ACK the webview's
    /// rule sends now, if any, so progress shows acknowledged bytes.  After
    /// any refusal every later write is refused.
    pub fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<Option<u64>, SinkError> {
        let checked = if self.broken {
            Err(SinkError::Failed("the sink has failed"))
        } else if bytes.is_empty() || bytes.len() > frames::FRAME_BYTES {
            Err(SinkError::Failed("a write of the wrong length"))
        } else if offset != self.written {
            Err(SinkError::Failed("a gap or an overlap"))
        } else if self.total - self.written < bytes.len() as u64 {
            Err(SinkError::Failed("bytes past the end of the envelope"))
        } else {
            self.write_file(bytes)
        };
        if let Err(error) = checked {
            self.broken = true;
            return Err(error);
        }
        self.written += bytes.len() as u64;
        let ack = frames::ack_due(self.written, self.acked, self.total);
        if let Some(next) = ack {
            self.acked = next;
        }
        Ok(ack)
    }

    fn write_file(&mut self, bytes: &[u8]) -> Result<(), SinkError> {
        #[cfg(test)]
        if let Some((after, kind)) = self.fail_writes_after
            && self.written + bytes.len() as u64 > after
        {
            return Err(io_error(&kind.into(), "write"));
        }
        self.envelope
            .as_file_mut()
            .write_all(bytes)
            .map_err(|e| io_error(&e, "write"))
    }

    /// END: verifies the envelope against the manifest and END's SHA-256 and
    /// size, then keeps the file in the Received folder.  Consumes the sink,
    /// so the envelope temp file is deleted however this returns, and the
    /// plaintext temp file is deleted unless it was kept.
    pub fn end(self, sha256: [u8; 32], size: u64) -> Result<Kept, SinkError> {
        self.verify(sha256, size)?.keep()
    }

    /// END's checks without keeping: the verified plaintext, still in a
    /// private temp file, ready for [`Verified::keep`].  Dropping it deletes
    /// the plaintext, so a transfer stopped between the two keeps nothing.
    pub fn verify(self, sha256: [u8; 32], size: u64) -> Result<Verified, SinkError> {
        if self.broken {
            return Err(SinkError::Failed("the sink has failed"));
        }
        // 1. Exactly E bytes.
        if self.written != self.total {
            return Err(SinkError::Failed("not every byte arrived"));
        }
        if size != self.manifest.size {
            return Err(SinkError::Failed("END names another size"));
        }
        self.envelope
            .as_file()
            .sync_all()
            .map_err(|e| io_error(&e, "sync"))?;
        // 2. Every record authenticates; the record count and padding match
        //    the header.  The plaintext is released only if all of it does.
        let (metadata, plain) = wildbloom_envelope::decrypt_file_to_private_temp(
            &self.key,
            self.envelope.path(),
            Limits::new(MAX_FILE_BYTES),
            &self.temp_dir,
            &mut |_, _| ControlFlow::Continue(()),
        )
        .map_err(|error| match error {
            wildbloom_envelope::Error::Io(e) => io_error(&e, "decrypt"),
            _ => SinkError::Failed("the envelope did not open"),
        })?;
        // 3. The metadata is the manifest, exactly.
        if metadata.name != self.manifest.name
            || metadata.size != self.manifest.size
            || metadata.media_type != self.manifest.media_type
        {
            return Err(SinkError::Failed("the metadata is not the manifest"));
        }
        // 4. The plaintext's size and SHA-256 are END's.
        let (length, digest) = digest_of(&plain).map_err(|e| io_error(&e, "read"))?;
        if length != size || digest != sha256 {
            return Err(SinkError::Failed("the size or SHA-256 is not END's"));
        }
        drop(self.envelope);
        Ok(Verified {
            plain,
            name: metadata.name,
            received_dir: self.received_dir,
        })
    }

    /// Leaves the temp file behind, as a killed process would.
    #[cfg(test)]
    pub(crate) fn leak(self) -> PathBuf {
        self.envelope.into_temp_path().keep().unwrap()
    }
}

/// A plaintext that passed every check of END, not yet in the Received
/// folder.  Dropping it deletes the plaintext.
pub struct Verified {
    plain: NamedTempFile,
    name: String,
    received_dir: PathBuf,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified").finish_non_exhaustive()
    }
}

impl Verified {
    /// Places the file in the Received folder.
    pub fn keep(self) -> Result<Kept, SinkError> {
        // Defence in depth: the name passed the name rule when the manifest
        // was read, and is checked again where it is placed.
        received::keep(self.plain, &self.received_dir, &self.name).map_err(|e| io_error(&e, "keep"))
    }
}

/// The length and SHA-256 of a file.
fn digest_of(file: &NamedTempFile) -> std::io::Result<(u64, [u8; 32])> {
    let mut input = std::fs::File::open(file.path())?;
    let mut hasher = Sha256::new();
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; 1024 * 1024]);
    let mut length = 0u64;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        length += n as u64;
    }
    Ok((length, hasher.finalize().into()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wildbloom_envelope::seal_bytes;

    pub(crate) fn manifest(name: &str, size: u64) -> Manifest {
        Manifest {
            name: name.into(),
            size,
            media_type: "text/plain".into(),
        }
    }

    /// A real FSWNENC2 envelope of `plain` and its manifest.
    pub(crate) fn sealed(key: &InputKey, name: &str, plain: &[u8]) -> (Manifest, Vec<u8>) {
        let manifest = manifest(name, plain.len() as u64);
        let envelope =
            seal_bytes(key, name, "text/plain", plain, Limits::new(MAX_FILE_BYTES)).unwrap();
        assert_eq!(
            Some(envelope.len() as u64),
            super::super::messages::envelope_bytes(&manifest)
        );
        (manifest, envelope)
    }

    pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    struct Dirs {
        _root: tempfile::TempDir,
        temp: PathBuf,
        received: PathBuf,
    }

    fn dirs() -> Dirs {
        let root = tempfile::tempdir().unwrap();
        let temp = root.path().join("drop-temp");
        let received = root.path().join("Downloads").join("Wildbloom Received");
        Dirs {
            temp,
            received,
            _root: root,
        }
    }

    /// Nothing but the lock file (if any) is left in the temp directory.
    fn temp_is_empty(dir: &Path) -> bool {
        std::fs::read_dir(dir).map_or(true, |entries| {
            entries
                .flatten()
                .all(|e| e.file_name() == ".wildbloom-temp.lock")
        })
    }

    fn feed(sink: &mut Sink, envelope: &[u8], chunk: usize) -> Vec<u64> {
        let mut acks = Vec::new();
        for (i, part) in envelope.chunks(chunk).enumerate() {
            if let Some(ack) = sink.write((i * chunk) as u64, part).unwrap() {
                acks.push(ack);
            }
        }
        acks
    }

    #[test]
    fn a_good_envelope_is_kept_and_nothing_else_remains() {
        let dirs = dirs();
        let key = InputKey::random().unwrap();
        let plain: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
        let (manifest, envelope) = sealed(&key, "Café notes.txt", &plain);
        let mut sink = Sink::create(&dirs.temp, &dirs.received, "t", key, manifest).unwrap();
        assert_eq!(sink.total(), envelope.len() as u64);
        let acks = feed(&mut sink, &envelope, 65_527);
        // An ACK at least every MiB, and one at E.
        assert_eq!(acks.last(), Some(&(envelope.len() as u64)));
        assert!(acks.windows(2).all(|w| w[1] - w[0] <= 1_048_576 + 65_527));
        let kept = sink.end(sha(&plain), plain.len() as u64).unwrap();
        assert_eq!(kept.name, "Café notes.txt");
        assert_eq!(kept.path, dirs.received.join("Café notes.txt"));
        assert_eq!(std::fs::read(&kept.path).unwrap(), plain);
        assert!(temp_is_empty(&dirs.temp));
    }

    #[test]
    fn an_empty_file_is_kept() {
        let dirs = dirs();
        let key = InputKey::random().unwrap();
        let (manifest, envelope) = sealed(&key, "empty.txt", b"");
        let mut sink = Sink::create(&dirs.temp, &dirs.received, "t", key, manifest).unwrap();
        feed(&mut sink, &envelope, 65_527);
        let kept = sink.end(sha(b""), 0).unwrap();
        assert_eq!(std::fs::metadata(&kept.path).unwrap().len(), 0);
    }

    /// Feeds `envelope` and ends with `end`; every failure leaves nothing.
    fn refused(
        manifest: Manifest,
        key: InputKey,
        envelope: &[u8],
        end: ([u8; 32], u64),
    ) -> SinkError {
        let dirs = dirs();
        let mut sink = Sink::create(&dirs.temp, &dirs.received, "t", key, manifest).unwrap();
        let mut error = None;
        for (i, part) in envelope.chunks(65_527).enumerate() {
            if let Err(e) = sink.write((i * 65_527) as u64, part) {
                error = Some(e);
                break;
            }
        }
        let error = match error {
            Some(error) => {
                drop(sink);
                error
            }
            None => sink.end(end.0, end.1).unwrap_err(),
        };
        assert!(temp_is_empty(&dirs.temp), "temp files left");
        assert!(!dirs.received.exists() || std::fs::read_dir(&dirs.received).unwrap().count() == 0);
        error
    }

    #[test]
    fn a_tampered_record_wrong_key_or_wrong_metadata_is_stop_2() {
        let key = InputKey::random().unwrap();
        let plain = b"synthetic direct send";
        let (manifest, envelope) = sealed(&key, "a.txt", plain);
        let end = (sha(plain), plain.len() as u64);

        let mut tampered = envelope.clone();
        tampered[100] ^= 1;
        let error = refused(manifest.clone(), key.clone(), &tampered, end);
        assert_eq!(error, SinkError::Failed("the envelope did not open"));
        assert_eq!(error.stop_code(), 2);

        let mut header = envelope.clone();
        header[15] ^= 1; // the record count
        assert_eq!(
            refused(manifest.clone(), key.clone(), &header, end).stop_code(),
            2
        );

        let other = InputKey::random().unwrap();
        assert_eq!(
            refused(manifest.clone(), other, &envelope, end),
            SinkError::Failed("the envelope did not open")
        );

        // The envelope is fine but says another name or type than the
        // manifest; same length, so every byte arrives.
        let (_, renamed) = sealed(&key, "b.txt", plain);
        assert_eq!(
            refused(manifest.clone(), key.clone(), &renamed, end),
            SinkError::Failed("the metadata is not the manifest")
        );
        let typed = seal_bytes(
            &key,
            "a.txt",
            "text/html",
            plain,
            Limits::new(MAX_FILE_BYTES),
        )
        .unwrap();
        assert_eq!(typed.len(), envelope.len());
        assert_eq!(
            refused(manifest, key, &typed, end),
            SinkError::Failed("the metadata is not the manifest")
        );
    }

    #[test]
    fn a_wrong_size_or_hash_in_end_is_stop_2() {
        let key = InputKey::random().unwrap();
        let plain = b"synthetic direct send";
        let (manifest, envelope) = sealed(&key, "a.txt", plain);
        assert_eq!(
            refused(
                manifest.clone(),
                key.clone(),
                &envelope,
                (sha(b"other"), plain.len() as u64)
            ),
            SinkError::Failed("the size or SHA-256 is not END's")
        );
        assert_eq!(
            refused(manifest, key, &envelope, (sha(plain), 3)),
            SinkError::Failed("END names another size")
        );
    }

    #[test]
    fn short_long_out_of_order_and_overlapping_writes_are_refused() {
        let dirs = dirs();
        let key = InputKey::random().unwrap();
        let plain = vec![7u8; 200_000];
        let (manifest, envelope) = sealed(&key, "a.bin", &plain);
        let new = || {
            Sink::create(
                &dirs.temp,
                &dirs.received,
                "t",
                key.clone(),
                manifest.clone(),
            )
            .unwrap()
        };
        // Each case's sink is dropped before the next, as the session drops it.
        {
            // Short: END before every byte.
            let mut sink = new();
            sink.write(0, &envelope[..1000]).unwrap();
            assert_eq!(
                sink.end(sha(&plain), plain.len() as u64),
                Err(SinkError::Failed("not every byte arrived"))
            );

            // Long: a byte past E.
            let mut sink = new();
            feed(&mut sink, &envelope, 65_527);
            assert_eq!(
                sink.write(envelope.len() as u64, &[0]),
                Err(SinkError::Failed("bytes past the end of the envelope"))
            );
            let mut sink = new();
            let last = envelope.len() - 10;
            for (i, part) in envelope[..last].chunks(65_527).enumerate() {
                sink.write((i * 65_527) as u64, part).unwrap();
            }
            assert_eq!(
                sink.write(last as u64, &[0; 11]),
                Err(SinkError::Failed("bytes past the end of the envelope"))
            );

            // A gap, then nothing more is accepted.
            let mut sink = new();
            sink.write(0, &envelope[..100]).unwrap();
            assert_eq!(
                sink.write(101, &envelope[101..200]),
                Err(SinkError::Failed("a gap or an overlap"))
            );
            assert_eq!(
                sink.write(100, &envelope[100..200]),
                Err(SinkError::Failed("the sink has failed"))
            );
            assert!(sink.end(sha(&plain), plain.len() as u64).is_err());

            // An overlap and an out-of-order write.
            let mut sink = new();
            sink.write(0, &envelope[..100]).unwrap();
            assert_eq!(
                sink.write(50, &envelope[50..150]),
                Err(SinkError::Failed("a gap or an overlap"))
            );
            let mut sink = new();
            assert_eq!(
                sink.write(100, &envelope[100..200]),
                Err(SinkError::Failed("a gap or an overlap"))
            );

            // Empty and oversized writes.
            let mut sink = new();
            assert!(sink.write(0, &[]).is_err());
            let mut sink = new();
            assert!(sink.write(0, &envelope[..65_537]).is_err());
        }
        assert!(temp_is_empty(&dirs.temp));
    }

    #[test]
    fn a_full_disk_is_stop_3_and_another_write_error_stop_2() {
        let dirs = dirs();
        let key = InputKey::random().unwrap();
        let plain = vec![9u8; 300_000];
        let (manifest, envelope) = sealed(&key, "a.bin", &plain);
        let mut sink = Sink::create(
            &dirs.temp,
            &dirs.received,
            "t",
            key.clone(),
            manifest.clone(),
        )
        .unwrap();
        sink.fail_writes_after = Some((100_000, std::io::ErrorKind::StorageFull));
        let mut result = Ok(None);
        for (i, part) in envelope.chunks(65_527).enumerate() {
            result = sink.write((i * 65_527) as u64, part);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(SinkError::Storage));
        assert_eq!(SinkError::Storage.stop_code(), 3);
        drop(sink);
        let mut sink = Sink::create(&dirs.temp, &dirs.received, "t", key, manifest).unwrap();
        sink.fail_writes_after = Some((0, std::io::ErrorKind::PermissionDenied));
        assert_eq!(sink.write(0, &envelope[..10]).unwrap_err().stop_code(), 2);
        drop(sink);
        assert!(temp_is_empty(&dirs.temp));
    }

    #[test]
    fn a_crash_leftover_is_swept_at_start() {
        let dirs = dirs();
        let key = InputKey::random().unwrap();
        let (manifest, envelope) = sealed(&key, "a.txt", b"x");
        let mut sink = Sink::create(&dirs.temp, &dirs.received, "t", key, manifest).unwrap();
        sink.write(0, &envelope[..1000]).unwrap();
        let left = sink.leak();
        assert!(left.exists());
        let lock = wildbloom_envelope::TempDirLock::acquire(&dirs.temp).unwrap();
        let report = wildbloom_envelope::sweep_stale_temp_files(&lock).unwrap();
        assert_eq!(report.removed, 1);
        assert!(!left.exists());
    }

    #[test]
    fn a_taken_name_gets_a_number() {
        let dirs = dirs();
        std::fs::create_dir_all(&dirs.received).unwrap();
        std::fs::write(dirs.received.join("a.txt"), b"older").unwrap();
        let key = InputKey::random().unwrap();
        let (manifest, envelope) = sealed(&key, "a.txt", b"newer");
        let mut sink = Sink::create(&dirs.temp, &dirs.received, "t", key, manifest).unwrap();
        feed(&mut sink, &envelope, 65_527);
        let kept = sink.end(sha(b"newer"), 5).unwrap();
        assert_eq!(kept.name, "a (2).txt");
        assert_eq!(
            std::fs::read(dirs.received.join("a.txt")).unwrap(),
            b"older"
        );
        assert_eq!(std::fs::read(&kept.path).unwrap(), b"newer");
    }
}
