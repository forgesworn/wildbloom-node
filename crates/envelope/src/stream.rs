//! The record loop, over `Read` and `Write`, and the private temp-file helpers.

use crate::{
    CHUNK_BYTES, Error, HEADER_BYTES, InputKey, KEY_BYTES, Limits, MAGIC, MAX_METADATA_BYTES,
    MIN_PADDING_BUCKET, Metadata, NONCE_PREFIX_BYTES, SALT_BYTES, TAG_BYTES, derive_envelope_key,
    normalise_media_type, sanitise_name,
};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::ops::ControlFlow;
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

/// Called after every record with `(envelope bytes processed, envelope bytes
/// total)`.  Returning `Break` stops the operation with [`Error::Cancelled`].
pub type Progress<'a> = &'a mut dyn FnMut(u64, u64) -> ControlFlow<()>;

const RECORD_BYTES: u64 = (CHUNK_BYTES + TAG_BYTES) as u64;

/// What an encryption produced.  The SHA-256 is the Blossom address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub metadata: Metadata,
    pub envelope_bytes: u64,
    pub sha256: [u8; 32],
}

/// How padding is filled.  Only the test build can choose the deterministic
/// vector fill, so a release build cannot reproduce a fixed envelope.
#[derive(Clone, Copy)]
pub(crate) enum Padding {
    Random,
    /// `byte[i] = (i * 73 + 41) mod 256` over the logical plaintext.
    #[cfg(test)]
    KnownAnswer,
}

/// The per-envelope public randomness.  Production always draws it fresh.
pub(crate) struct Fresh {
    pub(crate) nonce_prefix: [u8; NONCE_PREFIX_BYTES],
    pub(crate) salt: [u8; SALT_BYTES],
    pub(crate) padding: Padding,
}

impl Fresh {
    fn draw() -> Result<Self, Error> {
        let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
        let mut salt = [0u8; SALT_BYTES];
        getrandom::fill(&mut nonce_prefix).map_err(|_| Error::Random)?;
        getrandom::fill(&mut salt).map_err(|_| Error::Random)?;
        Ok(Self {
            nonce_prefix,
            salt,
            padding: Padding::Random,
        })
    }
}

/// `P(L)`: 64 KiB floor, the next power of two up to 1 MiB, then 1 MiB steps.
pub(crate) fn padded_length(length: u64) -> u64 {
    let chunk = CHUNK_BYTES as u64;
    if length <= MIN_PADDING_BUCKET as u64 {
        MIN_PADDING_BUCKET as u64
    } else if length <= chunk {
        length.next_power_of_two()
    } else {
        length.div_ceil(chunk) * chunk
    }
}

/// The envelope size for a padded plaintext of `plaintext` bytes.
fn envelope_len_for(plaintext: u64) -> u64 {
    let records = plaintext.div_ceil(CHUNK_BYTES as u64);
    HEADER_BYTES as u64 + plaintext + records * TAG_BYTES as u64
}

/// The exact envelope size `encrypt` will produce for this source, without
/// encrypting anything.  Lets a caller compare against a server's blob limit.
pub fn envelope_bytes(name: &str, media_type: &str, source_bytes: u64) -> Result<u64, Error> {
    let layout = layout(name, media_type, source_bytes, Limits::new(u64::MAX))?;
    Ok(envelope_len_for(layout.plaintext_len))
}

fn canonical_metadata(metadata: &Metadata) -> Result<Zeroizing<Vec<u8>>, Error> {
    // serde_json's escaping is the minimal profile ENCRYPTION.md requires: only
    // `"`, `\` and U+0000-U+001F, short escapes where they exist, `/` and
    // non-ASCII literal.
    let json = Zeroizing::new(serde_json::to_vec(metadata).map_err(|_| Error::Metadata("encode"))?);
    if json.len() > MAX_METADATA_BYTES {
        return Err(Error::MetadataTooLarge);
    }
    Ok(json)
}

struct Layout {
    metadata: Metadata,
    /// `u32 BE metadata length | canonical metadata JSON`.
    prefix: Zeroizing<Vec<u8>>,
    plaintext_len: u64,
    record_count: u32,
}

fn layout(
    name: &str,
    media_type: &str,
    source_bytes: u64,
    limits: Limits,
) -> Result<Layout, Error> {
    if source_bytes > limits.max_source_bytes() {
        return Err(Error::TooLarge);
    }
    let metadata = Metadata {
        name: sanitise_name(name),
        size: source_bytes,
        media_type: normalise_media_type(media_type)?,
    };
    let json = canonical_metadata(&metadata)?;
    let mut prefix = Zeroizing::new(Vec::with_capacity(4 + json.len()));
    prefix.extend_from_slice(&(json.len() as u32).to_be_bytes());
    prefix.extend_from_slice(&json);
    let logical = (prefix.len() as u64)
        .checked_add(source_bytes)
        .ok_or(Error::TooLarge)?;
    let plaintext_len = padded_length(logical);
    let record_count =
        u32::try_from(plaintext_len.div_ceil(CHUNK_BYTES as u64)).map_err(|_| Error::TooLarge)?;
    if record_count == 0 || record_count > limits.max_records() {
        return Err(Error::TooLarge);
    }
    Ok(Layout {
        metadata,
        prefix,
        plaintext_len,
        record_count,
    })
}

fn header_bytes(
    record_count: u32,
    nonce_prefix: &[u8; NONCE_PREFIX_BYTES],
    salt: &[u8; SALT_BYTES],
) -> [u8; HEADER_BYTES] {
    let mut header = [0u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8..12].copy_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    header[12..16].copy_from_slice(&record_count.to_be_bytes());
    header[16..24].copy_from_slice(nonce_prefix);
    header[24..56].copy_from_slice(salt);
    header
}

fn nonce_bytes(prefix: &[u8], counter: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// `header | u32 BE counter`: 60 bytes.
fn aad_bytes(header: &[u8; HEADER_BYTES], counter: u32) -> [u8; HEADER_BYTES + 4] {
    let mut aad = [0u8; HEADER_BYTES + 4];
    aad[..HEADER_BYTES].copy_from_slice(header);
    aad[HEADER_BYTES..].copy_from_slice(&counter.to_be_bytes());
    aad
}

fn cipher(key: &Zeroizing<[u8; KEY_BYTES]>) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key.as_ref()).expect("AES-256 takes a 32-byte key")
}

fn fill_padding(record: &mut [u8], _offset: u64, padding: Padding) -> Result<(), Error> {
    match padding {
        Padding::Random => getrandom::fill(record).map_err(|_| Error::Random),
        #[cfg(test)]
        Padding::KnownAnswer => {
            for (i, byte) in record.iter_mut().enumerate() {
                *byte = (((_offset + i as u64) * 73 + 41) % 256) as u8;
            }
            Ok(())
        }
    }
}

/// The part of logical range `[start, start + len)` that falls inside the
/// record at `[offset, offset + record_len)`, as record-relative indices.
fn overlap(offset: u64, record_len: usize, start: u64, len: u64) -> Option<(usize, usize)> {
    let from = start.max(offset);
    let to = (start + len).min(offset + record_len as u64);
    (to > from).then(|| ((from - offset) as usize, (to - offset) as usize))
}

fn report(progress: &mut Progress<'_>, done: u64, total: u64) -> Result<(), Error> {
    match progress(done, total) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(()) => Err(Error::Cancelled),
    }
}

/// Encrypts exactly `source_bytes` bytes from `source` into `out` as one
/// `FSWNENC2` envelope with a fresh salt, nonce prefix and random padding.
///
/// The length must be known up front because the record count is in the
/// header.  A source that ends early or keeps going is [`Error::SourceChanged`].
/// On error `out` holds a partial envelope, which the caller discards.
#[allow(clippy::too_many_arguments)]
pub fn encrypt<R: Read, W: Write>(
    key: &InputKey,
    source: R,
    source_bytes: u64,
    name: &str,
    media_type: &str,
    limits: Limits,
    out: W,
    progress: Progress<'_>,
) -> Result<Sealed, Error> {
    encrypt_with(
        key,
        source,
        source_bytes,
        name,
        media_type,
        limits,
        Fresh::draw()?,
        out,
        progress,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_with<R: Read, W: Write>(
    key: &InputKey,
    mut source: R,
    source_bytes: u64,
    name: &str,
    media_type: &str,
    limits: Limits,
    fresh: Fresh,
    mut out: W,
    mut progress: Progress<'_>,
) -> Result<Sealed, Error> {
    let layout = layout(name, media_type, source_bytes, limits)?;
    let header = header_bytes(layout.record_count, &fresh.nonce_prefix, &fresh.salt);
    let cipher = cipher(&derive_envelope_key(key, &fresh.salt));
    let total = envelope_len_for(layout.plaintext_len);
    let prefix_len = layout.prefix.len() as u64;
    let mut hasher = Sha256::new();
    out.write_all(&header)?;
    hasher.update(header);
    let mut written = HEADER_BYTES as u64;

    let mut record = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
    for counter in 0..layout.record_count {
        let offset = u64::from(counter) * CHUNK_BYTES as u64;
        let len = (layout.plaintext_len - offset).min(CHUNK_BYTES as u64) as usize;
        let buffer = &mut record[..len];
        fill_padding(buffer, offset, fresh.padding)?;
        if let Some((from, to)) = overlap(offset, len, 0, prefix_len) {
            let at = (offset + from as u64) as usize;
            buffer[from..to].copy_from_slice(&layout.prefix[at..at + (to - from)]);
        }
        if let Some((from, to)) = overlap(offset, len, prefix_len, source_bytes) {
            source
                .read_exact(&mut buffer[from..to])
                .map_err(|e| match e.kind() {
                    io::ErrorKind::UnexpectedEof => Error::SourceChanged,
                    _ => Error::Io(e),
                })?;
        }
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes(&fresh.nonce_prefix, counter)),
                &aad_bytes(&header, counter),
                buffer,
            )
            .map_err(|_| Error::TooLarge)?;
        out.write_all(buffer)?;
        out.write_all(&tag)?;
        hasher.update(&*buffer);
        hasher.update(tag);
        written += (len + TAG_BYTES) as u64;
        report(&mut progress, written, total)?;
    }
    let mut probe = [0u8; 1];
    if read_some(&mut source, &mut probe)? != 0 {
        return Err(Error::SourceChanged);
    }
    out.flush()?;
    debug_assert_eq!(written, total);
    Ok(Sealed {
        metadata: layout.metadata,
        envelope_bytes: written,
        sha256: hasher.finalize().into(),
    })
}

fn read_some<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// The four-byte length, the canonical JSON, and the fixed-point checks.
fn parse_metadata(plaintext: &[u8]) -> Result<(Metadata, u64), Error> {
    let length: [u8; 4] = plaintext
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::Metadata("truncated"))?;
    let length = u32::from_be_bytes(length) as usize;
    if !(2..=MAX_METADATA_BYTES).contains(&length) || 4 + length > plaintext.len() {
        return Err(Error::Metadata("length"));
    }
    let text = &plaintext[4..4 + length];
    std::str::from_utf8(text).map_err(|_| Error::Metadata("utf-8"))?;
    let metadata: Metadata = serde_json::from_slice(text).map_err(|_| Error::Metadata("shape"))?;
    if canonical_metadata(&metadata)?.as_slice() != text {
        return Err(Error::Metadata("canonical form"));
    }
    if sanitise_name(&metadata.name) != metadata.name {
        return Err(Error::Metadata("name"));
    }
    if normalise_media_type(&metadata.media_type).ok().as_deref() != Some(&metadata.media_type) {
        return Err(Error::Metadata("type"));
    }
    Ok((metadata, (4 + length) as u64))
}

/// Decrypts an `envelope_len`-byte envelope from `envelope`, streaming the
/// source bytes into `out`.  **`out` receives plaintext before the last record
/// has authenticated**, so this stays private: the public helpers below only
/// release output once this returns `Ok`.
pub(crate) fn decrypt<R: Read, W: Write>(
    key: &InputKey,
    mut envelope: R,
    envelope_len: u64,
    limits: Limits,
    mut out: W,
    mut progress: Progress<'_>,
) -> Result<Metadata, Error> {
    let short = |e: io::Error| match e.kind() {
        io::ErrorKind::UnexpectedEof => Error::Length,
        _ => Error::Io(e),
    };
    if envelope_len < MAGIC.len() as u64 {
        return Err(Error::Length);
    }
    let mut header = [0u8; HEADER_BYTES];
    envelope.read_exact(&mut header[..8]).map_err(short)?;
    if &header[..8] != MAGIC {
        return Err(Error::Magic);
    }
    if envelope_len < HEADER_BYTES as u64 {
        return Err(Error::Length);
    }
    envelope.read_exact(&mut header[8..]).map_err(short)?;
    let chunk = u32::from_be_bytes(header[8..12].try_into().expect("4 bytes"));
    let count = u32::from_be_bytes(header[12..16].try_into().expect("4 bytes"));
    if chunk as usize != CHUNK_BYTES || count == 0 || count > limits.max_records() {
        return Err(Error::Header);
    }
    let records = u64::from(count);
    let head = HEADER_BYTES as u64;
    let minimum = head + (records - 1) * RECORD_BYTES + 1 + TAG_BYTES as u64;
    let maximum = head + records * RECORD_BYTES;
    if envelope_len < minimum || envelope_len > maximum {
        return Err(Error::Length);
    }
    let plaintext_len = envelope_len - head - records * TAG_BYTES as u64;
    let cipher = cipher(&derive_envelope_key(key, &header[24..56]));

    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_BYTES + TAG_BYTES]);
    let mut opened: Option<(Metadata, u64)> = None;
    let mut read = head;
    for counter in 0..count {
        let len = if counter + 1 == count {
            (envelope_len - head - (records - 1) * RECORD_BYTES) as usize
        } else {
            RECORD_BYTES as usize
        };
        envelope.read_exact(&mut buffer[..len]).map_err(short)?;
        let (data, tag) = buffer[..len].split_at_mut(len - TAG_BYTES);
        cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes(&header[16..24], counter)),
                &aad_bytes(&header, counter),
                data,
                Tag::from_slice(tag),
            )
            .map_err(|_| Error::Authentication)?;
        if opened.is_none() {
            let (metadata, prefix_len) = parse_metadata(data)?;
            // Bound the authenticated integer before any arithmetic on it.
            if metadata.size > plaintext_len
                || padded_length(prefix_len + metadata.size) != plaintext_len
            {
                return Err(Error::Padding);
            }
            if metadata.size > limits.max_source_bytes() {
                return Err(Error::TooLarge);
            }
            opened = Some((metadata, prefix_len));
        }
        let (metadata, prefix_len) = opened.as_ref().expect("set by record 0");
        let offset = u64::from(counter) * CHUNK_BYTES as u64;
        if let Some((from, to)) = overlap(offset, data.len(), *prefix_len, metadata.size) {
            out.write_all(&data[from..to])?;
        }
        read += len as u64;
        report(&mut progress, read, envelope_len)?;
    }
    let mut probe = [0u8; 1];
    if read_some(&mut envelope, &mut probe)? != 0 {
        return Err(Error::Length);
    }
    out.flush()?;
    Ok(opened.expect("count is at least one").0)
}

/// Temp files this crate creates are named `.wildbloom-<random>.part`.
const TEMP_PREFIX: &str = ".wildbloom-";
const TEMP_SUFFIX: &str = ".part";

fn private_temp(dir: &Path) -> Result<NamedTempFile, Error> {
    wildbloom_private_state::private_directory(dir).map_err(Error::PrivateState)?;
    let temp = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .suffix(TEMP_SUFFIX)
        .tempfile_in(dir)?;
    wildbloom_private_state::check_file(temp.as_file()).map_err(Error::PrivateState)?;
    Ok(temp)
}

fn open_regular(path: &Path) -> Result<(File, u64), Error> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        )));
    }
    Ok((file, meta.len()))
}

/// Encrypts the file at `source` into a new private temp file in `temp_dir`
/// (created private if missing; refused if it already has broad access).
/// The temp file is deleted on any error or panic and when the returned handle
/// drops, so the caller persists (renames) or uploads it before letting go.
/// Persist under a name that is not `.wildbloom-*.part`, or
/// [`sweep_stale_temp_files`] will remove it.
pub fn encrypt_file_to_private_temp(
    key: &InputKey,
    source: &Path,
    name: &str,
    media_type: &str,
    limits: Limits,
    temp_dir: &Path,
    progress: Progress<'_>,
) -> Result<(Sealed, NamedTempFile), Error> {
    let (file, len) = open_regular(source)?;
    let temp = private_temp(temp_dir)?;
    let sealed = {
        let mut writer = BufWriter::with_capacity(64 * 1024, temp.as_file());
        let sealed = encrypt(
            key,
            file,
            len,
            name,
            media_type,
            limits,
            &mut writer,
            progress,
        )?;
        writer.flush()?;
        sealed
    };
    temp.as_file().sync_all()?;
    Ok((sealed, temp))
}

/// Deletes stale `.wildbloom-*.part` files left in `temp_dir` by a process that
/// was killed mid-operation.  A hard kill skips the temp file's cleanup, so a
/// partial decryption can leave authenticated plaintext behind; call this at
/// start-up, before any operation that uses `temp_dir`, and never while one is
/// running.  Returns how many files were removed.  A missing directory is
/// nothing to sweep; a directory with broad access is refused.  Only ordinary
/// files are removed: symlinks and directories are left alone.
pub fn sweep_stale_temp_files(temp_dir: &Path) -> Result<usize, Error> {
    match std::fs::symlink_metadata(temp_dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Error::Io(e)),
        Ok(_) => {}
    }
    wildbloom_private_state::check_directory(temp_dir).map_err(Error::PrivateState)?;
    let mut removed = 0;
    for entry in std::fs::read_dir(temp_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX)) {
            continue;
        }
        if !std::fs::symlink_metadata(entry.path())?
            .file_type()
            .is_file()
        {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(removed)
}

/// Decrypts the envelope at `envelope` into a new private temp file in
/// `temp_dir`.  The file is returned only after every record authenticated and
/// every check passed; on any error or panic it is deleted as this returns or
/// unwinds.  A hard kill cannot run that cleanup: see [`sweep_stale_temp_files`].
///
/// `temp_dir` must not be inside a synced or backed-up folder, because the
/// partial plaintext of a decryption in progress lives there.
pub fn decrypt_file_to_private_temp(
    key: &InputKey,
    envelope: &Path,
    limits: Limits,
    temp_dir: &Path,
    progress: Progress<'_>,
) -> Result<(Metadata, NamedTempFile), Error> {
    let (file, len) = open_regular(envelope)?;
    let temp = private_temp(temp_dir)?;
    // Unbuffered: records arrive in writes of up to 1 MiB, and a buffer would
    // be one more plaintext copy that cannot be wiped.
    let metadata = decrypt(key, file, len, limits, temp.as_file(), progress)?;
    temp.as_file().sync_all()?;
    Ok((metadata, temp))
}

/// Seals a small in-memory value (such as a key list) as one envelope.
pub fn seal_bytes(
    key: &InputKey,
    name: &str,
    media_type: &str,
    bytes: &[u8],
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encrypt(
        key,
        bytes,
        bytes.len() as u64,
        name,
        media_type,
        limits,
        &mut out,
        &mut |_, _| ControlFlow::Continue(()),
    )?;
    Ok(out)
}

/// Opens an in-memory envelope.  The plaintext is returned only on success and
/// is zeroised when dropped.
pub fn open_bytes(
    key: &InputKey,
    envelope: &[u8],
    limits: Limits,
) -> Result<(Metadata, Zeroizing<Vec<u8>>), Error> {
    // Reserve up front so growth never leaves an unzeroised copy behind.
    let mut out = Zeroizing::new(Vec::with_capacity(envelope.len()));
    let metadata = decrypt(
        key,
        envelope,
        envelope.len() as u64,
        limits,
        &mut *out,
        &mut |_, _| ControlFlow::Continue(()),
    )?;
    Ok((metadata, out))
}
