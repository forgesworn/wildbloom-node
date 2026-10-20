//! Where received files go.  A kept file lands in the Received folder,
//! outside `~/Wildbloom` (by default `Wildbloom Received` in the Downloads
//! folder), and "Add to Wildbloom" later moves it into the synced folder as
//! the owner's own file.  Neither ever replaces anything: a taken name gets
//! ` (2)`, ` (3)` and so on before its extension.

use crate::drop::folder;
use crate::drop::path::safe_component;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// The longest name, as the shared name rule counts it.
const MAX_NAME_UTF16: usize = 180;
/// The longest file name most file systems take, in UTF-8 bytes.
const MAX_NAME_BYTES: usize = 255;
/// How many numbered names are tried before giving up.
const MAX_TRIES: u32 = 999;

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The longest prefix of `text` within `units` UTF-16 units and `bytes`
/// UTF-8 bytes, never splitting a character.
fn truncate(text: &str, units: usize, bytes: usize) -> &str {
    let (mut used_units, mut end) = (0, 0);
    for (at, c) in text.char_indices() {
        used_units += c.len_utf16();
        if used_units > units || at + c.len_utf8() > bytes {
            break;
        }
        end = at + c.len_utf8();
    }
    &text[..end]
}

/// The `n`th name to try for `name`: the name itself for `n = 1`, otherwise
/// `"{stem} ({n}){ext}"`, where `ext` is the last `.xxx` unless the dot is
/// the first character.  The stem is cut so the whole stays within 180 UTF-16
/// units and 255 bytes, and the result is safe on every supported system.
/// The name is put through the shared name rule again first: it should
/// already be a fixed point of it.
pub fn candidate(name: &str, n: u32) -> String {
    let name = wildbloom_envelope::sanitise_name(name);
    let suffix = if n <= 1 {
        String::new()
    } else {
        format!(" ({n})")
    };
    let (mut stem, mut ext) = match name.rfind('.') {
        Some(at) if at > 0 => (&name[..at], &name[at..]),
        _ => (name.as_str(), ""),
    };
    // An extension too long to leave room for a stem is kept as stem text.
    if utf16_len(&suffix) + utf16_len(ext) >= MAX_NAME_UTF16 / 2 {
        stem = name.as_str();
        ext = "";
    }
    let stem = truncate(
        stem,
        MAX_NAME_UTF16.saturating_sub(utf16_len(&suffix) + utf16_len(ext)),
        MAX_NAME_BYTES.saturating_sub(suffix.len() + ext.len()),
    );
    safe_component(&format!("{stem}{suffix}{ext}"))
}

/// Moves `source` to `dir` under the first free candidate name, never
/// replacing anything.  A rename or link that cannot cross file systems
/// falls back to a hidden staging copy in `dir`, placed the same way, and
/// then the source is removed.  Returns the new path and name.
pub fn place(source: &Path, dir: &Path, name: &str) -> std::io::Result<(PathBuf, String)> {
    std::fs::create_dir_all(dir)?;
    for n in 1..=MAX_TRIES {
        let candidate = candidate(name, n);
        let target = dir.join(&candidate);
        if std::fs::symlink_metadata(&target).is_ok() {
            continue;
        }
        match folder::move_no_clobber(source, &target) {
            Ok(()) => return Ok((target, candidate)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return place_copy(source, dir, name),
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
}

/// The cross-file-system path: copy into a hidden staging file in `dir`
/// (which the folder mirror ignores), place that, then remove the source.
fn place_copy(source: &Path, dir: &Path, name: &str) -> std::io::Result<(PathBuf, String)> {
    let staging = tempfile::Builder::new()
        .prefix(".wildbloom-")
        .suffix(".part")
        .tempfile_in(dir)?;
    {
        let mut input = std::fs::File::open(source)?;
        let mut output = staging.as_file();
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
    }
    carry_quarantine(source, staging.path())?;
    let staging = staging.into_temp_path();
    for n in 1..=MAX_TRIES {
        let candidate = candidate(name, n);
        let target = dir.join(&candidate);
        if std::fs::symlink_metadata(&target).is_ok() {
            continue;
        }
        match folder::move_no_clobber(&staging, &target) {
            Ok(()) => {
                // Moved: nothing is left at the staging path to delete.
                let _ = staging.keep();
                let _ = std::fs::remove_file(source);
                return Ok((target, candidate));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
}

/// The extended attribute macOS reads to treat a file as downloaded.
#[cfg(target_os = "macos")]
const QUARANTINE: &str = "com.apple.quarantine";
/// `QTN_FLAG_DOWNLOAD` (0x0001) with 0x0080, as the non-sandboxed browsers
/// and apps that download files on macOS set it; 0x0040 (the person has
/// opened and approved it) stays clear, so the first open is checked.
#[cfg(target_os = "macos")]
const QUARANTINE_FLAGS: u16 = 0x0081;
/// The agent macOS names when it asks about opening the file.
#[cfg(target_os = "macos")]
const QUARANTINE_AGENT: &str = "Wildbloom";

/// The quarantine value: `flags;hex seconds;agent;UUID`, as macOS writes it.
#[cfg(target_os = "macos")]
fn quarantine_value(seconds: u64, uuid: [u8; 16]) -> String {
    let mut uuid = uuid;
    // A random (version 4, RFC 4122 variant) UUID.
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02X}")).collect::<String>();
    format!(
        "{QUARANTINE_FLAGS:04x};{seconds:08x};{QUARANTINE_AGENT};{}-{}-{}-{}-{}",
        hex(&uuid[0..4]),
        hex(&uuid[4..6]),
        hex(&uuid[6..8]),
        hex(&uuid[8..10]),
        hex(&uuid[10..16])
    )
}

/// Marks a file as downloaded and not yet opened, so Gatekeeper checks it
/// the first time it is opened, as it would a file from a browser.  Elsewhere
/// it does nothing.
pub fn quarantine(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut uuid = [0u8; 16];
        getrandom::fill(&mut uuid).map_err(|_| std::io::Error::other("no randomness"))?;
        xattr::set(path, QUARANTINE, quarantine_value(seconds, uuid).as_bytes())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(())
    }
}

/// Carries a quarantine flag from `from` to `to`, for a copy, which (unlike
/// a move) does not keep extended attributes.
fn carry_quarantine(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    if let Some(value) = xattr::get(from, QUARANTINE)? {
        xattr::set(to, QUARANTINE, &value)?;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (from, to);
    Ok(())
}

/// Keeps a verified plaintext temp file in the Received folder, marked as
/// downloaded ([`quarantine`]) before it is placed there.  On any error the
/// temp file is deleted.
pub fn keep(plain: NamedTempFile, dir: &Path, name: &str) -> std::io::Result<super::sink::Kept> {
    let plain = plain.into_temp_path();
    quarantine(&plain)?;
    let (path, name) = place(&plain, dir, name)?;
    // Moved: nothing is left at the temp path to delete.
    let _ = plain.keep();
    Ok(super::sink::Kept { path, name })
}

/// Deletes the hidden staging files a killed process left in `dir`.  Only
/// regular files named `.wildbloom-*.part` are touched.
pub fn sweep(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(".wildbloom-") && name.ends_with(".part")) {
            continue;
        }
        if std::fs::symlink_metadata(entry.path()).is_ok_and(|m| m.file_type().is_file())
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_names_go_before_the_extension() {
        assert_eq!(candidate("holiday.mp4", 1), "holiday.mp4");
        assert_eq!(candidate("holiday.mp4", 2), "holiday (2).mp4");
        assert_eq!(candidate("holiday.mp4", 10), "holiday (10).mp4");
        assert_eq!(candidate("archive.tar.gz", 3), "archive.tar (3).gz");
        assert_eq!(candidate("README", 2), "README (2)");
        assert_eq!(candidate("Café holiday.mp4", 2), "Café holiday (2).mp4");
        // Re-checked by the name rule, and made safe on Windows.
        assert_eq!(candidate("../x.txt", 1), "x.txt");
        assert_eq!(candidate("CON.txt", 1), "CON_.txt");
        assert_eq!(candidate("notes.", 1), "notes._");
    }

    #[test]
    fn numbered_names_stay_within_the_limits() {
        let long = format!("{}.txt", "a".repeat(176));
        assert_eq!(candidate(&long, 1), long);
        let two = candidate(&long, 2);
        assert_eq!(utf16_len(&two), 180);
        assert!(two.ends_with(" (2).txt"));
        // Three-byte characters hit the byte limit first.
        let wide = format!("{}.txt", "\u{4e00}".repeat(170));
        for n in [1, 2, 999] {
            let name = candidate(&wide, n);
            assert!(name.len() <= MAX_NAME_BYTES, "{n}: {}", name.len());
            assert!(name.ends_with(".txt"));
        }
        // An astral character is never split.
        let astral = format!("{}{}", "a".repeat(178), "\u{1F600}");
        assert_eq!(candidate(&astral, 1), astral);
        assert!(candidate(&astral, 2).ends_with(" (2)"));
        // A long extension is kept as stem text.
        let ext = format!("x.{}", "e".repeat(120));
        assert!(candidate(&ext, 2).ends_with(" (2)"));
    }

    #[test]
    fn placing_never_replaces_anything() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Received");
        let source = |bytes: &[u8]| {
            let path = root.path().join(format!("src-{}", bytes.len()));
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let (first, name) = place(&source(b"1"), &dir, "a.txt").unwrap();
        assert_eq!((first.clone(), name.as_str()), (dir.join("a.txt"), "a.txt"));
        let (second, name) = place(&source(b"22"), &dir, "a.txt").unwrap();
        assert_eq!(name, "a (2).txt");
        let (_, name) = place(&source(b"333"), &dir, "a.txt").unwrap();
        assert_eq!(name, "a (3).txt");
        assert_eq!(std::fs::read(first).unwrap(), b"1");
        assert_eq!(std::fs::read(second).unwrap(), b"22");
        // The sources were moved, not copied.
        assert!(!root.path().join("src-1").exists());
        // A folder in the way is a taken name too.
        std::fs::create_dir(dir.join("b.txt")).unwrap();
        let (_, name) = place(&source(b"4444"), &dir, "b.txt").unwrap();
        assert_eq!(name, "b (2).txt");
    }

    #[test]
    fn the_copy_path_places_and_removes_the_source() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Received");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"older").unwrap();
        let source = root.path().join("source");
        std::fs::write(&source, b"newer").unwrap();
        let (path, name) = place_copy(&source, &dir, "a.txt").unwrap();
        assert_eq!(name, "a (2).txt");
        assert_eq!(std::fs::read(path).unwrap(), b"newer");
        assert!(!source.exists());
        // No staging file is left.
        assert_eq!(sweep(&dir), 0);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
    }

    #[cfg(target_os = "macos")]
    fn quarantine_of(path: &Path) -> Option<String> {
        xattr::get(path, QUARANTINE)
            .unwrap()
            .map(|v| String::from_utf8(v).unwrap())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn quarantine_values_have_the_system_form() {
        let value = quarantine_value(0x6ad7_4ee8, [0xff; 16]);
        assert_eq!(
            value,
            "0081;6ad74ee8;Wildbloom;FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_kept_file_is_quarantined_on_either_path() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Received");
        // The move.
        let plain = tempfile::NamedTempFile::new_in(root.path()).unwrap();
        std::fs::write(plain.path(), b"kept").unwrap();
        let kept = keep(plain, &dir, "a.txt").unwrap();
        let value = quarantine_of(&kept.path).expect("quarantined");
        let fields: Vec<&str> = value.split(';').collect();
        assert_eq!(fields.len(), 4, "{value}");
        assert_eq!(fields[0], "0081");
        assert_eq!(u16::from_str_radix(fields[0], 16).unwrap() & 0x0040, 0);
        assert!(u64::from_str_radix(fields[1], 16).unwrap() > 1_700_000_000);
        assert_eq!(fields[2], "Wildbloom");
        assert_eq!(fields[3].len(), 36);
        // The copy, which keeps the source's flag.
        let source = root.path().join("source");
        std::fs::write(&source, b"copied").unwrap();
        quarantine(&source).unwrap();
        let flag = quarantine_of(&source);
        let (path, name) = place_copy(&source, &dir, "a.txt").unwrap();
        assert_eq!(name, "a (2).txt");
        assert!(flag.is_some());
        assert_eq!(quarantine_of(&path), flag);
    }

    #[test]
    fn the_sweep_removes_only_staging_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".wildbloom-abc.part"), b"x").unwrap();
        std::fs::write(root.path().join("film.part"), b"x").unwrap();
        std::fs::write(root.path().join(".wildbloom-abc"), b"x").unwrap();
        std::fs::create_dir(root.path().join(".wildbloom-dir.part")).unwrap();
        assert_eq!(sweep(root.path()), 1);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 3);
        assert_eq!(sweep(&root.path().join("missing")), 0);
    }
}
