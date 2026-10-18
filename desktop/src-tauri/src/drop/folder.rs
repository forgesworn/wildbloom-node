//! The Wildbloom folder on disk: whether it is there, where a relative path
//! really is, and the checks every read, write, rename and removal goes
//! through.
//!
//! - Nothing here follows a symbolic link.  Every component under the root
//!   must be a real directory; a symbolic link anywhere refuses the path.
//! - Nothing is written outside the root: paths are built from validated
//!   relative components, never from a string a node or the page supplied.
//! - Folders Wildbloom creates are 0700 and files it writes are 0600 on Unix.

use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization as _;

/// The hidden file that says "this is the Wildbloom folder", holding the
/// random folder id kept in the index.  An unmounted disk, a renamed root or
/// a deleted marker makes the folder unavailable, and nothing is then
/// imported, written or inferred.
pub const MARKER: &str = ".wildbloom-folder";

/// What is at a relative path under the root.
#[derive(Debug)]
pub enum Stat {
    /// A regular file.
    Present(std::fs::Metadata),
    /// Nothing there, or a component that should be a folder is a file.
    Missing,
    /// Could not tell: a component is unreadable or a symbolic link.  Never
    /// counted as missing.
    Unknown,
}

/// Nanosecond modification time, as links record it.
pub fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos().min(i64::MAX as u128) as i64)
}

/// Whether `root` is a real directory (not a symbolic link).
pub fn root_is_dir(root: &Path) -> bool {
    std::fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_dir())
}

/// Whether the folder is available: the root is a real directory and its
/// marker holds `folder_id`.
pub fn available(root: &Path, folder_id: &str) -> bool {
    if !root_is_dir(root) || folder_id.is_empty() {
        return false;
    }
    let marker = root.join(MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(meta) if meta.file_type().is_file() && meta.len() < 1024 => {}
        _ => return false,
    }
    std::fs::read_to_string(&marker).is_ok_and(|text| text.trim() == folder_id)
}

/// Creates a private directory (0700 on Unix).
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Creates the root if it is missing and writes the marker.  A root that is
/// a symbolic link or a file is refused.
pub fn write_marker(root: &Path, folder_id: &str) -> std::io::Result<()> {
    match std::fs::symlink_metadata(root) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::other(
                "the Wildbloom folder is not a folder",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = root.parent() {
                std::fs::create_dir_all(parent)?;
            }
            create_private_dir(root)?;
        }
        Err(e) => return Err(e),
    }
    let marker = root.join(MARKER);
    if std::fs::symlink_metadata(&marker).is_ok_and(|m| !m.file_type().is_file()) {
        return Err(std::io::Error::other("the folder marker is not a file"));
    }
    super::engine::write_private_file(&marker, folder_id.as_bytes())
}

/// The components of `path` relative to `root`: UTF-8 normal components
/// only, or `None`.
pub fn relative(root: &Path, path: &Path) -> Option<Vec<String>> {
    let rest = path.strip_prefix(root).ok()?;
    let mut out = Vec::new();
    for component in rest.components() {
        match component {
            std::path::Component::Normal(name) => out.push(name.to_str()?.to_owned()),
            _ => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// `relative` joined with `/` and in NFC: how a disk path reads as an entry
/// path.
pub fn relative_nfc(root: &Path, path: &Path) -> Option<String> {
    Some(
        relative(root, path)?
            .iter()
            .map(|c| c.nfc().collect::<String>())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// `root` joined with each relative component.  Components must be plain
/// names (no separators, `.` or `..`); anything else is `None`.
pub fn join(root: &Path, rel: &[String]) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for component in rel {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(['/', '\\'])
            || component.contains('\0')
        {
            return None;
        }
        out.push(component);
    }
    (out != root).then_some(out)
}

/// What is at `rel` under `root`, looking at each component without
/// following symbolic links.
pub fn stat_under(root: &Path, rel: &[String]) -> Stat {
    if !root_is_dir(root) {
        return Stat::Unknown;
    }
    let Some(path) = join(root, rel) else {
        return Stat::Unknown;
    };
    let mut current = root.to_path_buf();
    for (n, component) in rel.iter().enumerate() {
        current.push(component);
        let last = n + 1 == rel.len();
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => return Stat::Unknown,
            Ok(meta) if last => {
                return if meta.file_type().is_file() {
                    Stat::Present(meta)
                } else {
                    Stat::Missing
                };
            }
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Stat::Missing,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Stat::Missing,
            Err(_) => return Stat::Unknown,
        }
    }
    debug_assert_eq!(current, path);
    Stat::Unknown
}

/// [`stat_under`] for an absolute path.
pub fn stat_path(root: &Path, path: &Path) -> Stat {
    match relative(root, path) {
        Some(rel) => stat_under(root, &rel),
        None => Stat::Unknown,
    }
}

/// Whether a regular file at `meta` still has the recorded size and mtime.
pub fn matches(meta: &std::fs::Metadata, size: Option<u64>, mtime: Option<i64>) -> bool {
    Some(meta.len()) == size && Some(mtime_of(meta)) == mtime
}

fn other(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

/// Creates each missing folder above `rel` (0700), refusing any component
/// that is a symbolic link or not a folder.  Returns the parent folder.
pub fn ensure_parent(root: &Path, rel: &[String]) -> std::io::Result<PathBuf> {
    if !root_is_dir(root) {
        return Err(other("the Wildbloom folder is not there"));
    }
    join(root, rel).ok_or_else(|| other("not a relative path"))?;
    let mut current = root.to_path_buf();
    for component in &rel[..rel.len() - 1] {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(other("a folder in the path is not a folder")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match create_private_dir(&current) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        if !std::fs::symlink_metadata(&current)
                            .is_ok_and(|m| m.file_type().is_dir())
                        {
                            return Err(other("a folder in the path is not a folder"));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(current)
}

/// The path as it really is on disk: each component as its folder lists it,
/// the exact name first, else the one that folds equal (a case-insensitive
/// or normalising file system may store `rel` differently).
pub fn actual_path(root: &Path, rel: &[String]) -> Option<PathBuf> {
    let mut current = root.to_path_buf();
    for component in rel {
        let want = super::path::fold(component);
        let mut exact = false;
        let mut folded = None;
        for entry in std::fs::read_dir(&current).ok()?.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == component {
                exact = true;
                break;
            }
            if folded.is_none() && super::path::fold(name) == want {
                folded = Some(name.to_owned());
            }
        }
        if exact {
            current.push(component);
        } else {
            current.push(folded?);
        }
    }
    Some(current)
}

fn random_hex() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| other("random"))?;
    Ok(super::hex_lower(&bytes))
}

/// Copies `source` into a hidden staging file in the target's folder,
/// hashing as it copies, then places it at `rel` without replacing anything
/// there.  A known `expect`ed plaintext hash that differs places nothing.
/// Returns the path as it is on disk, its metadata and the SHA-256 (hex).
/// The caller holds the folder lock.
pub fn place_file(
    root: &Path,
    rel: &[String],
    source: &Path,
    expect: Option<[u8; 32]>,
) -> std::io::Result<(PathBuf, std::fs::Metadata, String)> {
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Write as _};
    let parent = ensure_parent(root, rel)?;
    let target = parent.join(&rel[rel.len() - 1]);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(std::io::ErrorKind::AlreadyExists.into());
    }
    // In the target's own folder, so placing it is a link or a rename on one
    // file system.  The walk ignores the dot prefix and `.part`.
    let staging = parent.join(format!(".wildbloom-{}.part", random_hex()?));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let copied = (|| -> std::io::Result<[u8; 32]> {
        let mut out = options.open(&staging)?;
        let mut input = std::fs::File::open(source)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 256 * 1024];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            out.write_all(&buffer[..n])?;
        }
        out.sync_all()?;
        Ok(hasher.finalize().into())
    })();
    // The staging file is Wildbloom's own copy, never the owner's file.
    let discard = || {
        let _ = std::fs::remove_file(&staging);
    };
    let hash = match copied {
        Ok(hash) => hash,
        Err(e) => {
            discard();
            return Err(e);
        }
    };
    if expect.is_some_and(|expect| expect != hash) {
        discard();
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    match std::fs::hard_link(&staging, &target) {
        Ok(()) => discard(),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            discard();
            return Err(e);
        }
        // No hard links (FAT, exFAT): rename once nothing is there.
        Err(_) => {
            if std::fs::symlink_metadata(&target).is_ok() {
                discard();
                return Err(std::io::ErrorKind::AlreadyExists.into());
            }
            if let Err(e) = std::fs::rename(&staging, &target) {
                discard();
                return Err(e);
            }
        }
    }
    let actual = actual_path(root, rel).unwrap_or(target);
    let meta = std::fs::symlink_metadata(&actual)?;
    Ok((actual, meta, super::hex_lower(&hash)))
}

/// Renames a file without replacing anything at `to`.
pub fn move_no_clobber(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::hard_link(from, to) {
        Ok(()) => {
            if let Err(e) = std::fs::remove_file(from) {
                // Back to one name: `to` is the same file as `from`.
                let _ = std::fs::remove_file(to);
                return Err(e);
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
        Err(_) => {
            if std::fs::symlink_metadata(to).is_ok() {
                return Err(std::io::ErrorKind::AlreadyExists.into());
            }
            std::fs::rename(from, to)
        }
    }
}

/// `"{stem} {n}{ext}"`, within one component's length limit.
pub fn numbered(component: &str, n: u32) -> String {
    let (stem, ext) = match component.rfind('.') {
        Some(at) if at > 0 => (&component[..at], &component[at..]),
        _ => (component, ""),
    };
    let suffix = format!(" {n}{ext}");
    let room = super::path::MAX_COMPONENT_UTF16.saturating_sub(suffix.encode_utf16().count());
    let mut units = 0;
    let mut cut = stem.len();
    for (at, c) in stem.char_indices() {
        units += c.len_utf16();
        if units > room {
            cut = at;
            break;
        }
    }
    super::path::safe_component(&format!("{}{suffix}", &stem[..cut]))
}

/// Moves the file at `rel` out of the folder: to the system Trash through
/// `trash`, or if that fails into `<root>/.wildbloom/removed/<date>/<rel>`.
/// Never deletes it.  `false` if both failed (the caller retries later).
pub fn remove_to_trash(
    root: &Path,
    rel: &[String],
    date: &str,
    trash: &dyn Fn(&Path) -> std::io::Result<()>,
) -> bool {
    let Some(path) = join(root, rel) else {
        return false;
    };
    if !matches!(stat_under(root, rel), Stat::Present(_)) {
        return false;
    }
    if trash(&path).is_ok() {
        return true;
    }
    let mut hidden = vec![
        ".wildbloom".to_owned(),
        "removed".to_owned(),
        date.to_owned(),
    ];
    hidden.extend(rel.iter().cloned());
    let Ok(parent) = ensure_parent(root, &hidden) else {
        return false;
    };
    let name = &rel[rel.len() - 1];
    for n in 1..1000u32 {
        let candidate = if n == 1 {
            name.clone()
        } else {
            numbered(name, n)
        };
        match move_no_clobber(&path, &parent.join(&candidate)) {
            Ok(()) => return true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return false,
        }
    }
    false
}

/// Removes each folder in `dirs` (and then its parents, up to but not
/// including the root) that Wildbloom left empty.
pub fn sweep_empty(root: &Path, dirs: &std::collections::BTreeSet<PathBuf>) {
    for dir in dirs.iter().rev() {
        let mut current = dir.clone();
        while current != root && current.starts_with(root) {
            if !std::fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_dir()) {
                break;
            }
            let empty = std::fs::read_dir(&current).is_ok_and(|mut e| e.next().is_none());
            if !empty || std::fs::remove_dir(&current).is_err() {
                break;
            }
            if !current.pop() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(path: &str) -> Vec<String> {
        path.split('/').map(str::to_owned).collect()
    }

    #[test]
    fn the_marker_decides_availability() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Wildbloom");
        let id = "ab".repeat(16);
        assert!(!available(&root, &id), "no root");
        write_marker(&root, &id).unwrap();
        assert!(available(&root, &id));
        assert!(
            !available(&root, &"cd".repeat(16)),
            "another folder's marker"
        );
        assert!(!available(&root, ""));
        std::fs::remove_file(root.join(MARKER)).unwrap();
        assert!(!available(&root, &id), "marker deleted");
        write_marker(&root, &id).unwrap();
        let moved = dir.path().join("Renamed");
        std::fs::rename(&root, &moved).unwrap();
        assert!(!available(&root, &id), "root renamed");
        std::fs::rename(&moved, &root).unwrap();
        assert!(available(&root, &id), "renamed back");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(root.join(MARKER))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let fresh = dir.path().join("Fresh");
            write_marker(&fresh, &id).unwrap();
            let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
            // A symbolic link is never the folder.
            let link = dir.path().join("Link");
            std::os::unix::fs::symlink(&root, &link).unwrap();
            assert!(!available(&link, &id));
            assert!(write_marker(&link, &id).is_err());
        }
    }

    #[test]
    fn stat_tells_missing_from_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Docs")).unwrap();
        std::fs::write(root.join("Docs/a.txt"), b"a").unwrap();
        std::fs::write(root.join("file"), b"f").unwrap();
        assert!(matches!(stat_under(root, &rel("Docs/a.txt")), Stat::Present(m) if m.len() == 1));
        assert!(matches!(
            stat_under(root, &rel("Docs/b.txt")),
            Stat::Missing
        ));
        assert!(matches!(
            stat_under(root, &rel("Gone/b.txt")),
            Stat::Missing
        ));
        assert!(matches!(
            stat_under(root, &rel("file/b.txt")),
            Stat::Missing
        ));
        assert!(matches!(stat_under(root, &rel("Docs")), Stat::Missing));
        assert!(matches!(stat_under(root, &rel("../x")), Stat::Unknown));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("Docs"), root.join("Link")).unwrap();
            assert!(matches!(
                stat_under(root, &rel("Link/a.txt")),
                Stat::Unknown
            ));
            std::os::unix::fs::symlink(root.join("file"), root.join("Docs/l.txt")).unwrap();
            assert!(matches!(
                stat_under(root, &rel("Docs/l.txt")),
                Stat::Unknown
            ));
        }
    }

    #[test]
    fn relative_paths_stay_under_the_root() {
        let root = Path::new("/w");
        assert_eq!(
            relative(root, Path::new("/w/Docs/a.txt")),
            Some(rel("Docs/a.txt"))
        );
        assert_eq!(relative(root, Path::new("/elsewhere/a.txt")), None);
        assert_eq!(relative(root, Path::new("/w")), None);
        assert_eq!(
            relative_nfc(root, Path::new("/w/e\u{301}te\u{301}.jpg")).as_deref(),
            Some("\u{e9}t\u{e9}.jpg")
        );
        assert_eq!(join(root, &rel("a/b")), Some(PathBuf::from("/w/a/b")));
        for bad in ["..", ".", "", "a/b", "a\\b"] {
            assert_eq!(join(root, &[bad.to_owned()]), None, "{bad:?}");
        }
        assert_eq!(join(root, &[]), None);
    }

    #[test]
    fn placing_never_replaces_and_checks_the_plaintext() {
        use sha2::{Digest as _, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Wildbloom");
        std::fs::create_dir(&root).unwrap();
        let source = dir.path().join("plain");
        std::fs::write(&source, b"hello").unwrap();
        let hash: [u8; 32] = Sha256::digest(b"hello").into();
        let (placed, meta, hex) =
            place_file(&root, &rel("Docs/Sub/a.txt"), &source, Some(hash)).unwrap();
        assert_eq!(placed, root.join("Docs/Sub/a.txt"));
        assert_eq!(meta.len(), 5);
        assert_eq!(hex, crate::drop::hex_lower(&hash));
        assert_eq!(std::fs::read(&placed).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            let folder = std::fs::metadata(root.join("Docs/Sub")).unwrap();
            assert_eq!(folder.permissions().mode() & 0o777, 0o700);
        }
        // Something already there is never replaced.
        std::fs::write(&source, b"other").unwrap();
        let taken = place_file(&root, &rel("Docs/Sub/a.txt"), &source, None).unwrap_err();
        assert_eq!(taken.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&placed).unwrap(), b"hello");
        // A plaintext that is not the entry's places nothing.
        let wrong = place_file(&root, &rel("b.txt"), &source, Some(hash)).unwrap_err();
        assert_eq!(wrong.kind(), std::io::ErrorKind::InvalidData);
        assert!(!root.join("b.txt").exists());
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(
            leftovers,
            vec![std::ffi::OsString::from("Docs")],
            "no staging file left"
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path(), root.join("Out")).unwrap();
            assert!(place_file(&root, &rel("Out/x.txt"), &source, None).is_err());
            assert!(
                !dir.path().join("x.txt").exists(),
                "nothing written outside the root"
            );
        }
    }

    #[test]
    fn removed_files_go_to_the_trash_or_a_hidden_folder() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Docs")).unwrap();
        std::fs::write(root.join("Docs/a.txt"), b"a").unwrap();
        let trashed = std::sync::Mutex::new(Vec::new());
        let works = |path: &Path| -> std::io::Result<()> {
            trashed.lock().unwrap().push(path.to_path_buf());
            std::fs::rename(path, root.join("trashed"))
        };
        assert!(remove_to_trash(
            root,
            &rel("Docs/a.txt"),
            "2026-10-18",
            &works
        ));
        assert_eq!(*trashed.lock().unwrap(), vec![root.join("Docs/a.txt")]);
        // The Trash refuses: the hidden folder keeps it, never deleted.
        std::fs::write(root.join("Docs/a.txt"), b"b").unwrap();
        let fails = |_: &Path| -> std::io::Result<()> { Err(std::io::Error::other("no")) };
        assert!(remove_to_trash(
            root,
            &rel("Docs/a.txt"),
            "2026-10-18",
            &fails
        ));
        let kept = root.join(".wildbloom/removed/2026-10-18/Docs/a.txt");
        assert_eq!(std::fs::read(&kept).unwrap(), b"b");
        std::fs::write(root.join("Docs/a.txt"), b"c").unwrap();
        assert!(remove_to_trash(
            root,
            &rel("Docs/a.txt"),
            "2026-10-18",
            &fails
        ));
        assert_eq!(
            std::fs::read(root.join(".wildbloom/removed/2026-10-18/Docs/a 2.txt")).unwrap(),
            b"c"
        );
        assert!(
            !remove_to_trash(root, &rel("Docs/a.txt"), "2026-10-18", &fails),
            "gone"
        );
        // The emptied folder goes; the root and others stay.
        std::fs::create_dir_all(root.join("Keep")).unwrap();
        std::fs::write(root.join("Keep/k.txt"), b"k").unwrap();
        sweep_empty(
            root,
            &[root.join("Docs"), root.join("Keep")].into_iter().collect(),
        );
        assert!(!root.join("Docs").exists());
        assert!(root.join("Keep/k.txt").exists());
        assert!(root.exists());
    }

    #[test]
    fn moves_never_replace_and_numbering_keeps_the_extension() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        assert_eq!(
            move_no_clobber(&a, &b).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&b).unwrap(), b"b");
        let c = dir.path().join("c");
        move_no_clobber(&a, &c).unwrap();
        assert!(!a.exists());
        assert_eq!(std::fs::read(&c).unwrap(), b"a");
        assert_eq!(numbered("report.pdf", 2), "report 2.pdf");
        assert_eq!(numbered("README", 3), "README 3");
        let long = numbered(&format!("{}.pdf", "s".repeat(178)), 12);
        assert_eq!(long.encode_utf16().count(), 180);
        assert!(long.ends_with(" 12.pdf"));
    }
}
