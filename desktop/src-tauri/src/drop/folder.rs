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
}
