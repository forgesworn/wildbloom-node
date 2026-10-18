//! The optional Wildbloom folder: files that appear in it are kept like
//! dropped files.  The folder is scanned on a short interval (not with a
//! file-system notification crate, whose licence is outside this project's
//! MIT/Apache rule), which also gives the settle rule directly: a file counts
//! once its size and modification time have been unchanged for 3 seconds and
//! it opens for reading.
//!
//! Originals are only ever read: never moved, renamed or deleted.  A file that
//! changes later becomes a new entry (Q15); the earlier copy stays.

use super::engine::{Engine, kv};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long size and mtime must hold still.
pub const SETTLE: Duration = Duration::from_secs(3);
/// Never walk deeper than this.
const MAX_DEPTH: usize = 16;
/// Never look at more than this many entries in one scan.
const MAX_ENTRIES: usize = 20_000;

/// Names never taken in: hidden files, partial downloads and OS litter.
pub fn ignored(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    name.starts_with('.')
        || name.starts_with("~$")
        || [".part", ".crdownload", ".download", ".tmp"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        || matches!(lower.as_str(), "desktop.ini" | "thumbs.db")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    size: u64,
    mtime: i64,
    since: Instant,
}

fn mtime_of(meta: &std::fs::Metadata) -> i64 {
    super::folder::mtime_of(meta)
}

/// One scan of the folder.  A scan says what it could not see, so absence
/// is never mistaken for deletion.
#[derive(Debug, Default)]
pub struct WalkReport {
    /// Regular files within the depth the path grammar allows.
    pub files: Vec<(PathBuf, std::fs::Metadata)>,
    /// Regular files one folder level too deep to keep.
    pub too_deep: Vec<(PathBuf, std::fs::Metadata)>,
    /// Folders that could not be read.  Files under them are not missing.
    pub unreadable: Vec<PathBuf>,
    /// The scan stopped at [`MAX_ENTRIES`]: nothing may be inferred from it.
    pub truncated: bool,
}

/// Regular files under `root` (no symbolic links followed), skipping ignored
/// and non-UTF-8 names.  Folders are walked [`MAX_DEPTH`] levels deep, so a
/// kept path has at most 17 components; files one level deeper are reported
/// as too deep, and nothing below that is looked at.
pub fn walk(root: &Path) -> WalkReport {
    let mut report = WalkReport::default();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => {
                report.unreadable.push(dir);
                continue;
            }
        };
        for entry in entries {
            let Ok(entry) = entry else {
                report.unreadable.push(dir.clone());
                break;
            };
            visited += 1;
            if visited > MAX_ENTRIES {
                report.truncated = true;
                return report;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if ignored(name) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                report.unreadable.push(entry.path());
                continue;
            };
            if meta.file_type().is_dir() {
                if depth < MAX_DEPTH + 1 {
                    stack.push((entry.path(), depth + 1));
                }
            } else if meta.file_type().is_file() {
                if depth > MAX_DEPTH {
                    report.too_deep.push((entry.path(), meta));
                } else {
                    report.files.push((entry.path(), meta));
                }
            }
        }
    }
    report
}

/// The deletion rule (spec 2.5) for one pass: a linked file counts as
/// deleted only when the folder is available, the scan was complete, no
/// folder import is still encrypting, and it was missing on two such scans
/// at least [`SETTLE`] apart.  `checks` is each linked row's id and what is
/// at its path now; `missing` remembers first misses between passes.
pub(crate) fn infer_missing(
    available: bool,
    truncated: bool,
    importing: bool,
    checks: &[(String, &super::folder::Stat)],
    missing: &mut HashMap<String, Instant>,
    now: Instant,
) -> Vec<String> {
    use super::folder::Stat;
    let mut out = Vec::new();
    for (id, stat) in checks {
        if !matches!(stat, Stat::Missing) {
            missing.remove(id);
            continue;
        }
        if !available || truncated || importing {
            continue;
        }
        match missing.get(id) {
            Some(since) if now.duration_since(*since) >= SETTLE => out.push(id.clone()),
            Some(_) => {}
            None => {
                missing.insert(id.clone(), now);
            }
        }
    }
    missing.retain(|id, _| checks.iter().any(|(c, _)| c == id));
    out
}

impl Engine {
    pub(crate) async fn watch_loop(self: Arc<Self>) {
        let mut candidates: HashMap<PathBuf, Seen> = HashMap::new();
        loop {
            let enabled =
                self.mirror_on() && self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false);
            if !enabled {
                candidates.clear();
                self.watch_wake.notified().await;
                continue;
            }
            self.watch_pass(&mut candidates).await;
            tokio::select! {
                _ = self.watch_wake.notified() => {}
                _ = tokio::time::sleep(self.cfg.watch_interval) => {}
            }
        }
    }

    async fn watch_pass(self: &Arc<Self>, candidates: &mut HashMap<PathBuf, Seen>) {
        let root = self.cfg.watch_dir.clone();
        let found = tokio::task::spawn_blocking(move || walk(&root).files)
            .await
            .unwrap_or_default();
        let now = Instant::now();
        let mut present = std::collections::HashSet::new();
        let mut settled = Vec::new();
        for (path, meta) in found {
            let size = meta.len();
            let mtime = mtime_of(&meta);
            present.insert(path.clone());
            let key = path.to_string_lossy().into_owned();
            if size == 0 || self.index.watch_seen(&key, size, mtime).unwrap_or(true) {
                candidates.remove(&path);
                continue;
            }
            match candidates.get(&path) {
                Some(seen) if seen.size == size && seen.mtime == mtime => {
                    if now.duration_since(seen.since) >= SETTLE
                        && std::fs::File::open(&path).is_ok()
                    {
                        settled.push((path.clone(), size, mtime));
                    }
                }
                _ => {
                    candidates.insert(
                        path.clone(),
                        Seen {
                            size,
                            mtime,
                            since: now,
                        },
                    );
                }
            }
        }
        candidates.retain(|path, _| present.contains(path));
        for (path, size, mtime) in settled {
            candidates.remove(&path);
            let key = path.to_string_lossy().into_owned();
            // Marked first, so a refused or duplicate file is not retried
            // every scan; a later change (new size or mtime) is a new entry.
            let _ = self.index.mark_watch_seen(&key, size, mtime);
            let _ = self.add_paths(vec![path], Some((size, mtime))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_partial_hidden_and_system_files() {
        for name in [
            ".DS_Store",
            ".hidden",
            "~$report.docx",
            "film.part",
            "film.PART",
            "a.crdownload",
            "a.download",
            "a.tmp",
            "desktop.ini",
            "Thumbs.db",
        ] {
            assert!(ignored(name), "{name}");
        }
        for name in ["report.docx", "photo.jpg", "partial.txt", "tmp.pdf"] {
            assert!(!ignored(name), "{name}");
        }
    }

    #[test]
    fn walks_regular_files_only() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("sub/b.txt"), b"b").unwrap();
        std::fs::write(dir.path().join("c.part"), b"c").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("a.txt"), dir.path().join("link.txt")).unwrap();
        let mut names: Vec<String> = walk(dir.path())
            .files
            .into_iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["a.txt", "b.txt"]);
    }

    #[test]
    fn the_walk_reports_what_it_could_not_see() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // 16 folder levels plus the file name: kept.  One deeper: too deep.
        let deep: PathBuf = (0..16).map(|n| format!("d{n}")).collect();
        std::fs::create_dir_all(root.join(&deep).join("x")).unwrap();
        std::fs::write(root.join(&deep).join("ok.txt"), b"o").unwrap();
        std::fs::write(root.join(&deep).join("x/deep.txt"), b"d").unwrap();
        std::fs::create_dir_all(root.join(&deep).join("x/y")).unwrap();
        std::fs::write(root.join(&deep).join("x/y/deeper.txt"), b"d").unwrap();
        let report = walk(root);
        assert!(!report.truncated);
        assert!(report.unreadable.is_empty());
        assert_eq!(report.files.len(), 1);
        assert!(report.files[0].0.ends_with("ok.txt"));
        assert_eq!(report.too_deep.len(), 1);
        assert!(report.too_deep[0].0.ends_with("x/deep.txt"));
        assert_eq!(
            super::super::folder::relative(root, &report.files[0].0)
                .unwrap()
                .len(),
            crate::drop::path::MAX_COMPONENTS
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let locked = root.join("Locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::write(locked.join("hidden.txt"), b"h").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let report = walk(root);
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
            // Running as a user that ignores permissions reads it anyway.
            if std::fs::read_dir(root.join("Locked")).is_ok() && report.unreadable.is_empty() {
                assert!(report.files.iter().any(|(p, _)| p.ends_with("hidden.txt")));
            } else {
                assert_eq!(report.unreadable, vec![locked.clone()]);
            }
        }

        let many = tempfile::tempdir().unwrap();
        for n in 0..=MAX_ENTRIES {
            std::fs::write(many.path().join(format!("{n}.txt")), b"").unwrap();
        }
        let report = walk(many.path());
        assert!(report.truncated);
        assert!(report.files.len() <= MAX_ENTRIES);
    }

    #[test]
    fn nothing_is_inferred_without_a_complete_available_scan() {
        use super::super::folder::{Stat, stat_under};
        let start = Instant::now();
        let later = start + SETTLE;
        let id = "aa".repeat(16);
        let gone = Stat::Missing;
        let checks = [(id.clone(), &gone)];
        // Marker missing (folder unavailable), a truncated scan, or a folder
        // import still encrypting: nothing, however many passes.
        for (available, truncated, importing) in [
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let mut missing = HashMap::new();
            for at in [start, later, later + SETTLE] {
                assert!(
                    infer_missing(available, truncated, importing, &checks, &mut missing, at)
                        .is_empty()
                );
            }
        }
        // Two misses at least 3 s apart on complete scans: deleted.
        let mut missing = HashMap::new();
        assert!(infer_missing(true, false, false, &checks, &mut missing, start).is_empty());
        assert!(
            infer_missing(
                true,
                false,
                false,
                &checks,
                &mut missing,
                start + SETTLE / 2
            )
            .is_empty(),
            "too soon"
        );
        assert_eq!(
            infer_missing(true, false, false, &checks, &mut missing, later),
            vec![id.clone()]
        );
        // A file that came back between scans starts again.
        let mut missing = HashMap::new();
        infer_missing(true, false, false, &checks, &mut missing, start);
        let back = Stat::Unknown;
        infer_missing(
            true,
            false,
            false,
            &[(id.clone(), &back)],
            &mut missing,
            start,
        );
        assert!(infer_missing(true, false, false, &checks, &mut missing, later).is_empty());

        // An unreadable ancestor is unknown, never missing.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = tempfile::tempdir().unwrap();
            let locked = dir.path().join("Locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::write(locked.join("a.txt"), b"a").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let stat = stat_under(dir.path(), &["Locked".into(), "a.txt".into()]);
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
            if !matches!(stat, Stat::Present(_)) {
                assert!(matches!(stat, Stat::Unknown), "{stat:?}");
                let checks = [(id.clone(), &stat)];
                let mut missing = HashMap::new();
                for at in [start, later] {
                    assert!(
                        infer_missing(true, false, false, &checks, &mut missing, at).is_empty()
                    );
                }
            }
        }
    }
}
