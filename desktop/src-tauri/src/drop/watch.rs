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
use std::time::{Duration, Instant, UNIX_EPOCH};

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
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos().min(i64::MAX as u128) as i64)
}

/// Regular files under `root` (no symbolic links followed), skipping ignored
/// names and folders.
fn walk(root: &Path) -> Vec<(PathBuf, std::fs::Metadata)> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_ENTRIES {
                return out;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if ignored(name) {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.file_type().is_dir() && depth < MAX_DEPTH {
                stack.push((entry.path(), depth + 1));
            } else if meta.file_type().is_file() {
                out.push((entry.path(), meta));
            }
        }
    }
    out
}

impl Engine {
    pub(crate) async fn watch_loop(self: Arc<Self>) {
        let mut candidates: HashMap<PathBuf, Seen> = HashMap::new();
        loop {
            let enabled = self.index.get_bool(kv::WATCH_ENABLED).unwrap_or(false)
                && self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false);
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
        let found = tokio::task::spawn_blocking(move || walk(&root))
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
            .into_iter()
            .map(|(p, _)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["a.txt", "b.txt"]);
    }
}
