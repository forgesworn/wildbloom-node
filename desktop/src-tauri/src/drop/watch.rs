//! The Wildbloom folder mirror: `~/Wildbloom` holds a readable copy of every
//! kept file, in the same subfolders, on every computer where it is on.
//!
//! The folder is scanned on a short interval (not with a file-system
//! notification crate, whose licence is outside this project's MIT/Apache
//! rule), which also gives the settle rule directly: a file counts once its
//! size and modification time have been unchanged for 3 seconds and it opens
//! for reading.  Each pass, under the folder lock:
//!
//! 1. Checks the folder is there (root and marker) and walks it.  An
//!    unavailable folder or a scan that hit the item limit changes nothing.
//! 2. Looks at every linked file: unchanged, changed (an edit becomes a new
//!    entry naming the old one as `prev`), or missing (a deletion, inferred
//!    only by the conservative rule in [`infer_missing`]).
//! 3. Takes in new files: linked to an entry already placed there when the
//!    content is the same, a "Not kept" row when the name, path or size can't
//!    be kept, and otherwise a new entry at its path.
//! 4. Lays out every row ([`super::layout`]), settles duplicates, renames
//!    linked files whose place changed (conflicts) and places the rest.
//!
//! Wildbloom never deletes a plaintext file: anything it replaces or removes
//! goes to the Trash.  A file changed here and not yet taken in is never
//! replaced or moved to the Trash.  (This replaces design question Q15's
//! "the earlier copy stays".)

use super::engine::{Engine, RemoveHow, kv};
use super::folder::{self, Stat};
use super::index::{FileRecord, local};
use super::layout::{self, Layout, LayoutEntry};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long size and mtime must hold still.
pub const SETTLE: Duration = Duration::from_secs(3);
/// Never walk deeper than this.
const MAX_DEPTH: usize = 16;
/// Deletions wait while a folder import made this recently still encrypts,
/// so a move publishes its add before its delete.
const IMPORT_WAIT_SECONDS: u64 = 600;
/// A placement that could not fetch its copy waits this long.
const PLACE_RETRY: Duration = Duration::from_secs(30);
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

/// What the folder pass remembers between passes.
#[derive(Default)]
pub(crate) struct PassState {
    /// Unknown files settling, by path.
    candidates: HashMap<PathBuf, Seen>,
    /// Linked files that changed, settling, by row id.
    edits: HashMap<String, Seen>,
    /// First misses of linked files, by row id.
    missing: HashMap<String, Instant>,
    /// Placements not to try again before this, by row id.
    retry: HashMap<String, Instant>,
}

/// Whether a file with this size and mtime has held still for [`SETTLE`].
fn settled<K: std::hash::Hash + Eq>(
    map: &mut HashMap<K, Seen>,
    key: K,
    meta: &std::fs::Metadata,
    now: Instant,
) -> bool {
    let (size, mtime) = (meta.len(), mtime_of(meta));
    match map.get(&key) {
        Some(seen) if seen.size == size && seen.mtime == mtime => {
            now.duration_since(seen.since) >= SETTLE
        }
        _ => {
            map.insert(
                key,
                Seen {
                    size,
                    mtime,
                    since: now,
                },
            );
            false
        }
    }
}

/// `rel` split into components.
fn components(rel: &str) -> Vec<String> {
    rel.split('/').map(str::to_owned).collect()
}

/// Why a file at `rel` (NFC) can't be kept, if it can't.
pub(crate) fn not_kept_reason(
    rel: &str,
    deep: bool,
    size: u64,
    limit: u64,
) -> Option<&'static str> {
    use super::path;
    if deep || rel.split('/').count() > path::MAX_COMPONENTS {
        Some("too_deep")
    } else if !path::valid_path(rel) {
        if rel.encode_utf16().count() > path::MAX_PATH_UTF16
            && rel.split('/').all(path::valid_component)
        {
            Some("too_long")
        } else {
            Some("name")
        }
    } else if size > limit {
        Some("too_big")
    } else {
        None
    }
}

/// The layout of every row that holds a place in the folder: all but rows
/// that are not kept.
pub(crate) fn layout_of(rows: &[FileRecord]) -> Layout {
    let entries: Vec<LayoutEntry> = rows
        .iter()
        .filter(|r| r.local != local::NOT_KEPT)
        .map(|r| LayoutEntry {
            id: r.id.clone(),
            path: super::keysync::entry_path(r),
            prev: r.prev.clone(),
            added: r.added,
            from: r.origin.clone(),
            plain: super::parse_sha256(&r.entry_plain),
        })
        .collect();
    layout::layout(&entries)
}

impl Engine {
    pub(crate) async fn watch_loop(self: Arc<Self>) {
        let mut state = PassState::default();
        loop {
            let enabled =
                self.mirror_on() && self.index.get_bool(kv::FIRST_RUN_DONE).unwrap_or(false);
            if !enabled {
                state = PassState::default();
                self.watch_wake.notified().await;
                continue;
            }
            self.folder_pass(&mut state).await;
            tokio::select! {
                _ = self.watch_wake.notified() => {}
                _ = tokio::time::sleep(self.cfg.watch_interval) => {}
            }
        }
    }

    /// One pass over the folder (see the module documentation).
    pub(crate) async fn folder_pass(self: &Arc<Self>, state: &mut PassState) {
        let _folder = self.folder_lock.lock().await;
        if !self.mirror_on() {
            return;
        }
        let root = self.cfg.watch_dir.clone();
        if !self.folder_available() {
            state.missing.clear();
            state.edits.clear();
            self.set_folder_state("unavailable");
            return;
        }
        let walk_root = root.clone();
        let Ok(report) = tokio::task::spawn_blocking(move || walk(&walk_root)).await else {
            return;
        };
        if report.truncated {
            state.missing.clear();
            self.set_folder_state("too_many");
            return;
        }
        // The marker could have gone while the walk ran.
        if !self.folder_available() {
            self.set_folder_state("unavailable");
            return;
        }
        self.set_folder_state("on");
        let now = Instant::now();
        let mut changed = false;
        let mut emptied = BTreeSet::new();

        // Linked files: unchanged, changed or missing.
        let rows = self.index.files().unwrap_or_default();
        let mut known = HashSet::new();
        let mut checks: Vec<(String, Stat)> = Vec::new();
        let mut edited = Vec::new();
        for row in &rows {
            let Some(link) = row.watch_path.as_deref() else {
                continue;
            };
            let path = PathBuf::from(link);
            // Under a folder the walk could not read: never counted missing.
            let stat = if report.unreadable.iter().any(|dir| path.starts_with(dir)) {
                Stat::Unknown
            } else {
                folder::stat_path(&root, &path)
            };
            if row.local == local::NOT_KEPT {
                // Gone or changed: the row goes, and a changed file is looked
                // at again as new.
                let keep = match &stat {
                    Stat::Unknown => true,
                    Stat::Present(meta) => folder::matches(meta, row.watch_size, row.watch_mtime),
                    Stat::Missing => false,
                };
                if keep {
                    known.insert(path);
                } else if self.index.delete_file(&row.id).is_ok() {
                    self.host.emit_removed(&row.id);
                    changed = true;
                }
                continue;
            }
            known.insert(path.clone());
            match &stat {
                Stat::Present(meta) if !folder::matches(meta, row.watch_size, row.watch_mtime) => {
                    if settled(&mut state.edits, row.id.clone(), meta, now)
                        && std::fs::File::open(&path).is_ok()
                    {
                        edited.push((row.clone(), path));
                    }
                }
                _ => {
                    state.edits.remove(&row.id);
                }
            }
            checks.push((row.id.clone(), stat));
        }
        state
            .edits
            .retain(|id, _| checks.iter().any(|(c, _)| c == id));
        let seconds = super::engine::now();
        let importing = rows.iter().any(|r| {
            r.watch_path.is_some()
                && matches!(r.local.as_str(), local::ENCRYPTING | local::PENDING)
                && r.added + IMPORT_WAIT_SECONDS >= seconds
        });
        let refs: Vec<(String, &Stat)> = checks.iter().map(|(id, s)| (id.clone(), s)).collect();
        for id in infer_missing(true, false, importing, &refs, &mut state.missing, now) {
            state.missing.remove(&id);
            if self.remove_row(&id, RemoveHow::FromFolder).await.is_ok() {
                changed = true;
            }
        }
        for (row, path) in edited {
            changed |= self.take_in_edit(&root, &row, &path, state).await;
        }

        // New files, once they hold still.
        let mut arrived = Vec::new();
        let mut present = HashSet::new();
        let found = report
            .files
            .into_iter()
            .map(|(p, m)| (p, m, false))
            .chain(report.too_deep.into_iter().map(|(p, m)| (p, m, true)));
        for (path, meta, deep) in found {
            if known.contains(&path) {
                continue;
            }
            present.insert(path.clone());
            // Empty files stay unkept and silent.
            if meta.len() == 0 {
                state.candidates.remove(&path);
                continue;
            }
            if settled(&mut state.candidates, path.clone(), &meta, now)
                && std::fs::File::open(&path).is_ok()
            {
                arrived.push((path, meta, deep));
            }
        }
        state.candidates.retain(|path, _| present.contains(path));
        if !arrived.is_empty() {
            let rows = self.index.files().unwrap_or_default();
            let layout = layout_of(&rows);
            for (path, meta, deep) in arrived {
                state.candidates.remove(&path);
                changed |= self
                    .take_in_new(&root, &path, &meta, deep, &rows, &layout)
                    .await;
            }
        }

        // Lay out, then settle duplicates, renames and placements.
        let rows = self.index.files().unwrap_or_default();
        let layout = layout_of(&rows);
        changed |= self.settle_duplicates(&rows, &layout).await;
        let rows = self.index.files().unwrap_or_default();
        let layout = layout_of(&rows);
        changed |= self.rename_moved(&root, &rows, &layout, &mut emptied);
        let rows = self.index.files().unwrap_or_default();
        changed |= self.place_missing(&root, &rows, &layout, state).await;
        if !emptied.is_empty() {
            let sweep_root = root.clone();
            let _ = tokio::task::spawn_blocking(move || folder::sweep_empty(&sweep_root, &emptied))
                .await;
        }
        if changed {
            self.emit_status();
        }
    }

    /// A linked file that changed and held still.  The same content only
    /// updates the link; new content is a new entry at the same path that
    /// names the old one as `prev`, and the link moves to it.
    async fn take_in_edit(
        self: &Arc<Self>,
        root: &Path,
        row: &FileRecord,
        path: &Path,
        state: &mut PassState,
    ) -> bool {
        // Still being encrypted: looked at again once it is kept.
        if row.local == local::ENCRYPTING {
            return false;
        }
        let Stat::Present(meta) = folder::stat_path(root, path) else {
            return false;
        };
        let hash_path = path.to_path_buf();
        let Ok(Ok(hash)) =
            tokio::task::spawn_blocking(move || super::engine::sha256_file(&hash_path)).await
        else {
            return false;
        };
        // Changed again while it was read: wait for it to hold still.
        match folder::stat_path(root, path) {
            Stat::Present(now) if now.len() == meta.len() && mtime_of(&now) == mtime_of(&meta) => {}
            _ => return false,
        }
        state.edits.remove(&row.id);
        let link = Some((
            path.to_string_lossy().into_owned(),
            meta.len(),
            mtime_of(&meta),
        ));
        if hash == row.plain_sha256 {
            let _ = self.index.set_link(&row.id, link);
            return false;
        }
        let Some(disk) = folder::relative_nfc(root, path) else {
            return false;
        };
        let name = wildbloom_envelope::sanitise_name(
            &path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        // The edit keeps the entry's path, unless that path is a legacy name
        // the grammar refuses (a key list entry must pass it or equal its
        // name), in which case it takes the file's real path.
        let entry = super::keysync::entry_path(row);
        let rel = if entry == name || super::path::valid_path(&entry) {
            entry
        } else {
            disk.clone()
        };
        if not_kept_reason(&rel, false, meta.len(), self.drop_max_bytes()).is_some()
            || not_kept_reason(&disk, false, meta.len(), self.drop_max_bytes()).is_some()
        {
            // An edit that can't be kept: the old version lets go of the
            // file, which is then looked at as new (a "Not kept" row).
            let _ = self.index.set_link(&row.id, None);
            self.emit_row(&row.id);
            return true;
        }
        if self
            .import_folder_file(path.to_path_buf(), rel, &meta, hash, Some(row.id.clone()))
            .await
            .is_ok()
        {
            let _ = self.index.set_link(&row.id, None);
            self.emit_row(&row.id);
            return true;
        }
        false
    }

    /// A new file in the folder.
    async fn take_in_new(
        self: &Arc<Self>,
        root: &Path,
        path: &Path,
        meta: &std::fs::Metadata,
        deep: bool,
        rows: &[FileRecord],
        layout: &Layout,
    ) -> bool {
        let Some(rel) = folder::relative_nfc(root, path) else {
            return false;
        };
        if let Some(reason) = not_kept_reason(&rel, deep, meta.len(), self.drop_max_bytes()) {
            return self.insert_not_kept(path, &rel, meta, reason).is_ok();
        }
        let hash_path = path.to_path_buf();
        let Ok(Ok(hash)) =
            tokio::task::spawn_blocking(move || super::engine::sha256_file(&hash_path)).await
        else {
            return false;
        };
        match folder::stat_path(root, path) {
            Stat::Present(now) if now.len() == meta.len() && mtime_of(&now) == mtime_of(meta) => {}
            _ => return false,
        }
        // Already placed here by an entry with the same content (the folder
        // was turned on, or used again): link it rather than take it in.
        let key = super::path::fold(&rel);
        let waiting = rows.iter().find(|r| {
            r.watch_path.is_none()
                && r.local != local::NOT_KEPT
                && layout
                    .placed
                    .get(&r.id)
                    .is_some_and(|target| super::path::fold(target) == key)
        });
        if let Some(row) = waiting
            && row.bytes == meta.len()
            && self.same_content(row, &hash).await
        {
            let _ = self.index.set_link(
                &row.id,
                Some((
                    path.to_string_lossy().into_owned(),
                    meta.len(),
                    mtime_of(meta),
                )),
            );
            let _ = self.index.set_plain_sha256(&row.id, &hash);
            self.emit_row(&row.id);
            return true;
        }
        self.import_folder_file(path.to_path_buf(), rel, meta, hash, None)
            .await
            .is_ok()
    }

    /// Whether `row`'s plaintext hashes to `hash`: its known hash, or its
    /// decrypted copy's.
    async fn same_content(self: &Arc<Self>, row: &FileRecord, hash: &str) -> bool {
        if super::parse_sha256(&row.plain_sha256).is_some() {
            return row.plain_sha256 == hash;
        }
        let Ok(plain) = self.decrypt_to_temp(row).await else {
            return false;
        };
        let want = hash.to_owned();
        tokio::task::spawn_blocking(move || {
            super::engine::sha256_file(plain.path()).is_ok_and(|h| h == want)
        })
        .await
        .unwrap_or(false)
    }

    /// A "Not kept" row for a folder file: no key, no envelope, never in the
    /// key list, and never matched as a duplicate.
    fn insert_not_kept(
        &self,
        path: &Path,
        rel: &str,
        meta: &std::fs::Metadata,
        reason: &'static str,
    ) -> Result<(), super::index::IndexError> {
        let Ok(id) = super::FileId::random().map(|id| id.to_string()) else {
            return Ok(());
        };
        let name = wildbloom_envelope::sanitise_name(
            &path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
        self.index.insert_file(&FileRecord {
            id: id.clone(),
            name: if name.is_empty() { "file".into() } else { name },
            media_type: String::new(),
            bytes: meta.len(),
            added: super::engine::now(),
            plain_sha256: format!("not_kept:{id}"),
            sha256: None,
            size: None,
            local: local::NOT_KEPT.into(),
            online: super::index::online::NONE.into(),
            attempts: 0,
            next_attempt: 0,
            watch_path: Some(path.to_string_lossy().into_owned()),
            watch_size: Some(meta.len()),
            watch_mtime: Some(mtime_of(meta)),
            path: rel.to_owned(),
            prev: None,
            origin: String::new(),
            entry_plain: String::new(),
            note: Some(reason.to_owned()),
        })?;
        self.emit_row(&id);
        Ok(())
    }

    /// Entries with the same path and plaintext as an earlier one: the link
    /// moves to the earlier entry and the later one is removed as
    /// superseded.  Every computer that does this writes the same tombstone.
    async fn settle_duplicates(self: &Arc<Self>, rows: &[FileRecord], layout: &Layout) -> bool {
        let mut changed = false;
        for (loser, winner) in &layout.duplicates {
            let (Some(loser), Some(winner)) = (
                rows.iter().find(|r| r.id == *loser),
                rows.iter().find(|r| r.id == *winner),
            ) else {
                continue;
            };
            // Both must be kept (an entry with an envelope) first.
            let ready = |r: &FileRecord| {
                r.sha256.is_some()
                    && !matches!(
                        r.local.as_str(),
                        local::ENCRYPTING | local::UNREADABLE | local::RESTORING
                    )
            };
            if !ready(loser) || !ready(winner) {
                continue;
            }
            if loser.watch_path.is_some() {
                if winner.watch_path.is_some() {
                    continue;
                }
                let link = loser.watch_path.clone().map(|path| {
                    (
                        path,
                        loser.watch_size.unwrap_or(0),
                        loser.watch_mtime.unwrap_or(0),
                    )
                });
                let _ = self.index.set_link(&winner.id, link);
                if super::parse_sha256(&loser.plain_sha256).is_some() {
                    let _ = self.index.set_plain_sha256(&winner.id, &loser.plain_sha256);
                }
                let _ = self.index.set_link(&loser.id, None);
                self.emit_row(&winner.id);
            }
            if self
                .remove_row(&loser.id, RemoveHow::Superseded)
                .await
                .is_ok()
            {
                changed = true;
            }
        }
        changed
    }

    /// Linked files whose place in the layout changed (a conflict, or the
    /// winner removed) are renamed there, never over anything.
    fn rename_moved(
        &self,
        root: &Path,
        rows: &[FileRecord],
        layout: &Layout,
        emptied: &mut BTreeSet<PathBuf>,
    ) -> bool {
        use super::path::fold;
        let mut changed = false;
        for row in rows {
            let (Some(link), Some(target)) =
                (row.watch_path.as_deref(), layout.placed.get(&row.id))
            else {
                continue;
            };
            if row.local == local::NOT_KEPT {
                continue;
            }
            let path = PathBuf::from(link);
            let Some(current) = folder::relative_nfc(root, &path) else {
                continue;
            };
            if fold(&current) == fold(target) {
                continue;
            }
            // Only the file as last seen: a change here is taken in first.
            let Stat::Present(meta) = folder::stat_path(root, &path) else {
                continue;
            };
            if !folder::matches(&meta, row.watch_size, row.watch_mtime) {
                continue;
            }
            let rel = components(target);
            if !matches!(folder::stat_under(root, &rel), Stat::Missing) {
                continue;
            }
            let Ok(parent) = folder::ensure_parent(root, &rel) else {
                continue;
            };
            let to = parent.join(&rel[rel.len() - 1]);
            if folder::move_no_clobber(&path, &to).is_err() {
                continue;
            }
            let actual = folder::actual_path(root, &rel).unwrap_or(to);
            let _ = self.index.set_link(
                &row.id,
                Some((
                    actual.to_string_lossy().into_owned(),
                    meta.len(),
                    mtime_of(&meta),
                )),
            );
            if let Some(parent) = path.parent() {
                emptied.insert(parent.to_path_buf());
            }
            self.emit_row(&row.id);
            changed = true;
        }
        changed
    }

    /// Places every unlinked entry the layout gives a place, from its
    /// encrypted copy.  A replaced version still at that place, unchanged,
    /// goes to the Trash first; a file nothing knows about is never replaced
    /// (it is taken in first, and the layout then treats it as a conflict).
    async fn place_missing(
        self: &Arc<Self>,
        root: &Path,
        rows: &[FileRecord],
        layout: &Layout,
        state: &mut PassState,
    ) -> bool {
        use super::path::fold;
        let now = Instant::now();
        state.retry.retain(|_, at| *at > now);
        // A version another row replaces is not placed again.
        let replaced: HashSet<&str> = rows.iter().filter_map(|r| r.prev.as_deref()).collect();
        let mut changed = false;
        for row in rows {
            let Some(target) = layout.placed.get(&row.id) else {
                continue;
            };
            if row.watch_path.is_some()
                || row.sha256.is_none()
                || !matches!(
                    row.local.as_str(),
                    local::OK | local::MISSING | local::PENDING
                )
                || replaced.contains(row.id.as_str())
                || state.retry.contains_key(&row.id)
            {
                continue;
            }
            let rel = components(target);
            match folder::stat_under(root, &rel) {
                Stat::Missing => {}
                Stat::Present(meta) => {
                    let key = fold(target);
                    let occupant = rows.iter().find(|r| {
                        r.id != row.id
                            && r.local != local::NOT_KEPT
                            && r.watch_path
                                .as_deref()
                                .and_then(|p| folder::relative_nfc(root, Path::new(p)))
                                .is_some_and(|p| fold(&p) == key)
                    });
                    let Some(occupant) = occupant else {
                        continue;
                    };
                    // Only a version with no place of its own (replaced, or
                    // a duplicate), exactly as last seen, gives way.
                    if layout.placed.contains_key(&occupant.id)
                        || !folder::matches(&meta, occupant.watch_size, occupant.watch_mtime)
                    {
                        continue;
                    }
                    if !self.move_to_trash(&rel) {
                        continue;
                    }
                    let _ = self.index.set_link(&occupant.id, None);
                    self.emit_row(&occupant.id);
                    changed = true;
                }
                Stat::Unknown => continue,
            }
            if self.place_row(root, row, rel, state).await {
                changed = true;
            }
        }
        changed
    }

    /// Writes one entry's plaintext at `rel` and links it.
    async fn place_row(
        self: &Arc<Self>,
        root: &Path,
        row: &FileRecord,
        rel: Vec<String>,
        state: &mut PassState,
    ) -> bool {
        let plain = match self.decrypt_to_temp(row).await {
            Ok(plain) => plain,
            Err(error) if error.code == "unreadable" => {
                let _ = self.index.set_local(&row.id, local::UNREADABLE);
                self.emit_row(&row.id);
                return true;
            }
            Err(_) => {
                state
                    .retry
                    .insert(row.id.clone(), Instant::now() + PLACE_RETRY);
                return false;
            }
        };
        let expect = super::parse_sha256(&row.entry_plain);
        let place_root = root.to_path_buf();
        let placed = tokio::task::spawn_blocking(move || {
            let placed = folder::place_file(&place_root, &rel, plain.path(), expect);
            drop(plain);
            placed
        })
        .await;
        match placed {
            Ok(Ok((path, meta, hash))) => {
                let _ = self.index.set_link(
                    &row.id,
                    Some((
                        path.to_string_lossy().into_owned(),
                        meta.len(),
                        mtime_of(&meta),
                    )),
                );
                // The real hash replaces a `restored:` marker, so a window
                // drop of the same file is seen as a duplicate.
                let _ = self.index.set_plain_sha256(&row.id, &hash);
                self.emit_row(&row.id);
                true
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                let _ = self.index.set_local(&row.id, local::UNREADABLE);
                self.emit_row(&row.id);
                true
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            _ => {
                state
                    .retry
                    .insert(row.id.clone(), Instant::now() + PLACE_RETRY);
                false
            }
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
