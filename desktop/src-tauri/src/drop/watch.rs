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
//!    only by the conservative rule in [`infer_missing`], then held back by
//!    the mass-removal [`brake`] when many files vanish at once).
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
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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
/// The mass-removal brake counts inferred deletions over this window.
pub const BRAKE_WINDOW: Duration = Duration::from_secs(600);
/// Fewer deletions than this in the window are never held.
pub const BRAKE_FLOOR: usize = 10;
/// This many deletions in the window are held whatever the folder's size.
pub const BRAKE_ANY: usize = 50;

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

/// What the mass-removal brake does with one pass's inferred deletions.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Braked {
    /// Removed now, as before the brake.
    pub release: Vec<String>,
    /// Held back until the owner chooses.
    pub hold: Vec<String>,
}

/// The mass-removal brake.  `inferred` is what [`infer_missing`] returned;
/// `moved` are those whose content is still in the folder (a move or a
/// rename loses nothing, so it is released and not counted); `holding` is
/// whether any row is held now; `pending` counts linked files missing now
/// that are not inferred yet (missed once, still settling) and not moved;
/// `linked` counts the linked files this pass looked at; `recent` holds when
/// each deletion released in the last [`BRAKE_WINDOW`] was inferred.
///
/// While a hold is in place every deletion that would lose content joins
/// it.  Otherwise they are held when, with the ones released in the window
/// and the ones still settling, they reach [`BRAKE_ANY`], or reach
/// [`BRAKE_FLOOR`] and are at least half the files the folder held over the
/// window.  Counting the ones still settling matters: each file is inferred
/// [`SETTLE`] after its own first miss, so a deletion that spans several
/// scans (Finder trashing many files) arrives over several passes, and its
/// first part must not slip through on its own.  The rest are held when
/// their turn comes, as the hold is then in place.
pub(crate) fn brake(
    inferred: Vec<String>,
    moved: &HashSet<String>,
    holding: bool,
    pending: usize,
    linked: usize,
    recent: &mut VecDeque<Instant>,
    now: Instant,
) -> Braked {
    while recent
        .front()
        .is_some_and(|at| now.saturating_duration_since(*at) >= BRAKE_WINDOW)
    {
        recent.pop_front();
    }
    let (release, losing): (Vec<String>, Vec<String>) =
        inferred.into_iter().partition(|id| moved.contains(id));
    let mut out = Braked {
        release,
        hold: Vec::new(),
    };
    if losing.is_empty() {
        return out;
    }
    let total = recent.len() + losing.len() + pending;
    let base = linked + recent.len();
    if holding || total >= BRAKE_ANY || (total >= BRAKE_FLOOR && total * 2 >= base) {
        out.hold = losing;
    } else {
        recent.extend(std::iter::repeat_n(now, losing.len()));
        out.release.extend(losing);
    }
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
        let held = self.index.held().unwrap_or_default();
        // Holds that end this pass, and held rows whose file is still gone.
        let mut ended: HashSet<String> = HashSet::new();
        let mut held_missing: Vec<&FileRecord> = Vec::new();
        let mut known = HashSet::new();
        let mut checks: Vec<(String, Stat)> = Vec::new();
        let mut edited = Vec::new();
        let walked: HashSet<&Path> = report
            .files
            .iter()
            .chain(&report.too_deep)
            .map(|(path, _)| path.as_path())
            .collect();
        for row in &rows {
            let Some(link) = row.watch_path.as_deref() else {
                continue;
            };
            let mut path = PathBuf::from(link);
            // Under a folder the walk could not read: never counted missing.
            let stat = if report.unreadable.iter().any(|dir| path.starts_with(dir)) {
                Stat::Unknown
            } else {
                folder::stat_path(&root, &path)
            };
            // A file system that ignores case (or Unicode form) still finds
            // a file renamed only in spelling at its old path, while the walk
            // lists it under the new one.  The link follows the spelling on
            // disk, or the file would be taken in again as a second entry,
            // and that entry's removal elsewhere would trash this one.
            if matches!(stat, Stat::Present(_))
                && !walked.contains(path.as_path())
                && let Some(actual) =
                    folder::relative(&root, &path).and_then(|rel| folder::actual_path(&root, &rel))
                && actual != path
            {
                let _ = self.index.set_link(
                    &row.id,
                    Some((
                        actual.to_string_lossy().into_owned(),
                        row.watch_size.unwrap_or(u64::MAX),
                        row.watch_mtime.unwrap_or(0),
                    )),
                );
                path = actual;
            }
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
            if held.contains(&row.id) {
                if !matches!(stat, Stat::Present(_)) {
                    // Held: never inferred again, never an edit.
                    state.edits.remove(&row.id);
                    if matches!(stat, Stat::Missing) {
                        held_missing.push(row);
                    }
                    continue;
                }
                // Back at its place: its hold ends.  Changed, it is an edit
                // as ever, which replaces the held version once kept.
                let _ = self.index.release_hold(&row.id);
                ended.insert(row.id.clone());
                self.emit_row(&row.id);
                changed = true;
            }
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
        let inferred = infer_missing(true, false, importing, &refs, &mut state.missing, now);
        // Content still in the folder: a linked file there as last seen with
        // the same plaintext, or a file not taken in yet with the same size
        // and modification time (a rename keeps both).
        let by_id: HashMap<&str, &FileRecord> = rows.iter().map(|r| (r.id.as_str(), r)).collect();
        let present_plain: HashSet<&str> = checks
            .iter()
            .filter_map(|(id, stat)| {
                let Stat::Present(meta) = stat else {
                    return None;
                };
                let row = by_id.get(id.as_str())?;
                (folder::matches(meta, row.watch_size, row.watch_mtime)
                    && super::parse_sha256(&row.plain_sha256).is_some())
                .then_some(row.plain_sha256.as_str())
            })
            .collect();
        let unknown_stamps: HashSet<(u64, i64)> = report
            .files
            .iter()
            .filter(|(path, _)| !known.contains(path))
            .map(|(_, meta)| (meta.len(), mtime_of(meta)))
            .collect();
        let still_here = |row: &FileRecord| {
            present_plain.contains(row.plain_sha256.as_str())
                || matches!((row.watch_size, row.watch_mtime),
                    (Some(size), Some(mtime)) if unknown_stamps.contains(&(size, mtime)))
        };
        let moved: HashSet<String> = inferred
            .iter()
            .filter(|id| by_id.get(id.as_str()).is_some_and(|r| still_here(r)))
            .cloned()
            .collect();
        // A held file whose content turned up elsewhere was moved after all.
        let moved_held: Vec<String> = held_missing
            .iter()
            .filter(|r| still_here(r))
            .map(|r| r.id.clone())
            .collect();
        ended.extend(moved_held.iter().cloned());
        let holding = held.iter().any(|id| !ended.contains(id));
        // Missed once and still settling, and not a move: the rest of a
        // deletion that spans several scans.
        let pending = state
            .missing
            .keys()
            .filter(|id| !inferred.contains(*id))
            .filter(|id| by_id.get(id.as_str()).is_some_and(|r| !still_here(r)))
            .count();
        let braked = match self.removal_window.lock() {
            Ok(mut recent) => brake(
                inferred,
                &moved,
                holding,
                pending,
                checks.len(),
                &mut recent,
                now,
            ),
            // Never remove without the brake's say.
            Err(_) => Braked::default(),
        };
        if !braked.hold.is_empty() && self.index.hold(&braked.hold, seconds).is_ok() {
            for id in &braked.hold {
                self.emit_row(id);
            }
            changed = true;
        }
        for id in moved_held.into_iter().chain(braked.release) {
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
        // Nor is a row whose deletion from the folder is held back.
        let held = self.index.held().unwrap_or_default();
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
                || held.contains(&row.id)
                || state.retry.contains_key(&row.id)
            {
                continue;
            }
            let rel = components(target);
            match folder::stat_under(root, &rel) {
                Stat::Missing => {
                    // A held row still linked to this empty place (its edit
                    // from another computer is placed here) lets go of it,
                    // so the placed file is never taken for its edit.
                    let key = fold(target);
                    for other in rows.iter().filter(|r| {
                        r.id != row.id
                            && held.contains(&r.id)
                            && r.watch_path
                                .as_deref()
                                .and_then(|p| folder::relative_nfc(root, Path::new(p)))
                                .is_some_and(|p| fold(&p) == key)
                    }) {
                        let _ = self.index.set_link(&other.id, None);
                    }
                }
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

    fn ids(n: usize, tag: &str) -> Vec<String> {
        (0..n).map(|i| format!("{tag}{i}")).collect()
    }

    #[test]
    fn the_brake_holds_only_mass_removals() {
        let start = Instant::now();
        let none = HashSet::new();
        // A handful never trips it, even all of a small folder.
        let mut recent = VecDeque::new();
        let out = brake(ids(9, "a"), &none, false, 0, 9, &mut recent, start);
        assert_eq!((out.release.len(), out.hold.len()), (9, 0));
        assert_eq!(recent.len(), 9, "released deletions are counted");
        // Ten that are half the folder are held, and not counted as gone.
        let mut recent = VecDeque::new();
        let out = brake(ids(10, "b"), &none, false, 0, 20, &mut recent, start);
        assert_eq!((out.release.len(), out.hold.len()), (0, 10));
        assert!(recent.is_empty());
        // Ten of 21 (under half) is a tidy-up and flows.
        let out = brake(
            ids(10, "c"),
            &none,
            false,
            0,
            21,
            &mut VecDeque::new(),
            start,
        );
        assert_eq!((out.release.len(), out.hold.len()), (10, 0));
        // 49 of 1,000 flow; 50 are held whatever the folder's size.
        let out = brake(
            ids(49, "d"),
            &none,
            false,
            0,
            1_000,
            &mut VecDeque::new(),
            start,
        );
        assert_eq!((out.release.len(), out.hold.len()), (49, 0));
        let out = brake(
            ids(50, "e"),
            &none,
            false,
            0,
            1_000,
            &mut VecDeque::new(),
            start,
        );
        assert_eq!((out.release.len(), out.hold.len()), (0, 50));

        // Bursts add up within the window: 8 of 20, then 8 of what is left
        // five minutes later, is 16 of 20.
        let mut recent = VecDeque::new();
        let out = brake(ids(8, "f"), &none, false, 0, 20, &mut recent, start);
        assert_eq!(out.release.len(), 8);
        let later = start + BRAKE_WINDOW / 2;
        let out = brake(ids(8, "g"), &none, false, 0, 12, &mut recent, later);
        assert_eq!((out.release.len(), out.hold.len()), (0, 8));
        // Outside the window they do not.
        let mut recent = VecDeque::new();
        brake(ids(8, "h"), &none, false, 0, 20, &mut recent, start);
        let out = brake(
            ids(8, "i"),
            &none,
            false,
            0,
            12,
            &mut recent,
            start + BRAKE_WINDOW,
        );
        assert_eq!((out.release.len(), out.hold.len()), (8, 0));
        assert_eq!(recent.len(), 8, "the earlier burst left the window");

        // Moves lose nothing: released, and not counted.
        let moved: HashSet<String> = ids(60, "m").into_iter().collect();
        let mut recent = VecDeque::new();
        let out = brake(ids(60, "m"), &moved, false, 0, 100, &mut recent, start);
        assert_eq!((out.release.len(), out.hold.len()), (60, 0));
        assert!(recent.is_empty());
        let mut inferred = ids(60, "m");
        inferred.extend(ids(5, "n"));
        let out = brake(inferred, &moved, false, 0, 100, &mut recent, start);
        assert_eq!((out.release.len(), out.hold.len()), (65, 0));
        assert_eq!(recent.len(), 5);

        // While a hold is in place, even one deletion joins it; a move still
        // flows.
        let mut inferred = ids(1, "o");
        inferred.extend(ids(1, "m"));
        let out = brake(
            inferred,
            &moved,
            true,
            0,
            1_000,
            &mut VecDeque::new(),
            start,
        );
        assert_eq!(out.release, vec!["m0".to_string()]);
        assert_eq!(out.hold, vec!["o0".to_string()]);
        // A deletion over several scans counts as one: 4 inferred now with 6
        // more still settling are 10 of 12, so the first 4 are held.
        let out = brake(
            ids(4, "p"),
            &none,
            false,
            6,
            12,
            &mut VecDeque::new(),
            start,
        );
        assert_eq!((out.release.len(), out.hold.len()), (0, 4));
        let out = brake(
            ids(4, "q"),
            &none,
            false,
            5,
            12,
            &mut VecDeque::new(),
            start,
        );
        assert_eq!(
            (out.release.len(), out.hold.len()),
            (4, 0),
            "9 is a handful"
        );
        // Nothing inferred: nothing to do, whatever is still settling.
        assert_eq!(
            brake(Vec::new(), &none, true, 0, 10, &mut VecDeque::new(), start),
            Braked::default()
        );
        assert_eq!(
            brake(
                Vec::new(),
                &none,
                false,
                100,
                100,
                &mut VecDeque::new(),
                start
            ),
            Braked::default()
        );
    }

    // ------------------------------------------- the brake on a real folder

    use crate::drop::engine::{EngineConfig, Host, LocalNode, ONLINE_BLOB_LIMIT};
    use crate::drop::keychain::{MemoryStore, SecretStore};
    use crate::drop::status::StatusLine;
    use crate::drop::types::*;

    /// A host with no nodes: envelopes stay in the outbox, which is where
    /// placement reads them from.
    struct NoNodes;

    impl Host for NoNodes {
        fn emit_file(&self, _: &FileRow) {}
        fn emit_removed(&self, _: &str) {}
        fn emit_status(&self, _: &DropStatus, _: &StatusLine) {}
        fn emit_share(&self, _: &ShareState) {}
        fn local_node(&self) -> LocalNode {
            LocalNode {
                state: "ok",
                endpoint: None,
            }
        }
        fn trust_changed(&self) {}
        fn node_settings_exist(&self) -> bool {
            true
        }
        fn ensure_node_settings(&self) -> Result<(), String> {
            Ok(())
        }
        fn pick_save_path(&self, _: &str) -> Option<PathBuf> {
            None
        }
        fn pick_files(&self) -> Vec<PathBuf> {
            Vec::new()
        }
        fn open_folder(&self, _: &Path) {}
        fn trash(&self, _: &Path) -> std::io::Result<()> {
            Err(std::io::Error::other("no Trash in tests"))
        }
        fn open_path(&self, _: &Path) {}
        fn reveal_path(&self, _: &Path) {}
    }

    /// An engine on `dir` (workers not started), sharing `store` as the OS
    /// keychain would be shared across restarts.
    fn engine_at(dir: &Path, store: &Arc<MemoryStore>) -> Arc<Engine> {
        let store = store.clone();
        Engine::new(
            EngineConfig {
                data_dir: dir.join("drop"),
                temp_dir: dir.join("drop-temp"),
                watch_dir: dir.join("Wildbloom"),
                watch_display: "~/Wildbloom".into(),
                get_base: "http://127.0.0.1:5472/get/".into(),
                relay_base: None,
                allow_loopback_http: true,
                signer_timeout: Duration::from_secs(1),
                computer_name: "Desk".into(),
                watch_interval: Duration::from_secs(60),
                online_blob_limit: ONLINE_BLOB_LIMIT,
                pull_interval: Duration::from_secs(60),
            },
            Arc::new(NoNodes),
            Box::new(move || Ok(store.clone() as Arc<dyn SecretStore>)),
            tokio::runtime::Handle::current(),
        )
        .unwrap()
    }

    /// As if `SETTLE` had passed since every first miss and first sighting.
    fn age(state: &mut PassState) {
        let past = Instant::now().checked_sub(SETTLE).unwrap();
        for at in state.missing.values_mut() {
            *at = past;
        }
        for seen in state
            .candidates
            .values_mut()
            .chain(state.edits.values_mut())
        {
            seen.since = past;
        }
    }

    /// Two passes `SETTLE` apart.
    async fn settle(engine: &Arc<Engine>, state: &mut PassState) {
        engine.folder_pass(state).await;
        age(state);
        engine.folder_pass(state).await;
    }

    /// Waits for every encryption, then marks pending rows kept, as the
    /// local node would (their envelopes stay in the outbox).
    async fn kept(engine: &Arc<Engine>) {
        for _ in 0..800 {
            let rows = engine.index.files().unwrap();
            if rows.iter().all(|r| r.local != local::ENCRYPTING) {
                for row in rows.iter().filter(|r| r.local == local::PENDING) {
                    engine.index.set_local(&row.id, local::OK).unwrap();
                }
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("encryption did not finish");
    }

    fn bytes(seed: u8) -> Vec<u8> {
        (0..2_000u32)
            .map(|i| (i as u8).wrapping_mul(seed) ^ seed)
            .collect()
    }

    fn row_at(engine: &Engine, rel: &str) -> Option<String> {
        let root = engine.cfg.watch_dir.clone();
        engine.index.files().unwrap().into_iter().find_map(|f| {
            let link = f.watch_path.as_deref()?;
            (folder::relative_nfc(&root, Path::new(link)).as_deref() == Some(rel)).then_some(f.id)
        })
    }

    fn states(engine: &Engine, state: &str) -> usize {
        engine.rows().iter().filter(|r| r.state == state).count()
    }

    #[tokio::test]
    async fn a_mass_deletion_is_held_until_the_owner_chooses() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::default());
        let mut engine = engine_at(dir.path(), &store);
        engine.set_online_node(None).await.unwrap();
        engine.confirm_recovery_saved().unwrap();
        engine.set_watch_folder(true).await.unwrap();
        let root = dir.path().join("Wildbloom");
        let mut state = PassState::default();
        let names: Vec<String> = (0..12).map(|i| format!("file-{i:02}.txt")).collect();
        std::fs::create_dir_all(root.join("Batch")).unwrap();
        for (i, name) in names.iter().enumerate() {
            std::fs::write(root.join("Batch").join(name), bytes(i as u8 + 1)).unwrap();
        }
        settle(&engine, &mut state).await;
        kept(&engine).await;
        assert_eq!(engine.index.files().unwrap().len(), 12);

        // A folder renamed is a move: nothing is held.
        std::fs::rename(root.join("Batch"), root.join("Moved")).unwrap();
        settle(&engine, &mut state).await;
        kept(&engine).await;
        assert!(
            engine.index.held().unwrap().is_empty(),
            "a move is not held"
        );
        assert_eq!(engine.index.tombstones().unwrap().len(), 12);
        let at = |name: &str| row_at(&engine, &format!("Moved/{name}"));
        assert!(names.iter().all(|n| at(n).is_some()), "taken in again");

        // Ten of twelve deleted at once: held, nothing removed anywhere.
        let gone: Vec<String> = names[..10].to_vec();
        let gone_ids: Vec<String> = gone.iter().map(|n| at(n).unwrap()).collect();
        let sha = |id: &String| engine.index.file(id).unwrap().unwrap().sha256.unwrap();
        let gone_shas: Vec<String> = gone_ids.iter().map(sha).collect();
        let queued_for = |engine: &Engine, shas: &[String]| {
            engine
                .index
                .pending_deletes()
                .unwrap()
                .iter()
                .filter(|d| shas.contains(&d.sha256))
                .count()
        };
        // Deleted over two scans: the first four are inferred while six are
        // still settling, and are held rather than slipping through alone.
        for name in &gone[..4] {
            std::fs::remove_file(root.join("Moved").join(name)).unwrap();
        }
        engine.folder_pass(&mut state).await;
        age(&mut state);
        for name in &gone[4..] {
            std::fs::remove_file(root.join("Moved").join(name)).unwrap();
        }
        engine.folder_pass(&mut state).await;
        assert_eq!(
            engine.index.held().unwrap().len(),
            4,
            "the first part is held"
        );
        assert_eq!(engine.index.tombstones().unwrap().len(), 12);
        age(&mut state);
        engine.folder_pass(&mut state).await;
        let held = engine.index.held().unwrap();
        assert_eq!(held, gone_ids.iter().cloned().collect());
        assert_eq!(states(&engine, "held"), 10);
        assert_eq!(engine.index.tombstones().unwrap().len(), 12, "no tombstone");
        assert_eq!(queued_for(&engine, &gone_shas), 0, "no copy deleted");
        let row = engine
            .rows()
            .into_iter()
            .find(|r| r.id == gone_ids[0])
            .unwrap();
        assert!(!row.in_watch_folder);
        assert_eq!(row.folder.as_deref(), Some("Moved"));
        assert_eq!(
            engine.status_line().text,
            "10 files were deleted from your Wildbloom folder. They're kept until you choose."
        );
        // More passes change nothing.
        settle(&engine, &mut state).await;
        assert_eq!(engine.index.held().unwrap().len(), 10);
        assert_eq!(engine.index.files().unwrap().len(), 12);

        // The hold survives a restart.
        for _ in 0..200 {
            if Arc::strong_count(&engine) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(engine);
        engine = engine_at(dir.path(), &store);
        let mut state = PassState::default();
        settle(&engine, &mut state).await;
        assert_eq!(engine.index.held().unwrap().len(), 10);
        assert_eq!(states(&engine, "held"), 10);
        assert_eq!(engine.index.tombstones().unwrap().len(), 12);

        // A file that comes back leaves the hold.
        std::fs::write(root.join("Moved").join(&gone[0]), bytes(1)).unwrap();
        engine.folder_pass(&mut state).await;
        assert!(!engine.index.is_held(&gone_ids[0]).unwrap());
        assert_eq!(engine.index.held().unwrap().len(), 9);

        // Put back four: written back from their encrypted copies.
        let back: Vec<String> = gone_ids[..5].to_vec();
        let done = engine
            .resolve_held_removals(&[back.clone(), back.clone()].concat(), "put_back")
            .await
            .unwrap();
        assert_eq!(done.count, 4, "the one already back is not held, each once");
        engine.folder_pass(&mut state).await;
        for (i, name) in gone[..5].iter().enumerate() {
            assert_eq!(
                std::fs::read(root.join("Moved").join(name)).unwrap(),
                bytes(i as u8 + 1),
                "{name}"
            );
        }
        assert!(gone_ids[..5].iter().all(|id| {
            engine
                .rows()
                .iter()
                .any(|r| r.id == *id && r.state != "held" && r.in_watch_folder)
        }));
        assert_eq!(engine.index.held().unwrap().len(), 5);

        // An unknown choice, or ids not held, change nothing.
        assert_eq!(
            engine
                .resolve_held_removals(&gone_ids, "maybe")
                .await
                .unwrap_err()
                .code,
            "bad_choice"
        );
        assert_eq!(
            engine
                .resolve_held_removals(&back, "remove")
                .await
                .unwrap()
                .count,
            0
        );
        assert_eq!(engine.index.tombstones().unwrap().len(), 12);

        // Remove them everywhere: the rest are removed as deletions.
        let rest: Vec<String> = gone_ids[5..].to_vec();
        let done = engine.resolve_held_removals(&rest, "remove").await.unwrap();
        assert_eq!(done.count, 5);
        assert!(engine.index.held().unwrap().is_empty());
        assert_eq!(engine.index.tombstones().unwrap().len(), 17);
        assert!(
            rest.iter()
                .all(|id| engine.index.file(id).unwrap().is_none())
        );
        assert_eq!(
            queued_for(&engine, &gone_shas[5..]),
            5,
            "their local copies are deleted when the node is back"
        );
        assert_eq!(queued_for(&engine, &gone_shas[..5]), 0);
        assert!(!engine.status_line().text.contains("deleted from your"));

        // A small deletion afterwards flows at once.
        std::fs::remove_file(root.join("Moved").join(&names[11])).unwrap();
        settle(&engine, &mut state).await;
        assert!(engine.index.held().unwrap().is_empty());
        assert_eq!(engine.index.tombstones().unwrap().len(), 18);

        // Turning the folder off ends a hold with nothing removed.
        let still = row_at(&engine, &format!("Moved/{}", names[10])).unwrap();
        engine.index.hold(std::slice::from_ref(&still), 1).unwrap();
        engine.set_watch_folder(false).await.unwrap();
        assert!(engine.index.held().unwrap().is_empty());
        assert!(engine.index.file(&still).unwrap().is_some());
        assert_eq!(engine.index.tombstones().unwrap().len(), 18);
    }
}
