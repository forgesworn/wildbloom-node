//! The folder layout: where each live entry's plaintext copy goes, derived
//! from the key list alone with one pure, deterministic function, so every
//! computer reaches the same answer whatever its clock or the order things
//! arrived in.
//!
//! 1. An entry is hidden (superseded) when another live entry names it as
//!    `prev` at the same folded path.
//! 2. The rest are placed in `(added, id)` order; the earlier keeps the clean
//!    path.
//! 3. A path whose folded key is taken, sits under a placed file, or is the
//!    folder of a placed file is a conflict.  An equal, non-empty `plain` at
//!    the same key is a duplicate instead and is not placed.  Otherwise the
//!    clashing component (the file name, or the ancestor folder that is a
//!    placed file) takes [`path::conflict_name`], numbered until free.
//! 4. Legacy components that are not valid on Windows are first given
//!    [`path::safe_component`].

use super::path;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// One live row, as the layout sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutEntry {
    pub id: String,
    /// The entry's relative path (`/`-joined).
    pub path: String,
    /// The id this entry replaces, if it is an edit.
    pub prev: Option<String>,
    /// Unix seconds.
    pub added: u64,
    /// The computer that made it; empty if unknown.
    pub from: String,
    /// The plaintext SHA-256, if known.
    pub plain: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    /// Entry id to the path it is placed at.
    pub placed: BTreeMap<String, String>,
    /// Entries replaced by a live edit at the same path.
    pub hidden: BTreeSet<String>,
    /// Entries with the same path and plaintext as an earlier one, mapped to
    /// that earlier (winning) entry.
    pub duplicates: BTreeMap<String, String>,
}

/// Folded keys of the files placed so far and of every folder above them.
#[derive(Default)]
struct Taken<'a> {
    files: HashMap<String, &'a LayoutEntry>,
    folders: HashSet<String>,
}

impl<'a> Taken<'a> {
    /// The folded keys of each proper prefix of `components`.
    fn ancestors(components: &[String]) -> Vec<String> {
        (1..components.len())
            .map(|n| path::fold(&components[..n].join("/")))
            .collect()
    }

    /// The index of the first ancestor component that is a placed file.
    fn blocking_ancestor(&self, components: &[String]) -> Option<usize> {
        Self::ancestors(components)
            .iter()
            .position(|key| self.files.contains_key(key))
    }

    fn free(&self, components: &[String]) -> bool {
        let key = path::fold(&components.join("/"));
        !self.files.contains_key(&key)
            && !self.folders.contains(&key)
            && self.blocking_ancestor(components).is_none()
    }

    fn place(&mut self, components: &[String], entry: &'a LayoutEntry) {
        self.folders.extend(Self::ancestors(components));
        self.files.insert(path::fold(&components.join("/")), entry);
    }
}

/// The layout of `entries` (every live row; order does not matter).
pub fn layout(entries: &[LayoutEntry]) -> Layout {
    let mut out = Layout::default();
    let replaced: HashSet<(&str, String)> = entries
        .iter()
        .filter_map(|e| {
            e.prev
                .as_deref()
                .filter(|prev| *prev != e.id)
                .map(|prev| (prev, path::fold(&e.path)))
        })
        .collect();
    let mut order: Vec<&LayoutEntry> = Vec::with_capacity(entries.len());
    for entry in entries {
        if replaced.contains(&(entry.id.as_str(), path::fold(&entry.path))) {
            out.hidden.insert(entry.id.clone());
        } else {
            order.push(entry);
        }
    }
    order.sort_by(|a, b| (a.added, &a.id).cmp(&(b.added, &b.id)));
    let mut taken = Taken::default();
    for entry in order {
        let components: Vec<String> = entry.path.split('/').map(path::safe_component).collect();
        if taken.free(&components) {
            taken.place(&components, entry);
            out.placed.insert(entry.id.clone(), components.join("/"));
            continue;
        }
        let key = path::fold(&components.join("/"));
        if let Some(winner) = taken.files.get(&key)
            && entry.plain.is_some()
            && winner.plain == entry.plain
        {
            out.duplicates.insert(entry.id.clone(), winner.id.clone());
            continue;
        }
        let at = taken
            .blocking_ancestor(&components)
            .unwrap_or(components.len() - 1);
        for n in 1u32.. {
            let mut renamed = components.clone();
            renamed[at] = path::conflict_name(&components[at], &entry.from, entry.added, n);
            if taken.free(&renamed) {
                taken.place(&renamed, entry);
                out.placed.insert(entry.id.clone(), renamed.join("/"));
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-18T12:00:00Z.
    const DAY0: u64 = 1_792_324_800;

    fn id(n: u8) -> String {
        format!("{n:02x}").repeat(16)
    }

    fn entry(n: u8, path: &str, added: u64) -> LayoutEntry {
        LayoutEntry {
            id: id(n),
            path: path.into(),
            prev: None,
            added,
            from: "Laptop".into(),
            plain: Some([n; 32]),
        }
    }

    fn placed(layout: &Layout, n: u8) -> Option<&str> {
        layout.placed.get(&id(n)).map(String::as_str)
    }

    #[test]
    fn a_single_entry_keeps_its_path() {
        let out = layout(&[entry(1, "Docs/report.pdf", DAY0)]);
        assert_eq!(placed(&out, 1), Some("Docs/report.pdf"));
        assert!(out.hidden.is_empty() && out.duplicates.is_empty());
        assert_eq!(layout(&[]), Layout::default());
    }

    #[test]
    fn two_edits_of_one_version_conflict_by_added_then_id() {
        let base = entry(1, "Docs/report.pdf", DAY0);
        let mut first = entry(2, "Docs/report.pdf", DAY0 + 60);
        first.prev = Some(id(1));
        first.from = "Desk".into();
        let mut second = entry(3, "Docs/report.pdf", DAY0 + 60);
        second.prev = Some(id(1));
        second.from = "Laptop".into();
        for entries in [
            vec![base.clone(), first.clone(), second.clone()],
            vec![second.clone(), base.clone(), first.clone()],
        ] {
            let out = layout(&entries);
            assert!(out.hidden.contains(&id(1)));
            // Same `added`: the lower id wins.
            assert_eq!(placed(&out, 2), Some("Docs/report.pdf"));
            assert_eq!(
                placed(&out, 3),
                Some("Docs/report (conflict from Laptop 2026-10-18).pdf")
            );
        }
        // An earlier `added` wins whatever the id.
        second.added = DAY0 + 30;
        let out = layout(&[base, first, second]);
        assert_eq!(placed(&out, 3), Some("Docs/report.pdf"));
        assert_eq!(
            placed(&out, 2),
            Some("Docs/report (conflict from Desk 2026-10-18).pdf")
        );
    }

    #[test]
    fn a_superseded_entry_is_hidden() {
        let old = entry(1, "a.txt", DAY0);
        let mut new = entry(2, "a.txt", DAY0 + 5);
        new.prev = Some(id(1));
        let out = layout(&[old.clone(), new.clone()]);
        assert_eq!(out.hidden, BTreeSet::from([id(1)]));
        assert_eq!(placed(&out, 2), Some("a.txt"));
        assert_eq!(placed(&out, 1), None);
        // A `prev` at another path does not hide it (a copy, not an edit).
        new.path = "b.txt".into();
        let out = layout(&[old, new]);
        assert!(out.hidden.is_empty());
        assert_eq!(placed(&out, 1), Some("a.txt"));
        assert_eq!(placed(&out, 2), Some("b.txt"));
    }

    #[test]
    fn a_case_clash_is_a_conflict() {
        let out = layout(&[
            entry(2, "report.pdf", DAY0 + 1),
            entry(1, "Report.pdf", DAY0),
        ]);
        assert_eq!(placed(&out, 1), Some("Report.pdf"));
        assert_eq!(
            placed(&out, 2),
            Some("report (conflict from Laptop 2026-10-18).pdf")
        );
    }

    #[test]
    fn nfd_and_nfc_share_one_key() {
        let out = layout(&[
            entry(1, "\u{e9}t\u{e9}.jpg", DAY0),
            entry(2, "e\u{301}te\u{301}.jpg", DAY0 + 1),
        ]);
        assert_eq!(placed(&out, 1), Some("\u{e9}t\u{e9}.jpg"));
        assert!(placed(&out, 2).unwrap().contains("(conflict from Laptop"));
    }

    #[test]
    fn a_taken_conflict_name_is_numbered() {
        let out = layout(&[
            entry(1, "a.txt", DAY0),
            entry(2, "a (conflict from Laptop 2026-10-18).txt", DAY0 + 1),
            entry(3, "a.txt", DAY0 + 2),
        ]);
        assert_eq!(placed(&out, 1), Some("a.txt"));
        assert_eq!(
            placed(&out, 2),
            Some("a (conflict from Laptop 2026-10-18).txt")
        );
        assert_eq!(
            placed(&out, 3),
            Some("a (conflict from Laptop 2026-10-18 2).txt")
        );
    }

    #[test]
    fn a_file_and_a_folder_clash() {
        // The file came first: the folder component of the later entry is renamed.
        let out = layout(&[entry(1, "Notes", DAY0), entry(2, "notes/a.txt", DAY0 + 1)]);
        assert_eq!(placed(&out, 1), Some("Notes"));
        assert_eq!(
            placed(&out, 2),
            Some("notes (conflict from Laptop 2026-10-18)/a.txt")
        );
        // The folder came first: the later file is renamed.
        let out = layout(&[entry(1, "notes/a.txt", DAY0), entry(2, "Notes", DAY0 + 1)]);
        assert_eq!(placed(&out, 1), Some("notes/a.txt"));
        assert_eq!(
            placed(&out, 2),
            Some("Notes (conflict from Laptop 2026-10-18)")
        );
    }

    #[test]
    fn removing_the_winner_promotes_the_loser() {
        let winner = entry(1, "a.txt", DAY0);
        let loser = entry(2, "a.txt", DAY0 + 1);
        let out = layout(&[winner, loser.clone()]);
        assert_ne!(placed(&out, 2), Some("a.txt"));
        let out = layout(&[loser]);
        assert_eq!(placed(&out, 2), Some("a.txt"));
    }

    #[test]
    fn equal_plaintext_at_one_path_is_a_duplicate() {
        let mut first = entry(1, "Shared/same.txt", DAY0);
        let mut second = entry(2, "shared/Same.txt", DAY0 + 1);
        second.plain = first.plain;
        let out = layout(&[second.clone(), first.clone()]);
        assert_eq!(placed(&out, 1), Some("Shared/same.txt"));
        assert_eq!(placed(&out, 2), None);
        assert_eq!(out.duplicates, BTreeMap::from([(id(2), id(1))]));
        // Unknown plaintext is never a duplicate.
        first.plain = None;
        second.plain = None;
        let out = layout(&[first, second]);
        assert!(out.duplicates.is_empty());
        assert!(placed(&out, 2).unwrap().contains("conflict"));
    }

    #[test]
    fn a_long_stem_is_truncated() {
        let name = format!("{}.pdf", "s".repeat(176));
        let out = layout(&[entry(1, &name, DAY0), entry(2, &name, DAY0 + 1)]);
        let loser = placed(&out, 2).unwrap();
        assert_eq!(loser.encode_utf16().count(), 180);
        assert!(loser.ends_with(" (conflict from Laptop 2026-10-18).pdf"));
        assert!(path::valid_path(loser));
    }

    #[test]
    fn a_legacy_reserved_name_gets_a_safe_component() {
        let out = layout(&[entry(1, "CON.txt", DAY0), entry(2, "file.", DAY0)]);
        assert_eq!(placed(&out, 1), Some("CON_.txt"));
        assert_eq!(placed(&out, 2), Some("file._"));
    }
}
