//! Relative paths in key list entries (format 2) and the names the folder
//! layout gives them.
//!
//! A path is 1 to 17 components joined with `/`.  Every component is a fixed
//! point of `wildbloom_envelope::sanitise_name` (so NFC, no controls, none of
//! `< > : " | ? * / \`, no leading `.` or whitespace, no trailing whitespace,
//! at most 180 UTF-16 units), does not end in `.` or a space, and is not a
//! reserved Windows device name.  The whole path is at most 220 UTF-16 units.
//!
//! Clash checks compare [`fold`]ed paths: NFC then lower case, per component,
//! so a macOS NFD name and its NFC form are one key.

use unicode_normalization::UnicodeNormalization;

/// At most 16 folder levels plus the file name, as the folder walk allows.
pub const MAX_COMPONENTS: usize = 17;
/// The whole path's limit, which keeps `C:\Users\<name>\Wildbloom\` plus the
/// path under Windows' 260-character Explorer limit.
pub const MAX_PATH_UTF16: usize = 220;
/// One component's limit, the same as a sanitised name's.
pub const MAX_COMPONENT_UTF16: usize = 180;
/// Shown in a conflict name when the other computer's name is unknown.
pub const UNKNOWN_COMPUTER: &str = "another computer";

fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// The longest prefix of `text` within `max` UTF-16 units, never splitting a
/// surrogate pair.
fn truncate_utf16(text: &str, max: usize) -> &str {
    let mut units = 0;
    for (at, c) in text.char_indices() {
        units += c.len_utf16();
        if units > max {
            return &text[..at];
        }
    }
    text
}

/// `CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9` and `COM`/`LPT`
/// with `¹`, `²` or `³`, compared case-insensitively on the part before the
/// first `.`.
pub fn reserved_device_name(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or("");
    let upper = base.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    ["COM", "LPT"].iter().any(|prefix| {
        upper.strip_prefix(prefix).is_some_and(|rest| {
            let mut chars = rest.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '¹' | '²' | '³'), None)
            )
        })
    })
}

/// Whether one path component is safe to write on every supported system.
pub fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && wildbloom_envelope::sanitise_name(component) == component
        && component != "."
        && component != ".."
        && !component.ends_with('.')
        && !component.ends_with(' ')
        && !reserved_device_name(component)
}

/// Whether `path` passes the format-2 path grammar.  A legacy entry whose
/// path equals its name is accepted separately by the key list.
pub fn valid_path(path: &str) -> bool {
    let count = path.split('/').count();
    (1..=MAX_COMPONENTS).contains(&count)
        && utf16_len(path) <= MAX_PATH_UTF16
        && path.split('/').all(valid_component)
}

/// The clash key: each component in NFC, then lower case.
pub fn fold(path: &str) -> String {
    path.split('/')
        .map(|c| c.nfc().collect::<String>().to_lowercase())
        .collect::<Vec<_>>()
        .join("/")
}

/// A component every system can write, for a legacy name (`path == name`)
/// that is not valid on Windows: `_` goes after a reserved base name
/// (`CON.txt` becomes `CON_.txt`) and after a trailing `.` or space (`file.`
/// becomes `file._`).  Valid components are returned unchanged.  The result
/// depends only on the input, so every computer derives the same name.
pub fn safe_component(component: &str) -> String {
    if valid_component(component) {
        return component.to_owned();
    }
    // Room for the two `_` the rules below may add.
    let mut out =
        wildbloom_envelope::sanitise_name(truncate_utf16(component, MAX_COMPONENT_UTF16 - 2));
    if reserved_device_name(&out) {
        let at = out.find('.').unwrap_or(out.len());
        out.insert(at, '_');
    }
    if out.ends_with('.') || out.ends_with(' ') {
        out.push('_');
    }
    if valid_component(&out) {
        out
    } else {
        "_".to_owned()
    }
}

/// The computer name as a key list entry's `from` carries it: no control
/// character, `"` or `\\`, trimmed, NFC and at most 64 UTF-16 units.  An
/// entry whose `from` breaks those rules makes every list holding it
/// unreadable on every other computer, so the name is cleaned before it is
/// frozen into a row.
pub fn computer_origin(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect::<String>()
        .nfc()
        .collect();
    let mut out = cleaned.trim().to_owned();
    // A cut can leave a sequence NFC recomposes, and NFC can lengthen a few
    // characters, so cut and normalise until both rules hold.
    loop {
        let cut: String = truncate_utf16(&out, super::device::MAX_FROM_UTF16)
            .trim_end()
            .nfc()
            .collect();
        if cut == out {
            return out;
        }
        out = cut;
    }
}

/// `YYYY-MM-DD` in UTC.
fn utc_date(unix: u64) -> String {
    let (year, month, day) = super::status::ymd(unix);
    format!("{year:04}-{month:02}-{day:02}")
}

/// A computer name as it may appear inside a component.
fn computer_label(from: &str) -> String {
    if from.is_empty() {
        return UNKNOWN_COMPUTER.to_owned();
    }
    from.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// The name a conflict loser's `component` takes:
/// `"{stem} (conflict from {from} {YYYY-MM-DD}){ext}"`, with ` {n}` before the
/// `)` for `n >= 2`.  `ext` is the last `.xxx` unless the dot is the first
/// character; `from` is [`UNKNOWN_COMPUTER`] when empty; the date is `added`
/// in UTC.  The stem is cut so the component stays within 180 UTF-16 units.
pub fn conflict_name(component: &str, from: &str, added: u64, n: u32) -> String {
    let number = if n >= 2 {
        format!(" {n}")
    } else {
        String::new()
    };
    let suffix = format!(
        " (conflict from {} {}{number})",
        computer_label(from),
        utc_date(added)
    );
    let (mut stem, mut ext) = match component.rfind('.') {
        Some(at) if at > 0 => (&component[..at], &component[at..]),
        _ => (component, ""),
    };
    // An extension too long to leave room for a stem is kept as stem text.
    if utf16_len(&suffix) + utf16_len(ext) >= MAX_COMPONENT_UTF16 {
        stem = component;
        ext = "";
    }
    let room = MAX_COMPONENT_UTF16.saturating_sub(utf16_len(&suffix) + utf16_len(ext));
    let stem = truncate_utf16(stem, room);
    safe_component(&format!("{stem}{suffix}{ext}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_grammar() {
        let seventeen = vec!["d"; 17].join("/");
        let accepted = [
            "report.pdf",
            "Docs/report.pdf",
            "Fotos/Café/été.jpg",
            "a b/c-d_e (1).txt",
            "COM10.txt",
            "console.log",
            seventeen.as_str(),
        ];
        for path in accepted {
            assert!(valid_path(path), "{path}");
        }
        let too_long = format!("{}/{}", "a".repeat(110), "b".repeat(110));
        let eighteen = vec!["d"; 18].join("/");
        let refused = [
            "",
            "..",
            ".",
            "a/../b",
            "/a",
            "a/",
            "a//b",
            "C:\\x",
            "a\\b",
            "CON.txt",
            "con",
            "Docs/lpt1",
            "COM¹.md",
            "LPT³",
            "aux.tar.gz",
            "file.",
            "file ",
            " file",
            ".hidden",
            "Docs/.git/config",
            "a\u{7}b",
            "a\nb",
            "e\u{301}te.jpg",
            "a<b",
            "a|b",
            "what?",
            eighteen.as_str(),
            too_long.as_str(),
        ];
        for path in refused {
            assert!(!valid_path(path), "{path:?}");
        }
        // Exactly 220 units passes; 221 does not.
        let edge = format!("{}/{}", "a".repeat(110), "b".repeat(109));
        assert_eq!(edge.encode_utf16().count(), 220);
        assert!(valid_path(&edge));
        assert!(!valid_component(&"x".repeat(181)));
        assert!(valid_component(&"x".repeat(180)));
    }

    #[test]
    fn folding_ignores_case_and_normal_form() {
        assert_eq!(fold("Docs/Report.PDF"), "docs/report.pdf");
        assert_eq!(fold("e\u{301}te\u{301}.jpg"), fold("\u{e9}t\u{e9}.jpg"));
        assert_eq!(fold("ÉTÉ/A"), "été/a");
        assert_ne!(fold("a/b"), fold("a_b"));
    }

    #[test]
    fn safe_components_for_legacy_names() {
        assert_eq!(safe_component("report.pdf"), "report.pdf");
        assert_eq!(safe_component("CON.txt"), "CON_.txt");
        assert_eq!(safe_component("nul"), "nul_");
        assert_eq!(safe_component("lpt1.tar.gz"), "lpt1_.tar.gz");
        assert_eq!(safe_component("file."), "file._");
        assert_eq!(safe_component("CON."), "CON_._");
        let long = format!("{}.", "x".repeat(179));
        let safe = safe_component(&long);
        assert!(valid_component(&safe), "{safe}");
        for name in ["CON.txt", "file.", "aux", "COM²"] {
            assert!(valid_component(&safe_component(name)), "{name}");
        }
    }

    #[test]
    fn conflict_names() {
        // 2026-10-18T12:00:00Z.
        let at = 1_792_324_800;
        assert_eq!(
            conflict_name("report.pdf", "Laptop", at, 1),
            "report (conflict from Laptop 2026-10-18).pdf"
        );
        assert_eq!(
            conflict_name("report.pdf", "Laptop", at, 2),
            "report (conflict from Laptop 2026-10-18 2).pdf"
        );
        assert_eq!(
            conflict_name("README", "", at, 1),
            "README (conflict from another computer 2026-10-18)"
        );
        // A computer name cannot break the component.
        assert_eq!(
            conflict_name("notes", "A/B: C", at, 1),
            "notes (conflict from A_B_ C 2026-10-18)"
        );
        // A folder-style name with a dot keeps its tail after the marker.
        assert_eq!(
            conflict_name("v1.2", "Laptop", at, 1),
            "v1 (conflict from Laptop 2026-10-18).2"
        );
        let long = format!("{}.pdf", "s".repeat(178));
        let named = conflict_name(&long, "Laptop", at, 3);
        assert_eq!(named.encode_utf16().count(), 180);
        assert!(named.ends_with(" (conflict from Laptop 2026-10-18 3).pdf"));
        assert!(valid_component(&named));
    }

    #[test]
    fn computer_names_are_safe_to_freeze() {
        assert_eq!(computer_origin("Laptop"), "Laptop");
        assert_eq!(
            computer_origin("  Office \"Mac\"\\Book\n "),
            "Office MacBook"
        );
        assert_eq!(computer_origin("Cafe\u{301}"), "Caf\u{e9}");
        let long = computer_origin(&"é".repeat(100));
        assert_eq!(long.encode_utf16().count(), 64);
        let emoji = computer_origin(&"\u{1f600}".repeat(40));
        assert_eq!(emoji.encode_utf16().count(), 64);
        // A combining mark cut from its letter is not left dangling.
        let edge = format!("{}e\u{301}", "a".repeat(63));
        assert!(crate::drop::device::valid_from(&computer_origin(&edge)));
        for name in [
            "Laptop",
            "Office \"Mac\"",
            "back\\slash",
            "tab\tname",
            "",
            "   ",
            &"\u{958}".repeat(70),
            &"x".repeat(200),
        ] {
            let origin = computer_origin(name);
            assert!(
                crate::drop::device::valid_from(&origin),
                "{name:?} -> {origin:?}"
            );
        }
    }
}
