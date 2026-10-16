//! The canonical metadata rules from `ENCRYPTION.md`, matched to Wildbloom's
//! TypeScript `sanitiseFileName` so a name sealed here is a fixed point there.

use crate::Error;
use unicode_normalization::UnicodeNormalization;

/// The longest stored name, in UTF-16 code units.
const MAX_NAME_UTF16: usize = 180;
/// The longest media type, in UTF-16 code units.
const MAX_MEDIA_TYPE_UTF16: usize = 255;

/// ECMAScript `WhiteSpace` and `LineTerminator`, the set `\s` and `trim` use.
/// Rust's `char::is_whitespace` differs (it omits U+FEFF and adds U+0085), so it
/// must not be used here.
fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'
            | '\u{000A}'
            | '\u{000B}'
            | '\u{000C}'
            | '\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}')
}

/// The source filename after, in order: the final `/` or `\` component;
/// control removal; NFC; `< > : " | ? *` to `_`; removal of every leading `.`
/// and whitespace; removal of trailing whitespace; `blob.bin` if empty; and
/// truncation to 180 UTF-16 units without splitting a surrogate pair, followed
/// by trailing-whitespace removal.
pub fn sanitise_name(value: &str) -> String {
    let leaf = value.rsplit(['/', '\\']).next().unwrap_or("");
    // Controls go before NFC so a removed control cannot leave a newly
    // composable sequence behind.
    let without_controls: String = leaf.chars().filter(|c| !is_control(*c)).collect();
    let mapped: String = without_controls
        .nfc()
        .map(|c| {
            if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = mapped
        .trim_start_matches(|c| c == '.' || is_js_whitespace(c))
        .trim_end_matches(is_js_whitespace);
    let fallback = if trimmed.is_empty() {
        "blob.bin"
    } else {
        trimmed
    };
    if fallback.encode_utf16().count() <= MAX_NAME_UTF16 {
        return fallback.to_string();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in fallback.chars() {
        let width = c.len_utf16();
        if units + width > MAX_NAME_UTF16 {
            break;
        }
        units += width;
        out.push(c);
    }
    out.trim_end_matches(is_js_whitespace).to_string()
}

/// The media type lower-cased, with an empty value replaced by
/// `application/octet-stream`.  Over 255 UTF-16 units or any control is refused,
/// never repaired.
pub fn normalise_media_type(value: &str) -> Result<String, Error> {
    let lowered = if value.is_empty() {
        "application/octet-stream".to_string()
    } else {
        value.to_lowercase()
    };
    if lowered.encode_utf16().count() > MAX_MEDIA_TYPE_UTF16 || lowered.chars().any(is_control) {
        return Err(Error::MediaType);
    }
    Ok(lowered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_published_name_rule() {
        assert_eq!(sanitise_name("dir/sub/world.dat"), "world.dat");
        assert_eq!(sanitise_name("C:\\Users\\x\\file.txt"), "file.txt");
        assert_eq!(sanitise_name("bad:name?.txt"), "bad_name_.txt");
        assert_eq!(sanitise_name("...hidden"), "hidden");
        assert_eq!(sanitise_name("../secret.txt"), "secret.txt");
        assert_eq!(sanitise_name(""), "blob.bin");
        assert_eq!(sanitise_name("   "), "blob.bin");
        assert_eq!(sanitise_name("a\u{0}b\u{7f}c"), "abc");
    }

    #[test]
    fn strips_dots_and_whitespace_together_so_the_result_is_a_fixed_point() {
        // Stripping dots then whitespace (as stash-rs does) leaves ".x" here.
        assert_eq!(sanitise_name(" .x"), "x");
        assert_eq!(sanitise_name(". . x"), "x");
        for name in [" .x", ". . x", "x \u{feff}", "\u{3000}y"] {
            let once = sanitise_name(name);
            assert_eq!(sanitise_name(&once), once, "{name:?}");
        }
    }

    #[test]
    fn uses_ecmascript_whitespace_not_rusts() {
        // U+FEFF is JS whitespace but not Rust whitespace; U+0085 is the reverse.
        assert_eq!(sanitise_name("\u{feff}name\u{feff}"), "name");
        assert_eq!(sanitise_name("name\u{85}"), "name\u{85}");
    }

    #[test]
    fn removes_controls_before_nfc() {
        // e + U+0001 + combining acute: removing the control first lets NFC
        // compose the pair, as the TypeScript reference does.
        assert_eq!(sanitise_name("e\u{1}\u{301}.txt"), "\u{e9}.txt");
        assert_eq!(sanitise_name("cafe\u{301}.txt"), "caf\u{e9}.txt");
    }

    #[test]
    fn truncates_at_180_utf16_units_without_splitting_a_pair() {
        assert_eq!(sanitise_name(&"a".repeat(400)).len(), 180);
        // 179 ASCII then an astral character: 181 units, so the pair is dropped.
        let name = format!("{}\u{1F600}", "a".repeat(179));
        assert_eq!(sanitise_name(&name), "a".repeat(179));
        // A space at the cut is trimmed after truncation.
        let name = format!("{} {}", "a".repeat(179), "b".repeat(10));
        assert_eq!(sanitise_name(&name), "a".repeat(179));
    }

    #[test]
    fn media_type_is_lowercased_defaulted_and_never_repaired() {
        assert_eq!(
            normalise_media_type("").unwrap(),
            "application/octet-stream"
        );
        assert_eq!(normalise_media_type("Text/Plain").unwrap(), "text/plain");
        assert!(normalise_media_type("text/\u{7f}plain").is_err());
        assert!(normalise_media_type(&"a".repeat(256)).is_err());
        assert!(normalise_media_type(&"a".repeat(255)).is_ok());
    }
}
