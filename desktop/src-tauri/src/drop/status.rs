//! The status line (design spec 6.1), resolved from the same data and in the
//! same priority order as `resolveStatus` in `ui/drop.js`, for the tray
//! tooltip and the tray menu's status item.

use super::types::{DropStatus, FileRow};

/// How the tray icon should look for a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Busy,
    Attention,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusLine {
    pub text: String,
    pub tone: Tone,
}

const DAY: u64 = 86_400;

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `"16 October 2027"`, as the UI's `fullDate` writes it.
pub fn full_date(unix: u64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let (year, month, day) = ymd(unix);
    format!("{day} {} {year}", MONTHS[(month - 1) as usize])
}

/// The UTC calendar date of a Unix time: (year, month 1-12, day 1-31).
pub fn ymd(unix: u64) -> (i64, u32, u32) {
    // Civil-from-days (Howard Hinnant), UTC.
    let days = (unix / DAY) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month as u32, day as u32)
}

pub fn resolve(status: &DropStatus, rows: &[FileRow], now: u64) -> StatusLine {
    let attention = |text: &str| StatusLine {
        text: text.to_owned(),
        tone: Tone::Attention,
    };
    if status.first_run.is_some() {
        return StatusLine {
            text: "Finish setting up Wildbloom Drop.".into(),
            tone: Tone::Normal,
        };
    }
    let failed = rows
        .iter()
        .filter(|r| matches!(r.state, "failed" | "missing_online"))
        .count();
    let copying = rows
        .iter()
        .filter(|r| matches!(r.state, "encrypting" | "queued" | "copying"))
        .count();
    if status.node != "ok" {
        return attention("Wildbloom Node has stopped.");
    }
    if status.keychain == "unavailable" {
        return attention("Wildbloom can't reach your keychain.");
    }
    if status.watch_folder.state == "unavailable" {
        return attention("Your Wildbloom folder can't be found. Changes there are paused.");
    }
    if status.watch_folder.state == "too_many" {
        return attention(
            "Your Wildbloom folder has more than 20,000 items. Changes there are paused.",
        );
    }
    if status.approval.state == "expired" {
        return attention("Approval for this computer has ended. New files stay on this computer.");
    }
    if status.online.configured && status.online.failed_checks > 2 {
        return attention(
            "Can't reach your online node. Files stay on this computer and copy when it's back.",
        );
    }
    if status.online.full {
        return attention("Your online space is full. New files stay on this computer.");
    }
    if failed > 0 {
        return attention(&format!(
            "{} only 1 copy.",
            plural(failed, "file has", "files have")
        ));
    }
    if status.recovery.key_list == "failed" {
        return attention(
            "Wildbloom couldn't update the list it needs to restore your files. Your files are safe on this computer.",
        );
    }
    let not_kept = rows.iter().filter(|r| r.state == "not_kept").count();
    if not_kept > 0 {
        return attention(&format!(
            "{} in your Wildbloom folder can't be kept.",
            plural(not_kept, "file", "files")
        ));
    }
    if copying > 0 {
        return StatusLine {
            text: format!(
                "Copying {} to your online node",
                plural(copying, "file", "files")
            ),
            tone: Tone::Busy,
        };
    }
    if !status.online.configured {
        return StatusLine {
            text: "Files have 1 copy, on this computer.".into(),
            tone: Tone::Normal,
        };
    }
    if status.approval.state == "active"
        && let Some(until) = status.approval.until
        && until.saturating_sub(now) < 30 * DAY
    {
        return StatusLine {
            text: format!("Approval for this computer ends on {}.", full_date(until)),
            tone: Tone::Attention,
        };
    }
    if !status.recovery.confirmed {
        return attention("Your recovery key isn't saved yet.");
    }
    let count = rows.len() - not_kept;
    if count >= 1 {
        return StatusLine {
            text: if count == 1 {
                "Your file has 2 copies.".into()
            } else {
                format!("All {count} files have 2 copies.")
            },
            tone: Tone::Normal,
        };
    }
    StatusLine {
        text: "No files yet".into(),
        tone: Tone::Normal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drop::types::*;

    fn status() -> DropStatus {
        DropStatus {
            first_run: None,
            node: "ok",
            keychain: "ok",
            online: OnlineStatus {
                configured: true,
                url: "https://storage.example/".into(),
                host: "storage.example".into(),
                reachable: true,
                failed_checks: 0,
                used_bytes: 0,
                limit_bytes: 5_000_000_000,
                full: false,
            },
            approval: ApprovalSummary {
                state: "active",
                by_npub: None,
                device_npub: None,
                until: Some(2_000_000_000),
                limit_bytes: None,
            },
            recovery: RecoveryStatus {
                key_list: "ok",
                saved_at: None,
                confirmed: true,
            },
            watch_folder: WatchFolderStatus {
                enabled: false,
                path: "~/Wildbloom".into(),
                state: "off",
            },
            limits: LimitsStatus {
                drop_max_bytes: 1,
                share_max_bytes: 1,
            },
            sharing: SharingSettings {
                after_download: "delete",
                expiry_seconds: 86_400,
            },
            browser_approval: false,
        }
    }

    fn row(state: &'static str) -> FileRow {
        FileRow {
            id: "a".into(),
            name: "a".into(),
            bytes: 1,
            added: 1,
            state,
            progress: None,
            shared_until: None,
            sharing_ended: None,
            downloaded_at: None,
            not_kept: None,
            folder: None,
            in_watch_folder: false,
        }
    }

    #[test]
    fn follows_the_ui_priority_order() {
        let now = 1_900_000_000;
        let mut s = status();
        assert_eq!(resolve(&s, &[], now).text, "No files yet");
        assert_eq!(
            resolve(&s, &[row("two_copies")], now).text,
            "Your file has 2 copies."
        );
        assert_eq!(
            resolve(&s, &[row("two_copies"), row("shared")], now).text,
            "All 2 files have 2 copies."
        );
        let busy = resolve(&s, &[row("copying"), row("failed")], now);
        assert_eq!(busy.text, "1 file has only 1 copy.");
        assert_eq!(busy.tone, Tone::Attention);
        assert_eq!(
            resolve(&s, &[row("copying"), row("queued")], now).text,
            "Copying 2 files to your online node"
        );
        s.recovery.key_list = "failed";
        assert!(
            resolve(&s, &[row("copying")], now)
                .text
                .starts_with("Wildbloom couldn't update the list")
        );
        s.recovery.key_list = "ok";
        s.online.failed_checks = 3;
        assert!(resolve(&s, &[], now).text.starts_with("Can't reach"));
        s.approval.state = "expired";
        assert!(
            resolve(&s, &[], now)
                .text
                .starts_with("Approval for this computer has ended")
        );
        s.node = "stopped";
        assert_eq!(resolve(&s, &[], now).text, "Wildbloom Node has stopped.");
    }

    #[test]
    fn folder_lines_sit_where_the_ui_puts_them() {
        let now = 1_900_000_000;
        let mut s = status();
        let rows = [row("two_copies"), row("not_kept"), row("not_kept")];
        assert_eq!(
            resolve(&s, &rows, now).text,
            "2 files in your Wildbloom folder can't be kept."
        );
        assert_eq!(
            resolve(&s, &[row("not_kept")], now).text,
            "1 file in your Wildbloom folder can't be kept."
        );
        // After the key list line, before copying.
        assert_eq!(
            resolve(&s, &[row("not_kept"), row("copying")], now).text,
            "1 file in your Wildbloom folder can't be kept."
        );
        assert_eq!(
            resolve(&s, &[row("not_kept"), row("failed")], now).text,
            "1 file has only 1 copy."
        );
        s.recovery.key_list = "failed";
        assert!(
            resolve(&s, &[row("not_kept")], now)
                .text
                .starts_with("Wildbloom couldn't update the list")
        );
        s.recovery.key_list = "ok";
        // Not-kept rows are not counted as having 2 copies.
        let mut kept = row("two_copies");
        kept.id = "b".into();
        s.watch_folder.enabled = true;
        s.watch_folder.state = "on";
        assert_eq!(
            resolve(&s, &[row("two_copies"), kept, row("not_kept")], now).text,
            "1 file in your Wildbloom folder can't be kept."
        );
        // Straight after the keychain line, unavailable then too many.
        s.watch_folder.state = "too_many";
        s.approval.state = "expired";
        assert!(
            resolve(&s, &[], now)
                .text
                .starts_with("Your Wildbloom folder has more than 20,000 items")
        );
        s.watch_folder.state = "unavailable";
        assert_eq!(
            resolve(&s, &[], now).text,
            "Your Wildbloom folder can't be found. Changes there are paused."
        );
        s.keychain = "unavailable";
        assert_eq!(
            resolve(&s, &[], now).text,
            "Wildbloom can't reach your keychain."
        );
    }

    #[test]
    fn dates_match_the_ui() {
        assert_eq!(full_date(1_792_108_800), "16 October 2026");
        assert_eq!(full_date(0), "1 January 1970");
        assert_eq!(full_date(951_782_400), "29 February 2000");
    }
}
