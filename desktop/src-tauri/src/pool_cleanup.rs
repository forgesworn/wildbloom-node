//! Explicit, bounded review/removal of disposable owner repair files.
//! Uses the daemon's coordinator.lock; never recursively removes a directory.
use serde::Serialize;
use std::{fs, path::Path, time::UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileReview {
    name: String,
    bytes: u64,
    modified: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PassReview {
    name: String,
    modified: String,
    files: Vec<FileReview>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Review {
    pub passes: Vec<PassReview>,
    pub bytes: u64,
}
fn ordinary(path: &Path, directory: bool) -> Result<fs::Metadata, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "Could not inspect repair files.")?;
    if meta.file_type().is_symlink()
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
    {
        return Err("Repair cleanup refuses links and unexpected file types. Review the work folder manually.".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("Repair cleanup refuses Windows reparse points.".into());
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !directory && meta.nlink() != 1 {
            return Err("Repair cleanup refuses multiply linked files.".into());
        }
    }
    Ok(meta)
}
fn modified(meta: &fs::Metadata) -> Result<String, String> {
    Ok(meta
        .modified()
        .map_err(|_| "Could not inspect file modification time.")?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Invalid file modification time.")?
        .as_nanos()
        .to_string())
}
fn suffix(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn disposable(name: &str) -> bool {
    suffix(name, ".tmp")
        || ["source-", "coded-"].iter().any(|p| {
            name.strip_prefix(p)
                .is_some_and(|s| s.parse::<u8>().is_ok_and(|n| n < 16 && n.to_string() == s))
        })
}
/// Lock is identical to the owner's CLI service and remains held across review/removal.
pub fn lock(work: &Path) -> Result<fs::File, String> {
    let meta = ordinary(work, true)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("Repair work directory must be private (0700 required).".into());
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    let path = work.join("coordinator.lock");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            ordinary(&path, false)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Could not inspect the repair lock.".into()),
    }
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| "Could not open the repair lock.")?;
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| "Repair files are in use. Stop the desktop or CLI owner service first.")?;
    Ok(file)
}
pub fn review(work: &Path) -> Result<Review, String> {
    ordinary(work, true)?;
    let mut result = Review {
        passes: vec![],
        bytes: 0,
    };
    for (index, entry) in fs::read_dir(work)
        .map_err(|_| "Could not read repair directory.")?
        .enumerate()
    {
        if index >= 256 {
            return Err(
                "Excessive work-directory entries. Review the work folder manually.".into(),
            );
        }
        let entry = entry.map_err(|_| "Could not inspect repair directory.")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("pool-pass-") {
            continue;
        }
        if !suffix(&name, "pool-pass-") || result.passes.len() >= 64 {
            return Err(
                "Unexpected or excessive repair folders. Review the work folder manually.".into(),
            );
        }
        let meta = ordinary(&entry.path(), true)?;
        let mut pass = PassReview {
            name,
            modified: modified(&meta)?,
            files: vec![],
        };
        for file in fs::read_dir(entry.path()).map_err(|_| "Could not read repair folder.")? {
            let file = file.map_err(|_| "Could not inspect repair file.")?;
            let name = file.file_name().to_string_lossy().into_owned();
            if !disposable(&name) || pass.files.len() >= 64 {
                return Err("Unexpected files in a repair folder. Review the work folder manually; nothing was cleared.".into());
            }
            let meta = ordinary(&file.path(), false)?;
            result.bytes = result
                .bytes
                .checked_add(meta.len())
                .ok_or("Repair file sizes exceed limits.")?;
            pass.files.push(FileReview {
                name,
                bytes: meta.len(),
                modified: modified(&meta)?,
            });
        }
        pass.files.sort_by(|a, b| a.name.cmp(&b.name));
        result.passes.push(pass);
    }
    result.passes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
/// Caller holds coordinator.lock and the desktop operation mutex throughout.
pub fn clear(work: &Path, expected: &Review) -> Result<(), String> {
    if &review(work)? != expected {
        return Err("Repair files changed since review. Review and confirm again.".into());
    }
    for pass in &expected.passes {
        let directory = work.join(&pass.name);
        ordinary(&directory, true)?;
        for file in &pass.files {
            let path = directory.join(&file.name);
            ordinary(&path, false)?;
            fs::remove_file(path).map_err(
                |_| "Cleanup was incomplete. Review remaining repair files before retrying.",
            )?;
        }
        // Never follow nested directories or erase files added since review.
        fs::remove_dir(directory).map_err(
            |_| "Cleanup was incomplete. Review remaining repair files before retrying.",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let pass = tempfile::Builder::new()
            .prefix("pool-pass-")
            .tempdir_in(root.path())
            .unwrap()
            .keep();
        fs::write(pass.join("source-0"), b"synthetic encrypted bytes").unwrap();
        (root, pass)
    }
    #[test]
    fn review_clear_preserves_receipts_reports_and_lock() {
        let (root, pass) = fixture();
        for name in ["receipt.json", "pool-report.json", "unrelated"] {
            fs::write(root.path().join(name), b"keep").unwrap();
        }
        let _lock = lock(root.path()).unwrap();
        let reviewed = review(root.path()).unwrap();
        assert_eq!(reviewed.passes.len(), 1);
        assert_eq!(reviewed.bytes, 25);
        assert!(pass.exists());
        clear(root.path(), &reviewed).unwrap();
        assert!(!pass.exists());
        for name in [
            "receipt.json",
            "pool-report.json",
            "unrelated",
            "coordinator.lock",
        ] {
            assert!(root.path().join(name).exists());
        }
    }
    #[test]
    fn active_owner_lock_and_stale_review_refuse_cleanup() {
        let (root, pass) = fixture();
        let owner = lock(root.path()).unwrap();
        assert!(lock(root.path()).is_err());
        drop(owner);
        let _lock = lock(root.path()).unwrap();
        let reviewed = review(root.path()).unwrap();
        fs::write(pass.join("coded-1"), b"new").unwrap();
        assert!(clear(root.path(), &reviewed).is_err());
        assert!(pass.join("source-0").exists());
        clear(root.path(), &review(root.path()).unwrap()).unwrap();
    }
    #[test]
    fn unexpected_files_and_nested_directories_are_never_deleted() {
        let (root, pass) = fixture();
        fs::write(pass.join("backup.json"), b"keep").unwrap();
        assert!(review(root.path()).is_err());
        fs::remove_file(pass.join("backup.json")).unwrap();
        fs::create_dir(pass.join("source-1")).unwrap();
        assert!(review(root.path()).is_err());
        assert!(pass.join("source-0").exists());
    }
    #[test]
    fn changed_file_and_unrecognised_pass_require_manual_review() {
        let (root, pass) = fixture();
        let reviewed = review(root.path()).unwrap();
        fs::write(pass.join("source-0"), b"changed length").unwrap();
        assert!(clear(root.path(), &reviewed).is_err());
        assert!(pass.exists());
        fs::create_dir(root.path().join("pool-pass-backup-files")).unwrap();
        assert!(review(root.path()).is_err());
        assert_eq!(fs::read(pass.join("source-0")).unwrap(), b"changed length");
    }
    #[cfg(unix)]
    #[test]
    fn root_and_pass_symlinks_cannot_escape_work_directory() {
        use std::os::unix::fs::symlink;
        let (root, _) = fixture();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("source-1"), b"keep").unwrap();
        symlink(outside.path(), root.path().join("pool-pass-Xy1234")).unwrap();
        assert!(review(root.path()).is_err());
        symlink(outside.path(), root.path().join("linked-work")).unwrap();
        assert!(lock(&root.path().join("linked-work")).is_err());
        assert_eq!(fs::read(outside.path().join("source-1")).unwrap(), b"keep");
    }
    #[cfg(unix)]
    #[test]
    fn links_to_outside_data_and_lock_are_refused() {
        use std::os::unix::fs::symlink;
        let (root, pass) = fixture();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), pass.join("coded-0")).unwrap();
        assert!(review(root.path()).is_err());
        fs::remove_file(pass.join("coded-0")).unwrap();
        fs::hard_link(outside.path(), pass.join("coded-0")).unwrap();
        assert!(review(root.path()).is_err());
        symlink(outside.path(), root.path().join("coordinator.lock")).unwrap();
        assert!(lock(root.path()).is_err());
        assert!(outside.path().exists());
    }
}
