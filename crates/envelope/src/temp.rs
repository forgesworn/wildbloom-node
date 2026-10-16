//! The private temp directory: its single-instance lock and the start-up sweep
//! of temp files a killed process left behind.

use crate::Error;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Temp files this crate creates are named `.wildbloom-<random>.part`.
pub(crate) const TEMP_PREFIX: &str = ".wildbloom-";
pub(crate) const TEMP_SUFFIX: &str = ".part";
/// The lock file inside the temp directory.  Its name never matches the sweep.
pub const TEMP_LOCK_FILE: &str = ".wildbloom-temp.lock";

/// An exclusive, process-lifetime claim on a temp directory.  The app takes it
/// at start-up and holds it until exit, so a second instance cannot sweep away
/// the first one's temp files while they are in use.  The OS releases the lock
/// when the process dies, so it never goes stale.
///
/// The lock is an advisory OS file lock (`flock` on Unix, `LockFileEx` on
/// Windows).  On network file systems such as NFS it may be unsupported or
/// only local to one machine, which is another reason the temp directory must
/// be local app data.
#[derive(Debug)]
pub struct TempDirLock {
    dir: PathBuf,
    _file: File,
}

impl TempDirLock {
    /// Creates `dir` private if missing (refusing one with broad access) and
    /// takes the lock, or [`Error::TempDirInUse`] if another holder has it.
    pub fn acquire(dir: &Path) -> Result<Self, Error> {
        wildbloom_private_state::private_directory(dir).map_err(Error::PrivateState)?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(dir.join(TEMP_LOCK_FILE))?;
        wildbloom_private_state::check_file(&file).map_err(Error::PrivateState)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| Error::TempDirInUse)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            _file: file,
        })
    }

    /// The locked directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// What a sweep did.  Files it could not remove (for example a Windows sharing
/// violation) are listed rather than stopping the sweep.
#[derive(Debug, Default)]
pub struct SweepReport {
    pub removed: usize,
    pub failed: Vec<(PathBuf, io::ErrorKind)>,
}

/// Deletes stale `.wildbloom-*.part` files in the locked temp directory.  A
/// hard kill skips a temp file's cleanup, so a partial decryption can leave
/// authenticated plaintext behind.  Call this once at start-up, after taking
/// the [`TempDirLock`] and before any operation that uses the directory: it
/// would also delete this process's own in-flight temp files.
///
/// Only ordinary files are removed; symlinks and directories are left alone.
/// Per-file failures are collected in [`SweepReport::failed`] and the sweep
/// carries on.  Failing to read the directory at all is an error.
pub fn sweep_stale_temp_files(lock: &TempDirLock) -> Result<SweepReport, Error> {
    let dir = lock.dir();
    wildbloom_private_state::check_directory(dir).map_err(Error::PrivateState)?;
    let mut report = SweepReport::default();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                report.failed.push((dir.to_path_buf(), e.kind()));
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX)) {
            continue;
        }
        let path = entry.path();
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => {}
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                report.failed.push((path, e.kind()));
                continue;
            }
        }
        match std::fs::remove_file(&path) {
            Ok(()) => report.removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => report.failed.push((path, e.kind())),
        }
    }
    Ok(report)
}
