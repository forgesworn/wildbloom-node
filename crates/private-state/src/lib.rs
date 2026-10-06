//! Private owner state shared by the daemon and desktop. Existing broad access
//! is refused, never silently changed. Administrators are inside the OS trust boundary.
use std::{fs, io, path::Path};

#[cfg(windows)]
mod windows;

pub fn private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    return windows::private_directory(path);
    #[cfg(not(windows))]
    {
        if !path.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
        }
        check_directory(path)
    }
}

pub fn check_directory(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other(
            "private state requires an ordinary directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("private directory requires mode 0700"));
        }
    }
    #[cfg(windows)]
    windows::check_path(path, true)?;
    Ok(())
}

/// Windows ACL check on the actual open handle before reading/writing bytes.
/// Unix callers retain their existing mode and link checks.
pub fn check_file(file: &fs::File) -> io::Result<()> {
    #[cfg(windows)]
    windows::check_file(file)?;
    #[cfg(not(windows))]
    let _ = file;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_reopen_and_inherit_private_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owner/work");
        private_directory(&root).unwrap();
        private_directory(&root).unwrap();
        let file = tempfile::NamedTempFile::new_in(&root).unwrap();
        check_file(file.as_file()).unwrap();
        let child = tempfile::tempdir_in(&root).unwrap();
        #[cfg(windows)]
        check_directory(child.path()).unwrap();
        let nested = tempfile::NamedTempFile::new_in(child.path()).unwrap();
        check_file(nested.as_file()).unwrap();
    }

    #[test]
    fn refuses_file_as_directory() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        assert!(private_directory(temp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_broad_modes_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owner");
        private_directory(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(&root).is_err());
        let link = temp.path().join("link");
        symlink(&root, &link).unwrap();
        assert!(private_directory(&link).is_err());
    }
}
