use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::Path,
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetAce, GetTokenInformation, IsValidAcl,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{
        CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private state ACL must allow only the current user, SYSTEM and Administrators; links are refused",
    )
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: pointers are allocated by the documented LocalAlloc-based APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}

// SAFETY: caller supplies a valid SID in a live token/security descriptor.
unsafe fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _memory = Local(text.cast());
    let mut len = 0;
    // Windows SID strings have a bounded system-defined representation.
    while len < 256 && unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    if len == 256 {
        return Err(denied());
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, len)
    }))
}

fn current_user() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: valid process pseudo-handle and writable output pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut needed = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed == 0 || needed > 65536 {
            return Err(denied());
        }
        // usize allocation supplies alignment for TOKEN_USER and its SID.
        let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        unsafe { sid_string(user.User.Sid) }
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

fn trusted(sid: &str, user: &str) -> bool {
    sid == user || sid == "S-1-5-18" || sid == "S-1-5-32-544"
}

fn check_acl(file: &File, directory: bool) -> io::Result<()> {
    let user = current_user()?;
    let mut owner = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    // SAFETY: open handle remains live; returned pointers share descriptor ownership.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _memory = Local(descriptor);
    if owner.is_null() || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(denied());
    }
    if !trusted(&unsafe { sid_string(owner)? }, &user) {
        return Err(denied());
    }
    let mut user_full = false;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = null_mut();
        if unsafe { GetAce(acl, u32::from(index), &mut ace) } == 0 {
            return Err(denied());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // Only simple allow ACEs: fail closed on deny, object, callback or unknown
        // forms rather than attempting to approximate Windows access evaluation.
        if header.AceType != 0 || usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(denied());
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = unsafe { sid_string(std::ptr::addr_of!(allowed.SidStart).cast_mut().cast())? };
        if !trusted(&sid, &user) {
            return Err(denied());
        }
        // Full access, effective here, and inheritable by files AND directories.
        let full = allowed.Mask & 0x001f01ff == 0x001f01ff || allowed.Mask & 0x10000000 != 0;
        if sid == user
            && full
            && header.AceFlags & 0x08 == 0
            && (!directory || header.AceFlags & 0x03 == 0x03 && header.AceFlags & 0x04 == 0)
        {
            user_full = true;
        }
    }
    if !user_full {
        return Err(denied());
    }
    Ok(())
}

pub fn check_file(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied());
    }
    check_acl(file, false)
}

pub fn check_path(path: &Path, directory: bool) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.is_dir() != directory || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied());
    }
    check_acl(&file, directory)
}

pub fn private_directory(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return check_path(path, true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            private_directory(parent)?;
        }
        if std::fs::symlink_metadata(parent)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(denied());
        }
    }
    let user = current_user()?;
    let sddl: Vec<u16> = format!("O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = null_mut();
    // Protection is supplied at creation: no create-then-chmod exposure window.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _memory = Local(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if wide[..wide.len() - 1].contains(&0) {
        return Err(denied());
    }
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    check_path(path, true)
}
