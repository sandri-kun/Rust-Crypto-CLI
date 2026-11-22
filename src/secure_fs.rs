//! Reject links in every path component, and resolve through pinned directory handles.
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

pub struct SecureFile {
    file: File,
    // On Windows, no-delete-sharing prevents ancestors being renamed or replaced.
    _parents: Vec<File>,
    #[cfg(unix)]
    name: std::ffi::CString,
}

impl Read for SecureFile {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl SecureFile {
    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn discard(&self) {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
            };
            let info = FILE_DISPOSITION_INFO { DeleteFile: true };
            // SAFETY: live owned handle, valid FILE_DISPOSITION_INFO and matching size.
            unsafe {
                SetFileInformationByHandle(
                    self.file.as_raw_handle(),
                    FileDispositionInfo,
                    (&info as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of_val(&info) as u32,
                );
            }
        }
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: pinned parent fd and a single validated NUL-terminated basename.
            unsafe {
                libc::unlinkat(
                    self._parents.last().unwrap().as_raw_fd(),
                    self.name.as_ptr(),
                    0,
                );
            }
        }
    }
}

fn invalid_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Links, reparse points, device paths and parent-directory components are not allowed.",
    )
}

fn absolute(path: &Path) -> io::Result<PathBuf> {
    // Check before normalization so a linked component followed by '..' cannot disappear.
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(invalid_path());
    }
    std::path::absolute(path)
}

pub fn open_read(path: &Path) -> io::Result<SecureFile> {
    open(path, false)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut output = open(path, true)?;
    if let Err(error) = output
        .file
        .write_all(bytes)
        .and_then(|()| output.file.sync_all())
    {
        output.discard();
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn open(path: &Path, create: bool) -> io::Result<SecureFile> {
    use std::{
        fs::{self, OpenOptions},
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
        path::Prefix,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    let path = absolute(path)?;
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid_path());
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
        return Err(invalid_path());
    }
    if components.next() != Some(Component::RootDir) {
        return Err(invalid_path());
    }
    let mut current = PathBuf::from(prefix.as_os_str());
    current.push("\\");
    let parts: Vec<_> = components
        .filter(|c| !matches!(c, Component::CurDir))
        .collect();
    if parts.is_empty() {
        return Err(invalid_path());
    }
    let mut parents = Vec::new();
    for part in &parts {
        // Pin each ancestor BEFORE resolving its child. Reparse tags are checked on handles.
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(0x80)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = match options.open(&current) {
            Ok(directory) => directory,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                options.open(&current)?
            }
            Err(error) => return Err(error),
        };
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_path());
        }
        parents.push(directory);
        let Component::Normal(name) = part else {
            return Err(invalid_path());
        };
        if name.encode_wide().any(|c| c == b':' as u16 || c == 0) {
            return Err(invalid_path());
        }
        current.push(name);
    }
    let mut options = OpenOptions::new();
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if create {
        // DELETE access permits removing an incomplete output through its own handle.
        options
            .write(true)
            .create_new(true)
            .access_mode(0x40010000)
            .share_mode(0);
    } else {
        options.read(true).share_mode(FILE_SHARE_READ);
    }
    let file = options.open(&current)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid_path());
    }
    Ok(SecureFile {
        file,
        _parents: parents,
    })
}

#[cfg(unix)]
fn open(path: &Path, create: bool) -> io::Result<SecureFile> {
    use std::{
        ffi::CString,
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
    };
    fn component(name: &std::ffi::OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| invalid_path())
    }
    fn owned(fd: libc::c_int) -> io::Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful open/openat returns a new, exclusively owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    let path = absolute(path)?;
    let mut parts: Vec<_> = path
        .components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .collect();
    let Some(Component::Normal(name)) = parts.pop() else {
        return Err(invalid_path());
    };
    let name = component(name)?;
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut parents = vec![root];
    for part in parts {
        let Component::Normal(part) = part else {
            return Err(invalid_path());
        };
        let part = component(part)?;
        let parent = parents.last().unwrap().as_raw_fd();
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: pinned parent fd, NUL-terminated child name, directory-only no-follow flags.
        let mut directory = owned(unsafe { libc::openat(parent, part.as_ptr(), flags) });
        if create
            && directory
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
        {
            // SAFETY: same validated parent/name; newly created directories are private.
            if unsafe { libc::mkdirat(parent, part.as_ptr(), 0o700) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            directory = owned(unsafe { libc::openat(parent, part.as_ptr(), flags) });
        }
        parents.push(directory?);
    }
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if create {
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
        } else {
            libc::O_RDONLY
        };
    // SAFETY: live parent, single basename; O_EXCL makes creation atomic, mode is private.
    let file = owned(unsafe {
        libc::openat(
            parents.last().unwrap().as_raw_fd(),
            name.as_ptr(),
            flags,
            0o600,
        )
    })?;
    if !file.metadata()?.is_file() {
        return Err(invalid_path());
    }
    Ok(SecureFile {
        file,
        _parents: parents,
        name,
    })
}

#[cfg(not(any(unix, windows)))]
fn open(_path: &Path, _create: bool) -> io::Result<SecureFile> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Secure filesystem access is unavailable on this platform.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn directory() -> PathBuf {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "seedcrypt-secure-fs-{:x}",
            u128::from_le_bytes(random)
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn reject_linked_ancestors_and_pin_open_directories() {
        let root = directory();
        let real = root.join("real");
        let link = root.join("redirect");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("source.bin"), b"source").unwrap();
        #[cfg(windows)]
        {
            let result = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&link)
                .arg(&real)
                .output()
                .unwrap();
            assert!(result.status.success(), "could not create test junction");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_read(&link.join("source.bin")).is_err());
        assert!(write_new(&link.join("leaked.bin"), b"secret").is_err());
        assert!(!real.join("leaked.bin").exists());
        assert!(absolute(Path::new("../blocked.bin")).is_err());
        let mut source = open_read(&real.join("source.bin")).unwrap();
        #[cfg(windows)]
        assert!(fs::rename(&real, root.join("replaced")).is_err());
        let mut bytes = Vec::new();
        source.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"source");
        drop(source);
        assert!(write_new(&real.join("source.bin"), b"overwrite").is_err());
        #[cfg(windows)]
        fs::remove_dir(link).unwrap();
        #[cfg(unix)]
        fs::remove_file(link).unwrap();
        fs::remove_file(real.join("source.bin")).unwrap();
        fs::remove_dir(real).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn incomplete_output_is_removed_via_its_handle() {
        let root = directory();
        let path = root.join("incomplete.bin");
        let mut output = open(&path, true).unwrap();
        output.file.write_all(b"partial plaintext").unwrap();
        output.discard();
        drop(output);
        assert!(!path.exists());
        fs::remove_dir(root).unwrap();
    }
}
