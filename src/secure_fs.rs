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
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir) || c.as_os_str() == "..")
    {
        return Err(invalid_path());
    }
    std::path::absolute(path)
}

pub fn open_directory(path: &Path) -> io::Result<SecureFile> {
    open_impl(path, false, true)
}

fn open(path: &Path, create: bool) -> io::Result<SecureFile> {
    open_impl(path, create, false)
}

pub fn open_read(path: &Path) -> io::Result<SecureFile> {
    open(path, false)
}

struct PendingFile {
    file: SecureFile,
    cleanup: bool,
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if self.cleanup {
            self.file.discard();
        }
    }
}

pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_new_with(path, |file| file.write_all(bytes))
}

fn write_new_with(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let path = absolute(path)?;
    let _name = path.file_name().ok_or_else(invalid_path)?;
    let parent = path.parent().ok_or_else(invalid_path)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        if _name.encode_wide().any(|c| c == b':' as u16 || c == 0) {
            return Err(invalid_path());
        }
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let temporary = parent.join(format!(
        ".seedcrypt-{:032x}.tmp",
        u128::from_le_bytes(random)
    ));
    let mut pending = PendingFile {
        file: open(&temporary, true)?,
        cleanup: true,
    };
    write(&mut pending.file.file)?;
    pending.file.file.sync_all()?;
    publish(&mut pending, &path)?;
    Ok(())
}

#[cfg(windows)]
fn publish(pending: &mut PendingFile, destination: &Path) -> io::Result<()> {
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle,
    };
    let wide: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let offset = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let size = offset + (wide.len() + 1) * 2;
    // u64 storage gives the structure its required alignment and room for the variable name.
    let mut storage = vec![0u64; size.div_ceil(8)];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: aligned zeroed buffer, sized for the full UTF-16 name; parent and file handles stay live.
    let success = unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (wide.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
            wide.len(),
        );
        SetFileInformationByHandle(
            pending.file.file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            size as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    // The handle now names the final file. Never delete it if the subsequent flush fails.
    pending.cleanup = false;
    pending.file.file.sync_all().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Output committed, but its final flush failed: {error}"),
        )
    })
}

#[cfg(unix)]
fn publish(pending: &mut PendingFile, destination: &Path) -> io::Result<()> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };
    let destination = CString::new(destination.file_name().ok_or_else(invalid_path)?.as_bytes())
        .map_err(|_| invalid_path())?;
    let parent = pending.file._parents.last().unwrap();
    // SAFETY: both are single basenames relative to the same pinned directory.
    // linkat fails with EEXIST, so publication is atomic without overwriting any target.
    if unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            pending.file.name.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("Output committed, but directory synchronization failed: {error}"),
        )
    })?;
    pending.file.discard();
    pending.cleanup = false;
    parent.sync_all()
}

#[cfg(not(any(unix, windows)))]
fn publish(_pending: &mut PendingFile, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Atomic publication is unavailable on this platform.",
    ))
}

#[cfg(windows)]
fn open_impl(path: &Path, create: bool, directory: bool) -> io::Result<SecureFile> {
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
    options.custom_flags(
        FILE_FLAG_OPEN_REPARSE_POINT
            | if directory {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            },
    );
    if create {
        // DELETE access permits removing an incomplete output through its own handle.
        options
            .write(true)
            .create_new(true)
            .access_mode(0x40010000)
            .share_mode(0);
    } else {
        options.read(true).share_mode(FILE_SHARE_READ);
        if directory {
            options.access_mode(0x80);
        }
    }
    let file = options.open(&current)?;
    let metadata = file.metadata()?;
    if (if directory {
        !metadata.is_dir()
    } else {
        !metadata.is_file()
    }) || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid_path());
    }
    Ok(SecureFile {
        file,
        _parents: parents,
    })
}

#[cfg(unix)]
fn open_impl(path: &Path, create: bool, directory: bool) -> io::Result<SecureFile> {
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
            parents.last().unwrap().sync_all()?;
            directory = owned(unsafe { libc::openat(parent, part.as_ptr(), flags) });
        }
        parents.push(directory?);
    }
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 }
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
    let metadata = file.metadata()?;
    if if directory {
        !metadata.is_dir()
    } else {
        !metadata.is_file()
    } {
        return Err(invalid_path());
    }
    Ok(SecureFile {
        file,
        _parents: parents,
        name,
    })
}

#[cfg(not(any(unix, windows)))]
fn open_impl(_path: &Path, _create: bool, _directory: bool) -> io::Result<SecureFile> {
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
    fn atomic_writer_cleans_partial_writes_and_unwinds_without_publishing() {
        let root = directory();
        let final_path = root.join("atomic.bin");
        let failed = write_new_with(&final_path, |file| {
            file.write_all(b"partial secret")?;
            assert!(!final_path.exists());
            Err(io::Error::other("injected disk failure"))
        });
        assert!(failed.is_err());
        assert!(!final_path.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let panic = std::panic::catch_unwind(|| {
            let _ = write_new_with(&final_path, |file| {
                file.write_all(b"partial secret")?;
                panic!("injected writer panic");
            });
        });
        assert!(panic.is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        write_new(&final_path, b"complete").unwrap();
        assert!(write_new(&final_path, b"overwrite").is_err());
        assert_eq!(fs::read(&final_path).unwrap(), b"complete");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_file(final_path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn concurrent_publication_has_one_winner_and_no_partial_final_file() {
        let root = directory();
        let path = root.join("race.bin");
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                write_new_with(&path, |file| {
                    file.write_all(b"AAAA")?;
                    barrier.wait();
                    Ok(())
                })
            });
            let b = scope.spawn(|| {
                write_new_with(&path, |file| {
                    file.write_all(b"BBBB")?;
                    barrier.wait();
                    Ok(())
                })
            });
            [a.join().unwrap(), b.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let bytes = fs::read(&path).unwrap();
        assert!(bytes == b"AAAA" || bytes == b"BBBB");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
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
        assert!(open_directory(&link).is_err());
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
