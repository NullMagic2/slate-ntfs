//! Module: slate_ntfs_tools::linux
//! Purpose: Share Linux ioctl numbers, open flags and descriptor helpers.
//! Created: 2026-10-03
//! Architecture: checker, recovery_io and ntfs_utils call these wrappers instead
//!     of declaring their own syscalls; libc supplies the raw system interface.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// Linux fs.h and Slate driver request numbers absent from libc.
pub const BLKGETSIZE64: libc::Ioctl = 0x8008_1272;
pub const FIFREEZE: libc::Ioctl = 0xc004_5877;
pub const FITHAW: libc::Ioctl = 0xc004_5878;
/// _IO('N', 0xe0 + operation): typed repair of the opened inode.
pub const SLATE_REPAIR_INODE: libc::Ioctl = 0x4ee0;
/// _IOW('N', 0xe2/0xe3, u64): EA summary of a record, or one bitmap sector.
pub const SLATE_REPAIR_EA_RECORD: libc::Ioctl = 0x4008_4ee2;
pub const SLATE_REPAIR_ALLOCATION: libc::Ioctl = 0x4008_4ee3;
/// User-supplied paths are opened without following links or blocking.
pub const NO_FOLLOW_NONBLOCK: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK;
/// Owner-only permissions for reports, journals, queues and staged images.
pub const PRIVATE_FILE_MODE: u32 = 0o600;

/// Issue one ioctl; negative results become the current OS error.
pub fn ioctl(file: &impl AsRawFd, request: libc::Ioctl, argument: *mut libc::c_void) -> io::Result<i32> {
    // SAFETY: callers pass the argument type documented for each request.

    let result = unsafe { libc::ioctl(file.as_raw_fd(), request, argument) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

/// A stable path to an already-opened descriptor; it survives path renames.
pub fn fd_path(file: &impl AsRawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Byte length of a regular image or a block device.
pub fn image_length(file: &File) -> io::Result<u64> {
    use std::os::unix::fs::FileTypeExt;

    let metadata = file.metadata()?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.file_type().is_block_device() {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "requires an image or block device"));
    }
    let mut length = 0_u64;
    ioctl(file, BLKGETSIZE64, (&mut length as *mut u64).cast())?;
    Ok(length)
}

pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.

    unsafe { libc::geteuid() }
}

/// Resolve the held descriptor's mount and require a mounted Slate filesystem.
pub fn require_slate_mount(file: &File) -> io::Result<()> {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    let mount_id = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:").map(str::trim))
        .ok_or_else(|| io::Error::other("cannot identify mounted repair target"))?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    let slate = mounts.lines().any(|line| {
        line.split_whitespace().next() == Some(mount_id)
            && line.split_once(" - ").is_some_and(|(_, fields)| fields.split_whitespace().next() == Some("ntfsrs"))
    });
    if !slate {
        return Err(io::Error::other("online repair requires a mounted Slate filesystem"));
    }
    Ok(())
}

/// The directory that will hold path; an empty parent means the current directory.
pub fn parent_directory(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."))
}
