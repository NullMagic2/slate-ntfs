//! Module: ntfs_utils::admin
//! Purpose: Explicit Linux administration.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

//! Explicit Linux administration. Never elevates credentials or edits mounted
//! NTFS metadata behind the filesystem driver. No operation is implicit in probe.
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Stable across Rust, C, Python and CLI exit codes. Separate from probe codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    Success = 0,
    Failure = 1,
    PermissionDenied = 2,
    Busy = 3,
    InvalidArgument = 4,
    Unsupported = 5,
    DependencyMissing = 6,
    VerificationFailed = 7,
}

#[derive(Clone, Debug)]
pub struct OperationResult {
    pub status: Status,
    /// Diagnostic. Failure after formatting starts may leave partial metadata.
    pub message: String,
}
impl OperationResult {
    pub fn is_success(&self) -> bool {
        self.status == Status::Success
    }
    pub fn new(status: Status, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
    fn from_io(error: io::Error) -> Self {
        let status = match error.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => Status::PermissionDenied,
            None if error.kind() == io::ErrorKind::PermissionDenied => Status::PermissionDenied,
            Some(libc::EBUSY | libc::EWOULDBLOCK) => Status::Busy,
            Some(libc::ENOTSUP | libc::ENOSYS | libc::EROFS) => Status::Unsupported,
            Some(libc::EINVAL | libc::ELOOP) => Status::InvalidArgument,
            _ => Status::Failure,
        };
        Self::new(status, error.to_string())
    }
}

/// One asynchronous repair. Dropping the handle waits; repairs are never
/// cancelled midway through durable publication by freeing an API object.
pub struct RepairJob {
    progress: std::sync::Arc<std::sync::Mutex<crate::RepairProgress>>,
    worker: std::sync::Mutex<Option<std::thread::JoinHandle<OperationResult>>>,
    result: std::sync::Mutex<Option<OperationResult>>,
}
impl RepairJob {
    pub fn progress(&self) -> crate::RepairProgress {
        *self.progress.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    pub fn is_finished(&self) -> bool {
        matches!(self.progress().phase, 13 | 14)
    }
    pub fn wait(&self) -> OperationResult {
        let mut worker = self.worker.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(worker) = worker.take() {
            *self.result.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(worker.join().unwrap_or_else(|_| OperationResult::new(Status::Failure, "repair worker panicked")));
        }
        self.result
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .unwrap_or_else(|| OperationResult::new(Status::Failure, "missing repair result"))
    }
}
impl Drop for RepairJob {
    fn drop(&mut self) {
        let _ = self.wait();
    }
}

/// mode: 0=copy repair (target=new image), 1=offline in-place, 2=resume
/// (target=external journal), 3=rescue, 4=resume rescue (target=external archive).
/// Rescue preserves readable sectors; it does not certify filesystem health.
pub fn start_repair(source: impl AsRef<Path>, target: impl AsRef<Path>, mode: u32) -> io::Result<RepairJob> {
    if mode > 4 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let source = source.as_ref().to_path_buf();
    let target = target.as_ref().to_path_buf();
    if source.as_os_str().is_empty() || target.as_os_str().is_empty() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let progress = std::sync::Arc::new(std::sync::Mutex::new(crate::RepairProgress::new(
        slate_ntfs_tools::recovery_io::Phase::Planning,
        0,
        0,
    )));
    let shared = progress.clone();
    let worker = std::thread::Builder::new().name("ntfs-repair".into()).spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut update = |value| { *shared.lock().unwrap_or_else(|p| p.into_inner()) = value; };
            if mode >= 3 {
                slate_ntfs_tools::recovery_io::rescue_to_with_progress(&source, &target, mode == 4, &mut update).map(|unresolved| {
                    if unresolved == 0 { OperationResult::new(Status::Success, "all sectors preserved in rescue archive; filesystem health not assessed") }
                    else { OperationResult::new(Status::VerificationFailed, format!("rescue scan complete; {unresolved} unresolved 512-byte sectors; readable data and damage records retained")) }
                })
            } else {
                let result = if mode == 0 { slate_ntfs_tools::recovery_io::repair_to(&source, &target, None, &mut update, Default::default()) }
                    else { slate_ntfs_tools::recovery_io::repair_in_place(&source, &target, mode == 2, &mut update, Default::default()) };
                result.map(|()| OperationResult::new(Status::Success, "repair complete; validation and durable publication finished"))
            }
        }));
        let result = match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => OperationResult::from_io(error),
            Err(_) => OperationResult::new(Status::Failure, "repair worker panicked; retain journal/intermediate image"),
        };
        if !result.is_success() {
            shared.lock().unwrap_or_else(|p| p.into_inner()).phase = 14;
        }
        result
    })?;
    Ok(RepairJob { progress, worker: std::sync::Mutex::new(Some(worker)), result: std::sync::Mutex::new(None) })
}

/// Publish a new image only when the external rescue archive contains every
/// original sector with consistent checksums and duplicate copies.
pub fn extract_rescue(archive: impl AsRef<Path>, destination: impl AsRef<Path>) -> OperationResult {
    match slate_ntfs_tools::recovery_io::extract_rescue_to(archive.as_ref(), destination.as_ref()) {
        Ok(sectors) => {
            OperationResult::new(Status::Success, format!("extracted {sectors} original sectors to a new image"))
        }
        Err(error) => OperationResult::from_io(error),
    }
}

/// Retry unresolved sectors from the original quiescent source, then extract
/// a complete new image. The archive remains the recovery authority.
pub fn reintegrate_rescue(
    source: impl AsRef<Path>,
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> OperationResult {
    match slate_ntfs_tools::recovery_io::reintegrate_rescue_to(
        source.as_ref(),
        archive.as_ref(),
        destination.as_ref(),
        &mut |_| {},
    ) {
        Ok(sectors) => {
            OperationResult::new(Status::Success, format!("reintegrated {sectors} original sectors into a new image"))
        }
        Err(error) => OperationResult::from_io(error),
    }
}

/// Publish a new audited image after retiring previously unreadable clusters
/// in standard $BadClus metadata and relocating every recoverable owner.
pub fn repair_rescue(
    source: impl AsRef<Path>,
    archive: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> OperationResult {
    match slate_ntfs_tools::recovery_io::repair_rescue_to(
        source.as_ref(),
        archive.as_ref(),
        destination.as_ref(),
        &mut |_| {},
    ) {
        Ok(sectors) => OperationResult::new(
            Status::Success,
            format!("repaired {sectors} original sectors into a new audited image"),
        ),
        Err(error) => OperationResult::from_io(error),
    }
}

#[derive(Clone, Debug)]
pub struct FormatOptions {
    pub label: String,
    /// Quick format rebuilds metadata; it does not erase old file contents.
    pub quick: bool,
    /// Zero selects the device logical sector size (512 for image files).
    pub sector_size: u32,
    /// Zero selects 4096, increasing as necessary for large volumes.
    pub cluster_size: u32,
    /// Zero uses the complete target. Otherwise count includes the backup boot sector.
    pub sectors: u64,
    pub partition_start: u32,
    pub heads: u16,
    pub sectors_per_track: u16,
    pub mft_zone_multiplier: u8,
    pub compression: bool,
    pub disable_indexing: bool,
    pub epoch_time: bool,
    pub with_uuid: bool,
    pub dry_run: bool,
}
impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            label: String::new(),
            quick: true,
            sector_size: 0,
            cluster_size: 0,
            sectors: 0,
            partition_start: 0,
            heads: 0,
            sectors_per_track: 0,
            mft_zone_multiplier: 1,
            compression: false,
            disable_indexing: false,
            epoch_time: false,
            with_uuid: false,
            dry_run: false,
        }
    }
}

fn error(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}
fn check_rc(rc: i32) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
fn same_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn unescape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b)) {
            let n = (bytes[i + 1] - b'0') as u16 * 64 + (bytes[i + 2] - b'0') as u16 * 8 + (bytes[i + 3] - b'0') as u16;
            if n <= 255 {
                out.push(n as u8);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Check every currently configured loop, including unmounted loops. Advisory
/// file locks cannot prevent another privileged process attaching a loop later.
fn image_in_use(meta: &fs::Metadata) -> io::Result<bool> {
    for entry in fs::read_dir("/sys/class/block")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_bytes = name.as_bytes();
        if !name_bytes.starts_with(b"loop") || name_bytes.len() <= 4 || !name_bytes[4..].iter().all(u8::is_ascii_digit)
        {
            continue;
        }
        let path = entry.path().join("loop/backing_file");
        match fs::read(&path) {
            Ok(mut bytes) => {
                if bytes.is_empty() {
                    continue;
                }
                // LOOP_GET_STATUS64 exposes the backing file's dev/inode,
                // even when its pathname belongs to a hidden host namespace
                // (as with WSL's Docker loop). This is stronger than path
                // comparison and detects hard-link aliases as well.
                let node = Path::new("/dev").join(&name);
                if let Ok(loop_file) = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
                    .open(node)
                {
                    let mut status = [0_u64; 29]; // struct loop_info64, 232 bytes
                    if unsafe { libc::ioctl(loop_file.as_raw_fd(), 0x4c05, status.as_mut_ptr()) } == 0 {
                        if status[0] == meta.dev() && status[1] == meta.ino() {
                            return Ok(true);
                        }
                        continue;
                    }
                }
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                let bytes = unescape(&bytes);
                let path = Path::new(std::ffi::OsStr::from_bytes(&bytes));
                match fs::metadata(path) {
                    Ok(backing) if same_inode(meta, &backing) => return Ok(true),
                    Ok(_) => (),
                    // An unresolved backing path cannot prove this image unused.
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "cannot verify {}/backing_file ({e}); query /dev/{} with sufficient permissions",
                                name.to_string_lossy(),
                                name.to_string_lossy()
                            ),
                        ))
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// Format an existing partition, whole-device NTFS volume, or regular image.
/// This destroys the old filesystem. Never creates a partition table or image.
/// Uses the caller's filesystem credentials, not a simulated UID/SID policy.
pub fn format_device(path: impl AsRef<Path>, options: &FormatOptions) -> OperationResult {
    if options.label.encode_utf16().count() > 128
        || options.label.chars().any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
    {
        return OperationResult::new(Status::InvalidArgument, "invalid NTFS volume label");
    }
    let operation = || -> io::Result<OperationResult> {
        let path = fs::canonicalize(path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(!options.dry_run)
            .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() && !meta.file_type().is_block_device() {
            return Err(error(libc::EINVAL));
        }
        // O_EXCL claims block devices through the kernel and rejects mounted
        // devices, held partitions, active swap and conflicting block holders.
        // flock is additional cooperative exclusion for regular image callers.
        check_rc(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) })?;
        if meta.is_file() {
            if meta.len() < 1024 * 1024 {
                return Err(error(libc::EINVAL));
            }
            if image_in_use(&meta)? {
                return Err(error(libc::EBUSY));
            }
        }
        let (size, device_sector) = if meta.is_file() {
            (meta.len(), 512_u32)
        } else {
            let mut logical_sector = 0_i32;
            let mut size = 0_u64;
            // Linux block ioctls on a held, exclusively claimed descriptor.
            check_rc(unsafe { libc::ioctl(file.as_raw_fd(), 0x1268, &mut logical_sector) })?;
            if options.sector_size != 0 && options.sector_size != logical_sector as u32 {
                return Err(error(libc::EINVAL));
            }
            check_rc(unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272_u64 as _, &mut size) })?;
            (size, logical_sector as u32)
        };
        let plan = crate::format_backend::Plan::new(size, options, device_sector)?;
        if options.dry_run {
            return Ok(OperationResult::new(Status::Success, plan.summary()));
        }
        if let Err(e) = plan.apply(&file, options.quick) {
            return Ok(OperationResult::new(
                Status::Failure,
                format!("native format failed: {e}; target may be partially formatted"),
            ));
        }
        // Success requires persistence and an independent shared-parser probe.
        // Verification failure is not rollback; formatting already took place.
        if let Err(e) = file.sync_all() {
            return Ok(OperationResult::new(Status::VerificationFailed, format!("formatted but flush failed: {e}")));
        }
        match crate::get_device(fd_path(&file)) {
            Ok(info) if !info.is_dirty && info.used_bytes.is_some() => {
                Ok(OperationResult::new(Status::Success, "formatted and verified NTFS; prior contents were destroyed"))
            }
            Ok(_) => Ok(OperationResult::new(Status::VerificationFailed, "formatted but volume verification failed")),
            Err(e) => {
                Ok(OperationResult::new(Status::VerificationFailed, format!("formatted but verification failed: {e}")))
            }
        }
    };
    operation().unwrap_or_else(OperationResult::from_io)
}

fn pin(path: impl AsRef<Path>) -> io::Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(path)?;
    if file.metadata()?.file_type().is_symlink() {
        return Err(error(libc::ELOOP));
    }
    Ok(file)
}
fn node(path: impl AsRef<Path>) -> io::Result<File> {
    let file = pin(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() && !meta.file_type().is_block_device() {
        return Err(error(libc::EINVAL));
    }
    Ok(file)
}
fn done(result: io::Result<()>) -> OperationResult {
    result
        .map(|()| OperationResult::new(Status::Success, "permission change applied"))
        .unwrap_or_else(OperationResult::from_io)
}
fn chmod(file: &File, mode: u32) -> io::Result<()> {
    if mode & !0o7777 != 0 {
        return Err(error(libc::EINVAL));
    }
    fs::set_permissions(fd_path(file), fs::Permissions::from_mode(mode))?;
    if file.metadata()?.mode() & 0o7777 != mode {
        return Err(error(libc::EOPNOTSUPP));
    }
    Ok(())
}
fn chown(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    // UINT32_MAX is reserved by chown for "unchanged", not a valid identity here.
    if uid == u32::MAX || gid == u32::MAX {
        return Err(error(libc::EINVAL));
    }
    check_rc(unsafe { libc::fchownat(file.as_raw_fd(), c"".as_ptr(), uid, gid, libc::AT_EMPTY_PATH) })?;
    let meta = file.metadata()?;
    if meta.uid() != uid || meta.gid() != gid {
        return Err(error(libc::EOPNOTSUPP));
    }
    Ok(())
}

pub fn set_device_mode(path: impl AsRef<Path>, mode: u32) -> OperationResult {
    done(node(path).and_then(|file| chmod(&file, mode)))
}
pub fn set_device_owner(path: impl AsRef<Path>, uid: u32, gid: u32) -> OperationResult {
    done(node(path).and_then(|file| chown(&file, uid, gid)))
}

// Resolve the held inode's actual mount ID, avoiding prefix matching, nested
// mount escapes, bind-mount ambiguity and path replacement during checks.
fn mounted_target(device: &Path, path: &Path) -> io::Result<(File, String)> {
    let file = pin(path)?;
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
    let id = fdinfo.lines().find_map(|l| l.strip_prefix("mnt_id:\t")).ok_or_else(|| error(libc::ENOTSUP))?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let fields: Vec<&str> = mountinfo
        .lines()
        .find(|l| l.split_whitespace().next() == Some(id))
        .ok_or_else(|| error(libc::ENOTSUP))?
        .split_whitespace()
        .collect();
    let sep = fields.iter().position(|s| *s == "-").ok_or_else(|| error(libc::EINVAL))?;
    if sep + 3 >= fields.len() {
        return Err(error(libc::EINVAL));
    }
    let kind = fields[sep + 1];
    if !["ntfsrs", "ntfs3", "fuseblk", "fuse.ntfs-3g"].contains(&kind) {
        return Err(error(libc::ENOTSUP));
    }
    let source = unescape(fields[sep + 2].as_bytes());
    let source_path = Path::new(std::ffi::OsStr::from_bytes(&source));
    let source_meta = fs::metadata(source_path)?;
    let selected = node(device)?;
    let selected_meta = selected.metadata()?;
    let matches = if selected_meta.file_type().is_block_device() {
        source_meta.file_type().is_block_device() && selected_meta.rdev() == source_meta.rdev()
    } else if source_meta.is_file() {
        same_inode(&selected_meta, &source_meta)
    } else if source_meta.file_type().is_block_device() {
        let dev = source_meta.rdev();
        let backing = fs::read(format!("/sys/dev/block/{}:{}/loop/backing_file", libc::major(dev), libc::minor(dev)))?;
        let bytes = unescape(backing.strip_suffix(b"\n").unwrap_or(&backing));
        same_inode(&selected_meta, &fs::metadata(Path::new(std::ffi::OsStr::from_bytes(&bytes)))?)
    } else {
        false
    };
    if !matches {
        return Err(error(libc::EXDEV));
    }
    // fuseblk is not specific to NTFS. Prove the selected source is NTFS.
    // This read also enforces access to the selected raw device; never elevates.
    crate::get_device(fd_path(&selected))?;
    Ok((file, kind.to_owned()))
}

/// POSIX mode/owner requests go through the mounted driver's mapping policy.
/// chmod can translate a native DACL; use set_file_security for exact ACEs.
pub fn set_file_mode(device: impl AsRef<Path>, path: impl AsRef<Path>, mode: u32) -> OperationResult {
    done(mounted_target(device.as_ref(), path.as_ref()).and_then(|(file, _)| chmod(&file, mode)))
}
pub fn set_file_owner(device: impl AsRef<Path>, path: impl AsRef<Path>, uid: u32, gid: u32) -> OperationResult {
    done(mounted_target(device.as_ref(), path.as_ref()).and_then(|(file, _)| chown(&file, uid, gid)))
}

/// Set an entire self-relative Windows descriptor without translating its ACEs.
/// This is an explicit replacement, not a merge. Backend authorization applies.
pub fn set_file_security(device: impl AsRef<Path>, path: impl AsRef<Path>, descriptor: &[u8]) -> OperationResult {
    if descriptor.len() > ntfs_rs::security::MAX_STORED_DESCRIPTOR
        || ntfs_rs::security::SecurityDescriptor::parse(descriptor).is_err()
    {
        return OperationResult::new(Status::InvalidArgument, "invalid self-relative security descriptor");
    }
    let result = (|| -> io::Result<OperationResult> {
        let (file, kind) = mounted_target(device.as_ref(), path.as_ref())?;
        let name = match kind.as_str() {
            // slate-ntfs uses the ntfs3 name and raw self-relative format;
            // it journals the change and republishes its descriptor cache.
            "ntfs3" | "ntfsrs" => c"system.ntfs_security",
            "fuseblk" | "fuse.ntfs-3g" => c"system.ntfs_acl",
            _ => return Err(error(libc::ENOTSUP)),
        };
        let path = CString::new(fd_path(&file).as_os_str().as_bytes()).unwrap();
        check_rc(unsafe {
            libc::setxattr(path.as_ptr(), name.as_ptr(), descriptor.as_ptr().cast(), descriptor.len(), 0)
        })?;
        let mut actual = vec![0; ntfs_rs::security::MAX_STORED_DESCRIPTOR];
        let len = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), actual.as_mut_ptr().cast(), actual.len()) };
        if len < 0 || &actual[..len.max(0) as usize] != descriptor {
            return Ok(OperationResult::new(
                Status::VerificationFailed,
                "ACL applied but exact descriptor readback failed; no rollback performed",
            ));
        }
        Ok(OperationResult::new(Status::Success, "native descriptor applied and verified"))
    })();
    result.unwrap_or_else(OperationResult::from_io)
}
