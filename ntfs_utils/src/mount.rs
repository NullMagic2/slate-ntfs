//! Module: ntfs_utils::mount
//! Purpose: Explicit mount policy.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

//! Explicit mount policy. Kernel authorization applies; no elevation or shell.
use crate::{OperationResult, Status};
use ntfs_rs::aes::wipe_bytes;
use ntfs_rs::bitlocker::FveVolume;
use ntfs_rs::sector::Method;
pub use slate_ntfs_tools::bitlocker_cli::{self, SecretInput, SecretSource};
use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::{Command, Stdio};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Compatibility {
    Linux = 0,
    #[default]
    Ntfs = 1,
}
impl Compatibility {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "linux" => Some(Self::Linux),
            "ntfs" => Some(Self::Ntfs),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Ntfs => "ntfs",
        }
    }
}

/// Who may access a mounted volume. Independent of [Compatibility], which
/// only selects how names, modes and metadata are presented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPolicy {
    /// Strict: evaluate each file's stored Windows ACL for the caller's
    /// mapped SIDs (the kernel default when no policy is given).
    Windows,
    /// NTFS-3G-style desktop mode: one owner, one group and read/write/
    /// execute bits for the whole mount. Stored Windows ownership and ACLs
    /// are preserved but not evaluated; chmod/chown succeed without effect.
    /// Read-only mounts and the Windows read-only attribute still apply.
    Desktop {
        uid: u32,
        gid: u32,
        /// Permission bits (0..=0o777) shown and enforced for files.
        file_mode: u32,
        /// Permission bits (0..=0o777) shown and enforced for directories.
        dir_mode: u32,
    },
}

impl AccessPolicy {
    /// Recommended desktop default: owner-only, files 0600, folders 0700.
    pub const fn private(uid: u32, gid: u32) -> Self {
        Self::Desktop { uid, gid, file_mode: 0o600, dir_mode: 0o700 }
    }
    /// Shared with one group: files 0660, folders 0770.
    pub const fn shared_group(uid: u32, gid: u32) -> Self {
        Self::Desktop { uid, gid, file_mode: 0o660, dir_mode: 0o770 }
    }
    /// Kernel mount options (NTFS-3G spelling: uid, gid, fmask, dmask).
    pub fn options(&self) -> Result<String, &'static str> {
        match *self {
            Self::Windows => Ok("permissions=windows".to_owned()),
            Self::Desktop { uid, gid, file_mode, dir_mode } => {
                if file_mode > 0o777 || dir_mode > 0o777 {
                    return Err("permission bits must be within 0777");
                }
                if uid == u32::MAX || gid == u32::MAX {
                    return Err("invalid uid/gid");
                }
                Ok(format!(
                    "permissions=desktop,uid={uid},gid={gid},fmask={:04o},dmask={:04o}",
                    0o777 & !file_mode,
                    0o777 & !dir_mode
                ))
            }
        }
    }
}

pub fn mount_options(sidmap: &str, compatibility: Compatibility) -> Result<String, ntfs_rs::Error> {
    ntfs_rs::identity::validate_sidmap(sidmap)?;
    Ok(format!("compatibility={},sidmap={sidmap}", compatibility.name()))
}

/// Mount a block device in the caller's current mount namespace. Use a loop
/// device for an image; this API never creates loops or changes namespaces.
/// BitLocker volumes are refused here; use [mount_fs_bitlocker].
pub fn mount_fs(
    device: &Path,
    target: &Path,
    sidmap: &str,
    compatibility: Compatibility,
    readonly: bool,
) -> OperationResult {
    let options = match mount_options(sidmap, compatibility) {
        Ok(s) => s,
        Err(e) => return OperationResult::new(Status::InvalidArgument, e.to_string()),
    };
    if let Ok(mut file) = std::fs::File::open(device) {
        if matches!(bitlocker_cli::probe_file(&mut file), Ok(Some(_))) {
            return OperationResult::new(
                Status::InvalidArgument,
                format!("BitLocker volume; unlock with {}", bitlocker_cli::USAGE),
            );
        }
    }
    mount_with_options(device, target, options, readonly, compatibility)
}

/// Mount with an explicit initial hidden-file policy. It can be changed later by set_visibility.
pub fn mount_fs_with_visibility(
    device: &Path,
    target: &Path,
    sidmap: &str,
    compatibility: Compatibility,
    readonly: bool,
    visibility: crate::Visibility,
) -> OperationResult {
    let options = match mount_options(sidmap, compatibility) {
        Ok(options) => format!("{options},visibility={}", visibility.flags()),
        Err(e) => return OperationResult::new(Status::InvalidArgument, e.to_string()),
    };
    mount_with_options(device, target, options, readonly, compatibility)
}

/// Unlock in user space, expose the verified NTFS view through dm-crypt and
/// dm-linear, then mount that view. The mappings are removed after unmount.
/// Volumes that are not fully encrypted mount read-only only.
pub fn mount_fs_bitlocker(
    device: &Path,
    target: &Path,
    sidmap: &str,
    compatibility: Compatibility,
    readonly: bool,
    input: &SecretInput,
) -> OperationResult {
    let options = match mount_options(sidmap, compatibility) {
        Ok(s) => s,
        Err(e) => return OperationResult::new(Status::InvalidArgument, e.to_string()),
    };
    let unlocked = (|| {
        let mut file = std::fs::File::open(device)?;
        let header = bitlocker_cli::probe_file(&mut file)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a BitLocker volume"))?;
        let (unlocked, file) = bitlocker_cli::unlock(file, header, input)?;
        let geometry = bitlocker_cli::volume_geometry(file, &unlocked)?;
        Ok::<_, std::io::Error>((unlocked, geometry))
    })();
    let (unlocked, geometry) = match unlocked {
        Ok(unlocked) => unlocked,
        Err(e) => {
            let status = match e.kind() {
                std::io::ErrorKind::PermissionDenied => Status::PermissionDenied,
                std::io::ErrorKind::InvalidInput => Status::InvalidArgument,
                _ => Status::Failure,
            };
            return OperationResult::new(status, e.to_string());
        }
    };
    if !readonly && !unlocked.info.fully_encrypted() {
        return OperationResult::new(
            Status::Unsupported,
            "BitLocker conversion is in progress or paused; mount with --read-only",
        );
    }
    let mapped = match map_bitlocker(device, &unlocked, &geometry, readonly) {
        Ok(mapped) => mapped,
        Err(e) => return OperationResult::new(Status::Failure, e.to_string()),
    };
    drop(geometry);
    drop(unlocked);
    let result = mount_with_options(&mapped.0, target, options, readonly, compatibility);
    if result.status != Status::Success {
        let _ = dm_remove(&mapped.1, false);
        let _ = dm_remove(&mapped.2, false);
        return result;
    }
    // Deferred removal retains both devices while the mounted filesystem holds
    // them open, and releases them without an ntfs-mount daemon at unmount.
    if let Err(e) = dm_remove(&mapped.2, true).and_then(|_| dm_remove(&mapped.1, true)) {
        if let Ok(target) = CString::new(target.as_os_str().as_bytes()) {
            if unsafe { libc::umount2(target.as_ptr(), 0) } == 0 {
                let _ = dm_remove(&mapped.1, false);
                let _ = dm_remove(&mapped.2, false);
                return OperationResult::new(Status::Failure, format!("mapping cleanup: {e}"));
            }
        }
        return OperationResult::new(Status::Failure, format!("mounted, but mapping cleanup failed: {e}"));
    }
    result
}

fn dm_run(args: &[&str], table: Option<&mut Vec<u8>>) -> std::io::Result<()> {
    let mut command = Command::new("dmsetup");
    command.args(args).stdout(Stdio::null()).stderr(Stdio::piped());
    if table.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            if let Some(table) = table {
                wipe_bytes(table);
            }
            return Err(error);
        }
    };
    if let Some(table) = table {
        let written = child.stdin.take().unwrap().write_all(table);
        wipe_bytes(table);
        if let Err(error) = written {
            let _ = child.wait();
            return Err(error);
        }
    }
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("dmsetup {}: {}", args[0], String::from_utf8_lossy(&output.stderr).trim())))
    }
}

fn dm_remove(name: &str, deferred: bool) -> std::io::Result<()> {
    if deferred {
        dm_run(&["remove", "--deferred", name], None)
    } else {
        dm_run(&["remove", name], None)
    }
}

fn map_bitlocker(
    device: &Path,
    unlocked: &bitlocker_cli::UnlockedVolume,
    geometry: &FveVolume,
    readonly: bool,
) -> std::io::Result<(std::path::PathBuf, String, String)> {
    let metadata = std::fs::metadata(device)?;
    if !metadata.file_type().is_block_device() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BitLocker mount requires a block device (use a loop device for an image)",
        ));
    }
    let source = format!("{}:{}", libc::major(metadata.rdev()), libc::minor(metadata.rdev()));
    let mut nonce = [0_u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let suffix = format!("{:016x}", u64::from_ne_bytes(nonce));
    let crypt = format!("slate-fve-{suffix}");
    let logical = format!("slate-ntfs-{suffix}");
    let cipher = match unlocked.key.method {
        Method::Aes128Diffuser | Method::Aes256Diffuser => "aes-cbc-elephant",
        Method::Aes128Cbc | Method::Aes256Cbc => "aes-cbc-eboiv",
        Method::Aes128Xts | Method::Aes256Xts => "aes-xts-plain64",
    };
    let key = unlocked.key.key_bytes();
    let mut table = Vec::with_capacity(256);
    write!(&mut table, "0 {} crypt {cipher} ", geometry.device_bytes() / 512)?;
    // The 128-bit Elephant FVEK has a reserved 16-byte gap between its AES
    // data and sector-key halves; dm-crypt takes those halves contiguously.
    for &byte in match unlocked.key.method {
        Method::Aes128Diffuser => &key[..16],
        _ => key,
    } {
        write!(&mut table, "{byte:02x}")?;
    }
    if unlocked.key.method == Method::Aes128Diffuser {
        for &byte in &key[32..48] {
            write!(&mut table, "{byte:02x}")?;
        }
    }
    write!(&mut table, " 0 {source} 0")?;
    if geometry.sector_bytes() > 512 {
        write!(&mut table, " 2 sector_size:{} iv_large_sectors", geometry.sector_bytes())?;
    }
    table.push(b'\n');
    let crypt_result = if readonly {
        dm_run(&["--readonly", "create", &crypt], Some(&mut table))
    } else {
        dm_run(&["create", &crypt], Some(&mut table))
    };
    crypt_result?;
    let (header_bytes, header_offset) = geometry.header_mapping();
    let mut cuts = vec![header_bytes, geometry.device_bytes()];
    for &(start, length) in geometry.protected_ranges() {
        if length > 0 {
            cuts.push(start);
            cuts.push(start + length);
        }
    }
    if geometry.encrypted_limit() < geometry.device_bytes() {
        cuts.push(geometry.encrypted_limit());
    }
    cuts.sort_unstable();
    cuts.dedup();
    let crypt_dev = format!("/dev/mapper/{crypt}");
    let mut table = format!("0 {} linear {crypt_dev} {}\n", header_bytes / 512, header_offset / 512).into_bytes();
    for pair in cuts.windows(2) {
        let (start, end) = (pair[0], pair[1]);
        if start < header_bytes || start >= geometry.device_bytes() || start == end {
            continue;
        }
        let protected = geometry.protected_ranges().iter().any(|&(p, len)| len > 0 && start >= p && start < p + len);
        if protected {
            write!(&mut table, "{} {} error\n", start / 512, (end - start) / 512)?;
        } else {
            let backing = if start >= geometry.encrypted_limit() { &source } else { &crypt_dev };
            write!(&mut table, "{} {} linear {backing} {}\n", start / 512, (end - start) / 512, start / 512)?;
        }
    }
    let logical_result = if readonly {
        dm_run(&["--readonly", "create", &logical], Some(&mut table))
    } else {
        dm_run(&["create", &logical], Some(&mut table))
    };
    if let Err(e) = logical_result {
        let _ = dm_remove(&crypt, false);
        return Err(e);
    }
    Ok((format!("/dev/mapper/{logical}").into(), logical, crypt))
}

fn mount_with_options(
    device: &Path,
    target: &Path,
    options: String,
    readonly: bool,
    compatibility: Compatibility,
) -> OperationResult {
    if device.as_os_str().is_empty() || target.as_os_str().is_empty() {
        return OperationResult::new(Status::InvalidArgument, "device and target are required");
    }
    if let Ok(mut file) = std::fs::File::open(device) {
        if matches!(bitlocker_cli::probe_file(&mut file), Ok(Some(_))) {
            return OperationResult::new(
                Status::InvalidArgument,
                format!("BitLocker volume; unlock with {}", bitlocker_cli::USAGE),
            );
        }
    }
    let strings = [
        CString::new(device.as_os_str().as_bytes()),
        CString::new(target.as_os_str().as_bytes()),
        CString::new(options),
    ];
    let [Ok(device), Ok(target), Ok(options)] = strings else {
        return OperationResult::new(Status::InvalidArgument, "embedded NUL");
    };
    let flags = libc::MS_NODEV | libc::MS_NOSUID | if readonly { libc::MS_RDONLY } else { 0 };
    // Pointers remain alive for the synchronous mount syscall. This uses the
    // caller's credentials and namespace; kernel mount checks are authoritative.
    if unsafe { libc::mount(device.as_ptr(), target.as_ptr(), c"ntfsrs".as_ptr(), flags, options.as_ptr().cast()) } != 0
    {
        let e = std::io::Error::last_os_error();
        let status = match e.raw_os_error() {
            Some(libc::EPERM | libc::EACCES | libc::ENOKEY | libc::EKEYREJECTED) => Status::PermissionDenied,
            Some(libc::EBUSY) => Status::Busy,
            Some(libc::EINVAL) => Status::InvalidArgument,
            Some(libc::ENODEV | libc::ENOSYS | libc::EOPNOTSUPP) => Status::Unsupported,
            _ => Status::Failure,
        };
        let detail = if e.raw_os_error() == Some(libc::EOPNOTSUPP) {
            " Check the kernel journal for the rejected NTFS feature; use an explicit read-only mount for diagnosis."
        } else {
            ""
        };
        return OperationResult::new(status, format!("mount {}: {e}.{detail}", target.to_string_lossy()));
    }
    OperationResult::new(Status::Success, format!("mounted with compatibility={}", compatibility.name()))
}

/// Mount with an explicit access policy. With sidmap == None the desktop
/// SID map for the policy owner (or the caller) is generated; in desktop mode
/// it also maps the chosen group, so files created by anyone record the owner.
pub fn mount_fs_with_access(
    device: &Path,
    target: &Path,
    sidmap: Option<&str>,
    compatibility: Compatibility,
    readonly: bool,
    visibility: crate::Visibility,
    access: AccessPolicy,
) -> OperationResult {
    let access_options = match access.options() {
        Ok(options) => options,
        Err(e) => return OperationResult::new(Status::InvalidArgument, e),
    };
    let generated;
    let map = match (sidmap, access) {
        (Some(map), _) => map,
        (None, AccessPolicy::Desktop { uid, gid, .. }) => {
            generated = match crate::desktop::desktop_mount_options(uid, gid) {
                Ok(options) => options,
                Err(e) => return OperationResult::new(Status::InvalidArgument, e.to_string()),
            };
            match generated.split(',').find_map(|s| s.strip_prefix("sidmap=")) {
                Some(map) => map,
                None => return OperationResult::new(Status::InvalidArgument, "missing desktop SID map"),
            }
        }
        (None, AccessPolicy::Windows) => {
            return OperationResult::new(
                Status::InvalidArgument,
                "windows permissions need an explicit SID map (or use mount_fs_for_user)",
            );
        }
    };
    let options = match mount_options(map, compatibility) {
        Ok(options) => format!("{options},visibility={},{access_options}", visibility.flags()),
        Err(e) => return OperationResult::new(Status::InvalidArgument, e.to_string()),
    };
    mount_with_options(device, target, options, readonly, compatibility)
}

/// Mount using the configured desktop SID map, or an identity map for uid/gid.
/// Caller privileges and namespace apply. The target must already exist.
pub fn mount_fs_for_user(
    device: &Path,
    target: &Path,
    uid: u32,
    gid: u32,
    compatibility: Compatibility,
    readonly: bool,
    visibility: crate::Visibility,
) -> OperationResult {
    let options = match crate::desktop::desktop_mount_options(uid, gid) {
        Ok(options) => options,
        Err(e) => return OperationResult::new(Status::InvalidArgument, e.to_string()),
    };
    let Some(map) = options.split(',').find_map(|s| s.strip_prefix("sidmap=")) else {
        return OperationResult::new(Status::InvalidArgument, "missing desktop SID map");
    };
    mount_fs_with_visibility(device, target, map, compatibility, readonly, visibility)
}

/// Normal unmount in the caller's namespace. Busy filesystems remain mounted.
/// No lazy detach, force, privilege elevation, or target-directory removal.
pub fn unmount_fs(target: &Path) -> OperationResult {
    let target = match CString::new(target.as_os_str().as_bytes()) {
        Ok(s) if !s.as_bytes().is_empty() => s,
        _ => return OperationResult::new(Status::InvalidArgument, "empty path or embedded NUL"),
    };
    if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        let status = match e.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => Status::PermissionDenied,
            Some(libc::EBUSY) => Status::Busy,
            Some(libc::EINVAL | libc::ENOENT) => Status::InvalidArgument,
            _ => Status::Failure,
        };
        return OperationResult::new(status, format!("unmount {}: {e}", target.to_string_lossy()));
    }
    OperationResult::new(Status::Success, "unmounted")
}

#[cfg(test)]
mod access_tests {
    use super::AccessPolicy;

    #[test]
    fn desktop_options_use_ntfs3g_spelling() {
        assert_eq!(
            AccessPolicy::private(1000, 1000).options().unwrap(),
            "permissions=desktop,uid=1000,gid=1000,fmask=0177,dmask=0077"
        );
        assert_eq!(
            AccessPolicy::shared_group(1000, 1500).options().unwrap(),
            "permissions=desktop,uid=1000,gid=1500,fmask=0117,dmask=0007"
        );
        assert_eq!(AccessPolicy::Windows.options().unwrap(), "permissions=windows");
    }

    #[test]
    fn desktop_options_reject_out_of_range_values() {
        assert!(AccessPolicy::Desktop { uid: 1, gid: 1, file_mode: 0o1777, dir_mode: 0o700 }.options().is_err());
        assert!(AccessPolicy::Desktop { uid: u32::MAX, gid: 1, file_mode: 0o600, dir_mode: 0o700 }.options().is_err());
    }
}
