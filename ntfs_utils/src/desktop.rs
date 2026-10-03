//! Module: ntfs_utils::desktop
//! Purpose: Linux desktop policy and live, per-view directory visibility.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

//! Linux desktop policy and live, per-view directory visibility.
//! These calls never elevate credentials or rewrite NTFS metadata.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Visibility {
    pub show_hidden: bool,
    pub show_system: bool,
    pub show_metadata: bool,
}
impl Visibility {
    pub const fn all() -> Self {
        Self { show_hidden: true, show_system: true, show_metadata: true }
    }
    pub const fn flags(self) -> u32 {
        self.show_hidden as u32 | ((self.show_system as u32) << 1) | ((self.show_metadata as u32) << 2)
    }
    pub fn from_flags(flags: u32) -> io::Result<Self> {
        if flags & !7 != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown visibility flags"));
        }
        Ok(Self { show_hidden: flags & 1 != 0, show_system: flags & 2 != 0, show_metadata: flags & 4 != 0 })
    }
}

/// Root is required for a host view; an application may update its own delegated view.
/// New directory enumerations see the policy immediately. Already drawn file-manager
/// listings may need Refresh. Hidden files remain accessible by their explicit names.
pub fn set_visibility(path: impl AsRef<Path>, visibility: Visibility) -> io::Result<()> {
    let file = File::open(path)?;
    let flags = visibility.flags();
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x4004_4ee5u32 as _, &flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub fn get_visibility(path: impl AsRef<Path>) -> io::Result<Visibility> {
    let file = File::open(path)?;
    let mut flags = 0u32;
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x8004_4ee4u32 as _, &mut flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Visibility::from_flags(flags)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesktopPolicy {
    pub automount: bool,
    pub visibility: Visibility,
}
impl Default for DesktopPolicy {
    fn default() -> Self {
        Self { automount: true, visibility: Visibility::default() }
    }
}
const SETTINGS: &str = "/etc/slate-ntfs/settings.conf";
const RULE: &str = "/etc/udev/rules.d/99-slate-ntfs-policy.rules";

pub fn get_desktop_policy() -> io::Result<DesktopPolicy> {
    let text = match fs::read_to_string(SETTINGS) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DesktopPolicy::default()),
        Err(e) => return Err(e),
    };
    let mut policy = DesktopPolicy::default();
    for line in text.lines().map(str::trim).filter(|s| !s.is_empty() && !s.starts_with('#')) {
        let (key, value) =
            line.split_once('=').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "desktop policy syntax"))?;
        match key {
            "automount" => {
                policy.automount = match value {
                    "1" => true,
                    "0" => false,
                    _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "automount must be 0 or 1")),
                }
            }
            "visibility" => {
                policy.visibility = Visibility::from_flags(
                    value.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "visibility number"))?,
                )?
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown desktop setting")),
        }
    }
    Ok(policy)
}

fn atomic_write(path: &Path, text: &str) -> io::Result<()> {
    let parent = path.parent().unwrap();
    let temporary = parent.join(format!(".slate-policy-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Persistent host policy. Disabling automount leaves mounted filesystems intact.
/// Refreshes udev hints for existing devices as well as future hotplug events.
pub fn set_desktop_policy(policy: DesktopPolicy) -> io::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    fs::create_dir_all("/etc/slate-ntfs")?;
    fs::set_permissions("/etc/slate-ntfs", fs::Permissions::from_mode(0o755))?;
    let lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/etc/slate-ntfs/.policy.lock")?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let auto = u8::from(policy.automount);
    // With a custom root, the adapter prepares fstab before mounting; avoid
    // a desktop racing ahead and selecting its usual /media mountpoint.
    let hint = if Path::new("/etc/slate-ntfs/mount-root").exists() { 0 } else { auto };
    // Apply the discovery hint before enabling/disabling the service's durable setting.
    atomic_write(Path::new(RULE), &format!(
        "# Managed by ntfs_utils; independent of desktop environment.\nSUBSYSTEM==\"block\", ENV{{ID_FS_TYPE}}==\"ntfs\", ENV{{UDISKS_AUTO}}=\"{hint}\"\n"))?;
    atomic_write(Path::new(SETTINGS), &format!("automount={auto}\nvisibility={}\n", policy.visibility.flags()))?;
    for arguments in [vec!["control", "--reload-rules"], vec!["trigger", "--action=change", "--subsystem-match=block"]]
    {
        let status = std::process::Command::new("udevadm").args(arguments).status()?;
        if !status.success() {
            return Err(io::Error::other("policy saved, but udev refresh failed"));
        }
    }
    Ok(())
}
pub fn set_automount(enabled: bool) -> io::Result<()> {
    let mut policy = get_desktop_policy()?;
    policy.automount = enabled;
    set_desktop_policy(policy)
}

/// Desktop ownership is an explicit UID/SID projection for the user authorized
/// by UDisks. An administrator can supply a complete map in sidmap.conf instead.
pub fn desktop_mount_options(uid: u32, gid: u32) -> io::Result<String> {
    let visibility = get_desktop_policy()?.visibility.flags();
    let sidmap = match fs::read_to_string("/etc/slate-ntfs/sidmap.conf") {
        Ok(map) => map.trim().to_owned(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => desktop_sidmap(uid, gid)?,
        Err(e) => return Err(e),
    };
    ntfs_rs::identity::validate_sidmap(&sidmap)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(format!("compatibility=ntfs,visibility={visibility},sidmap={sidmap}"))
}

// Explicitly map all of the volume owner's Linux groups. An unmapped group
// would otherwise make native ACL evaluation reject ordinary desktop processes.
fn desktop_sidmap(uid: u32, gid: u32) -> io::Result<String> {
    let mut storage = vec![0u8; 65536];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let error = unsafe { libc::getpwuid_r(uid, &mut passwd, storage.as_mut_ptr().cast(), storage.len(), &mut result) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    if result.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown desktop UID"));
    }
    // Use the host's NSS implementation even when ntfs-run is musl-static.
    let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) }
        .to_str()
        .map_err(|_| io::Error::other("account name is not UTF-8"))?;
    let output = std::process::Command::new("/usr/bin/id").args(["--groups", "--", name]).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "cannot resolve desktop groups: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let mut groups = std::str::from_utf8(&output.stdout)
        .map_err(|_| io::Error::other("invalid group lookup output"))?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("invalid group ID"))?;
    if groups.is_empty() {
        return Err(io::Error::other("no groups returned for account"));
    }
    groups.extend([gid, 0]);
    groups.sort_unstable();
    groups.dedup();
    if groups.len() + if uid == 0 { 1 } else { 2 } > 64 {
        return Err(io::Error::other("identity map exceeds 64 entries; provide /etc/slate-ntfs/sidmap.conf"));
    }
    let mut entries = vec![format!("u:{uid}:S-1-5-32-544")];
    if uid != 0 {
        entries.push("u:0:S-1-5-18".to_owned());
    }
    for group in groups {
        let sid = if group == gid {
            "S-1-5-18".to_owned()
        } else if group == 0 {
            "S-1-5-32-544".to_owned()
        } else {
            format!("S-1-22-2-{group}")
        };
        entries.push(format!("g:{group}:{sid}"));
    }
    Ok(entries.join(";"))
}
