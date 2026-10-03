//! Module: ntfs_utils::lib
//! Purpose: Read-only NTFS device information without modifying its input.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use the shared NTFS core and tools.

pub mod admin;
pub mod desktop;
pub use desktop::{
    get_desktop_policy, get_visibility, set_automount, set_desktop_policy, set_visibility, DesktopPolicy, Visibility,
};
pub mod application;
pub use application::{spawn_application, ApplicationOptions};
pub mod mount;
pub use mount::{
    mount_fs, mount_fs_for_user, mount_fs_with_access, mount_fs_with_visibility, unmount_fs, AccessPolicy,
    Compatibility,
};
mod ffi;
mod format_backend;
mod format_tables;
pub use admin::{extract_rescue, reintegrate_rescue, repair_rescue};
pub use admin::{format_device, FormatOptions, OperationResult, Status};
pub use admin::{start_repair, RepairJob};
pub use slate_ntfs_tools::checker::CheckReport;
pub use slate_ntfs_tools::recovery_io::RepairProgress;

/// Read-only, complete supported structural check of an offline device/image.
/// A successful call can report damage: inspect report.passed() and findings.
pub fn check_device(path: impl AsRef<std::path::Path>) -> std::io::Result<CheckReport> {
    slate_ntfs_tools::checker::check_device(path.as_ref(), Default::default(), None)
}

/// Check and optionally save the complete findings report to a new file.
pub fn check_device_with_log(
    path: impl AsRef<std::path::Path>,
    log: Option<&std::path::Path>,
) -> std::io::Result<CheckReport> {
    slate_ntfs_tools::checker::check_device(path.as_ref(), Default::default(), log)
}

use ntfs_rs::boot::BootSector;
use ntfs_rs::volume::Volume;
use slate_ntfs_tools::checker::Image;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DeviceKind {
    Other = 0,
    Hdd = 1,
    Ssd = 2,
    UsbStick = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanIssue {
    pub path: PathBuf,
    pub error: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanReport {
    pub devices: Vec<DeviceInfo>,
    /// Paths that could not be read or contained NTFS-looking but invalid data.
    pub skipped: Vec<ScanIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub path: PathBuf,
    pub kind: DeviceKind,
    pub is_dirty: bool,
    pub volume_flags: u16,
    pub volume_size_bytes: u64,
    /// Full parent hardware disk capacity; unknown for images or virtual devices.
    pub physical_size_bytes: Option<u64>,
    /// Whole clusters addressable by NTFS; may be smaller than volume size.
    pub allocatable_bytes: u64,
    /// Clusters marked allocated in NTFS $Bitmap, including metadata.
    pub used_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
    pub cluster_size_bytes: u32,
    pub volume_serial: u64,
    /// Hardware vendor, when Linux device metadata provides one.
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

impl DeviceInfo {
    pub fn check(&self) -> io::Result<CheckReport> {
        check_device(&self.path)
    }
    pub fn check_with_log(&self, log: Option<&Path>) -> io::Result<CheckReport> {
        check_device_with_log(&self.path, log)
    }
    /// Destructive, explicit reformat. This snapshot becomes stale on success.
    pub fn format_fs(&self, options: &FormatOptions) -> OperationResult {
        format_device(&self.path, options)
    }
}

fn invalid(error: ntfs_rs::Error) -> io::Error {
    let kind = match error {
        ntfs_rs::Error::Io => io::ErrorKind::Other,
        ntfs_rs::Error::Unsupported => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, error.to_string())
}

/// Exact descriptor snapshot, including the original ordered ACEs. This does
/// not map Linux identities or authorize access to a concurrently mounted file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSecurity {
    descriptor: Vec<u8>,
}

impl FileSecurity {
    pub fn raw(&self) -> &[u8] {
        &self.descriptor
    }

    /// Evaluate the supported discretionary policy for an explicitly resolved
    /// unrestricted Windows token. Unsupported policies return an error.
    pub fn check_access(&self, token: &ntfs_rs::security::FileAccessToken<'_>, mask: u32) -> io::Result<bool> {
        ntfs_rs::security::SecurityDescriptor::parse(&self.descriptor)
            .and_then(|sd| sd.check_file_access(token, mask))
            .map_err(invalid)
    }
}

/// Read-only snapshot by NTFS file reference (low 48 bits record number, high
/// 16 bits sequence). Reused/deallocated records are rejected. Use an offline
/// image or otherwise quiesced device; this API cannot lock another filesystem.
pub fn get_file_security(path: impl AsRef<Path>, file_reference: u64) -> io::Result<FileSecurity> {
    use ntfs_rs::mft::{MftRecord, ATTR_BITMAP};
    let mut file = File::open(path)?;
    let mut sector = [0; 512];
    file.read_exact(&mut sector)?;
    let boot = BootSector::parse(&sector).map_err(invalid)?;
    let mut volume = Volume::new(Image(file), boot).map_err(invalid)?;
    let mut zero = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut zero).map_err(invalid)?;
    let mft = MftRecord::parse(&mut zero, boot.bytes_per_sector).map_err(invalid)?;
    let number = file_reference & 0x0000_ffff_ffff_ffff;
    let mut bitmap = None;
    for attr in mft.attributes() {
        let attr = attr.map_err(invalid)?;
        if attr.kind == ATTR_BITMAP
            && attr.name_utf16le().map_err(invalid)?.is_empty()
            && bitmap.replace(attr).is_some()
        {
            return Err(invalid(ntfs_rs::Error::InvalidRecord));
        }
    }
    let mut bit = [0];
    volume
        .read_attribute(bitmap.ok_or_else(|| invalid(ntfs_rs::Error::Unsupported))?, number / 8, &mut bit)
        .map_err(invalid)?;
    if bit[0] & (1 << (number % 8)) == 0 {
        return Err(invalid(ntfs_rs::Error::InvalidRecord));
    }
    let mut record = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, number, &mut record).map_err(invalid)?;
    let record = MftRecord::parse(&mut record, boot.bytes_per_sector).map_err(invalid)?;
    if record.sequence_number().map_err(invalid)? != (file_reference >> 48) as u16 {
        return Err(invalid(ntfs_rs::Error::InvalidRecord));
    }
    let mut secure = vec![0; boot.record_bytes as usize];
    let mut index = vec![0; boot.index_block_bytes as usize];
    let mut result = vec![0; 0x20014];
    let sd = ntfs_rs::security_store::read_descriptor(&mut volume, &mft, &record, &mut secure, &mut index, &mut result)
        .map_err(invalid)?;
    Ok(FileSecurity { descriptor: sd.raw().to_vec() })
}

pub fn get_device(path: impl AsRef<Path>) -> io::Result<DeviceInfo> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut sector = [0_u8; 512];
    file.read_exact(&mut sector)?;
    let boot = BootSector::parse(&sector).map_err(invalid)?;
    let volume_size_bytes = boot
        .total_sectors
        .checked_mul(u64::from(boot.bytes_per_sector))
        .ok_or_else(|| invalid(ntfs_rs::Error::Overflow))?;
    let total_clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let allocatable_bytes =
        total_clusters.checked_mul(u64::from(boot.cluster_bytes)).ok_or_else(|| invalid(ntfs_rs::Error::Overflow))?;
    let metadata = file.metadata()?;
    if metadata.is_file() && metadata.len() < volume_size_bytes {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "image is shorter than its NTFS volume geometry"));
    }
    let mut volume = Volume::new(Image(file), boot).map_err(invalid)?;
    let record_size = boot.record_bytes as usize;
    let mut mft = vec![0_u8; record_size];
    let mut record = vec![0_u8; record_size];
    let info = volume.read_volume_info(&mut mft, &mut record).map_err(invalid)?;
    let mut extension = vec![0_u8; record_size];
    let mut chunk = vec![0_u8; 64 * 1024];
    let used_bytes = match volume.allocated_clusters(&mut mft, &mut record, &mut extension, &mut chunk) {
        Ok(clusters) => {
            Some(clusters.checked_mul(u64::from(boot.cluster_bytes)).ok_or_else(|| invalid(ntfs_rs::Error::Overflow))?)
        }
        Err(ntfs_rs::Error::Unsupported) => None,
        Err(error) => return Err(invalid(error)),
    };
    let free_bytes = used_bytes
        .map(|used| allocatable_bytes.checked_sub(used).ok_or_else(|| invalid(ntfs_rs::Error::InvalidAttribute)))
        .transpose()?;
    let (manufacturer, model) = hardware_identity(path);
    Ok(DeviceInfo {
        path: path.to_path_buf(),
        kind: device_kind(path),
        is_dirty: info.is_dirty(),
        volume_flags: info.flags,
        volume_size_bytes,
        physical_size_bytes: physical_capacity(path),
        allocatable_bytes,
        used_bytes,
        free_bytes,
        cluster_size_bytes: boot.cluster_bytes,
        volume_serial: boot.serial_number,
        manufacturer,
        model,
    })
}

fn classify(rotational: Option<bool>, removable: Option<bool>, usb: bool) -> DeviceKind {
    if usb && removable == Some(true) {
        DeviceKind::UsbStick
    } else {
        match rotational {
            Some(true) => DeviceKind::Hdd,
            Some(false) => DeviceKind::Ssd,
            None => DeviceKind::Other,
        }
    }
}

/// Enumerate Linux block devices, including NTFS partitions and whole-disk volumes.
/// Devices are opened read-only. An unreadable or damaged candidate is reported
/// in skipped; callers needing a complete inventory should inspect it.
pub fn scan_ntfs_devices() -> io::Result<ScanReport> {
    let mut report = ScanReport::default();
    for entry in fs::read_dir("/sys/class/block")? {
        let entry = entry?;
        let path = Path::new("/dev").join(entry.file_name());
        if fs::read_to_string(entry.path().join("size")).ok().is_some_and(|size| size.trim() == "0") {
            continue;
        }
        if !path.exists() {
            continue;
        }
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) => {
                report.skipped.push(ScanIssue { path, error: error.to_string() });
                continue;
            }
        };
        let mut sector = [0_u8; 512];
        if let Err(error) = file.read_exact(&mut sector) {
            report.skipped.push(ScanIssue { path, error: error.to_string() });
            continue;
        }
        if &sector[3..11] != b"NTFS    " {
            continue;
        }
        match get_device(&path) {
            Ok(info) => report.devices.push(info),
            Err(error) => report.skipped.push(ScanIssue { path, error: error.to_string() }),
        }
    }
    report.devices.sort_by(|a, b| a.path.cmp(&b.path));
    report.skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(report)
}

pub fn list_ntfs_devices() -> io::Result<Vec<DeviceInfo>> {
    Ok(scan_ntfs_devices()?.devices)
}

fn list_kind(kind: DeviceKind) -> io::Result<Vec<DeviceInfo>> {
    Ok(scan_ntfs_devices()?.devices.into_iter().filter(|d| d.kind == kind).collect())
}

pub fn list_ntfs_hdds() -> io::Result<Vec<DeviceInfo>> {
    list_kind(DeviceKind::Hdd)
}
pub fn list_ntfs_ssds() -> io::Result<Vec<DeviceInfo>> {
    list_kind(DeviceKind::Ssd)
}
pub fn list_ntfs_usb_sticks() -> io::Result<Vec<DeviceInfo>> {
    list_kind(DeviceKind::UsbStick)
}

fn block_device_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = fs::metadata(path).ok()?;
    if !metadata.file_type().is_block_device() {
        return None;
    }
    let device = metadata.rdev();
    Some((u64::from(libc::major(device)), u64::from(libc::minor(device))))
}

fn device_kind(path: &Path) -> DeviceKind {
    let Some((major, minor)) = block_device_id(path) else {
        return DeviceKind::Other;
    };
    let Ok(node) = fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")) else {
        return DeviceKind::Other;
    };
    if node.starts_with("/sys/devices/virtual") {
        return DeviceKind::Other;
    }
    let disk = node.ancestors().find(|ancestor| ancestor.join("queue/rotational").exists());
    let rotational = disk.and_then(|dir| read_sysfs_bool(&dir.join("queue/rotational")));
    let removable = disk.and_then(|dir| read_sysfs_bool(&dir.join("removable")));
    let usb_sysfs = disk.is_some_and(|dir| {
        dir.ancestors().any(|ancestor| {
            fs::canonicalize(ancestor.join("subsystem")).ok().is_some_and(|subsystem| subsystem.ends_with("usb"))
        })
    });
    let usb_udev = [
        format!("/run/udev/data/b{major}:{minor}"),
        disk.map(|dir| {
            let dev = fs::read_to_string(dir.join("dev")).unwrap_or_default();
            format!("/run/udev/data/b{}", dev.trim())
        })
        .unwrap_or_default(),
    ]
    .iter()
    .any(|file| fs::read_to_string(file).ok().is_some_and(|value| value.lines().any(|line| line == "E:ID_BUS=usb")));
    classify(rotational, removable, usb_sysfs || usb_udev)
}

fn read_sysfs_bool(path: &Path) -> Option<bool> {
    match fs::read_to_string(path).ok()?.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_and_media_classification() {
        assert_eq!(classify(Some(false), Some(true), true), DeviceKind::UsbStick);
        assert_eq!(classify(Some(true), Some(true), true), DeviceKind::UsbStick);
        assert_eq!(classify(Some(false), Some(false), true), DeviceKind::Ssd);
        assert_eq!(classify(Some(true), None, false), DeviceKind::Hdd);
        assert_eq!(classify(None, None, false), DeviceKind::Other);
    }
}

/// Read the capacity of the containing hardware disk without reading NTFS.
/// Linux sysfs reports size in 512-byte sectors, including on 4K-sector disks.
/// Partition nodes resolve to their parent disk; virtual devices and images
/// have no single hardware capacity and return None.
pub fn physical_capacity(path: impl AsRef<Path>) -> Option<u64> {
    let (major, minor) = block_device_id(path.as_ref())?;
    let node = fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()?;
    let disk = if node.join("partition").is_file() { node.parent()? } else { node.as_path() };
    if disk.starts_with("/sys/devices/virtual") || !disk.join("device").exists() {
        return None;
    }
    let sectors = fs::read_to_string(disk.join("size")).ok()?.trim().parse::<u64>().ok()?;
    sectors.checked_mul(512).filter(|bytes| *bytes != 0)
}

fn hardware_identity(path: &Path) -> (Option<String>, Option<String>) {
    let Some((major, minor)) = block_device_id(path) else {
        return (None, None);
    };
    if let Some(vendor) = udev_vendor(major, minor) {
        let model = sysfs_identity(major, minor).1;
        return (Some(vendor), model);
    }
    sysfs_identity(major, minor)
}

fn udev_vendor(major: u64, minor: u64) -> Option<String> {
    let content = fs::read_to_string(format!("/run/udev/data/b{major}:{minor}")).ok()?;
    for key in ["E:ID_VENDOR_FROM_DATABASE=", "E:ID_VENDOR="] {
        if let Some(value) = content.lines().find_map(|line| line.strip_prefix(key)).filter(|value| !value.is_empty()) {
            return Some(value.replace('_', " "));
        }
    }
    None
}

fn sysfs_identity(major: u64, minor: u64) -> (Option<String>, Option<String>) {
    let Ok(node) = fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")) else {
        return (None, None);
    };
    for ancestor in node.ancestors() {
        if ancestor.file_name().is_some_and(|name| name == "block") {
            break;
        }
        let vendor = read_sysfs_text(&ancestor.join("device/vendor"));
        let model = read_sysfs_text(&ancestor.join("device/model"));
        if vendor.is_some() || model.is_some() {
            let vendor = vendor.filter(|value| value != "ATA" && value != "NVMe");
            return (vendor, model);
        }
    }
    (None, None)
}

fn read_sysfs_text(path: &Path) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    if value.is_empty() || value.starts_with("0x") {
        None
    } else {
        Some(value.to_owned())
    }
}
