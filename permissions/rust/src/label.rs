//! Module: ntfs_permissions::label
//! Purpose: Rename the NTFS volume label and notify desktop device observers.
//! Created: 2026-10-01
//! Architecture: Mounted drives use the driver's journaled label ioctl; offline drives use
//! the same writer under an exclusive device claim. udev receives the result.

use crate::core::{list_drives, Applied, Outcome};
use ntfs_rs::boot::BootSector;
use ntfs_rs::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use ntfs_rs::volume::ReadAt;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::process::Command;

/// Windows Explorer shows at most 32 characters for an NTFS label.
pub const MAX_LABEL_CHARS: usize = 32;
/// FS_IOC_SETFSLABEL = _IOW(0x94, 50, char[FSLABEL_MAX = 256]).
const FS_IOC_SETFSLABEL: libc::c_ulong = 0x4100_9432;

/// The label as stored on the drive, or the reason it cannot be used.
pub fn validate_label(label: &str) -> Result<Vec<u16>, &'static str> {
    if label.trim().is_empty() {
        return Err("Type a name for the drive.");
    }
    if label.chars().any(char::is_control) {
        return Err("The name cannot contain control characters.");
    }
    let units: Vec<u16> = label.encode_utf16().collect();
    if units.len() > MAX_LABEL_CHARS {
        return Err("The name can have at most 32 characters.");
    }
    Ok(units)
}

fn findmnt(device: &str) -> Option<(String, String, String)> {
    let output =
        Command::new("findmnt").args(["-rn", "-o", "TARGET,FSTYPE,VFS-OPTIONS", "--source", device]).output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;
    let mut fields = line.split(' ');
    let unescape = |s: &str| s.replace("\\x20", " ").replace("\\x5c", "\\");
    Some((unescape(fields.next()?), fields.next()?.to_owned(), fields.next().unwrap_or("").to_owned()))
}

struct DeviceIo(File);

impl ReadAt for DeviceIo {
    fn read_exact_at(&mut self, offset: u64, data: &mut [u8]) -> ntfs_rs::Result<()> {
        FileExt::read_exact_at(&self.0, data, offset).map_err(|_| ntfs_rs::Error::Io)
    }
}

impl WriteIo for DeviceIo {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> ntfs_rs::Result<()> {
        self.0.write_all_at(data, offset).map_err(|_| ntfs_rs::Error::Io)
    }
    fn flush(&mut self) -> ntfs_rs::Result<()> {
        self.0.sync_data().map_err(|_| ntfs_rs::Error::Io)
    }
}

/// Rename a drive that is not open, with the driver's own journaled writer.
/// The device is opened exclusively, so nothing can mount it meanwhile.
pub fn relabel_offline(device: &str, units: &[u16]) -> Result<(), String> {
    let file =
        OpenOptions::new().read(true).write(true).custom_flags(libc::O_EXCL).open(device).map_err(|e| e.to_string())?;
    let mut io = DeviceIo(file);
    let mut raw = [0u8; 512];
    io.read_exact_at(0, &mut raw).map_err(|e| format!("{e:?}"))?;
    let boot = BootSector::parse(&raw).map_err(|e| format!("{e:?}"))?;
    let mut scratch = vec![0u8; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut io, boot, &mut scratch).map_err(|e| format!("{e:?}"))?;
    writer.initialize(&mut io, &mut scratch).map_err(|e| format!("{e:?}"))?;
    let renamed = writer.set_volume_label(&mut io, units, &mut scratch);
    // Always close the session cleanly when possible, even after a refusal.
    let finished = writer.finish(&mut io, &mut scratch);
    renamed.map_err(|e| format!("{e:?}"))?;
    finished.map_err(|e| format!("{e:?}"))?;
    io.0.sync_all().map_err(|e| e.to_string())
}

/// Ask the mounted Slate driver to rename the drive in place.
fn relabel_mounted(target: &str, label: &str) -> std::io::Result<()> {
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(target)?;
    let mut buffer = [0u8; 256];
    buffer[..label.len()].copy_from_slice(label.as_bytes());
    // SAFETY: the buffer is FSLABEL_MAX bytes and NUL-terminated.
    if unsafe { libc::ioctl(dir.as_raw_fd(), FS_IOC_SETFSLABEL as _, buffer.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Rename the NTFS drive with this UUID. Root only.
pub fn rename_drive(uuid: &str, label: &str) -> Outcome {
    let units = match validate_label(label) {
        Ok(units) => units,
        Err(message) => return Outcome::new(Applied::Error, message, ""),
    };
    let drives = list_drives().unwrap_or_default();
    let Some(drive) = drives.iter().find(|d| d.uuid.eq_ignore_ascii_case(uuid)) else {
        return Outcome::new(Applied::Error, "The drive is no longer connected.", "");
    };
    if drive.label == label {
        return Outcome::new(Applied::Applied, "Drive renamed.", "");
    }
    match findmnt(&drive.device) {
        Some((target, fstype, options)) => {
            if fstype != "ntfsrs" {
                return Outcome::new(
                    Applied::Error,
                    "The drive is open with another NTFS driver. Close it in the file manager and try again.",
                    fstype,
                );
            }
            if options.split(',').any(|o| o == "ro") {
                return Outcome::new(Applied::Error,
                    "The drive is open read-only, so it cannot be renamed. If Windows uses Fast Startup or hibernation, shut Windows down completely first.", "");
            }
            if let Err(error) = relabel_mounted(&target, label) {
                return match error.raw_os_error() {
                    Some(libc::ENOTTY) => Outcome::new(Applied::Error,
                        "Restart the computer once to load the updated driver; after that, drives can be renamed.", ""),
                    Some(libc::EPERM) | Some(libc::EACCES) => Outcome::new(Applied::Error,
                        "Only an administrator can rename drives.", ""),
                    Some(libc::EROFS) => Outcome::new(Applied::Error,
                        "The drive is open read-only, so it cannot be renamed. If Windows uses Fast Startup or hibernation, shut Windows down completely first.", ""),
                    _ => Outcome::new(Applied::Error, "Could not rename the drive:", error.to_string()),
                };
            }
        }
        None => {
            if let Err(detail) = relabel_offline(&drive.device, &units) {
                return Outcome::new(Applied::Error, "Could not rename the drive:", detail);
            }
        }
    }
    // udisks re-reads the label on "change"; the desktop and file managers follow.
    let _ = Command::new("udevadm").args(["trigger", "--action=change", &drive.device]).status();
    let _ = Command::new("udevadm").args(["settle", "--timeout=5"]).status();
    Outcome::new(Applied::Applied, "Drive renamed.", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_checked() {
        assert!(validate_label("Novo volume").is_ok());
        assert!(validate_label("Δίσκος ✓").is_ok());
        assert!(validate_label("   ").is_err());
        assert!(validate_label("a\tb").is_err());
        assert!(validate_label(&"x".repeat(33)).is_err());
        assert_eq!(validate_label(&"é".repeat(32)).unwrap().len(), 32);
    }

    /// SLATE_LABEL_IMAGE=<disposable NTFS image>: rename it twice offline.
    #[test]
    fn offline_rename_of_an_image() {
        let Ok(image) = std::env::var("SLATE_LABEL_IMAGE") else {
            return;
        };
        let name: Vec<u16> = "Meus arquivos de backup".encode_utf16().collect();
        relabel_offline(&image, &name).unwrap();
        let short: Vec<u16> = "Dados".encode_utf16().collect();
        relabel_offline(&image, &short).unwrap();
        relabel_offline(&image, &name).unwrap();
    }
}
