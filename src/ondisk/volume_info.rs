//! Module: ntfs_rs::volume_info
//! Purpose: Decode volume version and state without conflating settings with damage.
//! Created: 2026-10-01
//! Architecture: Shared volume-state policy for the writer, checker and recovery tools.

use super::bytes::u16_at;
use super::mft::MftRecord;
use super::{Error, Result};

pub const ATTR_VOLUME_INFORMATION: u32 = 0x70;
pub const VOLUME_IS_DIRTY: u16 = 0x0001;
/// Request to resize $LogFile; the log-resize operation clears it.
pub const VOLUME_RESIZE_LOG_FILE: u16 = 0x0002;
/// Windows was deleting the change journal; a check finishes the deletion.
pub const VOLUME_DELETE_USN_UNDERWAY: u16 = 0x0010;
/// The object-ID index needs repair, which a full check performs.
pub const VOLUME_REPAIR_OBJECT_IDS: u16 = 0x0020;
/// Windows found damage it could not heal online and requires a full check.
pub const VOLUME_FULL_CHECK_REQUIRED: u16 = 0x0100;
/// Windows queued confirmed damage for an offline spot fix.
pub const VOLUME_SPOT_FIX_REQUIRED: u16 = 0x0200;
/// A Windows check started and did not finish.
pub const VOLUME_CHECK_UNDERWAY: u16 = 0x4000;
/// A check changed the volume. Informational: Windows mounts such a volume as
/// clean and clears the flag itself, so it is preserved for Windows to see.
pub const VOLUME_MODIFIED_BY_CHECK: u16 = 0x8000;
/// Requests a completed, passing full check satisfies; the check audits the
/// object-ID index like every other structure. Windows' checker clears these
/// together with the two work requests below (mask 0x4333).
pub const CHECK_REQUEST_FLAGS: u16 = VOLUME_IS_DIRTY
    | VOLUME_REPAIR_OBJECT_IDS
    | VOLUME_FULL_CHECK_REQUIRED
    | VOLUME_SPOT_FIX_REQUIRED
    | VOLUME_CHECK_UNDERWAY;
/// Requests for specific work. Recovery tolerates them; each is cleared only
/// by the operation that performs its work, and both block writes until then.
pub const WORK_REQUEST_FLAGS: u16 = VOLUME_RESIZE_LOG_FILE | VOLUME_DELETE_USN_UNDERWAY;
/// Persistent Windows setting: disable short-name creation and the tunneling cache.
/// Source: https://dfir.ru/2019/01/19/ntfs-today/ ($VOLUME_INFORMATION).
pub const VOLUME_NO_SHORT_NAMES: u16 = 0x0080;

/// Only the supported persistent setting and the informational check marker
/// may remain on a clean writable volume. Every check request, dirty marker
/// and unknown flag continues to block writes.
pub fn flags_allow_writes(flags: u16) -> bool {
    flags & !(VOLUME_NO_SHORT_NAMES | VOLUME_MODIFIED_BY_CHECK) == 0
}

/// The flags word a completed, passing full check publishes.
pub fn flags_after_check(flags: u16) -> u16 {
    flags & !CHECK_REQUEST_FLAGS
}

/// The flags word a completed structural repair publishes: it also finishes a
/// change-journal deletion that was underway.
pub fn flags_after_repair(flags: u16) -> u16 {
    flags_after_check(flags) & !VOLUME_DELETE_USN_UNDERWAY
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeInfo {
    pub major_version: u8,
    pub minor_version: u8,
    pub flags: u16,
}

impl VolumeInfo {
    /// Read the resident $VOLUME_INFORMATION attribute of MFT record 3.
    /// The caller must have validated the record's fixups first.
    pub fn from_record(record: &MftRecord<'_>) -> Result<Self> {
        if record.flags()? & 1 == 0 || record.base_file_reference()? != 0 {
            return Err(Error::InvalidRecord);
        }
        let mut info = None;
        for item in record.attributes() {
            let attr = item?;
            if attr.kind != ATTR_VOLUME_INFORMATION {
                continue;
            }
            if info.is_some() || attr.nonresident || !attr.name_utf16le()?.is_empty() {
                return Err(Error::InvalidAttribute);
            }
            let value = attr.resident_value()?;
            if value.len() != 12 {
                return Err(Error::InvalidAttribute);
            }
            info = Some(Self { major_version: value[8], minor_version: value[9], flags: u16_at(value, 10)? });
        }
        info.ok_or(Error::InvalidAttribute)
    }

    pub fn is_dirty(self) -> bool {
        self.flags & VOLUME_IS_DIRTY != 0
    }

    /// The volume carries a request that only a completed check may clear.
    pub fn needs_check(self) -> bool {
        self.flags & CHECK_REQUEST_FLAGS != 0
    }

    /// The volume carries a request for specific work, such as a log resize.
    pub fn has_work_requests(self) -> bool {
        self.flags & WORK_REQUEST_FLAGS != 0
    }

    /// Recovery may accept check and work requests, but must still reject
    /// legacy and unknown flags.
    pub fn has_unsupported_flags(self) -> bool {
        let known = CHECK_REQUEST_FLAGS | WORK_REQUEST_FLAGS | VOLUME_NO_SHORT_NAMES | VOLUME_MODIFIED_BY_CHECK;
        self.flags & !known != 0
    }

    /// This is only the version/flag gate; journal and hibernation checks remain separate.
    pub fn supports_writes(self) -> bool {
        (self.major_version, self.minor_version) == (3, 1) && flags_allow_writes(self.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume_record(flags: u16) -> [u8; 1024] {
        let mut b = [0_u8; 1024];
        b[0..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
        b[6..8].copy_from_slice(&3_u16.to_le_bytes());
        b[0x14..0x16].copy_from_slice(&0x38_u16.to_le_bytes());
        b[0x16..0x18].copy_from_slice(&1_u16.to_le_bytes());
        b[0x18..0x1c].copy_from_slice(&0x68_u32.to_le_bytes());
        b[0x30..0x32].copy_from_slice(&0x1234_u16.to_le_bytes());
        b[0x32..0x34].copy_from_slice(&0xabcd_u16.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&0xef01_u16.to_le_bytes());
        b[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
        b[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
        b[0x38..0x3c].copy_from_slice(&ATTR_VOLUME_INFORMATION.to_le_bytes());
        b[0x3c..0x40].copy_from_slice(&0x28_u32.to_le_bytes());
        b[0x48..0x4c].copy_from_slice(&12_u32.to_le_bytes());
        b[0x4c..0x4e].copy_from_slice(&0x18_u16.to_le_bytes());
        b[0x58] = 3;
        b[0x59] = 1;
        b[0x5a..0x5c].copy_from_slice(&flags.to_le_bytes());
        b[0x60..0x64].copy_from_slice(&u32::MAX.to_le_bytes());
        b
    }

    #[test]
    fn reports_dirty_and_clean_volume_flags() {
        for (flags, dirty) in [(0, false), (1, true), (2, false), (3, true)] {
            let mut bytes = volume_record(flags);
            let record = MftRecord::parse(&mut bytes, 512).unwrap();
            let info = VolumeInfo::from_record(&record).unwrap();
            assert_eq!((info.major_version, info.minor_version), (3, 1));
            assert_eq!(info.is_dirty(), dirty);
        }
    }

    #[test]
    fn rejects_missing_volume_information() {
        let mut bytes = volume_record(1);
        bytes[0x38..0x3c].copy_from_slice(&0x80_u32.to_le_bytes());
        let record = MftRecord::parse(&mut bytes, 512).unwrap();
        assert_eq!(VolumeInfo::from_record(&record), Err(Error::InvalidAttribute));
    }

    #[test]
    fn only_supported_clean_settings_allow_writes() {
        for flags in 0..=u16::MAX {
            let info = VolumeInfo { major_version: 3, minor_version: 1, flags };
            let settings = VOLUME_NO_SHORT_NAMES | VOLUME_MODIFIED_BY_CHECK;
            assert_eq!(info.supports_writes(), flags & !settings == 0);
            let requests = CHECK_REQUEST_FLAGS | WORK_REQUEST_FLAGS;
            assert_eq!(!info.has_unsupported_flags(), flags & !(settings | requests) == 0);
            assert_eq!(info.has_work_requests(), flags & WORK_REQUEST_FLAGS != 0);
            assert_eq!(info.needs_check(), flags & CHECK_REQUEST_FLAGS != 0);
        }
        // Windows left 0x0181 on a volume it wanted checked; a passing check
        // keeps only the short-name setting, as chkdsk /f does.
        assert_eq!(flags_after_check(0x0181), VOLUME_NO_SHORT_NAMES);
        assert_eq!(flags_after_check(0x8181), VOLUME_NO_SHORT_NAMES | VOLUME_MODIFIED_BY_CHECK);
        // Together the two masks are what Windows' checker clears.
        assert_eq!(CHECK_REQUEST_FLAGS | WORK_REQUEST_FLAGS, 0x4333);
        // A check alone leaves work requests in place; a repair finishes the
        // journal deletion, and only the resize operation clears its request.
        assert_eq!(flags_after_check(0x4333), WORK_REQUEST_FLAGS);
        assert_eq!(flags_after_repair(0x4333), VOLUME_RESIZE_LOG_FILE);
        // Legacy upgrade flags stay unsupported.
        for flags in [0x0004, 0x0008] {
            assert!(VolumeInfo { major_version: 3, minor_version: 1, flags }.has_unsupported_flags());
        }
        for (major_version, minor_version) in [(1, 2), (3, 0), (3, 2), (4, 1)] {
            let info = VolumeInfo { major_version, minor_version, flags: VOLUME_NO_SHORT_NAMES };
            assert!(!info.supports_writes());
        }
    }
}
