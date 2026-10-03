//! Module: ntfs_rs::volume_info
//! Purpose: Decode volume version and state without conflating settings with damage.
//! Created: 2026-10-01
//! Architecture: Shared volume-state policy for the writer, checker and recovery tools.

use super::bytes::u16_at;
use super::mft::MftRecord;
use super::{Error, Result};

pub const ATTR_VOLUME_INFORMATION: u32 = 0x70;
pub const VOLUME_IS_DIRTY: u16 = 0x0001;
/// Persistent Windows setting: disable short-name creation and the tunneling cache.
/// Source: https://dfir.ru/2019/01/19/ntfs-today/ ($VOLUME_INFORMATION).
pub const VOLUME_NO_SHORT_NAMES: u16 = 0x0080;

/// Only the supported persistent setting may remain on a clean writable volume.
/// Every repair request, dirty marker and unknown flag continues to block writes.
pub fn flags_allow_writes(flags: u16) -> bool {
    flags & !VOLUME_NO_SHORT_NAMES == 0
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

    /// Recovery may accept dirty state, but must still reject unsupported flags.
    pub fn has_unsupported_flags(self) -> bool {
        self.flags & !(VOLUME_IS_DIRTY | VOLUME_NO_SHORT_NAMES) != 0
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
            assert_eq!(info.supports_writes(), matches!(flags, 0 | 0x0080));
            assert_eq!(!info.has_unsupported_flags(), matches!(flags, 0 | 1 | 0x0080 | 0x0081));
        }
        for (major_version, minor_version) in [(1, 2), (3, 0), (3, 2), (4, 1)] {
            let info = VolumeInfo { major_version, minor_version, flags: VOLUME_NO_SHORT_NAMES };
            assert!(!info.supports_writes());
        }
    }
}
