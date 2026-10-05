//! Module: ntfs_rs::std_info
//! Purpose: Read and update standard-information times and file attributes.
//! Created: 2026-10-01
//! Architecture: Reader and writer adapters convert NTFS intervals since 1601-01-01 UTC.
//! Linux atime, mtime and ctime map to access, modification and MFT-change
//! times; creation is statx birth time. Filename copies are refreshed separately.

use super::bytes::{u32_at, u64_at};
use super::mft::MftRecord;
use super::record_edit::{self, p32, p64};
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::tx::Tx;
use super::volume::Volume;
use super::{Error, Result};

pub const SI: u32 = 0x10;
pub const READONLY: u32 = 0x0001;
pub const HIDDEN: u32 = 0x0002;
pub const SYSTEM: u32 = 0x0004;
pub const DIRECTORY: u32 = 0x0010;
pub const ARCHIVE: u32 = 0x0020;
pub const TEMPORARY: u32 = 0x0100;
pub const SPARSE: u32 = 0x0200;
pub const REPARSE_POINT: u32 = 0x0400;
/// In a $FILE_NAME's duplicated attributes only: the name is a directory.
pub const DUP_INDEX_PRESENT: u32 = 0x1000_0000;
pub const COMPRESSED: u32 = 0x0800;
pub const OFFLINE: u32 = 0x1000;
pub const NOT_CONTENT_INDEXED: u32 = 0x2000;
pub const ENCRYPTED: u32 = 0x4000;
/// Attributes a caller with FILE_WRITE_ATTRIBUTES may change directly.
/// Structural flags (directory, reparse, sparse, compression, encryption)
/// always follow the on-disk layout and cannot be toggled this way.
pub const SETTABLE: u32 = READONLY | HIDDEN | SYSTEM | ARCHIVE | TEMPORARY | OFFLINE | NOT_CONTENT_INDEXED;

/// Index of each time in $STANDARD_INFORMATION and in times arrays.
pub const CREATED: usize = 0;
pub const MODIFIED: usize = 1;
pub const CHANGED: usize = 2;
pub const ACCESSED: usize = 3;
pub const TIME_COUNT: usize = 4;
/// Times lead the value; NTFS 1.2 values end after 48 bytes, 3.x values after 72.
pub const TIMES_BYTES: usize = TIME_COUNT * core::mem::size_of::<u64>();
pub const LEGACY_BYTES: usize = 48;
pub const CURRENT_BYTES: usize = 72;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StdInfo {
    /// Creation, data modification, MFT change and access times.
    pub times: [u64; TIME_COUNT],
    pub attributes: u32,
}

pub fn read(record: &MftRecord<'_>) -> Result<StdInfo> {
    let mut found = None;
    for a in record.attributes() {
        let a = a?;
        if a.kind == SI {
            if a.nonresident || found.is_some() {
                return Err(Error::InvalidAttribute);
            }
            found = Some(a.resident_value()?);
        }
    }
    let value = found.ok_or(Error::InvalidAttribute)?;
    if value.len() < LEGACY_BYTES {
        return Err(Error::InvalidAttribute);
    }
    Ok(StdInfo {
        times: [u64_at(value, 0)?, u64_at(value, 8)?, u64_at(value, 16)?, u64_at(value, 24)?],
        attributes: u32_at(value, 32)?,
    })
}

/// Edit a decoded record image in place. None keeps a time unchanged.
pub fn update(record: &mut [u8], times: [Option<u64>; 4], attributes: Option<(u32, u32)>) -> Result<()> {
    let at = record_edit::require(record, SI, &[])?;
    let offset = record_edit::resident_value_offset(record, at)?;
    if record_edit::resident_value(record, at)?.len() < 48 {
        return Err(Error::InvalidAttribute);
    }
    for (i, time) in times.iter().enumerate() {
        if let Some(time) = time {
            p64(record, offset + i * 8, *time)?;
        }
    }
    if let Some((mask, value)) = attributes {
        if mask & !SETTABLE != 0 {
            return Err(Error::NotPermitted);
        }
        let old = u32_at(record, offset + 32)?;
        p32(record, offset + 32, (old & !mask) | (value & mask))?;
    }
    record_edit::validate(record)
}

impl Writer {
    /// Journal new $STANDARD_INFORMATION times and/or settable attributes.
    /// The adapter authorizes FILE_WRITE_ATTRIBUTES (or ownership for Linux
    /// utimensat) and serializes the call.
    pub fn set_std_info<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        times: [Option<u64>; 4],
        attributes: Option<(u32, u32)>,
        scratch: &mut [u8],
    ) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let number = reference & 0x0000_ffff_ffff_ffff;
        if (number != 5 && number < 24) || reference >> 48 == 0 {
            return Err(Error::Unsupported);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, _) = rest.split_at_mut(64 * 1024);
        let file = tx.load_family(&mut volume, reference)?;
        if MftRecord::from_decoded(tx.record(file))?.base_file_reference()? != 0
            || u64_at(tx.record(file), 8)? > self.current_lsn
        {
            return Err(Error::Unsupported);
        }
        update(tx.record_mut(file), times, attributes)?;
        drop(volume);
        tx.commit(self, io, journal)
    }
}

/// Convert Linux seconds/nanoseconds to an NTFS time, saturating at 1601.
pub fn from_unix(seconds: i64, nanoseconds: u32) -> u64 {
    const EPOCH_DIFFERENCE: i128 = 11_644_473_600;
    let ticks = (i128::from(seconds) + EPOCH_DIFFERENCE) * 10_000_000 + i128::from(nanoseconds / 100);
    ticks.clamp(0, i128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_and_settable_attributes_round_trip() {
        let mut record = [0u8; 1024];
        record_edit::format_empty(&mut record, 64).unwrap();
        record_edit::p16(&mut record, 22, 1).unwrap();
        let mut si = [0u8; 72];
        si[32..36].copy_from_slice(&(ARCHIVE | REPARSE_POINT).to_le_bytes());
        let mut image = [0u8; 128];
        let n = record_edit::build_resident(SI, &[], &si, &mut image).unwrap();
        record_edit::insert(&mut record, &image[..n]).unwrap();
        update(&mut record, [None, Some(7), Some(8), None], Some((READONLY | HIDDEN, READONLY))).unwrap();
        let info = read(&MftRecord::from_decoded(&record).unwrap()).unwrap();
        assert_eq!(info.times, [0, 7, 8, 0]);
        assert_eq!(info.attributes, ARCHIVE | REPARSE_POINT | READONLY);
        assert_eq!(update(&mut record, [None; 4], Some((REPARSE_POINT, 0))), Err(Error::NotPermitted));
        assert_eq!(from_unix(-11_644_473_600, 0), 0);
        assert_eq!(from_unix(0, 150), 116_444_736_000_000_001);
    }
}
