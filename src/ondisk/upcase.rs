//! Module: ntfs_rs::upcase
//! Purpose: Validate the NTFS case-folding table, information checksum and name units.
//! Created: 2026-10-01
//! Architecture: Directory lookup, index collation and family entry ordering
//!     share volume mappings while retaining their own comparison policies;
//!     the formatter and offline checker share its information encoding.

use core::cmp::Ordering;

use super::index::FileName;
use super::{Error, Result};

pub use super::filename_metadata::CODE_UNIT_BYTES;
pub const CODE_UNITS: usize = u16::MAX as usize + 1;
pub const UPCASE_BYTES: usize = CODE_UNITS * CODE_UNIT_BYTES;
pub const INFORMATION_SIZE_OFFSET: usize = 0;
pub const INFORMATION_CHECKSUM_OFFSET: usize = 8;
pub const INFORMATION_CHECKSUM_BYTES: usize = core::mem::size_of::<u64>();
pub const INFORMATION_VERSION_OFFSET: usize = 16;
const CRC_POLYNOMIAL: u64 = 0x9a6c_9329_ac4b_c9b5;
const ASCII_UNITS: u16 = 128;
const ASCII_DELTA: u16 = b'a' as u16 - b'A' as u16;
const SURROGATE_START: u16 = 0xd800;
const SURROGATE_END: u16 = 0xdfff;

// Generated fixed NTFS collation profile. An intact volume table takes precedence;
// this profile supplies deterministic recovery when its mapping cannot be trusted.
pub const RECOVERY_MAPPING: &[u8; UPCASE_BYTES] = include_bytes!("upcase-default.bin");
pub const INFORMATION_BYTES: usize = 32;

/// Read one volume mapping, retaining the unit when its entry is unavailable.
/// Callers keep their own name ordering and namespace policies.
pub fn fold_unit(bytes: &[u8], unit: u16) -> u16 {
    super::bytes::u16_at(bytes, usize::from(unit) * CODE_UNIT_BYTES).unwrap_or(unit)
}

/// Protect the exact volume mapping without selecting a host Unicode version.
pub fn information_checksum(bytes: &[u8]) -> u64 {
    let mut crc = u64::MAX;
    for &byte in bytes {
        crc ^= u64::from(byte);
        for _ in 0..u8::BITS {
            crc = (crc >> 1) ^ if crc & 1 != 0 { CRC_POLYNOMIAL } else { 0 };
        }
    }
    !crc
}

/// Build the standard information header; optional version fields stay zero.
pub fn build_information(bytes: &[u8]) -> [u8; INFORMATION_BYTES] {
    let mut information = [0; INFORMATION_BYTES];
    information[..core::mem::size_of::<u32>()].copy_from_slice(&(INFORMATION_BYTES as u32).to_le_bytes());
    information[INFORMATION_CHECKSUM_OFFSET..INFORMATION_VERSION_OFFSET]
        .copy_from_slice(&information_checksum(bytes).to_le_bytes());
    information
}

/// Validate the fixed header while retaining any declared trailing information.
pub fn validate_information(bytes: &[u8], information: &[u8], stream_bytes: u64) -> Result<()> {
    if bytes.len() != UPCASE_BYTES
        || information.len() < INFORMATION_BYTES
        || stream_bytes < INFORMATION_BYTES as u64
        || u64::from(super::bytes::u32_at(information, INFORMATION_SIZE_OFFSET)?) != stream_bytes
        || super::bytes::u64_at(information, INFORMATION_CHECKSUM_OFFSET)? != information_checksum(bytes)
    {
        return Err(Error::InvalidAttribute);
    }
    Ok(())
}

/// Check stable mapping invariants without imposing a host Unicode version.
pub fn validate_mapping(bytes: &[u8]) -> Result<()> {
    let table = UpcaseTable::parse(bytes)?;
    for unit in 0..=u16::MAX {
        let folded = table.fold(unit);
        if table.fold(folded) != folded
            || ((SURROGATE_START..=SURROGATE_END).contains(&unit) && folded != unit)
            || (unit < ASCII_UNITS
                && folded
                    != if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) { unit - ASCII_DELTA } else { unit })
        {
            return Err(Error::InvalidAttribute);
        }
    }
    Ok(())
}

/// The volume's $UpCase table, indexed by UTF-16 code unit. NTFS compares
/// Win32 names using this on-disk mapping rather than Rust Unicode folding.
pub struct UpcaseTable<'a> {
    bytes: &'a [u8],
}

impl<'a> UpcaseTable<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != UPCASE_BYTES {
            return Err(Error::InvalidAttribute);
        }
        Ok(Self { bytes })
    }

    fn fold(&self, unit: u16) -> u16 {
        fold_unit(self.bytes, unit)
    }

    /// POSIX namespace names remain case-sensitive. Win32 and DOS namespace
    /// names use the volume's own case mapping.
    pub fn matches(&self, file_name: FileName<'_>, requested: &[u16]) -> bool {
        let mut disk = file_name.code_units();
        for &unit in requested {
            let Some(on_disk) = disk.next() else {
                return false;
            };
            let equal =
                if file_name.namespace & 3 == 0 { on_disk == unit } else { self.fold(on_disk) == self.fold(unit) };
            if !equal {
                return false;
            }
        }
        disk.next().is_none()
    }

    /// Where requested sorts against an indexed name in $I30 filename
    /// collation, ignoring case: folded units first, then length. Every
    /// spelling that matches() can accept compares Equal.
    pub fn collate(&self, requested: &[u16], file_name: FileName<'_>) -> Ordering {
        let mut disk = file_name.code_units();
        for &unit in requested {
            let Some(on_disk) = disk.next() else {
                return Ordering::Greater;
            };
            match self.fold(unit).cmp(&self.fold(on_disk)) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        if disk.next().is_some() {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }
}

#[cfg(test)]
#[path = "../tests/core/upcase.rs"]
mod tests;
