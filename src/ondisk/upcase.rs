//! Module: ntfs_rs::upcase
//! Purpose: Validate the NTFS case-folding table, information checksum and name units.
//! Created: 2026-10-01
//! Architecture: Directory lookup, index collation and family entry ordering
//!     share volume mappings while retaining their own comparison policies;
//!     the formatter and offline checker share its information encoding.

use core::cmp::Ordering;

use super::index::FileName;
use super::{Error, Result};

pub const UPCASE_BYTES: usize = 65_536 * 2;
pub const INFORMATION_BYTES: usize = 32;

/// Read one volume mapping, retaining the unit when its entry is unavailable.
/// Callers keep their own name ordering and namespace policies.
pub fn fold_unit(bytes: &[u8], unit: u16) -> u16 {
    super::bytes::u16_at(bytes, usize::from(unit) * 2).unwrap_or(unit)
}

/// Protect the exact volume mapping without selecting a host Unicode version.
pub fn information_checksum(bytes: &[u8]) -> u64 {
    let mut crc = u64::MAX;
    for &byte in bytes {
        crc ^= u64::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x9a6c_9329_ac4b_c9b5 } else { 0 };
        }
    }
    !crc
}

/// Build the standard information header; optional version fields stay zero.
pub fn build_information(bytes: &[u8]) -> [u8; INFORMATION_BYTES] {
    let mut information = [0; INFORMATION_BYTES];
    information[..4].copy_from_slice(&(INFORMATION_BYTES as u32).to_le_bytes());
    information[8..16].copy_from_slice(&information_checksum(bytes).to_le_bytes());
    information
}

/// Validate the fixed header while retaining any declared trailing information.
pub fn validate_information(bytes: &[u8], information: &[u8], stream_bytes: u64) -> Result<()> {
    if bytes.len() != UPCASE_BYTES
        || information.len() < INFORMATION_BYTES
        || stream_bytes < INFORMATION_BYTES as u64
        || u64::from(super::bytes::u32_at(information, 0)?) != stream_bytes
        || super::bytes::u64_at(information, 8)? != information_checksum(bytes)
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
            || ((0xd800..=0xdfff).contains(&unit) && folded != unit)
            || (unit < 128 && folded != if (97..=122).contains(&unit) { unit - 32 } else { unit })
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
mod tests {
    use super::*;

    #[test]
    fn single_unit_folding_retains_missing_and_partial_entries() {
        let mut bytes = [0_u8; UPCASE_BYTES];
        let offset = usize::from(b'a') * 2;
        bytes[offset..offset + 2].copy_from_slice(&u16::from(b'A').to_le_bytes());
        assert_eq!(fold_unit(&bytes, u16::from(b'a')), u16::from(b'A'));
        assert_eq!(fold_unit(&bytes[..offset + 1], u16::from(b'a')), u16::from(b'a'));
        assert_eq!(fold_unit(&[], u16::MAX), u16::MAX);
        bytes[UPCASE_BYTES - 2..].copy_from_slice(&0x1234_u16.to_le_bytes());
        assert_eq!(fold_unit(&bytes, u16::MAX), 0x1234);
        assert_eq!(fold_unit(&bytes[..UPCASE_BYTES - 1], u16::MAX), u16::MAX);
    }

    #[test]
    fn information_checksum_matches_fixed_vector() {
        assert_eq!(information_checksum(b"123456789"), 0xae8b_1486_0a79_9888);
    }

    #[test]
    fn information_checks_size_checksum_and_extended_header() {
        let mut bytes = [0; UPCASE_BYTES];
        let information = build_information(&bytes);
        validate_information(&bytes, &information, INFORMATION_BYTES as u64).unwrap();
        bytes[256] ^= 1;
        assert!(validate_information(&bytes, &information, INFORMATION_BYTES as u64).is_err());
        let mut extended = [0; INFORMATION_BYTES + 8];
        extended[..INFORMATION_BYTES].copy_from_slice(&build_information(&bytes));
        let size = extended.len() as u32;
        extended[..4].copy_from_slice(&size.to_le_bytes());
        validate_information(&bytes, &extended, extended.len() as u64).unwrap();
        assert!(validate_information(&bytes, &extended, INFORMATION_BYTES as u64).is_err());
        assert!(validate_information(&bytes, &extended[..16], 16).is_err());
    }

    #[test]
    fn uses_volume_mapping_and_posix_case_rules() {
        let mut bytes = [0_u8; UPCASE_BYTES];
        for unit in 0..=u16::MAX {
            let offset = usize::from(unit) * 2;
            bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes[usize::from(b'a') * 2..usize::from(b'a') * 2 + 2].copy_from_slice(&(b'A' as u16).to_le_bytes());
        let table = UpcaseTable::parse(&bytes).unwrap();
        let win32 = FileName { namespace: 1, utf16le: b"a\0" };
        assert!(table.matches(win32, &[b'A' as u16]));
        assert!(table.matches(FileName { namespace: 5, ..win32 }, &[b'A' as u16]));
        assert!(!table.matches(FileName { namespace: 4, ..win32 }, &[b'A' as u16]));
        assert!(table.matches(FileName { namespace: 4, ..win32 }, &[b'a' as u16]));
        assert!(!table.matches(FileName { namespace: 0, ..win32 }, &[b'A' as u16]));
        assert!(!table.matches(win32, &[b'A' as u16, b'B' as u16]));
        assert!(UpcaseTable::parse(&bytes[..UPCASE_BYTES - 1]).is_err());
    }

    #[test]
    fn collation_folds_case_then_orders_by_length() {
        let mut bytes = [0_u8; UPCASE_BYTES];
        for unit in 0..=u16::MAX {
            let folded = if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) { unit - 32 } else { unit };
            let offset = usize::from(unit) * 2;
            bytes[offset..offset + 2].copy_from_slice(&folded.to_le_bytes());
        }
        let table = UpcaseTable::parse(&bytes).unwrap();
        let units = |text: &str| text.encode_utf16().collect::<std::vec::Vec<u16>>();
        let name = |utf16le: &'static [u8]| FileName { namespace: 0, utf16le };
        // POSIX names still collate case-insensitively in $I30.
        assert_eq!(table.collate(&units("readme"), name(b"R\0E\0A\0D\0M\0E\0")), Ordering::Equal);
        assert_eq!(table.collate(&units("read"), name(b"R\0E\0A\0D\0M\0E\0")), Ordering::Less);
        assert_eq!(table.collate(&units("readme"), name(b"r\0e\0a\0d\0")), Ordering::Greater);
        assert_eq!(table.collate(&units("b"), name(b"A\0Z\0")), Ordering::Greater);
        // Folded units compare numerically: '_' (0x5f) sorts after 'a' -> 'A' (0x41).
        assert_eq!(table.collate(&units("_"), name(b"a\0")), Ordering::Greater);
    }
}
