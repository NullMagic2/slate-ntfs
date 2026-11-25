//! Module: ntfs_rs::upcase::tests
//! Purpose: Check table trust, collation and information framing.
//! Created: 2026-11-25
//! Architecture: Independent vectors exercise the shared core mapping API.

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

#[test]
fn recovery_profile_is_complete_stable_and_has_fixed_identity() {
    const PROFILE_SHA256: [u8; 32] = [
        0x41, 0xc2, 0x6b, 0xc7, 0xa1, 0x2b, 0xda, 0xeb, 0x26, 0x02, 0x5c, 0x93, 0x11, 0x86, 0x97, 0xc7, 0xe3, 0xef,
        0x81, 0xee, 0x04, 0x8b, 0x00, 0xfe, 0x5c, 0xce, 0x2a, 0x47, 0x2e, 0x0e, 0x07, 0x42,
    ];
    validate_mapping(RECOVERY_MAPPING).unwrap();
    assert_eq!(crate::sha256::digest(RECOVERY_MAPPING), PROFILE_SHA256);
    for (lower, upper) in [('é', 'É'), ('α', 'Α'), ('я', 'Я')] {
        assert_eq!(fold_unit(RECOVERY_MAPPING, lower as u16), upper as u16);
    }
}

#[test]
fn cycles_and_surrogate_mapping_are_invalid_even_with_matching_checksum() {
    const FIRST: u16 = 0x0378;
    const SECOND: u16 = 0x0379;
    let mut bytes = RECOVERY_MAPPING.to_vec();
    super::super::bytes::p16(&mut bytes, usize::from(FIRST) * CODE_UNIT_BYTES, SECOND).unwrap();
    super::super::bytes::p16(&mut bytes, usize::from(SECOND) * CODE_UNIT_BYTES, FIRST).unwrap();
    let info = build_information(&bytes);
    validate_information(&bytes, &info, INFORMATION_BYTES as u64).unwrap();
    assert!(validate_mapping(&bytes).is_err());
    let mut bytes = RECOVERY_MAPPING.to_vec();
    super::super::bytes::p16(&mut bytes, usize::from(SURROGATE_START) * CODE_UNIT_BYTES, FIRST).unwrap();
    assert!(validate_mapping(&bytes).is_err());
}
