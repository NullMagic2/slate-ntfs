//! Module: ntfs_rs::namespace_family::tests
//! Purpose: Verify namespace family contracts independently.
//! Created: 2026-10-03
//! Architecture: The production module references these selectable unit tests.

use super::*;
use core::cmp::Ordering;

#[test]
fn list_order_uses_vcn_after_folded_name_and_retains_missing_mapping() {
    let mut table = [0_u8; 196];
    for (unit, bytes) in table.chunks_exact_mut(2).enumerate() {
        bytes.copy_from_slice(&(unit as u16).to_le_bytes());
    }
    table[194..196].copy_from_slice(&u16::from(b'A').to_le_bytes());
    let lower = ListEntry {
        kind: super::super::mft::ATTR_DATA,
        first_vcn: 0,
        file_reference: 1,
        attribute_id: 2,
        name_utf16le: b"a\0",
    };
    let upper = ListEntry { first_vcn: 1, name_utf16le: b"A\0", ..lower };
    assert_eq!(entry_order(lower, upper, &table), Ordering::Less);
    assert_eq!(entry_order(lower, ListEntry { first_vcn: 0, ..upper }, &table), Ordering::Equal);
    assert_eq!(entry_order(lower, upper, &table[..195]), Ordering::Greater);
    assert_eq!(entry_order(lower, upper, &[]), Ordering::Greater);
}
