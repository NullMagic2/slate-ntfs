//! Module: ntfs_rs::attrlist::tests
//! Purpose: Verify attrlist contracts independently.
//! Created: 2026-10-03
//! Architecture: The production module references these selectable unit tests.

use super::*;

#[test]
fn parses_named_extension_and_rejects_zero_length() {
    let mut data = [0_u8; 0x20];
    data[0..4].copy_from_slice(&0x80_u32.to_le_bytes());
    data[4..6].copy_from_slice(&0x20_u16.to_le_bytes());
    data[6] = 1;
    data[7] = 0x1a;
    data[8..0x10].copy_from_slice(&7_u64.to_le_bytes());
    data[0x10..0x18].copy_from_slice(&0x0005_0000_0000_0011_u64.to_le_bytes());
    data[0x18..0x1a].copy_from_slice(&3_u16.to_le_bytes());
    data[0x1a..0x1c].copy_from_slice(&('X' as u16).to_le_bytes());
    let entry = AttributeList::new(&data).next().unwrap().unwrap();
    assert_eq!(entry.kind, 0x80);
    assert_eq!(entry.first_vcn, 7);
    assert_eq!(entry.attribute_id, 3);
    assert_eq!(entry.name_utf16le, b"X\0");
    let mut encoded = [0xa5; 40];
    assert_eq!(entry.encode(&mut encoded), Ok(data.len()));
    assert_eq!(&encoded[..data.len()], &data);
    assert_eq!(&encoded[data.len()..], &[0xa5; 8]);
    let mut short = [0xa5; 31];
    assert_eq!(entry.encode(&mut short), Err(Error::Truncated));
    assert_eq!(short, [0xa5; 31]);
    data[4] = 0;
    assert!(matches!(AttributeList::new(&data).next(), Some(Err(Error::InvalidAttributeList))));
}
