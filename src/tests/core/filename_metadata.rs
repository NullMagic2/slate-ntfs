//! Module: ntfs_rs::filename_metadata::tests
//! Purpose: Check filename value framing and retained UTF-16 metadata.
//! Created: 2026-10-21
//! Architecture: Exercises the shared parser used by record and index readers.

use super::*;

fn value() -> [u8; HEADER_BYTES + CODE_UNIT_BYTES] {
    let mut value = [0; HEADER_BYTES + CODE_UNIT_BYTES];
    value[..DUPLICATED_INFORMATION_OFFSET].copy_from_slice(&u64::MAX.to_le_bytes());
    value[DUPLICATED_INFORMATION_OFFSET..NAME_LENGTH_OFFSET].fill(0xa5);
    value[NAME_LENGTH_OFFSET] = 1;
    value[NAMESPACE_OFFSET] = 0xff;
    value[HEADER_BYTES..].copy_from_slice(&0xd800_u16.to_le_bytes());
    value
}

#[test]
fn views_preserve_reference_cache_namespace_and_raw_code_units() {
    let bytes = value();
    let parsed = FileNameValue::parse(&bytes).unwrap();
    assert_eq!(parsed.parent_reference, u64::MAX);
    assert_eq!(parsed.duplicated_information, &[0xa5; DUPLICATED_INFORMATION_BYTES]);
    assert_eq!(parsed.name.namespace, 0xff);
    assert_eq!(parsed.name.code_units().collect::<std::vec::Vec<_>>(), [0xd800]);
    assert_eq!(parsed.name.utf16le.as_ptr(), bytes[HEADER_BYTES..].as_ptr());
}

#[test]
fn every_truncated_header_or_declared_name_is_rejected() {
    let bytes = value();
    for length in 0..bytes.len() {
        assert!(matches!(FileNameValue::parse_prefix(&bytes[..length]), Err(Error::InvalidAttribute)));
        assert!(matches!(FileNameValue::parse(&bytes[..length]), Err(Error::InvalidAttribute)));
    }
}

#[test]
fn exact_and_prefix_parsers_keep_container_policies_separate() {
    let mut bytes = value().to_vec();
    bytes.push(0xee);
    assert!(FileNameValue::parse_prefix(&bytes).is_ok());
    assert!(matches!(FileNameValue::parse(&bytes), Err(Error::InvalidAttribute)));
    bytes[NAME_LENGTH_OFFSET] = 0;
    assert!(FileNameValue::parse(&bytes[..HEADER_BYTES]).unwrap().name.utf16le.is_empty());
    bytes.resize(MAX_VALUE_BYTES, 0);
    bytes[NAME_LENGTH_OFFSET] = u8::MAX;
    assert_eq!(FileNameValue::parse(&bytes).unwrap().name.utf16le.len(), MAX_NAME_BYTES);
    bytes.push(0);
    assert!(matches!(FileNameValue::parse(&bytes), Err(Error::InvalidAttribute)));
}
