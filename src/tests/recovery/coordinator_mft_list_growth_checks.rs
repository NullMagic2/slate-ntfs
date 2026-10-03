// Module: slate_ntfs_tools::recovery_io::coordinator_mft_list_growth_checks
// Purpose: Verify recovery coordination with disposable regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged into the test folder and included in its
// original private scope; this file cannot authorize production disk writes.

use super::*;
use ntfs_rs::record_edit as edit;

#[test]
fn base_owned_mft_streams_can_be_resolved_through_a_resident_list() {
    let mut raw = vec![0; 1024];
    edit::format_empty(&mut raw, 0).unwrap();
    let mut attribute = vec![0; 1024];
    let n = edit::build_resident(ATTR_DATA, &[], &[1], &mut attribute).unwrap();
    let data_at = edit::insert(&mut raw, &attribute[..n]).unwrap();
    let data_id = ntfs_rs::bytes::u16_at(&raw, data_at + 14).unwrap();
    let n = edit::build_resident(ATTR_BITMAP, &[], &[1], &mut attribute).unwrap();
    let bitmap_at = edit::insert(&mut raw, &attribute[..n]).unwrap();
    let bitmap_id = ntfs_rs::bytes::u16_at(&raw, bitmap_at + 14).unwrap();
    let sequence = ntfs_rs::bytes::u16_at(&raw, 16).unwrap();
    let reference = u64::from(sequence) << 48;
    let mut list = vec![0_u8; 64];
    for (i, (kind, id)) in [(ATTR_DATA, data_id), (ATTR_BITMAP, bitmap_id)].into_iter().enumerate() {
        let at = i * 32;
        list[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        list[at + 4..at + 6].copy_from_slice(&32_u16.to_le_bytes());
        list[at + 16..at + 24].copy_from_slice(&reference.to_le_bytes());
        list[at + 24..at + 26].copy_from_slice(&id.to_le_bytes());
    }
    let n = edit::build_resident(ATTR_ATTRIBUTE_LIST, &[], &list, &mut attribute).unwrap();
    let list_at = edit::insert(&mut raw, &attribute[..n]).unwrap();
    let record = MftRecord::from_decoded(&raw).unwrap();
    assert!(record.stream(ATTR_DATA, &[]).is_ok());
    assert!(record.stream(ATTR_BITMAP, &[]).is_ok());
    let list_value = edit::resident_value(&raw, list_at).unwrap();
    let mut damaged = list_value.to_vec();
    damaged[16..24].copy_from_slice(&(reference + 1).to_le_bytes());
    edit::set_resident_value(&mut raw, list_at, &damaged).unwrap();
    let record = MftRecord::from_decoded(&raw).unwrap();
    assert!(record.stream(ATTR_DATA, &[]).is_err());
}
