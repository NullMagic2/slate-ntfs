// Module: slate_ntfs_tools::recovery_io::models::semantic::quota_sid_tests
// Purpose: Check packed view entries and quota SID recovery contracts.
// Created: 2026-10-02
// Architecture: The semantic namespace includes these independent fixtures;
// tests exercise its real encoders and private validation routines.

use super::*;

#[test]
fn quota_repair_diagnostics_remain_specific() {
    const SID_HEADER_BYTES: usize = 8;
    const SID_REVISION: u8 = 1;
    let value = [SID_REVISION; SID_HEADER_BYTES];
    assert_eq!(metadata::quota_sid(&[], false).unwrap_err().to_string(), "invalid quota SID");
    assert_eq!(metadata::quota_sid(&value, false).unwrap_err().to_string(), "invalid quota SID length or padding");
}

#[test]
fn view_entry_preserves_fixed_frame_and_alignment_padding() {
    let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let value = [0xa1, 0xb2, 0xc3];
    // Data follows the packed twelve-byte key; padding ends the whole entry.
    let expected =
        [28, 0, 3, 0, 0, 0, 0, 0, 32, 0, 12, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0xa1, 0xb2, 0xc3, 0];
    assert_eq!(view_entry(&key, &value).unwrap(), expected);
    assert_eq!(view_entry(&vec![0; u16::MAX as usize], &[]).unwrap_err().to_string(), "view entry is too large");
}

#[test]
fn view_data_follows_each_key_without_inner_alignment_padding() {
    for key_bytes in [VIEW_U32_BYTES, VIEW_U32_BYTES + VIEW_U64_BYTES, OBJECT_ID_BYTES] {
        for value_bytes in [0, VIEW_U32_BYTES, OBJECT_PAYLOAD_BYTES] {
            let key = vec![1; key_bytes];
            let value = vec![2; value_bytes];
            let entry = view_entry(&key, &value).unwrap();
            let at = u16_at(&entry, VIEW_DATA_OFFSET).unwrap() as usize;
            assert_eq!(at, VIEW_HEADER_BYTES + key_bytes);
            assert_eq!(&entry[at..at + value_bytes], &value);
            assert_eq!(entry.len() % VIEW_ALIGNMENT, 0);
        }
    }
}

#[test]
fn lost_quota_defaults_disable_enforcement_and_request_rescan() {
    const TIMESTAMP: u64 = 123;
    let value = quota_defaults(TIMESTAMP);
    assert_eq!(value.len(), QUOTA_CONTROL_BYTES);
    assert_eq!(u32_at(&value, QUOTA_FLAGS_OFFSET).unwrap(), QUOTA_TRACKING_ENABLED | QUOTA_OUT_OF_DATE);
    assert_eq!(u64_at(&value, QUOTA_CHANGE_TIME_OFFSET).unwrap(), TIMESTAMP);
    assert_eq!(u64_at(&value, QUOTA_THRESHOLD_OFFSET).unwrap(), u64::MAX);
    assert_eq!(u64_at(&value, QUOTA_LIMIT_OFFSET).unwrap(), u64::MAX);
}

#[test]
fn quota_control_accepts_both_known_revisions_without_changing_policy_bytes() {
    for version in [QUOTA_LEGACY_REVISION, QUOTA_CONTROL_REVISION] {
        let mut value = quota_defaults(0);
        value[..VIEW_U32_BYTES].copy_from_slice(&version.to_le_bytes());
        let row = view_entry(&QUOTA_DEFAULT_ID.to_le_bytes(), &value).unwrap();
        assert_eq!(quota_control(&row).unwrap(), (QUOTA_DEFAULT_ID, value.as_slice()));
    }
    let row = view_entry(&QUOTA_DEFAULT_ID.to_le_bytes(), &[0; QUOTA_CONTROL_BYTES - 1]).unwrap();
    assert!(quota_control(&row).is_err());
}

#[test]
fn quota_page_io_failure_does_not_become_an_empty_recovered_policy() {
    use ntfs_rs::{mft, record_edit as edit, runlist::Extent};
    const RECORD_BYTES: usize = 1024;
    const BLOCK_BYTES: u32 = 4096;
    const SECTOR_BYTES: u16 = 512;
    const CLUSTERS_PER_BLOCK: u8 = 1;
    const SECTORS_PER_CLUSTER: u32 = BLOCK_BYTES / SECTOR_BYTES as u32;
    const SECTORS: u64 = 1024;
    const MFT_LCN: u64 = 4;
    const MIRROR_LCN: u64 = 2;
    const ALLOCATION_LCN: u64 = 64;
    const SERIAL: u64 = 1;
    const ROOT_GEOMETRY_BYTES: usize = 16;
    const ROOT_CLUSTER_OFFSET: usize = 12;
    const NODE_FLAGS_OFFSET: usize = 12;
    const NODE_ALLOCATED_OFFSET: usize = 8;
    struct Unreadable(std::rc::Rc<std::cell::Cell<usize>>);
    impl ReadAt for Unreadable {
        fn read_exact_at(&mut self, _: u64, _: &mut [u8]) -> ntfs_rs::Result<()> {
            self.0.set(self.0.get() + 1);
            Err(ntfs_rs::Error::Io)
        }
    }
    let boot = ntfs_rs::boot::BootSector {
        bytes_per_sector: SECTOR_BYTES,
        sectors_per_cluster: SECTORS_PER_CLUSTER,
        cluster_bytes: BLOCK_BYTES,
        total_sectors: SECTORS,
        mft_lcn: MFT_LCN,
        mft_mirror_lcn: MIRROR_LCN,
        record_bytes: RECORD_BYTES as u32,
        index_block_bytes: BLOCK_BYTES,
        serial_number: SERIAL,
    };
    let mut root = vec![0; ROOT_GEOMETRY_BYTES + VIEW_NODE_HEADER_BYTES + VIEW_HEADER_BYTES + VIEW_CHILD_BYTES];
    edit::p32(&mut root, VIEW_ROOT_COLLATION_OFFSET, COLLATION_QUOTA_ID).unwrap();
    edit::p32(&mut root, VIEW_ROOT_BLOCK_SIZE_OFFSET, BLOCK_BYTES).unwrap();
    root[ROOT_CLUSTER_OFFSET] = CLUSTERS_PER_BLOCK;
    edit::p32(&mut root, VIEW_ROOT_NODE_OFFSET, VIEW_NODE_HEADER_BYTES as u32).unwrap();
    let used = (root.len() - VIEW_ROOT_NODE_OFFSET) as u32;
    edit::p32(&mut root, VIEW_ROOT_NODE_OFFSET + VIEW_NODE_USED_OFFSET, used).unwrap();
    edit::p32(&mut root, VIEW_ROOT_NODE_OFFSET + NODE_ALLOCATED_OFFSET, used).unwrap();
    root[VIEW_ROOT_NODE_OFFSET + NODE_FLAGS_OFFSET] = VIEW_CHILD as u8;
    let terminal = VIEW_ROOT_NODE_OFFSET + VIEW_NODE_HEADER_BYTES;
    edit::p16(&mut root, terminal + VIEW_LENGTH_OFFSET, (VIEW_HEADER_BYTES + VIEW_CHILD_BYTES) as u16).unwrap();
    edit::p16(&mut root, terminal + VIEW_FLAGS_OFFSET, VIEW_END | VIEW_CHILD).unwrap();
    let mut record = vec![0; RECORD_BYTES];
    let mut attribute = vec![0; RECORD_BYTES];
    edit::format_empty(&mut record, 0).unwrap();
    let name = b"$\0Q\0";
    let length = edit::build_resident(mft::ATTR_INDEX_ROOT, name, &root, &mut attribute).unwrap();
    edit::insert(&mut record, &attribute[..length]).unwrap();
    let runs = [Extent { vcn: 0, lcn: Some(ALLOCATION_LCN), len: 1 }];
    let length = edit::build_nonresident(
        mft::ATTR_INDEX_ALLOCATION,
        name,
        &runs,
        BLOCK_BYTES as u64,
        BLOCK_BYTES as u64,
        BLOCK_BYTES as u64,
        &mut attribute,
    )
    .unwrap();
    edit::insert(&mut record, &attribute[..length]).unwrap();
    let length = edit::build_resident(ATTR_BITMAP, name, &[1], &mut attribute).unwrap();
    edit::insert(&mut record, &attribute[..length]).unwrap();
    let record = MftRecord::from_decoded(&record).unwrap();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let mut volume = Volume::new(Unreadable(calls.clone()), boot).unwrap();
    let error = quota_rows(&mut volume, &record, name, COLLATION_QUOTA_ID).unwrap_err();
    assert!(calls.get() > 0);
    assert!(!matches!(error.kind(), io::ErrorKind::InvalidData | io::ErrorKind::Unsupported));
}
