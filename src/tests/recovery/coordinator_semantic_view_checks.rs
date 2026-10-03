// Module: slate_ntfs_tools::recovery_io::coordinator_semantic_view_checks
// Purpose: Verify recovery coordination with disposable regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged into the test folder and included in its
// original private scope; this file cannot authorize production disk writes.

use super::*;

#[test]
fn patch_preview_preserves_partial_intersections_and_order() {
    let mut patch = Patch::new(10, vec![0; 4], vec![1, 2, 3, 4]);
    for (at, expected) in [(8, [0, 0, 1, 2]), (10, [1, 2, 3, 4]), (12, [3, 4, 0, 0]), (14, [0; 4])] {
        let mut out = [0; 4];
        patch.copy_after_into(at, &mut out);
        assert_eq!(out, expected);
    }
    let mut out = [0; 8];
    patch.copy_after_into(8, &mut out);
    patch.physical = 12;
    patch.after = vec![7, 8];
    patch.copy_after_into(8, &mut out);
    assert_eq!(out, [0, 0, 1, 2, 7, 8, 0, 0]);
}

#[test]
fn resident_view_requires_a_complete_leaf() {
    let mut root = vec![0_u8; 72];
    root[4..8].copy_from_slice(&17_u32.to_le_bytes());
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&56_u32.to_le_bytes());
    root[24..28].copy_from_slice(&56_u32.to_le_bytes());
    root[32..34].copy_from_slice(&20_u16.to_le_bytes());
    root[34..36].copy_from_slice(&4_u16.to_le_bytes());
    root[40..42].copy_from_slice(&24_u16.to_le_bytes());
    root[42..44].copy_from_slice(&4_u16.to_le_bytes());
    root[56 + 8..56 + 10].copy_from_slice(&16_u16.to_le_bytes());
    root[56 + 12..56 + 14].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(view_node_slots(&root, 16).unwrap().len(), 2);
    root[28] = 1;
    assert!(view_node_slots(&root, 16).is_err());
    root[28] = 0;
    root[56 + 12] = 0;
    assert!(view_node_slots(&root, 16).is_err());
}

#[test]
fn view_node_preserves_separator_and_terminal_children() {
    let mut root = vec![0_u8; 88];
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    root[20..24].copy_from_slice(&72_u32.to_le_bytes());
    root[24..28].copy_from_slice(&72_u32.to_le_bytes());
    root[28] = 1;
    root[32..34].copy_from_slice(&20_u16.to_le_bytes());
    root[34..36].copy_from_slice(&4_u16.to_le_bytes());
    root[40..42].copy_from_slice(&32_u16.to_le_bytes());
    root[42..44].copy_from_slice(&4_u16.to_le_bytes());
    root[44..46].copy_from_slice(&1_u16.to_le_bytes());
    root[56..64].copy_from_slice(&4_u64.to_le_bytes());
    root[64 + 8..64 + 10].copy_from_slice(&24_u16.to_le_bytes());
    root[64 + 12..64 + 14].copy_from_slice(&3_u16.to_le_bytes());
    root[80..88].copy_from_slice(&8_u64.to_le_bytes());
    let slots = view_node_slots(&root, 16).unwrap();
    assert_eq!(slots[0].1, Some(4));
    assert_eq!(slots[1].1, Some(8));
}

#[test]
fn object_lookup_builder_spills_into_valid_index_pages() {
    let boot = ntfs_rs::boot::BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: 1 << 20,
        mft_lcn: 4,
        mft_mirror_lcn: 8,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    };
    let mut entries = checker::consistency::scratch_file().unwrap();
    for i in 0..100_u32 {
        let mut entry = vec![0_u8; 88];
        entry[0..2].copy_from_slice(&32_u16.to_le_bytes());
        entry[2..4].copy_from_slice(&56_u16.to_le_bytes());
        entry[8..10].copy_from_slice(&88_u16.to_le_bytes());
        entry[10..12].copy_from_slice(&16_u16.to_le_bytes());
        entry[16..20].copy_from_slice(&i.to_le_bytes());
        entry[32..40].copy_from_slice(&(i as u64 + 16).to_le_bytes());
        repair_entry_write(&mut entries, &entry).unwrap();
    }
    let (root, mut pages, count) = rebuilt_index(boot, entries, 100, 8800, 512, 0, 19).unwrap();
    assert!(count > 0);
    assert_eq!(u32_at(&root, 4).unwrap(), 19);
    assert!(!view_node_slots(&root, 16).unwrap().is_empty());
    let mut page = vec![0; 4096];
    pages.read_exact(&mut page).unwrap();
    ntfs_rs::index::IndexBlock::parse(&mut page, 512, 0).unwrap();
    assert!(!view_node_slots(&page, 24).unwrap().is_empty());
}
