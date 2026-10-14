//! Module: ntfs_rs::metadata_tx::tests
//! Purpose: Verify streamed deallocation ranges, bounded encoding and bitmap selection.
//! Created: 2026-10-09
//! Architecture: Independent bitmap transitions exercise the writer's commit policy.
use super::*;
use std::{vec, vec::Vec};

#[test]
fn mixed_allocation_and_release_logs_the_released_bits() {
    for (before, after, released) in [(0x0f, 0xf0, true), (0x01, 0xfe, true), (0x01, 0x03, false), (0x03, 0x03, false)]
    {
        let mut after = [after];
        let patch = MetadataPatch {
            fresh: false,
            physical: 4096,
            logical: 0,
            stream_reference: system_record::BITMAP,
            mft: false,
            attribute_kind: ATTR_DATA,
            name: &[],
            before: &[before],
            after: &mut after,
        };
        assert_eq!(freed_ranges(&[patch]).next().is_some(), released);
    }
}

#[test]
fn file_payload_bit_changes_are_not_allocation_events() {
    let mut after = [0];
    let patch = MetadataPatch {
        fresh: false,
        physical: 4096,
        logical: 0,
        stream_reference: 48,
        mft: false,
        attribute_kind: ATTR_DATA,
        name: &[],
        before: &[255],
        after: &mut after,
    };
    assert!(!freed_ranges(&[patch]).next().is_some());
}

#[test]
fn contiguous_and_fragmented_releases_preserve_exact_cluster_numbers() {
    assert_eq!(released_ranges(512, &[0xff, 0xff, 0xff], &[0x7f, 0x00, 0xfe]).collect::<Vec<_>>(), vec![(4103, 10)]);
    let ranges: Vec<_> = released_ranges(512, &[0x55; 512], &[0; 512]).collect();
    assert_eq!(ranges.len(), 2048);
    for (i, range) in ranges.iter().enumerate() {
        assert_eq!(*range, (4096 + 2 * i as u64, 1));
    }
    assert_eq!(release_log_pages(ranges.len()), 9);
    assert_eq!(release_log_pages(0), 0);
    assert_eq!(release_log_pages(RANGES_PER_RECORD), 1);
    assert_eq!(release_log_pages(RANGES_PER_RECORD + 1), 2);
}
