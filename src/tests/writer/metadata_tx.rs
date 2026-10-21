//! Module: ntfs_rs::metadata_tx::tests
//! Purpose: Verify streamed deallocation ranges, bounded encoding and bitmap selection.
//! Created: 2026-10-09
//! Architecture: Independent bitmap transitions exercise the writer's commit policy.
use super::*;
use std::{boxed::Box, vec, vec::Vec};

#[test]
fn mixed_allocation_and_release_logs_the_released_bits() {
    for (before, after, released) in [(0x0f, 0xf0, true), (0x01, 0xfe, true), (0x01, 0x03, false), (0x03, 0x03, false)]
    {
        let mut after = [after];
        let patch = MetadataPatch {
            fresh: false,
            physical: 4096,
            physical_clusters: &[],
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
        physical_clusters: &[],
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

#[test]
fn mapped_hold_release_preserves_only_live_fragment_keys() {
    struct Held {
        keys: Vec<(u64, usize)>,
    }
    impl ReadAt for Held {
        fn read_exact_at(&mut self, _: u64, _: &mut [u8]) -> Result<()> {
            Err(Error::Io)
        }
    }
    impl WriteIo for Held {
        fn write_at(&mut self, _: u64, _: &[u8]) -> Result<()> {
            Ok(())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
        fn release_at(&mut self, physical: u64, len: usize) {
            self.keys.retain(|key| *key != (physical, len));
        }
    }
    const CLUSTER_BYTES: usize = super::super::boot::MIN_SECTOR_BYTES as usize;
    const FRAGMENT_COUNT: usize = 2;
    const RECORD_BYTES: usize = FRAGMENT_COUNT * CLUSTER_BYTES;
    const SHARED_LCN: u64 = 10;
    const RETIRED_LCN: u64 = 20;
    const NEW_LCN: u64 = 30;
    const MIRROR_LCN: u64 = 100;
    let old_map: Vec<_> = [SHARED_LCN, RETIRED_LCN].into_iter().flat_map(u64::to_le_bytes).collect();
    let new_map: Vec<_> = [SHARED_LCN, NEW_LCN].into_iter().flat_map(u64::to_le_bytes).collect();
    let mut writer = Writer::BLANK;
    writer.boot.cluster_bytes = CLUSTER_BYTES as u32;
    writer.boot.record_bytes = RECORD_BYTES as u32;
    writer.boot.mft_mirror_lcn = MIRROR_LCN;
    writer.batch.attach(Box::leak(vec![0; super::super::batch::BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.committed.attach(Box::leak(vec![0; super::super::batch::BATCH_BYTES].into_boxed_slice())).unwrap();
    let before = [0; RECORD_BYTES];
    let mut old_after = [1; RECORD_BYTES];
    let mut new_after = [2; RECORD_BYTES];
    let logical = system_record::VOLUME * RECORD_BYTES as u64;
    let old = MetadataPatch {
        fresh: false,
        physical: SHARED_LCN * CLUSTER_BYTES as u64,
        physical_clusters: &old_map,
        logical,
        stream_reference: system_record::MFT,
        mft: true,
        attribute_kind: ATTR_DATA,
        name: &[],
        before: &before,
        after: &mut old_after,
    };
    writer.committed.push(&old, old.before).unwrap();
    let pending = MetadataPatch { physical_clusters: &new_map, after: &mut new_after, ..old };
    writer.batch.push(&pending, pending.before).unwrap();
    let shared = (SHARED_LCN * CLUSTER_BYTES as u64, CLUSTER_BYTES);
    let retired = (RETIRED_LCN * CLUSTER_BYTES as u64, CLUSTER_BYTES);
    let added = (NEW_LCN * CLUSTER_BYTES as u64, CLUSTER_BYTES);
    let mirror = (MIRROR_LCN * CLUSTER_BYTES as u64 + logical, RECORD_BYTES);
    assert!(writer.pending_hold(&[], shared.0, shared.1).unwrap());
    assert!(!writer.pending_hold(&[], shared.0, RECORD_BYTES).unwrap());
    assert!(!writer.pending_hold(&[], retired.0, retired.1).unwrap());
    assert!(writer.pending_hold(&[], mirror.0, mirror.1).unwrap());
    let mut held = Held { keys: vec![shared, retired, added, mirror] };
    writer.release_unused_committed(&mut held, 0, &[]).unwrap();
    assert_eq!(held.keys, vec![shared, added, mirror]);
    let (arena, _) = writer.batch.take().unwrap();
    assert!(!writer.pending_hold(&[], shared.0, shared.1).unwrap());
    held.keys = vec![shared, retired, added, mirror];
    writer.write_committed_home(&mut held, &[pending]).unwrap();
    assert_eq!(held.keys, vec![shared, added, mirror]);
    assert_eq!(writer.committed.count(), 0);
    writer.batch.restore(arena);
}
