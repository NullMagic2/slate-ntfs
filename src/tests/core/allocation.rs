//! Module: ntfs_rs::allocation::tests
//! Purpose: Verify allocation contracts independently.
//! Created: 2026-10-03
//! Architecture: The production module references these selectable unit tests.

use super::super::runlist::DataRuns;
use super::*;
#[test]
fn mapping_pairs_roundtrip_negative_deltas_and_large_runs() {
    let runs = [Extent { vcn: 0, len: 300, lcn: Some(1000) }, Extent { vcn: 300, len: 1, lcn: Some(10) }];
    let mut bytes = [0; 40];
    let n = encode_runs(&runs, &mut bytes).unwrap();
    assert_eq!(DataRuns::new(&bytes[..n], 0).collect::<std::vec::Vec<_>>(), runs.map(Ok));
}
#[test]
fn mft_reservation_excludes_system_slots_and_rejects_double_free() {
    let mut bits = [0; 4];
    assert_eq!(reserve_mft_slot(&mut bits, 32), Ok(16));
    assert_eq!(reserve_mft_slot(&mut bits, 32), Ok(17));
    assert_eq!(release_mft_slot(&mut bits, 16, 32), Ok(()));
    assert_eq!(release_mft_slot(&mut bits, 16, 32), Err(Error::InvalidRecord));
    assert_eq!(release_mft_slot(&mut bits, 0, 32), Err(Error::InvalidRecord));
    assert_eq!(reserve_mft_slot(&mut bits, 32), Ok(16));
}

#[test]
fn bitmap_capacity_rejection_preserves_the_entire_plan() {
    use super::super::{
        boot::BootSector,
        mft::{system_record, MftRecord, ATTR_DATA},
        record_edit,
    };
    struct Zeros {
        reads: usize,
    }
    impl ReadAt for Zeros {
        fn read_exact_at(&mut self, _offset: u64, output: &mut [u8]) -> Result<()> {
            self.reads += 1;
            output.fill(0);
            Ok(())
        }
    }
    let geometry = BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 1,
        cluster_bytes: 512,
        total_sectors: 1 << 20,
        mft_lcn: 1,
        mft_mirror_lcn: 2,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    };
    let bitmap_bytes = (BITMAP_PATCHES as u64 + 1) * BITMAP_SECTOR_BYTES;
    let limit = bitmap_bytes * u64::from(u8::BITS);
    let mut raw = [0; 1024];
    record_edit::format_empty(&mut raw, system_record::BITMAP).unwrap();
    let mut descriptor = [0; 128];
    let len = record_edit::build_nonresident(
        ATTR_DATA,
        &[],
        &[Extent { vcn: 0, len: bitmap_bytes / u64::from(geometry.cluster_bytes), lcn: Some(1) }],
        bitmap_bytes,
        bitmap_bytes,
        bitmap_bytes,
        &mut descriptor,
    )
    .unwrap();
    record_edit::insert(&mut raw, &descriptor[..len]).unwrap();
    let record = MftRecord::from_decoded(&raw).unwrap();
    let attribute = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    let mut storage = std::vec![0; BITMAP_PLAN_BYTES];
    let mut plan = BitmapPlan::new(&mut storage).unwrap();
    let mut volume = Volume::new(Zeros { reads: 0 }, geometry).unwrap();
    assert_eq!(plan.change(&mut volume, attribute, 0, limit, true, limit), Err(Error::NoSpace));
    assert_eq!(volume.reader_mut().reads, 0);
    assert_eq!(plan.count, 0);
    assert!(plan.bytes.iter().all(|byte| *byte == 0));
    plan.change(&mut volume, attribute, 0, 0, true, limit).unwrap();
    for index in 0..BITMAP_PATCHES {
        plan.change(&mut volume, attribute, index as u64 * CLUSTERS_PER_BITMAP_SECTOR, 1, true, limit).unwrap();
    }
    let before = plan.bytes.to_vec();
    assert_eq!(
        plan.change(&mut volume, attribute, BITMAP_PATCHES as u64 * CLUSTERS_PER_BITMAP_SECTOR, 1, true, limit),
        Err(Error::NoSpace)
    );
    assert_eq!(plan.bytes, before);
    assert_eq!(plan.count, BITMAP_PATCHES);
}
