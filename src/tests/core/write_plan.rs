//! Module: tests::write_plan
//! Purpose: Verify complete, bounded physical metadata mappings.
//! Created: 2026-10-21
//! Architecture: Exercises the shared span mapper independently of disk I/O.

use super::super::mft::{MftRecord, ATTR_DATA};
use super::*;

fn sample_record() -> [u8; 1024] {
    let mut bytes = [0_u8; 1024];
    bytes[0..4].copy_from_slice(b"FILE");
    bytes[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&3_u16.to_le_bytes());
    bytes[0x14..0x16].copy_from_slice(&0x38_u16.to_le_bytes());
    bytes[0x18..0x1c].copy_from_slice(&0x88_u32.to_le_bytes());
    bytes[0x30..0x32].copy_from_slice(&0x1234_u16.to_le_bytes());
    bytes[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
    bytes[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
    bytes[0x38..0x3c].copy_from_slice(&ATTR_DATA.to_le_bytes());
    bytes[0x3c..0x40].copy_from_slice(&0x48_u32.to_le_bytes());
    bytes[0x40] = 1;
    bytes[0x50..0x58].copy_from_slice(&1_u64.to_le_bytes());
    bytes[0x58..0x5a].copy_from_slice(&0x40_u16.to_le_bytes());
    bytes[0x68..0x70].copy_from_slice(&8192_u64.to_le_bytes());
    bytes[0x70..0x78].copy_from_slice(&8192_u64.to_le_bytes());
    bytes[0x78..0x7f].copy_from_slice(&[0x11, 1, 10, 0x11, 1, 10, 0]);
    bytes[0x80..0x84].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes
}

fn boot() -> BootSector {
    BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: 8192,
        mft_lcn: 4,
        mft_mirror_lcn: 8,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    }
}

#[test]
fn maps_cross_extent_overwrite_without_writing() {
    let mut data = sample_record();
    let record = MftRecord::parse(&mut data, 512).unwrap();
    let attr = record.attributes().next().unwrap().unwrap();
    let mut spans = std::vec::Vec::new();
    assert_eq!(
        plan_nonresident_overwrite(attr, boot(), 4094, 4, |span| {
            spans.push(span);
            Ok(())
        }),
        Ok(2)
    );
    assert_eq!(
        spans,
        [
            WriteSpan { physical_offset: 10 * 4096 + 4094, source_offset: 0, length: 2 },
            WriteSpan { physical_offset: 20 * 4096, source_offset: 2, length: 2 },
        ]
    );
}

#[test]
fn refuses_sparse_and_extending_writes() {
    let mut data = sample_record();
    let record = MftRecord::parse(&mut data, 512).unwrap();
    let attr = record.attributes().next().unwrap().unwrap();
    assert_eq!(plan_nonresident_overwrite(attr, boot(), 8190, 4, |_| Ok(())), Err(Error::InvalidAttribute));
    let mut data = sample_record();
    data[0x7b] = 0x01; // sparse second run
    data[0x7e] = 0;
    let record = MftRecord::parse(&mut data, 512).unwrap();
    let attr = record.attributes().next().unwrap().unwrap();
    assert_eq!(plan_nonresident_overwrite(attr, boot(), 0, 4, |_| Ok(())), Err(Error::InvalidRunlist));
}

#[test]
fn sparse_hole_is_rejected_before_any_visitor_call() {
    let mut data = sample_record();
    data[0x44..0x46].copy_from_slice(&0x8000u16.to_le_bytes());
    data[0x3c..0x40].copy_from_slice(&0x58u32.to_le_bytes());
    data[0x58..0x5a].copy_from_slice(&0x48u16.to_le_bytes());
    data[0x78..0x80].copy_from_slice(&4096u64.to_le_bytes());
    data[0x80..0x90].fill(0);
    data[0x80..0x86].copy_from_slice(&[0x11, 1, 10, 0x01, 1, 0]);
    data[0x90..0x94].copy_from_slice(&u32::MAX.to_le_bytes());
    data[0x18..0x1c].copy_from_slice(&0x98u32.to_le_bytes());
    let record = MftRecord::parse(&mut data, 512).unwrap();
    let attr = record.attributes().next().unwrap().unwrap();
    let mut calls = 0;
    assert_eq!(
        plan_nonresident_overwrite(attr, boot(), 4094, 4, |_| {
            calls += 1;
            Ok(())
        }),
        Err(Error::InvalidRunlist)
    );
    assert_eq!(calls, 0);
    assert_eq!(plan_nonresident_overwrite(attr, boot(), 0, 4, |_| Ok(())), Ok(1));
}

#[test]
fn metadata_map_retains_nonadjacent_cluster_addresses() {
    let mut bytes = sample_record();
    let record = MftRecord::parse(&mut bytes, 512).unwrap();
    let attr = record.attributes().next().unwrap().unwrap();
    let mut geometry = boot();
    geometry.cluster_bytes = 512;
    geometry.sectors_per_cluster = 1;
    let mut mapping = [0; METADATA_MAP_BYTES];
    let (physical, used) = map_metadata(attr, geometry, 0, 1024, &mut mapping).unwrap();
    assert_eq!(physical, 10 * u64::from(geometry.cluster_bytes));
    assert_eq!(used, 2 * LCN_BYTES);
    let mut spans = std::vec::Vec::new();
    metadata_spans(physical, &mapping[..used], u64::from(geometry.cluster_bytes), 1024, |span| {
        spans.push(span);
        Ok(())
    })
    .unwrap();
    assert_eq!(spans.iter().map(|span| span.physical_offset).collect::<std::vec::Vec<_>>(), [10 * 512, 20 * 512]);
    assert!(metadata_overlap(physical, &mapping[..used], 1024, 20 * 512, &[], 512, 512).unwrap());
    assert!(!metadata_overlap(physical, &mapping[..used], 1024, 11 * 512, &[], 512, 512).unwrap());
}

#[test]
fn invalid_metadata_maps_are_rejected_before_io() {
    let cases = [std::vec![10_u64, 10], std::vec![11, 20], std::vec![10], std::vec![10, u64::MAX]];
    for lcns in cases {
        let map = lcns.into_iter().flat_map(u64::to_le_bytes).collect::<std::vec::Vec<_>>();
        let mut calls = 0;
        assert!(metadata_spans(10 * 512, &map, 512, 1024, |_| {
            calls += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(calls, 0);
    }
}

#[test]
fn maximum_metadata_mapping_covers_all_fixup_strides() {
    let map =
        (0..METADATA_CLUSTERS).flat_map(|index| (10 + index as u64 * 2).to_le_bytes()).collect::<std::vec::Vec<_>>();
    let mut covered = 0;
    metadata_spans(10 * 512, &map, 512, super::super::boot::MAX_WRITER_RECORD_BYTES, |span| {
        assert_eq!(span.source_offset, covered);
        covered += span.length;
        Ok(())
    })
    .unwrap();
    assert_eq!(covered, super::super::boot::MAX_WRITER_RECORD_BYTES as u64);
}
