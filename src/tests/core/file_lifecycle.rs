//! Module: tests::file_lifecycle
//! Purpose: Check record initialization and compressed reclamation boundaries.
//! Created: 2026-10-21
//! Architecture: Unit regressions exercise lifecycle internals through the parent module.

use super::super::{mft::MftRecord, runlist::Extent};
use super::*;

#[test]
fn empty_record_matches_original_physical_and_logical_images() {
    const NUMBER: u64 = 0x1234_5678_9abc;
    const GOLDEN_HEADER_BYTES: usize = 64;
    const GOLDEN_SEQUENCE_OFFSET: usize = 16;
    const GOLDEN_CAPACITY_OFFSET: usize = 28;
    // Fixed header bytes from the original archive's record initialization.
    const GOLDEN_HEADER: [u8; GOLDEN_HEADER_BYTES] = [
        0x46, 0x49, 0x4c, 0x45, 0x30, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x43,
        0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbc, 0x9a, 0x78, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    ];
    const RECORD: usize = 1024;
    for capacity in [RECORD, super::super::tx::RECORD_IMAGE] {
        for (sequence, expected_sequence) in
            [(0_u16, [0x01, 0x00]), (1_u16, [0x01, 0x00]), (0x4321_u16, [0x21, 0x43]), (u16::MAX, [0xff, 0xff])]
        {
            let mut expected = std::vec![0; capacity];
            expected[..GOLDEN_HEADER_BYTES].copy_from_slice(&GOLDEN_HEADER);
            expected[GOLDEN_SEQUENCE_OFFSET..GOLDEN_SEQUENCE_OFFSET + expected_sequence.len()]
                .copy_from_slice(&expected_sequence);
            let expected_capacity = (capacity as u32).to_le_bytes();
            expected[GOLDEN_CAPACITY_OFFSET..GOLDEN_CAPACITY_OFFSET + expected_capacity.len()]
                .copy_from_slice(&expected_capacity);
            let mut actual = std::vec![0xa5; capacity];
            empty_record(&mut actual, RECORD, NUMBER, sequence).unwrap();
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn continuation_reclamation_preserves_compression_boundaries() {
    for (first, clusters, budget, expected) in [(14, 2, 4, None), (16, 16, 4, Some(16)), (16, 16, 0, None)] {
        let mut record = [0; 1024];
        record_edit::format_empty(&mut record, 24).unwrap();
        let mut raw = [0; 1024];
        let bytes = (first + clusters) * 4096;
        let n = record_edit::build_nonresident_at(
            0x80,
            &[],
            &[Extent { vcn: first, len: clusters, lcn: Some(2048) }],
            first,
            bytes,
            bytes,
            bytes,
            &mut raw,
        )
        .unwrap();
        record_edit::p16(&mut raw, 12, 1).unwrap();
        record_edit::p16(&mut raw, 34, 4).unwrap();
        record_edit::p64(&mut raw, 64, bytes).unwrap();
        record_edit::insert(&mut record, &raw[..n]).unwrap();
        let view = MftRecord::from_decoded(&record).unwrap();
        let attribute = view.attributes().next().unwrap().unwrap();
        assert_eq!(reclaim_tail(attribute, budget).unwrap(), expected);
    }
}

#[test]
fn encoded_stream_reclamation_checks_flags_and_compression_boundaries() {
    let mut runs = std::vec::Vec::new();
    for unit in 0..20 {
        runs.push(Extent { vcn: unit * 16, len: 1, lcn: Some((unit + 1) * 4096) });
        runs.push(Extent { vcn: unit * 16 + 1, len: 15, lcn: None });
    }
    let mut attr = [0; 1024];
    let n = record_edit::build_nonresident(DATA, &[], &runs, 320 * 4096, 320 * 4096, 320 * 4096, &mut attr).unwrap();
    let mut raw = [0; 2048];
    record_edit::format_empty(&mut raw, 24).unwrap();
    let at = record_edit::insert(&mut raw, &attr[..n]).unwrap();
    record_edit::p16(&mut raw, at + 34, 4).unwrap();
    for flags in [1, 0x8001] {
        record_edit::p16(&mut raw, at + 12, flags).unwrap();
        let record = MftRecord::from_decoded(&raw).unwrap();
        let attr = record.local_attribute(DATA, &[]).unwrap().unwrap();
        let keep = reclaim_tail(attr, 4).unwrap().unwrap();
        assert_eq!(keep, 16 * 16);
        assert_eq!(keep % 16, 0);
    }
    record_edit::p16(&mut raw, at + 34, 0).unwrap();
    for flags in [0, 0x8000, 0x4000] {
        record_edit::p16(&mut raw, at + 12, flags).unwrap();
        let record = MftRecord::from_decoded(&raw).unwrap();
        let attr = record.local_attribute(DATA, &[]).unwrap().unwrap();
        assert_eq!(check_reclaim_attribute(attr), Ok(()));
    }
    for flags in [2, 0x4001, 0x1000, 1] {
        record_edit::p16(&mut raw, at + 12, flags).unwrap();
        let record = MftRecord::from_decoded(&raw).unwrap();
        let attr = record.local_attribute(DATA, &[]).unwrap().unwrap();
        assert_eq!(check_reclaim_attribute(attr), Err(Error::Unsupported));
    }
}

#[test]
fn sparse_compressed_head_retires_once_without_allocated_clusters() {
    const RECORD_NUMBER: u64 = 24;
    const CLUSTER_BYTES: u64 = BLOCK as u64;
    let mut record = [0; super::super::tx::MAX_RECORD];
    record_edit::format_empty(&mut record, RECORD_NUMBER).unwrap();
    let mut raw = [0; super::super::tx::MAX_RECORD];
    let bytes = af::COMPRESSION_UNIT_CLUSTERS * CLUSTER_BYTES;
    let n = record_edit::build_nonresident(
        DATA,
        &[],
        &[Extent { vcn: 0, len: af::COMPRESSION_UNIT_CLUSTERS, lcn: None }],
        bytes,
        bytes,
        bytes,
        &mut raw,
    )
    .unwrap();
    record_edit::p16(&mut raw, af::FLAGS_OFFSET, af::COMPRESSED | af::SPARSE).unwrap();
    record_edit::p16(&mut raw, af::COMPRESSION_UNIT_OFFSET, af::COMPRESSION_UNIT_SHIFT).unwrap();
    let at = record_edit::insert(&mut record, &raw[..n]).unwrap();
    let view = MftRecord::from_decoded(&record).unwrap();
    let attribute = view.local_attribute(DATA, &[]).unwrap().unwrap();
    assert_eq!(reclaim_tail(attribute, BITMAP_PATCHES).unwrap(), Some(0));
    record_edit::truncate_runs(&mut record, at, 0).unwrap();
    let view = MftRecord::from_decoded(&record).unwrap();
    let attribute = view.local_attribute(DATA, &[]).unwrap().unwrap();
    assert_eq!(reclaim_tail(attribute, BITMAP_PATCHES).unwrap(), None);
}
