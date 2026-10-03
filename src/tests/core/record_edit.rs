//! Module: ntfs_rs::record_edit::tests
//! Purpose: Verify record edit contracts independently.
//! Created: 2026-10-03
//! Architecture: The production module references these selectable unit tests.

use super::*;
fn empty() -> [u8; 1024] {
    let mut b = [0; 1024];
    format_empty(&mut b, 20).unwrap();
    p16(&mut b, 22, 1).unwrap();
    b
}
#[test]
fn insert_orders_attributes_and_assigns_ids() {
    let mut rec = empty();
    let mut a = [0; 128];
    let n = build_resident(0xb0, b"$\0I\x003\x000\0", &[0; 8], &mut a).unwrap();
    insert(&mut rec, &a[..n]).unwrap();
    let n = build_resident(0x10, &[], &[1; 72], &mut a).unwrap();
    let at = insert(&mut rec, &a[..n]).unwrap();
    validate(&rec).unwrap();
    assert_eq!(attr_kind(&rec, at).unwrap(), 0x10);
    assert_eq!(u16_at(&rec, at + 14).unwrap(), 1);
    set_resident_value(&mut rec, at, &[2; 48]).unwrap();
    validate(&rec).unwrap();
    let bitmap = require(&rec, 0xb0, b"$\0I\x003\x000\0").unwrap();
    remove(&mut rec, bitmap).unwrap();
    validate(&rec).unwrap();
    assert_eq!(find(&rec, 0xb0, b"$\0I\x003\x000\0").unwrap(), None);
}
#[test]
fn compressed_mapping_edits_preserve_unit_and_physical_size() {
    let runs = [
        Extent { vcn: 0, len: 2, lcn: Some(100) },
        Extent { vcn: 2, len: 14, lcn: None },
        Extent { vcn: 16, len: 16, lcn: Some(200) },
    ];
    let mut attr = [0; 256];
    let n = build_nonresident(0x80, &[], &runs, 32 * 4096, 32 * 4096, 32 * 4096, &mut attr).unwrap();
    p16(&mut attr, 12, 1).unwrap();
    p16(&mut attr, 34, 4).unwrap();
    p64(&mut attr, 64, 18 * 4096).unwrap();
    let mut record = empty();
    let at = insert(&mut record, &attr[..n]).unwrap();
    let decoded = MftRecord::from_decoded(&record).unwrap();
    let source = decoded.local_attribute(0x80, &[]).unwrap().unwrap();
    let mut packed = [0; 256];
    pack_mapping_segment(source, 0, &mut packed).unwrap();
    assert_eq!(u16_at(&packed, 12).unwrap(), 1);
    assert_eq!(u16_at(&packed, 34).unwrap(), 4);
    assert_eq!(u64_at(&packed, 64).unwrap(), 18 * 4096);
    truncate_runs(&mut record, at, 16).unwrap();
    set_sizes(&mut record, at, 16 * 4096, 16 * 4096, 16 * 4096).unwrap();
    validate(&record).unwrap();
    assert_eq!(u64_at(&record, at + 64).unwrap(), 2 * 4096);
    assert_eq!(u16_at(&record, at + 34).unwrap(), 4);
}

#[test]
fn mapping_segments_pack_by_bytes_and_reassemble_dense_and_sparse_runs() {
    let runs: std::vec::Vec<_> = (0..700)
        .map(|i| Extent {
            vcn: i,
            len: 1,
            lcn: if i % 11 == 0 {
                None
            } else if i % 2 == 0 {
                Some(100_000 + i * 3)
            } else {
                Some(100 + i * 3)
            },
        })
        .collect();
    let name = b"s\0t\0r\0e\0a\0m\0";
    let mut original = std::vec![0_u8; 8192];
    let length = build_nonresident(
        super::super::mft::ATTR_DATA,
        name,
        &runs,
        700 * 4096,
        700 * 4096 - 7,
        700 * 4096 - 17,
        &mut original,
    )
    .unwrap();
    let mut source = std::vec![0_u8; 16 * 1024];
    format_empty(&mut source, 30).unwrap();
    let at = insert(&mut source, &original[..length]).unwrap();
    let record = MftRecord::from_decoded(&source).unwrap();
    let attribute = record.local_attribute(0x80, name).unwrap().unwrap();
    let mut assembled = std::vec![0_u8; 16 * 1024];
    format_empty(&mut assembled, 30).unwrap();
    let mut segment = [0_u8; 960];
    let mut first = 0;
    let mut segments = 0;
    while first < 700 {
        let (length, next) = pack_mapping_segment(attribute, first, &mut segment).unwrap();
        assert!(next - first > 16, "packing must use the full record capacity");
        assert!(length <= segment.len());
        assert_eq!(u16_at(&segment, 12).unwrap(), 0x8000);
        assert_eq!(u64_at(&segment, 40).unwrap(), 700 * 4096);
        assert_eq!(u64_at(&segment, 48).unwrap(), 700 * 4096 - 7);
        assert_eq!(u64_at(&segment, 56).unwrap(), 700 * 4096 - 17);
        assert_eq!(u64_at(&segment, 64).unwrap(), u64_at(&source, at + 64).unwrap());
        merge_attribute(&mut assembled, &segment[..length]).unwrap();
        validate(&assembled).unwrap();
        first = next;
        segments += 1;
    }
    assert!(segments > 1 && segments < 6);
    let record = MftRecord::from_decoded(&assembled).unwrap();
    let attribute = record.local_attribute(0x80, name).unwrap().unwrap();
    let decoded = DataRuns::new(attribute.data_runs().unwrap(), 0).collect::<Result<std::vec::Vec<_>>>().unwrap();
    assert_eq!(decoded, runs);
    assert_eq!(attribute.flags().unwrap(), 0x8000);
}

#[test]
fn failed_mapping_merge_preserves_the_record() {
    let mut record = empty();
    let mut first = [0; 128];
    let run = Extent { vcn: 0, len: 1, lcn: Some(100) };
    let length = build_nonresident(0x80, &[], &[run], 8192, 8192, 8192, &mut first).unwrap();
    insert(&mut record, &first[..length]).unwrap();
    let mut tail = std::vec![0_u8; 8192];
    let runs: std::vec::Vec<_> = (1..600).map(|i| Extent { vcn: i, len: 1, lcn: Some(100 + i * 2) }).collect();
    let length = build_nonresident_at(0x80, &[], &runs, 1, 600 * 4096, 600 * 4096, 600 * 4096, &mut tail).unwrap();
    let before = record;
    assert_eq!(merge_attribute(&mut record, &tail[..length]), Err(Error::NoSpace));
    assert_eq!(record, before);
}

#[test]
fn mapping_lengths_use_positive_signed_widths_for_dense_and_sparse_runs() {
    for width in 1..=8 {
        let maximum = (1_u64 << (width * 8 - 1)) - 1;
        for length in [maximum, maximum.saturating_add(1)] {
            for delta in [None, Some(10), Some(-2)] {
                let mut bytes = [0_u8; 20];
                if length > i64::MAX as u64 {
                    assert_eq!(encode_extent(length, delta, &mut bytes), Err(Error::InvalidRunlist));
                    assert_eq!(bytes, [0; 20]);
                    continue;
                }
                let size = encode_extent(length, delta, &mut bytes).unwrap();
                let expected = width + usize::from(length > maximum);
                assert_eq!(usize::from(bytes[0] & 0xf), expected);
                assert_eq!(bytes[expected] & 0x80, 0);
                let decoded = pair(&bytes, 0, size).unwrap().unwrap();
                assert_eq!(decoded.length, length);
                assert_eq!(decoded.delta, delta.unwrap_or(0));
                assert_eq!(decoded.sparse, delta.is_none());
                if delta != Some(-2) {
                    let run = DataRuns::new(&bytes[..size + 1], 0).next().unwrap().unwrap();
                    assert_eq!(run.len, length);
                    assert_eq!(run.lcn, delta.map(|n| n as u64));
                }
            }
        }
    }
    for invalid in [0, u64::MAX] {
        let mut bytes = [0; 20];
        assert_eq!(encode_extent(invalid, None, &mut bytes), Err(Error::InvalidRunlist));
        assert_eq!(bytes, [0; 20]);
    }
}

#[test]
fn mapping_append_and_truncate_cross_signed_length_boundaries() {
    for initial in [127, 32767] {
        for lcn in [None, Some(100)] {
            let mut rec = empty();
            let mut raw = [0; 256];
            let run = Extent { vcn: 0, len: initial, lcn };
            let size =
                build_nonresident(0x80, &[], &[run], initial * 4096, initial * 4096, initial * 4096, &mut raw).unwrap();
            let at = insert(&mut rec, &raw[..size]).unwrap();
            append_extent(&mut rec, at, lcn.map(|n| n + initial), 1).unwrap();
            set_sizes(&mut rec, at, (initial + 1) * 4096, (initial + 1) * 4096, (initial + 1) * 4096).unwrap();
            validate(&rec).unwrap();
            let decoded = MftRecord::from_decoded(&rec).unwrap();
            let data = decoded.local_attribute(0x80, &[]).unwrap().unwrap();
            let extents = DataRuns::new(data.data_runs().unwrap(), 0).collect::<Result<std::vec::Vec<_>>>().unwrap();
            assert_eq!(extents.len(), 1);
            assert_eq!(extents[0].len, initial + 1);
            assert_eq!(extents[0].lcn, lcn);
            truncate_runs(&mut rec, at, initial).unwrap();
            set_sizes(&mut rec, at, initial * 4096, initial * 4096, initial * 4096).unwrap();
            validate(&rec).unwrap();
            let decoded = MftRecord::from_decoded(&rec).unwrap();
            let data = decoded.local_attribute(0x80, &[]).unwrap().unwrap();
            let extents = DataRuns::new(data.data_runs().unwrap(), 0).collect::<Result<std::vec::Vec<_>>>().unwrap();
            assert_eq!(extents, [run]);
            let before = rec;
            assert_eq!(
                append_extent(&mut rec, at, lcn.map(|n| n + initial), i64::MAX as u64),
                Err(Error::InvalidRunlist)
            );
            assert_eq!(rec, before);
        }
    }
}

#[test]
fn nonresident_runs_append_and_merge() {
    let mut rec = empty();
    let mut a = [0; 256];
    let runs0 = [Extent { vcn: 0, len: 1, lcn: Some(100) }];
    let n = build_nonresident(0xa0, b"$\0I\x003\x000\0", &runs0, 4096, 4096, 4096, &mut a).unwrap();
    let at = insert(&mut rec, &a[..n]).unwrap();
    append_run(&mut rec, at, 101, 1).unwrap();
    append_run(&mut rec, at, 7, 2).unwrap();
    set_sizes(&mut rec, at, 16384, 16384, 16384).unwrap();
    validate(&rec).unwrap();
    let mut out = [Extent { vcn: 0, len: 0, lcn: None }; 4];
    assert_eq!(runs(&rec, at, &mut out).unwrap(), 2);
    assert_eq!(out[0].len, 2);
    assert_eq!(out[1].lcn, Some(7));
    assert_eq!(u64_at(&rec, at + 24).unwrap(), 3);
}
