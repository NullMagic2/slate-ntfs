//! Module: ntfs_rs::runlist::tests
//! Purpose: Verify mapping frames and checked extent decoding independently.
//! Created: 2026-10-03
//! Architecture: This external test module preserves the former runlist tests
//! and adds shared byte-frame regression cases; production owns the shared mapping codec.

use super::*;

#[test]
fn decodes_relative_and_sparse_runs() {
    // Three clusters at LCN 10, two at LCN 8, one sparse cluster.
    let bytes = [0x11, 3, 10, 0x11, 2, 0xfe, 0x01, 1, 0];
    let extents: std::vec::Vec<_> = DataRuns::new(&bytes, 0).collect();
    assert_eq!(extents.len(), 3);
    assert_eq!(extents[0], Ok(Extent { vcn: 0, len: 3, lcn: Some(10) }));
    assert_eq!(extents[1], Ok(Extent { vcn: 3, len: 2, lcn: Some(8) }));
    assert_eq!(extents[2], Ok(Extent { vcn: 5, len: 1, lcn: None }));
}

#[test]
fn rejects_negative_lengths_at_every_width() {
    for width in 1..=8 {
        for physical in [false, true] {
            let mut bytes = [0_u8; 18];
            bytes[0] = width as u8 | if physical { 0x10 } else { 0 };
            bytes[width] = 0x80;
            if physical {
                bytes[width + 1] = 10;
            }
            let mut runs = DataRuns::new(&bytes, 0);
            assert_eq!(runs.next(), Some(Err(Error::InvalidRunlist)));
            assert_eq!(runs.next(), None);
        }
    }
}

#[test]
fn accepts_positive_signed_limits_without_losing_negative_deltas() {
    for width in 1..=8 {
        let length = (1_u64 << (width * 8 - 1)) - 1;
        let mut bytes = [0_u8; 24];
        bytes[0] = width as u8 | 0x10;
        bytes[1..=width].copy_from_slice(&length.to_le_bytes()[..width]);
        bytes[width + 1] = 10;
        bytes[width + 2..width + 5].copy_from_slice(&[0x11, 1, 0xfe]);
        let runs = DataRuns::new(&bytes, 0).collect::<Result<std::vec::Vec<_>>>().unwrap();
        assert_eq!(runs[0].len, length);
        assert_eq!(runs[0].lcn, Some(10));
        assert_eq!(runs[1].vcn, length);
        assert_eq!(runs[1].lcn, Some(8));
    }
}

#[test]
fn rejects_truncated_and_zero_runs() {
    assert_eq!(DataRuns::new(&[0x11, 1], 0).next(), Some(Err(Error::InvalidRunlist)));
    assert_eq!(DataRuns::new(&[0x01, 0, 0], 0).next(), Some(Err(Error::InvalidRunlist)));
}

#[test]
fn mapping_frame_reports_structure_before_body_without_enforcing_length_policy() {
    const NEGATIVE_LENGTH: [u8; 3] = [0x11, 0x80, 0xfe];
    const SPARSE_HEADER: [u8; 1] = [0x01];
    const INVALID_WIDTH: [u8; 1] = [0x19];

    let header = MappingPairHeader::read(&NEGATIVE_LENGTH, 0).unwrap().unwrap();
    let pair = header.decode(&NEGATIVE_LENGTH).unwrap();
    assert_eq!(pair.length, 128);
    assert!(pair.negative_length);
    assert_eq!(pair.delta, Some(-2));
    assert_eq!(pair.next_offset, NEGATIVE_LENGTH.len());
    let sparse = MappingPairHeader::read(&SPARSE_HEADER, 0).unwrap().unwrap();
    assert_eq!(sparse.delta_width(), 0);
    assert_eq!(sparse.decode(&SPARSE_HEADER), Err(MappingPairError::Truncated));
    assert_eq!(MappingPairHeader::read(&INVALID_WIDTH, 0), Err(MappingPairError::InvalidWidths));
    assert_eq!(MappingPairHeader::read(&[], 0), Err(MappingPairError::MissingHeader));
    let overflowing = MappingPairHeader { cursor: usize::MAX, length_width: 1, delta_width: 1 };
    assert_eq!(overflowing.decode(&[]), Err(MappingPairError::OffsetOverflow));
}

#[test]
fn signed_delta_boundaries_use_minimal_encoding() {
    const CASES: &[(i64, u8)] =
        &[(i64::MIN, 8), (-129, 2), (-128, 1), (-1, 1), (0, 1), (127, 1), (128, 2), (i64::MAX, 8)];
    for &(delta, width) in CASES {
        let mut bytes = [0xa5; 12];
        let size = encode_mapping_pair(1, Some(delta), &mut bytes).unwrap();
        assert_eq!(bytes[0], width << 4 | 1);
        assert_eq!(size, usize::from(width) + 2);
        let pair = MappingPairHeader::read(&bytes, 0).unwrap().unwrap().decode(&bytes).unwrap();
        assert_eq!(pair.delta, Some(delta));
        assert_eq!(bytes[size], 0xa5);
    }
}
