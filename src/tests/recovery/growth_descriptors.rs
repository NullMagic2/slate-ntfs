// Module: slate_ntfs_tools::recovery_io::models::growth::descriptor_tests
// Purpose: Verify segmentation against captured original output and fixed bytes.
// Created: 2026-10-02
// Architecture: Included in growth's private scope; fixed goldens preserve the
// prior codec's capacity decisions without retaining a second algorithm.

use super::*;
use ntfs_rs::bytes::u64_at;

const MAPPING_BUFFER_PREFIX_BYTES: usize = 96;
const MAX_MAPPING_PAIR_BYTES: usize = 17;
const U64_BYTES: usize = std::mem::size_of::<u64>();
const ATTRIBUTE_LENGTH_OFFSET: usize = 4;
const NONRESIDENT_FLAG_OFFSET: usize = 8;
const RECORD_BYTES: usize = 1024;
const CLUSTER_BYTES: u64 = 4096;
const FIRST_VCN_OFFSET: usize = 16;
const LAST_VCN_OFFSET: usize = 24;
const RUNS_OFFSET_FIELD: usize = 32;
const SIZE_FIELDS_START: usize = 40;
const DATA_SIZE_OFFSET: usize = SIZE_FIELDS_START + U64_BYTES;
const INITIALIZED_SIZE_OFFSET: usize = DATA_SIZE_OFFSET + U64_BYTES;
const SIZE_FIELDS_END: usize = INITIALIZED_SIZE_OFFSET + U64_BYTES;
const NONRESIDENT_HEADER_BYTES: usize = 72;
const SINGLE_RUN_ROOM_BYTES: usize = 80;
const ALIGNMENT_BYTES: usize = 8;
const ALLOCATED_BYTES: u64 = 1 << 30;
const DATA_BYTES: u64 = ALLOCATED_BYTES - CLUSTER_BYTES;
const GROWTH_CAPACITY_ERROR: &str = "MFT mapping pair exceeds record capacity";

fn runs() -> Vec<Extent> {
    vec![
        Extent { vcn: 0, lcn: Some(10), len: 128 },
        Extent { vcn: 128, lcn: Some(1000), len: 1 },
        Extent { vcn: 129, lcn: Some(2), len: 256 },
        Extent { vcn: 385, lcn: Some(30000), len: 65536 },
    ]
}

fn full_descriptor(runs: &[Extent]) -> Vec<u8> {
    let mut attribute = vec![0; MAPPING_BUFFER_PREFIX_BYTES + runs.len() * MAX_MAPPING_PAIR_BYTES];
    let used =
        e::build_nonresident(ATTR_DATA, &[], runs, ALLOCATED_BYTES, DATA_BYTES, DATA_BYTES, &mut attribute).unwrap();
    attribute.truncate(used);
    attribute
}

fn shared_segments(runs: &[Extent], room: usize) -> io::Result<Vec<Vec<u8>>> {
    relocation::mapping_descriptors(
        &full_descriptor(runs),
        runs.len(),
        |i| Ok(runs[i]),
        room,
        GROWTH_CAPACITY_ERROR,
    )
    .map(|changes| changes.into_iter().map(|change| change.attribute.unwrap()).collect())
}

#[test]
fn shared_growth_segments_match_previous_bytes_at_capacity_boundaries() {
    const ORIGINAL_DIGESTS: [[u8; 32]; 3] = [
        [
            0x5b, 0x56, 0xeb, 0x5e, 0xfa, 0x47, 0xb0, 0xf6, 0x06, 0xe7, 0xb2, 0x09, 0xc7, 0xe3, 0xcf, 0xd8, 0xf5, 0x8e,
            0x7d, 0x73, 0xc8, 0x99, 0x41, 0xc5, 0x77, 0x6d, 0x8e, 0xe9, 0x79, 0x2d, 0x41, 0x1c,
        ],
        [
            0x1b, 0x97, 0x13, 0x30, 0xec, 0x87, 0xb1, 0x60, 0x77, 0x9b, 0x92, 0x53, 0x65, 0x9e, 0xfa, 0xac, 0xea, 0xa4,
            0xd8, 0x9b, 0x1d, 0x4a, 0x08, 0xb7, 0x80, 0xc3, 0x22, 0xbd, 0x62, 0x7a, 0x75, 0x4b,
        ],
        [
            0x05, 0x2c, 0x6f, 0xe3, 0xee, 0x93, 0xe6, 0xf1, 0x08, 0x2b, 0x21, 0xf9, 0x72, 0x85, 0xda, 0xb4, 0x42, 0xa7,
            0x76, 0xfd, 0x3a, 0x54, 0xa5, 0x1f, 0xa3, 0x8a, 0x56, 0xc4, 0xda, 0xdd, 0x28, 0xa8,
        ],
    ];
    let runs = runs();
    // Each digest covers ordered u64 length + attribute bytes from the old codec.
    for (room, golden, lengths) in [
        (SINGLE_RUN_ROOM_BYTES, 0, &[80, 80, 80, 80][..]),
        (SINGLE_RUN_ROOM_BYTES + ALIGNMENT_BYTES - 1, 0, &[80, 80, 80, 80][..]),
        (SINGLE_RUN_ROOM_BYTES + ALIGNMENT_BYTES, 1, &[88, 80][..]),
        (SINGLE_RUN_ROOM_BYTES + ALIGNMENT_BYTES * 2 - 1, 1, &[88, 80][..]),
        (SINGLE_RUN_ROOM_BYTES + ALIGNMENT_BYTES * 2, 2, &[96][..]),
        (RECORD_BYTES, 2, &[96][..]),
    ] {
        let actual = shared_segments(&runs, room).unwrap();
        assert_eq!(actual.iter().map(Vec::len).collect::<Vec<_>>(), lengths);
        let mut framed = Vec::new();
        for attribute in &actual {
            framed.extend_from_slice(&(attribute.len() as u64).to_le_bytes());
            framed.extend_from_slice(attribute);
        }
        assert_eq!(ntfs_rs::sha256::digest(&framed), ORIGINAL_DIGESTS[golden]);
        assert!(actual.iter().all(|attribute| attribute.len() <= room));
        for (index, attribute) in actual.iter().enumerate() {
            if index == 0 {
                assert_eq!(u64_at(attribute, FIRST_VCN_OFFSET).unwrap(), 0);
                assert_eq!(u64_at(attribute, SIZE_FIELDS_START).unwrap(), ALLOCATED_BYTES);
            } else {
                assert!(u64_at(attribute, FIRST_VCN_OFFSET).unwrap() > 0);
                assert_eq!(&attribute[SIZE_FIELDS_START..SIZE_FIELDS_END], &[0; SIZE_FIELDS_END - SIZE_FIELDS_START]);
            }
        }
    }
    let error = shared_segments(&runs, SINGLE_RUN_ROOM_BYTES - 1).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(error.to_string(), GROWTH_CAPACITY_ERROR);
    let error = relocation::mapping_descriptors(
        &full_descriptor(&runs),
        runs.len(),
        |i| Ok(runs[i]),
        SINGLE_RUN_ROOM_BYTES - 1, relocation::DESCRIPTOR_CAPACITY,)
    .err()
    .unwrap();
    assert_eq!(error.to_string(), "relocation descriptor cannot fit an MFT record");
}

#[test]
fn shared_growth_segments_match_fixed_header_and_mapping_pair_golden() {
    let runs = runs();
    let actual = shared_segments(&runs, SINGLE_RUN_ROOM_BYTES).unwrap();
    assert_eq!(actual.len(), runs.len());
    let pairs = [
        vec![0x12, 0x80, 0x00, 0x0a, 0, 0, 0, 0],
        vec![0x21, 0x01, 0xe8, 0x03, 0, 0, 0, 0],
        vec![0x12, 0x00, 0x01, 0x02, 0, 0, 0, 0],
        vec![0x23, 0x00, 0x00, 0x01, 0x30, 0x75, 0, 0],
    ];
    for (index, (run, pairs)) in runs.iter().zip(pairs).enumerate() {
        let mut expected = vec![0; SINGLE_RUN_ROOM_BYTES];
        expected[..ATTRIBUTE_LENGTH_OFFSET].copy_from_slice(&ATTR_DATA.to_le_bytes());
        expected[ATTRIBUTE_LENGTH_OFFSET..NONRESIDENT_FLAG_OFFSET]
            .copy_from_slice(&(SINGLE_RUN_ROOM_BYTES as u32).to_le_bytes());
        expected[NONRESIDENT_FLAG_OFFSET] = 1;
        expected[FIRST_VCN_OFFSET..FIRST_VCN_OFFSET + U64_BYTES].copy_from_slice(&run.vcn.to_le_bytes());
        expected[LAST_VCN_OFFSET..LAST_VCN_OFFSET + U64_BYTES].copy_from_slice(&(run.vcn + run.len - 1).to_le_bytes());
        expected[RUNS_OFFSET_FIELD..RUNS_OFFSET_FIELD + 2]
            .copy_from_slice(&(NONRESIDENT_HEADER_BYTES as u16).to_le_bytes());
        if index == 0 {
            expected[SIZE_FIELDS_START..DATA_SIZE_OFFSET].copy_from_slice(&ALLOCATED_BYTES.to_le_bytes());
            expected[DATA_SIZE_OFFSET..INITIALIZED_SIZE_OFFSET].copy_from_slice(&DATA_BYTES.to_le_bytes());
            expected[INITIALIZED_SIZE_OFFSET..SIZE_FIELDS_END].copy_from_slice(&DATA_BYTES.to_le_bytes());
        }
        expected[NONRESIDENT_HEADER_BYTES..].copy_from_slice(&pairs);
        assert_eq!(actual[index], expected);
    }
}

#[test]
fn direct_mapping_encoder_preserves_retained_header_padding_and_sparse_segments() {
    use ntfs_rs::mft::attribute_layout as layout;

    const CUSTOM_HEADER_MARKER: u8 = 0x3c;
    const NAME: &[u8] = b"$\0X\0";
    const SHORT_HEADER_BYTES: usize = 64;
    const NAMED_MAPPING_OFFSET: usize = NONRESIDENT_HEADER_BYTES + ALIGNMENT_BYTES;
    const EXTENDED_COMPRESSED_SIZE: u64 = ALLOCATED_BYTES / 2;
    const PAYLOAD_BYTES: usize = ALIGNMENT_BYTES;
    const SEGMENTS: [(usize, usize, [u8; PAYLOAD_BYTES]); 3] = [
        (0, 2, [0x12, 0x80, 0x00, 0x0a, 0x01, 0x01, 0, 0]),
        (2, 3, [0x12, 0x00, 0x01, 0x02, 0, 0, 0, 0]),
        (3, 4, [0x23, 0x00, 0x00, 0x01, 0x30, 0x75, 0, 0]),
    ];

    let mut source_runs = runs();
    source_runs[1].lcn = None;
    for name in [&[][..], NAME] {
        let mut original =
            vec![0; MAPPING_BUFFER_PREFIX_BYTES + name.len() + source_runs.len() * MAX_MAPPING_PAIR_BYTES];
        let used =
            e::build_nonresident(ATTR_DATA, name, &source_runs, ALLOCATED_BYTES, DATA_BYTES, DATA_BYTES, &mut original)
                .unwrap();
        original.truncate(used);
        let old_offset = ntfs_rs::bytes::u16_at(&original, layout::MAPPING_PAIRS_OFFSET).unwrap() as usize;
        let offsets = if name.is_empty() {
            vec![SHORT_HEADER_BYTES, NONRESIDENT_HEADER_BYTES, NAMED_MAPPING_OFFSET + 1]
        } else {
            vec![NAMED_MAPPING_OFFSET, NAMED_MAPPING_OFFSET + 1, MAPPING_BUFFER_PREFIX_BYTES]
        };
        for offset in offsets {
            let mut attribute = original[..old_offset.min(offset)].to_vec();
            attribute.resize(offset, CUSTOM_HEADER_MARKER);
            attribute.extend_from_slice(&original[old_offset..]);
            e::p16(&mut attribute, layout::MAPPING_PAIRS_OFFSET, offset as u16).unwrap();
            let length = attribute.len() as u32;
            e::p32(&mut attribute, layout::LENGTH_OFFSET, length).unwrap();
            if offset >= layout::EXTENDED_HEADER_BYTES {
                e::p64(&mut attribute, layout::COMPRESSED_SIZE_OFFSET, EXTENDED_COMPRESSED_SIZE).unwrap();
            }
            let room = (offset + PAYLOAD_BYTES + ALIGNMENT_BYTES - 1) & !(ALIGNMENT_BYTES - 1);
            let actual =
                relocation::mapping_descriptors(&attribute, source_runs.len(), |index| Ok(source_runs[index]), room, relocation::DESCRIPTOR_CAPACITY)
                    .unwrap();
            assert_eq!(actual.len(), SEGMENTS.len());
            for (change, (first, end, pairs)) in actual.into_iter().zip(SEGMENTS) {
                let mut expected = attribute[..offset].to_vec();
                expected.extend_from_slice(&pairs);
                expected.resize(room, 0);
                e::p32(&mut expected, layout::LENGTH_OFFSET, room as u32).unwrap();
                e::p64(&mut expected, layout::FIRST_VCN_OFFSET, source_runs[first].vcn).unwrap();
                e::p64(&mut expected, layout::LAST_VCN_OFFSET, source_runs[end - 1].vcn + source_runs[end - 1].len - 1)
                    .unwrap();
                if first != 0 {
                    expected[layout::ALLOCATED_SIZE_OFFSET..layout::SIZE_FIELDS_END].fill(0);
                    if offset >= layout::EXTENDED_HEADER_BYTES {
                        expected[layout::COMPRESSED_SIZE_OFFSET..layout::EXTENDED_HEADER_BYTES].fill(0);
                    }
                }
                assert_eq!(change.attribute.unwrap(), expected);
            }
        }
    }
}
