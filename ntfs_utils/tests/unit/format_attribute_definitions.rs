// Module: ntfs_utils::format_backend::attribute_definition_tests
// Purpose: Verify formatting still emits the exact original AttrDef stream.
// Created: 2026-10-03
// Architecture: The external test exercises the formatter's shared core row codec.

#[test]
fn formatter_attribute_definitions_match_original_stream_golden() {
    const ORIGINAL_STREAM_BYTES: usize = 2560;
    const ORIGINAL_SHA256: [u8; 32] = [
        0xd7, 0xde, 0x5b, 0x1b, 0x2f, 0x79, 0xf4, 0x5f, 0x23, 0x5c, 0xeb, 0x1a, 0xdb, 0xc4, 0x69, 0x08, 0xed, 0x64,
        0xea, 0xe1, 0x74, 0xeb, 0x90, 0xed, 0x66, 0xae, 0xfe, 0x5f, 0x25, 0x16, 0x5d, 0xa3,
    ];

    let actual = super::attrdef();
    assert_eq!(ntfs_rs::mft::attribute_definition::STANDARD_STREAM_BYTES, ORIGINAL_STREAM_BYTES);
    assert_eq!(actual.len(), ORIGINAL_STREAM_BYTES);
    assert_eq!(ntfs_rs::sha256::digest(&actual), ORIGINAL_SHA256);
}
