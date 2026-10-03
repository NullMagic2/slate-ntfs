// Module: slate_ntfs_tools::recovery_io::models::metadata::attribute_definition_tests
// Purpose: Verify recovery's standard AttrDef dictionary preserves original bytes.
// Created: 2026-10-03
// Architecture: Included in metadata's private test scope; core owns row encoding.

#[test]
fn recovery_attribute_definitions_match_original_rows_golden() {
    const ORIGINAL_ROW_COUNT: usize = 15;
    const ORIGINAL_ROWS_BYTES: usize = 2400;
    const ORIGINAL_SHA256: [u8; 32] = [
        0x77, 0x12, 0x8a, 0x24, 0xaf, 0x56, 0x53, 0x34, 0x16, 0x23, 0xf7, 0x5c, 0x9a, 0xc8, 0x2b, 0x59, 0xca, 0xfe,
        0xe6, 0xe1, 0xbf, 0xd9, 0x56, 0xc7, 0xf2, 0xed, 0xf1, 0xae, 0xbc, 0xee, 0x46, 0x4d,
    ];

    let rows = super::standard_definitions();
    assert_eq!(rows.len(), ORIGINAL_ROW_COUNT);
    let mut bytes = Vec::new();
    for (kind, row) in rows {
        assert_eq!(ntfs_rs::bytes::u32_at(&row, super::attrdef::TYPE_OFFSET).unwrap(), kind);
        assert!(super::definition_valid(&row));
        bytes.extend_from_slice(&row);
    }
    assert_eq!(bytes.len(), ORIGINAL_ROWS_BYTES);
    assert_eq!(ntfs_rs::sha256::digest(&bytes), ORIGINAL_SHA256);
}
