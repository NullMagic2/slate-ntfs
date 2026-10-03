// Module: slate_ntfs_tools::recovery_io::models::semantic::quota_sid_tests
// Purpose: Exercise semantic recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

#[test]
fn quota_repair_diagnostics_remain_specific() {
    const SID_HEADER_BYTES: usize = 8;
    const SID_REVISION: u8 = 1;
    let value = [SID_REVISION; SID_HEADER_BYTES];
    assert_eq!(metadata::quota_sid(&[], false).unwrap_err().to_string(), "invalid quota SID");
    assert_eq!(metadata::quota_sid(&value, false).unwrap_err().to_string(), "invalid quota SID length or padding");
}

#[test]
fn view_entry_preserves_fixed_frame_and_alignment_padding() {
    let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let value = [0xa1, 0xb2, 0xc3];
    // This independent frame fixes data offset 32, total size 40 and key size 12.
    let expected = [
        32, 0, 3, 0, 0, 0, 0, 0, 40, 0, 12, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0, 0xa1,
        0xb2, 0xc3, 0, 0, 0, 0, 0,
    ];
    assert_eq!(view_entry(&key, &value).unwrap(), expected);
    assert_eq!(view_entry(&vec![0; u16::MAX as usize], &[]).unwrap_err().to_string(), "view entry is too large");
}
