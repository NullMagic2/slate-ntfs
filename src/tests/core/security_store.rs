//! Module: ntfs_rs::security_store::tests
//! Purpose: Reject malformed security index geometry and ordering.
//! Created: 2026-10-21
//! Architecture: External unit controls exercise the shared checked index reader.

use super::super::bytes::{p16, p32};
use super::*;

#[test]
fn search_refuses_invalid_header_geometry_before_entry_data() {
    let mut data = [0_u8; 64];
    p32(&mut data, 16, 16).unwrap();
    p32(&mut data, 20, 16).unwrap();
    p32(&mut data, 24, u32::MAX).unwrap();
    assert_eq!(search_node(&data, 16, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
    p32(&mut data, 24, 16).unwrap();
    data[28] = 2;
    assert_eq!(search_node(&data, 16, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
    assert_eq!(search_node(&data[..28], 16, (0, 0x100), false, None, None), Err(Error::Truncated));
}

#[test]
fn search_checks_entries_after_the_selected_match() {
    let mut data = [0_u8; 128];
    p32(&mut data, 0, 16).unwrap();
    p32(&mut data, 4, 128).unwrap();
    p32(&mut data, 8, 128).unwrap();
    for (cursor, id) in [(16, 0x100), (64, 0x101)] {
        p16(&mut data, cursor, 20).unwrap();
        p16(&mut data, cursor + 2, 20).unwrap();
        p16(&mut data, cursor + 8, 48).unwrap();
        p16(&mut data, cursor + 10, 4).unwrap();
        p32(&mut data, cursor + 16, id).unwrap();
        p32(&mut data, cursor + 24, id).unwrap();
    }
    p16(&mut data, 120, 16).unwrap();
    p16(&mut data, 124, 2).unwrap();
    let mut expected = [0_u8; 20];
    expected[4..8].copy_from_slice(&0x100_u32.to_le_bytes());
    assert_eq!(
        search_node(&data, 0, (0, 0x100), false, None, None),
        Ok((Search::Found(expected), None, Some((0, 0x100))))
    );
    // The second key is now out of order; finding the first never skips it.
    p32(&mut data, 80, 0xff).unwrap();
    assert_eq!(search_node(&data, 0, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
}
