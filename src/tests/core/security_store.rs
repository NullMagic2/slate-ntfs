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
    p32(&mut data, 4, 112).unwrap();
    p32(&mut data, 8, 112).unwrap();
    for (cursor, id) in [(16, 0x100), (56, 0x101)] {
        p16(&mut data, cursor, 20).unwrap();
        p16(&mut data, cursor + 2, 20).unwrap();
        p16(&mut data, cursor + 8, 40).unwrap();
        p16(&mut data, cursor + 10, 4).unwrap();
        p32(&mut data, cursor + 16, id).unwrap();
        p32(&mut data, cursor + 24, id).unwrap();
    }
    p16(&mut data, 104, 16).unwrap();
    p16(&mut data, 108, 2).unwrap();
    let mut expected = [0_u8; 20];
    expected[4..8].copy_from_slice(&0x100_u32.to_le_bytes());
    assert_eq!(
        search_node(&data, 0, (0, 0x100), false, None, None),
        Ok((Search::Found(expected), None, Some((0, 0x100))))
    );
    // The second key is now out of order; finding the first never skips it.
    p32(&mut data, 72, 0xff).unwrap();
    assert_eq!(search_node(&data, 0, (0, 0x100), false, None, None), Err(Error::InvalidIndex));
}

#[test]
fn index_header_evidence_requires_a_primary_bounded_descriptor() {
    let entry = SecurityIndexEntry {
        hash: 0x0123_4567,
        security_id: sds_layout::FIRST_SECURITY_ID,
        offset: 0,
        length: (SDS_HEADER_BYTES + DESCRIPTOR_HEADER_BYTES) as u32,
    };
    assert_eq!(index_header(&entry.header()), Ok(entry));
    for damaged in [
        SecurityIndexEntry { security_id: 0, ..entry },
        SecurityIndexEntry { offset: sds_layout::PRIMARY_REGION_BYTES, ..entry },
        SecurityIndexEntry { offset: sds_layout::ALIGNMENT - 1, ..entry },
        SecurityIndexEntry { offset: sds_layout::PRIMARY_REGION_BYTES - sds_layout::ALIGNMENT, ..entry },
        SecurityIndexEntry { length: entry.length - 1, ..entry },
        SecurityIndexEntry { length: (MAX_STORED_DESCRIPTOR + SDS_HEADER_BYTES + 1) as u32, ..entry },
    ] {
        assert_eq!(index_header(&damaged.header()), Err(Error::InvalidSecurity));
    }
}

#[test]
fn security_index_entries_use_packed_id_keys_and_padded_hash_keys() {
    let indexed =
        SecurityIndexEntry { hash: 0x1234, security_id: sds_layout::FIRST_SECURITY_ID, offset: 0, length: 40 };
    for hashed in [false, true] {
        let mut row = [0; index_layout::HASH_ENTRY_BYTES];
        let length = indexed.index_entry(hashed, &mut row).unwrap();
        let slot = security_slot(&row[..length], 0, length, false, hashed).unwrap();
        assert_eq!(slot.value, Some(indexed.header()));
        assert_eq!(slot.key, Some((if hashed { indexed.hash } else { 0 }, indexed.security_id)));
        let mut short = [0; index_layout::ID_ENTRY_BYTES - 1];
        assert_eq!(indexed.index_entry(hashed, &mut short), Err(Error::Truncated));
        if !hashed {
            row.copy_within(
                index_layout::HEADER_BYTES + index_layout::ID_KEY_BYTES..length,
                index_layout::HEADER_BYTES + index_layout::HASH_KEY_BYTES,
            );
            p16(
                &mut row,
                index_layout::DATA_OFFSET,
                (index_layout::HEADER_BYTES + index_layout::HASH_KEY_BYTES) as u16,
            )
            .unwrap();
            p16(&mut row, index_layout::LENGTH_OFFSET, index_layout::HASH_ENTRY_BYTES as u16).unwrap();
            assert!(security_slot(&row, 0, row.len(), false, false).is_err());
        }
    }
}
