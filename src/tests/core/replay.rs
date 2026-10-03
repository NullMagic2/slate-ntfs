//! Module: tests::core::replay
//! Purpose: Verify MFT protection encoding and log record classification.
//! Created: 2026-10-03
//! Architecture: Included by ntfs_rs::replay under cfg(test).

use super::super::logfile::{encode_lfs_record, encode_ntfs_operation, LfsRecordInput, NtfsOperationInput};
use super::super::mft::MftRecord;
use super::*;

#[test]
fn mft_protection_uses_fixed_mst_strides_with_wider_logical_sectors() {
    for sector in [512, 1024, 2048, 4096] {
        for usa in [0x30, 0x2a] {
            let mut raw = [0; 4096];
            super::super::record_edit::format_empty(&mut raw, 37).unwrap();
            if usa == 0x2a {
                raw.copy_within(0x30..0x42, 0x2a);
                raw[4..6].copy_from_slice(&0x2a_u16.to_le_bytes());
            }
            for piece in 0..8 {
                let tail = (piece + 1) * 512 - 2;
                raw[tail..tail + 2].copy_from_slice(&(0x1200 + piece as u16).to_le_bytes());
            }
            let original = raw;
            protect_mft_record(&mut raw, sector).unwrap();
            let record = MftRecord::parse(&mut raw, sector).unwrap();
            assert_eq!(record.physical_record_number().unwrap(), if usa == 0x2a { None } else { Some(37) });
            for offset in 0..raw.len() {
                if !(usa..usa + 18).contains(&offset) {
                    assert_eq!(raw[offset], original[offset]);
                }
            }
        }
    }
}

#[test]
fn legacy_mft_protection_roundtrips_without_fabricating_identity() {
    let mut decoded = [0; 1024];
    super::super::record_edit::format_empty(&mut decoded, 37).unwrap();
    decoded[4..6].copy_from_slice(&0x2a_u16.to_le_bytes());
    decoded[0x2a..0x30].copy_from_slice(&[7, 0, 0x11, 0x22, 0x33, 0x44]);
    decoded[510..512].copy_from_slice(&[0x12, 0x34]);
    decoded[1022..1024].copy_from_slice(&[0x56, 0x78]);
    let original = decoded.clone();
    protect_mft_record(&mut decoded, 512).unwrap();
    let record = MftRecord::parse(&mut decoded, 512).unwrap();
    assert_eq!(record.physical_record_number().unwrap(), None);
    assert_eq!(record.sequence_number().unwrap(), 1);
    assert_eq!(&decoded[..0x2a], &original[..0x2a]);
    assert_eq!(&decoded[0x30..], &original[0x30..]);
}

#[test]
fn mft_protection_refuses_other_short_or_odd_usa_offsets_without_changes() {
    for offset in [0x28_u16, 0x2c, 0x2e, 0x31] {
        let mut raw = [0; 1024];
        super::super::record_edit::format_empty(&mut raw, 37).unwrap();
        raw[4..6].copy_from_slice(&offset.to_le_bytes());
        let original = raw.clone();
        assert_eq!(protect_mft_record(&mut raw, 512), Err(Error::InvalidFixup));
        assert_eq!(raw, original);
    }
}

#[test]
fn extracts_metadata_intent_without_granting_replay() {
    let mut payload = [0_u8; 128];
    let size = encode_ntfs_operation(
        &NtfsOperationInput {
            redo_code: 7,
            undo_code: 7,
            target_attribute: 3,
            target_vcn: 5,
            lcns: &[6],
            redo: &[1],
            undo: &[2],
        },
        &mut payload,
    )
    .unwrap();
    let mut bytes = [0_u8; 256];
    let record_size = encode_lfs_record(
        &LfsRecordInput {
            this_lsn: 20,
            previous_lsn: 19,
            undo_next_lsn: 18,
            client_sequence: 1,
            client_index: 0,
            record_type: 1,
            transaction_id: 11,
            flags: 0,
            payload: &payload[..size],
        },
        &mut bytes,
    )
    .unwrap();
    let action = record_action(LfsRecord::parse(&bytes[..record_size]).unwrap()).unwrap();
    assert_eq!(action, RecordAction::Metadata);
}
