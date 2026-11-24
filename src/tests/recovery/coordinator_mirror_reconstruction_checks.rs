// Module: slate_ntfs_tools::recovery_io::coordinator_mirror_reconstruction_checks
// Purpose: Verify recovery coordination with disposable regression fixtures.
// Created: 2026-10-02
// Architecture: Checked record protection and private byte corruption exercise
// mirror assembly without granting source-device write authority.

use super::*;

const GEOMETRIES: [(usize, u16); 3] = [(1024, 512), (4096, 512), (4096, 4096)];

fn record(bytes: usize, sector: u16, legacy: bool) -> Vec<u8> {
    let mut raw = vec![0; bytes];
    ntfs_rs::record_edit::format_empty(&mut raw, system_record::MFT_MIRROR).unwrap();
    ntfs_rs::record_edit::p16(&mut raw, record_layout::FLAGS_OFFSET, record_layout::IN_USE).unwrap();
    if legacy {
        let offset = usize::from(u16_field(&raw, record_layout::USA_OFFSET).unwrap());
        let count = usize::from(u16_field(&raw, record_layout::USA_COUNT_OFFSET).unwrap());
        let words = raw[offset..offset + count * USA_WORD_BYTES].to_vec();
        let start = usize::from(record_layout::LEGACY_USA);
        raw[start..start + words.len()].copy_from_slice(&words);
        ntfs_rs::record_edit::p16(&mut raw, record_layout::USA_OFFSET, record_layout::LEGACY_USA).unwrap();
        let first = (start + words.len()).next_multiple_of(ntfs_rs::mft::attribute_layout::ALIGNMENT);
        raw[first..].fill(0);
        ntfs_rs::record_edit::p16(&mut raw, record_layout::FIRST_ATTRIBUTE_OFFSET, first as u16).unwrap();
        ntfs_rs::record_edit::p32(&mut raw, first, record_layout::END_MARKER).unwrap();
        ntfs_rs::record_edit::p32(
            &mut raw,
            record_layout::USED_OFFSET,
            (first + record_layout::END_MARKER_BYTES) as u32,
        )
        .unwrap();
    }
    protect_mft_record(&mut raw, sector).unwrap();
    raw
}

#[test]
fn combines_complementary_torn_mft_copies() {
    for (bytes, sector) in GEOMETRIES {
        for legacy in [false, true] {
            let good = record(bytes, sector, legacy);
            let mut a = good.clone();
            let mut b = good.clone();
            a[SECTOR_TAIL] ^= u8::MAX;
            b[bytes - USA_WORD_BYTES] ^= u8::MAX;
            let inputs = (a.clone(), b.clone());
            assert_eq!(reconstruct_mirror_sectors(&a, &b, sector).unwrap(), good);
            assert_eq!((a, b), inputs);
        }
    }
}

#[test]
fn refuses_generation_conflicts_and_shared_sector_loss() {
    for (bytes, sector) in GEOMETRIES {
        for legacy in [false, true] {
            let mut a = record(bytes, sector, legacy);
            let mut b = a.clone();
            a[SECTOR_TAIL] ^= u8::MAX;
            b[SECTOR_TAIL] ^= u8::MAX;
            let inputs = (a.clone(), b.clone());
            assert!(reconstruct_mirror_sectors(&a, &b, sector).is_err());
            assert_eq!((&a, &b), (&inputs.0, &inputs.1));
            b = record(bytes, sector, legacy);
            b[bytes - USA_WORD_BYTES] ^= u8::MAX;
            b[record_layout::LSN_OFFSET] ^= 1;
            assert!(reconstruct_mirror_sectors(&a, &b, sector).is_err());
            b = record(bytes, sector, legacy);
            b[bytes - USA_WORD_BYTES] ^= u8::MAX;
            let usa = usize::from(u16_field(&b, record_layout::USA_OFFSET).unwrap());
            b[usa] ^= 1;
            assert!(reconstruct_mirror_sectors(&a, &b, sector).is_err());
        }
    }
}
