// Module: slate_ntfs_tools::recovery_io::models::family::mft_scan_checks
// Purpose: Exercise family recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

struct Memory(Vec<u8>);

impl ReadAt for Memory {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> ntfs_rs::Result<()> {
        output.copy_from_slice(self.0.get(offset as usize..offset as usize + output.len()).ok_or(ntfs_rs::Error::Io)?);
        Ok(())
    }
}

fn fixture() -> (Memory, ntfs_rs::boot::BootSector) {
    let boot = ntfs_rs::boot::BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: 256,
        mft_lcn: 4,
        mft_mirror_lcn: 20,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    };
    let mut bytes = vec![0; 256 * 512];
    for number in 0..16 {
        let mut record = vec![0; 1024];
        e::format_empty(&mut record, number).unwrap();
        if number == 0 {
            e::p16(&mut record, 22, 1).unwrap();
        }
        protect_mft_record(&mut record, 512).unwrap();
        let cluster = [4, 9, 12, 16][number as usize / 4];
        let offset = cluster * 4096 + number as usize % 4 * 1024;
        bytes[offset..offset + 1024].copy_from_slice(&record);
        if number < 4 {
            let offset = 20 * 4096 + number as usize * 1024;
            bytes[offset..offset + 1024].copy_from_slice(&record);
        }
    }
    (Memory(bytes), boot)
}

#[test]
fn bitmap_padding_preserves_mapped_uninitialized_slots() {
    for resident in [false, true] {
        let (mut image, boot) = fixture();
        let mut record = image.0[4 * 4096..4 * 4096 + 1024].to_vec();
        MftRecord::parse(&mut record, 512).unwrap();
        let extents: Vec<_> = [4, 9, 12]
            .into_iter()
            .enumerate()
            .map(|(vcn, lcn)| Extent { vcn: vcn as u64, lcn: Some(lcn), len: 1 })
            .collect();
        let mut attribute = vec![0; 256];
        let length = e::build_nonresident(ATTR_DATA, &[], &extents, 12288, 8192, 8192, &mut attribute).unwrap();
        e::insert(&mut record, &attribute[..length]).unwrap();
        let length = if resident {
            let mut value = [0; 8];
            value[1] = (1 << 2) | (1 << 4);
            e::build_resident(ATTR_BITMAP, &[], &value, &mut attribute).unwrap()
        } else {
            e::build_nonresident(
                ATTR_BITMAP,
                &[],
                &[Extent { vcn: 0, lcn: Some(24), len: 1 }],
                4096,
                8,
                8,
                &mut attribute,
            )
            .unwrap()
        };
        e::insert(&mut record, &attribute[..length]).unwrap();
        let mut raw = record.clone();
        protect_mft_record(&mut raw, 512).unwrap();
        image.0[4 * 4096..4 * 4096 + 1024].copy_from_slice(&raw);
        image.0[24 * 4096 + 1] = (1 << 2) | (1 << 4);
        let before = image.0.clone();
        let mft = MftRecord::from_decoded(&record).unwrap();
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mut patches = Vec::new();
        mft_bitmap_padding_repairs(&mut volume, &mft, |patch| {
            patches.push(patch);
            Ok(())
        })
        .unwrap();
        if resident {
            assert_eq!(patches.len(), 2);
            assert_eq!(patches[0].physical, 4 * 4096);
            let mut after = patches[0].after.clone();
            let record = MftRecord::parse(&mut after, 512).unwrap();
            assert_eq!(record.stream(ATTR_BITMAP, &[]).unwrap().resident_value().unwrap()[1], 1 << 2);
        } else {
            assert_eq!(patches.len(), 1);
            assert_eq!(patches[0].physical, 24 * 4096 + 1);
            assert_eq!(patches[0].before[0], (1 << 2) | (1 << 4));
            assert_eq!(patches[0].after[0], 1 << 2);
        }
        drop(volume);
        assert_eq!(image.0, before);
    }
}

#[test]
fn recovers_fragmented_record_clusters_without_modifying_input() {
    let (mut image, boot) = fixture();
    let before = image.0.clone();
    let (runs, bytes) = scan_mft_mapping(&mut image, boot).unwrap();
    assert_eq!(bytes, 16384);
    assert_eq!(runs.len(), 4);
    for (vcn, lcn) in [4, 9, 12, 16].into_iter().enumerate() {
        assert_eq!(runs.get(vcn as u64).unwrap(), Extent { vcn: vcn as u64, lcn: Some(lcn), len: 1 });
    }
    assert_eq!(image.0, before);
}

#[test]
fn refuses_missing_clusters_and_preserves_torn_raw_group_precedence() {
    let (mut image, boot) = fixture();
    image.0[12 * 4096..13 * 4096].fill(0);
    assert!(scan_mft_mapping(&mut image, boot).is_err());

    let (mut image, boot) = fixture();
    for number in 0..4 {
        image.0[12 * 4096 + number * 1024 + 510] ^= 1;
    }
    let before = image.0.clone();
    let (runs, _) = scan_mft_mapping(&mut image, boot).unwrap();
    assert_eq!(runs.get(2).unwrap().lcn, Some(12));
    assert_eq!(image.0, before);
}

#[test]
fn reconstructs_missing_mft_data_without_changing_surviving_bytes() {
    let (mut image, boot) = fixture();
    let before = image.0.clone();
    let raw = image.0[4 * 4096..4 * 4096 + 1024].to_vec();
    let mut repaired = reconstruct_mft_data(&mut image, boot, &raw).unwrap();
    let record = MftRecord::parse(&mut repaired, 512).unwrap();
    let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    assert_eq!(data.data_size().unwrap(), 16384);
    assert_eq!(data.initialized_size().unwrap(), 16384);
    let extents =
        ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).collect::<ntfs_rs::Result<Vec<_>>>().unwrap();
    assert_eq!(extents.len(), 4);
    assert_eq!(image.0, before);
}

#[test]
fn distinguishes_descriptor_loss_from_a_wrong_critical_anchor() {
    let (mut image, boot) = fixture();
    let raw = image.0[4 * 4096..4 * 4096 + 1024].to_vec();
    let mut missing = raw.clone();
    let record = MftRecord::parse(&mut missing, 512).unwrap();
    assert_eq!(mft_mapping_state(&record, boot).unwrap(), MftMappingState::Reconstruct);

    let mut repaired = reconstruct_mft_data(&mut image, boot, &raw).unwrap();
    let record = MftRecord::parse(&mut repaired, 512).unwrap();
    assert_eq!(mft_mapping_state(&record, boot).unwrap(), MftMappingState::Ready);
    let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    let offset = data.record_offset();
    let pairs = offset + usize::from(ntfs_rs::bytes::u16_at(&repaired, offset + 32).unwrap());
    assert_eq!(repaired[pairs], 0x11);
    let mut short = repaired.clone();
    short[offset + 24..offset + 32].copy_from_slice(&0_u64.to_le_bytes());
    short[pairs + 3] = 0;
    let record = MftRecord::from_decoded(&short).unwrap();
    assert_eq!(mft_mapping_state(&record, boot).unwrap(), MftMappingState::Reconstruct);
    repaired[pairs + 2] = 5;
    let record = MftRecord::from_decoded(&repaired).unwrap();
    assert_eq!(mft_mapping_state(&record, boot).unwrap(), MftMappingState::WrongAnchor);

    let mut wrong_short = repaired.clone();
    e::p64(&mut wrong_short, offset + 48, 4096).unwrap();
    e::p64(&mut wrong_short, offset + 56, 4096).unwrap();
    let record = MftRecord::from_decoded(&wrong_short).unwrap();
    assert_eq!(mft_mapping_state(&record, boot).unwrap(), MftMappingState::WrongAnchor);

    repaired[pairs] = 0;
    let record = MftRecord::from_decoded(&repaired).unwrap();
    assert_eq!(mft_mapping_state(&record, boot).unwrap(), MftMappingState::Reconstruct);
}

#[test]
fn isolated_duplicates_use_raw_identity_counts_and_physical_tie_order() {
    let (mut image, boot) = fixture();
    let duplicate = image.0[9 * 4096..10 * 4096].to_vec();
    image.0[25 * 4096..26 * 4096].copy_from_slice(&duplicate);
    let before = image.0.clone();
    let (runs, _) = scan_mft_mapping(&mut image, boot).unwrap();
    assert_eq!(runs.get(1).unwrap().lcn, Some(9));
    assert_eq!(image.0, before);

    image.0[9 * 4096 + 510] ^= 1;
    let (runs, _) = scan_mft_mapping(&mut image, boot).unwrap();
    assert_eq!(runs.get(1).unwrap().lcn, Some(9));

    image.0[9 * 4096..9 * 4096 + 4].copy_from_slice(b"BAAD");
    let (runs, _) = scan_mft_mapping(&mut image, boot).unwrap();
    assert_eq!(runs.get(1).unwrap().lcn, Some(25));
}

#[test]
fn refuses_competing_contiguous_ranges_larger_than_one_cluster() {
    let (mut image, boot) = fixture();
    let second = image.0[12 * 4096..13 * 4096].to_vec();
    image.0[10 * 4096..11 * 4096].copy_from_slice(&second);
    image.0[12 * 4096..13 * 4096].fill(0);
    let duplicate = image.0[9 * 4096..11 * 4096].to_vec();
    image.0[25 * 4096..27 * 4096].copy_from_slice(&duplicate);
    let before = image.0.clone();
    assert!(scan_mft_mapping(&mut image, boot).is_err());
    assert_eq!(image.0, before);
}

#[test]
fn retained_mft_tail_requires_matching_mapping_and_family_owner() {
    let (mut image, boot) = fixture();
    let mut member = image.0[9 * 4096..9 * 4096 + 1024].to_vec();
    MftRecord::parse(&mut member, 512).unwrap();
    e::p16(&mut member, 22, 1).unwrap();
    e::p64(&mut member, 32, 1_u64 << 48).unwrap();
    let mut tail = vec![0; 256];
    let len = e::build_nonresident_at(
        ATTR_DATA,
        &[],
        &[Extent { vcn: 2, lcn: Some(12), len: 1 }, Extent { vcn: 3, lcn: Some(16), len: 1 }],
        2,
        0,
        0,
        0,
        &mut tail,
    )
    .unwrap();
    e::insert(&mut member, &tail[..len]).unwrap();
    protect_mft_record(&mut member, 512).unwrap();
    image.0[9 * 4096..9 * 4096 + 1024].copy_from_slice(&member);

    let mut base = image.0[4 * 4096..4 * 4096 + 1024].to_vec();
    MftRecord::parse(&mut base, 512).unwrap();
    let mut list = [0; 64];
    for (row, vcn, reference, identity) in [(0, 0, 1_u64 << 48, 2), (32, 2, (1_u64 << 48) | 4, 0)] {
        e::p32(&mut list, row, ATTR_DATA).unwrap();
        e::p16(&mut list, row + 4, 32).unwrap();
        e::p64(&mut list, row + 8, vcn).unwrap();
        e::p64(&mut list, row + 16, reference).unwrap();
        e::p16(&mut list, row + 24, identity).unwrap();
    }
    let mut descriptor = [0; 128];
    let len = e::build_resident(ATTR_ATTRIBUTE_LIST, &[], &list, &mut descriptor).unwrap();
    e::insert(&mut base, &descriptor[..len]).unwrap();
    let record = MftRecord::from_decoded(&base).unwrap();
    let (runs, bytes) = scan_mft_mapping(&mut image, boot).unwrap();
    let before = image.0.clone();
    assert_eq!(mft_reconstruction_prefix(&mut image, boot, &record, &runs, bytes, false).unwrap(), (2, Some(2)));
    assert_eq!(image.0, before);

    MftRecord::parse(&mut member, 512).unwrap();
    e::p64(&mut member, 32, (1_u64 << 48) | 3).unwrap();
    protect_mft_record(&mut member, 512).unwrap();
    image.0[9 * 4096..9 * 4096 + 1024].copy_from_slice(&member);
    assert!(mft_reconstruction_prefix(&mut image, boot, &record, &runs, bytes, false).is_err());
    assert!(mft_reconstruction_prefix(&mut image, boot, &record, &runs, bytes, true).is_err());
}

#[test]
#[ignore = "requires a disposable damaged MFT fixture"]
fn reconstructed_fixture_mapping_resolves_every_record_identity() {
    let path = std::env::var_os("SLATE_NTFS_TEST_MFT_SCAN_SOURCE").unwrap();
    let mut image = Image(File::open(path).unwrap());
    let mut sector = [0; 512];
    image.read_exact_at(0, &mut sector).unwrap();
    let boot = ntfs_rs::boot::BootSector::parse(&sector).unwrap();
    let mut raw = vec![0; boot.record_bytes as usize];
    image.read_exact_at(boot.mft_byte_offset().unwrap(), &mut raw).unwrap();
    let mut repaired = reconstruct_mft_data(&mut image, boot, &raw).unwrap();
    let mft = MftRecord::parse(&mut repaired, boot.bytes_per_sector).unwrap();
    let records = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap().initialized_size().unwrap()
        / u64::from(boot.record_bytes);
    let mut volume = Volume::new(image, boot).unwrap();
    for number in 0..records {
        volume.read_mft_record(&mft, number, &mut raw).unwrap();
        MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
        let identity =
            u64::from(u32_at(&raw, 44).unwrap()) | (u64::from(ntfs_rs::bytes::u16_at(&raw, 42).unwrap()) << 32);
        assert_eq!(identity, number);
    }
    assert!(records >= 16);
}
