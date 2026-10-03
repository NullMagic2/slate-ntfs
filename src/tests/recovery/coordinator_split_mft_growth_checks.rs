// Module: slate_ntfs_tools::recovery_io::coordinator_split_mft_growth_checks
// Purpose: Verify recovery coordination with disposable regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged into the test folder and included in its
// original private scope; this file cannot authorize production disk writes.

use super::*;
use ntfs_rs::{record_edit as edit, runlist::Extent};

fn run(spare: bool) {
    let boot = ntfs_rs::boot::BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: 512,
        mft_lcn: 4,
        mft_mirror_lcn: 2,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    };
    let mut base = vec![0; 1024];
    edit::format_empty(&mut base, 0).unwrap();
    edit::p16(&mut base, 16, 5).unwrap();
    edit::p16(&mut base, 22, 1).unwrap();
    let mut attr = vec![0; 1024];
    let initialized = if spare { 16384 } else { 32768 };
    let n = edit::build_nonresident(
        ATTR_DATA,
        &[],
        &[Extent { vcn: 0, lcn: Some(4), len: 4 }],
        32768,
        initialized,
        initialized,
        &mut attr,
    )
    .unwrap();
    let data_at = edit::insert(&mut base, &attr[..n]).unwrap();
    let data_id = ntfs_rs::bytes::u16_at(&base, data_at + 14).unwrap();
    let n = edit::build_resident(ATTR_BITMAP, &[], &[0x49, 0, 0, 0], &mut attr).unwrap();
    let bitmap_at = edit::insert(&mut base, &attr[..n]).unwrap();
    let bitmap_id = ntfs_rs::bytes::u16_at(&base, bitmap_at + 14).unwrap();
    let mut extension = vec![0; 1024];
    edit::format_empty(&mut extension, 3).unwrap();
    edit::p16(&mut extension, 16, 7).unwrap();
    edit::p16(&mut extension, 22, 1).unwrap();
    edit::p64(&mut extension, 32, 5_u64 << 48).unwrap();
    let n = edit::build_nonresident(ATTR_DATA, &[], &[Extent { vcn: 0, lcn: Some(20), len: 4 }], 0, 0, 0, &mut attr)
        .unwrap();
    edit::p64(&mut attr, 16, 4).unwrap();
    edit::p64(&mut attr, 24, 7).unwrap();
    let extension_at = edit::insert(&mut extension, &attr[..n]).unwrap();
    let extension_id = ntfs_rs::bytes::u16_at(&extension, extension_at + 14).unwrap();
    let mut list = vec![0; 96];
    for (i, (kind, vcn, reference, id)) in [
        (ATTR_DATA, 0, 5_u64 << 48, data_id),
        (ATTR_DATA, 4, (7_u64 << 48) | 3, extension_id),
        (ATTR_BITMAP, 0, 5_u64 << 48, bitmap_id),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = &mut list[i * 32..(i + 1) * 32];
        edit::p32(entry, 0, kind).unwrap();
        edit::p16(entry, 4, 32).unwrap();
        entry[7] = 26;
        edit::p64(entry, 8, vcn).unwrap();
        edit::p64(entry, 16, reference).unwrap();
        edit::p16(entry, 24, id).unwrap();
    }
    let n = edit::build_resident(ATTR_ATTRIBUTE_LIST, &[], &list, &mut attr).unwrap();
    edit::insert(&mut base, &attr[..n]).unwrap();
    let mut bitmap_file = vec![0; 1024];
    edit::format_empty(&mut bitmap_file, 6).unwrap();
    edit::p16(&mut bitmap_file, 16, 1).unwrap();
    edit::p16(&mut bitmap_file, 22, 1).unwrap();
    let mut allocation_bits = [0; 64];
    if !spare {
        allocation_bits[..4].fill(0xff);
    }
    let n = edit::build_resident(ATTR_DATA, &[], &allocation_bits, &mut attr).unwrap();
    edit::insert(&mut bitmap_file, &attr[..n]).unwrap();
    for record in [&mut base, &mut extension, &mut bitmap_file] {
        protect_mft_record(record, 512).unwrap();
    }
    let mut image = vec![0; 512 * 512];
    image[16384..17408].copy_from_slice(&base);
    image[19456..20480].copy_from_slice(&extension);
    image[22528..23552].copy_from_slice(&bitmap_file);
    let path = std::env::temp_dir().join(format!(
        "slate-split-growth-{}-{}-{}",
        std::process::id(),
        spare,
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::write(&path, &image).unwrap();
    let mut probe = Volume::new(Image(File::open(&path).unwrap()), boot).unwrap();
    let merged = checker::consistency::mft_image(&mut probe).expect("logical MFT fixture");
    let merged_record = MftRecord::from_decoded(&merged).unwrap();
    merged_record.stream(ATTR_DATA, &[]).expect("merged MFT data");
    merged_record.stream(ATTR_BITMAP, &[]).expect("merged MFT bitmap");
    let mut decoded_base = base.clone();
    let base_record = MftRecord::parse(&mut decoded_base, 512).unwrap();
    base_record.stream(ATTR_BITMAP, &[]).expect("base bitmap");
    let mut plan = RepairPlan::new(image.len() as u64).unwrap();
    let result = repair_mft_growth_in_place(&path, boot, &mut plan);
    if result.is_ok() {
        let reader = PlannedImage { image: Image(File::open(&path).unwrap()), patches: &plan };
        let mut volume = Volume::new(reader, boot).unwrap();
        let merged = checker::consistency::mft_image(&mut volume).unwrap();
        let record = MftRecord::from_decoded(&merged).unwrap();
        assert_eq!(record.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap(), if spare { 32768 } else { 98304 });
        let mut slot = vec![0; 1024];
        volume.read_mft_record(&record, if spare { 20 } else { 80 }, &mut slot).unwrap();
        assert_eq!(&slot[..4], b"FILE");
        assert_eq!(std::fs::read(&path).unwrap(), image);
    }
    std::fs::remove_file(&path).unwrap();
    result.unwrap();
}

#[test]
fn initializes_mapped_spare_slots_without_changing_split_extents() {
    run(true);
}

#[test]
fn appends_a_checked_run_to_the_final_split_extent() {
    run(false);
}
