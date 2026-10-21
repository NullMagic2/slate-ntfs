//! Module: writer_lifecycle::concurrent_reclaim
//! Purpose: Independently check allocations after mounted concurrent reclamation.
//! Created: 2026-10-21
//! Architecture: Reuses the lifecycle reader and family visitor; physical bitmap
//! checks distinguish storage retirement from legitimate subsequent reuse.

use super::*;
use ntfs_rs::{
    mft::{file_reference, reference_number, system_record, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA},
    runlist::DataRuns,
    volume::Volume,
};
use std::collections::BTreeSet;

fn open_readonly(path: &std::path::Path) -> (Image, BootSector) {
    let mut image = Image {
        file: File::open(path).unwrap(),
        flushes: 0,
        last: (0, 0),
        held: Vec::new(),
        writes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut boot = [0; ntfs_rs::boot::BOOT_SECTOR_BYTES];
    image.read_exact_at(0, &mut boot).unwrap();
    (image, BootSector::parse(&boot).unwrap())
}

fn allocated_families(image: &mut Image, boot: BootSector) -> BTreeSet<u64> {
    let bitmap = hard_links::bitmap(image, boot, system_record::MFT, ATTR_BITMAP);
    let mut volume = Volume::new(image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(boot.record_bytes as usize)];
    let mft = volume.load_mft(&mut zero).unwrap();
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut families = BTreeSet::new();
    for number in 0..bitmap.len() as u64 * u64::from(u8::BITS) {
        if !hard_links::allocated(&bitmap, number) {
            continue;
        }
        volume.read_mft_record(&mft, number, &mut raw).unwrap();
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
        if record.base_file_reference().unwrap() == 0 {
            families.insert(file_reference(number, record.sequence_number().unwrap()).unwrap());
        }
    }
    families
}

fn list_clusters(image: &mut Image, boot: BootSector, reference: u64) -> BTreeSet<u64> {
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(boot.record_bytes as usize)];
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut volume = Volume::new(image, boot).unwrap();
    let mft = volume.load_mft(&mut zero).unwrap();
    volume.read_mft_record(&mft, reference_number(reference), &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let mut clusters = BTreeSet::new();
    for attribute in record.attributes() {
        let attribute = attribute.unwrap();
        if attribute.kind == ATTR_ATTRIBUTE_LIST && attribute.nonresident {
            for run in DataRuns::new(attribute.data_runs().unwrap(), attribute.first_vcn().unwrap()) {
                let run = run.unwrap();
                if let Some(first) = run.lcn {
                    clusters.extend(first..first + run.len);
                }
            }
        }
    }
    clusters
}

#[test]
#[ignore = "requires SLATE_RECLAIM_SOURCE, SLATE_RECLAIM_RESULT and SLATE_RECLAIM_REFERENCE"]
fn allocated_retirement_matches_after_concurrent_reclaim() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_RECLAIM_SOURCE").unwrap());
    let result = std::path::PathBuf::from(std::env::var_os("SLATE_RECLAIM_RESULT").unwrap());
    let reference = std::env::var("SLATE_RECLAIM_REFERENCE").unwrap().parse::<u64>().unwrap();
    let (mut before, boot) = open_readonly(&source);
    let (records, mut clusters) = hard_links::owned_storage(&mut before, boot, reference);
    let list = list_clusters(&mut before, boot, reference);
    assert!(!list.is_empty() && records.len() > 1, "fixture must exercise a nonresident list and extensions");
    clusters.extend(list);
    let (mut after, result_boot) = open_readonly(&result);
    assert_eq!(boot.serial_number, result_boot.serial_number);
    let mft_bits = hard_links::bitmap(&mut after, boot, system_record::MFT, ATTR_BITMAP);
    for number in &records {
        assert!(!hard_links::allocated(&mft_bits, *number), "source family leaked MFT slot {number}");
    }
    let bitmap = hard_links::bitmap(&mut after, boot, system_record::BITMAP, ATTR_DATA);
    let mut new_owners = BTreeSet::new();
    for owner in allocated_families(&mut after, boot) {
        new_owners.extend(hard_links::owned_storage(&mut after, boot, owner).1);
        new_owners.extend(list_clusters(&mut after, boot, owner));
    }
    let mut reused = 0;
    for cluster in &clusters {
        if hard_links::allocated(&bitmap, *cluster) {
            assert!(new_owners.contains(cluster), "retired target cluster {cluster} leaked without a new owner");
            reused += 1;
        }
    }
    println!(
        "retired_mft_records={} retired_clusters={} legitimately_reused_clusters={reused}",
        records.len(),
        clusters.len()
    );
    assert_eq!(before.writes, 0);
    assert_eq!(after.writes, 0);
}
