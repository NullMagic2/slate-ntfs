//! Module: writer_lifecycle::native_storage
//! Purpose: Verify complete retirement of Windows-created stream families.
//! Created: 2026-10-21
//! Architecture: The real writer deletes native EFS, sparse, named-stream and
//! reparse fixtures; independent bitmaps account for every nonresident run.

use super::hard_links::{allocated, bitmap, owned_storage};
use super::*;
use ntfs_rs::file_lifecycle::Removal;
use ntfs_rs::mft::{file_reference, reference_number, system_record, MftRecord, ATTR_BITMAP, ATTR_DATA};
use ntfs_rs::volume::Volume;
use std::collections::BTreeMap;

const ROOT_SEQUENCE: u16 = 5;
const VICTIMS: [&str; 4] = ["encrypted.bin", "streams.bin", "sparse.bin", "native-link"];
const WITNESS: &str = "native-witness.bin";

fn root_entries(image: &mut Image, boot: BootSector) -> BTreeMap<String, u64> {
    let mut volume = Volume::new(image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mft = volume.load_mft(&mut zero).unwrap();
    let mut raw = vec![0; record_of(boot)];
    volume.read_mft_record(&mft, system_record::ROOT, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut entries = BTreeMap::new();
    volume
        .visit_directory(&record, &mut scratch, |entry| {
            let units: Vec<_> = entry.name.code_units().collect();
            entries.insert(String::from_utf16(&units).unwrap(), entry.file_reference);
            Ok(())
        })
        .unwrap();
    entries
}

#[test]
#[ignore = "requires SLATE_NATIVE_STORAGE_SOURCE with the Windows-created EFS/ADS fixture"]
fn native_streams_release_all_owned_records_and_attributes() {
    let source = std::env::var("SLATE_NATIVE_STORAGE_SOURCE").unwrap();
    retire_storage(&source, &VICTIMS, std::env::var_os("SLATE_NATIVE_STORAGE_RESULT"));
}

fn retire_storage(source: &str, victims: &[&str], result: Option<std::ffi::OsString>) {
    let (mut image, path, boot) = open_copy(source, "native-storage-delete");
    let original = root_entries(&mut image, boot);
    let witness = original[WITNESS];
    let content = read_resolved(&mut image, boot, witness);
    let ownership: Vec<_> = victims
        .iter()
        .map(|name| {
            let reference = original[*name];
            let (records, clusters) = owned_storage(&mut image, boot, reference);
            if *name != "native-link" {
                assert!(!clusters.is_empty(), "native fixture must own physical storage: {name}");
            }
            (*name, reference, records, clusters)
        })
        .collect();
    let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    for (name, reference, _, _) in &ownership {
        assert_eq!(
            writer.remove_node(&mut image, root, name, *reference, false, &mut scratch).unwrap(),
            Removal::Freed
        );
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let mft = bitmap(&mut image, boot, system_record::MFT, ATTR_BITMAP);
    let clusters = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    for (name, reference, records, runs) in ownership {
        assert!(records.iter().all(|record| !allocated(&mft, *record)), "MFT storage retained: {name}");
        assert!(runs.iter().all(|cluster| !allocated(&clusters, *cluster)), "attribute storage retained: {name}");
        eprintln!(
            "retired {name}: base={} records={} clusters={}",
            reference_number(reference),
            records.len(),
            runs.len()
        );
    }
    let after = root_entries(&mut image, boot);
    assert!(victims.iter().all(|name| !after.contains_key(*name)));
    assert_eq!(after[WITNESS], witness);
    assert_eq!(read_resolved(&mut image, boot, witness), content);
    if let Some(destination) = result {
        std::fs::copy(&path, destination).unwrap();
    }
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "requires SLATE_NATIVE_SPARSE_FAMILY_SOURCE with the native sparse-continuation fixture"]
fn sparse_continuations_release_all_family_storage() {
    const MINIMUM_RECORDS: usize = 21;
    const VICTIM: &str = "sparse-family.bin";
    let source = std::env::var("SLATE_NATIVE_SPARSE_FAMILY_SOURCE").unwrap();
    let (mut image, path, boot) = open_copy(&source, "sparse-family-inspection");
    let reference = root_entries(&mut image, boot)[VICTIM];
    let (records, clusters) = owned_storage(&mut image, boot, reference);
    assert!(records.len() >= MINIMUM_RECORDS, "fixture must exceed one transaction's family capacity");
    let mut volume = Volume::new(&mut image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mft = volume.load_mft(&mut zero).unwrap();
    let mut raw = vec![0; record_of(boot)];
    volume.read_mft_record(&mft, reference_number(reference), &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let mut work = vec![0; METADATA_SCRATCH_BYTES];
    let mut holes = 0;
    volume
        .visit_record_family(&mft, &record, &mut work, |_, attribute| {
            if attribute.kind == ATTR_DATA && attribute.nonresident {
                for run in ntfs_rs::runlist::DataRuns::new(attribute.data_runs()?, attribute.first_vcn()?) {
                    let run = run?;
                    if run.lcn.is_none() {
                        holes += run.len;
                    }
                }
            }
            Ok(())
        })
        .unwrap();
    assert!(holes > 0 && !clusters.is_empty());
    eprintln!("native sparse family: records={} allocated_clusters={} holes={holes}", records.len(), clusters.len());
    drop(volume);
    drop(image);
    std::fs::remove_file(path).unwrap();
    retire_storage(&source, &[VICTIM], std::env::var_os("SLATE_NATIVE_SPARSE_FAMILY_RESULT"));
}
