//! Module: writer_lifecycle::hard_links
//! Purpose: Verify surviving-link contents and final allocation reclamation.
//! Created: 2026-10-21
//! Architecture: Uses the lifecycle image adapter and real writer; independent
//! bitmap reads check base records, filename extensions and owned data clusters.

use super::*;
use ntfs_rs::{
    file_lifecycle::{NodeKind, Removal},
    mft::{file_reference, reference_number, system_record, MftRecord, ATTR_BITMAP, ATTR_DATA},
    runlist::DataRuns,
    volume::Volume,
};
use std::collections::BTreeSet;

const ROOT_SEQUENCE: u16 = 5;
const PAYLOAD_BYTES: usize = 8192;
const RESIDENT_BYTES: usize = 64;
const ALIAS_COUNT: usize = 16;
const ALIAS_PADDING: usize = 160;
const BITS_PER_BYTE: u64 = u8::BITS as u64;

pub(super) fn bitmap(image: &mut Image, boot: BootSector, record: u64, kind: u32) -> Vec<u8> {
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mut raw = vec![0; record_of(boot)];
    let mut volume = Volume::new(image, boot).unwrap();
    let mft = volume.load_mft(&mut zero).unwrap();
    volume.read_mft_record(&mft, record, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let attribute = record.local_attribute(kind, &[]).unwrap().unwrap();
    let mut bytes = vec![0; attribute.data_size().unwrap() as usize];
    volume.read_attribute(attribute, 0, &mut bytes).unwrap();
    bytes
}

pub(super) fn allocated(bytes: &[u8], number: u64) -> bool {
    bytes[number as usize / BITS_PER_BYTE as usize] & (1 << (number % BITS_PER_BYTE)) != 0
}

pub(super) fn owned_storage(image: &mut Image, boot: BootSector, reference: u64) -> (BTreeSet<u64>, BTreeSet<u64>) {
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mut raw = vec![0; record_of(boot)];
    let mut scratch = vec![0; FAMILY_VISIT_BYTES];
    let mut volume = Volume::new(image, boot).unwrap();
    let mft = volume.load_mft(&mut zero).unwrap();
    volume.read_mft_record(&mft, reference_number(reference), &mut raw).unwrap();
    let base = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let mut records = BTreeSet::from([reference_number(reference)]);
    let mut clusters = BTreeSet::new();
    volume
        .visit_record_family(&mft, &base, &mut scratch, |owner, attribute| {
            records.insert(reference_number(owner));
            if attribute.nonresident {
                for run in DataRuns::new(attribute.data_runs()?, attribute.first_vcn()?) {
                    let run = run?;
                    if let Some(first) = run.lcn {
                        clusters.extend(first..first + run.len);
                    }
                }
            }
            Ok(())
        })
        .unwrap();
    (records, clusters)
}

#[test]
fn last_hard_link_releases_records_and_data_across_parents() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    for bytes in [RESIDENT_BYTES, PAYLOAD_BYTES] {
        for deferred in [false, true] {
            let (mut image, path, boot) = open_copy(&source, &format!("hard-link-last-{bytes}-{deferred}"));
            let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
            let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
            let mut writer = start(&mut image, boot, &mut scratch);
            let mut parents = Vec::new();
            for name in ["links-a", "links-b"] {
                parents.push(
                    writer
                        .create_node(
                            &mut image,
                            root,
                            name,
                            NodeKind::Directory,
                            &NULL_DACL,
                            0,
                            None,
                            &[],
                            &mut scratch,
                        )
                        .unwrap(),
                );
            }
            let file = writer
                .file_lifecycle(&mut image, parents[0], "original.bin", None, &NULL_DACL, 0, &mut scratch)
                .unwrap();
            let payload = vec![b'H'; bytes];
            writer.write(&mut image, file, 0, &payload, &mut scratch).unwrap();
            let names: Vec<_> = (0..ALIAS_COUNT)
                .map(|index| {
                    (parents[index % parents.len()], format!("alias-{index:02}-{}", "x".repeat(ALIAS_PADDING)))
                })
                .collect();
            for (parent, name) in &names {
                writer
                    .with_compatibility(true, |w| w.hard_link(&mut image, file, *parent, name, &mut scratch))
                    .unwrap();
            }
            writer.finish(&mut image, &mut scratch).unwrap();
            let (records, clusters) = owned_storage(&mut image, boot, file);
            assert!(records.len() > 2, "fixture must spill filename attributes into multiple records");
            assert_eq!(clusters.is_empty(), bytes == RESIDENT_BYTES);

            let mut writer = start(&mut image, boot, &mut scratch);
            assert_eq!(
                writer.remove_node(&mut image, parents[0], "original.bin", file, deferred, &mut scratch).unwrap(),
                Removal::Unlinked
            );
            assert_eq!(read_resolved(&mut image, boot, file), payload);
            assert_eq!(usize::from(node(&mut image, boot, file).links), ALIAS_COUNT);
            for (index, (parent, name)) in names.iter().enumerate() {
                let last = index + 1 == names.len();
                let result = writer
                    .with_compatibility(true, |w| {
                        w.remove_node(&mut image, *parent, name, file, deferred, &mut scratch)
                    })
                    .unwrap();
                if last {
                    if deferred {
                        assert_eq!(result, Removal::Orphaned);
                        assert_eq!(node(&mut image, boot, file).links, 0);
                        assert_eq!(read_resolved(&mut image, boot, file), payload);
                        writer.reclaim_orphan(&mut image, file, &mut scratch).unwrap();
                    } else {
                        assert_eq!(result, Removal::Freed);
                    }
                } else {
                    assert_eq!(result, Removal::Unlinked);
                    assert_eq!(read_resolved(&mut image, boot, file), payload);
                    assert_eq!(usize::from(node(&mut image, boot, file).links), names.len() - index - 1);
                    let allocation = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
                    assert!(clusters.iter().all(|cluster| allocated(&allocation, *cluster)));
                }
            }
            writer.finish(&mut image, &mut scratch).unwrap();
            let mft_bits = bitmap(&mut image, boot, system_record::MFT, ATTR_BITMAP);
            let allocation = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
            assert!(records.iter().all(|record| !allocated(&mft_bits, *record)), "filename family leaked MFT records");
            assert!(clusters.iter().all(|cluster| !allocated(&allocation, *cluster)), "last-link removal leaked data");
            assert_eq!(node(&mut image, boot, file).flags, 0);
            std::fs::remove_file(path).unwrap();
        }
    }
}
