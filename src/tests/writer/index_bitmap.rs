//! Module: writer_lifecycle::index_bitmap
//! Purpose: Reproduce last-child deletion with a nonresident directory bitmap.
//! Created: 2026-10-13
//! Architecture: Reuses the lifecycle image adapter and writer helpers; fixture
//! edits transfer an allocated cluster without changing the source image.

use super::*;
use ntfs_rs::{
    file_lifecycle::{NodeKind, Removal},
    index_tree::I30,
    mft::{reference_number, system_record, MftRecord, ATTR_BITMAP, ATTR_DATA, ATTR_INDEX_ALLOCATION},
    record_edit,
    replay::protect_mft_record,
    runlist::{DataRuns, Extent},
    volume::Volume,
    write_plan::plan_nonresident_overwrite,
};

const FILLER_FILES: usize = 12;
const ROOT_SEQUENCE: u16 = 5;

#[test]
fn last_child_removal_retires_nonresident_index_bitmap() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    for orphan in [false, true] {
        let (mut image, path, boot) = open_copy(&source, &format!("external-index-bitmap-{orphan}"));
        let root = system_record::ROOT | (u64::from(ROOT_SEQUENCE) << 48);
        let cluster = cluster_of(boot);
        let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
        let mut writer = start(&mut image, boot, &mut scratch);
        let parent = writer
            .create_node(&mut image, root, "parent", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let victim = writer
            .create_node(&mut image, parent, "tools", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let mut fillers = Vec::new();
        for index in 0..FILLER_FILES {
            let name = format!("filler-{index}");
            let reference =
                writer.file_lifecycle(&mut image, parent, &name, None, &NULL_DACL, 0, &mut scratch).unwrap();
            fillers.push((name, reference));
        }
        for (name, reference) in fillers {
            writer.remove_node(&mut image, parent, &name, reference, false, &mut scratch).unwrap();
        }
        let backing =
            writer.file_lifecycle(&mut image, root, "bitmap-backing", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, backing, 0, &vec![0; cluster as usize], &mut scratch).unwrap();
        writer.finish(&mut image, &mut scratch).unwrap();

        let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
        let mut directory = vec![0; record_of(boot)];
        let mut backing_record = vec![0; record_of(boot)];
        let (offsets, bitmap, bitmap_run, allocation_runs) = {
            let mut volume = Volume::new(&mut image, boot).unwrap();
            let mft = volume.load_mft(&mut zero).unwrap();
            volume.read_mft_record(&mft, reference_number(parent), &mut directory).unwrap();
            volume.read_mft_record(&mft, reference_number(backing), &mut backing_record).unwrap();
            let directory_record = MftRecord::parse(&mut directory, boot.bytes_per_sector).unwrap();
            let bitmap = directory_record.local_attribute(ATTR_BITMAP, I30).unwrap().unwrap();
            assert!(!bitmap.nonresident);
            let bitmap = bitmap.resident_value().unwrap().to_vec();
            let allocation = directory_record.local_attribute(ATTR_INDEX_ALLOCATION, I30).unwrap().unwrap();
            let allocation_runs =
                DataRuns::new(allocation.data_runs().unwrap(), 0).collect::<Result<Vec<_>>>().unwrap();
            let record = MftRecord::parse(&mut backing_record, boot.bytes_per_sector).unwrap();
            let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            let bitmap_run = DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
            assert_eq!(bitmap_run.len, 1);
            let mft_data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            let mut offsets = [0; 2];
            for (index, reference) in [parent, backing].into_iter().enumerate() {
                plan_nonresident_overwrite(
                    mft_data,
                    boot,
                    reference_number(reference) * u64::from(boot.record_bytes),
                    u64::from(boot.record_bytes),
                    |span| {
                        assert_eq!(span.length, u64::from(boot.record_bytes));
                        offsets[index] = span.physical_offset;
                        Ok(())
                    },
                )
                .unwrap();
            }
            (offsets, bitmap, bitmap_run, allocation_runs)
        };

        // Transfer the backing file's cluster to the index bitmap while offline.
        // The allocation bit stays set and the cluster has exactly one owner.
        let mut block = vec![0; cluster as usize];
        block[..bitmap.len()].copy_from_slice(&bitmap);
        image.write_at(bitmap_run.lcn.unwrap() * cluster, &block).unwrap();
        let mut attribute = vec![0; record_of(boot)];
        let at = record_edit::require(&directory, ATTR_BITMAP, I30).unwrap();
        record_edit::remove(&mut directory, at).unwrap();
        let length = record_edit::build_nonresident(
            ATTR_BITMAP,
            I30,
            &[Extent { vcn: 0, ..bitmap_run }],
            cluster,
            bitmap.len() as u64,
            bitmap.len() as u64,
            &mut attribute,
        )
        .unwrap();
        record_edit::insert(&mut directory, &attribute[..length]).unwrap();
        let at = record_edit::require(&backing_record, ATTR_DATA, &[]).unwrap();
        record_edit::remove(&mut backing_record, at).unwrap();
        let length = record_edit::build_resident(ATTR_DATA, &[], &[], &mut attribute).unwrap();
        record_edit::insert(&mut backing_record, &attribute[..length]).unwrap();
        for (offset, record) in offsets.into_iter().zip([&mut directory, &mut backing_record]) {
            record_edit::validate(record).unwrap();
            protect_mft_record(record, boot.bytes_per_sector).unwrap();
            image.write_at(offset, record).unwrap();
        }
        image.flush().unwrap();

        if let Some(folder) = std::env::var_os("SLATE_INDEX_BITMAP_FIXTURES") {
            let destination = std::path::PathBuf::from(folder).join(format!("external-bitmap-{orphan}.img"));
            std::fs::copy(&path, destination).unwrap();
        }

        let mut writer = start(&mut image, boot, &mut scratch);
        let result = writer.remove_node(&mut image, parent, "tools", victim, orphan, &mut scratch).unwrap();
        if orphan {
            assert_eq!(result, Removal::Orphaned);
            writer.reclaim_orphan(&mut image, victim, &mut scratch).unwrap();
        } else {
            assert_eq!(result, Removal::Freed);
        }
        writer.finish(&mut image, &mut scratch).unwrap();
        assert!(image.held.is_empty());
        let mut retired = vec![0; cluster as usize];
        image.read_exact_at(bitmap_run.lcn.unwrap() * cluster, &mut retired).unwrap();
        assert_eq!(retired, block, "retired bitmap storage must not receive pending bit edits");
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mft = volume.load_mft(&mut zero).unwrap();
        volume.read_mft_record(&mft, reference_number(parent), &mut directory).unwrap();
        let record = MftRecord::parse(&mut directory, boot.bytes_per_sector).unwrap();
        assert!(record.local_attribute(ATTR_INDEX_ALLOCATION, I30).unwrap().is_none());
        assert!(record.local_attribute(ATTR_BITMAP, I30).unwrap().is_none());
        let mut work = vec![0; ntfs_rs::tx::BLOCK];
        let mut entries = 0;
        volume
            .visit_directory(&record, &mut work, |_| {
                entries += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, 0);
        volume.read_mft_record(&mft, system_record::BITMAP, &mut directory).unwrap();
        let record = MftRecord::parse(&mut directory, boot.bytes_per_sector).unwrap();
        let bitmap = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        for run in allocation_runs.into_iter().chain([bitmap_run]) {
            for cluster in run.lcn.unwrap()..run.lcn.unwrap() + run.len {
                let mut byte = [0];
                volume.read_attribute(bitmap, cluster / u64::from(u8::BITS), &mut byte).unwrap();
                assert_eq!(byte[0] & (1 << (cluster % u64::from(u8::BITS))), 0);
            }
        }
        drop(volume);
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}
