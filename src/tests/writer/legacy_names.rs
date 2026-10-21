//! Module: writer_lifecycle::legacy_names
//! Purpose: Exercise deletion and rename of names stored before punctuation escaping.
//! Created: 2026-10-21
//! Architecture: Builds clean writer fixtures, changes only matching physical
//! filename/index keys offline, then exercises the production namespace writer.

use super::*;
use ntfs_rs::{
    file_lifecycle::{NodeKind, Removal},
    filename::{FileNameValue, MAX_NAME_BYTES},
    index::IndexRoot,
    index_tree::I30,
    linux_names,
    mft::{file_reference, reference_number, system_record, MftRecord, ATTR_DATA, ATTR_FILE_NAME, ATTR_INDEX_ROOT},
    namespace_writer::RenameTarget,
    record_edit,
    replay::protect_mft_record,
    volume::Volume,
    write_plan::plan_nonresident_overwrite,
};
use std::collections::BTreeSet;

const ROOT_SEQUENCE: u16 = 5;
const EXTRA_LINKS: usize = 32;
const LONG_SUFFIX: usize = 100;
const PAYLOAD: &[u8] = b"legacy filename payload";
const CANONICAL: &[u8] = b"canonical filename payload";

fn cases() -> Vec<Vec<u8>> {
    let mut names = vec![format!("legacy:extension-{}", "x".repeat(LONG_SUFFIX)).into_bytes()];
    for character in linux_names::WINDOWS_RESERVED_CHARS {
        names.push(format!("legacy{character}name").into_bytes());
    }
    names.extend([
        b"legacy\x01control".to_vec(),
        b"legacy\xff?\x80".to_vec(),
        "café:旧🦀".as_bytes().to_vec(),
        b"trailing.".to_vec(),
        b"trailing ".to_vec(),
        b"NUL.txt".to_vec(),
    ]);
    names
}

fn rename_stored_key(image: &mut Image, boot: BootSector, file: u64, parent: u64, old: &[u8], new: &[u8]) -> u64 {
    let mut encoded = [0; MAX_NAME_BYTES];
    let old_len = linux_names::encode_linux(old, &mut encoded).unwrap();
    let mut plain = [0; MAX_NAME_BYTES];
    let new_len = linux_names::encode(new, &mut plain).unwrap();
    assert_eq!(old_len, new_len, "offline fixture preserves key length");
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mut family = vec![0; record_of(boot)];
    let mut visit = vec![0; FAMILY_VISIT_BYTES];
    let mut records = BTreeSet::from([parent]);
    {
        let mut volume = Volume::new(&mut *image, boot).unwrap();
        let mft = volume.load_mft(&mut zero).unwrap();
        volume.read_mft_record(&mft, reference_number(file), &mut family).unwrap();
        let base = MftRecord::parse(&mut family, boot.bytes_per_sector).unwrap();
        volume
            .visit_record_family(&mft, &base, &mut visit, |owner, attribute| {
                if attribute.kind == ATTR_FILE_NAME {
                    records.insert(owner);
                }
                Ok(())
            })
            .unwrap();
    }
    let mut name_owner = None;
    let mut index_matches = 0;
    for reference in records {
        let mut raw = vec![0; record_of(boot)];
        let (offset, edits) = {
            let mut volume = Volume::new(&mut *image, boot).unwrap();
            let mft = volume.load_mft(&mut zero).unwrap();
            volume.read_mft_record(&mft, reference_number(reference), &mut raw).unwrap();
            let start = raw.as_ptr() as usize;
            let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
            let mut edits = Vec::new();
            for attribute in record.attributes() {
                let attribute = attribute.unwrap();
                if attribute.kind == ATTR_FILE_NAME {
                    let value = FileNameValue::parse(attribute.resident_value().unwrap()).unwrap();
                    if value.parent_reference == parent && value.name.utf16le == &encoded[..old_len] {
                        assert!(name_owner.replace(reference).is_none());
                        edits.push(value.name.utf16le.as_ptr() as usize - start);
                    }
                } else if reference == parent
                    && attribute.kind == ATTR_INDEX_ROOT
                    && attribute.name_utf16le().unwrap() == I30
                {
                    let root = IndexRoot::parse(attribute.resident_value().unwrap()).unwrap();
                    assert!(!root.has_children(), "each fixture parent has a leaf index");
                    for entry in root.entries() {
                        let entry = entry.unwrap();
                        if entry.file_reference == file && entry.name.utf16le == &encoded[..old_len] {
                            index_matches += 1;
                            edits.push(entry.name.utf16le.as_ptr() as usize - start);
                        }
                    }
                }
            }
            let mut offset = None;
            plan_nonresident_overwrite(
                mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap(),
                boot,
                reference_number(reference) * u64::from(boot.record_bytes),
                u64::from(boot.record_bytes),
                |span| {
                    assert_eq!(span.length, u64::from(boot.record_bytes));
                    assert!(offset.replace(span.physical_offset).is_none());
                    Ok(())
                },
            )
            .unwrap();
            (offset.unwrap(), edits)
        };
        if !edits.is_empty() {
            for start in edits {
                raw[start..start + new_len].copy_from_slice(&plain[..new_len]);
            }
            record_edit::validate(&raw).unwrap();
            protect_mft_record(&mut raw, boot.bytes_per_sector).unwrap();
            image.write_at(offset, &raw).unwrap();
        }
    }
    assert_eq!(index_matches, 1);
    image.flush().unwrap();
    name_owner.unwrap()
}

#[test]
fn legacy_names_remove_rename_exchange_and_replace() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    for native in [false, true] {
        let (mut image, path, boot) = open_copy(&source, &format!("legacy-names-{native}"));
        let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
        let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
        let mut writer = start(&mut image, boot, &mut scratch);
        let seed = writer.file_lifecycle(&mut image, root, "d06-seed", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, seed, 0, PAYLOAD, &mut scratch).unwrap();
        for index in 0..EXTRA_LINKS {
            writer.hard_link(&mut image, seed, root, &format!("d06-extra-{index:02}"), &mut scratch).unwrap();
        }
        let mut entries = Vec::new();
        for (index, name) in cases().into_iter().enumerate() {
            let directory = writer
                .create_node(
                    &mut image,
                    root,
                    &format!("d06-case-{index:02}"),
                    NodeKind::Directory,
                    &NULL_DACL,
                    0,
                    None,
                    &[],
                    &mut scratch,
                )
                .unwrap();
            let file = if index == 0 {
                writer
                    .with_compatibility(true, |w| w.hard_link(&mut image, seed, directory, &name, &mut scratch))
                    .unwrap();
                seed
            } else {
                let file = writer
                    .with_compatibility(true, |w| {
                        w.file_lifecycle(&mut image, directory, &name, None, &NULL_DACL, 0, &mut scratch)
                    })
                    .unwrap();
                writer.write(&mut image, file, 0, PAYLOAD, &mut scratch).unwrap();
                file
            };
            entries.push((directory, file, name));
        }
        let collision = writer
            .create_node(&mut image, root, "d06-collision", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
            .unwrap();
        let canonical =
            writer.file_lifecycle(&mut image, collision, "same?name", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, canonical, 0, CANONICAL, &mut scratch).unwrap();
        let legacy =
            writer.file_lifecycle(&mut image, collision, "same~name", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, legacy, 0, PAYLOAD, &mut scratch).unwrap();
        writer.finish(&mut image, &mut scratch).unwrap();
        for (index, (directory, file, name)) in entries.iter().enumerate() {
            let owner = rename_stored_key(&mut image, boot, *file, *directory, name, name);
            if index == 0 {
                assert_ne!(owner, *file, "legacy target must live in a filename extension");
            }
        }
        rename_stored_key(&mut image, boot, legacy, collision, b"same~name", b"same?name");
        if let Some(folder) = std::env::var_os("SLATE_D06_FIXTURES") {
            std::fs::copy(&path, std::path::PathBuf::from(folder).join("legacy-names.img")).unwrap();
        }

        let mut writer = start(&mut image, boot, &mut scratch);
        for (index, (directory, file, name)) in entries.iter().enumerate() {
            let requested = if native { name.to_ascii_uppercase() } else { name.clone() };
            let expected = if *file == seed { Removal::Unlinked } else { Removal::Freed };
            if index % 2 == 0 {
                assert_eq!(
                    writer
                        .with_compatibility(!native, |w| w.remove_node(
                            &mut image,
                            *directory,
                            &requested,
                            *file,
                            false,
                            &mut scratch
                        ))
                        .unwrap(),
                    expected
                );
            } else {
                writer
                    .with_compatibility(!native, |w| {
                        w.move_entry(&mut image, *directory, *file, &requested, *directory, "normalized", &mut scratch)
                    })
                    .unwrap();
                assert_eq!(read_resolved(&mut image, boot, *file), PAYLOAD);
                assert_eq!(
                    writer.remove_node(&mut image, *directory, "normalized", *file, false, &mut scratch).unwrap(),
                    expected
                );
            }
        }
        assert_eq!(
            writer.remove_node(&mut image, collision, "same?name", canonical, false, &mut scratch).unwrap(),
            Removal::Freed
        );
        assert_eq!(read_resolved(&mut image, boot, legacy), PAYLOAD);
        let replacement =
            writer.file_lifecycle(&mut image, root, "d06-replacement", None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, replacement, 0, CANONICAL, &mut scratch).unwrap();
        assert_eq!(
            writer
                .rename_ex(
                    &mut image,
                    root,
                    replacement,
                    "d06-replacement",
                    collision,
                    "same?name",
                    RenameTarget::Replace(legacy),
                    &mut scratch
                )
                .unwrap(),
            Some(Removal::Orphaned)
        );
        writer.reclaim_orphan(&mut image, legacy, &mut scratch).unwrap();
        writer
            .rename_ex(
                &mut image,
                root,
                seed,
                "d06-seed",
                collision,
                "same?name",
                RenameTarget::Exchange(replacement),
                &mut scratch,
            )
            .unwrap();
        assert_eq!(read_resolved(&mut image, boot, seed), PAYLOAD);
        assert_eq!(read_resolved(&mut image, boot, replacement), CANONICAL);
        writer.finish(&mut image, &mut scratch).unwrap();
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}
