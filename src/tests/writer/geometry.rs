//! Module: writer_lifecycle::geometry
//! Purpose: Verify deletion across admitted geometry and scattered metadata.
//! Created: 2026-10-21
//! Architecture: Private image copies exercise the writer and independently
//! inspect directory membership, allocation bits and retained file contents.

use super::hard_links::{allocated, bitmap, owned_storage};
use super::*;
use ntfs_rs::{
    file_lifecycle::{NodeKind, Removal},
    index_tree::I30,
    mft::{
        attribute_layout as af, file_reference, reference_number, system_record, MftRecord, ATTR_BITMAP, ATTR_DATA,
        ATTR_INDEX_ALLOCATION,
    },
    record_edit,
    replay::protect_mft_record,
    runlist::{DataRuns, Extent},
    volume::Volume,
    write_plan::{plan_nonresident_overwrite, WriteSpan},
};

const ROOT_SEQUENCE: u16 = 5;
const LARGE_DIRECTORY_FILES: usize = 256;
const NAME_PADDING: usize = 100;
const WITNESS_BYTES: usize = 8192;
const LARGE_DATA_CLUSTER_LIMIT: u64 = 64 * 1024;

fn raw_record(image: &mut Image, boot: BootSector, number: u64) -> Vec<u8> {
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mut bytes = vec![0; record_of(boot)];
    let mut volume = Volume::new(image, boot).unwrap();
    let mft = volume.load_mft(&mut zero).unwrap();
    volume.read_mft_record(&mft, number, &mut bytes).unwrap();
    MftRecord::parse(&mut bytes, boot.bytes_per_sector).unwrap();
    bytes
}

fn mapped_spans(image: &mut Image, boot: BootSector, number: u64) -> Vec<WriteSpan> {
    let zero = raw_record(image, boot, system_record::MFT);
    let record = MftRecord::from_decoded(&zero).unwrap();
    let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    let mut spans = Vec::new();
    plan_nonresident_overwrite(
        data,
        boot,
        number * u64::from(boot.record_bytes),
        u64::from(boot.record_bytes),
        |span| {
            spans.push(span);
            Ok(())
        },
    )
    .unwrap();
    spans
}

fn publish_record(image: &mut Image, boot: BootSector, number: u64, bytes: &mut [u8]) {
    let spans = if number == system_record::MFT {
        let record = MftRecord::from_decoded(bytes).unwrap();
        let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        let mut spans = Vec::new();
        plan_nonresident_overwrite(data, boot, 0, u64::from(boot.record_bytes), |span| {
            spans.push(span);
            Ok(())
        })
        .unwrap();
        spans
    } else {
        mapped_spans(image, boot, number)
    };
    protect_mft_record(bytes, boot.bytes_per_sector).unwrap();
    for span in spans {
        let start = span.source_offset as usize;
        image.write_at(span.physical_offset, &bytes[start..start + span.length as usize]).unwrap();
    }
    if number < u64::from(system_record::MIRRORED) {
        image.write_at(boot.mft_mirror_lcn * cluster_of(boot) + number * u64::from(boot.record_bytes), bytes).unwrap();
    }
}

fn scatter_attribute(image: &mut Image, boot: BootSector, owner: u64, kind: u32, name: &[u8], vcns: &[u64]) {
    assert!(image.held.is_empty());
    let mut bytes = raw_record(image, boot, owner);
    let record = MftRecord::from_decoded(&bytes).unwrap();
    let attribute = record.local_attribute(kind, name).unwrap().unwrap();
    let sizes =
        (attribute.allocated_size().unwrap(), attribute.data_size().unwrap(), attribute.initialized_size().unwrap());
    let id = attribute.id;
    let mut runs = Vec::new();
    for run in DataRuns::new(attribute.data_runs().unwrap(), 0) {
        let run = run.unwrap();
        for index in 0..run.len {
            runs.push(Extent { vcn: run.vcn + index, len: 1, lcn: Some(run.lcn.unwrap() + index) });
        }
    }
    let mut bits = bitmap(image, boot, system_record::BITMAP, ATTR_DATA);
    let cluster = cluster_of(boot);
    let total = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let mut cursor = total / 2;
    let mut block = vec![0; cluster as usize];
    for vcn in vcns {
        let run = runs.iter_mut().find(|run| run.vcn == *vcn).unwrap();
        while allocated(&bits, cursor) || allocated(&bits, cursor - 1) || allocated(&bits, cursor + 1) {
            cursor += 2;
            assert!(cursor + 1 < total);
        }
        let old = run.lcn.unwrap();
        image.read_exact_at(old * cluster, &mut block).unwrap();
        image.write_at(cursor * cluster, &block).unwrap();
        bits[cursor as usize / u8::BITS as usize] |= 1 << (cursor % u64::from(u8::BITS));
        bits[old as usize / u8::BITS as usize] &= !(1 << (old % u64::from(u8::BITS)));
        run.lcn = Some(cursor);
        cursor += 2;
    }
    let mut merged: Vec<Extent> = Vec::new();
    for run in runs {
        if let Some(last) = merged.last_mut().filter(|last| last.lcn.unwrap() + last.len == run.lcn.unwrap()) {
            last.len += 1;
        } else {
            merged.push(run);
        }
    }
    let at = record_edit::require(&bytes, kind, name).unwrap();
    record_edit::remove(&mut bytes, at).unwrap();
    let mut descriptor = vec![0; record_of(boot)];
    let len = record_edit::build_nonresident(kind, name, &merged, sizes.0, sizes.1, sizes.2, &mut descriptor).unwrap();
    descriptor[af::ID_OFFSET..af::ID_OFFSET + core::mem::size_of::<u16>()].copy_from_slice(&id.to_le_bytes());
    record_edit::insert(&mut bytes, &descriptor[..len]).unwrap();
    let bitmap_record = raw_record(image, boot, system_record::BITMAP);
    let bitmap_record = MftRecord::from_decoded(&bitmap_record).unwrap();
    let allocation = bitmap_record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    plan_nonresident_overwrite(allocation, boot, 0, bits.len() as u64, |span| {
        let start = span.source_offset as usize;
        image.write_at(span.physical_offset, &bits[start..start + span.length as usize])
    })
    .unwrap();
    publish_record(image, boot, owner, &mut bytes);
    image.flush().unwrap();
}

fn save_fixture(path: &std::path::Path, name: &str) {
    if let Some(folder) = std::env::var_os("SLATE_GEOMETRY_RESULTS") {
        let folder = std::path::PathBuf::from(folder);
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::copy(path, folder.join(name)).unwrap();
    }
}

#[test]
fn geometry_large_directory_deletion_preserves_storage() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    let (mut image, path, boot) = open_copy(&source, "geometry-directory");
    let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let parent = writer
        .create_node(
            &mut image,
            root,
            "geometry-directory",
            NodeKind::Directory,
            &NULL_DACL,
            0,
            None,
            &[],
            &mut scratch,
        )
        .unwrap();
    let witness =
        writer.file_lifecycle(&mut image, root, "geometry-witness.bin", None, &NULL_DACL, 0, &mut scratch).unwrap();
    let payload = vec![b'G'; WITNESS_BYTES];
    writer.write(&mut image, witness, 0, &payload, &mut scratch).unwrap();
    let mut files = Vec::new();
    let count =
        std::env::var("SLATE_GEOMETRY_FILES").ok().map(|value| value.parse().unwrap()).unwrap_or(LARGE_DIRECTORY_FILES);
    for index in 0..count {
        let name = format!("entry-{index:04}-{}", "a".repeat(NAME_PADDING));
        let file = writer.file_lifecycle(&mut image, parent, &name, None, &NULL_DACL, 0, &mut scratch).unwrap();
        if index % 2 == 0 && cluster_of(boot) <= LARGE_DATA_CLUSTER_LIMIT {
            writer.write(&mut image, file, 0, &payload, &mut scratch).unwrap();
        }
        files.push((name, file));
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    save_fixture(&path, "large-directory-source.img");
    let owned: Vec<_> = files.iter().map(|(_, file)| owned_storage(&mut image, boot, *file)).collect();
    let mut writer = start(&mut image, boot, &mut scratch);
    for parity in [0, 1] {
        for index in (parity..files.len()).step_by(2) {
            let (name, file) = &files[index];
            assert_eq!(
                writer.remove_node(&mut image, parent, name, *file, true, &mut scratch).unwrap(),
                Removal::Orphaned
            );
            writer.reclaim_orphan(&mut image, *file, &mut scratch).unwrap();
        }
    }
    assert_eq!(
        writer.remove_node(&mut image, root, "geometry-directory", parent, false, &mut scratch).unwrap(),
        Removal::Freed
    );
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    assert_eq!(read_resolved(&mut image, boot, witness), payload);
    let mft = bitmap(&mut image, boot, system_record::MFT, ATTR_BITMAP);
    let clusters = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    for (records, data) in owned {
        assert!(records.iter().all(|number| !allocated(&mft, *number)));
        assert!(data.iter().all(|number| !allocated(&clusters, *number)));
    }
    save_fixture(&path, "large-directory-result.img");
    drop(image);
    std::fs::remove_file(path).unwrap();
}

fn scattered_metadata_deletion(split_journal: bool) {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    let (mut image, path, boot) =
        open_copy(&source, if split_journal { "geometry-scattered-journal" } else { "geometry-scattered" });
    assert!(cluster_of(boot) < ntfs_rs::tx::BLOCK as u64);
    let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let parent = writer
        .create_node(
            &mut image,
            root,
            "scattered-directory",
            NodeKind::Directory,
            &NULL_DACL,
            0,
            None,
            &[],
            &mut scratch,
        )
        .unwrap();
    let witness =
        writer.file_lifecycle(&mut image, root, "scattered-witness.bin", None, &NULL_DACL, 0, &mut scratch).unwrap();
    let payload = vec![b'S'; WITNESS_BYTES];
    writer.write(&mut image, witness, 0, &payload, &mut scratch).unwrap();
    let mut files = Vec::new();
    for index in 0..16 {
        let name = format!("scattered-{index:02}-{}", "s".repeat(NAME_PADDING));
        let file = writer.file_lifecycle(&mut image, parent, &name, None, &NULL_DACL, 0, &mut scratch).unwrap();
        writer.write(&mut image, file, 0, &payload, &mut scratch).unwrap();
        files.push((name, file));
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    let block_clusters = ntfs_rs::tx::BLOCK as u64 / cluster_of(boot);
    scatter_attribute(
        &mut image,
        boot,
        reference_number(parent),
        ATTR_INDEX_ALLOCATION,
        I30,
        &(0..block_clusters).step_by(2).collect::<Vec<_>>(),
    );
    if cluster_of(boot) < u64::from(boot.record_bytes) {
        let file_cluster = reference_number(files[0].1) * u64::from(boot.record_bytes) / cluster_of(boot);
        let volume_cluster = system_record::VOLUME * u64::from(boot.record_bytes) / cluster_of(boot);
        scatter_attribute(
            &mut image,
            boot,
            system_record::MFT,
            ATTR_DATA,
            &[],
            &[1, file_cluster + 1, volume_cluster + 1],
        );
        assert!(mapped_spans(&mut image, boot, reference_number(files[0].1)).len() > 1);
    }
    if split_journal {
        scatter_attribute(&mut image, boot, system_record::LOG, ATTR_DATA, &[], &[1, 9, 33]);
    }
    save_fixture(&path, if split_journal { "scattered-journal-source.img" } else { "scattered-source.img" });
    let mut writer = start(&mut image, boot, &mut scratch);
    writer.set_volume_label(&mut image, &"D28 split".encode_utf16().collect::<Vec<_>>(), &mut scratch).unwrap();
    for (name, file) in &files {
        assert_eq!(writer.remove_node(&mut image, parent, name, *file, false, &mut scratch).unwrap(), Removal::Freed);
    }
    assert_eq!(
        writer.remove_node(&mut image, root, "scattered-directory", parent, false, &mut scratch).unwrap(),
        Removal::Freed
    );
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    assert_eq!(read_resolved(&mut image, boot, witness), payload);
    save_fixture(&path, if split_journal { "scattered-journal-result.img" } else { "scattered-result.img" });
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn scattered_small_cluster_metadata_survives_deletion() {
    scattered_metadata_deletion(false);
}

#[test]
fn scattered_journal_pages_survive_deletion() {
    scattered_metadata_deletion(true);
}

const PREALLOCATED_RECORDS: usize = 96;
const SCATTERED_HOLES: u64 = 32;
const SCATTERED_CHILDREN: usize = 12;
const FULL_VOLUME_ATTEMPTS: usize = 8;

#[test]
fn full_volume_deletion_and_scattered_index_allocation() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    let (mut image, path, boot) = open_copy(&source, "geometry-full");
    assert!(cluster_of(boot) < ntfs_rs::tx::BLOCK as u64);
    let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let parent = writer
        .create_node(&mut image, root, "full-directory", NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
        .unwrap();
    let filler = writer.file_lifecycle(&mut image, root, "full-filler.bin", None, &NULL_DACL, 0, &mut scratch).unwrap();
    writer.write(&mut image, filler, 0, &vec![b'F'; WITNESS_BYTES], &mut scratch).unwrap();
    let mut prepared = Vec::new();
    for index in 0..PREALLOCATED_RECORDS {
        let name = format!("preallocated-{index}");
        let reference = writer.file_lifecycle(&mut image, parent, &name, None, &NULL_DACL, 0, &mut scratch).unwrap();
        prepared.push((name, reference));
    }
    for (name, reference) in prepared {
        writer.remove_node(&mut image, parent, &name, reference, false, &mut scratch).unwrap();
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    let count = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let bits = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    let free = (0..count).filter(|number| !allocated(&bits, *number)).count() as u64;
    let mut writer = start(&mut image, boot, &mut scratch);
    let filling =
        writer.fallocate(&mut image, filler, 0, free * cluster_of(boot) + WITNESS_BYTES as u64, 0, &mut scratch);
    if filling.is_err() {
        let bits = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
        eprintln!(
            "filling={filling:?} free_before={free} free_after={} filler_allocated={}",
            (0..count).filter(|number| !allocated(&bits, *number)).count(),
            node(&mut image, boot, filler).data_size
        );
    }
    filling.unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    let bits = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    assert!((0..count).all(|number| allocated(&bits, number)), "fixture must actually exhaust free clusters");
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut created = Vec::new();
    let mut refused = false;
    for index in 0..FULL_VOLUME_ATTEMPTS {
        let name = format!("no-space-{index}-{}", "n".repeat(NAME_PADDING));
        match writer.file_lifecycle(&mut image, parent, &name, None, &NULL_DACL, 0, &mut scratch) {
            Ok(reference) => created.push((name, reference)),
            Err(Error::NoSpace) => {
                refused = true;
                break;
            }
            Err(error) => panic!("full-volume insertion: {error:?}"),
        }
    }
    assert!(refused, "full volume must refuse index allocation without poisoning deletion");
    for (name, reference) in created {
        writer.remove_node(&mut image, parent, &name, reference, false, &mut scratch).unwrap();
    }
    assert_eq!(
        writer.remove_node(&mut image, root, "full-directory", parent, false, &mut scratch).unwrap(),
        Removal::Freed
    );
    writer.finish(&mut image, &mut scratch).unwrap();
    let mut writer = start(&mut image, boot, &mut scratch);
    let parent = writer
        .create_node(
            &mut image,
            root,
            "scattered-allocation",
            NodeKind::Directory,
            &NULL_DACL,
            0,
            None,
            &[],
            &mut scratch,
        )
        .unwrap();
    for index in 0..SCATTERED_HOLES {
        writer
            .fallocate(
                &mut image,
                filler,
                index * 2 * cluster_of(boot),
                cluster_of(boot),
                FALLOC_KEEP_SIZE | FALLOC_PUNCH_HOLE,
                &mut scratch,
            )
            .unwrap();
    }
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let bits = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    let free: Vec<_> = (0..count).filter(|number| !allocated(&bits, *number)).collect();
    assert!(free.len() >= SCATTERED_HOLES as usize);
    assert!(free.windows(2).all(|pair| pair[1] > pair[0] + 1), "fixture must have no adjacent free clusters");
    let mut children = Vec::new();
    for index in 0..SCATTERED_CHILDREN {
        let name = format!("fragmented-{index:02}-{}", "f".repeat(NAME_PADDING));
        let reference = writer.file_lifecycle(&mut image, parent, &name, None, &NULL_DACL, 0, &mut scratch).unwrap();
        children.push((name, reference));
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    let bytes = raw_record(&mut image, boot, reference_number(parent));
    let record = MftRecord::from_decoded(&bytes).unwrap();
    let index = record.local_attribute(ATTR_INDEX_ALLOCATION, I30).unwrap().unwrap();
    let runs = DataRuns::new(index.data_runs().unwrap(), 0).collect::<Result<Vec<_>>>().unwrap();
    assert!(runs.len() > 1, "index allocation must consume scattered free clusters");
    save_fixture(&path, "full-scattered-source.img");
    let mut writer = start(&mut image, boot, &mut scratch);
    for (name, reference) in children {
        writer.remove_node(&mut image, parent, &name, reference, false, &mut scratch).unwrap();
    }
    writer.remove_node(&mut image, root, "scattered-allocation", parent, false, &mut scratch).unwrap();
    writer.remove_node(&mut image, root, "full-filler.bin", filler, false, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let bits = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    let after = (0..count).filter(|number| !allocated(&bits, *number)).count() as u64;
    assert!(after >= free.len() as u64);
    save_fixture(&path, "full-scattered-result.img");
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unsupported_record_geometry_refuses_before_writes() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE")
        .expect("Set SLATE_LIFECYCLE_SOURCE to an unsupported disposable geometry");
    let (mut image, path, boot) = open_copy(&source, "geometry-refused");
    assert!(!boot.writable_geometry());
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    assert!(matches!(Writer::prepare(&mut image, boot, &mut scratch), Err(Error::Unsupported)));
    assert_eq!(image.writes, 0);
    assert!(image.held.is_empty());
    drop(image);
    std::fs::remove_file(path).unwrap();
}

const IMPORTED_ROOT_NAME_UNITS: usize = 60;
const IMPORTED_ROOT_ENTRIES: usize = 3;
const ROOT_HEADER_BYTES: usize = 16;
const NODE_HEADER_BYTES: usize = 16;
const NODE_USED_OFFSET: usize = 4;
const NODE_CAPACITY_OFFSET: usize = 8;
const NODE_FLAGS_OFFSET: usize = 12;
const ENTRY_HEADER_BYTES: usize = 16;
const ENTRY_LENGTH_OFFSET: usize = 8;
const ENTRY_FLAGS_OFFSET: usize = 12;
const ENTRY_TERMINAL: u16 = 2;
const STALE_MODIFICATION_TIME: u64 = 1;

#[test]
fn imported_large_root_allows_metadata_refresh_and_deletion() {
    use ntfs_rs::{
        attrlist::ListEntry,
        index_tree::directory_entry,
        mft::{record_layout as rf, ATTR_ATTRIBUTE_LIST, ATTR_FILE_NAME, ATTR_INDEX_ROOT},
        std_info,
    };
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a disposable image");
    for extension in [false, true] {
        for orphan in [false, true] {
            let case = format!("imported-root-{extension}-{orphan}");
            let (mut image, path, boot) = open_copy(&source, &case);
            let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
            let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
            let mut writer = start(&mut image, boot, &mut scratch);
            let parent = writer
                .create_node(
                    &mut image,
                    root,
                    "large-root",
                    NodeKind::Directory,
                    &NULL_DACL,
                    0,
                    None,
                    &[],
                    &mut scratch,
                )
                .unwrap();
            let mut branches = Vec::new();
            for ordinal in 0..IMPORTED_ROOT_ENTRIES {
                let name = char::from(b'a' + ordinal as u8).to_string().repeat(IMPORTED_ROOT_NAME_UNITS);
                let reference = writer
                    .create_node(&mut image, parent, &name, NodeKind::Directory, &NULL_DACL, 0, None, &[], &mut scratch)
                    .unwrap();
                branches.push((name, reference));
            }
            let victim = writer
                .create_node(
                    &mut image,
                    branches[0].1,
                    "victim",
                    NodeKind::Directory,
                    &NULL_DACL,
                    0,
                    None,
                    &[],
                    &mut scratch,
                )
                .unwrap();
            let spare = extension.then(|| {
                writer
                    .create_node(&mut image, root, "", NodeKind::Temporary, &NULL_DACL, 0, None, &[], &mut scratch)
                    .unwrap()
            });
            writer.finish(&mut image, &mut scratch).unwrap();
            let mut bytes = raw_record(&mut image, boot, reference_number(parent));
            let at = record_edit::require(&bytes, ATTR_INDEX_ROOT, I30).unwrap();
            let old = record_edit::resident_value(&bytes, at).unwrap();
            let mut imported = old[..ROOT_HEADER_BYTES + NODE_HEADER_BYTES].to_vec();
            for (_, reference) in &branches {
                let child = raw_record(&mut image, boot, reference_number(*reference));
                let at = record_edit::require(&child, ATTR_FILE_NAME, &[]).unwrap();
                let value = record_edit::resident_value(&child, at).unwrap();
                let mut entry = vec![0; record_of(boot)];
                let length = directory_entry(*reference, value, &mut entry).unwrap();
                imported.extend_from_slice(&entry[..length]);
            }
            let stop = imported.len();
            imported.resize(stop + ENTRY_HEADER_BYTES, 0);
            record_edit::p16(&mut imported, stop + ENTRY_LENGTH_OFFSET, ENTRY_HEADER_BYTES as u16).unwrap();
            record_edit::p16(&mut imported, stop + ENTRY_FLAGS_OFFSET, ENTRY_TERMINAL).unwrap();
            let length = (imported.len() - ROOT_HEADER_BYTES) as u32;
            for offset in [NODE_USED_OFFSET, NODE_CAPACITY_OFFSET] {
                record_edit::p32(&mut imported, ROOT_HEADER_BYTES + offset, length).unwrap();
            }
            imported[ROOT_HEADER_BYTES + NODE_FLAGS_OFFSET] = 0;
            let mut bits = bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
            let record = MftRecord::from_decoded(&bytes).unwrap();
            let allocation = record.local_attribute(ATTR_INDEX_ALLOCATION, I30).unwrap().unwrap();
            for run in DataRuns::new(allocation.data_runs().unwrap(), 0) {
                let run = run.unwrap();
                let first = run.lcn.unwrap();
                for cluster in first..first + run.len {
                    bits[cluster as usize / u8::BITS as usize] &= !(1 << (cluster % u64::from(u8::BITS)));
                }
            }
            for kind in [ATTR_INDEX_ALLOCATION, ATTR_BITMAP] {
                let at = record_edit::require(&bytes, kind, I30).unwrap();
                assert!(kind != ATTR_BITMAP || !record_edit::is_nonresident(&bytes, at).unwrap());
                record_edit::remove(&mut bytes, at).unwrap();
            }
            let at = record_edit::require(&bytes, ATTR_INDEX_ROOT, I30).unwrap();
            record_edit::set_resident_value(&mut bytes, at, &imported).unwrap();
            if let Some(spare) = spare {
                let mut member = raw_record(&mut image, boot, reference_number(spare));
                record_edit::format_empty(&mut member, reference_number(spare)).unwrap();
                record_edit::p16(
                    &mut member,
                    rf::SEQUENCE_OFFSET,
                    (spare >> ntfs_rs::mft::FILE_REFERENCE_SEQUENCE_SHIFT) as u16,
                )
                .unwrap();
                record_edit::p16(&mut member, rf::FLAGS_OFFSET, rf::IN_USE).unwrap();
                record_edit::p64(&mut member, rf::BASE_REFERENCE_OFFSET, parent).unwrap();
                let attr =
                    MftRecord::from_decoded(&bytes).unwrap().local_attribute(ATTR_INDEX_ROOT, I30).unwrap().unwrap();
                let at = attr.record_offset();
                let length = record_edit::attr_len(&bytes, at).unwrap();
                record_edit::insert(&mut member, &bytes[at..at + length]).unwrap();
                let at = record_edit::require(&bytes, ATTR_INDEX_ROOT, I30).unwrap();
                record_edit::remove(&mut bytes, at).unwrap();
                let mut list = Vec::new();
                for (owner, record) in [(parent, &bytes), (spare, &member)] {
                    for attr in MftRecord::from_decoded(record).unwrap().attributes() {
                        let attr = attr.unwrap();
                        let entry = ListEntry {
                            kind: attr.kind,
                            first_vcn: 0,
                            file_reference: owner,
                            attribute_id: attr.id,
                            name_utf16le: attr.name_utf16le().unwrap(),
                        };
                        let mut encoded = vec![0; entry.encoded_len().unwrap()];
                        entry.encode(&mut encoded).unwrap();
                        list.extend_from_slice(&encoded);
                    }
                }
                let mut attribute = vec![0; record_of(boot)];
                let length = record_edit::build_resident(ATTR_ATTRIBUTE_LIST, &[], &list, &mut attribute).unwrap();
                record_edit::insert(&mut bytes, &attribute[..length]).unwrap();
                publish_record(&mut image, boot, reference_number(spare), &mut member);
            }
            publish_record(&mut image, boot, reference_number(parent), &mut bytes);
            let bitmap_record = raw_record(&mut image, boot, system_record::BITMAP);
            let record = MftRecord::from_decoded(&bitmap_record).unwrap();
            let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            plan_nonresident_overwrite(data, boot, 0, bits.len() as u64, |span| {
                let at = span.source_offset as usize;
                image.write_at(span.physical_offset, &bits[at..at + span.length as usize])
            })
            .unwrap();
            // A cached filename can lag SI on an imported volume. Deleting its
            // child must refresh the ancestor's larger resident root in place.
            let mut branch = raw_record(&mut image, boot, reference_number(branches[0].1));
            let mut times = [None; std_info::TIME_COUNT];
            times[std_info::MODIFIED] = Some(STALE_MODIFICATION_TIME);
            std_info::update(&mut branch, times, None).unwrap();
            publish_record(&mut image, boot, reference_number(branches[0].1), &mut branch);
            image.flush().unwrap();
            save_fixture(&path, &format!("{case}-source.img"));
            let before = owned_storage(&mut image, boot, parent);
            let mut writer = start(&mut image, boot, &mut scratch);
            let result = writer.remove_node(&mut image, branches[0].1, "victim", victim, orphan, &mut scratch).unwrap();
            if orphan {
                assert_eq!(result, Removal::Orphaned);
                writer.reclaim_orphan(&mut image, victim, &mut scratch).unwrap();
            } else {
                assert_eq!(result, Removal::Freed);
            }
            writer.finish(&mut image, &mut scratch).unwrap();
            let after = owned_storage(&mut image, boot, parent);
            assert_eq!(before.1, after.1, "cache refresh must not allocate index blocks");
            assert!(after.1.is_empty());
            let mut writer = start(&mut image, boot, &mut scratch);
            for (name, reference) in branches {
                writer.remove_node(&mut image, parent, &name, reference, false, &mut scratch).unwrap();
            }
            writer.remove_node(&mut image, root, "large-root", parent, false, &mut scratch).unwrap();
            writer.finish(&mut image, &mut scratch).unwrap();
            save_fixture(&path, &format!("{case}-result.img"));
            drop(image);
            std::fs::remove_file(path).unwrap();
        }
    }
}
