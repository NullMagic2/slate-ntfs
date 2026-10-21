//! Module: writer_lifecycle::compressed_completion
//! Purpose: Exercise native-limit compressed families and dispersed reclamation.
//! Created: 2026-10-21
//! Architecture: Builds valid private record families with shared encoders; the
//! writer must retire all mapped allocations and MFT members without large assembly.

use super::*;
use ntfs_rs::{
    allocation::CLUSTERS_PER_BITMAP_SECTOR,
    attrlist::{ListEntry, MAX_ATTRIBUTE_LIST_BYTES},
    file_lifecycle::{NodeKind, Removal},
    filename,
    mft::{
        attribute_layout as af, file_reference, record_layout as rf, reference_number, reference_sequence,
        system_record,
    },
    mft::{MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA},
    record_edit as edit,
    replay::protect_mft_record,
    runlist::{DataRuns, Extent},
    volume::Volume,
};
use std::collections::BTreeSet;

const ROOT_SEQUENCE: u16 = 5;
const COMPRESSION_UNITS: u64 = 2;
const PAYLOAD_BYTE: u8 = 0x5a;
const FIXTURE_NAME: &str = "compressed-capacity-source";
const REPACK_LIST_BYTES: usize = LAYOUT_CLUSTER as usize;
const REPACK_BITMAP_SECTORS: u64 = 4;

fn offset(attribute: ntfs_rs::mft::Attribute<'_>, cluster_bytes: u64, logical: u64) -> u64 {
    for run in DataRuns::new(attribute.data_runs().unwrap(), attribute.first_vcn().unwrap()) {
        let run = run.unwrap();
        let first = run.vcn * cluster_bytes;
        let end = (run.vcn + run.len) * cluster_bytes;
        if (first..end).contains(&logical) {
            return run.lcn.unwrap() * cluster_bytes + logical - first;
        }
    }
    panic!("fixture offset has no allocated mapping");
}

fn set_bit(bytes: &mut [u8], cluster: u64, allocated: bool) {
    let index = cluster as usize / u8::BITS as usize;
    let mask = 1 << (cluster % u64::from(u8::BITS));
    if allocated {
        bytes[index] |= mask;
    } else {
        bytes[index] &= !mask;
    }
}

fn free_cluster(bits: &mut [u8], first: u64, end: u64) -> u64 {
    let cluster = (first..end).find(|&cluster| !hard_links::allocated(bits, cluster)).unwrap();
    set_bit(bits, cluster, true);
    cluster
}

fn entry(kind: u32, name: &[u8], first_vcn: u64, owner: u64, id: u16) -> ListEntry<'_> {
    ListEntry { kind, first_vcn, file_reference: owner, attribute_id: id, name_utf16le: name }
}

fn stream_names(bytes: usize) -> Vec<Vec<u8>> {
    let maximum = vec![0; filename::MAX_NAME_BYTES];
    let maximum_entry = entry(ATTR_DATA, &maximum, 0, 0, 0).encoded_len().unwrap();
    let mut remaining = bytes;
    let mut names = Vec::new();
    while remaining != 0 {
        let prefix = format!("stream-{:06}-", names.len());
        let minimum: Vec<_> = prefix.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let minimum_entry = entry(ATTR_DATA, &minimum, 0, 0, 0).encoded_len().unwrap();
        let mut desired = remaining.min(maximum_entry);
        if remaining > maximum_entry && remaining - maximum_entry < minimum_entry {
            desired -= minimum_entry - (remaining - maximum_entry);
        }
        let name = (prefix.len()..=u8::MAX as usize)
            .map(|chars| {
                format!("{prefix}{}", "x".repeat(chars - prefix.len()))
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            })
            .find(|name| entry(ATTR_DATA, name, 0, 0, 0).encoded_len().unwrap() == desired)
            .expect("the target list leaves room for a unique stream name");
        remaining -= desired;
        names.push(name);
    }
    names
}

fn export(path: &std::path::Path, tag: &str, stage: &str, reference: u64) {
    if let Some(folder) = std::env::var_os("SLATE_D20_COMPLETION_FIXTURES") {
        let destination = std::path::PathBuf::from(folder).join(format!("{tag}-{stage}.img"));
        std::fs::copy(path, &destination).unwrap();
        std::fs::write(destination.with_extension("reference"), reference.to_string()).unwrap();
    }
}

fn check_metadata_projection(image: &mut Image, boot: BootSector, reference: u64) {
    let mut volume = Volume::new(image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mut raw = vec![0; record_of(boot)];
    let mut output = vec![0; ntfs_rs::tx::RECORD_IMAGE];
    let mut work = vec![0; ntfs_rs::volume::FAMILY_SCRATCH_BYTES];
    let mft = volume.load_mft(&mut zero).unwrap();
    volume.read_mft_record(&mft, reference_number(reference), &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    volume.resolve_record_attributes(&mft, &record, &mut output, &mut work).unwrap();
    let projected = MftRecord::from_decoded(&output).unwrap();
    for attribute in projected.attributes() {
        let attribute = attribute.unwrap();
        if attribute.kind == ATTR_DATA {
            assert!(attribute.name_utf16le().unwrap().is_empty());
            assert!(!attribute.nonresident || attribute.first_vcn().unwrap() == 0);
        }
    }
    volume.resolve_record_metadata(&mft, &record, &mut output, &mut work).unwrap();
    assert!(MftRecord::from_decoded(&output).unwrap().attributes().all(|a| a.unwrap().kind != ATTR_DATA));
}

fn exercise(source: &str, dispersed: bool, list_bytes: usize) {
    let tag = if list_bytes == MAX_ATTRIBUTE_LIST_BYTES {
        format!("compressed-native-capacity-{dispersed}")
    } else {
        "compressed-list-repack".to_owned()
    };
    let (mut image, path, boot) = open_copy(source, &tag);
    assert_eq!(cluster_of(boot), LAYOUT_CLUSTER);
    assert_eq!(record_of(boot), LAYOUT_RECORD);
    let cluster_bytes = cluster_of(boot);
    let root = file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
    let data_segments = COMPRESSION_UNITS * af::COMPRESSION_UNIT_CLUSTERS;
    let length = data_segments * cluster_bytes;
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let reference = writer.file_lifecycle(&mut image, root, FIXTURE_NAME, None, &NULL_DACL, 0, &mut scratch).unwrap();
    writer.write(&mut image, reference, 0, &vec![PAYLOAD_BYTE; length as usize], &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();

    let mut base = vec![0; record_of(boot)];
    let metadata_bytes = {
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
        let mft = volume.load_mft(&mut zero).unwrap();
        volume.read_mft_record(&mft, reference_number(reference), &mut base).unwrap();
        let record = MftRecord::parse(&mut base, boot.bytes_per_sector).unwrap();
        record
            .attributes()
            .map(|attribute| attribute.unwrap())
            .filter(|attribute| attribute.kind != ATTR_DATA)
            .map(|attribute| {
                entry(attribute.kind, attribute.name_utf16le().unwrap(), 0, reference, attribute.id)
                    .encoded_len()
                    .unwrap()
            })
            .sum::<usize>()
    };
    let data_entry_bytes = entry(ATTR_DATA, &[], 0, reference, 0).encoded_len().unwrap();
    let names = stream_names(list_bytes - metadata_bytes - data_segments as usize * data_entry_bytes);
    let member_count = data_segments as usize - 1 + names.len();
    let mut writer = start(&mut image, boot, &mut scratch);
    writer.ensure_free_records(&mut image, member_count as u64, &mut scratch).unwrap();
    let mut extensions = Vec::new();
    for _ in 0..member_count {
        if writer.crowded() {
            writer.make_room(&mut image, &mut scratch).unwrap();
        }
        extensions.push(
            writer
                .with_compatibility(true, |writer| {
                    writer.create_node(
                        &mut image,
                        root,
                        "",
                        NodeKind::Temporary,
                        &NULL_DACL,
                        0,
                        None,
                        &[],
                        &mut scratch,
                    )
                })
                .unwrap(),
        );
    }
    writer.finish(&mut image, &mut scratch).unwrap();

    let mut bits;
    let mut data_clusters = Vec::new();
    let mut bitmap_writes = Vec::new();
    let mut record_offsets = Vec::new();
    {
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
        let mft = volume.load_mft(&mut zero).unwrap();
        let mft_data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        for owner in std::iter::once(reference).chain(extensions.iter().copied()) {
            record_offsets.push(offset(mft_data, cluster_bytes, reference_number(owner) * record_of(boot) as u64));
        }
        volume.read_mft_record(&mft, reference_number(reference), &mut base).unwrap();
        let record = MftRecord::parse(&mut base, boot.bytes_per_sector).unwrap();
        let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        for run in DataRuns::new(data.data_runs().unwrap(), 0) {
            let run = run.unwrap();
            data_clusters.extend(run.lcn.unwrap()..run.lcn.unwrap() + run.len);
        }
        let mut raw = vec![0; record_of(boot)];
        volume.read_mft_record(&mft, system_record::BITMAP, &mut raw).unwrap();
        let bitmap_record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
        let bitmap = bitmap_record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        bits = vec![0; bitmap.data_size().unwrap() as usize];
        volume.read_attribute(bitmap, 0, &mut bits).unwrap();
        for logical in (0..bits.len()).step_by(cluster_bytes as usize) {
            bitmap_writes.push((
                offset(bitmap, cluster_bytes, logical as u64),
                logical,
                (bits.len() - logical).min(cluster_bytes as usize),
            ));
        }
    }
    assert_eq!(data_clusters.len(), data_segments as usize);
    let total_clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let list_clusters = (MAX_ATTRIBUTE_LIST_BYTES as u64).div_ceil(cluster_bytes);
    let list_allocation = if dispersed {
        let old = std::mem::take(&mut data_clusters);
        for vcn in 0..data_segments {
            let first = vcn * CLUSTERS_PER_BITMAP_SECTOR;
            data_clusters.push(free_cluster(
                &mut bits,
                first,
                (first + CLUSTERS_PER_BITMAP_SECTOR).min(total_clusters),
            ));
        }
        for cluster in old {
            set_bit(&mut bits, cluster, false);
        }
        (0..list_clusters)
            .map(|vcn| {
                let first = (data_segments + vcn) * CLUSTERS_PER_BITMAP_SECTOR;
                free_cluster(&mut bits, first, (first + CLUSTERS_PER_BITMAP_SECTOR).min(total_clusters))
            })
            .collect::<Vec<_>>()
    } else if list_bytes != MAX_ATTRIBUTE_LIST_BYTES {
        (0..list_clusters)
            .map(|vcn| {
                let first = vcn % REPACK_BITMAP_SECTORS * CLUSTERS_PER_BITMAP_SECTOR;
                free_cluster(&mut bits, first, (first + CLUSTERS_PER_BITMAP_SECTOR).min(total_clusters))
            })
            .collect::<Vec<_>>()
    } else {
        let first = (1..total_clusters - list_clusters)
            .find(|&first| (first..first + list_clusters).all(|cluster| !hard_links::allocated(&bits, cluster)))
            .unwrap();
        (first..first + list_clusters).inspect(|&cluster| set_bit(&mut bits, cluster, true)).collect::<Vec<_>>()
    };
    for cluster in &data_clusters {
        image.write_at(cluster * cluster_bytes, &vec![PAYLOAD_BYTE; cluster_bytes as usize]).unwrap();
    }
    let at = edit::require(&base, ATTR_DATA, &[]).unwrap();
    edit::remove(&mut base, at).unwrap();
    let si = edit::require(&base, ntfs_rs::std_info::SI, &[]).unwrap();
    let si_value = edit::resident_value_offset(&base, si).unwrap();
    let attributes = ntfs_rs::bytes::u32_at(&base, si_value + ntfs_rs::std_info::TIMES_BYTES).unwrap();
    edit::p32(&mut base, si_value + ntfs_rs::std_info::TIMES_BYTES, attributes | ntfs_rs::std_info::COMPRESSED)
        .unwrap();
    let mut list_entries = Vec::new();
    let mut attribute = vec![0; record_of(boot)];
    for index in 0..=member_count {
        let owner = if index == 0 { reference } else { extensions[index - 1] };
        let mut raw = if index == 0 {
            base.clone()
        } else {
            let mut raw = vec![0; record_of(boot)];
            edit::format_empty(&mut raw, reference_number(owner)).unwrap();
            edit::p16(&mut raw, rf::SEQUENCE_OFFSET, reference_sequence(owner)).unwrap();
            edit::p16(&mut raw, rf::FLAGS_OFFSET, rf::IN_USE).unwrap();
            edit::p64(&mut raw, rf::BASE_REFERENCE_OFFSET, reference).unwrap();
            raw
        };
        let n = if index < data_segments as usize {
            let first = index as u64;
            let n = edit::build_nonresident_at(
                ATTR_DATA,
                &[],
                &[Extent { vcn: first, len: 1, lcn: Some(data_clusters[index]) }],
                first,
                length,
                length,
                length,
                &mut attribute,
            )
            .unwrap();
            edit::p16(&mut attribute, af::FLAGS_OFFSET, af::COMPRESSED).unwrap();
            edit::p16(&mut attribute, af::COMPRESSION_UNIT_OFFSET, af::COMPRESSION_UNIT_SHIFT).unwrap();
            edit::p64(&mut attribute, af::COMPRESSED_SIZE_OFFSET, length).unwrap();
            n
        } else {
            edit::build_resident(ATTR_DATA, &names[index - data_segments as usize], &[], &mut attribute).unwrap()
        };
        edit::insert(&mut raw, &attribute[..n]).unwrap();
        for attribute in MftRecord::from_decoded(&raw).unwrap().attributes() {
            let attribute = attribute.unwrap();
            list_entries.push((
                attribute.kind,
                attribute.name_utf16le().unwrap().to_vec(),
                if attribute.nonresident { attribute.first_vcn().unwrap() } else { 0 },
                owner,
                attribute.id,
            ));
        }
        if index == 0 {
            base = raw;
        } else {
            protect_mft_record(&mut raw, boot.bytes_per_sector).unwrap();
            image.write_at(record_offsets[index], &raw).unwrap();
        }
    }
    list_entries.sort();
    let mut list = vec![0; MAX_ATTRIBUTE_LIST_BYTES];
    let mut used = 0;
    for (kind, name, first, owner, id) in &list_entries {
        used += entry(*kind, name, *first, *owner, *id).encode(&mut list[used..]).unwrap();
    }
    assert_eq!(used, list_bytes);
    for (vcn, cluster) in list_allocation.iter().enumerate() {
        let first = vcn * cluster_bytes as usize;
        image.write_at(cluster * cluster_bytes, &list[first..first + cluster_bytes as usize]).unwrap();
    }
    let list_runs: Vec<_> = list_allocation
        .iter()
        .enumerate()
        .map(|(vcn, &lcn)| Extent { vcn: vcn as u64, len: 1, lcn: Some(lcn) })
        .collect();
    let n = edit::build_nonresident(
        ATTR_ATTRIBUTE_LIST,
        &[],
        &list_runs,
        MAX_ATTRIBUTE_LIST_BYTES as u64,
        used as u64,
        used as u64,
        &mut attribute,
    )
    .unwrap();
    edit::insert(&mut base, &attribute[..n]).unwrap();
    protect_mft_record(&mut base, boot.bytes_per_sector).unwrap();
    image.write_at(record_offsets[0], &base).unwrap();
    for (physical, first, len) in bitmap_writes {
        image.write_at(physical, &bits[first..first + len]).unwrap();
    }
    image.flush().unwrap();
    let (mut records, clusters) = hard_links::owned_storage(&mut image, boot, reference);
    assert_eq!(records.len(), member_count + 1);
    assert_eq!(clusters.len(), data_segments as usize);
    eprintln!("capacity_fixture list_bytes={used} named_streams={} data_segments={data_segments} list_sectors={} data_sectors={}", names.len(), list_allocation.iter().map(|cluster| cluster / CLUSTERS_PER_BITMAP_SECTOR).collect::<BTreeSet<_>>().len(), data_clusters.iter().map(|cluster| cluster / CLUSTERS_PER_BITMAP_SECTOR).collect::<BTreeSet<_>>().len());
    check_metadata_projection(&mut image, boot, reference);
    export(&path, &tag, "source", reference);
    let mut writer = start(&mut image, boot, &mut scratch);
    assert_eq!(
        writer.remove_node(&mut image, root, FIXTURE_NAME, reference, true, &mut scratch).unwrap(),
        Removal::Orphaned
    );
    writer.finish(&mut image, &mut scratch).unwrap();
    records.extend(hard_links::owned_storage(&mut image, boot, reference).0);
    check_metadata_projection(&mut image, boot, reference);
    export(&path, &tag, "orphan", reference);
    let mut writer = start(&mut image, boot, &mut scratch);
    assert!(!writer.reclaim_orphan_step(&mut image, reference, &mut scratch).unwrap());
    writer.finish(&mut image, &mut scratch).unwrap();
    records.extend(hard_links::owned_storage(&mut image, boot, reference).0);
    check_metadata_projection(&mut image, boot, reference);
    export(&path, &tag, "first-step", reference);
    let mut writer = start(&mut image, boot, &mut scratch);
    writer.reclaim_orphan(&mut image, reference, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    let mft_bits = hard_links::bitmap(&mut image, boot, system_record::MFT, ATTR_BITMAP);
    for record in records {
        assert!(!hard_links::allocated(&mft_bits, record), "MFT record {record} leaked");
    }
    let bits = hard_links::bitmap(&mut image, boot, system_record::BITMAP, ATTR_DATA);
    for cluster in data_clusters.iter().chain(&list_allocation) {
        assert!(!hard_links::allocated(&bits, *cluster), "cluster {cluster} leaked");
    }
    export(&path, &tag, "complete", reference);
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn maximum_native_list_with_compressed_continuations_reclaims_all_members() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    exercise(&source, false, MAX_ATTRIBUTE_LIST_BYTES);
}

#[test]
#[ignore = "requires SLATE_LIFECYCLE_LARGE_SOURCE with a private volume spanning 96 bitmap sectors"]
fn dispersed_native_list_and_compression_units_reclaim_all_members() {
    let source = std::env::var("SLATE_LIFECYCLE_LARGE_SOURCE").unwrap();
    exercise(&source, true, MAX_ATTRIBUTE_LIST_BYTES);
}

#[test]
fn fragmented_preallocated_list_retains_ownership_during_repacking() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    exercise(&source, false, REPACK_LIST_BYTES);
}
