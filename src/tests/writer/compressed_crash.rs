//! Module: writer_crash::compressed_crash
//! Purpose: Check interrupted compressed-unit retirement across DATA records.
//! Created: 2026-10-21
//! Architecture: Reuses the volatile writer adapter and recovery coordinator;
//! independent mapping and bitmap reads reject partial-unit publication or leaks.

use super::*;
use ntfs_rs::{
    mft::{attribute_layout as af, reference_number, system_record},
    runlist::DataRuns,
};

const FIRST_SECTOR_BYTES: usize = 512;
const SURVIVAL_MODES: usize = 4;

struct ReclaimState {
    allocated: u64,
    clusters: BTreeSet<u64>,
    members: BTreeSet<u64>,
    bits: Vec<u8>,
    mft_bits: Vec<u8>,
}

fn state(bytes: Vec<u8>, boot: BootSector, reference: u64) -> ReclaimState {
    let mut image = Image { bytes, held: Vec::new(), trace: Vec::new() };
    let mut volume = Volume::new(&mut image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(boot.record_bytes as usize)];
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut work = vec![0; METADATA_SCRATCH_BYTES];
    let mft = volume.load_mft(&mut zero).unwrap();
    volume.read_mft_record(&mft, reference_number(reference), &mut raw).unwrap();
    let base = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let mut allocated = None;
    let mut head = None;
    let mut clusters = BTreeSet::new();
    let mut encoded_clusters = BTreeSet::new();
    let mut members = BTreeSet::from([reference_number(reference)]);
    let mut take_runs = |attribute: ntfs_rs::mft::Attribute<'_>, encoded: bool| -> Result<()> {
        if attribute.nonresident {
            for run in DataRuns::new(attribute.data_runs()?, attribute.first_vcn()?) {
                let run = run?;
                if let Some(lcn) = run.lcn {
                    clusters.extend(lcn..lcn + run.len);
                    if encoded {
                        encoded_clusters.extend(lcn..lcn + run.len);
                    }
                }
            }
        }
        Ok(())
    };
    for attribute in base.attributes() {
        let attribute = attribute.unwrap();
        if attribute.kind == ntfs_rs::mft::ATTR_ATTRIBUTE_LIST {
            take_runs(attribute, false).unwrap();
        }
    }
    volume
        .visit_record_family(&mft, &base, &mut work, |owner, attribute| {
            members.insert(reference_number(owner));
            let encoded = attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() && attribute.nonresident;
            take_runs(attribute, encoded)?;
            if encoded && attribute.first_vcn()? == 0 {
                allocated = Some(attribute.allocated_size()?);
                head = Some((owner, attribute.record_offset()));
            }
            Ok(())
        })
        .unwrap();
    let (owner, at) = head.unwrap();
    volume.read_mft_record(&mft, reference_number(owner), &mut raw).unwrap();
    MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let physical = ntfs_rs::bytes::u64_at(&raw, at + af::COMPRESSED_SIZE_OFFSET).unwrap();
    volume.read_mft_record(&mft, system_record::BITMAP, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let bitmap = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    let mut bits = vec![0; bitmap.data_size().unwrap() as usize];
    volume.read_attribute(bitmap, 0, &mut bits).unwrap();
    let bitmap = mft.local_attribute(ntfs_rs::mft::ATTR_BITMAP, &[]).unwrap().unwrap();
    let mut mft_bits = vec![0; bitmap.data_size().unwrap() as usize];
    volume.read_attribute(bitmap, 0, &mut mft_bits).unwrap();
    let allocated = allocated.unwrap();
    assert_eq!(allocated % (af::COMPRESSION_UNIT_CLUSTERS * u64::from(boot.cluster_bytes)), 0);
    assert_eq!(physical, encoded_clusters.len() as u64 * u64::from(boot.cluster_bytes));
    for cluster in &clusters {
        assert!(bits[*cluster as usize / u8::BITS as usize] & (1 << (*cluster % u64::from(u8::BITS))) != 0);
    }
    ReclaimState { allocated, clusters, members, bits, mft_bits }
}

fn check_write_prefixes(source: std::path::PathBuf, unlink: bool) {
    let reference: u64 = fs::read_to_string(source.with_extension("reference")).unwrap().parse().unwrap();
    let dir = crash_directory("compressed-unit");
    let path = dir.join("cut.img");
    let mut image = Image { bytes: fs::read(&source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..FIRST_SECTOR_BYTES]).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    let original = state(baseline.clone(), boot, reference);
    image.trace.clear();
    if unlink {
        const ROOT_SEQUENCE: u16 = 5;
        let root = ntfs_rs::mft::file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
        assert_eq!(
            writer.remove_node(&mut image, root, "compressed-capacity-source", reference, true, &mut scratch).unwrap(),
            ntfs_rs::file_lifecycle::Removal::Orphaned
        );
    } else {
        assert!(!writer.reclaim_orphan_step(&mut image, reference, &mut scratch).unwrap());
    }
    writer.drain(&mut image, &mut scratch).unwrap();
    let mut projected = image.bytes.clone();
    for (at, bytes) in &image.held {
        projected[*at as usize..*at as usize + bytes.len()].copy_from_slice(bytes);
    }
    let projected = state(projected, boot, reference);
    assert!(projected.allocated <= original.allocated);
    assert!(
        projected.allocated < original.allocated
            || projected.clusters != original.clusters
            || projected.members != original.members
    );
    let tracked_clusters: BTreeSet<_> = original.clusters.union(&projected.clusters).copied().collect();
    let tracked_members: BTreeSet<_> = original.members.union(&projected.members).copied().collect();
    let mut durable = baseline.clone();
    let mut visible = baseline;
    let mut checked = BTreeSet::new();
    for (cut, event) in image.trace.iter().enumerate() {
        let mut isolated = durable.clone();
        let mut torn = durable.clone();
        match event {
            Some((at, bytes)) => {
                let start = *at as usize;
                let end = start + bytes.len();
                visible[start..end].copy_from_slice(bytes);
                isolated[start..end].copy_from_slice(bytes);
                let n = bytes.len().min(FIRST_SECTOR_BYTES);
                torn[start..start + n].copy_from_slice(&bytes[..n]);
            }
            None => durable.copy_from_slice(&visible),
        }
        let variants: [&[u8]; SURVIVAL_MODES] = [&durable, &visible, &isolated, &torn];
        for (mode, crashed) in variants.into_iter().enumerate() {
            let mut hash = DefaultHasher::new();
            crashed.hash(&mut hash);
            if !checked.insert(hash.finish()) {
                continue;
            }
            fs::write(&path, crashed).unwrap();
            let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            super::super::recover_created_copy(&path, &mut file, &mut 0, None)
                .unwrap_or_else(|error| panic!("cut={cut} mode={mode}: {error}"));
            let recovered = state(fs::read(&path).unwrap(), boot, reference);
            assert!(
                recovered.allocated == original.allocated || recovered.allocated == projected.allocated,
                "cut={cut} mode={mode}: partial unit retired"
            );
            for cluster in &tracked_clusters {
                let allocated = recovered.bits[*cluster as usize / u8::BITS as usize]
                    & (1 << (*cluster % u64::from(u8::BITS)))
                    != 0;
                assert_eq!(allocated, recovered.clusters.contains(cluster), "cut={cut} mode={mode}: cluster {cluster}");
            }
            for member in &tracked_members {
                let allocated = recovered.mft_bits[*member as usize / u8::BITS as usize]
                    & (1 << (*member % u64::from(u8::BITS)))
                    != 0;
                assert_eq!(allocated, recovered.members.contains(member), "cut={cut} mode={mode}: member {member}");
            }
        }
    }
    eprintln!("PASS compressed cleanup unlink={unlink}: {} distinct recovered write-prefix images", checked.len());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "requires SLATE_COMPRESSED_ORPHAN_SOURCE exported by the lifecycle family test"]
fn split_compression_unit_retirement_recovers_each_write_prefix() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_COMPRESSED_ORPHAN_SOURCE").unwrap());
    check_write_prefixes(source, false);
}

#[test]
#[ignore = "requires SLATE_COMPRESSED_UNLINK_SOURCE with a fragmented preallocated list"]
fn fragmented_list_transfer_recovers_each_write_prefix() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_COMPRESSED_UNLINK_SOURCE").unwrap());
    check_write_prefixes(source, true);
}
