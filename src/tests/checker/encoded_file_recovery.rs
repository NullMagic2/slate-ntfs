//! Module: recovery_io::encoded_file_recovery_tests
//! Purpose: Verify physical encoded loss and decoded compression-unit accounting.
//! Created: 2026-11-25
//! Architecture: A Windows-compressed private image exercises real recovery;
//! independent mounted or external readers verify the retained output payload.

use super::file_recovery_tests::error_archive;
use super::*;
use crate::linux::PRIVATE_DIRECTORY_MODE;
use ntfs_rs::mft::attribute_layout as af;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[test]
#[ignore = "requires SLATE_NTFS_TEST_COMPRESSED_IMAGE and SLATE_NTFS_TEST_RECOVERY_RECORD"]
fn compressed_recovery_counts_units_once_and_preserves_healthy_units() {
    const SECTOR: u64 = NTFS_SECTOR_BYTES as u64;
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_COMPRESSED_IMAGE").unwrap());
    let number = std::env::var("SLATE_NTFS_TEST_RECOVERY_RECORD").unwrap().parse::<u64>().unwrap();
    let original = std::fs::read(&source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-encoded-recovery-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
    let mut volume = checker::open_volume(&source).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    assert_eq!(data.flags().unwrap() & af::COMPRESSED, af::COMPRESSED);
    let unit_bytes = af::COMPRESSION_UNIT_CLUSTERS * u64::from(boot.cluster_bytes);
    let runs =
        ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).collect::<ntfs_rs::Result<Vec<_>>>().unwrap();
    let first = runs.iter().find(|run| run.vcn == 0).unwrap().lcn.unwrap() * u64::from(boot.cluster_bytes);
    let later = runs.iter().find(|run| run.vcn == af::COMPRESSION_UNIT_CLUSTERS * 2).unwrap().lcn.unwrap()
        * u64::from(boot.cluster_bytes);
    drop(volume);
    let mut released = RunSpool::new().unwrap();
    for run in runs.iter().rev() {
        if let Some(lcn) = run.lcn {
            released.push(ntfs_rs::runlist::Extent { vcn: lcn, lcn: None, len: run.len }).unwrap();
        }
    }
    let mut protected = RepairPlan::new(original.len() as u64).unwrap();
    reclaim_unowned_ranges(&source, boot, &mut protected, &released).unwrap();
    assert!(protected.is_empty(), "nonmonotonic ranges must preserve every live owner");
    for (label, failed, units) in [
        ("one", vec![first], 1_u64),
        ("same-unit", vec![first, first + SECTOR], 1),
        ("two-units", vec![first, later], 2),
    ] {
        let archive = directory.join(format!("{label}.rescue"));
        error_archive(&source, &archive, &original, &failed, false);
        let map = directory.join(format!("{label}.tsv"));
        let output = directory.join(format!("{label}.img"));
        let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, RepairOptions::default()).unwrap();
        assert_eq!(report.encoded_storage_loss_bytes, failed.len() as u64 * SECTOR);
        assert_eq!(report.affected_compressed_bytes, units * unit_bytes);
        assert_eq!(report.lost_file_bytes, 0);
        assert!(report.has_data_loss());
        assert!(checker::consistency::audit(&output, boot, Default::default()).unwrap().passed());
        let text = std::fs::read_to_string(&map).unwrap();
        assert_eq!(text.lines().filter(|line| line.starts_with("compressed-unit-zeroed")).count() as u64, units);
        if let Some(keep) = std::env::var_os("SLATE_NTFS_TEST_RECOVERY_KEEP") {
            let keep = Path::new(&keep);
            std::fs::create_dir_all(keep).unwrap();
            for path in [&archive, &map, &output] {
                std::fs::copy(path, keep.join(path.file_name().unwrap())).unwrap();
            }
        }
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_MIXED_IMAGE with plain, compressed and empty filler files"]
fn exhausted_owner_retries_after_compressed_unit_releases_checked_space() {
    use ntfs_rs::{record_edit as edit, runlist::Extent};
    const PLAIN: u64 = 64;
    const COMPRESSED: u64 = 65;
    const FILLER: u64 = 66;
    const SECTOR: u64 = NTFS_SECTOR_BYTES as u64;
    let input = PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_MIXED_IMAGE").unwrap());
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-full-recovery-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
    let source = directory.join("full.img");
    std::fs::copy(&input, &source).unwrap();
    let mut volume = checker::open_volume(&source).unwrap();
    let boot = volume.boot;
    let cluster = u64::from(boot.cluster_bytes);
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let bitmap_image = checked_family_image(&mut volume, &mft, ntfs_rs::mft::system_record::BITMAP).unwrap();
    let bitmap = MftRecord::from_decoded(&bitmap_image).unwrap();
    let data = bitmap.stream(ATTR_DATA, &[]).unwrap();
    let mut bits = vec![0; data.data_size().unwrap() as usize];
    volume.read_attribute(data, 0, &mut bits).unwrap();
    let mut runs: Vec<Extent> = Vec::new();
    let mut count = 0;
    for lcn in 0..boot.total_sectors / u64::from(boot.sectors_per_cluster) {
        let byte = &mut bits[(lcn / u64::from(u8::BITS)) as usize];
        let mask = 1 << (lcn % u64::from(u8::BITS));
        if *byte & mask != 0 {
            continue;
        }
        *byte |= mask;
        if let Some(previous) = runs.last_mut().filter(|run| run.lcn.unwrap() + run.len == lcn) {
            previous.len += 1;
        } else {
            runs.push(Extent { vcn: count, lcn: Some(lcn), len: 1 });
        }
        count += 1;
    }
    let mut plan = RepairPlan::new(std::fs::metadata(&source).unwrap().len()).unwrap();
    stage_overwrite(&mut volume, data, 0, &bits, &mut plan).unwrap();
    let filler = RepairFamily::load(&mut volume, &mft, FILLER).unwrap();
    let mut attribute = vec![0; boot.record_bytes as usize];
    let length = edit::build_nonresident(
        ATTR_DATA,
        &[],
        &runs,
        count * cluster,
        count * cluster,
        count * cluster,
        &mut attribute,
    )
    .unwrap();
    attribute.truncate(length);
    let mut space = RepairSpace::new(&mut volume, &mft).unwrap();
    filler.store(&mut volume, &mft, vec![StreamChange::replace(attribute).unwrap()], &mut space, &mut plan).unwrap();
    drop(volume);
    metadata::file_repairs(&source, boot, &mut plan).unwrap();
    directory_repairs(&source, boot, &mut plan).unwrap();
    let file = OpenOptions::new().read(true).write(true).open(&source).unwrap();
    for patch in plan.iter() {
        patch.unwrap().apply_to(&file, "full fixture changed").unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    assert!(checker::consistency::audit(&source, boot, Default::default()).unwrap().passed());
    let original = std::fs::read(&source).unwrap();
    let mut volume = checker::open_volume(&source).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let mut failed = Vec::new();
    let mut plain_id = 0;
    for number in [PLAIN, COMPRESSED] {
        let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
        let record = MftRecord::from_decoded(&family.logical).unwrap();
        let data = record.stream(ATTR_DATA, &[]).unwrap();
        if number == PLAIN {
            plain_id = data.id;
        }
        let first = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
        failed.push(first.lcn.unwrap() * cluster);
    }
    drop(volume);
    let mut plan = RepairPlan::new(original.len() as u64).unwrap();
    let unresolved = checker::consistency::scratch_file().unwrap();
    let first = failed[0] / cluster;
    assert_eq!(
        relocation::relocate(&source, boot, &mut plan, PLAIN, plain_id, Some(&unresolved), Some((first, first + 1)))
            .unwrap_err()
            .kind(),
        io::ErrorKind::StorageFull
    );
    assert!(plan.is_empty());
    let refused_archive = directory.join("exhausted.rescue");
    error_archive(&source, &refused_archive, &original, &failed[..1], false);
    let refused_output = directory.join("exhausted.img");
    let refused_map = directory.join("exhausted.tsv");
    let error =
        recover_archive_to(&refused_archive, &refused_map, &refused_output, &mut |_| {}, RepairOptions::default())
            .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::StorageFull);
    assert!(error.to_string().contains("all owners were attempted"));
    assert!(!refused_output.exists() && !refused_map.exists());
    assert!(refused_archive.exists());
    let archive = directory.join("full.rescue");
    error_archive(&source, &archive, &original, &failed, false);
    let map = directory.join("full.tsv");
    let output = directory.join("recovered.img");
    let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, RepairOptions::default()).unwrap();
    assert_eq!(report.lost_file_bytes, SECTOR);
    assert_eq!(report.encoded_storage_loss_bytes, SECTOR);
    assert_eq!(report.affected_compressed_bytes, af::COMPRESSION_UNIT_CLUSTERS * cluster);
    assert!(checker::consistency::audit(&output, boot, Default::default()).unwrap().passed());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    if let Some(keep) = std::env::var_os("SLATE_NTFS_TEST_RECOVERY_KEEP") {
        let keep = Path::new(&keep);
        std::fs::create_dir_all(keep).unwrap();
        for path in [&source, &map, &output] {
            std::fs::copy(path, keep.join(path.file_name().unwrap())).unwrap();
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_RECOVERY_IMAGE and SLATE_NTFS_TEST_RECOVERY_RECORD"]
fn opaque_encrypted_storage_preserves_readable_bytes_and_reports_no_plaintext_claim() {
    const SECTOR: u64 = NTFS_SECTOR_BYTES as u64;
    let input = PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_RECOVERY_IMAGE").unwrap());
    let number = std::env::var("SLATE_NTFS_TEST_RECOVERY_RECORD").unwrap().parse::<u64>().unwrap();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-ciphertext-recovery-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
    let source = directory.join("opaque.img");
    std::fs::copy(&input, &source).unwrap();
    let mut volume = checker::open_volume(&source).unwrap();
    let boot = volume.boot;
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let run = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
    let failed = run.lcn.unwrap() * u64::from(boot.cluster_bytes);
    let mut opaque = family.logical[data.record_offset()
        ..data.record_offset() + ntfs_rs::record_edit::attr_len(&family.logical, data.record_offset()).unwrap()]
        .to_vec();
    ntfs_rs::record_edit::p16(&mut opaque, af::FLAGS_OFFSET, af::ENCRYPTED).unwrap();
    let mut space = RepairSpace::new(&mut volume, &mft).unwrap();
    let mut plan = RepairPlan::new(std::fs::metadata(&source).unwrap().len()).unwrap();
    family.store(&mut volume, &mft, vec![StreamChange::replace(opaque).unwrap()], &mut space, &mut plan).unwrap();
    drop(volume);
    let file = OpenOptions::new().read(true).write(true).open(&source).unwrap();
    for patch in plan.iter() {
        patch.unwrap().apply_to(&file, "opaque fixture changed").unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    // This checks opaque physical transport, not encryption keys or EFS decryption.
    let original = std::fs::read(&source).unwrap();
    let archive = directory.join("opaque.rescue");
    error_archive(&source, &archive, &original, &[failed], false);
    let output = directory.join("recovered.img");
    let map = directory.join("opaque.tsv");
    let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, RepairOptions::default()).unwrap();
    assert_eq!(report.lost_file_bytes, 0);
    assert_eq!(report.encoded_storage_loss_bytes, SECTOR);
    assert_eq!(report.affected_compressed_bytes, 0);
    let text = std::fs::read_to_string(&map).unwrap();
    assert!(text.contains("ciphertext-loss") && text.contains("encoded_integrity=not_certified"));
    let mut volume = checker::open_volume(&output).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    assert_eq!(data.flags().unwrap(), af::ENCRYPTED);
    let mut retained = Vec::new();
    for run in ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0) {
        let run = run.unwrap();
        let mut bytes = vec![0; run.len as usize * boot.cluster_bytes as usize];
        volume.read_physical(run.lcn.unwrap() * u64::from(boot.cluster_bytes), &mut bytes).unwrap();
        retained.extend(bytes);
    }
    let mut expected = original[failed as usize..failed as usize + retained.len()].to_vec();
    expected[..SECTOR as usize].fill(0);
    assert_eq!(retained, expected);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}
