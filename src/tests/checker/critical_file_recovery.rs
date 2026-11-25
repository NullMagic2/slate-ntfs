//! Module: recovery_io::critical_file_recovery_tests
//! Purpose: Recover authenticated redundant metadata without inventing source bytes.
//! Created: 2026-11-25
//! Architecture: Private archives exercise the production classifier and copy
//! publisher; missing or conflicting authority must refuse publication.

use super::file_recovery_tests::error_archive;
use super::*;
use crate::linux::PRIVATE_DIRECTORY_MODE;
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore = "requires SLATE_NTFS_TEST_RECOVERY_IMAGE, a private clean NTFS fixture"]
fn redundant_metadata_copy_recovery_retains_capture_and_refuses_device_publication() {
    const CAPTURE_SECTOR: u64 = NTFS_SECTOR_BYTES as u64;
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_RECOVERY_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-critical-recovery-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
    let main = boot.mft_byte_offset().unwrap();
    let mirror = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes);
    let backup = boot.total_sectors * u64::from(boot.bytes_per_sector);
    let record = u64::from(boot.record_bytes);
    for (label, failed) in [
        ("boot", vec![0]),
        ("backup", vec![backup]),
        ("mft-head", vec![main]),
        ("mft-tail", vec![main + CAPTURE_SECTOR]),
        ("mirror", vec![mirror]),
        ("volume", vec![main + ntfs_rs::mft::system_record::VOLUME * record]),
    ] {
        let archive = directory.join(format!("{label}.rescue"));
        error_archive(&source, &archive, &original, &failed, false);
        let captured = std::fs::read(&archive).unwrap();
        let map = directory.join(format!("{label}.tsv"));
        let output = directory.join(format!("{label}.img"));
        let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, RepairOptions::default()).unwrap();
        assert_eq!(report.unreadable_bytes, CAPTURE_SECTOR);
        assert_eq!(report.recovered_bytes, original.len() as u64 - CAPTURE_SECTOR);
        assert_eq!(report.lost_file_bytes, 0);
        let text = std::fs::read_to_string(&map).unwrap();
        assert!(text.contains("metadata-redundant"));
        let audit = checker::consistency::audit(&output, boot, Default::default()).unwrap();
        assert!(audit.complete && audit.errors == 0);
        assert_eq!(std::fs::read(&archive).unwrap(), captured);
        if label == "boot" {
            let journal = directory.join("refused-device.journal");
            let device = OpenOptions::new().read(true).write(true).open(&source).unwrap();
            let error = recover_archive_on_claimed_source(
                device,
                &archive,
                &map,
                &journal,
                false,
                &mut |_| {},
                RepairOptions::default(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("replacement image"), "{error}");
            assert!(!journal.exists());
        }
        if let Some(keep) = std::env::var_os("SLATE_NTFS_TEST_RECOVERY_KEEP") {
            let keep = Path::new(&keep);
            std::fs::create_dir_all(keep).unwrap();
            for path in [&archive, &map, &output] {
                std::fs::copy(path, keep.join(path.file_name().unwrap())).unwrap();
            }
        }
    }
    for (label, failed, omit) in [
        ("both-boot", vec![0, backup], false),
        ("both-mft", vec![main, mirror], false),
        ("unmirrored", vec![main + ntfs_rs::mft::system_record::ROOT * record], false),
        ("unattempted", vec![main], true),
    ] {
        let archive = directory.join(format!("{label}.rescue"));
        error_archive(&source, &archive, &original, &failed, omit);
        let map = directory.join(format!("{label}.tsv"));
        let output = directory.join(format!("{label}.img"));
        assert!(recover_archive_to(&archive, &map, &output, &mut |_| {}, RepairOptions::default()).is_err());
        assert!(!output.exists());
    }
    const SURVIVING_BYTE_IN_SECTOR: u64 = 20;
    let mut contradictory = original.clone();
    contradictory[(main + CAPTURE_SECTOR + SURVIVING_BYTE_IN_SECTOR) as usize] ^= 1;
    let archive = directory.join("conflicting.rescue");
    error_archive(&source, &archive, &contradictory, &[main], false);
    let output = directory.join("conflicting.img");
    assert!(recover_archive_to(
        &archive,
        &directory.join("conflicting.tsv"),
        &output,
        &mut |_| {},
        RepairOptions::default()
    )
    .unwrap_err()
    .to_string()
    .contains("contradict"));
    assert!(!output.exists());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_RECOVERY_IMAGE with 4 KiB clusters and 1 KiB records"]
fn redundant_mft_recovery_covers_a_complete_four_kib_capture_sector() {
    const CAPTURE_SECTOR: u64 = 4096;
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_RECOVERY_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    assert_eq!(u64::from(boot.cluster_bytes), CAPTURE_SECTOR);
    assert_eq!(u64::from(boot.record_bytes) * ntfs_rs::mft::system_record::MIRRORED, CAPTURE_SECTOR);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-critical-four-kib-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE)).unwrap();
    let archive = directory.join("mft.rescue");
    super::file_recovery_tests::error_archive_with_sector(
        &source,
        &archive,
        &original,
        &[boot.mft_byte_offset().unwrap()],
        false,
        CAPTURE_SECTOR,
    );
    let output = directory.join("mft.img");
    let map = directory.join("mft.tsv");
    let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, RepairOptions::default()).unwrap();
    assert_eq!(report.unreadable_bytes, CAPTURE_SECTOR);
    assert_eq!(report.recovered_bytes, original.len() as u64 - CAPTURE_SECTOR);
    assert_eq!(report.lost_file_bytes, 0);
    assert!(checker::consistency::audit(&output, boot, Default::default()).unwrap().passed());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}
