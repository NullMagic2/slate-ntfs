//! Module: file_recovery_tests
//! Purpose: Verify explicit file loss, cluster retirement and durable publication.
//! Created: 2026-10-02
//! Architecture: Calls the archive recovery backend on private image copies;
//!     source bytes and logical stream readback establish preservation separately
//!     from the backend's metadata audit and publication checkpoints.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn append_test_entry(output: &mut File, offset: u64, size: u64, status: u64, payload: &[u8]) {
    let mut entry = Vec::new();
    for word in [offset, size, status] {
        entry.extend_from_slice(&word.to_le_bytes());
    }
    entry.extend_from_slice(&repair_checksum(repair_checksum(0, &entry), payload).to_le_bytes());
    output.write_all(&entry).unwrap();
    output.write_all(payload).unwrap();
}

// A recorded error replaces only the selected physical sector. Every other
// byte retains authenticated original payload, including its cluster siblings.
fn error_archive(source: &Path, archive: &Path, bytes: &[u8], failed: &[u64], omit: bool) {
    let identity = std::fs::metadata(source).unwrap();
    let mut output = OpenOptions::new().write(true).create_new(true).open(archive).unwrap();
    std::fs::set_permissions(archive, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut header = b"SLTRSC01".to_vec();
    for word in [
        bytes.len() as u64,
        identity.dev(),
        identity.ino(),
        identity.rdev(),
        identity.mtime() as u64,
        identity.mtime_nsec() as u64,
        512,
    ] {
        header.extend_from_slice(&word.to_le_bytes());
    }
    header.extend_from_slice(&repair_checksum(0, &header).to_le_bytes());
    output.write_all(&header).unwrap();
    let mut offset = 0_u64;
    while offset < bytes.len() as u64 {
        if failed.contains(&offset) {
            if !omit {
                append_test_entry(&mut output, offset, 512, 5, &[]);
            }
            offset += 512;
        } else {
            let next = failed.iter().copied().filter(|at| *at > offset).min().unwrap_or(bytes.len() as u64);
            let size = (next - offset).min(65536) as usize;
            append_test_entry(&mut output, offset, size as u64, 0, &bytes[offset as usize..offset as usize + size]);
            offset += size as u64;
        }
    }
    output.sync_all().unwrap();
}

fn stream_bytes(image: &Path, number: u64) -> Vec<u8> {
    let mut volume = checker::open_volume(image).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let mut payload = vec![0; data.data_size().unwrap() as usize];
    volume.read_attribute(data, 0, &mut payload).unwrap();
    payload
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_RECOVERY_IMAGE with checked nonresident ordinary DATA"]
fn ordinary_file_loss_free_space_and_publication_resume() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_RECOVERY_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "slate-file-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let before = checker::consistency::audit(&source, boot, Default::default()).unwrap();
    assert!(before.complete && before.errors == 0);
    let mut volume = checker::open_volume(&source).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let slots = mft.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap() / u64::from(boot.record_bytes);
    let bitmap = mft.stream(ATTR_BITMAP, &[]).unwrap();
    let mut cache = (u64::MAX, [0; 8192]);
    let selected = std::env::var("SLATE_NTFS_TEST_RECOVERY_RECORD").ok().map(|value| value.parse::<u64>().unwrap());
    let mut target = None;
    for number in 16..slots {
        if selected.is_some_and(|selected| selected != number) {
            continue;
        }
        if bitmap_byte(&mut volume, bitmap, number / 8, slots.div_ceil(8), &mut cache).unwrap() & (1 << (number % 8))
            == 0
        {
            continue;
        }
        let family = RepairFamily::load(&mut volume, &mft, number);
        let Ok(family) = family else {
            continue;
        };
        let record = MftRecord::from_decoded(&family.logical).unwrap();
        let Ok(data) = record.stream(ATTR_DATA, &[]) else {
            continue;
        };
        if !data.nonresident || data.flags().unwrap() != 0 || data.initialized_size().unwrap() < 1024 {
            continue;
        }
        let run = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
        if run.vcn == 0 && run.lcn.is_some() {
            target = Some((number, run.lcn.unwrap() * u64::from(boot.cluster_bytes)));
            break;
        }
    }
    let (number, failed) = target.expect("fixture needs initialized nonresident ordinary DATA");
    let bitmap_image = checked_family_image(&mut volume, &mft, 6).unwrap();
    let bitmap_record = MftRecord::from_decoded(&bitmap_image).unwrap();
    let allocation = bitmap_record.stream(ATTR_DATA, &[]).unwrap();
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let mut cache = (u64::MAX, [0; 8192]);
    let free = (32..clusters - 1)
        .find(|at| {
            bitmap_byte(&mut volume, allocation, at / 8, clusters.div_ceil(8), &mut cache).unwrap() & (1 << (at % 8))
                == 0
        })
        .unwrap()
        * u64::from(boot.cluster_bytes);
    drop(volume);
    let expected = stream_bytes(&source, number);
    let archive = directory.join("file-and-free.rescue");
    error_archive(&source, &archive, &original, &[failed, free], false);
    let archive_before = std::fs::read(&archive).unwrap();
    let map = directory.join("loss.tsv");
    let output = directory.join("recovered.img");
    let report = recover_archive_to(&archive, &map, &output, &mut |_| {}).unwrap();
    assert_eq!(report.recovered_bytes, original.len() as u64 - 1024);
    assert_eq!(report.unreadable_bytes, 1024);
    assert_eq!(report.lost_file_bytes, 512);
    let mut lost_expected = expected.clone();
    lost_expected[..512].fill(0);
    assert_eq!(stream_bytes(&output, number), lost_expected);
    let map_bytes = std::fs::read_to_string(&map).unwrap();
    assert!(map_bytes.contains("file-loss\t") && map_bytes.contains("free\t"));
    assert!(map_bytes.contains("lost_file_bytes=512"));
    assert!(checker::check_device(&output, Default::default(), None).unwrap().passed());
    assert_retired(&output, &[failed / u64::from(boot.cluster_bytes), free / u64::from(boot.cluster_bytes)]);
    let mut volume = checker::open_volume(&output).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    for run in ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0) {
        let run = run.unwrap();
        assert!(!run
            .lcn
            .is_some_and(|at| at <= failed / u64::from(boot.cluster_bytes)
                && failed / u64::from(boot.cluster_bytes) < at + run.len));
    }
    drop(volume);
    // Existing names can only be reused when the complete image and map agree.
    let published = std::fs::read(&output).unwrap();
    recover_archive_to(&archive, &map, &output, &mut |_| {}).unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), published);
    for step in ["map-private", "map-published", "image-published"] {
        let map = directory.join(format!("{step}.tsv"));
        let output = directory.join(format!("{step}.img"));
        unsafe {
            std::env::set_var("SLATE_NTFS_TEST_FILE_RECOVERY_STOP_AFTER", step);
        }
        let stopped = recover_archive_to(&archive, &map, &output, &mut |_| {});
        unsafe {
            std::env::remove_var("SLATE_NTFS_TEST_FILE_RECOVERY_STOP_AFTER");
        }
        assert!(stopped.unwrap_err().to_string().contains("injected file recovery"));
        assert_eq!(map.exists(), step != "map-private");
        assert_eq!(output.exists(), step == "image-published");
        recover_archive_to(&archive, &map, &output, &mut |_| {}).unwrap();
        assert_eq!(stream_bytes(&output, number), lost_expected);
        assert_eq!(std::fs::read(&output).unwrap(), published);
    }
    for (label, at, omit) in [("critical", 0, false), ("unattempted", free, true)] {
        let archive = directory.join(format!("{label}.rescue"));
        error_archive(&source, &archive, &original, &[at], omit);
        let map = directory.join(format!("{label}.tsv"));
        let output = directory.join(format!("{label}.img"));
        assert!(recover_archive_to(&archive, &map, &output, &mut |_| {}).is_err());
        assert!(!map.exists() && !output.exists());
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
    assert_eq!(std::fs::read(&archive).unwrap(), archive_before);
    if let Some(path) = std::env::var_os("SLATE_NTFS_TEST_RECOVERY_KEEP") {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(Path::new(&path).join("original-payload.bin"), &expected).unwrap();
        std::fs::write(Path::new(&path).join("expected-payload.bin"), &lost_expected).unwrap();
        std::fs::write(
            Path::new(&path).join("readback-manifest.txt"),
            format!("record={number} lost_logical_offset=0 lost_bytes=512 physical_offset={failed}\n"),
        )
        .unwrap();
        for (source, name) in [(&output, "recovered.img"), (&map, "loss.tsv"), (&archive, "capture.rescue")] {
            std::fs::copy(source, Path::new(&path).join(name)).unwrap();
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

fn assert_retired(image: &Path, targets: &[u64]) {
    let mut volume = checker::open_volume(image).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 8).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let bad = record.local_attribute(ATTR_DATA, b"$\0B\0a\0d\0").unwrap().unwrap();
    let runs =
        ntfs_rs::runlist::DataRuns::new(bad.data_runs().unwrap(), 0).collect::<ntfs_rs::Result<Vec<_>>>().unwrap();
    for target in targets {
        assert!(runs.iter().any(|run| run.lcn == Some(run.vcn) && run.vcn <= *target && *target < run.vcn + run.len));
    }
    let family = RepairFamily::load(&mut volume, &mft, 6).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let bitmap = record.stream(ATTR_DATA, &[]).unwrap();
    for target in targets {
        let mut byte = [0];
        volume.read_attribute(bitmap, *target / 8, &mut byte).unwrap();
        assert_ne!(byte[0] & (1 << (*target % 8)), 0);
    }
}

#[test]
fn saved_good_now_unreadable_keeps_payload_and_reports_failure_history() {
    struct Reader {
        bytes: std::io::Cursor<Vec<u8>>,
        fail: bool,
    }
    impl Read for Reader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let at = self.bytes.position();
            if self.fail && at < 1024 && at + output.len() as u64 > 512 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.bytes.read(output)
        }
    }
    impl Seek for Reader {
        fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(at)
        }
    }
    let saved = vec![0x5a; 1024];
    let mut reader = Reader { bytes: std::io::Cursor::new(saved.clone()), fail: true };
    let mut history = Vec::new();
    verify_rescue_payload(&mut reader, 0, &saved, 512, &mut |at, size| {
        history.push((at, size));
        Ok(())
    })
    .unwrap();
    assert_eq!(history, [(512, 512)]);
    assert_eq!(reader.bytes.get_ref(), &saved);
    reader.fail = false;
    history.clear();
    verify_rescue_payload(&mut reader, 0, &saved, 512, &mut |at, size| {
        history.push((at, size));
        Ok(())
    })
    .unwrap();
    assert!(history.is_empty());
    reader.bytes.get_mut()[0] ^= 1;
    assert!(verify_rescue_payload(&mut reader, 0, &saved, 512, &mut |_, _| Ok(()))
        .unwrap_err()
        .to_string()
        .contains("source changed"));
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_RECOVERY_IMAGE and ordinary record48 DATA"]
fn uninitialized_partial_loss_and_declared_bad_reservations() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_RECOVERY_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "slate-recovery-boundaries-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut volume = checker::open_volume(&source).unwrap();
    let boot = volume.boot;
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 48).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let stream = record.stream(ATTR_DATA, &[]).unwrap();
    assert!(stream.nonresident && stream.initialized_size().unwrap() > 1024);
    let run = ntfs_rs::runlist::DataRuns::new(stream.data_runs().unwrap(), 0).next().unwrap().unwrap();
    let failed = run.lcn.unwrap() * u64::from(boot.cluster_bytes);
    drop(volume);
    for initialized in [0_u64, 256] {
        let image = directory.join(format!("initialized-{initialized}.img"));
        std::fs::copy(&source, &image).unwrap();
        let mut volume = checker::open_volume(&image).unwrap();
        let zero = checker::consistency::mft_image(&mut volume).unwrap();
        let mft = MftRecord::from_decoded(&zero).unwrap();
        let record_size = u64::from(boot.record_bytes);
        let data = mft.stream(ATTR_DATA, &[]).unwrap();
        let offset = 48 * record_size;
        let mapped = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0)
            .map(|run| run.unwrap())
            .find(|run| {
                run.vcn <= offset / u64::from(boot.cluster_bytes)
                    && offset / u64::from(boot.cluster_bytes) < run.vcn + run.len
            })
            .unwrap();
        let physical = (mapped.lcn.unwrap() + offset / u64::from(boot.cluster_bytes) - mapped.vcn)
            * u64::from(boot.cluster_bytes)
            + offset % u64::from(boot.cluster_bytes);
        let mut raw = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(&mft, 48, &mut raw).unwrap();
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
        let at = record.stream(ATTR_DATA, &[]).unwrap().record_offset();
        ntfs_rs::record_edit::p64(&mut raw, at + 56, initialized).unwrap();
        protect_mft_record(&mut raw, boot.bytes_per_sector).unwrap();
        drop(volume);
        let mut output = OpenOptions::new().write(true).open(&image).unwrap();
        output.seek(SeekFrom::Start(physical)).unwrap();
        output.write_all(&raw).unwrap();
        output.sync_all().unwrap();
        drop(output);
        let bytes = std::fs::read(&image).unwrap();
        let archive = directory.join(format!("initialized-{initialized}.rescue"));
        error_archive(&image, &archive, &bytes, &[failed], false);
        let map = directory.join(format!("initialized-{initialized}.tsv"));
        let recovered = directory.join(format!("initialized-{initialized}-fixed.img"));
        let report = recover_archive_to(&archive, &map, &recovered, &mut |_| {}).unwrap();
        assert_eq!(report.lost_file_bytes, initialized);
        assert_eq!(report.unreadable_bytes, 512);
        assert!(stream_bytes(&recovered, 48).iter().all(|byte| *byte == 0));
        assert_retired(&recovered, &[failed / u64::from(boot.cluster_bytes)]);
        assert_eq!(std::fs::read(&image).unwrap(), bytes);
    }
    // Introduce one declaration using readable bytes, then lose that reserved
    // physical sector together with new initialized DATA in the next recovery.
    let declared_archive = directory.join("declared-good.rescue");
    error_archive(&source, &declared_archive, &original, &[], false);
    let mut archive = OpenOptions::new().append(true).open(&declared_archive).unwrap();
    append_test_entry(&mut archive, failed, 512, 5, &[]);
    archive.sync_all().unwrap();
    let declared = directory.join("declared.img");
    let map = directory.join("declared.tsv");
    recover_archive_to(&declared_archive, &map, &declared, &mut |_| {}).unwrap();
    assert_eq!(stream_bytes(&declared, 48), stream_bytes(&source, 48));
    assert_retired(&declared, &[failed / u64::from(boot.cluster_bytes)]);
    let mut volume = checker::open_volume(&declared).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 109).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let new_failed =
        ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap().lcn.unwrap()
            * u64::from(boot.cluster_bytes);
    drop(volume);
    let bytes = std::fs::read(&declared).unwrap();
    let archive = directory.join("declared-and-file.rescue");
    error_archive(&declared, &archive, &bytes, &[failed, new_failed], false);
    let map = directory.join("declared-and-file.tsv");
    let output = directory.join("declared-and-file.img");
    let report = recover_archive_to(&archive, &map, &output, &mut |_| {}).unwrap();
    assert_eq!(report.lost_file_bytes, 512);
    assert_eq!(report.unreadable_bytes, 1024);
    assert!(std::fs::read_to_string(map).unwrap().contains("declared-bad\t"));
    let mut expected = stream_bytes(&declared, 109);
    expected[..512].fill(0);
    assert_eq!(stream_bytes(&output, 109), expected);
    assert_eq!(stream_bytes(&output, 48), stream_bytes(&source, 48));
    assert_retired(&output, &[failed / u64::from(boot.cluster_bytes), new_failed / u64::from(boot.cluster_bytes)]);
    assert_eq!(std::fs::read(&declared).unwrap(), bytes);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}
