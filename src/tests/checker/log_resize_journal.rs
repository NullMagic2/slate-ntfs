//! Module: log_resize_journal_tests
//! Purpose: Verify durable log resize ordering, recovery and journal refusals.
//! Created: 2026-10-01
//! Architecture: Exercises the private journal engine on disposable descriptors;
//!     the public API independently requires an exclusive Linux block-device claim.

use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixtures {
    directory: std::path::PathBuf,
    base: std::path::PathBuf,
}

impl Fixtures {
    fn new() -> Self {
        let base = std::path::PathBuf::from(
            std::env::var_os("SLATE_NTFS_TEST_BASE_IMAGE").expect("supply an inactive disposable NTFS image"),
        );
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!("slate-log-journal-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(checker::check_device(&base, Default::default(), None).unwrap().passed());
        Self { directory, base }
    }

    fn copy(&self, source: &Path, name: &str) -> std::path::PathBuf {
        let target = self.directory.join(name);
        std::fs::copy(source, &target).unwrap();
        target
    }

    fn apply(&self, image: &Path, journal: &Path, bytes: u64, resume: bool, stop: Option<u64>) -> io::Result<()> {
        let device = OpenOptions::new().read(true).write(true).open(image)?;
        apply_in_place_journal(device, journal, resume, None, InPlaceOperation::ResizeLog(bytes), stop, &mut |_| {})
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        // This directory contains only fixtures created by this test invocation.
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn digest(path: &Path) -> String {
    // Independent SHA-256 checks avoid duplicating the journal checksum logic.
    let result = std::process::Command::new("sha256sum").arg(path).output().unwrap();
    assert!(result.status.success());
    String::from_utf8(result.stdout).unwrap().split_whitespace().next().unwrap().to_owned()
}

fn checked_resize(image: &Path, bytes: u64) {
    let report = checker::check_device(image, Default::default(), None).unwrap();
    assert!(report.passed(), "{report:?}");
    assert_eq!(
        checker::inspect_logfile_size(checker::Image::open(image).unwrap(), checker::probe(image).unwrap().boot)
            .unwrap()
            .data_bytes,
        bytes
    );
}

fn set_maintenance_flag(image: &Path) {
    let mut volume = checker::open_volume(image).unwrap();
    let boot = volume.boot;
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let mut raw = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 3, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let attr = record.stream(ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION, &[]).unwrap();
    let at = attr.record_offset() + attr.resident_value_offset().unwrap() + 10;
    let mut offsets = Vec::new();
    plan_nonresident_overwrite(
        mft.stream(ATTR_DATA, &[]).unwrap(),
        boot,
        3 * u64::from(boot.record_bytes) + at as u64,
        2,
        |span| {
            offsets.push(span.physical_offset);
            Ok(())
        },
    )
    .unwrap();
    offsets.push(boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + 3 * u64::from(boot.record_bytes) + at as u64);
    let mut file = OpenOptions::new().write(true).open(image).unwrap();
    for offset in offsets {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&2_u16.to_le_bytes()).unwrap();
    }
    file.sync_all().unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_BASE_IMAGE with an inactive disposable NTFS log"]
fn resize_journal_matrix() {
    let fixtures = Fixtures::new();
    let original = digest(&fixtures.base);
    let target = 4 * 1024 * 1024;
    let expected = fixtures.directory.join("expected.img");
    resize_log_to(&fixtures.base, &expected, target, None, &mut |_| {}).unwrap();
    let expected_digest = digest(&expected);
    let patches = log_resize::plan_resize(&fixtures.base, target, &mut |_| {}).unwrap();
    let boundaries = patches.len() as u64 + 8;

    // Every journal, dirty-guard, redo, clean-finalizer and publication boundary
    // must resume to the exact independently validated copy-resize result.
    for boundary in 1..=boundaries {
        let image = fixtures.copy(&fixtures.base, &format!("boundary-{boundary}.img"));
        let journal = fixtures.directory.join(format!("boundary-{boundary}.journal"));
        let error = fixtures.apply(&image, &journal, target, false, Some(boundary)).unwrap_err();
        assert!(error.to_string().contains("injected"), "boundary {boundary}: {error}");
        if boundary == 1 {
            assert_eq!(digest(&image), original);
        } else if boundary < patches.len() as u64 + 5 {
            assert_ne!(checker::probe(&image).unwrap().info.flags & 1, 0);
        }
        if journal.exists() {
            fixtures.apply(&image, &journal, target, true, None).unwrap();
        }
        assert!(journal.with_extension("journal.completed").exists());
        assert_eq!(digest(&image), expected_digest, "boundary {boundary}");
        checked_resize(&image, target);
        std::fs::remove_file(&image).unwrap();
        std::fs::remove_file(journal.with_extension("journal.completed")).unwrap();
        if boundary % 20 == 0 {
            eprintln!("Completed log resize journal boundary {boundary}/{boundaries}.");
        }
    }

    let image = fixtures.copy(&expected, "shrink.img");
    let journal = fixtures.directory.join("shrink.journal");
    fixtures.apply(&image, &journal, 2 * 1024 * 1024, false, None).unwrap();
    checked_resize(&image, 2 * 1024 * 1024);

    let image = fixtures.copy(&fixtures.base, "same.img");
    let journal = fixtures.directory.join("same.journal");
    fixtures.apply(&image, &journal, 2 * 1024 * 1024, false, None).unwrap();
    assert_eq!(digest(&image), original);
    assert!(!journal.exists());

    // Clearing the maintenance flag changes a finalizer's original preimage.
    // Cover both clean-word transitions and retries after final publication.
    for boundary in [1, 2, patches.len() as u64 + 4, patches.len() as u64 + 5, boundaries - 1] {
        let image = fixtures.copy(&fixtures.base, &format!("maintenance-{boundary}.img"));
        set_maintenance_flag(&image);
        let journal = fixtures.directory.join(format!("maintenance-{boundary}.journal"));
        fixtures.apply(&image, &journal, target, false, Some(boundary)).unwrap_err();
        fixtures.apply(&image, &journal, target, true, None).unwrap();
        checked_resize(&image, target);
        assert_eq!(checker::probe(&image).unwrap().info.flags, 0);
    }

    let image = fixtures.copy(&fixtures.base, "refusals.img");
    let journal = fixtures.directory.join("refusals.journal");
    fixtures.apply(&image, &journal, target, false, Some(1)).unwrap_err();
    let before = digest(&image);
    assert!(fixtures
        .apply(&image, &journal, 3 * 1024 * 1024, true, None)
        .unwrap_err()
        .to_string()
        .contains("size mismatch"));
    let device = OpenOptions::new().read(true).write(true).open(&image).unwrap();
    assert!(apply_in_place_journal(device, &journal, true, None, InPlaceOperation::Repair, None, &mut |_| {})
        .unwrap_err()
        .to_string()
        .contains("identity/count mismatch"));
    assert_eq!(digest(&image), before);
    let saved = std::fs::read(&journal).unwrap();
    let mut corrupt = saved.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&journal, &corrupt).unwrap();
    assert!(fixtures
        .apply(&image, &journal, target, true, None)
        .unwrap_err()
        .to_string()
        .contains("checksum mismatch"));
    assert_eq!(digest(&image), before);
    std::fs::write(&journal, &saved).unwrap();

    // A torn data write may contain bytes from either logged image; foreign
    // bytes must stop before dirty guards or any other target write occurs.
    let mut reader = &saved[48..];
    read_repair_patch(&mut reader, 64 * 1024 * 1024).unwrap();
    read_repair_patch(&mut reader, 64 * 1024 * 1024).unwrap();
    let patch = read_repair_patch(&mut reader, 64 * 1024 * 1024).unwrap();
    let mut file = OpenOptions::new().write(true).open(&image).unwrap();
    let foreign = (0..=255).find(|byte| *byte != patch.before[0] && *byte != patch.after[0]).unwrap();
    file.seek(SeekFrom::Start(patch.physical)).unwrap();
    file.write_all(&[foreign]).unwrap();
    file.sync_all().unwrap();
    let conflict = digest(&image);
    assert!(fixtures
        .apply(&image, &journal, target, true, None)
        .unwrap_err()
        .to_string()
        .contains("preimage conflict"));
    assert_eq!(digest(&image), conflict);
    file.seek(SeekFrom::Start(patch.physical)).unwrap();
    file.write_all(&patch.before).unwrap();
    for index in (0..patch.after.len()).step_by(2) {
        file.seek(SeekFrom::Start(patch.physical + index as u64)).unwrap();
        file.write_all(&patch.after[index..index + 1]).unwrap();
    }
    file.sync_all().unwrap();
    fixtures.apply(&image, &journal, target, true, None).unwrap();
    assert_eq!(digest(&image), expected_digest);

    let image = fixtures.copy(&fixtures.base, "public-refusal.img");
    let journal = fixtures.directory.join("public-refusal.journal");
    assert!(resize_log_in_place(&image, &journal, target, false, &mut |_| {})
        .unwrap_err()
        .to_string()
        .contains("unmounted block/loop"));
    assert_eq!(digest(&image), original);
    assert!(!journal.exists());
    assert_eq!(digest(&fixtures.base), original);
    eprintln!("Log resize journal: {boundaries} interruption boundaries, growth, shrink, no-op, maintenance flags, journal identity/size/checksum, foreign preimages, torn redo and public image refusal passed.");
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_BASE_IMAGE with an inactive disposable NTFS log"]
fn structural_journal_compatibility() {
    let fixtures = Fixtures::new();
    let damaged = fixtures.copy(&fixtures.base, "damaged.img");
    let mut volume = checker::open_volume(&damaged).unwrap();
    let boot = volume.boot;
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 2).unwrap();
    let log = MftRecord::from_decoded(&family.logical).unwrap();
    let run = ntfs_rs::runlist::DataRuns::new(log.stream(ATTR_DATA, &[]).unwrap().data_runs().unwrap(), 0)
        .next()
        .unwrap()
        .unwrap();
    let cluster = run.lcn.unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 6).unwrap();
    let bitmap = MftRecord::from_decoded(&family.logical).unwrap();
    let data = bitmap.stream(ATTR_DATA, &[]).unwrap();
    let mut value = [0];
    volume.read_attribute(data, cluster / 8, &mut value).unwrap();
    let mut offset = 0;
    plan_nonresident_overwrite(data, boot, cluster / 8, 1, |span| {
        offset = span.physical_offset;
        Ok(())
    })
    .unwrap();
    let mut file = OpenOptions::new().write(true).open(&damaged).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&[value[0] & !(1 << (cluster % 8))]).unwrap();
    file.sync_all().unwrap();
    assert!(!checker::check_device(&damaged, Default::default(), None).unwrap().passed());
    let count = structural_repair_plan(&damaged, &mut |_| {}, PlanInputs::default()).unwrap().len() as u64;
    assert_ne!(count, 0);
    for boundary in 1..=count + 8 {
        let image = fixtures.copy(&damaged, &format!("repair-{boundary}.img"));
        let journal = fixtures.directory.join(format!("repair-{boundary}.journal"));
        let open = || OpenOptions::new().read(true).write(true).open(&image).unwrap();
        let error = apply_in_place_journal(
            open(),
            &journal,
            false,
            None,
            InPlaceOperation::Repair,
            Some(boundary),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected"), "{error}");
        if journal.exists() {
            assert_eq!(&std::fs::read(&journal).unwrap()[..8], b"SLTRPR01");
            apply_in_place_journal(open(), &journal, true, None, InPlaceOperation::Repair, None, &mut |_| {}).unwrap();
        }
        assert!(checker::check_device(&image, Default::default(), None).unwrap().passed());
        assert!(structural_repair_plan(&image, &mut |_| {}, PlanInputs::default()).unwrap().is_empty());
    }
    eprintln!("Existing structural journal format and {} interruption boundaries passed.", count + 8);
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_BASE_IMAGE with an inactive disposable NTFS log"]
fn failed_final_audit_retains_dirty_state() {
    let fixtures = Fixtures::new();
    let image = fixtures.copy(&fixtures.base, "failed-audit.img");
    let journal = fixtures.directory.join("failed-audit.journal");
    let target = 4 * 1024 * 1024;
    let plan = log_resize::plan_resize(&image, target, &mut |_| {}).unwrap();
    let boot = checker::probe(&image).unwrap().boot;
    // Record 63 is unused in this bounded fixture. Its flags are outside the
    // resize plan, so the final audit must catch damage beyond logged ranges.
    let offset = boot.mft_lcn * u64::from(boot.cluster_bytes) + 63 * u64::from(boot.record_bytes) + 22;
    assert!(plan.iter().all(|patch| {
        let patch = patch.unwrap();
        offset + 2 <= patch.physical || offset >= patch.physical + patch.after.len() as u64
    }));
    fixtures.apply(&image, &journal, target, false, Some(plan.len() as u64 + 3)).unwrap_err();
    let mut file = OpenOptions::new().read(true).write(true).open(&image).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut original = [0; 2];
    file.read_exact(&mut original).unwrap();
    assert_eq!(u16::from_le_bytes(original) & 1, 0);
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&(u16::from_le_bytes(original) | 1).to_le_bytes()).unwrap();
    file.sync_all().unwrap();
    assert!(fixtures.apply(&image, &journal, target, true, None).is_err());
    assert_ne!(checker::probe(&image).unwrap().info.flags & 1, 0);
    assert!(journal.exists());
    assert!(!journal.with_extension("journal.completed").exists());
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&original).unwrap();
    file.sync_all().unwrap();
    fixtures.apply(&image, &journal, target, true, None).unwrap();
    checked_resize(&image, target);
    eprintln!("Failed final audit retained dirty flags and the journal; corrected fixture resumed successfully.");
}
