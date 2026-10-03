//! Module: index_repair_journal_tests
//! Purpose: Verify queued policies and MFT families survive interrupted offline repair.
//! Created: 2026-10-01
//! Architecture: Runs the durable journal engine on private disposable files;
//!     the public entry point separately requires an exclusive device claim.

use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore = "requires SLATE_NTFS_TEST_WINDOWS_CLEAN_IMAGE, a retained clean Windows volume"]
fn persistent_volume_setting_keeps_assessment_and_write_admission_separate() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_WINDOWS_CLEAN_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-setting-check-{}-{nonce}", std::process::id(),));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let image = directory.join("setting.img");
    std::fs::copy(&source, &image).unwrap();
    let mut volume = checker::open_volume(&image).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 3).unwrap();
    let mut edits = RepairPlan::new(original.len() as u64).unwrap();
    family
        .patch_resident_values(
            &mut volume,
            &mft,
            ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION,
            &[],
            &mut |value| {
                value[10..12].copy_from_slice(&ntfs_rs::volume_info::VOLUME_NO_SHORT_NAMES.to_le_bytes());
                Ok(())
            },
            &mut edits,
        )
        .unwrap();
    drop(volume);
    let mut file = OpenOptions::new().write(true).open(&image).unwrap();
    for edit in edits.iter() {
        let edit = edit.unwrap();
        file.seek(SeekFrom::Start(edit.physical)).unwrap();
        file.write_all(&edit.after).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    let before = std::fs::read(&image).unwrap();
    let report = checker::check_device(&image, Default::default(), None).unwrap();
    assert!(report.passed());
    assert_eq!(report.volume_flags, 0x80);
    assert_eq!(report.log_state, "clean-shutdown");
    assert!(!report.write_ready());
    assert_eq!(std::fs::read(&image).unwrap(), before);
    let repaired = directory.join("repaired.img");
    repair_to(&image, &repaired, None, &mut |_| {}, Default::default()).unwrap();
    let report = checker::check_device(&repaired, Default::default(), None).unwrap();
    assert!(report.passed() && report.write_ready());
    assert_eq!(report.volume_flags, 0x80);
    assert_eq!(report.log_state, "empty-checkpoint");
    assert_eq!(std::fs::read(&image).unwrap(), before);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_INDEX_STALE_IMAGE, a disposable inactive NTFS image"]
fn selected_index_policy_is_bound_to_the_journal_and_every_resume() {
    use checker::consistency::{AuditOptions, IndexCachePasses, IndexCheck};
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_INDEX_STALE_IMAGE").unwrap());
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-index-journal-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let options = AuditOptions { index_check: IndexCheck::Quick, ..Default::default() };
    let boot = checker::probe(&source).unwrap().boot;
    assert!(checker::consistency::audit(&source, boot, options).unwrap().passed());
    assert!(!checker::consistency::audit(&source, boot, Default::default()).unwrap().passed());
    let damaged = directory.join("damaged.img");
    std::fs::copy(&source, &damaged).unwrap();
    let mut volume = checker::open_volume(&damaged).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let bitmap_image = checked_family_image(&mut volume, &mft, 6).unwrap();
    let record = MftRecord::from_decoded(&bitmap_image).unwrap();
    let allocation = record.stream(ATTR_DATA, &[]).unwrap();
    let offset = boot.mft_lcn / 8;
    let mut byte = [0];
    volume.read_attribute(allocation, offset, &mut byte).unwrap();
    let mut physical = None;
    plan_nonresident_overwrite(allocation, boot, offset, 1, |span| {
        physical = Some(span.physical_offset);
        Ok(())
    })
    .unwrap();
    drop(volume);
    let mut file = OpenOptions::new().write(true).open(&damaged).unwrap();
    file.seek(SeekFrom::Start(physical.unwrap())).unwrap();
    file.write_all(&[byte[0] & !(1 << (boot.mft_lcn % 8))]).unwrap();
    file.sync_all().unwrap();
    let repair_options = RepairOptions { index_audit: options, ..Default::default() };
    let plan =
        structural_repair_plan(&damaged, &mut |_| {}, PlanInputs { options: repair_options, ..Default::default() })
            .unwrap();
    assert!(!plan.is_empty());
    let expected = directory.join("expected.img");
    repair_to(&damaged, &expected, None, &mut |_| {}, repair_options).unwrap();
    let expected_bytes = std::fs::read(&expected).unwrap();
    let boundaries = plan.len() as u64 + 8;
    let original = std::fs::read(&damaged).unwrap();
    let queue = directory.join("scan.queue");
    let mut audit = checker::consistency::audit(&damaged, boot, options).unwrap();
    let worklist = audit.worklist_file().unwrap();
    worklist.seek(SeekFrom::Start(0)).unwrap();
    let mut rows = Vec::new();
    worklist.read_to_end(&mut rows).unwrap();
    let digest = |bytes: &[u8]| {
        bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3))
    };
    // Independently encode a quick-mode queue for this real damaged image.
    // A regular test file has device identity zero at the journal boundary.
    let mut header = b"SLTSPT04".to_vec();
    for word in [
        0,
        boot.serial_number,
        boot.total_sectors,
        audit.fingerprint,
        audit.errors,
        rows.len() as u64,
        digest(&rows),
        0x1_ffff,
    ] {
        header.extend_from_slice(&word.to_le_bytes());
    }
    header.extend_from_slice(&digest(&header).to_le_bytes());
    header.extend_from_slice(&rows);
    std::fs::write(&queue, header).unwrap();
    std::fs::set_permissions(&queue, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ticket = checker::read_spotfix_ticket(&queue).unwrap();
    assert_eq!(ticket.index_audit, options);
    checker::verify_spotfix_worklist(&queue, &mut audit, ticket).unwrap();
    let mismatched_journal = directory.join("mismatched.journal");
    let error = apply_in_place_journal(
        OpenOptions::new().read(true).write(true).open(&damaged).unwrap(),
        &mismatched_journal,
        false,
        Some((&queue, ticket)),
        InPlaceOperation::Repair,
        None,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("policy disagrees"));
    assert!(!mismatched_journal.exists());
    assert_eq!(std::fs::read(&damaged).unwrap(), original);
    for boundary in 1..=boundaries {
        let image = directory.join(format!("{boundary}.img"));
        let journal = directory.join(format!("{boundary}.journal"));
        std::fs::copy(&damaged, &image).unwrap();
        let open = || OpenOptions::new().read(true).write(true).open(&image).unwrap();
        let error = apply_in_place_journal(
            open(),
            &journal,
            false,
            Some((&queue, ticket)),
            InPlaceOperation::RepairIndexes(options),
            Some(boundary),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected"), "{boundary}: {error}");
        if boundary == 1 {
            assert_eq!(std::fs::read(&image).unwrap(), original);
        }
        if journal.exists() {
            let before = std::fs::read(&image).unwrap();
            let changed = AuditOptions { index_cache_passes: IndexCachePasses::Streaming, ..options };
            let error = apply_in_place_journal(
                open(),
                &journal,
                true,
                None,
                InPlaceOperation::RepairIndexes(changed),
                None,
                &mut |_| {},
            )
            .unwrap_err();
            assert!(error.to_string().contains("policy mismatch"));
            assert_eq!(std::fs::read(&image).unwrap(), before);
            let error =
                apply_in_place_journal(open(), &journal, true, None, InPlaceOperation::Repair, None, &mut |_| {})
                    .unwrap_err();
            assert!(error.to_string().contains("identity/count mismatch"));
            assert_eq!(std::fs::read(&image).unwrap(), before);
            apply_in_place_journal(
                open(),
                &journal,
                true,
                None,
                InPlaceOperation::RepairIndexes(options),
                None,
                &mut |_| {},
            )
            .unwrap();
        }
        assert!(checker::consistency::audit(&image, boot, options).unwrap().passed());
        assert!(!checker::consistency::audit(&image, boot, Default::default()).unwrap().passed());
        assert!(journal.with_extension("journal.completed").exists());
        assert_eq!(std::fs::read(&image).unwrap(), expected_bytes, "boundary {boundary}");
        eprintln!("Passed index repair journal boundary {boundary}/{boundaries}.");
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_ORPHAN_IMAGE, two objects sharing a missing parent"]
fn recovery_directory_times_survive_every_stored_journal_boundary() {
    use checker::consistency::{AuditOptions, IndexCheck};
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_ORPHAN_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-orphan-journal-{}-{nonce}", std::process::id(),));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let prepared = directory.join("prepared.img");
    let template = directory.join("stored.journal");
    std::fs::copy(&source, &prepared).unwrap();
    let options = AuditOptions { index_check: IndexCheck::Quick, ..Default::default() };
    let operation = InPlaceOperation::RepairIndexes(options);
    let open = |path: &Path| OpenOptions::new().read(true).write(true).open(path).unwrap();
    let error =
        apply_in_place_journal(open(&prepared), &template, false, None, operation, Some(1), &mut |_| {}).unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert_eq!(std::fs::read(&prepared).unwrap(), original);

    // All interrupted resumes use this same durable plan and creation time.
    // Independently applying its stored redo bytes supplies the exact oracle.
    let stored = std::fs::read(&template).unwrap();
    let count = u64_at(&stored, 32).unwrap();
    let mut reader = std::io::Cursor::new(&stored);
    reader.set_position(operation.header_bytes() as u64);
    let mut expected = original.clone();
    for _ in 0..count {
        let patch = read_repair_patch(&mut reader, original.len() as u64).unwrap();
        let start = patch.physical as usize;
        assert_eq!(expected[start..start + patch.before.len()], patch.before);
        expected[start..start + patch.after.len()].copy_from_slice(&patch.after);
    }
    let expected_path = directory.join("expected.img");
    std::fs::write(&expected_path, &expected).unwrap();
    let boot = checker::probe(&expected_path).unwrap().boot;
    assert!(checker::consistency::audit(&expected_path, boot, Default::default()).unwrap().passed());
    let mut volume = checker::open_volume(&expected_path).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let slots = mft.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap() / u64::from(boot.record_bytes);
    let mut old_volume = checker::open_volume(&source).unwrap();
    let old_zero = checker::consistency::mft_image(&mut old_volume).unwrap();
    let old_mft = MftRecord::from_decoded(&old_zero).unwrap();
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut old_raw = raw.clone();
    let mut times = Vec::new();
    for number in 16..slots {
        volume.read_mft_record(&mft, number, &mut raw).unwrap();
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
        if record.flags().unwrap() != 3 {
            continue;
        }
        old_volume.read_mft_record(&old_mft, number, &mut old_raw).unwrap();
        let old = MftRecord::parse(&mut old_raw, boot.bytes_per_sector).unwrap();
        if old.flags().unwrap() & 1 != 0 {
            continue;
        }
        let standard = record.local_attribute(0x10, &[]).unwrap().unwrap();
        let value = standard.resident_value().unwrap();
        for offset in [0, 8, 16, 24] {
            times.push(u64_at(value, offset).unwrap());
        }
    }
    assert_eq!(times.len(), 8, "one found folder and one grouped directory");
    assert!(times[0] > 0);
    assert!(times.iter().all(|time| *time == times[0]));
    drop(volume);
    drop(old_volume);

    let boundaries = count + 4;
    for boundary in 1..=boundaries {
        let image = directory.join(format!("{boundary}.img"));
        let journal = directory.join(format!("{boundary}.journal"));
        std::fs::copy(&source, &image).unwrap();
        std::fs::write(&journal, &stored).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = apply_in_place_journal(open(&image), &journal, true, None, operation, Some(boundary), &mut |_| {})
            .unwrap_err();
        assert!(error.to_string().contains("injected"), "{boundary}: {error}");
        if journal.exists() {
            assert_eq!(std::fs::read(&journal).unwrap(), stored);
            apply_in_place_journal(open(&image), &journal, true, None, operation, None, &mut |_| {}).unwrap();
        }
        assert!(journal.with_extension("journal.completed").exists());
        assert_eq!(std::fs::read(&image).unwrap(), expected, "boundary {boundary}");
        assert!(checker::consistency::audit(&image, boot, Default::default()).unwrap().passed());
        assert_eq!(std::fs::read(&source).unwrap(), original);
        eprintln!("Passed recovery-directory journal boundary {boundary}/{boundaries}.");
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_RESIDENT_MFT_IMAGE, a disposable fragmented resident-bitmap MFT"]
fn resident_mft_externalization_survives_every_journal_boundary() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_RESIDENT_MFT_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let boot = ntfs_rs::boot::BootSector::parse(&original[..512]).unwrap();
    let start = boot.mft_byte_offset().unwrap() as usize;
    let mut raw = original[start..start + boot.record_bytes as usize].to_vec();
    let zero = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    assert!(!zero.stream(ATTR_BITMAP, &[]).unwrap().nonresident);
    assert!(!zero.attributes().any(|item| {
        let item = item.unwrap();
        item.kind == ATTR_DATA && item.name_utf16le().unwrap().is_empty()
    }));
    mft_publication_journal_boundaries(&source);
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_MFT_BITMAP_IMAGE, a disposable damaged MFT bitmap"]
fn mft_bitmap_reconstruction_survives_every_journal_boundary() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_MFT_BITMAP_IMAGE").unwrap());
    mft_publication_journal_boundaries(&source);
}

#[test]
#[ignore = "requires SLATE_NTFS_TEST_WINDOWS_CLEAN_IMAGE, a retained clean Windows volume"]
fn dirty_only_volume_journal_preserves_settings_and_legacy_resume() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_NTFS_TEST_WINDOWS_CLEAN_IMAGE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-dirty-only-journal-{}-{nonce}", std::process::id(),));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let image = directory.join("dirty.img");
    repair_to(&source, &image, None, &mut |_| {}, Default::default()).unwrap();
    let boot = checker::probe(&image).unwrap().boot;
    let mut volume = checker::open_volume(&image).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, 3).unwrap();
    let mut edits = RepairPlan::new(std::fs::metadata(&image).unwrap().len()).unwrap();
    family
        .patch_resident_values(
            &mut volume,
            &mft,
            ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION,
            &[],
            &mut |value| {
                value[10..12].copy_from_slice(&0x81_u16.to_le_bytes());
                Ok(())
            },
            &mut edits,
        )
        .unwrap();
    drop(volume);
    let open = |path: &Path| OpenOptions::new().read(true).write(true).open(path).unwrap();
    let mut file = open(&image);
    for edit in edits.iter() {
        let edit = edit.unwrap();
        file.seek(SeekFrom::Start(edit.physical)).unwrap();
        file.write_all(&edit.after).unwrap();
    }
    file.sync_all().unwrap();
    drop(file);
    let dirty = std::fs::read(&image).unwrap();
    let report = checker::check_device(&image, Default::default(), None).unwrap();
    assert_eq!(report.log_state, "empty-checkpoint");
    assert_eq!(report.volume_flags, 0x81);
    assert!(structural_repair_plan(&image, &mut |_| {}, PlanInputs::default()).unwrap().is_empty());
    mft_publication_journal_boundaries(&image);

    // A zero-change plan must still record both real guard preimages and
    // mirror-first clean finalizers. Retained old journals restore original
    // flags; new normal repair must subsequently clear only the dirty bit.
    let journal = directory.join("legacy.journal");
    let error =
        apply_in_place_journal(open(&image), &journal, false, None, InPlaceOperation::Repair, Some(1), &mut |_| {})
            .unwrap_err();
    assert!(error.to_string().contains("injected"), "{error}");
    let mut stored = std::fs::read(&journal).unwrap();
    let count = u64_at(&stored, 32).unwrap();
    assert_eq!(count, 4);
    let mut reader = std::io::Cursor::new(&stored);
    reader.set_position(InPlaceOperation::Repair.header_bytes() as u64);
    let mut records = Vec::new();
    let mut offsets = Vec::new();
    for _ in 0..count {
        let patch = read_repair_patch(&mut reader, dirty.len() as u64).unwrap();
        offsets.push(reader.position() as usize - patch.after.len());
        records.push(patch);
    }
    assert_eq!(records[2].physical, records[1].physical);
    assert_eq!(records[3].physical, records[0].physical);
    for index in 0..2 {
        assert_eq!(records[index].before, 0x81_u16.to_le_bytes());
        assert_eq!(records[index].after, 0x81_u16.to_le_bytes());
        assert_eq!(records[index + 2].after, 0x80_u16.to_le_bytes());
    }
    drop(reader);
    for index in 2..4 {
        stored[offsets[index]..offsets[index] + 2].copy_from_slice(&0x81_u16.to_le_bytes());
    }
    let trailer = stored.len() - 8;
    let checksum = repair_checksum(0, &stored[..trailer]).to_le_bytes();
    stored[trailer..].copy_from_slice(&checksum);
    std::fs::write(&journal, stored).unwrap();
    apply_in_place_journal(open(&image), &journal, true, None, InPlaceOperation::Repair, None, &mut |_| {}).unwrap();
    assert_eq!(std::fs::read(&image).unwrap(), dirty);
    assert_eq!(checker::check_device(&image, Default::default(), None).unwrap().volume_flags, 0x81);
    let current = directory.join("current.journal");
    apply_in_place_journal(open(&image), &current, false, None, InPlaceOperation::Repair, None, &mut |_| {}).unwrap();
    let report = checker::check_device(&image, Default::default(), None).unwrap();
    assert_eq!(report.volume_flags, 0x80);
    assert_eq!(report.log_state, "empty-checkpoint");
    assert!(report.passed() && report.write_ready());
    assert!(checker::consistency::audit(&image, boot, Default::default()).unwrap().passed());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

// Share the independent preimage/redo oracle across physical MFT publication
// cases. Every variant also exercises backup boot selection and serial refusal.
fn mft_publication_journal_boundaries(source: &Path) {
    let original = std::fs::read(source).unwrap();
    let boot = ntfs_rs::boot::BootSector::parse(&original[..512]).unwrap();
    let pristine = original;
    for damage_boot in [false, true] {
        let mut original = pristine.clone();
        if damage_boot {
            original[510..512].fill(0);
        }
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let directory =
            std::env::temp_dir().join(format!("slate-resident-mft-journal-{}-{nonce}", std::process::id(),));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let prepared = directory.join("prepared.img");
        let template = directory.join("stored.journal");
        std::fs::write(&prepared, &original).unwrap();
        let open = |path: &Path| OpenOptions::new().read(true).write(true).open(path).unwrap();
        let operation = InPlaceOperation::Repair;
        let error = apply_in_place_journal(open(&prepared), &template, false, None, operation, Some(1), &mut |_| {})
            .unwrap_err();
        assert!(error.to_string().contains("injected"), "{error}");
        assert_eq!(std::fs::read(&prepared).unwrap(), original);

        // The stored preimages independently prove publication order, and applying
        // its redo bytes yields an exact oracle for every interrupted resume.
        let stored = std::fs::read(&template).unwrap();
        let mismatched = directory.join("mismatched-serial.img");
        let mismatch_journal = directory.join("mismatched-serial.journal");
        let mut different = original.clone();
        let serial = boot.serial_number.wrapping_add(1).to_le_bytes();
        different[72..80].copy_from_slice(&serial);
        let backup = (boot.total_sectors * u64::from(boot.bytes_per_sector)) as usize;
        different[backup + 72..backup + 80].copy_from_slice(&serial);
        std::fs::write(&mismatched, &different).unwrap();
        std::fs::write(&mismatch_journal, &stored).unwrap();
        std::fs::set_permissions(&mismatch_journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error =
            apply_in_place_journal(open(&mismatched), &mismatch_journal, true, None, operation, None, &mut |_| {})
                .unwrap_err();
        assert!(error.to_string().contains("serial mismatch"), "{error}");
        assert_eq!(std::fs::read(&mismatched).unwrap(), different);
        assert_eq!(std::fs::read(&mismatch_journal).unwrap(), stored);
        let count = u64_at(&stored, 32).unwrap();
        let mut reader = std::io::Cursor::new(&stored);
        reader.set_position(operation.header_bytes() as u64);
        let mut expected = original.clone();
        for _ in 0..count {
            let patch = read_repair_patch(&mut reader, original.len() as u64).unwrap();
            let start = patch.physical as usize;
            assert_eq!(expected[start..start + patch.before.len()], patch.before);
            expected[start..start + patch.after.len()].copy_from_slice(&patch.after);
        }
        let expected_path = directory.join("expected.img");
        std::fs::write(&expected_path, &expected).unwrap();
        assert!(checker::consistency::audit(&expected_path, boot, Default::default()).unwrap().passed());
        let mut volume = checker::open_volume(&expected_path).unwrap();
        let zero = checker::consistency::mft_image(&mut volume).unwrap();
        let mft = MftRecord::from_decoded(&zero).unwrap();
        let bitmap = mft.stream(ATTR_BITMAP, &[]).unwrap();
        assert!(bitmap.nonresident);
        let slots = mft.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap() / u64::from(boot.record_bytes);
        let minimum_bitmap = slots.div_ceil(64) * 8;
        assert!(bitmap.data_size().unwrap() >= minimum_bitmap);
        assert_eq!(bitmap.data_size().unwrap() % 8, 0);
        assert!(bitmap.initialized_size().unwrap() >= minimum_bitmap);
        drop(volume);

        let boundaries = count + 4;
        for boundary in 1..=boundaries {
            let image = directory.join(format!("{boundary}.img"));
            let journal = directory.join(format!("{boundary}.journal"));
            std::fs::write(&image, &original).unwrap();
            std::fs::write(&journal, &stored).unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error =
                apply_in_place_journal(open(&image), &journal, true, None, operation, Some(boundary), &mut |_| {})
                    .unwrap_err();
            assert!(error.to_string().contains("injected"), "{boundary}: {error}");
            if journal.exists() {
                assert_eq!(std::fs::read(&journal).unwrap(), stored);
                apply_in_place_journal(open(&image), &journal, true, None, operation, None, &mut |_| {}).unwrap();
            }
            assert!(journal.with_extension("journal.completed").exists());
            assert_eq!(std::fs::read(&image).unwrap(), expected, "boundary {boundary}");
            assert!(checker::consistency::audit(&image, boot, Default::default()).unwrap().passed());
            assert_eq!(std::fs::read(&source).unwrap(), pristine);
            eprintln!("Passed repair journal boundary {boundary}/{boundaries}; damaged primary boot: {damage_boot}.");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
