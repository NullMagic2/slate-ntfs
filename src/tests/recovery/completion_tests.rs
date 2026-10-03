// Module: slate_ntfs_tools::recovery_io::models::completion::tests
// Purpose: Exercise completion recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

#[test]
#[ignore = "requires SLATE_REPLAY_COMPLETION_SOURCE pointing to an owned dirty-orphan image"]
fn replay_journal_resumes_at_every_durable_boundary() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_REPLAY_COMPLETION_SOURCE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let serial = checker::probe(&source).unwrap().boot.serial_number;
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-replay-resume-{}-{nonce}", std::process::id(),));
    std::fs::create_dir(&directory).unwrap();
    let image = directory.join("volume.img");
    let journal = directory.join("preimages.journal");
    let completed = directory.join("preimages.journal.completed");
    let open_image = || OpenOptions::new().read(true).write(true).open(&image).unwrap();
    std::fs::write(&image, &original).unwrap();
    let error = apply_in_place_journal(
        open_image(),
        &journal,
        false,
        None,
        InPlaceOperation::Replay(CompletionMode::Replay(Some(serial ^ 1))),
        None,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("volume serial differs"));
    assert!(!journal.exists());
    assert_eq!(std::fs::read(&image).unwrap(), original);

    // Descriptor tests use private regular files. The public API separately
    // requires an exclusive block-device claim; no device is used here.
    let mut finished = false;
    for boundary in 1..128 {
        std::fs::write(&image, &original).unwrap();
        let result = apply_in_place_journal(
            open_image(),
            &journal,
            false,
            None,
            InPlaceOperation::Replay(CompletionMode::Replay(Some(serial))),
            Some(boundary),
            &mut |_| {},
        );
        if let Err(error) = result {
            assert!(error.to_string().contains("injected in-place repair interruption"));
            apply_in_place_journal(
                open_image(),
                &journal,
                true,
                None,
                InPlaceOperation::Replay(CompletionMode::Replay(Some(serial))),
                None,
                &mut |_| {},
            )
            .unwrap();
        } else {
            finished = true;
        }
        let report = checker::check_device(&image, Default::default(), None).unwrap();
        assert!(report.passed() && report.write_ready());
        assert_eq!(report.volume_flags & 1, 0);
        assert!(!journal.exists() && completed.exists());
        std::fs::remove_file(&completed).unwrap();
        if finished {
            println!("replay_resume_durable_boundaries={}", boundary - 1);
            break;
        }
    }
    assert!(finished, "the fixture's journal must fit the boundary matrix");
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

// The fixture has durable native history, a marked orphan and intact peer
// data. Tests alter only private read overlays, keeping its bytes unchanged.
#[test]
#[ignore = "requires SLATE_REPLAY_COMPLETION_SOURCE pointing to an owned dirty-orphan image"]
fn completion_requires_a_valid_orphan_marker_and_complete_audit() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_REPLAY_COMPLETION_SOURCE").unwrap());
    let before = std::fs::metadata(&source).unwrap();
    let changes = completion_plan(&source, CompletionMode::Replay(None)).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let flags = clean_flags(&source, &changes, boot).unwrap();
    let mut volume = Volume::new(PlannedImage::open(&source, &changes).unwrap(), boot).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let data = mft.stream(ATTR_DATA, &[]).unwrap();
    let slots = data.initialized_size().unwrap() / u64::from(boot.record_bytes);
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut marker = None;
    for number in 24..slots {
        volume.read_mft_record(&mft, number, &mut raw).unwrap();
        let record_start = raw.as_ptr() as usize;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
        if record.flags().unwrap() & 1 == 0 {
            continue;
        }
        let Some(attr) = ntfs_rs::ea::attribute(&record).unwrap() else {
            continue;
        };
        if attr.nonresident {
            continue;
        }
        let stream = attr.resident_value().unwrap();
        ntfs_rs::ea::visit(stream, |name, _, _| {
            if name == ntfs_rs::file_lifecycle::ORPHAN {
                let offset = name.as_ptr() as usize - record_start;
                assert!(offset % usize::from(boot.bytes_per_sector) < usize::from(boot.bytes_per_sector) - 2);
                plan_nonresident_overwrite(
                    data,
                    boot,
                    number * u64::from(boot.record_bytes) + offset as u64,
                    1,
                    |span| {
                        marker = Some(Patch::new(span.physical_offset, vec![b'$'], vec![b'?']));
                        Ok(())
                    },
                )?;
            }
            Ok(())
        })
        .unwrap();
    }
    let marker = marker.expect("fixture must contain one resident Slate marker after replay");
    let mut invalid = flags.clone();
    invalid.push(marker);
    let error = candidate(&source, &changes, &invalid, boot).unwrap_err();
    assert!(error.to_string().contains("failed complete audit"));
    candidate(&source, &changes, &flags, boot).unwrap();
    let after = std::fs::metadata(&source).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
}
