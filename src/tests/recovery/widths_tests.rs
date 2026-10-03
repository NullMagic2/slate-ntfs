// Module: slate_ntfs_tools::recovery_io::models::widths::tests
// Purpose: Exercise widths recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

fn geometry() -> BootSector {
    BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: (u32::MAX as u64) * 8,
        mft_lcn: 4,
        mft_mirror_lcn: 20,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    }
}

#[test]
fn compact_lengths_preserve_signed_physical_deltas() {
    let bytes = [0x21, 128, 0x00, 0x01, 0x21, 224, 0x00, 0xff, 0];
    let (runs, corrected) = compact_runs(&bytes, geometry()).unwrap();
    assert_eq!(corrected, 2);
    assert_eq!(runs, vec![Extent { vcn: 0, len: 128, lcn: Some(256) }, Extent { vcn: 128, len: 224, lcn: Some(0) },]);
    for invalid in [
        vec![0x11, 0, 1, 0],
        vec![0x01, 128, 0],
        vec![0x11, 128, 255, 0],
        vec![0x11, 128, 1],
        vec![0x11, 128, 1, 0, 1],
        vec![0x11, 128, 1, 0x11, 128, 1, 0],
    ] {
        assert!(compact_runs(&invalid, geometry()).is_err());
    }
}

#[test]
#[ignore = "requires SLATE_WIDTH_RECORD containing an owned protected plain DATA record"]
fn pinned_record_preserves_every_extent_and_size() {
    let path = std::env::var_os("SLATE_WIDTH_RECORD").unwrap();
    let raw = std::fs::read(path).unwrap();
    let boot = geometry();
    let target = WidthRepairTarget {
        record: u64::from(u32_at(&raw, 44).unwrap()),
        raw_sha256: ntfs_rs::sha256::digest(&raw),
        expected_serial: None,
    };
    let mut old = raw.clone();
    MftRecord::parse(&mut old, 512).unwrap();
    let record = MftRecord::from_decoded(&old).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let (expected, defects) = compact_runs(data.data_runs().unwrap(), boot).unwrap();
    let (after, corrected) = canonical_record(&raw, boot, target).unwrap();
    assert_eq!(corrected, defects);
    let mut decoded = after.clone();
    MftRecord::parse(&mut decoded, 512).unwrap();
    let fixed = MftRecord::from_decoded(&decoded).unwrap();
    let fixed_data = fixed.stream(ATTR_DATA, &[]).unwrap();
    let actual = DataRuns::new(fixed_data.data_runs().unwrap(), 0).collect::<ntfs_rs::Result<Vec<_>>>().unwrap();
    assert_eq!(actual, expected);
    assert_eq!(fixed_data.data_size().unwrap(), data.data_size().unwrap());
    assert_eq!(fixed_data.initialized_size().unwrap(), data.initialized_size().unwrap());
    assert_eq!(fixed_data.allocated_size().unwrap(), data.allocated_size().unwrap());
    let mut wrong = target;
    wrong.raw_sha256[0] ^= 1;
    assert!(canonical_record(&raw, boot, wrong).is_err());
    wrong = target;
    wrong.record += 1;
    assert!(canonical_record(&raw, boot, wrong).is_err());
    let mut altered = raw.clone();
    altered[16] ^= 1;
    assert!(canonical_record(&altered, boot, target).is_err());
    let mut truncated = boot;
    truncated.total_sectors = 256;
    assert!(canonical_record(&raw, truncated, target).is_err());
    for (offset, value) in [
        (16, vec![0, 0]),
        (22, vec![3, 0]),
        (32, 1_u64.to_le_bytes().to_vec()),
        (data.record_offset() + 12, vec![0, 128]),
        (data.record_offset() + 34, vec![4, 0]),
    ] {
        let mut invalid_record = old.clone();
        invalid_record[offset..offset + value.len()].copy_from_slice(&value);
        protect_mft_record(&mut invalid_record, 512).unwrap();
        let invalid_target = WidthRepairTarget { raw_sha256: ntfs_rs::sha256::digest(&invalid_record), ..target };
        assert!(canonical_record(&invalid_record, boot, invalid_target).is_err());
    }
    println!(
        "mapping_widths={corrected} runs={} clusters={}",
        actual.len(),
        actual.iter().map(|run| run.len).sum::<u64>()
    );
}
#[test]
#[ignore = "requires SLATE_WIDTH_VOLUME pointing to an owned clean volume with plain nonresident DATA"]
fn width_journal_resumes_at_every_durable_boundary() {
    exercise_width_journal(false);
}

#[test]
#[ignore = "requires SLATE_WIDTH_VOLUME pointing to an owned clean volume with plain nonresident DATA"]
fn width_alias_journal_resumes_at_every_durable_boundary() {
    exercise_width_journal(true);
}

fn exercise_width_journal(normalize_aliases: bool) {
    use ntfs_rs::index::{IndexBlock, IndexRoot};
    use std::os::unix::fs::PermissionsExt;
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_WIDTH_VOLUME").unwrap());
    let original = std::fs::read(&source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let mut volume = Volume::new(Image(File::open(&source).unwrap()), boot).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let table = mft.stream(ATTR_DATA, &[]).unwrap();
    let slots = table.initialized_size().unwrap() / u64::from(boot.record_bytes);
    let mut selected = None;
    for number in 16..slots {
        let mut raw = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(&mft, number, &mut raw).unwrap();
        let mut decoded = raw.clone();
        if MftRecord::parse(&mut decoded, boot.bytes_per_sector).is_err() {
            continue;
        }
        let record = MftRecord::from_decoded(&decoded).unwrap();
        if record.flags().unwrap() != 1
            || record.base_file_reference().unwrap() != 0
            || record.attributes().any(|entry| entry.unwrap().kind == ATTR_ATTRIBUTE_LIST)
        {
            continue;
        }
        let Ok(data) = record.stream(ATTR_DATA, &[]) else {
            continue;
        };
        if !data.nonresident || data.flags().unwrap() != 0 {
            continue;
        }
        let runs = DataRuns::new(data.data_runs().unwrap(), 0).collect::<ntfs_rs::Result<Vec<_>>>().unwrap();
        if !runs.iter().any(|run| run.len >= 128) || runs.iter().any(|run| run.lcn.is_none()) {
            continue;
        }
        let at = data.record_offset();
        let mut split = Vec::new();
        for run in runs {
            let mut consumed = 0;
            while consumed < run.len {
                let length = (run.len - consumed).min(128);
                split.push(Extent { vcn: run.vcn + consumed, len: length, lcn: Some(run.lcn.unwrap() + consumed) });
                consumed += length;
            }
        }
        if ntfs_rs::record_edit::set_runs(&mut decoded, at, &split).is_err() {
            continue;
        }
        let mut bytes = Vec::new();
        let mut previous = 0_i64;
        for run in split {
            let delta = run.lcn.unwrap() as i64 - previous;
            let width = (1..=8)
                .find(|&width| width == 8 || delta >= -(1_i64 << (width * 8 - 1)) && delta < (1_i64 << (width * 8 - 1)))
                .unwrap();
            bytes.push(((width as u8) << 4) | 1);
            bytes.push(run.len as u8);
            bytes.extend_from_slice(&delta.to_le_bytes()[..width]);
            previous = run.lcn.unwrap() as i64;
        }
        bytes.push(0);
        let mapping = at + usize::from(u16_at(&decoded, at + 32).unwrap());
        let end = at + u32_at(&decoded, at + 4).unwrap() as usize;
        assert!(mapping + bytes.len() <= end);
        decoded[mapping..end].fill(0);
        decoded[mapping..mapping + bytes.len()].copy_from_slice(&bytes);
        if normalize_aliases {
            let record = MftRecord::from_decoded(&decoded).unwrap();
            let names = record
                .attributes()
                .filter_map(|attribute| {
                    let attribute = attribute.unwrap();
                    (attribute.kind == ntfs_rs::mft::ATTR_FILE_NAME).then_some(attribute)
                })
                .collect::<Vec<_>>();
            if names.len() != 1 || names[0].nonresident || names[0].resident_flags().unwrap() != 1 {
                continue;
            }
            let value = names[0].record_offset() + names[0].resident_value_offset().unwrap();
            decoded[value + 65] = 1;
        }
        protect_mft_record(&mut decoded, boot.bytes_per_sector).unwrap();
        selected = Some((number, decoded, record_spans(table, boot, number).unwrap()));
        break;
    }
    let (number, raw, spans) = selected.expect("fixture requires a sizeable plain DATA stream");
    let mut damaged = original.clone();
    for (physical, start, length) in &spans {
        damaged[*physical as usize..*physical as usize + *length].copy_from_slice(&raw[*start..*start + *length]);
    }
    if normalize_aliases {
        let mut decoded = raw.clone();
        MftRecord::parse(&mut decoded, boot.bytes_per_sector).unwrap();
        let record = MftRecord::from_decoded(&decoded).unwrap();
        let parent =
            u64_at(record.stream(ntfs_rs::mft::ATTR_FILE_NAME, &[]).unwrap().resident_value().unwrap(), 0).unwrap();
        let family = RepairFamily::load(&mut volume, &mft, parent & 0xffff_ffff_ffff).unwrap();
        let parent_image = family.logical.clone();
        let parent_record = MftRecord::from_decoded(&parent_image).unwrap();
        let key = b"$\0I\x003\x000\0";
        let root = parent_record.local_attribute(0x90, key).unwrap().unwrap();
        let unit =
            IndexRoot::parse(root.resident_value().unwrap()).unwrap().vcn_unit_bytes(boot.cluster_bytes).unwrap();
        let mut mutation = RepairPlan::new(original.len() as u64).unwrap();
        let mut count = 0;
        family
            .patch_resident_values(
                &mut volume,
                &mft,
                0x90,
                key,
                &mut |bytes| {
                    let root = IndexRoot::parse(bytes)?;
                    let mut cursor = root.first_entry_offset();
                    let mut positions = Vec::new();
                    loop {
                        let slot = root.slot_at(cursor)?;
                        let Some(entry) = slot.entry else { break };
                        if entry.file_reference & 0xffff_ffff_ffff == number {
                            positions.push(cursor + 81);
                        }
                        cursor = slot.next_offset;
                    }
                    for position in positions {
                        bytes[position] = 1;
                        count += 1;
                    }
                    Ok(())
                },
                &mut mutation,
            )
            .unwrap();
        if let Some(allocation) = parent_record.local_attribute(0xa0, key).unwrap() {
            let bitmap = parent_record.local_attribute(ATTR_BITMAP, key).unwrap().unwrap();
            let blocks = allocation.data_size().unwrap() / u64::from(boot.index_block_bytes);
            for block_number in 0..blocks {
                let mut bit = [0];
                volume.read_attribute(bitmap, block_number / 8, &mut bit).unwrap();
                if bit[0] & (1 << (block_number % 8)) == 0 {
                    continue;
                }
                let offset = block_number * u64::from(boot.index_block_bytes);
                let mut before = vec![0; boot.index_block_bytes as usize];
                volume.read_nonresident(allocation, offset, &mut before).unwrap();
                let mut after = before.clone();
                let block = IndexBlock::parse(&mut after, boot.bytes_per_sector, offset / unit).unwrap();
                let mut cursor = block.first_entry_offset();
                let mut positions = Vec::new();
                loop {
                    let slot = block.slot_at(cursor).unwrap();
                    let Some(entry) = slot.entry else { break };
                    if entry.file_reference & 0xffff_ffff_ffff == number {
                        positions.push(cursor + 81);
                    }
                    cursor = slot.next_offset;
                }
                if positions.is_empty() {
                    continue;
                }
                for position in positions {
                    after[position] = 1;
                    count += 1;
                }
                ntfs_rs::mft::protect_fixups(&mut after).unwrap();
                plan_nonresident_overwrite(allocation, boot, offset, before.len() as u64, |span| {
                    let start = span.source_offset as usize;
                    let end = start + span.length as usize;
                    mutation
                        .push(Patch::new(span.physical_offset, before[start..end].to_vec(), after[start..end].to_vec()))
                        .unwrap();
                    Ok(())
                })
                .unwrap();
            }
        }
        assert_eq!(count, 1);
        for patch in mutation.iter() {
            let patch = patch.unwrap();
            damaged[patch.physical as usize..patch.physical as usize + patch.after.len()].copy_from_slice(&patch.after);
        }
    }
    let target = WidthRepairTarget {
        record: number,
        raw_sha256: ntfs_rs::sha256::digest(&raw),
        expected_serial: Some(boot.serial_number),
    };
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let directory = std::env::temp_dir().join(format!("slate-width-journal-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let image = directory.join("volume.img");
    let journal = directory.join("width.journal");
    let completed = directory.join("width.journal.completed");
    let open_image = || OpenOptions::new().read(true).write(true).open(&image).unwrap();
    std::fs::write(&image, &damaged).unwrap();
    let changes = if normalize_aliases {
        assert!(completion::completion_plan(&image, completion::CompletionMode::Widths(target)).is_err());
        completion::completion_plan(&image, completion::CompletionMode::WidthsAndAliases(target)).unwrap()
    } else {
        completion::completion_plan(&image, completion::CompletionMode::Widths(target)).unwrap()
    };
    let mut expected = damaged.clone();
    for patch in changes.iter() {
        let patch = patch.unwrap();
        expected[patch.physical as usize..patch.physical as usize + patch.after.len()].copy_from_slice(&patch.after);
    }
    drop(changes);
    let operation = |target| {
        if normalize_aliases {
            InPlaceOperation::Replay(completion::CompletionMode::WidthsAndAliases(target))
        } else {
            InPlaceOperation::Replay(completion::CompletionMode::Widths(target))
        }
    };
    let mut wrong = target;
    wrong.raw_sha256[0] ^= 1;
    assert!(apply_in_place_journal(open_image(), &journal, false, None, operation(wrong), None, &mut |_| {}).is_err());
    assert!(!journal.exists());
    assert_eq!(std::fs::read(&image).unwrap(), damaged);
    let mut finished = false;
    for boundary in 1..128 {
        std::fs::write(&image, &damaged).unwrap();
        let result =
            apply_in_place_journal(open_image(), &journal, false, None, operation(target), Some(boundary), &mut |_| {});
        if let Err(error) = result {
            assert!(error.to_string().contains("injected in-place repair interruption"), "{error}");
            let prior = std::fs::read(&image).unwrap();
            assert!(apply_in_place_journal(open_image(), &journal, true, None, operation(wrong), None, &mut |_| {})
                .is_err());
            assert_eq!(std::fs::read(&image).unwrap(), prior);
            apply_in_place_journal(open_image(), &journal, true, None, operation(target), None, &mut |_| {}).unwrap();
        } else {
            finished = true;
        }
        assert_eq!(std::fs::read(&image).unwrap(), expected);
        assert!(checker::check_device(&image, Default::default(), None).unwrap().write_ready());
        assert!(!journal.exists() && completed.exists());
        std::fs::remove_file(&completed).unwrap();
        if finished {
            println!("width_journal_durable_boundaries={} target={number} aliases={normalize_aliases}", boundary - 1);
            break;
        }
    }
    assert!(finished);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn shared_mapping_frames_preserve_all_dense_widths_and_positive_unsigned_defects() {
    const MAX_WIDTH: usize = std::mem::size_of::<u64>();
    const MAPPING_NIBBLE_BITS: u32 = 4;
    const COMPACT_LENGTH: u8 = 128;
    const FULL_DELTA_HEADER: u8 = 0x81;

    let mut boot = geometry();
    boot.sectors_per_cluster = 1;
    boot.total_sectors = u64::MAX;
    for length_width in 1..=MAX_WIDTH {
        for delta_width in 1..=MAX_WIDTH {
            // The first run is valid signed data; the adjacent second run has
            // the compact unsigned defect at a separately representable LCN.
            let length = (1_u64 << (length_width * u8::BITS as usize - 1)) - 1;
            let mut bytes = vec![(length_width as u8) | ((delta_width as u8) << MAPPING_NIBBLE_BITS)];
            bytes.extend_from_slice(&length.to_le_bytes()[..length_width]);
            bytes.resize(bytes.len() + delta_width, 0);
            bytes.extend_from_slice(&[FULL_DELTA_HEADER, COMPACT_LENGTH]);
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.push(0);
            let (runs, corrected) = compact_runs(&bytes, boot).unwrap();
            assert_eq!(
                runs,
                vec![
                    Extent { vcn: 0, len: length, lcn: Some(0) },
                    Extent { vcn: length, len: u64::from(COMPACT_LENGTH), lcn: Some(length) },
                ]
            );
            assert_eq!(corrected, 1);
            assert_eq!(runs[0].len, length);
            assert_eq!(runs[1].lcn, Some(length));
            // Repair's unsigned-positive interpretation must never leak into
            // ordinary reads of these still-malformed source mappings.
            assert_eq!(DataRuns::new(&bytes, 0).nth(1), Some(Err(ntfs_rs::Error::InvalidRunlist)));
        }
    }
}
