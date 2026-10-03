// Module: slate_ntfs_tools::recovery_io::models::summaries::tests
// Purpose: Exercise summaries recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;
use std::path::PathBuf;

#[test]
#[ignore = "requires SLATE_REPLAY_SUMMARY_SOURCE pointing to an owned replay-completable image with linked ordinary files"]
fn informational_summaries_are_corrected_and_unrelated_damage_refuses() {
    let source = PathBuf::from(std::env::var_os("SLATE_REPLAY_SUMMARY_SOURCE").unwrap());
    let original = std::fs::read(&source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    for corrupt_reference in [false, true] {
        let mut changes = completion::completion_plan(&source, completion::CompletionMode::Replay(None)).unwrap();
        let mut mutation = RepairPlan::new(changes.length).unwrap();
        let mut volume =
            Volume::new(PlannedImage { image: Image(File::open(&source).unwrap()), patches: &changes }, boot).unwrap();
        let zero = checker::consistency::mft_image(&mut volume).unwrap();
        let mft = MftRecord::from_decoded(&zero).unwrap();
        let family = RepairFamily::load(&mut volume, &mft, 5).unwrap();
        let record = MftRecord::from_decoded(&family.logical).unwrap();
        let root_attribute = record.local_attribute(0x90, I30).unwrap().unwrap();
        let root = IndexRoot::parse(root_attribute.resident_value().unwrap()).unwrap();
        let allocation = record.local_attribute(0xa0, I30).unwrap().unwrap();
        let bitmap = record.local_attribute(ATTR_BITMAP, I30).unwrap().unwrap();
        let blocks = allocation.data_size().unwrap() / u64::from(boot.index_block_bytes);
        let unit = root.vcn_unit_bytes(boot.cluster_bytes).unwrap();
        let mut changed = false;
        for number in 0..blocks {
            let mut bit = [0];
            volume.read_attribute(bitmap, number / 8, &mut bit).unwrap();
            if bit[0] & (1 << (number % 8)) == 0 {
                continue;
            }
            let offset = number * u64::from(boot.index_block_bytes);
            let mut before = vec![0; boot.index_block_bytes as usize];
            volume.read_nonresident(allocation, offset, &mut before).unwrap();
            let mut after = before.clone();
            let block = IndexBlock::parse(&mut after, boot.bytes_per_sector, offset / unit).unwrap();
            let mut cursor = block.first_entry_offset();
            let mut target = None;
            loop {
                let slot = block.slot_at(cursor).unwrap();
                let Some(entry) = slot.entry else { break };
                if entry.file_reference & 0xffff_ffff_ffff >= 16 {
                    target = Some(cursor);
                    break;
                }
                cursor = slot.next_offset;
            }
            let Some(target) = target else { continue };
            // Alter either a cached allocation size or the full sequence
            // identity. All authoritative file bytes stay unchanged.
            let at = if corrupt_reference { target + 6 } else { target + 56 };
            after[at] ^= 1;
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
            changed = true;
            break;
        }
        assert!(changed, "fixture needs a linked ordinary file");
        drop(volume);
        for patch in mutation.iter() {
            changes.compose(patch.unwrap()).unwrap();
        }
        let audit = checker::consistency::audit_reader(
            PlannedImage { image: Image(File::open(&source).unwrap()), patches: &changes },
            boot,
            |_, _, _| Ok(()), |_| Ok(()), checker::consistency::AuditOptions::default(), checker::consistency::INDEX_CACHE_BYTES,)
        .unwrap();
        let before = changes.len();
        if corrupt_reference {
            assert!(audit.errors > 0);
            assert!(plan_summaries(&source, boot, &mut changes, &audit).is_err());
            assert_eq!(changes.len(), before);
        } else {
            assert_eq!(audit.errors, 0);
            let mut summaries = 0;
            audit
                .for_each_finding(|code, _, is_error, _| {
                    if code == "index-duplicate-information" {
                        assert!(!is_error);
                        summaries += 1;
                    }
                    Ok(())
                })
                .unwrap();
            assert!(summaries > 0);
            assert_eq!(plan_summaries(&source, boot, &mut changes, &audit).unwrap(), summaries);
            let final_audit = checker::consistency::audit_reader(
                PlannedImage { image: Image(File::open(&source).unwrap()), patches: &changes },
                boot,
                |_, _, _| Ok(()), |_| Ok(()), checker::consistency::AuditOptions::default(), checker::consistency::INDEX_CACHE_BYTES,)
            .unwrap();
            assert!(final_audit.passed());
            final_audit
                .for_each_finding(|code, _, _, _| {
                    assert_ne!(code, "index-duplicate-information");
                    Ok(())
                })
                .unwrap();
        }
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
}
