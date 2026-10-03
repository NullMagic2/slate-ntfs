// Module: slate_ntfs_tools::recovery_io::models::plan::tests
// Purpose: Exercise plan recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

#[test]
fn pending_payload_views_preserve_updates_through_eviction() {
    let original: Vec<_> = (0..3 * WRITE_VIEW_BYTES + 17).map(|n| (n % 251) as u8).collect();
    let mut expected = original.clone();
    let replacements = [(WRITE_VIEW_BYTES - 5, vec![9; 23]), (7, vec![3; 19]), (2 * WRITE_VIEW_BYTES + 1, vec![6; 11])];
    for (at, bytes) in &replacements {
        expected[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    for pages in [0, 1, 3] {
        let mut payload =
            PlanPayload::new(checker::consistency::scratch_file().unwrap(), (pages * WRITE_VIEW_BYTES) as u64).unwrap();
        payload.write_at(0, &original).unwrap();
        for (at, bytes) in &replacements {
            payload.write_at(*at as u64, bytes).unwrap();
        }
        let mut observed = vec![0; expected.len()];
        payload.read_at(0, &mut observed).unwrap();
        assert_eq!(observed, expected);
        assert!(payload.stats.peak_bytes <= (pages * WRITE_VIEW_BYTES) as u64);
        if pages != 0 {
            assert!(payload.stats.hits > 0);
            assert!(payload.stats.spills > 0);
        } else {
            assert_eq!(payload.stats.peak_bytes, 0);
        }
        assert!(payload.read_at(payload.length, &mut [0]).is_err());
    }
}

#[test]
fn failed_pending_view_spill_retains_the_only_valid_payload() {
    use std::os::fd::AsRawFd;
    let backing = checker::consistency::scratch_file().unwrap();
    let read_only = File::open(format!("/proc/self/fd/{}", backing.as_raw_fd())).unwrap();
    let mut payload = PlanPayload::new(read_only, WRITE_VIEW_BYTES as u64).unwrap();
    payload.write_at(0, &[7, 8, 9]).unwrap();
    assert!(payload.write_at(WRITE_VIEW_BYTES as u64, &[2]).is_err());
    let mut bytes = [0; 3];
    payload.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, [7, 8, 9]);
    assert_eq!(payload.length, 3);
    assert_eq!(payload.stats.spills, 0);
    assert_eq!(backing.metadata().unwrap().len(), 0);
}

#[test]
fn only_the_primary_repair_plan_receives_pending_views() {
    let budget = checker::ScanBudget {
        read_buffer_bytes: 0,
        index_cache_bytes: 0,
        write_view_cache_bytes: (2 * WRITE_VIEW_BYTES) as u64,
    };
    let mut cached = RepairPlan::with_scan_budget(1024 * 1024, Some(budget)).unwrap();
    let mut staging = RepairPlan::new(cached.length).unwrap();
    let patch = Patch::new(11, vec![1; 70000], vec![2; 70000]);
    cached.push(patch.clone()).unwrap();
    staging.push(patch.clone()).unwrap();
    let update = Patch { before: patch.after.clone(), after: vec![3; patch.after.len()], ..patch.clone() };
    cached.push(update.clone()).unwrap();
    staging.push(update).unwrap();
    assert!(cached.matches(&staging).unwrap());
    let mut projected = vec![1; 70000];
    cached.overlay(11, &mut projected).unwrap();
    assert_eq!(projected, vec![3; 70000]);
    assert_eq!(cached.get(0).unwrap().before, vec![1; 65536]);
    assert!(cached.write_view_stats().hits > 0);
    assert!(cached.write_view_stats().peak_bytes <= budget.write_view_cache_bytes);
    assert_eq!(staging.write_view_stats().peak_bytes, 0);
}
