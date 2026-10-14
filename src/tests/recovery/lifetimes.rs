//! Module: recovery_lifetimes::tests
//! Purpose: Verify mapping lifetimes without volume-specific identities.
//! Created: 2026-10-09
//! Architecture: Synthetic FILE records exercise the production transition parser.
use super::*;
use ntfs_rs::{mft::ATTR_INDEX_ALLOCATION, record_edit as edit};

const NUMBER: u64 = 48;
const SEQUENCE: u16 = 7;
const CLUSTERS: u64 = 4096;
const NAME: &[u8] = b"$\0I\03\00\0";

fn record(runs: &[Extent], sequence: u16) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    edit::format_empty(&mut raw, NUMBER).unwrap();
    edit::p16(&mut raw, record_layout::SEQUENCE_OFFSET, sequence).unwrap();
    edit::p16(&mut raw, record_layout::FLAGS_OFFSET, record_layout::IN_USE).unwrap();
    if !runs.is_empty() {
        let mut attr = vec![0; 512];
        let bytes = runs.iter().map(|run| run.len).sum::<u64>() * 4096;
        let used = edit::build_nonresident(ATTR_INDEX_ALLOCATION, NAME, runs, bytes, bytes, bytes, &mut attr).unwrap();
        edit::insert(&mut raw, &attr[..used]).unwrap();
    }
    raw
}

fn change(before: &[Extent], after: &[Extent]) -> Transition {
    Transition {
        before: Snapshot::read(&record(before, SEQUENCE), NUMBER, CLUSTERS).unwrap().unwrap(),
        after: Snapshot::read(&record(after, SEQUENCE), NUMBER, CLUSTERS).unwrap().unwrap(),
    }
}

fn extent(vcn: u64, lcn: u64, len: u64) -> Extent {
    Extent { vcn, lcn: Some(lcn), len }
}

fn retires(change: &Transition, vcn: u64, lcn: u64) -> Result<bool> {
    change.retires(file_reference(NUMBER, SEQUENCE).unwrap(), ATTR_INDEX_ALLOCATION, NAME, vcn, lcn)
}

#[test]
fn deletion_and_recreation_are_separate_lifetimes() {
    let deletion = change(&[extent(0, 100, 2)], &[]);
    assert_eq!(retires(&deletion, 0, 100), Ok(true));
    assert_eq!(retires(&deletion, 1, 101), Ok(true));
    let recreation = change(&[], &[extent(0, 700, 2)]);
    assert_eq!(retires(&recreation, 0, 100), Ok(false));
}

#[test]
fn truncation_and_relocation_preserve_unchanged_ranges() {
    let old = [extent(0, 100, 2), extent(2, 700, 2)];
    let truncated = change(&old, &[extent(0, 100, 2)]);
    assert_eq!(retires(&truncated, 0, 100), Ok(false));
    assert_eq!(retires(&truncated, 2, 700), Ok(true));
    let moved = change(&old, &[extent(0, 900, 2), extent(2, 700, 2)]);
    assert_eq!(retires(&moved, 0, 100), Ok(true));
    assert_eq!(retires(&moved, 2, 700), Ok(false));
}

#[test]
fn unexplained_lcn_or_wrong_owner_never_authorizes_retirement() {
    let deletion = change(&[extent(0, 100, 2)], &[]);
    assert_eq!(retires(&deletion, 0, 200), Err(Error::InvalidLog));
    assert_eq!(
        deletion.retires(file_reference(NUMBER, SEQUENCE + 1).unwrap(), ATTR_INDEX_ALLOCATION, NAME, 0, 100),
        Ok(false)
    );
    assert_eq!(deletion.retires(file_reference(NUMBER, SEQUENCE).unwrap(), ATTR_DATA, NAME, 0, 100), Ok(false));
    assert_eq!(
        deletion.retires(file_reference(NUMBER, SEQUENCE).unwrap(), ATTR_INDEX_ALLOCATION, b"other", 0, 100),
        Ok(false)
    );
}

#[test]
fn malformed_identity_and_out_of_volume_runs_are_rejected() {
    let raw = record(&[extent(0, 100, 2)], SEQUENCE);
    assert!(matches!(Snapshot::read(&raw, NUMBER + 1, CLUSTERS), Err(Error::InvalidLog)));
    let raw = record(&[extent(0, CLUSTERS - 1, 2)], SEQUENCE);
    assert!(matches!(Snapshot::read(&raw, NUMBER, CLUSTERS), Err(Error::InvalidLog)));
}

#[test]
fn attribute_family_movement_is_not_mistaken_for_deletion() {
    let mut raw = record(&[extent(0, 100, 2)], SEQUENCE);
    edit::p64(&mut raw, record_layout::BASE_REFERENCE_OFFSET, file_reference(47, 1).unwrap()).unwrap();
    assert!(Snapshot::read(&raw, NUMBER, CLUSTERS).unwrap().is_none());
}

#[test]
fn base_attribute_lists_do_not_authorize_local_retirement() {
    let mut raw = record(&[extent(0, 100, 2)], SEQUENCE);
    let mut attribute = [0; 64];
    let n = edit::build_resident(ATTR_ATTRIBUTE_LIST, &[], &[], &mut attribute).unwrap();
    edit::insert(&mut raw, &attribute[..n]).unwrap();
    assert!(Snapshot::read(&raw, NUMBER, CLUSTERS).unwrap().is_none());
}
