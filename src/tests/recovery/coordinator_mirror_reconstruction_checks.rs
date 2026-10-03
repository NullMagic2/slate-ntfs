// Module: slate_ntfs_tools::recovery_io::coordinator_mirror_reconstruction_checks
// Purpose: Verify recovery coordination with disposable regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged into the test folder and included in its
// original private scope; this file cannot authorize production disk writes.

use super::*;
fn record() -> Vec<u8> {
    let mut raw = vec![0; 1024];
    ntfs_rs::record_edit::format_empty(&mut raw, 1).unwrap();
    ntfs_rs::record_edit::p16(&mut raw, 22, 1).unwrap();
    protect_mft_record(&mut raw, 512).unwrap();
    raw
}
#[test]
fn combines_complementary_torn_mft_copies() {
    let good = record();
    let mut a = good.clone();
    let mut b = good.clone();
    a[510] ^= 0xff;
    b[1022] ^= 0xff;
    assert_eq!(reconstruct_mirror_sectors(&a, &b, 512).unwrap(), good);
}
#[test]
fn refuses_generation_conflicts_and_shared_sector_loss() {
    let mut a = record();
    let mut b = a.clone();
    a[510] ^= 0xff;
    b[510] ^= 0xff;
    assert!(reconstruct_mirror_sectors(&a, &b, 512).is_err());
    b = record();
    b[1022] ^= 0xff;
    b[8] = 1;
    assert!(reconstruct_mirror_sectors(&a, &b, 512).is_err());
}
