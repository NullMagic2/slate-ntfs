//! Module: ntfs_rs::allocation::tests
//! Purpose: Verify allocation contracts independently.
//! Created: 2026-10-03
//! Architecture: The production module references these selectable unit tests.

use super::super::runlist::DataRuns;
use super::*;
#[test]
fn mapping_pairs_roundtrip_negative_deltas_and_large_runs() {
    let runs = [Extent { vcn: 0, len: 300, lcn: Some(1000) }, Extent { vcn: 300, len: 1, lcn: Some(10) }];
    let mut bytes = [0; 40];
    let n = encode_runs(&runs, &mut bytes).unwrap();
    assert_eq!(DataRuns::new(&bytes[..n], 0).collect::<std::vec::Vec<_>>(), runs.map(Ok));
}
#[test]
fn mft_reservation_excludes_system_slots_and_rejects_double_free() {
    let mut bits = [0; 4];
    assert_eq!(reserve_mft_slot(&mut bits, 32), Ok(16));
    assert_eq!(reserve_mft_slot(&mut bits, 32), Ok(17));
    assert_eq!(release_mft_slot(&mut bits, 16, 32), Ok(()));
    assert_eq!(release_mft_slot(&mut bits, 16, 32), Err(Error::InvalidRecord));
    assert_eq!(release_mft_slot(&mut bits, 0, 32), Err(Error::InvalidRecord));
    assert_eq!(reserve_mft_slot(&mut bits, 32), Ok(16));
}
