// Module: slate_ntfs_tools::recovery_io::coordinator_unrecoverable_evidence_checks
// Purpose: Verify recovery coordination with disposable regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged into the test folder and included in its
// original private scope; this file cannot authorize production disk writes.

use super::*;
use ntfs_rs::{record_edit as edit, runlist::Extent};

fn fixture(crosslink: bool) -> (std::path::PathBuf, Vec<u8>) {
    let mut image = vec![0_u8; 512 * 512];
    image[3..11].copy_from_slice(b"NTFS    ");
    image[11..13].copy_from_slice(&512_u16.to_le_bytes());
    image[13] = 8;
    image[40..48].copy_from_slice(&512_u64.to_le_bytes());
    image[48..56].copy_from_slice(&4_u64.to_le_bytes());
    image[56..64].copy_from_slice(&2_u64.to_le_bytes());
    image[64] = (-10_i8) as u8;
    image[68] = (-12_i8) as u8;
    image[72..80].copy_from_slice(&1_u64.to_le_bytes());
    image[510..512].copy_from_slice(&[0x55, 0xaa]);
    let mut base = vec![0; 1024];
    edit::format_empty(&mut base, 0).unwrap();
    edit::p16(&mut base, 16, 5).unwrap();
    edit::p16(&mut base, 22, 1).unwrap();
    let mut attr = vec![0; 1024];
    let n = edit::build_nonresident(
        ATTR_DATA,
        &[],
        &[Extent { vcn: 0, lcn: Some(4), len: 4 }],
        16384,
        16384,
        16384,
        &mut attr,
    )
    .unwrap();
    edit::insert(&mut base, &attr[..n]).unwrap();
    let n = edit::build_resident(ATTR_BITMAP, &[], &[if crosslink { 0x03 } else { 0x41 }, 0], &mut attr).unwrap();
    edit::insert(&mut base, &attr[..n]).unwrap();
    protect_mft_record(&mut base, 512).unwrap();
    image[16384..17408].copy_from_slice(&base);
    if crosslink {
        let mut other = vec![0; 1024];
        edit::format_empty(&mut other, 1).unwrap();
        edit::p16(&mut other, 16, 3).unwrap();
        edit::p16(&mut other, 22, 1).unwrap();
        let n = edit::build_nonresident(
            ATTR_DATA,
            &[],
            &[Extent { vcn: 0, lcn: Some(4), len: 1 }],
            4096,
            4096,
            4096,
            &mut attr,
        )
        .unwrap();
        edit::insert(&mut other, &attr[..n]).unwrap();
        protect_mft_record(&mut other, 512).unwrap();
        image[17408..18432].copy_from_slice(&other);
    } else {
        let mut damaged = vec![0; 1024];
        edit::format_empty(&mut damaged, 6).unwrap();
        edit::p16(&mut damaged, 16, 2).unwrap();
        edit::p16(&mut damaged, 22, 1).unwrap();
        protect_mft_record(&mut damaged, 512).unwrap();
        damaged[510] ^= 1;
        image[22528..23552].copy_from_slice(&damaged);
    }
    let path = std::env::temp_dir().join(format!(
        "slate-evidence-{}-{}-{}",
        std::process::id(),
        crosslink,
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::write(&path, &image).unwrap();
    (path, image)
}

#[test]
fn preserves_a_torn_allocated_record() {
    let (source, original) = fixture(false);
    let report = source.with_extension("evidence.txt");
    let result = export_repair_evidence(&source, &report);
    if result.is_ok() {
        let text = std::fs::read_to_string(&report).unwrap();
        assert!(text.contains("issue=unrecoverable-mft-record"));
        assert!(text.contains("span=mft-record-6 physical=22528 length=1024"));
        assert!(text.contains("46494c45"));
        assert_eq!(std::fs::read(&source).unwrap(), original);
    }
    let _ = std::fs::remove_file(&report);
    std::fs::remove_file(&source).unwrap();
    result.unwrap();
}

#[test]
fn preserves_both_reserved_claims_and_shared_bytes() {
    let (source, original) = fixture(true);
    let report = source.with_extension("evidence.txt");
    let result = export_repair_evidence(&source, &report);
    if result.is_ok() {
        let text = std::fs::read_to_string(&report).unwrap();
        assert!(text.contains("issue=unresolved-reserved-crosslink"));
        assert!(text.contains("span=shared-clusters physical=16384 length=4096"));
        assert!(text.contains("span=first-owner-record"));
        assert!(text.contains("span=second-owner-record"));
        assert_eq!(std::fs::read(&source).unwrap(), original);
    }
    let _ = std::fs::remove_file(&report);
    std::fs::remove_file(&source).unwrap();
    result.unwrap();
}
