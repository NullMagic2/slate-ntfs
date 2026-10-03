//! Module: src.tests.core.robustness
//! Purpose: Verify robustness behavior on disposable fixtures.
//! Created: 2026-10-01
//! Architecture: Disposable fixtures exercise the production core or its mounted adapter and
//! verify resulting state.

use ntfs_rs::attrlist::AttributeList;
use ntfs_rs::boot::BootSector;
use ntfs_rs::index::{IndexBlock, IndexRoot};
use ntfs_rs::mft::MftRecord;
use ntfs_rs::runlist::DataRuns;

// The parser consumes disk-controlled bytes in kernel context. This test
// exercises corrupted lengths and offsets without depending on a disk image.
#[test]
fn malformed_input_does_not_panic() {
    let mut state = 0x91e1_0da5_u64;
    for _ in 0..10_000 {
        let mut bytes = [0_u8; 1024];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let _ = BootSector::parse(&bytes[..512]);
        let _ = DataRuns::new(&bytes[..64], 0).collect::<Vec<_>>();
        let _ = AttributeList::new(&bytes[..64]).collect::<Vec<_>>();
        if let Ok(root) = IndexRoot::parse(&bytes[..256]) {
            let _ = root.entries().collect::<Vec<_>>();
        }
        bytes[0..4].copy_from_slice(b"INDX");
        if let Ok(block) = IndexBlock::parse(&mut bytes, 512, 0) {
            let _ = block.entries().collect::<Vec<_>>();
        }
        if let Ok(record) = MftRecord::parse(&mut bytes, 512) {
            let _ = record.attributes().collect::<Vec<_>>();
        }
    }
}
