//! Module: recovery_io::usn_history_tests
//! Purpose: Check journal page boundaries, advance limits and read failures.
//! Created: 2026-11-25
//! Architecture: Bounded independent memory images exercise the shared journal
//! validator without mounting a filesystem or relying on the repair planner.

use super::*;
use ntfs_rs::{mft::attribute_layout, record_edit as edit, runlist::Extent};

const CLUSTER_BYTES: u32 = 64 * 1024;
const RECORD_BYTES: u32 = 1024;
const SECTOR_BYTES: u16 = 512;
const DATA_LCN: u64 = 1;
const MFT_LCN: u64 = 4;
const MIRROR_LCN: u64 = 2;
const SERIAL: u64 = 1;
const JOURNAL_ID: u64 = 7;
const INDEX_BYTES: u32 = 4096;
const NAME_BYTES: u16 = std::mem::size_of::<u16>() as u16;
const SECTORS: u64 = 1024;
const RECORD_LENGTH: u32 = 64;

struct Memory {
    bytes: Vec<u8>,
    fail: bool,
}

impl ReadAt for Memory {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> ntfs_rs::Result<()> {
        if self.fail {
            return Err(ntfs_rs::Error::Io);
        }
        output.copy_from_slice(&self.bytes[offset as usize..offset as usize + output.len()]);
        Ok(())
    }
}

fn fixture(oversized: bool, fail: bool) -> (Volume<Memory>, Vec<u8>, [u8; USN_MAX_BYTES]) {
    let boot = BootSector {
        bytes_per_sector: SECTOR_BYTES,
        sectors_per_cluster: CLUSTER_BYTES / u32::from(SECTOR_BYTES),
        cluster_bytes: CLUSTER_BYTES,
        total_sectors: SECTORS,
        mft_lcn: MFT_LCN,
        mft_mirror_lcn: MIRROR_LCN,
        record_bytes: RECORD_BYTES,
        index_block_bytes: INDEX_BYTES,
        serial_number: SERIAL,
    };
    let mut bytes = vec![0; CLUSTER_BYTES as usize * 2];
    for logical in [0, USN_PAGE_BYTES as usize] {
        let at = CLUSTER_BYTES as usize + logical;
        edit::p32(&mut bytes, at, RECORD_LENGTH).unwrap();
        edit::p16(&mut bytes, at + USN_MAJOR_OFFSET, USN_V2_MAJOR).unwrap();
        edit::p64(&mut bytes, at + USN_V2_NUMBER_OFFSET, logical as u64).unwrap();
        edit::p16(&mut bytes, at + USN_V2_NAME_LENGTH, NAME_BYTES).unwrap();
        edit::p16(&mut bytes, at + USN_V2_NAME_OFFSET, USN_V2_BYTES as u16).unwrap();
        bytes[at + USN_V2_BYTES] = b'x';
    }
    if oversized {
        edit::p32(&mut bytes, CLUSTER_BYTES as usize, (USN_PAGE_BYTES + USN_ALIGNMENT) as u32).unwrap();
    }
    let mut raw = vec![0; RECORD_BYTES as usize];
    let mut attribute = vec![0; RECORD_BYTES as usize];
    edit::format_empty(&mut raw, 0).unwrap();
    let runs = [Extent { vcn: 0, lcn: Some(DATA_LCN), len: 1 }];
    let size = USN_PAGE_BYTES + u64::from(RECORD_LENGTH);
    let length =
        edit::build_nonresident(ATTR_DATA, USN_J_NAME, &runs, CLUSTER_BYTES as u64, size, size, &mut attribute)
            .unwrap();
    edit::p16(&mut attribute, attribute_layout::FLAGS_OFFSET, attribute_layout::SPARSE).unwrap();
    edit::p64(&mut attribute, attribute_layout::COMPRESSED_SIZE_OFFSET, CLUSTER_BYTES as u64).unwrap();
    edit::insert(&mut raw, &attribute[..length]).unwrap();
    let mut config = [0; USN_MAX_BYTES];
    edit::p64(&mut config, USN_ID_OFFSET, JOURNAL_ID).unwrap();
    (Volume::new(Memory { bytes, fail }, boot).unwrap(), raw, config)
}

#[test]
fn journal_padding_uses_four_kib_pages_inside_a_large_cluster() {
    let (mut volume, raw, config) = fixture(false, false);
    let record = MftRecord::from_decoded(&raw).unwrap();
    assert!(!usn_damaged(&mut volume, record.stream(ATTR_DATA, USN_J_NAME).unwrap(), &config).unwrap());
}

#[test]
fn oversized_record_and_real_io_failure_remain_distinct() {
    let (mut volume, raw, config) = fixture(true, false);
    let record = MftRecord::from_decoded(&raw).unwrap();
    let j = record.stream(ATTR_DATA, USN_J_NAME).unwrap();
    assert!(usn_damaged(&mut volume, j, &config).unwrap());
    let (mut volume, raw, config) = fixture(false, true);
    let record = MftRecord::from_decoded(&raw).unwrap();
    let j = record.stream(ATTR_DATA, USN_J_NAME).unwrap();
    assert!(usn_damaged(&mut volume, j, &config).is_err());
}

#[test]
fn advancing_past_maximum_file_usn_requests_a_full_counter_reset() {
    assert_eq!(usn_advance_position(0), USN_ADVANCE_BYTES);
    assert_eq!(usn_advance_position(USN_ADVANCE_BYTES - USN_ALIGNMENT), USN_ADVANCE_BYTES);
    assert_eq!(usn_advance_position(USN_ADVANCE_BYTES), USN_ADVANCE_BYTES * 2);
    assert_eq!(usn_advance_position(USN_ADVANCE_LIMIT - USN_ALIGNMENT), USN_ADVANCE_LIMIT);
    assert_eq!(usn_advance_position(USN_ADVANCE_LIMIT), 0);
    assert_eq!(usn_advance_position(u64::MAX), 0);
}
