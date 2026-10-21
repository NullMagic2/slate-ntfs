//! Module: volume::empty_family
//! Purpose: Check empty nonresident heads in a retained attribute list.
//! Created: 2026-10-21
//! Architecture: Uses checked record builders and the family visitor without disk I/O;
//! the list must preserve empty stream semantics and reject overflowing mappings.

use super::super::{
    attrlist::{ListEntry, ENTRY_MIN_BYTES},
    mft::{attribute_layout as af, record_layout as rf},
    record_edit as edit,
};
use super::*;

const RECORD_BYTES: usize = 1024;
const BASE_NUMBER: u64 = 24;
const SEQUENCE: u16 = 1;
const BOOT: BootSector = BootSector {
    bytes_per_sector: 512,
    sectors_per_cluster: 8,
    cluster_bytes: 4096,
    total_sectors: 128,
    mft_lcn: 1,
    mft_mirror_lcn: 2,
    record_bytes: RECORD_BYTES as u32,
    index_block_bytes: 4096,
    serial_number: 1,
};

struct NoRead;

impl ReadAt for NoRead {
    fn read_exact_at(&mut self, _offset: u64, _output: &mut [u8]) -> Result<()> {
        Err(Error::Io)
    }
}

#[test]
fn listed_empty_nonresident_head_has_zero_vcn_end() {
    for (flags, data_size, physical_size, expected) in [
        (af::NO_FLAGS, 0, 0, Ok(())),
        (af::COMPRESSED | af::SPARSE, 0, 0, Ok(())),
        (af::COMPRESSED | af::SPARSE, 1, 0, Err(Error::Overflow)),
        (af::COMPRESSED | af::SPARSE, 0, 1, Err(Error::Overflow)),
    ] {
        let mut base = [0; RECORD_BYTES];
        edit::format_empty(&mut base, BASE_NUMBER).unwrap();
        edit::p16(&mut base, rf::SEQUENCE_OFFSET, SEQUENCE).unwrap();
        edit::p16(&mut base, rf::FLAGS_OFFSET, rf::IN_USE).unwrap();
        let mut attribute = [0; RECORD_BYTES];
        let n = edit::build_nonresident(ATTR_DATA, &[], &[], 0, data_size, 0, &mut attribute).unwrap();
        edit::p16(&mut attribute, af::FLAGS_OFFSET, flags).unwrap();
        edit::p64(&mut attribute, af::COMPRESSED_SIZE_OFFSET, physical_size).unwrap();
        if flags & af::COMPRESSED != 0 {
            edit::p16(&mut attribute, af::COMPRESSION_UNIT_OFFSET, af::COMPRESSION_UNIT_SHIFT).unwrap();
        }
        let at = edit::insert(&mut base, &attribute[..n]).unwrap();
        let id = super::super::bytes::u16_at(&base, at + af::ID_OFFSET).unwrap();
        let mut list = [0; ENTRY_MIN_BYTES];
        let n = ListEntry {
            kind: ATTR_DATA,
            first_vcn: 0,
            file_reference: file_reference(BASE_NUMBER, SEQUENCE).unwrap(),
            attribute_id: id,
            name_utf16le: &[],
        }
        .encode(&mut list)
        .unwrap();
        let n = edit::build_resident(ATTR_ATTRIBUTE_LIST, &[], &list[..n], &mut attribute).unwrap();
        edit::insert(&mut base, &attribute[..n]).unwrap();
        let base = MftRecord::from_decoded(&base).unwrap();
        let mut zero = [0; RECORD_BYTES];
        edit::format_empty(&mut zero, super::super::mft::system_record::MFT).unwrap();
        let mft = MftRecord::from_decoded(&zero).unwrap();
        let mut volume = Volume::new(NoRead, BOOT).unwrap();
        let mut scratch = [0; RECORD_BYTES + ENTRY_MIN_BYTES];
        let mut visited = 0;
        let result = volume.visit_record_family(&mft, &base, &mut scratch, |_, _| {
            visited += 1;
            Ok(())
        });
        assert_eq!(result, expected, "flags={flags:#x} data_size={data_size} physical_size={physical_size}");
        if expected.is_ok() {
            assert_eq!(visited, 1);
        }
    }
}
