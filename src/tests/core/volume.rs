//! Module: ntfs_rs::volume::tests
//! Purpose: Verify bounded volume reads and record-family resolution.
//! Created: 2026-10-21
//! Architecture: Exercises the shared volume reader using private memory images.

use super::*;

fn read_runs<R: ReadAt>(
    reader: &mut R,
    volume_bytes: u64,
    cluster_bytes: u64,
    runs: &[u8],
    last_vcn: u64,
    data_size: u64,
    initialized_size: u64,
    offset: u64,
    output: &mut [u8],
) -> Result<()> {
    read_runs_checked(
        reader,
        volume_bytes,
        cluster_bytes,
        runs,
        0,
        last_vcn,
        data_size,
        initialized_size,
        offset,
        output,
        true,
        true,
    )
}

use std::vec;
use std::vec::Vec;

struct Memory([u8; 64]);

impl ReadAt for Memory {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::Io)?;
        let end = start.checked_add(output.len()).ok_or(Error::Io)?;
        output.copy_from_slice(self.0.get(start..end).ok_or(Error::Io)?);
        Ok(())
    }
}

#[test]
fn reads_fragmented_and_sparse_stream_without_crossing_volume() {
    let mut memory = Memory([0; 64]);
    memory.0[8..12].copy_from_slice(b"abcd");
    memory.0[24..28].copy_from_slice(b"efgh");
    let runs = [0x11, 1, 2, 0x01, 1, 0x11, 1, 4, 0];
    let mut output = [0; 12];
    read_runs(&mut memory, 64, 4, &runs, 2, 12, 10, 0, &mut output).unwrap();
    assert_eq!(&output, b"abcd\0\0\0\0ef\0\0");
    assert_eq!(read_runs(&mut memory, 16, 4, &runs, 2, 12, 12, 8, &mut [0; 4]), Err(Error::InvalidRunlist));
}

struct Image(Vec<u8>);

impl ReadAt for Image {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| Error::Io)?;
        let end = start.checked_add(output.len()).ok_or(Error::Io)?;
        output.copy_from_slice(self.0.get(start..end).ok_or(Error::Io)?);
        Ok(())
    }
}

fn record(sequence: u16, base_ref: u64, attribute: &[u8]) -> [u8; 1024] {
    let mut record = [0_u8; 1024];
    record[..4].copy_from_slice(b"FILE");
    record[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
    record[6..8].copy_from_slice(&3_u16.to_le_bytes());
    record[0x10..0x12].copy_from_slice(&sequence.to_le_bytes());
    record[0x14..0x16].copy_from_slice(&0x38_u16.to_le_bytes());
    record[0x16..0x18].copy_from_slice(&1_u16.to_le_bytes());
    record[0x18..0x1c].copy_from_slice(&(0x38_u32 + attribute.len() as u32 + 4).to_le_bytes());
    record[0x20..0x28].copy_from_slice(&base_ref.to_le_bytes());
    record[0x30..0x32].copy_from_slice(&0x1234_u16.to_le_bytes());
    record[0x38..0x38 + attribute.len()].copy_from_slice(attribute);
    record[0x38 + attribute.len()..0x3c + attribute.len()].copy_from_slice(&u32::MAX.to_le_bytes());
    record[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
    record[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
    record
}

#[test]
fn resolves_resident_data_in_checked_extension_record() {
    let mut mft_data = [0_u8; 0x48];
    mft_data[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
    mft_data[4..8].copy_from_slice(&0x48_u32.to_le_bytes());
    mft_data[8] = 1;
    mft_data[0x10..0x18].copy_from_slice(&0_u64.to_le_bytes());
    mft_data[0x18..0x20].copy_from_slice(&7_u64.to_le_bytes());
    mft_data[0x20..0x22].copy_from_slice(&0x40_u16.to_le_bytes());
    mft_data[0x28..0x30].copy_from_slice(&4096_u64.to_le_bytes());
    mft_data[0x30..0x38].copy_from_slice(&4096_u64.to_le_bytes());
    mft_data[0x38..0x40].copy_from_slice(&4096_u64.to_le_bytes());
    mft_data[0x40..0x44].copy_from_slice(&[0x11, 8, 8, 0]);
    let mut mft_bytes = record(1, 0, &mft_data);
    let mft = MftRecord::parse(&mut mft_bytes, 512).unwrap();

    let base_ref = file_reference(1, 2).unwrap();
    let mut list_attr = [0_u8; 0x38];
    list_attr[0..4].copy_from_slice(&ATTR_ATTRIBUTE_LIST.to_le_bytes());
    list_attr[4..8].copy_from_slice(&0x38_u32.to_le_bytes());
    list_attr[0x10..0x14].copy_from_slice(&0x20_u32.to_le_bytes());
    list_attr[0x14..0x16].copy_from_slice(&0x18_u16.to_le_bytes());
    list_attr[0x18..0x1c].copy_from_slice(&ATTR_DATA.to_le_bytes());
    list_attr[0x1c..0x1e].copy_from_slice(&0x20_u16.to_le_bytes());
    list_attr[0x28..0x30].copy_from_slice(&file_reference(2, 3).unwrap().to_le_bytes());
    list_attr[0x30..0x32].copy_from_slice(&7_u16.to_le_bytes());
    let mut base_bytes = record(2, 0, &list_attr);
    let base = MftRecord::parse(&mut base_bytes, 512).unwrap();

    let mut data_attr = [0_u8; 0x20];
    data_attr[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
    data_attr[4..8].copy_from_slice(&0x20_u32.to_le_bytes());
    data_attr[0x0e..0x10].copy_from_slice(&7_u16.to_le_bytes());
    data_attr[0x10..0x14].copy_from_slice(&5_u32.to_le_bytes());
    data_attr[0x14..0x16].copy_from_slice(&0x18_u16.to_le_bytes());
    data_attr[0x18..0x1d].copy_from_slice(b"hello");
    let ext_bytes = record(3, base_ref, &data_attr);
    let mut image = vec![0_u8; 64 * 1024];
    image[6144..7168].copy_from_slice(&ext_bytes);
    let boot = BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 1,
        cluster_bytes: 512,
        total_sectors: 128,
        mft_lcn: 8,
        mft_mirror_lcn: 16,
        record_bytes: 1024,
        index_block_bytes: 1024,
        serial_number: 0,
    };
    let mut volume = Volume::new(Image(image), boot).unwrap();
    let mut scratch = [0_u8; 1024];
    assert_eq!(volume.data_size_resolved(&mft, &base, 1, &mut scratch).unwrap(), 5);
    let mut output = [0_u8; 5];
    volume.read_data_resolved(&mft, &base, 1, &mut scratch, 0, &mut output).unwrap();
    assert_eq!(&output, b"hello");
    let mut bad = record(2, 0, &list_attr);
    bad[0x66] = 4; // Change extension sequence in the list.
    let bad_base = MftRecord::parse(&mut bad, 512).unwrap();
    assert_eq!(volume.data_size_resolved(&mft, &bad_base, 1, &mut scratch), Err(Error::InvalidAttributeList));
    volume.reader.0[6144 + 0x20] = 3; // Wrong base-record back-reference.
    assert_eq!(volume.data_size_resolved(&mft, &base, 1, &mut scratch), Err(Error::InvalidAttributeList));
}

fn nonresident_data(id: u16, first: u64, lcn: u8, size: u64) -> [u8; 0x48] {
    let mut attr = [0_u8; 0x48];
    attr[0..4].copy_from_slice(&ATTR_DATA.to_le_bytes());
    attr[4..8].copy_from_slice(&0x48_u32.to_le_bytes());
    attr[8] = 1;
    attr[0x0e..0x10].copy_from_slice(&id.to_le_bytes());
    attr[0x10..0x18].copy_from_slice(&first.to_le_bytes());
    attr[0x18..0x20].copy_from_slice(&first.to_le_bytes());
    attr[0x20..0x22].copy_from_slice(&0x40_u16.to_le_bytes());
    attr[0x28..0x30].copy_from_slice(&size.to_le_bytes());
    attr[0x30..0x38].copy_from_slice(&size.to_le_bytes());
    attr[0x38..0x40].copy_from_slice(&size.to_le_bytes());
    attr[0x40..0x44].copy_from_slice(&[0x11, 1, lcn, 0]);
    attr
}

#[test]
fn reads_across_checked_attribute_list_extents() {
    let mft_data = {
        let mut attr = nonresident_data(1, 0, 8, 4096);
        attr[0x18..0x20].copy_from_slice(&7_u64.to_le_bytes());
        attr[0x40..0x44].copy_from_slice(&[0x11, 8, 8, 0]);
        attr
    };
    let mut mft_bytes = record(1, 0, &mft_data);
    let mft = MftRecord::parse(&mut mft_bytes, 512).unwrap();

    let base_ref = file_reference(1, 2).unwrap();
    let mut list = [0_u8; 0x58];
    list[0..4].copy_from_slice(&ATTR_ATTRIBUTE_LIST.to_le_bytes());
    list[4..8].copy_from_slice(&0x58_u32.to_le_bytes());
    list[0x10..0x14].copy_from_slice(&0x40_u32.to_le_bytes());
    list[0x14..0x16].copy_from_slice(&0x18_u16.to_le_bytes());
    for (index, reference, vcn, id) in
        [(0x18, base_ref, 0_u64, 7_u16), (0x38, file_reference(2, 3).unwrap(), 1_u64, 8_u16)]
    {
        list[index..index + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        list[index + 4..index + 6].copy_from_slice(&0x20_u16.to_le_bytes());
        list[index + 8..index + 16].copy_from_slice(&vcn.to_le_bytes());
        list[index + 16..index + 24].copy_from_slice(&reference.to_le_bytes());
        list[index + 24..index + 26].copy_from_slice(&id.to_le_bytes());
    }
    let first = nonresident_data(7, 0, 32, 1024);
    let second = nonresident_data(8, 1, 33, 0);
    let mut base_attributes = Vec::from(list);
    base_attributes.extend_from_slice(&first);
    let mut base_bytes = record(2, 0, &base_attributes);
    let base = MftRecord::parse(&mut base_bytes, 512).unwrap();
    let ext_bytes = record(3, base_ref, &second);
    let mut image = vec![0_u8; 64 * 1024];
    image[6144..7168].copy_from_slice(&ext_bytes);
    image[32 * 512..33 * 512].fill(b'A');
    image[33 * 512..34 * 512].fill(b'B');
    let boot = BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 1,
        cluster_bytes: 512,
        total_sectors: 128,
        mft_lcn: 8,
        mft_mirror_lcn: 16,
        record_bytes: 1024,
        index_block_bytes: 1024,
        serial_number: 0,
    };
    let mut volume = Volume::new(Image(image), boot).unwrap();
    let mut scratch = [0_u8; 1024];
    assert_eq!(volume.data_size_resolved(&mft, &base, 1, &mut scratch).unwrap(), 1024);
    let mut output = [0_u8; 12];
    volume.read_data_resolved(&mft, &base, 1, &mut scratch, 508, &mut output).unwrap();
    assert_eq!(&output, b"AAAABBBBBBBB");

    list[0x38 + 8..0x38 + 16].copy_from_slice(&2_u64.to_le_bytes());
    base_attributes[..list.len()].copy_from_slice(&list);
    let mut bad_base_bytes = record(2, 0, &base_attributes);
    let bad_base = MftRecord::parse(&mut bad_base_bytes, 512).unwrap();
    assert_eq!(
        volume.read_data_resolved(&mft, &bad_base, 1, &mut scratch, 508, &mut output),
        Err(Error::InvalidAttributeList)
    );

    list[0x38 + 8..0x38 + 16].copy_from_slice(&1_u64.to_le_bytes());
    base_attributes[..list.len()].copy_from_slice(&list);
    base_attributes.extend_from_slice(&nonresident_data(9, 2, 34, 0));
    let mut omitted_bytes = record(2, 0, &base_attributes);
    let omitted = MftRecord::parse(&mut omitted_bytes, 512).unwrap();
    assert_eq!(volume.data_size_resolved(&mft, &omitted, 1, &mut scratch), Err(Error::InvalidAttributeList));
}

#[test]
fn accepts_empty_nonresident_stream() {
    let mut attr = nonresident_data(7, 0, 0, 0);
    attr[0x18..0x20].copy_from_slice(&u64::MAX.to_le_bytes());
    attr[0x40] = 0;
    let mut record_bytes = record(2, 0, &attr);
    let record = MftRecord::parse(&mut record_bytes, 512).unwrap();
    let boot = BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 1,
        cluster_bytes: 512,
        total_sectors: 128,
        mft_lcn: 8,
        mft_mirror_lcn: 16,
        record_bytes: 1024,
        index_block_bytes: 1024,
        serial_number: 0,
    };
    let mut volume = Volume::new(Image(vec![0; 64 * 1024]), boot).unwrap();
    let mut scratch = [0_u8; 1024];
    assert_eq!(volume.data_size_resolved(&record, &record, 1, &mut scratch), Ok(0));
    assert_eq!(volume.read_data_resolved(&record, &record, 1, &mut scratch, 0, &mut []), Ok(()));
}

#[test]
#[ignore = "requires SLATE_LEGACY_FAMILY_SOURCE containing a mapped legacy base and a listed DATA continuation"]
fn mapped_legacy_family_requires_the_exact_source_slot() {
    use super::super::mft::record_layout;

    const BASE_RECORD: u64 = 37;
    const LOGICAL_CAPACITY: usize = 4096;
    const WORK_CAPACITY: usize = 8192;

    let path = std::env::var_os("SLATE_LEGACY_FAMILY_SOURCE").unwrap();
    let original = std::fs::read(&path).unwrap();
    let boot = BootSector::parse(&original).unwrap();
    let mut volume = Volume::new(Image(original.clone()), boot).unwrap();
    let mut zero = vec![0; boot.record_bytes as usize];
    volume.read_physical(boot.mft_byte_offset().unwrap(), &mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, boot.bytes_per_sector).unwrap();
    let mut raw = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, BASE_RECORD, &mut raw).unwrap();
    MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let base = MftRecord::from_decoded(&raw).unwrap();
    assert_eq!(base.physical_record_number().unwrap(), None);
    let mut logical = vec![0; LOGICAL_CAPACITY];
    let mut scratch = vec![0; WORK_CAPACITY];
    assert_eq!(volume.resolve_record(&mft, &base, &mut logical, &mut scratch), Err(Error::Unsupported));
    assert_eq!(
        volume.resolve_record_at(&mft, BASE_RECORD + 1, &base, &mut logical, &mut scratch),
        Err(Error::InvalidRecord)
    );
    volume.resolve_record_at(&mft, BASE_RECORD, &base, &mut logical, &mut scratch).unwrap();
    let assembled = MftRecord::from_decoded(&logical).unwrap();
    assert_eq!(assembled.physical_record_number().unwrap(), None);
    assert!(assembled.attributes().all(|attribute| attribute.unwrap().kind != ATTR_ATTRIBUTE_LIST));
    assert!(!assembled.stream(ATTR_DATA, &[]).unwrap().resident_value().unwrap().is_empty());
    let mut changed = raw.clone();
    changed[record_layout::SEQUENCE_OFFSET] ^= 1;
    assert_eq!(
        volume.resolve_record_at(
            &mft,
            BASE_RECORD,
            &MftRecord::from_decoded(&changed).unwrap(),
            &mut logical,
            &mut scratch
        ),
        Err(Error::InvalidRecord)
    );
    assert_eq!(std::fs::read(path).unwrap(), original);
}
