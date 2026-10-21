//! Module: writer_lifecycle::security_family
//! Purpose: Exercise shared descriptors whose indexes spill into extension records.
//! Created: 2026-10-21
//! Architecture: Real writer transactions grow $Secure; checked readers must
//! resolve its complete family and reject a stale extension identity.

use super::*;
use ntfs_rs::{
    attrlist::AttributeList,
    file_lifecycle::NodeKind,
    mft::{record_layout, reference_number, system_record, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_DATA, ATTR_INDEX_ROOT},
    security::{SecurityDescriptor, MAX_STORED_DESCRIPTOR},
    security_writer::{SecurityPolicy, SecurityPrivileges, SECURITY_SCRATCH_BYTES},
    volume::Volume,
};

const OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
const GROUP_PREFIX: [u8; 12] = [1, 2, 0, 0, 0, 0, 0, 22, 2, 0, 0, 0];
const DESCRIPTOR_ATTEMPTS: u32 = 32;
const DESCRIPTOR_BUFFER_BYTES: usize = 512;
const ROOT_SEQUENCE: u64 = 5;
const FILE_MODE: u16 = 0o100600;
const REPLACEMENT_MODE: u16 = 0o100640;

struct Administrator;

impl SecurityPolicy for Administrator {
    fn allowed(&self, _: SecurityDescriptor<'_>, _: u32) -> Result<bool> {
        Ok(true)
    }

    fn user_sid(&self) -> Result<&[u8]> {
        Ok(&OWNER)
    }

    fn privileges(&self) -> SecurityPrivileges {
        SecurityPrivileges { security: true, restore: true, take_ownership: true, integrity: 0 }
    }
}

fn descriptor(image: &mut Image, boot: BootSector, reference: u64) -> Result<Vec<u8>> {
    let mut volume = Volume::new(image, boot)?;
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mft = volume.load_mft(&mut zero)?;
    let mut raw = vec![0; record_of(boot)];
    volume.read_mft_record(&mft, reference_number(reference), &mut raw)?;
    let file = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
    let mut secure = vec![0; record_of(boot)];
    let mut work = vec![0; ntfs_rs::security_store::descriptor_scratch_bytes(boot.index_block_bytes as usize)];
    let mut result = vec![0; MAX_STORED_DESCRIPTOR + ntfs_rs::security::SDS_HEADER_BYTES];
    ntfs_rs::security_store::read_descriptor(&mut volume, &mft, &file, &mut secure, &mut work, &mut result)
        .map(|descriptor| descriptor.raw().to_vec())
}

fn external_index(image: &mut Image, boot: BootSector) -> Option<u64> {
    let mut volume = Volume::new(image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mft = volume.load_mft(&mut zero).unwrap();
    let mut raw = vec![0; record_of(boot)];
    volume.read_mft_record(&mft, system_record::SECURE, &mut raw).unwrap();
    let secure = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let list = secure.attributes().map(Result::unwrap).find(|attribute| attribute.kind == ATTR_ATTRIBUTE_LIST)?;
    let mut bytes = vec![0; list.data_size().unwrap() as usize];
    volume.read_attribute(list, 0, &mut bytes).unwrap();
    AttributeList::new(&bytes).map(Result::unwrap).find_map(|entry| {
        (entry.kind == ATTR_INDEX_ROOT && reference_number(entry.file_reference) != system_record::SECURE)
            .then_some(entry.file_reference)
    })
}

#[test]
fn shared_descriptor_indexes_in_extension_records() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    let (mut image, path, boot) = open_copy(&source, "security-family");
    let mut scratch = vec![0; SECURITY_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let root = (ROOT_SEQUENCE << ntfs_rs::mft::FILE_REFERENCE_SEQUENCE_SHIFT) | system_record::ROOT;
    let file = writer
        .create_node(&mut image, root, "security-family", NodeKind::File, &NULL_DACL, 0, None, &[], &mut scratch)
        .unwrap();
    let mut extension = None;
    for identity in 0..DESCRIPTOR_ATTEMPTS {
        let mut group = GROUP_PREFIX.to_vec();
        group.extend_from_slice(&identity.to_le_bytes());
        let mut bytes = [0; DESCRIPTOR_BUFFER_BYTES];
        let length =
            ntfs_rs::security_create::descriptor(&NULL_DACL, &OWNER, &group, FILE_MODE, false, &mut bytes).unwrap();
        writer.set_security(&mut image, file, &bytes[..length], &Administrator, &mut scratch).unwrap();
        writer.drain(&mut image, &mut scratch).unwrap();
        assert_eq!(descriptor(&mut image, boot, file).unwrap(), bytes[..length]);
        extension = external_index(&mut image, boot);
        if extension.is_some() {
            // A second update must authorize against the external shared index too.
            writer.set_owner(&mut image, file, Some(&OWNER), Some(&group), &Administrator, &mut scratch).unwrap();
            let length =
                ntfs_rs::security_create::descriptor(&NULL_DACL, &OWNER, &group, REPLACEMENT_MODE, false, &mut bytes)
                    .unwrap();
            writer.set_security(&mut image, file, &bytes[..length], &Administrator, &mut scratch).unwrap();
            writer.drain(&mut image, &mut scratch).unwrap();
            assert_eq!(descriptor(&mut image, boot, file).unwrap(), bytes[..length]);
            break;
        }
    }
    let extension = extension.expect("fixture must spill a shared security index");
    writer.finish(&mut image, &mut scratch).unwrap();
    let mut volume = Volume::new(&mut image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(record_of(boot))];
    let mft = volume.load_mft(&mut zero).unwrap();
    let data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    let mut spans = Vec::new();
    ntfs_rs::write_plan::plan_nonresident_overwrite(
        data,
        boot,
        reference_number(extension) * u64::from(boot.record_bytes),
        u64::from(boot.record_bytes),
        |span| {
            spans.push(span);
            Ok(())
        },
    )
    .unwrap();
    let mut raw = vec![0; record_of(boot)];
    volume.read_mft_record(&mft, reference_number(extension), &mut raw).unwrap();
    drop(volume);
    MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let original = raw.clone();
    ntfs_rs::bytes::p64(&mut raw, record_layout::BASE_REFERENCE_OFFSET, file).unwrap();
    ntfs_rs::replay::protect_mft_record(&mut raw, boot.bytes_per_sector).unwrap();
    for span in &spans {
        let start = span.source_offset as usize;
        image.write_at(span.physical_offset, &raw[start..start + span.length as usize]).unwrap();
    }
    assert_eq!(descriptor(&mut image, boot, file), Err(Error::InvalidAttributeList));
    let mut raw = original;
    let stale = ntfs_rs::mft::reference_sequence(extension).checked_add(1).unwrap();
    ntfs_rs::bytes::p16(&mut raw, record_layout::SEQUENCE_OFFSET, stale).unwrap();
    ntfs_rs::replay::protect_mft_record(&mut raw, boot.bytes_per_sector).unwrap();
    for span in &spans {
        let start = span.source_offset as usize;
        image.write_at(span.physical_offset, &raw[start..start + span.length as usize]).unwrap();
    }
    assert_eq!(descriptor(&mut image, boot, file), Err(Error::InvalidAttributeList));
    drop(image);
    std::fs::remove_file(path).unwrap();
}
