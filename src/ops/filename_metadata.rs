//! Module: ntfs_rs::filename_metadata
//! Purpose: Decode FILE_NAME values and keep indexed filename metadata consistent.
//! Created: 2026-10-01
//! Architecture: Index readers, namespace editors and offline recovery share
//! borrowed views and layout constants here, retaining their own naming policy.
//! Tx uses the metadata encoder and updates attributes and parent index entries
//! together before family packing; record editors and the journal publish them.

use super::bytes::{u16_at, u32_at, u64_at};
use super::index_tree::{directory_entry, IndexKind};
use super::mft::reference_number;
use super::mft::{MftRecord, ATTR_DATA};
use super::record_edit;
use super::runlist::DataRuns;
use super::tx::{Tx, MAX_RECORDS, R_DIRTY, R_USED, SKIP_FILENAME_REFRESH};
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

pub const PARENT_REFERENCE_OFFSET: usize = 0;
pub const DUPLICATED_INFORMATION_OFFSET: usize = 8;
pub const DUPLICATED_INFORMATION_BYTES: usize = 56;
pub const NAME_LENGTH_OFFSET: usize = DUPLICATED_INFORMATION_OFFSET + DUPLICATED_INFORMATION_BYTES;
pub const NAMESPACE_OFFSET: usize = NAME_LENGTH_OFFSET + 1;
pub const HEADER_BYTES: usize = NAMESPACE_OFFSET + 1;
pub const CODE_UNIT_BYTES: usize = core::mem::size_of::<u16>();
pub const MAX_NAME_BYTES: usize = u8::MAX as usize * CODE_UNIT_BYTES;
pub const MAX_VALUE_BYTES: usize = HEADER_BYTES + MAX_NAME_BYTES;
pub const POSIX: u8 = 0;
pub const WIN32: u8 = 1;
pub const DOS: u8 = 2;
pub const WIN32_AND_DOS: u8 = WIN32 | DOS;

#[derive(Clone, Copy, Debug)]
pub struct FileName<'a> {
    /// Retain the raw byte; its low two bits identify the namespace class.
    pub namespace: u8,
    pub utf16le: &'a [u8],
}

impl FileName<'_> {
    pub fn code_units(&self) -> impl Iterator<Item = u16> + '_ {
        super::bytes::units(&self.utf16le)
    }
}

/// A framed attribute or index key. Cached information is retained byte for byte;
/// parsing it does not establish that the cache is current or needs a repair.
#[derive(Clone, Copy, Debug)]
pub struct FileNameValue<'a> {
    pub parent_reference: u64,
    pub duplicated_information: &'a [u8; DUPLICATED_INFORMATION_BYTES],
    pub name: FileName<'a>,
}

impl<'a> FileNameValue<'a> {
    /// Attribute values must contain exactly the declared number of code units.
    /// Empty names and raw namespace bits remain a caller's policy decision.
    pub fn parse(value: &'a [u8]) -> Result<Self> {
        let parsed = Self::parse_prefix(value)?;
        if value.len() != HEADER_BYTES + parsed.name.utf16le.len() {
            return Err(Error::InvalidAttribute);
        }
        Ok(parsed)
    }

    /// Index readers may accept suffix bytes inside an already-framed key.
    /// Only the declared name is exposed; index framing validates its container.
    pub fn parse_prefix(value: &'a [u8]) -> Result<Self> {
        let header = value.get(..HEADER_BYTES).ok_or(Error::InvalidAttribute)?;
        let name_bytes = usize::from(header[NAME_LENGTH_OFFSET]) * CODE_UNIT_BYTES;
        let utf16le = value.get(HEADER_BYTES..HEADER_BYTES + name_bytes).ok_or(Error::InvalidAttribute)?;
        let duplicated_information = header[DUPLICATED_INFORMATION_OFFSET..NAME_LENGTH_OFFSET]
            .try_into()
            .map_err(|_| Error::InvalidAttribute)?;
        Ok(Self {
            parent_reference: u64_at(header, PARENT_REFERENCE_OFFSET)?,
            duplicated_information,
            name: FileName { namespace: header[NAMESPACE_OFFSET], utf16le },
        })
    }
}

/// Encode the NTFS duplicated-information payload from an assembled family.
/// Sparse allocation counts physical clusters, and resident allocation rounds
/// the value to eight bytes rather than charging an entire disk cluster.
pub fn duplicated_information<R: ReadAt>(
    volume: &mut Volume<R>,
    record: &MftRecord<'_>,
) -> Result<[u8; DUPLICATED_INFORMATION_BYTES]> {
    let si = record.local_attribute(0x10, &[])?.ok_or(Error::InvalidAttribute)?;
    let si = si.resident_value()?;
    if !matches!(si.len(), super::std_info::LEGACY_BYTES | super::std_info::CURRENT_BYTES) {
        return Err(Error::Unsupported);
    }
    let mut info = [0; DUPLICATED_INFORMATION_BYTES];
    info[..32].copy_from_slice(&si[..32]);
    let mut flags = u32_at(si, 32)?;
    let record_flags = record.flags()?;
    if record_flags & 2 != 0 {
        flags |= 0x1000_0000;
    }
    if record_flags & 8 != 0 {
        flags |= 0x2000_0000;
    }
    info[48..52].copy_from_slice(&flags.to_le_bytes());
    if let Some(data) = record.local_attribute(ATTR_DATA, &[])? {
        let size = data.data_size()?;
        let allocated = if !data.nonresident {
            size.checked_add(7).ok_or(Error::Overflow)? & !7
        } else if data.flags()? & 0x80ff != 0 {
            let mut clusters = 0_u64;
            for run in DataRuns::new(data.data_runs()?, data.first_vcn()?) {
                let run = run?;
                if run.lcn.is_some() {
                    clusters = clusters.checked_add(run.len).ok_or(Error::Overflow)?;
                }
            }
            clusters.checked_mul(u64::from(volume.boot.cluster_bytes)).ok_or(Error::Overflow)?
        } else {
            data.allocated_size()?
        };
        info[32..40].copy_from_slice(&allocated.to_le_bytes());
        info[40..48].copy_from_slice(&size.to_le_bytes());
    }
    if let Some(reparse) = record.local_attribute(0xc0, &[])? {
        volume.read_attribute(reparse, 0, &mut info[52..56])?;
    } else if let Some(ea) = record.local_attribute(super::ea::EA_INFO, &[])? {
        let ea = ea.resident_value()?;
        if ea.len() != 8 {
            return Err(Error::InvalidAttribute);
        }
        let packed = u16_at(ea, 0)?;
        info[52..54].copy_from_slice(&packed.to_le_bytes());
        if let Some(extra) = u32_at(ea, 4)?.checked_sub(u32::from(packed)).and_then(|n| u16::try_from(n).ok()) {
            info[54..56].copy_from_slice(&extra.to_le_bytes());
        }
    }
    Ok(info)
}

impl Tx<'_> {
    /// Refresh original dirty base families only. Loading and editing parents
    /// must not recursively refresh their own parents during the same commit.
    pub(crate) fn refresh_file_names<R: ReadAt>(&mut self, volume: &mut Volume<R>) -> Result<()> {
        let mut dirty = 0_u16;
        for slot in 0..MAX_RECORDS {
            if self.rec_slot(slot)[24] & (R_USED | R_DIRTY) == (R_USED | R_DIRTY)
                && self.record_number(slot) >= 16
                && self.rec_slot(slot)[SKIP_FILENAME_REFRESH] == 0
                && !self.preserved_family(slot)
                && u64_at(self.record(slot), 32)? == 0
                && u16_at(self.record(slot), 22)? & 1 != 0
            {
                dirty |= 1 << slot;
            }
        }
        for slot in 0..MAX_RECORDS {
            if dirty & (1 << slot) == 0 {
                continue;
            }
            let record = MftRecord::from_decoded(self.record(slot))?;
            let info = duplicated_information(volume, &record)?;
            let reference = self.record_number(slot) | u64::from(record.sequence_number()?) << 48;
            let mut next = usize::from(u16_at(self.record(slot), 20)?);
            loop {
                let mut name = [0_u8; MAX_VALUE_BYTES];
                let found = MftRecord::from_decoded(self.record(slot))?.attributes().find_map(|a| match a {
                    Ok(a) if a.kind == 0x30 && a.record_offset() >= next => Some(Ok(a)),
                    Err(e) => Some(Err(e)),
                    _ => None,
                });
                let Some(attr) = found else { break };
                let attr = attr?;
                let at = attr.record_offset();
                next = at + attr.raw().len();
                let value = attr.resident_value()?;
                let parsed = FileNameValue::parse(value)?;
                if parsed.duplicated_information == &info {
                    continue;
                }
                let length = value.len();
                name[..length].copy_from_slice(value);
                name[DUPLICATED_INFORMATION_OFFSET..NAME_LENGTH_OFFSET].copy_from_slice(&info);
                let parent = parsed.parent_reference;
                if reference_number(parent) == self.record_number(slot) {
                    return Err(Error::InvalidIndex);
                }
                // Validate the indexed identity before modifying either copy.
                // Updating the payload in place retains ordering and children.
                let owner = self.load_family(volume, parent)?;
                self.load_upcase(volume)?;
                let tree = self.open_tree(owner, IndexKind::Directory)?;
                directory_entry(reference, &name[..length], self.temp_mut(0))?;
                self.tree_update_filename(volume, &tree, 0, reference, &info)?;
                let offset = record_edit::resident_value_offset(self.record(slot), at)?;
                self.record_mut(slot)[offset + DUPLICATED_INFORMATION_OFFSET..offset + NAME_LENGTH_OFFSET]
                    .copy_from_slice(&info);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value() -> [u8; HEADER_BYTES + CODE_UNIT_BYTES] {
        let mut value = [0; HEADER_BYTES + CODE_UNIT_BYTES];
        value[..DUPLICATED_INFORMATION_OFFSET].copy_from_slice(&u64::MAX.to_le_bytes());
        value[DUPLICATED_INFORMATION_OFFSET..NAME_LENGTH_OFFSET].fill(0xa5);
        value[NAME_LENGTH_OFFSET] = 1;
        value[NAMESPACE_OFFSET] = 0xff;
        value[HEADER_BYTES..].copy_from_slice(&0xd800_u16.to_le_bytes());
        value
    }

    #[test]
    fn views_preserve_reference_cache_namespace_and_raw_code_units() {
        let bytes = value();
        let parsed = FileNameValue::parse(&bytes).unwrap();
        assert_eq!(parsed.parent_reference, u64::MAX);
        assert_eq!(parsed.duplicated_information, &[0xa5; DUPLICATED_INFORMATION_BYTES]);
        assert_eq!(parsed.name.namespace, 0xff);
        assert_eq!(parsed.name.code_units().collect::<std::vec::Vec<_>>(), [0xd800]);
        assert_eq!(parsed.name.utf16le.as_ptr(), bytes[HEADER_BYTES..].as_ptr());
    }

    #[test]
    fn every_truncated_header_or_declared_name_is_rejected() {
        let bytes = value();
        for length in 0..bytes.len() {
            assert!(matches!(FileNameValue::parse_prefix(&bytes[..length]), Err(Error::InvalidAttribute)));
            assert!(matches!(FileNameValue::parse(&bytes[..length]), Err(Error::InvalidAttribute)));
        }
    }

    #[test]
    fn exact_and_prefix_parsers_keep_container_policies_separate() {
        let mut bytes = value().to_vec();
        bytes.push(0xee);
        assert!(FileNameValue::parse_prefix(&bytes).is_ok());
        assert!(matches!(FileNameValue::parse(&bytes), Err(Error::InvalidAttribute)));
        bytes[NAME_LENGTH_OFFSET] = 0;
        assert!(FileNameValue::parse(&bytes[..HEADER_BYTES]).unwrap().name.utf16le.is_empty());
        bytes.resize(MAX_VALUE_BYTES, 0);
        bytes[NAME_LENGTH_OFFSET] = u8::MAX;
        assert_eq!(FileNameValue::parse(&bytes).unwrap().name.utf16le.len(), MAX_NAME_BYTES);
        bytes.push(0);
        assert!(matches!(FileNameValue::parse(&bytes), Err(Error::InvalidAttribute)));
    }
}
