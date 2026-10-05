//! Module: ntfs_rs::attrlist
//! Purpose: Encode and validate attribute-list entries and continuation identities.
//! Created: 2026-10-01
//! Architecture: Volume resolution and Tx family assembly use these entries to locate external
//! attributes.

use super::bytes::{p16, p32, p64, range, u16_at, u32_at, u64_at, u8_at};
use super::filename_metadata::CODE_UNIT_BYTES;
use super::{Error, Result};

const ENTRY_KIND_OFFSET: usize = 0;
const ENTRY_LENGTH_OFFSET: usize = 4;
const ENTRY_NAME_LENGTH_OFFSET: usize = 6;
const ENTRY_NAME_OFFSET_OFFSET: usize = 7;
const ENTRY_VCN_OFFSET: usize = 8;
const ENTRY_REFERENCE_OFFSET: usize = 16;
const ENTRY_ID_OFFSET: usize = 24;
const ENTRY_HEADER_BYTES: usize = 26;
const ENTRY_ALIGNMENT: usize = 8;
/// The smallest entry: its header rounded up to the entry alignment.
pub(crate) const ENTRY_MIN_BYTES: usize = 32;
const MAX_NAME_BYTES: usize = u8::MAX as usize * CODE_UNIT_BYTES;

/// Entries in an NTFS $ATTRIBUTE_LIST value. The caller supplies exactly
/// the data-size bytes, excluding any allocated-space padding.
pub struct AttributeList<'a> {
    data: &'a [u8],
    cursor: usize,
    done: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ListEntry<'a> {
    pub kind: u32,
    pub first_vcn: u64,
    pub file_reference: u64,
    pub attribute_id: u16,
    pub name_utf16le: &'a [u8],
}

impl ListEntry<'_> {
    pub fn encoded_len(&self) -> Result<usize> {
        if self.name_utf16le.len() > MAX_NAME_BYTES {
            return Err(Error::Truncated);
        }
        Ok((ENTRY_HEADER_BYTES + self.name_utf16le.len()).next_multiple_of(ENTRY_ALIGNMENT))
    }

    // Retain raw name bytes; callers own Unicode and family-membership validation.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let size = self.encoded_len()?;
        let entry = out.get_mut(..size).ok_or(Error::Truncated)?;
        entry.fill(0);
        p32(entry, ENTRY_KIND_OFFSET, self.kind)?;
        p16(entry, ENTRY_LENGTH_OFFSET, size as u16)?;
        entry[ENTRY_NAME_LENGTH_OFFSET] = (self.name_utf16le.len() / CODE_UNIT_BYTES) as u8;
        entry[ENTRY_NAME_OFFSET_OFFSET] = ENTRY_HEADER_BYTES as u8;
        p64(entry, ENTRY_VCN_OFFSET, self.first_vcn)?;
        p64(entry, ENTRY_REFERENCE_OFFSET, self.file_reference)?;
        p16(entry, ENTRY_ID_OFFSET, self.attribute_id)?;
        entry[ENTRY_HEADER_BYTES..ENTRY_HEADER_BYTES + self.name_utf16le.len()].copy_from_slice(self.name_utf16le);
        Ok(size)
    }
}

impl<'a> AttributeList<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0, done: false }
    }
}

impl<'a> Iterator for AttributeList<'a> {
    type Item = Result<ListEntry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.cursor == self.data.len() {
            return None;
        }
        let result = (|| {
            let header = range(self.data, self.cursor, ENTRY_HEADER_BYTES).map_err(|_| Error::InvalidAttributeList)?;
            let length = usize::from(u16_at(header, ENTRY_LENGTH_OFFSET)?);
            if length < ENTRY_MIN_BYTES || length % ENTRY_ALIGNMENT != 0 {
                return Err(Error::InvalidAttributeList);
            }
            let entry = range(self.data, self.cursor, length).map_err(|_| Error::InvalidAttributeList)?;
            let chars = usize::from(u8_at(entry, ENTRY_NAME_LENGTH_OFFSET)?);
            let name_offset = usize::from(u8_at(entry, ENTRY_NAME_OFFSET_OFFSET)?);
            let name_bytes = chars.checked_mul(CODE_UNIT_BYTES).ok_or(Error::Overflow)?;
            let name_utf16le = if chars == 0 {
                &[][..]
            } else {
                if name_offset < ENTRY_HEADER_BYTES || name_offset % CODE_UNIT_BYTES != 0 {
                    return Err(Error::InvalidAttributeList);
                }
                range(entry, name_offset, name_bytes).map_err(|_| Error::InvalidAttributeList)?
            };
            self.cursor = self.cursor.checked_add(length).ok_or(Error::Overflow)?;
            Ok(ListEntry {
                kind: u32_at(entry, ENTRY_KIND_OFFSET)?,
                first_vcn: u64_at(entry, ENTRY_VCN_OFFSET)?,
                file_reference: u64_at(entry, ENTRY_REFERENCE_OFFSET)?,
                attribute_id: u16_at(entry, ENTRY_ID_OFFSET)?,
                name_utf16le,
            })
        })();
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

#[cfg(test)]
#[path = "../tests/core/attrlist.rs"]
mod tests;
