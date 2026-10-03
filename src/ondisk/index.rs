//! Module: ntfs_rs::index
//! Purpose: Parse checked directory index roots, blocks and filename entries.
//! Created: 2026-09-30
//! Architecture: Volume traversal and index editors use these parsers to validate
//!     node framing, child references and fixups. Callers own storage reads,
//!     collation, traversal and publication of changes.

use super::bytes::{range, u16_at, u32_at, u64_at, u8_at};
pub use super::filename::FileName;
use super::filename::{FileNameValue, HEADER_BYTES};
use super::mft::apply_fixups;
use super::{Error, Result};

/// Directory $INDEX_ROOT value, including its 16-byte root header.
pub struct IndexRoot<'a> {
    data: &'a [u8],
    first_entry: usize,
    end: usize,
    has_children: bool,
    index_block_bytes: u32,
    index_block_units: u8,
}

impl<'a> IndexRoot<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x20 || u32_at(data, 0)? != 0x30 || u32_at(data, 4)? != 1 {
            return Err(Error::InvalidIndex);
        }
        let index_block_bytes = u32_at(data, 8)?;
        let index_block_units = u8_at(data, 0x0c)?;
        let flags = u8_at(data, 0x1c)?;
        if flags & !1 != 0 || index_block_bytes < 512 || index_block_units == 0 {
            return Err(Error::InvalidIndex);
        }
        let entry_offset = usize::try_from(u32_at(data, 0x10)?).map_err(|_| Error::Overflow)?;
        let index_length = usize::try_from(u32_at(data, 0x14)?).map_err(|_| Error::Overflow)?;
        let allocated = usize::try_from(u32_at(data, 0x18)?).map_err(|_| Error::Overflow)?;
        if entry_offset < 0x10 || index_length < entry_offset || allocated < index_length {
            return Err(Error::InvalidIndex);
        }
        let first_entry = 0x10_usize.checked_add(entry_offset).ok_or(Error::Overflow)?;
        let end = 0x10_usize.checked_add(index_length).ok_or(Error::Overflow)?;
        let allocation_end = 0x10_usize.checked_add(allocated).ok_or(Error::Overflow)?;
        if end > data.len() || allocation_end > data.len() || first_entry > end {
            return Err(Error::InvalidIndex);
        }
        Ok(Self { data, first_entry, end, has_children: flags & 1 != 0, index_block_bytes, index_block_units })
    }

    pub fn has_children(&self) -> bool {
        self.has_children
    }

    pub fn index_block_bytes(&self) -> u32 {
        self.index_block_bytes
    }

    pub fn vcn_unit_bytes(&self, cluster_bytes: u32) -> Result<u64> {
        let unit = if self.index_block_bytes < cluster_bytes { 512_u32 } else { cluster_bytes };
        if self.index_block_bytes % unit != 0
            || self.index_block_bytes / unit != u32::from(self.index_block_units)
            || !self.index_block_units.is_power_of_two()
        {
            return Err(Error::InvalidIndex);
        }
        Ok(u64::from(unit))
    }

    pub fn first_entry_offset(&self) -> usize {
        self.first_entry
    }

    pub fn slot_at(&self, offset: usize) -> Result<IndexSlot<'a>> {
        parse_slot(self.data, offset, self.end)
    }

    pub fn entries(&self) -> IndexEntries<'a> {
        IndexEntries { data: self.data, cursor: self.first_entry, end: self.end, done: false }
    }
}

/// Caller-owned copy of one $INDEX_ALLOCATION block. Its fixups are applied
/// in place after all sector tails have been verified.
pub struct IndexBlock<'a> {
    data: &'a [u8],
    first_entry: usize,
    end: usize,
    pub vcn: u64,
    has_children: bool,
}

impl<'a> IndexBlock<'a> {
    pub fn parse(data: &'a mut [u8], bytes_per_sector: u16, expected_vcn: u64) -> Result<Self> {
        if data.len() < 512 || range(data, 0, 4)? != b"INDX" {
            return Err(Error::InvalidIndex);
        }
        let entry_offset = usize::try_from(u32_at(data, 0x18)?).map_err(|_| Error::Overflow)?;
        let index_length = usize::try_from(u32_at(data, 0x1c)?).map_err(|_| Error::Overflow)?;
        let allocated = usize::try_from(u32_at(data, 0x20)?).map_err(|_| Error::Overflow)?;
        let first_entry = 0x18_usize.checked_add(entry_offset).ok_or(Error::Overflow)?;
        let end = 0x18_usize.checked_add(index_length).ok_or(Error::Overflow)?;
        let allocation_end = 0x18_usize.checked_add(allocated).ok_or(Error::Overflow)?;
        if entry_offset < 0x10
            || entry_offset % 8 != 0
            || first_entry > end
            || end > allocation_end
            || allocation_end != data.len()
        {
            return Err(Error::InvalidIndex);
        }
        apply_fixups(data, bytes_per_sector, 0x28, first_entry)?;
        let vcn = u64_at(data, 0x10)?;
        if vcn != expected_vcn {
            return Err(Error::InvalidIndex);
        }
        let flags = u8_at(data, 0x24)?;
        if flags & !1 != 0 {
            return Err(Error::InvalidIndex);
        }
        Ok(Self { data, first_entry, end, vcn, has_children: flags & 1 != 0 })
    }

    pub fn has_children(&self) -> bool {
        self.has_children
    }

    pub fn first_entry_offset(&self) -> usize {
        self.first_entry
    }

    pub fn slot_at(&self, offset: usize) -> Result<IndexSlot<'a>> {
        parse_slot(self.data, offset, self.end)
    }

    pub fn entries(&self) -> IndexEntries<'a> {
        IndexEntries { data: self.data, cursor: self.first_entry, end: self.end, done: false }
    }
}

pub struct IndexEntries<'a> {
    data: &'a [u8],
    cursor: usize,
    end: usize,
    done: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct IndexEntry<'a> {
    /// Complete validated FILE_NAME key, including duplicated metadata.
    pub file_name_value: &'a [u8],
    pub file_reference: u64,
    pub flags: u16,
    pub name: FileName<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct IndexSlot<'a> {
    /// None is the terminal entry of a node.
    pub entry: Option<IndexEntry<'a>>,
    pub child_vcn: Option<u64>,
    pub next_offset: usize,
}

fn parse_slot(data: &[u8], cursor: usize, end: usize) -> Result<IndexSlot<'_>> {
    if cursor >= end {
        return Err(Error::InvalidIndex);
    }
    let header = range(data, cursor, 0x10).map_err(|_| Error::InvalidIndex)?;
    let entry_len = usize::from(u16_at(header, 8)?);
    let key_len = usize::from(u16_at(header, 10)?);
    let flags = u16_at(header, 12)?;
    if entry_len < 0x10 || entry_len % 8 != 0 || flags & !3 != 0 {
        return Err(Error::InvalidIndex);
    }
    let next = cursor.checked_add(entry_len).ok_or(Error::Overflow)?;
    if next > end {
        return Err(Error::InvalidIndex);
    }
    let entry = range(data, cursor, entry_len)?;
    let child_vcn = if flags & 1 != 0 {
        if entry_len < 0x18 {
            return Err(Error::InvalidIndex);
        }
        Some(u64_at(entry, entry_len - 8)?)
    } else {
        None
    };
    if flags & 2 != 0 {
        if key_len != 0 || entry_len != if child_vcn.is_some() { 0x18 } else { 0x10 } || next != end {
            return Err(Error::InvalidIndex);
        }
        return Ok(IndexSlot { entry: None, child_vcn, next_offset: next });
    }
    let key_end = entry_len - if child_vcn.is_some() { 8 } else { 0 };
    if key_len < HEADER_BYTES || 0x10 + key_len > key_end {
        return Err(Error::InvalidIndex);
    }
    // Filename entries contain the aligned header, key and optional child VCN.
    // Padding beyond that boundary does not belong to the entry.
    let canonical_length = (0x10 + key_len + if child_vcn.is_some() { 8 } else { 0 } + 7) & !7;
    if entry_len != canonical_length {
        return Err(Error::InvalidIndex);
    }
    let key = range(entry, 0x10, key_len)?;
    let value = FileNameValue::parse_prefix(key).map_err(|_| Error::InvalidIndex)?;
    if value.name.utf16le.is_empty() {
        return Err(Error::InvalidIndex);
    }
    Ok(IndexSlot {
        entry: Some(IndexEntry { file_name_value: key, file_reference: u64_at(header, 0)?, flags, name: value.name }),
        child_vcn,
        next_offset: next,
    })
}

impl<'a> Iterator for IndexEntries<'a> {
    type Item = Result<IndexEntry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match parse_slot(self.data, self.cursor, self.end) {
            Ok(slot) => {
                self.cursor = slot.next_offset;
                if slot.entry.is_none() {
                    self.done = true;
                }
                slot.entry.map(Ok)
            }
            Err(error) => {
                self.done = true;
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_block() -> [u8; 1024] {
        let mut data = [0; 1024];
        data[..4].copy_from_slice(b"INDX");
        data[4..6].copy_from_slice(&0x28_u16.to_le_bytes());
        data[6..8].copy_from_slice(&3_u16.to_le_bytes());
        data[0x18..0x1c].copy_from_slice(&0x20_u32.to_le_bytes());
        data[0x1c..0x20].copy_from_slice(&0x30_u32.to_le_bytes());
        data[0x20..0x24].copy_from_slice(&0x3e8_u32.to_le_bytes());
        data[0x40..0x42].copy_from_slice(&16_u16.to_le_bytes());
        data[0x44..0x46].copy_from_slice(&2_u16.to_le_bytes());
        data[0x28..0x2a].copy_from_slice(&0x1234_u16.to_le_bytes());
        data[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
        data[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
        data
    }

    #[test]
    fn validates_block_capacity_and_aligned_entry_start() {
        let mut valid = leaf_block();
        let block = IndexBlock::parse(&mut valid, 512, 0).unwrap();
        assert!(block.slot_at(block.first_entry_offset()).unwrap().entry.is_none());

        for (offset, value) in [(0x18, 0x21_u32), (0x20, 0x3e0_u32)] {
            let mut invalid = leaf_block();
            invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(IndexBlock::parse(&mut invalid, 512, 0), Err(Error::InvalidIndex)));
        }
    }

    #[test]
    fn checks_terminal_child_framing_without_accepting_unused_entry_bytes() {
        for child in [false, true] {
            let size = if child { 24 } else { 16 };
            let mut terminal = [0; 32];
            terminal[8..10].copy_from_slice(&(size as u16).to_le_bytes());
            terminal[12..14].copy_from_slice(&(2 | u16::from(child)).to_le_bytes());
            assert!(parse_slot(&terminal, 0, size).unwrap().entry.is_none());
            terminal[8..10].copy_from_slice(&((size + 8) as u16).to_le_bytes());
            assert!(matches!(parse_slot(&terminal, 0, size + 8), Err(Error::InvalidIndex)));
            terminal[8..10].copy_from_slice(&(size as u16).to_le_bytes());
            terminal[10..12].copy_from_slice(&2_u16.to_le_bytes());
            assert!(matches!(parse_slot(&terminal, 0, size), Err(Error::InvalidIndex)));
        }
    }

    #[test]
    fn validates_filename_entry_alignment_and_nonempty_name() {
        for child in [false, true] {
            let size = if child { 96 } else { 88 };
            let mut entry = [0; 104];
            entry[8..10].copy_from_slice(&(size as u16).to_le_bytes());
            entry[10..12].copy_from_slice(&68_u16.to_le_bytes());
            entry[12..14].copy_from_slice(&u16::from(child).to_le_bytes());
            entry[80] = 1;
            entry[81] = 1;
            entry[82..84].copy_from_slice(&('A' as u16).to_le_bytes());
            assert_eq!(parse_slot(&entry, 0, size).unwrap().entry.unwrap().name.utf16le, &[65, 0]);
            entry[81] = 5;
            assert_eq!(parse_slot(&entry, 0, size).unwrap().entry.unwrap().name.namespace, 5);
            entry[8..10].copy_from_slice(&((size + 8) as u16).to_le_bytes());
            assert!(matches!(parse_slot(&entry, 0, size + 8), Err(Error::InvalidIndex)));
            entry[8..10].copy_from_slice(&(size as u16).to_le_bytes());
            entry[80] = 0;
            assert!(matches!(parse_slot(&entry, 0, size), Err(Error::InvalidIndex)));
        }
    }

    #[test]
    fn filename_key_suffix_is_retained_outside_the_declared_name() {
        use super::super::bytes::p16;
        use super::super::filename::{CODE_UNIT_BYTES, NAMESPACE_OFFSET, NAME_LENGTH_OFFSET};

        const ENTRY_HEADER_BYTES: usize = 16;
        const ENTRY_ALIGNMENT: usize = 8;
        const CHILD_BYTES: usize = 8;
        const KEY_LENGTH_OFFSET: usize = 10;
        const ENTRY_LENGTH_OFFSET: usize = 8;
        const ENTRY_FLAGS_OFFSET: usize = 12;
        const SUFFIX: [u8; 2] = [0xde, 0xad];
        const KEY_BYTES: usize = HEADER_BYTES + CODE_UNIT_BYTES + SUFFIX.len();

        for child in [false, true] {
            let child_bytes = if child { CHILD_BYTES } else { 0 };
            let entry_bytes =
                (ENTRY_HEADER_BYTES + KEY_BYTES + child_bytes).div_ceil(ENTRY_ALIGNMENT) * ENTRY_ALIGNMENT;
            let mut bytes = std::vec![0; entry_bytes];
            p16(&mut bytes, ENTRY_LENGTH_OFFSET, entry_bytes as u16).unwrap();
            p16(&mut bytes, KEY_LENGTH_OFFSET, KEY_BYTES as u16).unwrap();
            p16(&mut bytes, ENTRY_FLAGS_OFFSET, u16::from(child)).unwrap();
            let key = &mut bytes[ENTRY_HEADER_BYTES..ENTRY_HEADER_BYTES + KEY_BYTES];
            key[NAME_LENGTH_OFFSET] = 1;
            key[NAMESPACE_OFFSET] = u8::MAX;
            key[HEADER_BYTES..HEADER_BYTES + CODE_UNIT_BYTES].copy_from_slice(&u16::from(b'A').to_le_bytes());
            key[HEADER_BYTES + CODE_UNIT_BYTES..].copy_from_slice(&SUFFIX);

            let slot = parse_slot(&bytes, 0, entry_bytes).unwrap();
            let entry = slot.entry.unwrap();
            let name: FileName<'_> = entry.name;
            assert_eq!(name.namespace, u8::MAX);
            assert_eq!(name.code_units().collect::<std::vec::Vec<_>>(), [u16::from(b'A')]);
            assert_eq!(entry.file_name_value.len(), KEY_BYTES);
            assert_eq!(&entry.file_name_value[HEADER_BYTES + CODE_UNIT_BYTES..], &SUFFIX);
            assert_eq!(slot.child_vcn, child.then_some(0));
        }
    }

    #[test]
    fn rejects_out_of_bounds_index() {
        let mut data = [0_u8; 0x20];
        data[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0x10_u32.to_le_bytes());
        data[0x14..0x18].copy_from_slice(&0x100_u32.to_le_bytes());
        data[0x18..0x1c].copy_from_slice(&0x100_u32.to_le_bytes());
        assert!(matches!(IndexRoot::parse(&data), Err(Error::InvalidIndex)));
    }

    #[test]
    fn validates_index_vcn_units_for_small_and_large_blocks() {
        fn root(block_bytes: u32, units: u8) -> [u8; 0x20] {
            let mut data = [0_u8; 0x20];
            data[0..4].copy_from_slice(&0x30_u32.to_le_bytes());
            data[4..8].copy_from_slice(&1_u32.to_le_bytes());
            data[8..12].copy_from_slice(&block_bytes.to_le_bytes());
            data[12] = units;
            data[0x10..0x14].copy_from_slice(&0x10_u32.to_le_bytes());
            data[0x14..0x18].copy_from_slice(&0x10_u32.to_le_bytes());
            data[0x18..0x1c].copy_from_slice(&0x10_u32.to_le_bytes());
            data
        }
        assert_eq!(IndexRoot::parse(&root(1024, 2)).unwrap().vcn_unit_bytes(4096), Ok(512));
        assert_eq!(IndexRoot::parse(&root(8192, 2)).unwrap().vcn_unit_bytes(4096), Ok(4096));
        assert_eq!(IndexRoot::parse(&root(8192, 1)).unwrap().vcn_unit_bytes(4096), Err(Error::InvalidIndex));
    }

    #[test]
    fn rejects_torn_index_block_without_mutation() {
        let mut data = [0_u8; 1024];
        data[0..4].copy_from_slice(b"INDX");
        data[4..6].copy_from_slice(&0x28_u16.to_le_bytes());
        data[6..8].copy_from_slice(&3_u16.to_le_bytes());
        data[0x18..0x1c].copy_from_slice(&0x20_u32.to_le_bytes());
        data[0x1c..0x20].copy_from_slice(&0x30_u32.to_le_bytes());
        data[0x20..0x24].copy_from_slice(&0x3e8_u32.to_le_bytes());
        data[0x28..0x2a].copy_from_slice(&0x1234_u16.to_le_bytes());
        data[0x2a..0x2c].copy_from_slice(&0xabcd_u16.to_le_bytes());
        data[0x2c..0x2e].copy_from_slice(&0xef01_u16.to_le_bytes());
        data[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
        data[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
        data[1022] = 0;
        let before = data;
        assert!(matches!(IndexBlock::parse(&mut data, 512, 0), Err(Error::InvalidFixup)));
        assert_eq!(data, before);
    }
}
