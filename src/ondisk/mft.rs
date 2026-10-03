//! Module: ntfs_rs::mft
//! Purpose: Validate MFT records, file references, attribute framing and fixups.
//! Created: 2026-09-30
//! Architecture: Volume readers and metadata editors use these checked record
//!     views. This module owns local parsing; family resolution, runlist reads
//!     and durable publication belong to their respective callers.

use super::bytes::{range, range_mut, u16_at, u32_at, u64_at, u8_at};
use super::runlist::DataRuns;
use super::{Error, Result};

pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_OBJECT_ID: u32 = 0x40;
pub const ATTR_VOLUME_NAME: u32 = 0x60;
pub const ATTR_LOGGED_UTILITY_STREAM: u32 = 0x100;
pub const ATTR_SECURITY_DESCRIPTOR: u32 = 0x50;
pub const ATTR_INDEX_ROOT: u32 = 0x90;
pub const ATTR_INDEX_ALLOCATION: u32 = 0xa0;
pub const ATTR_BITMAP: u32 = 0xb0;
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTRIBUTE_TYPE_ALIGNMENT: u32 = 0x10;

/// Byte layout shared by checked attribute parsers and recovery encoders.
pub mod attribute_layout {

    pub const ALIGNMENT: usize = core::mem::size_of::<u64>();
    pub const TYPE_OFFSET: usize = 0;
    pub const LENGTH_OFFSET: usize = 4;
    pub const NONRESIDENT_OFFSET: usize = 8;
    pub const NAME_LENGTH_OFFSET: usize = 9;
    pub const NAME_OFFSET_OFFSET: usize = 10;
    pub const FLAGS_OFFSET: usize = 12;
    pub const ID_OFFSET: usize = 14;
    pub const ID_END: usize = ID_OFFSET + core::mem::size_of::<u16>();
    pub const FIRST_VCN_OFFSET: usize = 16;
    pub const LAST_VCN_OFFSET: usize = 24;
    pub const MAPPING_PAIRS_OFFSET: usize = 32;
    pub const COMPRESSION_UNIT_OFFSET: usize = 34;
    pub const ALLOCATED_SIZE_OFFSET: usize = 40;
    pub const DATA_SIZE_OFFSET: usize = 48;
    pub const INITIALIZED_SIZE_OFFSET: usize = 56;
    pub const SIZE_FIELDS_END: usize = INITIALIZED_SIZE_OFFSET + core::mem::size_of::<u64>();
    pub const COMPRESSED_SIZE_OFFSET: usize = SIZE_FIELDS_END;
    pub const EXTENDED_HEADER_BYTES: usize = COMPRESSED_SIZE_OFFSET + core::mem::size_of::<u64>();
    pub const NO_FLAGS: u16 = 0;
    pub const COMPRESSED: u16 = 0x0001;
    pub const ENCRYPTED: u16 = 0x4000;
    pub const SPARSE: u16 = 0x8000;
}

/// FILE header layout, independent of the volume's record-size geometry.
pub mod record_layout {

    pub const SIGNATURE_BYTES: usize = 4;
    pub const USA_OFFSET: usize = 4;
    /// NTFS 1.x records start the USA here and carry no record-number field;
    /// NTFS 3.1 records start it after the 48-byte header.
    pub const LEGACY_USA: u16 = 0x2a;
    pub const CURRENT_USA: u16 = 0x30;
    pub const USA_COUNT_OFFSET: usize = 6;
    pub const LSN_OFFSET: usize = 8;
    pub const LSN_END: usize = LSN_OFFSET + core::mem::size_of::<u64>();
    pub const SEQUENCE_OFFSET: usize = 16;
    pub const SEQUENCE_END: usize = SEQUENCE_OFFSET + core::mem::size_of::<u16>();
    pub const LINK_COUNT_OFFSET: usize = 18;
    pub const FIRST_ATTRIBUTE_OFFSET: usize = 20;
    pub const FLAGS_OFFSET: usize = 22;
    pub const USED_OFFSET: usize = 24;
    pub const CAPACITY_OFFSET: usize = 28;
    pub const BASE_REFERENCE_OFFSET: usize = 32;
    pub const BASE_REFERENCE_END: usize = BASE_REFERENCE_OFFSET + core::mem::size_of::<u64>();
    pub const NEXT_ATTRIBUTE_ID_OFFSET: usize = 40;
    pub const NUMBER_HIGH_OFFSET: usize = 42;
    pub const NUMBER_LOW_OFFSET: usize = 44;
    pub const HEADER_BYTES: usize = NUMBER_LOW_OFFSET + core::mem::size_of::<u32>();
    pub const NUMBER_HIGH_SHIFT: u32 = u32::BITS;
    /// The attribute end marker and its padding to the next alignment.
    pub const END_MARKER: u32 = u32::MAX;
    pub const END_MARKER_BYTES: usize = 8;
    pub const IN_USE: u16 = 1;
    pub const DIRECTORY: u16 = 2;
    pub const KNOWN_FLAGS: u16 = 0x000f;
}

/// The shared historical AttrDef profile used to create and reconstruct volumes.
/// Callers choose row storage and preserve any separately validated custom rows.
pub mod attribute_definition {
    use super::{
        ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA, ATTR_FILE_NAME, ATTR_INDEX_ALLOCATION, ATTR_INDEX_ROOT,
        ATTR_LOGGED_UTILITY_STREAM, ATTR_OBJECT_ID, ATTR_SECURITY_DESCRIPTOR, ATTR_STANDARD_INFORMATION,
        ATTR_VOLUME_NAME,
    };

    pub const ROW_BYTES: usize = 160;
    pub const NAME_BYTES: usize = 128;
    pub const TYPE_OFFSET: usize = NAME_BYTES;
    pub const FLAGS_OFFSET: usize = 140;
    pub const MINIMUM_OFFSET: usize = FLAGS_OFFSET + core::mem::size_of::<u32>();
    pub const MAXIMUM_OFFSET: usize = MINIMUM_OFFSET + core::mem::size_of::<i64>();
    pub const TYPE_ALIGNMENT: u32 = super::ATTRIBUTE_TYPE_ALIGNMENT;
    pub const UNBOUNDED: i64 = -1;
    pub const STANDARD_COUNT: usize = 15;
    pub const STANDARD_STREAM_BYTES: usize = (STANDARD_COUNT + 1) * ROW_BYTES;

    const RESIDENT_ONLY: u32 = 0x40;
    const NONRESIDENT_ONLY: u32 = 0x80;
    const INDEXED: u32 = 2;
    const STANDARD_INFORMATION_LEGACY_BYTES: i64 = 48;
    const STANDARD_INFORMATION_MODERN_BYTES: i64 = 72;
    const MINIMUM_FILENAME_BYTES: i64 =
        (super::super::filename_metadata::HEADER_BYTES + super::super::filename_metadata::CODE_UNIT_BYTES) as i64;
    // This historical profile differs from the parser's maximum framed value.
    const HISTORICAL_FILENAME_LIMIT: i64 = 578;
    const SMALL_VALUE_LIMIT: i64 = 256;
    const VOLUME_INFORMATION_BYTES: i64 = 12;
    const EA_INFORMATION_BYTES: i64 = 8;
    const SMALL_STREAM_LIMIT: i64 = 64 * 1024;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AttributeDefinition {
        name: &'static str,
        kind: u32,
        flags: u32,
        minimum_bytes: i64,
        maximum_bytes: i64,
    }

    impl AttributeDefinition {
        const fn new(name: &'static str, kind: u32, flags: u32, minimum_bytes: i64, maximum_bytes: i64) -> Self {
            Self { name, kind, flags, minimum_bytes, maximum_bytes }
        }

        pub fn kind(&self) -> u32 {
            self.kind
        }

        // Construction stays private: every standard name fits the fixed name
        // field, and numeric limits are the shared historical format profile.
        pub fn encode(&self) -> [u8; ROW_BYTES] {
            let mut row = [0; ROW_BYTES];
            for (index, unit) in self.name.encode_utf16().enumerate() {
                let start = index * core::mem::size_of::<u16>();
                row[start..start + core::mem::size_of::<u16>()].copy_from_slice(&unit.to_le_bytes());
            }
            row[TYPE_OFFSET..TYPE_OFFSET + core::mem::size_of::<u32>()].copy_from_slice(&self.kind.to_le_bytes());
            row[FLAGS_OFFSET..MINIMUM_OFFSET].copy_from_slice(&self.flags.to_le_bytes());
            row[MINIMUM_OFFSET..MAXIMUM_OFFSET].copy_from_slice(&self.minimum_bytes.to_le_bytes());
            row[MAXIMUM_OFFSET..ROW_BYTES].copy_from_slice(&self.maximum_bytes.to_le_bytes());
            row
        }
    }

    pub const STANDARD: [AttributeDefinition; STANDARD_COUNT] = [
        AttributeDefinition::new(
            "$STANDARD_INFORMATION",
            ATTR_STANDARD_INFORMATION,
            RESIDENT_ONLY,
            STANDARD_INFORMATION_LEGACY_BYTES,
            STANDARD_INFORMATION_MODERN_BYTES,
        ),
        AttributeDefinition::new("$ATTRIBUTE_LIST", ATTR_ATTRIBUTE_LIST, NONRESIDENT_ONLY, 0, UNBOUNDED),
        AttributeDefinition::new(
            "$FILE_NAME",
            ATTR_FILE_NAME,
            RESIDENT_ONLY | INDEXED,
            MINIMUM_FILENAME_BYTES,
            HISTORICAL_FILENAME_LIMIT,
        ),
        AttributeDefinition::new("$OBJECT_ID", ATTR_OBJECT_ID, RESIDENT_ONLY, 0, SMALL_VALUE_LIMIT),
        AttributeDefinition::new("$SECURITY_DESCRIPTOR", ATTR_SECURITY_DESCRIPTOR, NONRESIDENT_ONLY, 0, UNBOUNDED),
        AttributeDefinition::new(
            "$VOLUME_NAME",
            ATTR_VOLUME_NAME,
            RESIDENT_ONLY,
            super::super::filename_metadata::CODE_UNIT_BYTES as i64,
            SMALL_VALUE_LIMIT,
        ),
        AttributeDefinition::new(
            "$VOLUME_INFORMATION",
            super::super::volume_info::ATTR_VOLUME_INFORMATION,
            RESIDENT_ONLY,
            VOLUME_INFORMATION_BYTES,
            VOLUME_INFORMATION_BYTES,
        ),
        AttributeDefinition::new("$DATA", ATTR_DATA, 0, 0, UNBOUNDED),
        AttributeDefinition::new("$INDEX_ROOT", ATTR_INDEX_ROOT, RESIDENT_ONLY, 0, UNBOUNDED),
        AttributeDefinition::new("$INDEX_ALLOCATION", ATTR_INDEX_ALLOCATION, NONRESIDENT_ONLY, 0, UNBOUNDED),
        AttributeDefinition::new("$BITMAP", ATTR_BITMAP, NONRESIDENT_ONLY, 0, UNBOUNDED),
        AttributeDefinition::new(
            "$REPARSE_POINT",
            super::super::reparse::ATTR_REPARSE,
            NONRESIDENT_ONLY,
            0,
            super::super::reparse::MAX_CREATE as i64,
        ),
        AttributeDefinition::new(
            "$EA_INFORMATION",
            super::super::ea::EA_INFO,
            RESIDENT_ONLY,
            EA_INFORMATION_BYTES,
            EA_INFORMATION_BYTES,
        ),
        AttributeDefinition::new("$EA", super::super::ea::EA, 0, 0, SMALL_STREAM_LIMIT),
        AttributeDefinition::new(
            "$LOGGED_UTILITY_STREAM",
            ATTR_LOGGED_UTILITY_STREAM,
            NONRESIDENT_ONLY,
            0,
            SMALL_STREAM_LIMIT,
        ),
    ];
}

/// Fixed MFT record numbers of the NTFS system files.
pub mod system_record {
    pub const MFT: u64 = 0;
    pub const MFT_MIRROR: u64 = 1;
    pub const LOG: u64 = 2;
    pub const VOLUME: u64 = 3;
    pub const ATTRDEF: u64 = 4;
    pub const ROOT: u64 = 5;
    pub const BITMAP: u64 = 6;
    pub const BOOT: u64 = 7;
    pub const BADCLUS: u64 = 8;
    pub const SECURE: u64 = 9;
    pub const UPCASE: u64 = 10;
    pub const EXTEND: u64 = 11;
    /// Records copied to $MFTMirr, and records reserved for system metadata.
    pub const MIRRORED: u64 = 4;
    pub const RESERVED: u64 = 16;
}

pub const FILE_REFERENCE_NUMBER_MASK: u64 = 0x0000_ffff_ffff_ffff;
pub const FILE_REFERENCE_SEQUENCE_SHIFT: u32 = 48;

/// Extract identity fields without imposing a caller's sequence admission policy.
pub const fn reference_number(reference: u64) -> u64 {
    reference & FILE_REFERENCE_NUMBER_MASK
}

pub const fn reference_sequence(reference: u64) -> u16 {
    (reference >> FILE_REFERENCE_SEQUENCE_SHIFT) as u16
}

/// Pack a representable record number. Zero sequence remains valid for discovery.
/// Sequence number a reused record slot receives; zero is never issued.
pub fn next_sequence(record: &[u8]) -> Result<u16> {
    Ok(u16_at(record, record_layout::SEQUENCE_OFFSET)?.wrapping_add(1).max(1))
}

pub fn file_reference(number: u64, sequence: u16) -> Result<u64> {
    if number > FILE_REFERENCE_NUMBER_MASK {
        return Err(Error::InvalidRecord);
    }
    Ok(number | (u64::from(sequence) << FILE_REFERENCE_SEQUENCE_SHIFT))
}

pub struct MftRecord<'a> {
    data: &'a [u8],
    first_attribute: usize,
    bytes_used: usize,
}

impl<'a> MftRecord<'a> {
    /// Applies the NTFS update sequence array to a caller-owned record copy.
    /// Never call this on a shared or mapped disk buffer.
    pub fn parse(data: &'a mut [u8], bytes_per_sector: u16) -> Result<Self> {
        if bytes_per_sector < 512
            || !bytes_per_sector.is_power_of_two()
            || data.len() < 512
            || data.len() % usize::from(bytes_per_sector) != 0
        {
            return Err(Error::InvalidRecord);
        }
        if range(data, 0, 4)? != b"FILE" {
            return Err(Error::InvalidRecord);
        }
        let first_attribute = usize::from(u16_at(data, 0x14)?);
        let usa = u16_at(data, record_layout::USA_OFFSET)?;
        let minimum_usa = usize::from(if usa == record_layout::LEGACY_USA { usa } else { record_layout::CURRENT_USA });
        apply_fixups(data, bytes_per_sector, minimum_usa, first_attribute)?;
        Self::from_decoded(data)
    }

    /// A caller-owned record whose USA has already been validated and decoded.
    /// This validates structure only; it must never replace on-disk fixup checks.
    pub fn from_decoded(data: &'a [u8]) -> Result<Self> {
        if range(data, 0, 4)? != b"FILE" {
            return Err(Error::InvalidRecord);
        }
        let first_attribute = usize::from(u16_at(data, 0x14)?);
        let bytes_used = usize::try_from(u32_at(data, 0x18)?).map_err(|_| Error::Overflow)?;
        if first_attribute < 0x30
            || first_attribute % 8 != 0
            || bytes_used > data.len()
            || first_attribute >= bytes_used
        {
            return Err(Error::InvalidRecord);
        }
        Ok(Self { data, first_attribute, bytes_used })
    }

    /// Resolve a physical attribute header by its exact record offset.
    /// Earlier malformed attributes are refused before inspecting later headers.
    pub fn attribute_at(&self, offset: usize) -> Result<Attribute<'a>> {
        for attribute in self.attributes() {
            let attribute = attribute?;
            if attribute.record_offset() == offset {
                return Ok(attribute);
            }
        }
        Err(Error::InvalidAttribute)
    }

    /// Resolve an attribute which is wholly in this record. An attribute list
    /// must confirm that ownership; external/split attributes are not guessed.
    /// The single local attribute of kind and name; absence is InvalidAttribute.
    pub fn stream(&self, kind: u32, name: &[u8]) -> Result<Attribute<'a>> {
        self.local_attribute(kind, name)?.ok_or(Error::InvalidAttribute)
    }

    pub fn local_attribute(&self, kind: u32, name: &[u8]) -> Result<Option<Attribute<'a>>> {
        let mut found = None;
        let mut list = None;
        for a in self.attributes() {
            let a = a?;
            if a.kind == ATTR_ATTRIBUTE_LIST && list.replace(a).is_some() {
                return Err(Error::InvalidAttributeList);
            }
            if a.kind == kind && a.name_utf16le()? == name && found.replace(a).is_some() {
                return Err(Error::InvalidAttribute);
            }
        }
        if let Some(list) = list {
            if list.nonresident {
                return Err(Error::Unsupported);
            }
            let reference =
                file_reference(self.physical_record_number()?.ok_or(Error::Unsupported)?, self.sequence_number()?)?;
            let mut count = 0;
            for entry in super::attrlist::AttributeList::new(list.resident_value()?) {
                let entry = entry?;
                if entry.kind != kind || entry.name_utf16le != name {
                    continue;
                }
                if entry.file_reference != reference || entry.first_vcn != 0 {
                    return Err(Error::Unsupported);
                }
                if found.as_ref().map(|a| a.id) != Some(entry.attribute_id) {
                    return Err(Error::InvalidAttributeList);
                }
                count += 1;
            }
            if count != usize::from(found.is_some()) {
                return Err(Error::InvalidAttributeList);
            }
        }
        Ok(found)
    }

    pub fn sequence_number(&self) -> Result<u16> {
        u16_at(self.data, record_layout::SEQUENCE_OFFSET)
    }

    /// The legacy header uses these bytes for USA replacements instead.
    /// Its physical identity must come from the caller's checked mapping.
    pub fn physical_record_number(&self) -> Result<Option<u64>> {
        if u16_at(self.data, record_layout::USA_OFFSET)? == record_layout::LEGACY_USA {
            return Ok(None);
        }
        Ok(Some(
            u64::from(u32_at(self.data, record_layout::NUMBER_LOW_OFFSET)?)
                | (u64::from(u16_at(self.data, record_layout::NUMBER_HIGH_OFFSET)?)
                    << record_layout::NUMBER_HIGH_SHIFT),
        ))
    }

    pub fn flags(&self) -> Result<u16> {
        u16_at(self.data, record_layout::FLAGS_OFFSET)
    }

    pub fn link_count(&self) -> Result<u16> {
        u16_at(self.data, 0x12)
    }

    pub fn base_file_reference(&self) -> Result<u64> {
        u64_at(self.data, record_layout::BASE_REFERENCE_OFFSET)
    }

    /// NTFS 3.x security ID from resident $STANDARD_INFORMATION. None
    /// means this record has no 0x38-byte standard-information value; callers
    /// must then check for a legacy descriptor or refuse permission decisions.
    pub fn security_id(&self) -> Result<Option<u32>> {
        let mut found = None;
        for entry in self.attributes() {
            let attribute = entry?;
            if attribute.kind != ATTR_STANDARD_INFORMATION {
                continue;
            }
            if found.is_some() || attribute.nonresident || !attribute.name_utf16le()?.is_empty() {
                return Err(Error::InvalidAttribute);
            }
            let value = attribute.resident_value()?;
            if value.len() < 0x30 {
                return Err(Error::InvalidAttribute);
            }
            found = Some(if value.len() >= 0x38 { Some(u32_at(value, 0x34)?) } else { None });
        }
        Ok(found.flatten())
    }

    pub(crate) fn decoded(&self) -> &'a [u8] {
        self.data
    }

    pub fn attributes(&self) -> Attributes<'a> {
        Attributes { data: &self.data[..self.bytes_used], cursor: self.first_attribute, done: false }
    }
}

/// Multi-sector transfer protection stride, independent of the logical sector size.
pub const FIXUP_STRIDE: usize = 512;

/// Re-protect a decoded multi-sector structure (FILE, INDX, RSTR, RCRD): bump
/// the update-sequence token and move each stride tail into the array.
/// Callers validate their own signature and header before calling.
pub fn protect_fixups(data: &mut [u8]) -> Result<()> {
    let usa = usize::from(u16_at(data, record_layout::USA_OFFSET)?);
    let count = usize::from(u16_at(data, record_layout::USA_COUNT_OFFSET)?);
    if data.len() % FIXUP_STRIDE != 0
        || count != data.len() / FIXUP_STRIDE + 1
        || usa % 2 != 0
        || usa + count * 2 > data.len()
    {
        return Err(Error::InvalidFixup);
    }
    let token = u16_at(data, usa)?.wrapping_add(1).max(1).to_le_bytes();
    data[usa..usa + 2].copy_from_slice(&token);
    for index in 0..count - 1 {
        let tail = (index + 1) * FIXUP_STRIDE - 2;
        data.copy_within(tail..tail + 2, usa + 2 + index * 2);
        data[tail..tail + 2].copy_from_slice(&token);
    }
    Ok(())
}

/// Validate every sector tail before replacing any. protected_end is the
/// first byte of the caller's payload, which the USA must not overlap.
pub(crate) fn apply_fixups(
    data: &mut [u8],
    bytes_per_sector: u16,
    minimum_usa_offset: usize,
    protected_end: usize,
) -> Result<()> {
    if bytes_per_sector < 512
        || !bytes_per_sector.is_power_of_two()
        || data.len() < usize::from(bytes_per_sector)
        || data.len() % usize::from(bytes_per_sector) != 0
    {
        return Err(Error::InvalidFixup);
    }
    // NTFS multi-sector transfer protection uses fixed 512-byte strides,
    // including on volumes whose BPB logical sector size is 1024–4096.
    let bytes_per_sector = 512_u16;
    let usa_offset = usize::from(u16_at(data, 4)?);
    let usa_count = usize::from(u16_at(data, 6)?);
    let sector_count = data.len() / usize::from(bytes_per_sector);
    if usa_count != sector_count + 1 || usa_offset < minimum_usa_offset || usa_offset % 2 != 0 {
        return Err(Error::InvalidFixup);
    }
    let usa_bytes = usa_count.checked_mul(2).ok_or(Error::Overflow)?;
    if usa_offset.checked_add(usa_bytes).ok_or(Error::Overflow)? > protected_end {
        return Err(Error::InvalidFixup);
    }
    let usa = range(data, usa_offset, usa_bytes)?;
    let sequence = [usa[0], usa[1]];
    for sector in 0..sector_count {
        let tail = (sector + 1)
            .checked_mul(usize::from(bytes_per_sector))
            .and_then(|n| n.checked_sub(2))
            .ok_or(Error::Overflow)?;
        if range(data, tail, 2)? != sequence {
            return Err(Error::InvalidFixup);
        }
    }
    for sector in 0..sector_count {
        let tail = (sector + 1) * usize::from(bytes_per_sector) - 2;
        let replacement = [data[usa_offset + 2 + sector * 2], data[usa_offset + 3 + sector * 2]];
        range_mut(data, tail, 2)?.copy_from_slice(&replacement);
    }
    Ok(())
}

pub struct Attributes<'a> {
    data: &'a [u8],
    cursor: usize,
    done: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    pub kind: u32,
    pub id: u16,
    pub nonresident: bool,
    record_offset: usize,
    data: &'a [u8],
}

impl<'a> Attribute<'a> {
    pub fn record_offset(&self) -> usize {
        self.record_offset
    }

    /// Validate resident framing or nonresident VCN and initialized-size bounds.
    /// Record ordering, capacity and writer admission remain with the caller.
    pub fn validate_value(&self) -> Result<()> {
        if self.nonresident {
            let mut next = self.first_vcn()?;
            for run in DataRuns::new(self.data_runs()?, next) {
                let run = run?;
                if run.vcn != next {
                    return Err(Error::InvalidRunlist);
                }
                next = next.checked_add(run.len).ok_or(Error::Overflow)?;
            }
            if next.wrapping_sub(1) != self.last_vcn()? || self.initialized_size()? > self.data_size()? {
                return Err(Error::InvalidRunlist);
            }
        } else {
            self.resident_value()?;
        }
        Ok(())
    }

    pub fn resident_value_offset(&self) -> Result<usize> {
        self.resident_value()?;
        Ok(usize::from(u16_at(self.data, 0x14)?))
    }

    pub fn resident_value(&self) -> Result<&'a [u8]> {
        if self.nonresident {
            return Err(Error::InvalidAttribute);
        }
        let value_len = usize::try_from(u32_at(self.data, 0x10)?).map_err(|_| Error::Overflow)?;
        let value_offset = usize::from(u16_at(self.data, 0x14)?);
        if value_offset < 0x18 {
            return Err(Error::InvalidAttribute);
        }
        range(self.data, value_offset, value_len).map_err(|_| Error::InvalidAttribute)
    }

    pub fn data_runs(&self) -> Result<&'a [u8]> {
        if !self.nonresident || self.data.len() < 0x40 {
            return Err(Error::InvalidAttribute);
        }
        let offset = usize::from(u16_at(self.data, 0x20)?);
        if offset < 0x40 || offset >= self.data.len() {
            return Err(Error::InvalidAttribute);
        }
        range(self.data, offset, self.data.len() - offset).map_err(|_| Error::InvalidAttribute)
    }

    pub(crate) fn raw(&self) -> &'a [u8] {
        self.data
    }

    /// Resident attribute flags, including $FILE_NAME's indexed bit.
    pub fn resident_flags(&self) -> Result<u8> {
        if self.nonresident {
            return Err(Error::InvalidAttribute);
        }
        u8_at(self.data, 22)
    }

    pub fn data_size(&self) -> Result<u64> {
        if self.nonresident {
            u64_at(self.data, attribute_layout::DATA_SIZE_OFFSET)
        } else {
            Ok(u64::from(u32_at(self.data, 0x10)?))
        }
    }

    pub fn initialized_size(&self) -> Result<u64> {
        if !self.nonresident {
            return self.data_size();
        }
        u64_at(self.data, attribute_layout::INITIALIZED_SIZE_OFFSET)
    }

    pub fn allocated_size(&self) -> Result<u64> {
        if !self.nonresident {
            return Err(Error::InvalidAttribute);
        }
        u64_at(self.data, attribute_layout::ALLOCATED_SIZE_OFFSET)
    }

    pub fn first_vcn(&self) -> Result<u64> {
        if !self.nonresident {
            return Err(Error::InvalidAttribute);
        }
        u64_at(self.data, attribute_layout::FIRST_VCN_OFFSET)
    }

    pub fn last_vcn(&self) -> Result<u64> {
        if !self.nonresident {
            return Err(Error::InvalidAttribute);
        }
        u64_at(self.data, attribute_layout::LAST_VCN_OFFSET)
    }

    pub fn flags(&self) -> Result<u16> {
        u16_at(self.data, attribute_layout::FLAGS_OFFSET)
    }

    pub fn name_utf16le(&self) -> Result<&'a [u8]> {
        let chars = usize::from(u8_at(self.data, 9)?);
        let offset = usize::from(u16_at(self.data, 0x0a)?);
        if chars == 0 {
            return Ok(&[]);
        }
        let bytes = chars.checked_mul(2).ok_or(Error::Overflow)?;
        range(self.data, offset, bytes).map_err(|_| Error::InvalidAttribute)
    }
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Result<Attribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let kind = match u32_at(self.data, self.cursor) {
            Ok(kind) => kind,
            Err(_) => {
                self.done = true;
                return Some(Err(Error::InvalidAttribute));
            }
        };
        if kind == u32::MAX {
            self.done = true;
            return None;
        }
        let result = (|| {
            let length = usize::try_from(u32_at(self.data, self.cursor + 4)?).map_err(|_| Error::Overflow)?;
            if length < 0x18 || length % 8 != 0 {
                return Err(Error::InvalidAttribute);
            }
            let data = range(self.data, self.cursor, length).map_err(|_| Error::InvalidAttribute)?;
            let nonresident = match u8_at(data, 8)? {
                0 => false,
                1 => true,
                _ => return Err(Error::InvalidAttribute),
            };
            if nonresident && length < 0x40 {
                return Err(Error::InvalidAttribute);
            }
            let attr = Attribute { kind, id: u16_at(data, 0x0e)?, nonresident, record_offset: self.cursor, data };
            attr.name_utf16le()?;
            self.cursor = self.cursor.checked_add(length).ok_or(Error::Overflow)?;
            Ok(attr)
        })();
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_fields_preserve_raw_encodings_and_reject_oversized_numbers() {
        for (number, sequence, encoded) in [
            (0, 0, 0),
            (5, 0, 5),
            (0x1234_5678_9abc, 0x5678, 0x5678_1234_5678_9abc),
            (0xffff_ffff_ffff, u16::MAX, u64::MAX),
        ] {
            assert_eq!(file_reference(number, sequence), Ok(encoded));
            assert_eq!(reference_number(encoded), number);
            assert_eq!(reference_sequence(encoded), sequence);
        }
        for number in [0x0001_0000_0000_0000, u64::MAX] {
            assert_eq!(file_reference(number, 0), Err(Error::InvalidRecord));
            assert_eq!(file_reference(number, u16::MAX), Err(Error::InvalidRecord));
        }
    }

    #[test]
    fn value_validation_checks_resident_bounds() {
        let mut bytes = [0_u8; 32];
        bytes[16..20].copy_from_slice(&4_u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&24_u16.to_le_bytes());
        fn attribute(data: &[u8]) -> Attribute<'_> {
            Attribute { kind: ATTR_DATA, id: 0, nonresident: false, record_offset: 0, data }
        }
        assert_eq!(attribute(&bytes).validate_value(), Ok(()));
        bytes[16..20].copy_from_slice(&9_u32.to_le_bytes());
        assert_eq!(attribute(&bytes).validate_value(), Err(Error::InvalidAttribute));
    }

    #[test]
    fn value_validation_checks_mapping_sizes_and_preserves_empty_streams() {
        let mut bytes = [0_u8; 72];
        bytes[24..32].copy_from_slice(&1_u64.to_le_bytes());
        bytes[32..34].copy_from_slice(&64_u16.to_le_bytes());
        bytes[48..56].copy_from_slice(&4096_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&4096_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&[0x11, 2, 4, 0]);
        fn attribute(data: &[u8]) -> Attribute<'_> {
            Attribute { kind: ATTR_DATA, id: 0, nonresident: true, record_offset: 0, data }
        }
        assert_eq!(attribute(&bytes).validate_value(), Ok(()));
        bytes[24..32].copy_from_slice(&2_u64.to_le_bytes());
        assert_eq!(attribute(&bytes).validate_value(), Err(Error::InvalidRunlist));
        bytes[24..32].copy_from_slice(&1_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&4097_u64.to_le_bytes());
        assert_eq!(attribute(&bytes).validate_value(), Err(Error::InvalidRunlist));
        bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[48..72].fill(0);
        assert_eq!(attribute(&bytes).validate_value(), Ok(()));
    }

    fn record() -> [u8; 1024] {
        let mut b = [0_u8; 1024];
        b[0..4].copy_from_slice(b"FILE");
        b[4..6].copy_from_slice(&0x30_u16.to_le_bytes());
        b[6..8].copy_from_slice(&3_u16.to_le_bytes());
        b[0x14..0x16].copy_from_slice(&0x38_u16.to_le_bytes());
        b[0x18..0x1c].copy_from_slice(&0x60_u32.to_le_bytes());
        b[0x30..0x32].copy_from_slice(&0x1234_u16.to_le_bytes());
        b[0x32..0x34].copy_from_slice(&0xabcd_u16.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&0xef01_u16.to_le_bytes());
        b[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
        b[1022..1024].copy_from_slice(&0x1234_u16.to_le_bytes());
        b[0x38..0x3c].copy_from_slice(&ATTR_DATA.to_le_bytes());
        b[0x3c..0x40].copy_from_slice(&0x20_u32.to_le_bytes());
        b[0x40] = 0;
        b[0x48..0x4c].copy_from_slice(&4_u32.to_le_bytes());
        b[0x4c..0x4e].copy_from_slice(&0x18_u16.to_le_bytes());
        b[0x50..0x54].copy_from_slice(b"data");
        b[0x58..0x5c].copy_from_slice(&u32::MAX.to_le_bytes());
        b
    }

    #[test]
    fn applies_fixups_and_reads_resident_data() {
        let mut b = record();
        let rec = MftRecord::parse(&mut b, 512).unwrap();
        let attrs: std::vec::Vec<_> = rec.attributes().collect();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].as_ref().unwrap().resident_value().unwrap(), b"data");
        assert_eq!(&b[510..512], &0xabcd_u16.to_le_bytes());
    }

    #[test]
    fn attribute_offset_lookup_requires_an_exact_header() {
        const DATA_OFFSET: usize = 0x38;
        const END_OFFSET: usize = 0x58;
        let mut bytes = record();
        let parsed = MftRecord::parse(&mut bytes, 512).unwrap();
        let attribute = parsed.attribute_at(DATA_OFFSET).unwrap();
        assert_eq!(attribute.kind, ATTR_DATA);
        assert_eq!(attribute.resident_value(), Ok(b"data".as_slice()));
        for offset in [0, DATA_OFFSET + 1, END_OFFSET, usize::MAX] {
            assert!(matches!(parsed.attribute_at(offset), Err(Error::InvalidAttribute)));
        }
    }

    #[test]
    fn attribute_offset_lookup_refuses_a_malformed_predecessor() {
        const DATA_OFFSET: usize = 0x38;
        const ATTRIBUTE_BYTES: usize = 0x20;
        const LENGTH_OFFSET: usize = DATA_OFFSET + 4;
        const MALFORMED_LENGTH: u32 = 8;
        const USED_BYTES: u32 = 0x80;
        let next_offset = DATA_OFFSET + ATTRIBUTE_BYTES;
        let end_offset = next_offset + ATTRIBUTE_BYTES;
        let mut bytes = record();
        MftRecord::parse(&mut bytes, 512).unwrap();
        bytes.copy_within(DATA_OFFSET..next_offset, next_offset);
        bytes[end_offset..end_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&USED_BYTES.to_le_bytes());
        let parsed = MftRecord::from_decoded(&bytes).unwrap();
        assert_eq!(parsed.attribute_at(next_offset).unwrap().kind, ATTR_DATA);

        bytes[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&MALFORMED_LENGTH.to_le_bytes());
        let parsed = MftRecord::from_decoded(&bytes).unwrap();
        assert!(matches!(parsed.attribute_at(next_offset), Err(Error::InvalidAttribute)));
    }

    #[test]
    fn rejects_torn_sector_without_mutation() {
        let mut b = record();
        b[1022] = 0;
        let before = b;
        assert!(matches!(MftRecord::parse(&mut b, 512), Err(Error::InvalidFixup)));
        assert_eq!(b, before);
    }

    #[test]
    fn legacy_usa_replacements_are_not_record_identity() {
        let mut b = record();
        b[4..6].copy_from_slice(&0x2a_u16.to_le_bytes());
        b.copy_within(0x30..0x36, 0x2a);
        let rec = MftRecord::parse(&mut b, 512).unwrap();
        assert_eq!(rec.physical_record_number(), Ok(None));
        assert_eq!(rec.local_attribute(ATTR_DATA, &[]).unwrap().unwrap().resident_value(), Ok(b"data".as_slice()));
        assert_eq!(&b[510..512], &0xabcd_u16.to_le_bytes());

        let mut torn = record();
        torn[4..6].copy_from_slice(&0x2a_u16.to_le_bytes());
        torn.copy_within(0x30..0x36, 0x2a);
        torn[1022] = 0;
        let before = torn;
        assert!(matches!(MftRecord::parse(&mut torn, 512), Err(Error::InvalidFixup)));
        assert_eq!(torn, before);
    }

    #[test]
    fn reads_the_full_physical_record_identity() {
        let mut b = record();
        b[42..44].copy_from_slice(&3_u16.to_le_bytes());
        b[44..48].copy_from_slice(&7_u32.to_le_bytes());
        let rec = MftRecord::parse(&mut b, 512).unwrap();
        assert_eq!(rec.physical_record_number(), Ok(Some((3_u64 << 32) | 7)));
    }

    #[test]
    fn reads_security_id_from_standard_information() {
        let mut b = record();
        b[0x18..0x1c].copy_from_slice(&0xa0_u32.to_le_bytes());
        b[0x38..0x3c].copy_from_slice(&ATTR_STANDARD_INFORMATION.to_le_bytes());
        b[0x3c..0x40].copy_from_slice(&0x60_u32.to_le_bytes());
        b[0x48..0x4c].copy_from_slice(&0x38_u32.to_le_bytes());
        b[0x50..0x98].fill(0);
        b[0x84..0x88].copy_from_slice(&0x123_u32.to_le_bytes());
        b[0x98..0x9c].copy_from_slice(&u32::MAX.to_le_bytes());
        let record = MftRecord::parse(&mut b, 512).unwrap();
        assert_eq!(record.security_id(), Ok(Some(0x123)));
    }
}
