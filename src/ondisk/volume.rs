//! Module: ntfs_rs::volume
//! Purpose: Resolve checked attribute families and read NTFS records and streams.
//! Created: 2026-09-30
//! Architecture: Offline tools and mounted engines supply ReadAt adapters. Shared
//!     parsers validate records, runlists and directory indexes; this module owns
//!     family resolution and bounded reads without granting write authority.

use core::cmp::Ordering;

use super::attrlist::{AttributeList, ListEntry};
use super::boot::BootSector;
use super::bytes::range;
use super::index::{IndexBlock, IndexEntry, IndexRoot};
use super::mft::{
    file_reference, reference_number, reference_sequence, Attribute, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP,
    ATTR_DATA, ATTR_INDEX_ALLOCATION, ATTR_INDEX_ROOT,
};
use super::runlist::DataRuns;
use super::volume_info::VolumeInfo;
use super::{Error, Result};

/// A caller-owned, read-only device or image. Implementations must fill the
/// whole destination or return Error::Io.
pub trait ReadAt {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<()>;
}

impl<T: ReadAt + ?Sized> ReadAt for &mut T {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        (**self).read_exact_at(offset, output)
    }
}

pub struct Volume<R> {
    reader: R,
    pub boot: BootSector,
    volume_bytes: u64,
}

impl<R> Volume<R> {
    /// Shared writer engines borrow their own adapter; the read API itself
    /// neither requests writes nor grants permission to perform them.
    pub(crate) fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

const MAX_INDEX_DEPTH: usize = 32;

#[derive(Clone, Copy)]
enum Node {
    Root,
    Block(u64),
}

#[derive(Clone, Copy)]
struct Frame {
    node: Node,
    cursor: usize,
    after_child: bool,
}

impl<R: ReadAt> Volume<R> {
    pub fn new(reader: R, boot: BootSector) -> Result<Self> {
        let volume_bytes = boot.total_sectors.checked_mul(u64::from(boot.bytes_per_sector)).ok_or(Error::Overflow)?;
        Ok(Self { reader, boot, volume_bytes })
    }

    /// Read MFT record zero directly from the boot-sector location. The
    /// caller must then parse its fixups before using it to locate other
    /// records.
    pub fn read_mft_zero(&mut self, output: &mut [u8]) -> Result<()> {
        self.check_record_buffer(output)?;
        let offset = self.boot.mft_byte_offset()?;
        self.read_physical(offset, output)
    }

    /// Inspect $VOLUME_INFORMATION using two caller-owned, record-sized
    /// buffers. A failed read or malformed record is an error, never clean.
    pub fn read_volume_info(&mut self, mft_buffer: &mut [u8], volume_buffer: &mut [u8]) -> Result<VolumeInfo> {
        self.read_mft_zero(mft_buffer)?;
        let mft = MftRecord::parse(mft_buffer, self.boot.bytes_per_sector)?;
        self.read_mft_record(&mft, 3, volume_buffer)?;
        let record = MftRecord::parse(volume_buffer, self.boot.bytes_per_sector)?;
        VolumeInfo::from_record(&record)
    }

    /// Count allocated clusters in the volume's $Bitmap (MFT record 6).
    /// All buffers are caller-owned; the bitmap is streamed in chunks.
    /// This counts NTFS allocation, not physical storage used by a sparse
    /// backing image or device.
    pub fn allocated_clusters(
        &mut self,
        mft_buffer: &mut [u8],
        bitmap_record_buffer: &mut [u8],
        extension_buffer: &mut [u8],
        chunk: &mut [u8],
    ) -> Result<u64> {
        if chunk.is_empty() {
            return Err(Error::InvalidGeometry);
        }
        self.read_mft_zero(mft_buffer)?;
        let mft = MftRecord::parse(mft_buffer, self.boot.bytes_per_sector)?;
        self.read_mft_record(&mft, 6, bitmap_record_buffer)?;
        let bitmap = MftRecord::parse(bitmap_record_buffer, self.boot.bytes_per_sector)?;
        if bitmap.flags()? & 1 == 0 || bitmap.base_file_reference()? != 0 {
            return Err(Error::InvalidRecord);
        }
        self.visit_unnamed_data(&mft, &bitmap, 6, extension_buffer, |_, attr| {
            if attr.flags()? != 0 {
                return Err(Error::Unsupported);
            }
            if attr.nonresident {
                for run in DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
                    if run?.lcn.is_none() {
                        return Err(Error::Unsupported);
                    }
                }
            }
            Ok(())
        })?;
        let clusters = self.boot.total_sectors / u64::from(self.boot.sectors_per_cluster);
        let needed = clusters.checked_add(7).ok_or(Error::Overflow)? / 8;
        let bitmap_size = self.data_size_resolved(&mft, &bitmap, 6, extension_buffer)?;
        if bitmap_size < needed {
            return Err(Error::InvalidAttribute);
        }
        let mut used = 0_u64;
        let mut offset = 0_u64;
        while offset < needed {
            let amount = usize::try_from((needed - offset).min(chunk.len() as u64)).map_err(|_| Error::Overflow)?;
            self.read_data_resolved(&mft, &bitmap, 6, extension_buffer, offset, &mut chunk[..amount])?;
            for (index, byte) in chunk[..amount].iter().enumerate() {
                let byte_number = offset.checked_add(index as u64).ok_or(Error::Overflow)?;
                let valid = if byte_number == needed - 1 && clusters % 8 != 0 {
                    *byte & ((1_u8 << (clusters % 8)) - 1)
                } else {
                    *byte
                };
                used = used.checked_add(u64::from(valid.count_ones())).ok_or(Error::Overflow)?;
            }
            offset = offset.checked_add(amount as u64).ok_or(Error::Overflow)?;
        }
        Ok(used)
    }

    /// Read a record through the unnamed $DATA stream of record zero.
    /// Attribute lists and fragmented MFT attributes are deliberately refused
    /// until their cross-record references can be validated.
    pub fn read_mft_record(&mut self, mft_zero: &MftRecord<'_>, number: u64, output: &mut [u8]) -> Result<()> {
        self.check_record_buffer(output)?;
        let offset = number.checked_mul(u64::from(self.boot.record_bytes)).ok_or(Error::Overflow)?;
        let attribute = unnamed_data(mft_zero)?;
        self.read_nonresident(attribute, offset, output)
    }

    /// Read an unnamed file stream into a caller-owned buffer. This supports
    /// resident data and ordinary uncompressed nonresident extents.
    pub fn read_data(&mut self, record: &MftRecord<'_>, offset: u64, output: &mut [u8]) -> Result<()> {
        let attribute = unnamed_data(record)?;
        self.read_attribute(attribute, offset, output)
    }

    pub fn read_attribute(&mut self, attribute: Attribute<'_>, offset: u64, output: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(output.len() as u64).ok_or(Error::Overflow)?;
        if end > attribute.data_size()? {
            return Err(Error::InvalidAttribute);
        }
        if attribute.nonresident {
            self.read_nonresident(attribute, offset, output)
        } else {
            let start = usize::try_from(offset).map_err(|_| Error::Overflow)?;
            output.copy_from_slice(range(attribute.resident_value()?, start, output.len())?);
            Ok(())
        }
    }

    pub fn data_size(&self, record: &MftRecord<'_>) -> Result<u64> {
        unnamed_data(record)?.data_size()
    }

    /// Resolve an unnamed stream through a resident or nonresident attribute list. Extension
    /// records are checked against both the list's sequence number and the
    /// base record's back-reference before their data is used. The caller
    /// lends one record-sized scratch buffer, reused for each extent.
    pub fn read_data_resolved(
        &mut self,
        mft_zero: &MftRecord<'_>,
        base: &MftRecord<'_>,
        base_number: u64,
        scratch: &mut [u8],
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        let end = offset.checked_add(output.len() as u64).ok_or(Error::Overflow)?;
        let mut size = None;
        let mut initialized = 0;
        let mut covered = 0;
        let mut copied = 0;
        self.visit_unnamed_data(mft_zero, base, base_number, scratch, |volume, attr| {
            if size.is_none() {
                let data_size = attr.data_size()?;
                if end > data_size {
                    return Err(Error::InvalidAttribute);
                }
                initialized = attr.initialized_size()?;
                if initialized > data_size {
                    return Err(Error::InvalidAttribute);
                }
                size = Some(data_size);
            }
            if attr.nonresident {
                if attr.first_vcn()? == 0 && attr.last_vcn()? == u64::MAX && size == Some(0) {
                    covered = 0;
                    return Ok(());
                }
                let cluster = u64::from(volume.boot.cluster_bytes);
                let start = attr.first_vcn()?.checked_mul(cluster).ok_or(Error::Overflow)?;
                let stop =
                    attr.last_vcn()?.checked_add(1).and_then(|vcn| vcn.checked_mul(cluster)).ok_or(Error::Overflow)?;
                let from = offset.max(start);
                let to = end.min(stop);
                if from < to {
                    let destination = usize::try_from(from - offset).map_err(|_| Error::Overflow)?;
                    let count = usize::try_from(to - from).map_err(|_| Error::Overflow)?;
                    volume.read_nonresident_extent(
                        attr,
                        size.ok_or(Error::InvalidAttribute)?,
                        initialized,
                        from,
                        &mut output[destination..destination + count],
                    )?;
                    copied += count;
                } else {
                    volume.read_nonresident_extent(
                        attr,
                        size.ok_or(Error::InvalidAttribute)?,
                        initialized,
                        start,
                        &mut [],
                    )?;
                }
                covered = stop;
            } else {
                volume.read_attribute(attr, offset, output)?;
                copied = output.len();
                covered = attr.data_size()?;
            }
            Ok(())
        })?;
        if size.ok_or(Error::InvalidAttribute)? > covered || copied != output.len() {
            return Err(Error::InvalidAttributeList);
        }
        Ok(())
    }

    pub fn data_size_resolved(
        &mut self,
        mft_zero: &MftRecord<'_>,
        base: &MftRecord<'_>,
        base_number: u64,
        scratch: &mut [u8],
    ) -> Result<u64> {
        let cluster_bytes = u64::from(self.boot.cluster_bytes);
        let mut size = None;
        let mut covered = 0;
        self.visit_unnamed_data(mft_zero, base, base_number, scratch, |_, attr| {
            if size.is_none() {
                let data_size = attr.data_size()?;
                if attr.initialized_size()? > data_size {
                    return Err(Error::InvalidAttribute);
                }
                size = Some(data_size);
            }
            covered = if attr.nonresident {
                if attr.first_vcn()? == 0 && attr.last_vcn()? == u64::MAX && size == Some(0) {
                    0
                } else {
                    attr.last_vcn()?
                        .checked_add(1)
                        .and_then(|vcn| vcn.checked_mul(cluster_bytes))
                        .ok_or(Error::Overflow)?
                }
            } else {
                attr.data_size()?
            };
            Ok(())
        })?;
        let size = size.ok_or(Error::InvalidAttribute)?;
        if size > covered {
            return Err(Error::InvalidAttributeList);
        }
        Ok(size)
    }

    pub(crate) fn visit_unnamed_data(
        &mut self,
        mft_zero: &MftRecord<'_>,
        base: &MftRecord<'_>,
        base_number: u64,
        scratch: &mut [u8],
        mut operation: impl FnMut(&mut Self, Attribute<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut list = None;
        let mut base_data_attributes = 0_usize;
        for item in base.attributes() {
            let attr = item?;
            if attr.kind == ATTR_ATTRIBUTE_LIST && list.replace(attr).is_some() {
                return Err(Error::Unsupported);
            }
            if attr.kind == ATTR_DATA && attr.name_utf16le()?.is_empty() {
                base_data_attributes += 1;
            }
        }
        let Some(list) = list else {
            let attribute = unnamed_data(base)?;
            if attribute.nonresident && attribute.first_vcn()? != 0 {
                return Err(Error::InvalidAttributeList);
            }
            return operation(self, attribute);
        };
        if list.nonresident {
            let needed = 2 * super::tx::RECORD_IMAGE + self.boot.record_bytes as usize;
            if scratch.len() < needed {
                return Err(Error::Truncated);
            }
            if base.physical_record_number()?.ok_or(Error::Unsupported)? != base_number {
                return Err(Error::InvalidRecord);
            }
            let (image, work) = scratch.split_at_mut(super::tx::RECORD_IMAGE);
            self.resolve_record(mft_zero, base, image, work)?;
            let record = MftRecord::from_decoded(image)?;
            return operation(self, unnamed_data(&record)?);
        }
        let base_reference = file_reference(base_number, base.sequence_number()?)?;
        if base.base_file_reference()? != 0 {
            return Err(Error::InvalidRecord);
        }
        let scratch = scratch.get_mut(..self.boot.record_bytes as usize).ok_or(Error::Truncated)?;
        let mut next_vcn = 0_u64;
        let mut seen = false;
        let mut resident = false;
        let mut stream_flags = None;
        let mut listed_base_attributes = 0_usize;
        for item in AttributeList::new(list.resident_value()?) {
            let entry = item?;
            if entry.kind == ATTR_DATA && entry.name_utf16le.is_empty() {
                if resident || entry.first_vcn != next_vcn {
                    return Err(Error::InvalidAttributeList);
                }
                let mut visit = |volume: &mut Self, attr: Attribute<'_>| -> Result<()> {
                    let flags = attr.flags()?;
                    if stream_flags.is_some_and(|previous| previous != flags) {
                        return Err(Error::InvalidAttributeList);
                    }
                    stream_flags = Some(flags);
                    if attr.nonresident {
                        let last = attr.last_vcn()?;
                        if last == u64::MAX && !seen && next_vcn == 0 && attr.data_size()? == 0 {
                            resident = true;
                        } else if last < next_vcn {
                            return Err(Error::InvalidAttributeList);
                        } else {
                            next_vcn = last.checked_add(1).ok_or(Error::Overflow)?;
                        }
                    } else {
                        if seen || entry.first_vcn != 0 {
                            return Err(Error::InvalidAttributeList);
                        }
                        resident = true;
                    }
                    seen = true;
                    operation(volume, attr)
                };
                if entry.file_reference == base_reference {
                    visit(self, listed_attribute(base, entry)?)?;
                    listed_base_attributes += 1;
                } else {
                    let extension_number = reference_number(entry.file_reference);
                    self.read_mft_record(mft_zero, extension_number, scratch)?;
                    let extension = MftRecord::parse(scratch, self.boot.bytes_per_sector)?;
                    if extension.sequence_number()? != reference_sequence(entry.file_reference)
                        || extension.base_file_reference()? != base_reference
                        || extension.flags()? & 1 == 0
                    {
                        return Err(Error::InvalidAttributeList);
                    }
                    visit(self, listed_attribute(&extension, entry)?)?;
                }
            }
        }
        if !seen {
            return Err(Error::InvalidAttributeList);
        }
        if listed_base_attributes != base_data_attributes {
            return Err(Error::InvalidAttributeList);
        }
        Ok(())
    }

    /// Assemble a checked attribute family in caller scratch. The result is
    /// an in-memory record only; no enlarged record is written to the volume.
    pub fn resolve_record(
        &mut self,
        mft: &MftRecord<'_>,
        base: &MftRecord<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<()> {
        self.resolve_record_projection(mft, base, output, scratch, true)
    }

    /// Resolve orphan metadata without assembling all DATA mapping pairs.
    /// The checked visitor still validates every DATA continuation identity.
    pub fn resolve_record_metadata(
        &mut self,
        mft: &MftRecord<'_>,
        base: &MftRecord<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<()> {
        self.resolve_record_projection(mft, base, output, scratch, false)
    }

    fn resolve_record_projection(
        &mut self,
        mft: &MftRecord<'_>,
        base: &MftRecord<'_>,
        output: &mut [u8],
        scratch: &mut [u8],
        all_data: bool,
    ) -> Result<()> {
        use super::{bytes::u16_at, record_edit as edit};
        let mut list = None;
        for a in base.attributes() {
            let a = a?;
            if a.kind == ATTR_ATTRIBUTE_LIST && list.replace(a).is_some() {
                return Err(Error::InvalidAttributeList);
            }
        }
        edit::validate(base.decoded())?;
        let source = base.decoded();
        if source.len() > output.len() {
            return Err(Error::NoSpace);
        }
        output.fill(0);
        output[..source.len()].copy_from_slice(source);
        edit::p32(output, 28, output.len() as u32)?;
        if list.is_none() {
            return Ok(());
        }
        let start = usize::from(u16_at(output, 20)?);
        output[start..].fill(0);
        edit::p32(output, start, u32::MAX)?;
        edit::p32(output, 24, (start + 8) as u32)?;
        edit::p16(output, 40, 0)?;
        self.visit_record_family(mft, base, scratch, |_, a| {
            if !all_data && a.kind == ATTR_DATA && a.nonresident && a.first_vcn()? != 0 {
                return Ok(());
            }
            edit::merge_attribute(output, a.raw())
        })?;
        edit::validate(output)
    }

    /// Validate a family without assembling its data runlists or retaining
    /// every physical record in a writer transaction. Caller scratch carries
    /// the attribute list and membership bits; only one record is read at a time.
    pub fn visit_record_family<F>(
        &mut self,
        mft: &MftRecord<'_>,
        base: &MftRecord<'_>,
        scratch: &mut [u8],
        mut visitor: F,
    ) -> Result<()>
    where
        F: for<'a> FnMut(u64, super::mft::Attribute<'a>) -> Result<()>,
    {
        use super::record_edit as edit;
        edit::validate(base.decoded())?;
        let mut list = None;
        for a in base.attributes() {
            let a = a?;
            if a.kind == ATTR_ATTRIBUTE_LIST && list.replace(a).is_some() {
                return Err(Error::InvalidAttributeList);
            }
        }
        let Some(list) = list else {
            let reference =
                file_reference(base.physical_record_number()?.ok_or(Error::Unsupported)?, base.sequence_number()?)?;
            for a in base.attributes() {
                visitor(reference, a?)?;
            }
            return Ok(());
        };
        let n = usize::try_from(list.data_size()?).map_err(|_| Error::Overflow)?;
        let record_bytes = self.boot.record_bytes as usize;
        if n == 0
            || n.checked_add(record_bytes).is_none_or(|needed| scratch.len() < needed)
            || list.flags()? != 0
            || !list.name_utf16le()?.is_empty()
            || (list.nonresident && list.first_vcn()? != 0)
            || base.base_file_reference()? != 0
        {
            return Err(Error::InvalidAttributeList);
        }
        let (entries, rest) = scratch.split_at_mut(n);
        let (raw, table) = rest.split_at_mut(record_bytes);
        let table_capacity = if table.len() / 24 > super::tx::MAX_RECORDS { table.len() / 24 } else { 0 };
        let (refs, seen) = table.split_at_mut(table_capacity * 8);
        // Caller scratch is reusable. Discard membership bits from an earlier
        // resolution before checking this family's attribute ordinals.
        seen[..table_capacity * 16].fill(0);
        // Existing kernel callers supply exactly an entry buffer and one MFT
        // record. Keep their bounded stack path; offline callers can provide
        // extra scratch for larger families.
        let mut stack_refs = [0u64; super::tx::MAX_RECORDS];
        let mut stack_seen = [0u128; super::tx::MAX_RECORDS];
        let capacity = if table_capacity == 0 { stack_refs.len() } else { table_capacity };
        self.read_attribute(list, 0, entries)?;
        let reference =
            file_reference(base.physical_record_number()?.ok_or(Error::Unsupported)?, base.sequence_number()?)?;
        let mut count = 0;
        let mut previous: Option<ListEntry<'_>> = None;
        let mut next_vcn = 0;
        let mut previous_nonresident = false;
        let mut previous_flags = 0;
        for entry in AttributeList::new(entries) {
            let entry = entry?;
            if entry.kind == ATTR_ATTRIBUTE_LIST || reference_sequence(entry.file_reference) == 0 {
                return Err(Error::InvalidAttributeList);
            }
            let existing = if table_capacity == 0 {
                stack_refs[..count].iter().position(|&r| r == entry.file_reference)
            } else {
                refs[..count * 8]
                    .chunks_exact(8)
                    .position(|r| u64::from_le_bytes(r.try_into().unwrap()) == entry.file_reference)
            };
            let index = if let Some(i) = existing {
                i
            } else {
                if count == capacity {
                    return Err(Error::NoSpace);
                }
                if table_capacity == 0 {
                    stack_refs[count] = entry.file_reference;
                } else {
                    refs[count * 8..count * 8 + 8].copy_from_slice(&entry.file_reference.to_le_bytes());
                }
                count += 1;
                count - 1
            };
            let extension;
            let record = if entry.file_reference == reference {
                base
            } else {
                self.read_mft_record(mft, reference_number(entry.file_reference), raw)?;
                extension = MftRecord::parse(raw, self.boot.bytes_per_sector)?;
                if extension.sequence_number()? != reference_sequence(entry.file_reference)
                    || extension.base_file_reference()? != reference
                    || extension.flags()? & 1 == 0
                {
                    return Err(Error::InvalidAttributeList);
                }
                &extension
            };
            edit::validate(record.decoded())?;
            let a = listed_attribute(record, entry)?;
            let ordinal = record
                .attributes()
                .position(|candidate| candidate.is_ok_and(|c| c.id == a.id))
                .ok_or(Error::InvalidAttributeList)?;
            let marked = if table_capacity == 0 {
                stack_seen[index]
            } else {
                u128::from_le_bytes(seen[index * 16..index * 16 + 16].try_into().unwrap())
            };
            if ordinal >= 128 || marked & (1u128 << ordinal) != 0 {
                return Err(Error::InvalidAttributeList);
            }
            if table_capacity == 0 {
                stack_seen[index] = marked | (1u128 << ordinal);
            } else {
                seen[index * 16..index * 16 + 16].copy_from_slice(&(marked | (1u128 << ordinal)).to_le_bytes());
            }
            if let Some(prev) = previous {
                if entry.kind < prev.kind {
                    return Err(Error::InvalidAttributeList);
                }
                let same = entry.kind == prev.kind && entry.name_utf16le == prev.name_utf16le;
                if same && entry.kind != 0x30 {
                    if !a.nonresident
                        || !previous_nonresident
                        || a.first_vcn()? != next_vcn
                        || a.flags()? != previous_flags
                    {
                        return Err(Error::InvalidAttributeList);
                    }
                } else if a.nonresident && a.first_vcn()? != 0 {
                    return Err(Error::InvalidAttributeList);
                }
            } else if a.nonresident && a.first_vcn()? != 0 {
                return Err(Error::InvalidAttributeList);
            }
            previous = Some(entry);
            previous_nonresident = a.nonresident;
            previous_flags = a.flags()?;
            if a.nonresident {
                next_vcn = a.last_vcn()?.checked_add(1).ok_or(Error::Overflow)?;
            }
            visitor(entry.file_reference, a)?;
        }
        let contains_base = if table_capacity == 0 {
            stack_refs[..count].contains(&reference)
        } else {
            refs[..count * 8].chunks_exact(8).any(|r| u64::from_le_bytes(r.try_into().unwrap()) == reference)
        };
        if !contains_base {
            return Err(Error::InvalidAttributeList);
        }
        // No hidden/unlisted attributes may be discarded during assembly.
        for index in 0..count {
            let r = if table_capacity == 0 {
                stack_refs[index]
            } else {
                u64::from_le_bytes(refs[index * 8..index * 8 + 8].try_into().unwrap())
            };
            let extension;
            let record = if r == reference {
                base
            } else {
                self.read_mft_record(mft, reference_number(r), raw)?;
                extension = MftRecord::parse(raw, self.boot.bytes_per_sector)?;
                &extension
            };
            for (ordinal, a) in record.attributes().enumerate() {
                let a = a?;
                let marked = if table_capacity == 0 {
                    stack_seen[index]
                } else {
                    u128::from_le_bytes(seen[index * 16..index * 16 + 16].try_into().unwrap())
                };
                if a.kind != ATTR_ATTRIBUTE_LIST && (ordinal >= 128 || marked & (1u128 << ordinal) == 0) {
                    return Err(Error::InvalidAttributeList);
                }
            }
        }
        Ok(())
    }

    /// Scratch bytes a directory walk needs to assemble a listed family.
    pub fn directory_scratch_bytes(&self) -> usize {
        self.boot.index_block_bytes as usize + 2 * super::tx::RECORD_IMAGE + 2 * self.boot.record_bytes as usize
    }

    /// Walk every reachable index node in depth-first order. The caller owns
    /// one index-block buffer; parent nodes are reread after visiting a child.
    /// Child VCNs are measured in clusters for large index blocks and in
    /// 512-byte units for index blocks smaller than a cluster.
    pub fn visit_directory<F>(&mut self, record: &MftRecord<'_>, block_buffer: &mut [u8], visitor: F) -> Result<()>
    where
        F: for<'entry> FnMut(IndexEntry<'entry>) -> Result<()>,
    {
        self.visit_directory_impl(record, block_buffer, false, false, |_| Ok(Ordering::Equal), visitor)
    }

    /// Visit only the entries order() reports Equal, descending the index
    /// B+ tree instead of walking it. order() says where the sought key sorts
    /// against an entry and must agree with the index collation; subtrees
    /// that cannot hold an Equal entry are never read.
    pub fn search_directory<O, F>(
        &mut self,
        record: &MftRecord<'_>,
        block_buffer: &mut [u8],
        order: O,
        visitor: F,
    ) -> Result<()>
    where
        O: for<'entry> FnMut(&IndexEntry<'entry>) -> Result<Ordering>,
        F: for<'entry> FnMut(IndexEntry<'entry>) -> Result<()>,
    {
        self.visit_directory_impl(record, block_buffer, false, false, order, visitor)
    }

    /// Offline checker traversal, including allocated-but-unreachable blocks.
    /// validated_list requires a caller-validated attribute list with all
    /// $I30 root, allocation and bitmap attributes in this base record.
    /// Other layouts are assembled with the shared checked family resolver.
    pub fn audit_directory<F>(
        &mut self,
        record: &MftRecord<'_>,
        block_buffer: &mut [u8],
        validated_list: bool,
        visitor: F,
    ) -> Result<()>
    where
        F: for<'entry> FnMut(IndexEntry<'entry>) -> Result<()>,
    {
        self.visit_directory_impl(record, block_buffer, validated_list, true, |_| Ok(Ordering::Equal), visitor)
    }

    fn visit_directory_impl<O, F>(
        &mut self,
        record: &MftRecord<'_>,
        block_buffer: &mut [u8],
        allow_validated_attribute_list: bool,
        audit: bool,
        mut order: O,
        mut visitor: F,
    ) -> Result<()>
    where
        O: for<'entry> FnMut(&IndexEntry<'entry>) -> Result<Ordering>,
        F: for<'entry> FnMut(IndexEntry<'entry>) -> Result<()>,
    {
        let block_bytes = self.boot.index_block_bytes as usize;
        if !allow_validated_attribute_list
            && record.attributes().any(|a| a.is_ok_and(|a| a.kind == ATTR_ATTRIBUTE_LIST))
        {
            if block_buffer.len() < self.directory_scratch_bytes() {
                return Err(Error::Truncated);
            }
            let (block, rest) = block_buffer.split_at_mut(block_bytes);
            let (image, rest) = rest.split_at_mut(super::tx::RECORD_IMAGE);
            let (zero, rest) = rest.split_at_mut(self.boot.record_bytes as usize);
            self.read_mft_zero(zero)?;
            let mft = MftRecord::parse(zero, self.boot.bytes_per_sector)?;
            self.resolve_record(&mft, record, image, rest)?;
            let record = MftRecord::from_decoded(image)?;
            return self.visit_directory_impl(&record, block, false, audit, order, visitor);
        }
        let block_buffer = block_buffer.get_mut(..block_bytes).ok_or(Error::InvalidIndex)?;
        let mut root_value = None;
        let mut allocation = None;
        let mut bitmap = None;
        for item in record.attributes() {
            let attribute = item?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST {
                if !allow_validated_attribute_list {
                    for kind in [ATTR_INDEX_ROOT, ATTR_INDEX_ALLOCATION, ATTR_BITMAP] {
                        record.local_attribute(kind, b"$\0I\x003\x000\0")?;
                    }
                }
                continue;
            }
            if !is_i30(attribute)? {
                continue;
            }
            match attribute.kind {
                ATTR_INDEX_ROOT => {
                    if root_value.replace(attribute.resident_value()?).is_some() {
                        return Err(Error::InvalidIndex);
                    }
                }
                ATTR_INDEX_ALLOCATION => {
                    if allocation.replace(attribute).is_some() {
                        return Err(Error::InvalidIndex);
                    }
                }
                ATTR_BITMAP => {
                    if bitmap.replace(attribute).is_some() {
                        return Err(Error::InvalidIndex);
                    }
                }
                _ => {}
            }
        }
        let root = IndexRoot::parse(root_value.ok_or(Error::InvalidIndex)?)?;
        if root.index_block_bytes() != self.boot.index_block_bytes {
            return Err(Error::InvalidIndex);
        }
        let vcn_unit_bytes = root.vcn_unit_bytes(self.boot.cluster_bytes)?;
        let vcns_per_block = u64::from(self.boot.index_block_bytes) / vcn_unit_bytes;
        let max_blocks = if root.has_children() {
            let allocation = allocation.ok_or(Error::InvalidIndex)?;
            if bitmap.is_none() || allocation.data_size()? % u64::from(self.boot.index_block_bytes) != 0 {
                return Err(Error::InvalidIndex);
            }
            allocation.data_size()? / u64::from(self.boot.index_block_bytes)
        } else {
            if let Some(allocation) = allocation {
                if bitmap.is_none() {
                    return Err(Error::InvalidIndex);
                }
                self.validate_unused_index_allocation(allocation)?;
            }
            0
        };
        let empty = Frame { node: Node::Root, cursor: usize::MAX, after_child: false };
        let mut frames = [empty; MAX_INDEX_DEPTH];
        let mut depth = 1_usize;
        let mut visited_blocks = 0_u64;
        while depth != 0 {
            let frame = frames[depth - 1];
            let (first, has_children, slot) = match frame.node {
                Node::Root => {
                    let first = root.first_entry_offset();
                    let cursor = if frame.cursor == usize::MAX { first } else { frame.cursor };
                    (first, root.has_children(), root.slot_at(cursor)?)
                }
                Node::Block(vcn) => {
                    if vcn % vcns_per_block != 0 || vcn / vcns_per_block >= max_blocks {
                        return Err(Error::InvalidIndex);
                    }
                    let bitmap = bitmap.ok_or(Error::InvalidIndex)?;
                    let bit_number = vcn / vcns_per_block;
                    let byte_offset = bit_number / 8;
                    let mut bit = [0_u8; 1];
                    self.read_attribute(bitmap, byte_offset, &mut bit)?;
                    if bit[0] & (1 << (bit_number % 8)) == 0 {
                        return Err(Error::InvalidIndex);
                    }
                    let byte_offset = vcn.checked_mul(vcn_unit_bytes).ok_or(Error::Overflow)?;
                    self.read_nonresident(allocation.ok_or(Error::InvalidIndex)?, byte_offset, block_buffer)?;
                    let block = IndexBlock::parse(block_buffer, self.boot.bytes_per_sector, vcn)?;
                    let first = block.first_entry_offset();
                    let cursor = if frame.cursor == usize::MAX { first } else { frame.cursor };
                    (first, block.has_children(), block.slot_at(cursor)?)
                }
            };
            let cursor = if frame.cursor == usize::MAX { first } else { frame.cursor };
            if has_children != slot.child_vcn.is_some() {
                return Err(Error::InvalidIndex);
            }
            // The terminal entry sorts after every key of its node.
            let ordering = match &slot.entry {
                Some(entry) => order(entry)?,
                None => Ordering::Less,
            };
            if ordering == Ordering::Greater {
                // This entry and the subtree before it sort before the key.
                frames[depth - 1].cursor = slot.next_offset;
                frames[depth - 1].after_child = false;
                continue;
            }
            if !frame.after_child {
                if let Some(child_vcn) = slot.child_vcn {
                    if depth == MAX_INDEX_DEPTH || visited_blocks >= max_blocks {
                        return Err(Error::Unsupported);
                    }
                    if frames[..depth]
                        .iter()
                        .any(|ancestor| matches!(ancestor.node, Node::Block(vcn) if vcn == child_vcn))
                    {
                        return Err(Error::InvalidIndex);
                    }
                    visited_blocks += 1;
                    frames[depth - 1].cursor = cursor;
                    frames[depth - 1].after_child = true;
                    frames[depth] = Frame { node: Node::Block(child_vcn), cursor: usize::MAX, after_child: false };
                    depth += 1;
                    continue;
                }
            }
            match slot.entry {
                Some(entry) if ordering == Ordering::Equal => {
                    visitor(entry)?;
                    frames[depth - 1].cursor = slot.next_offset;
                    frames[depth - 1].after_child = false;
                }
                // Past the key: the rest of this node sorts after it.
                _ => depth -= 1,
            }
        }
        if audit || !root.has_children() {
            if let Some(bitmap) = bitmap {
                self.validate_index_bitmap(bitmap, max_blocks, visited_blocks)?;
            }
        }
        Ok(())
    }

    /// A leaf can retain index reservations after its last child is removed.
    /// Validate their full mapping without reading unused or uninitialized pages.
    /// The leaf bitmap is checked separately and must have no occupied blocks.
    fn validate_unused_index_allocation(&self, allocation: Attribute<'_>) -> Result<()> {
        if !allocation.nonresident || allocation.flags()? != 0 || allocation.first_vcn()? != 0 {
            return Err(Error::InvalidIndex);
        }
        let cluster_bytes = u64::from(self.boot.cluster_bytes);
        let allocated = allocation.allocated_size()?;
        let data = allocation.data_size()?;
        if allocated % cluster_bytes != 0
            || data > allocated
            || data % u64::from(self.boot.index_block_bytes) != 0
            || allocation.initialized_size()? > data
        {
            return Err(Error::InvalidIndex);
        }
        let capacity = allocated / cluster_bytes;
        let mut end_vcn = 0_u64;
        for run in DataRuns::new(allocation.data_runs()?, 0) {
            let run = run?;
            let lcn = run.lcn.ok_or(Error::InvalidIndex)?;
            let physical_end =
                lcn.checked_add(run.len).and_then(|end| end.checked_mul(cluster_bytes)).ok_or(Error::Overflow)?;
            end_vcn = end_vcn.checked_add(run.len).ok_or(Error::Overflow)?;
            if run.vcn != end_vcn - run.len || end_vcn > capacity || physical_end > self.volume_bytes {
                return Err(Error::InvalidIndex);
            }
        }
        if end_vcn != capacity || allocation.last_vcn()? != end_vcn.wrapping_sub(1) {
            return Err(Error::InvalidIndex);
        }
        Ok(())
    }

    /// Bound offline inventory work; validate all bitmap bytes, including
    /// padding beyond the stream capacity. No allocation or online read cost.
    pub fn validate_index_bitmap(&mut self, bitmap: Attribute<'_>, max_blocks: u64, visited_blocks: u64) -> Result<()> {
        let bytes = bitmap.data_size()?;
        if bytes > 512 * 1024 {
            return Err(Error::Unsupported);
        }
        if bytes % 8 != 0 || bytes < max_blocks.checked_add(7).ok_or(Error::Overflow)? / 8 {
            return Err(Error::InvalidIndex);
        }
        let mut buffer = [0_u8; 512];
        let mut counted = 0_u64;
        for at in (0..bytes).step_by(buffer.len()) {
            let n = (bytes - at).min(buffer.len() as u64) as usize;
            self.read_attribute(bitmap, at, &mut buffer[..n])?;
            for (i, byte) in buffer[..n].iter().enumerate() {
                let first = (at + i as u64) * 8;
                let valid = max_blocks.saturating_sub(first).min(8) as u32;
                let mask = ((1_u16 << valid) - 1) as u8;
                if byte & !mask != 0 {
                    return Err(Error::InvalidIndex);
                }
                counted += u64::from(byte.count_ones());
            }
        }
        if counted != visited_blocks {
            return Err(Error::InvalidIndex);
        }
        Ok(())
    }

    pub fn read_nonresident(&mut self, attribute: Attribute<'_>, offset: u64, output: &mut [u8]) -> Result<()> {
        if !attribute.nonresident || attribute.first_vcn()? != 0 {
            return Err(Error::Unsupported);
        }
        // Compression and EFS encryption need separate decoding layers.
        if attribute.flags()? & (0x0001 | 0x4000) != 0 {
            return Err(Error::Unsupported);
        }
        let data_size = attribute.data_size()?;
        let initialized_size = attribute.initialized_size()?;
        if initialized_size > data_size {
            return Err(Error::InvalidAttribute);
        }
        let last_vcn = attribute.last_vcn()?;
        read_runs(
            &mut self.reader,
            self.volume_bytes,
            u64::from(self.boot.cluster_bytes),
            attribute.data_runs()?,
            last_vcn,
            data_size,
            initialized_size,
            offset,
            output,
        )
    }

    fn read_nonresident_extent(
        &mut self,
        attribute: Attribute<'_>,
        data_size: u64,
        initialized_size: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        if !attribute.nonresident || attribute.flags()? & (0x0001 | 0x4000) != 0 {
            return Err(Error::Unsupported);
        }
        read_runs_checked(
            &mut self.reader,
            self.volume_bytes,
            u64::from(self.boot.cluster_bytes),
            attribute.data_runs()?,
            attribute.first_vcn()?,
            attribute.last_vcn()?,
            data_size,
            initialized_size,
            offset,
            output,
            false,
        )
    }

    fn check_record_buffer(&self, output: &[u8]) -> Result<()> {
        if output.len() != self.boot.record_bytes as usize {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    /// Read a physical range after checking the volume boundary. No write authority.
    pub fn read_physical(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        let end = offset.checked_add(output.len() as u64).ok_or(Error::Overflow)?;
        if end > self.volume_bytes {
            return Err(Error::InvalidGeometry);
        }
        self.reader.read_exact_at(offset, output)
    }
}

fn is_i30(attribute: Attribute<'_>) -> Result<bool> {
    Ok(attribute.name_utf16le()? == b"$\0I\03\00\0")
}

fn listed_attribute<'a>(record: &'a MftRecord<'_>, entry: ListEntry<'_>) -> Result<Attribute<'a>> {
    let mut found = None;
    for item in record.attributes() {
        let attr = item?;
        if attr.kind == entry.kind
            && attr.id == entry.attribute_id
            && attr.name_utf16le()? == entry.name_utf16le
            && (!attr.nonresident || attr.first_vcn()? == entry.first_vcn)
            && (attr.nonresident || entry.first_vcn == 0)
        {
            if found.replace(attr).is_some() {
                return Err(Error::InvalidAttributeList);
            }
        }
    }
    found.ok_or(Error::InvalidAttributeList)
}

fn unnamed_data<'a>(record: &'a MftRecord<'_>) -> Result<Attribute<'a>> {
    let mut data = None;
    for item in record.attributes() {
        let attribute = item?;
        if attribute.kind == ATTR_ATTRIBUTE_LIST {
            return Err(Error::Unsupported);
        }
        if attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() {
            if data.replace(attribute).is_some() {
                return Err(Error::Unsupported);
            }
        }
    }
    data.ok_or(Error::InvalidRecord)
}

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
    )
}

#[allow(clippy::too_many_arguments)]
fn read_runs_checked<R: ReadAt>(
    reader: &mut R,
    volume_bytes: u64,
    cluster_bytes: u64,
    runs: &[u8],
    first_vcn: u64,
    last_vcn: u64,
    data_size: u64,
    initialized_size: u64,
    offset: u64,
    output: &mut [u8],
    complete_stream: bool,
) -> Result<()> {
    if cluster_bytes == 0 {
        return Err(Error::InvalidGeometry);
    }
    let end = offset.checked_add(output.len() as u64).ok_or(Error::Overflow)?;
    if (!output.is_empty() && end > data_size) || initialized_size > data_size {
        return Err(Error::InvalidAttribute);
    }
    if data_size == 0 && output.is_empty() && complete_stream {
        return Ok(());
    }
    if first_vcn > last_vcn {
        return Err(Error::InvalidRunlist);
    }
    let expected_vcns = last_vcn.checked_add(1).ok_or(Error::InvalidRunlist)?;
    let mut total_vcns = first_vcn;
    for item in DataRuns::new(runs, first_vcn) {
        let run = item?;
        if run.vcn != total_vcns {
            return Err(Error::InvalidRunlist);
        }
        total_vcns = total_vcns.checked_add(run.len).ok_or(Error::Overflow)?;
        if total_vcns > expected_vcns {
            return Err(Error::InvalidRunlist);
        }
        if let Some(lcn) = run.lcn {
            let physical_end = lcn
                .checked_add(run.len)
                .and_then(|cluster| cluster.checked_mul(cluster_bytes))
                .ok_or(Error::Overflow)?;
            if physical_end > volume_bytes {
                return Err(Error::InvalidRunlist);
            }
        }
    }
    let covered_bytes = total_vcns.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
    if total_vcns != expected_vcns || (complete_stream && data_size > covered_bytes) {
        return Err(Error::InvalidRunlist);
    }
    if output.is_empty() {
        return Ok(());
    }
    let segment_start = first_vcn.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
    if offset < segment_start || end > covered_bytes {
        return Err(Error::InvalidRunlist);
    }
    let mut cursor = offset;
    let mut written = 0;
    for item in DataRuns::new(runs, first_vcn) {
        let run = item?;
        let run_end = run.vcn.checked_add(run.len).ok_or(Error::Overflow)?;
        let byte_start = run.vcn.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
        let byte_end = run_end.checked_mul(cluster_bytes).ok_or(Error::Overflow)?;
        if cursor >= byte_end || cursor < byte_start {
            continue;
        }
        while cursor < byte_end && cursor < end {
            let available = (byte_end - cursor).min(end - cursor);
            let count = usize::try_from(available).map_err(|_| Error::Overflow)?;
            let dest = &mut output[written..written + count];
            if cursor >= initialized_size || run.lcn.is_none() {
                dest.fill(0);
            } else {
                let initialized_count =
                    usize::try_from((initialized_size - cursor).min(available)).map_err(|_| Error::Overflow)?;
                let physical = run
                    .lcn
                    .ok_or(Error::InvalidRunlist)?
                    .checked_mul(cluster_bytes)
                    .and_then(|base| base.checked_add(cursor - byte_start))
                    .ok_or(Error::Overflow)?;
                let physical_end = physical.checked_add(initialized_count as u64).ok_or(Error::Overflow)?;
                if physical_end > volume_bytes {
                    return Err(Error::InvalidRunlist);
                }
                reader.read_exact_at(physical, &mut dest[..initialized_count])?;
                dest[initialized_count..].fill(0);
            }
            cursor += available;
            written += count;
        }
        if cursor == end {
            return Ok(());
        }
    }
    if cursor == end {
        Ok(())
    } else {
        Err(Error::InvalidRunlist)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
