//! Module: ntfs_rs::tx
//! Purpose: Assemble bounded metadata transactions and physical MFT families.
//! Created: 2026-10-01
//! Architecture: Operations edit caller-owned record, index and bitmap images without heap
//! or OS resources. Commit validates all images before the shared journal
//! publishes them; an earlier error cannot change the volume.

use super::allocation::{find_free_run_planned, BitmapPlan, BITMAP_PLAN_BYTES, BITMAP_SLOT};
use super::attrlist::ListEntry;
use super::batch::{Ranges, QUARANTINE};
use super::boot::BootSector;
use super::bytes::{u16_at, u64_at};
use super::metadata_tx::{patch_scratch_bytes, patch_slots, MetadataPatch, COMMIT_SCRATCH_BYTES, MAX_PATCHES};
use super::mft::{file_reference, reference_number, reference_sequence, Attribute, MftRecord, ATTR_BITMAP, ATTR_DATA};
use super::record_edit;
use super::resident_writer::{mapped, unnamed};
use super::resident_writer::{WriteIo, Writer};
use super::runlist::DataRuns;
use super::upcase::UPCASE_BYTES;
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

/// The largest file record the writer admits; a volume's own size is in
/// its boot sector.
pub const MAX_RECORD: usize = super::boot::MAX_WRITER_RECORD_BYTES;
/// Bytes in an index block, the only size the writer admits.
pub const BLOCK: usize = 4096;
/// Bytes one device request of the transaction's own buffer carries.
pub(crate) const IO_CHUNK: usize = 4096;
pub(crate) const REC_HEAD: usize = 32;
/// Logical record assembly is scratch only; publication always emits 1 KiB records.
pub const RECORD_IMAGE: usize = 16 * 1024;
pub(crate) const REC_SLOT: usize = REC_HEAD + MAX_RECORD + RECORD_IMAGE;
pub const MAX_RECORDS: usize = 16;
pub(crate) const NODE_HEAD: usize = 64;
pub(crate) const NODE_WORK: usize = 8192;
pub(crate) const NODE_SLOT: usize = NODE_HEAD + BLOCK + NODE_WORK;
pub const MAX_NODES: usize = 20;
/// Cluster ranges one transaction can free before a drain is forced.
const TX_FREED: usize = 16;
pub(crate) const TEMP: usize = 1024;
pub(crate) const TEMPS: usize = 4;
// Record slot header.
pub(crate) const R_USED: u8 = 1;
pub(crate) const R_DIRTY: u8 = 2;
// Record slot family state: unloaded, assembled, physically packed, or selective.
pub(crate) const FAMILY_STATE: usize = 25;
pub(crate) const FAMILY_ASSEMBLED: u8 = 1;
pub(crate) const FAMILY_PACKED: u8 = 2;
pub(crate) const FAMILY_SELECTIVE: u8 = 3;
/// Room kept in a base record for the descriptor of its attribute list
/// while the family's other attributes are placed.
pub(crate) const LIST_RESERVE: usize = 96;
/// Room kept in record 0 for $MFT's resident attribute list: its header and
/// an entry for each attribute of record 0 and for a map segment in every
/// reserved extension record. A longer list goes to clusters of its own.
const TABLE_LIST_RESERVE: usize = 24 + 32 * (4 + 8);
// Selective namespace edits preserve duplicated stream metadata; orphan cleanup
// has no remaining filenames to refresh.
pub(crate) const SKIP_FILENAME_REFRESH: usize = 26;
// Journal (64 KiB), old/new EA streams (160 KiB), and security/tree work
// (160 KiB). The checked family visitor uses the rest of the 2 MiB arena.
const OPERATION_WORKSPACE: usize = 384 * 1024;
// Node slot header flags.
pub(crate) const N_USED: u8 = 1;
pub(crate) const N_DIRTY: u8 = 2;
pub(crate) const N_FRESH: u8 = 4;
pub(crate) const N_FREED: u8 = 8;
pub(crate) const N_ROOT: u8 = 16;

pub struct Tx<'s> {
    pub(crate) linux_compatibility: bool,
    pub(crate) boot: BootSector,
    pub(crate) records: &'s mut [u8],
    pub(crate) nodes: &'s mut [u8],
    pub(crate) family: &'s mut [u8],
    pub(crate) namespace_work: &'s mut [u8],
    pub(crate) temp: &'s mut [u8],
    pub(crate) io_buf: &'s mut [u8],
    pub(crate) mft_zero: &'s mut [u8],
    pub(crate) bitmap_record: &'s mut [u8],
    pub(crate) upcase: &'s mut [u8],
    pub(crate) upcase_loaded: bool,
    pub(crate) clusters: BitmapPlan<'s>,
    pub(crate) mft_bits: BitmapPlan<'s>,
    pub(crate) aux_bits: BitmapPlan<'s>,
    /// Owner record slot and index kind code whose nonresident index bitmap
    /// is tracked by aux_bits.
    pub(crate) aux_owner: Option<(usize, u8)>,
    /// A copy of the writer's journal map: a few words that view every piece.
    log: super::resident_writer::LogMap,
    /// Ranges freed by earlier deferred transactions: free on disk, not yet
    /// durable, so not allocatable.
    blocked: Ranges<QUARANTINE>,
    /// Ranges this transaction frees; freed_overflow when they did not fit.
    freed: Ranges<TX_FREED>,
    freed_overflow: bool,
    total_clusters: u64,
    next_record: u64,
    next_cluster: u64,
}

fn split<'s>(bytes: &'s mut [u8], n: usize) -> Result<(&'s mut [u8], &'s mut [u8])> {
    if bytes.len() < n {
        return Err(Error::Truncated);
    }
    Ok(bytes.split_at_mut(n))
}

/// The parts of a record slot: its head, the record as loaded and its image.
fn slot_parts(slot: &mut [u8], record_bytes: usize) -> (&mut [u8], &mut [u8], &mut [u8]) {
    let (head, rest) = slot.split_at_mut(REC_HEAD);
    let (before, after) = rest.split_at_mut(MAX_RECORD);
    (head, &mut before[..record_bytes], after)
}

impl<'s> Tx<'s> {
    /// Split scratch and snapshot $MFT record 0 and $Bitmap record 6.
    pub fn new<R: ReadAt>(
        writer: &Writer,
        volume: &mut Volume<R>,
        scratch: &'s mut [u8],
    ) -> Result<(Self, &'s mut [u8])> {
        let boot = writer.boot;
        let record_bytes = boot.record_bytes as usize;
        if record_bytes > MAX_RECORD || boot.index_block_bytes as usize != BLOCK {
            return Err(Error::Unsupported);
        }
        let (records, rest) = split(scratch, MAX_RECORDS * REC_SLOT)?;
        let (nodes, rest) = split(rest, MAX_NODES * NODE_SLOT)?;
        let (family, rest) = split(rest, 2 * RECORD_IMAGE + MAX_RECORD)?;
        let (temp, rest) = split(rest, TEMPS * TEMP)?;
        let (a, rest) = split(rest, BITMAP_PLAN_BYTES)?;
        let (b, rest) = split(rest, BITMAP_PLAN_BYTES)?;
        let (c, rest) = split(rest, BITMAP_PLAN_BYTES)?;
        let (mft_space, rest) = split(rest, super::volume::mft_space_bytes(record_bytes))?;
        let (bitmap_record, rest) = split(rest, record_bytes)?;
        let (io_buf, rest) = split(rest, IO_CHUNK)?;
        let (upcase, rest) = split(rest, UPCASE_BYTES)?;
        // Keep the namespace visitor separate from physical record slots.
        // The remaining operation workspace covers journal, EA and security edits.
        let reserve = rest.len().saturating_sub(OPERATION_WORKSPACE);
        let (namespace_work, rest) = split(rest, reserve)?;
        records.fill(0);
        nodes[..].chunks_exact_mut(NODE_SLOT).for_each(|n| n[..NODE_HEAD].fill(0));
        // The map of the whole table, also when it is split across records.
        let mft_zero = {
            let range = volume.locate_mft(mft_space)?;
            &mut mft_space[range]
        };
        let mft = MftRecord::from_decoded(mft_zero)?;
        unnamed(&mft, ATTR_DATA)?;
        volume.read_mft_record(&mft, 6, bitmap_record)?;
        let bitmap = MftRecord::parse(bitmap_record, 512)?;
        unnamed(&bitmap, ATTR_DATA)?;
        let total_clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
        Ok((
            Self {
                linux_compatibility: writer.linux_compatibility,
                boot,
                records,
                nodes,
                family,
                namespace_work,
                temp,
                io_buf,
                mft_zero,
                bitmap_record,
                upcase,
                upcase_loaded: false,
                clusters: BitmapPlan::new(a)?,
                mft_bits: BitmapPlan::new(b)?,
                aux_bits: BitmapPlan::new(c)?,
                aux_owner: None,
                log: writer.log,
                blocked: writer.blocked(),
                freed: Ranges::new(),
                freed_overflow: false,
                total_clusters,
                next_record: writer.next_record,
                next_cluster: writer.next_cluster,
            },
            rest,
        ))
    }

    pub fn load_upcase<R: ReadAt>(&mut self, volume: &mut Volume<R>) -> Result<()> {
        if self.upcase_loaded {
            return Ok(());
        }
        let mft = MftRecord::from_decoded(self.mft_zero)?;
        let (raw, _) = self.io_buf.split_at_mut(self.boot.record_bytes as usize);
        volume.read_mft_record(&mft, 10, raw)?;
        let record = MftRecord::parse(raw, 512)?;
        volume.read_attribute(unnamed(&record, ATTR_DATA)?, 0, self.upcase)?;
        super::upcase::UpcaseTable::parse(self.upcase)?;
        self.upcase_loaded = true;
        Ok(())
    }

    pub fn mft_reference(&self) -> Result<u64> {
        file_reference(0, MftRecord::from_decoded(self.mft_zero)?.sequence_number()?)
    }
    pub fn bitmap_reference(&self) -> Result<u64> {
        file_reference(6, MftRecord::from_decoded(self.bitmap_record)?.sequence_number()?)
    }
    pub fn mft_zero(&self) -> &[u8] {
        self.mft_zero
    }

    // ----- Volume geometry ---------------------------------------------------

    /// Bytes in one file record of this volume.
    pub(crate) fn record_bytes(&self) -> usize {
        self.boot.record_bytes as usize
    }

    /// Bytes in one cluster of this volume.
    pub(crate) fn cluster_bytes(&self) -> u64 {
        u64::from(self.boot.cluster_bytes)
    }

    /// Index VCNs one index block spans.
    pub(crate) fn index_block_vcns(&self) -> u64 {
        BLOCK as u64 / self.boot.index_vcn_bytes()
    }

    /// Give a record's image the capacity of a file record, less a reserve.
    pub(crate) fn limit_record(&mut self, slot: usize, reserve: usize) -> Result<()> {
        let capacity = self.record_bytes() - reserve;
        record_edit::p32(self.record_mut(slot), 28, capacity as u32)
    }

    // ----- MFT record slots -------------------------------------------------

    pub(crate) fn rec_slot(&self, i: usize) -> &[u8] {
        &self.records[i * REC_SLOT..(i + 1) * REC_SLOT]
    }
    pub(crate) fn rec_slot_mut(&mut self, i: usize) -> &mut [u8] {
        &mut self.records[i * REC_SLOT..(i + 1) * REC_SLOT]
    }
    pub fn record_number(&self, i: usize) -> u64 {
        u64_at(self.rec_slot(i), 0).unwrap_or(u64::MAX)
    }
    /// File reference (sequence number from the preimage) of a loaded record.
    pub fn record_reference(&self, i: usize) -> Result<u64> {
        file_reference(self.record_number(i), u16_at(self.record_before(i), 16)?)
    }
    pub fn record(&self, i: usize) -> &[u8] {
        &self.rec_slot(i)[REC_HEAD + MAX_RECORD..REC_SLOT]
    }
    pub fn record_before(&self, i: usize) -> &[u8] {
        &self.rec_slot(i)[REC_HEAD..REC_HEAD + self.record_bytes()]
    }
    pub fn record_mut(&mut self, i: usize) -> &mut [u8] {
        let slot = self.rec_slot_mut(i);
        slot[24] |= R_DIRTY;
        &mut slot[REC_HEAD + MAX_RECORD..REC_SLOT]
    }
    /// Load an allocated base record once. Its sequence number is checked when
    /// reference carries one (non-zero upper 16 bits).
    pub fn load_record<R: ReadAt>(&mut self, volume: &mut Volume<R>, reference: u64) -> Result<usize> {
        let number = reference_number(reference);
        let mut free = None;
        for i in 0..MAX_RECORDS {
            let slot = self.rec_slot(i);
            if slot[24] & R_USED != 0 {
                if u64_at(slot, 0)? == number {
                    self.check_sequence(i, reference)?;
                    return Ok(i);
                }
            } else if free.is_none() {
                free = Some(i);
            }
        }
        let i = free.ok_or(Error::Unsupported)?;
        let mft = MftRecord::from_decoded(self.mft_zero)?;
        let mft_data = unnamed(&mft, ATTR_DATA)?;
        let record_bytes = self.record_bytes();
        let physical = mapped(mft_data, self.boot, number * record_bytes as u64, record_bytes as u64)?;
        let mut bit = [0];
        volume.read_attribute(unnamed(&mft, ATTR_BITMAP)?, number / 8, &mut bit)?;
        if bit[0] & (1 << (number % 8)) == 0 {
            return Err(Error::InvalidRecord);
        }
        let slot = &mut self.records[i * REC_SLOT..(i + 1) * REC_SLOT];
        let (head, before, after) = slot_parts(slot, record_bytes);
        volume.reader_mut().read_exact_at(physical, before)?;
        MftRecord::parse(before, 512)?;
        let record = MftRecord::from_decoded(before)?;
        if record.flags()? & 1 == 0 {
            return Err(Error::InvalidRecord);
        }
        record_edit::validate(before)?;
        after.fill(0);
        after[..record_bytes].copy_from_slice(before);
        record_edit::p32(after, 28, RECORD_IMAGE as u32)?;
        head.fill(0);
        head[..8].copy_from_slice(&number.to_le_bytes());
        head[8..16].copy_from_slice(&physical.to_le_bytes());
        head[24] = R_USED;
        self.check_sequence(i, reference)?;
        Ok(i)
    }

    /// Load and validate every listed member, then assemble logical attributes
    /// in the base scratch image. Extension records remain as journal preimages.
    pub fn load_family<R: ReadAt>(&mut self, volume: &mut Volume<R>, reference: u64) -> Result<usize> {
        let base = self.load_record(volume, reference)?;
        if self.rec_slot(base)[FAMILY_STATE] != 0 {
            return Ok(base);
        }
        if MftRecord::from_decoded(self.record(base))?.base_file_reference()? != 0 {
            return Err(Error::InvalidAttributeList);
        }
        let buffers = core::mem::take(&mut self.family);
        let result = self.assemble_family(volume, base, buffers);
        self.family = buffers;
        result?;
        self.rec_slot_mut(base)[FAMILY_STATE] = FAMILY_ASSEMBLED;
        Ok(base)
    }

    fn assemble_family<R: ReadAt>(&mut self, volume: &mut Volume<R>, base: usize, buffers: &mut [u8]) -> Result<()> {
        let (image, list) = buffers.split_at_mut(RECORD_IMAGE);
        let mut length = 0;
        let mut list_at = None;
        for a in MftRecord::from_decoded(self.record(base))?.attributes() {
            let a = a?;
            if a.kind == 0x20 {
                if list_at.replace(a.record_offset()).is_some()
                    || a.flags()? != 0
                    || !a.name_utf16le()?.is_empty()
                    || (a.nonresident && a.first_vcn()? != 0)
                {
                    return Err(Error::InvalidAttributeList);
                }
                length = usize::try_from(a.data_size()?).map_err(|_| Error::Overflow)?;
                if length == 0 || length > list.len() {
                    return Err(Error::NoSpace);
                }
                volume.read_attribute(a, 0, &mut list[..length])?;
            }
        }
        if length == 0 {
            return Ok(());
        }
        let reference = self.record_reference(base)?;
        let mut seen = [0u128; MAX_RECORDS];
        image.copy_from_slice(self.record(base));
        let start = usize::from(u16_at(image, 20)?);
        image[start..].fill(0);
        record_edit::p32(image, start, u32::MAX)?;
        record_edit::p32(image, 24, (start + 8) as u32)?;
        record_edit::p16(image, 40, 0)?;
        for entry in super::attrlist::AttributeList::new(&list[..length]) {
            let entry = entry?;
            if entry.kind == 0x20 || reference_sequence(entry.file_reference) == 0 {
                return Err(Error::InvalidAttributeList);
            }
            let slot = self.load_record(volume, entry.file_reference)?;
            let record = MftRecord::from_decoded(self.record(slot))?;
            if slot != base && record.base_file_reference()? != reference {
                return Err(Error::InvalidAttributeList);
            }
            let mut found = false;
            for (index, a) in record.attributes().enumerate() {
                let a = a?;
                if index >= 128 {
                    return Err(Error::NoSpace);
                }
                if a.id != entry.attribute_id {
                    continue;
                }
                if found
                    || seen[slot] & (1u128 << index) != 0
                    || a.kind != entry.kind
                    || a.name_utf16le()? != entry.name_utf16le
                    || (if a.nonresident { a.first_vcn()? } else { 0 }) != entry.first_vcn
                {
                    return Err(Error::InvalidAttributeList);
                }
                let at = a.record_offset();
                let n = record_edit::attr_len(self.record(slot), at)?;
                record_edit::merge_attribute(image, &self.record(slot)[at..at + n])?;
                seen[slot] |= 1u128 << index;
                found = true;
            }
            if !found {
                return Err(Error::InvalidAttributeList);
            }
        }
        for slot in 0..MAX_RECORDS {
            if !self.family_member(base, slot)? {
                continue;
            }
            for (index, a) in MftRecord::from_decoded(self.record(slot))?.attributes().enumerate() {
                let a = a?;
                if a.kind != 0x20 && (index >= 128 || seen[slot] & (1u128 << index) == 0) {
                    return Err(Error::InvalidAttributeList);
                }
            }
        }
        // Preserve ownership of an old list until commit; its allocation is
        // released while packing, never overwritten by newly staged contents.
        if let Some(at) = list_at {
            if record_edit::is_nonresident(self.record(base), at)? {
                self.free_attribute_runs(volume, base, at)?;
            }
        }
        for slot in 0..MAX_RECORDS {
            if slot == base || !self.family_member(base, slot)? {
                continue;
            }
            let rec = self.record_mut(slot);
            let start = usize::from(u16_at(rec, 20)?);
            rec[start..].fill(0);
            record_edit::p32(rec, start, u32::MAX)?;
            record_edit::p32(rec, 24, (start + 8) as u32)?;
            record_edit::p16(rec, 40, 0)?;
        }
        self.record_mut(base).copy_from_slice(image);
        Ok(())
    }

    pub(crate) fn family_member(&self, base: usize, slot: usize) -> Result<bool> {
        Ok(self.rec_slot(slot)[24] & R_USED != 0
            && u16_at(self.record(slot), 22)? & 1 != 0
            && (slot == base || u64_at(self.record(slot), 32)? == self.record_reference(base)?))
    }

    pub(crate) fn name_location(&self, base: usize, parent: u64, name: &[u8], native: bool) -> Result<(usize, usize)> {
        let mut found = None;
        for slot in 0..MAX_RECORDS {
            if !self.family_member(base, slot)? {
                continue;
            }
            if let Some(at) = super::namespace_writer::find_linked_name(self, self.record(slot), parent, name, native)?
            {
                if found.replace((slot, at)).is_some() {
                    return Err(Error::InvalidAttributeList);
                }
            }
        }
        found.ok_or(Error::NotFound)
    }

    pub(crate) fn insert_family_name<R: ReadAt>(
        &mut self,
        _volume: &mut Volume<R>,
        base: usize,
        image: &[u8],
        _extensions_only: bool,
    ) -> Result<()> {
        self.insert_family_attribute(_volume, base, image)
    }

    /// Insert edited metadata in a physical record while DATA segments remain
    /// untouched. The family packer handles assembled transaction images.
    pub(crate) fn insert_family_attribute<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
        image: &[u8],
    ) -> Result<()> {
        if self.preserved_family(base) {
            match record_edit::insert(self.record_mut(base), image) {
                Ok(_) => return Ok(()),
                Err(Error::NoSpace) => (),
                Err(e) => return Err(e),
            }
            let reference = self.record_reference(base)?;
            let slot = self.allocate_record(volume)?;
            let number = self.record_number(slot);
            let sequence = reference_sequence(self.record_reference(slot)?);
            let record_bytes = self.record_bytes();
            record_edit::format_empty(&mut self.record_mut(slot)[..record_bytes], number)?;
            record_edit::p16(self.record_mut(slot), 16, sequence)?;
            record_edit::p16(self.record_mut(slot), 22, 1)?;
            record_edit::p64(self.record_mut(slot), 32, reference)?;
            record_edit::insert(self.record_mut(slot), image)?;
            self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_SELECTIVE;
            return Ok(());
        }
        record_edit::insert(self.record_mut(base), image)?;
        self.rec_slot_mut(base)[FAMILY_STATE] = FAMILY_ASSEMBLED;
        Ok(())
    }

    /// Pack a logical record into standard records. Large runlists split only
    /// at run boundaries. A standard nonresident list avoids recursive list growth.
    // Kernel stacks are small: this frame must end before the commit descends
    // into the journal and the block layer.
    #[inline(never)]
    fn pack_family<R: WriteIo>(
        &mut self,
        volume: &mut Volume<&mut R>,
        writer: &mut Writer,
        base: usize,
        buffers: &mut [u8],
    ) -> Result<()> {
        let (image, rest) = buffers.split_at_mut(RECORD_IMAGE);
        let (list, segment) = rest.split_at_mut(RECORD_IMAGE);
        let record_bytes = self.record_bytes();
        image.copy_from_slice(self.record(base));
        let reference = self.record_reference(base)?;
        let live = u16_at(image, 22)? & 1 != 0;
        let table = self.record_number(base) == 0;
        // $MFT alone among the system files may spread over several records:
        // its map grows with every extent. It stays in one record while it
        // fits there and has no extension records to give back.
        let table_split = table
            && (record_edit::used(image)? > record_bytes
                || (0..MAX_RECORDS).any(|slot| {
                    slot != base
                        && self.rec_slot(slot)[24] & R_USED != 0
                        && u64_at(self.record(slot), 32).ok() == Some(reference)
                }));
        if matches!(self.record_number(base), 1 | 2 | 6)
            || (table && !table_split)
            || (!table && self.rec_slot(base)[FAMILY_STATE] == 0 && record_edit::used(image)? <= record_bytes)
        {
            if record_edit::used(image)? > record_bytes {
                return Err(Error::NoSpace);
            }
            self.limit_record(base, 0)?;
            self.rec_slot_mut(base)[FAMILY_STATE] = FAMILY_PACKED;
            return Ok(());
        }
        if !live {
            let start = usize::from(u16_at(image, 20)?);
            let rec = self.record_mut(base);
            rec[start..].fill(0);
            record_edit::p32(rec, start, u32::MAX)?;
            record_edit::p32(rec, 24, (start + 8) as u32)?;
        }
        let members: [bool; MAX_RECORDS] = core::array::from_fn(|slot| {
            slot != base
                && self.rec_slot(slot)[24] & R_USED != 0
                && u64_at(self.record(slot), 32).ok() == Some(reference)
        });
        let mut used = [false; MAX_RECORDS];
        used[base] = true;
        if live {
            let start = usize::from(u16_at(image, 20)?);
            let rec = self.record_mut(base);
            rec[start..].fill(0);
            record_edit::p32(rec, start, u32::MAX)?;
            record_edit::p32(rec, 24, (start + 8) as u32)?;
            record_edit::p16(rec, 40, 0)?;
            // Reserve enough base space for either resident or nonresident list.
            // $MFT's list stays resident while its reserved records suffice,
            // so record 0 and its list then reach the disk as one image.
            let list_reserve = if table { TABLE_LIST_RESERVE } else { LIST_RESERVE };
            record_edit::p32(rec, 28, (record_bytes - list_reserve) as u32)?;
            let mut list_len = 0;
            for a in MftRecord::from_decoded(image)?.attributes() {
                let a = a?;
                if a.kind == 0x20 {
                    return Err(Error::InvalidAttributeList);
                }
                let at = a.record_offset();
                let n = record_edit::attr_len(image, at)?;
                if table && a.kind == ATTR_DATA && a.nonresident && a.name_utf16le()?.is_empty() {
                    // Smaller attributes that follow keep their place in record 0.
                    let mut later = 0;
                    for other in MftRecord::from_decoded(image)?.attributes() {
                        let other = other?;
                        let length = record_edit::attr_len(image, other.record_offset())?;
                        if other.record_offset() > at && length <= record_edit::attribute_room(record_bytes) {
                            later += length;
                        }
                    }
                    self.pack_table_map(volume, base, &members, &mut used, a, later, (list, &mut list_len), segment)?;
                } else if n <= record_edit::attribute_room(record_bytes) {
                    self.pack_attribute(volume, base, &members, &mut used, &image[at..at + n], list, &mut list_len)?;
                } else if a.nonresident {
                    self.pack_runs(volume, base, &members, &mut used, a, (list, &mut list_len), segment)?;
                } else {
                    return Err(Error::NoSpace);
                }
            }
            self.limit_record(base, 0)?;
            if used.iter().enumerate().any(|(i, used)| i != base && *used) {
                let attr = &mut segment[..record_bytes];
                let resident = record_edit::build_resident(0x20, &[], &list[..list_len], attr)
                    .and_then(|n| record_edit::insert(self.record_mut(base), &attr[..n]));
                if matches!(resident, Err(Error::NoSpace) | Err(Error::Unsupported)) {
                    let cluster = self.cluster_bytes();
                    let count = (list_len as u64).div_ceil(cluster);
                    let lcn = self.allocate_clusters(volume, count, None)?;
                    stage_bytes(writer, &mut **volume.reader_mut(), lcn * cluster, &list[..list_len], self.io_buf)?;
                    let run = super::runlist::Extent { vcn: 0, len: count, lcn: Some(lcn) };
                    let n = record_edit::build_nonresident(
                        0x20,
                        &[],
                        &[run],
                        count * cluster,
                        list_len as u64,
                        list_len as u64,
                        attr,
                    )?;
                    record_edit::insert(self.record_mut(base), &attr[..n])?;
                } else {
                    resident?;
                }
            }
        }
        for slot in 0..MAX_RECORDS {
            if members[slot] && !used[slot] {
                let number = self.record_number(slot);
                let sequence = super::mft::next_sequence(self.record(slot))?;
                record_edit::format_empty(&mut self.record_mut(slot)[..record_bytes], number)?;
                record_edit::p16(self.record_mut(slot), 16, sequence)?;
                self.mark_record(volume, number, false)?;
            }
            if slot == base || used[slot] || members[slot] {
                self.limit_record(slot, 0)?;
                self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_PACKED;
            }
        }
        Ok(())
    }

    /// Fill each extension record with whole encoded mapping pairs. Splitting
    /// every sixteen runs wastes most of each record and makes fragmented
    /// copies exhaust MAX_RECORDS long before the byte capacity is reached.
    // Kernel stacks are small: this frame must end before the commit descends
    // into the journal and the block layer.
    #[inline(never)]
    fn pack_runs<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
        members: &[bool; MAX_RECORDS],
        used: &mut [bool; MAX_RECORDS],
        attribute: Attribute<'_>,
        (list, list_len): (&mut [u8], &mut usize),
        segment: &mut [u8],
    ) -> Result<()> {
        let attr = &mut segment[..record_edit::attribute_room(self.record_bytes())];
        let mut first_vcn = attribute.first_vcn()?;
        let end_vcn = attribute.last_vcn()?.checked_add(1).ok_or(Error::Overflow)?;
        while first_vcn < end_vcn {
            // Leave room for the FILE header, USA and end marker. Encoding
            // streams directly into this bounded buffer without a run table.
            let (length, next_vcn) = record_edit::pack_mapping_segment(attribute, first_vcn, attr)?;
            self.pack_attribute(volume, base, members, used, &attr[..length], list, list_len)?;
            first_vcn = next_vcn;
        }
        Ok(())
    }

    /// Pack $MFT's own map. Its first segment must stay in record 0, from
    /// which every reader starts, and takes the room left there after
    /// `reserve` bytes for the attributes that follow; later segments go to
    /// extension records.
    // Kernel stacks are small: this frame must end before the commit descends
    // into the journal and the block layer.
    #[inline(never)]
    fn pack_table_map<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
        members: &[bool; MAX_RECORDS],
        used: &mut [bool; MAX_RECORDS],
        attribute: Attribute<'_>,
        reserve: usize,
        (list, list_len): (&mut [u8], &mut usize),
        segment: &mut [u8],
    ) -> Result<()> {
        let attr = &mut segment[..record_edit::attribute_room(self.record_bytes())];
        let (cluster, record) = (self.cluster_bytes(), self.record_bytes() as u64);
        let free = record_edit::capacity(self.record(base))?.saturating_sub(record_edit::used(self.record(base))?);
        let budget = free.saturating_sub(reserve).min(attr.len()) & !7;
        let end_vcn = attribute.last_vcn()?.checked_add(1).ok_or(Error::Overflow)?;
        let (length, mut first_vcn) = record_edit::pack_mapping_segment(attribute, 0, &mut attr[..budget])?;
        // The reserved extension records are read through this segment alone.
        if first_vcn < end_vcn && first_vcn * cluster / record < super::mft_growth::FIRST_USER_RECORD {
            return Err(Error::NoSpace);
        }
        let at = record_edit::insert(self.record_mut(base), &attr[..length])?;
        self.list_entry(base, at, &attr[..length], list, list_len)?;
        while first_vcn < end_vcn {
            let (length, next_vcn) = record_edit::pack_mapping_segment(attribute, first_vcn, attr)?;
            // A reader finds this segment through the ones before it, so
            // its record must lie among the records they map.
            let reach = first_vcn * cluster / record;
            self.pack_attribute_within(volume, base, members, used, &attr[..length], list, list_len, reach)?;
            first_vcn = next_vcn;
        }
        Ok(())
    }

    /// Take a free record for one of $MFT's extension records, below reach:
    /// first among those NTFS reserves for the purpose, whose bitmap bits
    /// stay set while they are free, then any free record. Running out is
    /// a lack of space: the caller may gather the map into fewer extents.
    // Kernel stacks are small: this frame must end before the commit descends
    // into the journal and the block layer.
    #[inline(never)]
    fn allocate_table_extension<R: ReadAt>(&mut self, volume: &mut Volume<R>, reach: u64) -> Result<usize> {
        let end = self.record_limit()?.min(reach);
        let record_bytes = self.record_bytes();
        let mut number = super::mft_growth::FIRST_TABLE_EXTENSION;
        while number < end {
            if number >= super::mft_growth::FIRST_USER_RECORD {
                match self.free_record(volume, number, end)? {
                    Some(free) => number = free,
                    None => break,
                }
            } else if self.record_loaded(number) {
                number += 1;
                continue;
            }
            let Some(i) = (0..MAX_RECORDS).find(|&i| self.rec_slot(i)[24] & R_USED == 0) else {
                break;
            };
            let (physical, marked) = {
                let mft = MftRecord::from_decoded(self.mft_zero)?;
                let data = unnamed(&mft, ATTR_DATA)?;
                let physical = mapped(data, self.boot, number * record_bytes as u64, record_bytes as u64)?;
                let mut bit = [0];
                volume.read_attribute(unnamed(&mft, ATTR_BITMAP)?, number / 8, &mut bit)?;
                (physical, bit[0] & (1 << (number % 8)) != 0)
            };
            let (head, before, after) = slot_parts(self.rec_slot_mut(i), record_bytes);
            volume.reader_mut().read_exact_at(physical, before)?;
            let free = MftRecord::parse(before, 512)
                .and_then(|record| Ok(record.flags()? & 1 == 0 && record.sequence_number()? != 0))
                .unwrap_or(false);
            if !free || record_edit::validate(before).is_err() {
                number += 1;
                continue;
            }
            after.fill(0);
            after[..record_bytes].copy_from_slice(before);
            record_edit::p32(after, 28, RECORD_IMAGE as u32)?;
            head.fill(0);
            head[..8].copy_from_slice(&number.to_le_bytes());
            head[8..16].copy_from_slice(&physical.to_le_bytes());
            head[24] = R_USED;
            if !marked {
                self.mark_record(volume, number, true)?;
            }
            return Ok(i);
        }
        Err(Error::NoSpace)
    }

    /// Append the attribute-list entry of the attribute at `at` in `slot`.
    fn list_entry(&self, slot: usize, at: usize, attr: &[u8], list: &mut [u8], list_len: &mut usize) -> Result<()> {
        let entry = ListEntry {
            kind: super::bytes::u32_at(attr, 0)?,
            first_vcn: if attr[8] != 0 { u64_at(attr, 16)? } else { 0 },
            file_reference: self.record_reference(slot)?,
            attribute_id: u16_at(self.record(slot), at + 14)?,
            name_utf16le: record_edit::attr_name(attr, 0)?,
        };
        let n = entry.encoded_len()?;
        let out = list.get_mut(*list_len..*list_len + n).ok_or(Error::NoSpace)?;
        entry.encode(out)?;
        *list_len += n;
        Ok(())
    }

    // Kernel stacks are small: this frame must end before the commit descends
    // into the journal and the block layer.
    #[inline(never)]
    fn pack_attribute<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
        members: &[bool; MAX_RECORDS],
        used: &mut [bool; MAX_RECORDS],
        attr: &[u8],
        list: &mut [u8],
        list_len: &mut usize,
    ) -> Result<()> {
        self.pack_attribute_within(volume, base, members, used, attr, list, list_len, u64::MAX)
    }

    /// Place an attribute in the base record or in an extension record
    /// whose number is below reach.
    // Kernel stacks are small: this frame must end before the commit descends
    // into the journal and the block layer.
    #[inline(never)]
    fn pack_attribute_within<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
        members: &[bool; MAX_RECORDS],
        used: &mut [bool; MAX_RECORDS],
        attr: &[u8],
        list: &mut [u8],
        list_len: &mut usize,
        reach: u64,
    ) -> Result<()> {
        let mut target = None;
        for slot in 0..MAX_RECORDS {
            if slot != base && (!used[slot] || self.record_number(slot) >= reach) {
                continue;
            }
            // A record can contain multiple segments, but our editor deliberately
            // keeps one segment per type/name in each published record.
            match record_edit::insert(self.record_mut(slot), attr) {
                Ok(at) => {
                    target = Some((slot, at));
                    break;
                }
                Err(Error::NoSpace) | Err(Error::InvalidAttribute) => (),
                Err(e) => return Err(e),
            }
        }
        let (slot, at) = if let Some(target) = target {
            target
        } else {
            let spare = (0..MAX_RECORDS).find(|&s| members[s] && !used[s] && self.record_number(s) < reach);
            let slot = if let Some(slot) = spare {
                slot
            } else if self.record_number(base) == 0 {
                self.allocate_table_extension(volume, reach)?
            } else {
                self.allocate_record(volume)?
            };
            let reference = self.record_reference(base)?;
            let number = self.record_number(slot);
            let sequence = reference_sequence(self.record_reference(slot)?);
            let record_bytes = self.record_bytes();
            let rec = self.record_mut(slot);
            record_edit::format_empty(&mut rec[..record_bytes], number)?;
            record_edit::p16(rec, 16, sequence)?;
            record_edit::p16(rec, 22, 1)?;
            record_edit::p64(rec, 32, reference)?;
            let at = record_edit::insert(rec, attr)?;
            used[slot] = true;
            (slot, at)
        };
        self.list_entry(slot, at, attr, list, list_len)
    }

    fn check_sequence(&self, i: usize, reference: u64) -> Result<()> {
        let seq = reference_sequence(reference);
        if seq != 0 && u16_at(self.record_before(i), 16)? != seq {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    /// Load a free, initialized user record. Its tombstone is the undo image;
    /// allocation is published in the same transaction as the new namespace.
    pub fn allocate_record<R: ReadAt>(&mut self, volume: &mut Volume<R>) -> Result<usize> {
        let limit = self.record_limit()?;
        let mut number = None;
        let first = super::mft_growth::FIRST_USER_RECORD;
        let cursor = self.next_record.clamp(first, limit.max(first));
        for (from, end) in [(cursor, limit), (first, cursor)] {
            number = self.free_record(volume, from, end)?;
            if number.is_some() {
                break;
            }
        }
        let mft = MftRecord::from_decoded(self.mft_zero)?;
        let data = unnamed(&mft, ATTR_DATA)?;
        let number = number.ok_or(Error::NoSpace)?;
        let i = (0..MAX_RECORDS).find(|&i| self.rec_slot(i)[24] & R_USED == 0).ok_or(Error::Unsupported)?;
        let record_bytes = self.record_bytes();
        let physical = mapped(data, self.boot, number * record_bytes as u64, record_bytes as u64)?;
        let (head, before, after) = slot_parts(self.rec_slot_mut(i), record_bytes);
        volume.reader_mut().read_exact_at(physical, before)?;
        let record = MftRecord::parse(before, 512)?;
        if record.flags()? & 1 != 0 || record.sequence_number()? == 0 {
            return Err(Error::InvalidRecord);
        }
        record_edit::validate(before)?;
        after.fill(0);
        after[..record_bytes].copy_from_slice(before);
        record_edit::p32(after, 28, RECORD_IMAGE as u32)?;
        head.fill(0);
        head[..8].copy_from_slice(&number.to_le_bytes());
        head[8..16].copy_from_slice(&physical.to_le_bytes());
        head[24] = R_USED;
        self.set_record_allocated(volume, number, true)?;
        self.next_record = number + 1;
        Ok(i)
    }

    /// Records the table holds: initialized and covered by its bitmap.
    fn record_limit(&self) -> Result<u64> {
        let mft = MftRecord::from_decoded(self.mft_zero)?;
        let records = unnamed(&mft, ATTR_DATA)?.initialized_size()? / self.record_bytes() as u64;
        Ok(records.min(unnamed(&mft, ATTR_BITMAP)?.data_size()? * 8))
    }

    /// Whether this transaction holds the record with this number.
    fn record_loaded(&self, number: u64) -> bool {
        (0..MAX_RECORDS).any(|slot| self.rec_slot(slot)[24] & R_USED != 0 && self.record_number(slot) == number)
    }

    /// The first record in from..end that the table's bitmap shows free and
    /// this transaction does not hold.
    fn free_record<R: ReadAt>(&mut self, volume: &mut Volume<R>, mut from: u64, end: u64) -> Result<Option<u64>> {
        let mft = MftRecord::from_decoded(self.mft_zero)?;
        let bitmap = unnamed(&mft, ATTR_BITMAP)?;
        while from < end {
            let start = from / 8;
            let n = ((end - start * 8).div_ceil(8) as usize).min(self.io_buf.len());
            volume.read_attribute(bitmap, start, &mut self.io_buf[..n])?;
            for (i, &byte) in self.io_buf[..n].iter().enumerate() {
                if byte == 0xff {
                    continue;
                }
                for bit in 0..8 {
                    let candidate = (start + i as u64) * 8 + bit;
                    if candidate >= from && candidate < end && byte & (1 << bit) == 0 && !self.record_loaded(candidate) {
                        return Ok(Some(candidate));
                    }
                }
            }
            from = (start + n as u64) * 8;
        }
        Ok(None)
    }

    pub fn set_record_allocated<R: ReadAt>(&mut self, volume: &mut Volume<R>, number: u64, on: bool) -> Result<()> {
        if number < super::mft_growth::FIRST_USER_RECORD {
            return Err(Error::Unsupported);
        }
        self.mark_record(volume, number, on)
    }

    /// Change one bit of $MFT's bitmap, for any record number.
    fn mark_record<R: ReadAt>(&mut self, volume: &mut Volume<R>, number: u64, on: bool) -> Result<()> {
        let mft = MftRecord::from_decoded(self.mft_zero)?;
        let bitmap = unnamed(&mft, ATTR_BITMAP)?;
        if bitmap.nonresident {
            return self.mft_bits.change(volume, bitmap, number, 1, on, bitmap.data_size()? * 8);
        }
        let zero = self.load_family(volume, self.mft_reference()?)?;
        let at = record_edit::require(self.record(zero), ATTR_BITMAP, &[])?;
        let offset = record_edit::resident_value_offset(self.record(zero), at)?;
        let value = record_edit::resident_value(self.record(zero), at)?;
        let byte = usize::try_from(number / 8).map_err(|_| Error::Overflow)?;
        let old = *value.get(byte).ok_or(Error::InvalidRecord)?;
        let mask = 1 << (number % 8);
        if (old & mask != 0) == on {
            return Err(Error::InvalidRecord);
        }
        self.record_mut(zero)[offset + byte] = if on { old | mask } else { old & !mask };
        Ok(())
    }

    // ----- Cluster allocation ----------------------------------------------

    pub(super) fn protected_overlap(&self, lcn: u64, count: u64) -> Result<bool> {
        let cluster = self.cluster_bytes();
        let start = lcn.checked_mul(cluster).ok_or(Error::Overflow)?;
        let end = lcn.checked_add(count).and_then(|n| n.checked_mul(cluster)).ok_or(Error::Overflow)?;
        let overlaps = |a: u64, b: u64| start < b && a < end;
        if lcn == 0 || self.log.overlaps(start, end) {
            return Ok(true);
        }
        let mirror = self.boot.mft_mirror_lcn * cluster;
        if overlaps(mirror, mirror + self.boot.mirror_bytes()) {
            return Ok(true);
        }
        for record in [&*self.mft_zero, &*self.bitmap_record] {
            let record = MftRecord::from_decoded(record)?;
            for a in record.attributes() {
                let a = a?;
                if !a.nonresident {
                    continue;
                }
                for run in DataRuns::new(a.data_runs()?, a.first_vcn()?) {
                    let run = run?;
                    if let Some(l) = run.lcn {
                        if overlaps(l * cluster, (l + run.len) * cluster) {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Reserve count contiguous free clusters in the pending $Bitmap.
    pub fn allocate_clusters<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        count: u64,
        hint: Option<u64>,
    ) -> Result<u64> {
        let record = MftRecord::from_decoded(self.bitmap_record)?;
        let attr = unnamed(&record, ATTR_DATA)?;
        let lcn = find_free_run_planned(
            volume,
            attr,
            &self.clusters,
            self.blocked.as_slice(),
            count,
            self.total_clusters,
            hint,
            self.next_cluster,
            self.io_buf,
        )?;
        // A corrupt bitmap must never let a stream alias protected metadata.
        if self.protected_overlap(lcn, count)? {
            return Err(Error::InvalidRunlist);
        }
        self.clusters.change(volume, attr, lcn, count, true, self.total_clusters)?;
        self.next_cluster = lcn + count;
        Ok(lcn)
    }

    /// Reserve clusters for a metadata stream without moving the cursor that
    /// file data is allocated from. Data then does not settle directly behind
    /// the new extent, which would force the stream's next growth elsewhere.
    pub fn allocate_apart<R: ReadAt>(&mut self, volume: &mut Volume<R>, count: u64, hint: Option<u64>) -> Result<u64> {
        let cursor = self.next_cluster;
        let lcn = self.allocate_clusters(volume, count, hint)?;
        self.next_cluster = cursor;
        Ok(lcn)
    }

    pub fn free_clusters<R: ReadAt>(&mut self, volume: &mut Volume<R>, lcn: u64, count: u64) -> Result<()> {
        if self.protected_overlap(lcn, count)? {
            return Err(Error::InvalidRunlist);
        }
        self.release(volume, lcn, count)
    }

    /// Free an extent that $MFT's mapping named when this transaction began
    /// and that the edited record 0 no longer names. `free_clusters` protects
    /// the starting mapping and would refuse it.
    pub(super) fn free_retired_mft_extent<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        lcn: u64,
        count: u64,
    ) -> Result<()> {
        self.release(volume, lcn, count)
    }

    fn release<R: ReadAt>(&mut self, volume: &mut Volume<R>, lcn: u64, count: u64) -> Result<()> {
        let record = MftRecord::from_decoded(self.bitmap_record)?;
        let attr = unnamed(&record, ATTR_DATA)?;
        self.clusters.change(volume, attr, lcn, count, false, self.total_clusters)?;
        self.freed_overflow |= !self.freed.add(lcn, count);
        Ok(())
    }

    /// Free every run of a nonresident attribute image in a loaded record.
    pub fn free_attribute_runs<R: ReadAt>(&mut self, volume: &mut Volume<R>, slot: usize, at: usize) -> Result<()> {
        self.free_attribute_tail(volume, slot, at, 0)
    }

    /// Free the clusters at or after VCN keep of a nonresident attribute.
    /// Runs are visited in small batches so no run table lives on the stack.
    pub fn free_attribute_tail<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        slot: usize,
        at: usize,
        keep: u64,
    ) -> Result<()> {
        let mut next = 0;
        loop {
            let mut batch = [(0u64, 0u64); 8];
            let mut n = 0;
            let mut resume = next;
            let record = MftRecord::from_decoded(self.record(slot))?;
            let attr = record
                .attributes()
                .find_map(|a| match a {
                    Ok(a) if a.record_offset() == at => Some(Ok(a)),
                    Err(e) => Some(Err(e)),
                    _ => None,
                })
                .ok_or(Error::InvalidAttribute)??;
            for (index, r) in DataRuns::new(attr.data_runs()?, attr.first_vcn()?).enumerate() {
                let r = r?;
                let skip = keep.saturating_sub(r.vcn).min(r.len);
                if index >= next && skip < r.len && r.lcn.is_some() && n < batch.len() {
                    batch[n] = (r.lcn.unwrap() + skip, r.len - skip);
                    n += 1;
                    resume = index + 1;
                }
            }
            for &(lcn, len) in &batch[..n] {
                self.free_clusters(volume, lcn, len)?;
            }
            if n < batch.len() {
                return Ok(());
            }
            next = resume;
        }
    }

    // ----- Commit ----------------------------------------------------------

    /// Validate every final image and publish them as one journaled
    /// transaction. Records precede index blocks so recovery resolves new
    /// index mappings from the already-redone owner record.
    pub fn commit<I: WriteIo>(mut self, writer: &mut Writer, io: &mut I, journal: &mut [u8]) -> Result<()> {
        // A pending batch may need another descriptor set during commit_barrier.
        if journal.len() < COMMIT_SCRATCH_BYTES + 2 * patch_scratch_bytes(MAX_PATCHES) {
            return Err(Error::Unsupported);
        }
        let (patches, journal) = patch_slots(journal, MAX_PATCHES)?;
        let record_bytes = self.record_bytes();
        let index_vcn_bytes = self.boot.index_vcn_bytes();
        {
            let mut volume = Volume::new(&mut *io, writer.boot)?;
            self.finish_namespace_families(writer, &mut volume)?;
            self.refresh_file_names(&mut volume)?;
            let buffers = core::mem::take(&mut self.family);
            let result = (|| {
                for base in 0..MAX_RECORDS {
                    if self.rec_slot(base)[24] & R_USED != 0
                        && self.rec_slot(base)[FAMILY_STATE] != FAMILY_PACKED
                        && u64_at(self.record(base), 32)? == 0
                        && self.rec_slot(base)[24] & R_DIRTY != 0
                    {
                        self.pack_family(&mut volume, writer, base, buffers)?;
                    }
                }
                Ok(())
            })();
            self.family = buffers;
            result?;
        }
        let mft_reference = self.mft_reference()?;
        let bitmap_reference = self.bitmap_reference()?;
        let mut references = [0_u64; MAX_RECORDS];
        for (i, reference) in references.iter_mut().enumerate() {
            if self.rec_slot(i)[24] & R_USED != 0 {
                *reference = self.record_reference(i)?;
            }
        }
        let Tx {
            records,
            nodes,
            clusters,
            mft_bits,
            aux_bits,
            aux_owner,
            freed,
            freed_overflow,
            next_record,
            next_cluster,
            ..
        } = self;
        let mut count = 0;
        for slot in records.chunks_exact_mut(REC_SLOT) {
            let (head, before, work) = slot_parts(slot, record_bytes);
            if head[24] & R_USED == 0 {
                continue;
            }
            let after = &mut work[..record_bytes];
            if head[24] & R_DIRTY == 0 || before == after {
                continue;
            }
            record_edit::validate(after)?;
            if MftRecord::from_decoded(after)?.attributes().any(|a| a.is_ok_and(|a| a.kind == 0x20))
                && head[FAMILY_STATE] != FAMILY_PACKED
            {
                return Err(Error::Unsupported);
            }
            let number = u64_at(head, 0)?;
            if count == MAX_PATCHES {
                return Err(Error::Unsupported);
            }
            patches[count] = MetadataPatch {
                fresh: false,
                physical: u64_at(head, 8)?,
                logical: number * record_bytes as u64,
                stream_reference: mft_reference,
                mft: true,
                attribute_kind: ATTR_DATA,
                name: &[],
                before,
                after,
            };
            count += 1;
        }
        for slot in nodes.chunks_exact_mut(NODE_SLOT) {
            let (head, rest) = slot.split_at_mut(NODE_HEAD);
            let flags = head[0];
            if flags & N_USED == 0 || flags & N_ROOT != 0 || flags & N_FREED != 0 {
                continue;
            }
            let (before, work) = rest.split_at_mut(BLOCK);
            let after = &mut work[..BLOCK];
            if flags & N_DIRTY == 0 || (flags & N_FRESH == 0 && before == &after[..]) {
                continue;
            }
            super::index_tree::validate_block(after)?;
            let owner = usize::from(head[1] >> 2);
            let kind = super::index_tree::IndexKind::from_code(head[1] & 3)?;
            if count == MAX_PATCHES {
                return Err(Error::Unsupported);
            }
            patches[count] = MetadataPatch {
                fresh: flags & N_FRESH != 0,
                physical: u64_at(head, 16)?,
                logical: u64_at(head, 8)? * index_vcn_bytes,
                stream_reference: *references.get(owner).ok_or(Error::InvalidIndex)?,
                mft: false,
                attribute_kind: 0xa0,
                name: kind.name(),
                before,
                after,
            };
            count += 1;
        }
        let aux_name = match aux_owner {
            Some((_, code)) => super::index_tree::IndexKind::from_code(code)?.name(),
            None => &[],
        };
        let aux_reference = match aux_owner {
            Some((owner, _)) => references[owner],
            None => 0,
        };
        let allocation_changed = clusters.count != 0;
        for (plan, reference, kind, name) in [
            (clusters, bitmap_reference, ATTR_DATA, &[][..]),
            (mft_bits, mft_reference, ATTR_BITMAP, &[][..]),
            (aux_bits, aux_reference, ATTR_BITMAP, aux_name),
        ] {
            let used = plan.count;
            for slot in plan.bytes.chunks_exact_mut(BITMAP_SLOT).take(used) {
                let logical = u64_at(slot, 0)?;
                let physical = u64_at(slot, 8)?;
                let (old, new) = slot[16..].split_at_mut(512);
                if old == &new[..] {
                    continue;
                }
                if count == MAX_PATCHES {
                    return Err(Error::Unsupported);
                }
                patches[count] = MetadataPatch {
                    fresh: false,
                    physical,
                    logical,
                    stream_reference: reference,
                    mft: false,
                    attribute_kind: kind,
                    name,
                    before: old,
                    after: new,
                };
                count += 1;
            }
        }
        if count == 0 {
            return Ok(());
        }
        if allocation_changed {
            for w in &mut writer.windows {
                w.1 = 0;
                w.2 = 0;
            }
        }
        writer.commit_metadata(io, &mut patches[..count], journal)?;
        // Forget trim ownership only after deletion is accepted; a rejected
        // delete must retain its file's preallocation for close/unmount.
        for p in &patches[..count] {
            if p.mft && u16_at(p.after, 22)? & 1 == 0 {
                for w in &mut writer.windows {
                    if reference_number(w.0) == p.logical / record_bytes as u64 {
                        *w = (0, 0, 0);
                    }
                }
            }
        }
        writer.next_record = next_record;
        writer.next_cluster = next_cluster;
        if writer.pending() != 0 && !freed.as_slice().is_empty() {
            // Deferred: released clusters stay unavailable until the drain.
            if freed_overflow {
                writer.drain(io, journal)?;
            } else {
                writer.quarantine(io, freed.as_slice(), journal)?;
            }
        }
        Ok(())
    }
}

/// Stage a byte stream at a device offset, a buffer at a time, with zeroes
/// after it up to the end of its last buffer or cluster, whichever is
/// smaller. What remains of a larger cluster lies past the stream's size
/// and is never read.
pub(crate) fn stage_bytes<I: WriteIo>(
    writer: &mut Writer,
    io: &mut I,
    physical: u64,
    bytes: &[u8],
    chunk: &mut [u8],
) -> Result<()> {
    let unit = chunk.len().min(writer.boot.cluster_bytes as usize);
    for from in (0..bytes.len()).step_by(chunk.len()) {
        let n = (bytes.len() - from).min(chunk.len());
        let padded = n.div_ceil(unit) * unit;
        chunk[..n].copy_from_slice(&bytes[from..from + n]);
        chunk[n..padded].fill(0);
        stage(writer, io, &[(physical + from as u64, &chunk[..padded])], true)?;
    }
    Ok(())
}

/// Stage data without a barrier. exposure requires it durable before the
/// commit; only bytes that no commit publishes, or an overwrite of bytes
/// already published, may omit that requirement.
pub fn stage<I: WriteIo>(writer: &mut Writer, io: &mut I, writes: &[(u64, &[u8])], exposure: bool) -> Result<()> {
    if !writer.initialized || writer.failed {
        return Err(Error::Io);
    }
    for (at, data) in writes {
        outside_log(writer, *at, data.len())?;
    }
    let dirty = writes.iter().any(|(_, data)| !data.is_empty());
    writer.data_dirty |= dirty;
    writer.exposure_dirty |= dirty && exposure;
    let result = writes.iter().try_for_each(|(at, data)| io.write_data_at(*at, data));
    if result.is_err() {
        writer.failed = true;
    }
    result
}

/// Refuse a data write that would land on the journal.
pub fn outside_log(writer: &Writer, at: u64, len: usize) -> Result<()> {
    let end = at.checked_add(len as u64).ok_or(Error::Overflow)?;
    if writer.log.overlaps(at, end) {
        return Err(Error::InvalidRunlist);
    }
    Ok(())
}

/// Map a range of a nonresident attribute to exactly one physical span.
pub fn map_one(attr: Attribute<'_>, boot: BootSector, offset: u64, length: u64) -> Result<u64> {
    let mut physical = None;
    super::write_plan::plan_nonresident_recovery(attr, boot, offset, length, |span| {
        if physical.replace(span.physical_offset).is_some() {
            return Err(Error::Unsupported);
        }
        Ok(())
    })?;
    physical.ok_or(Error::InvalidRunlist)
}
