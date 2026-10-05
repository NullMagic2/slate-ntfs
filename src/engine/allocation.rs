//! Module: ntfs_rs::allocation
//! Purpose: Reserve checked bitmap ranges and encode runlists.
//! Created: 2026-10-01
//! Architecture: Writer operations edit caller-owned bitmap scratch; adapters publish changes.
//! Mapping-pair bytes and widths come from the shared runlist encoder.

use super::bytes::u64_at;
use super::mft::Attribute;
use super::runlist::{encode_mapping_pair, mapping_pair_widths, Extent};
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

pub const BITMAP_PATCHES: usize = 16;
pub const BITMAP_SLOT: usize = 16 + 1024;
pub const BITMAP_PLAN_BYTES: usize = BITMAP_PATCHES * BITMAP_SLOT;

/// Inventory every allocated physical record before selecting repair space.
/// A corrupt allocation bit or unreadable record must not hide an owner.
/// Extension records are scanned independently; no family assembly is needed
/// to account for their physical runs. The caller serializes all mutations.
pub(crate) fn visit_owned_runs<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &super::mft::MftRecord<'_>,
    raw: &mut [u8],
    bits: &mut [u8],
    mut visit: impl FnMut(u64, u16, Extent) -> Result<()>,
) -> Result<()> {
    use super::mft::{MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA};
    use super::resident_writer::unnamed;
    let record_bytes = u64::from(volume.boot.record_bytes);
    if mft.local_attribute(ATTR_ATTRIBUTE_LIST, &[])?.is_some() || raw.len() as u64 != record_bytes || bits.len() < 512 {
        return Err(Error::Unsupported);
    }
    let data = unnamed(mft, ATTR_DATA)?;
    let bitmap = unnamed(mft, ATTR_BITMAP)?;
    let size = data.initialized_size()?;
    let slots = size / record_bytes;
    if size % record_bytes != 0 || !(16..=0x0000_ffff_ffff_ffff).contains(&slots) || bitmap.data_size()? < slots.div_ceil(8) {
        return Err(Error::Unsupported);
    }
    let limit = volume.boot.total_sectors / u64::from(volume.boot.sectors_per_cluster);
    for number in 0..slots {
        if number % 4096 == 0 {
            let n = (slots.div_ceil(8) - number / 8).min(512) as usize;
            bits.fill(0);
            volume.read_attribute(bitmap, number / 8, &mut bits[..n])?;
        }
        volume.read_mft_record(mft, number, raw)?;
        let allocated = bits[(number % 4096 / 8) as usize] & (1 << (number % 8)) != 0;
        let in_use = &raw[..4] == b"FILE" && super::bytes::u16_at(raw, 22)? & 1 != 0;
        if allocated != in_use {
            return Err(Error::InvalidRecord);
        }
        if !allocated {
            if raw.iter().any(|byte| *byte != 0) {
                MftRecord::parse(raw, volume.boot.bytes_per_sector)?;
                super::record_edit::validate(raw)?;
            }
            continue;
        }
        MftRecord::parse(raw, volume.boot.bytes_per_sector)?;
        super::record_edit::validate(raw)?;
        let record = MftRecord::from_decoded(raw)?;
        // FILE stores the low 32 bits of its 48-bit MFT slot number. The
        // upper bits are determined by the slot we read from $MFT.
        if super::bytes::u32_at(raw, 44)? != number as u32 || record.sequence_number()? == 0 {
            return Err(Error::InvalidRecord);
        }
        for a in record.attributes() {
            let a = a?;
            if !a.nonresident {
                continue;
            }
            let first = a.first_vcn()?;
            if first == 0 && a.initialized_size()? > a.data_size()? {
                return Err(Error::InvalidAttribute);
            }
            let mut next = first;
            for run in super::runlist::DataRuns::new(a.data_runs()?, first) {
                let run = run?;
                if run.vcn != next {
                    return Err(Error::InvalidRunlist);
                }
                next = next.checked_add(run.len).ok_or(Error::Overflow)?;
                if let Some(lcn) = run.lcn {
                    if lcn.checked_add(run.len).is_none_or(|end| end > limit) {
                        return Err(Error::InvalidRunlist);
                    }
                    visit(number, super::bytes::u16_at(raw, a.record_offset() + 14)?, run)?;
                }
            }
            if next.wrapping_sub(1) != a.last_vcn()? {
                return Err(Error::InvalidRunlist);
            }
        }
    }
    Ok(())
}

/// Bytes in one $Bitmap sector, the unit a BitmapPlan slot edits and journals.
pub const BITMAP_SECTOR_BYTES: u64 = 512;
/// Clusters whose allocation bits one $Bitmap sector holds.
pub const CLUSTERS_PER_BITMAP_SECTOR: u64 = BITMAP_SECTOR_BYTES * 8;

/// Distinct $Bitmap sectors a transaction would edit, seeded with the sectors
/// its plan already holds. Callers ask whether further runs still fit a limit
/// before freeing them, because a partly applied plan cannot be undone.
pub struct SectorBudget {
    sectors: [u64; BITMAP_PATCHES],
    count: usize,
    limit: usize,
}

impl SectorBudget {
    /// None when the plan already holds more sectors than limit.
    pub fn new(plan: &BitmapPlan<'_>, limit: usize) -> Result<Option<Self>> {
        let limit = limit.min(BITMAP_PATCHES);
        if plan.count > limit {
            return Ok(None);
        }
        let mut sectors = [0_u64; BITMAP_PATCHES];
        for (index, sector) in sectors.iter_mut().take(plan.count).enumerate() {
            *sector = u64_at(plan.bytes, index * BITMAP_SLOT)? / BITMAP_SECTOR_BYTES;
        }
        Ok(Some(Self { sectors, count: plan.count, limit }))
    }

    /// Add the sectors of a cluster run; false once the limit would be exceeded.
    pub fn add_run(&mut self, lcn: u64, len: u64) -> Result<bool> {
        let last = lcn.checked_add(len).and_then(|end| end.checked_sub(1)).ok_or(Error::Overflow)?;
        let (first, last) = (lcn / CLUSTERS_PER_BITMAP_SECTOR, last / CLUSTERS_PER_BITMAP_SECTOR);
        if last - first + 1 > self.limit as u64 {
            return Ok(false);
        }
        for sector in first..=last {
            if self.sectors[..self.count].contains(&sector) {
                continue;
            }
            if self.count == self.limit {
                return Ok(false);
            }
            self.sectors[self.count] = sector;
            self.count += 1;
        }
        Ok(true)
    }

    /// Sectors counted so far, including those the plan already held.
    pub fn count(&self) -> usize {
        self.count
    }
}

pub struct BitmapPlan<'a> {
    pub bytes: &'a mut [u8],
    pub count: usize,
}
impl<'a> BitmapPlan<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Result<Self> {
        if bytes.len() < BITMAP_PLAN_BYTES {
            return Err(Error::Truncated);
        }
        Ok(Self { bytes, count: 0 })
    }
    pub fn change<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        attr: Attribute<'_>,
        start: u64,
        count: u64,
        allocate: bool,
        limit: u64,
    ) -> Result<()> {
        let end = start.checked_add(count).ok_or(Error::Overflow)?;
        if end > limit || end > attr.data_size()?.checked_mul(8).ok_or(Error::Overflow)? {
            return Err(Error::InvalidRunlist);
        }
        for bit in start..end {
            let logical = (bit / 8) / 512 * 512;
            let index = match (0..self.count).find(|&i| u64_at(self.bytes, i * BITMAP_SLOT).ok() == Some(logical)) {
                Some(i) => i,
                None => {
                    if self.count == BITMAP_PATCHES {
                        return Err(Error::NoSpace);
                    }
                    let slot = &mut self.bytes[self.count * BITMAP_SLOT..(self.count + 1) * BITMAP_SLOT];
                    let physical = map_sector(attr, volume.boot, logical)?;
                    slot[..8].copy_from_slice(&logical.to_le_bytes());
                    slot[8..16].copy_from_slice(&physical.to_le_bytes());
                    volume.reader_mut().read_exact_at(physical, &mut slot[16..528])?;
                    slot.copy_within(16..528, 528);
                    self.count += 1;
                    self.count - 1
                }
            };
            let byte = &mut self.bytes[index * BITMAP_SLOT + 528 + (bit / 8 - logical) as usize];
            let mask = 1 << (bit % 8);
            if (*byte & mask != 0) == allocate {
                return Err(Error::InvalidRunlist);
            }
            if allocate {
                *byte |= mask;
            } else {
                *byte &= !mask;
            }
        }
        Ok(())
    }
}

impl BitmapPlan<'_> {
    /// Replace bytes of a disk-read 512-byte bitmap sector with this plan's
    /// pending image, so later searches never select already reserved bits.
    pub fn overlay(&self, logical: u64, sector: &mut [u8]) {
        for i in 0..self.count {
            let slot = &self.bytes[i * BITMAP_SLOT..(i + 1) * BITMAP_SLOT];
            if u64_at(slot, 0).ok() == Some(logical) {
                sector[..512].copy_from_slice(&slot[528..1040]);
            }
        }
    }

    /// OR the pending image into a disk-read sector: a bit is unavailable if
    /// it was allocated before this transaction or reserved during it.
    /// Clusters freed by the transaction stay unavailable until it commits,
    /// so no rollback can find its old data overwritten by a new allocation.
    pub fn overlay_reserved(&self, logical: u64, sector: &mut [u8]) {
        for i in 0..self.count {
            let slot = &self.bytes[i * BITMAP_SLOT..(i + 1) * BITMAP_SLOT];
            if u64_at(slot, 0).ok() == Some(logical) {
                for (b, p) in sector[..512].iter_mut().zip(&slot[528..1040]) {
                    *b |= *p;
                }
            }
        }
    }

    /// Pending state of one bit, falling back to disk for untouched sectors.
    pub fn is_set<R: ReadAt>(&self, volume: &mut Volume<R>, attr: Attribute<'_>, bit: u64) -> Result<bool> {
        let logical = (bit / 8) / 512 * 512;
        let mut sector = [0xff_u8; 512];
        read_sector(volume, attr, logical, &mut sector)?;
        self.overlay(logical, &mut sector);
        Ok(sector[(bit / 8 - logical) as usize] & (1 << (bit % 8)) != 0)
    }
}

/// Map a 512-byte bitmap sector. The final sector may extend past the valid
/// stream length into the same allocated cluster; its slack bytes are copied
/// unchanged, and only bits below the caller's limit are ever modified.
pub fn map_sector(attr: Attribute<'_>, boot: super::boot::BootSector, logical: u64) -> Result<u64> {
    if logical >= attr.data_size()? || logical % 512 != 0 {
        return Err(Error::InvalidRunlist);
    }
    let mut physical = None;
    super::write_plan::plan_nonresident_recovery(attr, boot, logical, 512, |span| {
        if physical.replace(span.physical_offset).is_some() || span.length != 512 {
            return Err(Error::Unsupported);
        }
        Ok(())
    })?;
    physical.ok_or(Error::InvalidRunlist)
}

/// Read one bitmap sector; bytes past the stream end read as allocated.
fn read_sector<R: ReadAt>(volume: &mut Volume<R>, attr: Attribute<'_>, logical: u64, out: &mut [u8]) -> Result<()> {
    let size = attr.data_size()?;
    out[..512].fill(0xff);
    if logical >= size {
        return Ok(());
    }
    let n = (size - logical).min(512) as usize;
    volume.read_attribute(attr, logical, &mut out[..n])
}

/// Mark clusters freed by not-yet-durable transactions as unavailable in one
/// disk-read bitmap sector. They may not be reused before their release is
/// journaled, or a crash could leave old data overwritten.
fn block(blocked: &[(u64, u64)], logical: u64, sector: &mut [u8]) {
    let first = logical * 8;
    for &(start, count) in blocked {
        let (from, to) = (start.max(first), (start + count).min(first + 4096));
        for bit in from..to.max(from) {
            sector[((bit - first) / 8) as usize] |= 1 << (bit % 8);
        }
    }
}

/// Plan-aware contiguous search. hint is tried first so extents can grow in
/// place; otherwise search from cursor, wrapping once. Cluster 0 is never returned.
/// blocked lists (lcn, count) ranges that are free on disk but must not
/// be handed out yet.
pub fn find_free_run_planned<R: ReadAt>(
    volume: &mut Volume<R>,
    attr: Attribute<'_>,
    plan: &BitmapPlan<'_>,
    blocked: &[(u64, u64)],
    count: u64,
    limit: u64,
    hint: Option<u64>,
    cursor: u64,
    scratch: &mut [u8],
) -> Result<u64> {
    if count == 0 || count > limit || scratch.len() < 512 {
        return Err(Error::NoSpace);
    }
    if let Some(start) = hint.filter(|h| *h > 0 && h.checked_add(count).is_some_and(|e| e <= limit)) {
        let mut free = true;
        let mut loaded = u64::MAX;
        for bit in start..start + count {
            let logical = (bit / 8) / 512 * 512;
            if logical != loaded {
                read_sector(volume, attr, logical, &mut scratch[..512])?;
                plan.overlay_reserved(logical, &mut scratch[..512]);
                block(blocked, logical, &mut scratch[..512]);
                loaded = logical;
            }
            if scratch[(bit / 8 - logical) as usize] & (1 << (bit % 8)) != 0 {
                free = false;
                break;
            }
        }
        if free {
            return Ok(start);
        }
    }
    let cursor = cursor.clamp(1, limit);
    // The second pass overlaps by count - 1 so a free run crossing the
    // cursor is still found. Never join the physical end to cluster zero.
    for (from, end) in [(cursor, limit), (1, cursor.saturating_add(count - 1).min(limit))] {
        let mut consecutive = 0;
        for sector in from / 4096..end.div_ceil(4096) {
            read_sector(volume, attr, sector * 512, &mut scratch[..512])?;
            plan.overlay_reserved(sector * 512, &mut scratch[..512]);
            block(blocked, sector * 512, &mut scratch[..512]);
            for (index, &byte) in scratch[..512].iter().enumerate() {
                if byte == 0xff {
                    consecutive = 0;
                    continue;
                }
                for within in 0..8 {
                    let bit = sector * 4096 + index as u64 * 8 + within;
                    if bit < from || bit >= end {
                        continue;
                    }
                    if byte & (1 << within) == 0 {
                        consecutive += 1;
                        if consecutive == count {
                            return Ok(bit + 1 - count);
                        }
                    } else {
                        consecutive = 0;
                    }
                }
            }
        }
    }
    Err(Error::NoSpace)
}

/// Minimal signed-delta NTFS mapping-pairs encoding; output includes terminator.
pub fn encode_runs(runs: &[Extent], out: &mut [u8]) -> Result<usize> {
    encode_runs_at(0, runs, out)
}

/// Encode mapping pairs for an extent whose first run starts at first_vcn.
pub fn encode_runs_at(first_vcn: u64, runs: &[Extent], out: &mut [u8]) -> Result<usize> {
    let mut used = 0;
    let mut previous = 0_i64;
    let mut vcn = first_vcn;
    for run in runs {
        let lcn = run.lcn.map(i64::try_from).transpose().map_err(|_| Error::Overflow)?.unwrap_or(previous);
        if run.vcn != vcn || run.len == 0 {
            return Err(Error::InvalidRunlist);
        }
        let delta = lcn.checked_sub(previous).ok_or(Error::Overflow)?;
        if run.len > i64::MAX as u64 {
            return Err(Error::Overflow);
        }
        let delta = run.lcn.map(|_| delta);
        let (length_bytes, delta_bytes) = mapping_pair_widths(run.len, delta)?;
        let end = used + 1 + length_bytes + delta_bytes;
        if end >= out.len() {
            return Err(Error::NoSpace);
        }
        encode_mapping_pair(run.len, delta, &mut out[used..end])?;
        used = end;
        previous = lcn;
        vcn = vcn.checked_add(run.len).ok_or(Error::Overflow)?;
    }
    if used >= out.len() {
        return Err(Error::NoSpace);
    }
    out[used] = 0;
    Ok(used + 1)
}

/// Reserve an already provisioned, unallocated MFT slot in a caller-owned
/// bitmap snapshot. Publishing it requires a transaction containing the new
/// record and its namespace reference; this never creates an orphan on disk.
pub fn reserve_mft_slot(bitmap: &mut [u8], initialized_records: u64) -> Result<u64> {
    if initialized_records > bitmap.len() as u64 * 8 {
        return Err(Error::InvalidRecord);
    }
    for number in 16..initialized_records {
        let byte = &mut bitmap[number as usize / 8];
        let mask = 1 << (number % 8);
        if *byte & mask == 0 {
            *byte |= mask;
            return Ok(number);
        }
    }
    Err(Error::NoSpace)
}
pub fn release_mft_slot(bitmap: &mut [u8], number: u64, initialized_records: u64) -> Result<()> {
    if number < 16 || number >= initialized_records || initialized_records > bitmap.len() as u64 * 8 {
        return Err(Error::InvalidRecord);
    }
    let byte = &mut bitmap[number as usize / 8];
    let mask = 1 << (number % 8);
    if *byte & mask == 0 {
        return Err(Error::InvalidRecord);
    }
    *byte &= !mask;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/core/allocation.rs"]
mod tests;
