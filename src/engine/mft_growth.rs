//! Module: ntfs_rs::mft_growth
//! Purpose: Grow the system MFT DATA and BITMAP streams through the journal.
//! Created: 2026-10-01
//! Architecture: Writer operations reserve bitmap ranges, then durably stage unused FILE
//! records and newly valid bitmap bytes before publishing record 0, its mirror
//! and allocation changes in one transaction. Recovery never exposes unstaged
//! records; adapters own scratch, serialization and durable I/O.

use super::bytes::{u16_at, u64_at};
use super::mft::{record_layout, MftRecord, ATTR_BITMAP, ATTR_DATA};
use super::record_edit;
use super::replay::protect_mft_record;
use super::resident_writer::unnamed;
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::tx::{map_one, stage, Tx, IO_CHUNK};
use super::volume::Volume;
use super::{Error, Result};

/// First record number that ordinary files may use; 16..23 are reserved
/// for $MFT extension records by Windows.
pub const FIRST_USER_RECORD: u64 = 24;
/// First of the records reserved for $MFT's own extension records.
pub const FIRST_TABLE_EXTENSION: u64 = 16;
/// Growth granularity in records (a whole number of bitmap quad-words).
pub const GROWTH_RECORDS: u64 = 64;
const MAX_GROWTH_RECORDS: u64 = 65536;
/// Automatic growth adds this fraction of the table beyond the request, so
/// the number of growth steps, and of extents, rises with its logarithm.
const AHEAD_DIVISOR: u64 = 8;
/// Upper bound of that read-ahead: 16 MiB of records.
const AHEAD_RECORDS: u64 = 16384;
/// Free records made usable at once when blank slots are met.
const FORMAT_AHEAD_RECORDS: u64 = 256;
/// Free records prepared for the table's map once its reserved ones are
/// taken: as many extension records as one family holds.
const SPARE_EXTENSIONS: u64 = super::tx::MAX_RECORDS as u64;
/// Journal scratch one growth transaction commits through.
const JOURNAL_BYTES: usize = 64 * 1024;
/// Bytes of the table's bitmap read at a time while free records are sought.
const SECTOR: usize = 512;
/// Factor between two attempted growth sizes when space is short.
const RETRY_DIVISOR: u64 = 4;
/// Trailing extents one compaction gathers, and the clusters it may copy.
const COMPACT_RUNS: usize = 8;
const COMPACT_BYTES: u64 = 16 * 1024 * 1024;

/// Where a growth step may place its new extent.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Placement {
    /// Only directly behind the final extent, which adds no mapping pair.
    Adjacent,
    Anywhere,
}

fn last_lcn(rec: &[u8], at: usize) -> Result<Option<u64>> {
    record_edit::last_run_end(rec, at)
}

/// Write formatted, unused records from..to, one buffer of them at a time,
/// which never crosses a cluster. The journal flushes them before it names
/// the new records.
fn stage_records<I: WriteIo>(
    writer: &mut Writer,
    io: &mut I,
    mft_data: super::mft::Attribute<'_>,
    boot: super::boot::BootSector,
    from: u64,
    to: u64,
    staging: &mut [u8],
) -> Result<()> {
    if !writer.initialized || writer.failed {
        return Err(Error::Io);
    }
    let record_bytes = boot.record_bytes as usize;
    // One write stays inside a cluster, or is one record on smaller ones.
    let chunk = staging.len().min((boot.cluster_bytes as usize).max(record_bytes));
    let per_chunk = (chunk / record_bytes) as u64;
    let mut written = false;
    let result = (|| {
        let mut first = from;
        while first < to {
            let count = (per_chunk - first % per_chunk).min(to - first);
            let bytes = (count as usize) * record_bytes;
            let physical = map_one(mft_data, boot, first * record_bytes as u64, bytes as u64)?;
            if writer.log.overlaps(physical, physical + bytes as u64) {
                return Err(Error::InvalidRunlist);
            }
            for (i, record) in staging[..bytes].chunks_exact_mut(record_bytes).enumerate() {
                record_edit::format_empty(record, first + i as u64)?;
                protect_mft_record(record, 512)?;
            }
            written = true;
            io.write_at(physical, &staging[..bytes])?;
            first += count;
        }
        Ok(())
    })();
    // A mapping refused before any write changed nothing: the caller drops
    // its transaction and the session continues.
    if result.is_err() && written {
        writer.failed = true;
    }
    result
}

/// Windows can leave bitmap-free slots entirely zero inside initialized $MFT
/// data, among them the records reserved for the table's own extensions.
/// Write a valid unused record there before its first allocation, so that
/// journal undo has a durable FILE image. Nonzero contents are never
/// normalized. Returns whether a record was written; `wrote` is set before
/// the write is attempted.
fn stage_tombstone<I: WriteIo>(
    writer: &Writer,
    io: &mut I,
    physical: u64,
    number: u64,
    record: &mut [u8],
    wrote: &mut bool,
) -> Result<bool> {
    if !record.iter().all(|byte| *byte == 0) {
        return Ok(false);
    }
    super::tx::outside_log(writer, physical, record.len())?;
    record_edit::format_empty(record, number)?;
    protect_mft_record(record, 512)?;
    *wrote = true;
    io.write_at(physical, record)?;
    Ok(true)
}

/// Count the free records in the ranges, in order, until wanted are found,
/// and make each blank one a valid unused record. Once a blank one was met,
/// the count goes on to ahead. Sets staged when a record was written.
fn stage_free_records<I: WriteIo>(
    writer: &Writer,
    volume: &mut Volume<&mut I>,
    mft: &MftRecord<'_>,
    ranges: &[(u64, u64)],
    (wanted, ahead): (u64, u64),
    (sector, record): (&mut [u8], &mut [u8]),
    (staged, wrote): (&mut bool, &mut bool),
) -> Result<u64> {
    let data = unnamed(mft, ATTR_DATA)?;
    let bitmap = unnamed(mft, ATTR_BITMAP)?;
    let bitmap_bytes = bitmap.data_size()?;
    let record_bytes = record.len() as u64;
    let mut free = 0;
    let mut loaded = u64::MAX;
    for &(from, end) in ranges {
        for number in from..end {
            if free >= if *staged { wanted.max(ahead) } else { wanted } {
                return Ok(free);
            }
            let logical = number / 8 / SECTOR as u64 * SECTOR as u64;
            if logical != loaded {
                let n = bitmap_bytes.saturating_sub(logical).min(SECTOR as u64) as usize;
                if n == 0 {
                    return Ok(free);
                }
                sector.fill(0xff);
                volume.read_attribute(bitmap, logical, &mut sector[..n])?;
                loaded = logical;
            }
            if sector[(number / 8 - logical) as usize] & (1 << (number % 8)) != 0 {
                continue;
            }
            let physical = map_one(data, writer.boot, number * record_bytes, record_bytes)?;
            volume.reader_mut().read_exact_at(physical, record)?;
            *staged |= stage_tombstone(writer, &mut **volume.reader_mut(), physical, number, record, wrote)?;
            free += 1;
        }
    }
    Ok(free)
}

impl Writer {
    /// Make the records reserved for $MFT's extension records usable: a
    /// blank one becomes a valid unused record. When none of them is free,
    /// the first free records of the table are prepared in their place.
    #[inline(never)]
    fn prepare_table_extensions<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        let mut wrote = false;
        let result = (|| {
            let record_bytes = self.boot.record_bytes as usize;
            let (zero, rest) = scratch.split_at_mut(super::volume::mft_space_bytes(record_bytes));
            let (sector, rest) = rest.split_at_mut(SECTOR);
            let record = &mut rest[..record_bytes];
            let mut volume = Volume::new(&mut *io, self.boot)?;
            let mft = volume.load_mft(zero)?;
            let data = unnamed(&mft, ATTR_DATA)?;
            let mut staged = false;
            let mut spare = false;
            for number in FIRST_TABLE_EXTENSION..FIRST_USER_RECORD {
                let physical = map_one(data, self.boot, number * record_bytes as u64, record_bytes as u64)?;
                volume.reader_mut().read_exact_at(physical, record)?;
                staged |= stage_tombstone(self, &mut **volume.reader_mut(), physical, number, record, &mut wrote)?;
                spare |= u16_at(record, record_layout::FLAGS_OFFSET)? & record_layout::IN_USE == 0;
            }
            if !spare {
                let records = data.initialized_size()? / record_bytes as u64;
                let ranges = [(FIRST_USER_RECORD, records)];
                let counts = (SPARE_EXTENSIONS, SPARE_EXTENSIONS);
                let flags = (&mut staged, &mut wrote);
                stage_free_records(self, &mut volume, &mft, &ranges, counts, (sector, record), flags)?;
            }
            if staged {
                volume.reader_mut().flush()?;
            }
            Ok(())
        })();
        if result.is_err() && wrote {
            self.failed = true;
        }
        result
    }

    /// Ensure at least wanted free user records exist, growing the MFT once
    /// if necessary. Returns the resulting number of initialized records.
    pub fn ensure_free_records<I: WriteIo>(&mut self, io: &mut I, wanted: u64, scratch: &mut [u8]) -> Result<u64> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        let record_bytes = self.boot.record_bytes as usize;
        if scratch.len() < super::volume::mft_space_bytes(record_bytes) + record_bytes + SECTOR {
            return Err(Error::Truncated);
        }
        let mut staged = false;
        let mut wrote = false;
        let result = (|| {
            let (zero, rest) = scratch.split_at_mut(super::volume::mft_space_bytes(record_bytes));
            let (sector, rest) = rest.split_at_mut(SECTOR);
            let record = &mut rest[..record_bytes];
            let mut volume = Volume::new(&mut *io, self.boot)?;
            let mft = volume.load_mft(zero)?;
            let data = unnamed(&mft, ATTR_DATA)?;
            let bitmap = unnamed(&mft, ATTR_BITMAP)?;
            let records = (data.initialized_size()? / record_bytes as u64).min(bitmap.data_size()? * 8);
            let cursor = self.next_record.clamp(FIRST_USER_RECORD, records.max(FIRST_USER_RECORD));
            // Match Tx's allocation order, including cursor wraparound. The
            // prepared slots cover every record the following transaction
            // can use. Once a blank slot had to be formatted, a whole stretch
            // ahead goes under the same flush: one flush for many new files.
            let ranges = [(cursor, records), (FIRST_USER_RECORD, cursor)];
            let counts = (wanted, FORMAT_AHEAD_RECORDS);
            let flags = (&mut staged, &mut wrote);
            let free = stage_free_records(self, &mut volume, &mft, &ranges, counts, (sector, record), flags)?;
            if staged {
                volume.reader_mut().flush()?;
            }
            Ok((free, records))
        })();
        let (free, records) = match result {
            Ok(counts) => counts,
            Err(error) => {
                if wrote {
                    self.failed = true;
                }
                return Err(error);
            }
        };
        if free >= wanted {
            return Ok(records);
        }
        self.grow_ahead(io, wanted - free, records, scratch)
    }

    /// Grow by at least needed records. Prefer a large step directly behind
    /// the table, then a large step anywhere, then smaller ones; when the
    /// table's record has no room for another extent, gather its scattered
    /// tail into one extent first.
    // Kernel stacks are small: these frames must not be merged into one.
    #[inline(never)]
    fn grow_ahead<I: WriteIo>(&mut self, io: &mut I, needed: u64, records: u64, scratch: &mut [u8]) -> Result<u64> {
        let ahead = (records / AHEAD_DIVISOR).clamp(needed, AHEAD_RECORDS.max(needed));
        for placement in [Placement::Adjacent, Placement::Anywhere] {
            let mut size = ahead;
            loop {
                match self.extend_mft_placed(io, size, placement, scratch) {
                    Err(Error::NoSpace) if size > needed => size = (size / RETRY_DIVISOR).max(needed),
                    Err(Error::NoSpace) => break,
                    other => return other,
                }
            }
        }
        self.compact_mft_tail(io, scratch)?;
        self.extend_mft_placed(io, needed, Placement::Anywhere, scratch)
    }

    /// Replace the final extents of $MFT's mapping with one extent holding
    /// the same records, which frees room in record 0 for further growth.
    /// The copies are durable before the journal names their new place.
    // Kernel stacks are small: these frames must not be merged into one.
    #[inline(never)]
    fn compact_mft_tail<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        // Pending and committed images are addressed by device offset:
        // write them home before any record moves.
        self.checkpoint(io, scratch)?;
        let boot = self.boot;
        let mut volume = Volume::new(&mut *io, boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, rest) = rest.split_at_mut(JOURNAL_BYTES);
        let (staging, _) = rest.split_at_mut(IO_CHUNK);
        let cluster = u64::from(boot.cluster_bytes);
        let mft_reference = tx.mft_reference()?;
        let zero = tx.load_family(&mut volume, mft_reference)?;
        if u64_at(tx.record(zero), 8)? > self.current_lsn {
            return Err(Error::Unsupported);
        }
        let data_at = record_edit::require(tx.record(zero), ATTR_DATA, &[])?;
        let (allocated, data, initialized) = record_edit::sizes(tx.record(zero), data_at)?;
        let mut tail = [super::runlist::Extent { vcn: 0, len: 0, lcn: None }; COMPACT_RUNS];
        let count = record_edit::tail_runs(tx.record(zero), data_at, &mut tail)?;
        // Take the longest suffix within the copy limit. The first extent
        // stays: the boot sector and the bootstrap records name its place.
        let mut from = count;
        let mut clusters = 0;
        while from > 0 && tail[from - 1].vcn != 0 && clusters + tail[from - 1].len <= COMPACT_BYTES / cluster {
            from -= 1;
            clusters += tail[from].len;
        }
        let moved = &tail[from..count];
        if moved.len() < 2 {
            return Err(Error::NoSpace);
        }
        let lcn = tx.allocate_apart(&mut volume, clusters, None)?;
        let mut target = lcn.checked_mul(cluster).ok_or(Error::Overflow)?;
        for run in moved {
            let source = run.lcn.ok_or(Error::Unsupported)?.checked_mul(cluster).ok_or(Error::Overflow)?;
            let staging = &mut staging[..IO_CHUNK.min(cluster as usize)];
            for copied in (0..run.len * cluster).step_by(staging.len()) {
                volume.reader_mut().read_exact_at(source + copied, staging)?;
                stage(self, &mut **volume.reader_mut(), &[(target, &staging[..])], true)?;
                target += staging.len() as u64;
            }
        }
        record_edit::truncate_runs(tx.record_mut(zero), data_at, moved[0].vcn)?;
        record_edit::append_run(tx.record_mut(zero), data_at, lcn, clusters)?;
        let data_at = record_edit::require(tx.record(zero), ATTR_DATA, &[])?;
        record_edit::set_sizes(tx.record_mut(zero), data_at, allocated, data, initialized)?;
        record_edit::validate(tx.record(zero))?;
        for run in moved {
            tx.free_retired_mft_extent(&mut volume, run.lcn.ok_or(Error::Unsupported)?, run.len)?;
        }
        drop(volume);
        let committed = tx.commit(self, io, journal);
        // The map changed, perhaps only in an extension record.
        io.drop_table();
        committed?;
        // Nothing may still address the old extents once they are free.
        self.checkpoint(io, scratch)
    }

    /// Grow $MFT by at least records formatted records (rounded up to
    /// GROWTH_RECORDS). Returns the new number of initialized records.
    pub fn extend_mft<I: WriteIo>(&mut self, io: &mut I, records: u64, scratch: &mut [u8]) -> Result<u64> {
        self.extend_mft_placed(io, records, Placement::Anywhere, scratch)
    }

    // Kernel stacks are small: these frames must not be merged into one.
    #[inline(never)]
    fn extend_mft_placed<I: WriteIo>(
        &mut self,
        io: &mut I,
        records: u64,
        placement: Placement,
        scratch: &mut [u8],
    ) -> Result<u64> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if records == 0 || records > MAX_GROWTH_RECORDS || scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        // This growth may be the one that spills the map into them.
        self.prepare_table_extensions(io, scratch)?;
        let boot = self.boot;
        let mut volume = Volume::new(&mut *io, boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, rest) = rest.split_at_mut(JOURNAL_BYTES);
        let (staging, _) = rest.split_at_mut(IO_CHUNK);
        let cluster = u64::from(boot.cluster_bytes);
        let record_bytes = u64::from(boot.record_bytes);
        let mft_reference = tx.mft_reference()?;
        let zero = tx.load_family(&mut volume, mft_reference)?;
        if u64_at(tx.record(zero), 8)? > self.current_lsn {
            return Err(Error::Unsupported);
        }
        // $DATA: new records, contiguous with the last extent when possible.
        let data_at = record_edit::require(tx.record(zero), ATTR_DATA, &[])?;
        let (allocated, data, initialized) = record_edit::sizes(tx.record(zero), data_at)?;
        // NTFS-3G and Windows may leave the valid length at any record
        // boundary inside the last allocated cluster.
        if data != initialized || data % record_bytes != 0 || allocated % cluster != 0 || data > allocated {
            return Err(Error::Unsupported);
        }
        let old_total = data / record_bytes;
        let new_total = (old_total + records).div_ceil(GROWTH_RECORDS) * GROWTH_RECORDS;
        let new_data = new_total * record_bytes;
        let mut new_allocated = allocated;
        if new_data > allocated {
            let clusters = (new_data - allocated).div_ceil(cluster);
            let hint = last_lcn(tx.record(zero), data_at)?;
            let lcn = tx.allocate_apart(&mut volume, clusters, hint)?;
            if placement == Placement::Adjacent && Some(lcn) != hint {
                return Err(Error::NoSpace);
            }
            record_edit::append_run(tx.record_mut(zero), data_at, lcn, clusters)?;
            new_allocated = allocated + clusters * cluster;
        }
        let data_at = record_edit::require(tx.record(zero), ATTR_DATA, &[])?;
        record_edit::set_sizes(tx.record_mut(zero), data_at, new_allocated, new_data, new_data)?;
        // $BITMAP: one bit per record, quad-word granular, new bits zero.
        let bitmap_bytes = new_total.div_ceil(64) * 8;
        let bitmap_at = record_edit::require(tx.record(zero), ATTR_BITMAP, &[])?;
        let mut zero_range = None;
        if record_edit::is_nonresident(tx.record(zero), bitmap_at)? {
            let (b_alloc, b_data, b_init) = record_edit::sizes(tx.record(zero), bitmap_at)?;
            if b_data != b_init {
                return Err(Error::Unsupported);
            }
            if bitmap_bytes > b_data {
                let mut b_alloc = b_alloc;
                if bitmap_bytes > b_alloc {
                    let clusters = (bitmap_bytes - b_alloc).div_ceil(cluster);
                    let hint = last_lcn(tx.record(zero), bitmap_at)?;
                    let lcn = tx.allocate_apart(&mut volume, clusters, hint)?;
                    record_edit::append_run(tx.record_mut(zero), bitmap_at, lcn, clusters)?;
                    b_alloc += clusters * cluster;
                }
                let bitmap_at = record_edit::require(tx.record(zero), ATTR_BITMAP, &[])?;
                record_edit::set_sizes(tx.record_mut(zero), bitmap_at, b_alloc, bitmap_bytes, bitmap_bytes)?;
                zero_range = Some((b_data, bitmap_bytes));
            }
        } else {
            let old = record_edit::resident_value(tx.record(zero), bitmap_at)?;
            if (bitmap_bytes as usize) > old.len() {
                let mut value = [0_u8; 512];
                if bitmap_bytes as usize > value.len() {
                    return Err(Error::NoSpace);
                }
                value[..old.len()].copy_from_slice(old);
                record_edit::set_resident_value(tx.record_mut(zero), bitmap_at, &value[..bitmap_bytes as usize])?;
            }
        }
        record_edit::validate(tx.record(zero))?;
        // Stage formatted records through the new mapping. Only new record
        // slots are written, so live records sharing a cluster are untouched.
        let after = MftRecord::from_decoded(tx.record(zero))?;
        let mft_data = unnamed(&after, ATTR_DATA)?;
        stage_records(self, &mut **volume.reader_mut(), mft_data, boot, old_total, new_total, staging)?;
        if let Some((from, to)) = zero_range {
            let bitmap = unnamed(&after, ATTR_BITMAP)?;
            staging.fill(0);
            let mut at = from;
            while at < to {
                let unit = (IO_CHUNK as u64).min(cluster);
                let n = (unit - at % unit).min(to - at);
                let physical = map_one(bitmap, boot, at, n)?;
                stage(self, &mut **volume.reader_mut(), &[(physical, &staging[..n as usize])], true)?;
                at += n;
            }
        }
        drop(volume);
        let committed = tx.commit(self, io, journal);
        // The map changed, perhaps only in an extension record.
        io.drop_table();
        committed?;
        // Write the table's records home now. Every later lookup, and a
        // recovery after a power cut, then starts from a map that is
        // complete on disk.
        self.checkpoint(io, scratch)?;
        Ok(new_total)
    }
}
