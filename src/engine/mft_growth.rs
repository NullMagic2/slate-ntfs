//! Module: ntfs_rs::mft_growth
//! Purpose: Grow the system MFT DATA and BITMAP streams through the journal.
//! Created: 2026-10-01
//! Architecture: Writer operations reserve bitmap ranges, then durably stage unused FILE
//! records and newly valid bitmap bytes before publishing record 0, its mirror
//! and allocation changes in one transaction. Recovery never exposes unstaged
//! records; adapters own scratch, serialization and durable I/O.

use super::bytes::u64_at;
use super::mft::{MftRecord, ATTR_BITMAP, ATTR_DATA};
use super::record_edit;
use super::replay::protect_mft_record;
use super::resident_writer::unnamed;
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::tx::{map_one, stage, Tx, BLOCK, RECORD};
use super::volume::Volume;
use super::{Error, Result};

/// First record number that ordinary files may use; 16..23 are reserved
/// for $MFT extension records by Windows.
pub const FIRST_USER_RECORD: u64 = 24;
/// Growth granularity in records (a whole number of bitmap quad-words).
pub const GROWTH_RECORDS: u64 = 64;
const MAX_GROWTH_RECORDS: u64 = 65536;

fn last_lcn(rec: &[u8], at: usize) -> Result<Option<u64>> {
    record_edit::last_run_end(rec, at)
}

/// Write formatted, unused records from..to, one contiguous run per
/// cluster. The journal flushes them before it names the new records.
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
    let per_cluster = (BLOCK / RECORD) as u64;
    let result = (|| {
        let mut first = from;
        while first < to {
            let count = (per_cluster - first % per_cluster).min(to - first);
            let bytes = (count as usize) * RECORD;
            let physical = map_one(mft_data, boot, first * RECORD as u64, bytes as u64)?;
            if physical < writer.log + writer.log_bytes && writer.log < physical + bytes as u64 {
                return Err(Error::InvalidRunlist);
            }
            for (i, record) in staging[..bytes].chunks_exact_mut(RECORD).enumerate() {
                record_edit::format_empty(record, first + i as u64)?;
                protect_mft_record(record, 512)?;
            }
            io.write_at(physical, &staging[..bytes])?;
            first += count;
        }
        Ok(())
    })();
    if result.is_err() {
        writer.failed = true;
    }
    result
}

impl Writer {
    /// Ensure at least wanted free user records exist, growing the MFT once
    /// if necessary. Returns the resulting number of initialized records.
    pub fn ensure_free_records<I: WriteIo>(&mut self, io: &mut I, wanted: u64, scratch: &mut [u8]) -> Result<u64> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < 2 * RECORD + 512 {
            return Err(Error::Truncated);
        }
        let mut staged = false;
        let result = (|| {
            let (zero, rest) = scratch.split_at_mut(RECORD);
            let (sector, rest) = rest.split_at_mut(512);
            let record = &mut rest[..RECORD];
            let mut volume = Volume::new(&mut *io, self.boot)?;
            volume.read_mft_zero(zero)?;
            let mft = MftRecord::parse(zero, 512)?;
            let data = unnamed(&mft, ATTR_DATA)?;
            let bitmap = unnamed(&mft, ATTR_BITMAP)?;
            let records = (data.initialized_size()? / RECORD as u64).min(bitmap.data_size()? * 8);
            let bitmap_bytes = bitmap.data_size()?;
            let cursor = self.next_record.clamp(FIRST_USER_RECORD, records.max(FIRST_USER_RECORD));
            let mut free = 0;
            let mut loaded = u64::MAX;
            // Match Tx's allocation order, including cursor wraparound. The
            // prepared slots cover every record the following transaction can use.
            'scan: for (from, end) in [(cursor, records), (FIRST_USER_RECORD, cursor)] {
                for number in from..end {
                    if free >= wanted {
                        break 'scan;
                    }
                    let logical = number / 8 / 512 * 512;
                    if logical != loaded {
                        let n = bitmap_bytes.saturating_sub(logical).min(512) as usize;
                        if n == 0 {
                            break 'scan;
                        }
                        sector.fill(0xff);
                        volume.read_attribute(bitmap, logical, &mut sector[..n])?;
                        loaded = logical;
                    }
                    if sector[(number / 8 - logical) as usize] & (1 << (number % 8)) != 0 {
                        continue;
                    }
                    let physical = map_one(data, self.boot, number * RECORD as u64, RECORD as u64)?;
                    volume.reader_mut().read_exact_at(physical, record)?;
                    if record.iter().all(|byte| *byte == 0) {
                        // Windows can leave bitmap-free slots entirely zero
                        // inside initialized $MFT data. Stage a valid tombstone
                        // before its first allocation so journal undo has a
                        // durable FILE image. Never normalize nonzero corruption.
                        super::tx::outside_log(self, physical, RECORD)?;
                        record_edit::format_empty(record, number)?;
                        protect_mft_record(record, 512)?;
                        staged = true;
                        volume.reader_mut().write_at(physical, record)?;
                    }
                    free += 1;
                }
            }
            if staged {
                volume.reader_mut().flush()?;
            }
            Ok((free, records))
        })();
        let (free, records) = match result {
            Ok(counts) => counts,
            Err(error) => {
                if staged {
                    self.failed = true;
                }
                return Err(error);
            }
        };
        if free >= wanted {
            return Ok(records);
        }
        self.extend_mft(io, wanted - free, scratch)
    }

    /// Grow $MFT by at least records formatted records (rounded up to
    /// GROWTH_RECORDS). Returns the new number of initialized records.
    pub fn extend_mft<I: WriteIo>(&mut self, io: &mut I, records: u64, scratch: &mut [u8]) -> Result<u64> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if records == 0 || records > MAX_GROWTH_RECORDS || scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        let boot = self.boot;
        let mut volume = Volume::new(&mut *io, boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, rest) = rest.split_at_mut(64 * 1024);
        let (staging, _) = rest.split_at_mut(BLOCK);
        let mft_reference = tx.mft_reference()?;
        let zero = tx.load_record(&mut volume, mft_reference)?;
        if u64_at(tx.record(zero), 8)? > self.current_lsn {
            return Err(Error::Unsupported);
        }
        // $DATA: new records, contiguous with the last extent when possible.
        let data_at = record_edit::require(tx.record(zero), ATTR_DATA, &[])?;
        let (allocated, data, initialized) = record_edit::sizes(tx.record(zero), data_at)?;
        // NTFS-3G and Windows may leave the valid length at any record
        // boundary inside the last allocated cluster.
        if data != initialized || data % RECORD as u64 != 0 || allocated % BLOCK as u64 != 0 || data > allocated {
            return Err(Error::Unsupported);
        }
        let old_total = data / RECORD as u64;
        let new_total = (old_total + records).div_ceil(GROWTH_RECORDS) * GROWTH_RECORDS;
        let new_data = new_total * RECORD as u64;
        let mut new_allocated = allocated;
        if new_data > allocated {
            let clusters = (new_data - allocated) / BLOCK as u64;
            let hint = last_lcn(tx.record(zero), data_at)?;
            let lcn = tx.allocate_clusters(&mut volume, clusters, hint)?;
            record_edit::append_run(tx.record_mut(zero), data_at, lcn, clusters)?;
            new_allocated = new_data;
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
                    let clusters = (bitmap_bytes - b_alloc).div_ceil(BLOCK as u64);
                    let hint = last_lcn(tx.record(zero), bitmap_at)?;
                    let lcn = tx.allocate_clusters(&mut volume, clusters, hint)?;
                    record_edit::append_run(tx.record_mut(zero), bitmap_at, lcn, clusters)?;
                    b_alloc += clusters * BLOCK as u64;
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
                let within = at % BLOCK as u64;
                let n = (BLOCK as u64 - within).min(to - at);
                let physical = map_one(bitmap, boot, at, n)?;
                stage(self, &mut **volume.reader_mut(), &[(physical, &staging[..n as usize])], true)?;
                at += n;
            }
        }
        drop(volume);
        tx.commit(self, io, journal)?;
        Ok(new_total)
    }
}
