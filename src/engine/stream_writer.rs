//! Module: ntfs_rs::stream_writer
//! Purpose: Write and resize DATA streams through bounded transactions.
//! Created: 2026-10-01
//! Architecture: Writer operations edit MFT and allocation images in caller-owned scratch.
//! New append windows are durably zeroed before publication; initialized
//! overwrites touch no metadata. Adapters own serialization and barriers.

use super::bytes::{u16_at, u32_at};
use super::mft::{reference_number, reference_sequence};
use super::mft::{Attribute, MftRecord, ATTR_DATA};
use super::record_edit as edit;
use super::resident_writer::unnamed;
use super::resident_writer::{WriteIo, Writer, MAX_WRITE, METADATA_SCRATCH_BYTES};
use super::tx::{stage, Tx, BLOCK};
use super::volume::{ReadAt, Volume};
use super::write_plan::{plan_nonresident_overwrite, plan_nonresident_recovery};
use super::{Error, Result};

/// Clusters one resize step may allocate or free (64 MiB).
const STEP: u64 = 16384;
/// Clusters one write may allocate before the file is grown separately.
const GROW: u64 = 512;
/// Small append window: 64 KiB at the supported 4 KiB cluster size.
const WINDOW: u64 = 16;
/// Assembly buffer for blocks that are not entirely caller data.
const CHUNK: usize = 1 << 16;
/// Journal scratch handed to Tx::commit.
const JOURNAL: usize = 64 * 1024;
/// Resident bytes carried across a resident-to-nonresident conversion.
const SAVED: usize = 1024;

enum Op<'a> {
    Write(u64, &'a [u8]),
    Resize(u64),
    Allocate(u64, bool),
}

/// Grow(to): the operation needs the file resized to to first (a resize
/// step that is not yet complete reports the same thing).
enum Step {
    Done,
    Grow(u64),
    Allocate(u64, u64),
}

impl Writer {
    /// Restore missing allocation bits in one logical $Bitmap sector. The
    /// caller freezes the volume and holds the writer lock. The offset is a
    /// hint only: derive ownership again from live MFT records, and never
    /// accept replacement bitmap bytes from userspace. Clearing unowned bits
    /// requires the complete offline audit and stays in the spotfix planner.
    pub fn repair_allocation_sector<I: WriteIo>(
        &mut self,
        io: &mut I,
        logical: u64,
        scratch: &mut [u8],
    ) -> Result<bool> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        if logical % 512 != 0 {
            return Err(Error::InvalidAttribute);
        }
        self.drain(io, scratch)?;
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        if rest.len() < JOURNAL + 1024 + 3 * 512 {
            return Err(Error::Truncated);
        }
        let (journal, rest) = rest.split_at_mut(JOURNAL);
        let (raw, rest) = rest.split_at_mut(1024);
        let (bits, rest) = rest.split_at_mut(512);
        let (owned, rest) = rest.split_at_mut(512);
        let current = &mut rest[..512];
        owned.fill(0);
        let first = logical.checked_mul(8).ok_or(Error::Overflow)?;
        let limit = self.boot.total_sectors / u64::from(self.boot.sectors_per_cluster);
        if first >= limit {
            return Err(Error::InvalidRunlist);
        }
        let end = first.saturating_add(4096).min(limit);
        super::allocation::visit_owned_runs(
            &mut volume,
            &MftRecord::from_decoded(tx.mft_zero())?,
            raw,
            bits,
            |_, _, run| {
                let start = run.lcn.ok_or(Error::InvalidRunlist)?;
                let stop = start.checked_add(run.len).ok_or(Error::Overflow)?.min(end);
                for bit in start.max(first)..stop {
                    owned[((bit - first) / 8) as usize] |= 1 << (bit % 8);
                }
                Ok(())
            },
        )?;
        let bitmap = MftRecord::from_decoded(tx.bitmap_record)?;
        let allocation = unnamed(&bitmap, ATTR_DATA)?;
        if allocation.data_size()? < limit.div_ceil(8) {
            return Err(Error::InvalidAttribute);
        }
        current.fill(0xff);
        let size = (allocation.data_size()? - logical).min(512) as usize;
        volume.read_attribute(allocation, logical, &mut current[..size])?;
        let mut changed = false;
        for bit in first..end {
            let byte = ((bit - first) / 8) as usize;
            let mask = 1 << (bit % 8);
            if owned[byte] & mask != 0 && current[byte] & mask == 0 {
                tx.clusters.change(&mut volume, allocation, bit, 1, true, limit)?;
                changed = true;
            }
        }
        if !changed {
            return Ok(false);
        }
        drop(volume);
        tx.commit(self, io, journal)?;
        self.drain(io, scratch)?;
        Ok(true)
    }

    /// Repair referenced allocation bits and one proven cross-linked DATA
    /// interval. Caller quiesces data/mmap/DIO on the mounted volume. A full
    /// physical-record inventory proves new space has no surviving owner.
    /// Return bits: 1 = allocation repaired, 2 = a shared interval relocated.
    pub fn repair_data<I: WriteIo>(&mut self, io: &mut I, reference: u64, scratch: &mut [u8]) -> Result<u32> {
        use super::allocation::visit_owned_runs;
        use super::runlist::{DataRuns, Extent};
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let number = reference_number(reference);
        if number < 24 || reference_sequence(reference) == 0 {
            return Err(Error::Unsupported);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        if rest.len() < JOURNAL + CHUNK + 2048 {
            return Err(Error::Truncated);
        }
        let (journal, rest) = rest.split_at_mut(JOURNAL);
        let (raw, rest) = rest.split_at_mut(1024);
        let (bits, rest) = rest.split_at_mut(512);
        let (map, chunk) = rest.split_at_mut(512);
        let file = tx.load_record(&mut volume, reference)?;
        let record = MftRecord::from_decoded(tx.record(file))?;
        if record.flags()? & 2 != 0
            || record.base_file_reference()? != 0
            || record.local_attribute(super::mft::ATTR_ATTRIBUTE_LIST, &[])?.is_some()
            || super::bytes::u64_at(tx.record(file), 8)? > self.current_lsn
        {
            return Err(Error::Unsupported);
        }
        let data = unnamed(&record, ATTR_DATA)?;
        if !data.nonresident {
            return Ok(0);
        }
        if data.flags()? != 0 || data.first_vcn()? != 0 || data.allocated_size()? > 64 * 1024 * 1024 {
            return Err(Error::Unsupported);
        }
        let at = data.record_offset();
        let id = u16_at(tx.record(file), at + 14)?;
        let empty = Extent { vcn: 0, len: 0, lcn: None };
        let mut runs = [empty; 64];
        let mut count = 0;
        for run in DataRuns::new(data.data_runs()?, 0) {
            let run = run?;
            if count == 62 || run.lcn.is_none() {
                return Err(Error::Unsupported);
            }
            runs[count] = run;
            count += 1;
        }
        let mut collision = None;
        visit_owned_runs(&mut volume, &MftRecord::from_decoded(tx.mft_zero())?, raw, bits, |owner, attr, other| {
            let other_start = other.lcn.ok_or(Error::InvalidRunlist)?;
            for (i, run) in runs[..count].iter().enumerate() {
                if owner == number && attr == id && other.vcn == run.vcn {
                    continue;
                }
                let start = run.lcn.ok_or(Error::InvalidRunlist)?.max(other_start);
                let end = (run.lcn.unwrap() + run.len).min(other_start + other.len);
                if start < end && collision.is_none() {
                    collision = Some((i, start, (end - start).min(256)));
                }
            }
            Ok(())
        })?;
        // Only set referenced bits. Never free old shared clusters: another
        // surviving owner still references every byte of the cloned interval.
        let mut changed = 0;
        {
            let bitmap = MftRecord::from_decoded(tx.bitmap_record)?;
            let allocation = unnamed(&bitmap, ATTR_DATA)?;
            let limit = self.boot.total_sectors / u64::from(self.boot.sectors_per_cluster);
            for run in &runs[..count] {
                let mut bit = run.lcn.unwrap();
                let end = bit.checked_add(run.len).ok_or(Error::Overflow)?;
                while bit < end {
                    let logical = bit / 4096 * 512;
                    volume.read_attribute(allocation, logical, map)?;
                    tx.clusters.overlay(logical, map);
                    let stop = end.min((bit / 4096 + 1) * 4096);
                    while bit < stop {
                        if map[(bit / 8 - logical) as usize] & (1 << (bit % 8)) == 0 {
                            tx.clusters.change(&mut volume, allocation, bit, 1, true, limit)?;
                            changed |= 1;
                        }
                        bit += 1;
                    }
                }
            }
        }
        if let Some((index, old, length)) = collision {
            let new = tx.allocate_clusters(&mut volume, length, None)?;
            visit_owned_runs(&mut volume, &MftRecord::from_decoded(tx.mft_zero())?, raw, bits, |_, _, run| {
                let lcn = run.lcn.ok_or(Error::InvalidRunlist)?;
                if new < lcn + run.len && lcn < new + length {
                    return Err(Error::InvalidRunlist);
                }
                Ok(())
            })?;
            let source = runs[index];
            let prefix = old - source.lcn.unwrap();
            let mut replacement = [empty; 64];
            let mut n = 0;
            for (i, &run) in runs[..count].iter().enumerate() {
                if i != index {
                    replacement[n] = run;
                    n += 1;
                    continue;
                }
                if prefix != 0 {
                    replacement[n] = Extent { len: prefix, ..run };
                    n += 1;
                }
                replacement[n] = Extent { vcn: run.vcn + prefix, len: length, lcn: Some(new) };
                n += 1;
                let tail = run.len - prefix - length;
                if tail != 0 {
                    replacement[n] = Extent { vcn: run.vcn + prefix + length, len: tail, lcn: Some(old + length) };
                    n += 1;
                }
            }
            edit::set_runs(tx.record_mut(file), at, &replacement[..n])?;
            if edit::used(tx.record(file))? > super::tx::RECORD {
                return Err(Error::NoSpace);
            }
            edit::validate(tx.record(file))?;
            let mut copied = 0;
            while copied < length * BLOCK as u64 {
                let n = ((length * BLOCK as u64 - copied) as usize).min(CHUNK);
                volume.reader_mut().read_exact_at(old * BLOCK as u64 + copied, &mut chunk[..n])?;
                stage(self, &mut **volume.reader_mut(), &[(new * BLOCK as u64 + copied, &chunk[..n])], true)?;
                copied += n as u64;
            }
            changed |= 2;
        }
        if changed == 0 {
            return Ok(0);
        }
        drop(volume);
        tx.commit(self, io, journal)?;
        self.drain(io, scratch)?;
        for window in &mut self.windows {
            if window.0 == reference {
                *window = (0, 0, 0, false);
            }
        }
        Ok(changed)
    }

    /// Write data at offset, extending the stream as needed. Bytes between
    /// the old end and offset read as zero.
    pub fn write<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        offset: u64,
        data: &[u8],
        scratch: &mut [u8],
    ) -> Result<()> {
        if data.len() > MAX_WRITE {
            return Err(Error::Unsupported);
        }
        if data.is_empty() {
            return Ok(());
        }
        for _ in 0..3 {
            match self.step(io, reference, Op::Write(offset, data), scratch)? {
                Step::Done => return Ok(()),
                Step::Grow(to) => self.resize(io, reference, to, scratch)?,
                Step::Allocate(offset, length) => {
                    self.fallocate(io, reference, offset, length, 1, scratch)?;
                }
            }
        }
        Err(Error::Unsupported)
    }

    /// Set the stream length. Growth is zero-filled lazily (initialized size
    /// stays put); every step allocates or frees at least one cluster.
    pub fn resize<I: WriteIo>(&mut self, io: &mut I, reference: u64, size: u64, scratch: &mut [u8]) -> Result<()> {
        for w in &mut self.windows {
            if w.0 == reference {
                w.1 = 0;
                w.2 = 0;
                w.3 = false;
            }
        }
        while let Step::Grow(_) = self.step(io, reference, Op::Resize(size), scratch)? {}
        Ok(())
    }

    /// Reserve real clusters without initializing them; reads past initialized
    /// size remain zero. Explicit preallocation survives close and remount.
    pub fn allocate_file<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        end: u64,
        keep_size: bool,
        scratch: &mut [u8],
    ) -> Result<()> {
        while let Step::Grow(_) = self.step(io, reference, Op::Allocate(end, keep_size), scratch)? {}
        for w in &mut self.windows {
            if w.0 == reference {
                *w = (0, 0, 0, false);
            }
        }
        Ok(())
    }

    /// Linux allocation/range operations. New mappings and released clusters
    /// are published in one transaction; replacement data precedes its commit.
    pub fn fallocate<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        offset: u64,
        length: u64,
        mode: u32,
        scratch: &mut [u8],
    ) -> Result<u64> {
        if !matches!(mode, 0 | 1 | 3 | 8 | 16 | 17 | 32 | 64 | 65) || length == 0 {
            return Err(Error::InvalidAttribute);
        }
        let end = offset.checked_add(length).ok_or(Error::Overflow)?;
        if scratch.len() < METADATA_SCRATCH_BYTES || !self.initialized || self.failed {
            return Err(Error::Io);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, rest) = rest.split_at_mut(JOURNAL);
        let (image, rest) = rest.split_at_mut(super::tx::RECORD_IMAGE);
        let block = &mut rest[..CHUNK];
        let slot = tx.load_family(&mut volume, reference)?;
        image.copy_from_slice(tx.record(slot));
        let record = MftRecord::from_decoded(image)?;
        if record.flags()? != 1 {
            return Err(Error::InvalidAttribute);
        }
        let old = unnamed(&record, ATTR_DATA)?;
        if old.flags()? & !0x8000 != 0 {
            return Err(Error::Unsupported);
        }
        let size = old.data_size()?;
        let init = old.initialized_size()?;
        let shift = mode == 8 || mode == 32;
        if shift
            && (offset % BLOCK as u64 != 0
                || length % BLOCK as u64 != 0
                || offset >= size
                || (mode == 8 && end >= size))
        {
            return Err(Error::InvalidAttribute);
        }
        if mode == 3 && offset >= old.allocated_size()? {
            return Ok(size);
        }
        if !old.nonresident {
            drop(tx);
            drop(volume);
            self.allocate_file(io, reference, size.max(1), true, scratch)?;
            return self.fallocate(io, reference, offset, length, mode, scratch);
        }
        let allocated = old.allocated_size()?;
        if init > size || size > allocated {
            return Err(Error::InvalidAttribute);
        }
        // Validate all old ownership before the first write, including ranges
        // to be released; no hole owns physical storage.
        let mut covered = 0u64;
        for r in super::runlist::DataRuns::new(old.data_runs()?, 0) {
            let r = r?;
            if r.vcn != covered {
                return Err(Error::InvalidRunlist);
            }
            covered = covered.checked_add(r.len).ok_or(Error::Overflow)?;
            if let Some(lcn) = r.lcn {
                if tx.protected_overlap(lcn, r.len)?
                    || lcn
                        .checked_add(r.len)
                        .and_then(|n| n.checked_mul(BLOCK as u64))
                        .filter(|&n| n <= self.boot.total_sectors * u64::from(self.boot.bytes_per_sector))
                        .is_none()
                {
                    return Err(Error::InvalidRunlist);
                }
            }
        }
        if covered.checked_mul(BLOCK as u64) != Some(allocated) {
            return Err(Error::InvalidRunlist);
        }
        let new_size = match mode {
            8 => size - length,
            32 => size.checked_add(length).ok_or(Error::Overflow)?,
            _ if mode & 1 != 0 => size,
            _ => size.max(end),
        };
        let new_init = match mode {
            8 if offset < init => offset.max(init.saturating_sub(length)),
            32 if offset < init => init.checked_add(length).ok_or(Error::Overflow)?,
            _ => init,
        }
        .min(new_size);
        let from = if mode == 3 { offset.div_ceil(BLOCK as u64) } else { offset / BLOCK as u64 };
        let to = if mode == 3 { end / BLOCK as u64 } else { end.div_ceil(BLOCK as u64) };
        let mut attr = [0u8; 128];
        let n = edit::build_nonresident(ATTR_DATA, &[], &[], 0, 0, 0, &mut attr)?;
        edit::p16(&mut attr, 12, old.flags()?)?;
        let at = old.record_offset();
        edit::remove(tx.record_mut(slot), at)?;
        let at = edit::insert(tx.record_mut(slot), &attr[..n])?;
        let mut logical = 0u64;
        let mut inserted = false;
        let limit = if matches!(mode, 3 | 8 | 32) { covered } else { covered.max(to) };
        let mut iterator = super::runlist::DataRuns::new(old.data_runs()?, 0);
        let mut source = 0u64;
        while source < limit {
            let r = if source < covered {
                iterator.next().ok_or(Error::InvalidRunlist)??
            } else {
                super::runlist::Extent { vcn: covered, len: limit - covered, lcn: None }
            };
            let mut v = r.vcn;
            let stop = r.vcn + r.len;
            while v < stop {
                if mode == 32 && !inserted && v >= from {
                    edit::append_extent(tx.record_mut(slot), at, None, length / BLOCK as u64)?;
                    logical += length / BLOCK as u64;
                    inserted = true;
                }
                let next = if v < from {
                    stop.min(from)
                } else if v < to {
                    stop.min(to)
                } else {
                    stop
                };
                let count = next - v;
                let lcn = r.lcn.map(|l| l + v - r.vcn);
                let inside = v >= from && v < to && mode != 32;
                if inside && matches!(mode, 3 | 8) {
                    if let Some(lcn) = lcn {
                        tx.free_clusters(&mut volume, lcn, count)?;
                    }
                    if mode == 3 {
                        edit::append_extent(tx.record_mut(slot), at, None, count)?;
                        logical += count;
                    }
                } else if inside && (matches!(mode, 16 | 17) || lcn.is_none()) {
                    let mut done = 0;
                    while done < count {
                        let mut n = (count - done).min(STEP);
                        let new_lcn = loop {
                            match tx.allocate_clusters(&mut volume, n, None) {
                                Err(Error::NoSpace) if n > 1 => n = n.div_ceil(2),
                                other => break other?,
                            }
                        };
                        let mut bytes = 0u64;
                        while bytes < n * BLOCK as u64 {
                            let len = ((n * BLOCK as u64 - bytes) as usize).min(block.len());
                            block[..len].fill(0);
                            let start = (v + done) * BLOCK as u64 + bytes;
                            if matches!(mode, 16 | 17) {
                                // Preserve bytes outside an unaligned zero range.
                                let head = offset.min(init).min(start + len as u64);
                                if start < head {
                                    volume.read_attribute(old, start, &mut block[..(head - start) as usize])?;
                                }
                                let tail = end.max(start);
                                let keep = init.min(start + len as u64);
                                if tail < keep {
                                    volume.read_attribute(
                                        old,
                                        tail,
                                        &mut block[(tail - start) as usize..(keep - start) as usize],
                                    )?;
                                }
                            }
                            stage(
                                self,
                                &mut **volume.reader_mut(),
                                &[(new_lcn * BLOCK as u64 + bytes, &block[..len])],
                                true,
                            )?;
                            bytes += len as u64;
                        }
                        edit::append_extent(tx.record_mut(slot), at, Some(new_lcn), n)?;
                        logical += n;
                        done += n;
                    }
                    if let Some(lcn) = lcn {
                        tx.free_clusters(&mut volume, lcn, count)?;
                    }
                } else {
                    edit::append_extent(tx.record_mut(slot), at, lcn, count)?;
                    logical += count;
                }
                v = next;
            }
            source = stop;
        }
        if mode == 3 {
            // Edge bytes remain allocated. Zero only initialized bytes, with
            // all destinations validated before staging either edge.
            for (a, b) in [
                (offset, (offset.div_ceil(BLOCK as u64) * BLOCK as u64).min(end).min(init)),
                ((end / BLOCK as u64 * BLOCK as u64).max(offset), end.min(init)),
            ] {
                if a >= b {
                    continue;
                }
                let r = super::runlist::DataRuns::new(old.data_runs()?, 0)
                    .find_map(|r| match r {
                        Ok(r) if r.vcn <= a / BLOCK as u64 && a / (BLOCK as u64) < r.vcn + r.len => Some(Ok(r)),
                        Err(e) => Some(Err(e)),
                        _ => None,
                    })
                    .ok_or(Error::InvalidRunlist)??;
                if r.lcn.is_none() {
                    continue;
                }
                block[..(b - a) as usize].fill(0);
                super::write_plan::plan_nonresident_recovery(old, self.boot, a, b - a, |span| {
                    stage(
                        self,
                        &mut **volume.reader_mut(),
                        &[(
                            span.physical_offset,
                            &block[span.source_offset as usize..(span.source_offset + span.length) as usize],
                        )],
                        false,
                    )
                })?;
            }
        }
        edit::set_sizes(
            tx.record_mut(slot),
            at,
            logical.checked_mul(BLOCK as u64).ok_or(Error::Overflow)?,
            new_size,
            new_init,
        )?;
        let sparse = super::bytes::u16_at(tx.record(slot), at + 12)? & 0x8000 != 0;
        let si = edit::require(tx.record(slot), 0x10, &[])?;
        let value = edit::resident_value_offset(tx.record(slot), si)?;
        let flags = super::bytes::u32_at(tx.record(slot), value + 32)?;
        edit::p32(
            tx.record_mut(slot),
            value + 32,
            if sparse { flags | super::std_info::SPARSE } else { flags & !super::std_info::SPARSE },
        )?;
        drop(volume);
        tx.commit(self, io, journal)?;
        for w in &mut self.windows {
            if w.0 == reference {
                *w = (0, 0, 0, false);
            }
        }
        Ok(new_size)
    }

    /// Return unused append-window clusters without changing the file length.
    pub fn trim<I: WriteIo>(&mut self, io: &mut I, reference: u64, scratch: &mut [u8]) -> Result<()> {
        if !self.windows.iter().any(|w| w.0 == reference) {
            return Ok(());
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, _) = Tx::new(self, &mut volume, scratch)?;
        let slot = tx.load_family(&mut volume, reference)?;
        let size = unnamed(&MftRecord::from_decoded(tx.record(slot))?, ATTR_DATA)?.data_size()?;
        drop(tx);
        drop(volume);
        self.resize(io, reference, size, scratch)?;
        for w in &mut self.windows {
            if w.0 == reference {
                *w = (0, 0, 0, false);
            }
        }
        Ok(())
    }

    fn step<I: WriteIo>(&mut self, io: &mut I, reference: u64, op: Op<'_>, scratch: &mut [u8]) -> Result<Step> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES || reference_number(reference) < 16 {
            return Err(Error::Unsupported);
        }
        let end = match op {
            Op::Write(offset, data) => offset.checked_add(data.len() as u64).ok_or(Error::Overflow)?,
            Op::Resize(size) | Op::Allocate(size, _) => size,
        };
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, work) = rest.split_at_mut(JOURNAL);
        let (saved, chunk) = work.split_at_mut(SAVED);
        let chunk = chunk.get_mut(..CHUNK).ok_or(Error::Truncated)?;
        let slot = tx.load_family(&mut volume, reference)?;
        let (mut at, resident_len) = {
            let record = MftRecord::from_decoded(tx.record(slot))?;
            if record.flags()? != 1 || record.base_file_reference()? != 0 {
                return Err(Error::Unsupported);
            }
            let attr = unnamed(&record, ATTR_DATA)?;
            if attr.flags()? & !0x8000 != 0 {
                return Err(Error::Unsupported);
            }
            if attr.nonresident && attr.flags()? & 0x8000 != 0 {
                if let Op::Write(offset, data) = op {
                    let from = offset.min(attr.initialized_size()?) / BLOCK as u64;
                    let to = (offset + data.len() as u64).div_ceil(BLOCK as u64);
                    for run in super::runlist::DataRuns::new(attr.data_runs()?, 0) {
                        let run = run?;
                        if run.lcn.is_none() && run.vcn < to && from < run.vcn + run.len {
                            return Ok(Step::Allocate(from * BLOCK as u64, (to - from) * BLOCK as u64));
                        }
                    }
                }
            }
            let at = attr.record_offset();
            let len = if attr.nonresident { None } else { Some(u64::from(u32_at(tx.record(slot), at + 16)?)) };
            (at, len)
        };

        let mut converted = 0;
        if let Some(length) = resident_len {
            let rec = tx.record(slot);
            let value = usize::from(u16_at(rec, at + 20)?);
            let room = (edit::capacity(rec)? - edit::used(rec)? + edit::attr_len(rec, at)?)
                .saturating_sub(value)
                .min(512) as u64;
            let need = if matches!(op, Op::Resize(_)) { end } else { length.max(end) };
            if need <= room && !matches!(op, Op::Allocate(..)) {
                let (n, keep) = (need as usize, length.min(need) as usize);
                saved[..n].fill(0);
                saved[..keep].copy_from_slice(&edit::resident_value(rec, at)?[..keep]);
                if let Op::Write(offset, data) = op {
                    saved[offset as usize..offset as usize + data.len()].copy_from_slice(data);
                }
                edit::set_resident_value(tx.record_mut(slot), at, &saved[..n])?;
                drop(volume);
                tx.commit(self, io, journal)?;
                return Ok(Step::Done);
            }
            // Too large for the record: keep the bytes, continue as an empty
            // nonresident stream that already covers them.
            converted = length as usize;
            saved.get_mut(..converted).ok_or(Error::NoSpace)?.copy_from_slice(edit::resident_value(rec, at)?);
            let mut image = [0_u8; 128];
            let n = edit::build_nonresident(ATTR_DATA, &[], &[], 0, length, length, &mut image)?;
            edit::remove(tx.record_mut(slot), at)?;
            at = edit::insert(tx.record_mut(slot), &image[..n])?;
        }

        let (alloc, size, init) = edit::sizes(tx.record(slot), at)?;
        let cur = alloc / BLOCK as u64;
        let wanted = |bytes: u64| bytes.div_ceil(BLOCK as u64).saturating_sub(cur);

        // Shrink: free the tail in bounded steps.
        if let Op::Resize(to) = op {
            if to == size && converted == 0 && cur == to.div_ceil(BLOCK as u64) {
                return Ok(Step::Done);
            }
            if to <= size && (to < size || cur > to.div_ceil(BLOCK as u64)) {
                let keep = to.div_ceil(BLOCK as u64);
                let next = keep.max(cur.saturating_sub(STEP));
                let last = next == keep;
                if next < cur {
                    tx.free_attribute_tail(&mut volume, slot, at, next)?;
                    edit::truncate_runs(tx.record_mut(slot), at, next)?;
                }
                let alloc = next * BLOCK as u64;
                let size = if last { to } else { size.min(alloc) };
                edit::set_sizes(tx.record_mut(slot), at, alloc, size, init.min(size))?;
                drop(volume);
                tx.commit(self, io, journal)?;
                return Ok(if last { Step::Done } else { Step::Grow(to) });
            }
        }

        let want = match op {
            Op::Write(..) => wanted(end.max(size)).min(GROW + 1),
            Op::Resize(_) | Op::Allocate(..) => wanted(end).min(STEP),
        };
        if matches!(op, Op::Write(..)) && want > GROW {
            return Ok(Step::Grow(end));
        }
        let window_slot =
            self.windows.iter().position(|w| w.0 == reference).or_else(|| self.windows.iter().position(|w| w.0 == 0));
        let window = want > 0 && window_slot.is_some() && matches!(op, Op::Write(offset, _) if offset >= size);
        let requested = if window { want.max(WINDOW).min(GROW) } else { want };
        let safe_exposure = converted == 0
            && want == 0
            && self.windows.iter().any(|w| w.0 == reference && w.3 && w.1 <= init && end <= w.2);
        let in_place = matches!(op, Op::Write(..)) && converted == 0 && end <= init && want == 0;
        let new_size = if in_place {
            size
        } else {
            let got = extend(&mut tx, &mut volume, slot, at, requested, want)?;
            let alloc = alloc + got * BLOCK as u64;
            let (size, init) = match op {
                Op::Write(..) => (size.max(end), init.max(end)),
                Op::Resize(to) => (to.min(alloc), init),
                Op::Allocate(to, keep) => (if keep { size } else { size.max(to.min(alloc)) }, init),
            };
            edit::set_sizes(tx.record_mut(slot), at, alloc, size, init)?;
            size
        };
        drop(volume);

        let record = MftRecord::from_decoded(tx.record(slot))?;
        let attr = unnamed(&record, ATTR_DATA)?;
        let allocation = attr.allocated_size()?;
        let window_end = if window { allocation } else { 0 };
        // Validate every destination before the first data write, including
        // block padding and all extents of $MFT (not just its first cluster).
        if let Op::Write(offset, data) = op {
            let start = offset.min(init) / BLOCK as u64 * BLOCK as u64;
            let stop = ((offset + data.len() as u64).div_ceil(BLOCK as u64) * BLOCK as u64).max(window_end);
            if in_place {
                plan_nonresident_overwrite(attr, self.boot, offset, data.len() as u64, |_| Ok(()))?;
            }
            plan_nonresident_recovery(attr, self.boot, start, stop - start, |span| {
                if tx.protected_overlap(span.physical_offset / BLOCK as u64, span.length.div_ceil(BLOCK as u64))? {
                    return Err(Error::InvalidRunlist);
                }
                Ok(())
            })?;
        }
        if converted != 0 {
            put(self, io, attr, 0, &saved[..converted], 0, chunk, true)?;
        }
        if let Op::Write(offset, data) = op {
            put(self, io, attr, offset, data, init, chunk, !(in_place || safe_exposure))?;
            if window_end > end {
                // Reuse the assembly buffer; preserve a partial data cluster,
                // and zero only the uncovered tail. Full data clusters are not rewritten.
                put(self, io, attr, window_end, &[], end, chunk, true)?;
            }
        }
        if !in_place {
            tx.commit(self, io, journal)?;
        }
        if window_end > end {
            self.windows[window_slot.unwrap()] = (reference, end, window_end, !self.data_dirty);
        }
        Ok(match op {
            Op::Resize(to) if new_size < to => Step::Grow(to),
            Op::Allocate(to, _) if allocation < to => Step::Grow(to),
            _ => Step::Done,
        })
    }
}

/// Append want clusters to the stream, in several runs when free space is
/// fragmented. Returns the clusters obtained (want unless it fails).
fn extend<R: ReadAt>(
    tx: &mut Tx<'_>,
    volume: &mut Volume<R>,
    slot: usize,
    at: usize,
    want: u64,
    required: u64,
) -> Result<u64> {
    let mut got = 0;
    while got < want {
        let hint = edit::last_run_end(tx.record(slot), at)?;
        let mut n = want - got;
        let lcn = loop {
            match tx.allocate_clusters(volume, n, hint) {
                Err(Error::NoSpace) if got >= required => return Ok(got),
                Err(Error::NoSpace) if n > 1 => n = n.div_ceil(2),
                other => break other?,
            }
        };
        edit::append_run(tx.record_mut(slot), at, lcn, n)?;
        got += n;
    }
    Ok(got)
}

/// Read out.len() bytes at stream offset at, which lie inside the mapping.
fn get<I: WriteIo>(io: &mut I, attr: Attribute<'_>, writer: &Writer, at: u64, out: &mut [u8]) -> Result<()> {
    plan_nonresident_recovery(attr, writer.boot, at, out.len() as u64, |span| {
        let from = span.source_offset as usize;
        io.read_exact_at(span.physical_offset, &mut out[from..from + span.length as usize])
    })?;
    Ok(())
}

/// Stage data at stream offset offset into the mapped clusters. Bytes of
/// touched blocks that are neither caller data nor initialized (the gap from
/// init up to offset, and the block tail past the end) are written as
/// zero; initialized bytes around the write are preserved.
fn put<I: WriteIo>(
    writer: &mut Writer,
    io: &mut I,
    attr: Attribute<'_>,
    offset: u64,
    data: &[u8],
    init: u64,
    buf: &mut [u8],
    exposure: bool,
) -> Result<()> {
    let block = BLOCK as u64;
    let end = offset + data.len() as u64;
    let mut start = offset.min(init) / block * block;
    let stop = end.div_ceil(block) * block;
    while start < stop {
        let next = stop.min(start + buf.len() as u64);
        let n = (next - start) as usize;
        let chunk = &mut buf[..n];
        chunk.fill(0);
        let keep = init.min(next);
        if start < keep {
            let head = offset.min(keep);
            if start < head {
                get(io, attr, writer, start, &mut chunk[..(head - start) as usize])?;
            }
            let tail = end.max(start);
            if tail < keep {
                get(io, attr, writer, tail, &mut chunk[(tail - start) as usize..(keep - start) as usize])?;
            }
        }
        let (left, right) = (offset.max(start), end.min(next));
        if left < right {
            chunk[(left - start) as usize..(right - start) as usize]
                .copy_from_slice(&data[(left - offset) as usize..(right - offset) as usize]);
        }
        plan_nonresident_recovery(attr, writer.boot, start, n as u64, |span| {
            let from = span.source_offset as usize;
            stage(writer, io, &[(span.physical_offset, &chunk[from..from + span.length as usize])], exposure)
        })?;
        start = next;
    }
    Ok(())
}
