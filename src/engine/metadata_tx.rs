//! Module: ntfs_rs::metadata_tx
//! Purpose: Batch metadata edits and publish journaled transactions durably.
//! Created: 2026-10-01
//! Architecture: Stream resizing and allocation submit checked metadata patches
//! here. This module coordinates batching, journal commits and checkpoints with
//! Writer; its WriteIo adapter supplies device reads, writes and flushes.
//!
//! Multi-page metadata transactions, shared by stream resizing and allocation.
use super::batch::{patches as batch_patches, same_image, Fit, Ranges, QUARANTINE};
use super::bytes::u16_at;
use super::journal::{stored_slot, PageReservation};
use super::logfile::*;
use super::mft::{reference_number, system_record, MftRecord, ATTR_DATA};
use super::replay::protect_mft_record;
use super::resident_writer::{record_page, write_restarts, WriteIo, Writer};
use super::volume::ReadAt;
use super::{Error, Result};

/// Changed records, their scattered MFT bits, and the cluster bitmap plan.
pub const MAX_PATCHES: usize = 2 * super::tx::MAX_RECORDS + super::allocation::BITMAP_PATCHES;

/// Net clusters that the $Bitmap sectors among patches mark allocated. Every
/// cluster allocation and release reaches the volume as such a patch.
fn allocation_change(patches: &[MetadataPatch<'_>]) -> i64 {
    let ones = |bytes: &[u8]| bytes.iter().map(|byte| i64::from(byte.count_ones())).sum::<i64>();
    patches
        .iter()
        .filter(|p| {
            !p.mft && p.attribute_kind == ATTR_DATA && reference_number(p.stream_reference) == system_record::BITMAP
        })
        .map(|p| ones(p.after) - ones(p.before))
        .sum()
}
const BITS_PER_BYTE: usize = u8::BITS as usize;
const RANGE_RECORD_OVERHEAD: usize = lfs_layout::HEADER_BYTES + log_operation::HEADER_BYTES;
const RANGES_PER_RECORD: usize =
    (log_page_layout::FRAGMENT_BYTES - RANGE_RECORD_OVERHEAD) / log_operation::CLUSTER_RANGE_BYTES;

/// One bitmap transition, streamed in cluster order without allocating a range table.
pub(super) fn released_ranges<'a>(
    logical: u64,
    before: &'a [u8],
    after: &'a [u8],
) -> impl Iterator<Item = (u64, u64)> + 'a {
    let mut bit = 0;
    core::iter::from_fn(move || {
        let freed =
            |bit: usize| before[bit / BITS_PER_BYTE] & !after[bit / BITS_PER_BYTE] & (1 << (bit % BITS_PER_BYTE)) != 0;
        let limit = before.len().min(after.len()) * BITS_PER_BYTE;
        while bit < limit && !freed(bit) {
            bit += 1;
        }
        if bit == limit {
            return None;
        }
        let start = bit;
        while bit < limit && freed(bit) {
            bit += 1;
        }
        Some((logical * BITS_PER_BYTE as u64 + start as u64, (bit - start) as u64))
    })
}

pub(super) fn volume_bitmap(mft: bool, kind: u32, reference: u64, name: &[u8]) -> bool {
    !mft && kind == ATTR_DATA && reference_number(reference) == system_record::BITMAP && name.is_empty()
}

fn freed_ranges<'a>(patches: &'a [MetadataPatch<'_>]) -> impl Iterator<Item = (u64, u64)> + 'a {
    patches
        .iter()
        .filter(|p| volume_bitmap(p.mft, p.attribute_kind, p.stream_reference, p.name))
        .flat_map(|p| released_ranges(p.logical, p.before, p.after))
}

pub(super) fn patch_log_pages(len: usize, fresh: bool) -> usize {
    let undo_bytes = if fresh { 0 } else { len };
    let update_header = RANGE_RECORD_OVERHEAD + super::write_plan::METADATA_MAP_BYTES;
    let compensation_header = update_header + lfs_layout::HEADER_BYTES;
    let redo = (update_header + len + undo_bytes).div_ceil(log_page_layout::FRAGMENT_BYTES);
    let rollback = if fresh { 0 } else { (compensation_header + 2 * len).div_ceil(log_page_layout::FRAGMENT_BYTES) };
    1 + redo + rollback
}

fn update_header(patch: &MetadataPatch<'_>, cluster: u64) -> usize {
    RANGE_RECORD_OVERHEAD
        + ((patch.physical % cluster + patch.after.len() as u64).div_ceil(cluster) as usize)
            * super::write_plan::LCN_BYTES
}

pub(super) fn release_log_pages(ranges: usize) -> usize {
    ranges.div_ceil(RANGES_PER_RECORD)
}

fn freed_target(patches: &[MetadataPatch<'_>], physical: u64, map: &[u8], len: usize, cluster: u64) -> Result<bool> {
    let mut freed = false;
    super::write_plan::metadata_spans(physical, map, cluster, len, |span| {
        freed |= freed_ranges(patches).any(|(start, count)| {
            span.physical_offset < (start + count) * cluster && start * cluster < span.physical_offset + span.length
        });
        Ok(())
    })?;
    Ok(freed)
}

fn patches_overlap(a: &MetadataPatch<'_>, b: &MetadataPatch<'_>, cluster: u64) -> Result<bool> {
    super::write_plan::metadata_overlap(
        a.physical,
        a.physical_clusters,
        a.before.len(),
        b.physical,
        b.physical_clusters,
        b.before.len(),
        cluster,
    )
}

pub(super) fn read_target<I: ReadAt>(
    io: &mut I,
    physical: u64,
    map: &[u8],
    cluster: u64,
    output: &mut [u8],
) -> Result<()> {
    super::write_plan::metadata_spans(physical, map, cluster, output.len(), |span| {
        let start = span.source_offset as usize;
        io.read_exact_at(span.physical_offset, &mut output[start..start + span.length as usize])
    })
}

pub(super) fn write_target<I: WriteIo>(
    io: &mut I,
    physical: u64,
    map: &[u8],
    cluster: u64,
    bytes: &[u8],
) -> Result<()> {
    super::write_plan::metadata_spans(physical, map, cluster, bytes.len(), |span| {
        let start = span.source_offset as usize;
        io.write_at(span.physical_offset, &bytes[start..start + span.length as usize])
    })
}

pub(super) fn hold_target<I: WriteIo>(
    io: &mut I,
    physical: u64,
    map: &[u8],
    cluster: u64,
    bytes: &[u8],
    first: bool,
) -> Result<()> {
    super::write_plan::metadata_spans(physical, map, cluster, bytes.len(), |span| {
        let start = span.source_offset as usize;
        io.hold_at(span.physical_offset, &bytes[start..start + span.length as usize], first)
    })
}

pub(super) fn release_target<I: WriteIo>(
    io: &mut I,
    physical: u64,
    map: &[u8],
    cluster: u64,
    len: usize,
) -> Result<()> {
    super::write_plan::metadata_spans(physical, map, cluster, len, |span| {
        io.release_at(span.physical_offset, span.length as usize);
        Ok(())
    })
}

/// Clusters the largest journaled structure spans: a 4 KiB block on the
/// smallest cluster.
const MAX_SPANNED: usize = super::write_plan::METADATA_CLUSTERS;
/// Minimum scratch for commit_metadata.
pub const COMMIT_SCRATCH_BYTES: usize = 4096 + 45056;
pub struct MetadataPatch<'a> {
    /// The target's previous contents are not a live structure (a newly
    /// allocated index block). Its preimage is compared byte-for-byte but not
    /// parsed, and the logged undo action is Noop: rollback leaves free space.
    pub fresh: bool,
    pub physical: u64,
    /// Actual LCNs for a split structure; empty means contiguous.
    pub physical_clusters: &'a [u8],
    pub logical: u64,
    /// $MFT or $Bitmap file reference, including sequence number.
    pub stream_reference: u64,
    pub mft: bool,
    pub attribute_kind: u32,
    pub name: &'a [u8],
    /// MFT bytes have already had USA fixups decoded. Bitmap bytes are raw.
    pub before: &'a [u8],
    pub after: &'a mut [u8],
}

pub(super) const fn patch_scratch_bytes(count: usize) -> usize {
    count * core::mem::size_of::<MetadataPatch<'static>>() + core::mem::align_of::<MetadataPatch<'static>>()
}

/// Keep transaction descriptors in the caller's large scratch buffer rather
/// than on the small kernel stack. The one cast below only changes aligned,
/// fully initialized MaybeUninit slots into their initialized type.
#[allow(unsafe_code)]
pub(super) fn patch_slots<'a>(scratch: &mut [u8], count: usize) -> Result<(&mut [MetadataPatch<'a>], &mut [u8])> {
    let bytes = count
        .checked_mul(core::mem::size_of::<MetadataPatch<'a>>())
        .and_then(|n| n.checked_add(core::mem::align_of::<MetadataPatch<'a>>()))
        .ok_or(Error::Overflow)?;
    if scratch.len() < bytes {
        return Err(Error::NoSpace);
    }
    let (storage, rest) = scratch.split_at_mut(bytes);
    // MaybeUninit accepts any byte pattern, and align_to_mut supplies the
    // alignment required by MetadataPatch.
    let (_, slots, _) = unsafe { storage.align_to_mut::<core::mem::MaybeUninit<MetadataPatch<'a>>>() };
    for slot in &mut slots[..count] {
        slot.write(MetadataPatch {
            fresh: false,
            physical: 0,
            physical_clusters: &[],
            logical: 0,
            stream_reference: 0,
            mft: false,
            attribute_kind: 0x80,
            name: &[],
            before: &[],
            after: &mut [],
        });
    }
    // The entire returned range was initialized above and is disjoint from
    // rest, which remains the journal workspace.
    let patches = unsafe { core::slice::from_raw_parts_mut(slots.as_mut_ptr().cast(), count) };
    Ok((patches, rest))
}

impl Writer {
    /// Publish patches as one transaction. With a batch attached the images
    /// become visible immediately and join the pending group commit; without
    /// one (or when the set cannot join it) they are journaled right away.
    pub(super) fn commit_metadata<I: WriteIo>(
        &mut self,
        io: &mut I,
        patches: &mut [MetadataPatch<'_>],
        scratch: &mut [u8],
    ) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if patches.is_empty() || patches.len() > MAX_PATCHES || scratch.len() < COMMIT_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        let allocated = allocation_change(patches);
        if !(self.batch.attached() && self.defer(io, patches, scratch)?) {
            self.commit_barrier(io, patches, scratch)?;
        }
        self.allocated_delta += allocated;
        Ok(())
    }

    /// Clusters that transactions of this session have allocated, less those
    /// they freed, counting pending ones as readers see them. Statfs adds it
    /// to a single count of $Bitmap instead of counting again.
    pub fn allocated_delta(&self) -> i64 {
        self.allocated_delta
    }

    /// Journal patches immediately, after everything pending is durable.
    pub(super) fn commit_barrier<I: WriteIo>(
        &mut self,
        io: &mut I,
        patches: &mut [MetadataPatch<'_>],
        scratch: &mut [u8],
    ) -> Result<()> {
        self.drain(io, scratch)?;
        self.commit_now(io, patches, scratch, false, true)
    }

    /// User data still waiting for a durability barrier.
    pub fn data_pending(&self) -> bool {
        self.data_dirty
    }

    /// Number of metadata structures waiting for the next drain.
    pub fn pending(&self) -> usize {
        self.batch.pending()
    }

    /// Whether the caller should drain before its next operation, while its
    /// stack is still shallow: see `Batch::crowded`.
    pub fn crowded(&self) -> bool {
        self.batch.crowded()
    }

    /// Hand the writer an arena for group commit. Must precede initialize.
    pub fn attach_batch(&mut self, arena: &'static mut [u8]) -> Result<()> {
        if self.initialized {
            return Err(Error::Unsupported);
        }
        if arena.len() < super::batch::BATCH_BYTES {
            return Err(Error::Unsupported);
        }
        let (pending, committed) = arena.split_at_mut(arena.len() / 2);
        self.committed.attach(committed)?;
        self.batch.attach(pending)
    }

    /// Freed clusters that must not be allocated before the next drain.
    pub(super) fn blocked(&self) -> Ranges<QUARANTINE> {
        self.batch.blocked()
    }

    /// Remember clusters freed by the transaction just deferred. A full table
    /// forces the drain that makes them reusable.
    pub(super) fn quarantine<I: WriteIo>(
        &mut self,
        io: &mut I,
        ranges: &[(u64, u64)],
        scratch: &mut [u8],
    ) -> Result<()> {
        if self.batch.pending() != 0 && !self.batch.quarantine(ranges) {
            self.drain(io, scratch)?;
        }
        Ok(())
    }

    fn check_shape(&self, patch: &MetadataPatch<'_>) -> Result<()> {
        let len = patch.before.len();
        if len != patch.after.len()
            || (patch.mft && len != self.boot.record_bytes as usize)
            || (!patch.mft && len != if patch.attribute_kind == 0xa0 { 4096 } else { 512 })
            || patch.name.len() > 510
            || patch.name.len() % 2 != 0
            || patch.physical % 512 != 0
            || patch.logical % 512 != 0
            || patch.logical % u64::from(self.boot.cluster_bytes) != patch.physical % u64::from(self.boot.cluster_bytes)
        {
            return Err(Error::Unsupported);
        }
        let end = self.boot.total_sectors * u64::from(self.boot.bytes_per_sector);
        super::write_plan::metadata_spans(
            patch.physical,
            patch.physical_clusters,
            u64::from(self.boot.cluster_bytes),
            len,
            |span| {
                if span.physical_offset + span.length > end
                    || self.log.overlaps(span.physical_offset, span.physical_offset + span.length)
                {
                    return Err(Error::InvalidRunlist);
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Current on-disk (or cached) image must be a valid structure equal to
    /// the caller's preimage. verify is scratch of at least the patch size.
    fn check_preimage<I: ReadAt>(
        io: &mut I,
        patch: &MetadataPatch<'_>,
        index_vcn_bytes: u64,
        cluster: u64,
        verify: &mut [u8],
    ) -> Result<()> {
        let len = patch.before.len();
        let verify = &mut verify[..len];
        read_target(io, patch.physical, patch.physical_clusters, cluster, verify)?;
        if patch.fresh {
            if patch.mft {
                return Err(Error::Unsupported);
            }
        } else if patch.mft {
            MftRecord::parse(verify, 512)?;
        } else if patch.attribute_kind == 0xa0 {
            super::index::IndexBlock::parse(verify, 512, patch.logical / index_vcn_bytes)?;
        }
        if !same_image(verify, patch.before, !patch.fresh && (patch.mft || patch.attribute_kind == 0xa0)) {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    /// Whether the caller's preimage is pending entry e as readers see it. A
    /// fresh target, such as an index block a pending deletion freed, was read
    /// raw through its protected hold rather than decoded, so it is compared
    /// with the protected form of the pending image. verify is scratch.
    fn matches_pending(&self, patch: &MetadataPatch<'_>, e: usize, verify: &mut [u8]) -> Result<bool> {
        let pending = self.batch.after(e);
        let structured = patch.mft || patch.attribute_kind == 0xa0;
        if !patch.fresh || !structured {
            return Ok(same_image(patch.before, pending, structured));
        }
        let protected = verify.get_mut(..pending.len()).ok_or(Error::Truncated)?;
        protected.copy_from_slice(pending);
        if patch.mft {
            protect_mft_record(protected, 512)?;
        } else {
            protect_index(protected)?;
        }
        Ok(same_image(patch.before, protected, true))
    }

    /// Whether patches can join the pending group: None if they conflict
    /// with it, Some(false) if they merely do not fit right now.
    fn admit(&self, patches: &[MetadataPatch<'_>]) -> Option<bool> {
        let (mut new, mut bytes, mut pages) = (0, 0, self.batch.log_pages());
        pages += release_log_pages(freed_ranges(patches).count());
        for p in patches {
            match self.batch.classify(p, u64::from(self.boot.cluster_bytes)) {
                Fit::Conflict => return None,
                Fit::Merge(_) => {}
                Fit::New => {
                    new += 1;
                    bytes += 2 * p.before.len() + p.name.len() + p.physical_clusters.len();
                    pages += patch_log_pages(p.before.len(), p.fresh);
                }
            }
        }
        Some(
            self.batch.count() + new <= MAX_PATCHES
                && self.batch.used() + bytes <= self.batch.capacity()
                && pages <= self.log_pages,
        )
    }

    /// Make the images visible and queue them. Ok(false): the set cannot be
    /// queued and must be journaled directly.
    fn defer<I: WriteIo>(&mut self, io: &mut I, patches: &mut [MetadataPatch<'_>], scratch: &mut [u8]) -> Result<bool> {
        for (i, patch) in patches.iter().enumerate() {
            self.check_shape(patch)?;
            if patches[..i]
                .iter()
                .any(|p| patches_overlap(patch, p, u64::from(self.boot.cluster_bytes)).unwrap_or(true))
            {
                return Err(Error::InvalidRecord);
            }
        }
        match self.admit(patches) {
            None => return Ok(false),
            Some(true) => {}
            Some(false) => {
                if self.batch.pending() == 0 {
                    return Ok(false);
                }
                self.make_room(io, scratch)?;
                if self.admit(patches) != Some(true) {
                    return Ok(false);
                }
            }
        }
        // Different fragment keys cannot coexist as read overlays: retire old
        // committed holds before installing the pending layout's images.
        if patches
            .iter()
            .any(|patch| matches!(self.committed.classify(patch, u64::from(self.boot.cluster_bytes)), Fit::Conflict))
        {
            if let Err(error) = self.write_committed_home(io, &[]) {
                self.failed = true;
                return Err(error);
            }
        }
        let verify = &mut scratch[..4096];
        let index_vcn_bytes = self.boot.index_vcn_bytes();
        for patch in patches.iter() {
            match self.batch.classify(patch, u64::from(self.boot.cluster_bytes)) {
                Fit::Merge(e) => {
                    if !self.matches_pending(patch, e, verify)? {
                        return Err(Error::InvalidRecord);
                    }
                }
                _ => Self::check_preimage(io, patch, index_vcn_bytes, u64::from(self.boot.cluster_bytes), verify)?,
            }
        }
        // Everything is valid; failures from here on poison the session.
        let mirror = self.boot.mft_mirror_lcn * u64::from(self.boot.cluster_bytes);
        let result = (|| {
            for patch in patches.iter_mut() {
                let structured = patch.mft || patch.attribute_kind == 0xa0;
                let first = match self.batch.classify(patch, u64::from(self.boot.cluster_bytes)) {
                    Fit::Merge(e) => {
                        self.batch.replace_after(e, patch.after);
                        false
                    }
                    _ => {
                        // Undo image: the exact current preimage, with the
                        // live LSN and fixup token.
                        self.batch.push(patch, patch.before)?;
                        if structured && !patch.fresh {
                            let e = self.batch.count() - 1;
                            let head = &mut verify[..64];
                            io.read_exact_at(patch.physical, head)?;
                            self.batch.refresh_stamp(e, head)?;
                        }
                        true
                    }
                };
                if patch.mft {
                    protect_mft_record(patch.after, 512)?;
                } else if patch.attribute_kind == 0xa0 {
                    protect_index(patch.after)?;
                }
                hold_target(
                    io,
                    patch.physical,
                    patch.physical_clusters,
                    u64::from(self.boot.cluster_bytes),
                    patch.after,
                    first,
                )?;
                if patch.mft && patch.logical < self.boot.mirrored_bytes() {
                    io.hold_at(mirror + patch.logical, patch.after, first)?;
                }
            }
            Ok::<(), Error>(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result.map(|()| true)
    }

    /// Journal pending structures, retaining their committed images until
    /// checkpoint. Data a commit publishes must be durable before it, so
    /// that a power cut never exposes a cluster's previous contents.
    pub fn drain<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        self.drain_batch(io, scratch, true)
    }

    /// Journal pending structures to free the batch, without waiting for the
    /// device: the commit becomes durable at the next flush, which precedes
    /// any home write of its targets. A batch that freed clusters still
    /// drains durably, since its quarantine ends with the drain.
    pub fn make_room<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        let durable = !self.batch.blocked().as_slice().is_empty();
        self.drain_batch(io, scratch, durable)
    }

    /// A commit journaled by make_room still awaits its device flush.
    pub fn log_unflushed(&self) -> bool {
        self.log_unflushed
    }

    /// Flush a commit that make_room left without one. Committed targets may
    /// reach their home location only after their commit record is durable.
    fn settle_log<I: WriteIo>(&mut self, io: &mut I) -> Result<()> {
        if self.log_unflushed {
            io.flush()?;
            self.log_unflushed = false;
        }
        Ok(())
    }

    fn drain_batch<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8], durable: bool) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if self.batch.pending() == 0 {
            if durable && (self.data_dirty || self.log_unflushed) {
                if let Err(e) = io.flush() {
                    self.failed = true;
                    return Err(e);
                }
                self.data_dirty = false;
                self.exposure_dirty = false;
                self.log_unflushed = false;
            }
            return Ok(());
        }
        if scratch.len() < COMMIT_SCRATCH_BYTES + patch_scratch_bytes(self.batch.pending()) {
            return Err(Error::Unsupported);
        }
        let (patches, work) = patch_slots(scratch, self.batch.pending())?;
        let Some((arena, used)) = self.batch.take() else {
            return Err(Error::Io);
        };
        // commit_now owns exposure and log-ordering barriers.
        batch_patches(&mut arena[..used], self.batch.entries(), patches);
        let result = self.commit_now(io, patches, work, true, durable);
        self.batch.restore(arena);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Drain and publish an empty checkpoint at sync_fs/unmount boundaries.
    pub fn checkpoint<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        self.drain(io, scratch)?;
        self.checkpoint_now(io, scratch, &[])
    }

    fn checkpoint_now<I: WriteIo>(
        &mut self,
        io: &mut I,
        scratch: &mut [u8],
        pending: &[MetadataPatch<'_>],
    ) -> Result<()> {
        if self.current_lsn == self.checkpoint_lsn {
            return Ok(());
        }
        if scratch.len() < COMMIT_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        let (restart, rest) = scratch.split_at_mut(4096);
        let (page, rest) = rest.split_at_mut(4096);
        let (payload, encoding) = rest.split_at_mut(64);
        self.failed = true;
        let result = (|| {
            self.log.read(io, 0, restart)?;
            page.copy_from_slice(restart);
            let mut header = RestartPage::parse(page, 512)?;
            if header.current_lsn != self.checkpoint_lsn {
                return Err(Error::InvalidLog);
            }
            header.current_lsn = self.current_lsn;
            super::journal::reserve_pages_into(header, 1, page)?;
            let slot = stored_slot(page, 0)?;
            self.settle_log(io)?;
            // Flush the last COMMITTED images, not newer pending overlays.
            // The mount-owned copies stay readable even if buffer heads evict.
            let mirror = self.boot.mft_mirror_lcn * u64::from(self.boot.cluster_bytes);
            for (i, e) in self.committed.entries().iter().enumerate() {
                write_target(
                    io,
                    e.physical,
                    self.committed.mapping(i),
                    u64::from(self.boot.cluster_bytes),
                    self.committed.after(i),
                )?;
                if e.mft && e.logical < self.boot.mirrored_bytes() {
                    io.write_at(mirror + e.logical, self.committed.after(i))?;
                }
            }
            // Never publish a checkpoint until all targets are durable.
            io.flush()?;
            payload.fill(0);
            payload[..4].copy_from_slice(&1u32.to_le_bytes());
            payload[8..16].copy_from_slice(&slot.lsn.to_le_bytes());
            let n = encode_lfs_record(
                &LfsRecordInput {
                    this_lsn: slot.lsn,
                    previous_lsn: 0,
                    undo_next_lsn: 0,
                    client_sequence: 0,
                    client_index: 0,
                    record_type: 2,
                    transaction_id: 0,
                    flags: 0,
                    payload,
                },
                encoding,
            )?;
            record_page(io, &self.log, slot, &encoding[..n], 0, page)?;
            self.log.write(io, slot.offset, page)?;
            io.flush()?;
            advance_restart_checkpoint(restart, 512, slot.lsn)?;
            write_restarts(io, &self.log, restart)?;
            self.current_lsn = slot.lsn;
            self.checkpoint_lsn = slot.lsn;
            self.open_attribute_count = 0;
            self.data_dirty = false;
            self.exposure_dirty = false;
            for i in 0..self.committed.count() {
                self.release_unused_committed(io, i, pending)?;
            }
            if let Some((arena, _)) = self.committed.take() {
                self.committed.restore(arena);
            }
            Ok(())
        })();
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    /// Spill retained committed target images home without moving the checkpoint.
    /// Their commits are durable once settle_log has run; a later checkpoint
    /// flushes the targets before the restart area. Pending batch overlays keep
    /// their holds. The caller guards the session's failed state.
    fn write_committed_home<I: WriteIo>(&mut self, io: &mut I, pending: &[MetadataPatch<'_>]) -> Result<()> {
        if !self.committed.attached() || self.committed.count() == 0 {
            return Ok(());
        }
        let mirror = self.boot.mft_mirror_lcn * u64::from(self.boot.cluster_bytes);
        let result = (|| {
            self.settle_log(io)?;
            for (i, e) in self.committed.entries().iter().enumerate() {
                write_target(
                    io,
                    e.physical,
                    self.committed.mapping(i),
                    u64::from(self.boot.cluster_bytes),
                    self.committed.after(i),
                )?;
                if e.mft && e.logical < self.boot.mirrored_bytes() {
                    io.write_at(mirror + e.logical, self.committed.after(i))?;
                }
            }
            for i in 0..self.committed.count() {
                self.release_unused_committed(io, i, pending)?;
            }
            let Some((arena, _)) = self.committed.take() else {
                return Err(Error::Io);
            };
            self.committed.restore(arena);
            Ok(())
        })();
        result
    }

    // The adapter keys holds by the exact physical span, including its length.
    // A detached batch has descriptors but no readable arena; its live patches
    // carry the sidecars until the drain restores that arena.
    fn pending_hold(&self, pending: &[MetadataPatch<'_>], physical: u64, len: usize) -> Result<bool> {
        let cluster = u64::from(self.boot.cluster_bytes);
        let mirror = self.boot.mft_mirror_lcn * cluster;
        let mut needed = false;
        let mut inspect = |at: u64, map: &[u8], bytes: usize, mft: bool, logical: u64| {
            super::write_plan::metadata_spans(at, map, cluster, bytes, |span| {
                needed |= span.physical_offset == physical && span.length as usize == len;
                Ok(())
            })?;
            needed |= mft && logical < self.boot.mirrored_bytes() && mirror + logical == physical && bytes == len;
            Ok::<(), Error>(())
        };
        for patch in pending {
            inspect(patch.physical, patch.physical_clusters, patch.after.len(), patch.mft, patch.logical)?;
        }
        if self.batch.attached() {
            for (i, entry) in self.batch.entries().iter().enumerate() {
                inspect(entry.physical, self.batch.mapping(i), entry.len, entry.mft, entry.logical)?;
            }
        }
        Ok(needed)
    }

    fn release_unused_committed<I: WriteIo>(
        &self,
        io: &mut I,
        index: usize,
        pending: &[MetadataPatch<'_>],
    ) -> Result<()> {
        let entry = self.committed.entries()[index];
        let cluster = u64::from(self.boot.cluster_bytes);
        super::write_plan::metadata_spans(entry.physical, self.committed.mapping(index), cluster, entry.len, |span| {
            if !self.pending_hold(pending, span.physical_offset, span.length as usize)? {
                io.release_at(span.physical_offset, span.length as usize);
            }
            Ok(())
        })?;
        if entry.mft && entry.logical < self.boot.mirrored_bytes() {
            let mirror = self.boot.mft_mirror_lcn * cluster + entry.logical;
            if !self.pending_hold(pending, mirror, entry.len)? {
                io.release_at(mirror, entry.len);
            }
        }
        Ok(())
    }

    fn commit_now<I: WriteIo>(
        &mut self,
        io: &mut I,
        patches: &mut [MetadataPatch<'_>],
        scratch: &mut [u8],
        verified: bool,
        durable: bool,
    ) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if patches.is_empty() || patches.len() > MAX_PATCHES || scratch.len() < COMMIT_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        for p in patches.iter() {
            self.check_shape(p)?;
            if volume_bitmap(p.mft, p.attribute_kind, p.stream_reference, p.name)
                && p.logical
                    .checked_add(p.before.len() as u64)
                    .and_then(|n| n.checked_mul(BITS_PER_BYTE as u64))
                    .is_none()
            {
                return Err(Error::Overflow);
            }
        }
        let clusters = self.boot.total_sectors / u64::from(self.boot.sectors_per_cluster);
        let mut range_count = 0;
        for (start, count) in freed_ranges(patches) {
            if start == 0 || start + count > clusters {
                return Err(Error::InvalidRunlist);
            }
            range_count += 1;
        }
        let release_records = release_log_pages(range_count);
        // Reuse is allowed when this call returns, including make_room.
        let durable = durable || range_count != 0;
        // Bounded retention: spill already-committed target images before
        // admitting a set that would fill the arena or reuse an address with a
        // different shape. Do not move the checkpoint just to free RAM.
        let mut count = self.committed.count();
        let mut bytes = self.committed.used();
        let mut conflict = false;
        for p in patches.iter() {
            match self.committed.classify(p, u64::from(self.boot.cluster_bytes)) {
                Fit::Merge(_) => {}
                Fit::Conflict => conflict = true,
                Fit::New => {
                    count += 1;
                    bytes += 2 * p.before.len() + p.name.len() + p.physical_clusters.len();
                }
            }
        }
        // The spill waits for this commit's own barrier, which makes every
        // earlier commit durable, so it costs no device flush of its own.
        let spill = self.committed.attached() && (conflict || count > MAX_PATCHES || bytes > self.committed.capacity());
        let cache_targets = self.committed.attached()
            && patches.iter().map(|p| 2 * p.before.len() + p.name.len() + p.physical_clusters.len()).sum::<usize>()
                <= self.committed.capacity();
        let mut open_of = [0u8; MAX_PATCHES];
        let mut opens = 0;
        let mut packed_bytes =
            RANGE_RECORD_OVERHEAD * (1 + release_records) + range_count * log_operation::CLUSTER_RANGE_BYTES;
        for i in 0..patches.len() {
            let p = &patches[i];
            let shared = (0..i).find(|&j| {
                let q = &patches[j];
                q.stream_reference == p.stream_reference
                    && q.attribute_kind == p.attribute_kind
                    && q.name == p.name
                    && q.mft == p.mft
            });
            open_of[i] = match shared {
                Some(j) => open_of[j],
                None => {
                    opens += 1;
                    packed_bytes += (120 + p.name.len() + 7) & !7;
                    (opens - 1) as u8
                }
            };
            packed_bytes += (update_header(p, u64::from(self.boot.cluster_bytes))
                + p.after.len()
                + if p.fresh { 0 } else { p.before.len() }
                + 7)
                & !7;
        }
        if self.open_attribute_count + opens > open_attribute_layout::MAX_ENTRIES {
            self.checkpoint_now(io, scratch, patches)?;
        }
        // A single page's USA protects the whole metadata transaction. New
        // user data needs a preceding barrier even when the log fits one page.
        let packed = packed_bytes <= 4032;
        let pages = if packed {
            1
        } else {
            opens
                + patches
                    .iter()
                    .map(|p| {
                        (update_header(p, u64::from(self.boot.cluster_bytes))
                            + p.after.len()
                            + if p.fresh { 0 } else { p.before.len() })
                        .div_ceil(4032)
                    })
                    .sum::<usize>()
                + release_records
                + 1
        };
        // A crash before commit leaves a loser transaction. Recovery must
        // append every compensation record before publishing its checkpoint;
        // reserving only that checkpoint can strand a nearly full journal.
        let rollback_pages: usize = patches
            .iter()
            .filter(|p| !p.fresh)
            .map(|p| {
                (update_header(p, u64::from(self.boot.cluster_bytes))
                    + lfs_layout::HEADER_BYTES
                    + p.before.len()
                    + p.after.len())
                .div_ceil(4032)
            })
            .sum();
        let reserved_pages = pages + rollback_pages + 1;
        let mut reservation = None;
        for attempt in 0..2 {
            let (_, rest) = scratch.split_at_mut(4096);
            let restart = &mut rest[..4096];
            self.log.read(io, 0, restart)?;
            let mut header = RestartPage::parse(restart, 512)?;
            if header.current_lsn != self.checkpoint_lsn {
                return Err(Error::InvalidLog);
            }
            header.current_lsn = self.current_lsn;
            match PageReservation::new(header, reserved_pages) {
                Ok(slots) => {
                    reservation = Some(slots);
                    break;
                }
                Err(Error::NoSpace) if attempt == 0 => self.checkpoint_now(io, scratch, patches)?,
                Err(e) => return Err(e),
            }
        }
        let (_, rest) = scratch.split_at_mut(4096);
        let (_restart, rest) = rest.split_at_mut(4096);
        let (page, rest) = rest.split_at_mut(4096);
        let (payload, rest) = rest.split_at_mut(16384);
        let (encoding, verify) = rest.split_at_mut(16384);
        let reservation = reservation.ok_or(Error::NoSpace)?;
        let slots = |i: usize| reservation.slot(i);
        if !verified {
            for (i, p) in patches.iter().enumerate() {
                self.check_shape(p)?;
                if patches[..i]
                    .iter()
                    .any(|q| patches_overlap(p, q, u64::from(self.boot.cluster_bytes)).unwrap_or(true))
                {
                    return Err(Error::InvalidRecord);
                }
                Self::check_preimage(io, p, self.boot.index_vcn_bytes(), u64::from(self.boot.cluster_bytes), verify)?;
            }
        }
        // A drain often reuses many adjacent journal pages. Fetch their old
        // images together before encoding any replacement page, so validating
        // each old USA/LSN below does not serialize one device read per page.
        if !packed {
            let mut index = 0;
            while index < pages {
                let first = slots(index)?;
                let mut count = 1;
                while count < verify.len() / 4096
                    && index + count < pages
                    && slots(index + count)?.offset == first.offset + count as u64 * 4096
                {
                    count += 1;
                }
                if count > 1 {
                    // Adjacent in the journal; its pieces may part them on the device.
                    for (page, bytes) in verify[..count * 4096].chunks_exact_mut(4096).enumerate() {
                        self.log.read(io, first.offset + page as u64 * 4096, bytes)?;
                    }
                }
                index += count;
            }
        }
        // A later OPEN must not replace an earlier stream's redo identity.
        // Reuse starts only after checkpoint has made all older targets durable.
        let open_base = self.open_attribute_count;
        self.open_attribute_count += opens;
        self.failed = true;
        let result = (|| {
            // A packed commit has no barrier of its own; an earlier commit
            // left unflushed must be durable before this one can be.
            if packed && (self.exposure_dirty || self.log_unflushed) {
                io.flush()?;
                self.log_unflushed = false;
            }
            if packed && spill {
                self.write_committed_home(io, patches)?;
            }
            // Page offsets cannot repeat before checkpoint; therefore these
            // standard transaction-table IDs are unique within live history.
            let cluster = u64::from(self.boot.cluster_bytes);
            let transaction_id = 24 + 40 * (slots(0)?.offset / 4096) as u32;
            let mut index = 0;
            let mut used = 0;
            let mut previous = 0;
            let commit_ordinal = opens + patches.len();
            let last_ordinal = commit_ordinal + release_records;
            let mut range_cursor = 0;
            for ordinal in 0..=last_ordinal {
                let commit = ordinal == commit_ordinal;
                let slot = if packed {
                    let mut s = slots(0)?;
                    s.lsn += used as u64 / 8;
                    s
                } else {
                    slots(index)?
                };
                let len = if ordinal < opens {
                    let i = open_of[..patches.len()].iter().position(|&n| n as usize == ordinal).unwrap();
                    let p = &patches[i];
                    let mut entry = [0u8; open_attribute_layout::ENTRY_BYTES];
                    entry[..4].fill(0xff);
                    entry[4..8].copy_from_slice(&(if p.attribute_kind == 0xa0 { 4096u32 } else { 0 }).to_le_bytes());
                    entry[8..12].copy_from_slice(&p.attribute_kind.to_le_bytes());
                    entry[16..24].copy_from_slice(&p.stream_reference.to_le_bytes());
                    entry[24..32].copy_from_slice(&slot.lsn.to_le_bytes());
                    encode_ntfs_operation(
                        &NtfsOperationInput {
                            redo_code: 0x1c,
                            undo_code: 0,
                            target_attribute: (open_attribute_layout::TABLE_HEADER_BYTES
                                + (open_base + ordinal) * open_attribute_layout::ENTRY_BYTES)
                                as u16,
                            target_vcn: 0,
                            lcns: &[],
                            redo: &entry,
                            undo: p.name,
                        },
                        payload,
                    )?
                } else if ordinal < opens + patches.len() {
                    let i = ordinal - opens;
                    let p = &mut patches[i];
                    if p.mft || p.attribute_kind == 0xa0 {
                        p.after[8..16].copy_from_slice(&slot.lsn.to_le_bytes());
                    }
                    let code = if p.mft { 2 } else { 8 };
                    // Log every actual cluster, including nonadjacent pieces.
                    let first_lcn = p.physical / cluster;
                    let spanned =
                        ((p.physical % cluster + p.after.len() as u64).div_ceil(cluster) as usize).min(MAX_SPANNED);
                    let lcns: [u64; MAX_SPANNED] = core::array::from_fn(|index| {
                        if p.physical_clusters.is_empty() || index >= spanned {
                            first_lcn + index as u64
                        } else {
                            u64::from_le_bytes(
                                p.physical_clusters
                                    [index * super::write_plan::LCN_BYTES..(index + 1) * super::write_plan::LCN_BYTES]
                                    .try_into()
                                    .unwrap(),
                            )
                        }
                    });
                    let n = encode_ntfs_operation(
                        &NtfsOperationInput {
                            redo_code: code,
                            undo_code: if p.fresh { 0 } else { code },
                            target_attribute: (open_attribute_layout::TABLE_HEADER_BYTES
                                + (open_base + usize::from(open_of[i])) * open_attribute_layout::ENTRY_BYTES)
                                as u16,
                            target_vcn: p.logical / cluster,
                            lcns: &lcns[..spanned],
                            redo: p.after,
                            undo: if p.fresh { &[] } else { p.before },
                        },
                        payload,
                    )?;
                    payload[20..22].copy_from_slice(&((p.logical % cluster / 512) as u16).to_le_bytes());
                    n
                } else if !commit {
                    let mut bytes = 0;
                    for (start, count) in freed_ranges(patches).skip(range_cursor).take(RANGES_PER_RECORD) {
                        encoding[bytes..bytes + log_operation::CLUSTER_RANGE_COUNT_OFFSET]
                            .copy_from_slice(&start.to_le_bytes());
                        encoding[bytes + log_operation::CLUSTER_RANGE_COUNT_OFFSET
                            ..bytes + log_operation::CLUSTER_RANGE_BYTES]
                            .copy_from_slice(&count.to_le_bytes());
                        bytes += log_operation::CLUSTER_RANGE_BYTES;
                        range_cursor += 1;
                    }
                    encode_ntfs_operation(
                        &NtfsOperationInput {
                            redo_code: log_operation::DELETE_DIRTY_CLUSTERS,
                            undo_code: log_operation::NOOP,
                            target_attribute: 0,
                            target_vcn: 0,
                            lcns: &[],
                            redo: &encoding[..bytes],
                            undo: &[],
                        },
                        payload,
                    )?
                } else {
                    if !packed {
                        io.flush()?; // updates AND newly exposed user data
                        self.log_unflushed = false;
                        if spill {
                            self.write_committed_home(io, patches)?;
                        }
                    }
                    encode_ntfs_operation(
                        &NtfsOperationInput {
                            redo_code: 0x1a,
                            undo_code: 0,
                            target_attribute: 0,
                            target_vcn: 0,
                            lcns: &[],
                            redo: &[],
                            undo: &[],
                        },
                        payload,
                    )?
                };
                let op = NtfsLogOperation::parse(&payload[..len])?;
                let fragments = (48 + len).div_ceil(4032);
                let n = encode_lfs_record(
                    &LfsRecordInput {
                        this_lsn: slot.lsn,
                        previous_lsn: previous,
                        undo_next_lsn: previous,
                        client_sequence: 0,
                        client_index: 0,
                        record_type: 1,
                        transaction_id,
                        flags: u16::from(fragments > 1)
                            | u16::from(op.redo.is_empty()) * 2
                            | u16::from(op.undo.is_empty()) * 4,
                        payload: &payload[..len],
                    },
                    encoding,
                )?;
                if packed {
                    let padded = (n + 7) & !7;
                    verify[used..used + padded].fill(0);
                    verify[used..used + n].copy_from_slice(&encoding[..n]);
                    used += padded;
                    if ordinal == last_ordinal {
                        record_page(io, &self.log, slots(0)?, &verify[..used], 0, page)?;
                        self.log.write(io, slots(0)?.offset, page)?;
                    }
                } else {
                    for fragment in 0..fragments {
                        record_page(io, &self.log, slots(index + fragment)?, &encoding[..n], fragment, page)?;
                        self.log.write(io, slots(index + fragment)?.offset, page)?;
                    }
                    index += fragments;
                }
                // Post-commit invalidation must not survive a missing commit.
                // Packed records share one USA-protected page; otherwise order
                // the commit durably before publishing any retirement records.
                if commit && release_records != 0 && !packed {
                    io.flush()?;
                    self.log_unflushed = false;
                }
                previous = slot.lsn;
            }
            // A durable commit before any target enters writeback. Retained
            // targets wait in memory, so make_room may leave the flush to
            // settle_log or the next commit's barrier.
            if durable || !cache_targets {
                io.flush()?;
                self.log_unflushed = false;
            } else {
                self.log_unflushed = true;
            }
            self.current_lsn = previous;
            self.data_dirty = false;
            self.exposure_dirty = false;
            // A retired cached image must never be written over a later owner.
            let mut i = 0;
            while i < self.committed.count() {
                let e = self.committed.entries()[i];
                if freed_target(patches, e.physical, self.committed.mapping(i), e.len, cluster)? {
                    release_target(io, e.physical, self.committed.mapping(i), cluster, e.len)?;
                    self.committed.remove(i)?;
                } else {
                    i += 1;
                }
            }
            for i in 0..patches.len() {
                let p = &patches[i];
                if freed_target(patches, p.physical, p.physical_clusters, p.after.len(), cluster)? {
                    release_target(io, p.physical, p.physical_clusters, cluster, p.after.len())?;
                    continue;
                }
                let p = &mut patches[i];
                if p.mft {
                    protect_mft_record(p.after, 512)?;
                } else if p.attribute_kind == 0xa0 {
                    protect_index(p.after)?;
                }
                if cache_targets {
                    match self.committed.classify(p, u64::from(self.boot.cluster_bytes)) {
                        Fit::Merge(i) => self.committed.replace_after(i, p.after),
                        Fit::New => self.committed.push(p, p.after)?,
                        Fit::Conflict => return Err(Error::InvalidRecord),
                    }
                    hold_target(io, p.physical, p.physical_clusters, cluster, p.after, false)?;
                    if p.mft && p.logical < self.boot.mirrored_bytes() {
                        io.hold_at(
                            self.boot.mft_mirror_lcn * u64::from(self.boot.cluster_bytes) + p.logical,
                            p.after,
                            false,
                        )?;
                    }
                } else {
                    write_target(io, p.physical, p.physical_clusters, cluster, p.after)?;
                    release_target(io, p.physical, p.physical_clusters, cluster, p.after.len())?;
                    if p.mft && p.logical < self.boot.mirrored_bytes() {
                        let mirror = self.boot.mft_mirror_lcn * u64::from(self.boot.cluster_bytes) + p.logical;
                        io.write_at(mirror, p.after)?;
                        io.release_at(mirror, p.after.len());
                    }
                }
            }
            Ok(())
        })();
        if result.is_ok() {
            self.failed = false;
        }
        result
    }
}

fn protect_index(b: &mut [u8]) -> Result<()> {
    if b.len() != 4096 || b.get(..4) != Some(b"INDX") || u16_at(b, 6)? != 9 {
        return Err(Error::InvalidIndex);
    }
    let usa = u16_at(b, 4)? as usize;
    if usa < 40 || usa + 18 > 64 {
        return Err(Error::InvalidFixup);
    }
    super::mft::protect_fixups(b)
}

#[cfg(test)]
#[path = "../tests/writer/metadata_tx.rs"]
mod tests;
