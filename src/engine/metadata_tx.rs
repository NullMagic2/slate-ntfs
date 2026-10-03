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
use super::journal::{reserve_pages_into, stored_slot};
use super::logfile::*;
use super::mft::MftRecord;
use super::replay::protect_mft_record;
use super::resident_writer::{record_page, write_restarts, WriteIo, Writer};
use super::volume::ReadAt;
use super::{Error, Result};

pub const MAX_PATCHES: usize = 32;
/// Minimum scratch for commit_metadata.
pub const COMMIT_SCRATCH_BYTES: usize = 4096 + 45056;
pub struct MetadataPatch<'a> {
    /// The target's previous contents are not a live structure (a newly
    /// allocated index block). Its preimage is compared byte-for-byte but not
    /// parsed, and the logged undo action is Noop: rollback leaves free space.
    pub fresh: bool,
    pub physical: u64,
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
        if self.batch.attached() && self.defer(io, patches, scratch)? {
            return Ok(());
        }
        self.commit_barrier(io, patches, scratch)
    }

    /// Journal patches immediately, after everything pending is durable.
    pub(super) fn commit_barrier<I: WriteIo>(
        &mut self,
        io: &mut I,
        patches: &mut [MetadataPatch<'_>],
        scratch: &mut [u8],
    ) -> Result<()> {
        self.drain(io, scratch)?;
        self.commit_now(io, patches, scratch, false)
    }

    /// User data still waiting for a durability barrier.
    pub fn data_pending(&self) -> bool {
        self.data_dirty
    }

    /// Number of metadata structures waiting for the next drain.
    pub fn pending(&self) -> usize {
        self.batch.pending()
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
            || (patch.mft && len != 1024)
            || (!patch.mft && len != if patch.attribute_kind == 0xa0 { 4096 } else { 512 })
            || patch.name.len() > 510
            || patch.name.len() % 2 != 0
            || patch.physical % 512 != 0
            || patch.logical % 512 != 0
            || patch.physical % 4096 + len as u64 > 4096
        {
            return Err(Error::Unsupported);
        }
        if patch.physical < self.log + self.log_bytes && self.log < patch.physical + len as u64 {
            return Err(Error::InvalidRunlist);
        }
        Ok(())
    }

    /// Current on-disk (or cached) image must be a valid structure equal to
    /// the caller's preimage. verify is scratch of at least the patch size.
    fn check_preimage<I: ReadAt>(io: &mut I, patch: &MetadataPatch<'_>, verify: &mut [u8]) -> Result<()> {
        let len = patch.before.len();
        let verify = &mut verify[..len];
        io.read_exact_at(patch.physical, verify)?;
        if patch.fresh {
            if patch.mft {
                return Err(Error::Unsupported);
            }
        } else if patch.mft {
            MftRecord::parse(verify, 512)?;
        } else if patch.attribute_kind == 0xa0 {
            super::index::IndexBlock::parse(verify, 512, patch.logical / 4096)?;
        }
        if !same_image(verify, patch.before, !patch.fresh && (patch.mft || patch.attribute_kind == 0xa0)) {
            return Err(Error::InvalidRecord);
        }
        Ok(())
    }

    /// Whether patches can join the pending group: None if they conflict
    /// with it, Some(false) if they merely do not fit right now.
    fn admit(&self, patches: &[MetadataPatch<'_>]) -> Option<bool> {
        let (mut new, mut bytes, mut pages) = (0, 0, self.batch.log_pages());
        for p in patches {
            match self.batch.classify(p) {
                Fit::Conflict => return None,
                Fit::Merge(_) => {}
                Fit::New => {
                    new += 1;
                    bytes += 2 * p.before.len() + p.name.len();
                    pages += 1 + (88 + 2 * p.before.len()).div_ceil(4032);
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
            let len = patch.before.len() as u64;
            if patches[..i]
                .iter()
                .any(|p| patch.physical < p.physical + p.before.len() as u64 && p.physical < patch.physical + len)
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
                self.drain(io, scratch)?;
                if self.admit(patches) != Some(true) {
                    return Ok(false);
                }
            }
        }
        let verify = &mut scratch[..4096];
        for patch in patches.iter() {
            match self.batch.classify(patch) {
                Fit::Merge(e) => {
                    let structured = patch.mft || patch.attribute_kind == 0xa0;
                    if !same_image(patch.before, self.batch.after(e), structured) {
                        return Err(Error::InvalidRecord);
                    }
                }
                _ => Self::check_preimage(io, patch, verify)?,
            }
        }
        // Everything is valid; failures from here on poison the session.
        let mirror = self.boot.mft_mirror_lcn * 4096;
        let result = (|| {
            for patch in patches.iter_mut() {
                let structured = patch.mft || patch.attribute_kind == 0xa0;
                let first = match self.batch.classify(patch) {
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
                io.hold_at(patch.physical, patch.after, first)?;
                if patch.mft && patch.logical < 4096 {
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
    /// checkpoint. Unknown data must precede commit; durably zeroed space
    /// can share the packed commit's flush without exposing previous contents.
    pub fn drain<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if self.batch.pending() == 0 {
            if self.data_dirty {
                if let Err(e) = io.flush() {
                    self.failed = true;
                    return Err(e);
                }
                self.data_dirty = false;
                self.exposure_dirty = false;
                for w in &mut self.windows {
                    if w.0 != 0 {
                        w.3 = true;
                    }
                }
            }
            return Ok(());
        }
        if scratch.len() < COMMIT_SCRATCH_BYTES + patch_scratch_bytes(self.batch.pending()) {
            return Err(Error::Unsupported);
        }
        let (patches, work) = patch_slots(scratch, self.batch.pending())?;
        let Some((arena, entries, count, used)) = self.batch.take() else {
            return Err(Error::Io);
        };
        // commit_now owns exposure and log-ordering barriers.
        let result = {
            batch_patches(&mut arena[..used], &entries[..count], patches);
            self.commit_now(io, patches, work, true)
        };
        self.batch.restore(arena);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Drain and publish an empty checkpoint at sync_fs/unmount boundaries.
    pub fn checkpoint<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        self.drain(io, scratch)?;
        self.checkpoint_now(io, scratch)
    }

    fn checkpoint_now<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
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
            io.read_exact_at(self.log, restart)?;
            page.copy_from_slice(restart);
            let mut header = RestartPage::parse(page, 512)?;
            if header.current_lsn != self.checkpoint_lsn {
                return Err(Error::InvalidLog);
            }
            header.current_lsn = self.current_lsn;
            super::journal::reserve_pages_into(header, 1, page)?;
            let slot = stored_slot(page, 0)?;
            // Flush the last COMMITTED images, not newer pending overlays.
            // The mount-owned copies stay readable even if buffer heads evict.
            let mirror = self.boot.mft_mirror_lcn * 4096;
            for (i, e) in self.committed.entries().iter().enumerate() {
                io.write_at(e.physical, self.committed.after(i))?;
                if e.mft && e.logical < 4096 {
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
            record_page(io, self.log, slot, &encoding[..n], 0, page)?;
            io.write_at(self.log + slot.offset, page)?;
            io.flush()?;
            advance_restart_checkpoint(restart, 512, slot.lsn)?;
            write_restarts(io, self.log, restart)?;
            self.current_lsn = slot.lsn;
            self.checkpoint_lsn = slot.lsn;
            self.data_dirty = false;
            self.exposure_dirty = false;
            for w in &mut self.windows {
                if w.0 != 0 {
                    w.3 = true;
                }
            }
            for e in self.committed.entries() {
                if !self.batch.entries().iter().any(|p| p.physical == e.physical && p.len == e.len) {
                    io.release_at(e.physical, e.len);
                    if e.mft && e.logical < 4096 {
                        io.release_at(mirror + e.logical, e.len);
                    }
                }
            }
            if let Some((arena, _, _, _)) = self.committed.take() {
                self.committed.restore(arena);
            }
            Ok(())
        })();
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    /// Spill retained committed target images to the device without moving the
    /// journal checkpoint. Their transactions are already durable in the log,
    /// so no barrier is needed here: a later real checkpoint flushes these
    /// targets before advancing the restart area. Pending batch overlays keep
    /// their holds until that batch itself is committed.
    fn spill_committed<I: WriteIo>(&mut self, io: &mut I) -> Result<()> {
        if !self.committed.attached() || self.committed.count() == 0 {
            return Ok(());
        }
        let mirror = self.boot.mft_mirror_lcn * 4096;
        self.failed = true;
        let result = (|| {
            for (i, e) in self.committed.entries().iter().enumerate() {
                io.write_at(e.physical, self.committed.after(i))?;
                if e.mft && e.logical < 4096 {
                    io.write_at(mirror + e.logical, self.committed.after(i))?;
                }
            }
            for e in self.committed.entries() {
                if !self.batch.entries().iter().any(|p| p.physical == e.physical && p.len == e.len) {
                    io.release_at(e.physical, e.len);
                    if e.mft && e.logical < 4096 {
                        io.release_at(mirror + e.logical, e.len);
                    }
                }
            }
            let Some((arena, _, _, _)) = self.committed.take() else {
                return Err(Error::Io);
            };
            self.committed.restore(arena);
            Ok(())
        })();
        if result.is_ok() {
            self.failed = false;
        }
        result
    }

    fn commit_now<I: WriteIo>(
        &mut self,
        io: &mut I,
        patches: &mut [MetadataPatch<'_>],
        scratch: &mut [u8],
        verified: bool,
    ) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if patches.is_empty() || patches.len() > MAX_PATCHES || scratch.len() < COMMIT_SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        // Bounded retention: spill already-committed target images before
        // admitting a set that would fill the arena or reuse an address with a
        // different shape. Do not move the checkpoint just to free RAM.
        let mut count = self.committed.count();
        let mut bytes = self.committed.used();
        let mut conflict = false;
        for p in patches.iter() {
            match self.committed.classify(p) {
                Fit::Merge(_) => {}
                Fit::Conflict => conflict = true,
                Fit::New => {
                    count += 1;
                    bytes += 2 * p.before.len() + p.name.len();
                }
            }
        }
        if self.committed.attached() && (conflict || count > MAX_PATCHES || bytes > self.committed.capacity()) {
            self.spill_committed(io)?;
        }
        let cache_targets = self.committed.attached()
            && patches.iter().map(|p| 2 * p.before.len() + p.name.len()).sum::<usize>() <= self.committed.capacity();
        let mut open_of = [0u8; MAX_PATCHES];
        let mut opens = 0;
        let mut packed_bytes = 80; // commit
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
            packed_bytes += (88 + p.after.len() + if p.fresh { 0 } else { p.before.len() } + 7) & !7;
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
                    .map(|p| (88 + p.after.len() + if p.fresh { 0 } else { p.before.len() }).div_ceil(4032))
                    .sum::<usize>()
                + 1
        };
        if pages + 1 > MAX_PATCHES * 4 + 2 {
            return Err(Error::Unsupported);
        }
        // A crash before commit leaves a loser transaction. Recovery must
        // append every compensation record before publishing its checkpoint;
        // reserving only that checkpoint can strand a nearly full journal.
        let rollback_pages: usize =
            patches.iter().filter(|p| !p.fresh).map(|p| (136 + p.before.len() + p.after.len()).div_ceil(4032)).sum();
        let reserved_pages = pages + rollback_pages + 1;
        if reserved_pages * 16 > 4096 {
            return Err(Error::Unsupported);
        }
        for attempt in 0..2 {
            let (slots, rest) = scratch.split_at_mut(4096);
            let restart = &mut rest[..4096];
            io.read_exact_at(self.log, restart)?;
            let mut header = RestartPage::parse(restart, 512)?;
            if header.current_lsn != self.checkpoint_lsn {
                return Err(Error::InvalidLog);
            }
            header.current_lsn = self.current_lsn;
            match reserve_pages_into(header, reserved_pages, slots) {
                Ok(()) => break,
                Err(Error::NoSpace) if attempt == 0 => self.checkpoint_now(io, scratch)?,
                Err(e) => return Err(e),
            }
        }
        let (slot_bytes, rest) = scratch.split_at_mut(4096);
        let (_restart, rest) = rest.split_at_mut(4096);
        let (page, rest) = rest.split_at_mut(4096);
        let (payload, rest) = rest.split_at_mut(16384);
        let (encoding, verify) = rest.split_at_mut(16384);
        let slots = |i: usize| stored_slot(slot_bytes, i);
        if !verified {
            for (i, p) in patches.iter().enumerate() {
                self.check_shape(p)?;
                if patches[..i].iter().any(|q| {
                    p.physical < q.physical + q.before.len() as u64 && q.physical < p.physical + p.before.len() as u64
                }) {
                    return Err(Error::InvalidRecord);
                }
                Self::check_preimage(io, p, verify)?;
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
                    io.read_exact_at(self.log + first.offset, &mut verify[..count * 4096])?;
                }
                index += count;
            }
        }
        self.failed = true;
        let result = (|| {
            if packed && self.exposure_dirty {
                io.flush()?;
            }
            // Page offsets cannot repeat before checkpoint; therefore these
            // standard transaction-table IDs are unique within live history.
            let transaction_id = 24 + 40 * (slots(0)?.offset / 4096) as u32;
            let mut index = 0;
            let mut used = 0;
            let mut previous = 0;
            for ordinal in 0..opens + patches.len() + 1 {
                let commit = ordinal == opens + patches.len();
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
                    let mut entry = [0u8; 40];
                    entry[..4].fill(0xff);
                    entry[4..8].copy_from_slice(&(if p.attribute_kind == 0xa0 { 4096u32 } else { 0 }).to_le_bytes());
                    entry[8..12].copy_from_slice(&p.attribute_kind.to_le_bytes());
                    entry[16..24].copy_from_slice(&p.stream_reference.to_le_bytes());
                    entry[24..32].copy_from_slice(&slot.lsn.to_le_bytes());
                    encode_ntfs_operation(
                        &NtfsOperationInput {
                            redo_code: 0x1c,
                            undo_code: 0,
                            target_attribute: (24 + ordinal * 40) as u16,
                            target_vcn: 0,
                            lcns: &[],
                            redo: &entry,
                            undo: p.name,
                        },
                        payload,
                    )?
                } else if !commit {
                    let i = ordinal - opens;
                    let p = &mut patches[i];
                    if p.mft || p.attribute_kind == 0xa0 {
                        p.after[8..16].copy_from_slice(&slot.lsn.to_le_bytes());
                    }
                    let code = if p.mft { 2 } else { 8 };
                    let n = encode_ntfs_operation(
                        &NtfsOperationInput {
                            redo_code: code,
                            undo_code: if p.fresh { 0 } else { code },
                            target_attribute: (24 + usize::from(open_of[i]) * 40) as u16,
                            target_vcn: p.logical / 4096,
                            lcns: &[p.physical / 4096],
                            redo: p.after,
                            undo: if p.fresh { &[] } else { p.before },
                        },
                        payload,
                    )?;
                    payload[20..22].copy_from_slice(&((p.logical % 4096 / 512) as u16).to_le_bytes());
                    n
                } else {
                    if !packed {
                        io.flush()?;
                    } // updates AND newly exposed user data
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
                    if commit {
                        record_page(io, self.log, slots(0)?, &verify[..used], 0, page)?;
                        io.write_at(self.log + slots(0)?.offset, page)?;
                    }
                } else {
                    for fragment in 0..fragments {
                        record_page(io, self.log, slots(index + fragment)?, &encoding[..n], fragment, page)?;
                        io.write_at(self.log + slots(index + fragment)?.offset, page)?;
                    }
                    index += fragments;
                }
                previous = slot.lsn;
            }
            io.flush()?; // durable commit before any target enters writeback
            self.current_lsn = previous;
            self.data_dirty = false;
            self.exposure_dirty = false;
            for w in &mut self.windows {
                if w.0 != 0 {
                    w.3 = true;
                }
            }
            for p in patches.iter_mut() {
                if p.mft {
                    protect_mft_record(p.after, 512)?;
                } else if p.attribute_kind == 0xa0 {
                    protect_index(p.after)?;
                }
                if cache_targets {
                    match self.committed.classify(p) {
                        Fit::Merge(i) => self.committed.replace_after(i, p.after),
                        Fit::New => self.committed.push(p, p.after)?,
                        Fit::Conflict => return Err(Error::InvalidRecord),
                    }
                    io.hold_at(p.physical, p.after, false)?;
                    if p.mft && p.logical < 4096 {
                        io.hold_at(self.boot.mft_mirror_lcn * 4096 + p.logical, p.after, false)?;
                    }
                } else {
                    io.write_at(p.physical, p.after)?;
                    io.release_at(p.physical, p.after.len());
                    if p.mft && p.logical < 4096 {
                        let mirror = self.boot.mft_mirror_lcn * 4096 + p.logical;
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
