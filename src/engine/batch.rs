//! Module: ntfs_rs::batch
//! Purpose: Bound metadata changes that are visible before journal publication.
//! Created: 2026-10-01
//! Architecture: Adapters supply the arena and serialize access. One drain journals all
//! pending images together, avoiding a device flush for each operation.

use super::bytes::u16_at;
use super::metadata_tx::{MetadataPatch, MAX_PATCHES};
use super::{Error, Result};

/// Arena the adapter attaches with Writer::attach_batch.
// Pending and committed images each receive half of this persistent arena.
pub const BATCH_BYTES: usize = 1 << 19;
/// Freed cluster ranges that stay unavailable until their release is durable.
pub const QUARANTINE: usize = 32;

/// Small sorted-free set of (start, count) cluster ranges; neighbours merge.
#[derive(Clone, Copy)]
pub struct Ranges<const N: usize> {
    items: [(u64, u64); N],
    len: usize,
}

impl<const N: usize> Ranges<N> {
    pub const fn new() -> Self {
        Self { items: [(0, 0); N], len: 0 }
    }
    pub fn as_slice(&self) -> &[(u64, u64)] {
        &self.items[..self.len]
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
    /// False when a disjoint range does not fit.
    pub fn add(&mut self, start: u64, count: u64) -> bool {
        let end = start + count;
        if let Some(r) = self.items[..self.len].iter_mut().find(|r| start <= r.0 + r.1 && r.0 <= end) {
            let (s, e) = (r.0.min(start), (r.0 + r.1).max(end));
            *r = (s, e - s);
        } else if self.len < N {
            self.items[self.len] = (start, count);
            self.len += 1;
        } else {
            return false;
        }
        true
    }
}

/// One target structure: before (first touch), after (latest) and the
/// stream name are stored back to back in the arena, in first-touch order.
#[derive(Clone, Copy)]
pub(super) struct Entry {
    pub fresh: bool,
    pub mft: bool,
    pub kind: u32,
    pub physical: u64,
    pub logical: u64,
    pub stream_reference: u64,
    pub len: usize,
    pub name_len: usize,
    pub off: usize,
}

impl Entry {
    const EMPTY: Entry = Entry {
        fresh: false,
        mft: false,
        kind: 0,
        physical: 0,
        logical: 0,
        stream_reference: 0,
        len: 0,
        name_len: 0,
        off: 0,
    };
    fn bytes(&self) -> usize {
        2 * self.len + self.name_len
    }
    /// Log pages this entry can occupy: one open record plus its update.
    pub fn log_pages(&self) -> usize {
        1 + (88 + 2 * self.len).div_ceil(4032)
    }
}

/// How a patch relates to what is already pending.
pub(super) enum Fit {
    New,
    Merge(usize),
    /// Same address with another shape, or a partial overlap.
    Conflict,
}

pub(super) struct Batch {
    arena: Option<&'static mut [u8]>,
    entries: [Entry; MAX_PATCHES],
    count: usize,
    used: usize,
    freed: Ranges<QUARANTINE>,
}

/// Image comparison that ignores the log sequence number and the fixup array,
/// which a drain or a deferred write legitimately changes. Sector tails remain
/// compared after the caller has decoded fixups.
pub(super) fn same_image(a: &[u8], b: &[u8], structured: bool) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if !structured {
        return a == b;
    }
    let Ok(usa) = u16_at(a, 4).map(usize::from) else {
        return false;
    };
    let Ok(count) = u16_at(a, 6).map(usize::from) else {
        return false;
    };
    let Some(end) = count.checked_mul(2).and_then(|n| usa.checked_add(n)) else {
        return false;
    };
    usa >= 16 && end <= a.len() && a[..8] == b[..8] && a[16..usa] == b[16..usa] && a[end..] == b[end..]
}

impl Batch {
    pub const fn new() -> Self {
        Self { arena: None, entries: [Entry::EMPTY; MAX_PATCHES], count: 0, used: 0, freed: Ranges::new() }
    }
    pub fn attach(&mut self, arena: &'static mut [u8]) -> Result<()> {
        if self.count != 0 || arena.len() < 2 * 4096 + 512 {
            return Err(Error::Unsupported);
        }
        self.arena = Some(arena);
        Ok(())
    }
    pub fn attached(&self) -> bool {
        self.arena.is_some()
    }
    pub fn pending(&self) -> usize {
        self.count
    }
    pub fn capacity(&self) -> usize {
        self.arena.as_ref().map_or(0, |a| a.len())
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn used(&self) -> usize {
        self.used
    }
    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.count]
    }
    /// Upper bound of journal pages a drain of this batch would use.
    pub fn log_pages(&self) -> usize {
        2 + self.entries().iter().map(Entry::log_pages).sum::<usize>()
    }

    pub fn classify(&self, patch: &MetadataPatch<'_>) -> Fit {
        let len = patch.before.len();
        let mut fit = Fit::New;
        for (i, e) in self.entries().iter().enumerate() {
            if e.physical == patch.physical {
                let same = e.len == len
                    && e.mft == patch.mft
                    && e.kind == patch.attribute_kind
                    && e.logical == patch.logical
                    && e.stream_reference == patch.stream_reference
                    && self.name(i) == patch.name;
                if !same {
                    return Fit::Conflict;
                }
                fit = Fit::Merge(i);
            } else if patch.physical < e.physical + e.len as u64 && e.physical < patch.physical + len as u64 {
                return Fit::Conflict;
            }
        }
        fit
    }

    fn arena(&self) -> &[u8] {
        self.arena.as_deref().unwrap_or(&[])
    }
    pub fn after(&self, i: usize) -> &[u8] {
        let e = &self.entries[i];
        &self.arena()[e.off + e.len..e.off + 2 * e.len]
    }
    fn name(&self, i: usize) -> &[u8] {
        let e = &self.entries[i];
        &self.arena()[e.off + 2 * e.len..e.off + e.bytes()]
    }

    pub fn fits(&self, patch: &MetadataPatch<'_>) -> bool {
        self.used + 2 * patch.before.len() + patch.name.len() <= self.capacity()
    }

    /// Append a first-touch entry. before is the exact current image.
    pub fn push(&mut self, patch: &MetadataPatch<'_>, before: &[u8]) -> Result<()> {
        let len = patch.before.len();
        if self.count == MAX_PATCHES || !self.fits(patch) || before.len() != len {
            return Err(Error::Unsupported);
        }
        let entry = Entry {
            fresh: patch.fresh,
            mft: patch.mft,
            kind: patch.attribute_kind,
            physical: patch.physical,
            logical: patch.logical,
            stream_reference: patch.stream_reference,
            len,
            name_len: patch.name.len(),
            off: self.used,
        };
        let arena = self.arena.as_deref_mut().ok_or(Error::Unsupported)?;
        arena[entry.off..entry.off + len].copy_from_slice(before);
        arena[entry.off + len..entry.off + 2 * len].copy_from_slice(patch.after);
        arena[entry.off + 2 * len..entry.off + entry.bytes()].copy_from_slice(patch.name);
        self.used += entry.bytes();
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Carry the live log sequence number and fixup token of the on-disk
    /// structure into the undo image, so it matches what the log will see.
    pub fn refresh_stamp(&mut self, i: usize, head: &[u8]) -> Result<()> {
        let e = self.entries[i];
        if head.len() < 16 || e.len < 16 {
            return Err(Error::InvalidAttribute);
        }
        let usa = usize::from(u16_at(head, 4)?);
        let arena = self.arena.as_deref_mut().ok_or(Error::Unsupported)?;
        let before = &mut arena[e.off..e.off + e.len];
        if usa < 16 || usa + 2 > before.len() || usa + 2 > head.len() {
            return Err(Error::InvalidAttribute);
        }
        before[8..16].copy_from_slice(&head[8..16]);
        before[usa..usa + 2].copy_from_slice(&head[usa..usa + 2]);
        Ok(())
    }

    pub fn replace_after(&mut self, i: usize, after: &[u8]) {
        let e = self.entries[i];
        if let Some(arena) = self.arena.as_deref_mut() {
            arena[e.off + e.len..e.off + 2 * e.len].copy_from_slice(after);
        }
    }

    /// Detach the arena and entry table for one drain.
    pub fn take(&mut self) -> Option<(&'static mut [u8], [Entry; MAX_PATCHES], usize, usize)> {
        let arena = self.arena.take()?;
        Some((arena, self.entries, self.count, self.used))
    }
    pub fn restore(&mut self, arena: &'static mut [u8]) {
        self.arena = Some(arena);
        self.count = 0;
        self.used = 0;
        self.freed.clear();
    }

    // ----- freed-cluster quarantine ---------------------------------------

    pub fn blocked(&self) -> Ranges<QUARANTINE> {
        self.freed
    }
    /// Add ranges freed by a deferred transaction. False when the table is
    /// full; the caller then drains.
    pub fn quarantine(&mut self, ranges: &[(u64, u64)]) -> bool {
        ranges.iter().all(|&(start, count)| self.freed.add(start, count))
    }
}

/// Rebuild the patch list of a detached batch. Images are borrowed from the
/// arena in first-touch order.
pub(super) fn patches<'a>(arena: &'a mut [u8], entries: &[Entry], output: &mut [MetadataPatch<'a>]) {
    let mut rest = arena;
    for (slot, e) in output.iter_mut().zip(entries) {
        let (chunk, tail) = core::mem::take(&mut rest).split_at_mut(e.bytes());
        rest = tail;
        let (before, chunk) = chunk.split_at_mut(e.len);
        let (after, name) = chunk.split_at_mut(e.len);
        *slot = MetadataPatch {
            fresh: e.fresh,
            physical: e.physical,
            logical: e.logical,
            stream_reference: e.stream_reference,
            mft: e.mft,
            attribute_kind: e.kind,
            name,
            before,
            after,
        };
    }
}
