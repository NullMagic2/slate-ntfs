//! Module: slate_ntfs_tools::recovery_io::models
//! Purpose: Own reusable recovery data, replay analysis and metadata repair planners.
//! Created: 2026-10-02
//! Architecture: RecordStore owns private scratch payloads; ReplayPlan and
//!     RepairPlan own proposed edits; domain planners validate evidence and use
//!     core format types. recovery_io coordinates admission and durable I/O.

use super::*;

// Recovery policies share these units; wire-field offsets belong to core MFT views.
const BITMAP_BITS_PER_BYTE: u64 = u8::BITS as u64;
const BITMAP_WORD_BITS: u64 = u64::BITS as u64;
const BITMAP_WORD_BYTES: u64 = std::mem::size_of::<u64>() as u64;
const BITMAP_CACHE_BYTES: usize = 8 * 1024;
const REPAIR_CHUNK_BYTES: u64 = 64 * 1024;
pub(super) const NTFS_SECTOR_BYTES: usize = 512;
const RESTART_PROBE_BYTES: usize = NTFS_SECTOR_BYTES;
const RESTART_COPY_COUNT: u64 = 2;
const FIXUP_WORD_BYTES: usize = std::mem::size_of::<u16>();
const FIRST_ALLOCATABLE_CLUSTER: u64 = 1;
const SCRATCH_INITIAL_CAPACITY: u64 = 1024;
const SCRATCH_CAPACITY_GROWTH: u64 = 2;
const SCRATCH_LOAD_DENOMINATOR: u64 = 2;
const ENCODED_BOOL_TRUE: u8 = 1;

/// Scratch spool failures surface as I/O errors in the core error domain.
trait CoreIo<T> {
    fn io(self) -> ntfs_rs::Result<T>;
}

impl<T, E> CoreIo<T> for std::result::Result<T, E> {
    fn io(self) -> ntfs_rs::Result<T> {
        self.map_err(|_| ntfs_rs::Error::Io)
    }
}

pub(super) mod storage {
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::FileExt;

    pub(crate) const WORD_BYTES: usize = std::mem::size_of::<u64>();
    const INDEX_ENTRY_WORDS: usize = 2;
    const INDEX_ENTRY_BYTES: usize = WORD_BYTES * INDEX_ENTRY_WORDS;
    const MAPPING_ALIGNMENT: u64 = 64 * 1024;

    // Fixed-word scratch rows share byte framing; each caller retains its own
    // key policy, sparse-row handling and checked index-offset diagnostics.
    pub(crate) fn read_words<const WORDS: usize>(file: &File, offset: u64) -> io::Result<[u64; WORDS]> {
        let mut bytes = [[0; WORD_BYTES]; WORDS];
        file.read_exact_at(bytes.as_flattened_mut(), offset)?;
        Ok(bytes.map(u64::from_le_bytes))
    }

    pub(crate) fn write_words<const WORDS: usize>(file: &File, offset: u64, words: [u64; WORDS]) -> io::Result<()> {
        file.write_all_at(words.map(u64::to_le_bytes).as_flattened(), offset)
    }

    /// Recovery payloads and schedule rows are held in private scratch files. The fixed-width
    /// offset table is also disk backed, so the active history does not require a
    /// Vec of every record payload or an index proportional to the log size.
    pub(crate) struct RecordStore {
        data: File,
        index: File,
        data_len: u64,
        count: usize,
    }

    pub(crate) struct RecordView {
        map: memmap2::Mmap,
        start: usize,
        len: usize,
    }

    impl std::ops::Deref for RecordView {
        type Target = [u8];

        fn deref(&self) -> &[u8] {
            &self.map[self.start..self.start + self.len]
        }
    }

    impl RecordStore {
        /// Byte offset and length of one stored row.
        fn descriptor(&self, number: usize) -> io::Result<(u64, usize)> {
            if number >= self.count {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            let [offset, len] = read_words(&self.index, (number * INDEX_ENTRY_BYTES) as u64)?;
            Ok((offset, len as usize))
        }

        pub(crate) fn new() -> io::Result<Self> {
            let scratch = super::checker::consistency::scratch_file;
            Ok(Self { data: scratch()?, index: scratch()?, data_len: 0, count: 0 })
        }

        pub(crate) fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.data.write_all_at(bytes, self.data_len)?;
            write_words(&self.index, (self.count * INDEX_ENTRY_BYTES) as u64, [self.data_len, bytes.len() as u64])?;
            self.data_len += bytes.len() as u64;
            self.count += 1;
            Ok(())
        }

        pub(crate) fn len(&self) -> usize {
            self.count
        }

        pub(crate) fn is_empty(&self) -> bool {
            self.count == 0
        }

        pub(crate) fn index(&self, number: usize) -> io::Result<usize> {
            let raw: [u8; WORD_BYTES] =
                self.get(number)?.try_into().map_err(|_| io::Error::other("invalid schedule entry"))?;
            Ok(u64::from_le_bytes(raw) as usize)
        }

        pub(crate) fn get(&self, number: usize) -> io::Result<Vec<u8>> {
            let (offset, len) = self.descriptor(number)?;
            let mut result = vec![0; len];
            self.data.read_exact_at(&mut result, offset)?;
            Ok(result)
        }

        /// Map one record from its private spool without allocating a payload-sized
        /// Vec. A fixed 64 KiB boundary keeps mapping offsets aligned.
        pub(crate) fn view(&self, number: usize) -> io::Result<RecordView> {
            let (offset, len) = self.descriptor(number)?;
            if len == 0 {
                return Err(io::Error::other("empty record mapping"));
            }
            let aligned = offset / MAPPING_ALIGNMENT * MAPPING_ALIGNMENT;
            let start = (offset - aligned) as usize;
            // The anonymous scratch file is owned by this store and is never
            // truncated. Callers map immutable rows and must end a view before
            // replacing that row; append operations preserve mapped bytes.

            let map = unsafe { memmap2::MmapOptions::new().offset(aligned).len(start + len).map(&self.data)? };
            Ok(RecordView { map, start, len })
        }

        pub(crate) fn replace(&self, number: usize, bytes: &[u8]) -> io::Result<()> {
            let (offset, len) = self.descriptor(number)?;
            if len != bytes.len() {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            self.data.write_all_at(bytes, offset)
        }
    }

    #[cfg(test)]
    mod tests {
        include!("../tests/recovery/storage_tests.rs");
    }
}

pub(super) mod plan {
    use super::storage::{read_words, write_words, RecordStore, WORD_BYTES};
    use super::CoreIo;
    use super::{checker, reject, Image};
    use checker::consistency::{inventory_lower_bound, inventory_next, DiskInventory, Row, INVENTORY_BYTES};
    use ntfs_rs::volume::ReadAt;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::FileExt;

    /// Encoded PatchSet rows: physical offset, image size, undo and continuation
    /// flags, then the before and after images.
    const PATCH_SIZE_OFFSET: usize = WORD_BYTES;
    const PATCH_UNDO_OFFSET: usize = PATCH_SIZE_OFFSET + WORD_BYTES;
    const PATCH_CONTINUATION_OFFSET: usize = PATCH_UNDO_OFFSET + 1;
    const PATCH_HEADER_BYTES: usize = PATCH_CONTINUATION_OFFSET + 1;
    use super::ENCODED_BOOL_TRUE;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct Patch {
        pub(crate) physical: u64,
        pub(crate) before: Vec<u8>,
        pub(crate) after: Vec<u8>,
        pub(crate) undo: bool,
        // Physical fragments of one logical metadata record share a flush.
        pub(crate) continuation: bool,
    }

    impl Patch {
        /// An ordinary redo patch that owns its own flush.
        pub(crate) fn new(physical: u64, before: Vec<u8>, after: Vec<u8>) -> Self {
            Self { physical, before, after, undo: false, continuation: false }
        }

        fn end(&self) -> u64 {
            self.physical + self.after.len() as u64
        }

        /// Write the after image only while the target still holds the before image.
        pub(crate) fn apply_to(&self, output: &File, changed: &str) -> io::Result<()> {
            let mut observed = vec![0; self.before.len()];
            output.read_exact_at(&mut observed, self.physical)?;
            if observed != self.before {
                return Err(reject(changed));
            }
            output.write_all_at(&self.after, self.physical)
        }

        /// Overlay validated extents; caller iteration order decides later overrides.
        pub(crate) fn copy_after_into(&self, at: u64, out: &mut [u8]) {
            let lo = at.max(self.physical);
            let hi = (at + out.len() as u64).min(self.end());
            if lo < hi {
                out[(lo - at) as usize..(hi - at) as usize]
                    .copy_from_slice(&self.after[(lo - self.physical) as usize..(hi - self.physical) as usize]);
            }
        }
    }

    pub(crate) struct PatchSet {
        rows: RecordStore,
        /// Sorted (physical, number, size) rows built once the plan is complete.
        physical: Option<File>,
    }

    impl PatchSet {
        pub(crate) fn new() -> io::Result<Self> {
            Ok(Self { rows: RecordStore::new()?, physical: None })
        }

        pub(crate) fn len(&self) -> usize {
            self.rows.len()
        }

        pub(crate) fn is_empty(&self) -> bool {
            self.rows.is_empty()
        }

        pub(crate) fn encode(patch: &Patch) -> io::Result<Vec<u8>> {
            if patch.before.len() != patch.after.len() {
                return Err(reject("patch size mismatch"));
            }
            let mut row = Vec::with_capacity(PATCH_HEADER_BYTES + 2 * patch.after.len());
            row.extend_from_slice(&patch.physical.to_le_bytes());
            row.extend_from_slice(&(patch.before.len() as u64).to_le_bytes());
            row.push(u8::from(patch.undo));
            row.push(u8::from(patch.continuation));
            row.extend_from_slice(&patch.before);
            row.extend_from_slice(&patch.after);
            Ok(row)
        }

        pub(crate) fn push(&mut self, patch: Patch) -> io::Result<()> {
            self.rows.push(&Self::encode(&patch)?)
        }

        pub(crate) fn extend(&mut self, patches: impl IntoIterator<Item = Patch>) -> io::Result<()> {
            patches.into_iter().try_for_each(|patch| self.push(patch))
        }

        pub(crate) fn get(&self, number: usize) -> io::Result<Patch> {
            let row = self.rows.get(number)?;
            if row.len() < PATCH_HEADER_BYTES {
                return Err(reject("short replay patch"));
            }
            let size = ntfs_rs::bytes::u64_at(&row, PATCH_SIZE_OFFSET)? as usize;
            if Some(row.len()) != size.checked_mul(2).and_then(|images| images.checked_add(PATCH_HEADER_BYTES))
                || row[PATCH_UNDO_OFFSET] > ENCODED_BOOL_TRUE
                || row[PATCH_CONTINUATION_OFFSET] > ENCODED_BOOL_TRUE
            {
                return Err(reject("invalid replay patch"));
            }
            Ok(Patch {
                physical: ntfs_rs::bytes::u64_at(&row, 0)?,
                before: row[PATCH_HEADER_BYTES..PATCH_HEADER_BYTES + size].to_vec(),
                after: row[PATCH_HEADER_BYTES + size..].to_vec(),
                undo: row[PATCH_UNDO_OFFSET] != 0,
                continuation: row[PATCH_CONTINUATION_OFFSET] != 0,
            })
        }

        pub(crate) fn replace(&self, number: usize, patch: &Patch) -> io::Result<()> {
            self.rows.replace(number, &Self::encode(patch)?)
        }

        pub(crate) fn iter(&self) -> impl Iterator<Item = io::Result<Patch>> + '_ {
            (0..self.len()).map(|number| self.get(number))
        }

        pub(crate) fn matches(&self, other: &Self) -> io::Result<bool> {
            same_patches(self.len(), other.len(), |number| Ok((self.get(number)?, other.get(number)?)))
        }

        pub(crate) fn clear(&mut self) -> io::Result<()> {
            *self = Self::new()?;
            Ok(())
        }

        pub(crate) fn build_index(&mut self) -> io::Result<()> {
            let mut entries = DiskInventory::new();
            for number in 0..self.len() {
                let patch = self.get(number)?;
                entries.push([patch.physical, number as u64, patch.after.len() as u64, 0])?;
            }
            let mut index = entries.finish()?;
            let mut previous_end = 0;
            while let Some([at, _, size, _]) = inventory_next(&mut index)? {
                if at < previous_end {
                    return Err(reject("overlapping replay targets"));
                }
                previous_end = at.checked_add(size).ok_or_else(|| reject("replay target overflow"))?;
            }
            self.physical = Some(index);
            Ok(())
        }

        pub(crate) fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let end = at.checked_add(out.len() as u64).ok_or_else(|| reject("replay read overflow"))?;
            let index = self.physical.as_ref().ok_or_else(|| reject("missing replay patch index"))?;
            let count = index.metadata()?.len() / INVENTORY_BYTES as u64;
            // Start one row early: a patch beginning before at may still overlap it.

            let first = inventory_lower_bound(index, at)?.saturating_sub(1);
            for position in first..count {
                let [physical, number, size, _] = read_words::<4>(index, position * INVENTORY_BYTES as u64)?;
                if physical >= end {
                    break;
                }
                let patch = self.get(number as usize)?;
                if patch.physical != physical || patch.after.len() as u64 != size {
                    return Err(reject("replay patch index mismatch"));
                }
                patch.copy_after_into(at, out);
            }
            Ok(())
        }
    }

    /// Compare two equally ordered patch sequences by value.
    fn same_patches(
        left: usize,
        right: usize,
        mut pair: impl FnMut(usize) -> io::Result<(Patch, Patch)>,
    ) -> io::Result<bool> {
        if left != right {
            return Ok(false);
        }
        for number in 0..left {
            let (a, b) = pair(number)?;
            if a != b {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) struct ReplayPlan {
        pub(crate) preparation: PatchSet,
        pub(crate) patches: PatchSet,
        pub(crate) publication: PatchSet,
        // Advanced-history diagnostics. Legacy plans leave these at zero.
        pub(crate) tail_pages: usize,
        pub(crate) transaction_instances: usize,
        pub(crate) compensation_records: usize,
    }

    impl ReplayPlan {
        pub(crate) fn matches(&self, other: &Self) -> io::Result<bool> {
            Ok(self.tail_pages == other.tail_pages
                && self.transaction_instances == other.transaction_instances
                && self.compensation_records == other.compensation_records
                && self.preparation.matches(&other.preparation)?
                && self.patches.matches(&other.patches)?
                && self.publication.matches(&other.publication)?)
        }
    }

    // Read the proposed recovery result without changing the source. A torn root
    // index must be repairable before it can be used to look for hiberfil.sys.
    pub(crate) struct PlannedImage<'a, P: ?Sized, R = Image> {
        pub(crate) image: R,
        pub(crate) patches: &'a P,
    }

    impl<'a, P: PatchOverlay + ?Sized> PlannedImage<'a, P> {
        // Every projection opens a fresh read-only handle. Never retain a view
        // across plan mutation or merge the separate validation passes.
        pub(crate) fn open(source: &std::path::Path, patches: &'a P) -> io::Result<Self> {
            Ok(Self { image: Image::open(source)?, patches })
        }

        pub(crate) fn volume(
            source: &std::path::Path,
            patches: &'a P,
            boot: ntfs_rs::boot::BootSector,
        ) -> io::Result<ntfs_rs::volume::Volume<Self>> {
            Ok(ntfs_rs::volume::Volume::new(Self::open(source, patches)?, boot)?)
        }
    }

    pub(crate) trait PatchOverlay {
        fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()>;
    }

    impl PatchOverlay for [Patch] {
        fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.iter().for_each(|patch| patch.copy_after_into(at, out));
            Ok(())
        }
    }

    impl PatchOverlay for Vec<Patch> {
        fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.as_slice().overlay(at, out)
        }
    }

    impl PatchOverlay for PatchSet {
        fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            PatchSet::overlay(self, at, out)
        }
    }

    impl PatchOverlay for RepairPlan {
        fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            RepairPlan::overlay(self, at, out)
        }
    }

    impl<P: PatchOverlay + ?Sized, R: ReadAt> ReadAt for PlannedImage<'_, P, R> {
        fn read_exact_at(&mut self, at: u64, out: &mut [u8]) -> ntfs_rs::Result<()> {
            self.image.read_exact_at(at, out)?;
            self.patches.overlay(at, out).io()
        }
    }

    pub(crate) const WRITE_VIEW_BYTES: usize = 128 * 1024;
    const VIEW_BYTES: u64 = WRITE_VIEW_BYTES as u64;

    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct WriteViewStats {
        pub peak_bytes: u64,
        pub hits: u64,
        pub spills: u64,
    }

    struct PayloadView {
        bytes: Vec<u8>,
        touched: u64,
    }

    // Only private pending payloads enter these views. Eviction writes to the
    // existing scratch file; it never publishes bytes or grants device authority.
    struct PlanPayload {
        file: File,
        length: u64,
        views: BTreeMap<u64, PayloadView>,
        max_views: usize,
        clock: u64,
        stats: WriteViewStats,
    }

    impl PlanPayload {
        fn new(file: File, budget: u64) -> io::Result<Self> {
            Ok(Self {
                length: file.metadata()?.len(),
                file,
                views: BTreeMap::new(),
                max_views: (budget / VIEW_BYTES) as usize,
                clock: 0,
                stats: WriteViewStats::default(),
            })
        }

        /// Load the view at offset, evicting the least recently used one;
        /// false means this access streams through the scratch file instead.
        fn admit(&mut self, offset: u64) -> io::Result<bool> {
            self.clock += 1;
            if let Some(view) = self.views.get_mut(&offset) {
                view.touched = self.clock;
                return Ok(true);
            }
            if self.max_views == 0 {
                return Ok(false);
            }
            if self.views.len() == self.max_views {
                let oldest = *self.views.iter().min_by_key(|(_, view)| view.touched).unwrap().0;
                let valid = self.length.saturating_sub(oldest).min(VIEW_BYTES) as usize;
                // Retain the full pending view if the backing write fails.

                self.file.write_all_at(&self.views[&oldest].bytes[..valid], oldest)?;
                self.views.remove(&oldest);
                self.stats.spills += 1;
            }
            let mut bytes = vec![0; WRITE_VIEW_BYTES];
            let mut done = 0;
            while done < bytes.len() {
                match self.file.read_at(&mut bytes[done..], offset + done as u64) {
                    Ok(0) => break,
                    Ok(read) => done += read,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            self.views.insert(offset, PayloadView { bytes, touched: self.clock });
            self.stats.peak_bytes = self.stats.peak_bytes.max(self.views.len() as u64 * VIEW_BYTES);
            Ok(true)
        }

        fn write_at(&mut self, mut at: u64, mut bytes: &[u8]) -> io::Result<()> {
            while !bytes.is_empty() {
                let offset = at / VIEW_BYTES * VIEW_BYTES;
                let within = (at - offset) as usize;
                let count = bytes.len().min(WRITE_VIEW_BYTES - within);
                if self.admit(offset)? {
                    self.views.get_mut(&offset).unwrap().bytes[within..within + count].copy_from_slice(&bytes[..count]);
                } else {
                    self.file.write_all_at(&bytes[..count], at)?;
                }
                at += count as u64;
                self.length = self.length.max(at);
                bytes = &bytes[count..];
            }
            Ok(())
        }

        fn read_at(&mut self, mut at: u64, mut output: &mut [u8]) -> io::Result<()> {
            if at + output.len() as u64 > self.length {
                return Err(reject("pending payload read exceeds its recorded length"));
            }
            while !output.is_empty() {
                let offset = at / VIEW_BYTES * VIEW_BYTES;
                let within = (at - offset) as usize;
                let count = output.len().min(WRITE_VIEW_BYTES - within);
                if let Some(view) = self.views.get_mut(&offset) {
                    self.clock += 1;
                    view.touched = self.clock;
                    output[..count].copy_from_slice(&view.bytes[within..within + count]);
                    self.stats.hits += 1;
                } else {
                    self.file.read_exact_at(&mut output[..count], at)?;
                }
                at += count as u64;
                output = &mut output[count..];
            }
            Ok(())
        }
    }

    const REPAIR_UNIT_BYTES: usize = super::REPAIR_CHUNK_BYTES as usize;
    const PLAN_SECTOR_BYTES: u64 = super::NTFS_SECTOR_BYTES as u64;
    /// A sector-index word holds a biased link offset; zero ends the chain.
    const PLAN_LINK_ABSENT: u64 = 0;
    const PLAN_LINK_OFFSET_BIAS: u64 = 1;
    const PLAN_LINK_BYTES: u64 = 2 * WORD_BYTES as u64;

    // Structural plans retain descriptors, payloads and a sparse sector index on
    // disk. No volume-wide vector of patch bytes or interval nodes is retained.
    // Each descriptor is at most 64 KiB, independently redoable from the durable
    // external journal; the full dependency plan remains guarded until validation.
    struct RepairStorage {
        /// One word per sector: the head of its descriptor link chain.
        sector_index: File,
        /// Rows of (physical, payload offset, size, 0).
        descriptors: File,
        payload: PlanPayload,
        /// Rows of (descriptor number, next link).
        links: File,
        links_len: u64,
    }

    impl RepairStorage {
        fn descriptor(&self, number: u64) -> io::Result<Row> {
            read_words(&self.descriptors, number * INVENTORY_BYTES as u64)
                .map_err(|_| reject("truncated plan descriptor"))
        }

        /// Visit every descriptor linked from the sectors covering physical..end.
        fn visit(
            &self,
            physical: u64,
            end: u64,
            mut visit: impl FnMut(u64, u64, Row) -> io::Result<()>,
        ) -> io::Result<()> {
            for sector in physical / PLAN_SECTOR_BYTES..end.div_ceil(PLAN_SECTOR_BYTES) {
                let [mut link] = read_words(&self.sector_index, sector * WORD_BYTES as u64)?;
                while link != PLAN_LINK_ABSENT {
                    let [number, next] = read_words(&self.links, link - PLAN_LINK_OFFSET_BIAS)?;
                    visit(sector, number, self.descriptor(number)?)?;
                    link = next;
                }
            }
            Ok(())
        }
    }

    pub(crate) struct RepairPlan {
        pub(crate) length: u64,
        pub(crate) recovery_created: u64,
        pub(crate) count: usize,
        pub(crate) index_cache_bytes: u64,
        storage: std::cell::RefCell<RepairStorage>,
    }

    impl RepairPlan {
        pub(crate) fn write_view_stats(&self) -> WriteViewStats {
            self.storage.borrow().payload.stats
        }

        pub(crate) fn new(length: u64) -> io::Result<Self> {
            Self::with_scan_budget(length, None)
        }

        pub(crate) fn with_scan_budget(length: u64, budget: Option<checker::ScanBudget>) -> io::Result<Self> {
            let scratch = checker::consistency::scratch_file;
            let sector_index = scratch()?;
            sector_index.set_len(length.div_ceil(PLAN_SECTOR_BYTES) * WORD_BYTES as u64)?;
            let elapsed =
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(io::Error::other)?;
            Ok(Self {
                length,
                recovery_created: ntfs_rs::std_info::from_unix(elapsed.as_secs() as i64, elapsed.subsec_nanos()),
                count: 0,
                index_cache_bytes: budget
                    .map_or(checker::consistency::INDEX_CACHE_BYTES, |budget| budget.index_cache_bytes),
                storage: std::cell::RefCell::new(RepairStorage {
                    sector_index,
                    descriptors: scratch()?,
                    payload: PlanPayload::new(scratch()?, budget.map_or(0, |budget| budget.write_view_cache_bytes))?,
                    links: scratch()?,
                    links_len: 0,
                }),
            })
        }

        pub(crate) fn len(&self) -> usize {
            self.count
        }

        pub(crate) fn is_empty(&self) -> bool {
            self.count == 0
        }

        pub(crate) fn get(&self, number: usize) -> io::Result<Patch> {
            if number >= self.count {
                return Err(reject("invalid plan descriptor"));
            }
            let storage = &mut *self.storage.borrow_mut();
            let [physical, offset, size, _] = storage.descriptor(number as u64)?;
            if size == 0 || size > REPAIR_UNIT_BYTES as u64 {
                return Err(reject("invalid plan unit"));
            }
            let mut before = vec![0; size as usize];
            let mut after = before.clone();
            storage.payload.read_at(offset, &mut before)?;
            storage.payload.read_at(offset + size, &mut after)?;
            Ok(Patch::new(physical, before, after))
        }

        pub(crate) fn iter(&self) -> impl Iterator<Item = io::Result<Patch>> + '_ {
            (0..self.count).map(|i| self.get(i))
        }

        pub(crate) fn matches(&self, other: &Self) -> io::Result<bool> {
            same_patches(self.count, other.count, |number| Ok((self.get(number)?, other.get(number)?)))
        }

        pub(crate) fn push(&mut self, patch: Patch) -> io::Result<()> {
            if patch.before.len() != patch.after.len()
                || patch.after.is_empty()
                || patch.physical.checked_add(patch.after.len() as u64).is_none_or(|end| end > self.length)
            {
                return Err(reject("invalid structural repair range"));
            }
            let storage = self.storage.get_mut();
            for start in (0..patch.after.len()).step_by(REPAIR_UNIT_BYTES) {
                let size = (patch.after.len() - start).min(REPAIR_UNIT_BYTES);
                let (before, after) = (&patch.before[start..start + size], &patch.after[start..start + size]);
                let physical = patch.physical + start as u64;
                let end = physical + size as u64;
                let mut existing = None;
                storage.visit(physical, end, |_, _, [at, payload, bytes, _]| {
                    if physical < at + bytes && at < end {
                        if at != physical || bytes != size as u64 {
                            return Err(reject("overlapping structural repair targets"));
                        }
                        existing = Some(payload + bytes);
                    }
                    Ok(())
                })?;
                if let Some(after_at) = existing {
                    let mut current = vec![0; size];
                    storage.payload.read_at(after_at, &mut current)?;
                    if current != before {
                        return Err(reject("conflicting repair preimages"));
                    }
                    storage.payload.write_at(after_at, after)?;
                    continue;
                }
                let offset = storage.payload.length;
                storage.payload.write_at(offset, before)?;
                storage.payload.write_at(offset + size as u64, after)?;
                let number = self.count as u64;
                write_words(&storage.descriptors, number * INVENTORY_BYTES as u64, [physical, offset, size as u64, 0])?;
                for sector in physical / PLAN_SECTOR_BYTES..end.div_ceil(PLAN_SECTOR_BYTES) {
                    let at = sector * WORD_BYTES as u64;
                    let [previous] = read_words(&storage.sector_index, at)?;
                    write_words(&storage.links, storage.links_len, [number, previous])?;
                    write_words(&storage.sector_index, at, [storage.links_len + PLAN_LINK_OFFSET_BIAS])?;
                    storage.links_len += PLAN_LINK_BYTES;
                }
                self.count += 1;
            }
            Ok(())
        }

        pub(crate) fn overlay(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
            let end = at
                .checked_add(out.len() as u64)
                .filter(|end| *end <= self.length)
                .ok_or_else(|| reject("plan read outside source"))?;
            let storage = &mut *self.storage.borrow_mut();
            let mut reads = Vec::new();
            storage.visit(at, end, |sector, _, [physical, payload, size, _]| {
                let lo = at.max(physical).max(sector * PLAN_SECTOR_BYTES);
                let hi = end.min(physical + size).min((sector + 1) * PLAN_SECTOR_BYTES);
                if lo < hi {
                    reads.push((payload + size + lo - physical, lo, hi));
                }
                Ok(())
            })?;
            for (source, lo, hi) in reads {
                storage.payload.read_at(source, &mut out[(lo - at) as usize..(hi - at) as usize])?;
            }
            Ok(())
        }

        // Combine successive edits of the same record without losing its original
        // preimage. Other overlaps remain an error in the final plan validation.
        pub(crate) fn compose(&mut self, patch: Patch) -> io::Result<()> {
            if patch.before.len() != patch.after.len() || patch.after.is_empty() {
                return Err(reject("invalid composed repair range"));
            }
            let end = patch
                .physical
                .checked_add(patch.after.len() as u64)
                .filter(|&end| end <= self.length)
                .ok_or_else(|| reject("composed repair exceeds volume"))?;
            let mut numbers = BTreeSet::new();
            self.storage.get_mut().visit(patch.physical, end, |_, number, [physical, _, size, _]| {
                if physical < end && patch.physical < physical + size {
                    numbers.insert(number as usize);
                }
                Ok(())
            })?;
            let mut old = numbers.into_iter().map(|n| self.get(n)).collect::<io::Result<Vec<_>>>()?;
            old.sort_by_key(|p| p.physical);
            let mut updates = Vec::new();
            let mut cursor = patch.physical;
            let slice = |from: u64, to: u64| {
                let (a, b) = ((from - patch.physical) as usize, (to - patch.physical) as usize);
                Patch::new(from, patch.before[a..b].to_vec(), patch.after[a..b].to_vec())
            };
            for previous in old {
                let from = patch.physical.max(previous.physical);
                let to = end.min(previous.end());
                let source = (from - patch.physical) as usize;
                let destination = (from - previous.physical) as usize;
                let size = (to - from) as usize;
                if previous.after[destination..destination + size] != patch.before[source..source + size] {
                    return Err(reject("conflicting composed repair preimages"));
                }
                if cursor < from {
                    updates.push(slice(cursor, from));
                }
                let mut after = previous.after.clone();
                after[destination..destination + size].copy_from_slice(&patch.after[source..source + size]);
                updates.push(Patch::new(previous.physical, previous.after, after));
                cursor = to;
            }
            if cursor < end {
                updates.push(slice(cursor, end));
            }
            updates.into_iter().try_for_each(|update| self.push(update))
        }
    }

    #[cfg(test)]
    mod tests {
        include!("../tests/recovery/plan_tests.rs");
    }
    #[cfg(test)]
    include!("../tests/recovery/plan_support.rs");
}

pub(super) mod log {
    use super::storage::{read_words, write_words, RecordStore};
    use super::CoreIo;
    use ntfs_rs::bytes::{u16_at, u32_at, u64_at};
    use ntfs_rs::logfile::{lsn_stream_offset, LfsRecord, NtfsCheckpoint, RecordPage, RestartPage, RestartTable};
    use ntfs_rs::{Error, Result};
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::io::Write;

    use super::storage::WORD_BYTES;
    use super::{BITMAP_BITS_PER_BYTE, RESTART_COPY_COUNT};
    use ntfs_rs::filename_metadata::CODE_UNIT_BYTES;
    use ntfs_rs::logfile::{lfs_layout as lfs, log_operation as operation, log_page_layout as page_layout};
    const OPEN_REFERENCE_OFFSET: usize = 0;
    const OPEN_SLOT_ABSENT: u64 = 0;
    const OPEN_SLOT_INDEX_BIAS: u64 = 1;
    const OPEN_KIND_OFFSET: usize = WORD_BYTES;
    const OPEN_INDEX_BYTES_OFFSET: usize = OPEN_KIND_OFFSET + std::mem::size_of::<u32>();
    pub(super) const OPEN_ENTRY_VERSION_LEGACY: u32 = 0;
    pub(super) const OPEN_ENTRY_VERSION_CURRENT: u32 = 1;
    pub(super) const OPEN_ENTRY_LEGACY_BYTES: usize = 44;
    const OPEN_ENTRY_CURRENT_BYTES: usize = 40;
    const OPEN_ENTRY_ALLOCATED_OFFSET: usize = 0;
    const OPEN_CURRENT_INDEX_OFFSET: usize = 4;
    const OPEN_CURRENT_KIND_OFFSET: usize = 8;
    const OPEN_CURRENT_REFERENCE_OFFSET: usize = 16;
    const OPEN_LEGACY_REFERENCE_OFFSET: usize = 8;
    const OPEN_LEGACY_KIND_OFFSET: usize = 28;
    const OPEN_LEGACY_INDEX_OFFSET: usize = 40;
    use ntfs_rs::mft::ATTRIBUTE_TYPE_ALIGNMENT;
    const ATTRIBUTE_NAME_LENGTH_OFFSET: usize = std::mem::size_of::<u16>();
    const ATTRIBUTE_NAME_HEADER_BYTES: usize = 2 * std::mem::size_of::<u16>();
    const ATTRIBUTE_NAME_TRAILER_BYTES: usize = CODE_UNIT_BYTES;
    const ATTRIBUTE_NAME_FIXED_BYTES: usize = ATTRIBUTE_NAME_HEADER_BYTES + ATTRIBUTE_NAME_TRAILER_BYTES;
    const SEED_ID_OFFSET: usize = 0;
    const SEED_STATE_OFFSET: usize = std::mem::size_of::<u32>();
    const SEED_PADDING_OFFSET: usize = SEED_STATE_OFFSET + 1;
    const SEED_FIRST_OFFSET: usize = WORD_BYTES;
    const SEED_PREVIOUS_OFFSET: usize = SEED_FIRST_OFFSET + WORD_BYTES;
    const SEED_UNDO_OFFSET: usize = SEED_PREVIOUS_OFFSET + WORD_BYTES;
    const SEED_ROW_BYTES: usize = SEED_UNDO_OFFSET + WORD_BYTES;
    pub(super) const TRANSACTION_ACTIVE: u8 = 1;
    pub(super) const TRANSACTION_PREPARED: u8 = 2;
    pub(super) const TRANSACTION_COMMITTED: u8 = 3;
    pub(super) const TRANSACTION_ENTRY_BYTES: usize = 40;
    const DIRTY_TARGET_OFFSET: usize = 0;
    const DIRTY_PADDING_OFFSET: usize = std::mem::size_of::<u16>();
    const DIRTY_BYTES_OFFSET: usize = 4;
    const DIRTY_VCN_OFFSET: usize = WORD_BYTES;
    const DIRTY_OLDEST_OFFSET: usize = DIRTY_VCN_OFFSET + WORD_BYTES;
    const DIRTY_COUNT_OFFSET: usize = DIRTY_OLDEST_OFFSET + WORD_BYTES;
    const DIRTY_HEADER_BYTES: usize = DIRTY_COUNT_OFFSET + WORD_BYTES;
    const DIRTY_ENTRY_TARGET_OFFSET: usize = 4;
    const DIRTY_ENTRY_BYTES_OFFSET: usize = 8;
    const DIRTY_ENTRY_COUNT_OFFSET: usize = 12;
    const DIRTY_ENTRY_LEGACY_VCN_OFFSET: usize = 20;
    const DIRTY_ENTRY_CURRENT_VCN_OFFSET: usize = 16;
    const DIRTY_ENTRY_LCN_OFFSET: usize = 2 * WORD_BYTES;
    const PAGE_PRESENT_OFFSET: usize = 0;
    const PAGE_ENDS_OFFSET: usize = 1;
    const PAGE_COUNT_OFFSET: usize = 2;
    const PAGE_POSITION_OFFSET: usize = 4;
    const PAGE_PADDING_OFFSET: usize = 6;
    const PAGE_STORAGE_OFFSET: usize = WORD_BYTES;
    const PAGE_LAST_OFFSET: usize = PAGE_STORAGE_OFFSET + WORD_BYTES;
    const PAGE_END_OFFSET: usize = PAGE_LAST_OFFSET + WORD_BYTES;
    const PAGE_NEXT_OFFSET: usize = PAGE_END_OFFSET + WORD_BYTES;
    const PAGE_RESERVED_OFFSET: usize = PAGE_NEXT_OFFSET + WORD_BYTES;
    const PAGE_ROW_BYTES: usize = PAGE_RESERVED_OFFSET + WORD_BYTES;
    const PAGE_PRESENT: u8 = 1;
    use super::ENCODED_BOOL_TRUE;
    const FIRST_GROUP_POSITION: u16 = 1;
    const MAX_HISTORY_GENERATION_DISTANCE: u64 = 1;
    const RESTART_PAGE_SIZES: [usize; 8] = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

    #[derive(Clone, Debug)]
    pub struct OpenAttribute {
        pub reference: u64,
        pub kind: u32,
        pub index_bytes: u32,
        pub name: Vec<u8>,
    }
    const OPEN_ATTRIBUTE_HEADER_BYTES: usize = OPEN_INDEX_BYTES_OFFSET + std::mem::size_of::<u32>();

    impl OpenAttribute {
        pub fn encode(&self) -> Vec<u8> {
            let mut bytes = Vec::with_capacity(OPEN_ATTRIBUTE_HEADER_BYTES + self.name.len());
            bytes.extend_from_slice(&self.reference.to_le_bytes());
            bytes.extend_from_slice(&self.kind.to_le_bytes());
            bytes.extend_from_slice(&self.index_bytes.to_le_bytes());
            bytes.extend_from_slice(&self.name);
            bytes
        }
        pub fn decode(bytes: &[u8]) -> Result<Self> {
            if bytes.len() < OPEN_ATTRIBUTE_HEADER_BYTES || bytes.len() % CODE_UNIT_BYTES != 0 {
                return Err(Error::InvalidLog);
            }
            Ok(Self {
                reference: u64_at(bytes, OPEN_REFERENCE_OFFSET)?,
                kind: u32_at(bytes, OPEN_KIND_OFFSET)?,
                index_bytes: u32_at(bytes, OPEN_INDEX_BYTES_OFFSET)?,
                name: bytes[OPEN_ATTRIBUTE_HEADER_BYTES..].to_vec(),
            })
        }
    }
    const OPEN_ATTRIBUTE_SLOT_BYTES: usize = WORD_BYTES;
    const OPEN_ATTRIBUTE_SLOTS: u64 = u16::MAX as u64 + 1;

    pub struct OpenAttributeStore {
        /// One word per attribute ID: the biased index of its value row.
        slots: File,
        values: RecordStore,
    }

    impl OpenAttributeStore {
        pub fn new() -> Result<Self> {
            let slots = super::checker::consistency::scratch_file().io()?;
            slots.set_len(OPEN_ATTRIBUTE_SLOTS * OPEN_ATTRIBUTE_SLOT_BYTES as u64).io()?;
            Ok(Self { slots, values: RecordStore::new().io()? })
        }

        pub fn get(&self, id: u16) -> Result<Option<OpenAttribute>> {
            let [index] = read_words(&self.slots, u64::from(id) * OPEN_ATTRIBUTE_SLOT_BYTES as u64).io()?;
            if index == OPEN_SLOT_ABSENT {
                return Ok(None);
            }
            OpenAttribute::decode(&self.values.get((index - OPEN_SLOT_INDEX_BIAS) as usize).io()?).map(Some)
        }

        pub fn insert(&mut self, id: u16, value: OpenAttribute) -> Result<()> {
            let number = self.values.len() as u64;
            self.values.push(&value.encode()).io()?;
            let at = u64::from(id) * OPEN_ATTRIBUTE_SLOT_BYTES as u64;
            write_words(&self.slots, at, [number + OPEN_SLOT_INDEX_BIAS]).io()
        }

        pub fn copy(&self) -> Result<Self> {
            let mut copy = Self::new()?;
            for id in 0..=u16::MAX {
                if let Some(value) = self.get(id)? {
                    copy.insert(id, value)?;
                }
            }
            Ok(copy)
        }
    }

    #[derive(Clone, Debug)]
    pub struct TransactionSeed {
        pub state: u8,
        pub first: u64,
        pub previous: u64,
        pub undo: u64,
    }
    pub struct TransactionSeedStore {
        rows: RecordStore,
    }
    impl TransactionSeedStore {
        pub fn new() -> Result<Self> {
            Ok(Self { rows: RecordStore::new().io()? })
        }
        pub fn insert(&mut self, id: u32, seed: TransactionSeed) -> Result<()> {
            let mut row = [0; SEED_ROW_BYTES];
            row[..SEED_STATE_OFFSET].copy_from_slice(&id.to_le_bytes());
            row[SEED_STATE_OFFSET] = seed.state;
            row[SEED_FIRST_OFFSET..SEED_PREVIOUS_OFFSET].copy_from_slice(&seed.first.to_le_bytes());
            row[SEED_PREVIOUS_OFFSET..SEED_UNDO_OFFSET].copy_from_slice(&seed.previous.to_le_bytes());
            row[SEED_UNDO_OFFSET..SEED_ROW_BYTES].copy_from_slice(&seed.undo.to_le_bytes());
            self.rows.push(&row).io()
        }
        fn get(&self, number: usize) -> Result<(u32, TransactionSeed)> {
            let row = self.rows.get(number).io()?;
            if row.len() != SEED_ROW_BYTES
                || row[SEED_PADDING_OFFSET..SEED_FIRST_OFFSET] != [0; SEED_FIRST_OFFSET - SEED_PADDING_OFFSET]
                || !matches!(row[SEED_STATE_OFFSET], TRANSACTION_ACTIVE..=TRANSACTION_COMMITTED)
            {
                return Err(Error::InvalidLog);
            }
            Ok((
                u32_at(&row, SEED_ID_OFFSET)?,
                TransactionSeed {
                    state: row[SEED_STATE_OFFSET],
                    first: u64_at(&row, SEED_FIRST_OFFSET)?,
                    previous: u64_at(&row, SEED_PREVIOUS_OFFSET)?,
                    undo: u64_at(&row, SEED_UNDO_OFFSET)?,
                },
            ))
        }
        pub fn for_each(&self, mut visitor: impl FnMut(u32, TransactionSeed) -> Result<()>) -> Result<()> {
            let mut keys = super::checker::consistency::DiskInventory::new();
            for number in 0..self.rows.len() {
                let (id, _) = self.get(number)?;
                keys.push([u64::from(id), number as u64, 0, 0]).io()?;
            }
            let mut keys = keys.finish().io()?;
            let mut pending = None;
            while let Some([id, number, _, _]) = super::checker::consistency::inventory_next(&mut keys).io()? {
                if let Some((prior, index)) = pending {
                    if prior != id {
                        let (id, seed) = self.get(index)?;
                        visitor(id, seed)?;
                    }
                }
                pending = Some((id, number as usize));
            }
            if let Some((_, index)) = pending {
                let (id, seed) = self.get(index)?;
                visitor(id, seed)?;
            }
            Ok(())
        }
    }
    #[derive(Clone, Debug)]
    pub struct DirtyPage {
        pub target: u16,
        pub vcn: u64,
        pub oldest: u64,
        pub bytes: u32,
        pub lcns: Vec<u64>,
    }
    impl DirtyPage {
        pub fn encode(&self) -> Vec<u8> {
            let mut row = Vec::with_capacity(DIRTY_HEADER_BYTES + self.lcns.len() * WORD_BYTES);
            row.extend_from_slice(&self.target.to_le_bytes());
            row.extend_from_slice(&[0; DIRTY_BYTES_OFFSET - DIRTY_PADDING_OFFSET]);
            row.extend_from_slice(&self.bytes.to_le_bytes());
            row.extend_from_slice(&self.vcn.to_le_bytes());
            row.extend_from_slice(&self.oldest.to_le_bytes());
            row.extend_from_slice(&(self.lcns.len() as u64).to_le_bytes());
            for lcn in &self.lcns {
                row.extend_from_slice(&lcn.to_le_bytes());
            }
            row
        }
        pub fn decode(row: &[u8]) -> Result<Self> {
            if row.len() < DIRTY_HEADER_BYTES
                || row[DIRTY_PADDING_OFFSET..DIRTY_BYTES_OFFSET] != [0; DIRTY_BYTES_OFFSET - DIRTY_PADDING_OFFSET]
            {
                return Err(Error::InvalidLog);
            }
            let count = u64_at(row, DIRTY_COUNT_OFFSET)? as usize;
            if row.len()
                != DIRTY_HEADER_BYTES
                    .checked_add(count.checked_mul(WORD_BYTES).ok_or(Error::Overflow)?)
                    .ok_or(Error::Overflow)?
            {
                return Err(Error::InvalidLog);
            }
            Ok(Self {
                target: u16_at(row, DIRTY_TARGET_OFFSET)?,
                bytes: u32_at(row, DIRTY_BYTES_OFFSET)?,
                vcn: u64_at(row, DIRTY_VCN_OFFSET)?,
                oldest: u64_at(row, DIRTY_OLDEST_OFFSET)?,
                lcns: row[DIRTY_HEADER_BYTES..]
                    .chunks_exact(WORD_BYTES)
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .collect(),
            })
        }
    }
    pub struct History {
        pub records: RecordStore,
        pub restart: RestartPage,
        pub template: Vec<u8>,
        pub opens: OpenAttributeStore,
        pub transactions: TransactionSeedStore,
        pub dirty: RecordStore,
        pub tail_pages: usize,
        pub checkpoint_lsn: u64,
        pub occupied_pages: PageBits,
        pub discarded_pages: PageBits,
        pub end_page: u64,
    }
    pub struct PageBits {
        _backing: File,
        bits: memmap2::MmapMut,
        page_bytes: u64,
        slots: u64,
    }
    impl PageBits {
        pub fn new(log_bytes: usize, page_bytes: usize) -> Result<Self> {
            if page_bytes == 0 || log_bytes % page_bytes != 0 {
                return Err(Error::InvalidLog);
            }
            let slots = log_bytes / page_bytes;
            let bytes = slots.div_ceil(BITMAP_BITS_PER_BYTE as usize);
            if bytes == 0 {
                return Err(Error::InvalidLog);
            }
            let backing = super::checker::consistency::scratch_file().io()?;
            backing.set_len(bytes as u64).io()?;
            let bits = unsafe { memmap2::MmapMut::map_mut(&backing).io()? };
            Ok(Self { _backing: backing, bits, page_bytes: page_bytes as u64, slots: slots as u64 })
        }
        fn bit(&self, at: u64) -> Result<(usize, u8)> {
            if at % self.page_bytes != 0 || at / self.page_bytes >= self.slots {
                return Err(Error::InvalidLog);
            }
            let slot = at / self.page_bytes;
            Ok(((slot / BITMAP_BITS_PER_BYTE) as usize, 1 << (slot % BITMAP_BITS_PER_BYTE)))
        }
        pub fn contains(&self, at: u64) -> Result<bool> {
            let (byte, mask) = self.bit(at)?;
            Ok(self.bits[byte] & mask != 0)
        }
        pub fn insert(&mut self, at: u64) -> Result<bool> {
            let (byte, mask) = self.bit(at)?;
            let fresh = self.bits[byte] & mask == 0;
            self.bits[byte] |= mask;
            Ok(fresh)
        }
        pub fn positions(&self) -> impl Iterator<Item = u64> + '_ {
            (0..self.slots)
                .filter(|&slot| {
                    self.bits[(slot / BITMAP_BITS_PER_BYTE) as usize] & (1 << (slot % BITMAP_BITS_PER_BYTE)) != 0
                })
                .map(|slot| slot * self.page_bytes)
        }
    }
    #[derive(Clone)]
    struct Page {
        storage_at: usize,
        last: u64,
        end: u64,
        next: usize,
        count: u16,
        position: u16,
        ends: bool,
    }
    struct PageIndex {
        _backing: File,
        rows: memmap2::MmapMut,
        page_bytes: u64,
        slots: u64,
        count: usize,
    }
    impl PageIndex {
        fn new(log_bytes: usize, page_bytes: usize) -> Result<Self> {
            if page_bytes == 0 || log_bytes % page_bytes != 0 {
                return Err(Error::InvalidLog);
            }
            let slots = log_bytes / page_bytes;
            let bytes = slots.checked_mul(PAGE_ROW_BYTES).ok_or(Error::Overflow)?;
            if bytes == 0 {
                return Err(Error::InvalidLog);
            }
            let backing = super::checker::consistency::scratch_file().io()?;
            backing.set_len(bytes as u64).io()?;
            let rows = unsafe { memmap2::MmapMut::map_mut(&backing).io()? };
            Ok(Self { _backing: backing, rows, page_bytes: page_bytes as u64, slots: slots as u64, count: 0 })
        }
        fn position(&self, at: u64) -> Result<usize> {
            if at % self.page_bytes != 0 || at / self.page_bytes >= self.slots {
                return Err(Error::InvalidLog);
            }
            usize::try_from(at / self.page_bytes * PAGE_ROW_BYTES as u64).map_err(|_| Error::Overflow)
        }
        fn get(&self, at: u64) -> Result<Option<Page>> {
            let pos = self.position(at)?;
            let row = &self.rows[pos..pos + PAGE_ROW_BYTES];
            if row[PAGE_PRESENT_OFFSET] == 0 {
                return Ok(None);
            }
            if row[PAGE_PRESENT_OFFSET] != PAGE_PRESENT
                || row[PAGE_ENDS_OFFSET] > ENCODED_BOOL_TRUE
                || row[PAGE_PADDING_OFFSET..PAGE_STORAGE_OFFSET] != [0; PAGE_STORAGE_OFFSET - PAGE_PADDING_OFFSET]
                || row[PAGE_RESERVED_OFFSET..PAGE_ROW_BYTES] != [0; WORD_BYTES]
            {
                return Err(Error::InvalidLog);
            }
            let word = |at| u64::from_le_bytes(row[at..at + WORD_BYTES].try_into().unwrap());
            Ok(Some(Page {
                storage_at: word(PAGE_STORAGE_OFFSET) as usize,
                last: word(PAGE_LAST_OFFSET),
                end: word(PAGE_END_OFFSET),
                next: word(PAGE_NEXT_OFFSET) as usize,
                count: u16::from_le_bytes(row[PAGE_COUNT_OFFSET..PAGE_POSITION_OFFSET].try_into().unwrap()),
                position: u16::from_le_bytes(row[PAGE_POSITION_OFFSET..PAGE_PADDING_OFFSET].try_into().unwrap()),
                ends: row[PAGE_ENDS_OFFSET] != 0,
            }))
        }
        fn insert(&mut self, at: u64, page: Page) -> Result<()> {
            let pos = self.position(at)?;
            let row = &mut self.rows[pos..pos + PAGE_ROW_BYTES];
            if row[PAGE_PRESENT_OFFSET] == 0 {
                self.count += 1;
            }
            row.fill(0);
            row[PAGE_PRESENT_OFFSET] = PAGE_PRESENT;
            row[PAGE_ENDS_OFFSET] = u8::from(page.ends);
            row[PAGE_COUNT_OFFSET..PAGE_POSITION_OFFSET].copy_from_slice(&page.count.to_le_bytes());
            row[PAGE_POSITION_OFFSET..PAGE_PADDING_OFFSET].copy_from_slice(&page.position.to_le_bytes());
            for (offset, value) in [
                (PAGE_STORAGE_OFFSET, page.storage_at as u64),
                (PAGE_LAST_OFFSET, page.last),
                (PAGE_END_OFFSET, page.end),
                (PAGE_NEXT_OFFSET, page.next as u64),
            ] {
                row[offset..offset + WORD_BYTES].copy_from_slice(&value.to_le_bytes());
            }
            Ok(())
        }
        fn len(&self) -> usize {
            self.count
        }
    }
    struct Reader<'a> {
        restart: RestartPage,
        pages: PageIndex,
        first: u64,
        log: &'a [u8],
    }
    struct PageSpan {
        first: u64,
        count: u64,
        page_bytes: u64,
        log_first: u64,
        log_end: u64,
    }
    impl PageSpan {
        fn positions(&self) -> impl Iterator<Item = u64> + '_ {
            (0..self.count).map(|number| {
                let at = self.first + number * self.page_bytes;
                if at < self.log_end {
                    at
                } else {
                    self.log_first + at - self.log_end
                }
            })
        }
        fn contains(&self, at: u64) -> bool {
            if at < self.log_first || at >= self.log_end || at % self.page_bytes != 0 {
                return false;
            }
            let distance =
                if at >= self.first { at - self.first } else { self.log_end - self.first + at - self.log_first };
            distance / self.page_bytes < self.count
        }
    }
    impl Reader<'_> {
        fn bytes(&self, page: &Page) -> &[u8] {
            let at = page.storage_at;
            &self.log[at..at + self.restart.log_page_bytes as usize]
        }
        fn offset(&self, lsn: u64) -> Result<u64> {
            let at = lsn_stream_offset(lsn, self.restart.sequence_bits, self.restart.log_bytes)?;
            if at < self.first
                || at % u64::from(self.restart.log_page_bytes) < u64::from(self.restart.record_data_offset)
            {
                return Err(Error::InvalidLog);
            }
            Ok(at)
        }
        fn next_page(&self, at: u64) -> u64 {
            let next = at + u64::from(self.restart.log_page_bytes);
            if next == self.restart.log_bytes {
                self.first
            } else {
                next
            }
        }
        fn group(&self, at: u64) -> Result<()> {
            let p = self.pages.get(at)?.ok_or(Error::InvalidLog)?;
            let size = u64::from(self.restart.log_page_bytes);
            if usize::from(p.count) > self.pages.len() {
                return Err(Error::InvalidLog);
            }
            let mut first = at;
            for _ in FIRST_GROUP_POSITION..p.position {
                first = if first == self.first { self.restart.log_bytes - size } else { first - size };
            }
            let mut cursor = first;
            let mut last = 0;
            for position in FIRST_GROUP_POSITION..=p.count {
                let page = self.pages.get(cursor)?.ok_or(Error::InvalidLog)?;
                if page.count != p.count || page.position != position || (page.ends && page.last < last) {
                    return Err(Error::InvalidLog);
                }
                last = last.max(page.last);
                cursor = self.next_page(cursor);
            }
            Ok(())
        }
        fn record(&self, lsn: u64) -> Result<(memmap2::Mmap, u64, PageSpan)> {
            let size = u64::from(self.restart.log_page_bytes);
            let offset = self.offset(lsn)?;
            let mut at = offset / size * size;
            let mut cursor = (offset % size) as usize;
            let first = self.pages.get(at)?.ok_or(Error::InvalidLog)?;
            let first_bytes = self.bytes(&first);
            let total = LfsRecord::peek_total_bytes(first_bytes.get(cursor..).ok_or(Error::InvalidLog)?)?;
            if total as u64 > self.restart.log_bytes - self.first {
                return Err(Error::InvalidLog);
            }
            let spanning = total > first_bytes.len() - cursor;
            let mut spool = super::checker::consistency::scratch_file().io()?;
            let mut written = 0_usize;
            let mut count = 0;
            let first_page = at;
            let active_pages = (self.restart.log_bytes - self.first) / size;
            loop {
                count += 1;
                if count > active_pages {
                    return Err(Error::InvalidLog);
                }
                self.group(at)?;
                let page = self.pages.get(at)?.ok_or(Error::InvalidLog)?;
                if page.ends && page.last < lsn {
                    return Err(Error::InvalidLog);
                }
                let bytes = self.bytes(&page);
                let take = (total - written).min(bytes.len() - cursor);
                spool.write_all(&bytes[cursor..cursor + take]).io()?;
                written += take;
                cursor += take;
                if written == total {
                    cursor = (cursor + lfs::ALIGNMENT - 1) & !(lfs::ALIGNMENT - 1);
                    if !page.ends || page.end < lsn || cursor > page.next {
                        return Err(Error::InvalidLog);
                    }
                    break;
                }
                at = self.next_page(at);
                cursor = usize::from(self.restart.record_data_offset);
            }
            let raw = unsafe { memmap2::MmapOptions::new().len(total).map(&spool).io()? };
            let record = LfsRecord::parse(&raw)?;
            let client = self.restart.client.ok_or(Error::InvalidLog)?;
            if record.this_lsn != lsn
                || record.multi_page != spanning
                || record.client_index != client.index
                || record.client_sequence != client.sequence
            {
                return Err(Error::InvalidLog);
            }
            let page = self.pages.get(at)?.ok_or(Error::InvalidLog)?;
            let bits = u64::BITS - self.restart.sequence_bits;
            // Windows starts a record wherever its header fits, including exactly
            // at next_record_offset when that record spans into the next page;
            // the page's last LSN then covers it. Our writer instead moves such
            // records to a fresh page, which next_record_offset alone describes.
            let here = at + cursor as u64;
            // A record that ran past the end of the file ends in the first
            // pages, in the next generation: so does the position after it.
            let here_generation = (lsn >> bits) + u64::from(here <= offset);
            let here_lsn = (here_generation << bits) | (here / lfs::LSN_OFFSET_UNIT_BYTES);
            let fits = self.bytes(&page).len() - cursor >= lfs::HEADER_BYTES;
            let next_offset = if fits && (cursor < page.next || here_lsn <= page.last) {
                here
            } else {
                self.next_page(at) + u64::from(self.restart.record_data_offset)
            };
            let generation = (lsn >> bits) + u64::from(next_offset <= offset);
            if generation >= 1_u64 << self.restart.sequence_bits {
                return Err(Error::Overflow);
            }
            Ok((
                raw,
                (generation << bits) | (next_offset / lfs::LSN_OFFSET_UNIT_BYTES),
                PageSpan {
                    first: first_page,
                    count,
                    page_bytes: size,
                    log_first: self.first,
                    log_end: self.restart.log_bytes,
                },
            ))
        }
    }
    fn parse_page(
        raw: &mut [u8],
        storage_at: usize,
        restart: RestartPage,
        sector: u16,
        tail: bool,
    ) -> Result<(u64, Page)> {
        let p = RecordPage::parse(raw, sector, restart.record_data_offset)?;
        let target =
            if restart.major_version == page_layout::VERSION_LEGACY { p.last_lsn } else { u64::from(p.file_offset) };
        let mut last = p.last_lsn;
        if tail && restart.major_version == page_layout::VERSION_LEGACY {
            last = p.last_end_lsn;
        }
        let result = (
            target,
            Page {
                last,
                end: p.last_end_lsn,
                next: p.next_record_offset(),
                count: p.page_count,
                position: p.page_position,
                ends: p.ends_record,
                storage_at,
            },
        );
        Ok(result)
    }

    pub fn open_entry(bytes: &[u8], version: u32) -> Result<OpenAttribute> {
        let (kind, reference, index_bytes) = match (version, bytes.len()) {
            (OPEN_ENTRY_VERSION_CURRENT, OPEN_ENTRY_CURRENT_BYTES) => (
                u32_at(bytes, OPEN_CURRENT_KIND_OFFSET)?,
                u64_at(bytes, OPEN_CURRENT_REFERENCE_OFFSET)?,
                u32_at(bytes, OPEN_CURRENT_INDEX_OFFSET)?,
            ),
            (OPEN_ENTRY_VERSION_LEGACY, OPEN_ENTRY_LEGACY_BYTES) => (
                u32_at(bytes, OPEN_LEGACY_KIND_OFFSET)?,
                u64_at(bytes, OPEN_LEGACY_REFERENCE_OFFSET)?,
                u32_at(bytes, OPEN_LEGACY_INDEX_OFFSET)?,
            ),
            _ => return Err(Error::Unsupported),
        };
        if u32_at(bytes, OPEN_ENTRY_ALLOCATED_OFFSET)? != u32::MAX
            || kind < ATTRIBUTE_TYPE_ALIGNMENT
            || kind % ATTRIBUTE_TYPE_ALIGNMENT != 0
            || ntfs_rs::mft::reference_sequence(reference) == 0
        {
            return Err(Error::InvalidLog);
        }
        Ok(OpenAttribute { reference, kind, index_bytes, name: Vec::new() })
    }

    pub fn discover(log: &mut [u8], sector: u16) -> Result<History> {
        // Recover the geometry from a valid secondary copy if the primary header
        // itself was torn. A candidate must reside at its declared system-page size.
        let system = match RestartPage::peek_system_page_bytes(log) {
            Ok(n) => n as usize,
            Err(_) => {
                let mut found = None;
                for size in RESTART_PAGE_SIZES {
                    let Some(bytes) = log.get(size..size * RESTART_COPY_COUNT as usize) else {
                        continue;
                    };
                    if let Ok(r) = RestartPage::parse(&mut bytes.to_vec(), sector) {
                        if r.system_page_bytes as usize == size {
                            if found.replace(size).is_some() {
                                return Err(Error::InvalidLog);
                            }
                        }
                    }
                }
                found.ok_or(Error::InvalidLog)?
            }
        };
        if log.len() < system * RESTART_COPY_COUNT as usize {
            return Err(Error::InvalidLog);
        }
        let a = RestartPage::parse(&mut log[..system].to_vec(), sector);
        let b = RestartPage::parse(&mut log[system..system * RESTART_COPY_COUNT as usize].to_vec(), sector);
        let (restart, template) = match (a, b) {
            (Ok(a), Ok(b)) => {
                if (
                    a.system_page_bytes,
                    a.log_page_bytes,
                    a.major_version,
                    a.minor_version,
                    a.sequence_bits,
                    a.log_bytes,
                ) != (
                    b.system_page_bytes,
                    b.log_page_bytes,
                    b.major_version,
                    b.minor_version,
                    b.sequence_bits,
                    b.log_bytes,
                ) {
                    return Err(Error::InvalidLog);
                }
                if a.current_lsn == b.current_lsn && !a.same_checkpoint(b) {
                    return Err(Error::InvalidLog);
                }
                // A flag-only transition cannot make the surviving dirty copy clean.
                if a.current_lsn > b.current_lsn
                    || (a.current_lsn == b.current_lsn && (!a.clean_shutdown || b.clean_shutdown))
                {
                    (a, log[..system].to_vec())
                } else {
                    (b, log[system..system * RESTART_COPY_COUNT as usize].to_vec())
                }
            }
            (Ok(a), Err(_)) => (a, log[..system].to_vec()),
            (Err(_), Ok(b)) => (b, log[system..system * RESTART_COPY_COUNT as usize].to_vec()),
            _ => return Err(Error::InvalidLog),
        };
        if !matches!(
            (restart.major_version, restart.minor_version),
            (page_layout::VERSION_LEGACY, page_layout::MINOR_LEGACY)
                | (page_layout::VERSION_CURRENT, page_layout::MINOR_CURRENT)
        ) || restart.chkdsk_marker
            || restart.log_bytes != log.len() as u64
        {
            return Err(Error::Unsupported);
        }
        let size = restart.log_page_bytes as usize;
        let first = (if restart.major_version == page_layout::VERSION_LEGACY {
            page_layout::LEGACY_FIRST_RECORD_PAGE
        } else {
            page_layout::CURRENT_FIRST_RECORD_PAGE
        }) * size;
        if system != size || first >= log.len() {
            return Err(Error::Unsupported);
        }
        let client = restart.client.ok_or(Error::InvalidLog)?;
        if client.oldest_lsn == lfs::NO_LSN
            || client.oldest_lsn > client.restart_lsn
            || client.restart_lsn > restart.current_lsn
        {
            return Err(Error::InvalidLog);
        }
        let bits = u64::BITS - restart.sequence_bits;
        let oldest_generation = client.oldest_lsn >> bits;
        let current_generation = restart.current_lsn >> bits;
        if current_generation.saturating_sub(oldest_generation) > MAX_HISTORY_GENERATION_DISTANCE {
            return Err(Error::InvalidLog);
        }
        let mut pages = PageIndex::new(log.len(), size)?;
        for at in (first..log.len()).step_by(size) {
            if let Ok((_, page)) = parse_page(&mut log[at..at + size], at, restart, sector, false) {
                pages.insert(at as u64, page)?;
            }
        }
        let mut tail_pages = 0;
        for at in (system * RESTART_COPY_COUNT as usize..first).step_by(size) {
            let Ok((target, page)) = parse_page(&mut log[at..at + size], at, restart, sector, true) else {
                continue;
            };
            if page.last.max(page.end) < client.oldest_lsn {
                continue;
            }
            if target < first as u64 || target % size as u64 != 0 || target + size as u64 > log.len() as u64 {
                return Err(Error::InvalidLog);
            }
            let replace = match pages.get(target)? {
                None => true,
                Some(old) => {
                    let rank = (page.last, page.end, page.next);
                    let old_rank = (old.last, old.end, old.next);
                    if rank == old_rank {
                        // USA sequence arrays may differ; compare actual record bytes.
                        let begin = usize::from(restart.record_data_offset);
                        let end = if page.ends { page.next } else { size };
                        if log[page.storage_at + begin..page.storage_at + end]
                            != log[old.storage_at + begin..old.storage_at + end]
                        {
                            return Err(Error::InvalidLog);
                        }
                    }
                    rank > old_rank
                }
            };
            if replace {
                pages.insert(target, page)?;
                tail_pages += 1;
            }
        }
        let reader = Reader { restart, pages, first: first as u64, log };
        let (cp_raw, _, _) = reader.record(client.restart_lsn)?;
        let cp_record = LfsRecord::parse(&cp_raw)?;
        if cp_record.record_type != lfs::CHECKPOINT_RECORD {
            return Err(Error::InvalidLog);
        }
        let cp = NtfsCheckpoint::parse(cp_record.payload())?;
        let mut opens = OpenAttributeStore::new()?;
        let mut transactions = TransactionSeedStore::new()?;
        let mut dirty = RecordStore::new().io()?;
        let mut occupied_pages = PageBits::new(log.len(), size)?;
        let mut named_slots = BTreeSet::new();
        for (lsn, length, code) in [
            (cp.open_attributes_lsn, cp.open_attributes_bytes, operation::OPEN_ATTRIBUTE_TABLE_DUMP),
            (cp.attribute_names_lsn, cp.attribute_names_bytes, operation::ATTRIBUTE_NAMES_DUMP),
            (cp.dirty_pages_lsn, cp.dirty_pages_bytes, operation::DIRTY_PAGE_TABLE_DUMP),
            (cp.transactions_lsn, cp.transactions_bytes, operation::TRANSACTION_TABLE_DUMP),
        ] {
            if lsn == lfs::NO_LSN {
                continue;
            }
            if lsn > client.restart_lsn || lsn < client.oldest_lsn {
                return Err(Error::InvalidLog);
            }
            let (raw, _, pages) = reader.record(lsn)?;
            for at in pages.positions() {
                occupied_pages.insert(at)?;
            }
            let op = LfsRecord::parse(&raw)?.ntfs_operation()?;
            if op.redo_code != code || op.redo.len() != length as usize {
                return Err(Error::InvalidLog);
            }
            if code == operation::ATTRIBUTE_NAMES_DUMP {
                let mut at = 0;
                while at < op.redo.len() {
                    let id = u16_at(op.redo, at)?;
                    let n = usize::from(u16_at(op.redo, at + ATTRIBUTE_NAME_LENGTH_OFFSET)?);
                    if id == 0 && n == 0 {
                        if op.redo[at..].iter().any(|&b| b != 0) {
                            return Err(Error::InvalidLog);
                        }
                        break;
                    }
                    if n % CODE_UNIT_BYTES != 0
                        || at + ATTRIBUTE_NAME_FIXED_BYTES + n > op.redo.len()
                        || op.redo[at + ATTRIBUTE_NAME_HEADER_BYTES + n..at + ATTRIBUTE_NAME_FIXED_BYTES + n]
                            != [0; ATTRIBUTE_NAME_TRAILER_BYTES]
                        || !named_slots.insert(id)
                    {
                        return Err(Error::InvalidLog);
                    }
                    let mut target = opens.get(id)?.ok_or(Error::InvalidLog)?;
                    if !target.name.is_empty() {
                        return Err(Error::InvalidLog);
                    }
                    target.name =
                        op.redo[at + ATTRIBUTE_NAME_HEADER_BYTES..at + ATTRIBUTE_NAME_HEADER_BYTES + n].to_vec();
                    opens.insert(id, target)?;
                    at += ATTRIBUTE_NAME_FIXED_BYTES + n;
                }
            } else {
                RestartTable::parse(op.redo)?.visit_slots(|id, entry| {
                    match code {
                        operation::OPEN_ATTRIBUTE_TABLE_DUMP => {
                            opens.insert(
                                u16::try_from(id).map_err(|_| Error::Overflow)?,
                                open_entry(entry, cp.major_version)?,
                            )?;
                        }
                        operation::TRANSACTION_TABLE_DUMP => {
                            if entry.len() != TRANSACTION_ENTRY_BYTES
                                || !matches!(entry[SEED_STATE_OFFSET], TRANSACTION_ACTIVE..=TRANSACTION_COMMITTED)
                            {
                                return Err(Error::InvalidLog);
                            }
                            let seed = TransactionSeed {
                                state: entry[SEED_STATE_OFFSET],
                                first: u64_at(entry, SEED_FIRST_OFFSET)?,
                                previous: u64_at(entry, SEED_PREVIOUS_OFFSET)?,
                                undo: u64_at(entry, SEED_UNDO_OFFSET)?,
                            };
                            if seed.first > seed.previous
                                || seed.previous > client.restart_lsn
                                || seed.undo > seed.previous
                            {
                                return Err(Error::InvalidLog);
                            }
                            transactions.insert(id, seed)?;
                        }
                        operation::DIRTY_PAGE_TABLE_DUMP => {
                            let n = u32_at(entry, DIRTY_ENTRY_COUNT_OFFSET)? as usize;
                            let off = if cp.major_version == OPEN_ENTRY_VERSION_LEGACY {
                                DIRTY_ENTRY_LEGACY_VCN_OFFSET
                            } else {
                                DIRTY_ENTRY_CURRENT_VCN_OFFSET
                            };
                            if n == 0 || off + DIRTY_ENTRY_LCN_OFFSET + n * WORD_BYTES > entry.len() {
                                return Err(Error::InvalidLog);
                            }
                            let target = u16::try_from(u32_at(entry, DIRTY_ENTRY_TARGET_OFFSET)?)
                                .map_err(|_| Error::InvalidLog)?;
                            let page = DirtyPage {
                                target,
                                bytes: u32_at(entry, DIRTY_ENTRY_BYTES_OFFSET)?,
                                vcn: u64_at(entry, off)?,
                                oldest: u64_at(entry, off + WORD_BYTES)?,
                                lcns: (0..n)
                                    .map(|i| u64_at(entry, off + DIRTY_ENTRY_LCN_OFFSET + i * WORD_BYTES))
                                    .collect::<Result<Vec<_>>>()?,
                            };
                            if opens.get(target)?.is_none()
                                || page.oldest < client.oldest_lsn
                                || page.oldest > client.restart_lsn
                                || page.bytes == 0
                            {
                                return Err(Error::InvalidLog);
                            }
                            dirty.push(&page.encode()).io()?;
                        }
                        _ => return Err(Error::InvalidLog),
                    }
                    Ok(())
                })?;
            }
        }
        let mut records = RecordStore::new().io()?;
        let mut lsn = client.oldest_lsn;
        let mut last = 0;
        let mut saw_restart = false;
        let mut end_page = 0;
        let mut history_bytes = 0usize;
        loop {
            if last != 0 && lsn <= last {
                return Err(Error::InvalidLog);
            }
            let result = reader.record(lsn);
            let (raw, next, pages) = match result {
                Ok(r) => r,
                Err(e) => {
                    if last < restart.current_lsn {
                        return Err(e);
                    }
                    break;
                }
            };
            let r = LfsRecord::parse(&raw)?;
            if r.this_lsn <= last
                || (r.this_lsn >> bits).saturating_sub(oldest_generation) > MAX_HISTORY_GENERATION_DISTANCE
            {
                return Err(Error::InvalidLog);
            }
            // Unpublished checkpoint is not adopted as a new authoritative restart.
            if lsn > restart.current_lsn && r.record_type == lfs::CHECKPOINT_RECORD {
                break;
            }
            for at in pages.positions() {
                occupied_pages.insert(at)?;
            }
            end_page = if next & ((1_u64 << (u64::BITS - restart.sequence_bits)) - 1)
                == (reader.first + u64::from(restart.record_data_offset)) / lfs::LSN_OFFSET_UNIT_BYTES
            {
                restart.log_bytes - size as u64
            } else {
                let next_at = reader.offset(next)?;
                if next_at % size as u64 == u64::from(restart.record_data_offset) {
                    next_at / size as u64 * size as u64 - size as u64
                } else {
                    next_at / size as u64 * size as u64
                }
            };
            history_bytes = history_bytes.checked_add(raw.len()).ok_or(Error::Overflow)?;
            if history_bytes > log.len() - first {
                return Err(Error::InvalidLog);
            }
            last = lsn;
            saw_restart |= lsn == client.restart_lsn;
            records.push(&raw).io()?;
            lsn = next;
        }
        if last < restart.current_lsn || !saw_restart {
            return Err(Error::InvalidLog);
        }
        // A hole before a newer valid page is not an end-of-log proof. Only the
        // immediately following independent, unpublished empty checkpoint can be
        // ignored. Never discard an unseen durable commit after a damaged page.
        let mut discarded_pages = PageBits::new(log.len(), size)?;
        for slot in 0..reader.pages.slots {
            let at = slot * size as u64;
            let Some(p) = reader.pages.get(at)? else {
                continue;
            };
            if p.end.max(p.last) <= last || occupied_pages.contains(at)? {
                continue;
            }
            let pending = reader.record(lsn).ok().and_then(|(raw, _, pages)| {
                let r = LfsRecord::parse(&raw).ok()?;
                if r.record_type != lfs::CHECKPOINT_RECORD
                    || r.transaction_id != lfs::NO_TRANSACTION_ID
                    || r.previous_lsn != lfs::NO_LSN
                    || r.undo_next_lsn != lfs::NO_LSN
                    || !pages.contains(at)
                {
                    return None;
                }
                let c = NtfsCheckpoint::parse(r.payload()).ok()?;
                if c.open_attributes_lsn != lfs::NO_LSN
                    || c.attribute_names_lsn != lfs::NO_LSN
                    || c.dirty_pages_lsn != lfs::NO_LSN
                    || c.transactions_lsn != lfs::NO_LSN
                {
                    return None;
                }
                Some(())
            });
            if pending.is_none() {
                // Writes after the published head may be an incomplete, reordered
                // loser tail. No target may depend on an unflushed log record.
                // Permit only update/open records here: a commit, compensation,
                // checkpoint or unknown operation beyond a hole is still fatal.
                if p.last <= restart.current_lsn {
                    return Err(Error::InvalidLog);
                }
                if p.count > FIRST_GROUP_POSITION {
                    let first = reader.offset(p.last)? / size as u64 * size as u64;
                    if let Some(head) = reader.pages.get(first)?.filter(|head| head.last == p.last) {
                        let raw = &reader.bytes(&head)[usize::from(restart.record_data_offset)..];
                        let total = LfsRecord::peek_total_bytes(raw)?;
                        // Even if a transfer is incomplete, its surviving first
                        // sector identifies a full-image update, never a commit.
                        if total <= size - usize::from(restart.record_data_offset)
                            || u64_at(raw, lfs::THIS_LSN_OFFSET)? != p.last
                            || u32_at(raw, lfs::TYPE_OFFSET)? != lfs::UPDATE_RECORD
                            || u16_at(raw, lfs::FLAGS_OFFSET)? & lfs::MULTI_PAGE == 0
                            || u16_at(raw, lfs::CLIENT_SEQUENCE_OFFSET)? != client.sequence
                            || u16_at(raw, lfs::CLIENT_INDEX_OFFSET)? != client.index
                            || !matches!(
                                u16_at(raw, lfs::HEADER_BYTES + operation::REDO_CODE_OFFSET)?,
                                operation::INITIALIZE_FILE_RECORD | operation::UPDATE_NONRESIDENT_VALUE
                            )
                            || u16_at(raw, lfs::HEADER_BYTES + operation::UNDO_CODE_OFFSET)? == operation::COMPENSATION
                        {
                            return Err(Error::InvalidLog);
                        }
                    } else if p.position == FIRST_GROUP_POSITION {
                        return Err(Error::InvalidLog);
                    }
                    discarded_pages.insert(at)?;
                    continue;
                }
                let mut cursor = usize::from(restart.record_data_offset);
                while cursor < p.next {
                    let r = LfsRecord::parse(&reader.bytes(&p)[cursor..])?;
                    let op = r.ntfs_operation()?;
                    if r.this_lsn <= restart.current_lsn
                        || r.record_type != lfs::UPDATE_RECORD
                        || r.client_index != client.index
                        || r.client_sequence != client.sequence
                        || !(super::transactions::metadata(op.redo_code)
                            || op.redo_code == operation::OPEN_NONRESIDENT_ATTRIBUTE)
                        || op.undo_code == operation::COMPENSATION
                    {
                        return Err(Error::InvalidLog);
                    }
                    cursor += (r.raw().len() + lfs::ALIGNMENT - 1) & !(lfs::ALIGNMENT - 1);
                }
                discarded_pages.insert(at)?;
            }
        }
        let mut restart = restart;
        restart.current_lsn = last;
        Ok(History {
            records,
            restart,
            template,
            opens,
            transactions,
            dirty,
            tail_pages,
            checkpoint_lsn: client.restart_lsn,
            occupied_pages,
            discarded_pages,
            end_page,
        })
    }
}

pub(super) mod transactions {
    use super::CoreIo;

    use super::checker::consistency::{inventory_find, inventory_write, scratch_file};
    use super::log::TransactionSeedStore;
    use super::storage::{read_words, write_words, RecordStore, WORD_BYTES};
    use ntfs_rs::logfile::LfsRecord;
    use ntfs_rs::{Error, Result};
    use std::fs::File;
    use std::io::{Seek, SeekFrom};

    use super::log::{TRANSACTION_ACTIVE, TRANSACTION_COMMITTED, TRANSACTION_ENTRY_BYTES, TRANSACTION_PREPARED};
    use ntfs_rs::logfile::{lfs_layout as lfs, log_operation as operation};
    const ACTIVE_EPOCH_ABSENT: u64 = 0;
    const ACTIVE_EPOCH_BIAS: u64 = 1;
    const OWNER_EPOCH_WORD: usize = 1;
    const RECORD_INDEX_WORD: usize = 1;
    const ACTIVE_LIVE_WORD: usize = 0;
    const ACTIVE_SEEDED_WORD: usize = 1;
    const UNDO_HEAP_WORDS: usize = 2;
    const UNDO_HEAP_BYTES: usize = UNDO_HEAP_WORDS * WORD_BYTES;
    const TX_FIRST_OFFSET: usize = 0;
    const TX_PREVIOUS_OFFSET: usize = WORD_BYTES;
    const TX_UNDO_OFFSET: usize = TX_PREVIOUS_OFFSET + WORD_BYTES;
    const TX_STATE_OFFSET: usize = TX_UNDO_OFFSET + WORD_BYTES;
    const TX_CLOSED_OFFSET: usize = TX_STATE_OFFSET + 1;
    const TX_RESERVED_OFFSET: usize = TX_CLOSED_OFFSET + 1;
    const TX_ROW_BYTES: usize = 4 * WORD_BYTES;
    use super::ENCODED_BOOL_TRUE;
    const TRANSACTION_TABLE_HEADER_BYTES: u32 = 24;
    const TRANSACTION_SLOT_WORDS: usize = 2;
    const TRANSACTION_SLOT_BYTES: u64 = (TRANSACTION_SLOT_WORDS * WORD_BYTES) as u64;

    // Transaction IDs are native restart-table slot numbers. Sparse direct slots
    // retain only epoch numbers, with zero representing absence. No log contents
    // or transaction bodies are stored in this lookup file.
    struct ActiveIds(File);
    impl ActiveIds {
        fn new() -> Result<Self> {
            Ok(Self(scratch_file().io()?))
        }
        fn read(&mut self, id: u32) -> Result<[u64; TRANSACTION_SLOT_WORDS]> {
            let offset = u64::from(id) * TRANSACTION_SLOT_BYTES;
            if self.0.metadata().io()?.len() < offset + TRANSACTION_SLOT_BYTES {
                return Ok([0; TRANSACTION_SLOT_WORDS]);
            }
            read_words(&mut self.0, offset).io()
        }
        fn write(&mut self, id: u32, row: [u64; TRANSACTION_SLOT_WORDS]) -> Result<()> {
            write_words(&mut self.0, u64::from(id) * TRANSACTION_SLOT_BYTES, row).io()
        }
        fn live(&mut self, id: u32) -> Result<Option<usize>> {
            let word = self.read(id)?[ACTIVE_LIVE_WORD];
            if word == ACTIVE_EPOCH_ABSENT {
                Ok(None)
            } else {
                usize::try_from(word - ACTIVE_EPOCH_BIAS).map(Some).map_err(|_| Error::Overflow)
            }
        }
        fn seeded(&mut self, id: u32) -> Result<Option<usize>> {
            let word = self.read(id)?[ACTIVE_SEEDED_WORD];
            if word == ACTIVE_EPOCH_ABSENT {
                Ok(None)
            } else {
                usize::try_from(word - ACTIVE_EPOCH_BIAS).map(Some).map_err(|_| Error::Overflow)
            }
        }
        fn set_live(&mut self, id: u32, epoch: Option<usize>) -> Result<()> {
            let mut row = self.read(id)?;
            row[ACTIVE_LIVE_WORD] = match epoch {
                Some(n) => (n as u64).checked_add(ACTIVE_EPOCH_BIAS).ok_or(Error::Overflow)?,
                None => ACTIVE_EPOCH_ABSENT,
            };
            self.write(id, row)
        }
        fn set_seeded(&mut self, id: u32, epoch: usize) -> Result<()> {
            let mut row = self.read(id)?;
            row[ACTIVE_SEEDED_WORD] = (epoch as u64).checked_add(ACTIVE_EPOCH_BIAS).ok_or(Error::Overflow)?;
            self.write(id, row)
        }
    }

    // Max-heap of unfinished undo-chain heads. A heap level holds only two
    // fixed-width words, even when many transactions are simultaneously active.
    struct UndoHeap {
        file: File,
        len: u64,
    }
    impl UndoHeap {
        fn new() -> Result<Self> {
            Ok(Self { file: scratch_file().io()?, len: 0 })
        }
        fn get(&mut self, index: u64) -> Result<(u64, u64)> {
            if index >= self.len {
                return Err(Error::InvalidLog);
            }
            let offset = index.checked_mul(UNDO_HEAP_BYTES as u64).ok_or(Error::Overflow)?;
            let [lsn, epoch] = read_words(&mut self.file, offset).io()?;
            Ok((lsn, epoch))
        }
        fn set(&mut self, index: u64, entry: (u64, u64)) -> Result<()> {
            let offset = index.checked_mul(UNDO_HEAP_BYTES as u64).ok_or(Error::Overflow)?;
            write_words(&mut self.file, offset, [entry.0, entry.1]).io()
        }
        fn push(&mut self, entry: (u64, usize)) -> Result<()> {
            let entry = (entry.0, entry.1 as u64);
            let mut child = self.len;
            self.len += 1;
            while child > 0 {
                let parent = (child - 1) / 2;
                let value = self.get(parent)?;
                if value >= entry {
                    break;
                }
                self.set(child, value)?;
                child = parent;
            }
            self.set(child, entry)
        }
        fn pop(&mut self) -> Result<Option<(u64, usize)>> {
            if self.len == 0 {
                return Ok(None);
            }
            let top = self.get(0)?;
            let tail = self.get(self.len - 1)?;
            self.len -= 1;
            if self.len > 0 {
                let mut parent = 0;
                while parent < self.len / 2 {
                    let left = parent * 2 + 1;
                    let right = left + 1;
                    let child = if right < self.len && self.get(right)? > self.get(left)? { right } else { left };
                    let value = self.get(child)?;
                    if value <= tail {
                        break;
                    }
                    self.set(parent, value)?;
                    parent = child;
                }
                self.set(parent, tail)?;
            }
            Ok(Some((top.0, top.1 as usize)))
        }
    }

    #[derive(Clone, Debug)]
    struct Tx {
        first: u64,
        previous: u64,
        undo: u64,
        state: u8,
        closed: bool,
    }
    impl Tx {
        fn encode(&self) -> [u8; TX_ROW_BYTES] {
            let mut row = [0; TX_ROW_BYTES];
            row[TX_FIRST_OFFSET..TX_PREVIOUS_OFFSET].copy_from_slice(&self.first.to_le_bytes());
            row[TX_PREVIOUS_OFFSET..TX_UNDO_OFFSET].copy_from_slice(&self.previous.to_le_bytes());
            row[TX_UNDO_OFFSET..TX_STATE_OFFSET].copy_from_slice(&self.undo.to_le_bytes());
            row[TX_STATE_OFFSET] = self.state;
            row[TX_CLOSED_OFFSET] = u8::from(self.closed);
            row
        }
        fn decode(row: &[u8]) -> Result<Self> {
            if row.len() != TX_ROW_BYTES
                || row[TX_RESERVED_OFFSET..].iter().any(|&b| b != 0)
                || row[TX_CLOSED_OFFSET] > ENCODED_BOOL_TRUE
            {
                return Err(Error::InvalidLog);
            }
            Ok(Self {
                first: u64::from_le_bytes(row[TX_FIRST_OFFSET..TX_PREVIOUS_OFFSET].try_into().unwrap()),
                previous: u64::from_le_bytes(row[TX_PREVIOUS_OFFSET..TX_UNDO_OFFSET].try_into().unwrap()),
                undo: u64::from_le_bytes(row[TX_UNDO_OFFSET..TX_STATE_OFFSET].try_into().unwrap()),
                state: row[TX_STATE_OFFSET],
                closed: row[TX_CLOSED_OFFSET] != 0,
            })
        }
    }
    pub struct Schedule {
        pub redo: RecordStore,
        pub undo: RecordStore,
        pub epochs: usize,
        pub compensated: usize,
    }
    pub fn metadata(code: u16) -> bool {
        matches!(code, operation::INITIALIZE_FILE_RECORD..=operation::UPDATE_MAPPING_PAIRS | operation::SET_NEW_ATTRIBUTE_SIZES..=operation::CLEAR_BITMAP_BITS | operation::UPDATE_RECORD_DATA_ROOT..=operation::ZERO_FILE_RECORD_TAIL)
    }

    pub fn analyze(raw: &RecordStore, checkpoint: u64, seeds: &TransactionSeedStore) -> Result<Schedule> {
        let mut index = scratch_file().io()?;
        let mut last_index_lsn = 0;
        for i in 0..raw.len() {
            let bytes = raw.view(i).io()?;
            let r = LfsRecord::parse(&bytes)?;
            if r.this_lsn <= last_index_lsn {
                return Err(Error::InvalidLog);
            }
            last_index_lsn = r.this_lsn;
            inventory_write(&mut index, [r.this_lsn, i as u64, 0, 0]).io()?;
        }
        let mut active = ActiveIds::new()?;
        let mut txs = RecordStore::new().io()?;
        seeds.for_each(|id, s| {
            if inventory_find(&mut index, s.first).io()?.is_none() {
                let epoch = txs.len();
                active.set_live(id, Some(epoch))?;
                active.set_seeded(id, epoch)?;
                txs.push(
                    &Tx { first: s.first, previous: s.previous, undo: s.undo, state: s.state, closed: false }.encode(),
                )
                .io()?;
            }
            Ok(())
        })?;
        let mut owner = scratch_file().io()?;
        let mut redo = RecordStore::new().io()?;
        let mut finished = std::collections::BTreeSet::new();
        let mut compensated = 0;
        let mut prior = 0;
        for i in 0..raw.len() {
            let bytes = raw.view(i).io()?;
            let r = LfsRecord::parse(&bytes)?;
            if r.this_lsn <= prior {
                return Err(Error::InvalidLog);
            }
            prior = r.this_lsn;
            if r.record_type == lfs::CHECKPOINT_RECORD {
                continue;
            }
            let op = r.ntfs_operation()?;
            if matches!(op.redo_code, operation::OPEN_ATTRIBUTE_TABLE_DUMP..=operation::TRANSACTION_TABLE_DUMP)
                && r.transaction_id == lfs::NO_TRANSACTION_ID
            {
                continue;
            }
            if r.transaction_id < TRANSACTION_TABLE_HEADER_BYTES
                || (r.transaction_id - TRANSACTION_TABLE_HEADER_BYTES) % TRANSACTION_ENTRY_BYTES as u32 != 0
            {
                return Err(Error::InvalidLog);
            }
            if let Some(epoch) = active.seeded(r.transaction_id)?.filter(|_| r.this_lsn <= checkpoint) {
                if r.this_lsn < Tx::decode(&txs.get(epoch).io()?)?.first {
                    return Err(Error::InvalidLog);
                }
                owner.seek(SeekFrom::End(0)).io()?;
                inventory_write(&mut owner, [r.this_lsn, epoch as u64, 0, 0]).io()?;
                if metadata(op.redo_code) {
                    redo.push(&(i as u64).to_le_bytes()).io()?;
                }
                continue;
            }
            // A transaction that finished before the checkpoint is absent from
            // its transaction table, and its earlier records precede the log
            // window. Its changes are committed intent: redo them where pages
            // are still dirty, never undo. A fresh transaction reusing the slot
            // starts with no previous LSN and is analysed normally.
            if r.previous_lsn == lfs::NO_LSN {
                finished.remove(&r.transaction_id);
            } else if r.this_lsn < checkpoint
                && active.live(r.transaction_id)?.is_none()
                && (finished.contains(&r.transaction_id) || inventory_find(&mut index, r.previous_lsn).io()?.is_none())
            {
                finished.insert(r.transaction_id);
                if metadata(op.redo_code) {
                    redo.push(&(i as u64).to_le_bytes()).io()?;
                }
                continue;
            }
            // Windows reuses a transaction slot only after its transaction
            // completed, so a new chain (no previous LSN) in a live slot ends
            // the previous occupant as committed; it is never undone.
            if r.previous_lsn == lfs::NO_LSN {
                if let Some(old) = active.live(r.transaction_id)? {
                    let mut done = Tx::decode(&txs.get(old).io()?)?;
                    done.state = TRANSACTION_COMMITTED;
                    done.closed = true;
                    txs.replace(old, &done.encode()).io()?;
                    active.set_live(r.transaction_id, None)?;
                }
            }
            let epoch = match active.live(r.transaction_id)? {
                Some(epoch) => epoch,
                None => {
                    if r.previous_lsn != lfs::NO_LSN {
                        return Err(Error::InvalidLog);
                    }
                    let epoch = txs.len();
                    active.set_live(r.transaction_id, Some(epoch))?;
                    txs.push(
                        &Tx {
                            first: r.this_lsn,
                            previous: lfs::NO_LSN,
                            undo: lfs::NO_LSN,
                            state: TRANSACTION_ACTIVE,
                            closed: false,
                        }
                        .encode(),
                    )
                    .io()?;
                    epoch
                }
            };
            let mut tx = Tx::decode(&txs.get(epoch).io()?)?;
            if r.previous_lsn != tx.previous
                || tx.closed
                || (tx.state == TRANSACTION_COMMITTED && op.redo_code != operation::FORGET_TRANSACTION)
            {
                return Err(Error::InvalidLog);
            }
            if op.undo_code != operation::COMPENSATION
                && !matches!(
                    op.redo_code,
                    operation::COMPENSATION | operation::END_TOP_LEVEL_ACTION | operation::FORGET_TRANSACTION
                )
                && r.undo_next_lsn != tx.undo
            {
                return Err(Error::InvalidLog);
            }
            if r.undo_next_lsn != lfs::NO_LSN
                && (r.undo_next_lsn >= r.this_lsn
                    || r.undo_next_lsn < tx.first
                    || inventory_find(&mut owner, r.undo_next_lsn).io()?.map(|row| row[OWNER_EPOCH_WORD])
                        != Some(epoch as u64))
            {
                return Err(Error::InvalidLog);
            }
            owner.seek(SeekFrom::End(0)).io()?;
            inventory_write(&mut owner, [r.this_lsn, epoch as u64, 0, 0]).io()?;
            tx.previous = r.this_lsn;
            if op.undo_code == operation::COMPENSATION
                || op.redo_code == operation::COMPENSATION
                || op.redo_code == operation::END_TOP_LEVEL_ACTION
            {
                tx.undo = r.undo_next_lsn;
                compensated += 1;
            } else {
                tx.undo = r.this_lsn;
            }
            match op.redo_code {
                operation::PREPARE_TRANSACTION => {
                    if tx.state != TRANSACTION_ACTIVE {
                        return Err(Error::InvalidLog);
                    }
                    tx.state = TRANSACTION_PREPARED;
                }
                operation::COMMIT_TRANSACTION => tx.state = TRANSACTION_COMMITTED,
                operation::FORGET_TRANSACTION => {
                    if tx.state != TRANSACTION_COMMITTED && r.undo_next_lsn != lfs::NO_LSN {
                        return Err(Error::InvalidLog);
                    }
                    tx.closed = true;
                    active.set_live(r.transaction_id, None)?;
                }
                operation::NOOP
                | operation::COMPENSATION
                | operation::DELETE_DIRTY_CLUSTERS
                | operation::HOT_FIX
                | operation::END_TOP_LEVEL_ACTION
                | operation::OPEN_NONRESIDENT_ATTRIBUTE..=operation::TRANSACTION_TABLE_DUMP => {}
                code if metadata(code) => redo.push(&(i as u64).to_le_bytes()).io()?,
                _ => return Err(Error::Unsupported),
            }
            txs.replace(epoch, &tx.encode()).io()?;
        }
        let mut heap = UndoHeap::new()?;
        for epoch in 0..txs.len() {
            let tx = Tx::decode(&txs.get(epoch).io()?)?;
            // An unresolved prepared transaction cannot be replayed safely.
            if tx.state == TRANSACTION_PREPARED && !tx.closed {
                return Err(Error::Unsupported);
            }
            if tx.state == TRANSACTION_ACTIVE && !tx.closed && tx.undo != lfs::NO_LSN {
                heap.push((tx.undo, epoch))?;
            }
        }
        let mut undo = RecordStore::new().io()?;
        while let Some((lsn, epoch)) = heap.pop()? {
            // Each epoch contributes one chain. Every next LSN is strictly lower,
            // so a chain cannot cycle; the owner lookup rejects cross-epoch joins.
            if inventory_find(&mut owner, lsn).io()?.map(|row| row[OWNER_EPOCH_WORD]) != Some(epoch as u64) {
                return Err(Error::InvalidLog);
            }
            let i = (inventory_find(&mut index, lsn).io()?.ok_or(Error::InvalidLog)?[RECORD_INDEX_WORD]) as usize;
            let bytes = raw.view(i).io()?;
            let r = LfsRecord::parse(&bytes)?;
            let op = r.ntfs_operation()?;
            if metadata(op.undo_code) {
                undo.push(&(i as u64).to_le_bytes()).io()?;
            }
            let next = r.undo_next_lsn;
            if next != lfs::NO_LSN {
                if next >= lsn {
                    return Err(Error::InvalidLog);
                }
                heap.push((next, epoch))?;
            }
        }
        Ok(Schedule { redo, undo, epochs: txs.len(), compensated })
    }
}

pub(super) mod dirty {
    use super::log::{DirtyPage, History, OpenAttribute};
    use super::storage::{read_words, write_words, RecordStore, WORD_BYTES};
    use super::transactions;
    use super::CoreIo;
    use ntfs_rs::bytes::u64_at;
    use ntfs_rs::logfile::{LfsRecord, NtfsLogOperation};
    use ntfs_rs::{Error, Result};
    use std::collections::hash_map::RandomState;
    use std::fs::File;
    use std::hash::BuildHasher;

    use super::{SCRATCH_CAPACITY_GROWTH, SCRATCH_INITIAL_CAPACITY, SCRATCH_LOAD_DENOMINATOR};
    use ntfs_rs::logfile::{lfs_layout as lfs, log_operation as operation};
    const DIRTY_KEY_HEADER_BYTES: usize = 2 * WORD_BYTES + 2 * std::mem::size_of::<u32>();
    const DIRTY_HASH_WORD: usize = 0;
    const DIRTY_KEY_WORD: usize = 1;
    const DIRTY_LCN_WORD: usize = 2;
    const DIRTY_OLDEST_WORD: usize = 3;
    const DIRTY_OCCUPIED_WORD: usize = 4;
    const DIRTY_EMPTY: u64 = 0;
    const CLUSTER_RANGE_START_OFFSET: usize = 0;
    const DIRTY_OCCUPIED: u64 = 1;
    const DIRTY_DISCARDED_LCN: u64 = 0;
    const CLUSTER_RANGE_BYTES: usize = 2 * WORD_BYTES;
    const DIRTY_SLOT_WORDS: usize = 5;
    const DIRTY_SLOT_BYTES: u64 = (DIRTY_SLOT_WORDS * WORD_BYTES) as u64;

    #[derive(Clone, Copy)]
    struct Cell {
        lcn: u64,
        oldest: u64,
    }

    // Private exact-key table. Each collision checks the full stored key. Growth
    // copies fixed-width slots on disk, not an inventory of keys through RAM.
    pub struct DirtyMappings {
        slots: File,
        keys: RecordStore,
        capacity: u64,
        count: u64,
        hasher: RandomState,
    }

    fn key(open: &OpenAttribute, vcn: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(DIRTY_KEY_HEADER_BYTES + open.name.len());
        out.extend_from_slice(&open.reference.to_le_bytes());
        out.extend_from_slice(&open.kind.to_le_bytes());
        out.extend_from_slice(&vcn.to_le_bytes());
        out.extend_from_slice(&(open.name.len() as u32).to_le_bytes());
        out.extend_from_slice(&open.name);
        out
    }
    fn read_slot(file: &mut File, position: u64) -> Result<[u64; DIRTY_SLOT_WORDS]> {
        let offset = position.checked_mul(DIRTY_SLOT_BYTES).ok_or(Error::Overflow)?;
        read_words(file, offset).io()
    }
    fn write_slot(file: &mut File, position: u64, row: [u64; DIRTY_SLOT_WORDS]) -> Result<()> {
        let offset = position.checked_mul(DIRTY_SLOT_BYTES).ok_or(Error::Overflow)?;
        write_words(file, offset, row).io()
    }
    impl DirtyMappings {
        fn new() -> Result<Self> {
            let slots = super::checker::consistency::scratch_file().io()?;
            slots.set_len(SCRATCH_INITIAL_CAPACITY * DIRTY_SLOT_BYTES).io()?;
            Ok(Self {
                slots,
                keys: RecordStore::new().io()?,
                capacity: SCRATCH_INITIAL_CAPACITY,
                count: 0,
                hasher: RandomState::new(),
            })
        }
        fn locate(&mut self, bytes: &[u8]) -> Result<(u64, Option<Cell>)> {
            let hashed = self.hasher.hash_one(bytes);
            let mut at = hashed & (self.capacity - 1);
            for _ in 0..self.capacity {
                let row = read_slot(&mut self.slots, at)?;
                if row[DIRTY_OCCUPIED_WORD] == DIRTY_EMPTY {
                    return Ok((at, None));
                }
                if row[DIRTY_HASH_WORD] == hashed && self.keys.get(row[DIRTY_KEY_WORD] as usize).io()? == bytes {
                    return Ok((at, Some(Cell { lcn: row[DIRTY_LCN_WORD], oldest: row[DIRTY_OLDEST_WORD] })));
                }
                at = (at + 1) & (self.capacity - 1);
            }
            Err(Error::Overflow)
        }
        fn grow(&mut self) -> Result<()> {
            let next = self.capacity.checked_mul(SCRATCH_CAPACITY_GROWTH).ok_or(Error::Overflow)?;
            let mut output = super::checker::consistency::scratch_file().io()?;
            output.set_len(next.checked_mul(DIRTY_SLOT_BYTES).ok_or(Error::Overflow)?).io()?;
            for position in 0..self.capacity {
                let row = read_slot(&mut self.slots, position)?;
                if row[DIRTY_OCCUPIED_WORD] == DIRTY_EMPTY {
                    continue;
                }
                let mut at = row[DIRTY_HASH_WORD] & (next - 1);
                loop {
                    if read_slot(&mut output, at)?[DIRTY_OCCUPIED_WORD] == DIRTY_EMPTY {
                        write_slot(&mut output, at, row)?;
                        break;
                    }
                    at = (at + 1) & (next - 1);
                }
            }
            self.slots = output;
            self.capacity = next;
            Ok(())
        }
        fn put(&mut self, bytes: &[u8], cell: Cell) -> Result<Option<Cell>> {
            let (mut position, mut old) = self.locate(bytes)?;
            if old.is_none() && self.count >= self.capacity / SCRATCH_LOAD_DENOMINATOR {
                self.grow()?;
                (position, old) = self.locate(bytes)?;
            }
            let key_index = if old.is_some() {
                read_slot(&mut self.slots, position)?[DIRTY_KEY_WORD]
            } else {
                let index = self.keys.len() as u64;
                self.keys.push(bytes).io()?;
                self.count += 1;
                index
            };
            write_slot(
                &mut self.slots,
                position,
                [self.hasher.hash_one(bytes), key_index, cell.lcn, cell.oldest, DIRTY_OCCUPIED],
            )?;
            Ok(old)
        }
        fn get(&mut self, bytes: &[u8]) -> Result<Option<Cell>> {
            Ok(self.locate(bytes)?.1)
        }

        pub fn analyze(h: &History, bound: &RecordStore, clusters: u64) -> Result<Self> {
            let mut result = Self::new()?;
            for number in 0..h.dirty.len() {
                let d = DirtyPage::decode(&h.dirty.get(number).io()?)?;
                let open = h.opens.get(d.target)?.ok_or(Error::InvalidLog)?;
                if d.bytes == 0 || d.lcns.is_empty() {
                    return Err(Error::InvalidLog);
                }
                for (i, &lcn) in d.lcns.iter().enumerate() {
                    if lcn >= clusters {
                        return Err(Error::InvalidLog);
                    }
                    let k = key(&open, d.vcn.checked_add(i as u64).ok_or(Error::Overflow)?);
                    if let Some(old) = result.put(&k, Cell { lcn, oldest: d.oldest })? {
                        if old.lcn != lcn || old.oldest != d.oldest {
                            return Err(Error::InvalidLog);
                        }
                    }
                }
            }
            for i in 0..h.records.len() {
                let raw = h.records.view(i).io()?;
                let r = LfsRecord::parse(&raw)?;
                if r.record_type == lfs::CHECKPOINT_RECORD || r.this_lsn <= h.checkpoint_lsn {
                    continue;
                }
                let op = r.ntfs_operation()?;
                match op.redo_code {
                    operation::DELETE_DIRTY_CLUSTERS => {
                        if op.redo.is_empty() || op.redo.len() % CLUSTER_RANGE_BYTES != 0 {
                            return Err(Error::InvalidLog);
                        }
                        for range in op.redo.chunks_exact(CLUSTER_RANGE_BYTES) {
                            let start = u64_at(range, CLUSTER_RANGE_START_OFFSET)?;
                            let count = u64_at(range, WORD_BYTES)?;
                            let end = start.checked_add(count).ok_or(Error::Overflow)?;
                            if count == 0 || end > clusters {
                                return Err(Error::InvalidLog);
                            }
                            for position in 0..result.capacity {
                                let mut row = read_slot(&mut result.slots, position)?;
                                if row[DIRTY_OCCUPIED_WORD] != DIRTY_EMPTY
                                    && row[DIRTY_LCN_WORD] >= start
                                    && row[DIRTY_LCN_WORD] < end
                                {
                                    row[DIRTY_LCN_WORD] = DIRTY_DISCARDED_LCN;
                                    write_slot(&mut result.slots, position, row)?;
                                }
                            }
                        }
                    }
                    operation::HOT_FIX => {
                        if op.lcns.len() != WORD_BYTES {
                            return Err(Error::InvalidLog);
                        }
                        let lcn = u64_at(op.lcns, 0)?;
                        if lcn == 0 || lcn >= clusters {
                            return Err(Error::InvalidLog);
                        }
                        let bytes = bound.get(i).io()?;
                        let open = OpenAttribute::decode(&bytes)?;
                        let k = key(&open, op.target_vcn);
                        if let Some(mut cell) = result.get(&k)? {
                            if cell.lcn != DIRTY_DISCARDED_LCN {
                                cell.lcn = lcn;
                                result.put(&k, cell)?;
                            }
                        }
                    }
                    code if transactions::metadata(code) => {
                        let bytes = bound.get(i).io()?;
                        let open = OpenAttribute::decode(&bytes)?;
                        for (c, raw) in op.lcns.chunks_exact(WORD_BYTES).enumerate() {
                            let lcn = u64_at(raw, 0)?;
                            if lcn == 0 || lcn >= clusters {
                                return Err(Error::InvalidLog);
                            }
                            let k = key(&open, op.target_vcn.checked_add(c as u64).ok_or(Error::Overflow)?);
                            let mut cell = result.get(&k)?.unwrap_or(Cell { lcn, oldest: r.this_lsn });
                            // Operations for one stream cluster must agree on its physical owner.
                            // Only HotFix or deallocation may redirect or clear the mapping;
                            // ordinary metadata cannot hide a corrupt logged LCN by remapping it.
                            if cell.lcn != DIRTY_DISCARDED_LCN && cell.lcn != lcn {
                                return Err(Error::InvalidLog);
                            }
                            if cell.lcn == DIRTY_DISCARDED_LCN {
                                cell.oldest = r.this_lsn;
                            }
                            cell.lcn = lcn;
                            result.put(&k, cell)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(result)
        }

        /// Zero marks a discarded or already-clean cluster. Keep the operation's
        /// logical offsets intact; callers may only mutate retained clusters.
        pub fn redo_lcns(&mut self, open: &OpenAttribute, op: NtfsLogOperation<'_>, lsn: u64) -> Result<Vec<u8>> {
            let mut out = Vec::with_capacity(op.lcns.len());
            for i in 0..op.lcns.len() / WORD_BYTES {
                let k = key(open, op.target_vcn.checked_add(i as u64).ok_or(Error::Overflow)?);
                let lcn = self.get(&k)?.filter(|c| lsn >= c.oldest).map_or(DIRTY_DISCARDED_LCN, |c| c.lcn);
                out.extend_from_slice(&lcn.to_le_bytes());
            }
            Ok(out)
        }
    }
}

pub(super) mod replay {
    use super::log::{self, History, OpenAttribute};
    use super::storage::{read_words, write_words, RecordStore, WORD_BYTES};
    use super::transactions;
    use super::CoreIo;
    use super::{checker, reject, Patch, ReplayPlan};
    use crate::recovery_io::overwrite_spans;
    use ntfs_rs::bytes::{u16_at, u32_at, u64_at};
    use ntfs_rs::logfile::*;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::mft::{Attribute, MftRecord};
    use ntfs_rs::volume::{ReadAt, Volume};
    use ntfs_rs::write_plan::{plan_nonresident_overwrite, plan_nonresident_recovery, WriteSpan};
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::io::{self, Seek, SeekFrom};

    use super::{BITMAP_BITS_PER_BYTE, FIXUP_WORD_BYTES, NTFS_SECTOR_BYTES};
    use ntfs_rs::logfile::{lfs_layout as lfs, log_operation as operation, log_page_layout as page_layout};
    use ntfs_rs::mft::{
        record_layout, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA, ATTR_INDEX_ALLOCATION,
    };
    const NO_MIRROR_OFFSET: u64 = u64::MAX;
    use ntfs_rs::filename_metadata::CODE_UNIT_BYTES;
    const EMPTY_HISTORY_RECORDS: usize = 1;
    // Reserve the original conservative operation-header/alignment workspace;
    // this capacity policy is independent of the enclosing record-page header.
    const OPERATION_BUFFER_OVERHEAD_BYTES: usize = 64;
    const MAX_REPLAY_TARGET_BYTES: usize = 64 * 1024;
    const MAX_INDEX_BLOCK_BYTES: usize = 64 * 1024;
    use super::{SCRATCH_CAPACITY_GROWTH, SCRATCH_INITIAL_CAPACITY, SCRATCH_LOAD_DENOMINATOR};
    const TARGET_HASH_MULTIPLIER: u64 = 0x9e37_79b9_7f4a_7c15;
    const TARGET_HASH_ROTATION: u32 = 23;
    const TARGET_PHYSICAL_WORD: usize = 0;
    const TARGET_SIZE_WORD: usize = 1;
    const TARGET_INDEX_WORD: usize = 2;
    const TARGET_ABSENT: u64 = 0;
    const TARGET_INDEX_BIAS: u64 = 1;
    const TARGET_MIRROR_OFFSET: usize = 0;
    const TARGET_MIRROR_INDEX_OFFSET: usize = WORD_BYTES;
    const TARGET_BEFORE_OFFSET: usize = TARGET_MIRROR_INDEX_OFFSET + WORD_BYTES;
    const TARGET_BYTES_OFFSET: usize = TARGET_BEFORE_OFFSET + WORD_BYTES;
    const TARGET_STATE_OFFSET: usize = TARGET_BYTES_OFFSET + WORD_BYTES;
    const TARGET_SPAN_COUNT_OFFSET: usize = TARGET_STATE_OFFSET + WORD_BYTES;
    const TARGET_KIND_OFFSET: usize = TARGET_SPAN_COUNT_OFFSET + WORD_BYTES;
    const TARGET_CHANGED_OFFSET: usize = TARGET_KIND_OFFSET + 1;
    const TARGET_UNDO_OFFSET: usize = TARGET_CHANGED_OFFSET + 1;
    const TARGET_RESERVED_OFFSET: usize = TARGET_UNDO_OFFSET + 1;
    const TARGET_RESERVED_BYTES: usize = 5;
    const TARGET_HEADER_BYTES: usize = TARGET_RESERVED_OFFSET + TARGET_RESERVED_BYTES;
    const TARGET_KIND_MFT: u8 = 0;
    const TARGET_KIND_INDEX: u8 = 1;
    const TARGET_KIND_RAW: u8 = 2;
    use super::ENCODED_BOOL_TRUE;
    const SPAN_PHYSICAL_OFFSET: usize = 0;
    const SPAN_SOURCE_OFFSET: usize = WORD_BYTES;
    const SPAN_LENGTH_OFFSET: usize = SPAN_SOURCE_OFFSET + WORD_BYTES;
    const SPAN_BYTES: usize = SPAN_LENGTH_OFFSET + WORD_BYTES;
    const BITMAP_RANGE_FIRST_OFFSET: usize = 0;
    const BITMAP_RANGE_COUNT_OFFSET: usize = std::mem::size_of::<u32>();
    const BITMAP_RANGE_BYTES: usize = 2 * std::mem::size_of::<u32>();
    const PAGE_LSN_OFFSET: usize = record_layout::LSN_OFFSET;
    const PAGE_LSN_END: usize = PAGE_LSN_OFFSET + WORD_BYTES;
    const INDEX_VCN_OFFSET: usize = 16;
    const INDEX_HEADER_OFFSET: usize = 24;
    const INDEX_USED_BYTES_OFFSET: usize = INDEX_HEADER_OFFSET + std::mem::size_of::<u32>();
    const INDEX_MIN_INITIALIZATION_BYTES: usize = 40;
    const MFT_SCAN_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
    const PROTECTED_LOG_RANGE: u64 = 1;
    const PROTECTED_MFT_RANGE: u64 = 2;
    const DISCARDED_PAGE_BYTE: u8 = 0xff;
    const TARGET_SLOT_WORDS: usize = 3;
    const TARGET_SLOT_BYTES: u64 = (TARGET_SLOT_WORDS * WORD_BYTES) as u64;

    #[derive(Clone, Copy, PartialEq)]
    enum ReplayTargetKind {
        Mft,
        Index,
        Raw,
    }

    // The same serialized word has two meanings. Keep that distinction in the
    // type so bitmap evidence can never be compared with a structured page LSN.
    #[derive(Clone, Copy)]
    enum ReplayState {
        Mft { lsn: u64 },
        Index { lsn: u64 },
        Raw { verified_sectors: u64 },
    }

    impl ReplayState {
        fn from_word(kind: ReplayTargetKind, word: u64) -> Self {
            match kind {
                ReplayTargetKind::Mft => Self::Mft { lsn: word },
                ReplayTargetKind::Index => Self::Index { lsn: word },
                ReplayTargetKind::Raw => Self::Raw { verified_sectors: word },
            }
        }

        fn kind(self) -> ReplayTargetKind {
            match self {
                Self::Mft { .. } => ReplayTargetKind::Mft,
                Self::Index { .. } => ReplayTargetKind::Index,
                Self::Raw { .. } => ReplayTargetKind::Raw,
            }
        }

        fn word(self) -> u64 {
            match self {
                Self::Mft { lsn } | Self::Index { lsn } => lsn,
                Self::Raw { verified_sectors } => verified_sectors,
            }
        }

        fn page_lsn(self) -> Option<u64> {
            match self {
                Self::Mft { lsn } | Self::Index { lsn } => Some(lsn),
                Self::Raw { .. } => None,
            }
        }

        fn sector_verified(self, sector: usize) -> bool {
            match self {
                Self::Raw { verified_sectors } => {
                    sector < u64::BITS as usize && verified_sectors & (1_u64 << sector) != 0
                }
                Self::Mft { .. } | Self::Index { .. } => false,
            }
        }

        fn verify_sector(&mut self, sector: usize) {
            if let Self::Raw { verified_sectors } = self {
                if sector < u64::BITS as usize {
                    *verified_sectors |= 1_u64 << sector;
                }
            }
        }
    }

    struct ReplayTarget {
        spans: Vec<WriteSpan>,
        mirror: Option<(u64, usize)>,
        before: usize,
        bytes: usize,
        state: ReplayState,
        changed: bool,
        undo: bool,
    }
    // Exact physical-and-length keys live in a private open-addressed scratch
    // index. Descriptors (including variable-length spans) are stored in RecordStore;
    // edited bytes and preimages remain in the separate target image store.
    struct TargetTable {
        slots: RefCell<File>,
        rows: RecordStore,
        capacity: u64,
        count: u64,
        /// Extension records this history initializes, by physical offset:
        /// the image of the last such record in the redo schedule.
        later_extensions: std::collections::BTreeMap<u64, Vec<u8>>,
        /// File records this history rewrites whole, by physical offset: the
        /// undo image of the first such rewrite, the record as the history
        /// found it. It stands in for a home copy that a cut write tore.
        earlier_records: std::collections::BTreeMap<u64, Vec<u8>>,
    }
    struct Previous(File);
    impl Previous {
        fn new() -> io::Result<Self> {
            Ok(Self(checker::consistency::scratch_file()?))
        }
        fn get(&mut self, id: u32) -> io::Result<u64> {
            let at = u64::from(id) * WORD_BYTES as u64;
            if self.0.metadata()?.len() < at + WORD_BYTES as u64 {
                return Ok(lfs::NO_LSN);
            }
            let [lsn] = read_words(&mut self.0, at)?;
            Ok(lsn)
        }
        fn set(&mut self, id: u32, lsn: u64) -> io::Result<()> {
            write_words(&mut self.0, u64::from(id) * WORD_BYTES as u64, [lsn])
        }
    }
    impl TargetTable {
        fn new() -> io::Result<Self> {
            let slots = checker::consistency::scratch_file()?;
            slots.set_len(SCRATCH_INITIAL_CAPACITY * TARGET_SLOT_BYTES)?;
            Ok(Self {
                slots: RefCell::new(slots),
                rows: RecordStore::new()?,
                capacity: SCRATCH_INITIAL_CAPACITY,
                count: 0,
                later_extensions: std::collections::BTreeMap::new(),
                earlier_records: std::collections::BTreeMap::new(),
            })
        }
        fn slot(file: &mut File, at: u64) -> io::Result<[u64; TARGET_SLOT_WORDS]> {
            let offset = at.checked_mul(TARGET_SLOT_BYTES).ok_or_else(|| reject("target index overflow"))?;
            read_words(file, offset)
        }
        fn write_slot(file: &mut File, at: u64, row: [u64; TARGET_SLOT_WORDS]) -> io::Result<()> {
            let offset = at.checked_mul(TARGET_SLOT_BYTES).ok_or_else(|| reject("target index overflow"))?;
            write_words(file, offset, row)
        }
        fn hash(key: (u64, usize)) -> u64 {
            key.0.wrapping_mul(TARGET_HASH_MULTIPLIER) ^ (key.1 as u64).rotate_left(TARGET_HASH_ROTATION)
        }
        fn find(&self, key: (u64, usize)) -> io::Result<(u64, Option<usize>)> {
            let mut slots = self.slots.borrow_mut();
            let mut at = Self::hash(key) & (self.capacity - 1);
            for _ in 0..self.capacity {
                let row = Self::slot(&mut slots, at)?;
                if row[TARGET_INDEX_WORD] == TARGET_ABSENT {
                    return Ok((at, None));
                }
                if row[TARGET_PHYSICAL_WORD] == key.0 && row[TARGET_SIZE_WORD] == key.1 as u64 {
                    return Ok((at, Some((row[TARGET_INDEX_WORD] - TARGET_INDEX_BIAS) as usize)));
                }
                at = (at + 1) & (self.capacity - 1);
            }
            Err(reject("target index full"))
        }
        fn grow(&mut self) -> io::Result<()> {
            let next =
                self.capacity.checked_mul(SCRATCH_CAPACITY_GROWTH).ok_or_else(|| reject("target index overflow"))?;
            let mut output = checker::consistency::scratch_file()?;
            output.set_len(next.checked_mul(TARGET_SLOT_BYTES).ok_or_else(|| reject("target index overflow"))?)?;
            let slots = self.slots.get_mut();
            for position in 0..self.capacity {
                let row = Self::slot(slots, position)?;
                if row[TARGET_INDEX_WORD] == TARGET_ABSENT {
                    continue;
                }
                let mut at = Self::hash((row[TARGET_PHYSICAL_WORD], row[TARGET_SIZE_WORD] as usize)) & (next - 1);
                loop {
                    if Self::slot(&mut output, at)?[TARGET_INDEX_WORD] == TARGET_ABSENT {
                        Self::write_slot(&mut output, at, row)?;
                        break;
                    }
                    at = (at + 1) & (next - 1);
                }
            }
            *slots = output;
            self.capacity = next;
            Ok(())
        }
        fn encode(target: &ReplayTarget) -> io::Result<Vec<u8>> {
            let size = target
                .spans
                .len()
                .checked_mul(SPAN_BYTES)
                .and_then(|n| n.checked_add(TARGET_HEADER_BYTES))
                .ok_or_else(|| reject("target descriptor overflow"))?;
            let mut row = Vec::with_capacity(size);
            for word in [
                target.mirror.map_or(NO_MIRROR_OFFSET, |m| m.0),
                target.mirror.map_or(0, |m| m.1 as u64),
                target.before as u64,
                target.bytes as u64,
                target.state.word(),
                target.spans.len() as u64,
            ] {
                row.extend_from_slice(&word.to_le_bytes());
            }
            row.push(match target.state.kind() {
                ReplayTargetKind::Mft => TARGET_KIND_MFT,
                ReplayTargetKind::Index => TARGET_KIND_INDEX,
                ReplayTargetKind::Raw => TARGET_KIND_RAW,
            });
            row.push(u8::from(target.changed));
            row.push(u8::from(target.undo));
            row.extend_from_slice(&[0; TARGET_RESERVED_BYTES]);
            for span in &target.spans {
                for word in [span.physical_offset, span.source_offset, span.length] {
                    row.extend_from_slice(&word.to_le_bytes());
                }
            }
            Ok(row)
        }
        fn decode(row: &[u8]) -> io::Result<ReplayTarget> {
            if row.len() < TARGET_HEADER_BYTES
                || row[TARGET_CHANGED_OFFSET] > ENCODED_BOOL_TRUE
                || row[TARGET_UNDO_OFFSET] > ENCODED_BOOL_TRUE
                || row[TARGET_RESERVED_OFFSET..TARGET_HEADER_BYTES] != [0; TARGET_RESERVED_BYTES]
            {
                return Err(reject("invalid target descriptor"));
            }
            let word = |at: usize| u64::from_le_bytes(row[at..at + WORD_BYTES].try_into().unwrap());
            let count = word(TARGET_SPAN_COUNT_OFFSET) as usize;
            if row.len()
                != count
                    .checked_mul(SPAN_BYTES)
                    .and_then(|n| n.checked_add(TARGET_HEADER_BYTES))
                    .ok_or_else(|| reject("target descriptor overflow"))?
            {
                return Err(reject("target descriptor size mismatch"));
            }
            let kind = match row[TARGET_KIND_OFFSET] {
                TARGET_KIND_MFT => ReplayTargetKind::Mft,
                TARGET_KIND_INDEX => ReplayTargetKind::Index,
                TARGET_KIND_RAW => ReplayTargetKind::Raw,
                _ => return Err(reject("invalid target kind")),
            };
            let mirror = if word(TARGET_MIRROR_OFFSET) == NO_MIRROR_OFFSET {
                None
            } else {
                Some((word(TARGET_MIRROR_OFFSET), word(TARGET_MIRROR_INDEX_OFFSET) as usize))
            };
            let mut spans = Vec::with_capacity(count);
            for raw in row[TARGET_HEADER_BYTES..].chunks_exact(SPAN_BYTES) {
                spans.push(WriteSpan {
                    physical_offset: u64::from_le_bytes(
                        raw[SPAN_PHYSICAL_OFFSET..SPAN_SOURCE_OFFSET].try_into().unwrap(),
                    ),
                    source_offset: u64::from_le_bytes(raw[SPAN_SOURCE_OFFSET..SPAN_LENGTH_OFFSET].try_into().unwrap()),
                    length: u64::from_le_bytes(raw[SPAN_LENGTH_OFFSET..].try_into().unwrap()),
                });
            }
            Ok(ReplayTarget {
                spans,
                mirror,
                before: word(TARGET_BEFORE_OFFSET) as usize,
                bytes: word(TARGET_BYTES_OFFSET) as usize,
                state: ReplayState::from_word(kind, word(TARGET_STATE_OFFSET)),
                changed: row[TARGET_CHANGED_OFFSET] != 0,
                undo: row[TARGET_UNDO_OFFSET] != 0,
            })
        }
        fn get(&self, key: (u64, usize)) -> io::Result<Option<ReplayTarget>> {
            self.find(key)?.1.map(|number| Self::decode(&self.rows.get(number)?)).transpose()
        }
        fn insert(&mut self, key: (u64, usize), target: ReplayTarget) -> io::Result<()> {
            if self.find(key)?.1.is_some() {
                return Err(reject("duplicate target descriptor"));
            }
            if self.count >= self.capacity / SCRATCH_LOAD_DENOMINATOR {
                self.grow()?;
            }
            let (at, _) = self.find(key)?;
            let number = self.rows.len();
            self.rows.push(&Self::encode(&target)?)?;
            Self::write_slot(
                self.slots.get_mut(),
                at,
                [
                    key.0,
                    key.1 as u64,
                    (number as u64).checked_add(TARGET_INDEX_BIAS).ok_or_else(|| reject("target row overflow"))?,
                ],
            )?;
            self.count += 1;
            Ok(())
        }
        fn replace(&self, key: (u64, usize), target: &ReplayTarget) -> io::Result<()> {
            let number = self.find(key)?.1.ok_or_else(|| reject("missing target descriptor"))?;
            self.rows.replace(number, &Self::encode(target)?)
        }
        fn ordered_keys(&self) -> io::Result<File> {
            let mut inventory = checker::consistency::DiskInventory::new();
            let mut slots = self.slots.borrow_mut();
            for at in 0..self.capacity {
                let row = Self::slot(&mut slots, at)?;
                if row[TARGET_INDEX_WORD] != TARGET_ABSENT {
                    inventory.push([row[TARGET_PHYSICAL_WORD], row[TARGET_SIZE_WORD], 0, 0])?;
                }
            }
            inventory.finish()
        }
    }
    fn named<'a>(record: &MftRecord<'a>, kind: u32, name: &[u8]) -> io::Result<Attribute<'a>> {
        let mut found = None;
        for a in record.attributes() {
            let a = a?;
            if a.kind == kind && a.name_utf16le()? == name {
                if found.replace(a).is_some() {
                    return Err(reject("ambiguous recovery stream"));
                }
            }
        }
        found.ok_or_else(|| reject("recovery stream not present"))
    }
    fn op_raw(target: &mut [u8], op: NtfsLogOperation<'_>, undo: bool, origin: usize) -> io::Result<()> {
        let code = if undo { op.undo_code } else { op.redo_code };
        let data = if undo { op.undo } else { op.redo };
        if code == operation::UPDATE_NONRESIDENT_VALUE {
            if op.attribute_offset != 0 {
                return Err(reject("nonresident value offset layout"));
            }
            let at = origin + usize::from(op.record_offset);
            let end = at.checked_add(data.len()).ok_or_else(|| reject("raw patch overflow"))?;
            target.get_mut(at..end).ok_or_else(|| reject("raw patch bounds"))?.copy_from_slice(data);
        } else if matches!(code, operation::SET_BITMAP_BITS | operation::CLEAR_BITMAP_BITS) {
            if data.len() != BITMAP_RANGE_BYTES || op.record_offset != 0 || op.attribute_offset != 0 {
                return Err(reject("bitmap operation layout"));
            }
            let first = origin * BITMAP_BITS_PER_BYTE as usize + u32_at(data, BITMAP_RANGE_FIRST_OFFSET)? as usize;
            let count = u32_at(data, BITMAP_RANGE_COUNT_OFFSET)? as usize;
            let end = first.checked_add(count).ok_or_else(|| reject("bitmap range overflow"))?;
            if count == 0 || end > target.len() * BITMAP_BITS_PER_BYTE as usize {
                return Err(reject("bitmap range bounds"));
            }
            for bit in first..end {
                if code == operation::SET_BITMAP_BITS {
                    target[bit / BITMAP_BITS_PER_BYTE as usize] |= 1 << (bit % BITMAP_BITS_PER_BYTE as usize);
                } else {
                    target[bit / BITMAP_BITS_PER_BYTE as usize] &= !(1 << (bit % BITMAP_BITS_PER_BYTE as usize));
                }
            }
        } else if code != operation::NOOP {
            return Err(reject("unsupported raw metadata action"));
        }
        Ok(())
    }
    fn execute(
        target: &mut ReplayTarget,
        store: &RecordStore,
        op: NtfsLogOperation<'_>,
        undo: bool,
        lsn: u64,
    ) -> io::Result<()> {
        if !undo && target.state.page_lsn().is_some_and(|page_lsn| page_lsn >= lsn) {
            return Ok(());
        }
        let mut bytes = store.get(target.bytes)?;
        if target.state.kind() == ReplayTargetKind::Raw {
            op_raw(&mut bytes, op, undo, 0)?;
        } else {
            let mut scratch = vec![0; bytes.len()];
            crate::metadata_replay::apply(
                &mut bytes,
                &mut scratch,
                op,
                undo,
                target.state.kind() == ReplayTargetKind::Index,
            )?;
            bytes[PAGE_LSN_OFFSET..PAGE_LSN_END].copy_from_slice(&lsn.to_le_bytes());
            target.state = ReplayState::from_word(target.state.kind(), lsn);
        }
        store.replace(target.bytes, &bytes)?;
        target.changed = true;
        target.undo |= undo;
        Ok(())
    }
    fn log_patch<R: ReadAt>(
        volume: &mut Volume<R>,
        data: Attribute<'_>,
        boot: ntfs_rs::boot::BootSector,
        offset: u64,
        mut after: Vec<u8>,
    ) -> io::Result<Vec<Patch>> {
        let spans = overwrite_spans(data, boot, offset, after.len() as u64)?;
        let mut before = vec![0; after.len()];
        volume.read_attribute(data, offset, &mut before)?;
        if after.starts_with(b"RCRD") {
            // A reused log page must not reuse its old sector token: otherwise a
            // mixture of old and new sectors could pass the update-sequence check.
            let old_usa = u16_at(&before, record_layout::USA_OFFSET)? as usize;
            let previous_token = before
                .get(old_usa..old_usa.saturating_add(FIXUP_WORD_BYTES))
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            RecordPage::parse(&mut after, NTFS_SECTOR_BYTES as u16, page_layout::RECORD_DATA_OFFSET as u16)?;
            let usa = u16_at(&after, record_layout::USA_OFFSET)? as usize;
            after[usa..usa + FIXUP_WORD_BYTES].copy_from_slice(&previous_token.to_le_bytes());
            ntfs_rs::mft::protect_fixups(&mut after)?;
        }
        let count = spans.len();
        Ok(spans
            .into_iter()
            .enumerate()
            .map(|(i, s)| {
                let start = s.source_offset as usize;
                let end = (s.source_offset + s.length) as usize;
                Patch {
                    physical: s.physical_offset,
                    before: before[start..end].to_vec(),
                    after: after[start..end].to_vec(),
                    undo: false,
                    continuation: i + 1 != count,
                }
            })
            .collect())
    }
    pub(crate) fn plan<R: ReadAt, D: ReadAt>(
        mut volume: Volume<R>,
        mut disk: D,
        h: &History,
    ) -> io::Result<ReplayPlan> {
        let boot = volume.boot;
        if h.restart.log_page_bytes != page_layout::PUBLICATION_PAGE_BYTES as u32
            || h.restart.record_data_offset != page_layout::RECORD_DATA_OFFSET as u16
        {
            return Err(reject("recovery publication currently requires 4K log pages with 64-byte headers"));
        }
        let schedule = transactions::analyze(&h.records, h.checkpoint_lsn, &h.transactions)?;
        let mut zero = vec![0; boot.record_bytes as usize];
        volume.read_mft_zero(&mut zero)?;
        MftRecord::parse(&mut zero, boot.bytes_per_sector)?;
        let mft = MftRecord::from_decoded(&zero)?;
        named(&mft, ATTR_DATA, &[])?;
        let mut lr = vec![0; boot.record_bytes as usize];
        let mapped = checker::consistency::mft_image(&mut volume)?;
        let mapped = MftRecord::from_decoded(&mapped)?;
        volume.read_mft_record(&mapped, system_record::LOG, &mut lr)?;
        let log_record = MftRecord::parse(&mut lr, boot.bytes_per_sector)?;
        let log_data = named(&log_record, ATTR_DATA, &[])?;
        let mut opens = h.opens.copy()?;
        let mut bound = RecordStore::new()?;
        let mut previous = Previous::new()?;
        h.transactions.for_each(|id, t| previous.set(id, t.previous).io())?;
        for i in 0..h.records.len() {
            let raw = h.records.view(i)?;
            let r = LfsRecord::parse(&raw)?;
            if r.record_type == lfs::CHECKPOINT_RECORD {
                bound.push(&[])?;
                continue;
            }
            let op = r.ntfs_operation()?;
            previous.set(r.transaction_id, r.this_lsn)?;
            let mut binding = None;
            if op.redo_code == operation::OPEN_NONRESIDENT_ATTRIBUTE {
                let mut entry = log::open_entry(
                    op.redo,
                    if op.redo.len() == log::OPEN_ENTRY_LEGACY_BYTES {
                        log::OPEN_ENTRY_VERSION_LEGACY
                    } else {
                        log::OPEN_ENTRY_VERSION_CURRENT
                    },
                )?;
                if !op.undo.is_empty() {
                    if op.undo.len() % CODE_UNIT_BYTES != 0 {
                        return Err(reject("odd attribute name"));
                    }
                    entry.name = op.undo.to_vec();
                    while entry.name.ends_with(&[0; CODE_UNIT_BYTES]) {
                        entry.name.truncate(entry.name.len() - CODE_UNIT_BYTES);
                    }
                }
                opens.insert(op.target_attribute, entry)?;
            } else if transactions::metadata(op.redo_code)
                || transactions::metadata(op.undo_code)
                || op.redo_code == operation::HOT_FIX
            {
                binding =
                    Some(opens.get(op.target_attribute)?.ok_or_else(|| reject("unresolved open attribute"))?.encode());
            }
            bound.push(binding.as_deref().unwrap_or(&[]))?;
        }
        let mut targets = TargetTable::new()?;
        let mut target_images = RecordStore::new()?;
        let mut dirty =
            super::dirty::DirtyMappings::analyze(h, &bound, boot.total_sectors / u64::from(boot.sectors_per_cluster))?;
        // One journal write can log a base record before the new extension
        // record its attribute list names, and an update located through
        // that extension in between. Remember the extension records this
        // history initializes, so such an update can still be located. Every
        // location found this way is checked against the logged clusters.
        for step in 0..schedule.redo.len() {
            let i = schedule.redo.index(step)?;
            let raw = h.records.view(i)?;
            let op = LfsRecord::parse(&raw)?.ntfs_operation()?;
            if op.redo_code != operation::INITIALIZE_FILE_RECORD
                || op.record_offset != 0
                || op.redo.len() > boot.record_bytes as usize
            {
                continue;
            }
            let open = OpenAttribute::decode(&bound.get(i)?)?;
            if ntfs_rs::mft::reference_number(open.reference) != system_record::MFT
                || open.kind != ATTR_DATA
                || !open.name.is_empty()
            {
                continue;
            }
            let Some(lcn) = op.lcns.chunks_exact(WORD_BYTES).next().map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            else {
                continue;
            };
            let at = lcn
                .checked_mul(u64::from(boot.cluster_bytes))
                .and_then(|at| at.checked_add(u64::from(op.cluster_offset) * NTFS_SECTOR_BYTES as u64))
                .ok_or_else(|| reject("record offset overflow"))?;
            if op.undo_code == operation::INITIALIZE_FILE_RECORD
                && op.undo.len() == boot.record_bytes as usize
                && MftRecord::from_decoded(op.undo).is_ok()
            {
                targets.earlier_records.entry(at).or_insert_with(|| op.undo.to_vec());
            }
            let mut image = vec![0; boot.record_bytes as usize];
            image[..op.redo.len()].copy_from_slice(op.redo);
            let extension = MftRecord::from_decoded(&image).is_ok_and(|record| {
                record.base_file_reference().is_ok_and(|base| base != 0)
                    && record.flags().is_ok_and(|flags| flags & record_layout::IN_USE != 0)
            });
            if lcn != 0 && extension {
                let physical = lcn
                    .checked_mul(u64::from(boot.cluster_bytes))
                    .and_then(|at| at.checked_add(u64::from(op.cluster_offset) * NTFS_SECTOR_BYTES as u64))
                    .ok_or_else(|| reject("extension record offset overflow"))?;
                targets.later_extensions.insert(physical, image);
            }
        }
        let mut evidence = RawEvidence { history: h, bindings: &bound, dirty: &mut dirty };
        for step in 0..schedule.redo.len() {
            let i = schedule.redo.index(step)?;
            let raw = h.records.view(i)?;
            let record = LfsRecord::parse(&raw)?;
            let mut op = record.ntfs_operation()?;
            let open = OpenAttribute::decode(&bound.get(i)?)?;
            let lcns = evidence.dirty.redo_lcns(&open, op, record.this_lsn)?;
            if !lcns.is_empty() && lcns.chunks_exact(WORD_BYTES).all(|c| c == [0; WORD_BYTES]) {
                continue;
            }
            op.lcns = &lcns;
            resolve_apply(
                &mut volume,
                &mut disk,
                boot,
                &zero,
                &mut targets,
                &mut target_images,
                &open,
                op,
                false,
                record.this_lsn,
                Some(&mut evidence),
            )?;
        }
        let mut preparation = super::PatchSet::new()?;
        // Remove only the proven uncommitted suffix before filling its gap with
        // compensation/checkpoint records. Each invalidation is independently
        // restartable; a surviving commit beyond the gap was refused at discovery.
        for at in h.discarded_pages.positions() {
            preparation.extend(log_patch(
                &mut volume,
                log_data,
                boot,
                at,
                vec![DISCARDED_PAGE_BYTE; page_layout::PUBLICATION_PAGE_BYTES],
            )?)?;
        }
        let mut publication = super::PatchSet::new()?;
        let restart = h.restart;
        let mut last_page = h.end_page;
        let mut generation = restart.current_lsn >> (u64::BITS - restart.sequence_bits);
        let start_page = lsn_stream_offset(restart.current_lsn, restart.sequence_bits, restart.log_bytes)?
            / page_layout::PUBLICATION_PAGE_BYTES as u64
            * page_layout::PUBLICATION_PAGE_BYTES as u64;
        generation += u64::from(last_page < start_page);
        let mut reserved = log::PageBits::new(restart.log_bytes as usize, page_layout::PUBLICATION_PAGE_BYTES)?;
        let client = restart.client.ok_or_else(|| reject("missing log client"))?;
        let mut reserve = || -> io::Result<(u64, u64)> {
            last_page += page_layout::PUBLICATION_PAGE_BYTES as u64;
            if last_page == restart.log_bytes {
                last_page = if restart.major_version == page_layout::VERSION_LEGACY {
                    page_layout::LEGACY_FIRST_RECORD_PAGE as u64 * page_layout::PUBLICATION_PAGE_BYTES as u64
                } else {
                    page_layout::CURRENT_FIRST_RECORD_PAGE as u64 * page_layout::PUBLICATION_PAGE_BYTES as u64
                };
                generation += 1;
            }
            if h.occupied_pages.contains(last_page)? || !reserved.insert(last_page)? {
                return Err(reject("insufficient free log pages for rollback/checkpoint"));
            }
            if generation >= (1_u64 << restart.sequence_bits) {
                return Err(reject("log sequence generation exhausted"));
            }
            Ok((
                last_page,
                (generation << (u64::BITS - restart.sequence_bits))
                    | ((last_page + page_layout::RECORD_DATA_OFFSET as u64) / lfs::LSN_OFFSET_UNIT_BYTES),
            ))
        };
        for step in 0..schedule.undo.len() {
            let i = schedule.undo.index(step)?;
            let raw = h.records.view(i)?;
            let r = LfsRecord::parse(&raw)?;
            let op = r.ntfs_operation()?;
            let open = OpenAttribute::decode(&bound.get(i)?)?;
            let (offset, lsn) = reserve()?;
            let lcns: Vec<_> =
                op.lcns.chunks_exact(WORD_BYTES).map(|b| u64::from_le_bytes(b.try_into().unwrap())).collect();
            let mut payload = vec![0; OPERATION_BUFFER_OVERHEAD_BYTES + op.lcns.len() + op.redo.len() + op.undo.len()];
            let n = encode_ntfs_operation(
                &NtfsOperationInput {
                    redo_code: op.undo_code,
                    undo_code: operation::COMPENSATION,
                    target_attribute: op.target_attribute,
                    target_vcn: op.target_vcn,
                    lcns: &lcns,
                    redo: op.undo,
                    undo: op.redo,
                },
                &mut payload,
            )?;
            payload[operation::RECORD_OFFSET_OFFSET..operation::OFFSETS_END].copy_from_slice(
                &[op.record_offset.to_le_bytes(), op.attribute_offset.to_le_bytes(), op.cluster_offset.to_le_bytes()]
                    .concat(),
            );
            let mut raw = vec![0; lfs::HEADER_BYTES + n];
            let nraw = encode_lfs_record(
                &LfsRecordInput {
                    this_lsn: lsn,
                    previous_lsn: previous.get(r.transaction_id)?,
                    undo_next_lsn: r.undo_next_lsn,
                    client_sequence: client.sequence,
                    client_index: client.index,
                    record_type: lfs::UPDATE_RECORD,
                    transaction_id: r.transaction_id,
                    flags: if lfs::HEADER_BYTES + n > page_layout::FRAGMENT_BYTES { lfs::MULTI_PAGE } else { 0 }
                        | if op.redo.is_empty() { lfs::NO_UNDO } else { 0 },
                    payload: &payload[..n],
                },
                &mut raw,
            )?;
            for fragment in 0..nraw.div_ceil(page_layout::FRAGMENT_BYTES) {
                let at = if fragment == 0 { offset } else { reserve()?.0 };
                let mut page = vec![0; page_layout::PUBLICATION_PAGE_BYTES];
                encode_record_fragment(&mut page, at as u32, &raw[..nraw], fragment)?;
                preparation.extend(log_patch(&mut volume, log_data, boot, at, page)?)?;
            }
            previous.set(r.transaction_id, lsn)?;
            resolve_apply(
                &mut volume,
                &mut disk,
                boot,
                &zero,
                &mut targets,
                &mut target_images,
                &open,
                op,
                true,
                lsn,
                None,
            )?;
        }
        // Compensation pages are individually flushed before any target update.
        // Discovery follows durable appends, so rollback remains recoverable even
        // if restart publication lags. A final empty checkpoint completes replay.
        let (offset, checkpoint_lsn) = reserve()?;
        let mut cp = [0; page_layout::CHECKPOINT_PAYLOAD_BYTES];
        cp[..std::mem::size_of::<u32>()].copy_from_slice(&page_layout::CHECKPOINT_VERSION.to_le_bytes());
        cp[page_layout::CHECKPOINT_LSN_OFFSET..page_layout::CHECKPOINT_LSN_OFFSET + WORD_BYTES]
            .copy_from_slice(&checkpoint_lsn.to_le_bytes());
        let mut raw = [0; lfs::HEADER_BYTES + page_layout::CHECKPOINT_PAYLOAD_BYTES];
        encode_lfs_record(
            &LfsRecordInput {
                this_lsn: checkpoint_lsn,
                previous_lsn: lfs::NO_LSN,
                undo_next_lsn: lfs::NO_LSN,
                client_sequence: client.sequence,
                client_index: client.index,
                record_type: lfs::CHECKPOINT_RECORD,
                transaction_id: lfs::NO_TRANSACTION_ID,
                flags: lfs::NO_FLAGS,
                payload: &cp,
            },
            &mut raw,
        )?;
        let mut page = vec![0; page_layout::PUBLICATION_PAGE_BYTES];
        encode_single_record_page(
            &mut page,
            NTFS_SECTOR_BYTES as u16,
            page_layout::RECORD_DATA_OFFSET as u16,
            offset as u32,
            &raw,
        )?;
        publication.extend(log_patch(&mut volume, log_data, boot, offset, page)?)?;
        let mut template = h.template.clone();
        advance_restart_checkpoint(&mut template, NTFS_SECTOR_BYTES as u16, checkpoint_lsn)?;
        for at in [page_layout::PUBLICATION_PAGE_BYTES as u64, 0] {
            publication.extend(log_patch(&mut volume, log_data, boot, at, template.clone())?)?;
        }
        // Check the entire write set against log storage and mirror/boot regions.
        let mut log_write_order = checker::consistency::DiskInventory::new();
        for (set_id, set) in [&preparation, &publication].into_iter().enumerate() {
            for number in 0..set.len() {
                log_write_order.push([set.get(number)?.physical, set_id as u64, number as u64, 0])?;
            }
        }
        let mut log_write_order = log_write_order.finish()?;
        let mut previous_write: Option<(u64, Vec<u8>)> = None;
        while let Some([physical, set_id, number, _]) = checker::consistency::inventory_next(&mut log_write_order)? {
            let set = if set_id == 0 { &preparation } else { &publication };
            let mut patch = set.get(number as usize)?;
            if let Some((old_physical, old_after)) = &previous_write {
                if *old_physical == physical {
                    patch.before = old_after.clone();
                    set.replace(number as usize, &patch)?;
                }
            }
            previous_write = Some((physical, patch.after));
        }
        let mut protected = checker::consistency::DiskInventory::new();
        let mut inventory_error = None;
        let mapped = plan_nonresident_overwrite(log_data, boot, 0, log_data.data_size()?, |s| {
            let result = s
                .physical_offset
                .checked_add(s.length)
                .ok_or_else(|| reject("log extent overflow"))
                .and_then(|end| protected.push([s.physical_offset, end, PROTECTED_LOG_RANGE, 0]));
            if let Err(error) = result {
                inventory_error = Some(error);
                return Err(ntfs_rs::Error::Io);
            }
            Ok(())
        });
        if let Some(error) = inventory_error {
            return Err(error);
        }
        mapped?;
        let mirror = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes);
        let mirror_len = u64::from(boot.cluster_bytes).max(u64::from(boot.record_bytes) * system_record::MIRRORED);
        // Check raw writes against the final $MFT mapping, including extents
        // added by replayed MFT growth and those held in extension records.
        let final_zero = targets
            .get((boot.mft_byte_offset()?, boot.record_bytes as usize))?
            .map(|t| target_images.get(t.bytes))
            .transpose()?
            .unwrap_or_else(|| zero.clone());
        let final_mft = MftRecord::from_decoded(&final_zero)?;
        mft_extents_into(&mut protected, &mut volume, &mut disk, boot, &final_mft, &targets, &target_images)?;
        mft_extents_into(&mut protected, &mut volume, &mut disk, boot, &mft, &targets, &target_images)?;
        let mut protected = io::BufReader::new(protected.finish()?);
        let mut next_protected = checker::consistency::inventory_next(&mut protected)?;
        let mut log_end = 0_u64;
        let mut mft_end = 0_u64;
        let mut keys = targets.ordered_keys()?;
        let mut ranges = checker::consistency::DiskInventory::new();
        while let Some([physical, size, _, _]) = checker::consistency::inventory_next(&mut keys)? {
            let t = targets.get((physical, size as usize))?.ok_or_else(|| reject("missing target in index"))?;
            for span in &t.spans {
                ranges.push([
                    span.physical_offset,
                    span.length,
                    u64::from(t.state.kind() == ReplayTargetKind::Raw),
                    0,
                ])?;
            }
        }
        let mut ranges = io::BufReader::new(ranges.finish()?);
        let mut end = 0;
        while let Some([at, size, raw, _]) = checker::consistency::inventory_next(&mut ranges)? {
            let target_end = at.checked_add(size).ok_or_else(|| reject("target range overflow"))?;
            while next_protected.is_some_and(|row| row[TARGET_PHYSICAL_WORD] < target_end) {
                let [_, stop, kind, _] = next_protected.take().unwrap();
                if kind == PROTECTED_LOG_RANGE {
                    log_end = log_end.max(stop);
                } else if kind == PROTECTED_MFT_RANGE {
                    mft_end = mft_end.max(stop);
                } else {
                    return Err(reject("invalid protected range kind"));
                }
                next_protected = checker::consistency::inventory_next(&mut protected)?;
            }
            if at < end
                || at < u64::from(boot.cluster_bytes)
                || (at < mirror + mirror_len && target_end > mirror)
                || log_end > at
            {
                return Err(reject("metadata write-set overlap"));
            }
            end = target_end;
            if raw != 0 && mft_end > at {
                return Err(reject("raw stream aliases MFT"));
            }
        }
        let mut patches = super::PatchSet::new()?;
        keys.seek(SeekFrom::Start(0))?;
        while let Some([physical, size, _, _]) = checker::consistency::inventory_next(&mut keys)? {
            let t = targets.get((physical, size as usize))?.ok_or_else(|| reject("missing target in index"))?;
            if !t.changed {
                continue;
            }
            let before = target_images.get(t.before)?;
            let mut bytes = target_images.get(t.bytes)?;
            if t.state.kind() != ReplayTargetKind::Raw {
                ntfs_rs::mft::protect_fixups(&mut bytes)?;
            }
            let span_count = t.spans.len();
            for (i, s) in t.spans.iter().enumerate() {
                let at = s.source_offset as usize;
                let end = at + s.length as usize;
                patches.push(Patch {
                    physical: s.physical_offset,
                    before: before[at..end].to_vec(),
                    after: bytes[at..end].to_vec(),
                    undo: t.undo,
                    continuation: i + 1 != span_count || t.mirror.is_some(),
                })?;
            }
            if let Some((physical, mirror_index)) = t.mirror {
                patches.push(Patch {
                    physical,
                    before: target_images.get(mirror_index)?,
                    after: bytes,
                    undo: t.undo,
                    continuation: false,
                })?;
            }
        }
        if schedule.redo.is_empty() && schedule.undo.is_empty() && h.records.len() == EMPTY_HISTORY_RECORDS {
            preparation.clear()?;
            publication.clear()?;
        }
        Ok(ReplayPlan {
            preparation,
            patches,
            publication,
            tail_pages: h.tail_pages,
            transaction_instances: schedule.epochs,
            compensation_records: schedule.compensated,
        })
    }

    // Resolve at execution time, including during rollback: earlier actions can
    // create/remove attributes or change their mapping. Never retain borrowed
    // attributes across a mutation of their owning MFT record.
    fn resolve_apply<R: ReadAt, D: ReadAt>(
        volume: &mut Volume<R>,
        disk: &mut D,
        boot: ntfs_rs::boot::BootSector,
        zero: &[u8],
        targets: &mut TargetTable,
        target_images: &mut RecordStore,
        open: &OpenAttribute,
        op: NtfsLogOperation<'_>,
        undo: bool,
        lsn: u64,
        evidence: Option<&mut RawEvidence<'_>>,
    ) -> io::Result<()> {
        // A Noop action (such as the undo of a fresh index-block initialization)
        // changes nothing; its target may no longer even be mapped.
        if (if undo { op.undo_code } else { op.redo_code }) == operation::NOOP {
            return Ok(());
        }
        let current_zero = targets
            .get((boot.mft_byte_offset()?, boot.record_bytes as usize))?
            .map(|t| target_images.get(t.bytes))
            .transpose()?
            .unwrap_or_else(|| zero.to_vec());
        let mft = MftRecord::from_decoded(&current_zero)?;
        let owner = ntfs_rs::mft::reference_number(open.reference);
        let mut raw = vec![0; boot.record_bytes as usize];
        // Locate the owner through the current $MFT mapping, including $DATA
        // extents held in $MFT extension records and extents added by earlier
        // redo of MFT growth in this history.
        let owner_spans = mft_record_spans(volume, disk, boot, &mft, targets, target_images, owner)?;
        let cached = match owner_spans.first() {
            Some(s) => targets.get((s.physical_offset, boot.record_bytes as usize))?,
            None => None,
        };
        if let Some(cached) = cached {
            raw.copy_from_slice(&target_images.get(cached.bytes)?);
        } else if owner == system_record::MFT {
            // read_mft_zero chose a whole copy: the primary, or $MFTMirr's
            // when an interrupted write tore the primary.
            raw.copy_from_slice(zero);
        } else {
            for s in &owner_spans {
                disk.read_exact_at(
                    s.physical_offset,
                    &mut raw[s.source_offset as usize..(s.source_offset + s.length) as usize],
                )?;
            }
            if let Err(error) = MftRecord::parse(&mut raw, boot.bytes_per_sector) {
                // A cut write tore the home copy; the journal holds the
                // record as this history found it.
                let earlier = owner_spans.first().and_then(|s| targets.earlier_records.get(&s.physical_offset));
                raw.copy_from_slice(earlier.ok_or(error)?);
            }
        }
        let file = MftRecord::from_decoded(&raw)?;
        if u64::from(file.sequence_number()?) != u64::from(ntfs_rs::mft::reference_sequence(open.reference)) {
            return Err(reject("stale stream reference"));
        }
        let kind = if owner == system_record::MFT && open.kind == ATTR_DATA {
            ReplayTargetKind::Mft
        } else if open.kind == ATTR_INDEX_ALLOCATION {
            ReplayTargetKind::Index
        } else {
            ReplayTargetKind::Raw
        };
        let within = u64::from(op.cluster_offset) * NTFS_SECTOR_BYTES as u64;
        let logical = op
            .target_vcn
            .checked_mul(u64::from(boot.cluster_bytes))
            .and_then(|n| n.checked_add(within))
            .ok_or_else(|| reject("target overflow"))?;
        if kind == ReplayTargetKind::Raw {
            return apply_raw(volume, disk, boot, &mft, &file, targets, target_images, open, op, undo, lsn, evidence);
        }
        let size = match kind {
            ReplayTargetKind::Mft => {
                if logical % u64::from(boot.record_bytes) != 0 {
                    return Err(reject("unaligned MFT target"));
                }
                boot.record_bytes as usize
            }
            ReplayTargetKind::Index => {
                let n = open.index_bytes as usize;
                if !(NTFS_SECTOR_BYTES..=MAX_INDEX_BLOCK_BYTES).contains(&n) || !n.is_power_of_two() {
                    return Err(reject("index geometry"));
                }
                n
            }
            ReplayTargetKind::Raw => {
                if matches!(op.redo_code, operation::SET_BITMAP_BITS | operation::CLEAR_BITMAP_BITS)
                    && !(open.kind == ATTR_BITMAP || (owner == system_record::BITMAP && open.kind == ATTR_DATA))
                {
                    return Err(reject("bit operation on non-bitmap stream"));
                }
                let stream = named(&file, open.kind, &open.name)?;
                (u64::from(boot.cluster_bytes) - within.min(u64::from(boot.cluster_bytes)))
                    .min(stream.initialized_size()?.saturating_sub(logical)) as usize
            }
        };
        if size == 0 || size > MAX_REPLAY_TARGET_BYTES {
            return Err(reject("target size limit"));
        }
        let spans = stream_spans(volume, disk, boot, &mft, &file, open, logical, size as u64, targets, target_images)?;
        if spans.is_empty() {
            return Err(reject("missing physical target"));
        }
        let physical = spans[0].physical_offset;
        let clusters = (within + size as u64).div_ceil(u64::from(boot.cluster_bytes));
        if op.lcns.len() != clusters as usize * WORD_BYTES {
            return Err(reject("logged LCN coverage mismatch"));
        }
        for c in 0..clusters {
            let byte = c.saturating_mul(u64::from(boot.cluster_bytes)).saturating_sub(within);
            let span = spans
                .iter()
                .find(|s| byte >= s.source_offset && byte < s.source_offset + s.length)
                .ok_or_else(|| reject("incomplete metadata transfer"))?;
            let mapped = (span.physical_offset + byte - span.source_offset) / u64::from(boot.cluster_bytes);
            if u64_at(op.lcns, c as usize * WORD_BYTES)? != mapped {
                return Err(reject("logged LCN disagrees with stream mapping"));
            }
        }
        let key = (physical, size);
        if targets.get(key)?.is_none() {
            let mut before = vec![0; size];
            for s in &spans {
                disk.read_exact_at(
                    s.physical_offset,
                    &mut before[s.source_offset as usize..(s.source_offset + s.length) as usize],
                )?;
            }
            let mut bytes = before.clone();
            let mut lsn = if kind == ReplayTargetKind::Raw { lfs::NO_LSN } else { u64_at(&bytes, PAGE_LSN_OFFSET)? };
            let action = if undo { op.undo_code } else { op.redo_code };
            let payload = if undo { op.undo } else { op.redo };
            if kind == ReplayTargetKind::Mft {
                if MftRecord::parse(&mut bytes, boot.bytes_per_sector).is_err() {
                    if let Some(mirrored) = mirrored_record(disk, boot, owner, logical, size)? {
                        // Replay brings the mirror's older or equal image
                        // forward, as it would the torn primary's.
                        lsn = u64_at(&mirrored, PAGE_LSN_OFFSET)?;
                        bytes = mirrored;
                    } else {
                        if action != operation::INITIALIZE_FILE_RECORD
                            || op.record_offset != 0
                            || payload.len() < record_layout::HEADER_BYTES
                        {
                            return Err(reject("invalid MFT preimage without complete initialization"));
                        }
                        bytes.fill(0);
                        lsn = lfs::NO_LSN;
                    }
                }
            } else if kind == ReplayTargetKind::Index {
                let unit =
                    if open.index_bytes >= boot.cluster_bytes { boot.cluster_bytes } else { NTFS_SECTOR_BYTES as u32 };
                let expected_vcn = logical / u64::from(unit);
                if ntfs_rs::index::IndexBlock::parse(&mut bytes, NTFS_SECTOR_BYTES as u16, expected_vcn).is_err() {
                    if action != operation::UPDATE_NONRESIDENT_VALUE
                        || op.record_offset != 0
                        || op.attribute_offset != 0
                        || payload.len() < INDEX_MIN_INITIALIZATION_BYTES
                        || payload.get(..record_layout::SIGNATURE_BYTES) != Some(b"INDX")
                        || u64_at(payload, INDEX_VCN_OFFSET)? != expected_vcn
                        || INDEX_HEADER_OFFSET + u32_at(payload, INDEX_USED_BYTES_OFFSET)? as usize > payload.len()
                    {
                        return Err(reject("invalid index preimage without complete initialization"));
                    }
                    bytes.fill(0);
                    lsn = lfs::NO_LSN;
                }
            }
            let mirror = if kind == ReplayTargetKind::Mft
                && logical < u64::from(boot.cluster_bytes).max(system_record::MIRRORED * u64::from(boot.record_bytes))
            {
                let at = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + logical;
                let mut mirror_before = vec![0; size];
                disk.read_exact_at(at, &mut mirror_before)?;
                let differs = mirror_before != before;
                let index = target_images.len();
                target_images.push(&mirror_before)?;
                Some((at, index, differs))
            } else {
                None
            };
            let before_index = target_images.len();
            target_images.push(&before)?;
            let bytes_index = target_images.len();
            target_images.push(&bytes)?;
            targets.insert(
                key,
                ReplayTarget {
                    spans: spans.clone(),
                    mirror: mirror.as_ref().map(|(at, index, _)| (*at, *index)),
                    before: before_index,
                    bytes: bytes_index,
                    state: ReplayState::from_word(kind, lsn),
                    changed: mirror.is_some_and(|(_, _, differs)| differs),
                    undo: false,
                },
            )?;
        } else {
            let old = targets.get(key)?.ok_or_else(|| reject("missing target descriptor"))?;
            if old.state.kind() != kind || old.spans != spans {
                return Err(reject("metadata target alias"));
            }
        }
        let mut target = targets.get(key)?.ok_or_else(|| reject("missing target descriptor"))?;
        execute(&mut target, target_images, op, undo, lsn)?;
        targets.replace(key, &target)?;
        Ok(())
    }

    // Raw bitmap sectors have no page LSN. During checkpoint writeback a newer
    // committed sector may reach disk before restart publication. Accept it only
    // when its complete bytes and identity match a later validated log image.
    struct RawEvidence<'a> {
        history: &'a History,
        bindings: &'a RecordStore,
        dirty: &'a mut super::dirty::DirtyMappings,
    }

    impl RawEvidence<'_> {
        fn later_bitmap_image(
            &mut self,
            open: &OpenAttribute,
            op: NtfsLogOperation<'_>,
            lsn: u64,
            physical: u64,
            cluster: usize,
            current: &[u8],
        ) -> io::Result<bool> {
            if current.len() != NTFS_SECTOR_BYTES || op.redo.len() != NTFS_SECTOR_BYTES || op.lcns.len() != WORD_BYTES {
                return Ok(false);
            }
            for index in 0..self.history.records.len() {
                let raw = self.history.records.view(index)?;
                let record = LfsRecord::parse(&raw)?;
                if record.record_type != lfs::UPDATE_RECORD || record.this_lsn <= lsn {
                    continue;
                }
                let candidate = record.ntfs_operation()?;
                if candidate.redo_code != operation::UPDATE_NONRESIDENT_VALUE
                    || candidate.redo != current
                    || candidate.target_vcn != op.target_vcn
                    || candidate.cluster_offset != op.cluster_offset
                    || candidate.record_offset != op.record_offset
                    || candidate.attribute_offset != op.attribute_offset
                    || candidate.lcns.len() != WORD_BYTES
                {
                    continue;
                }
                let binding = self.bindings.get(index)?;
                if binding.is_empty() {
                    continue;
                }
                let owner = OpenAttribute::decode(&binding)?;
                if owner.reference != open.reference || owner.kind != open.kind || owner.name != open.name {
                    continue;
                }
                // Dirty-cluster invalidations and HotFix mappings remain binding;
                // a matching payload from a reused or redirected LCN is no proof.
                let lcns = self.dirty.redo_lcns(&owner, candidate, record.this_lsn)?;
                if u64_at(&lcns, 0)? == physical / cluster as u64 {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    // Raw metadata has no page LSN. Cache by physical cluster, so transfers with
    // different lengths/offsets still share the same bytes and repeat in log order.
    fn apply_raw<R: ReadAt, D: ReadAt>(
        volume: &mut Volume<R>,
        disk: &mut D,
        boot: ntfs_rs::boot::BootSector,
        mft: &MftRecord<'_>,
        file: &MftRecord<'_>,
        targets: &mut TargetTable,
        target_images: &mut RecordStore,
        open: &OpenAttribute,
        op: NtfsLogOperation<'_>,
        undo: bool,
        lsn: u64,
        mut evidence: Option<&mut RawEvidence<'_>>,
    ) -> io::Result<()> {
        let cluster = boot.cluster_bytes as usize;
        let count = op.lcns.len() / WORD_BYTES;
        let length = count.checked_mul(cluster).ok_or_else(|| reject("raw transfer overflow"))?;
        if count == 0 {
            return Err(reject("empty raw transfer"));
        }
        let offset = op.target_vcn.checked_mul(cluster as u64).ok_or_else(|| reject("raw VCN overflow"))?;
        let origin = usize::from(op.cluster_offset) * NTFS_SECTOR_BYTES;
        if origin >= length {
            return Err(reject("raw cluster offset bounds"));
        }
        let code = if undo { op.undo_code } else { op.redo_code };
        let data = if undo { op.undo } else { op.redo };
        let owner = ntfs_rs::mft::reference_number(open.reference);
        if matches!(code, operation::SET_BITMAP_BITS | operation::CLEAR_BITMAP_BITS) {
            if !(open.kind == ATTR_BITMAP || (owner == system_record::BITMAP && open.kind == ATTR_DATA)) {
                return Err(reject("bit operation on non-bitmap stream"));
            }
            if op.undo_code != operation::COMPENSATION
                && (!matches!(
                    (op.redo_code, op.undo_code),
                    (operation::SET_BITMAP_BITS, operation::CLEAR_BITMAP_BITS)
                        | (operation::CLEAR_BITMAP_BITS, operation::SET_BITMAP_BITS)
                ) || op.redo != op.undo)
            {
                return Err(reject("bitmap inverse does not match"));
            }
            // The volume never grows, so cluster bits stay within it. Windows sets
            // MFT and index bits before the logged operation that extends their
            // allocation, so those bits may exceed the pre-replay size; they are
            // bounded by the logged transfer, which the patch bounds also enforce.
            let units = if owner == system_record::BITMAP && open.kind == ATTR_DATA {
                boot.total_sectors / u64::from(boot.sectors_per_cluster)
            } else {
                (offset + length as u64).checked_mul(BITMAP_BITS_PER_BYTE).ok_or_else(|| reject("bitmap transfer overflow"))?
            };
            let end = (offset + origin as u64)
                .checked_mul(BITMAP_BITS_PER_BYTE)
                .and_then(|n| n.checked_add(u64::from(u32_at(data, BITMAP_RANGE_FIRST_OFFSET).ok()?)))
                .and_then(|n| n.checked_add(u64::from(u32_at(data, BITMAP_RANGE_COUNT_OFFSET).ok()?)))
                .ok_or_else(|| reject("bitmap interval overflow"))?;
            if end > units {
                return Err(reject("bitmap interval exceeds addressable units"));
            }
        }
        // The logged LCN list may describe much more than the changed interval.
        // Validate each mapping, but retain and edit only clusters touched by the
        // operation. This avoids allocating the entire transfer in memory.
        let (start, end) = match code {
            operation::NOOP => (0, 0),
            operation::UPDATE_NONRESIDENT_VALUE => {
                if op.attribute_offset != 0 {
                    return Err(reject("nonresident value offset layout"));
                }
                let start =
                    origin.checked_add(usize::from(op.record_offset)).ok_or_else(|| reject("raw patch overflow"))?;
                let end = start.checked_add(data.len()).ok_or_else(|| reject("raw patch overflow"))?;
                if end > length {
                    return Err(reject("raw patch bounds"));
                }
                (start, end)
            }
            operation::SET_BITMAP_BITS | operation::CLEAR_BITMAP_BITS => {
                if data.len() != BITMAP_RANGE_BYTES || op.record_offset != 0 || op.attribute_offset != 0 {
                    return Err(reject("bitmap operation layout"));
                }
                let first = origin
                    .checked_mul(BITMAP_BITS_PER_BYTE as usize)
                    .and_then(|n| n.checked_add(u32_at(data, BITMAP_RANGE_FIRST_OFFSET).ok()? as usize))
                    .ok_or_else(|| reject("bitmap interval overflow"))?;
                let end = first
                    .checked_add(u32_at(data, BITMAP_RANGE_COUNT_OFFSET)? as usize)
                    .ok_or_else(|| reject("bitmap interval overflow"))?;
                if first == end || end > length * BITMAP_BITS_PER_BYTE as usize {
                    return Err(reject("bitmap range bounds"));
                }
                (first / BITMAP_BITS_PER_BYTE as usize, end.div_ceil(BITMAP_BITS_PER_BYTE as usize))
            }
            _ => return Err(reject("unsupported raw metadata action")),
        };
        let mut touched = BTreeSet::new();
        for i in 0..count {
            if !undo && u64_at(op.lcns, i * WORD_BYTES)? == 0 {
                continue;
            }
            let spans = stream_spans(
                volume,
                disk,
                boot,
                mft,
                file,
                open,
                offset + (i * cluster) as u64,
                cluster as u64,
                targets,
                target_images,
            )?;
            let source = 0;
            let span = spans
                .iter()
                .find(|s| source >= s.source_offset && source < s.source_offset + s.length)
                .ok_or_else(|| reject("missing raw cluster mapping"))?;
            let physical = span.physical_offset + source - span.source_offset;
            if physical % cluster as u64 != 0 || physical / cluster as u64 != u64_at(op.lcns, i * WORD_BYTES)? {
                return Err(reject("raw logged LCN disagrees with mapping"));
            }
            if i * cluster >= end || (i + 1) * cluster <= start {
                continue;
            }
            let key = (physical, cluster);
            if !touched.insert(key) {
                return Err(reject("raw log aliases one physical cluster"));
            }
            if let Some(t) = targets.get(key)? {
                if t.state.kind() != ReplayTargetKind::Raw {
                    return Err(reject("raw target aliases a protected record"));
                }
            } else {
                let mut before = vec![0; cluster];
                disk.read_exact_at(physical, &mut before)?;
                let before_index = target_images.len();
                target_images.push(&before)?;
                let bytes_index = target_images.len();
                target_images.push(&before)?;
                targets.insert(
                    key,
                    ReplayTarget {
                        spans: vec![WriteSpan { physical_offset: physical, source_offset: 0, length: cluster as u64 }],
                        mirror: None,
                        bytes: bytes_index,
                        before: before_index,
                        state: ReplayState::Raw { verified_sectors: 0 },
                        changed: false,
                        undo: false,
                    },
                )?;
            }
            let mut t = targets.get(key)?.ok_or_else(|| reject("missing raw target"))?;
            let mut bytes = target_images.get(t.bytes)?;
            let old = bytes.clone();
            match code {
                operation::UPDATE_NONRESIDENT_VALUE => {
                    let lo = start.max(i * cluster);
                    let hi = end.min((i + 1) * cluster);
                    if op.redo_code == operation::UPDATE_NONRESIDENT_VALUE
                        && op.undo_code == operation::UPDATE_NONRESIDENT_VALUE
                        && op.redo.len() == op.undo.len()
                        && !op.redo.is_empty()
                    {
                        let expected = if undo { op.redo } else { op.undo };
                        let replacement = if undo { op.undo } else { op.redo };
                        let current = &bytes[lo - i * cluster..hi - i * cluster];
                        let from = lo - start;
                        let to = hi - start;
                        if current != &expected[from..to] && current != &replacement[from..to] {
                            let sector = (lo - i * cluster) / NTFS_SECTOR_BYTES;
                            let bitmap =
                                open.kind == ATTR_BITMAP || (owner == system_record::BITMAP && open.kind == ATTR_DATA);
                            let first = sector < u64::BITS as usize && !t.state.sector_verified(sector);
                            let known = if !undo && bitmap && first && lo % NTFS_SECTOR_BYTES == 0 {
                                match evidence.as_deref_mut() {
                                    Some(proof) => {
                                        proof.later_bitmap_image(open, op, lsn, physical, cluster, current)?
                                    }
                                    None => false,
                                }
                            } else {
                                false
                            };
                            if !known {
                                return Err(reject("raw replay preimage does not match logged bytes"));
                            }
                            // Rebuild this sector from the oldest preimage in the
                            // private plan; subsequent redo/undo still checks every
                            // transition. Keep its real disk preimage for commit.
                            bytes[lo - i * cluster..hi - i * cluster].copy_from_slice(&expected[from..to]);
                        }
                        let sector = (lo - i * cluster) / NTFS_SECTOR_BYTES;
                        if lo % NTFS_SECTOR_BYTES == 0 && hi - lo == NTFS_SECTOR_BYTES && sector < u64::BITS as usize {
                            t.state.verify_sector(sector);
                        }
                    }
                    bytes[lo - i * cluster..hi - i * cluster].copy_from_slice(&data[lo - start..hi - start]);
                }
                operation::SET_BITMAP_BITS | operation::CLEAR_BITMAP_BITS => {
                    let first =
                        origin * BITMAP_BITS_PER_BYTE as usize + u32_at(data, BITMAP_RANGE_FIRST_OFFSET)? as usize;
                    let end = first + u32_at(data, BITMAP_RANGE_COUNT_OFFSET)? as usize;
                    for bit in first.max(i * cluster * BITMAP_BITS_PER_BYTE as usize)
                        ..end.min((i + 1) * cluster * BITMAP_BITS_PER_BYTE as usize)
                    {
                        let cell = &mut bytes[bit / BITMAP_BITS_PER_BYTE as usize - i * cluster];
                        if code == operation::SET_BITMAP_BITS {
                            *cell |= 1 << (bit % BITMAP_BITS_PER_BYTE as usize);
                        } else {
                            *cell &= !(1 << (bit % BITMAP_BITS_PER_BYTE as usize));
                        }
                    }
                }
                _ => {}
            }
            t.changed |= bytes != old;
            target_images.replace(t.bytes, &bytes)?;
            t.undo |= undo;
            targets.replace(key, &t)?;
        }
        Ok(())
    }

    /// Physical spans of one MFT record through the current $MFT:$DATA,
    /// following record 0's attribute list into $MFT extension records.
    fn mft_record_spans<R: ReadAt, D: ReadAt>(
        volume: &mut Volume<R>,
        disk: &mut D,
        boot: ntfs_rs::boot::BootSector,
        mft: &MftRecord<'_>,
        targets: &TargetTable,
        target_images: &RecordStore,
        number: u64,
    ) -> io::Result<Vec<WriteSpan>> {
        let open = OpenAttribute {
            reference: ntfs_rs::mft::file_reference(system_record::MFT, mft.sequence_number()?)?,
            kind: ATTR_DATA,
            index_bytes: 0,
            name: Vec::new(),
        };
        let offset =
            number.checked_mul(u64::from(boot.record_bytes)).ok_or_else(|| reject("MFT record offset overflow"))?;
        stream_spans(volume, disk, boot, mft, mft, &open, offset, u64::from(boot.record_bytes), targets, target_images)
    }

    /// Inventory $MFT:$DATA in bounded logical windows for write-set checks.
    fn mft_extents_into<R: ReadAt, D: ReadAt>(
        protected: &mut checker::consistency::DiskInventory,
        volume: &mut Volume<R>,
        disk: &mut D,
        boot: ntfs_rs::boot::BootSector,
        mft: &MftRecord<'_>,
        targets: &TargetTable,
        target_images: &RecordStore,
    ) -> io::Result<()> {
        let size = named(mft, ATTR_DATA, &[])?.data_size()?;
        let open = OpenAttribute {
            reference: ntfs_rs::mft::file_reference(system_record::MFT, mft.sequence_number()?)?,
            kind: ATTR_DATA,
            index_bytes: 0,
            name: Vec::new(),
        };
        let mut offset = 0_u64;
        while offset < size {
            let length = (size - offset).min(MFT_SCAN_WINDOW_BYTES);
            for span in stream_spans(volume, disk, boot, mft, mft, &open, offset, length, targets, target_images)? {
                let end = span.physical_offset.checked_add(span.length).ok_or_else(|| reject("MFT extent overflow"))?;
                protected.push([span.physical_offset, end, PROTECTED_MFT_RANGE, 0])?;
            }
            offset += length;
        }
        Ok(())
    }

    /// The decoded $MFTMirr copy of a mirrored $MFT record whose primary
    /// copy an interrupted write tore; None for a record Windows does not
    /// mirror or a mirror copy that is not whole either.
    fn mirrored_record<D: ReadAt>(
        disk: &mut D,
        boot: ntfs_rs::boot::BootSector,
        owner: u64,
        logical: u64,
        size: usize,
    ) -> io::Result<Option<Vec<u8>>> {
        let end = logical.checked_add(size as u64).ok_or_else(|| reject("mirror overflow"))?;
        if owner != system_record::MFT || end > boot.mirrored_bytes() {
            return Ok(None);
        }
        let mirror = boot
            .mft_mirror_lcn
            .checked_mul(u64::from(boot.cluster_bytes))
            .and_then(|base| base.checked_add(logical))
            .ok_or_else(|| reject("mirror overflow"))?;
        let mut bytes = vec![0; size];
        disk.read_exact_at(mirror, &mut bytes)?;
        Ok(MftRecord::parse(&mut bytes, boot.bytes_per_sector).is_ok().then_some(bytes))
    }

    fn stream_spans<R: ReadAt, D: ReadAt>(
        volume: &mut Volume<R>,
        disk: &mut D,
        boot: ntfs_rs::boot::BootSector,
        mft: &MftRecord<'_>,
        base: &MftRecord<'_>,
        open: &OpenAttribute,
        offset: u64,
        length: u64,
        targets: &TargetTable,
        target_images: &RecordStore,
    ) -> io::Result<Vec<WriteSpan>> {
        let end = offset.checked_add(length).ok_or_else(|| reject("stream range overflow"))?;
        let mut spans = Vec::new();
        // The byte range of the stream that one segment maps.
        let segment = |a: Attribute<'_>| -> io::Result<(u64, u64)> {
            if !a.nonresident || a.flags()? != ntfs_rs::mft::attribute_layout::NO_FLAGS {
                return Err(reject("nonresident ordinary metadata extent required"));
            }
            let start = a
                .first_vcn()?
                .checked_mul(u64::from(boot.cluster_bytes))
                .ok_or_else(|| reject("extent start overflow"))?;
            let stop = a
                .last_vcn()?
                .checked_add(1)
                .and_then(|n| n.checked_mul(u64::from(boot.cluster_bytes)))
                .ok_or_else(|| reject("extent end overflow"))?;
            Ok((start, stop))
        };
        let mut include = |a: Attribute<'_>| -> io::Result<()> {
            let (start, stop) = segment(a)?;
            let from = offset.max(start);
            let to = end.min(stop);
            if from < to {
                plan_nonresident_recovery(a, boot, from, to - from, |mut s| {
                    s.source_offset += from - offset;
                    spans.push(s);
                    Ok(())
                })?;
            }
            Ok(())
        };
        let mut list = None;
        let mut base_covers = false;
        for a in base.attributes() {
            let a = a?;
            if a.kind == open.kind && a.name_utf16le()? == open.name {
                let (start, stop) = segment(a)?;
                base_covers |= start <= offset && end <= stop;
                include(a)?;
            }
            if a.kind == ATTR_ATTRIBUTE_LIST {
                if list.replace(a).is_some() {
                    return Err(reject("duplicate attribute list"));
                }
            }
        }
        // A range the base record maps by itself needs no extension record.
        // $MFT's own extension records lie in such a range, and after a power
        // cut one of them may still await the redo that this lookup serves.
        if let Some(list) = list.filter(|_| !base_covers) {
            let size = list.data_size()?;
            let size = size as usize;
            let backing = checker::consistency::scratch_file()?;
            backing.set_len(size as u64)?;
            let mut mapped = if size == 0 { None } else { Some(unsafe { memmap2::MmapMut::map_mut(&backing)? }) };
            let mut empty = [];
            let bytes = mapped.as_deref_mut().unwrap_or(&mut empty);
            if list.nonresident {
                let mut read_error = None;
                let mapped = plan_nonresident_recovery(list, boot, 0, size as u64, |s| {
                    let result = (|| -> io::Result<()> {
                        let destination = &mut bytes[s.source_offset as usize..(s.source_offset + s.length) as usize];
                        disk.read_exact_at(s.physical_offset, destination)?;
                        let cluster = u64::from(boot.cluster_bytes);
                        let fragment_end = s.physical_offset + s.length;
                        let mut at = s.physical_offset / cluster * cluster;
                        while at < fragment_end {
                            if let Some(target) = targets.get((at, cluster as usize))? {
                                if target.state.kind() == ReplayTargetKind::Raw {
                                    let target_bytes = target_images.get(target.bytes)?;
                                    let from = at.max(s.physical_offset);
                                    let to = (at + cluster).min(fragment_end);
                                    let src = (from - at) as usize;
                                    let dst = (from - s.physical_offset) as usize;
                                    destination[dst..dst + (to - from) as usize]
                                        .copy_from_slice(&target_bytes[src..src + (to - from) as usize]);
                                }
                            }
                            at = at.checked_add(cluster).ok_or_else(|| reject("cluster offset overflow"))?;
                        }
                        Ok(())
                    })();
                    if let Err(error) = result {
                        read_error = Some(error);
                        return Err(ntfs_rs::Error::Io);
                    }
                    Ok(())
                });
                if let Some(error) = read_error {
                    return Err(error);
                }
                mapped?;
            } else {
                bytes.copy_from_slice(list.resident_value()?);
            }
            let mut seen = checker::consistency::DiskInventory::new();
            for e in ntfs_rs::attrlist::AttributeList::new(&bytes) {
                let e = e?;
                if e.kind != open.kind || e.name_utf16le != open.name {
                    continue;
                }
                seen.push([e.first_vcn, u64::from(e.attribute_id), e.file_reference, 0])?;
                if e.file_reference == open.reference {
                    continue;
                }
                let number = ntfs_rs::mft::reference_number(e.file_reference);
                let mut record = vec![0; boot.record_bytes as usize];
                let data = named(mft, ATTR_DATA, &[])?;
                let mut record_spans = Vec::new();
                let direct = plan_nonresident_recovery(
                    data,
                    boot,
                    number * u64::from(boot.record_bytes),
                    u64::from(boot.record_bytes),
                    |s| {
                        record_spans.push(s);
                        Ok(())
                    },
                );
                if direct.is_err() {
                    record_spans.clear();
                    let mapped = checker::consistency::mft_image(volume)?;
                    let mapped = MftRecord::from_decoded(&mapped)?;
                    plan_nonresident_recovery(
                        named(&mapped, ATTR_DATA, &[])?,
                        boot,
                        number * u64::from(boot.record_bytes),
                        u64::from(boot.record_bytes),
                        |s| {
                            record_spans.push(s);
                            Ok(())
                        },
                    )?;
                }
                let key = (
                    record_spans.first().ok_or_else(|| reject("missing extension extent"))?.physical_offset,
                    record.len(),
                );
                // The listed extension, as this base names it.
                let current = |record: &[u8]| -> io::Result<bool> {
                    let extension = MftRecord::from_decoded(record)?;
                    Ok(u64::from(extension.sequence_number()?)
                        == u64::from(ntfs_rs::mft::reference_sequence(e.file_reference))
                        && extension.base_file_reference()? == open.reference)
                };
                let planned = match targets.get(key)? {
                    Some(t) => {
                        record.copy_from_slice(&target_images.get(t.bytes)?);
                        current(&record)?
                    }
                    None => false,
                };
                // After a power cut the planned image of an extension record
                // can still be the one from before it joined this base while
                // the record on disk is already current, and the reverse.
                // Either one that belongs to this base names its extents.
                if !planned {
                    for span in &record_spans {
                        disk.read_exact_at(
                            span.physical_offset,
                            &mut record[span.source_offset as usize..(span.source_offset + span.length) as usize],
                        )?;
                    }
                    let on_disk = MftRecord::parse(&mut record, boot.bytes_per_sector).is_ok() && current(&record)?;
                    if !on_disk {
                        // The redo that initializes it comes later in this history.
                        match targets.later_extensions.get(&key.0) {
                            Some(later) if current(later)? => record.copy_from_slice(later),
                            _ => return Err(reject("stale or foreign extension reference")),
                        }
                    }
                }
                let extension = MftRecord::from_decoded(&record)?;
                let mut found = false;
                for a in extension.attributes() {
                    let a = a?;
                    if a.id == e.attribute_id && a.kind == open.kind && a.name_utf16le()? == open.name {
                        if found || a.first_vcn()? != e.first_vcn {
                            return Err(reject("ambiguous extension attribute"));
                        }
                        include(a)?;
                        found = true;
                    }
                }
                if !found {
                    return Err(reject("missing extension attribute"));
                }
            }
            let mut ordered = seen.finish()?;
            let mut previous = None;
            while let Some(row) = checker::consistency::inventory_next(&mut ordered)? {
                if previous == Some(row) {
                    return Err(reject("duplicate recovery extent entry"));
                }
                previous = Some(row);
            }
        }
        spans.sort_by_key(|s| s.source_offset);
        let mut covered = 0;
        for s in &spans {
            if s.source_offset != covered {
                return Err(reject("stream extent gap or overlap"));
            }
            covered += s.length;
        }
        if covered != length {
            return Err(reject("incomplete stream extent mapping"));
        }
        Ok(spans)
    }

    #[cfg(test)]
    mod state_tests {
        include!("../tests/recovery/replay_state_tests.rs");
    }
}

pub(super) mod family {
    use super::*;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::mft::{attribute_layout as af, file_reference, record_layout as rf};
    use ntfs_rs::{record_edit as e, runlist::Extent};

    pub(crate) const MFT_ATTRIBUTE_RESERVE_BYTES: usize = 384;
    pub(crate) const NONRESIDENT_BUILD_OVERHEAD_BYTES: usize = 96;
    pub(crate) const MAX_MAPPING_PAIR_BYTES: usize = 1 + 2 * std::mem::size_of::<u64>();
    const MIN_ALLOCATED_MAPPING_PAIR_BYTES: u64 = 3;
    const MFT_MAPPING_HEADER_BYTES: usize = 64;
    const RESIDENT_BUILD_OVERHEAD_BYTES: usize = 32;
    const EMPTY_ATTRIBUTE_SCRATCH_BYTES: usize = 32;
    const ATTRIBUTE_LIST_SPACE_RESERVE_BYTES: usize = 96;
    const FAMILY_MEMBER_SLACK_BYTES: usize = 24;
    const ATTRIBUTE_LIST_HEADER_BYTES: usize = 26;
    const ATTRIBUTE_LIST_TYPE_OFFSET: usize = 0;
    const ATTRIBUTE_LIST_LENGTH_OFFSET: usize = 4;
    const ATTRIBUTE_LIST_NAME_LENGTH_OFFSET: usize = 6;
    const ATTRIBUTE_LIST_NAME_OFFSET_OFFSET: usize = 7;
    const ATTRIBUTE_LIST_VCN_OFFSET: usize = 8;
    const ATTRIBUTE_LIST_REFERENCE_OFFSET: usize = 16;
    const ATTRIBUTE_LIST_ID_OFFSET: usize = 24;
    const MIN_INDEX_ROOT_ROOM: usize = 64;
    const RESIDENT_INDEX_BITMAP_MAX_BYTES: usize = 64;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum MftMappingState {
        Ready,
        Reconstruct,
        WrongAnchor,
    }

    /// Distinguish recoverable descriptor loss from a contradictory critical run.
    /// Family continuation ownership is validated by the caller after bootstrap.
    pub(crate) fn mft_mapping_state(
        record: &MftRecord<'_>,
        boot: ntfs_rs::boot::BootSector,
    ) -> io::Result<MftMappingState> {
        let mut found = None;
        let mut has_list = false;
        for attribute in record.attributes() {
            let attribute = attribute?;
            has_list |= attribute.kind == ATTR_ATTRIBUTE_LIST;
            if attribute.kind != ATTR_DATA || !attribute.name_utf16le()?.is_empty() {
                continue;
            }
            if !attribute.nonresident {
                return Ok(MftMappingState::Reconstruct);
            }
            if attribute.first_vcn()? == 0 && found.replace(attribute).is_some() {
                return Ok(MftMappingState::Reconstruct);
            }
        }
        let Some(data) = found else {
            return Ok(MftMappingState::Reconstruct);
        };
        if data.flags()? != 0 {
            return Ok(MftMappingState::Reconstruct);
        }
        let mut runs = ntfs_rs::runlist::DataRuns::new(data.data_runs()?, 0);
        let Some(Ok(first)) = runs.next() else {
            return Ok(MftMappingState::Reconstruct);
        };
        let critical = system_record::MIRRORED * u64::from(boot.record_bytes);
        if first.lcn != Some(boot.mft_lcn) || first.len < critical.div_ceil(u64::from(boot.cluster_bytes)) {
            return Ok(MftMappingState::WrongAnchor);
        }
        // A readable contradictory anchor remains ambiguous even when the size
        // fields also need reconstruction.
        let minimum = system_record::RESERVED * u64::from(boot.record_bytes);
        if data.data_size()? < minimum
            || data.initialized_size()? < minimum
            || data.initialized_size()? > data.data_size()?
        {
            return Ok(MftMappingState::Reconstruct);
        }
        if ntfs_rs::write_plan::plan_nonresident_recovery(data, boot, 0, critical, |_| Ok(())).is_err() {
            return Ok(MftMappingState::Reconstruct);
        }
        if !has_list && plan_nonresident_overwrite(data, boot, 0, data.initialized_size()?, |_| Ok(())).is_err() {
            return Ok(MftMappingState::Reconstruct);
        }
        Ok(MftMappingState::Ready)
    }

    /// Recover candidate mapping from contiguous physical FILE identity groups.
    /// Raw headers establish duplicate precedence; the caller validates fixups,
    /// attributes, family ownership and the completed volume before publication.
    pub(crate) fn scan_mft_mapping<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
    ) -> io::Result<(RunSpool, u64)> {
        scan_mft_mapping_policy(image, boot, true)
    }

    fn scan_mft_mapping_policy<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        allow_isolated_duplicates: bool,
    ) -> io::Result<(RunSpool, u64)> {
        let cluster = u64::from(boot.cluster_bytes);
        let record_bytes = u64::from(boot.record_bytes);
        let volume_bytes = boot
            .total_sectors
            .checked_mul(u64::from(boot.bytes_per_sector))
            .ok_or_else(|| reject("MFT scan geometry overflow"))?;
        let mut candidates = checker::consistency::DiskInventory::new();
        let mut raw = vec![0; record_bytes as usize];
        let mut maximum = None;
        let mut group: Option<(u64, u64, u64)> = None;
        let mut physical = 0_u64;
        while physical.checked_add(record_bytes).is_some_and(|end| end <= volume_bytes) {
            image.read_exact_at(physical, &mut raw)?;
            let identity = mft_scan_identity(&raw).filter(|&number| {
                number.checked_mul(record_bytes).is_some_and(|logical| {
                    logical.checked_add(record_bytes).is_some_and(|end| end <= volume_bytes)
                        && logical % cluster == physical % cluster
                })
            });
            if let Some((start, first, last)) = group {
                if identity != last.checked_add(1) || physical != start + (last - first + 1) * record_bytes {
                    mft_scan_group(&mut candidates, start, first, last, record_bytes, cluster)?;
                    group = None;
                }
            }
            if let Some(number) = identity {
                maximum = Some(maximum.map_or(number, |old: u64| old.max(number)));
                group = Some(match group {
                    Some((start, first, _)) => (start, first, number),
                    None => (physical, number, number),
                });
            }
            physical += if identity.is_some() { record_bytes } else { record_bytes.min(cluster) };
        }
        if let Some((start, first, last)) = group {
            mft_scan_group(&mut candidates, start, first, last, record_bytes, cluster)?;
        }
        let bytes = maximum
            .and_then(|number| number.checked_add(1))
            .and_then(|records| records.checked_mul(record_bytes))
            .filter(|&bytes| bytes >= system_record::RESERVED * record_bytes)
            .ok_or_else(|| reject("MFT scan lacks the required initialized record range"))?;
        let clusters = bytes.div_ceil(cluster);
        let critical_clusters = (system_record::MIRRORED * record_bytes).div_ceil(cluster);
        let mut input = std::io::BufReader::new(candidates.finish()?);
        let mut pending = checker::consistency::inventory_next(&mut input)?;
        let mut runs = RunSpool::new()?;
        let mut cluster_raw = vec![0; cluster as usize];
        for vcn in 0..clusters {
            if pending.is_none_or(|[row_vcn, _, _, _]| row_vcn != vcn) {
                return Err(reject("MFT scan leaves an unmapped cluster"));
            }
            let mut selected: Option<(u64, u64, u64)> = None;
            while pending.is_some_and(|[row_vcn, _, _, _]| row_vcn == vcn) {
                let [_, lcn, _, mut end] = pending.unwrap();
                while pending.is_some_and(|[row_vcn, row_lcn, _, _]| row_vcn == vcn && row_lcn == lcn) {
                    let [_, _, _, next_end] = pending.unwrap();
                    end = end.max(next_end);
                    pending = checker::consistency::inventory_next(&mut input)?;
                }
                if vcn < critical_clusters {
                    if lcn == boot.mft_lcn + vcn {
                        selected = Some((lcn, end, 0));
                    } else if lcn != boot.mft_mirror_lcn + vcn {
                        return Err(reject("MFT scan has a contradictory critical-record copy"));
                    }
                    continue;
                }
                if selected.is_some() && !allow_isolated_duplicates {
                    return Err(reject("MFT header repair has competing physical record copies"));
                }
                let score = mft_scan_cluster_score(image, boot, vcn, lcn, &mut cluster_raw)?;
                match selected {
                    Some((_, previous_end, _)) if end.min(previous_end) - vcn > 1 => {
                        return Err(reject("MFT scan has overlapping multi-cluster record copies"));
                    }
                    Some((_, _, previous_score)) if score <= previous_score => {}
                    _ => selected = Some((lcn, end, score)),
                }
            }
            let lcn = selected.ok_or_else(|| reject("MFT scan lacks its primary critical-record anchor"))?.0;
            runs.push(Extent { vcn, lcn: Some(lcn), len: 1 })?;
        }
        Ok((runs, bytes))
    }

    fn mft_scan_identity(raw: &[u8]) -> Option<u64> {
        if raw.get(..rf::SIGNATURE_BYTES) != Some(b"FILE")
            || ntfs_rs::bytes::u16_at(raw, rf::USA_OFFSET).ok()? < rf::HEADER_BYTES as u16
        {
            return None;
        }
        Some(
            u64::from(u32_at(raw, rf::NUMBER_LOW_OFFSET).ok()?)
                | (u64::from(ntfs_rs::bytes::u16_at(raw, rf::NUMBER_HIGH_OFFSET).ok()?) << rf::NUMBER_HIGH_SHIFT),
        )
    }

    // Group boundaries retain the overlap width needed to reject competing ranges.
    fn mft_scan_group(
        candidates: &mut checker::consistency::DiskInventory,
        physical: u64,
        first: u64,
        last: u64,
        record_bytes: u64,
        cluster: u64,
    ) -> io::Result<()> {
        let first_vcn = first * record_bytes / cluster;
        let end_vcn = ((last + 1) * record_bytes).div_ceil(cluster);
        for vcn in first_vcn..end_vcn {
            candidates.push([vcn, physical / cluster + vcn - first_vcn, first_vcn, end_vcn])?;
        }
        Ok(())
    }

    // A torn USA must not promote a later copy over an equally complete raw group.
    fn mft_scan_cluster_score<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        vcn: u64,
        lcn: u64,
        raw: &mut [u8],
    ) -> io::Result<u64> {
        image.read_exact_at(lcn * u64::from(boot.cluster_bytes), raw)?;
        let mut expected = vcn * u64::from(boot.cluster_bytes) / u64::from(boot.record_bytes);
        let mut score = 0;
        for record in raw.chunks(boot.record_bytes as usize) {
            score += u64::from(mft_scan_identity(record) == Some(expected));
            expected += 1;
        }
        Ok(score)
    }

    /// Read a complete base list through the ordinary checked attribute reader.
    /// External lists must be fully initialized and physically covered before
    /// their entries can authorize continuation ownership.
    pub(crate) fn mft_attribute_list<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        attribute: Attribute<'_>,
    ) -> io::Result<Vec<u8>> {
        if !attribute.nonresident {
            return Ok(attribute.resident_value()?.to_vec());
        }
        let length = attribute.data_size()?;
        let volume_bytes = boot
            .total_sectors
            .checked_mul(u64::from(boot.bytes_per_sector))
            .ok_or_else(|| reject("MFT list geometry overflow"))?;
        if attribute.flags()? != 0
            || attribute.first_vcn()? != 0
            || attribute.initialized_size()? != length
            || length > volume_bytes
        {
            return Err(reject("MFT list lacks a complete physical stream"));
        }
        plan_nonresident_overwrite(attribute, boot, 0, length, |_| Ok(()))?;
        let length = length as usize;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(io::Error::other)?;
        bytes.resize(length, 0);
        Volume::new(image, boot)?.read_attribute(attribute, 0, &mut bytes)?;
        Ok(bytes)
    }

    // A zero sequence or stale sequence in a same-base backreference can be
    // restored from the intact list only when all other attributes keep exact
    // membership. Distinct nonzero sequences and different base numbers refuse.
    fn mft_member_header_repairs<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        record: &MftRecord<'_>,
        runs: &RunSpool,
    ) -> io::Result<Vec<Patch>> {
        let Some(list) = record
            .attributes()
            .find_map(|attribute| attribute.ok().filter(|attribute| attribute.kind == ATTR_ATTRIBUTE_LIST))
        else {
            return Ok(Vec::new());
        };
        let list = mft_attribute_list(image, boot, list)?;
        let entries = ntfs_rs::attrlist::AttributeList::new(&list).collect::<ntfs_rs::Result<Vec<_>>>()?;
        let base_reference = file_reference(0, record.sequence_number()?)?;
        let mut references = BTreeMap::new();
        for entry in &entries {
            if entry.kind != ATTR_DATA || !entry.name_utf16le.is_empty() || entry.first_vcn == 0 {
                continue;
            }
            let number = ntfs_rs::mft::reference_number(entry.file_reference);
            if references.insert(number, entry.file_reference).is_some_and(|old| old != entry.file_reference) {
                return Err(reject("MFT list has competing continuation identities"));
            }
        }
        let mut patches = Vec::new();
        for (number, reference) in references {
            let before = mft_scan_read_record(image, boot, runs, number)?;
            let mut decoded = before.clone();
            let member = MftRecord::parse(&mut decoded, boot.bytes_per_sector)?;
            let sequence = u64::from(member.sequence_number()?);
            let owner = member.base_file_reference()?;
            if sequence == u64::from(ntfs_rs::mft::reference_sequence(reference)) && owner == base_reference {
                continue;
            }
            if number < system_record::RESERVED
                || member.physical_record_number()? != Some(number)
                || member.flags()? & rf::IN_USE == 0
                || u64::from(ntfs_rs::mft::reference_sequence(reference)) == 0
                || (sequence != 0 && sequence != u64::from(ntfs_rs::mft::reference_sequence(reference)))
                || owner == 0
                || ntfs_rs::mft::reference_number(owner) != 0
            {
                return Err(reject("MFT continuation header lacks unambiguous ownership"));
            }
            let attributes = member.attributes().collect::<ntfs_rs::Result<Vec<_>>>()?;
            let matches = |attribute: &Attribute<'_>, entry: &ntfs_rs::attrlist::ListEntry<'_>| {
                attribute.id == entry.attribute_id
                    && attribute.kind == entry.kind
                    && attribute.name_utf16le().is_ok_and(|name| name == entry.name_utf16le)
                    && if attribute.nonresident {
                        attribute.first_vcn().ok() == Some(entry.first_vcn)
                    } else {
                        entry.first_vcn == 0
                    }
            };
            for attribute in &attributes {
                if attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() {
                    continue;
                }
                if entries.iter().filter(|entry| entry.file_reference == reference && matches(attribute, entry)).count()
                    != 1
                {
                    return Err(reject("MFT header repair would change non-DATA membership"));
                }
            }
            for entry in entries.iter().filter(|entry| {
                entry.file_reference == reference && (entry.kind != ATTR_DATA || !entry.name_utf16le.is_empty())
            }) {
                if attributes.iter().filter(|attribute| matches(attribute, entry)).count() != 1 {
                    return Err(reject("MFT header repair lacks a surviving listed attribute"));
                }
            }
            decoded[rf::SEQUENCE_OFFSET..rf::SEQUENCE_END]
                .copy_from_slice(&((u64::from(ntfs_rs::mft::reference_sequence(reference))) as u16).to_le_bytes());
            decoded[rf::BASE_REFERENCE_OFFSET..rf::BASE_REFERENCE_END].copy_from_slice(&base_reference.to_le_bytes());
            protect_mft_record(&mut decoded, boot.bytes_per_sector)?;
            let start = number * u64::from(boot.record_bytes);
            let end = start + u64::from(boot.record_bytes);
            let cluster = u64::from(boot.cluster_bytes);
            for index in 0..runs.len() {
                let run = runs.get(index)?;
                let first = start.max(run.vcn * cluster);
                let stop = end.min((run.vcn + run.len) * cluster);
                if first >= stop {
                    continue;
                }
                let offset = (first - start) as usize;
                let length = (stop - first) as usize;
                patches.push(Patch::new(
                    run.lcn.ok_or_else(|| reject("MFT header repair is sparse"))? * cluster + first - run.vcn * cluster,
                    before[offset..offset + length].to_vec(),
                    decoded[offset..offset + length].to_vec(),
                ));
            }
        }
        if !patches.is_empty() {
            // Header authority requires one physical mapping, even where an
            // ordinary descriptor repair permits a calibrated isolated duplicate.
            scan_mft_mapping_policy(image, boot, false)?;
        }
        Ok(patches)
    }

    // Retained descriptors must agree with the mapping. A complete scanned
    // mapping can replace damaged DATA descriptors only in checked owned members.
    fn mft_reconstruction_prefix<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        record: &MftRecord<'_>,
        runs: &RunSpool,
        bytes: u64,
        rebuild_descriptors: bool,
    ) -> io::Result<(u64, Option<u16>)> {
        let last = runs.get(runs.len().checked_sub(1).ok_or_else(|| reject("empty MFT mapping"))?)?;
        let clusters = last
            .vcn
            .checked_add(last.len)
            .filter(|&clusters| clusters >= bytes.div_ceil(u64::from(boot.cluster_bytes)))
            .ok_or_else(|| reject("MFT mapping is shorter than its initialized range"))?;
        let mut list = None;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST && list.replace(attribute).is_some() {
                return Err(reject("MFT base has competing attribute lists"));
            }
        }
        let Some(list) = list else {
            return Ok((clusters, None));
        };
        let list_bytes = mft_attribute_list(image, boot, list)?;
        let entries = ntfs_rs::attrlist::AttributeList::new(&list_bytes).collect::<ntfs_rs::Result<Vec<_>>>()?;
        let base_reference = file_reference(0, record.sequence_number()?)?;
        let mut data: Vec<_> =
            entries.into_iter().filter(|entry| entry.kind == ATTR_DATA && entry.name_utf16le.is_empty()).collect();
        data.sort_by_key(|entry| entry.first_vcn);
        let first = data.first().ok_or_else(|| reject("MFT list omits its base DATA identity"))?;
        if first.first_vcn != 0 || first.file_reference != base_reference {
            return Err(reject("MFT list lacks its owned base DATA identity"));
        }
        let prefix = data.get(1).map_or(clusters, |entry| entry.first_vcn);
        if prefix < (system_record::MIRRORED * u64::from(boot.record_bytes)).div_ceil(u64::from(boot.cluster_bytes)) {
            return Err(reject("MFT continuation interrupts its critical prefix"));
        }
        let mut next = prefix;
        for (index, entry) in data.iter().enumerate().skip(1) {
            if entry.first_vcn != next || entry.file_reference == base_reference {
                return Err(reject("MFT DATA continuation is not an external contiguous segment"));
            }
            let number = ntfs_rs::mft::reference_number(entry.file_reference);
            let mut raw = mft_scan_read_record(image, boot, runs, number)?;
            let member = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            if member.physical_record_number()? != Some(number)
                || member.sequence_number()? as u64 != u64::from(ntfs_rs::mft::reference_sequence(entry.file_reference))
                || member.base_file_reference()? != base_reference
                || member.flags()? & rf::IN_USE == 0
            {
                return Err(reject("MFT DATA continuation has a stale or foreign owner"));
            }
            if rebuild_descriptors {
                let end = data.get(index + 1).map_or(clusters, |next| next.first_vcn);
                if end <= next || end > clusters {
                    return Err(reject("MFT DATA continuation has a contradictory list range"));
                }
                for attribute in member.attributes() {
                    attribute?;
                }
                next = end;
                continue;
            }
            let attributes = member.attributes().collect::<ntfs_rs::Result<Vec<_>>>()?;
            let attribute = attributes
                .into_iter()
                .find(|attribute| {
                    attribute.id == entry.attribute_id
                        && attribute.kind == ATTR_DATA
                        && attribute.name_utf16le().is_ok_and(|name| name.is_empty())
                })
                .ok_or_else(|| reject("MFT DATA continuation is missing its listed attribute"))?;
            if !attribute.nonresident || attribute.flags()? != 0 || attribute.first_vcn()? != next {
                return Err(reject("MFT DATA continuation has a contradictory descriptor"));
            }
            let end = attribute
                .last_vcn()?
                .checked_add(1)
                .filter(|&end| end > next && end <= clusters)
                .ok_or_else(|| reject("MFT DATA continuation exceeds the recovered stream"))?;
            ntfs_rs::write_plan::plan_nonresident_recovery(
                attribute,
                boot,
                next * u64::from(boot.cluster_bytes),
                (end - next) * u64::from(boot.cluster_bytes),
                |_| Ok(()),
            )?;
            for extent in ntfs_rs::runlist::DataRuns::new(attribute.data_runs()?, next) {
                let extent = extent?;
                let mut covered = extent.vcn;
                for index in 0..runs.len() {
                    let expected = runs.get(index)?;
                    let start = extent.vcn.max(expected.vcn);
                    let stop = (extent.vcn + extent.len).min(expected.vcn + expected.len);
                    if start >= stop {
                        continue;
                    }
                    if start != covered
                        || extent.lcn.map(|lcn| lcn + start - extent.vcn)
                            != expected.lcn.map(|lcn| lcn + start - expected.vcn)
                    {
                        return Err(reject("MFT continuation differs from the recovered physical mapping"));
                    }
                    covered = stop;
                }
                if covered != extent.vcn + extent.len {
                    return Err(reject("MFT continuation lacks recovered physical coverage"));
                }
            }
            next = end;
        }
        if next != clusters {
            return Err(reject("MFT family lacks the complete recovered tail"));
        }
        Ok((prefix, Some(first.attribute_id)))
    }

    // Read one bounded physical record through candidate runs; decoding and
    // ownership checks remain mandatory before those bytes can authorize repair.
    fn mft_scan_read_record<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        runs: &RunSpool,
        number: u64,
    ) -> io::Result<Vec<u8>> {
        let cluster = u64::from(boot.cluster_bytes);
        let start = number
            .checked_mul(u64::from(boot.record_bytes))
            .ok_or_else(|| reject("MFT candidate record offset overflow"))?;
        let end = start
            .checked_add(u64::from(boot.record_bytes))
            .ok_or_else(|| reject("MFT candidate record range overflow"))?;
        let mut raw = vec![0; boot.record_bytes as usize];
        let mut covered = start;
        for index in 0..runs.len() {
            let run = runs.get(index)?;
            let first = start.max(run.vcn * cluster);
            let stop = end.min((run.vcn + run.len) * cluster);
            if first >= stop {
                continue;
            }
            if first != covered {
                return Err(reject("MFT candidate record has a mapping gap"));
            }
            let physical =
                run.lcn.ok_or_else(|| reject("MFT candidate record is sparse"))? * cluster + first - run.vcn * cluster;
            image.read_exact_at(physical, &mut raw[(first - start) as usize..(stop - start) as usize])?;
            covered = stop;
        }
        if covered != end {
            return Err(reject("MFT candidate record is incompletely mapped"));
        }
        Ok(raw)
    }

    /// Rebuild DATA in an intact base whose mapping fits one physical record.
    /// The proposed protected record still requires caller validation/publication.
    pub(crate) fn reconstruct_mft_data<R: ReadAt>(
        image: &mut R,
        boot: ntfs_rs::boot::BootSector,
        raw: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut decoded = raw.to_vec();
        let record = MftRecord::parse(&mut decoded, boot.bytes_per_sector)?;
        if record.attributes().any(|attribute| attribute.is_ok_and(|a| a.kind == ATTR_ATTRIBUTE_LIST)) {
            return Err(reject("MFT mapping reconstruction requires family publication"));
        }
        let (runs, bytes) = scan_mft_mapping(image, boot)?;
        let mut proposed = mft_mapping_image(&decoded, boot, &runs, bytes, bytes, None, decoded.len())?;
        protect_mft_record(&mut proposed, boot.bytes_per_sector)?;
        Ok(proposed)
    }

    // Keep complete mapping in decoded scratch. Physical publication and its
    // descriptor capacity belong to the caller's ordinary family publisher.
    fn mft_mapping_image(
        decoded: &[u8],
        boot: ntfs_rs::boot::BootSector,
        runs: &RunSpool,
        data_bytes: u64,
        initialized: u64,
        listed_identity: Option<u16>,
        capacity: usize,
    ) -> io::Result<Vec<u8>> {
        let parsed = MftRecord::from_decoded(decoded)?;
        if parsed.base_file_reference()? != 0
            || parsed.flags()? & rf::IN_USE == 0
            || parsed.physical_record_number()? != Some(0)
        {
            return Err(reject("MFT reconstruction lacks an identified valid base record"));
        }
        let mut remove = Vec::new();
        let mut identity = listed_identity;
        for attribute in parsed.attributes() {
            let attribute = attribute?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST {
                remove.push(attribute.record_offset());
            } else if attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() {
                remove.push(attribute.record_offset());
                identity.get_or_insert(attribute.id);
            }
        }
        // Even the shortest descriptor takes three bytes. Bound caller-owned
        // scratch before collecting spooled extents; physical capacity belongs
        // to the family publisher or the single-record caller.
        if capacity < decoded.len() || runs.len() > capacity as u64 / MIN_ALLOCATED_MAPPING_PAIR_BYTES {
            return Err(reject("reconstructed MFT mapping requires extension records"));
        }
        let extents = (0..runs.len()).map(|number| runs.get(number)).collect::<io::Result<Vec<_>>>()?;
        let mut attribute = vec![0; capacity];
        let allocated = runs
            .mapped_clusters()?
            .checked_mul(u64::from(boot.cluster_bytes))
            .ok_or_else(|| reject("MFT reconstructed allocation overflow"))?;
        let length =
            e::build_nonresident(ATTR_DATA, &[], &extents, allocated, data_bytes, initialized, &mut attribute)?;
        attribute.truncate(length);
        let mut record = decoded.to_vec();
        record.resize(capacity, 0);
        e::p32(&mut record, rf::CAPACITY_OFFSET, u32::try_from(capacity).map_err(io::Error::other)?)?;
        for offset in remove.into_iter().rev() {
            e::remove(&mut record, offset)?;
        }
        let offset = e::insert(&mut record, &attribute)?;
        if let Some(identity) = identity {
            e::p16(&mut record, offset + af::ID_OFFSET, identity)?;
        }
        e::validate(&record)?;
        Ok(record)
    }

    // Capacity comes from the complete checked mapping, independently of stream
    // length fields. Slots in an allocated but uninitialized suffix remain real.
    fn mft_physical_capacity<R: ReadAt>(volume: &Volume<R>, mft: &MftRecord<'_>) -> io::Result<u64> {
        let data = mft.stream(ATTR_DATA, &[])?;
        if !data.nonresident || data.flags()? != 0 {
            return Err(reject("MFT padding lacks a dense physical mapping"));
        }
        let mut clusters = 0_u64;
        for extent in ntfs_rs::runlist::DataRuns::new(data.data_runs()?, 0) {
            let extent = extent?;
            if extent.vcn != clusters || extent.lcn.is_none() {
                return Err(reject("MFT padding lacks continuous physical coverage"));
            }
            clusters = clusters.checked_add(extent.len).ok_or_else(|| reject("MFT capacity overflow"))?;
        }
        let bytes = clusters
            .checked_mul(u64::from(volume.boot.cluster_bytes))
            .ok_or_else(|| reject("MFT capacity overflow"))?;
        ntfs_rs::write_plan::plan_nonresident_recovery(data, volume.boot, 0, bytes, |_| Ok(()))?;
        Ok(bytes / u64::from(volume.boot.record_bytes))
    }

    // A resident value remains in its checked owner with its existing attribute ID.
    // Missing allocation bits are refused; growth only supplies reserved padding.
    pub(crate) fn mft_resident_bitmap_repairs<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        clear_padding: bool,
        mut emit: impl FnMut(Patch) -> io::Result<()>,
    ) -> io::Result<()> {
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        if bitmap.nonresident {
            return Ok(());
        }
        if bitmap.flags()? != 0 {
            return Err(reject("unsupported resident MFT bitmap flags"));
        }
        let old = bitmap.resident_value()?;
        let initialized = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
        if (old.len() as u64) < initialized.div_ceil(BITMAP_BITS_PER_BYTE) {
            return Err(reject("resident MFT bitmap lacks actual allocation bits"));
        }
        let size = ((old.len() as u64).div_ceil(BITMAP_WORD_BYTES) * BITMAP_WORD_BYTES)
            .max(initialized.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES);
        let mut value = old.to_vec();
        value.resize(size as usize, 0);
        if clear_padding {
            let slots = mft_physical_capacity(volume, mft)?;
            let offset = (slots / BITMAP_BITS_PER_BYTE) as usize;
            if offset < value.len() {
                let partial = slots % BITMAP_BITS_PER_BYTE;
                value[offset] &= if partial == 0 { 0 } else { (1_u8 << partial) - 1 };
                value[offset + 1..].fill(0);
            }
        }
        if value == old {
            return Ok(());
        }
        let family = RepairFamily::load(volume, mft, system_record::MFT)?;
        let mut plan = RepairPlan::new(
            volume
                .boot
                .total_sectors
                .checked_mul(u64::from(volume.boot.bytes_per_sector))
                .ok_or_else(|| reject("MFT bitmap publication length overflow"))?,
        )?;
        let mut target = None;
        for (&reference, (_, member)) in &family.members {
            for attribute in MftRecord::from_decoded(member)?.attributes() {
                let attribute = attribute?;
                if attribute.kind == ATTR_BITMAP
                    && attribute.name_utf16le()?.is_empty()
                    && target.replace((reference, attribute.record_offset())).is_some()
                {
                    return Err(reject("competing resident MFT bitmap owners"));
                }
            }
        }
        let (reference, offset) = target.ok_or_else(|| reject("missing resident MFT bitmap owner"))?;
        let (before, member) = &family.members[&reference];
        let mut after = member.clone();
        e::set_resident_value(&mut after, offset, &value)?;
        e::validate(&after)?;
        protect_mft_record(&mut after, volume.boot.bytes_per_sector)?;
        repair_record_patch(
            volume,
            mft.stream(ATTR_DATA, &[])?,
            ntfs_rs::mft::reference_number(reference),
            before,
            &after,
            &mut plan,
        )?;
        for patch in plan.iter() {
            emit(patch?)?;
        }
        Ok(())
    }

    // Only bits beyond complete dense physical capacity are padding. Declared
    // initialization may be damaged, so bits inside that mapping remain intact.
    pub(crate) fn mft_bitmap_padding_repairs<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        mut emit: impl FnMut(Patch) -> io::Result<()>,
    ) -> io::Result<()> {
        let slots = mft_physical_capacity(volume, mft)?;
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        if !bitmap.nonresident {
            return mft_resident_bitmap_repairs(volume, mft, true, emit);
        }
        let end = bitmap.initialized_size()?;
        let mut offset = slots / BITMAP_BITS_PER_BYTE;
        while offset < end {
            let count = (end - offset).min(REPAIR_CHUNK_BYTES) as usize;
            let mut before = vec![0; count];
            volume.read_attribute(bitmap, offset, &mut before)?;
            let mut after = vec![0; count];
            if offset == slots / BITMAP_BITS_PER_BYTE && slots % BITMAP_BITS_PER_BYTE != 0 {
                after[0] = before[0] & ((1_u8 << (slots % BITMAP_BITS_PER_BYTE)) - 1);
            }
            if after != before {
                for span in overwrite_spans(bitmap, volume.boot, offset, count as u64)? {
                    let start = span.source_offset as usize;
                    let stop = start + span.length as usize;
                    emit(Patch::new(span.physical_offset, before[start..stop].to_vec(), after[start..stop].to_vec()))?;
                }
            }
            offset += count as u64;
        }
        Ok(())
    }

    // With no usable list, a unique complete mapping can locate members whose
    // physical identity and exact base backreference independently agree.
    fn mft_unlisted_members<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        reference: u64,
    ) -> io::Result<BTreeMap<u64, (Vec<u8>, Vec<u8>)>> {
        let slots = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
        let volume_clusters = volume.boot.total_sectors / u64::from(volume.boot.sectors_per_cluster);
        let mut members = BTreeMap::new();
        for number in 0..slots {
            let mut raw = vec![0; volume.boot.record_bytes as usize];
            volume.read_mft_record(mft, number, &mut raw)?;
            let before = raw.clone();
            let member = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
            if member.flags()? & rf::IN_USE == 0 {
                continue;
            }
            let owner = member.base_file_reference()?;
            if number != 0 && owner != reference {
                if owner != 0 {
                    // A foreign continuation cannot authorize the lost MFT list,
                    // especially when it claims those same physical DATA runs.
                    for attribute in member.attributes() {
                        let attribute = attribute?;
                        if attribute.kind != ATTR_DATA
                            || !attribute.nonresident
                            || !attribute.name_utf16le()?.is_empty()
                        {
                            continue;
                        }
                        for claimed in ntfs_rs::runlist::DataRuns::new(attribute.data_runs()?, attribute.first_vcn()?) {
                            let claimed = claimed?;
                            let Some(start) = claimed.lcn else { continue };
                            let end = start
                                .checked_add(claimed.len)
                                .filter(|&end| end <= volume_clusters)
                                .ok_or_else(|| reject("foreign MFT candidate DATA exceeds the volume"))?;
                            for mapped in ntfs_rs::runlist::DataRuns::new(mft.stream(ATTR_DATA, &[])?.data_runs()?, 0) {
                                let mapped = mapped?;
                                let Some(lcn) = mapped.lcn else { continue };
                                let mapped_end = lcn
                                    .checked_add(mapped.len)
                                    .filter(|&end| end <= volume_clusters)
                                    .ok_or_else(|| reject("recovered MFT DATA exceeds the volume"))?;
                                if start < mapped_end && lcn < end {
                                    return Err(reject("unlisted MFT DATA has a competing foreign owner"));
                                }
                            }
                        }
                    }
                }
                continue;
            }
            let sequence = u64::from(member.sequence_number()?);
            if member.physical_record_number()? != Some(number)
                || sequence == 0
                || (number == 0
                    && (member.base_file_reference()? != 0
                        || sequence != u64::from(ntfs_rs::mft::reference_sequence(reference))))
            {
                return Err(reject("unlisted MFT member lacks its physical ownership identity"));
            }
            for attribute in member.attributes() {
                let attribute = attribute?;
                if number != 0 && attribute.kind == ATTR_ATTRIBUTE_LIST {
                    return Err(reject("unlisted MFT member has competing family topology"));
                }
            }
            members.insert(file_reference(number, sequence as u16)?, (before, raw));
        }
        if !members.contains_key(&reference) {
            return Err(reject("unlisted MFT family lacks its critical base"));
        }
        Ok(members)
    }

    // A stale allocation claim can be cleared only for a framed, modern empty
    // placeholder. Missing flags on a record with any surviving attributes do not
    // establish that its ownership has ended.
    pub(crate) fn mft_empty_free_slot(record: &MftRecord<'_>, number: u64) -> io::Result<bool> {
        if number < system_record::RESERVED
            || record.physical_record_number()? != Some(number)
            || record.flags()? != 0
            || record.sequence_number()? == 0
        {
            return Ok(false);
        }
        if let Some(attribute) = record.attributes().next() {
            attribute?;
            return Ok(false);
        }
        Ok(true)
    }

    // A historical backreference is harmless only when its readable live base
    // has no membership for this empty slot. Reuse ordinary family validation;
    // unreadable or contradictory live ownership cannot authorize clearing.
    pub(crate) fn mft_empty_slot_unowned<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        record: &MftRecord<'_>,
        number: u64,
    ) -> io::Result<bool> {
        let owner = record.base_file_reference()?;
        if owner == 0 {
            return Ok(true);
        }
        let base = ntfs_rs::mft::reference_number(owner);
        let slots = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
        if base >= slots {
            return Ok(true);
        }
        let mut raw = vec![0; volume.boot.record_bytes as usize];
        volume.read_mft_record(mft, base, &mut raw)?;
        let candidate = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
        if candidate.flags()? & rf::IN_USE == 0 {
            return Ok(true);
        }
        let family = RepairFamily::load(volume, mft, base)?;
        Ok(!family.members.keys().any(|reference| ntfs_rs::mft::reference_number(*reference) == number))
    }

    // Reconcile missing bitmap bits with every framed, uniquely mapped record.
    // Retain readable claims; only framed empty slots can lose stale claims.
    // Validate live families before exposing any derived free space.
    fn mft_missing_bitmap_bits<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        members: &BTreeMap<u64, (Vec<u8>, Vec<u8>)>,
    ) -> io::Result<Option<(File, u64)>> {
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let known = bitmap.initialized_size()?;
        let slots = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
        if bitmap.flags()? != 0 || known > bitmap.data_size()? {
            return Err(reject("unsupported MFT bitmap initialization"));
        }
        let readable = !bitmap.nonresident
            || (bitmap.first_vcn()? == 0
                && plan_nonresident_overwrite(bitmap, volume.boot, 0, known, |_| Ok(())).is_ok());
        let known = if readable { known } else { 0 };
        if readable && known >= slots.div_ceil(BITMAP_BITS_PER_BYTE) {
            return Ok(None);
        }
        let bytes = bitmap
            .data_size()?
            .checked_add(BITMAP_WORD_BYTES - 1)
            .map(|bytes| (bytes & !(BITMAP_WORD_BYTES - 1)).max(slots.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES))
            .ok_or_else(|| reject("derived MFT bitmap length overflow"))?;
        let mut value = checker::consistency::scratch_file()?;
        let mut cache = (u64::MAX, [0_u8; BITMAP_CACHE_BYTES]);
        let mut byte = 0_u8;
        let boot = volume.boot;
        let mut raw = vec![0; boot.record_bytes as usize];
        for number in 0..slots {
            if number % BITMAP_BITS_PER_BYTE == 0 {
                byte = if number / BITMAP_BITS_PER_BYTE < known {
                    bitmap_byte(volume, bitmap, number / BITMAP_BITS_PER_BYTE, known, &mut cache)?
                } else {
                    0
                };
            }
            volume.read_mft_record(mft, number, &mut raw)?;
            MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            e::validate(&raw)?;
            let record = MftRecord::from_decoded(&raw)?;
            let identity = record.physical_record_number()?;
            let legacy_base = identity.is_none()
                && number >= system_record::RESERVED
                && record.flags()? & rf::IN_USE != 0
                && record.sequence_number()? != 0
                && record.base_file_reference()? == 0
                && !record
                    .attributes()
                    .any(|attribute| attribute.is_ok_and(|attribute| attribute.kind == ATTR_ATTRIBUTE_LIST));
            if (identity != Some(number) && !legacy_base) || record.flags()? & !rf::KNOWN_FLAGS != 0 {
                return Err(reject("missing MFT bit lacks a checked mapped record identity"));
            }
            // A legacy live base can derive its own bit through the existing
            // mapping. Its USA is not an identity field, and it cannot establish
            // extension membership or an unused slot without an existing claim.
            if record.flags()? & rf::IN_USE == 0 {
                if byte & (1 << (number % BITMAP_BITS_PER_BYTE)) != 0 {
                    if !mft_empty_free_slot(&record, number)? {
                        return Err(reject("claimed free MFT slot lacks an empty physical record"));
                    }
                    let owner = record.base_file_reference()?;
                    // This MFT family's membership was already validated against
                    // the recovered mapping; its damaged raw base is not authority.
                    let unowned = if owner != 0 && ntfs_rs::mft::reference_number(owner) == 0 {
                        !members.keys().any(|reference| ntfs_rs::mft::reference_number(*reference) == number)
                    } else {
                        mft_empty_slot_unowned(volume, mft, &record, number)?
                    };
                    if !unowned {
                        return Err(reject("claimed empty MFT slot still has live ownership"));
                    }
                    byte &= !(1 << (number % BITMAP_BITS_PER_BYTE));
                }
                if number % BITMAP_BITS_PER_BYTE == BITMAP_BITS_PER_BYTE - 1 || number + 1 == slots {
                    value.write_all(&[byte])?;
                    byte = 0;
                }
                continue;
            }
            let sequence = u64::from(record.sequence_number()?);
            if sequence == 0 {
                return Err(reject("missing MFT bit has an unowned live record"));
            }
            let reference = file_reference(number, sequence as u16)?;
            let owner = record.base_file_reference()?;
            if !members.contains_key(&reference) {
                let base = if owner == 0 { reference } else { owner };
                let family = RepairFamily::load(volume, mft, ntfs_rs::mft::reference_number(base))?;
                if family.reference != base || !family.members.contains_key(&reference) {
                    return Err(reject("missing MFT bit has a stale or foreign family owner"));
                }
                for (&identity, (_, decoded)) in &family.members {
                    let member = MftRecord::from_decoded(decoded)?;
                    let mapped_legacy_base = legacy_base
                        && family.members.len() == 1
                        && identity == reference
                        && member.physical_record_number()?.is_none();
                    if (member.physical_record_number()? != Some(ntfs_rs::mft::reference_number(identity))
                        && !mapped_legacy_base)
                        || member.flags()? & rf::IN_USE == 0
                        || u64::from(member.sequence_number()?) != u64::from(ntfs_rs::mft::reference_sequence(identity))
                    {
                        return Err(reject("missing MFT bit has a contradictory family identity"));
                    }
                }
            }
            byte |= 1 << (number % BITMAP_BITS_PER_BYTE);
            if number % BITMAP_BITS_PER_BYTE == BITMAP_BITS_PER_BYTE - 1 || number + 1 == slots {
                value.write_all(&[byte])?;
                byte = 0;
            }
        }
        let mut present = value.stream_position()?;
        let zeros = [0_u8; BITMAP_CACHE_BYTES];
        while present < bytes {
            let count = (bytes - present).min(zeros.len() as u64) as usize;
            value.write_all(&zeros[..count])?;
            present += count as u64;
        }
        value.rewind()?;
        Ok(Some((value, bytes)))
    }

    // Replace one unreadable first segment only in private decoded scratch. Its
    // owner and ID remain available to the ordinary family publisher; independently
    // validated physical records must supply every actual bit before allocation.
    fn mft_unreadable_bitmap(decoded: &mut [u8], boot: ntfs_rs::boot::BootSector) -> io::Result<bool> {
        let mut damaged_bitmap = None;
        for attribute in MftRecord::from_decoded(decoded)?.attributes() {
            let attribute = attribute?;
            if attribute.kind == ATTR_BITMAP
                && attribute.name_utf16le()?.is_empty()
                && attribute.nonresident
                && attribute.first_vcn()? == 0
                && ntfs_rs::write_plan::plan_nonresident_recovery(attribute, boot, 0, 0, |_| Ok(())).is_err()
            {
                if attribute.flags()? != 0
                    || damaged_bitmap.replace((attribute.record_offset(), attribute.id)).is_some()
                {
                    return Err(reject("MFT bitmap has unsupported or competing descriptors"));
                }
            }
        }
        if let Some((offset, identity)) = damaged_bitmap {
            // Unreadable bytes provide no allocation claims. A private empty
            // descriptor permits checked record-state derivation below; it is
            // never published or used by an allocator.
            e::remove(decoded, offset)?;
            let mut empty = [0; EMPTY_ATTRIBUTE_SCRATCH_BYTES];
            let length = e::build_resident(ATTR_BITMAP, &[], &[], &mut empty)?;
            let at = e::insert(decoded, &empty[..length])?;
            e::p16(decoded, at + af::ID_OFFSET, identity)?;
        }
        Ok(damaged_bitmap.is_some())
    }

    /// Consolidate checked MFT DATA segments through ordinary family publication.
    /// The temporary full mapping is never itself published. Every returned
    /// preimage is read from the real input view, including the mirrored base.
    pub(crate) fn reconstruct_mft_family(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        previous: &Vec<Patch>,
        raw: &[u8],
    ) -> io::Result<Vec<Patch>> {
        let mut decoded = raw.to_vec();
        MftRecord::parse(&mut decoded, boot.bytes_per_sector)?;
        let damaged_bitmap = mft_unreadable_bitmap(&mut decoded, boot)?;
        let mut damaged_list = None;
        let mut surviving_list = None;
        let mut list_count = 0;
        let volume_bytes = boot
            .total_sectors
            .checked_mul(u64::from(boot.bytes_per_sector))
            .ok_or_else(|| reject("MFT list geometry overflow"))?;
        let mut reader = PlannedImage::open(source, previous)?;
        for attribute in MftRecord::from_decoded(&decoded)?.attributes() {
            let attribute = attribute?;
            if attribute.kind != ATTR_ATTRIBUTE_LIST {
                continue;
            }
            list_count += 1;
            if list_count > 1 {
                return Err(reject("MFT base has competing attribute lists"));
            }
            let bytes = match mft_attribute_list(&mut reader, boot, attribute) {
                Ok(bytes) => Some(bytes),
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidData
                        && attribute.nonresident
                        && attribute.flags()? == 0
                        && attribute.name_utf16le()?.is_empty()
                        && attribute.first_vcn()? == 0
                        && attribute.data_size()? <= volume_bytes
                        && attribute.allocated_size()? <= volume_bytes
                        && attribute.initialized_size()? == attribute.data_size()? =>
                {
                    None
                }
                Err(error) => return Err(error),
            };
            let (rebuild, retain) = if let Some(bytes) = &bytes {
                match ntfs_rs::attrlist::AttributeList::new(bytes).collect::<ntfs_rs::Result<Vec<_>>>() {
                    Err(_) => (true, false),
                    Ok(entries) => {
                        // An omitted base DATA row supplies no contrary owner.
                        // Every remaining readable identity stays authoritative.
                        let absent = !entries.iter().any(|entry| {
                            entry.kind == ATTR_DATA && entry.name_utf16le.is_empty() && entry.first_vcn == 0
                        });
                        (absent, absent)
                    }
                }
            } else {
                (true, false)
            };
            if rebuild {
                if damaged_list.replace(attribute.record_offset()).is_some() {
                    return Err(reject("MFT list has competing damaged descriptors"));
                }
                if retain {
                    surviving_list = bytes;
                }
            }
        }
        let mut canonical_raw = raw.to_vec();
        if let Some(offset) = damaged_list {
            // Retain the record's other bytes; real member ownership must be
            // established through the complete mapping before list publication.
            e::remove(&mut decoded, offset)?;
            e::validate(&decoded)?;
            canonical_raw = decoded.clone();
            protect_mft_record(&mut canonical_raw, boot.bytes_per_sector)?;
        } else if damaged_bitmap {
            canonical_raw = decoded.clone();
            protect_mft_record(&mut canonical_raw, boot.bytes_per_sector)?;
        }
        let record = MftRecord::from_decoded(&decoded)?;
        let has_list = record.attributes().any(|attribute| attribute.is_ok_and(|a| a.kind == ATTR_ATTRIBUTE_LIST));
        // The caller may already have repaired an admitted reserved identity.
        // Use that private base for member reads; rebase all preimages below.
        let main_at = boot.mft_byte_offset()?;
        let mut before = vec![0; raw.len()];
        PlannedImage::open(source, previous)?.read_exact_at(main_at, &mut before)?;
        let mut canonical = previous.clone();
        canonical.push(Patch::new(main_at, before, canonical_raw));
        let mut original = PlannedImage::volume(source, &canonical, boot)?;
        let mut runs = RunSpool::new()?;
        let state = mft_mapping_state(&record, boot)?;
        let mut rebuild_descriptors = state == MftMappingState::Reconstruct;
        let (data_bytes, initialized) = match state {
            MftMappingState::Ready => {
                match checker::consistency::mft_image(&mut original) {
                    Ok(logical) => {
                        let mft = MftRecord::from_decoded(&logical)?;
                        let data = mft.stream(ATTR_DATA, &[])?;
                        for run in ntfs_rs::runlist::DataRuns::new(data.data_runs()?, 0) {
                            runs.push(run?)?;
                        }
                        (data.initialized_size()?, data.initialized_size()?)
                    }
                    Err(_) => {
                        // An intact critical anchor can precede damaged listed
                        // DATA. Complete physical identities supply its mapping;
                        // continuation ownership remains checked below.
                        let mut reader = PlannedImage::open(source, previous)?;
                        let (recovered, bytes) = scan_mft_mapping(&mut reader, boot)?;
                        runs = recovered;
                        rebuild_descriptors = true;
                        (bytes, bytes)
                    }
                }
            }
            MftMappingState::Reconstruct => {
                let mut reader = PlannedImage::open(source, previous)?;
                let (recovered, bytes) = scan_mft_mapping(&mut reader, boot)?;
                runs = recovered;
                (bytes, bytes)
            }
            MftMappingState::WrongAnchor => return Err(reject("MFT family contradicts its critical anchor")),
        };
        let mut reader = PlannedImage::open(source, previous)?;
        let headers = mft_member_header_repairs(&mut reader, boot, &record, &runs)?;
        let headers_repaired = !headers.is_empty();
        drop(original);
        canonical.extend(headers);
        let mut reader = PlannedImage::open(source, &canonical)?;
        let (_, identity) =
            mft_reconstruction_prefix(&mut reader, boot, &record, &runs, initialized, rebuild_descriptors)?;
        let capacity = usize::try_from(runs.len())
            .ok()
            .and_then(|count| count.checked_mul(MAX_MAPPING_PAIR_BYTES))
            .and_then(|bytes| bytes.checked_add(decoded.len()))
            .and_then(|bytes| bytes.checked_add(MFT_MAPPING_HEADER_BYTES))
            .filter(|&capacity| u32::try_from(capacity).is_ok())
            .ok_or_else(|| reject("MFT mapping scratch size overflow"))?;
        let mapping = mft_mapping_image(&decoded, boot, &runs, data_bytes, initialized, identity, capacity)?;
        let mapped_base = MftRecord::from_decoded(&mapping)?;
        let reference = file_reference(0, mapped_base.sequence_number()?)?;
        let mut original = PlannedImage::volume(source, &canonical, boot)?;
        let mut members = if has_list {
            repair_members(&mut original, &mapped_base, reference)?
        } else {
            let members = mft_unlisted_members(&mut original, &mapped_base, reference)?;
            if members.len() > 1 {
                scan_mft_mapping_policy(&mut reader, boot, false)?;
            }
            members
        };
        if let Some(bytes) = &surviving_list {
            let mut seen = BTreeSet::new();
            for entry in ntfs_rs::attrlist::AttributeList::new(bytes) {
                let entry = entry?;
                if !seen.insert((
                    entry.file_reference,
                    entry.kind,
                    entry.attribute_id,
                    entry.first_vcn,
                    entry.name_utf16le.to_vec(),
                )) {
                    return Err(reject("MFT list has duplicate surviving membership"));
                }
                let (_, decoded) = members
                    .get(&entry.file_reference)
                    .ok_or_else(|| reject("MFT list has a surviving foreign membership"))?;
                let record = MftRecord::from_decoded(decoded)?;
                let mut matches = 0;
                for attribute in record.attributes() {
                    let attribute = attribute?;
                    if attribute.kind == entry.kind
                        && attribute.id == entry.attribute_id
                        && attribute.name_utf16le()? == entry.name_utf16le
                        && if attribute.nonresident {
                            attribute.first_vcn()? == entry.first_vcn
                        } else {
                            entry.first_vcn == 0
                        }
                    {
                        matches += 1;
                    }
                }
                if matches != 1 {
                    return Err(reject("MFT list has a contradictory surviving attribute"));
                }
            }
        }
        let mut bitmap_members = Vec::new();
        for (&owner, (_, member)) in &mut members {
            if owner != reference && mft_unreadable_bitmap(member, boot)? {
                bitmap_members.push(owner);
            }
        }
        let list_rebuild = damaged_list.is_some() || (!has_list && members.len() > 1);
        // The bitmap and other streams may live in surviving members. Assemble
        // their checked attributes with the full mapping only in private scratch.
        let capacity = members
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(boot.record_bytes as usize))
            .map(|capacity| capacity.max(mapping.len()))
            .filter(|&capacity| u32::try_from(capacity).is_ok())
            .ok_or_else(|| reject("MFT family scratch size overflow"))?;
        let mut logical = mapping.clone();
        logical.resize(capacity, 0);
        e::p32(&mut logical, rf::CAPACITY_OFFSET, capacity as u32)?;
        for (&owner, (_, member)) in &members {
            if owner == reference {
                continue;
            }
            for attribute in MftRecord::from_decoded(member)?.attributes() {
                let attribute = attribute?;
                if attribute.kind == ATTR_ATTRIBUTE_LIST
                    || (attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty())
                {
                    continue;
                }
                let start = attribute.record_offset();
                let end = start + e::attr_len(member, start)?;
                e::merge_attribute(&mut logical, &member[start..end])?;
            }
        }
        let bitmap_absent = !MftRecord::from_decoded(&logical)?.attributes().any(|attribute| {
            attribute.is_ok_and(|a| a.kind == ATTR_BITMAP && a.name_utf16le().is_ok_and(|name| name.is_empty()))
        });
        if bitmap_absent {
            let mut empty = [0; EMPTY_ATTRIBUTE_SCRATCH_BYTES];
            let length = e::build_resident(ATTR_BITMAP, &[], &[], &mut empty)?;
            e::insert(&mut logical, &empty[..length])?;
        }
        e::validate(&logical)?;
        let mut reconstructed_bitmap = {
            let mft = MftRecord::from_decoded(&logical)?;
            let bitmap = mft.stream(ATTR_BITMAP, &[])?;
            let unreadable_bitmap = bitmap.nonresident
                && plan_nonresident_overwrite(bitmap, boot, 0, bitmap.initialized_size()?, |_| Ok(())).is_err();
            if bitmap_absent
                || unreadable_bitmap
                || bitmap.initialized_size()?
                    < (initialized / u64::from(boot.record_bytes)).div_ceil(BITMAP_BITS_PER_BYTE)
            {
                let (unique, bytes) = scan_mft_mapping_policy(&mut reader, boot, false)?;
                if bytes < initialized {
                    return Err(reject("missing MFT bitmap bits have competing physical mapping"));
                }
                let mut expected_index = 0;
                for index in 0..unique.len() {
                    let actual = unique.get(index)?;
                    let end = actual
                        .vcn
                        .checked_add(actual.len)
                        .ok_or_else(|| reject("unique MFT mapping range overflow"))?
                        .min(initialized.div_ceil(u64::from(boot.cluster_bytes)));
                    if actual.vcn >= end {
                        break;
                    }
                    let mut at = actual.vcn;
                    while at < end {
                        let expected = runs.get(expected_index)?;
                        let expected_end = expected
                            .vcn
                            .checked_add(expected.len)
                            .ok_or_else(|| reject("selected MFT mapping range overflow"))?;
                        if at < expected.vcn
                            || at >= expected_end
                            || actual.lcn.and_then(|lcn| lcn.checked_add(at - actual.vcn))
                                != expected.lcn.and_then(|lcn| lcn.checked_add(at - expected.vcn))
                        {
                            return Err(reject("missing MFT bitmap bits contradict the selected mapping"));
                        }
                        at = end.min(expected_end);
                        if at == expected_end {
                            expected_index += 1;
                        }
                    }
                }
            }
            mft_missing_bitmap_bits(&mut original, &mft, &members)?
        };
        let mft = MftRecord::from_decoded(&logical)?;
        let data = mft.stream(ATTR_DATA, &[])?;
        let attribute =
            logical[data.record_offset()..data.record_offset() + e::attr_len(&logical, data.record_offset())?].to_vec();
        let mut changes = relocation::mapping_descriptors(
            &attribute,
            runs.len() as usize,
            |index| runs.get(index as u64),
            (boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES),
            relocation::DESCRIPTOR_CAPACITY,
        )?;
        // A large mapping may require several physical descriptors. Once their
        // checked segmentation already matches the publisher, retain its IDs.
        if state == MftMappingState::Ready {
            let mut current = Vec::new();
            for (_, member) in members.values() {
                for item in MftRecord::from_decoded(member)?.attributes() {
                    let item = item?;
                    if item.kind == ATTR_DATA && item.name_utf16le()?.is_empty() {
                        let at = item.record_offset();
                        let mut attribute = member[at..at + e::attr_len(member, at)?].to_vec();
                        attribute[af::ID_OFFSET..af::ID_END].fill(0);
                        current.push((item.first_vcn()?, attribute));
                    }
                }
            }
            current.sort_by_key(|(first_vcn, _)| *first_vcn);
            let unchanged = current.len() == changes.len()
                && current.iter().zip(&changes).all(|((_, current), change)| {
                    change.attribute.as_ref().is_some_and(|proposed| {
                        current[..af::ID_OFFSET] == proposed[..af::ID_OFFSET]
                            && current[af::ID_END..] == proposed[af::ID_END..]
                    })
                });
            if unchanged && !headers_repaired && !list_rebuild {
                changes.clear();
            }
        }
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let bitmap_bytes = bitmap.data_size()?;
        let bitmap_initialized = bitmap.initialized_size()?;
        let slots = initialized / u64::from(boot.record_bytes);
        let minimum = slots.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES;
        let data_bytes = bitmap_bytes
            .checked_add(BITMAP_WORD_BYTES - 1)
            .map(|bytes| (bytes & !(BITMAP_WORD_BYTES - 1)).max(minimum))
            .ok_or_else(|| reject("MFT bitmap data length overflow"))?;
        let initialized_bytes = bitmap_initialized.max(minimum);
        let mut padding = Vec::new();
        let resident_bits = if bitmap.nonresident || reconstructed_bitmap.is_some() {
            None
        } else {
            if bitmap.flags()? != 0 || bitmap_initialized < slots.div_ceil(BITMAP_BITS_PER_BYTE) {
                return Err(reject("resident MFT bitmap lacks actual allocation bits"));
            }
            let mut bits = bitmap.resident_value()?.to_vec();
            bits.resize(data_bytes as usize, 0);
            Some(bits)
        };
        let bitmap_resize = data_bytes != bitmap_bytes || initialized_bytes != bitmap_initialized;
        if bitmap_resize && bitmap.nonresident && reconstructed_bitmap.is_none() {
            if bitmap.flags()? != 0 || bitmap_initialized < slots.div_ceil(BITMAP_BITS_PER_BYTE) {
                return Err(reject("MFT bitmap lacks complete initialized allocation bits"));
            }
            // The admitted extra bytes represent slots beyond the stream. Preserve
            // every existing bit and clear only this bounded new padding range.
            let mut proposed = logical.clone();
            e::set_sizes(
                &mut proposed,
                bitmap.record_offset(),
                bitmap.allocated_size()?,
                data_bytes,
                initialized_bytes,
            )?;
            let record = MftRecord::from_decoded(&proposed)?;
            let bitmap = record.stream(ATTR_BITMAP, &[])?;
            plan_nonresident_overwrite(
                bitmap,
                boot,
                bitmap_initialized,
                initialized_bytes - bitmap_initialized,
                |span| {
                    padding.push((span.physical_offset, span.length as usize));
                    Ok(())
                },
            )?;
            let extents =
                ntfs_rs::runlist::DataRuns::new(bitmap.data_runs()?, 0).collect::<ntfs_rs::Result<Vec<_>>>()?;
            let at = bitmap.record_offset();
            changes.extend(relocation::mapping_descriptors(
                &proposed[at..at + e::attr_len(&proposed, at)?],
                extents.len(),
                |index| Ok(extents[index]),
                (boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES),
                relocation::DESCRIPTOR_CAPACITY,
            )?);
        }
        // Existing resident bits can remain local for a fitting single-base edit.
        // Spill them before family allocation or retirement, never by inventing bits.
        let base = &members[&reference].1;
        let mut base_space = e::capacity(base)?
            .checked_sub(e::used(base)?)
            .ok_or_else(|| reject("MFT base capacity is inconsistent"))?;
        for item in MftRecord::from_decoded(base)?.attributes() {
            let item = item?;
            if (item.kind == ATTR_DATA && item.name_utf16le()?.is_empty()) || item.kind == ATTR_ATTRIBUTE_LIST {
                base_space = base_space
                    .checked_add(e::attr_len(base, item.record_offset())?)
                    .ok_or_else(|| reject("MFT base capacity overflow"))?;
            }
        }
        let data_changes = changes.iter().filter(|change| change.kind == ATTR_DATA);
        let descriptors = data_changes.clone().count();
        let needs_base_space = data_changes
            .filter_map(|change| change.attribute.as_ref())
            .any(|attribute| base_space < attribute.len().saturating_add(ATTRIBUTE_LIST_SPACE_RESERVE_BYTES));
        let bitmap_spill = reconstructed_bitmap.is_some()
            || (resident_bits.is_some()
                && (bitmap_resize
                    || (!changes.is_empty() && (members.len() > 1 || descriptors > 1 || needs_base_space))));
        if changes.is_empty() && !bitmap_spill {
            return Ok(Vec::new());
        }
        let family = RepairFamily { reference, logical: logical.clone(), members };
        // Inventory reads still use the complete logical mapping above. Remove
        // only broken DATA from the private physical base so it cannot supply
        // contradictory allocation claims; protect the recovered extents below.
        let mut protected = decoded.clone();
        let mut remove = Vec::new();
        for item in record.attributes() {
            let item = item?;
            if item.name_utf16le()?.is_empty()
                && (item.kind == ATTR_DATA
                    || (item.kind == ATTR_BITMAP
                        && reconstructed_bitmap.is_some()
                        && item.nonresident
                        && plan_nonresident_overwrite(item, boot, 0, item.initialized_size()?, |_| Ok(())).is_err()))
            {
                remove.push(item.record_offset());
            }
        }
        for offset in remove.into_iter().rev() {
            e::remove(&mut protected, offset)?;
        }
        e::validate(&protected)?;
        protect_mft_record(&mut protected, boot.bytes_per_sector)?;
        let mut provisional = canonical.clone();
        provisional.push(Patch::new(boot.mft_byte_offset()?, raw.to_vec(), protected));
        for owner in bitmap_members {
            let (before, decoded) = &family.members[&owner];
            let mut after = decoded.clone();
            protect_mft_record(&mut after, boot.bytes_per_sector)?;
            let offset = (ntfs_rs::mft::reference_number(owner))
                .checked_mul(u64::from(boot.record_bytes))
                .ok_or_else(|| reject("MFT bitmap member offset overflow"))?;
            plan_nonresident_overwrite(
                mft.stream(ATTR_DATA, &[])?,
                boot,
                offset,
                u64::from(boot.record_bytes),
                |span| {
                    let start = span.source_offset as usize;
                    let end = start + span.length as usize;
                    provisional.push(Patch::new(
                        span.physical_offset,
                        before[start..end].to_vec(),
                        after[start..end].to_vec(),
                    ));
                    Ok(())
                },
            )?;
        }
        let mut volume = PlannedImage::volume(source, &provisional, boot)?;
        let mut space = if let Some((bits, _)) = &mut reconstructed_bitmap {
            RepairSpace::from_ownership_bitmap(&mut volume, &mft, bits)
        } else {
            RepairSpace::from_ownership(&mut volume, &mft)
        }
        .map_err(|error| io::Error::other(format!("MFT family ownership: {error}")))?;
        space.protect_extents(&runs)?;
        let mut plan = RepairPlan::new(image_length(&File::open(source)?)?)?;
        for (physical, length) in padding {
            let mut before = vec![0; length];
            volume.read_physical(physical, &mut before)?;
            plan.push(Patch::new(physical, before, vec![0; length]))?;
        }
        if bitmap_spill {
            let attribute = if let Some((bits, bytes)) = &mut reconstructed_bitmap {
                bits.rewind()?;
                space.stream(&mut volume, ATTR_BITMAP, &[], bits, *bytes, &mut plan)?
            } else {
                let bits = resident_bits.as_ref().ok_or_else(|| reject("missing resident bitmap evidence"))?;
                space.stream(&mut volume, ATTR_BITMAP, &[], &mut &bits[..], bits.len() as u64, &mut plan)?
            };
            let mut publication = logical.clone();
            repair_replace(&mut publication, &attribute)?;
            let mft = MftRecord::from_decoded(&publication)?;
            changes.push(StreamChange::replace(attribute)?);
            drop(volume);
            // Allocation reads the newly staged bitmap, while source bytes and the
            // caller's earlier plan remain untouched until full publication succeeds.
            let mut volume =
                Volume::new(PlannedImage { image: PlannedImage::open(source, &provisional)?, patches: &plan }, boot)?;
            let mut family_stage = RepairPlan::new(plan.length)?;
            family
                .store(&mut volume, &mft, changes, &mut space, &mut family_stage)
                .map_err(|error| io::Error::other(format!("MFT family publication: {error}")))?;
            drop(volume);
            for patch in family_stage.iter() {
                plan.compose(patch?)?;
            }
        } else {
            family
                .store(&mut volume, &mft, changes, &mut space, &mut plan)
                .map_err(|error| io::Error::other(format!("MFT family publication: {error}")))?;
        }
        let mut input = PlannedImage::open(source, previous)?;
        plan.iter()
            .map(|patch| {
                let mut patch = patch?;
                input.read_exact_at(patch.physical, &mut patch.before)?;
                Ok(patch)
            })
            .collect()
    }

    pub(crate) struct RepairFamily {
        pub reference: u64,
        pub logical: Vec<u8>,
        members: BTreeMap<u64, (Vec<u8>, Vec<u8>)>,
    }

    pub(crate) struct StreamChange {
        pub kind: u32,
        pub name: Vec<u8>,
        pub attribute: Option<Vec<u8>>,
    }
    impl StreamChange {
        pub fn remove(kind: u32, name: &[u8]) -> Self {
            Self { kind, name: name.to_vec(), attribute: None }
        }
        pub fn replace(attribute: Vec<u8>) -> io::Result<Self> {
            Ok(Self {
                kind: u32_at(&attribute, 0)?,
                name: e::attr_name(&attribute, 0)?.to_vec(),
                attribute: Some(attribute),
            })
        }
        pub fn resident(kind: u32, name: &[u8], value: &[u8]) -> io::Result<Self> {
            let mut image = vec![0; RESIDENT_BUILD_OVERHEAD_BYTES + name.len() + value.len()];
            let n = e::build_resident(kind, name, value, &mut image)?;
            image.truncate(n);
            Self::replace(image)
        }
    }

    impl RepairFamily {
        pub fn load<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>, number: u64) -> io::Result<Self> {
            let mut raw = vec![0; volume.boot.record_bytes as usize];
            volume.read_mft_record(mft, number, &mut raw)?;
            let base = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
            let reference = file_reference(number, base.sequence_number()?)?;
            let members = repair_members(volume, mft, reference)?;
            let record = MftRecord::from_decoded(&members[&reference].1)?;
            let list_bytes = record
                .attributes()
                .collect::<ntfs_rs::Result<Vec<_>>>()?
                .into_iter()
                .find(|a| a.kind == ATTR_ATTRIBUTE_LIST)
                .map(|a| a.data_size())
                .transpose()?
                .unwrap_or(0);
            let list_bytes = list_bytes as usize;
            let capacity = members
                .len()
                .checked_add(1)
                .and_then(|n| n.checked_mul(raw.len()))
                .filter(|n| u32::try_from(*n).is_ok())
                .ok_or_else(|| reject("family assembly size overflow"))?;
            let work_size = list_bytes
                .checked_add(raw.len())
                .and_then(|n| n.checked_add(members.len() * FAMILY_MEMBER_SLACK_BYTES))
                .ok_or_else(|| reject("family scratch size overflow"))?;
            let mut logical = vec![0; capacity];
            let mut work = vec![0; work_size];
            volume.resolve_record(mft, &record, &mut logical, &mut work)?;
            Ok(Self { reference, logical, members })
        }

        /// Edit fixed-size resident values in their current physical records.
        /// Attribute IDs, list entries and extension ownership stay intact.
        pub fn patch_resident_values<R: ReadAt>(
            mut self,
            volume: &mut Volume<R>,
            mft: &MftRecord<'_>,
            kind: u32,
            name: &[u8],
            edit: &mut impl FnMut(&mut [u8]) -> io::Result<()>,
            extra: &mut RepairPlan,
        ) -> io::Result<bool> {
            let mut changed = false;
            for (&reference, (before, image)) in &mut self.members {
                let mut spans = Vec::new();
                for attr in MftRecord::from_decoded(image)?.attributes() {
                    let attr = attr?;
                    if attr.kind == kind && attr.name_utf16le()? == name {
                        let value = attr.resident_value()?;
                        spans.push((attr.record_offset() + attr.resident_value_offset()?, value.len()));
                    }
                }
                let decoded_before = image.clone();
                for (start, length) in spans {
                    edit(&mut image[start..start + length])?;
                }
                if *image == decoded_before {
                    continue;
                }
                e::validate(image)?;
                protect_mft_record(image, volume.boot.bytes_per_sector)?;
                repair_record_patch(
                    volume,
                    mft.stream(ATTR_DATA, &[])?,
                    ntfs_rs::mft::reference_number(reference),
                    before,
                    image,
                    extra,
                )?;
                changed = true;
            }
            Ok(changed)
        }

        fn insert<R: ReadAt>(
            &mut self,
            volume: &mut Volume<R>,
            mft: &MftRecord<'_>,
            attribute: &[u8],
            cursor: &mut u64,
            extra: &mut RepairPlan,
            skip_base: bool,
        ) -> io::Result<()> {
            let kind = u32_at(attribute, 0)?;
            let name = e::attr_name(attribute, 0)?;
            let mft_tail = ntfs_rs::mft::reference_number(self.reference) == 0
                && kind == ATTR_DATA
                && name.is_empty()
                && attribute[af::NONRESIDENT_OFFSET] != 0
                && u64_at(attribute, af::FIRST_VCN_OFFSET)? != 0;
            let limit = if mft_tail {
                u64_at(attribute, af::FIRST_VCN_OFFSET)?
                    .checked_mul(u64::from(volume.boot.cluster_bytes))
                    .ok_or_else(|| reject("MFT prefix overflow"))?
                    / u64::from(volume.boot.record_bytes)
            } else {
                u64::MAX
            };
            // Leave room for the list descriptor in the base. A resident list may
            // spill to disk without moving the base's standard information.
            let mut candidates: Vec<_> = self
                .members
                .iter()
                .map(|(&r, (_, image))| {
                    let free = e::capacity(image).unwrap_or(0).saturating_sub(e::used(image).unwrap_or(usize::MAX));
                    (r, free.saturating_sub(if r == self.reference { ATTRIBUTE_LIST_SPACE_RESERVE_BYTES } else { 0 }))
                })
                .collect();
            candidates.sort_by_key(|&(r, free)| (std::cmp::Reverse(free), r));
            for (r, free) in candidates {
                if ntfs_rs::mft::reference_number(r) >= limit {
                    continue;
                }
                if skip_base && r == self.reference {
                    continue;
                }
                if free < attribute.len() {
                    continue;
                }
                let mut candidate = self.members[&r].1.clone();
                if kind != ntfs_rs::mft::ATTR_FILE_NAME
                    && MftRecord::from_decoded(&candidate)?
                        .attributes()
                        .any(|a| a.is_ok_and(|a| a.kind == kind && a.name_utf16le().is_ok_and(|n| n == name)))
                {
                    continue;
                }
                match e::insert(&mut candidate, attribute) {
                    Ok(_) => {
                        self.members.get_mut(&r).unwrap().1 = candidate;
                        return Ok(());
                    }
                    Err(ntfs_rs::Error::NoSpace) => continue,
                    Err(error) => return Err(invalid(error)),
                }
            }
            let (reference, mut pair) = repair_new_extension(volume, mft, self.reference, cursor, extra, limit)?;
            e::insert(&mut pair.1, attribute)?;
            self.members.insert(reference, pair);
            Ok(())
        }

        pub fn store<R: ReadAt>(
            mut self,
            volume: &mut Volume<R>,
            mft: &MftRecord<'_>,
            changes: Vec<StreamChange>,
            space: &mut RepairSpace,
            extra: &mut RepairPlan,
        ) -> io::Result<()> {
            let mft_family = ntfs_rs::mft::reference_number(self.reference) == 0;
            let retain_list = mft_family
                && MftRecord::from_decoded(&self.members[&self.reference].1)?
                    .attributes()
                    .any(|attribute| attribute.is_ok_and(|attribute| attribute.kind == ATTR_ATTRIBUTE_LIST));
            // A single MFT base can publish existing attributes without changing
            // allocation bits. Extension reservation still requires an external map.
            if !mft.stream(ATTR_BITMAP, &[])?.nonresident && !(mft_family && self.members.len() == 1) {
                return Err(io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "MFT bitmap must be externalized before updating attribute families",
                ));
            }
            let mut keys = BTreeSet::new();
            let mut stream_ends = BTreeMap::new();
            for change in &changes {
                let segmented = change.attribute.as_ref().is_some_and(|a| a[af::NONRESIDENT_OFFSET] != 0);
                if segmented {
                    let a = change.attribute.as_ref().ok_or_else(|| reject("cannot remove MFT DATA"))?;
                    let end = stream_ends.entry((change.kind, change.name.clone())).or_insert(0);
                    if u64_at(a, af::FIRST_VCN_OFFSET)? != *end {
                        return Err(reject("replacement stream extents are not contiguous"));
                    }
                    *end =
                        u64_at(a, af::LAST_VCN_OFFSET)?.checked_add(1).ok_or_else(|| reject("MFT extent overflow"))?;
                }
                if !keys.insert((change.kind, change.name.clone()))
                    && !segmented
                    && change.kind != ntfs_rs::mft::ATTR_FILE_NAME
                {
                    return Err(reject("duplicate family stream change"));
                }
            }
            for (_, image) in self.members.values_mut() {
                let mut remove = Vec::new();
                for item in MftRecord::from_decoded(image)?.attributes() {
                    let attr = item?;
                    if attr.kind == ATTR_ATTRIBUTE_LIST || keys.contains(&(attr.kind, attr.name_utf16le()?.to_vec())) {
                        remove.push(attr.record_offset());
                    }
                }
                for at in remove.into_iter().rev() {
                    e::remove(image, at)?;
                }
            }
            let mut cursor = if ntfs_rs::mft::reference_number(self.reference) == 0 {
                system_record::RESERVED
            } else {
                ntfs_rs::mft_growth::FIRST_USER_RECORD
            };
            for change in changes {
                if let Some(attribute) = change.attribute {
                    if ntfs_rs::mft::reference_number(self.reference) == 0
                        && change.kind == ATTR_DATA
                        && change.name.is_empty()
                        && u64_at(&attribute, af::FIRST_VCN_OFFSET)? == 0
                    {
                        // The MFT must bootstrap from record zero. Move unrelated
                        // attributes out before installing its complete mapping.
                        loop {
                            let base = &self.members[&self.reference].1;
                            if e::capacity(base)? - e::used(base)?
                                >= attribute.len() + ATTRIBUTE_LIST_SPACE_RESERVE_BYTES
                            {
                                break;
                            }
                            let candidate = MftRecord::from_decoded(base)?
                                .attributes()
                                .collect::<ntfs_rs::Result<Vec<_>>>()?
                                .into_iter()
                                .filter(|a| {
                                    a.kind != ntfs_rs::mft::ATTR_STANDARD_INFORMATION
                                        && a.kind != ATTR_ATTRIBUTE_LIST
                                        && a.kind != ATTR_DATA
                                })
                                .max_by_key(|a| e::attr_len(base, a.record_offset()).unwrap_or(0))
                                .ok_or_else(|| reject("MFT mapping needs more than one extent record"))?;
                            let at = candidate.record_offset();
                            let moved = base[at..at + e::attr_len(base, at)?].to_vec();
                            e::remove(&mut self.members.get_mut(&self.reference).unwrap().1, at)?;
                            self.insert(volume, mft, &moved, &mut cursor, extra, true)?;
                        }
                        e::insert(&mut self.members.get_mut(&self.reference).unwrap().1, &attribute)?;
                    } else {
                        let continuation = ntfs_rs::mft::reference_number(self.reference) == 0
                            && change.kind == ATTR_DATA
                            && change.name.is_empty();
                        self.insert(volume, mft, &attribute, &mut cursor, extra, continuation)?;
                    }
                }
            }
            let mut freed = Vec::new();
            for (&r, (_, image)) in &self.members {
                if r != self.reference && MftRecord::from_decoded(image)?.attributes().next().is_none() {
                    freed.push(r);
                }
            }
            for r in freed {
                let (before, mut after) = self.members.remove(&r).unwrap();
                retire_empty_extension(volume, mft, r, &before, &mut after, extra, mft_family)?;
                protect_mft_record(&mut after, volume.boot.bytes_per_sector)?;
                repair_record_patch(
                    volume,
                    mft.stream(ATTR_DATA, &[])?,
                    ntfs_rs::mft::reference_number(r),
                    &before,
                    &after,
                    extra,
                )?;
            }
            if self.members.len() > 1 || retain_list {
                // Make descriptor room by moving a complete attribute, never a
                // partial value. Existing family membership was validated at load.
                loop {
                    let base = &self.members[&self.reference].1;
                    if e::capacity(base)? - e::used(base)? >= ATTRIBUTE_LIST_SPACE_RESERVE_BYTES {
                        break;
                    }
                    let candidate = MftRecord::from_decoded(base)?
                        .attributes()
                        .collect::<ntfs_rs::Result<Vec<_>>>()?
                        .into_iter()
                        .filter(|a| {
                            a.kind != ntfs_rs::mft::ATTR_STANDARD_INFORMATION
                                && a.kind != ATTR_ATTRIBUTE_LIST
                                && !(ntfs_rs::mft::reference_number(self.reference) == 0 && a.kind == ATTR_DATA)
                        })
                        .max_by_key(|a| e::attr_len(base, a.record_offset()).unwrap_or(0))
                        .ok_or_else(|| reject("family base has no movable attribute for its list"))?;
                    let at = candidate.record_offset();
                    let attribute = base[at..at + e::attr_len(base, at)?].to_vec();
                    e::remove(&mut self.members.get_mut(&self.reference).unwrap().1, at)?;
                    self.insert(volume, mft, &attribute, &mut cursor, extra, true)?;
                }
                let mut entries = Vec::new();
                for (&reference, (_, image)) in &self.members {
                    for item in MftRecord::from_decoded(image)?.attributes() {
                        let a = item?;
                        entries.push(FamilyKey {
                            kind: a.kind,
                            name: a.name_utf16le()?.to_vec(),
                            vcn: if a.nonresident { a.first_vcn()? } else { 0 },
                            reference,
                            id: a.id,
                        });
                    }
                }
                entries.sort_by(family_key_order);
                let mut list = Vec::new();
                for key in entries {
                    let n = (ATTRIBUTE_LIST_HEADER_BYTES + key.name.len() + af::ALIGNMENT - 1) & !(af::ALIGNMENT - 1);
                    let start = list.len();
                    list.resize(start + n, 0);
                    let row = &mut list[start..];
                    e::p32(row, ATTRIBUTE_LIST_TYPE_OFFSET, key.kind)?;
                    e::p16(row, ATTRIBUTE_LIST_LENGTH_OFFSET, n as u16)?;
                    row[ATTRIBUTE_LIST_NAME_LENGTH_OFFSET] = (key.name.len() / std::mem::size_of::<u16>()) as u8;
                    row[ATTRIBUTE_LIST_NAME_OFFSET_OFFSET] = ATTRIBUTE_LIST_HEADER_BYTES as u8;
                    e::p64(row, ATTRIBUTE_LIST_VCN_OFFSET, key.vcn)?;
                    e::p64(row, ATTRIBUTE_LIST_REFERENCE_OFFSET, key.reference)?;
                    e::p16(row, ATTRIBUTE_LIST_ID_OFFSET, key.id)?;
                    row[ATTRIBUTE_LIST_HEADER_BYTES..ATTRIBUTE_LIST_HEADER_BYTES + key.name.len()]
                        .copy_from_slice(&key.name);
                }
                let resident = StreamChange::resident(ATTR_ATTRIBUTE_LIST, &[], &list)?.attribute.unwrap();
                let mut candidate = self.members[&self.reference].1.clone();
                if e::insert(&mut candidate, &resident).is_ok() {
                    self.members.get_mut(&self.reference).unwrap().1 = candidate;
                } else {
                    let attribute =
                        space.stream(volume, ATTR_ATTRIBUTE_LIST, &[], &mut &list[..], list.len() as u64, extra)?;
                    e::insert(&mut self.members.get_mut(&self.reference).unwrap().1, &attribute)?;
                }
            }
            // Extensions become durable before the base publishes its new list.
            let base = self.members.remove(&self.reference).unwrap();
            for (reference, (before, after)) in self.members.into_iter().chain(std::iter::once((self.reference, base)))
            {
                let mut decoded = before.clone();
                if MftRecord::parse(&mut decoded, volume.boot.bytes_per_sector).is_ok() && decoded == after {
                    continue;
                }
                e::validate(&after)?;
                let mut after = after;
                protect_mft_record(&mut after, volume.boot.bytes_per_sector)?;
                repair_record_patch(
                    volume,
                    mft.stream(ATTR_DATA, &[])?,
                    ntfs_rs::mft::reference_number(reference),
                    &before,
                    &after,
                    extra,
                )?;
            }
            Ok(())
        }
    }

    pub(crate) struct RepairSpace {
        owned: std::io::BufReader<File>,
        reserved: File,
        cursor: u64,
        bitmap: Vec<u8>,
        ownership_only: bool,
    }
    impl RepairSpace {
        pub fn protect_extents(&mut self, runs: &RunSpool) -> io::Result<()> {
            let mut all = checker::consistency::DiskInventory::new();
            self.owned.seek(SeekFrom::Start(0))?;
            while let Some(row) = checker::consistency::inventory_next(&mut self.owned)? {
                all.push(row)?;
            }
            for number in 0..runs.len() {
                let run = runs.get(number)?;
                if let Some(lcn) = run.lcn {
                    all.push([lcn, lcn.checked_add(run.len).ok_or_else(|| reject("reserved range overflow"))?, 0, 0])?;
                }
            }
            self.owned = std::io::BufReader::new(all.finish()?);
            Ok(())
        }
        pub fn from_ownership<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>) -> io::Result<Self> {
            Ok(Self {
                owned: std::io::BufReader::new(repair_owned_ranges(volume, mft)?),
                reserved: checker::consistency::scratch_file()?,
                cursor: FIRST_ALLOCATABLE_CLUSTER,
                bitmap: Vec::new(),
                ownership_only: true,
            })
        }
        fn from_ownership_bitmap<R: ReadAt>(
            volume: &mut Volume<R>,
            mft: &MftRecord<'_>,
            bits: &mut File,
        ) -> io::Result<Self> {
            let bytes = (mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes))
                .div_ceil(BITMAP_BITS_PER_BYTE);
            let mut cache = (u64::MAX, [0_u8; BITMAP_CACHE_BYTES]);
            let owned = repair_owned_ranges_with_bits(volume, mft, |_, number| {
                let offset = number / BITMAP_BITS_PER_BYTE;
                let start = offset / cache.1.len() as u64 * cache.1.len() as u64;
                if start != cache.0 {
                    let count = (bytes - start).min(cache.1.len() as u64) as usize;
                    bits.seek(SeekFrom::Start(start))?;
                    bits.read_exact(&mut cache.1[..count])?;
                    cache.0 = start;
                }
                Ok(cache.1[(offset - start) as usize] & (1 << (number % BITMAP_BITS_PER_BYTE)) != 0)
            })?;
            Ok(Self {
                owned: std::io::BufReader::new(owned),
                reserved: checker::consistency::scratch_file()?,
                cursor: FIRST_ALLOCATABLE_CLUSTER,
                bitmap: Vec::new(),
                ownership_only: true,
            })
        }
        pub fn claim_range(&mut self, lcn: u64, count: u64) -> io::Result<()> {
            if lcn < self.cursor || count == 0 {
                return Err(reject("repair reservation is out of order"));
            }
            self.cursor = lcn.checked_add(count).ok_or_else(|| reject("repair reservation overflow"))?;
            self.reserved.seek(SeekFrom::End(0))?;
            checker::consistency::inventory_write(&mut self.reserved, [lcn, self.cursor, 0, 0])?;
            Ok(())
        }
        pub fn new<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>) -> io::Result<Self> {
            let owned = std::io::BufReader::new(repair_owned_ranges(volume, mft)?);
            let bitmap = RepairFamily::load(volume, mft, system_record::BITMAP)?.logical;
            Ok(Self {
                owned,
                reserved: checker::consistency::scratch_file()?,
                cursor: FIRST_ALLOCATABLE_CLUSTER,
                bitmap,
                ownership_only: false,
            })
        }
        pub fn allocate<R: ReadAt>(&mut self, volume: &mut Volume<R>, count: u64) -> io::Result<u64> {
            if self.ownership_only {
                return Ok(reserved::unowned_extents(
                    &mut self.owned,
                    &mut self.reserved,
                    count,
                    &mut self.cursor,
                    volume.boot.total_sectors / u64::from(volume.boot.sectors_per_cluster),
                    true,
                )?[0]
                    .lcn
                    .unwrap());
            }
            let record = MftRecord::from_decoded(&self.bitmap)?;
            repair_reserve(
                volume,
                record.stream(ATTR_DATA, &[])?,
                &mut self.owned,
                &mut self.reserved,
                count,
                &mut self.cursor,
            )
        }
        pub fn fragments<R: ReadAt>(&mut self, volume: &mut Volume<R>, count: u64) -> io::Result<Vec<Extent>> {
            if self.ownership_only {
                return reserved::unowned_extents(
                    &mut self.owned,
                    &mut self.reserved,
                    count,
                    &mut self.cursor,
                    volume.boot.total_sectors / u64::from(volume.boot.sectors_per_cluster),
                    false,
                );
            }
            let record = MftRecord::from_decoded(&self.bitmap)?;
            repair_reserve_fragments(
                volume,
                record.stream(ATTR_DATA, &[])?,
                &mut self.owned,
                &mut self.reserved,
                count,
                &mut self.cursor,
            )
        }
        pub fn stream<R: ReadAt>(
            &mut self,
            volume: &mut Volume<R>,
            kind: u32,
            name: &[u8],
            input: &mut impl Read,
            bytes: u64,
            extra: &mut RepairPlan,
        ) -> io::Result<Vec<u8>> {
            let cluster = u64::from(volume.boot.cluster_bytes);
            let count = bytes.div_ceil(cluster);
            if count == 0 {
                return Err(reject("cannot allocate an empty nonresident stream"));
            }
            let runs = self.fragments(volume, count)?;
            let allocated = count.checked_mul(cluster).ok_or_else(|| reject("repair stream size overflow"))?;
            let mut offset = 0;
            let mut run_number = 0;
            while offset < allocated {
                let n = (allocated - offset).min(REPAIR_CHUNK_BYTES) as usize;
                let mut after = vec![0; n];
                while runs.get(run_number).is_some_and(|r| offset / cluster >= r.vcn + r.len) {
                    run_number += 1;
                }
                let run = runs
                    .get(run_number)
                    .filter(|r| offset / cluster >= r.vcn)
                    .ok_or_else(|| reject("repair stream mapping gap"))?;
                let n = n.min(((run.vcn + run.len) * cluster - offset) as usize);
                // Read only this fragment; the next one may be physically distant.
                after.truncate(n);
                let valid = bytes.saturating_sub(offset).min(n as u64) as usize;
                input.read_exact(&mut after[..valid])?;
                let physical = run.lcn.unwrap() * cluster + offset - run.vcn * cluster;
                let mut before = vec![0; n];
                volume.read_physical(physical, &mut before)?;
                extra.push(Patch::new(physical, before, after))?;
                offset += n as u64;
            }
            let mut attr = vec![0; NONRESIDENT_BUILD_OVERHEAD_BYTES + name.len() + runs.len() * MAX_MAPPING_PAIR_BYTES];
            let n = e::build_nonresident(kind, name, &runs, allocated, bytes, bytes, &mut attr)?;
            attr.truncate(n);
            Ok(attr)
        }
        pub fn stream_changes<R: ReadAt>(
            &mut self,
            volume: &mut Volume<R>,
            kind: u32,
            name: &[u8],
            input: &mut impl Read,
            bytes: u64,
            extra: &mut RepairPlan,
        ) -> io::Result<Vec<StreamChange>> {
            let attribute = self.stream(volume, kind, name, input, bytes, extra)?;
            let offset = ntfs_rs::bytes::u16_at(&attribute, af::MAPPING_PAIRS_OFFSET)? as usize;
            let runs = ntfs_rs::runlist::DataRuns::new(&attribute[offset..], 0).collect::<ntfs_rs::Result<Vec<_>>>()?;
            relocation::mapping_descriptors(
                &attribute,
                runs.len(),
                |i| Ok(runs[i]),
                (volume.boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES),
                relocation::DESCRIPTOR_CAPACITY,
            )
        }
    }

    pub(crate) fn install_view<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        family: RepairFamily,
        name: &[u8],
        collation: u32,
        rows: &[Vec<u8>],
        space: &mut RepairSpace,
        extra: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut entries = checker::consistency::scratch_file()?;
        let mut bytes = 0;
        for row in rows {
            repair_entry_write(&mut entries, row)?;
            bytes += row.len() as u64;
        }
        let room =
            (volume.boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES).max(MIN_INDEX_ROOT_ROOM);
        let (root, mut pages, count) =
            rebuilt_index(volume.boot, entries, rows.len() as u64, bytes, room, 0, collation)?;
        let mut changes = vec![StreamChange::resident(ntfs_rs::mft::ATTR_INDEX_ROOT, name, &root)?];
        if count == 0 {
            changes.push(StreamChange::remove(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, name));
            changes.push(StreamChange::remove(ATTR_BITMAP, name));
        } else {
            changes.extend(
                space.stream_changes(
                    volume,
                    ntfs_rs::mft::ATTR_INDEX_ALLOCATION,
                    name,
                    &mut pages,
                    count
                        .checked_mul(u64::from(volume.boot.index_block_bytes))
                        .ok_or_else(|| reject("index size overflow"))?,
                    extra,
                )?,
            );
            let mut bitmap = vec![0; (count.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES) as usize];
            for (i, byte) in bitmap.iter_mut().enumerate() {
                *byte = ((1_u16 << count.saturating_sub(i as u64 * BITMAP_BITS_PER_BYTE).min(BITMAP_BITS_PER_BYTE)) - 1)
                    as u8;
            }
            if bitmap.len() <= RESIDENT_INDEX_BITMAP_MAX_BYTES {
                changes.push(StreamChange::resident(ATTR_BITMAP, name, &bitmap)?);
            } else {
                changes.extend(space.stream_changes(
                    volume,
                    ATTR_BITMAP,
                    name,
                    &mut &bitmap[..],
                    bitmap.len() as u64,
                    extra,
                )?);
            }
        }
        family.store(volume, mft, changes, space, extra)
    }

    #[cfg(test)]
    mod mft_scan_checks {
        include!("../tests/recovery/family_mft_scan_checks.rs");
    }
}

pub(super) mod growth {
    use super::family::{MAX_MAPPING_PAIR_BYTES, MFT_ATTRIBUTE_RESERVE_BYTES, NONRESIDENT_BUILD_OVERHEAD_BYTES};
    use super::*;
    use ntfs_rs::mft::record_layout as rf;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::{
        record_edit as e,
        runlist::{DataRuns, Extent},
    };

    const SYNTHETIC_MAPPING_RESERVE_BYTES: usize = 512;

    pub(crate) fn repack(source: &Path, boot: ntfs_rs::boot::BootSector, patches: &mut RepairPlan) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::MFT)?;
        let data = mft.stream(ATTR_DATA, &[])?;
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let initialized = data.initialized_size()?;
        let allocated = data.allocated_size()?;
        let cluster = u64::from(boot.cluster_bytes);
        let record = u64::from(boot.record_bytes);
        if initialized != data.data_size()? || initialized % record != 0 || allocated % cluster != 0 {
            return Err(reject("MFT growth requires consistent stream sizes"));
        }
        let old_slots = initialized / record;
        let new_slots = if allocated > initialized {
            (allocated / record).min(old_slots + ntfs_rs::mft_growth::GROWTH_RECORDS)
        } else {
            old_slots + ntfs_rs::mft_growth::GROWTH_RECORDS
        };
        if new_slots > u64::from(u32::MAX) {
            return Err(reject("MFT slot number overflow"));
        }
        let new_bytes = new_slots * record;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut runs = DataRuns::new(data.data_runs()?, 0).collect::<ntfs_rs::Result<Vec<_>>>()?;
        if runs.iter().any(|r| r.lcn.is_none())
            || runs.last().and_then(|r| r.vcn.checked_add(r.len)).and_then(|n| n.checked_mul(cluster))
                != Some(allocated)
        {
            return Err(reject("MFT allocation differs from its validated extents"));
        }
        let new_allocated = if new_bytes > allocated {
            let count = (new_bytes - allocated).div_ceil(cluster);
            let lcn = space.allocate(&mut volume, count)?;
            runs.push(Extent { vcn: allocated / cluster, lcn: Some(lcn), len: count });
            allocated + count * cluster
        } else {
            allocated
        };
        let attr_capacity = runs
            .len()
            .checked_mul(MAX_MAPPING_PAIR_BYTES)
            .and_then(|n| n.checked_add(NONRESIDENT_BUILD_OVERHEAD_BYTES))
            .ok_or_else(|| reject("MFT mapping size overflow"))?;
        let mut data_attr = vec![0; attr_capacity];
        let n = e::build_nonresident(ATTR_DATA, &[], &runs, new_allocated, new_bytes, new_bytes, &mut data_attr)?;
        data_attr.truncate(n);
        // Split by encoded size; the family writer still owns MFT bootstrap placement.
        let base_room = (boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES);
        let mut data_changes = relocation::mapping_descriptors(
            &data_attr,
            runs.len(),
            |i| Ok(runs[i]),
            base_room,
            "MFT mapping pair exceeds record capacity",
        )?;
        let old_bitmap = bitmap.data_size()? as usize;
        if old_bitmap as u64 * BITMAP_BITS_PER_BYTE < old_slots || bitmap.initialized_size()? != old_bitmap as u64 {
            return Err(reject("MFT bitmap size evidence is inconsistent"));
        }
        let mut bits = vec![0; old_bitmap.max((new_slots.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES) as usize)];
        volume.read_attribute(bitmap, 0, &mut bits[..old_bitmap])?;
        for slot in old_slots..new_slots {
            bits[(slot / BITMAP_BITS_PER_BYTE) as usize] &= !(1 << (slot % BITMAP_BITS_PER_BYTE));
        }
        let mut stage = RepairPlan::new(patches.length)?;
        let bitmap_attr = space.stream(&mut volume, ATTR_BITMAP, &[], &mut &bits[..], bits.len() as u64, &mut stage)?;
        // A synthetic image is a mapping for the planner only. It is never written.
        let mapping_bytes = (data_attr.len() + bitmap_attr.len() + SYNTHETIC_MAPPING_RESERVE_BYTES)
            .div_ceil(boot.record_bytes as usize)
            * boot.record_bytes as usize;
        let mut mapping = vec![0; mapping_bytes];
        e::format_empty(&mut mapping, system_record::MFT)?;
        e::p16(
            &mut mapping,
            rf::SEQUENCE_OFFSET,
            (u64::from(ntfs_rs::mft::reference_sequence(family.reference))) as u16,
        )?;
        e::insert(&mut mapping, &data_attr)?;
        e::insert(&mut mapping, &bitmap_attr)?;
        let new_mft = MftRecord::from_decoded(&mapping)?;
        let new_data = new_mft.stream(ATTR_DATA, &[])?;
        for number in old_slots..new_slots {
            let mut after = vec![0; boot.record_bytes as usize];
            e::format_empty(&mut after, number)?;
            protect_mft_record(&mut after, boot.bytes_per_sector)?;
            stage_overwrite(&mut volume, new_data, number * record, &after, &mut stage)?;
        }
        drop(volume);
        // Read newly formatted slots through a separate immutable preview; keep
        // the caller's plan unchanged until the complete family update succeeds.
        let mut preview = RepairPlan::new(patches.length)?;
        for patch in patches.iter().chain(stage.iter()) {
            preview.compose(patch?)?;
        }
        let mut volume = PlannedImage::volume(source, &preview, boot)?;
        let mut family_stage = RepairPlan::new(patches.length)?;
        data_changes.push(StreamChange::replace(bitmap_attr)?);
        family.store(&mut volume, &new_mft, data_changes, &mut space, &mut family_stage)?;
        drop(volume);
        // Normalize overlapping subranges (bitmap bits and formatted slots) while
        // retaining the original before-image of every physical byte.
        for patch in family_stage.iter() {
            stage.compose(patch?)?;
        }
        for patch in stage.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }
    #[cfg(test)]
    mod descriptor_tests {
        include!("../tests/recovery/growth_descriptors.rs");
    }
}

pub(super) mod log_resize {
    use super::family::{MAX_MAPPING_PAIR_BYTES, MFT_ATTRIBUTE_RESERVE_BYTES, NONRESIDENT_BUILD_OVERHEAD_BYTES};
    use super::*;
    use ntfs_rs::mft::record_layout as rf;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::{
        boot::BootSector,
        logfile::{classify_restart_pair, encode_checked_marker, LogState},
        record_edit as e,
        runlist::{DataRuns, Extent},
    };

    const MIN_LOG_BYTES: u64 = 2 * 1024 * 1024;
    const LOG_SIZE_ALIGNMENT_BYTES: u64 = 1024;
    const CHECKED_MARKER_BYTES: usize = 16;
    const SUPPORTED_NTFS_VERSION: (u8, u8) = (3, 1);
    use ntfs_rs::volume_info::VOLUME_RESIZE_LOG_FILE;
    const VOLUME_FLAGS_OFFSET: usize = 10;
    const VOLUME_FLAGS_END: usize = VOLUME_FLAGS_OFFSET + std::mem::size_of::<u16>();

    pub(crate) fn validate_size(bytes: u64) -> io::Result<()> {
        if !(MIN_LOG_BYTES..=u64::from(u32::MAX)).contains(&bytes) || bytes % LOG_SIZE_ALIGNMENT_BYTES != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log size must be a multiple of 1 KiB, at least 2 MiB, and below 4 GiB",
            ));
        }
        Ok(())
    }

    // Preserve every surviving physical extent. Only the missing tail needs free
    // storage; shrinking must also work when no free clusters remain.
    fn resized_runs<R: ReadAt>(
        volume: &mut Volume<R>,
        data: Attribute<'_>,
        bytes: u64,
        space: &mut RepairSpace,
    ) -> io::Result<Vec<Extent>> {
        let cluster = u64::from(volume.boot.cluster_bytes);
        let old = data.allocated_size()? / cluster;
        let wanted = bytes.div_ceil(cluster);
        let mut runs = Vec::new();
        let mut end = 0;
        for run in DataRuns::new(data.data_runs()?, 0) {
            let run = run?;
            if run.vcn != end || run.lcn.is_none() {
                return Err(reject("log stream has a gap or sparse allocation"));
            }
            end = end.checked_add(run.len).ok_or_else(|| reject("log mapping overflow"))?;
            if run.vcn < wanted {
                runs.push(Extent { len: run.len.min(wanted - run.vcn), ..run });
            }
        }
        if end != old {
            return Err(reject("log allocation and mapping disagree"));
        }
        if wanted > old {
            for mut run in space.fragments(volume, wanted - old)? {
                run.vcn += old;
                if let Some(last) = runs
                    .last_mut()
                    .filter(|last| last.vcn + last.len == run.vcn && last.lcn.unwrap() + last.len == run.lcn.unwrap())
                {
                    last.len += run.len;
                } else {
                    runs.push(run);
                }
            }
        }
        Ok(runs)
    }

    fn restart_pages<R: ReadAt>(volume: &mut Volume<R>, data: Attribute<'_>) -> io::Result<(u32, u64)> {
        let size = data.data_size()?;
        let mut prefix = [0; RESTART_PROBE_BYTES];
        volume.read_attribute(data, 0, &mut prefix)?;
        let bytes = RestartPage::peek_system_page_bytes(&prefix)?;
        if u64::from(bytes) * RESTART_COPY_COUNT > size {
            return Err(reject("log restart pair is truncated"));
        }
        let mut pages = [vec![0; bytes as usize], vec![0; bytes as usize]];
        for (n, page) in pages.iter_mut().enumerate() {
            volume.read_attribute(data, n as u64 * u64::from(bytes), page)?;
        }
        let [a, b] = pages.each_mut().map(|p| RestartPage::parse(p, volume.boot.bytes_per_sector));
        let (a, b) = (a?, b?);
        if (!a.chkdsk_marker && a.log_bytes != size)
            || (!b.chkdsk_marker && b.log_bytes != size)
            || classify_restart_pair(Ok(a), Ok(b)) == LogState::NeedsReview
        {
            return Err(reject("log restart copies disagree"));
        }
        // The enclosing recovery gate validates active-client checkpoints before
        // they reach this operation. Record data is never interpreted as free.
        Ok((bytes, if a.current_lsn >= b.current_lsn { a.current_lsn } else { b.current_lsn }))
    }

    fn map_bytes<R: ReadAt>(
        volume: &mut Volume<R>,
        data: Attribute<'_>,
        offset: u64,
        bytes: u64,
        extra: &mut RepairPlan,
        mut contents: impl FnMut(u64, &mut [u8]),
    ) -> io::Result<()> {
        for span in overwrite_spans(data, volume.boot, offset, bytes)? {
            let mut at = 0;
            while at < span.length {
                let n = (span.length - at).min(REPAIR_CHUNK_BYTES) as usize;
                let physical = span.physical_offset + at;
                let mut before = vec![0; n];
                volume.read_physical(physical, &mut before)?;
                let mut after = before.clone();
                contents(span.source_offset + at, &mut after);
                extra.push(Patch::new(physical, before, after))?;
                at += n as u64;
            }
        }
        Ok(())
    }

    // Allocation follows the complete proposed ownership inventory, including
    // descriptors that moved into extension records while the log was resized.
    fn reconcile_allocation(
        source: &Path,
        boot: BootSector,
        patches: &mut RepairPlan,
        pending_log_index: bool,
    ) -> io::Result<()> {
        let mut candidates = checker::consistency::DiskInventory::new();
        let audit = checker::consistency::audit_reader(
            PlannedImage { image: Image(File::open(source)?), patches },
            boot,
            |at, before, after| {
                candidates.push([at, u64::from(before), u64::from(after), 0])?;
                Ok(())
            },
            |_| Ok(()),
            checker::consistency::AuditOptions::default(),
            checker::consistency::INDEX_CACHE_BYTES,
        )?;
        if !audit.complete
            || audit.errors
                != audit
                    .findings
                    .iter()
                    .filter(|f| {
                        f.is_error
                            && (matches!(
                                f.code.as_str(),
                                "cluster-marked-free" | "cluster-marked-free-count" | "unreferenced-clusters"
                            ) || (pending_log_index
                                && f.code == "index-duplicate-information"
                                && f.record == Some(system_record::LOG)))
                    })
                    .count() as u64
        {
            return Err(reject("resized log has errors beyond allocation updates"));
        }
        let mut candidates = candidates.finish()?;
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::BITMAP)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let data = record.stream(ATTR_DATA, &[])?;
        let mut extra = RepairPlan::new(patches.length)?;
        if data.nonresident {
            while let Some([at, before, after, _]) = checker::consistency::inventory_next(&mut candidates)? {
                let mut mismatch = false;
                map_bytes(&mut volume, data, at, 1, &mut extra, |_, out| {
                    mismatch |= out[0] != before as u8;
                    out[0] = after as u8;
                })?;
                if mismatch {
                    return Err(reject("allocation preimage changed while planning log resize"));
                }
            }
        } else {
            family.patch_resident_values(
                &mut volume,
                &mft,
                ATTR_DATA,
                &[],
                &mut |value| {
                    candidates.seek(SeekFrom::Start(0))?;
                    while let Some([at, before, after, _]) = checker::consistency::inventory_next(&mut candidates)? {
                        let byte = value.get_mut(at as usize).ok_or_else(|| reject("resident bitmap is truncated"))?;
                        if *byte != before as u8 {
                            return Err(reject("resident bitmap preimage changed"));
                        }
                        *byte = after as u8;
                    }
                    Ok(())
                },
                &mut extra,
            )?;
        }
        drop(volume);
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }

    pub(crate) fn plan_resize(
        source: &Path,
        bytes: u64,
        progress: &mut dyn FnMut(RepairProgress),
    ) -> io::Result<RepairPlan> {
        validate_size(bytes)?;
        let probe = checker::probe(source)?;
        let boot = probe.boot;
        if (probe.info.major_version, probe.info.minor_version) != SUPPORTED_NTFS_VERSION
            || probe.info.flags
                & !(VOLUME_RESIZE_LOG_FILE
                    | ntfs_rs::volume_info::VOLUME_NO_SHORT_NAMES
                    | ntfs_rs::volume_info::VOLUME_MODIFIED_BY_CHECK)
                != 0
        {
            return Err(reject("log resizing requires clean NTFS 3.1"));
        }
        let recovery = checker::inspect_recovery(Image::open(source)?, boot)?;
        if write_gate(recovery.hibernation, false) != HibernationWriteGate::Clear
            || !(matches!(recovery.log, LogState::NoActiveClients | LogState::CheckedVolume)
                || (recovery.log == LogState::ReplayRequired && replay_is_empty(source)?)
                // A cleanly shut down Windows journal has nothing left to apply.
                || (recovery.log == LogState::CleanShutdown && replay_changes_nothing(source)?))
        {
            return Err(reject("log resizing requires a validated inactive journal and no hibernation"));
        }
        progress(RepairProgress::new(Phase::Planning, 0, 0));
        if !checker::consistency::audit(source, boot, Default::default())?.passed() {
            return Err(reject("run a complete repair before resizing the log"));
        }
        let mut patches = RepairPlan::new(image_length(&File::open(source)?)?)?;
        let mut volume = checker::open_volume(source)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::LOG)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let data = record.stream(ATTR_DATA, &[])?;
        let old_bytes = data.data_size()?;
        let cluster = u64::from(boot.cluster_bytes);
        if record.flags()? & (rf::IN_USE | rf::DIRECTORY) != rf::IN_USE
            || !data.nonresident
            || data.flags()? != 0
            || data.initialized_size()? != old_bytes
            || data.allocated_size()? % cluster != 0
        {
            return Err(reject("log data must be fully initialized and nonsparse"));
        }
        let (page_bytes, lsn) = restart_pages(&mut volume, data)?;
        if bytes < u64::from(page_bytes) * RESTART_COPY_COUNT {
            return Err(reject("new log is smaller than the restart pair"));
        }
        // A log that already has the wanted size needs no new mapping. A resize
        // request from Windows is then answered by the checked markers alone.
        let same_size = old_bytes == bytes;
        if same_size && probe.info.flags & VOLUME_RESIZE_LOG_FILE == 0 {
            return Ok(patches);
        }
        let mut marker = [0; CHECKED_MARKER_BYTES];
        encode_checked_marker(&mut marker, lsn)?;
        for offset in [0, u64::from(page_bytes)] {
            map_bytes(&mut volume, data, offset, CHECKED_MARKER_BYTES as u64, &mut patches, |at, out| {
                out.copy_from_slice(&marker[at as usize..at as usize + out.len()]);
            })?;
        }
        if same_size {
            drop(volume);
        } else {
            let mut space = RepairSpace::new(&mut volume, &mft)?;
            let runs = resized_runs(&mut volume, data, bytes, &mut space)?;
            let mut attribute = vec![0; NONRESIDENT_BUILD_OVERHEAD_BYTES + runs.len() * MAX_MAPPING_PAIR_BYTES];
            let used = e::build_nonresident(
                ATTR_DATA,
                &[],
                &runs,
                bytes.div_ceil(cluster) * cluster,
                bytes,
                bytes,
                &mut attribute,
            )?;
            attribute.truncate(used);
            let mut temporary = vec![0; boot.record_bytes as usize];
            e::format_empty(&mut temporary, system_record::LOG)?;
            // This logical record supplies an attribute view only. Keep the physical
            // header geometry while giving fragmented mappings enough scratch space.
            temporary.resize(temporary.len() + attribute.len(), 0);
            let capacity = u32::try_from(temporary.len()).map_err(io::Error::other)?;
            e::p32(&mut temporary, rf::CAPACITY_OFFSET, capacity)?;
            e::insert(&mut temporary, &attribute)?;
            let replacement = MftRecord::from_decoded(&temporary)?;
            let replacement_data = replacement.stream(ATTR_DATA, &[])?;
            if bytes > old_bytes {
                map_bytes(&mut volume, replacement_data, old_bytes, bytes - old_bytes, &mut patches, |_, out| {
                    out.fill(u8::MAX)
                })?;
            }
            let changes = relocation::mapping_descriptors(
                &attribute,
                runs.len(),
                |n| Ok(runs[n]),
                (boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES),
                relocation::DESCRIPTOR_CAPACITY,
            )?;
            // Keep metadata edits separate until every member and list can be stored.
            let mut extra = RepairPlan::new(patches.length)?;
            family.store(&mut volume, &mft, changes, &mut space, &mut extra)?;
            drop(volume);
            for patch in extra.iter() {
                patches.compose(patch?)?;
            }
            metadata::file_repairs(source, boot, &mut patches)?;
            // Released tail clusters are available to index publication even when the
            // original volume is full. Only the log's cached index values may be stale
            // at this intermediate stage; the final audit requires every value to match.
            reconcile_allocation(source, boot, &mut patches, true)?;
            directory_repairs_with_options(
                source,
                boot,
                &mut patches,
                checker::consistency::AuditOptions::default(),
                checker::consistency::scratch_file()?,
                &mut |_| {},
            )?;
            reconcile_allocation(source, boot, &mut patches, false)?;
        }
        if probe.info.flags & VOLUME_RESIZE_LOG_FILE != 0 {
            let mut volume = PlannedImage::volume(source, &patches, boot)?;
            let zero = checker::consistency::mft_image(&mut volume)?;
            let mft = MftRecord::from_decoded(&zero)?;
            let family = RepairFamily::load(&mut volume, &mft, system_record::VOLUME)?;
            let mut extra = RepairPlan::new(patches.length)?;
            family.patch_resident_values(
                &mut volume,
                &mft,
                ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION,
                &[],
                &mut |value| {
                    let flags = ntfs_rs::bytes::u16_at(value, VOLUME_FLAGS_OFFSET)?;
                    value[VOLUME_FLAGS_OFFSET..VOLUME_FLAGS_END]
                        .copy_from_slice(&(flags & !VOLUME_RESIZE_LOG_FILE).to_le_bytes());
                    Ok(())
                },
                &mut extra,
            )?;
            drop(volume);
            for patch in extra.iter() {
                patches.compose(patch?)?;
            }
        }
        if !checker::consistency::audit_reader(
            PlannedImage::open(source, &patches)?,
            boot,
            |_, _, _| Ok(()),
            |_| Ok(()),
            checker::consistency::AuditOptions::default(),
            checker::consistency::INDEX_CACHE_BYTES,
        )?
        .passed()
        {
            return Err(reject("proposed log resize does not pass the complete audit"));
        }
        if checker::inspect_recovery(PlannedImage::open(source, &patches)?, boot)?.log != LogState::CheckedVolume {
            return Err(reject("proposed checked-volume markers do not validate"));
        }
        Ok(patches)
    }

    // The real device stays dirty until the hypothetical clean result passes every
    // audit. Both dirty guards are overlaid, so validation cannot publish clean state.
    pub(crate) fn validate_in_place_result(source: &Path, bytes: u64, finalizers: &Vec<Patch>) -> io::Result<()> {
        let boot = checker::probe(source)?.boot;
        let view = || -> io::Result<_> { Ok(PlannedImage::open(source, finalizers)?) };
        let size = checker::inspect_logfile_size(view()?, boot)?;
        let recovery = checker::inspect_recovery(view()?, boot)?;
        if size.data_bytes != bytes
            || size.initialized_bytes != bytes
            || recovery.log != LogState::CheckedVolume
            || write_gate(recovery.hibernation, false) != HibernationWriteGate::Clear
            || !checker::consistency::audit_reader(
                view()?,
                boot,
                |_, _, _| Ok(()),
                |_| Ok(()),
                checker::consistency::AuditOptions::default(),
                checker::consistency::INDEX_CACHE_BYTES,
            )?
            .passed()
        {
            return Err(reject("post-resize validation failed; dirty flags and journal retained"));
        }
        Ok(())
    }

    /// Resize the log in a newly published image after validating the complete
    /// source and proposed result. Existing log extents and history are retained.
    pub fn resize_to(
        source: &Path,
        destination: &Path,
        bytes: u64,
        stop_after: Option<usize>,
        progress: &mut dyn FnMut(RepairProgress),
    ) -> io::Result<()> {
        let planned = plan_resize(source, bytes, progress)?;
        if stop_after.is_some_and(|n| n == 0 || n > planned.len() + 1) {
            return Err(reject("test flush boundary is outside this resize plan"));
        }
        let mut input = File::open(source)?;
        let original = input.metadata()?;
        if !original.is_file() {
            return Err(reject("copy log resizing requires an offline regular image"));
        }
        let StagedCopy { mut output, temporary } =
            StagedCopy::create(&mut input, &original, destination, ".log-resize-incomplete", progress)?;
        let temporary = temporary.as_path();
        let mut flushes = 0;
        flush(&mut output, &mut flushes, stop_after)?;
        let actual = plan_resize(temporary, bytes, progress)?;
        if !planned.matches(&actual)? {
            return Err(reject("copied image does not match log resize plan"));
        }
        for patch in actual.iter() {
            let patch = patch?;
            patch.apply_to(&output, "log resize preimage changed")?;
            flush(&mut output, &mut flushes, stop_after)?;
        }
        let probe = checker::probe(temporary)?;
        if checker::inspect_logfile_size(Image::open(temporary)?, probe.boot)?.data_bytes != bytes
            || !checker::check_device(temporary, Default::default(), None)?.write_ready()
        {
            return Err(reject("resized image does not pass final validation"));
        }
        publish_staged(&output, temporary, destination)?;
        let total = original.len().div_ceil(NTFS_SECTOR_BYTES as u64);
        progress(RepairProgress::new(Phase::Complete, total, total));
        Ok(())
    }
}

pub(super) mod relocation {
    use super::family::{MAX_MAPPING_PAIR_BYTES, MFT_ATTRIBUTE_RESERVE_BYTES, NONRESIDENT_BUILD_OVERHEAD_BYTES};
    use super::*;
    use ntfs_rs::mft::attribute_layout as af;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::{
        record_edit as e,
        runlist::{DataRuns, Extent},
    };

    const COMPRESSION_UNIT_SHIFT: u16 = 4;
    const COMPRESSION_UNIT_CLUSTERS: u64 = 1 << COMPRESSION_UNIT_SHIFT;
    const MAX_COMPRESSED_CLUSTER_BYTES: u32 = 4096;
    const ENCODED_DATA_FLAGS: u16 = af::COMPRESSED | af::ENCRYPTED | af::SPARSE;
    const COMPRESSED_DATA_FLAGS: u16 = af::COMPRESSED | af::SPARSE;

    /// Validate encoded DATA without granting ordinary file-write authority.
    pub(crate) fn validate_data_stream(
        record: &[u8],
        attr: Attribute<'_>,
        boot: ntfs_rs::boot::BootSector,
    ) -> io::Result<()> {
        let flags = attr.flags()?;
        if !attr.nonresident
            || flags & !ENCODED_DATA_FLAGS != 0
            || flags & (af::ENCRYPTED | af::COMPRESSED) == (af::ENCRYPTED | af::COMPRESSED)
        {
            return Err(reject("unsupported recovery DATA encoding"));
        }
        if flags & af::COMPRESSED != 0 {
            compression_layout(record, attr, boot)?;
        }
        Ok(())
    }

    // A missing encoded cluster invalidates its decoded unit, even when the
    // physical sector lies beyond that unit's initialized logical prefix.
    pub(crate) fn compressed_loss_range(
        record: &[u8],
        attr: Attribute<'_>,
        boot: ntfs_rs::boot::BootSector,
        failed_lcn: u64,
    ) -> io::Result<Option<(u64, u64)>> {
        let runs = compression_layout(record, attr, boot)?;
        for run in runs {
            if let Some(lcn) = run.lcn {
                let end = lcn.checked_add(run.len).ok_or_else(|| reject("compressed physical extent overflow"))?;
                if lcn <= failed_lcn && failed_lcn < end {
                    let first = (run.vcn + failed_lcn - lcn) / COMPRESSION_UNIT_CLUSTERS * COMPRESSION_UNIT_CLUSTERS;
                    let cluster = u64::from(boot.cluster_bytes);
                    let start = first.checked_mul(cluster).ok_or_else(|| reject("compressed logical unit overflow"))?;
                    let end = first
                        .checked_add(COMPRESSION_UNIT_CLUSTERS)
                        .and_then(|vcn| vcn.checked_mul(cluster))
                        .ok_or_else(|| reject("compressed logical unit overflow"))?;
                    return Ok(Some((start, end)));
                }
            }
        }
        Ok(None)
    }

    fn compression_layout(
        record: &[u8],
        attr: Attribute<'_>,
        boot: ntfs_rs::boot::BootSector,
    ) -> io::Result<Vec<Extent>> {
        let at = attr.record_offset();
        let flags = attr.flags()?;
        let header = record
            .get(at..at + e::attr_len(record, at)?)
            .ok_or_else(|| reject("truncated compressed DATA descriptor"))?;
        if !attr.nonresident
            || flags & af::COMPRESSED == 0
            || flags & !COMPRESSED_DATA_FLAGS != 0
            || attr.first_vcn()? != 0
            || ntfs_rs::bytes::u16_at(header, af::MAPPING_PAIRS_OFFSET)? < af::EXTENDED_HEADER_BYTES as u16
            || ntfs_rs::bytes::u16_at(header, af::COMPRESSION_UNIT_OFFSET)? != COMPRESSION_UNIT_SHIFT
            || boot.cluster_bytes > MAX_COMPRESSED_CLUSTER_BYTES
        {
            return Err(reject("unsupported compressed DATA unit geometry"));
        }
        let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
        let runs = DataRuns::new(attr.data_runs()?, 0).collect::<ntfs_rs::Result<Vec<_>>>()?;
        let mut end = 0_u64;
        let mut sparse_end = 0_u64;
        let mut physical = 0_u64;
        for run in &runs {
            if run.len == 0 || run.vcn != end {
                return Err(reject("compressed DATA mapping has a gap"));
            }
            end = run.vcn.checked_add(run.len).ok_or_else(|| reject("compressed DATA mapping overflow"))?;
            if let Some(lcn) = run.lcn {
                if run.vcn < sparse_end || lcn.checked_add(run.len).is_none_or(|end| end > clusters) {
                    return Err(reject("compressed unit has allocated bytes after its sparse tail"));
                }
                physical =
                    physical.checked_add(run.len).ok_or_else(|| reject("compressed physical allocation overflow"))?;
            } else {
                sparse_end = end
                    .checked_add(COMPRESSION_UNIT_CLUSTERS - 1)
                    .ok_or_else(|| reject("compressed unit boundary overflow"))?
                    / COMPRESSION_UNIT_CLUSTERS
                    * COMPRESSION_UNIT_CLUSTERS;
            }
        }
        let coverage =
            end.checked_mul(u64::from(boot.cluster_bytes)).ok_or_else(|| reject("compressed DATA size overflow"))?;
        let physical = physical
            .checked_mul(u64::from(boot.cluster_bytes))
            .ok_or_else(|| reject("compressed physical size overflow"))?;
        if end == 0
            || end % COMPRESSION_UNIT_CLUSTERS != 0
            || attr.last_vcn()?.checked_add(1) != Some(end)
            || attr.data_size()? > coverage
            || attr.initialized_size()? > attr.data_size()?
            || attr.allocated_size()? != coverage
            || u64_at(header, af::COMPRESSED_SIZE_OFFSET)? != physical
        {
            return Err(reject("compressed DATA size and mapping disagree"));
        }
        Ok(runs)
    }

    fn damaged_compression_units(
        unresolved: Option<&File>,
        runs: &[Extent],
        clusters: u64,
    ) -> io::Result<Vec<(u64, u64)>> {
        let Some(unresolved) = unresolved else {
            return Ok(Vec::new());
        };
        let mut missing = std::io::BufReader::new(unresolved.try_clone()?);
        missing.seek(SeekFrom::Start(0))?;
        let mut units = checker::consistency::DiskInventory::new();
        let mut previous = 0;
        // Historical EIO reservations can have subsequently authenticated bytes.
        // Only unresolved archive sectors authorize discarding a decoded unit.
        while let Some([bad_lcn, bad_end, reserved, extra]) = checker::consistency::inventory_next(&mut missing)? {
            if bad_lcn < previous || bad_lcn >= bad_end || bad_end > clusters || reserved != 0 || extra != 0 {
                return Err(reject("invalid unresolved encoded-cluster catalog"));
            }
            previous = bad_lcn;
            for run in runs {
                let Some(lcn) = run.lcn else {
                    continue;
                };
                let end = lcn.checked_add(run.len).ok_or_else(|| reject("compressed physical extent overflow"))?;
                let first = lcn.max(bad_lcn);
                let last = end.min(bad_end);
                if first < last {
                    let start = (run.vcn + first - lcn) / COMPRESSION_UNIT_CLUSTERS * COMPRESSION_UNIT_CLUSTERS;
                    let end = (run.vcn + last - lcn)
                        .checked_add(COMPRESSION_UNIT_CLUSTERS - 1)
                        .ok_or_else(|| reject("compressed unit range overflow"))?
                        / COMPRESSION_UNIT_CLUSTERS
                        * COMPRESSION_UNIT_CLUSTERS;
                    units.push([start, end, 0, 0])?;
                }
            }
        }
        let mut units = std::io::BufReader::new(units.finish()?);
        let mut merged: Vec<(u64, u64)> = Vec::new();
        while let Some([start, end, _, _]) = checker::consistency::inventory_next(&mut units)? {
            if let Some(previous) = merged.last_mut().filter(|previous| start <= previous.1) {
                previous.1 = previous.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(merged)
    }

    // Whole sparse units are the canonical zero representation. Keep every
    // unaffected encoded extent and its VCN; never patch compressed payload bytes
    // as though their physical offsets were decoded logical offsets.
    fn zero_compression_units(runs: &[Extent], units: &[(u64, u64)]) -> Vec<Extent> {
        let mut result = Vec::new();
        for run in runs {
            let mut cursor = run.vcn;
            let end = run.vcn + run.len;
            for &(start, stop) in units {
                let first = cursor.max(start);
                let last = end.min(stop);
                if first >= last {
                    continue;
                }
                if cursor < first {
                    result.push(Extent {
                        vcn: cursor,
                        len: first - cursor,
                        lcn: run.lcn.map(|lcn| lcn + cursor - run.vcn),
                    });
                }
                result.push(Extent { vcn: first, len: last - first, lcn: None });
                cursor = last;
            }
            if cursor < end {
                result.push(Extent { vcn: cursor, len: end - cursor, lcn: run.lcn.map(|lcn| lcn + cursor - run.vcn) });
            }
        }
        result
    }

    pub(crate) fn relocate(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
        number: u64,
        id: u16,
        unresolved: Option<&File>,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let mut raw = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(&mft, number, &mut raw)?;
        let physical = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let attr = physical
            .attributes()
            .collect::<ntfs_rs::Result<Vec<_>>>()?
            .into_iter()
            .find(|a| a.id == id)
            .ok_or_else(|| reject("relocation attribute disappeared"))?;
        let (kind, name) = (attr.kind, attr.name_utf16le()?.to_vec());
        let base = physical.base_file_reference()?;
        let owner = if base == 0 { number } else { ntfs_rs::mft::reference_number(base) };
        let family = RepairFamily::load(&mut volume, &mft, owner)?;
        let file = MftRecord::from_decoded(&family.logical)?;
        let attr = file.local_attribute(kind, &name)?.ok_or_else(|| reject("relocation stream disappeared"))?;
        let compressed = owner >= system_record::RESERVED && kind == ATTR_DATA && attr.flags()? & af::COMPRESSED != 0;
        let runs = if compressed {
            let runs = compression_layout(&family.logical, attr, boot)?;
            let units =
                damaged_compression_units(unresolved, &runs, boot.total_sectors / u64::from(boot.sectors_per_cluster))?;
            zero_compression_units(&runs, &units)
        } else {
            if owner >= system_record::RESERVED && kind == ATTR_DATA {
                validate_data_stream(&family.logical, attr, boot)?;
            }
            DataRuns::new(attr.data_runs()?, 0).collect::<ntfs_rs::Result<Vec<_>>>()?
        };
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut extra = RepairPlan::new(patches.length)?;
        let mut source_image = Image(File::open(source)?);
        let cluster = u64::from(boot.cluster_bytes);
        let mut replacement = Vec::new();
        for run in runs {
            let Some(old) = run.lcn else {
                replacement.push(run);
                continue;
            };
            for mut destination in space.fragments(&mut volume, run.len)? {
                let from = old * cluster + destination.vcn * cluster;
                let to = destination.lcn.unwrap() * cluster;
                let length = destination.len * cluster;
                let mut at = 0;
                while at < length {
                    let n = (length - at).min(REPAIR_CHUNK_BYTES) as usize;
                    let mut before = vec![0; n];
                    let mut after = vec![0; n];
                    volume.read_physical(to + at, &mut before)?;
                    if owner < system_record::RESERVED || kind != ATTR_DATA {
                        volume.read_physical(from + at, &mut after)?;
                    } else {
                        source_image.read_exact_at(from + at, &mut after)?;
                    }
                    extra.push(Patch::new(to + at, before, after))?;
                    at += n as u64;
                }
                destination.vcn += run.vcn;
                replacement.push(destination);
            }
        }
        let mut descriptor_image = family.logical.clone();
        if compressed {
            let physical = replacement
                .iter()
                .filter(|run| run.lcn.is_some())
                .try_fold(0_u64, |size, run| size.checked_add(run.len))
                .and_then(|clusters| clusters.checked_mul(cluster))
                .ok_or_else(|| reject("replacement compressed allocation overflow"))?;
            e::p64(&mut descriptor_image, attr.record_offset() + af::COMPRESSED_SIZE_OFFSET, physical)?;
        }
        let descriptor_file = MftRecord::from_decoded(&descriptor_image)?;
        let descriptor =
            descriptor_file.local_attribute(kind, &name)?.ok_or_else(|| reject("replacement stream disappeared"))?;
        let changes = descriptors(
            &descriptor_image,
            descriptor,
            &replacement,
            (boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES),
        )?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return relocate(source, boot, patches, number, id, unresolved);
        }
        result?;
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }

    // Keep original flags, compression unit, size fields, name and extended
    // header. Only mapping pairs and continuation VCN bounds change.
    pub(crate) fn descriptors(
        record: &[u8],
        attr: Attribute<'_>,
        runs: &[Extent],
        room: usize,
    ) -> io::Result<Vec<StreamChange>> {
        let at = attr.record_offset();
        mapping_descriptors(
            &record[at..at + e::attr_len(record, at)?],
            runs.len(),
            |i| Ok(runs[i]),
            room,
            DESCRIPTOR_CAPACITY,
        )
    }

    pub(crate) const DESCRIPTOR_CAPACITY: &str = "relocation descriptor cannot fit an MFT record";

    // Capacity failure belongs to the caller; descriptor framing and continuation
    // encoding stay shared between relocation and ordinary MFT growth.
    pub(crate) fn mapping_descriptors(
        attribute: &[u8],
        count: usize,
        mut get: impl FnMut(usize) -> io::Result<Extent>,
        room: usize,
        capacity_error: &'static str,
    ) -> io::Result<Vec<StreamChange>> {
        let offset = ntfs_rs::bytes::u16_at(attribute, af::MAPPING_PAIRS_OFFSET)? as usize;
        let header = attribute.get(..offset).ok_or_else(|| reject("truncated stream header"))?;
        let name = e::attr_name(attribute, 0)?;
        let flags = ntfs_rs::bytes::u16_at(attribute, af::FLAGS_OFFSET)?;
        let mut changes = Vec::new();
        let mut first = 0;
        while first < count {
            let base = get(first)?;
            let mut encode = |end: usize| -> io::Result<Vec<u8>> {
                let normalized: Vec<_> = (first..end)
                    .map(|i| get(i).map(|r| Extent { vcn: r.vcn - base.vcn, ..r }))
                    .collect::<io::Result<_>>()?;
                let mut built =
                    vec![0; NONRESIDENT_BUILD_OVERHEAD_BYTES + name.len() + normalized.len() * MAX_MAPPING_PAIR_BYTES];
                let used = ntfs_rs::allocation::encode_runs(&normalized, &mut built)?;
                // Pad the mapping payload and complete attribute independently;
                // a retained header can have an unaligned mapping offset.
                let pairs_end = (used + af::ALIGNMENT - 1) & !(af::ALIGNMENT - 1);
                let mut out = header.to_vec();
                out.extend_from_slice(&built[..pairs_end]);
                out.resize((out.len() + af::ALIGNMENT - 1) & !(af::ALIGNMENT - 1), 0);
                let size = out.len() as u32;
                e::p32(&mut out, af::LENGTH_OFFSET, size)?;
                e::p64(&mut out, af::FIRST_VCN_OFFSET, base.vcn)?;
                let last = get(end - 1)?;
                e::p64(&mut out, af::LAST_VCN_OFFSET, last.vcn + last.len - 1)?;
                if first != 0 {
                    out[af::ALLOCATED_SIZE_OFFSET..af::SIZE_FIELDS_END].fill(0);
                    if flags & COMPRESSED_DATA_FLAGS != 0 && offset >= af::EXTENDED_HEADER_BYTES {
                        out[af::COMPRESSED_SIZE_OFFSET..af::EXTENDED_HEADER_BYTES].fill(0);
                    }
                }
                Ok(out)
            };
            let (mut lo, mut hi) = (first + 1, count + 1);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if encode(mid)?.len() <= room {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let end = lo - 1;
            if end == first {
                return Err(reject(capacity_error));
            }
            changes.push(StreamChange::replace(encode(end)?)?);
            first = end;
        }
        Ok(changes)
    }
}

pub(super) mod reserved {
    use super::family::{MAX_MAPPING_PAIR_BYTES, MFT_ATTRIBUTE_RESERVE_BYTES, NONRESIDENT_BUILD_OVERHEAD_BYTES};
    use super::*;
    use ntfs_rs::mft::record_layout as rf;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::{record_edit as e, runlist::Extent};

    const MIN_INACTIVE_LOG_BYTES: u64 = RESTART_COPY_COUNT * RESTART_PROBE_BYTES as u64;
    const RESTART_AREA_OFFSET: usize = 24;
    const RESTART_AREA_LENGTH_OFFSET: usize = 20;
    const RESTART_HEADER_BYTES: usize = 30;
    const BOOT_CODE_BYTES: u64 = 8192;

    // When $Bitmap is missing, allocate only from the complete ownership inventory.
    // An unreadable bitmap never establishes that its clusters are free.
    pub(crate) fn unowned_extents(
        owned: &mut (impl Read + Seek),
        reserved: &mut File,
        count: u64,
        cursor: &mut u64,
        clusters: u64,
        contiguous: bool,
    ) -> io::Result<Vec<Extent>> {
        use checker::consistency::inventory_next;
        if count == 0 {
            return Err(reject("empty ownership allocation"));
        }
        owned.seek(SeekFrom::Start(0))?;
        reserved.seek(SeekFrom::Start(0))?;
        let (mut owner, mut claim) = (inventory_next(owned)?, inventory_next(reserved)?);
        let mut at = (*cursor).max(FIRST_ALLOCATABLE_CLUSTER);
        let mut left = count;
        let mut runs = Vec::new();
        while at < clusters && left != 0 {
            while owner.is_some_and(|r| r[1] <= at) {
                owner = inventory_next(owned)?;
            }
            while claim.is_some_and(|r| r[1] <= at) {
                claim = inventory_next(reserved)?;
            }
            if let Some(row) = owner.filter(|r| r[0] <= at) {
                at = row[1];
                continue;
            }
            if let Some(row) = claim.filter(|r| r[0] <= at) {
                at = row[1];
                continue;
            }
            let end = clusters.min(owner.map_or(clusters, |r| r[0])).min(claim.map_or(clusters, |r| r[0]));
            let take = left.min(end - at);
            if !contiguous || take == count {
                runs.push(Extent { vcn: count - left, lcn: Some(at), len: take });
                left -= take;
                at += take;
            } else {
                at = end;
            }
        }
        if left != 0 {
            return Err(reject("insufficient unowned storage for reserved metadata"));
        }
        reserved.seek(SeekFrom::End(0))?;
        for run in &runs {
            checker::consistency::inventory_write(reserved, [run.lcn.unwrap(), run.lcn.unwrap() + run.len, 0, 0])?;
        }
        *cursor = at;
        Ok(runs)
    }

    pub(crate) fn ensure_bitmap(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::BITMAP)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let needed = (boot.total_sectors / u64::from(boot.sectors_per_cluster)).div_ceil(BITMAP_BITS_PER_BYTE);
        if let Some(data) = record.local_attribute(ATTR_DATA, &[])? {
            if data.data_size()? >= needed && data.initialized_size()? >= needed {
                return Ok(());
            }
        }
        drop(volume);
        bitmap(source, boot, patches)
    }

    pub(crate) fn inactive_log<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>) -> io::Result<bool> {
        use ntfs_rs::logfile::{classify_restart_pair, LogState};
        let family = RepairFamily::load(volume, mft, system_record::LOG)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let data = record.stream(ATTR_DATA, &[])?;
        let size = data.data_size()?;
        if size < MIN_INACTIVE_LOG_BYTES || data.initialized_size()? != size || data.flags()? != 0 {
            return Ok(false);
        }
        let mut prefix = [0; RESTART_PROBE_BYTES];
        volume.read_attribute(data, 0, &mut prefix)?;
        if prefix.iter().all(|&b| b == u8::MAX) {
            let mut offset = 0;
            let mut chunk = [0; REPAIR_CHUNK_BYTES as usize];
            while offset < size {
                let n = (size - offset).min(chunk.len() as u64) as usize;
                volume.read_attribute(data, offset, &mut chunk[..n])?;
                if chunk[..n].iter().any(|&b| b != u8::MAX) {
                    return Ok(false);
                }
                offset += n as u64;
            }
            return Ok(true);
        }
        let Ok(bytes) = RestartPage::peek_system_page_bytes(&prefix) else {
            return Ok(false);
        };
        if u64::from(bytes) * RESTART_COPY_COUNT > size {
            return Ok(false);
        }
        let mut a = vec![0; bytes as usize];
        let mut b = a.clone();
        volume.read_attribute(data, 0, &mut a)?;
        volume.read_attribute(data, u64::from(bytes), &mut b)?;
        let a = RestartPage::parse(&mut a, volume.boot.bytes_per_sector);
        let b = RestartPage::parse(&mut b, volume.boot.bytes_per_sector);
        Ok(a.is_ok_and(|r| r.chkdsk_marker || r.log_bytes == size)
            && b.is_ok_and(|r| r.chkdsk_marker || r.log_bytes == size)
            && matches!(classify_restart_pair(a, b), LogState::NoActiveClients | LogState::CheckedVolume))
    }

    // A stale valid restart is insufficient evidence for replacing a torn newer
    // checkpoint. Require the complete control area in an intact first sector,
    // and agreement of every other surviving sector after USA normalization.
    pub(crate) fn matching_restart_copy(bad: &[u8], good: &[u8], sector: u16) -> bool {
        let mut decoded = good.to_vec();
        let Ok(restart) = RestartPage::parse(&mut decoded, sector) else {
            return false;
        };
        if restart.active_clients || restart.chkdsk_marker || bad.len() != good.len() {
            return false;
        }
        // Match NTFS multi-sector transfer protection, which uses 512-byte
        // strides even when the volume advertises larger logical sectors.
        let sector = NTFS_SECTOR_BYTES;
        if bad.len() % sector != 0 {
            return false;
        }
        let usa = ntfs_rs::bytes::u16_at(good, rf::USA_OFFSET).unwrap() as usize;
        let count = ntfs_rs::bytes::u16_at(good, rf::USA_COUNT_OFFSET).unwrap() as usize;
        let area = ntfs_rs::bytes::u16_at(good, RESTART_AREA_OFFSET).unwrap() as usize;
        let length = ntfs_rs::bytes::u16_at(&decoded, area + RESTART_AREA_LENGTH_OFFSET).unwrap() as usize;
        if usa + count * FIXUP_WORD_BYTES > sector - FIXUP_WORD_BYTES
            || area + length > sector - FIXUP_WORD_BYTES
            || bad.get(..RESTART_HEADER_BYTES) != good.get(..RESTART_HEADER_BYTES)
            || count != bad.len() / sector + 1
        {
            return false;
        }
        let token = &bad[usa..usa + FIXUP_WORD_BYTES];
        let mut torn = false;
        for (i, bytes) in bad.chunks_exact(sector).enumerate() {
            if &bytes[sector - FIXUP_WORD_BYTES..] != token {
                if i == 0 {
                    return false;
                }
                torn = true;
                continue;
            }
            let mut candidate = bytes.to_vec();
            candidate[sector - FIXUP_WORD_BYTES..]
                .copy_from_slice(&bad[usa + FIXUP_WORD_BYTES * (i + 1)..usa + FIXUP_WORD_BYTES * (i + 2)]);
            let mut expected = decoded[i * sector..(i + 1) * sector].to_vec();
            if i == 0 {
                candidate[usa..usa + count * FIXUP_WORD_BYTES].fill(0);
                expected[usa..usa + count * FIXUP_WORD_BYTES].fill(0);
            }
            if candidate != expected {
                return false;
            }
        }
        torn
    }

    pub(crate) fn restart_copies(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::LOG)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let data = record.stream(ATTR_DATA, &[])?;
        let mut prefix = [0; RESTART_PROBE_BYTES];
        volume.read_attribute(data, 0, &mut prefix)?;
        let Ok(bytes) = RestartPage::peek_system_page_bytes(&prefix) else {
            return Ok(());
        };
        if u64::from(bytes) * RESTART_COPY_COUNT > data.data_size()? {
            return Ok(());
        }
        let mut copies = [vec![0; bytes as usize], vec![0; bytes as usize]];
        for (i, page) in copies.iter_mut().enumerate() {
            volume.read_attribute(data, i as u64 * u64::from(bytes), page)?;
        }
        let parsed = copies.each_ref().map(|p| RestartPage::parse(&mut p.clone(), boot.bytes_per_sector));
        let (bad, good) = match parsed {
            [Ok(_), Err(_)] => (1, 0),
            [Err(_), Ok(_)] => (0, 1),
            _ => return Ok(()),
        };
        if parsed[good].unwrap().log_bytes != data.data_size()?
            || !matching_restart_copy(&copies[bad], &copies[good], boot.bytes_per_sector)
        {
            return Ok(());
        }
        let mut extra = RepairPlan::new(patches.length)?;
        stage_change(
            data,
            boot,
            bad as u64 * u64::from(bytes),
            u64::from(bytes),
            &copies[bad],
            &copies[good],
            &mut extra,
        )?;
        drop(volume);
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }

    // Bootstrap has already compared the boot sectors and decoded primary/mirror
    // records. Their physical locations are independent of these stream mappings.
    pub(crate) fn canonical_streams(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        for number in [system_record::MFT_MIRROR, system_record::BOOT] {
            let mut volume = PlannedImage::volume(source, patches, boot)?;
            let logical = checker::consistency::mft_image(&mut volume)?;
            let mft = MftRecord::from_decoded(&logical)?;
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let data = record.local_attribute(ATTR_DATA, &[])?;
            let cluster = u64::from(boot.cluster_bytes);
            let bytes = if number == system_record::MFT_MIRROR {
                cluster.max(system_record::MIRRORED * u64::from(boot.record_bytes))
            } else {
                // The boot file reserves the complete boot-code area. Its size is
                // fixed by cluster geometry, so a missing or damaged descriptor
                // cannot supply the reconstruction length.
                BOOT_CODE_BYTES.div_ceil(cluster) * cluster
            };
            let lcn = if number == system_record::MFT_MIRROR { boot.mft_mirror_lcn } else { 0 };
            let count = bytes.div_ceil(cluster);
            let canonical = if let Some(data) = data.filter(|data| data.nonresident) {
                let sizes = if number == system_record::BOOT {
                    // A complete boot reservation can retain a shorter valid
                    // length. Reconstruct sizes only when rebuilding its mapping.
                    data.initialized_size()? <= data.data_size()? && data.data_size()? <= bytes
                } else {
                    data.data_size()? == bytes && data.initialized_size()? == bytes
                };
                let mapping = if number == system_record::BOOT {
                    let mut runs = ntfs_rs::runlist::DataRuns::new(data.data_runs()?, data.first_vcn()?);
                    data.first_vcn()? == 0
                        && data.last_vcn()? == count - 1
                        && runs.next().is_some_and(|run| {
                            run.is_ok_and(|run| run.vcn == 0 && run.lcn == Some(0) && run.len == count)
                        })
                        && runs.next().is_none()
                } else {
                    plan_nonresident_overwrite(data, boot, 0, bytes, |span| {
                        if span.physical_offset != lcn * cluster + span.source_offset {
                            return Err(ntfs_rs::Error::InvalidRunlist);
                        }
                        Ok(())
                    })
                    .is_ok()
                };
                data.flags()? == 0 && data.allocated_size()? == count * cluster && sizes && mapping
            } else {
                false
            };
            if canonical {
                continue;
            }
            // The canonical bytes must be readable in full before changing their
            // owner. Do not copy the corrupt descriptor's competing stream.
            let mut contents = vec![0; bytes as usize];
            volume.read_physical(lcn * cluster, &mut contents)?;
            if number == system_record::MFT_MIRROR {
                for (n, copy) in contents.chunks_exact(boot.record_bytes as usize).enumerate() {
                    let mut primary = vec![0; copy.len()];
                    volume.read_mft_record(&mft, n as u64, &mut primary)?;
                    let mut mirror = copy.to_vec();
                    MftRecord::parse(&mut primary, boot.bytes_per_sector)?;
                    MftRecord::parse(&mut mirror, boot.bytes_per_sector)?;
                    // Update sequence array values are physical write details.
                    for raw in [&mut primary, &mut mirror] {
                        let at = ntfs_rs::bytes::u16_at(raw, rf::USA_OFFSET)? as usize;
                        let n = ntfs_rs::bytes::u16_at(raw, rf::USA_COUNT_OFFSET)? as usize;
                        raw[at..at + FIXUP_WORD_BYTES * n].fill(0);
                    }
                    if primary != mirror {
                        return Err(reject("mirror reconstruction evidence changed"));
                    }
                }
            } else {
                let parsed = ntfs_rs::boot::BootSector::parse(&contents)?;
                if parsed.mft_lcn != boot.mft_lcn
                    || parsed.mft_mirror_lcn != boot.mft_mirror_lcn
                    || parsed.total_sectors != boot.total_sectors
                    || parsed.serial_number != boot.serial_number
                {
                    return Err(reject("boot reconstruction evidence changed"));
                }
            }
            let mut attribute = vec![0; boot.record_bytes as usize];
            let used = e::build_nonresident(
                ATTR_DATA,
                &[],
                &[Extent { vcn: 0, lcn: Some(lcn), len: count }],
                count * cluster,
                bytes,
                bytes,
                &mut attribute,
            )?;
            attribute.truncate(used);
            let mut space = RepairSpace::new(&mut volume, &mft)?;
            // Canonical locations are occupied even if a damaged descriptor no
            // longer claims them; extension/list allocation cannot reuse them.
            if lcn != 0 {
                space.claim_range(lcn, count)?;
            } else if count > 1 {
                space.claim_range(1, count - 1)?;
            }
            let mut extra = RepairPlan::new(patches.length)?;
            let result =
                family.store(&mut volume, &mft, vec![StreamChange::replace(attribute)?], &mut space, &mut extra);
            drop(volume);
            if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
                repair_mft_growth(source, boot, patches)?;
                return canonical_streams(source, boot, patches);
            }
            result?;
            for patch in extra.iter() {
                patches.compose(patch?)?;
            }
        }
        Ok(())
    }

    pub(crate) fn bitmap(source: &Path, boot: ntfs_rs::boot::BootSector, patches: &mut RepairPlan) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::BITMAP)?;
        let cluster = u64::from(boot.cluster_bytes);
        let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
        let bytes = clusters.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES;
        let count = bytes.div_ceil(cluster);
        let mut owned = repair_owned_ranges(&mut volume, &mft)?;
        let mut space = RepairSpace::from_ownership(&mut volume, &mft)?;
        let runs = space.fragments(&mut volume, count)?;
        let mut payload = checker::consistency::scratch_file()?;
        payload.set_len(count * cluster)?;
        owned.seek(SeekFrom::Start(0))?;
        // Start with all unowned clusters free, then preserve every declared
        // owner, including disputed claims, until the final complete audit.
        fn mark(file: &mut File, start: u64, end: u64) -> io::Result<()> {
            let mut at = start;
            while at < end {
                if at % BITMAP_BITS_PER_BYTE == 0 && end - at >= BITMAP_BITS_PER_BYTE {
                    let bytes = ((end - at) / BITMAP_BITS_PER_BYTE).min(REPAIR_CHUNK_BYTES) as usize;
                    file.seek(SeekFrom::Start(at / BITMAP_BITS_PER_BYTE))?;
                    file.write_all(&vec![u8::MAX; bytes])?;
                    at += bytes as u64 * BITMAP_BITS_PER_BYTE;
                    continue;
                }
                let byte = at / BITMAP_BITS_PER_BYTE;
                let next = ((byte + 1) * BITMAP_BITS_PER_BYTE).min(end);
                let mut value = [0];
                file.seek(SeekFrom::Start(byte))?;
                file.read_exact(&mut value)?;
                for bit in at..next {
                    value[0] |= 1 << (bit % BITMAP_BITS_PER_BYTE);
                }
                file.seek(SeekFrom::Start(byte))?;
                file.write_all(&value)?;
                at = next;
            }
            Ok(())
        }
        mark(&mut payload, 0, 1)?;
        for run in &runs {
            mark(&mut payload, run.lcn.unwrap(), run.lcn.unwrap() + run.len)?;
        }
        mark(&mut payload, clusters, bytes * BITMAP_BITS_PER_BYTE)?;
        while let Some(row) = checker::consistency::inventory_next(&mut owned)? {
            mark(&mut payload, row[0], row[1])?;
        }
        let mut extra = RepairPlan::new(patches.length)?;
        payload.seek(SeekFrom::Start(0))?;
        let mut offset = 0;
        while offset < count * cluster {
            let n = (count * cluster - offset).min(REPAIR_CHUNK_BYTES) as usize;
            let mut before = vec![0; n];
            let mut after = vec![0; n];
            let run = runs
                .iter()
                .find(|r| offset / cluster >= r.vcn && offset / cluster < r.vcn + r.len)
                .ok_or_else(|| reject("bitmap reconstruction mapping gap"))?;
            let n = n.min(((run.vcn + run.len) * cluster - offset) as usize);
            before.resize(n, 0);
            after.resize(n, 0);
            let physical = run.lcn.unwrap() * cluster + offset - run.vcn * cluster;
            volume.read_physical(physical, &mut before)?;
            payload.read_exact(&mut after)?;
            extra.push(Patch::new(physical, before, after))?;
            offset += n as u64;
        }
        let mut attribute = vec![0; NONRESIDENT_BUILD_OVERHEAD_BYTES + runs.len() * MAX_MAPPING_PAIR_BYTES];
        let n = e::build_nonresident(ATTR_DATA, &[], &runs, count * cluster, bytes, bytes, &mut attribute)?;
        attribute.truncate(n);
        let changes = relocation::mapping_descriptors(
            &attribute,
            runs.len(),
            |i| Ok(runs[i]),
            (boot.record_bytes as usize).saturating_sub(MFT_ATTRIBUTE_RESERVE_BYTES),
            relocation::DESCRIPTOR_CAPACITY,
        )?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if result.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return bitmap(source, boot, patches);
        }
        result?;
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }
}

pub(super) mod semantic {
    use super::*;
    use ntfs_rs::bytes::u16_at;

    pub(crate) const VIEW_HEADER_BYTES: usize = 16;
    pub(crate) const VIEW_ALIGNMENT: usize = std::mem::size_of::<u64>();
    pub(crate) const VIEW_DATA_OFFSET: usize = 0;
    pub(crate) const VIEW_DATA_LENGTH_OFFSET: usize = 2;
    pub(crate) const VIEW_LENGTH_OFFSET: usize = 8;
    pub(crate) const VIEW_KEY_LENGTH_OFFSET: usize = 10;
    pub(crate) const VIEW_FLAGS_OFFSET: usize = 12;
    pub(crate) const VIEW_CHILD: u16 = 1;
    pub(crate) const VIEW_END: u16 = 2;
    pub(crate) const VIEW_CHILD_BYTES: usize = std::mem::size_of::<u64>();
    pub(crate) const VIEW_U32_BYTES: usize = std::mem::size_of::<u32>();
    pub(crate) const VIEW_U16_BYTES: usize = std::mem::size_of::<u16>();
    pub(crate) const VIEW_U64_BYTES: usize = std::mem::size_of::<u64>();
    pub(crate) const VIEW_ROOT_NODE_OFFSET: usize = 16;
    const VIEW_BLOCK_NODE_OFFSET: usize = 24;
    const VIEW_NODE_HEADER_BYTES: usize = 16;
    const VIEW_NODE_USED_OFFSET: usize = 4;
    const VIEW_ROOT_COLLATION_OFFSET: usize = 4;
    const VIEW_ROOT_BLOCK_SIZE_OFFSET: usize = 8;
    pub(crate) const VIEW_ROOT_MIN_BYTES: usize = 32;
    pub(crate) const COLLATION_QUOTA_ID: u32 = 16;
    pub(crate) const COLLATION_SID: u32 = 17;
    pub(crate) const COLLATION_U32_SEQUENCE: u32 = 19;
    pub(crate) const ATTR_OBJECT_ID: u32 = 0x40;
    pub(crate) const OBJECT_ID_BYTES: usize = 16;
    pub(crate) const OBJECT_ID_WORDS: usize = OBJECT_ID_BYTES / VIEW_U32_BYTES;
    pub(crate) const OBJECT_PAYLOAD_BYTES: usize = 56;
    pub(crate) const QUOTA_CONTROL_BYTES: usize = 48;
    pub(crate) const QUOTA_CONTROL_REVISION: u32 = 2;
    pub(crate) const QUOTA_DEFAULT_ID: u32 = 1;
    pub(crate) const FIRST_QUOTA_OWNER: u32 = 0x100;
    pub(crate) const QUOTA_CHARGE_OFFSET: usize = 8;
    pub(crate) const SI_LEGACY_BYTES: usize = 48;
    pub(crate) const SI_MODERN_BYTES: usize = 72;
    pub(crate) const SI_OWNER_OFFSET: usize = 48;
    pub(crate) const SI_QUOTA_CHARGE_OFFSET: usize = 56;
    /// The last change-journal sequence number, the final field of the modern layout.
    pub(crate) const SI_USN_OFFSET: usize = 64;

    fn leaf(row: &[u8]) -> io::Result<Vec<u8>> {
        let mut row = row.to_vec();
        if u16_at(&row, VIEW_FLAGS_OFFSET)? & VIEW_CHILD != 0 {
            row.truncate(row.len() - VIEW_CHILD_BYTES);
        }
        let length = row.len() as u16;
        row[VIEW_LENGTH_OFFSET..VIEW_LENGTH_OFFSET + VIEW_U16_BYTES].copy_from_slice(&length.to_le_bytes());
        row[VIEW_FLAGS_OFFSET..VIEW_FLAGS_OFFSET + VIEW_U16_BYTES].fill(0);
        Ok(row)
    }

    pub(crate) fn view_entry(key: &[u8], value: &[u8]) -> io::Result<Vec<u8>> {
        let at = (VIEW_HEADER_BYTES + key.len() + VIEW_ALIGNMENT - 1) & !(VIEW_ALIGNMENT - 1);
        let length = (at + value.len() + VIEW_ALIGNMENT - 1) & !(VIEW_ALIGNMENT - 1);
        if length > u16::MAX as usize {
            return Err(reject("view entry is too large"));
        }
        let mut row = vec![0; length];
        row[..VIEW_U16_BYTES].copy_from_slice(&(at as u16).to_le_bytes());
        row[VIEW_DATA_LENGTH_OFFSET..VIEW_DATA_LENGTH_OFFSET + VIEW_U16_BYTES]
            .copy_from_slice(&(value.len() as u16).to_le_bytes());
        row[VIEW_LENGTH_OFFSET..VIEW_LENGTH_OFFSET + VIEW_U16_BYTES].copy_from_slice(&(length as u16).to_le_bytes());
        row[VIEW_KEY_LENGTH_OFFSET..VIEW_KEY_LENGTH_OFFSET + VIEW_U16_BYTES]
            .copy_from_slice(&(key.len() as u16).to_le_bytes());
        row[VIEW_HEADER_BYTES..VIEW_HEADER_BYTES + key.len()].copy_from_slice(key);
        row[at..at + value.len()].copy_from_slice(value);
        Ok(row)
    }

    #[cfg(test)]
    mod quota_sid_tests {
        include!("../tests/recovery/semantic_quota_sid_tests.rs");
    }

    // STANDARD_INFORMATION records carry the per-file quota charge, once per
    // base record regardless of hard-link count or extension count.
    fn quota_usage<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>) -> io::Result<Option<BTreeMap<u32, u64>>> {
        let slots = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let mut bits = (u64::MAX, [0; BITMAP_CACHE_BYTES]);
        let mut raw = vec![0; volume.boot.record_bytes as usize];
        let mut result = BTreeMap::<u32, u64>::new();
        for number in 0..slots {
            if !bitmap_bit(volume, bitmap, number, slots, &mut bits)? {
                continue;
            }
            volume.read_mft_record(mft, number, &mut raw)?;
            let record = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
            if record.base_file_reference()? != 0 {
                continue;
            }
            let family = RepairFamily::load(volume, mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let Some(si) = record.local_attribute(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[])? else {
                return Ok(None);
            };
            let value = si.resident_value()?;
            if value.len() == SI_LEGACY_BYTES {
                continue;
            }
            if value.len() != SI_MODERN_BYTES {
                return Err(reject("quota charge has an unknown standard-information layout"));
            }
            let owner = u32_at(value, SI_OWNER_OFFSET)?;
            let charge = u64_at(value, SI_QUOTA_CHARGE_OFFSET)?;
            if owner == 0 && charge == 0 {
                continue;
            }
            if owner < FIRST_QUOTA_OWNER {
                return Err(reject("file has a reserved quota owner identity"));
            }
            let total = result.entry(owner).or_default();
            *total = total.checked_add(charge).ok_or_else(|| reject("quota charge overflow"))?;
        }
        Ok(Some(result))
    }

    pub(crate) fn quota_repairs(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let Some(owner) = extend_metadata_file(&mut volume, &mft, "$Quota")? else {
            return Ok(());
        };
        let family = RepairFamily::load(&mut volume, &mft, owner)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let q = b"$\0Q\0";
        let o = b"$\0O\0";
        let q_root = record
            .local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, q)?
            .ok_or_else(|| reject("quota controls are missing; custom limits cannot be inferred"))?;
        let mut authority = BTreeMap::<Vec<u8>, u32>::new();
        let mut ids = BTreeSet::new();
        let mut controls = BTreeMap::new();
        let mut control_order = Vec::new();
        let mut rows = Vec::new();
        let traversal = visit_view_index(
            &mut volume,
            q_root.resident_value()?,
            record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, q)?,
            record.local_attribute(ATTR_BITMAP, q)?,
            0,
            COLLATION_QUOTA_ID,
            &mut |row| {
                rows.push(row.to_vec());
                Ok(())
            },
        );
        let mut q_dirty = traversal.is_err();
        if let Err(error) = traversal {
            if !matches!(error.kind(), io::ErrorKind::InvalidData | io::ErrorKind::Unsupported) {
                return Err(error);
            }
            // Preserve all controls, including separator rows and disconnected
            // allocated pages. Missing pages or ambiguous limits are not inferred.
            rows = recover_view_rows(
                &mut volume,
                q_root.resident_value()?,
                record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, q)?,
                record.local_attribute(ATTR_BITMAP, q)?,
                COLLATION_QUOTA_ID,
            )?;
        }
        for row in &rows {
            let data = u16_at(row, VIEW_DATA_OFFSET)? as usize;
            let size = u16_at(row, VIEW_DATA_LENGTH_OFFSET)? as usize;
            if u16_at(row, VIEW_KEY_LENGTH_OFFSET)? != VIEW_U32_BYTES as u16
                || size < QUOTA_CONTROL_BYTES
                || u32_at(row, data)? != QUOTA_CONTROL_REVISION
            {
                return Err(reject("quota control version or key is ambiguous"));
            }
            let id = u32_at(row, VIEW_HEADER_BYTES)?;
            let value = leaf(row)?;
            if !ids.insert(id) {
                if controls.get(&id) != Some(&value) {
                    return Err(reject("conflicting quota owner controls; limits preserved"));
                }
                q_dirty = true;
                continue;
            }
            controls.insert(id, value);
            control_order.push(id);
            if id == QUOTA_DEFAULT_ID {
                if size != QUOTA_CONTROL_BYTES {
                    return Err(reject("quota defaults contain unknown fields"));
                }
            } else {
                if id < FIRST_QUOTA_OWNER {
                    return Err(reject("reserved quota owner ID"));
                }
                let key = metadata::quota_sid(&row[data + QUOTA_CONTROL_BYTES..data + size], true)?.to_vec();
                if authority.insert(key, id).is_some() {
                    return Err(reject("conflicting quota SID controls; limits preserved"));
                }
            }
        }
        if !controls.contains_key(&QUOTA_DEFAULT_ID) {
            return Err(reject("quota default policy is missing; limits cannot be inferred"));
        }
        q_dirty |= control_order.windows(2).any(|w| w[0] >= w[1]);
        if let Some(usage) = quota_usage(&mut volume, &mft)? {
            if usage.keys().any(|id| !controls.contains_key(id)) {
                return Err(reject("file quota owner has no control; custom limits are unavailable"));
            }
            for (&id, row) in &mut controls {
                if id == QUOTA_DEFAULT_ID {
                    continue;
                }
                let at = u16_at(row, VIEW_DATA_OFFSET)? as usize;
                let total = usage.get(&id).copied().unwrap_or(0);
                if u64_at(row, at + QUOTA_CHARGE_OFFSET)? != total {
                    row[at + QUOTA_CHARGE_OFFSET..at + QUOTA_CHARGE_OFFSET + VIEW_U64_BYTES]
                        .copy_from_slice(&total.to_le_bytes());
                    q_dirty = true;
                }
            }
        }
        if q_dirty {
            let rows: Vec<_> = controls.into_values().collect();
            let mut space = RepairSpace::new(&mut volume, &mft)?;
            let mut extra = RepairPlan::new(patches.length)?;
            let result =
                family::install_view(&mut volume, &mft, family, q, COLLATION_QUOTA_ID, &rows, &mut space, &mut extra);
            drop(volume);
            if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
                repair_mft_growth(source, boot, patches)?;
                return quota_repairs(source, boot, patches);
            }
            result?;
            for patch in extra.iter() {
                patches.compose(patch?)?;
            }
            return quota_repairs(source, boot, patches);
        }
        let mut wanted = BTreeMap::new();
        for (sid, id) in &authority {
            wanted.insert(sid.clone(), view_entry(sid, &id.to_le_bytes())?);
        }
        let mut original_order = Vec::new();
        let mut dirty = false;
        if let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, o)? {
            let mut seen = BTreeSet::new();
            let mut unknown_sid = false;
            let read = visit_view_index(
                &mut volume,
                root.resident_value()?,
                record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, o)?,
                record.local_attribute(ATTR_BITMAP, o)?,
                0,
                COLLATION_SID,
                &mut |row| {
                    let size = u16_at(row, VIEW_KEY_LENGTH_OFFSET)? as usize;
                    let key = metadata::quota_sid(&row[VIEW_HEADER_BYTES..VIEW_HEADER_BYTES + size], false)?.to_vec();
                    if !seen.insert(key.clone()) {
                        dirty = true;
                        return Ok(());
                    }
                    let Some(&id) = authority.get(&key) else {
                        unknown_sid = true;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "quota lookup names a SID with no owner control; limits are unavailable",
                        ));
                    };
                    let data = u16_at(row, VIEW_DATA_OFFSET)? as usize;
                    if u16_at(row, VIEW_DATA_LENGTH_OFFSET)? < VIEW_U32_BYTES as u16 {
                        return Err(reject("short quota lookup data"));
                    }
                    let mut corrected = leaf(row)?;
                    if u32_at(row, data)? != id {
                        corrected[data..data + VIEW_U32_BYTES].copy_from_slice(&id.to_le_bytes());
                        dirty = true;
                    }
                    original_order.push(key.clone());
                    wanted.insert(key, corrected);
                    Ok(())
                },
            );
            if let Err(error) = read {
                if unknown_sid || !matches!(error.kind(), io::ErrorKind::InvalidData | io::ErrorKind::Unsupported) {
                    return Err(error);
                }
                // The complete $Q controls are independent authority for $O.
                // A damaged derived tree is replaced while its preimages survive.
                dirty = true;
            }
            if seen.len() != authority.len() || original_order.windows(2).any(|w| w[0] >= w[1]) {
                dirty = true;
            }
        } else {
            dirty = true;
        }
        if !dirty {
            return Ok(());
        }
        let rows: Vec<_> = wanted.into_values().collect();
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut extra = RepairPlan::new(patches.length)?;
        let result = family::install_view(&mut volume, &mft, family, o, COLLATION_SID, &rows, &mut space, &mut extra);
        drop(volume);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return quota_repairs(source, boot, patches);
        }
        result?;
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }

    // Recover an index with damaged topology only when every allocated node is
    // intact. This is stricter than derived object-ID recovery: quota controls
    // contain policies which cannot be recreated from per-file metadata.
    fn recover_view_rows<R: ReadAt>(
        volume: &mut Volume<R>,
        root: &[u8],
        allocation: Option<Attribute<'_>>,
        bitmap: Option<Attribute<'_>>,
        collation: u32,
    ) -> io::Result<Vec<Vec<u8>>> {
        if root.len() < VIEW_ROOT_MIN_BYTES
            || u32_at(root, 0)? != 0
            || u32_at(root, VIEW_ROOT_COLLATION_OFFSET)? != collation
            || u32_at(root, VIEW_ROOT_BLOCK_SIZE_OFFSET)? != volume.boot.index_block_bytes
        {
            return Err(reject("control index geometry is damaged"));
        }
        let mut rows = Vec::new();
        let mut collect = |bytes: &[u8], head| -> io::Result<()> {
            for (row, _) in view_node_slots(bytes, head)? {
                if let Some(row) = row {
                    rows.push(row);
                }
            }
            Ok(())
        };
        collect(root, VIEW_ROOT_NODE_OFFSET)?;
        match (allocation, bitmap) {
            (None, None) => {}
            (Some(allocation), Some(bitmap)) => {
                let bytes = u64::from(volume.boot.index_block_bytes);
                let initialized = allocation.initialized_size()?;
                if initialized % bytes != 0 {
                    return Err(reject("control index has a partial allocated page"));
                }
                let pages = initialized / bytes;
                let bitmap_bytes = bitmap.data_size()?;
                if bitmap_bytes < pages.div_ceil(BITMAP_BITS_PER_BYTE) {
                    return Err(reject("control index bitmap is truncated"));
                }
                let unit = if bytes < u64::from(volume.boot.cluster_bytes) {
                    NTFS_SECTOR_BYTES as u64
                } else {
                    u64::from(volume.boot.cluster_bytes)
                };
                let mut cache = (u64::MAX, [0; BITMAP_CACHE_BYTES]);
                // Allocated pages beyond the readable stream cannot be discarded.
                for byte in 0..bitmap_bytes {
                    let bits = bitmap_byte(volume, bitmap, byte, bitmap_bytes, &mut cache)?;
                    for bit in 0..BITMAP_BITS_PER_BYTE {
                        if bits & (1 << bit) == 0 {
                            continue;
                        }
                        let page = byte * BITMAP_BITS_PER_BYTE + bit;
                        if page >= pages {
                            return Err(reject("control index allocates an unavailable page"));
                        }
                        let mut raw = vec![0; bytes as usize];
                        volume.read_attribute(allocation, page * bytes, &mut raw)?;
                        ntfs_rs::index::IndexBlock::parse(&mut raw, volume.boot.bytes_per_sector, page * bytes / unit)?;
                        collect(&raw, VIEW_BLOCK_NODE_OFFSET)?;
                    }
                }
            }
            _ => return Err(reject("control index allocation/bitmap pair is incomplete")),
        }
        Ok(rows)
    }

    // Salvage only framed rows in the resident root and bitmap-allocated,
    // fixup-valid pages. Never search slack or unallocated pages for GUIDs.
    fn salvage_object_rows<R: ReadAt>(
        volume: &mut Volume<R>,
        root: &[u8],
        allocation: Option<Attribute<'_>>,
        bitmap: Option<Attribute<'_>>,
    ) -> io::Result<Vec<Vec<u8>>> {
        fn node(bytes: &[u8], head: usize, rows: &mut Vec<Vec<u8>>) {
            if bytes.len() < head + VIEW_NODE_HEADER_BYTES {
                return;
            }
            let first = u32_at(bytes, head).unwrap() as usize;
            let used = u32_at(bytes, head + VIEW_NODE_USED_OFFSET).unwrap() as usize;
            if first < VIEW_NODE_HEADER_BYTES
                || first % VIEW_ALIGNMENT != 0
                || used < first
                || used > bytes.len() - head
            {
                return;
            }
            let mut at = head + first;
            let end = head + used;
            while at + VIEW_HEADER_BYTES <= end {
                let size = u16_at(bytes, at + VIEW_LENGTH_OFFSET).unwrap() as usize;
                let flags = u16_at(bytes, at + VIEW_FLAGS_OFFSET).unwrap();
                if size < VIEW_HEADER_BYTES
                    || size % VIEW_ALIGNMENT != 0
                    || size > end - at
                    || flags & !(VIEW_CHILD | VIEW_END) != 0
                {
                    break;
                }
                if flags & VIEW_END != 0 {
                    break;
                }
                let available = size - if flags & VIEW_CHILD != 0 { VIEW_CHILD_BYTES } else { 0 };
                let data = u16_at(bytes, at).unwrap() as usize;
                let length = u16_at(bytes, at + VIEW_DATA_LENGTH_OFFSET).unwrap() as usize;
                if u16_at(bytes, at + VIEW_KEY_LENGTH_OFFSET).unwrap() == OBJECT_ID_BYTES as u16
                    && data >= VIEW_HEADER_BYTES + OBJECT_ID_BYTES
                    && matches!(length, VIEW_U64_BYTES | OBJECT_PAYLOAD_BYTES)
                    && data + length <= available
                {
                    rows.push(bytes[at..at + size].to_vec());
                }
                at += size;
            }
        }
        let mut rows = Vec::new();
        node(root, VIEW_ROOT_NODE_OFFSET, &mut rows);
        if let (Some(allocation), Some(bitmap)) = (allocation, bitmap) {
            let bytes = u64::from(volume.boot.index_block_bytes);
            let unit = if bytes < u64::from(volume.boot.cluster_bytes) {
                NTFS_SECTOR_BYTES as u64
            } else {
                u64::from(volume.boot.cluster_bytes)
            };
            let pages = allocation.initialized_size()? / bytes;
            let bits = bitmap.data_size()?.saturating_mul(BITMAP_BITS_PER_BYTE);
            let mut cache = (u64::MAX, [0; BITMAP_CACHE_BYTES]);
            for page in 0..pages.min(bits) {
                if !bitmap_bit(volume, bitmap, page, bits, &mut cache)? {
                    continue;
                }
                let mut raw = vec![0; bytes as usize];
                volume.read_attribute(allocation, page * bytes, &mut raw)?;
                if ntfs_rs::index::IndexBlock::parse(&mut raw, volume.boot.bytes_per_sector, page * bytes / unit)
                    .is_ok()
                {
                    node(&raw, VIEW_BLOCK_NODE_OFFSET, &mut rows);
                }
            }
        }
        Ok(rows)
    }

    pub(crate) fn object_id_repairs(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
        mode: checker::consistency::IndexCheck,
    ) -> io::Result<()> {
        if mode == checker::consistency::IndexCheck::Quick {
            let mut volume = PlannedImage::volume(source, patches, boot)?;
            let zero = checker::consistency::mft_image(&mut volume)?;
            if super::metadata::object_index_intact(&mut volume, &MftRecord::from_decoded(&zero)?)? {
                return Ok(());
            }
        }
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let Some(owner) = extend_metadata_file(&mut volume, &mft, "$ObjId")? else {
            return Ok(());
        };
        let data = mft.stream(ATTR_DATA, &[])?;
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let slots = data.initialized_size()? / u64::from(boot.record_bytes);
        let mut bits = (u64::MAX, [0; BITMAP_CACHE_BYTES]);
        let mut raw = vec![0; boot.record_bytes as usize];
        let mut objects = BTreeMap::<[u32; OBJECT_ID_WORDS], Vec<u8>>::new();
        let mut identities = BTreeMap::new();
        for number in 0..slots {
            if !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
                continue;
            }
            volume.read_mft_record(&mft, number, &mut raw)?;
            let base = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            if base.base_file_reference()? != 0 {
                continue;
            }
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let Some(attr) = record.local_attribute(ATTR_OBJECT_ID, &[])? else {
                continue;
            };
            let value = attr.resident_value()?;
            if value.len() != OBJECT_ID_BYTES || value.iter().all(|&b| b == 0) {
                return Err(reject("object-ID attribute has no trustworthy identity"));
            }
            let key = std::array::from_fn(|i| u32_at(value, i * VIEW_U32_BYTES).unwrap());
            let mut payload = family.reference.to_le_bytes().to_vec();
            payload.resize(OBJECT_PAYLOAD_BYTES, 0);
            let row = view_entry(&value[..OBJECT_ID_BYTES], &payload)?;
            if objects.insert(key, row).is_some() {
                return Err(reject("duplicate object ID; conflicting attributes preserved"));
            }
            identities.insert(family.reference, key);
        }
        let family = RepairFamily::load(&mut volume, &mft, owner)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let name = b"$\0O\0";
        let mut dirty = false;
        let mut seen = BTreeSet::new();
        let mut original_order = Vec::new();
        let mut restore = BTreeMap::new();
        if let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, name)? {
            let mut rows = Vec::new();
            let traversal = visit_view_index(
                &mut volume,
                root.resident_value()?,
                record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, name)?,
                record.local_attribute(ATTR_BITMAP, name)?,
                0,
                COLLATION_U32_SEQUENCE,
                &mut |row| {
                    rows.push(row.to_vec());
                    Ok(())
                },
            );
            if traversal.is_err() {
                // Re-read the allocated nodes independently. Broken child links,
                // node bounds and fixups do not invalidate per-file attributes.
                rows = salvage_object_rows(
                    &mut volume,
                    root.resident_value()?,
                    record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, name)?,
                    record.local_attribute(ATTR_BITMAP, name)?,
                )?;
                dirty = true;
            }
            for row in &rows {
                let mut reconcile = || -> io::Result<()> {
                    if u16_at(row, VIEW_KEY_LENGTH_OFFSET)? != OBJECT_ID_BYTES as u16 {
                        dirty = true;
                        return Ok(());
                    }
                    let key: [u32; OBJECT_ID_WORDS] =
                        std::array::from_fn(|i| u32_at(row, VIEW_HEADER_BYTES + i * VIEW_U32_BYTES).unwrap());
                    let at = u16_at(row, VIEW_DATA_OFFSET)? as usize;
                    let size = u16_at(row, VIEW_DATA_LENGTH_OFFSET)? as usize;
                    if !matches!(size, VIEW_U64_BYTES | OBJECT_PAYLOAD_BYTES) {
                        dirty = true;
                        return Ok(());
                    }
                    if !seen.insert(key) {
                        dirty = true;
                        // A file's primary ID does not establish the independent
                        // birth fields. Only identical rows resolve duplicates.
                        if rows
                            .iter()
                            .filter(|r| {
                                r.get(VIEW_HEADER_BYTES..VIEW_HEADER_BYTES + OBJECT_ID_BYTES)
                                    == row.get(VIEW_HEADER_BYTES..VIEW_HEADER_BYTES + OBJECT_ID_BYTES)
                            })
                            .all(|r| r == row)
                        {
                            return Ok(());
                        }
                        return Err(reject("conflicting object-ID birth evidence"));
                    }
                    original_order.push(key);
                    if let Some(expected) = objects.get_mut(&key) {
                        let expected_at = u16_at(expected, VIEW_DATA_OFFSET)? as usize;
                        if size == OBJECT_PAYLOAD_BYTES {
                            let mut kept = leaf(row)?;
                            if row[at..at + VIEW_U64_BYTES] != expected[expected_at..expected_at + VIEW_U64_BYTES] {
                                kept[at..at + VIEW_U64_BYTES]
                                    .copy_from_slice(&expected[expected_at..expected_at + VIEW_U64_BYTES]);
                                dirty = true;
                            }
                            *expected = kept;
                        } else {
                            dirty = true;
                        }
                    } else {
                        let reference = u64_at(row, at)?;
                        if identities.contains_key(&reference) {
                            return Err(reject("object-ID lookup conflicts with a file's existing identity"));
                        }
                        // Restore only the primary ID in the file. Birth IDs
                        // remain independent fields of the lookup entry.
                        let value = row[VIEW_HEADER_BYTES..VIEW_HEADER_BYTES + OBJECT_ID_BYTES].to_vec();
                        if restore.insert(reference, value).is_some() {
                            return Err(reject(
                                "multiple object IDs claim one file without an authoritative attribute",
                            ));
                        }
                        dirty = true;
                    }
                    Ok(())
                };
                reconcile()?;
            }
        } else {
            dirty = true;
        }
        let mut restores = RepairPlan::new(patches.length)?;
        let mut restore_space = None;
        for (reference, value) in restore {
            let number = ntfs_rs::mft::reference_number(reference);
            let allocated = number < slots && bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)?;
            if allocated {
                volume.read_mft_record(&mft, number, &mut raw)?;
                let file = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
                if file.base_file_reference()? == 0
                    && u64::from(file.sequence_number()?) == u64::from(ntfs_rs::mft::reference_sequence(reference))
                {
                    let target = RepairFamily::load(&mut volume, &mft, number)?;
                    if restore_space.is_none() {
                        restore_space = Some(RepairSpace::new(&mut volume, &mft)?);
                    }
                    let result = target.store(
                        &mut volume,
                        &mft,
                        vec![StreamChange::resident(ATTR_OBJECT_ID, &[], &value)?],
                        restore_space.as_mut().unwrap(),
                        &mut restores,
                    );
                    if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
                        drop(volume);
                        repair_mft_growth(source, boot, patches)?;
                        return object_id_repairs(source, boot, patches, checker::consistency::IndexCheck::Full);
                    }
                    result?;
                }
            }
            // A sequence mismatch or free slot proves the lookup is stale.
        }
        if !restores.is_empty() {
            drop(volume);
            for patch in restores.iter() {
                patches.compose(patch?)?;
            }
            return object_id_repairs(source, boot, patches, checker::consistency::IndexCheck::Full);
        }
        if seen.len() != objects.len() || original_order.windows(2).any(|w| w[0] >= w[1]) {
            dirty = true;
        }
        if !dirty {
            return Ok(());
        }
        let rows: Vec<_> = objects.into_values().collect();
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut extra = RepairPlan::new(patches.length)?;
        let result = family::install_view(
            &mut volume,
            &mft,
            family,
            name,
            COLLATION_U32_SEQUENCE,
            &rows,
            &mut space,
            &mut extra,
        );
        drop(volume);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return object_id_repairs(source, boot, patches, checker::consistency::IndexCheck::Full);
        }
        result?;
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }
}

pub(super) mod metadata {
    use super::CoreIo;
    use super::*;
    use ntfs_rs::mft::attribute_definition as attrdef;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::{
        bytes::u16_at,
        record_edit as e,
        security::{MAX_SID_SUBAUTHORITIES, SID_HEADER_BYTES, SID_SUBAUTHORITY_BYTES},
    };
    use ntfs_rs::{
        filename_metadata as filename,
        mft::{attribute_layout, record_layout},
    };

    const REPARSE_HEADER_BYTES: usize = 8;
    const REPARSE_GUID_HEADER_BYTES: usize = REPARSE_HEADER_BYTES + semantic::OBJECT_ID_BYTES;
    const REPARSE_LENGTH_OFFSET: usize = 4;
    const REPARSE_RESERVED_TAG_MAX: u32 = 1;
    const REPARSE_RESERVED_TAG_BITS: u32 = 0x0fff_0000;
    const REPARSE_MICROSOFT_TAG: u32 = 0x8000_0000;
    const REPARSE_KEY_WORDS: usize = 3;
    const REPARSE_KEY_BYTES: usize = REPARSE_KEY_WORDS * semantic::VIEW_U32_BYTES;
    const DOS_NAME_UNITS: usize = 12;
    const DOS_STEM_UNITS: usize = 8;
    const DOS_EXTENSION_UNITS: usize = 3;
    const ASCII_PRINTABLE_MIN: u16 = b' ' as u16;
    const SI_FLAGS_OFFSET: usize = 32;
    const SI_FLAGS_END: usize = SI_FLAGS_OFFSET + std::mem::size_of::<u32>();
    const SI_SECURITY_ID_OFFSET: usize = 52;
    const SI_TIMES_BYTES: usize = SI_FLAGS_OFFSET;
    const TIME_BYTES: usize = std::mem::size_of::<u64>();
    const RESIDENT_INDEXED_OFFSET: usize = 22;
    const RESIDENT_INDEXED: u8 = 1;
    const RECORD_LINKS_OFFSET: usize = 18;
    const USN_MAX_BYTES: usize = 32;
    const ORPHAN_NAME_UNITS: usize = 240;
    const ORPHAN_ORDINAL_UNITS: usize = 8;
    const ORPHAN_ORDINAL_END: usize = filename::HEADER_BYTES + ORPHAN_ORDINAL_UNITS * filename::CODE_UNIT_BYTES;
    const FALLBACK_DIRECTORY_MIN_UNITS: usize = 11;
    const FALLBACK_DIRECTORY_PREFIX_UNITS: usize = 3;
    const CHK_SUFFIX_UNITS: usize = 4;
    const DECIMAL_RADIX: u32 = 10;
    const HEX_DIGIT_BITS: u32 = 4;
    const DIGIT_ZERO: u16 = b'0' as u16;
    const DIGIT_NINE: u16 = b'9' as u16;
    const HEX_A: u16 = b'A' as u16;
    const HEX_F: u16 = b'F' as u16;
    const RECOVERY_FOLDER_UNITS: usize = 9;
    const RECOVERY_FOLDER_PREFIX_UNITS: usize = 6;
    const RECOVERY_FOLDER_DIGITS: u32 = 3;
    const RECOVERY_FOLDER_COUNT: usize = (DECIMAL_RADIX as usize).pow(RECOVERY_FOLDER_DIGITS);
    const RECOVERY_DIRECTORY_FLAGS: u32 = ntfs_rs::std_info::HIDDEN | ntfs_rs::std_info::SYSTEM;
    const NEW_INDEX_ROOT_ROOM: usize = 128;
    const COLLATION_FILENAME: u32 = 1;
    const SECURITY_DESCRIPTOR_HEADER_BYTES: usize = 20;
    const FIRST_SECURITY_ID: u32 = 256;
    const FIRST_PRUNABLE_SECURITY_ID: u64 = 260;
    const EA_INFORMATION_BYTES: usize = 8;
    const SID_REVISION_OFFSET: usize = 0;
    const SID_COUNT_OFFSET: usize = 1;
    const ALIAS_PAIR_MEMBERS: usize = 2;
    const SDS_HEADER_BYTES: usize = 20;
    const SDS_ALIGNMENT: u64 = 16;
    const SDS_MIRROR_REGION_BYTES: u64 = 0x40000;
    const SDS_PAIR_BYTES: u64 = SDS_MIRROR_REGION_BYTES * 2;
    const SDS_OFFSET_FIELD: usize = 8;
    const MAX_ATTRDEF_STREAM_BYTES: u64 = 16 * 1024 * 1024;
    const ASCII_CODE_UNITS: u16 = 128;
    const ASCII_CASE_DELTA: u16 = b'a' as u16 - b'A' as u16;
    const ASCII_UPCASE_BYTES: u64 = ASCII_CODE_UNITS as u64 * filename::CODE_UNIT_BYTES as u64;
    const UPCASE_CHECKSUM_OFFSET: usize = 8;
    const UPCASE_CHECKSUM_BYTES: usize = std::mem::size_of::<u64>();

    const R: &[u8] = b"$\0R\0";
    const O: &[u8] = b"$\0O\0";
    const UPCASE_INFO: &[u8] = b"$\0I\0n\0f\0o\0";

    fn base_numbers<Rd: ReadAt>(volume: &mut Volume<Rd>, mft: &MftRecord<'_>) -> io::Result<File> {
        let slots = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let mut bits = (u64::MAX, [0; BITMAP_CACHE_BYTES]);
        let mut raw = vec![0; volume.boot.record_bytes as usize];
        let mut rows = checker::consistency::DiskInventory::new();
        for number in 0..slots {
            if !bitmap_bit(volume, bitmap, number, slots, &mut bits)? {
                continue;
            }
            volume.read_mft_record(mft, number, &mut raw)?;
            let record = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
            if record.base_file_reference()? == 0 {
                rows.push([number, 0, 0, 0])?;
            }
        }
        rows.finish()
    }

    fn reparse_tag<Rd: ReadAt>(volume: &mut Volume<Rd>, record: &MftRecord<'_>) -> io::Result<Option<u32>> {
        let Some(attr) = record.local_attribute(ntfs_rs::reparse::ATTR_REPARSE, &[])? else {
            return Ok(None);
        };
        let size = attr.data_size()? as usize;
        if !(REPARSE_HEADER_BYTES..=ntfs_rs::reparse::MAX_CREATE).contains(&size) || attr.flags()? != 0 {
            return Err(reject("invalid reparse attribute size or flags"));
        }
        let mut value = vec![0; size];
        volume.read_attribute(attr, 0, &mut value)?;
        let tag = u32_at(&value, 0)?;
        if tag <= REPARSE_RESERVED_TAG_MAX || tag & REPARSE_RESERVED_TAG_BITS != 0 {
            return Err(reject("reserved reparse tag"));
        }
        let header = if tag & REPARSE_MICROSOFT_TAG == 0 { REPARSE_GUID_HEADER_BYTES } else { REPARSE_HEADER_BYTES };
        if usize::from(u16_at(&value, REPARSE_LENGTH_OFFSET)?) + header != size {
            return Err(reject("reparse payload length disagrees with its tag header"));
        }
        if header == REPARSE_GUID_HEADER_BYTES
            && value[REPARSE_HEADER_BYTES..REPARSE_GUID_HEADER_BYTES].iter().all(|&b| b == 0)
        {
            return Err(reject("third-party reparse GUID is zero"));
        }
        if ntfs_rs::reparse::is_link_tag(tag) {
            ntfs_rs::reparse::target(&value, 0, &mut vec![0; ntfs_rs::reparse::MAX_TARGET])?;
        } else if ntfs_rs::reparse::special_type(tag).is_some() && size != REPARSE_HEADER_BYTES {
            return Err(reject("WSL special-file reparse payload is not empty"));
        }
        Ok(Some(tag))
    }

    fn reparse_key(tag: u32, reference: u64) -> [u32; REPARSE_KEY_WORDS] {
        [tag, reference as u32, (reference >> u32::BITS) as u32]
    }

    fn reparse_rows<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
    ) -> io::Result<BTreeSet<[u32; REPARSE_KEY_WORDS]>> {
        let mut numbers = base_numbers(volume, mft)?;
        let mut wanted = BTreeSet::new();
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            let family = RepairFamily::load(volume, mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            if let Some(tag) = reparse_tag(volume, &record)? {
                wanted.insert(reparse_key(tag, family.reference));
            }
        }
        Ok(wanted)
    }

    fn compare_reparse<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        record: &MftRecord<'_>,
        wanted: &BTreeSet<[u32; REPARSE_KEY_WORDS]>,
    ) -> io::Result<bool> {
        let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, R)? else {
            return Ok(false);
        };
        let mut expected = wanted.iter();
        let mut equal = true;
        visit_view_index(
            volume,
            root.resident_value()?,
            record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, R)?,
            record.local_attribute(ATTR_BITMAP, R)?,
            0,
            semantic::COLLATION_U32_SEQUENCE,
            &mut |row| {
                if u16_at(row, semantic::VIEW_KEY_LENGTH_OFFSET)? != REPARSE_KEY_BYTES as u16
                    || u16_at(row, semantic::VIEW_DATA_LENGTH_OFFSET)? != 0
                {
                    equal = false;
                } else {
                    let key = std::array::from_fn(|i| {
                        u32_at(row, semantic::VIEW_HEADER_BYTES + i * semantic::VIEW_U32_BYTES).unwrap()
                    });
                    if expected.next() != Some(&key) {
                        equal = false;
                    }
                }
                Ok(())
            },
        )?;
        Ok(equal && expected.next().is_none())
    }

    pub(crate) fn reparse_repairs(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let wanted = reparse_rows(&mut volume, &mft)?;
        let Some(owner) = extend_metadata_file(&mut volume, &mft, "$Reparse")? else {
            if wanted.is_empty() {
                return Ok(());
            }
            return Err(reject("reparse points exist but the $Reparse file identity is missing"));
        };
        let family = RepairFamily::load(&mut volume, &mft, owner)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        match compare_reparse(&mut volume, &record, &wanted) {
            Ok(true) => return Ok(()),
            Err(error) if !matches!(error.kind(), io::ErrorKind::InvalidData | io::ErrorKind::Unsupported) => {
                return Err(error)
            }
            _ => {}
        }
        let rows = wanted
            .into_iter()
            .map(|key| {
                let key = key.map(u32::to_le_bytes);
                let mut row = semantic::view_entry(key.as_flattened(), &[])?;
                // Empty reparse rows retain their original zero data-offset field.
                row[..semantic::VIEW_U16_BYTES].fill(0);
                Ok(row)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut extra = RepairPlan::new(patches.length)?;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let result = family::install_view(
            &mut volume,
            &mft,
            family,
            R,
            semantic::COLLATION_U32_SEQUENCE,
            &rows,
            &mut space,
            &mut extra,
        );
        drop(volume);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return reparse_repairs(source, boot, patches);
        }
        result?;
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(())
    }

    // Value framing is independent of name content and namespace presentation.
    // A rejected name cannot authorize a directory link or an index key.
    pub(crate) fn filename_value_valid(value: &[u8]) -> bool {
        filename_value_error(value).is_none()
    }

    // Namespace identity occupies the low two bits. Preserve the raw byte and
    // report the specific rule that prevents this value from identifying a name.
    pub(crate) fn filename_value_error(value: &[u8]) -> Option<&'static str> {
        if ntfs_rs::filename::FileNameValue::parse(value).is_err() {
            return Some("filename length does not match its declared UTF-16 name");
        }
        let name = &value[filename::HEADER_BYTES..];
        if name.is_empty() {
            return Some("filename is empty");
        }
        if name.chunks_exact(filename::CODE_UNIT_BYTES).any(|unit| {
            let character = u16::from_le_bytes([unit[0], unit[1]]);
            character < ASCII_PRINTABLE_MIN
                || character == u16::from(b'/')
                || ntfs_rs::linux_names::WINDOWS_RESERVED_CHARS.map(|c| c as u16).contains(&character)
        }) {
            return Some("filename contains a forbidden character");
        }
        if value[filename::NAMESPACE_OFFSET] & filename::DOS == 0 || name == [b'.', 0] {
            return None;
        }
        let count = name.len() / filename::CODE_UNIT_BYTES;
        if count > DOS_NAME_UNITS {
            return Some("DOS filename exceeds its 8.3 name limits");
        }
        let mut dot = None;
        for (index, unit) in name.chunks_exact(filename::CODE_UNIT_BYTES).enumerate() {
            let character = u16::from_le_bytes([unit[0], unit[1]]);
            if [b'+', b',', b';', b'=', b'[', b']'].map(u16::from).contains(&character) {
                return Some("DOS filename contains a forbidden character");
            }
            if character == u16::from(b'.') && dot.replace(index).is_some() {
                return Some("DOS filename contains multiple extension separators");
            }
        }
        let stem = dot.unwrap_or(count);
        let last = |index: usize| {
            u16::from_le_bytes([name[index * filename::CODE_UNIT_BYTES], name[index * filename::CODE_UNIT_BYTES + 1]])
        };
        if !(1..=DOS_STEM_UNITS).contains(&stem)
            || last(stem - 1) == u16::from(b' ')
            || dot.is_some_and(|index| {
                !(1..=DOS_EXTENSION_UNITS).contains(&(count - index - 1)) || last(count - 1) == u16::from(b' ')
            })
        {
            return Some("DOS filename has an invalid stem or extension");
        }
        None
    }

    // The MFT header counts surviving physical FILE_NAME attributes, including a
    // separate DOS alias. Namespace presentation alone cannot reduce this count.
    fn link_count(record: &MftRecord<'_>) -> io::Result<u16> {
        let mut count = 0_u64;
        for item in record.attributes() {
            let attr = item?;
            if attr.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            let value = attr.resident_value()?;
            if !filename_value_valid(value) {
                return Err(reject("filename framing cannot establish a link count"));
            }
            count += 1;
        }
        u16::try_from(count).map_err(|_| reject("hard-link count exceeds its on-disk field"))
    }

    #[cfg(test)]
    mod filename_metadata_tests {
        include!("../tests/recovery/metadata_filename_metadata_tests.rs");
    }

    fn ea_summary<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        record: &MftRecord<'_>,
    ) -> io::Result<Option<[u8; EA_INFORMATION_BYTES]>> {
        let Some(ea) = record.local_attribute(ntfs_rs::ea::EA, &[])? else {
            return Ok(None);
        };
        let size = ea.data_size()? as usize;
        if size > ntfs_rs::ea::MAX_STREAM {
            return Err(reject("EA stream exceeds NTFS size bound"));
        }
        let mut value = vec![0; size];
        volume.read_attribute(ea, 0, &mut value)?;
        let mut buffer = vec![0; ntfs_rs::ea::MAX_STREAM];
        let mut builder = ntfs_rs::ea::Builder::new(&mut buffer);
        let mut names = BTreeSet::new();
        ntfs_rs::ea::visit(&value, |name, value, flags| {
            if !names.insert(name.to_vec()) {
                return Err(ntfs_rs::Error::InvalidAttribute);
            }
            builder.push(name, value, flags)
        })?;
        if builder.len() != size {
            return Err(reject("EA stream has noncanonical framing"));
        }
        Ok(Some(builder.info()))
    }

    pub(crate) fn file_repairs(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let mut numbers = base_numbers(&mut volume, &mft)?;
        drop(volume);
        let mut space = None;
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            loop {
                let mut volume = PlannedImage::volume(source, patches, boot)?;
                let zero = checker::consistency::mft_image(&mut volume)?;
                let mft = MftRecord::from_decoded(&zero)?;
                let family = RepairFamily::load(&mut volume, &mft, number)?;
                let record = MftRecord::from_decoded(&family.logical)?;
                let links = link_count(&record)?;
                let ea = ea_summary(&mut volume, &record)?;
                let info = record.local_attribute(ntfs_rs::ea::EA_INFO, &[])?;
                let change = match (ea, info) {
                    (Some(expected), Some(old)) if old.resident_value()? == expected => None,
                    (Some(expected), _) => Some(StreamChange::resident(ntfs_rs::ea::EA_INFO, &[], &expected)?),
                    (None, Some(_)) => Some(StreamChange::remove(ntfs_rs::ea::EA_INFO, &[])),
                    _ => None,
                };
                let mut extra = RepairPlan::new(patches.length)?;
                if let Some(change) = change {
                    if space.is_none() {
                        space = Some(RepairSpace::new(&mut volume, &mft)?);
                    }
                    let result = family.store(&mut volume, &mft, vec![change], space.as_mut().unwrap(), &mut extra);
                    drop(volume);
                    if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
                        // Growth changes the MFT mapping. Reopen this family and
                        // discard reservations from the unpublished attempt.
                        space = None;
                        repair_mft_growth(source, boot, patches)?;
                        continue;
                    }
                    result?;
                    for patch in extra.iter() {
                        patches.compose(patch?)?;
                    }
                    // Read the newly published base before editing its header.
                    continue;
                }
                if let Some(si) = record.local_attribute(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[])? {
                    let value = si.resident_value()?;
                    if !matches!(value.len(), semantic::SI_LEGACY_BYTES | semantic::SI_MODERN_BYTES) {
                        return Err(reject("unknown standard-information layout"));
                    }
                    let old_flags = u32_at(&value, SI_FLAGS_OFFSET)?;
                    let flags = (old_flags & !ntfs_rs::std_info::REPARSE_POINT)
                        | if record.local_attribute(ntfs_rs::reparse::ATTR_REPARSE, &[])?.is_some() {
                            ntfs_rs::std_info::REPARSE_POINT
                        } else {
                            0
                        };
                    if flags != old_flags {
                        family.patch_resident_values(
                            &mut volume,
                            &mft,
                            ntfs_rs::mft::ATTR_STANDARD_INFORMATION,
                            &[],
                            &mut |value| {
                                value[SI_FLAGS_OFFSET..SI_FLAGS_END].copy_from_slice(&flags.to_le_bytes());
                                Ok(())
                            },
                            &mut extra,
                        )?;
                        drop(volume);
                        for patch in extra.iter() {
                            patches.compose(patch?)?;
                        }
                        continue;
                    }
                }
                // FILE_NAME caches can lag STANDARD_INFORMATION and DATA until a
                // namespace operation. Preserve them when the name itself is valid;
                // differing cached metadata does not justify rewriting this family.
                // Reserved records have special namespace/reference conventions.
                if number < system_record::RESERVED || u16_at(&family.logical, RECORD_LINKS_OFFSET)? == links {
                    break;
                }
                let mut before = vec![0; boot.record_bytes as usize];
                volume.read_mft_record(&mft, number, &mut before)?;
                let mut after = before.clone();
                MftRecord::parse(&mut after, boot.bytes_per_sector)?;
                e::p16(&mut after, RECORD_LINKS_OFFSET, links)?;
                e::validate(&after)?;
                protect_mft_record(&mut after, boot.bytes_per_sector)?;
                repair_record_patch(&mut volume, mft.stream(ATTR_DATA, &[])?, number, &before, &after, &mut extra)?;
                drop(volume);
                for patch in extra.iter() {
                    patches.compose(patch?)?;
                }
                break;
            }
        }
        Ok(())
    }

    // A framed directory root identifies the ordinary object's type. A damaged
    // present root remains a directory-recovery decision, not evidence of a file.
    pub(crate) fn filename_directory_type(record: &MftRecord<'_>) -> io::Result<Option<bool>> {
        let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, ntfs_rs::index_tree::I30)? else {
            return Ok(Some(false));
        };
        if root.nonresident {
            return Ok(None);
        }
        let value = root.resident_value()?;
        Ok(ntfs_rs::index::IndexRoot::parse(value).ok().map(|_| true))
    }

    // The root has one combined-name claim to itself. This reserved identity is
    // mandatory even when an index with missing or renamed keys is well framed.
    pub(crate) fn root_filename_valid(record: &MftRecord<'_>, reference: u64) -> io::Result<bool> {
        let mut found = false;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            if attribute.nonresident {
                return Ok(false);
            }
            let value = attribute.resident_value()?;
            if found
                || attribute.resident_flags()? & RESIDENT_INDEXED == 0
                || value.len() != filename::HEADER_BYTES + filename::CODE_UNIT_BYTES
                || u64_at(value, filename::PARENT_REFERENCE_OFFSET)? != reference
                || value[filename::NAME_LENGTH_OFFSET] != 1
                || value[filename::NAMESPACE_OFFSET] & filename::WIN32_AND_DOS != filename::WIN32_AND_DOS
                || value[filename::HEADER_BYTES..] != [b'.', 0]
            {
                return Ok(false);
            }
            found = true;
        }
        Ok(found)
    }

    fn system_filename(number: u64) -> Option<&'static str> {
        Some(match number {
            system_record::MFT => "$MFT",
            system_record::MFT_MIRROR => "$MFTMirr",
            system_record::LOG => "$LogFile",
            system_record::VOLUME => "$Volume",
            system_record::ATTRDEF => "$AttrDef",
            system_record::ROOT => ".",
            system_record::BITMAP => "$Bitmap",
            system_record::BOOT => "$Boot",
            system_record::BADCLUS => "$BadClus",
            system_record::SECURE => "$Secure",
            system_record::UPCASE => "$UpCase",
            system_record::EXTEND => "$Extend",
            _ => return None,
        })
    }

    // Conventional system identities require one indexed combined-name claim.
    // Parent validation remains with directory traversal, except the root's self link.
    fn system_filename_valid(record: &MftRecord<'_>, reference: u64) -> io::Result<bool> {
        let number = ntfs_rs::mft::reference_number(reference);
        if number == system_record::ROOT {
            return root_filename_valid(record, reference);
        }
        let name = system_filename(number).ok_or_else(|| reject("unknown system filename"))?;
        let text: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut found = false;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            if attribute.nonresident {
                return Ok(false);
            }
            let value = attribute.resident_value()?;
            if found
                || attribute.resident_flags()? & RESIDENT_INDEXED == 0
                || !filename_value_valid(value)
                || value[filename::NAMESPACE_OFFSET] & filename::WIN32_AND_DOS != filename::WIN32_AND_DOS
                || value[filename::HEADER_BYTES..] != text
            {
                return Ok(false);
            }
            found = true;
        }
        Ok(found)
    }

    // Alias classes belong to the complete ordinary-file family. An inconsistent
    // set retains its paths as POSIX names; one equivalent pair retains Win32 text.
    fn normalize_file_aliases(names: &mut Vec<(Vec<u8>, u8)>, upcase: Option<&[u8]>) -> io::Result<bool> {
        let mut long = None;
        let mut dos = None;
        let mut inconsistent = false;
        for (index, (value, _)) in names.iter().enumerate() {
            if value[filename::NAMESPACE_OFFSET] & filename::WIN32 != 0 && long.replace(index).is_some() {
                inconsistent = true;
            }
            if value[filename::NAMESPACE_OFFSET] & filename::DOS != 0 && dos.replace(index).is_some() {
                inconsistent = true;
            }
        }
        match (long, dos) {
            (None, None) => return Ok(false),
            (Some(long), Some(dos)) => {
                inconsistent |= names[long].0[..filename::DUPLICATED_INFORMATION_OFFSET]
                    != names[dos].0[..filename::DUPLICATED_INFORMATION_OFFSET];
                if !inconsistent && long != dos {
                    let mut long_dos = names[long].0.clone();
                    long_dos[filename::NAMESPACE_OFFSET] |= filename::DOS;
                    if filename_value_valid(&long_dos) {
                        if let Some(table) = upcase {
                            if table.len() != ntfs_rs::upcase::UPCASE_BYTES {
                                return Err(reject("alias comparison requires a complete case table"));
                            }
                            let a = &names[long].0[filename::HEADER_BYTES..];
                            let b = &names[dos].0[filename::HEADER_BYTES..];
                            if ntfs_rs::index_tree::names_equal_ignoring_case(table, a, b) {
                                names[long].0[filename::NAMESPACE_OFFSET] |= filename::DOS;
                                names.remove(dos);
                                return Ok(true);
                            }
                        }
                    }
                }
            }
            _ => inconsistent = true,
        }
        if inconsistent {
            for (value, _) in names {
                value[filename::NAMESPACE_OFFSET] &= !filename::WIN32_AND_DOS;
            }
        }
        Ok(inconsistent)
    }

    // Index comparison observes the effective complete-family alias identities.
    // This projection does not change the stored values or their cached metadata.
    pub(crate) fn filename_alias_projection(
        record: &MftRecord<'_>,
        upcase: Option<&[u8]>,
    ) -> io::Result<Option<Vec<Vec<u8>>>> {
        let mut names = Vec::new();
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            if attribute.nonresident || attribute.resident_flags()? & RESIDENT_INDEXED == 0 {
                continue;
            }
            let value = attribute.resident_value()?;
            if !filename_value_valid(value) {
                continue;
            }
            names.push((value.to_vec(), attribute.resident_flags()?));
        }
        if normalize_file_aliases(&mut names, upcase)? {
            Ok(Some(names.into_iter().map(|(value, _)| value).collect()))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn audit<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
        mode: checker::consistency::IndexCheck,
        upcase: Option<&[u8]>,
        emit: &mut impl FnMut(&'static str, Option<u64>, String),
    ) -> io::Result<()> {
        audit_definitions(volume, mft, emit)?;
        let mut numbers = base_numbers(volume, mft)?;
        let mut objects = BTreeMap::<[u32; semantic::OBJECT_ID_WORDS], (u64, Vec<u8>)>::new();
        let mut reparse = BTreeSet::new();
        let mut charges = BTreeMap::<u32, u64>::new();
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            let family = RepairFamily::load(volume, mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let actual = u16_at(&family.logical, RECORD_LINKS_OFFSET)?;
            if number != system_record::ROOT
                && system_filename(number).is_some()
                && !system_filename_valid(&record, family.reference)?
            {
                emit(
                    "system-filename-invalid",
                    Some(number),
                    "reserved filename differs from its conventional indexed identity".into(),
                );
            }
            match link_count(&record) {
                Ok(wanted) if number >= system_record::RESERVED && wanted != actual => {
                    emit("hardlink-count-invalid", Some(number), format!("stored={actual} expected={wanted}"))
                }
                Err(error) => emit("filename-invalid", Some(number), error.to_string()),
                _ => {}
            }
            let mut filename_keys = BTreeSet::new();
            for attribute in record.attributes() {
                let attribute = attribute?;
                if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME
                    || attribute.nonresident
                    || attribute.resident_flags()? & RESIDENT_INDEXED == 0
                {
                    continue;
                }
                let value = attribute.resident_value()?;
                if !filename_value_valid(value) {
                    continue;
                }
                // Cached metadata and namespace presentation do not distinguish
                // two claims for the same exact parent and spelling.
                let key = (u64_at(value, filename::PARENT_REFERENCE_OFFSET)?, value[filename::HEADER_BYTES..].to_vec());
                if !filename_keys.insert(key) {
                    emit(
                        "filename-duplicate",
                        Some(number),
                        "multiple filename claims have the same parent and exact spelling".into(),
                    );
                }
            }
            if number >= system_record::RESERVED
                && record.flags()? & record_layout::DIRECTORY == 0
                && filename_alias_projection(&record, upcase)?.is_some()
            {
                emit(
                    "filename-alias-invalid",
                    Some(number),
                    "Win32 and DOS claims do not form a consistent distinct alias set".into(),
                );
            }
            match ea_summary(volume, &record) {
                Ok(expected) => {
                    let info = record.local_attribute(ntfs_rs::ea::EA_INFO, &[])?;
                    let equal = match (expected, info) {
                        (None, None) => true,
                        (Some(value), Some(info)) => info.resident_value()? == value,
                        _ => false,
                    };
                    // The assembled image omits ATTRIBUTE_LIST; compare every family.
                    if !equal {
                        emit(
                            "ea-family-summary-invalid",
                            Some(number),
                            "EA_INFORMATION differs from the complete family EA stream".into(),
                        );
                    }
                }
                Err(error) => emit("ea-family-invalid", Some(number), error.to_string()),
            }
            if let Some(si) = record.local_attribute(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[])? {
                let value = si.resident_value()?;
                if value.len() >= SI_FLAGS_END
                    && (u32_at(value, SI_FLAGS_OFFSET)? & ntfs_rs::std_info::REPARSE_POINT != 0)
                        != record.local_attribute(ntfs_rs::reparse::ATTR_REPARSE, &[])?.is_some()
                {
                    emit(
                        "reparse-flag-mismatch",
                        Some(number),
                        "standard information reparse flag differs from attribute presence".into(),
                    );
                }
            }
            // FILE_NAME retains metadata from namespace publication. Ordinary
            // writes may update standard information and DATA without refreshing
            // that cache; the directory index is checked against the live summary.
            match reparse_tag(volume, &record) {
                Ok(Some(tag)) => {
                    reparse.insert(reparse_key(tag, family.reference));
                }
                Ok(None) => {}
                Err(error) => emit("reparse-invalid", Some(number), error.to_string()),
            }
            if let Some(attr) = record.local_attribute(semantic::ATTR_OBJECT_ID, &[])? {
                let value = attr.resident_value()?;
                if value.len() != semantic::OBJECT_ID_BYTES
                    || value[..semantic::OBJECT_ID_BYTES].iter().all(|&b| b == 0)
                {
                    emit("object-id-invalid", Some(number), "object ID has invalid length or zero identity".into());
                } else {
                    let key = std::array::from_fn(|i| u32_at(value, i * semantic::VIEW_U32_BYTES).unwrap());
                    if let Some((previous, _)) = objects.insert(key, (family.reference, value.to_vec())) {
                        emit("object-id-duplicate", Some(number), format!("also claimed by reference {previous:#x}"));
                    }
                }
            }
            if let Some(si) = record.local_attribute(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[])? {
                let value = si.resident_value()?;
                if value.len() == semantic::SI_MODERN_BYTES {
                    let owner = u32_at(value, semantic::SI_OWNER_OFFSET)?;
                    let charge = u64_at(value, semantic::SI_QUOTA_CHARGE_OFFSET)?;
                    if owner != 0 || charge != 0 {
                        if owner < semantic::FIRST_QUOTA_OWNER {
                            emit("quota-file-owner-invalid", Some(number), format!("reserved owner {owner}"));
                        } else {
                            let total = charges.entry(owner).or_default();
                            *total = total.checked_add(charge).ok_or_else(|| reject("quota accounting overflow"))?;
                        }
                    }
                }
            }
        }
        match extend_metadata_file(volume, mft, "$Reparse")? {
            Some(number) => {
                let family = RepairFamily::load(volume, mft, number)?;
                let record = MftRecord::from_decoded(&family.logical)?;
                match compare_reparse(volume, &record, &reparse) {
                    Ok(true) => {}
                    Ok(false) => emit(
                        "reparse-index-mismatch",
                        Some(number),
                        "$R keys differ from valid per-file reparse attributes".into(),
                    ),
                    Err(error) => emit("reparse-index-invalid", Some(number), error.to_string()),
                }
            }
            None if !reparse.is_empty() => emit(
                "reparse-file-missing",
                Some(system_record::EXTEND),
                "reparse points have no $Reparse system index".into(),
            ),
            None => {}
        }
        audit_objects(volume, mft, &objects, mode, emit)?;
        audit_quotas(volume, mft, &charges, emit)?;
        if let Some(number) = extend_metadata_file(volume, mft, "$UsnJrnl")? {
            let family = RepairFamily::load(volume, mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let check = (|| -> io::Result<bool> {
                let max = record.local_attribute(ATTR_DATA, b"$\0M\0a\0x\0")?.ok_or_else(|| reject("missing $Max"))?;
                let j = record.local_attribute(ATTR_DATA, b"$\0J\0")?.ok_or_else(|| reject("missing $J"))?;
                if max.data_size()? != USN_MAX_BYTES as u64
                    || !j.nonresident
                    || j.flags()? & !attribute_layout::SPARSE != 0
                {
                    return Err(reject("invalid USN stream geometry"));
                }
                let mut config = [0; USN_MAX_BYTES];
                volume.read_attribute(max, 0, &mut config)?;
                usn_damaged(volume, j, &config)
            })();
            match check {
                Ok(false) => {}
                Ok(true) => emit(
                    "usn-history-invalid",
                    Some(number),
                    "$Max generation or valid $J suffix requires reset".into(),
                ),
                Err(error) => emit("usn-invalid", Some(number), error.to_string()),
            }
        }
        Ok(())
    }

    fn audit_objects<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
        objects: &BTreeMap<[u32; semantic::OBJECT_ID_WORDS], (u64, Vec<u8>)>,
        mode: checker::consistency::IndexCheck,
        emit: &mut impl FnMut(&'static str, Option<u64>, String),
    ) -> io::Result<()> {
        let Some(number) = extend_metadata_file(volume, mft, "$ObjId")? else {
            if !objects.is_empty() {
                emit(
                    "object-id-file-missing",
                    Some(system_record::EXTEND),
                    "per-file object IDs have no $ObjId lookup".into(),
                );
            }
            return Ok(());
        };
        let family = RepairFamily::load(volume, mft, number)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, O)? else {
            emit("object-id-index-missing", Some(number), "$O root is missing".into());
            return Ok(());
        };
        let mut seen = BTreeSet::new();
        let mut previous = None;
        let result = visit_view_index(
            volume,
            root.resident_value()?,
            record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, O)?,
            record.local_attribute(ATTR_BITMAP, O)?,
            0,
            semantic::COLLATION_U32_SEQUENCE,
            &mut |row| {
                if u16_at(row, semantic::VIEW_KEY_LENGTH_OFFSET)? != semantic::OBJECT_ID_BYTES as u16 {
                    return Err(reject("object lookup key length is invalid"));
                }
                let key: [u32; semantic::OBJECT_ID_WORDS] = std::array::from_fn(|i| {
                    u32_at(row, semantic::VIEW_HEADER_BYTES + i * semantic::VIEW_U32_BYTES).unwrap()
                });
                if previous.is_some_and(|p| p >= key) {
                    emit("object-id-index-order", Some(number), "keys are not strictly ordered".into());
                }
                previous = Some(key);
                if !seen.insert(key) {
                    emit("object-id-index-duplicate", Some(number), "duplicate lookup key".into());
                }
                let at = u16_at(row, semantic::VIEW_DATA_OFFSET)? as usize;
                let size = u16_at(row, semantic::VIEW_DATA_LENGTH_OFFSET)? as usize;
                if !matches!(size, semantic::VIEW_U64_BYTES | semantic::OBJECT_PAYLOAD_BYTES) {
                    return Err(reject("object lookup value has invalid length"));
                }
                if mode == checker::consistency::IndexCheck::Quick {
                    return Ok(());
                }
                if size != semantic::OBJECT_PAYLOAD_BYTES {
                    return Err(reject("object lookup has no complete birth information"));
                }
                match objects.get(&key) {
                    None => {
                        emit("object-id-index-stale", Some(number), "lookup has no matching per-file identity".into())
                    }
                    Some((reference, _)) => {
                        if u64_at(row, at)? != *reference {
                            emit(
                                "object-id-index-mismatch",
                                Some(ntfs_rs::mft::reference_number(*reference)),
                                "lookup reference differs from the per-file object identity".into(),
                            );
                        }
                    }
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            emit("object-id-index-invalid", Some(number), error.to_string());
        }
        for (key, (reference, _)) in objects {
            if mode == checker::consistency::IndexCheck::Full && !seen.contains(key) {
                emit(
                    "object-id-index-missing",
                    Some(ntfs_rs::mft::reference_number(*reference)),
                    "per-file identity is absent from $O".into(),
                );
            }
        }
        Ok(())
    }

    pub(crate) fn object_index_intact<Rd: ReadAt>(volume: &mut Volume<Rd>, mft: &MftRecord<'_>) -> io::Result<bool> {
        let mut intact = true;
        audit_objects(volume, mft, &BTreeMap::new(), checker::consistency::IndexCheck::Quick, &mut |_, _, _| {
            intact = false
        })?;
        Ok(intact)
    }

    const QUOTA_SID_REVISION: u8 = 1;
    const MAX_QUOTA_SID_PADDING: usize = semantic::VIEW_ALIGNMENT - 1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum QuotaSidError {
        Identity,
        Framing,
    }

    /// Auditing and repair use the same SID identity and zero-padding rules.
    /// The borrowed result lets callers allocate only when retaining an owned key.
    pub(crate) fn quota_sid_bytes(value: &[u8], padded: bool) -> std::result::Result<&[u8], QuotaSidError> {
        if value.len() < SID_HEADER_BYTES
            || value[SID_REVISION_OFFSET] != QUOTA_SID_REVISION
            || value[SID_COUNT_OFFSET] > MAX_SID_SUBAUTHORITIES
        {
            return Err(QuotaSidError::Identity);
        }
        let length = SID_HEADER_BYTES + usize::from(value[SID_COUNT_OFFSET]) * SID_SUBAUTHORITY_BYTES;
        if length > value.len()
            || (!padded && length != value.len())
            || value.len() - length > MAX_QUOTA_SID_PADDING
            || value[length..].iter().any(|&byte| byte != 0)
        {
            return Err(QuotaSidError::Framing);
        }
        Ok(&value[..length])
    }

    pub(super) fn quota_sid(value: &[u8], padded: bool) -> io::Result<&[u8]> {
        quota_sid_bytes(value, padded).map_err(|error| {
            reject(match error {
                QuotaSidError::Identity => "invalid quota SID",
                QuotaSidError::Framing => "invalid quota SID length or padding",
            })
        })
    }

    #[cfg(test)]
    mod quota_sid_tests {
        include!("../tests/recovery/metadata_quota_sid_tests.rs");
    }

    fn audit_quotas<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
        charges: &BTreeMap<u32, u64>,
        emit: &mut impl FnMut(&'static str, Option<u64>, String),
    ) -> io::Result<()> {
        let Some(number) = extend_metadata_file(volume, mft, "$Quota")? else {
            if !charges.is_empty() {
                emit(
                    "quota-file-missing",
                    Some(system_record::EXTEND),
                    "per-file charges have no $Quota controls".into(),
                );
            }
            return Ok(());
        };
        let family = RepairFamily::load(volume, mft, number)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let q = b"$\0Q\0";
        let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, q)? else {
            emit("quota-controls-missing", Some(number), "$Q root is missing".into());
            return Ok(());
        };
        let mut owners = BTreeMap::new();
        let mut ids = BTreeSet::new();
        let mut previous = None;
        let result = visit_view_index(
            volume,
            root.resident_value()?,
            record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, q)?,
            record.local_attribute(ATTR_BITMAP, q)?,
            0,
            semantic::COLLATION_QUOTA_ID,
            &mut |row| {
                if u16_at(row, semantic::VIEW_KEY_LENGTH_OFFSET)? != semantic::VIEW_U32_BYTES as u16 {
                    return Err(reject("quota owner key is not a ULONG"));
                }
                let id = u32_at(row, semantic::VIEW_HEADER_BYTES)?;
                if previous.is_some_and(|p| p >= id) {
                    emit("quota-control-order", Some(number), "owner IDs are not strictly ordered".into());
                }
                previous = Some(id);
                if !ids.insert(id) {
                    emit("quota-control-duplicate", Some(number), format!("owner={id}"));
                }
                let at = u16_at(row, semantic::VIEW_DATA_OFFSET)? as usize;
                let size = u16_at(row, semantic::VIEW_DATA_LENGTH_OFFSET)? as usize;
                if size < semantic::QUOTA_CONTROL_BYTES || u32_at(row, at)? != semantic::QUOTA_CONTROL_REVISION {
                    return Err(reject("quota control layout is invalid"));
                }
                if id == semantic::QUOTA_DEFAULT_ID {
                    if size != semantic::QUOTA_CONTROL_BYTES {
                        return Err(reject("quota defaults contain unexpected data"));
                    }
                } else {
                    if id < semantic::FIRST_QUOTA_OWNER {
                        return Err(reject("quota owner ID is reserved"));
                    }
                    let sid = quota_sid(&row[at + semantic::QUOTA_CONTROL_BYTES..at + size], true)?.to_vec();
                    if owners.insert(sid, id).is_some() {
                        emit("quota-sid-duplicate", Some(number), "SID has competing owner controls".into());
                    }
                    let expected = charges.get(&id).copied().unwrap_or(0);
                    if u64_at(row, at + semantic::QUOTA_CHARGE_OFFSET)? != expected {
                        emit("quota-usage-mismatch", Some(number), format!("owner={id} expected={expected}"));
                    }
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            emit("quota-controls-invalid", Some(number), error.to_string());
            return Ok(());
        }
        if !ids.contains(&semantic::QUOTA_DEFAULT_ID) {
            emit("quota-defaults-missing", Some(number), "$Q has no default policy control".into());
        }
        for id in charges.keys() {
            if !ids.contains(id) {
                emit("quota-owner-missing", Some(number), format!("charged owner={id} has no control"));
            }
        }
        let Some(root) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, O)? else {
            emit("quota-lookup-missing", Some(number), "$O root is missing".into());
            return Ok(());
        };
        let mut seen = BTreeSet::new();
        let mut previous = None;
        let result = visit_view_index(
            volume,
            root.resident_value()?,
            record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, O)?,
            record.local_attribute(ATTR_BITMAP, O)?,
            0,
            semantic::COLLATION_SID,
            &mut |row| {
                let size = u16_at(row, semantic::VIEW_KEY_LENGTH_OFFSET)? as usize;
                let sid =
                    quota_sid(&row[semantic::VIEW_HEADER_BYTES..semantic::VIEW_HEADER_BYTES + size], false)?.to_vec();
                if previous.as_ref().is_some_and(|p| p >= &sid) {
                    emit("quota-lookup-order", Some(number), "SID keys are not strictly ordered".into());
                }
                previous = Some(sid.clone());
                if !seen.insert(sid.clone()) {
                    emit("quota-lookup-duplicate", Some(number), "duplicate SID lookup".into());
                }
                let at = u16_at(row, semantic::VIEW_DATA_OFFSET)? as usize;
                if u16_at(row, semantic::VIEW_DATA_LENGTH_OFFSET)? != semantic::VIEW_U32_BYTES as u16
                    || owners.get(&sid).copied() != Some(u32_at(row, at)?)
                {
                    emit("quota-lookup-mismatch", Some(number), "SID lookup disagrees with owner controls".into());
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            emit("quota-lookup-invalid", Some(number), error.to_string());
        }
        if owners.keys().any(|sid| !seen.contains(sid)) {
            emit("quota-lookup-missing", Some(number), "owner controls are missing from SID lookup".into());
        }
        Ok(())
    }

    fn recovery_filename<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        record: &MftRecord<'_>,
        parent: u64,
        name: &str,
    ) -> io::Result<Vec<u8>> {
        let text: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if text.len() > filename::MAX_NAME_BYTES {
            return Err(reject("recovery filename is too long"));
        }
        let mut value = vec![0; filename::HEADER_BYTES + text.len()];
        value[..filename::DUPLICATED_INFORMATION_OFFSET].copy_from_slice(&parent.to_le_bytes());
        value[filename::DUPLICATED_INFORMATION_OFFSET..filename::NAME_LENGTH_OFFSET]
            .copy_from_slice(&ntfs_rs::filename_metadata::duplicated_information(volume, record)?);
        value[filename::NAME_LENGTH_OFFSET] = (text.len() / filename::CODE_UNIT_BYTES) as u8;
        value[filename::NAMESPACE_OFFSET] = filename::WIN32;
        value[filename::HEADER_BYTES..].copy_from_slice(&text);
        Ok(value)
    }

    // Recovery ordinals occupy eight reversed hexadecimal digits. Keep names within
    // 240 UTF-16 units and retain a suffix when shortening would cut an extension.
    pub(crate) fn orphan_filename<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        record: &MftRecord<'_>,
        parent: u64,
        ordinal: u32,
        preferred: Option<&[u8]>,
    ) -> io::Result<Vec<u8>> {
        let prefix: String = format!("{ordinal:0width$X}", width = ORPHAN_ORDINAL_UNITS).chars().rev().collect();
        let mut text: Vec<u16> = prefix.encode_utf16().collect();
        if let Some(preferred) = preferred {
            if preferred.is_empty()
                || preferred.len() % filename::CODE_UNIT_BYTES != 0
                || preferred.len() > filename::MAX_NAME_BYTES
            {
                return Err(reject("invalid preferred recovery name"));
            }
            text.push(u16::from(b'-'));
            let name: Vec<u16> = ntfs_rs::bytes::units(preferred).collect();
            let available = ORPHAN_NAME_UNITS - text.len();
            if name.len() > available {
                let excess = name.len() - available;
                if let Some(dot) = (excess + 1..name.len()).find(|&at| name[at] == u16::from(b'.')) {
                    text.extend_from_slice(&name[..dot - excess]);
                    text.extend_from_slice(&name[dot..]);
                } else {
                    text.extend_from_slice(&name[..available]);
                }
            } else {
                text.extend_from_slice(&name);
            }
        } else {
            let suffix = if record.flags()? & record_layout::DIRECTORY != 0 { "_dir.chk" } else { "file.chk" };
            text.extend(suffix.encode_utf16());
        }
        let mut value = vec![0; filename::HEADER_BYTES];
        value[..filename::DUPLICATED_INFORMATION_OFFSET].copy_from_slice(&parent.to_le_bytes());
        value[filename::DUPLICATED_INFORMATION_OFFSET..filename::NAME_LENGTH_OFFSET]
            .copy_from_slice(&ntfs_rs::filename_metadata::duplicated_information(volume, record)?);
        value[filename::NAME_LENGTH_OFFSET] = text.len() as u8;
        value[filename::NAMESPACE_OFFSET] = filename::POSIX;
        value.extend(text.into_iter().flat_map(u16::to_le_bytes));
        Ok(value)
    }

    // Earlier recovered objects may already occupy ordinals in the plan's folder.
    // File names and fallback directory names use independent counters.
    pub(crate) fn next_recovery_ordinal<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
        parent: u64,
        directory_fallback: bool,
    ) -> io::Result<u32> {
        let mut numbers = base_numbers(volume, mft)?;
        let mut next = 0u32;
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            let family = RepairFamily::load(volume, mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            for attribute in record.attributes() {
                let attribute = attribute?;
                if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME || attribute.nonresident {
                    continue;
                }
                let value = attribute.resident_value()?;
                if value.len() < filename::HEADER_BYTES || u64_at(value, filename::PARENT_REFERENCE_OFFSET)? != parent {
                    continue;
                }
                if directory_fallback {
                    let text: Vec<_> = ntfs_rs::bytes::units(&value[filename::HEADER_BYTES..]).collect();
                    if text.len() >= FALLBACK_DIRECTORY_MIN_UNITS
                        && text[..FALLBACK_DIRECTORY_PREFIX_UNITS] == [b'd', b'i', b'r'].map(u16::from)
                        && text[text.len() - CHK_SUFFIX_UNITS..] == [b'.', b'c', b'h', b'k'].map(u16::from)
                        && text[FALLBACK_DIRECTORY_PREFIX_UNITS..text.len() - CHK_SUFFIX_UNITS]
                            .iter()
                            .all(|unit| (DIGIT_ZERO..=DIGIT_NINE).contains(unit))
                    {
                        let mut ordinal = 0u32;
                        for digit in &text[FALLBACK_DIRECTORY_PREFIX_UNITS..text.len() - CHK_SUFFIX_UNITS] {
                            ordinal = ordinal
                                .checked_mul(DECIMAL_RADIX)
                                .and_then(|value| value.checked_add(u32::from(*digit - DIGIT_ZERO)))
                                .ok_or_else(|| reject("recovery directory ordinal exhausted"))?;
                        }
                        next = next
                            .max(ordinal.checked_add(1).ok_or_else(|| reject("recovery directory ordinal exhausted"))?);
                        continue;
                    }
                }
                if value.len() < ORPHAN_ORDINAL_END {
                    continue;
                }
                let mut ordinal = 0u32;
                let mut valid = true;
                for unit in
                    value[filename::HEADER_BYTES..ORPHAN_ORDINAL_END].chunks_exact(filename::CODE_UNIT_BYTES).rev()
                {
                    let unit = u16::from_le_bytes([unit[0], unit[1]]);
                    let digit = match unit {
                        DIGIT_ZERO..=DIGIT_NINE => u32::from(unit - DIGIT_ZERO),
                        HEX_A..=HEX_F => u32::from(unit - HEX_A) + DECIMAL_RADIX,
                        _ => {
                            valid = false;
                            break;
                        }
                    };
                    ordinal = (ordinal << HEX_DIGIT_BITS) | digit;
                }
                let suffix: Vec<_> = ntfs_rs::bytes::units(&value[ORPHAN_ORDINAL_END..]).collect();
                let directory = suffix == "_dir.chk".encode_utf16().collect::<Vec<_>>();
                if valid && directory == directory_fallback {
                    next =
                        next.max(ordinal.checked_add(1).ok_or_else(|| reject("recovery filename ordinal exhausted"))?);
                }
            }
        }
        Ok(next)
    }

    fn unique_filename_changes<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
        reference: u64,
        directory: bool,
        upcase: &[u8],
    ) -> io::Result<Option<Vec<StreamChange>>> {
        let mut resident = Vec::new();
        let mut changed = false;
        for (member, (_, image)) in repair_members(volume, mft, reference)? {
            for attribute in MftRecord::from_decoded(&image)?.attributes() {
                let attribute = attribute?;
                if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                    continue;
                }
                if attribute.nonresident {
                    changed = true;
                    continue;
                }
                let value = attribute.resident_value()?;
                if !filename_value_valid(value) {
                    // The attribute frame is intact, but its name cannot identify
                    // a link. Retain other streams and any valid sibling names.
                    changed = true;
                    continue;
                }
                if image[attribute.record_offset() + RESIDENT_INDEXED_OFFSET] & 1 == 0 {
                    changed = true;
                    continue;
                }
                resident.push((value.to_vec(), attribute.resident_flags()?, member == reference));
            }
        }
        // Link identity excludes cached metadata and namespace bits. Base claims
        // remain distinct from continuation claims; separate continuations share
        // one placement class. Exact spelling is retained at this structural stage.
        resident.sort_by(|a, b| {
            a.2.cmp(&b.2)
                .then_with(|| {
                    a.0[..filename::DUPLICATED_INFORMATION_OFFSET].cmp(&b.0[..filename::DUPLICATED_INFORMATION_OFFSET])
                })
                .then_with(|| a.0[filename::HEADER_BYTES..].cmp(&b.0[filename::HEADER_BYTES..]))
        });
        let mut names = Vec::new();
        let mut start = 0;
        while start < resident.len() {
            let mut end = start + 1;
            while end < resident.len()
                && resident[end].2 == resident[start].2
                && resident[end].0[..filename::DUPLICATED_INFORMATION_OFFSET]
                    == resident[start].0[..filename::DUPLICATED_INFORMATION_OFFSET]
                && resident[end].0[filename::HEADER_BYTES..] == resident[start].0[filename::HEADER_BYTES..]
            {
                end += 1;
            }
            changed |= end - start > 1;
            if (end - start) % ALIAS_PAIR_MEMBERS != 0 {
                let (value, flags, _) = &resident[end - 1];
                names.push((value.clone(), *flags));
            }
            start = end;
        }
        let mut keys = BTreeMap::<(u64, Vec<u8>), (Vec<u8>, u8)>::new();
        for (value, resident_flags) in names {
            let key = (u64_at(&value, filename::PARENT_REFERENCE_OFFSET)?, value[filename::HEADER_BYTES..].to_vec());
            if let Some((previous, _)) = keys.get_mut(&key) {
                changed = true;
                // Separate Win32 and DOS claims cannot serve as one another's
                // aliases at the same exact key. An existing combined claim can.
                previous[filename::NAMESPACE_OFFSET] = match (
                    previous[filename::NAMESPACE_OFFSET] & filename::WIN32_AND_DOS,
                    value[filename::NAMESPACE_OFFSET] & filename::WIN32_AND_DOS,
                ) {
                    (filename::WIN32, filename::DOS) | (filename::DOS, filename::WIN32) => {
                        (previous[filename::NAMESPACE_OFFSET] | value[filename::NAMESPACE_OFFSET])
                            & !filename::WIN32_AND_DOS
                    }
                    _ => previous[filename::NAMESPACE_OFFSET] | value[filename::NAMESPACE_OFFSET],
                };
            } else {
                keys.insert(key, (value, resident_flags));
            }
        }
        let mut names: Vec<_> = keys.into_values().collect();
        if !directory {
            changed |= normalize_file_aliases(&mut names, Some(upcase))?;
        }
        let mut changes = Vec::new();
        for (value, resident_flags) in names {
            let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
            change.attribute.as_mut().unwrap()[RESIDENT_INDEXED_OFFSET] = resident_flags;
            changes.push(change);
        }
        if changes.is_empty() {
            changes.push(StreamChange::remove(ntfs_rs::mft::ATTR_FILE_NAME, &[]));
        } else if directory && (changed || changes.len() == 1) {
            // Multi-claim directory repair still needs the original alias namespace
            // to prove which old index links survive. Normalize an unchanged family
            // here only when its sole claim cannot have an alias partner.
            changed |= super::normalize_surviving_aliases(&mut changes)?;
        }
        Ok(changed.then_some(changes))
    }

    /// Restore names only for intact allocated base objects. Lost attribute
    /// contents and ambiguous extension ownership never become empty placeholders.
    pub(crate) fn namespace_repairs(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
        changed: &mut File,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let table = checked_family_image(&mut volume, &mft, system_record::UPCASE)?;
        let table = MftRecord::from_decoded(&table)?;
        let mut upcase = vec![0; ntfs_rs::upcase::UPCASE_BYTES];
        volume.read_attribute(table.stream(ATTR_DATA, &[])?, 0, &mut upcase)?;
        ntfs_rs::upcase::validate_mapping(&upcase)?;
        let mut numbers = base_numbers(&mut volume, &mft)?;
        drop(volume);
        let mut space = None;
        let mut recovery_parent = None;
        let mut file_ordinal = 0u32;
        let mut directory_ordinal = 0u32;
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            if number < system_record::RESERVED && system_filename(number).is_none() {
                continue;
            }
            loop {
                let mut volume = PlannedImage::volume(source, patches, boot)?;
                let zero = checker::consistency::mft_image(&mut volume)?;
                let mft = MftRecord::from_decoded(&zero)?;
                let family = RepairFamily::load(&mut volume, &mft, number)?;
                let reference = family.reference;
                let record = MftRecord::from_decoded(&family.logical)?;
                if let Some(name) = system_filename(number) {
                    if !system_filename_valid(&record, family.reference)? {
                        let parent = if number == system_record::ROOT {
                            reference
                        } else {
                            RepairFamily::load(&mut volume, &mft, system_record::ROOT)?.reference
                        };
                        drop(volume);
                        super::repair_system_filename(source, boot, patches, reference, name, parent)?;
                        checker::consistency::audit_slot(changed, number, Some(Some(reference)))?;
                        space = None;
                        continue;
                    }
                    break;
                }
                if let Some(directory) = filename_directory_type(&record)? {
                    let old = record.flags()?;
                    let flags =
                        (old & !record_layout::DIRECTORY) | if directory { record_layout::DIRECTORY } else { 0 };
                    if flags != old {
                        let mut before = vec![0; boot.record_bytes as usize];
                        volume.read_mft_record(&mft, number, &mut before)?;
                        let mut after = before.clone();
                        MftRecord::parse(&mut after, boot.bytes_per_sector)?;
                        e::p16(&mut after, record_layout::FLAGS_OFFSET, flags)?;
                        e::validate(&after)?;
                        protect_mft_record(&mut after, boot.bytes_per_sector)?;
                        let mut extra = RepairPlan::new(patches.length)?;
                        repair_record_patch(
                            &mut volume,
                            mft.stream(ATTR_DATA, &[])?,
                            number,
                            &before,
                            &after,
                            &mut extra,
                        )?;
                        drop(volume);
                        for patch in extra.iter() {
                            patches.compose(patch?)?;
                        }
                        checker::consistency::audit_slot(changed, number, Some(Some(reference)))?;
                        continue;
                    }
                }
                if let Some(changes) = unique_filename_changes(
                    &mut volume,
                    &mft,
                    family.reference,
                    record.flags()? & record_layout::DIRECTORY != 0,
                    &upcase,
                )? {
                    let mut extra = RepairPlan::new(patches.length)?;
                    if space.is_none() {
                        space = Some(RepairSpace::new(&mut volume, &mft)?);
                    }
                    let result = family.store(&mut volume, &mft, changes, space.as_mut().unwrap(), &mut extra);
                    drop(volume);
                    if result.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::OutOfMemory) {
                        space = None;
                        repair_mft_growth(source, boot, patches)?;
                        continue;
                    }
                    result?;
                    for patch in extra.iter() {
                        patches.compose(patch?)?;
                    }
                    checker::consistency::audit_slot(changed, number, Some(Some(reference)))?;
                    continue;
                }
                if record.attributes().any(|a| a.is_ok_and(|a| a.kind == ntfs_rs::mft::ATTR_FILE_NAME)) {
                    break;
                }
                let Some(parent) = recovery_parent else {
                    // Allocating the folder can grow the MFT and consume free slots.
                    // Reload the family and allocation state before publishing names.
                    drop(volume);
                    let parent = recovery_directory(source, boot, patches)
                        .map_err(|error| io::Error::new(error.kind(), format!("recovery directory: {error}")))?;
                    checker::consistency::audit_slot(
                        changed,
                        ntfs_rs::mft::reference_number(parent),
                        Some(Some(parent)),
                    )?;
                    recovery_parent = Some(parent);
                    space = None;
                    continue;
                };
                let directory = record.flags()? & record_layout::DIRECTORY != 0;
                let ordinal = if directory { directory_ordinal } else { file_ordinal };
                let value = orphan_filename(&mut volume, &record, parent, ordinal, None)?;
                let mut attribute = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
                attribute.attribute.as_mut().unwrap()[RESIDENT_INDEXED_OFFSET] = RESIDENT_INDEXED;
                let mut extra = RepairPlan::new(patches.length)?;
                if space.is_none() {
                    space = Some(RepairSpace::new(&mut volume, &mft)?);
                }
                let result = family.store(&mut volume, &mft, vec![attribute], space.as_mut().unwrap(), &mut extra);
                drop(volume);
                if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
                    space = None;
                    repair_mft_growth(source, boot, patches)?;
                    continue;
                }
                result?;
                for patch in extra.iter() {
                    patches.compose(patch?)?;
                }
                checker::consistency::audit_slot(changed, number, Some(Some(reference)))?;
                let counter = if directory { &mut directory_ordinal } else { &mut file_ordinal };
                *counter += 1;
                break;
            }
        }
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        // Only derived system files are recreated. Quota policies and journal
        // histories cannot be manufactured from unrelated files.
        let mut needs_object = false;
        let mut needs_reparse = false;
        numbers.seek(SeekFrom::Start(0))?;
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            needs_object |= record.local_attribute(semantic::ATTR_OBJECT_ID, &[])?.is_some();
            needs_reparse |= record.local_attribute(ntfs_rs::reparse::ATTR_REPARSE, &[])?.is_some();
        }
        for (needed, name, index) in [(needs_object, "$ObjId", O), (needs_reparse, "$Reparse", R)] {
            if needed && extend_metadata_file(&mut volume, &mft, name)?.is_none() {
                drop(volume);
                create_indexed_file(source, boot, patches, name, index, None)?;
                return namespace_repairs(source, boot, patches, changed);
            }
        }
        Ok(())
    }

    // New indexed objects inherit their explicit parent's security identity.
    // Reuse the repair allocator so bitmap and record edits stay ordered.
    fn create_indexed_file(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
        name: &str,
        index: &[u8],
        directory: Option<(u64, u32)>,
    ) -> io::Result<u64> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let parent = RepairFamily::load(
            &mut volume,
            &mft,
            directory.map_or(system_record::EXTEND, |(reference, _)| ntfs_rs::mft::reference_number(reference)),
        )?;
        if directory.is_some_and(|(reference, _)| parent.reference != reference) {
            return Err(reject("recovery directory parent identity changed"));
        }
        let record = MftRecord::from_decoded(&parent.logical)?;
        let mut si = record
            .local_attribute(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[])?
            .ok_or_else(|| reject("metadata parent has no security identity"))?
            .resident_value()?
            .to_vec();
        if !matches!(si.len(), semantic::SI_LEGACY_BYTES | semantic::SI_MODERN_BYTES) {
            return Err(reject("unknown parent standard-information layout"));
        }
        let flags = if let Some((_, flags)) = directory {
            flags
        } else {
            (u32_at(&si, SI_FLAGS_OFFSET)?
                & !(ntfs_rs::std_info::DIRECTORY
                    | ntfs_rs::std_info::SPARSE
                    | ntfs_rs::std_info::REPARSE_POINT
                    | ntfs_rs::std_info::COMPRESSED
                    | ntfs_rs::std_info::ENCRYPTED))
                | RECOVERY_DIRECTORY_FLAGS
        };
        // Capture one creation time for the fresh recovery folder. Its group
        // directories inherit that batch time; existing objects keep their times.
        if directory.is_some_and(|(_, flags)| flags == RECOVERY_DIRECTORY_FLAGS) {
            let created = patches.recovery_created;
            for time in si[..SI_TIMES_BYTES].chunks_exact_mut(TIME_BYTES) {
                time.copy_from_slice(&created.to_le_bytes());
            }
        }
        si[SI_FLAGS_OFFSET..SI_FLAGS_END].copy_from_slice(&flags.to_le_bytes());
        // New system metadata has no inherited quota charge or USN history.
        if si.len() == semantic::SI_MODERN_BYTES {
            si[semantic::SI_OWNER_OFFSET..SI_SECURITY_ID_OFFSET].fill(0);
            si[semantic::SI_QUOTA_CHARGE_OFFSET..semantic::SI_MODERN_BYTES].fill(0);
        }
        let descriptor = if let Some(attribute) = record.local_attribute(ntfs_rs::mft::ATTR_SECURITY_DESCRIPTOR, &[])? {
            let size = attribute.data_size()? as usize;
            if !(SECURITY_DESCRIPTOR_HEADER_BYTES..=ntfs_rs::security::MAX_STORED_DESCRIPTOR).contains(&size) {
                return Err(reject("parent security descriptor size is unsupported"));
            }
            let mut bytes = vec![0; size];
            volume.read_attribute(attribute, 0, &mut bytes)?;
            ntfs_rs::security::validate_storable(&bytes)?;
            Some((bytes, attribute.nonresident))
        } else {
            None
        };
        if descriptor.is_none()
            && (si.len() != semantic::SI_MODERN_BYTES || u32_at(&si, SI_SECURITY_ID_OFFSET)? < FIRST_SECURITY_ID)
        {
            return Err(reject("parent has no validated descriptor identity for new metadata"));
        }
        let mut extra = RepairPlan::new(patches.length)?;
        let mut cursor = ntfs_rs::mft_growth::FIRST_USER_RECORD;
        let allocation = repair_new_extension(&mut volume, &mft, 0, &mut cursor, &mut extra, u64::MAX);
        let (reference, (before, mut after)) = match allocation {
            Ok(pair) => pair,
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                drop(volume);
                repair_mft_growth(source, boot, patches)?;
                return create_indexed_file(source, boot, patches, name, index, directory);
            }
            Err(error) => return Err(error),
        };
        let mut attrs = vec![StreamChange::resident(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[], &si)?];
        if let Some((bytes, nonresident)) = descriptor {
            if nonresident {
                // A copied descriptor owns fresh storage; sharing its parent's
                // extents would create a metadata cross-link.
                let mut space = RepairSpace::new(&mut volume, &mft)?;
                let attribute = space.stream(
                    &mut volume,
                    ntfs_rs::mft::ATTR_SECURITY_DESCRIPTOR,
                    &[],
                    &mut bytes.as_slice(),
                    bytes.len() as u64,
                    &mut extra,
                )?;
                e::insert(&mut after, &attribute)?;
            } else {
                attrs.push(StreamChange::resident(ntfs_rs::mft::ATTR_SECURITY_DESCRIPTOR, &[], &bytes)?);
            }
        }
        for attr in attrs {
            e::insert(&mut after, &attr.attribute.unwrap())?;
        }
        if directory.is_some() {
            e::p16(&mut after, record_layout::FLAGS_OFFSET, record_layout::IN_USE | record_layout::DIRECTORY)?;
        }
        let mut filename = recovery_filename(&mut volume, &MftRecord::from_decoded(&after)?, parent.reference, name)?;
        if directory.is_some() {
            filename[filename::NAMESPACE_OFFSET] = filename::WIN32_AND_DOS;
        }
        let mut attr = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &filename)?.attribute.unwrap();
        attr[RESIDENT_INDEXED_OFFSET] = RESIDENT_INDEXED;
        e::insert(&mut after, &attr)?;
        let (root, _, _) = rebuilt_index(
            boot,
            checker::consistency::scratch_file()?,
            0,
            0,
            NEW_INDEX_ROOT_ROOM,
            if directory.is_some() { ntfs_rs::mft::ATTR_FILE_NAME } else { 0 },
            if directory.is_some() { COLLATION_FILENAME } else { semantic::COLLATION_U32_SEQUENCE },
        )?;
        e::insert(
            &mut after,
            &StreamChange::resident(ntfs_rs::mft::ATTR_INDEX_ROOT, index, &root)?.attribute.unwrap(),
        )?;
        e::p16(&mut after, RECORD_LINKS_OFFSET, 1)?;
        e::p64(&mut after, record_layout::BASE_REFERENCE_OFFSET, 0)?;
        e::validate(&after)?;
        protect_mft_record(&mut after, boot.bytes_per_sector)?;
        repair_record_patch(
            &mut volume,
            mft.stream(ATTR_DATA, &[])?,
            ntfs_rs::mft::reference_number(reference),
            &before,
            &after,
            &mut extra,
        )?;
        drop(volume);
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        Ok(reference)
    }

    fn recovery_folder_ordinal(text: &[u8], upcase: &[u8]) -> io::Result<Option<usize>> {
        if text.len() != RECOVERY_FOLDER_UNITS * filename::CODE_UNIT_BYTES {
            return Ok(None);
        }
        let mut folded = [0; RECOVERY_FOLDER_UNITS];
        for (index, unit) in text.chunks_exact(filename::CODE_UNIT_BYTES).enumerate() {
            let unit = u16::from_le_bytes([unit[0], unit[1]]);
            folded[index] = u16_at(upcase, usize::from(unit) * filename::CODE_UNIT_BYTES)?;
        }
        if folded[..RECOVERY_FOLDER_PREFIX_UNITS] != [b'F', b'O', b'U', b'N', b'D', b'.'].map(u16::from)
            || folded[RECOVERY_FOLDER_PREFIX_UNITS..].iter().any(|unit| !(DIGIT_ZERO..=DIGIT_NINE).contains(unit))
        {
            return Ok(None);
        }
        Ok(Some(
            usize::from(folded[RECOVERY_FOLDER_PREFIX_UNITS] - DIGIT_ZERO) * (DECIMAL_RADIX as usize).pow(2)
                + usize::from(folded[RECOVERY_FOLDER_PREFIX_UNITS + 1] - DIGIT_ZERO) * DECIMAL_RADIX as usize
                + usize::from(folded[RECOVERY_FOLDER_PREFIX_UNITS + 2] - DIGIT_ZERO),
        ))
    }

    // Existing found folders reserve their names. Only a folder allocated by this
    // plan may receive additional recovered objects during the same repair.
    pub(crate) fn recovery_directory(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<u64> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let root = RepairFamily::load(&mut volume, &mft, system_record::ROOT)?.reference;
        let table = checked_family_image(&mut volume, &mft, system_record::UPCASE)?;
        let table = MftRecord::from_decoded(&table)?;
        let mut upcase = vec![0; ntfs_rs::upcase::UPCASE_BYTES];
        volume.read_attribute(table.stream(ATTR_DATA, &[])?, 0, &mut upcase)?;
        let mut occupied = [false; RECOVERY_FOLDER_COUNT];
        let mut numbers = base_numbers(&mut volume, &mft)?;
        let mut original = Volume::new(Image(File::open(source)?), boot)?;
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            for attribute in record.attributes() {
                let attribute = attribute?;
                if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME || attribute.nonresident {
                    continue;
                }
                let value = attribute.resident_value()?;
                if value.len() < filename::HEADER_BYTES || u64_at(value, filename::PARENT_REFERENCE_OFFSET)? != root {
                    continue;
                }
                let Some(ordinal) = recovery_folder_ordinal(&value[filename::HEADER_BYTES..], &upcase)? else {
                    continue;
                };
                occupied[ordinal] = true;
                if record.flags()? & record_layout::DIRECTORY == 0 {
                    continue;
                }
                let mut before = vec![0; boot.record_bytes as usize];
                original.read_mft_record(&mft, number, &mut before)?;
                // Only a free or newly formatted source slot proves this directory
                // belongs to the current plan. Existing found folders stay occupied.
                if before.iter().all(|byte| *byte == 0)
                    || (before.get(..record_layout::SIGNATURE_BYTES) == Some(b"FILE")
                        && u16_at(&before, record_layout::FLAGS_OFFSET)? & record_layout::IN_USE == 0)
                {
                    return Ok(family.reference);
                }
            }
        }
        let ordinal = occupied
            .iter()
            .position(|present| !present)
            .ok_or_else(|| reject("all recovery directory names are occupied"))?;
        drop(volume);
        create_indexed_file(
            source,
            boot,
            patches,
            &format!("found.{ordinal:03}"),
            ntfs_rs::index_tree::I30,
            Some((root, RECOVERY_DIRECTORY_FLAGS)),
        )
    }

    // Missing-parent groups share the fallback directory counter, but retain their
    // children's names. Their ordinary flags differ from the enclosing found folder.
    pub(crate) fn recovery_subdirectory(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
        parent: u64,
        ordinal: u32,
    ) -> io::Result<u64> {
        create_indexed_file(
            source,
            boot,
            patches,
            &format!("dir{ordinal:04}.chk"),
            ntfs_rs::index_tree::I30,
            Some((parent, 0)),
        )
    }

    /// Compact validated descriptors without renumbering security IDs or changing
    /// any surviving ACL, owner, group, SACL or mandatory integrity label.
    pub(crate) fn security_cleanup(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let mut numbers = base_numbers(&mut volume, &mft)?;
        let mut referenced = BTreeSet::new();
        while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            if record.local_attribute(ntfs_rs::mft::ATTR_SECURITY_DESCRIPTOR, &[])?.is_none() {
                if let Some(id) = record.security_id()?.filter(|id| *id >= FIRST_SECURITY_ID) {
                    referenced.insert(id);
                }
            }
        }
        let family = RepairFamily::load(&mut volume, &mft, system_record::SECURE)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let name = b"$\0S\0D\0S\0";
        let sds = record.local_attribute(ATTR_DATA, name)?.ok_or_else(|| reject("missing $SDS"))?;
        let mut inventory = checker::consistency::DiskInventory::new();
        let mut failed = None;
        ntfs_rs::security_store::visit_record_descriptors(
            &mut volume,
            &record,
            &mut vec![0; boot.index_block_bytes as usize],
            &mut vec![0; boot.index_block_bytes as usize],
            &mut vec![0; ntfs_rs::security::MAX_STORED_DESCRIPTOR + SDS_HEADER_BYTES],
            |entry| {
                if let Err(error) =
                    inventory.push([u64::from(entry.security_id), entry.offset, u64::from(entry.length), 0])
                {
                    failed = Some(error);
                    return Err(ntfs_rs::Error::Io);
                }
                Ok(())
            },
        )
        .map_err(|error| failed.unwrap_or_else(|| invalid(error)))?;
        let mut inventory = inventory.finish()?;
        let mut payload = checker::consistency::scratch_file()?;
        let mut pair = 0_u64;
        let mut at = 0_u64;
        let mut discarded = 0_u64;
        let mut retained = 0_u64;
        while let Some([id, offset, length, _]) = checker::consistency::inventory_next(&mut inventory)? {
            // Keep the established initial templates as well as referenced IDs.
            if id >= FIRST_PRUNABLE_SECURITY_ID && !referenced.contains(&(id as u32)) {
                discarded += 1;
                continue;
            }
            let padded = (length + SDS_ALIGNMENT - 1) & !(SDS_ALIGNMENT - 1);
            if padded > SDS_MIRROR_REGION_BYTES {
                return Err(reject("descriptor does not fit an SDS block"));
            }
            if at + padded > SDS_MIRROR_REGION_BYTES {
                pair += SDS_PAIR_BYTES;
                at = 0;
            }
            let mut bytes = vec![0; length as usize];
            volume.read_attribute(sds, offset, &mut bytes)?;
            ntfs_rs::security::SdsEntry::parse(&bytes, offset)?;
            bytes[SDS_OFFSET_FIELD..SDS_OFFSET_FIELD + std::mem::size_of::<u64>()]
                .copy_from_slice(&(pair + at).to_le_bytes());
            for position in [pair + at, pair + SDS_MIRROR_REGION_BYTES + at] {
                payload.seek(SeekFrom::Start(position))?;
                payload.write_all(&bytes)?;
            }
            referenced.remove(&(id as u32));
            at += padded;
            retained += 1;
        }
        if !referenced.is_empty() {
            return Err(reject("referenced security IDs have no valid descriptor; cleanup refused"));
        }
        if discarded == 0 || retained == 0 {
            return Ok(());
        }
        let bytes = pair + SDS_MIRROR_REGION_BYTES + at;
        payload.set_len(bytes)?;
        payload.seek(SeekFrom::Start(0))?;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut extra = RepairPlan::new(patches.length)?;
        let changes = space.stream_changes(&mut volume, ATTR_DATA, name, &mut payload, bytes, &mut extra)?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return security_cleanup(source, boot, patches);
        }
        result?;
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        // Index offsets follow the compacted SDS. Rebuild from the new headers.
        security_repairs(source, boot, patches)
    }

    // Standard NTFS 3.x type definitions. Private definitions remain volume
    // metadata and are retained verbatim when their framing is intact.
    fn standard_definitions() -> BTreeMap<u32, Vec<u8>> {
        attrdef::STANDARD.iter().map(|definition| (definition.kind(), definition.encode().to_vec())).collect()
    }

    #[cfg(test)]
    mod attribute_definition_tests {
        include!("../tests/recovery/metadata_attribute_definitions.rs");
    }

    fn definition_valid(row: &[u8]) -> bool {
        let kind = u32_at(row, attrdef::TYPE_OFFSET).unwrap();
        let end = row[..attrdef::NAME_BYTES].chunks_exact(filename::CODE_UNIT_BYTES).position(|b| b == [0, 0]);
        let min = i64::from_le_bytes(row[attrdef::MINIMUM_OFFSET..attrdef::MAXIMUM_OFFSET].try_into().unwrap());
        let max = i64::from_le_bytes(row[attrdef::MAXIMUM_OFFSET..attrdef::ROW_BYTES].try_into().unwrap());
        kind != 0
            && kind != u32::MAX
            && kind % attrdef::TYPE_ALIGNMENT == 0
            && end.is_some_and(|end| {
                end != 0 && row[end * filename::CODE_UNIT_BYTES..attrdef::NAME_BYTES].iter().all(|b| *b == 0)
            })
            && min >= 0
            && (max == attrdef::UNBOUNDED || max >= min)
    }

    fn definition_bytes<Rd: ReadAt>(volume: &mut Volume<Rd>, record: &MftRecord<'_>) -> io::Result<Option<Vec<u8>>> {
        let Some(data) = record.local_attribute(ATTR_DATA, &[])? else {
            return Ok(None);
        };
        let bytes = data.data_size()?;
        if bytes > MAX_ATTRDEF_STREAM_BYTES {
            return Err(reject("attribute definition table is too large"));
        }
        if data.flags()? != 0 || data.initialized_size()? != bytes {
            return Err(reject("attribute definition stream has invalid flags or initialization"));
        }
        let mut value = vec![0; bytes as usize];
        volume.read_attribute(data, 0, &mut value)?;
        Ok(Some(value))
    }

    fn definitions_valid(value: &[u8]) -> bool {
        if value.len() < attrdef::ROW_BYTES || value.len() % attrdef::ROW_BYTES != 0 {
            return false;
        }
        let mut expected = standard_definitions();
        let mut previous = 0;
        for (i, row) in value.chunks_exact(attrdef::ROW_BYTES).enumerate() {
            if row.iter().all(|b| *b == 0) {
                return expected.is_empty() && value[i * attrdef::ROW_BYTES..].iter().all(|b| *b == 0);
            }
            let kind = u32_at(row, attrdef::TYPE_OFFSET).unwrap();
            if !definition_valid(row) || kind <= previous {
                return false;
            }
            previous = kind;
            if let Some(standard) = expected.remove(&kind) {
                if row != standard {
                    return false;
                }
            }
        }
        false
    }

    fn audit_definitions<Rd: ReadAt>(
        volume: &mut Volume<Rd>,
        mft: &MftRecord<'_>,
        emit: &mut impl FnMut(&'static str, Option<u64>, String),
    ) -> io::Result<()> {
        let result = (|| -> io::Result<bool> {
            let family = RepairFamily::load(volume, mft, system_record::ATTRDEF)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            Ok(definition_bytes(volume, &record)?.is_some_and(|value| definitions_valid(&value)))
        })();
        match result {
            Ok(true) => {}
            Ok(false) => emit(
                "attribute-definitions-invalid",
                Some(system_record::ATTRDEF),
                "$AttrDef definitions, ordering or terminator are invalid".into(),
            ),
            Err(error) => emit("attribute-definitions-invalid", Some(system_record::ATTRDEF), error.to_string()),
        }
        Ok(())
    }

    pub(crate) fn system_table_repairs(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        patches: &mut RepairPlan,
    ) -> io::Result<()> {
        loop {
            let mut volume = PlannedImage::volume(source, patches, boot)?;
            let zero = checker::consistency::mft_image(&mut volume)?;
            let mft = MftRecord::from_decoded(&zero)?;
            let family = RepairFamily::load(&mut volume, &mft, system_record::ATTRDEF)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let old = definition_bytes(&mut volume, &record)?;
            if old.as_ref().is_some_and(|value| definitions_valid(value)) {
                break;
            }
            let mut rows = standard_definitions();
            if let Some(value) = old {
                if value.len() % attrdef::ROW_BYTES != 0 {
                    return Err(reject("partial attribute definition cannot be classified"));
                }
                for row in value.chunks_exact(attrdef::ROW_BYTES) {
                    if row.iter().all(|b| *b == 0) {
                        continue;
                    }
                    let kind = u32_at(row, attrdef::TYPE_OFFSET).unwrap();
                    if attrdef::STANDARD.iter().any(|definition| definition.kind() == kind) {
                        continue;
                    }
                    if !definition_valid(row) {
                        return Err(reject("damaged private attribute definition cannot be inferred"));
                    }
                    if let Some(previous) = rows.insert(kind, row.to_vec()) {
                        if previous != row {
                            return Err(reject("conflicting private attribute definitions"));
                        }
                    }
                }
            }
            // Never publish a table which leaves an existing private type undefined.
            let mut numbers = base_numbers(&mut volume, &mft)?;
            while let Some([number, _, _, _]) = checker::consistency::inventory_next(&mut numbers)? {
                let file = RepairFamily::load(&mut volume, &mft, number)?;
                for attr in MftRecord::from_decoded(&file.logical)?.attributes() {
                    if !rows.contains_key(&attr?.kind) {
                        return Err(reject("existing attribute type has no recoverable definition"));
                    }
                }
            }
            let mut value: Vec<u8> = rows.into_values().flatten().collect();
            value.resize(value.len() + attrdef::ROW_BYTES, 0);
            let mut space = RepairSpace::new(&mut volume, &mft)?;
            let mut extra = RepairPlan::new(patches.length)?;
            let changes = space.stream_changes(
                &mut volume,
                ATTR_DATA,
                &[],
                &mut value.as_slice(),
                value.len() as u64,
                &mut extra,
            )?;
            let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
            drop(volume);
            if !commit_store(result, extra, source, boot, patches)? {
                continue;
            }
            break;
        }
        // ASCII mappings are version-independent. Retain every other code unit;
        // wider damage needs the volume's NLS table rather than host Unicode rules.
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let family = RepairFamily::load(&mut volume, &mft, system_record::UPCASE)?;
        let record = MftRecord::from_decoded(&family.logical)?;
        let data = record.stream(ATTR_DATA, &[])?;
        if data.data_size()? != ntfs_rs::upcase::UPCASE_BYTES as u64
            || data.initialized_size()? != data.data_size()?
            || data.flags()? != 0
        {
            return Err(reject("$UpCase has no complete table to retain"));
        }
        let mut before = vec![0; ntfs_rs::upcase::UPCASE_BYTES];
        volume.read_attribute(data, 0, &mut before)?;
        let mut after = before.clone();
        for unit in 0..ASCII_CODE_UNITS {
            let upper =
                if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) { unit - ASCII_CASE_DELTA } else { unit };
            after[unit as usize * filename::CODE_UNIT_BYTES..(unit as usize + 1) * filename::CODE_UNIT_BYTES]
                .copy_from_slice(&upper.to_le_bytes());
        }
        ntfs_rs::upcase::validate_mapping(&after)?;
        if !data.nonresident {
            return Err(reject("$UpCase must have a nonresident mapping"));
        }
        let mut extra = RepairPlan::new(patches.length)?;
        if before != after {
            stage_change(data, boot, 0, ASCII_UPCASE_BYTES, &before, &after, &mut extra)?;
        }
        drop(volume);
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        // Publish mapping bytes and their information checksum in one repair plan.
        // Intact information keeps its version fields, trailing bytes and ownership.
        let checksum = ntfs_rs::upcase::information_checksum(&after).to_le_bytes();
        loop {
            let mut volume = PlannedImage::volume(source, patches, boot)?;
            let zero = checker::consistency::mft_image(&mut volume)?;
            let mft = MftRecord::from_decoded(&zero)?;
            let family = RepairFamily::load(&mut volume, &mft, system_record::UPCASE)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let information = record.local_attribute(ATTR_DATA, UPCASE_INFO)?;
            let mut header = [0; ntfs_rs::upcase::INFORMATION_BYTES];
            let framed = if let Some(info) = information {
                info.flags()? == 0
                    && info.data_size()? >= header.len() as u64
                    && info.initialized_size()? == info.data_size()?
                    && {
                        volume.read_attribute(info, 0, &mut header)?;
                        u64::from(u32_at(&header, 0)?) == info.data_size()?
                    }
            } else {
                false
            };
            if framed && header[UPCASE_CHECKSUM_OFFSET..UPCASE_CHECKSUM_OFFSET + UPCASE_CHECKSUM_BYTES] == checksum {
                break;
            }
            let mut extra = RepairPlan::new(patches.length)?;
            let result = if framed {
                let info = information.ok_or_else(|| reject("missing information stream"))?;
                if info.nonresident {
                    plan_nonresident_overwrite(
                        info,
                        boot,
                        UPCASE_CHECKSUM_OFFSET as u64,
                        UPCASE_CHECKSUM_BYTES as u64,
                        |span| {
                            let start = span.source_offset as usize;
                            let end = start + span.length as usize;
                            extra
                                .push(Patch::new(
                                    span.physical_offset,
                                    header[UPCASE_CHECKSUM_OFFSET + start..UPCASE_CHECKSUM_OFFSET + end].to_vec(),
                                    checksum[start..end].to_vec(),
                                ))
                                .io()
                        },
                    )
                    .map(|_| ())
                    .map_err(invalid)
                } else {
                    family
                        .patch_resident_values(
                            &mut volume,
                            &mft,
                            ATTR_DATA,
                            UPCASE_INFO,
                            &mut |value| {
                                value[UPCASE_CHECKSUM_OFFSET..UPCASE_CHECKSUM_OFFSET + UPCASE_CHECKSUM_BYTES]
                                    .copy_from_slice(&checksum);
                                Ok(())
                            },
                            &mut extra,
                        )
                        .map(|_| ())
                }
            } else {
                let information = ntfs_rs::upcase::build_information(&after);
                let change = StreamChange::resident(ATTR_DATA, UPCASE_INFO, &information)?;
                let mut space = RepairSpace::new(&mut volume, &mft)?;
                family.store(&mut volume, &mft, vec![change], &mut space, &mut extra)
            };
            drop(volume);
            if !commit_store(result, extra, source, boot, patches)? {
                continue;
            }
            break;
        }
        Ok(())
    }
}

pub mod journal {

    use std::fs::{self, File};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
    const PRIVATE_FORBIDDEN_MODE: u32 = 0o077;
    const SHARED_FORBIDDEN_MODE: u32 = 0o022;

    #[derive(Clone, Copy)]
    pub enum JournalKind {
        Repair,
        Replay,
    }

    impl JournalKind {
        fn directory(self) -> &'static str {
            match self {
                Self::Repair => "fsck",
                Self::Replay => "replay",
            }
        }
    }

    pub fn exists(path: &Path) -> io::Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn protected_directory(path: &Path, private: bool) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        let forbidden = if private { PRIVATE_FORBIDDEN_MODE } else { SHARED_FORBIDDEN_MODE };
        if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & forbidden != 0 {
            return Err(io::Error::other("unsafe recovery journal directory ownership or permissions"));
        }
        Ok(())
    }

    // Separate operation directories prevent automatic replay from selecting a
    // pending structural repair. The backend checks volume identity and preimages.
    fn directory(device: &Path, kind: JournalKind, create: bool) -> io::Result<PathBuf> {
        use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
        let metadata = fs::metadata(device)?;
        if !metadata.file_type().is_block_device() {
            return Err(io::Error::other("recovery requires an unmounted block/loop device"));
        }
        let directory =
            PathBuf::from(format!("/var/lib/slate-ntfs/{}/device-{:016x}", kind.directory(), metadata.rdev(),));
        for path in directory.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let private = path == directory;
            if exists(path)? {
                protected_directory(path, private)?;
                if fs::metadata(path)?.dev() == metadata.rdev() {
                    return Err(io::Error::other("recovery journal must reside outside the target device"));
                }
            } else if create {
                fs::DirBuilder::new().mode(PRIVATE_DIRECTORY_MODE).create(path)?;
                protected_directory(path, private)?;
                if let Some(parent) = path.parent() {
                    File::open(parent)?.sync_all()?;
                }
            }
        }
        Ok(directory)
    }

    pub fn pending(device: &Path, kind: JournalKind) -> io::Result<Option<PathBuf>> {
        let directory = directory(device, kind, false)?;
        if !exists(&directory)? {
            return Ok(None);
        }
        let mut pending = None;
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().is_some_and(|extension| extension == "journal") && pending.replace(path).is_some() {
                return Err(io::Error::other("multiple pending recoveries; select one with --journal PATH"));
            }
        }
        Ok(pending)
    }

    pub fn new(device: &Path, kind: JournalKind) -> io::Result<PathBuf> {
        let directory = directory(device, kind, true)?;
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
        // Completed journals retain their names. New dirty events get fresh names;
        // interrupted work remains discoverable through its original journal.
        Ok(directory.join(format!("recovery-{}-{}.journal", elapsed.as_nanos(), std::process::id(),)))
    }
}

pub(super) mod completion {
    use super::*;
    use ntfs_rs::boot::BootSector;
    use ntfs_rs::mft::system_record;
    use ntfs_rs::resident_writer::Writer;

    const SUPPORTED_NTFS_VERSION: (u8, u8) = (3, 1);
    const VOLUME_FLAGS_OFFSET: usize = 10;
    const VOLUME_FLAGS_BYTES: u64 = std::mem::size_of::<u16>() as u64;
    // The historical guard refuses the field and the byte preceding a USA tail.
    const FLAGS_TAIL_GUARD_BYTES: usize = 3;
    const FLAG_TARGET_COUNT: usize = 2;
    const JOURNAL_FLAG_GUARDS: u64 = 2;

    // Locate both words through checked mapping and fixups. Only the dirty bit can
    // change; persistent settings survive recovery and unknown flags remain blockers.
    fn clean_flags(source: &Path, changes: &RepairPlan, boot: BootSector) -> io::Result<Vec<Patch>> {
        let mut volume = Volume::new(PlannedImage::open(source, changes)?, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let mut raw = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(&mft, system_record::VOLUME, &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let info = ntfs_rs::volume_info::VolumeInfo::from_record(&record)?;
        if (info.major_version, info.minor_version) != SUPPORTED_NTFS_VERSION || info.has_unsupported_flags() {
            return Err(reject("journal completion requires NTFS 3.1 and supported persistent flags"));
        }
        let attr = record.stream(ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION, &[])?;
        let at = attr.record_offset() + attr.resident_value_offset()? + VOLUME_FLAGS_OFFSET;
        if at % usize::from(boot.bytes_per_sector) >= usize::from(boot.bytes_per_sector) - FLAGS_TAIL_GUARD_BYTES {
            return Err(reject("volume flags overlap a protected sector tail"));
        }
        let before = info.flags.to_le_bytes().to_vec();
        let after = ntfs_rs::volume_info::flags_after_check(info.flags).to_le_bytes().to_vec();
        let mut flags = Vec::new();
        plan_nonresident_overwrite(
            mft.stream(ATTR_DATA, &[])?,
            boot,
            system_record::VOLUME * u64::from(boot.record_bytes) + at as u64,
            VOLUME_FLAGS_BYTES,
            |span| {
                if span.length != VOLUME_FLAGS_BYTES {
                    return Err(ntfs_rs::Error::Unsupported);
                }
                flags.push(Patch::new(span.physical_offset, before.clone(), after.clone()));
                Ok(())
            },
        )?;
        let mirror =
            boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + system_record::VOLUME * u64::from(boot.record_bytes);
        volume.read_physical(mirror, &mut raw)?;
        let mirror_record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let mirror_info = ntfs_rs::volume_info::VolumeInfo::from_record(&mirror_record)?;
        let mirror_attr = mirror_record.stream(ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION, &[])?;
        let mirror_at = mirror_attr.record_offset() + mirror_attr.resident_value_offset()? + VOLUME_FLAGS_OFFSET;
        if mirror_at != at
            || (mirror_info.major_version, mirror_info.minor_version) != SUPPORTED_NTFS_VERSION
            || ntfs_rs::volume_info::flags_after_check(mirror_info.flags)
                != ntfs_rs::volume_info::flags_after_check(info.flags)
        {
            return Err(reject("recovered primary and mirror volume settings disagree"));
        }
        flags.push(Patch::new(mirror + at as u64, mirror_info.flags.to_le_bytes().to_vec(), after));
        if flags.len() != FLAG_TARGET_COUNT {
            return Err(reject("unsupported volume flag mapping"));
        }
        Ok(flags)
    }

    fn candidate(source: &Path, changes: &RepairPlan, flags: &[Patch], boot: BootSector) -> io::Result<()> {
        let audit = checker::consistency::audit_reader(
            PlannedImage { image: PlannedImage::open(source, changes)?, patches: flags },
            boot,
            |_, _, _| Ok(()),
            |_| Ok(()),
            checker::consistency::AuditOptions::default(),
            checker::consistency::INDEX_CACHE_BYTES,
        )?;
        if !audit.passed() {
            audit.write_report(&mut io::stderr().lock())?;
            return Err(reject(&format!(
                "journal-only recovery candidate failed complete audit: errors={}, complete={}; structural repair is required separately",
                audit.errors, audit.complete,
            )));
        }
        let mut scratch = vec![0; ntfs_rs::resident_writer::SCRATCH_BYTES];
        let mut image = PlannedImage { image: PlannedImage::open(source, changes)?, patches: flags };
        let mut reason = None;
        Writer::prepare_with_diagnostics(&mut image, boot, &mut scratch, |message| reason = Some(message)).map_err(
            |error| {
                reject(&format!(
                    "journal-only recovery candidate fails writable admission: {} ({error})",
                    reason.unwrap_or("metadata, journal or mirror validation failed")
                ))
            },
        )?;
        Ok(())
    }

    /// Journal completion variant; each carries the volume serial it is bound to.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum CompletionMode {
        Replay(Option<u64>),
        Summaries(Option<u64>),
        Widths(WidthRepairTarget),
        WidthsAndAliases(WidthRepairTarget),
    }

    impl CompletionMode {
        pub(crate) fn expected_serial(self) -> Option<u64> {
            match self {
                Self::Replay(serial) | Self::Summaries(serial) => serial,
                Self::Widths(target) | Self::WidthsAndAliases(target) => target.expected_serial,
            }
        }

        pub(crate) fn width_target(self) -> Option<WidthRepairTarget> {
            match self {
                Self::Widths(target) | Self::WidthsAndAliases(target) => Some(target),
                Self::Replay(_) | Self::Summaries(_) => None,
            }
        }
    }

    pub(crate) fn completion_plan(source: &Path, mode: CompletionMode) -> io::Result<RepairPlan> {
        let probe = checker::probe(source)?;
        if (probe.info.major_version, probe.info.minor_version) != SUPPORTED_NTFS_VERSION
            || probe.info.has_unsupported_flags()
        {
            return Err(reject("journal completion requires NTFS 3.1 and supported persistent flags"));
        }
        let length = image_length(&File::open(source)?)?;
        let mut changes = RepairPlan::new(length)?;
        let recovery = checker::inspect_recovery(PlannedImage::open(source, &changes)?, probe.boot)
            .map_err(crate::recovery_io::stage("reading the restart area"))?;
        // An uninitialized log has no history to replay. Its metadata must still
        // pass the complete audit and the writer's fresh admission checks below.
        let replay = if recovery.log == ntfs_rs::logfile::LogState::Uninitialized { None } else { Some(plan(source)?) };
        // An external journal protects the entire operation while the volume stays
        // dirty. Merge sequential changes to the same target into its final image;
        // any unsupported overlapping target geometry fails before journal creation.
        if let Some(replay) = replay {
            for patch in replay.preparation.iter().chain(replay.patches.iter()).chain(replay.publication.iter()) {
                changes.push(patch?)?;
            }
        }
        if let Some(target) = mode.width_target() {
            let corrected = widths::append_width_repair(source, &mut changes, probe.boot, target)?;
            println!("mapping_width_corrections={corrected}");
        }
        let flags = clean_flags(source, &changes, probe.boot).map_err(crate::recovery_io::stage("restoring volume flags"))?;
        if matches!(mode, CompletionMode::Summaries(_)) {
            // This opt-in mode accepts only derived summary findings after a complete
            // structural audit. Recheck the entire corrected candidate before any
            // external journal is created or any source write becomes possible.
            let audit = checker::consistency::audit_reader(
                PlannedImage { image: PlannedImage::open(source, &changes)?, patches: flags.as_slice() },
                probe.boot,
                |_, _, _| Ok(()),
                |_| Ok(()),
                checker::consistency::AuditOptions::default(),
                checker::consistency::INDEX_CACHE_BYTES,
            )?;
            let corrected = summaries::plan_summaries(source, probe.boot, &mut changes, &audit)?;
            println!("index_summary_corrections={corrected}");
        }
        if let CompletionMode::WidthsAndAliases(target) = mode {
            let audit = checker::consistency::audit_reader(
                PlannedImage { image: PlannedImage::open(source, &changes)?, patches: flags.as_slice() },
                probe.boot,
                |_, _, _| Ok(()),
                |_| Ok(()),
                checker::consistency::AuditOptions::default(),
                checker::consistency::INDEX_CACHE_BYTES,
            )?;
            let corrected = widths::append_alias_repairs(source, &mut changes, probe.boot, target, &audit)?;
            println!("alias_namespace_corrections={corrected}");
        }
        candidate(source, &changes, &flags, probe.boot).map_err(crate::recovery_io::stage("checking the recovered volume"))?;
        Ok(changes)
    }

    /// Read-only candidate validation. Block devices must be unmounted so an
    /// exclusive claim makes the source stable; regular images must be quiescent.
    pub fn validate_replay(source: &Path, mode: CompletionMode) -> io::Result<()> {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        };
        let file = File::open(source)?;
        let original = file.metadata()?;
        let file = if original.file_type().is_block_device() {
            // Device aliases are resolved before the no-follow exclusive claim.
            // The already-open target binds that claim to the observed device.
            let resolved = std::fs::canonicalize(source)?;
            let claimed = OpenOptions::new().read(true).custom_flags(libc::O_EXCL | libc::O_NOFOLLOW).open(resolved)?;
            let metadata = claimed.metadata()?;
            if !metadata.file_type().is_block_device()
                || (metadata.dev(), metadata.ino(), metadata.rdev())
                    != (original.dev(), original.ino(), original.rdev())
            {
                return Err(reject("validation device changed before its exclusive claim"));
            }
            claimed
        } else {
            file
        };
        let stable = std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        if let Some(expected) = mode.expected_serial() {
            let mut reader = Image(file.try_clone()?);
            let mut boot = [0; NTFS_SECTOR_BYTES];
            reader.read_exact_at(0, &mut boot)?;
            if BootSector::parse(&boot)?.serial_number != expected {
                return Err(reject("claimed source volume serial differs from the authorized target"));
            }
        }
        let before = file.metadata()?;
        let changes = completion_plan(&stable, mode)?;
        let after = file.metadata()?;
        if before.is_file() && (before.len() != after.len() || before.modified()? != after.modified()?) {
            return Err(reject("image changed during completion validation"));
        }
        println!("replay_completion_supported=1 metadata_and_journal_targets={} complete_audit=passed candidate_write_admission=accepted source_unchanged=1", changes.len());
        Ok(())
    }

    /// Apply checked journal recovery under the same exclusive claim and durable
    /// external preimage protocol as repair. Each mode has a distinct journal identity.
    pub fn replay_in_place(
        source: &Path,
        journal: &Path,
        resume: bool,
        mode: CompletionMode,
        progress: &mut dyn FnMut(RepairProgress),
    ) -> io::Result<()> {
        repair_in_place_queued(source, journal, resume, None, InPlaceOperation::Replay(mode), progress)
    }

    pub(crate) fn validate_journal_candidate(
        source: &Path,
        reader: &mut (impl Read + Seek),
        header_bytes: usize,
        count: u64,
        length: u64,
        guards: &[Patch],
        finalizers: &[Patch],
    ) -> io::Result<()> {
        let mut changes = RepairPlan::new(length)?;
        reader.seek(SeekFrom::Start(header_bytes as u64))?;
        for index in 0..count {
            let patch = read_repair_patch(reader, length)?;
            if index >= JOURNAL_FLAG_GUARDS && index < count - JOURNAL_FLAG_GUARDS {
                // Resume can observe preimages, postimages or interrupted mixtures.
                // Authentication happened before this call; the overlay reconstructs
                // only the logged final result without changing the target.
                changes.push(patch)?;
            }
        }
        let mut boot = [0; NTFS_SECTOR_BYTES];
        PlannedImage::open(source, &changes)?.read_exact_at(0, &mut boot)?;
        let boot = BootSector::parse(&boot)?;
        let flags = clean_flags(source, &changes, boot)?;
        if flags.iter().zip(finalizers).zip(guards).any(|((expected, finalizer), guard)| {
            expected.physical != finalizer.physical
                || expected.physical != guard.physical
                || expected.after != finalizer.after
                || expected.after
                    != ntfs_rs::volume_info::flags_after_check(u16::from_le_bytes(guard.before[..].try_into().unwrap()))
                        .to_le_bytes()
        }) {
            return Err(reject("replay journal flag targets or persistent settings disagree"));
        }
        candidate(source, &changes, &flags, boot)
    }

    pub(crate) fn validate_completed_targets(source: &Path, length: u64, finalizers: &[Patch]) -> io::Result<()> {
        let empty = RepairPlan::new(length)?;
        let boot = checker::probe(source)?.boot;
        let recovery = checker::inspect_recovery(PlannedImage::open(source, &empty)?, boot)?;
        if recovery.log != ntfs_rs::logfile::LogState::Uninitialized {
            let replay = plan(source)?;
            if !replay.preparation.is_empty() || !replay.patches.is_empty() || !replay.publication.is_empty() {
                return Err(reject("journal checkpoint has not converged; dirty flags retained"));
            }
        }
        let flags = clean_flags(source, &empty, boot)?;
        if flags
            .iter()
            .zip(finalizers)
            .any(|(expected, finalizer)| expected.physical != finalizer.physical || expected.after != finalizer.after)
        {
            return Err(reject("post-replay volume identity changed; dirty flags retained"));
        }
        candidate(source, &empty, &flags, boot)
    }

    #[cfg(test)]
    mod tests {
        include!("../tests/recovery/completion_tests.rs");
    }
}

pub(super) mod summaries {
    use super::*;
    use checker::consistency::{inventory_find, inventory_next, DiskInventory};
    use ntfs_rs::index::{IndexBlock, IndexEntry, IndexRoot};
    use ntfs_rs::mft::system_record;
    use ntfs_rs::{filename_metadata as filename, mft::record_layout};

    use ntfs_rs::index_tree::I30;

    const SUMMARY_EAGER_TIMES_BYTES: usize = 3 * std::mem::size_of::<u64>();
    const SUMMARY_SIZES_OFFSET: usize = 32;
    const SUMMARY_FLAGS_OFFSET: usize = 48;
    const SUMMARY_REPARSE_TAG_OFFSET: usize = 54;
    const SUMMARY_NAMESPACE_OFFSET: usize = filename::NAMESPACE_OFFSET - filename::DUPLICATED_INFORMATION_OFFSET;
    const INDEX_SUMMARY_OFFSET: usize = semantic::VIEW_HEADER_BYTES + filename::DUPLICATED_INFORMATION_OFFSET;
    const DIRECTORY_BITMAP_READ_BYTES: usize = 512;

    struct Edit {
        offset: usize,
        before: Vec<u8>,
        after: Vec<u8>,
    }

    // Derive ordinary summaries from the complete authoritative family. Reserved
    // records retain their special cached-information convention. Revalidate each
    // filename identity independently even though the complete audit passed it.
    fn entry_edit<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        parent: u64,
        entry: IndexEntry<'_>,
        offset: usize,
        targets: &mut File,
    ) -> io::Result<Option<Edit>> {
        let number = ntfs_rs::mft::reference_number(entry.file_reference);
        if inventory_find(targets, number)?.is_none() {
            return Ok(None);
        }
        let family = RepairFamily::load(volume, mft, number)?;
        if family.reference != entry.file_reference {
            return Err(reject("summary target sequence changed"));
        }
        let record = MftRecord::from_decoded(&family.logical)?;
        let mut filename = None;
        for item in record.attributes() {
            let attribute = item?;
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            let value = attribute.resident_value()?;
            if value.len() < filename::HEADER_BYTES {
                return Err(reject("summary filename is truncated"));
            }
            if u64_at(value, filename::PARENT_REFERENCE_OFFSET)? == parent
                && value[filename::NAMESPACE_OFFSET] == entry.name.namespace
                && value[filename::HEADER_BYTES..] == *entry.name.utf16le
            {
                if filename.replace(value).is_some() {
                    return Err(reject("summary filename identity is ambiguous"));
                }
            }
        }
        let filename = filename.ok_or_else(|| reject("summary filename identity changed"))?;
        let expected = if number < system_record::RESERVED {
            filename[filename::DUPLICATED_INFORMATION_OFFSET..filename::NAME_LENGTH_OFFSET].try_into().unwrap()
        } else {
            ntfs_rs::filename_metadata::duplicated_information(volume, &record)?
        };
        let before: [u8; filename::DUPLICATED_INFORMATION_BYTES] = entry.file_name_value
            [filename::DUPLICATED_INFORMATION_OFFSET..filename::NAME_LENGTH_OFFSET]
            .try_into()
            .unwrap();
        if duplicated_name_equal(&expected, &before) {
            return Ok(None);
        }
        let mut after = before;
        after[..SUMMARY_EAGER_TIMES_BYTES].copy_from_slice(&expected[..SUMMARY_EAGER_TIMES_BYTES]);
        after[SUMMARY_SIZES_OFFSET..SUMMARY_REPARSE_TAG_OFFSET]
            .copy_from_slice(&expected[SUMMARY_SIZES_OFFSET..SUMMARY_REPARSE_TAG_OFFSET]);
        if u32_at(&expected, SUMMARY_FLAGS_OFFSET)? & ntfs_rs::std_info::REPARSE_POINT != 0 {
            after[SUMMARY_REPARSE_TAG_OFFSET..filename::DUPLICATED_INFORMATION_BYTES]
                .copy_from_slice(&expected[SUMMARY_REPARSE_TAG_OFFSET..filename::DUPLICATED_INFORMATION_BYTES]);
        }
        Ok(Some(Edit { offset, before: before.to_vec(), after: after.to_vec() }))
    }

    fn apply(bytes: &mut [u8], edits: &[Edit]) -> io::Result<()> {
        for edit in edits {
            let value = bytes
                .get_mut(edit.offset..edit.offset + edit.before.len())
                .ok_or_else(|| reject("summary field lies outside its validated node"))?;
            if value != edit.before {
                return Err(reject("summary node preimage changed during planning"));
            }
            value.copy_from_slice(&edit.after);
        }
        Ok(())
    }

    pub(crate) fn plan_summaries(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        changes: &mut RepairPlan,
        audit: &checker::consistency::Audit,
    ) -> io::Result<u64> {
        if !audit.complete {
            return Err(reject("summary repair requires a complete audit"));
        }
        let mut targets = DiskInventory::new();
        let mut parents = DiskInventory::new();
        let mut summaries = 0;
        let mut errors = 0;
        audit.for_each_finding(|code, record, is_error, detail| {
            errors += u64::from(is_error);
            if code != "index-duplicate-information" {
                if !is_error {
                    return Ok(());
                }
                return Err(reject("summary repair refuses structural or unrelated findings"));
            }
            let number = record.ok_or_else(|| reject("summary finding has no target"))?;
            let parent = detail
                .strip_prefix("parent ")
                .and_then(|text| text.split_whitespace().next())
                .and_then(|text| text.parse::<u64>().ok())
                .ok_or_else(|| reject("summary finding has no validated parent"))?;
            targets.push([number, 0, 0, 0])?;
            parents.push([parent, 0, 0, 0])?;
            summaries += 1;
            Ok(())
        })?;
        if errors != audit.errors {
            return Err(reject("summary finding inventory is incomplete"));
        }
        if summaries == 0 {
            return Ok(0);
        }
        if usize::from(boot.bytes_per_sector) != NTFS_SECTOR_BYTES {
            return Err(reject("summary publication requires the supported 512-byte sector geometry"));
        }
        let targets = targets.finish()?;
        let parents = parents.finish()?;
        plan_index_values(source, boot, changes, targets, parents, summaries, None)
    }

    // Shared checked-node publication keeps namespace and summary corrections on
    // the same physical preimage, fixup and allocated-block validation path.
    pub(crate) fn plan_alias_indexes(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        changes: &mut RepairPlan,
        targets: File,
        parent: u64,
        count: u64,
    ) -> io::Result<u64> {
        let mut parents = DiskInventory::new();
        parents.push([ntfs_rs::mft::reference_number(parent), 0, 0, 0])?;
        plan_index_values(source, boot, changes, targets, parents.finish()?, count, Some(parent))
    }

    fn alias_entry_edit<R: ReadAt>(
        volume: &mut Volume<R>,
        mft: &MftRecord<'_>,
        parent: u64,
        entry: IndexEntry<'_>,
        offset: usize,
        targets: &mut File,
    ) -> io::Result<Option<Edit>> {
        let number = ntfs_rs::mft::reference_number(entry.file_reference);
        if inventory_find(targets, number)?.is_none() {
            return Ok(None);
        }
        let family = RepairFamily::load(volume, mft, number)?;
        if family.reference != entry.file_reference {
            return Err(reject("alias index target sequence changed"));
        }
        let record = MftRecord::from_decoded(&family.logical)?;
        let value = widths::alias_filename(&record, number, parent)?;
        if u64_at(entry.file_name_value, filename::PARENT_REFERENCE_OFFSET)? != parent
            || entry.name.namespace != filename::WIN32
            || entry.name.utf16le != &value[filename::HEADER_BYTES..]
        {
            return Err(reject("alias index key does not match its exact stored filename"));
        }
        Ok(Some(Edit {
            offset: offset + SUMMARY_NAMESPACE_OFFSET,
            before: vec![filename::WIN32],
            after: vec![filename::POSIX],
        }))
    }

    fn plan_index_values(
        source: &Path,
        boot: ntfs_rs::boot::BootSector,
        changes: &mut RepairPlan,
        mut targets: File,
        parents: File,
        expected_count: u64,
        alias_parent: Option<u64>,
    ) -> io::Result<u64> {
        if usize::from(boot.bytes_per_sector) != NTFS_SECTOR_BYTES {
            return Err(reject("index field publication requires 512-byte sector geometry"));
        }
        let mut parents = std::io::BufReader::new(parents);
        let mut extra = RepairPlan::new(changes.length)?;
        let mut volume = PlannedImage::volume(source, changes, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let mut previous = None;
        let mut repaired = 0_u64;
        while let Some([number, _, _, _]) = inventory_next(&mut parents)? {
            if previous == Some(number) {
                continue;
            }
            previous = Some(number);
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            if record.flags()? & record_layout::DIRECTORY == 0 {
                return Err(reject("summary parent is no longer a directory"));
            }
            if alias_parent.is_some_and(|parent| parent != family.reference) {
                return Err(reject("alias parent generation changed"));
            }
            let root_attribute = record
                .local_attribute(ntfs_rs::mft::ATTR_INDEX_ROOT, I30)?
                .ok_or_else(|| reject("summary parent has no root"))?;
            let root = IndexRoot::parse(root_attribute.resident_value()?)?;
            let unit = root.vcn_unit_bytes(boot.cluster_bytes)?;
            let mut edits = Vec::new();
            let mut cursor = root.first_entry_offset();
            loop {
                let slot = root.slot_at(cursor)?;
                let Some(entry) = slot.entry else { break };
                let edit = if alias_parent.is_some() {
                    alias_entry_edit(
                        &mut volume,
                        &mft,
                        family.reference,
                        entry,
                        cursor + INDEX_SUMMARY_OFFSET,
                        &mut targets,
                    )?
                } else {
                    entry_edit(&mut volume, &mft, family.reference, entry, cursor + INDEX_SUMMARY_OFFSET, &mut targets)?
                };
                if let Some(edit) = edit {
                    edits.push(edit);
                }
                cursor = slot.next_offset;
            }
            repaired += edits.len() as u64;
            if let Some(allocation) = record.local_attribute(ntfs_rs::mft::ATTR_INDEX_ALLOCATION, I30)? {
                let bitmap = record
                    .local_attribute(ATTR_BITMAP, I30)?
                    .ok_or_else(|| reject("summary allocation has no bitmap"))?;
                let blocks = allocation.data_size()? / u64::from(boot.index_block_bytes);
                let mut bitmap_bytes = [0; DIRECTORY_BITMAP_READ_BYTES];
                let mut before = vec![0; boot.index_block_bytes as usize];
                for start in (0..blocks.div_ceil(BITMAP_BITS_PER_BYTE)).step_by(bitmap_bytes.len()) {
                    let length =
                        (blocks.div_ceil(BITMAP_BITS_PER_BYTE) - start).min(bitmap_bytes.len() as u64) as usize;
                    volume.read_attribute(bitmap, start, &mut bitmap_bytes[..length])?;
                    for (byte, bits) in bitmap_bytes[..length].iter().enumerate() {
                        for bit in 0..BITMAP_BITS_PER_BYTE {
                            if bits & (1 << bit) == 0 {
                                continue;
                            }
                            let block_number = (start + byte as u64) * BITMAP_BITS_PER_BYTE + bit;
                            if block_number >= blocks {
                                return Err(reject("summary bitmap padding is allocated"));
                            }
                            let offset = block_number * u64::from(boot.index_block_bytes);
                            volume.read_nonresident(allocation, offset, &mut before)?;
                            let mut after = before.clone();
                            let block = IndexBlock::parse(&mut after, boot.bytes_per_sector, offset / unit)?;
                            let mut block_edits = Vec::new();
                            let mut cursor = block.first_entry_offset();
                            loop {
                                let slot = block.slot_at(cursor)?;
                                let Some(entry) = slot.entry else { break };
                                let edit = if alias_parent.is_some() {
                                    alias_entry_edit(
                                        &mut volume,
                                        &mft,
                                        family.reference,
                                        entry,
                                        cursor + INDEX_SUMMARY_OFFSET,
                                        &mut targets,
                                    )?
                                } else {
                                    entry_edit(
                                        &mut volume,
                                        &mft,
                                        family.reference,
                                        entry,
                                        cursor + INDEX_SUMMARY_OFFSET,
                                        &mut targets,
                                    )?
                                };
                                if let Some(edit) = edit {
                                    block_edits.push(edit);
                                }
                                cursor = slot.next_offset;
                            }
                            if block_edits.is_empty() {
                                continue;
                            }
                            repaired += block_edits.len() as u64;
                            apply(&mut after, &block_edits)?;
                            ntfs_rs::mft::protect_fixups(&mut after)?;
                            stage_change(allocation, boot, offset, before.len() as u64, &before, &after, &mut extra)?;
                        }
                    }
                }
            }
            if !edits.is_empty() {
                family.patch_resident_values(
                    &mut volume,
                    &mft,
                    ntfs_rs::mft::ATTR_INDEX_ROOT,
                    I30,
                    &mut |bytes| apply(bytes, &edits),
                    &mut extra,
                )?;
            }
        }
        if repaired != expected_count {
            return Err(reject("index field correction count differs from the complete audit"));
        }
        drop(volume);
        for patch in extra.iter() {
            changes.compose(patch?)?;
        }
        Ok(repaired)
    }

    #[cfg(test)]
    mod tests {
        include!("../tests/recovery/summaries_tests.rs");
    }
}

pub(super) mod widths {
    use super::*;
    use ntfs_rs::boot::BootSector;
    use ntfs_rs::bytes::u16_at;
    use ntfs_rs::runlist::{DataRuns, Extent, MappingPairError, MappingPairHeader};
    use ntfs_rs::{
        filename_metadata as filename,
        mft::{attribute_layout, record_layout},
    };

    const SHA256_BYTES: usize = 32;
    const RESIDENT_INDEXED: u8 = 1;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct WidthRepairTarget {
        pub record: u64,
        pub raw_sha256: [u8; SHA256_BYTES],
        pub expected_serial: Option<u64>,
    }

    fn mapping_pair_error(error: MappingPairError) -> io::Error {
        reject(match error {
            MappingPairError::MissingHeader => "missing mapping terminator",
            MappingPairError::InvalidWidths => "width correction requires dense physical mappings",
            MappingPairError::OffsetOverflow => "mapping width overflow",
            MappingPairError::Truncated => "truncated mapping pair",
        })
    }

    // Only the compact positive length defect is admitted. Signed physical deltas
    // remain signed, and the original size fields must independently prove coverage.
    fn compact_runs(bytes: &[u8], boot: BootSector) -> io::Result<(Vec<Extent>, u64)> {
        let mut runs = Vec::new();
        let mut cursor = 0;
        let mut vcn = 0_u64;
        let mut previous = 0_i64;
        let mut corrected = 0;
        loop {
            let Some(header) = MappingPairHeader::read(bytes, cursor).map_err(mapping_pair_error)? else {
                if bytes[cursor..].iter().any(|&byte| byte != 0) {
                    return Err(reject("nonzero mapping padding"));
                }
                break;
            };
            // Dense admission precedes body reads, retaining the original refusal
            // for a sparse header even when that header has no payload bytes.
            if header.delta_width() == 0 {
                return Err(reject("width correction requires dense physical mappings"));
            }
            let pair = header.decode(bytes).map_err(mapping_pair_error)?;
            let length = pair.length;
            if length == 0 || length > i64::MAX as u64 {
                return Err(reject("mapping length is not positive and representable"));
            }
            if pair.negative_length {
                // A set top bit proves this positive unsigned value already uses
                // its minimal width; the signed-positive limit was checked above.
                corrected += 1;
            }
            previous = previous
                .checked_add(pair.delta.unwrap())
                .filter(|&lcn| lcn >= 0)
                .ok_or_else(|| reject("mapping physical delta overflow"))?;
            let lcn = previous as u64;
            let physical_end = lcn
                .checked_add(length)
                .filter(|&end| end <= boot.total_sectors / u64::from(boot.sectors_per_cluster))
                .ok_or_else(|| reject("mapping exceeds volume"))?;
            if runs.iter().any(|run: &Extent| {
                let start = run.lcn.unwrap();
                start < physical_end && lcn < start + run.len
            }) {
                return Err(reject("mapping contains overlapping physical extents"));
            }
            runs.push(Extent { vcn, len: length, lcn: Some(lcn) });
            vcn = vcn.checked_add(length).ok_or_else(|| reject("mapping VCN overflow"))?;
            cursor = pair.next_offset;
        }
        if corrected == 0 || runs.is_empty() {
            return Err(reject("pinned record has no compact mapping length defect"));
        }
        Ok((runs, corrected))
    }

    fn canonical_record(protected: &[u8], boot: BootSector, target: WidthRepairTarget) -> io::Result<(Vec<u8>, u64)> {
        if target.record < ntfs_rs::mft_growth::FIRST_USER_RECORD
            || ntfs_rs::sha256::digest(protected) != target.raw_sha256
        {
            return Err(reject("mapping target record or protected preimage digest mismatch"));
        }
        let mut decoded = protected.to_vec();
        MftRecord::parse(&mut decoded, boot.bytes_per_sector)?;
        let record = MftRecord::from_decoded(&decoded)?;
        if record.physical_record_number()? != Some(target.record)
            || record.sequence_number()? == 0
            || record.flags()? != record_layout::IN_USE
            || record.base_file_reference()? != 0
        {
            return Err(reject("mapping target is not an identified allocated plain base record"));
        }
        let mut data = None;
        for entry in record.attributes() {
            let attribute = entry?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST {
                return Err(reject("mapping width correction does not admit split families"));
            }
            if attribute.kind == ATTR_DATA {
                if data.is_some() || !attribute.name_utf16le()?.is_empty() {
                    return Err(reject("mapping width correction requires one unnamed DATA stream"));
                }
                data = Some(attribute);
            }
        }
        let data = data.ok_or_else(|| reject("mapping target has no DATA stream"))?;
        let at = data.record_offset();
        if !data.nonresident
            || data.flags()? != 0
            || data.first_vcn()? != 0
            || u16_at(&decoded, at + attribute_layout::COMPRESSION_UNIT_OFFSET)? != 0
        {
            return Err(reject("mapping target DATA is not plain dense nonresident storage"));
        }
        let (runs, corrected) = compact_runs(data.data_runs()?, boot)?;
        let clusters = runs
            .last()
            .unwrap()
            .vcn
            .checked_add(runs.last().unwrap().len)
            .ok_or_else(|| reject("mapping size overflow"))?;
        let allocated =
            clusters.checked_mul(u64::from(boot.cluster_bytes)).ok_or_else(|| reject("mapping allocation overflow"))?;
        let sizes = (data.allocated_size()?, data.data_size()?, data.initialized_size()?);
        if data.last_vcn()?.checked_add(1) != Some(clusters)
            || sizes.0 != allocated
            || sizes.2 > sizes.1
            || sizes.1 > sizes.0
            || sizes.1.div_ceil(u64::from(boot.cluster_bytes)) != clusters
        {
            return Err(reject("mapping coverage disagrees with original DATA sizes"));
        }
        ntfs_rs::record_edit::set_runs(&mut decoded, at, &runs)?;
        ntfs_rs::record_edit::validate(&decoded)?;
        let check = MftRecord::from_decoded(&decoded)?;
        let check_data = check.stream(ATTR_DATA, &[])?;
        let encoded = DataRuns::new(check_data.data_runs()?, 0).collect::<ntfs_rs::Result<Vec<_>>>()?;
        if encoded != runs
            || (check_data.allocated_size()?, check_data.data_size()?, check_data.initialized_size()?) != sizes
        {
            return Err(reject("canonical mapping changed extents or DATA sizes"));
        }
        protect_mft_record(&mut decoded, boot.bytes_per_sector)?;
        Ok((decoded, corrected))
    }

    fn record_spans(data: Attribute<'_>, boot: BootSector, number: u64) -> io::Result<Vec<(u64, usize, usize)>> {
        let offset =
            number.checked_mul(u64::from(boot.record_bytes)).ok_or_else(|| reject("record offset overflow"))?;
        Ok(overwrite_spans(data, boot, offset, u64::from(boot.record_bytes))?
            .into_iter()
            .map(|span| (span.physical_offset, span.source_offset as usize, span.length as usize))
            .collect())
    }

    // Bind both the original physical record and its replay-projected location.
    // Pending replay may not silently supply a different record for this authority.
    pub(crate) fn append_width_repair(
        source: &Path,
        changes: &mut RepairPlan,
        boot: BootSector,
        target: WidthRepairTarget,
    ) -> io::Result<u64> {
        if target.expected_serial.is_some_and(|serial| serial != boot.serial_number) {
            return Err(reject("mapping target volume serial mismatch"));
        }
        let mut original = Volume::new(Image(File::open(source)?), boot)?;
        let zero = checker::consistency::mft_image(&mut original)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let table = mft.stream(ATTR_DATA, &[])?;
        let offset = target
            .record
            .checked_mul(u64::from(boot.record_bytes))
            .and_then(|offset| offset.checked_add(u64::from(boot.record_bytes)))
            .ok_or_else(|| reject("mapping target offset overflow"))?;
        if target.record < ntfs_rs::mft_growth::FIRST_USER_RECORD || offset > table.initialized_size()? {
            return Err(reject("mapping target is outside initialized MFT"));
        }
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let byte = bitmap_byte(
            &mut original,
            bitmap,
            target.record / BITMAP_BITS_PER_BYTE,
            bitmap.data_size()?,
            &mut (u64::MAX, [0; BITMAP_CACHE_BYTES]),
        )?;
        if byte & (1 << (target.record % BITMAP_BITS_PER_BYTE)) == 0 {
            return Err(reject("mapping target allocation bit is not set"));
        }
        let mut before = vec![0; boot.record_bytes as usize];
        original.read_mft_record(&mft, target.record, &mut before)?;
        let spans = record_spans(table, boot, target.record)?;
        let mut projected = PlannedImage::volume(source, changes, boot)?;
        let projected_zero = checker::consistency::mft_image(&mut projected)?;
        let projected_mft = MftRecord::from_decoded(&projected_zero)?;
        let projected_bitmap = projected_mft.stream(ATTR_BITMAP, &[])?;
        let projected_byte = bitmap_byte(
            &mut projected,
            projected_bitmap,
            target.record / BITMAP_BITS_PER_BYTE,
            projected_bitmap.data_size()?,
            &mut (u64::MAX, [0; BITMAP_CACHE_BYTES]),
        )?;
        if projected_byte & (1 << (target.record % BITMAP_BITS_PER_BYTE)) == 0 {
            return Err(reject("pending replay clears the pinned record allocation bit"));
        }
        let mut projected_raw = vec![0; before.len()];
        projected.read_mft_record(&projected_mft, target.record, &mut projected_raw)?;
        if projected_raw != before || record_spans(projected_mft.stream(ATTR_DATA, &[])?, boot, target.record)? != spans
        {
            return Err(reject("pending replay changes the pinned record or physical location"));
        }
        drop(projected);
        let (after, corrected) = canonical_record(&before, boot, target)?;
        for (physical, start, length) in spans {
            changes.compose(Patch::new(
                physical,
                before[start..start + length].to_vec(),
                after[start..start + length].to_vec(),
            ))?;
        }
        Ok(corrected)
    }

    // Only a complete, single ordinary base claim is admitted. Alias corrections
    // preserve its full parent reference, spelling, flags and cached information.
    pub(crate) fn alias_filename<'a>(record: &MftRecord<'a>, number: u64, parent: u64) -> io::Result<&'a [u8]> {
        if number < ntfs_rs::mft_growth::FIRST_USER_RECORD
            || record.physical_record_number()? != Some(number)
            || record.flags()? != record_layout::IN_USE
            || record.sequence_number()? == 0
            || record.base_file_reference()? != 0
        {
            return Err(reject("alias target is not an identified ordinary base file"));
        }
        let mut found = None;
        for item in record.attributes() {
            let attribute = item?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST {
                return Err(reject("alias correction does not admit split file families"));
            }
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            if found.is_some()
                || attribute.nonresident
                || attribute.resident_flags()? != RESIDENT_INDEXED
                || !attribute.name_utf16le()?.is_empty()
            {
                return Err(reject("alias correction requires one indexed resident filename"));
            }
            let value = attribute.resident_value()?;
            if !metadata::filename_value_valid(value)
                || value[filename::NAMESPACE_OFFSET] != filename::WIN32
                || u64_at(value, filename::PARENT_REFERENCE_OFFSET)? != parent
            {
                return Err(reject("alias target filename identity or namespace is unsupported"));
            }
            found = Some(value);
        }
        found.ok_or_else(|| reject("alias target has no filename"))
    }

    // A complete audit bounds this opt-in correction set. Index namespace alone
    // may change; any topology, ownership or unrelated error stops publication.
    pub(crate) fn append_alias_repairs(
        source: &Path,
        changes: &mut RepairPlan,
        boot: BootSector,
        target: WidthRepairTarget,
        audit: &checker::consistency::Audit,
    ) -> io::Result<u64> {
        use checker::consistency::{inventory_next, DiskInventory};
        if !audit.complete {
            return Err(reject("alias correction requires a complete candidate audit"));
        }
        let mut targets = DiskInventory::new();
        let mut count = 0_u64;
        audit.for_each_finding(|code, record, is_error, detail| {
            if !is_error {
                return Ok(());
            }
            let valid_detail = detail
                .strip_prefix("parent ")
                .and_then(|text| text.split_once(' '))
                .is_some_and(|(_, rest)| rest == "index namespace 1 differs from effective filename namespace 0");
            if code != "index-filename-namespace" || !valid_detail {
                return Err(reject("alias correction refuses topology, ownership or unrelated errors"));
            }
            let number = record.ok_or_else(|| reject("alias finding has no file identity"))?;
            targets.push([number, 0, 0, 0])?;
            count += 1;
            Ok(())
        })?;
        if count != audit.errors {
            return Err(reject("alias correction inventory is incomplete"));
        }
        if count == 0 {
            return Ok(0);
        }
        let mut targets = targets.finish()?;
        let mut extra = RepairPlan::new(changes.length)?;
        let mut volume = PlannedImage::volume(source, changes, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let pinned = RepairFamily::load(&mut volume, &mft, target.record)?;
        let pinned_record = MftRecord::from_decoded(&pinned.logical)?;
        let pinned_name = pinned_record.stream(ntfs_rs::mft::ATTR_FILE_NAME, &[])?;
        let parent = u64_at(pinned_name.resident_value()?, 0)?;
        alias_filename(&pinned_record, target.record, parent)?;
        let directory = RepairFamily::load(&mut volume, &mft, ntfs_rs::mft::reference_number(parent))?;
        let parent_record = MftRecord::from_decoded(&directory.logical)?;
        if directory.reference != parent
            || parent_record.flags()? != (record_layout::IN_USE | record_layout::DIRECTORY)
            || parent_record.base_file_reference()? != 0
            || parent_record.local_attribute(ntfs_rs::mft::ATTR_STANDARD_INFORMATION, &[])?.is_none()
        {
            return Err(reject("alias correction parent generation or directory identity is invalid"));
        }
        let mut previous = None;
        let mut found = 0;
        while let Some([number, _, _, _]) = inventory_next(&mut targets)? {
            if previous == Some(number) {
                return Err(reject("alias target has competing index namespace findings"));
            }
            previous = Some(number);
            let family = RepairFamily::load(&mut volume, &mft, number)?;
            let record = MftRecord::from_decoded(&family.logical)?;
            let expected = alias_filename(&record, number, parent)?.to_vec();
            family.patch_resident_values(
                &mut volume,
                &mft,
                ntfs_rs::mft::ATTR_FILE_NAME,
                &[],
                &mut |value| {
                    if value != expected {
                        return Err(reject("alias filename preimage changed during planning"));
                    }
                    value[filename::NAMESPACE_OFFSET] = filename::POSIX;
                    Ok(())
                },
                &mut extra,
            )?;
            found += 1;
        }
        if found != count {
            return Err(reject("alias finding count differs from validated file identities"));
        }
        drop(volume);
        targets.seek(SeekFrom::Start(0))?;
        summaries::plan_alias_indexes(source, boot, changes, targets, parent, count)?;
        for patch in extra.iter() {
            changes.compose(patch?)?;
        }
        Ok(count)
    }

    #[cfg(test)]
    mod tests {
        include!("../tests/recovery/widths_tests.rs");
    }
}
