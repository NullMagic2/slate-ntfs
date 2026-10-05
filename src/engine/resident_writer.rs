//! Module: ntfs_rs::resident_writer
//! Purpose: Admit writable volumes and serialize journaled metadata changes.
//! Created: 2026-10-01
//! Architecture: Adapters supply I/O; this engine owns NTFS safety and flush ordering.

use super::batch::Batch;
use super::boot::BootSector;
use super::bytes::{u16_at, u64_at};
use super::journal::{reserve_resident, Slot};
use super::logfile::*;
use super::mft::{Attribute, MftRecord, ATTR_BITMAP, ATTR_DATA};
use super::upcase::{UpcaseTable, UPCASE_BYTES};
use super::volume::{ReadAt, Volume};
use super::volume_info::{VolumeInfo, VOLUME_IS_DIRTY};
use super::write_plan::plan_nonresident_overwrite;
use super::{Error, Result};

pub const SCRATCH_BYTES: usize = 262144;
/// Scratch for B-tree, security-descriptor and MFT-growth transactions.
pub const METADATA_SCRATCH_BYTES: usize = 2 << 20;
/// Bytes read at once while scanning the journal or the file table.
pub(super) const SCAN_SPAN_BYTES: usize = 64 * 1024;
pub const MAX_WRITE: usize = 1 << 20;
/// $VOLUME_NAME: up to 128 UTF-16 code units (Windows shows at most 32).
pub const ATTR_VOLUME_NAME: u32 = 0x60;
pub const MAX_LABEL_UNITS: usize = 128;
/// The file record of $Volume.
const VOLUME_RECORD: u64 = super::mft::system_record::VOLUME;
pub trait WriteIo: ReadAt {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    /// Staged stream bytes may bypass an adapter's data cache. Journal and
    /// record publication still use write_at and the same ordering barriers.
    fn write_data_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.write_at(offset, data)
    }
    fn flush(&mut self) -> Result<()>;
    /// Make data visible to readers without scheduling it for writeback;
    /// the journal owns the eventual write. first: the region was not held
    /// before. Adapters without a cache just write.
    fn hold_at(&mut self, offset: u64, data: &[u8], _first: bool) -> Result<()> {
        self.write_at(offset, data)
    }
    /// Remove the read overlay after its committed image is checkpointed.
    fn release_at(&mut self, _offset: u64, _len: usize) {}
}

pub struct Writer {
    pub(super) linux_compatibility: bool,
    pub(super) boot: BootSector,
    pub(super) log: LogMap,
    /// Lent by `attach_journal_map` until admission fills the map from it.
    journal_storage: Option<&'static mut [u64]>,
    pub(super) log_bytes: u64,
    volume: u64,
    mirror: u64,
    // Preserve admitted Windows settings across dirty/clean journal transitions.
    volume_flags: u16,
    pub(super) current_lsn: u64,
    pub(super) checkpoint_lsn: u64,
    pub(super) data_dirty: bool,
    pub(super) exposure_dirty: bool,
    // A commit journaled without its device flush; committed targets stay
    // held until a flush makes it durable. See Writer::make_room.
    pub(super) log_unflushed: bool,
    // Net clusters allocated this session; see Writer::allocated_delta.
    pub(super) allocated_delta: i64,
    // (file reference, zeroed-from, zeroed-to, durable). References remain
    // tracked after invalidation so finish can return unused preallocation.
    pub(super) windows: [(u64, u64, u64); 32],
    pub(super) committed: Batch,
    pub(super) next_record: u64,
    pub(super) next_cluster: u64,
    pub(super) initialized: bool,
    pub(super) failed: bool,
    resume_log: bool,
    reset_clean_log: bool,
    // Idle and published clean; resume precedes the next change.
    parked: bool,
    pub(super) batch: Batch,
    /// Log pages one drain may use.
    pub(super) log_pages: usize,
}

pub(super) fn unnamed<'a>(record: &MftRecord<'a>, kind: u32) -> Result<Attribute<'a>> {
    for a in record.attributes() {
        if a?.kind == 0xc0 {
            return Err(Error::Unsupported);
        }
    }
    record.stream(kind, &[])
}
pub(super) fn mapped(attr: Attribute<'_>, boot: BootSector, offset: u64, length: u64) -> Result<u64> {
    let mut physical = None;
    plan_nonresident_overwrite(attr, boot, offset, length, |span| {
        if physical.replace(span.physical_offset).is_some() {
            return Err(Error::Unsupported);
        }
        Ok(())
    })?;
    physical.ok_or(Error::InvalidRunlist)
}

impl Writer {
    /// Borrow a naming policy for one serialized operation. The journal and
    /// allocator are never copied. Tx captures the policy before any I/O.
    pub fn with_compatibility<T>(&mut self, linux: bool, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let previous = self.linux_compatibility;
        self.linux_compatibility = linux;
        let result = operation(self);
        self.linux_compatibility = previous;
        result
    }

    /// Mount policy is fixed before initialization; it never rewrites metadata.
    pub fn set_linux_compatibility(&mut self, enabled: bool) -> Result<()> {
        if self.initialized {
            return Err(Error::Unsupported);
        }
        self.linux_compatibility = enabled;
        Ok(())
    }
    pub fn linux_compatibility(&self) -> bool {
        self.linux_compatibility
    }

    /// No writes. Admit an uninitialized journal, our empty checkpoint, or
    /// a validated clean Windows journal. Dirty histories require recovery.
    pub fn prepare<R: ReadAt>(io: &mut R, boot: BootSector, scratch: &mut [u8]) -> Result<Self> {
        Self::prepare_with_diagnostics(io, boot, scratch, |_| {})
    }

    /// Same safety checks as prepare; reports unsupported admission without disk writes.
    pub fn prepare_with_diagnostics<R: ReadAt>(
        io: &mut R,
        boot: BootSector,
        scratch: &mut [u8],
        rejection: impl FnMut(&'static str),
    ) -> Result<Self> {
        let mut writer = Self::BLANK;
        // The by-value form serves tools and tests, which run a writer for
        // the life of the process: its journal map storage is never returned.
        #[cfg(feature = "std")]
        writer.attach_journal_map(std::boxed::Box::leak(std::vec![0; JOURNAL_MAP_WORDS].into_boxed_slice()));
        writer.prepare_in(io, boot, scratch, rejection)?;
        Ok(writer)
    }

    /// A writer admitted to nothing: the value storage holds before
    /// `prepare_in` fills it. Every operation on it fails.
    pub const BLANK: Self = Self {
        linux_compatibility: false,
        boot: BootSector {
            bytes_per_sector: 0,
            sectors_per_cluster: 0,
            cluster_bytes: 0,
            total_sectors: 0,
            mft_lcn: 0,
            mft_mirror_lcn: 0,
            record_bytes: 0,
            index_block_bytes: 0,
            serial_number: 0,
        },
        log: LogMap::EMPTY,
        journal_storage: None,
        log_bytes: 0,
        volume: 0,
        mirror: 0,
        volume_flags: 0,
        current_lsn: 0,
        checkpoint_lsn: 0,
        data_dirty: false,
        exposure_dirty: false,
        log_unflushed: false,
        allocated_delta: 0,
        windows: [(0, 0, 0); 32],
        committed: Batch::new(),
        next_record: 0,
        next_cluster: 0,
        initialized: false,
        failed: true,
        resume_log: false,
        reset_clean_log: false,
        parked: false,
        batch: Batch::new(),
        log_pages: 0,
    };

    /// `prepare_with_diagnostics` into a writer the caller already holds,
    /// normally a copy of `BLANK`. A writer is several kilobytes; filled in
    /// place, none lies on the stack beneath the admission scans, which a
    /// kernel stack cannot afford. On an error the writer stays unusable.
    pub fn prepare_in<R: ReadAt>(
        &mut self,
        io: &mut R,
        boot: BootSector,
        scratch: &mut [u8],
        mut rejection: impl FnMut(&'static str),
    ) -> Result<()> {
        if scratch.len() < SCRATCH_BYTES || !boot.writable_geometry() {
            rejection("unsupported write geometry: requires 4 KiB index blocks and 1 KiB or 4 KiB file records");
            return Err(Error::Unsupported);
        }
        let record_bytes = boot.record_bytes as usize;
        let (record_span, cluster) = (u64::from(boot.record_bytes), u64::from(boot.cluster_bytes));
        let (zero, rest) = scratch.split_at_mut(super::volume::mft_space_bytes(record_bytes));
        let (raw, rest) = rest.split_at_mut(record_bytes);
        let (other, rest) = rest.split_at_mut(4096);
        let (upcase, directory_work) = rest.split_at_mut(UPCASE_BYTES);
        let mut volume = Volume::new(&mut *io, boot)?;
        let mft = volume.load_mft(zero)?;
        let mft_data = unnamed(&mft, ATTR_DATA)?;
        let mft_bitmap = unnamed(&mft, ATTR_BITMAP)?;
        volume.read_mft_record(&mft, 3, raw)?;
        let record = MftRecord::parse(raw, 512)?;
        let info = VolumeInfo::from_record(&record)?;
        if !info.supports_writes() {
            let reason = if (info.major_version, info.minor_version) != (3, 1) {
                "unsupported NTFS version: writable admission requires NTFS 3.1"
            } else if info.is_dirty() {
                "volume is dirty: offline journal recovery is required before writable admission"
            } else {
                "unsupported volume flags: writable admission accepts only the supported short-name setting on a clean volume"
            };
            rejection(reason);
            return Err(Error::Unsupported);
        }
        let volume_offset = mapped(mft_data, boot, VOLUME_RECORD * record_span, record_span)?;
        volume.read_mft_record(&mft, 2, raw)?;
        let record = MftRecord::parse(raw, 512)?;
        let data = unnamed(&record, ATTR_DATA)?;
        let log_bytes = data.data_size()?;
        if !supported_log_bytes(log_bytes) {
            rejection("unsupported journal size: requires a 4 KiB-aligned journal between 192 KiB and 4 GiB");
            return Err(Error::Unsupported);
        }
        let storage = self.journal_storage.take();
        self.log.fill(storage, data, log_bytes, cluster).inspect_err(|_| {
            rejection("unsupported journal layout: the journal has a hole or more pieces than its map holds");
        })?;
        let log = &self.log;
        volume.read_attribute(data, 0, other)?;
        let mut reset_clean_log = false;
        let mut clean_head = 0;
        let resume_lsn = if other.iter().all(|b| *b == 0xff) {
            // A never-used journal is blank throughout. Read it in large
            // spans: one device request each instead of one per page.
            let span = &mut directory_work[..SCAN_SPAN_BYTES];
            let mut offset = 4096;
            while offset < log_bytes {
                let n = (log_bytes - offset).min(SCAN_SPAN_BYTES as u64) as usize;
                volume.read_attribute(data, offset, &mut span[..n])?;
                if !span[..n].iter().all(|b| *b == 0xff) {
                    rejection("journal lacks a valid initialized restart pair");
                    return Err(Error::Unsupported);
                }
                offset += n as u64;
            }
            None
        } else {
            volume.read_attribute(data, 4096, &mut upcase[..4096])?;
            let identical = other == &upcase[..4096];
            let a = RestartPage::parse(other, 512)?;
            let b = RestartPage::parse(&mut upcase[..4096], 512)?;
            if a.chkdsk_marker && b.chkdsk_marker {
                // A checker verified the volume and voided the log history.
                // Start the log over above its marker, as Windows does at mount.
                if a.current_lsn != b.current_lsn {
                    return Err(Error::InvalidLog);
                }
                reset_clean_log = true;
                clean_head = a.current_lsn;
                None
            } else {
                let restart = if a.current_lsn >= b.current_lsn { a } else { b };
                if restart.log_bytes != log_bytes
                    || a.log_bytes != b.log_bytes
                    || a.system_page_bytes != b.system_page_bytes
                    || a.log_page_bytes != b.log_page_bytes
                    || a.sequence_bits != b.sequence_bits
                    || (a.major_version, a.minor_version) != (b.major_version, b.minor_version)
                    || a.chkdsk_marker
                    || b.chkdsk_marker
                    || (a.current_lsn == b.current_lsn && a != b)
                {
                    return Err(Error::InvalidLog);
                }
                // The standard clean-shutdown flag is meaningful only after USA
                // validation. Require both copies: never discard history on the
                // strength of a possibly stale clean copy beside a torn one.
                let clean = |page: &[u8], r: RestartPage| -> Result<bool> {
                    let flags = u16_at(page, usize::from(u16_at(page, 0x18)?) + 0x0e)?;
                    Ok(!r.active_clients || flags & 2 != 0)
                };
                let clean_pair = clean(other, a)? && clean(&upcase[..4096], b)?;
                let own_checkpoint = if identical {
                    if let Ok(at) = empty_checkpoint_offset(restart) {
                        volume.read_attribute(data, at / 4096 * 4096, other)?;
                        validate_empty_checkpoint(other, restart, at).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                };
                if own_checkpoint {
                    Some(restart.current_lsn)
                } else {
                    if !clean_pair
                        || restart.system_page_bytes != 4096
                        || restart.log_page_bytes != 4096
                        || !matches!((restart.major_version, restart.minor_version), (1, 1) | (2, 0))
                    {
                        rejection("journal requires recovery or has unsupported restart-page geometry/version");
                        return Err(Error::Unsupported);
                    }
                    reset_clean_log = true;
                    clean_head = restart.current_lsn;
                    None
                }
            }
        };
        let mirror_base = boot.mft_mirror_lcn.checked_mul(cluster).ok_or(Error::Overflow)?;
        // No piece may hold the boot sector, the mirror or any part of the table.
        if log.overlaps(0, 512) || log.overlaps(mirror_base, mirror_base + boot.mirror_bytes()) {
            return Err(Error::InvalidRunlist);
        }
        plan_nonresident_overwrite(mft_data, boot, 0, mft_data.initialized_size()?, |span| {
            if log.overlaps(span.physical_offset, span.physical_offset + span.length) {
                return Err(Error::InvalidRunlist);
            }
            Ok(())
        })?;
        // Audit allocated MFT records and derive a generation above all live
        // record LSNs, not just the first file selected by a caller.
        let records = mft_data.initialized_size()? / record_span;
        if records > 1_048_576 || mft_bitmap.data_size()? * 8 < records {
            rejection("MFT exceeds the writer audit limit or has an insufficient allocation bitmap");
            return Err(Error::Unsupported);
        }
        let mut max_lsn = clean_head;
        volume.scan_mft_records(&mft, 0, &mut directory_work[..SCAN_SPAN_BYTES], |_, raw| {
            max_lsn = max_lsn.max(u64_at(raw, 8)?);
            let record = MftRecord::parse(raw, 512)?;
            if record.flags()? & 1 == 0 {
                return Err(Error::InvalidRecord);
            }
            for attr in record.attributes() {
                attr?;
            }
            Ok(true)
        })?;
        volume.read_mft_record(&mft, 10, raw)?;
        let record = MftRecord::parse(raw, 512)?;
        volume.read_attribute(unnamed(&record, ATTR_DATA)?, 0, upcase)?;
        let table = UpcaseTable::parse(upcase)?;
        volume.read_mft_record(&mft, 5, raw)?;
        let root = MftRecord::parse(raw, 512)?;
        volume.visit_directory(&root, directory_work, |entry| {
            // Safety markers are case-insensitive even for POSIX-namespace
            // directory entries. Ordinary lookup still preserves POSIX case.
            let name = super::index::FileName { namespace: 1, utf16le: entry.name.utf16le };
            if table.matches(name, &[104, 105, 98, 101, 114, 102, 105, 108, 46, 115, 121, 115]) {
                rejection("hiberfil.sys present: writable admission refused");
                return Err(Error::Unsupported);
            }
            Ok(())
        })?;
        // $Extend must contain no change journal: USN updates are not implemented.
        volume.read_mft_record(&mft, 11, raw)?;
        let extend = MftRecord::parse(raw, 512)?;
        volume.visit_directory(&extend, directory_work, |entry| {
            let name = super::index::FileName { namespace: 1, utf16le: entry.name.utf16le };
            if table.matches(name, &[36, 85, 115, 110, 74, 114, 110, 108]) {
                rejection("USN journal present: writable USN updates are not supported");
                return Err(Error::Unsupported);
            }
            Ok(())
        })?;
        drop(volume);
        // Validate the mirror against exact original bytes before initialization.
        for number in 0..boot.mirrored_bytes() / record_span {
            let address = mapped(mft_data, boot, number * record_span, record_span)?;
            io.read_exact_at(address, raw)?;
            io.read_exact_at(mirror_base + number * record_span, &mut other[..record_bytes])?;
            if raw != &other[..record_bytes] {
                return Err(Error::InvalidRecord);
            }
        }
        let bits = (64 - log_bytes.leading_zeros()) - 3;
        if resume_lsn.is_some_and(|lsn| lsn < max_lsn) {
            return Err(Error::InvalidLog);
        }
        let generation = (max_lsn >> bits).checked_add(1).ok_or(Error::Overflow)?;
        if generation > u64::MAX >> bits {
            return Err(Error::Overflow);
        }
        let first_lsn = resume_lsn.unwrap_or((generation << bits) | ((4 * 4096 + 64) / 8));
        self.boot = boot;
        self.log_bytes = log_bytes;
        self.volume = volume_offset;
        self.mirror = mirror_base + VOLUME_RECORD * record_span;
        self.volume_flags = info.flags;
        self.current_lsn = first_lsn;
        self.checkpoint_lsn = first_lsn;
        self.next_record = super::mft_growth::FIRST_USER_RECORD;
        self.next_cluster = 1;
        self.resume_log = resume_lsn.is_some();
        self.reset_clean_log = reset_clean_log;
        self.log_pages = (log_bytes / 4096).saturating_sub(6) as usize;
        self.linux_compatibility = false;
        self.failed = false;
        Ok(())
    }

    /// Initialize before publishing a writable superblock. An error poisons
    /// the session; subsequent writes are prohibited, including after a flush error.
    pub fn initialize<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        if self.initialized || self.failed || scratch.len() < SCRATCH_BYTES {
            return Err(Error::Unsupported);
        }
        self.failed = true;
        let (page, rest) = scratch.split_at_mut(4096);
        let (payload, rest) = rest.split_at_mut(4096);
        if !self.resume_log {
            if self.reset_clean_log {
                // No metadata has changed, and both original restart pages
                // still certify clean shutdown. Remove obsolete records and
                // tail copies before publishing our higher-generation head.
                // A failure here leaves metadata untouched and admission can
                // retry from the original clean pair. Never erase the pair.
                // Each write covers as much of one piece as the buffer holds.
                let blank = rest.len().min(MAX_WRITE) / LOG_PAGE as usize * LOG_PAGE as usize;
                rest[..blank].fill(0xff);
                let mut at = RESTART_PAIR_BYTES;
                while at < self.log_bytes {
                    let (physical, run) = self.log.span(at)?;
                    let n = run.min(self.log_bytes - at).min(blank as u64);
                    io.write_at(physical, &rest[..n as usize])?;
                    at += n;
                }
                io.flush()?;
            }
            payload[..64].fill(0);
            payload[..4].copy_from_slice(&1_u32.to_le_bytes());
            payload[8..16].copy_from_slice(&self.current_lsn.to_le_bytes());
            let n = encode_lfs_record(
                &LfsRecordInput {
                    this_lsn: self.current_lsn,
                    previous_lsn: 0,
                    undo_next_lsn: 0,
                    client_sequence: 0,
                    client_index: 0,
                    record_type: 2,
                    transaction_id: 0,
                    flags: 0,
                    payload: &payload[..64],
                },
                rest,
            )?;
            record_page(io, &self.log, Slot { offset: 4 * 4096, lsn: self.current_lsn }, &rest[..n], 0, page)?;
            io.write_at(self.log.at(4 * 4096)?, page)?;
            io.flush()?;
            encode_initial_restart(page, self.log_bytes, self.current_lsn)?;
            write_restarts(io, &self.log, page)?;
        } else {
            io.read_exact_at(self.log.at(0)?, page)?;
            set_restart_clean(page, 512, false)?;
            write_restarts(io, &self.log, page)?;
        }
        self.initialized = true;
        self.publish_volume_flag(io, self.volume_flags, self.volume_flags | VOLUME_IS_DIRTY, scratch)?;
        self.checkpoint(io, scratch)
    }

    /// Both copies are covered by the native log before either is changed.
    /// Recovery can complete a committed flag change even if only one copy
    /// reached disk. Keep this transition inside the existing transaction path.
    fn publish_volume_flag<I: WriteIo>(&mut self, io: &mut I, old: u16, new: u16, scratch: &mut [u8]) -> Result<()> {
        let record_bytes = self.boot.record_bytes as usize;
        let (before, rest) = scratch.split_at_mut(record_bytes);
        let (after, journal) = rest.split_at_mut(record_bytes);
        io.read_exact_at(self.volume, before)?;
        io.read_exact_at(self.mirror, after)?;
        if before != after {
            return Err(Error::InvalidRecord);
        }
        MftRecord::parse(before, 512)?;
        let record = MftRecord::from_decoded(before)?;
        if VolumeInfo::from_record(&record)?.flags != old {
            return Err(Error::Unsupported);
        }
        let attr = unnamed(&record, 0x70)?;
        let offset = attr.record_offset() + attr.resident_value_offset()? + 10;
        after.copy_from_slice(before);
        after[offset..offset + 2].copy_from_slice(&new.to_le_bytes());
        io.read_exact_at(self.boot.mft_byte_offset()?, &mut journal[..record_bytes])?;
        let sequence = MftRecord::parse(&mut journal[..record_bytes], 512)?.sequence_number()?;
        self.failed = false;
        let result = self.commit_barrier(
            io,
            &mut [super::metadata_tx::MetadataPatch {
                fresh: false,
                physical: self.volume,
                logical: VOLUME_RECORD * record_bytes as u64,
                stream_reference: u64::from(sequence) << 48,
                mft: true,
                attribute_kind: 0x80,
                name: &[],
                before,
                after,
            }],
            journal,
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Replace the volume label ($VOLUME_NAME in $Volume). The change is
    /// journaled like the dirty flag: both MFT copies are covered by the log
    /// before either is changed, and the result is checkpointed at once so
    /// tools that read the raw device (blkid, udisks) see the new name.
    /// The adapter authorizes the caller and serializes the call.
    pub fn set_volume_label<I: WriteIo>(&mut self, io: &mut I, label: &[u16], scratch: &mut [u8]) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        if label.len() > MAX_LABEL_UNITS || label.contains(&0) {
            return Err(Error::Unsupported);
        }
        // Start from durable state: no newer image of $Volume is pending.
        self.checkpoint(io, scratch)?;
        let record_bytes = self.boot.record_bytes as usize;
        let (before, rest) = scratch.split_at_mut(record_bytes);
        let (after, rest) = rest.split_at_mut(record_bytes);
        let (value, journal) = rest.split_at_mut(2 * MAX_LABEL_UNITS + 8);
        io.read_exact_at(self.volume, before)?;
        io.read_exact_at(self.mirror, after)?;
        if before != after {
            return Err(Error::InvalidRecord);
        }
        MftRecord::parse(before, 512)?;
        let bytes = 2 * label.len();
        for (i, unit) in label.iter().enumerate() {
            value[2 * i..2 * i + 2].copy_from_slice(&unit.to_le_bytes());
        }
        after.copy_from_slice(before);
        match super::record_edit::find(after, ATTR_VOLUME_NAME, &[])? {
            Some(at) => {
                if super::record_edit::resident_value(after, at)? == &value[..bytes] {
                    return Ok(());
                }
                super::record_edit::set_resident_value(after, at, &value[..bytes])?;
            }
            None => {
                if bytes == 0 {
                    return Ok(());
                }
                let mut image = [0u8; 2 * MAX_LABEL_UNITS + 32];
                let n = super::record_edit::build_resident(ATTR_VOLUME_NAME, &[], &value[..bytes], &mut image)?;
                super::record_edit::insert(after, &image[..n])?;
            }
        }
        super::record_edit::validate(after)?;
        io.read_exact_at(self.boot.mft_byte_offset()?, &mut journal[..record_bytes])?;
        let sequence = MftRecord::parse(&mut journal[..record_bytes], 512)?.sequence_number()?;
        let result = self.commit_barrier(
            io,
            &mut [super::metadata_tx::MetadataPatch {
                fresh: false,
                physical: self.volume,
                logical: VOLUME_RECORD * record_bytes as u64,
                stream_reference: u64::from(sequence) << 48,
                mft: true,
                attribute_kind: ATTR_VOLUME_NAME,
                name: &[],
                before,
                after,
            }],
            journal,
        );
        if result.is_err() {
            self.failed = true;
            return result;
        }
        self.checkpoint(io, scratch)
    }

    /// Called only after VFS has quiesced all mutations. A clean flag is
    /// published only for our durable empty checkpoint and a healthy session.
    pub fn finish<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        if !self.initialized || self.failed || scratch.len() < SCRATCH_BYTES {
            return Err(Error::Io);
        }
        for i in 0..self.windows.len() {
            let reference = self.windows[i].0;
            if reference != 0 {
                self.trim(io, reference, scratch)?;
            }
        }
        self.checkpoint(io, scratch)?;
        self.failed = true;
        let (page, rest) = scratch.split_at_mut(4096);
        let verify = &mut rest[..4096];
        io.read_exact_at(self.log.at(0)?, page)?;
        io.read_exact_at(self.log.at(4096)?, verify)?;
        if page != verify {
            return Err(Error::InvalidLog);
        }
        let restart = RestartPage::parse(page, 512)?;
        if restart.current_lsn != self.current_lsn {
            return Err(Error::InvalidLog);
        }
        let at = empty_checkpoint_offset(restart)?;
        io.read_exact_at(self.log.at(at / 4096 * 4096)?, page)?;
        validate_empty_checkpoint(page, restart, at)?;
        self.publish_volume_flag(io, self.volume_flags | VOLUME_IS_DIRTY, self.volume_flags, scratch)?;
        self.checkpoint(io, scratch)?;
        // All metadata and the final checkpoint are durable before either
        // restart copy advertises clean shutdown to Windows or ntfs-3g.
        self.failed = true;
        let page = &mut scratch[..4096];
        io.read_exact_at(self.log.at(0)?, page)?;
        set_restart_clean(page, 512, true)?;
        write_restarts(io, &self.log, page)?;
        self.initialized = false;
        self.failed = false;
        Ok(())
    }

    /// True once an error has ended the session; every later change is refused.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// True while an idle session rests in the published clean state.
    pub fn parked(&self) -> bool {
        self.parked
    }

    /// Lend storage for the journal map before admission: JOURNAL_MAP_WORDS
    /// holds any journal. Without it a journal of more than a few pieces is
    /// refused. The storage must outlive the writer.
    pub fn attach_journal_map(&mut self, storage: &'static mut [u64]) {
        self.journal_storage = Some(storage);
    }

    /// Pieces the journal lies in on the device.
    pub fn journal_pieces(&self) -> usize {
        self.log.piece_count()
    }

    /// Bytes of the log consumed so far; any journaled change advances it.
    pub fn activity(&self) -> u64 {
        self.current_lsn
    }

    /// Publish the clean state of an idle session without ending it, so an
    /// unplugged idle volume needs no recovery. The caller guarantees that
    /// no file is open for writing. This is the unmount sequence; resume is
    /// the matching mount sequence.
    pub fn park<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        if self.parked {
            return Ok(());
        }
        self.finish(io, scratch)?;
        self.parked = true;
        Ok(())
    }

    /// Mark the volume dirty again before the first change after park. The
    /// session continues from its own clean checkpoint, as a new mount would.
    pub fn resume<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<()> {
        if !self.parked {
            return Ok(());
        }
        self.parked = false;
        self.resume_log = true;
        self.reset_clean_log = false;
        let result = self.initialize(io, scratch);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

fn empty_checkpoint_offset(restart: RestartPage) -> Result<u64> {
    reserve_resident(restart)?;
    let client = restart.client.ok_or(Error::InvalidLog)?;
    if client.index != 0 || client.sequence != 0 || restart.chkdsk_marker {
        return Err(Error::Unsupported);
    }
    lsn_stream_offset(restart.current_lsn, restart.sequence_bits, restart.log_bytes)
}
fn validate_empty_checkpoint(page: &mut [u8], restart: RestartPage, at: u64) -> Result<()> {
    let page = RecordPage::parse(page, 512, 64)?;
    if page.page_count != 1 || page.last_lsn != restart.current_lsn || page.last_end_lsn != restart.current_lsn {
        return Err(Error::InvalidLog);
    }
    let record = page.contained_record_at((at % 4096) as usize)?;
    if record.this_lsn != restart.current_lsn
        || record.record_type != 2
        || record.client_index != 0
        || record.client_sequence != 0
    {
        return Err(Error::InvalidLog);
    }
    let cp = NtfsCheckpoint::parse(record.payload())?;
    if cp.start_lsn != restart.current_lsn
        || cp.open_attributes_lsn != 0
        || cp.attribute_names_lsn != 0
        || cp.dirty_pages_lsn != 0
        || cp.transactions_lsn != 0
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// Publish the secondary durably before replacing the primary.
/// Where the journal lies on the device. Windows keeps it in one piece when
/// it can, but a journal it grew on a full volume lies in many; every page of
/// the journal is reached through this map.
///
/// The pieces live in storage the mount lends for the session
/// (`Writer::attach_journal_map`), two words each, so the map has no limit of
/// its own and is small enough to copy: a transaction, which lives on a
/// kernel stack, carries the same view of every piece. Without lent storage
/// the map holds `INLINE_PIECES` itself, enough for the tools and tests.
#[derive(Clone, Copy, Debug)]
pub struct LogMap {
    lent: Option<&'static [u64]>,
    inline: [LogPiece; INLINE_PIECES],
    count: usize,
}

/// One extent of the journal: its first page within the journal, its length
/// in pages and its byte offset on the device. A journal is below 4 GiB, so
/// page counts fit 32 bits.
#[derive(Clone, Copy, Debug, Default)]
struct LogPiece {
    first_page: u32,
    pages: u32,
    start: u64,
}

impl LogPiece {
    /// Whether the device range [start, end) touches this piece.
    fn overlaps(&self, start: u64, end: u64) -> bool {
        start < self.start + u64::from(self.pages) * LOG_PAGE && self.start < end
    }
    /// The two words a piece occupies in lent storage.
    fn words(&self) -> [u64; PIECE_WORDS] {
        [u64::from(self.first_page) | u64::from(self.pages) << 32, self.start]
    }
    fn from_words(words: &[u64]) -> Self {
        Self { first_page: words[0] as u32, pages: (words[0] >> 32) as u32, start: words[1] }
    }
}

const INLINE_PIECES: usize = 4;
const PIECE_WORDS: usize = 2;
const LOG_PAGE: u64 = LOG_PAGE_BYTES;
/// The two restart pages at the head of the journal.
const RESTART_PAIR_BYTES: u64 = 2 * LOG_PAGE;
/// The shortest mapping pair: a header byte, one length byte, one offset byte.
const SHORTEST_RUN_BYTES: usize = 3;
/// Words of storage that hold the map of any journal the writer admits. The
/// journal is mapped by its base record alone, so no layout has more pieces
/// than the largest file record has room for mapping pairs.
pub const JOURNAL_MAP_WORDS: usize = PIECE_WORDS * (super::boot::MAX_WRITER_RECORD_BYTES / SHORTEST_RUN_BYTES);

impl LogMap {
    const EMPTY: Self = Self { lent: None, inline: [LogPiece { first_page: 0, pages: 0, start: 0 }; INLINE_PIECES], count: 0 };

    /// Map a journal of the given size from its unnamed DATA attribute into
    /// the storage, or into the map itself when none was lent. Adjacent runs
    /// count as one piece. A hole is damage, not a layout: Windows never
    /// leaves one in its journal.
    fn fill(
        &mut self,
        mut storage: Option<&'static mut [u64]>,
        data: Attribute<'_>,
        bytes: u64,
        cluster: u64,
    ) -> Result<()> {
        if !data.nonresident || data.first_vcn()? != 0 || data.flags()? != 0 {
            return Err(Error::Unsupported);
        }
        *self = Self::EMPTY;
        let capacity = storage.as_ref().map_or(INLINE_PIECES, |words| words.len() / PIECE_WORDS);
        let pages = bytes / LOG_PAGE;
        let mut covered = 0_u64;
        let mut last: Option<LogPiece> = None;
        let mut put = |index: usize, piece: LogPiece, inline: &mut [LogPiece; INLINE_PIECES]| match storage.as_deref_mut() {
            Some(words) => words[index * PIECE_WORDS..(index + 1) * PIECE_WORDS].copy_from_slice(&piece.words()),
            None => inline[index] = piece,
        };
        for run in super::runlist::DataRuns::new(data.data_runs()?, 0) {
            let run = run?;
            if covered >= pages {
                break;
            }
            // A piece holds whole pages: a page split between two runs of
            // small clusters is a layout the map does not describe.
            let run_bytes = run.len.checked_mul(cluster).ok_or(Error::Overflow)?;
            if run.vcn * cluster != covered * LOG_PAGE || (run_bytes % LOG_PAGE != 0 && run_bytes < (pages - covered) * LOG_PAGE) {
                return Err(Error::Unsupported);
            }
            let start = run.lcn.ok_or(Error::Unsupported)?.checked_mul(cluster).ok_or(Error::Overflow)?;
            let length = (run_bytes / LOG_PAGE).min(pages - covered);
            let piece = match last {
                Some(previous) if previous.start + u64::from(previous.pages) * LOG_PAGE == start => {
                    LogPiece { pages: previous.pages + length as u32, ..previous }
                }
                _ => {
                    if self.count == capacity {
                        return Err(Error::Unsupported);
                    }
                    self.count += 1;
                    LogPiece { first_page: covered as u32, pages: length as u32, start }
                }
            };
            put(self.count - 1, piece, &mut self.inline);
            last = Some(piece);
            covered += length;
        }
        if covered != pages {
            return Err(Error::InvalidRunlist);
        }
        // Filled once; from here the storage is only read.
        self.lent = storage.map(|words| &*words);
        Ok(())
    }

    fn piece(&self, index: usize) -> LogPiece {
        match self.lent {
            Some(words) => LogPiece::from_words(&words[index * PIECE_WORDS..(index + 1) * PIECE_WORDS]),
            None => self.inline[index],
        }
    }

    /// Device offset of the journal byte at an offset in the journal.
    pub(super) fn at(&self, offset: u64) -> Result<u64> {
        Ok(self.span(offset)?.0)
    }

    /// Device offset of a journal byte, and how many bytes from it on lie
    /// together on the device.
    pub(super) fn span(&self, offset: u64) -> Result<(u64, u64)> {
        let page = offset / LOG_PAGE;
        // Binary search for the last piece that starts at or before the page.
        let (mut low, mut high) = (0, self.count);
        while low < high {
            let middle = low + (high - low) / 2;
            if u64::from(self.piece(middle).first_page) <= page {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let piece = low.checked_sub(1).map(|index| self.piece(index)).ok_or(Error::InvalidLog)?;
        let within = page - u64::from(piece.first_page);
        if within >= u64::from(piece.pages) {
            return Err(Error::InvalidLog);
        }
        let inside = offset % LOG_PAGE;
        Ok((piece.start + within * LOG_PAGE + inside, (u64::from(piece.pages) - within) * LOG_PAGE - inside))
    }

    /// Whether the device range [start, end) touches the journal.
    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        (0..self.count).any(|index| self.piece(index).overlaps(start, end))
    }

    /// Number of pieces, for diagnostics and tests.
    pub fn piece_count(&self) -> usize {
        self.count
    }
}

pub(super) fn write_restarts<I: WriteIo>(io: &mut I, log: &LogMap, restart: &[u8]) -> Result<()> {
    for at in [log.at(4096)?, log.at(0)?] {
        io.write_at(at, restart)?;
        io.flush()?;
    }
    Ok(())
}

pub(super) fn record_page<I: ReadAt>(
    io: &mut I,
    log: &LogMap,
    slot: Slot,
    record: &[u8],
    fragment: usize,
    page: &mut [u8],
) -> Result<()> {
    io.read_exact_at(log.at(slot.offset)?, page)?;
    let sequence = if page.iter().all(|b| *b == 0xff) {
        1
    } else {
        let usa = u16_at(page, 4)? as usize;
        let old = u16_at(page, usa)?;
        // Require valid obsolete contents before reusing a page.
        let parsed = RecordPage::parse(page, 512, 64)?;
        if parsed.last_lsn >= slot.lsn {
            return Err(Error::InvalidLog);
        }
        old.wrapping_add(1).max(1)
    };
    if LfsRecord::parse(record)?.multi_page {
        encode_record_fragment(page, slot.offset as u32, record, fragment)?;
    } else {
        encode_single_record_page(page, 512, 64, slot.offset as u32, record)?;
    }
    page[40..42].copy_from_slice(&sequence.to_le_bytes());
    for i in 1..=8 {
        page[i * 512 - 2..i * 512].copy_from_slice(&sequence.to_le_bytes());
    }
    Ok(())
}
