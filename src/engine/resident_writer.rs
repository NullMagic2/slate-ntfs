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
pub const MAX_WRITE: usize = 1 << 20;
/// $VOLUME_NAME: up to 128 UTF-16 code units (Windows shows at most 32).
pub const ATTR_VOLUME_NAME: u32 = 0x60;
pub const MAX_LABEL_UNITS: usize = 128;
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
    pub(super) log: u64,
    pub(super) log_bytes: u64,
    volume: u64,
    mirror: u64,
    // Preserve admitted Windows settings across dirty/clean journal transitions.
    volume_flags: u16,
    pub(super) current_lsn: u64,
    pub(super) checkpoint_lsn: u64,
    pub(super) data_dirty: bool,
    pub(super) exposure_dirty: bool,
    // (file reference, zeroed-from, zeroed-to, durable). References remain
    // tracked after invalidation so finish can return unused preallocation.
    pub(super) windows: [(u64, u64, u64, bool); 32],
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
fn overlap(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    a < b.saturating_add(blen) && b < a.saturating_add(alen)
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
        mut rejection: impl FnMut(&'static str),
    ) -> Result<Self> {
        if scratch.len() < SCRATCH_BYTES
            || boot.bytes_per_sector != 512
            || boot.record_bytes != 1024
            || boot.cluster_bytes != 4096
            || boot.index_block_bytes != 4096
        {
            rejection("unsupported write geometry: requires 512-byte sectors, 4096-byte clusters/index blocks and 1024-byte records");
            return Err(Error::Unsupported);
        }
        let (zero, rest) = scratch.split_at_mut(1024);
        let (raw, rest) = rest.split_at_mut(1024);
        let (other, rest) = rest.split_at_mut(4096);
        let (upcase, directory_work) = rest.split_at_mut(UPCASE_BYTES);
        let mut volume = Volume::new(&mut *io, boot)?;
        volume.read_mft_zero(zero)?;
        let mft = MftRecord::parse(zero, 512)?;
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
        let volume_offset = mapped(mft_data, boot, 3072, 1024)?;
        volume.read_mft_record(&mft, 2, raw)?;
        let record = MftRecord::parse(raw, 512)?;
        let data = unnamed(&record, ATTR_DATA)?;
        let log_bytes = data.data_size()?;
        if !(196608..=64 * 1024 * 1024).contains(&log_bytes) || log_bytes % 4096 != 0 {
            rejection("unsupported journal size: requires a 4 KiB-aligned journal between 192 KiB and 64 MiB");
            return Err(Error::Unsupported);
        }
        let log = mapped(data, boot, 0, log_bytes).inspect_err(|_| {
            rejection("unsupported journal layout: writable admission requires a contiguous journal");
        })?;
        volume.read_attribute(data, 0, other)?;
        let mut reset_clean_log = false;
        let mut clean_head = 0;
        let resume_lsn = if other.iter().all(|b| *b == 0xff) {
            for offset in (4096..log_bytes).step_by(4096) {
                volume.read_attribute(data, offset, other)?;
                if !other.iter().all(|b| *b == 0xff) {
                    rejection("journal lacks a valid initialized restart pair");
                    return Err(Error::Unsupported);
                }
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
        let mirror_base = boot.mft_mirror_lcn.checked_mul(4096).ok_or(Error::Overflow)?;
        if log < 512 || overlap(log, log_bytes, mirror_base, 4096) {
            return Err(Error::InvalidRunlist);
        }
        plan_nonresident_overwrite(mft_data, boot, 0, mft_data.initialized_size()?, |span| {
            if overlap(log, log_bytes, span.physical_offset, span.length) {
                return Err(Error::InvalidRunlist);
            }
            Ok(())
        })?;
        // Audit allocated MFT records and derive a generation above all live
        // record LSNs, not just the first file selected by a caller.
        let records = mft_data.initialized_size()? / 1024;
        if records > 1_048_576 || mft_bitmap.data_size()? * 8 < records {
            rejection("MFT exceeds the writer audit limit or has an insufficient allocation bitmap");
            return Err(Error::Unsupported);
        }
        let mut max_lsn = clean_head;
        let mut bit = [0];
        for number in 0..records {
            volume.read_attribute(mft_bitmap, number / 8, &mut bit)?;
            if bit[0] & (1 << (number % 8)) == 0 {
                continue;
            }
            volume.read_mft_record(&mft, number, raw)?;
            max_lsn = max_lsn.max(u64_at(raw, 8)?);
            let record = MftRecord::parse(raw, 512)?;
            if record.flags()? & 1 == 0 {
                return Err(Error::InvalidRecord);
            }
            for attr in record.attributes() {
                attr?;
            }
        }
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
        for number in 0..4 {
            let address = mapped(mft_data, boot, number * 1024, 1024)?;
            io.read_exact_at(address, raw)?;
            io.read_exact_at(mirror_base + number * 1024, &mut other[..1024])?;
            if raw != &other[..1024] {
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
        Ok(Self {
            boot,
            log,
            log_bytes,
            volume: volume_offset,
            mirror: mirror_base + 3072,
            volume_flags: info.flags,
            current_lsn: resume_lsn.unwrap_or((generation << bits) | ((4 * 4096 + 64) / 8)),
            checkpoint_lsn: resume_lsn.unwrap_or((generation << bits) | ((4 * 4096 + 64) / 8)),
            data_dirty: false,
            exposure_dirty: false,
            windows: [(0, 0, 0, false); 32],
            committed: Batch::new(),
            next_record: super::mft_growth::FIRST_USER_RECORD,
            next_cluster: 1,
            initialized: false,
            linux_compatibility: false,
            failed: false,
            resume_log: resume_lsn.is_some(),
            reset_clean_log,
            parked: false,
            batch: Batch::new(),
            log_pages: (log_bytes / 4096).saturating_sub(6) as usize,
        })
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
                page.fill(0xff);
                for at in (8192..self.log_bytes).step_by(4096) {
                    io.write_at(self.log + at, page)?;
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
            record_page(io, self.log, Slot { offset: 4 * 4096, lsn: self.current_lsn }, &rest[..n], 0, page)?;
            io.write_at(self.log + 4 * 4096, page)?;
            io.flush()?;
            encode_initial_restart(page, self.log_bytes, self.current_lsn)?;
            write_restarts(io, self.log, page)?;
        } else {
            io.read_exact_at(self.log, page)?;
            set_restart_clean(page, 512, false)?;
            write_restarts(io, self.log, page)?;
        }
        self.initialized = true;
        self.publish_volume_flag(io, self.volume_flags, self.volume_flags | VOLUME_IS_DIRTY, scratch)?;
        self.checkpoint(io, scratch)
    }

    /// Both copies are covered by the native log before either is changed.
    /// Recovery can complete a committed flag change even if only one copy
    /// reached disk. Keep this transition inside the existing transaction path.
    fn publish_volume_flag<I: WriteIo>(&mut self, io: &mut I, old: u16, new: u16, scratch: &mut [u8]) -> Result<()> {
        let (before, rest) = scratch.split_at_mut(1024);
        let (after, journal) = rest.split_at_mut(1024);
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
        io.read_exact_at(self.boot.mft_byte_offset()?, &mut journal[..1024])?;
        let sequence = MftRecord::parse(&mut journal[..1024], 512)?.sequence_number()?;
        self.failed = false;
        let result = self.commit_barrier(
            io,
            &mut [super::metadata_tx::MetadataPatch {
                fresh: false,
                physical: self.volume,
                logical: 3072,
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
        let (before, rest) = scratch.split_at_mut(1024);
        let (after, rest) = rest.split_at_mut(1024);
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
        io.read_exact_at(self.boot.mft_byte_offset()?, &mut journal[..1024])?;
        let sequence = MftRecord::parse(&mut journal[..1024], 512)?.sequence_number()?;
        let result = self.commit_barrier(
            io,
            &mut [super::metadata_tx::MetadataPatch {
                fresh: false,
                physical: self.volume,
                logical: 3072,
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
        io.read_exact_at(self.log, page)?;
        io.read_exact_at(self.log + 4096, verify)?;
        if page != verify {
            return Err(Error::InvalidLog);
        }
        let restart = RestartPage::parse(page, 512)?;
        if restart.current_lsn != self.current_lsn {
            return Err(Error::InvalidLog);
        }
        let at = empty_checkpoint_offset(restart)?;
        io.read_exact_at(self.log + at / 4096 * 4096, page)?;
        validate_empty_checkpoint(page, restart, at)?;
        self.publish_volume_flag(io, self.volume_flags | VOLUME_IS_DIRTY, self.volume_flags, scratch)?;
        self.checkpoint(io, scratch)?;
        // All metadata and the final checkpoint are durable before either
        // restart copy advertises clean shutdown to Windows or ntfs-3g.
        self.failed = true;
        let page = &mut scratch[..4096];
        io.read_exact_at(self.log, page)?;
        set_restart_clean(page, 512, true)?;
        write_restarts(io, self.log, page)?;
        self.initialized = false;
        self.failed = false;
        Ok(())
    }

    /// True while an idle session rests in the published clean state.
    pub fn parked(&self) -> bool {
        self.parked
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
pub(super) fn write_restarts<I: WriteIo>(io: &mut I, log: u64, restart: &[u8]) -> Result<()> {
    for at in [log + 4096, log] {
        io.write_at(at, restart)?;
        io.flush()?;
    }
    Ok(())
}

pub(super) fn record_page<I: ReadAt>(
    io: &mut I,
    log: u64,
    slot: Slot,
    record: &[u8],
    fragment: usize,
    page: &mut [u8],
) -> Result<()> {
    io.read_exact_at(log + slot.offset, page)?;
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
