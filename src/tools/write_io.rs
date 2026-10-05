//! Module: slate_ntfs_tools::write_io
//! Purpose: Create native transactions on exclusively created disposable image copies.
//! Created: 2026-10-01
//! Architecture: Shares volume admission policy with the engine; laboratory I/O stays in
//! userspace.

use crate::{checker, recovery_io};
use checker::Image;
use ntfs_rs::boot::BootSector;
use ntfs_rs::bytes::u64_at;
use ntfs_rs::hibernation::{write_gate, HibernationWriteGate};
use ntfs_rs::logfile::{
    advance_restart_tail, encode_initial_restart, encode_lfs_record, encode_ntfs_operation, encode_single_record_page,
    supported_log_bytes, LfsRecordInput, LogState, NtfsLogOperation, NtfsOperationInput,
};
use ntfs_rs::mft::reference_number;
use ntfs_rs::mft::{Attribute, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA};
use ntfs_rs::replay::protect_mft_record;
use ntfs_rs::volume::{ReadAt, Volume};
use ntfs_rs::write_plan::plan_nonresident_overwrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn unnamed<'a>(record: &MftRecord<'a>, kind: u32) -> io::Result<Attribute<'a>> {
    for attr in record.attributes() {
        if matches!(attr?.kind, ATTR_ATTRIBUTE_LIST | 0xc0) {
            return Err(bad("attribute lists and reparse points are unsupported"));
        }
    }
    Ok(record.stream(kind, &[])?)
}
fn mapped(attr: Attribute<'_>, boot: BootSector, offset: u64, length: u64) -> io::Result<u64> {
    let mut spans = Vec::new();
    plan_nonresident_overwrite(attr, boot, offset, length, |s| {
        spans.push(s);
        Ok(())
    })?;
    if spans.len() != 1 {
        return Err(bad("write crosses an extent"));
    }
    Ok(spans[0].physical_offset)
}

#[derive(Debug, Eq, PartialEq)]
struct Layout {
    boot: BootSector,
    log: u64,
    log_bytes: u64,
    target: u64,
    logical: u64,
    mft_sequence: u16,
    record_offset: u16,
    attribute_offset: u16,
    target_lsn: u64,
    volume: u64,
    mirror: u64,
    volume_before: Vec<u8>,
    volume_dirty: Vec<u8>,
}

fn layout(path: &Path, name: &str, offset: usize, expected: &[u8]) -> io::Result<Layout> {
    let probe = checker::probe(path)?;
    let boot = probe.boot;
    if boot.bytes_per_sector != 512 || !probe.info.supports_writes() {
        return Err(bad("requires clean 512-byte-sector image"));
    }
    let recovery = checker::inspect_recovery(checker::Image::open(path)?, boot)?;
    if recovery.log != LogState::Uninitialized || write_gate(recovery.hibernation, false) != HibernationWriteGate::Clear
    {
        return Err(bad("requires uninitialized log and no hibernation"));
    }
    let mut volume = Volume::new(Image(File::open(path)?), boot)?;
    let mut zero = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut zero)?;
    let mft = MftRecord::parse(&mut zero, boot.bytes_per_sector)?;
    let mft_data = unnamed(&mft, ATTR_DATA)?;
    let mut root = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 5, &mut root)?;
    let root = MftRecord::parse(&mut root, boot.bytes_per_sector)?;
    let requested: Vec<u16> = name.encode_utf16().collect();
    let mut reference = None;
    volume.visit_directory(
        &root,
        &mut vec![0; boot.index_block_bytes as usize + 2 * ntfs_rs::tx::RECORD_IMAGE + 2 * boot.record_bytes as usize],
        |entry| {
            if entry.name.code_units().eq(requested.iter().copied())
                && reference.replace(entry.file_reference).is_some()
            {
                return Err(ntfs_rs::Error::InvalidIndex);
            }
            Ok(())
        },
    )?;
    let reference = reference.ok_or_else(|| bad("root file not found"))?;
    let number = reference_number(reference);
    if number < 16 {
        return Err(bad("system file is not a write target"));
    }
    let logical = number.checked_mul(u64::from(boot.record_bytes)).ok_or_else(|| bad("MFT offset overflow"))?;
    let target = mapped(mft_data, boot, logical, u64::from(boot.record_bytes))?;
    if logical % u64::from(boot.cluster_bytes) + u64::from(boot.record_bytes) > u64::from(boot.cluster_bytes) {
        return Err(bad("MFT record crosses a cluster"));
    }
    let mut allocated = [0];
    volume.read_attribute(unnamed(&mft, ATTR_BITMAP)?, number / 8, &mut allocated)?;
    if allocated[0] & (1 << (number % 8)) == 0 {
        return Err(bad("unallocated target"));
    }
    let mut record = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, number, &mut record)?;
    let target_lsn = u64_at(&record, 8)?;
    let record = MftRecord::parse(&mut record, boot.bytes_per_sector)?;
    if record.flags()? != 1
        || record.base_file_reference()? != 0
        || record.sequence_number()? != (reference >> 48) as u16
    {
        return Err(bad("target identity or flags changed"));
    }
    let data = unnamed(&record, ATTR_DATA)?;
    if data.nonresident || data.flags()? != 0 {
        return Err(bad("journaled mode currently requires ordinary resident data"));
    }
    let end = offset.checked_add(expected.len()).ok_or_else(|| bad("data offset overflow"))?;
    if data.resident_value()?.get(offset..end) != Some(expected) {
        return Err(bad("resident preimage mismatch"));
    }
    let record_offset = u16::try_from(data.record_offset()).map_err(|_| bad("record offset overflow"))?;
    let attribute_offset =
        u16::try_from(data.resident_value_offset()? + offset).map_err(|_| bad("attribute offset overflow"))?;
    let mut log_record = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 2, &mut log_record)?;
    let log_record = MftRecord::parse(&mut log_record, boot.bytes_per_sector)?;
    let log_data = unnamed(&log_record, ATTR_DATA)?;
    let log_bytes = log_data.data_size()?;
    if !supported_log_bytes(log_bytes) {
        return Err(bad("unsupported log size"));
    }
    let log = mapped(log_data, boot, 0, log_bytes)?;
    let mut volume_before = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 3, &mut volume_before)?;
    let mut volume_dirty = volume_before.clone();
    let vol_record = MftRecord::parse(&mut volume_dirty, boot.bytes_per_sector)?;
    let flags = unnamed(&vol_record, 0x70)?;
    let flag_offset = flags.record_offset() + flags.resident_value_offset()? + 10;
    if flags.resident_value()?.len() != 12 {
        return Err(bad("invalid volume information"));
    }
    // Change only the dirty bit; retain persistent Windows volume settings.
    let dirty_flags = probe.info.flags | ntfs_rs::volume_info::VOLUME_IS_DIRTY;
    volume_dirty[flag_offset..flag_offset + 2].copy_from_slice(&dirty_flags.to_le_bytes());
    protect_mft_record(&mut volume_dirty, boot.bytes_per_sector)?;
    let volume_offset = mapped(mft_data, boot, 3 * u64::from(boot.record_bytes), u64::from(boot.record_bytes))?;
    let mirror = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + 3 * u64::from(boot.record_bytes);
    let mut image = Image(File::open(path)?);
    let mut mirror_bytes = vec![0; volume_before.len()];
    image.read_exact_at(mirror, &mut mirror_bytes)?;
    if mirror_bytes != volume_before {
        return Err(bad("MFT mirror differs before write"));
    }
    let mut mft_spans = Vec::new();
    plan_nonresident_overwrite(mft_data, boot, 0, mft_data.initialized_size()?, |s| {
        mft_spans.push(s);
        Ok(())
    })?;
    if log < 512
        || mft_spans.iter().any(|s| log < s.physical_offset + s.length && log + log_bytes > s.physical_offset)
        || (log < mirror + u64::from(boot.record_bytes)
            && log + log_bytes > boot.mft_mirror_lcn * u64::from(boot.cluster_bytes))
    {
        return Err(bad("log aliases protected metadata"));
    }
    Ok(Layout {
        boot,
        log,
        log_bytes,
        target,
        logical,
        mft_sequence: mft.sequence_number()?,
        record_offset,
        attribute_offset,
        target_lsn,
        volume: volume_offset,
        mirror,
        volume_before,
        volume_dirty,
    })
}

fn write_at(file: &mut File, at: u64, bytes: &[u8]) -> io::Result<()> {
    file.seek(SeekFrom::Start(at))?;
    file.write_all(bytes)
}
fn page(lsn: u64, at: u32, payload: &[u8], kind: u32, tid: u32, previous: u64) -> io::Result<Vec<u8>> {
    // Windows recovery requires the LFS absent-buffer flags even when the
    // NTFS operation already carries zero redo/undo lengths. Restart records
    // contain a different payload and must not be interpreted as operations.
    let flags = if kind == 1 {
        let operation = NtfsLogOperation::parse(payload)?;
        u16::from(operation.redo.is_empty()) * 2 | u16::from(operation.undo.is_empty()) * 4
    } else {
        0
    };
    let mut record = vec![0; 48 + payload.len()];
    encode_lfs_record(
        &LfsRecordInput {
            this_lsn: lsn,
            previous_lsn: previous,
            undo_next_lsn: previous,
            client_sequence: 0,
            client_index: 0,
            record_type: kind,
            transaction_id: tid,
            flags,
            payload,
        },
        &mut record,
    )?;
    let mut page = vec![0; 4096];
    encode_single_record_page(&mut page, 512, 64, at, &record)?;
    Ok(page)
}
fn operation(code: u16, target: u16, redo: &[u8], undo: &[u8], lcn: &[u64], vcn: u64) -> io::Result<Vec<u8>> {
    let mut out = vec![0; 4096];
    let len = encode_ntfs_operation(
        &NtfsOperationInput {
            redo_code: code,
            undo_code: if code == 7 { 7 } else { 0 },
            target_attribute: target,
            target_vcn: vcn,
            lcns: lcn,
            redo,
            undo,
        },
        &mut out,
    )?;
    out.truncate(len);
    Ok(out)
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Create an actual native log transaction and recover/apply it through the
/// same engine used by ntfs-chkdsk. Only newly created image files are writable.
pub fn journaled_write_to(
    source: &Path,
    destination: &Path,
    name: &str,
    offset: usize,
    expected: &[u8],
    replacement: &[u8],
    stop_after: Option<usize>,
) -> io::Result<()> {
    if expected.is_empty() || expected.len() != replacement.len() || expected == replacement {
        return Err(bad("requires differing equal-length byte strings"));
    }
    let mut input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err(bad("source must be an offline regular image file"));
    }
    let planned = layout(source, name, offset, expected)?;
    checker::audit_mft_records(source, planned.boot)?;
    checker::check_known_structures(source, planned.boot)?;
    let bits = (64 - planned.log_bytes.leading_zeros()) - 3;
    let generation = (planned.target_lsn >> bits).checked_add(1).ok_or_else(|| bad("LSN overflow"))?;
    if generation > (u64::MAX >> bits) {
        return Err(bad("LSN generation overflow"));
    }
    let lsn = |page: u64| (generation << bits) | ((page * 4096 + 64) / 8);
    let mut checkpoint = vec![0; 64];
    checkpoint[..4].copy_from_slice(&1_u32.to_le_bytes());
    checkpoint[8..16].copy_from_slice(&lsn(4).to_le_bytes());
    let checkpoint = page(lsn(4), 4 * 4096, &checkpoint, 2, 0, 0)?;
    let mut restart = vec![0; 4096];
    encode_initial_restart(&mut restart, planned.log_bytes, lsn(4))?;
    let mut target = vec![0; 40];
    target[..4].fill(0xff);
    target[8..12].copy_from_slice(&ATTR_DATA.to_le_bytes());
    target[16..24].copy_from_slice(&(u64::from(planned.mft_sequence) << 48).to_le_bytes());
    target[24..32].copy_from_slice(&lsn(5).to_le_bytes());
    let opened = operation(0x1c, 24, &target, &[], &[], 0)?;
    let mut update = operation(
        7,
        24,
        replacement,
        expected,
        &[planned.target / u64::from(planned.boot.cluster_bytes)],
        planned.logical / u64::from(planned.boot.cluster_bytes),
    )?;
    update[16..18].copy_from_slice(&planned.record_offset.to_le_bytes());
    update[18..20].copy_from_slice(&planned.attribute_offset.to_le_bytes());
    update[20..22]
        .copy_from_slice(&((planned.logical % u64::from(planned.boot.cluster_bytes) / 512) as u16).to_le_bytes());
    let commit = operation(0x1a, 0, &[], &[], &[], 0)?;
    let opened_page = page(lsn(5), 5 * 4096, &opened, 1, 24, 0)?;
    let update_page = page(lsn(6), 6 * 4096, &update, 1, 24, lsn(5))?;
    let commit_page = page(lsn(7), 7 * 4096, &commit, 1, 24, lsn(6))?;
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let filename = destination.file_name().ok_or_else(|| bad("destination needs a filename"))?;
    let mut staging_name = filename.to_os_string();
    staging_name.push(format!(".initializing-{}", std::process::id()));
    let staging_path = parent.join(staging_name);
    let mut output = OpenOptions::new().read(true).write(true).create_new(true).open(&staging_path)?;
    let staging = Staging(staging_path);
    io::copy(&mut input, &mut output)?;
    if layout(&staging.0, name, offset, expected)? != planned {
        return Err(bad("source changed during copy"));
    }
    // Initialization is private. No visible output exists until it has a
    // complete empty checkpoint and a durable dirty flag in both MFT copies.
    write_at(&mut output, planned.log + 4 * 4096, &checkpoint)?;
    output.sync_all()?;
    write_at(&mut output, planned.log + 4096, &restart)?;
    output.sync_all()?;
    write_at(&mut output, planned.log, &restart)?;
    output.sync_all()?;
    write_at(&mut output, planned.mirror, &planned.volume_dirty)?;
    output.sync_all()?;
    write_at(&mut output, planned.volume, &planned.volume_dirty)?;
    output.sync_all()?;
    // Atomic create-without-replacement; a partial initializer is never
    // confused with a published transaction image.
    fs::hard_link(&staging.0, destination)?;
    File::open(parent)?.sync_all()?;
    drop(staging);
    let mut flushes = 0;
    recovery_io::flush(&mut output, &mut flushes, stop_after)?;
    // Write-ahead intent, followed by its restart publication.
    write_at(&mut output, planned.log + 5 * 4096, &opened_page)?;
    write_at(&mut output, planned.log + 6 * 4096, &update_page)?;
    recovery_io::flush(&mut output, &mut flushes, stop_after)?;
    advance_restart_tail(&mut restart, 512, lsn(6), update.len() as u32)?;
    for at in [planned.log + 4096, planned.log] {
        write_at(&mut output, at, &restart)?;
        recovery_io::flush(&mut output, &mut flushes, stop_after)?;
    }
    // The commit becomes durable before the target MFT record is touched.
    write_at(&mut output, planned.log + 7 * 4096, &commit_page)?;
    recovery_io::flush(&mut output, &mut flushes, stop_after)?;
    advance_restart_tail(&mut restart, 512, lsn(7), commit.len() as u32)?;
    for at in [planned.log + 4096, planned.log] {
        write_at(&mut output, at, &restart)?;
        recovery_io::flush(&mut output, &mut flushes, stop_after)?;
    }
    recovery_io::recover_created_copy(destination, &mut output, &mut flushes, stop_after)?;
    checker::audit_mft_records(destination, planned.boot)?;
    checker::check_known_structures(destination, planned.boot)?;
    println!("written_bytes={}\nnative_transaction_committed=1", replacement.len());
    Ok(())
}
