//! Module: slate_ntfs_tools::checker
//! Purpose: Inspect NTFS geometry, recovery state and filesystem consistency.
//! Created: 2026-09-30
//! Architecture: Uses the shared on-disk parsers and consistency audits;
//!     recovery_io separately authorizes and applies repairs. linux supplies
//!     the ioctl and descriptor helpers used by the mounted scan paths.

use crate::delete_plan::{plan_hiberfile_deletion, HiberDeletePlan};
use crate::linux;
use ntfs_rs::boot::BootSector;
use ntfs_rs::hibernation::{classify_header, HibernationState};
use ntfs_rs::logfile::{
    classify_restart_pair, lfs_layout, log_operation, log_page_layout, lsn_stream_offset, LfsRecord, LogState,
    NtfsCheckpoint, RecordPage, RestartPage, RestartTable,
};
use ntfs_rs::mft::{
    record_layout, reference_number, reference_sequence, system_record, MftRecord, ATTR_BITMAP, ATTR_DATA,
};
use ntfs_rs::replay::{record_action, RecordAction};
use ntfs_rs::volume::{ReadAt, Volume};
use ntfs_rs::volume_info::{flags_allow_writes, VolumeInfo};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[path = "consistency.rs"]
pub mod consistency;
use consistency::{Audit, AuditOptions};

pub(crate) const FNV1A64_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV1A64_PRIME: u64 = 0x100000001b3;
const SECTOR_BYTES: u64 = 512;
const KIB: u64 = 1024;
const MIB: u64 = KIB * KIB;
const PERCENT: u64 = 100;
const DIGEST_BLOCK_BYTES: usize = 64 * 1024;
const PROBE_CHUNK_BYTES: usize = 8 * 1024;
const HIBERNATION_PAGE_BYTES: usize = 4096;
const HIBERFILE_NAME: &[u8] = b"hiberfil.sys";
const MINIMUM_LOG_BYTES: u64 = 1024;
const ERASED_LOG_BYTE: u8 = 0xff;
const RESTART_PAGE_COPIES: u64 = 2;
const LFS_RECORD_CONTINUES: u16 = 1;
const DIRTY_PAGE_ENTRY_BYTES: usize = 0x20;
const DIRTY_PAGE_LCN_COUNT_OFFSET: usize = 0x0c;
const BITS_PER_BYTE: u64 = u8::BITS as u64;
/// Errors that leave a mounted repair candidate queued: ENOENT, EAGAIN, EACCES,
/// EBUSY, EINVAL, ENOTTY, ENOSPC, EOPNOTSUPP and ESTALE.
const DEFERRED_REPAIR_ERRORS: [i32; 9] = [
    libc::ENOENT,
    libc::EAGAIN,
    libc::EACCES,
    libc::EBUSY,
    libc::EINVAL,
    libc::ENOTTY,
    libc::ENOSPC,
    libc::EOPNOTSUPP,
    libc::ESTALE,
];
/// Mounted inode repair operations: 0 recomputes EA summaries, 1 a DATA cross-link.
const REPAIR_EA: u8 = 0;
const REPAIR_DATA: u8 = 1;
const REPAIR_EA_FLAGS: i32 = 1;
const REPAIR_DATA_FLAGS: i32 = 3;
/// System records are never cross-link repair candidates.
const FIRST_DATA_REPAIR_RECORD: u64 = ntfs_rs::mft_growth::FIRST_USER_RECORD;
const SPOTFIX_MAGIC_V3: &[u8; 8] = b"SLTSPT03";
const SPOTFIX_MAGIC_V4: &[u8; 8] = b"SLTSPT04";
const SPOTFIX_WORD_BYTES: usize = std::mem::size_of::<u64>();
/// Header words: device, serial, sectors, fingerprint, errors, worklist bytes and
/// digest; version 4 adds the index policy. A checksum word follows.
const SPOTFIX_V3_BYTES: usize = SPOTFIX_MAGIC_V3.len() + 8 * SPOTFIX_WORD_BYTES;
const SPOTFIX_V4_BYTES: usize = SPOTFIX_V3_BYTES + SPOTFIX_WORD_BYTES;
const SPOTFIX_POLICY_WORD: usize = 7;
use crate::linux::PRIVATE_FILE_MODE;
const GROUP_OTHER_MODE_BITS: u32 = 0o077;

/// Continue the checksum used by audit fingerprints and persisted spotfix queues.
pub(crate) fn fnv1a64_update(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(FNV1A64_PRIME))
}

pub fn invalid(error: ntfs_rs::Error) -> io::Error {
    error.into()
}

pub struct Image(pub File);

impl Image {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self(File::open(path)?))
    }
}

impl ReadAt for Image {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> ntfs_rs::Result<()> {
        self.0.seek(SeekFrom::Start(offset)).and_then(|_| self.0.read_exact(output)).map_err(|_| ntfs_rs::Error::Io)
    }
}

/// Read and fixup-decode one MFT record into a caller-owned image.
pub(crate) fn read_record<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>, number: u64) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; volume.boot.record_bytes as usize];
    volume.read_mft_record(mft, number, &mut bytes)?;
    MftRecord::parse(&mut bytes, volume.boot.bytes_per_sector)?;
    Ok(bytes)
}

/// Assemble the $LogFile family; callers parse its unnamed DATA attribute.
fn log_record<R: ReadAt>(volume: &mut Volume<R>) -> io::Result<Vec<u8>> {
    let mft_bytes = consistency::mft_image(volume)?;
    let mft = MftRecord::from_decoded(&mft_bytes)?;
    crate::recovery_io::checked_family_image(volume, &mft, system_record::LOG)
}

fn record_flags(record: &MftRecord<'_>) -> io::Result<u16> {
    record.flags().map_err(invalid)
}

/// Find hiberfil.sys in the root index; conflicting references are refused.
fn find_hiberfile<R: ReadAt>(volume: &mut Volume<R>, root: &MftRecord<'_>) -> io::Result<Option<u64>> {
    let mut block = vec![0_u8; volume.directory_scratch_bytes()];
    let mut found = None;
    volume.visit_directory(root, &mut block, |entry| {
        let mut units = entry.name.code_units();
        let matches = HIBERFILE_NAME.iter().all(|expected| {
            units.next().is_some_and(|unit| u8::try_from(unit).is_ok_and(|unit| unit.eq_ignore_ascii_case(expected)))
        }) && units.next().is_none();
        if matches {
            if found.is_some_and(|previous| previous != entry.file_reference) {
                return Err(ntfs_rs::Error::InvalidIndex);
            }
            found = Some(entry.file_reference);
        }
        Ok(())
    })?;
    Ok(found)
}

#[derive(Debug)]
pub struct CheckReport {
    pub volume_flags: u16,
    pub volume_serial: u64,
    pub log_state: &'static str,
    pub hibernated: bool,
    pub audit: Audit,
}

impl CheckReport {
    /// Borrow one contiguous JSON report without collecting it on the heap.
    /// The private file and read-only mapping remain alive through receive.
    pub fn with_json_bytes<T>(&self, receive: impl FnOnce(&[u8]) -> T) -> io::Result<T> {
        let file = consistency::scratch_file()?;
        let mut output = io::BufWriter::new(&file);
        self.write_json(&mut output)?;
        output.flush()?;
        drop(output);
        let bytes = unsafe { memmap2::Mmap::map(&file)? };
        Ok(receive(&bytes))
    }

    pub fn write_report(&self, output: &mut impl Write) -> io::Result<()> {
        self.audit.write_report(output)
    }

    pub fn save_report(&self, path: &Path) -> io::Result<()> {
        self.audit.save_report(path)
    }

    pub fn passed(&self) -> bool {
        self.audit.passed()
    }

    /// Assessment success does not authorize a metadata writer. Recovery and
    /// hibernation prerequisites remain separate from structural findings.
    pub fn write_ready(&self) -> bool {
        self.audit.passed()
            && flags_allow_writes(self.volume_flags)
            && !self.hibernated
            && matches!(self.log_state, "uninitialized" | "no-active-clients" | "checked-volume" | "empty-checkpoint")
    }

    pub fn write_json(&self, output: &mut impl Write) -> io::Result<()> {
        write!(
            output,
            "{{\"schema_version\":1,\"passed\":{},\"volume_flags\":{},\"volume_serial\":{},\"log_state\":",
            self.passed(),
            self.volume_flags,
            self.volume_serial
        )?;
        consistency::json_string(output, self.log_state)?;
        write!(output, ",\"hibernated\":{},\"write_ready\":{},", self.hibernated, self.write_ready())?;
        self.audit.write_json_fields(output)?;
        output.write_all(b"}")
    }
}

/// Read-only structural check. Linux block devices are exclusively claimed:
/// use the online audit for mounted devices. Regular images must be quiesced
/// by their owner; a file lock cannot exclude external loop/raw-device access.
/// A report log, when requested, receives every finding.
pub fn check_device(path: &Path, options: AuditOptions, log: Option<&Path>) -> io::Result<CheckReport> {
    check_device_with_progress(path, options, log, &mut |_| {})
}

/// `check_device`, reporting how far the audit's scans have come.
pub fn check_device_with_progress(
    path: &Path,
    options: AuditOptions,
    log: Option<&Path>,
    progress: &mut dyn FnMut(crate::recovery_io::RepairProgress),
) -> io::Result<CheckReport> {
    let mut file = File::open(path)?;
    if file.metadata()?.file_type().is_block_device() {
        file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_EXCL).open(linux::fd_path(&file))?;
    }
    let stable = linux::fd_path(&file);
    let before = file.metadata()?;
    let probe = probe(&stable)?;
    let mut audit = consistency::audit_with_progress(&stable, probe.boot, options, progress)?;
    let recovery = match inspect_recovery(Image::open(&stable)?, probe.boot) {
        Ok(recovery) => recovery,
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                && audit.findings.iter().any(|finding| {
                    finding.code == "directory-invalid" && finding.record == Some(system_record::ROOT)
                }) =>
        {
            // A diagnosed damaged root prevents reliable hiberfile lookup.
            // Retain its audit findings while refusing every write prerequisite.

            audit.complete = false;
            RecoveryStatus { log: LogState::NeedsReview, hibernation: HibernationState::Unknown }
        }
        Err(error) => return Err(error),
    };
    let log_state = match recovery.log {
        LogState::Uninitialized => "uninitialized",
        LogState::NoActiveClients => "no-active-clients",
        LogState::CheckedVolume => "checked-volume",
        LogState::NeedsReview => "needs-review",
        LogState::ReplayRequired | LogState::CleanShutdown => {
            if crate::recovery_io::replay_is_empty(&stable).unwrap_or(false) {
                "empty-checkpoint"
            } else if recovery.log == LogState::CleanShutdown {
                "clean-shutdown"
            } else {
                "replay-required"
            }
        }
    };
    let report = CheckReport {
        volume_flags: probe.info.flags,
        volume_serial: probe.boot.serial_number,
        log_state,
        hibernated: ntfs_rs::hibernation::write_gate(recovery.hibernation, false)
            != ntfs_rs::hibernation::HibernationWriteGate::Clear,
        audit,
    };
    let after = file.metadata()?;
    if before.is_file() && (before.len() != after.len() || before.modified()? != after.modified()?) {
        return Err(io::Error::other("image changed during check"));
    }
    if let Some(log) = log {
        report.save_report(log)?;
    }
    Ok(report)
}

/// Open a mounted path for a private Slate repair request.
fn open_repair_target(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new().read(true).custom_flags(linux::NO_FOLLOW_NONBLOCK).open(path)
}

/// Request one typed repair through the mounted driver's transaction engine.
/// The kernel derives the replacement from live data; no offline patch or
/// userspace audit snapshot is trusted as authority for a mounted write.
pub fn online_repair(path: &Path, operation: u8) -> io::Result<u32> {
    online_repair_verified(path, operation, None)
}

fn online_repair_verified(path: &Path, operation: u8, expected: Option<(u64, u64)>) -> io::Result<u32> {
    let maximum = match operation {
        REPAIR_EA => REPAIR_EA_FLAGS,
        REPAIR_DATA => REPAIR_DATA_FLAGS,
        _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
    };
    let file = open_repair_target(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(io::Error::other("online repair requires a Slate regular file or directory"));
    }
    if expected.is_some_and(|(device, number)| metadata.dev() != device || metadata.ino() != number) {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
    linux::require_slate_mount(&file)?;
    // No payload; the driver restricts this to initial-namespace administrators.

    let request = linux::SLATE_REPAIR_INODE + libc::Ioctl::from(operation);
    match linux::ioctl(&file, request, std::ptr::null_mut())? {
        flags if flags <= maximum => Ok(flags as u32),
        _ => Err(io::Error::other("unexpected mounted repair result")),
    }
}

/// Restore missing allocation bits in the indicated logical $Bitmap sector.
/// The mounted writer inventories current ownership under a filesystem freeze.
pub fn online_repair_allocation_sector(mount: &Path, logical: u64) -> io::Result<bool> {
    if logical % SECTOR_BYTES != 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    online_repair_number(mount, logical, linux::SLATE_REPAIR_ALLOCATION, None)
}

fn online_repair_number(
    mount: &Path,
    mut number: u64,
    command: libc::Ioctl,
    expected_device: Option<u64>,
) -> io::Result<bool> {
    let file = open_repair_target(mount)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::other("online repair needs a mount directory"));
    }
    if expected_device.is_some_and(|device| metadata.dev() != device) {
        return Err(io::Error::other("mounted repair volume changed during online scan"));
    }
    linux::require_slate_mount(&file)?;
    match linux::ioctl(&file, command, (&mut number as *mut u64).cast())? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(io::Error::other("unexpected mounted repair result")),
    }
}

/// A separate-session helper owns the freeze. Its stdin pipe closes even if
/// the checking process is killed, allowing the helper to thaw the filesystem.
/// No journal or repair writes are performed by this online audit path.
pub fn freeze_guard(mount: &Path, expected_device: u64) -> io::Result<()> {
    let file = File::open(mount)?;
    if file.metadata()?.dev() != expected_device {
        return Err(io::Error::other("mount/device identity changed"));
    }
    // Only thaw a freeze this helper acquired.

    linux::ioctl(&file, linux::FIFREEZE, std::ptr::null_mut())?;
    let wait = (|| {
        io::stdout().write_all(b"frozen\n")?;
        io::stdout().flush()?;
        let mut byte = [0];
        loop {
            match io::stdin().read(&mut byte) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => return result.map(|_| ()),
            }
        }
    })();
    linux::ioctl(&file, linux::FITHAW, std::ptr::null_mut())?;
    wait
}

/// Audit a mounted volume while its writers are frozen.
pub fn online_audit(mount: &Path, device: &Path, options: AuditOptions, log: Option<&Path>) -> io::Result<Audit> {
    if let Some(log) = log {
        verify_external_report_path(device, log)?;
    }
    let audit = with_frozen_volume(mount, device, |stable, boot| consistency::audit(stable, boot, options))?;
    if let Some(log) = log {
        audit.save_report(log)?;
    }
    Ok(audit)
}

fn freeze_guard_executable() -> io::Result<PathBuf> {
    const HELPER: &str = "ntfs-chkdsk";

    if let Some(path) = std::env::var_os("SLATE_NTFS_FREEZE_GUARD") {
        return std::fs::canonicalize(path);
    }
    let executable = std::env::current_exe()?;
    if executable.file_name().is_some_and(|name| name == HELPER) {
        return Ok(executable);
    }
    let sibling = executable.parent().map(|parent| parent.join(HELPER));
    let path = std::env::var_os("PATH").unwrap_or_default();
    let candidates = sibling.into_iter().chain(std::env::split_paths(&path).map(|directory| directory.join(HELPER)));
    for candidate in candidates {
        if candidate.is_file() {
            return std::fs::canonicalize(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "online audit needs the ntfs-chkdsk freeze helper on PATH or SLATE_NTFS_FREEZE_GUARD",
    ))
}

fn with_frozen_volume<T>(
    mount: &Path,
    device: &Path,
    inspect: impl FnOnce(&Path, BootSector) -> io::Result<T>,
) -> io::Result<T> {
    use std::io::BufRead;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let source = File::open(device)?;
    let metadata = source.metadata()?;
    let frozen = metadata.rdev();
    if !metadata.file_type().is_block_device() || File::open(mount)?.metadata()?.dev() != frozen {
        return Err(io::Error::other("online audit needs a mount on the specified NTFS block device"));
    }
    if std::env::temp_dir().metadata()?.dev() == frozen {
        return Err(io::Error::other("online audit needs TMPDIR outside the filesystem being frozen"));
    }
    let executable = freeze_guard_executable()?;
    if executable.metadata()?.dev() == frozen
        || std::env::current_exe()?.metadata()?.dev() == frozen
        || std::env::current_dir()?.metadata()?.dev() == frozen
    {
        return Err(io::Error::other("run online audit from outside the filesystem being frozen"));
    }
    let stable = linux::fd_path(&source);
    // Confirm NTFS before asking the mounted filesystem to freeze.

    probe(&stable)?;
    let mut command = Command::new(executable);
    command
        .arg("--freeze-guard")
        .arg(mount)
        .arg(frozen.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // setsid is async-signal-safe and keeps terminal Ctrl-C from killing the guard.

    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guard = command.spawn()?;
    let lease = guard.stdin.take();
    let mut ready = String::new();
    let ready_result = io::BufReader::new(guard.stdout.take().unwrap()).read_line(&mut ready);
    let result = ready_result.and_then(|_| {
        if ready != "frozen\n" {
            return Err(io::Error::other("filesystem freeze did not complete"));
        }
        inspect(&stable, probe(&stable)?.boot)
    });
    // EOF requests thaw, on both success and an audit error.

    drop(lease);
    if !guard.wait()?.success() {
        return Err(io::Error::other("freeze guard failed; verify filesystem thaw state"));
    }
    result
}

#[derive(Clone, Copy, Debug)]
pub struct SpotfixTicket {
    pub device: u64,
    pub serial: u64,
    pub sectors: u64,
    pub fingerprint: u64,
    pub errors: u64,
    pub worklist_bytes: u64,
    pub worklist_digest: u64,
    pub index_audit: AuditOptions,
    worklist_offset: u64,
}

fn worklist_digest(file: &mut File) -> io::Result<(u64, u64)> {
    file.seek(SeekFrom::Start(0))?;
    let digest = stream_digest(file)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(digest)
}

fn stream_digest(file: &mut impl Read) -> io::Result<(u64, u64)> {
    let mut hash = FNV1A64_OFFSET_BASIS;
    let mut size = 0_u64;
    let mut block = vec![0_u8; DIGEST_BLOCK_BYTES];
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            return Ok((size, hash));
        }
        size += n as u64;
        hash = fnv1a64_update(hash, &block[..n]);
    }
}

fn defer_online_repair(error: &io::Error) -> bool {
    // Busy/pinned files, unsupported layouts and stale candidates remain in
    // the next complete audit. A real I/O failure aborts the live pass.

    error.raw_os_error().is_some_and(|code| DEFERRED_REPAIR_ERRORS.contains(&code))
        || matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::Unsupported)
}

fn online_snapshot(mount: &Path, device: &Path, options: OnlineScanOptions) -> io::Result<(Audit, File)> {
    with_frozen_volume(mount, device, |stable, boot| {
        let mut sectors = consistency::scratch_file()?;
        let mut previous = None;
        let budget = options.scan_budget();
        let audit = consistency::audit_reader(
            ScanImage::open(stable, budget)?,
            boot,
            |offset, before, after| {
                let sector = offset / SECTOR_BYTES * SECTOR_BYTES;
                if after & !before != 0 && previous != Some(sector) {
                    sectors.write_all(&sector.to_le_bytes())?;
                    previous = Some(sector);
                }
                Ok(())
            },
            |_| Ok(()),
            options.index_audit,
            budget.index_cache_bytes,
        )?;
        sectors.seek(SeekFrom::Start(0))?;
        Ok((audit, sectors))
    })
}

fn online_remaining(audit: &Audit) -> u128 {
    u128::from(audit.errors) + u128::from(audit.missing_clusters) + u128::from(audit.cross_linked_clusters)
}

fn online_repair_crosslinks(mount: &Path, device: u64, audit: &Audit) -> io::Result<u64> {
    const PENDING: u64 = 0;
    const ATTEMPTED: u64 = 1;
    const VISITED: Option<Option<u64>> = Some(Some(1));

    let mut inventory = consistency::DiskInventory::new();
    for finding in audit.findings.iter() {
        if finding.code == "cross-linked-clusters" {
            if let Some(number) = finding.record.filter(|number| *number >= FIRST_DATA_REPAIR_RECORD) {
                inventory.push([number, PENDING, 0, 0])?;
            }
        }
    }
    let mut targets = inventory.finish()?;
    if targets.metadata()?.len() == 0 {
        return Ok(0);
    }
    let root = std::fs::metadata(mount)?;
    if root.dev() != device {
        return Err(io::Error::other("mounted repair volume changed during online scan"));
    }
    let mut visited = consistency::scratch_file()?;
    consistency::audit_slot(&mut visited, root.ino(), VISITED)?;
    // Walk the mounted namespace once. A record without a reachable regular
    // file remains queued; the path is only a way to obtain the inode lock.

    let mut directories = vec![std::fs::read_dir(mount)?];
    let mut changed = 0_u64;
    while let Some(directory) = directories.last_mut() {
        let Some(next) = directory.next() else {
            directories.pop();
            continue;
        };
        let Ok(entry) = next else {
            continue;
        };
        let (Ok(kind), Ok(meta)) = (entry.file_type(), entry.metadata()) else {
            continue;
        };
        if (!kind.is_file() && !kind.is_dir()) || meta.dev() != device {
            continue;
        }
        if kind.is_dir() {
            if consistency::audit_slot(&mut visited, meta.ino(), VISITED)?.is_none() {
                if let Ok(children) = std::fs::read_dir(entry.path()) {
                    directories.push(children);
                }
            }
            continue;
        }
        let number = meta.ino();
        if consistency::inventory_find(&mut targets, number)?.is_none_or(|row| row[1] != PENDING) {
            continue;
        }
        match online_repair_verified(&entry.path(), REPAIR_DATA, Some((device, number))) {
            Ok(flags) => changed += u64::from(flags != 0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) if defer_online_repair(&error) => {}
            Err(error) => return Err(error),
        }
        let position = targets.stream_position()? - consistency::INVENTORY_BYTES as u64;
        targets.seek(SeekFrom::Start(position))?;
        consistency::inventory_write(&mut targets, [number, ATTEMPTED, 0, 0])?;
    }
    Ok(changed)
}

/// Select bounded read-ahead and index-cache budgets for each frozen snapshot.
/// Execution resources never change which checks run or enter the repair queue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ScanResources {
    #[default]
    Balanced,
    High,
}

const MIN_WRITE_CACHE_BYTES: u64 = 1280 * KIB;
const MAX_WRITE_CACHE_BYTES: u64 = 128 * MIB;
const DEFAULT_WRITE_CACHE_BYTES: u64 = 64 * MIB;
const WRITE_VIEW_BYTES: u64 = crate::recovery_io::WRITE_VIEW_BYTES as u64;
const BALANCED_READ_BYTES: usize = 64 * KIB as usize;
const HIGH_READ_BYTES: usize = 4 * MIB as usize;
const BALANCED_MINIMUM_BYTES: u64 = 512 * MIB;
const HIGH_FALLBACK_BYTES: u64 = 256 * MIB;
/// Scans use four fifths of available memory; balanced scans a quarter of that.
const HEADROOM_NUMERATOR: u64 = 4;
const HEADROOM_DENOMINATOR: u64 = 5;
const BALANCED_SHARE: u64 = 4;
const WRITE_CACHE_SHARE: u64 = 16;

/// Accept byte counts or explicit binary units for the pending-write allowance.
pub fn scan_write_cache_size(value: &str) -> Option<u64> {
    let (value, factor) = if let Some(value) = value.strip_suffix("MiB") {
        (value, MIB)
    } else if let Some(value) = value.strip_suffix("KiB") {
        (value, KIB)
    } else {
        (value, 1)
    };
    let bytes = value.parse::<u64>().ok()?.checked_mul(factor)?;
    (MIN_WRITE_CACHE_BYTES..=MAX_WRITE_CACHE_BYTES).contains(&bytes).then_some(bytes)
}

fn headroom(memory: ScanMemory) -> u64 {
    memory.available.min(memory.total) / HEADROOM_DENOMINATOR * HEADROOM_NUMERATOR
}

impl ScanResources {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "balanced" => Some(Self::Balanced),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::High => "high",
        }
    }

    pub fn read_buffer_bytes(self) -> usize {
        match self {
            Self::Balanced => BALANCED_READ_BYTES,
            Self::High => HIGH_READ_BYTES,
        }
    }

    fn budget(self, memory: Option<ScanMemory>, percent: Option<u8>, requested: Option<u64>) -> ScanBudget {
        let scaled = |bytes: u64, percent: u8| (u128::from(bytes) * u128::from(percent) / u128::from(PERCENT)) as u64;
        let working = match (memory, self) {
            (Some(memory), Self::High) => headroom(memory),
            (Some(memory), Self::Balanced) => percent.map_or_else(
                || (headroom(memory) / BALANCED_SHARE).max(BALANCED_MINIMUM_BYTES).min(headroom(memory)),
                |percent| scaled(headroom(memory), percent),
            ),
            (None, Self::High) => HIGH_FALLBACK_BYTES,
            (None, Self::Balanced) => percent.map_or(consistency::INDEX_CACHE_BYTES, |percent| {
                consistency::INDEX_CACHE_BYTES * u64::from(percent) / PERCENT
            }),
        };
        let read_buffer_bytes = self.read_buffer_bytes().min(working as usize);
        // Pending write views share the allowance with the read/index caches.
        // Unknown memory disables them; small pressure budgets stream instead.

        let write_view_cache_bytes = memory.map_or(0, |memory| {
            requested
                .unwrap_or_else(|| (headroom(memory) / WRITE_CACHE_SHARE).min(DEFAULT_WRITE_CACHE_BYTES))
                .min(working.saturating_sub(read_buffer_bytes as u64))
        }) / WRITE_VIEW_BYTES
            * WRITE_VIEW_BYTES;
        ScanBudget {
            read_buffer_bytes,
            index_cache_bytes: working.saturating_sub(read_buffer_bytes as u64 + write_view_cache_bytes),
            write_view_cache_bytes,
        }
    }
}

/// Apply a best-effort block I/O scheduling hint to the scanning thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanIoPriority {
    Low,
    Normal,
    High,
}

/// ioprio(7): class in the bits above IOPRIO_CLASS_SHIFT, level below.
const IOPRIO_CLASS_SHIFT: u32 = 13;
const IOPRIO_CLASS_RT: i64 = 1;
const IOPRIO_CLASS_BE: libc::c_int = 2;
const IOPRIO_WHO_PROCESS: libc::c_int = 1;
/// Who zero targets the calling thread, keeping other library callers unchanged.
const IOPRIO_CURRENT_THREAD: libc::c_int = 0;

fn ioprio_get() -> io::Result<libc::c_int> {
    let value = unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, IOPRIO_CURRENT_THREAD) };
    if value < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value as libc::c_int)
}

fn ioprio_set(value: libc::c_int) -> io::Result<()> {
    let result = unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, IOPRIO_CURRENT_THREAD, value) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl ScanIoPriority {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "normal" => Some(Self::Normal),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }

    fn encoded(self) -> libc::c_int {
        let level = match self {
            Self::Low => 7,
            Self::Normal => 4,
            Self::High => 0,
        };
        (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | level
    }
}

struct ScanPriorityGuard {
    previous: Option<libc::c_int>,
}

impl ScanPriorityGuard {
    fn enter(priority: ScanIoPriority) -> io::Result<Self> {
        let previous = ioprio_get()?;
        // A real-time class may outlive the capability that granted it.
        // Verify that it can be restored before lowering this thread to BE.

        if i64::from(previous) >> IOPRIO_CLASS_SHIFT == IOPRIO_CLASS_RT {
            ioprio_set(previous)?;
        }
        ioprio_set(priority.encoded())?;
        Ok(Self { previous: Some(previous) })
    }

    fn restore(&mut self) -> io::Result<()> {
        if let Some(previous) = self.previous {
            ioprio_set(previous)?;
            self.previous = None;
        }
        Ok(())
    }
}

impl Drop for ScanPriorityGuard {
    fn drop(&mut self) {
        // Restore the exact inherited class and level, including default zero.

        let _ = self.restore();
    }
}

/// Resolved once for each frozen snapshot; allocation remains demand-driven.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ScanBudget {
    pub read_buffer_bytes: usize,
    pub index_cache_bytes: u64,
    pub write_view_cache_bytes: u64,
}

impl Default for ScanBudget {
    fn default() -> Self {
        ScanResources::Balanced.budget(None, None, None)
    }
}

#[derive(Clone, Copy, Debug)]
struct ScanMemory {
    total: u64,
    available: u64,
}

fn parse_scan_memory(text: &str) -> Option<ScanMemory> {
    let field = |key| {
        let line = text.lines().find_map(|line| line.strip_prefix(key))?;
        let mut fields = line.split_whitespace();
        let bytes = fields.next()?.parse::<u64>().ok()?.checked_mul(KIB)?;
        (fields.next()? == "kB").then_some(bytes)
    };
    Some(ScanMemory { total: field("MemTotal:")?, available: field("MemAvailable:")? })
}

// Mountinfo escapes whitespace and backslashes as octal bytes. Decode only
// those documented escapes so a cgroup mount with spaces stays addressable.
fn memory_mount_path(text: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut output = Vec::new();
    let mut bytes = text.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        output.push(if byte == b'\\' {
            match &[bytes.next()?, bytes.next()?, bytes.next()?] {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return None,
            }
        } else {
            byte
        });
    }
    Some(std::ffi::OsString::from_vec(output).into())
}

fn cgroup_scan_memory(mut memory: ScanMemory, mount: &Path, group: &Path, unified: bool) -> Option<ScanMemory> {
    if !group.starts_with(mount) {
        return None;
    }
    if !group.is_dir() {
        memory.available = 0;
        return Some(memory);
    }
    let (limits, usage): (&[&str], &str) = if unified {
        (&["memory.max", "memory.high"], "memory.current")
    } else {
        (&["memory.limit_in_bytes"], "memory.usage_in_bytes")
    };
    for directory in group.ancestors().take_while(|directory| directory.starts_with(mount)) {
        for name in limits {
            let text = match std::fs::read_to_string(directory.join(name)) {
                Ok(text) => text,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    memory.available = 0;
                    continue;
                }
            };
            if text.trim() == "max" {
                continue;
            }
            let Ok(limit) = text.trim().parse::<u64>() else {
                memory.available = 0;
                continue;
            };
            memory.total = memory.total.min(limit);
            let used =
                std::fs::read_to_string(directory.join(usage)).ok().and_then(|text| text.trim().parse::<u64>().ok());
            // Keep every verified ancestor cap even when pressure information
            // is unavailable. An unknown remaining allowance disables caching.

            memory.available = memory.available.min(used.map_or(0, |used| limit.saturating_sub(used)));
        }
    }
    Some(memory)
}

fn scan_memory() -> Option<ScanMemory> {
    let memory = parse_scan_memory(&std::fs::read_to_string("/proc/meminfo").ok()?)?;
    let constrained = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .zip(std::fs::read_to_string("/proc/self/mountinfo").ok())
        .and_then(|(groups, mounts)| constrain_scan_memory(memory, &groups, &mounts));
    Some(constrained.unwrap_or(ScanMemory { total: memory.total, available: 0 }))
}

fn constrain_scan_memory(memory: ScanMemory, groups: &str, mounts: &str) -> Option<ScanMemory> {
    let mut effective = memory;
    for line in groups.lines() {
        let mut fields = line.splitn(3, ':');
        fields.next()?;
        let controllers = fields.next()?;
        let path = Path::new(fields.next()?);
        let unified = controllers.is_empty();
        if !unified && !controllers.split(',').any(|name| name == "memory") {
            continue;
        }
        let mut found = false;
        for line in mounts.lines() {
            let (left, right) = line.split_once(" - ")?;
            let right: Vec<_> = right.split_whitespace().collect();
            if right.first().copied() != Some(if unified { "cgroup2" } else { "cgroup" })
                || (!unified && !right.get(2)?.split(',').any(|name| name == "memory"))
            {
                continue;
            }
            let fields: Vec<_> = left.split_whitespace().collect();
            let root = memory_mount_path(fields.get(3)?)?;
            let mount = memory_mount_path(fields.get(4)?)?;
            let Ok(relative) = path.strip_prefix(&root) else {
                continue;
            };
            if relative.components().any(|part| !matches!(part, std::path::Component::Normal(_))) {
                return None;
            }
            effective = cgroup_scan_memory(effective, &mount, &mount.join(relative), unified)?;
            found = true;
        }
        if !found {
            return None;
        }
    }
    Some(effective)
}

// Keep read-ahead local to one frozen snapshot. Reusing it across thaw or a
// mounted repair could return obsolete metadata and change repair decisions.
struct ScanImage<R = File> {
    source: R,
    buffer: Vec<u8>,
    start: u64,
    valid: usize,
    window: usize,
    budget: usize,
}

impl ScanImage<File> {
    fn open(path: &Path, budget: ScanBudget) -> io::Result<Self> {
        Ok(Self::with_budget(File::open(path)?, budget))
    }
}

impl<R: Read + Seek> ScanImage<R> {
    fn with_budget(source: R, budget: ScanBudget) -> Self {
        Self {
            source,
            buffer: Vec::new(),
            start: 0,
            valid: 0,
            window: BALANCED_READ_BYTES,
            budget: budget.read_buffer_bytes,
        }
    }

    fn read_window(&mut self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let end = offset + output.len() as u64;
        if output.is_empty() {
            return Ok(());
        }
        if offset >= self.start && end <= self.start + self.valid as u64 {
            let at = (offset - self.start) as usize;
            output.copy_from_slice(&self.buffer[at..at + output.len()]);
            return Ok(());
        }
        // Grow only when the caller consumes consecutive windows. Random
        // metadata lookups retain a small fill instead of amplifying device I/O.

        self.window = if self.valid != 0 && offset == self.start + self.valid as u64 {
            self.window.saturating_mul(2).min(self.budget)
        } else {
            BALANCED_READ_BYTES.min(self.budget)
        };
        self.valid = 0;
        self.source.seek(SeekFrom::Start(offset))?;
        if output.len() >= self.window {
            return self.source.read_exact(output);
        }
        self.start = offset;
        let length = self.window.min((u64::MAX - offset) as usize);
        self.buffer.resize(length, 0);
        while self.valid < length {
            match self.source.read(&mut self.buffer[self.valid..]) {
                Ok(0) => break,
                Ok(count) => self.valid += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if self.valid < output.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        output.copy_from_slice(&self.buffer[..output.len()]);
        Ok(())
    }
}

impl<R: Read + Seek> ReadAt for ScanImage<R> {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> ntfs_rs::Result<()> {
        if offset.checked_add(output.len() as u64).is_some() && self.read_window(offset, output).is_ok() {
            return Ok(());
        }
        self.valid = 0;
        if offset.checked_add(output.len() as u64).is_none() {
            return Err(ntfs_rs::Error::Io);
        }
        // Read-ahead is optional. An unreadable neighboring region must
        // not hide a readable requested span or supply partial cache data.

        self.source
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.source.read_exact(output))
            .map_err(|_| ntfs_rs::Error::Io)
    }
}

/// Controls whether a mounted scan may issue filesystem repair requests.
#[derive(Clone, Copy, Debug, Default)]
pub struct OnlineScanOptions {
    /// Collect defects for offline repair without attempting online repairs.
    pub force_offline_fix: bool,
    /// Apply the same index policy to each snapshot and queued repair.
    pub index_audit: AuditOptions,
    /// Increase scan working memory without changing the checking policy.
    pub resources: ScanResources,
    /// Override the balanced working-memory percentage; valid values are 1–100.
    pub memory_percent: Option<u8>,
    /// Override the balanced scan thread's I/O priority; high resources bypass it.
    pub io_priority: Option<ScanIoPriority>,
    /// Bound pending write views; the effective allowance obeys memory pressure.
    pub write_cache_bytes: Option<u64>,
}

impl OnlineScanOptions {
    fn memory_percent(self) -> Option<u8> {
        self.memory_percent.filter(|_| self.resources == ScanResources::Balanced)
    }

    fn io_priority(self) -> Option<ScanIoPriority> {
        self.io_priority.filter(|_| self.resources == ScanResources::Balanced)
    }

    fn scan_budget(self) -> ScanBudget {
        self.resources.budget(scan_memory(), self.memory_percent(), self.write_cache_bytes)
    }
}

fn online_repairs(
    mount: &Path,
    stable: &Path,
    device: u64,
    options: OnlineScanOptions,
) -> io::Result<consistency::OnlineRepairStatus> {
    let mut status = consistency::OnlineRepairStatus {
        scan_resources: options.resources,
        scan_memory_percent: options.memory_percent(),
        scan_io_priority: options.io_priority(),
        scan_write_cache_bytes: options.write_cache_bytes,
        ..Default::default()
    };
    if options.force_offline_fix {
        status.online_repairs_bypassed = true;
        return Ok(status);
    }
    let attempt = |result: io::Result<bool>, count: &mut u64| match result {
        Ok(changed) => {
            *count += u64::from(changed);
            Ok(changed)
        }
        Err(error) if defer_online_repair(&error) => Ok(false),
        Err(error) => Err(error),
    };
    let (mut audit, mut sectors) = online_snapshot(mount, stable, options)?;
    loop {
        let previous_remaining = online_remaining(&audit);
        let mut changed = false;
        let mut row = [0; std::mem::size_of::<u64>()];
        let count = sectors.metadata()?.len();
        if count % row.len() as u64 != 0 {
            return Err(io::Error::other("truncated allocation candidate list"));
        }
        for _ in 0..count / row.len() as u64 {
            sectors.read_exact(&mut row)?;
            let sector = u64::from_le_bytes(row);
            let result = online_repair_number(mount, sector, linux::SLATE_REPAIR_ALLOCATION, Some(device));
            changed |= attempt(result, &mut status.allocation_repairs)?;
        }
        for finding in audit.findings.iter() {
            if matches!(finding.code.as_str(), "ea-summary-invalid" | "ea-info-orphan") {
                if let Some(number) = finding.record {
                    let result = online_repair_number(mount, number, linux::SLATE_REPAIR_EA_RECORD, Some(device));
                    changed |= attempt(result, &mut status.ea_repairs)?;
                }
            }
        }
        let data_changes = online_repair_crosslinks(mount, device, &audit)?;
        changed |= data_changes != 0;
        status.data_repairs += data_changes;
        if !changed {
            break;
        }
        (audit, sectors) = online_snapshot(mount, stable, options)?;
        // A large overlap may take several bounded writer transactions.
        // Continue while measured defects decrease, without a record-count cap.

        if online_remaining(&audit) >= previous_remaining {
            break;
        }
    }
    Ok(status)
}

/// Persist the complete scan identity outside the mounted volume. Spotfix
/// rechecks every finding after acquiring an exclusive claim and before
/// planning a write. A report log, when requested, receives every finding.
pub fn online_scan(
    mount: &Path,
    device: &Path,
    queue: &Path,
    log: Option<&Path>,
    options: OnlineScanOptions,
) -> io::Result<Audit> {
    if let Some(log) = log {
        verify_external_report_path(device, log)?;
    }
    if options.index_audit.skip_directory_cycles {
        return Err(io::Error::other("online scan requires directory cycle checking"));
    }
    if options.memory_percent.is_some_and(|percent| !(1..=PERCENT as u8).contains(&percent)) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan memory percentage must be between 1 and 100"));
    }
    if options.write_cache_bytes.is_some_and(|bytes| !(MIN_WRITE_CACHE_BYTES..=MAX_WRITE_CACHE_BYTES).contains(&bytes))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scan write cache size must be between 1280KiB and 128MiB",
        ));
    }
    let mut priority = options.io_priority().map(ScanPriorityGuard::enter).transpose()?;
    let source = File::open(device)?;
    let identity = source.metadata()?;
    if !identity.file_type().is_block_device() {
        return Err(io::Error::other("online scan needs a block device"));
    }
    let stable = linux::fd_path(&source);
    let parent = File::open(linux::parent_directory(queue))?;
    if parent.metadata()?.dev() == identity.rdev() {
        return Err(io::Error::other("spotfix queue must be outside the scanned volume"));
    }
    match std::fs::symlink_metadata(queue) {
        Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let before = probe(&stable)?;
    let mut status = online_repairs(mount, &stable, identity.rdev(), options)?;
    // Derive the assessment and its worklist from the SAME frozen snapshot.
    // The preflight uses the selected checking policy and audits its overlay.

    let (mut audit, boot, blocker, budget, write_views) = with_frozen_volume(mount, &stable, |stable, boot| {
        if before.boot.serial_number != boot.serial_number || before.boot.total_sectors != boot.total_sectors {
            return Err(io::Error::other("volume identity changed during online scan"));
        }
        let budget = options.scan_budget();
        let audit = consistency::audit_reader(
            ScanImage::open(stable, budget)?,
            boot,
            |_, _, _| Ok(()),
            |_| Ok(()),
            options.index_audit,
            budget.index_cache_bytes,
        )?;
        let preflight = if audit.passed() {
            Ok(crate::recovery_io::WriteViewStats::default())
        } else {
            crate::recovery_io::preflight_frozen_repairs(stable, options.index_audit, budget)
        };
        let (blocker, write_views) = match preflight {
            Ok(stats) => (None, Some(stats)),
            Err(error) => (Some(error.to_string()), None),
        };
        Ok((audit, boot, blocker, budget, write_views))
    })?;
    if let Some(priority) = &mut priority {
        priority.restore()?;
    }
    status.scan_budget = budget;
    status.write_views = write_views;
    if let Some(reason) = blocker {
        status.unresolved_findings = audit.errors;
        status.blocker = Some(reason);
    }
    queue_scan_findings(queue, &parent, identity.rdev(), boot, &mut audit, &mut status, options)?;
    audit.online_repair = Some(status);
    if let Some(log) = log {
        audit.save_report(log)?;
    }
    Ok(audit)
}

fn queue_scan_findings(
    queue: &Path,
    parent: &File,
    device: u64,
    boot: BootSector,
    audit: &mut Audit,
    status: &mut consistency::OnlineRepairStatus,
    options: OnlineScanOptions,
) -> io::Result<()> {
    // Forced offline scans retain every defect even when the current planner
    // cannot repair it. Spotfix still validates and plans before device writes.

    if audit.errors != 0 && (options.force_offline_fix || status.blocker.is_none()) {
        publish_spotfix_queue(queue, parent, device, boot, audit, options.index_audit)?;
        status.queued_findings = audit.errors;
        status.queue_written = true;
    }
    Ok(())
}

fn publish_spotfix_queue(
    queue: &Path,
    parent: &File,
    device: u64,
    boot: BootSector,
    audit: &mut Audit,
    index_audit: AuditOptions,
) -> io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    if index_audit.skip_directory_cycles || audit.index_check != index_audit.index_check {
        return Err(io::Error::other("spotfix scan policy disagrees with its audit"));
    }
    let (worklist_bytes, worklist_digest) = worklist_digest(audit.worklist_file()?)?;
    let mut bytes = Vec::with_capacity(SPOTFIX_V4_BYTES);
    bytes.extend_from_slice(SPOTFIX_MAGIC_V4);
    for word in [
        device,
        boot.serial_number,
        boot.total_sectors,
        audit.fingerprint,
        audit.errors,
        worklist_bytes,
        worklist_digest,
        index_audit.index_policy_word(),
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let checksum = fnv1a64_update(FNV1A64_OFFSET_BASIS, &bytes);
    bytes.extend_from_slice(&checksum.to_le_bytes());
    let (temporary, mut output) = loop {
        let mut path = queue.as_os_str().to_os_string();
        path.push(format!(".pending-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let path = PathBuf::from(path);
        match std::fs::OpenOptions::new().write(true).create_new(true).mode(PRIVATE_FILE_MODE).open(&path) {
            Ok(output) => break (path, output),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };
    let result = (|| {
        output.write_all(&bytes)?;
        io::copy(audit.worklist_file()?, &mut output)?;
        output.sync_all()?;
        // Atomic publication; never overwrite an existing queue.

        std::fs::hard_link(&temporary, queue)?;
        parent.sync_all()
    })();
    drop(output);
    let cleanup = std::fs::remove_file(&temporary);
    result?;
    cleanup?;
    parent.sync_all()
}

fn open_spotfix_queue(queue: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(queue)
}

pub fn read_spotfix_ticket(queue: &Path) -> io::Result<SpotfixTicket> {
    let mut file = open_spotfix_queue(queue)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.len() < SPOTFIX_V3_BYTES as u64
        || meta.mode() & GROUP_OTHER_MODE_BITS != 0
        || meta.uid() != linux::effective_uid()
    {
        return Err(io::Error::other("invalid spotfix queue file"));
    }
    let mut bytes = vec![0_u8; SPOTFIX_V3_BYTES];
    file.read_exact(&mut bytes)?;
    let word = |bytes: &[u8], index: usize| {
        let at = SPOTFIX_MAGIC_V4.len() + index * SPOTFIX_WORD_BYTES;
        u64::from_le_bytes(bytes[at..at + SPOTFIX_WORD_BYTES].try_into().unwrap())
    };
    let index_audit = match &bytes[..SPOTFIX_MAGIC_V4.len()] {
        magic if magic == SPOTFIX_MAGIC_V3 => AuditOptions::default(),
        magic if magic == SPOTFIX_MAGIC_V4 => {
            bytes.resize(SPOTFIX_V4_BYTES, 0);
            file.read_exact(&mut bytes[SPOTFIX_V3_BYTES..])?;
            AuditOptions::from_index_policy_word(word(&bytes, SPOTFIX_POLICY_WORD))
                .ok_or_else(|| io::Error::other("invalid spotfix index policy"))?
        }
        _ => return Err(io::Error::other("spotfix queue requires a fresh scan")),
    };
    let checksum_at = bytes.len() - SPOTFIX_WORD_BYTES;
    let checksum = fnv1a64_update(FNV1A64_OFFSET_BASIS, &bytes[..checksum_at]);
    if checksum != u64::from_le_bytes(bytes[checksum_at..].try_into().unwrap()) {
        return Err(io::Error::other("spotfix queue checksum mismatch"));
    }
    let ticket = SpotfixTicket {
        device: word(&bytes, 0),
        serial: word(&bytes, 1),
        sectors: word(&bytes, 2),
        fingerprint: word(&bytes, 3),
        errors: word(&bytes, 4),
        worklist_bytes: word(&bytes, 5),
        worklist_digest: word(&bytes, 6),
        index_audit,
        worklist_offset: bytes.len() as u64,
    };
    if ticket.errors == 0 || ticket.worklist_bytes == 0 {
        return Err(io::Error::other("spotfix queue contains no scan findings"));
    }
    if ticket.worklist_bytes.checked_add(ticket.worklist_offset) != Some(meta.len()) {
        return Err(io::Error::other("spotfix queue length mismatch"));
    }
    let (size, hash) = stream_digest(&mut (&mut file).take(ticket.worklist_bytes))?;
    if size != ticket.worklist_bytes {
        return Err(io::Error::other("truncated spotfix worklist"));
    }
    if hash != ticket.worklist_digest {
        return Err(io::Error::other("spotfix worklist checksum mismatch"));
    }
    Ok(ticket)
}

pub fn verify_spotfix_worklist(queue: &Path, audit: &mut Audit, ticket: SpotfixTicket) -> io::Result<()> {
    let mut queued = open_spotfix_queue(queue)?;
    if audit.index_check != ticket.index_audit.index_check || !audit.directory_cycles_checked {
        return Err(io::Error::other("spotfix checking policy changed since online scan"));
    }
    queued.seek(SeekFrom::Start(ticket.worklist_offset))?;
    let live = audit.worklist_file()?;
    let (size, hash) = worklist_digest(live)?;
    if size != ticket.worklist_bytes || hash != ticket.worklist_digest {
        return Err(io::Error::other("spotfix findings changed since online scan"));
    }
    let mut left = size;
    let (mut expected, mut actual) = (vec![0_u8; DIGEST_BLOCK_BYTES], vec![0_u8; DIGEST_BLOCK_BYTES]);
    while left != 0 {
        let n = left.min(DIGEST_BLOCK_BYTES as u64) as usize;
        queued.read_exact(&mut expected[..n])?;
        live.read_exact(&mut actual[..n])?;
        if expected[..n] != actual[..n] {
            return Err(io::Error::other("spotfix worklist differs from fresh audit"));
        }
        left -= n as u64;
    }
    Ok(())
}

fn verify_external_report_path(device: &Path, log: &Path) -> io::Result<()> {
    if linux::parent_directory(log).metadata()?.dev() == device.metadata()?.rdev() {
        return Err(io::Error::other("online findings report must be outside the scanned volume"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub boot: BootSector,
    pub info: VolumeInfo,
}

#[derive(Clone, Copy, Debug)]
pub struct MftAudit {
    pub record_slots: u64,
    pub allocated_records: u64,
    pub attributes: u64,
    pub security_references: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryStatus {
    pub log: LogState,
    pub hibernation: HibernationState,
}

/// Read-only identity and runlist preflight for the simple hiberfile deletion
/// subset. This does not validate or change the NTFS metadata required to
/// unlink the file and does not grant write permission.
pub fn inspect_hiber_delete_plan(path: &Path, boot: BootSector) -> io::Result<HiberDeletePlan> {
    let mut volume = Volume::new(Image::open(path)?, boot)?;
    let mft_bytes = consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&mft_bytes)?;
    let root_bytes = read_record(&mut volume, &mft, system_record::ROOT)?;
    let root = MftRecord::from_decoded(&root_bytes)?;
    let reference = find_hiberfile(&mut volume, &root)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let file_bytes = read_record(&mut volume, &mft, reference_number(reference))?;
    let file = MftRecord::from_decoded(&file_bytes)?;
    plan_hiberfile_deletion(&file, reference, boot, |_| Ok(())).map_err(invalid)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogInventory {
    pub scanned_pages: u64,
    pub record_pages: u64,
    pub records: u64,
    pub metadata_intents: u64,
    pub control_records: u64,
    pub unresolved_pages: u64,
    pub invalid_pages: u64,
    pub multi_page_sets: u64,
    pub continuation_pages: u64,
    pub restart_lsn: u64,
    pub client_oldest_lsn: u64,
    pub client_sequence: u16,
    pub restart_page_count: u16,
    pub restart_page_position: u16,
    pub restart_record_valid: bool,
    pub checkpoint_tables_referenced: u8,
    pub checkpoint_tables_validated: u8,
    pub checkpoint_table_mask: u8,
    pub checkpoint: Option<NtfsCheckpoint>,
}

fn invalid_log() -> io::Error {
    invalid(ntfs_rs::Error::InvalidLog)
}

/// Reconstruct one client record into private disk-backed storage. This reads
/// bytes only; it does not decide which circular-log generation is current.
fn read_log_record(
    volume: &mut Volume<Image>,
    data: ntfs_rs::mft::Attribute<'_>,
    restart: RestartPage,
    lsn: u64,
) -> io::Result<memmap2::Mmap> {
    let sector = volume.boot.bytes_per_sector;
    let page_bytes = u64::from(restart.log_page_bytes);
    let position = lsn_stream_offset(lsn, restart.sequence_bits, restart.log_bytes)?;
    let mut page_offset = position & !(page_bytes - 1);
    let reserved = if restart.major_version == log_page_layout::VERSION_LEGACY {
        log_page_layout::LEGACY_FIRST_RECORD_PAGE
    } else {
        log_page_layout::CURRENT_FIRST_RECORD_PAGE
    };
    let first_page = page_bytes * reserved as u64;
    if page_offset < first_page {
        return Err(invalid_log());
    }
    let mut page = vec![0_u8; page_bytes as usize];
    volume.read_attribute(data, page_offset, &mut page)?;
    let first = RecordPage::parse(&mut page, sector, restart.record_data_offset)?;
    let start = (position - page_offset) as usize;
    if start < usize::from(restart.record_data_offset) {
        return Err(invalid_log());
    }
    let header = first.bytes().get(start..start + lfs_layout::HEADER_BYTES).ok_or_else(invalid_log)?;
    let total = LfsRecord::peek_total_bytes(header)?;
    if total as u64 > restart.log_bytes.saturating_sub(first_page) {
        return Err(invalid_log());
    }
    let mut backing = consistency::scratch_file()?;
    let first_bytes = first.bytes().get(start..).ok_or_else(invalid_log)?;
    let mut written = first_bytes.len().min(total);
    backing.write_all(&first_bytes[..written])?;
    let (mut prior_count, mut prior_position) = (first.page_count, first.page_position);
    let flags = ntfs_rs::bytes::u16_at(header, lfs_layout::FLAGS_OFFSET)?;
    if written < total && flags & LFS_RECORD_CONTINUES == 0 {
        return Err(invalid_log());
    }
    let max_pages = restart.log_bytes.saturating_sub(first_page) / page_bytes;
    let mut pages = 1_u64;
    while written < total {
        if pages >= max_pages {
            return Err(invalid_log());
        }
        pages += 1;
        page_offset += page_bytes;
        if page_offset + page_bytes > restart.log_bytes {
            page_offset = first_page;
        }
        volume.read_attribute(data, page_offset, &mut page)?;
        let next = RecordPage::parse(&mut page, sector, restart.record_data_offset)?;
        let expected_position = if prior_position == prior_count { 1 } else { prior_position + 1 };
        if next.page_position != expected_position || (expected_position != 1 && next.page_count != prior_count) {
            return Err(invalid_log());
        }
        let continuation = next.bytes().get(restart.record_data_offset as usize..).ok_or_else(invalid_log)?;
        let take = continuation.len().min(total - written);
        backing.write_all(&continuation[..take])?;
        written += take;
        (prior_count, prior_position) = (next.page_count, next.page_position);
    }
    let bytes = unsafe { memmap2::Mmap::map(&backing)? };
    if LfsRecord::parse(&bytes)?.this_lsn != lsn {
        return Err(invalid_log());
    }
    Ok(bytes)
}

fn validate_checkpoint_table(
    volume: &mut Volume<Image>,
    data: ntfs_rs::mft::Attribute<'_>,
    restart: RestartPage,
    lsn: u64,
    bytes: u32,
    operation: u16,
) -> io::Result<()> {
    let context = |what: &str, error: &dyn std::fmt::Display| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {error}"))
    };
    let raw = read_log_record(volume, data, restart, lsn)
        .map_err(|error| io::Error::new(error.kind(), format!("record reconstruction: {error}")))?;
    let record = LfsRecord::parse(&raw).map_err(|error| context("record parse", &error))?;
    let client = restart.client.ok_or_else(invalid_log)?;
    if record.record_type != lfs_layout::UPDATE_RECORD
        || record.client_index != client.index
        || record.client_sequence != client.sequence
    {
        return Err(invalid_log());
    }
    let payload = record.ntfs_operation().map_err(|error| context("operation parse", &error))?;
    if payload.redo_code != operation || payload.redo.len() != bytes as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "operation or length mismatch: op={:#x}, redo_bytes={}, expected_op={operation:#x}, expected_bytes={bytes}",
                payload.redo_code,
                payload.redo.len()
            ),
        ));
    }
    if operation == log_operation::DIRTY_PAGE_TABLE_DUMP {
        RestartTable::parse(payload.redo).and_then(|table| {
            table.visit_allocated(|entry| {
                if entry.len() < DIRTY_PAGE_ENTRY_BYTES {
                    return Err(ntfs_rs::Error::InvalidLog);
                }
                let lcns = ntfs_rs::bytes::u32_at(entry, DIRTY_PAGE_LCN_COUNT_OFFSET)? as usize;
                if lcns * std::mem::size_of::<u64>() + DIRTY_PAGE_ENTRY_BYTES > entry.len() {
                    return Err(ntfs_rs::Error::InvalidLog);
                }
                Ok(())
            })
        })?;
    } else if matches!(operation, log_operation::OPEN_ATTRIBUTE_TABLE_DUMP | log_operation::TRANSACTION_TABLE_DUMP) {
        RestartTable::parse(payload.redo)?;
    }
    Ok(())
}

/// Read and decode both restart pages of an initialized log stream.
fn read_restart_pair(
    volume: &mut Volume<Image>,
    data: ntfs_rs::mft::Attribute<'_>,
    system_bytes: u32,
) -> io::Result<[Vec<u8>; 2]> {
    let mut pages = [vec![0_u8; system_bytes as usize], vec![0_u8; system_bytes as usize]];
    for (index, page) in pages.iter_mut().enumerate() {
        volume.read_attribute(data, index as u64 * u64::from(system_bytes), page)?;
    }
    Ok(pages)
}

/// Count format-checked, wholly contained log records. This diagnostic does
/// not select a checkpoint, resolve circular LSN order or authorize replay.
pub fn inspect_log_inventory(path: &Path, boot: BootSector) -> io::Result<LogInventory> {
    let mut volume = Volume::new(Image::open(path)?, boot)?;
    let log_image = log_record(&mut volume)?;
    let logfile = MftRecord::from_decoded(&log_image)?;
    let data = logfile.stream(ATTR_DATA, &[])?;
    let stream_bytes = data.data_size()?;
    let mut prefix = [0_u8; SECTOR_BYTES as usize];
    volume.read_attribute(data, 0, &mut prefix)?;
    if prefix.iter().all(|byte| *byte == ERASED_LOG_BYTE) {
        // The status command verifies the whole stream before calling it
        // uninitialized. This inventory requires an initialized restart pair.

        return Err(invalid(ntfs_rs::Error::Unsupported));
    }
    let system_bytes = RestartPage::peek_system_page_bytes(&prefix)?;
    let records_start = u64::from(system_bytes) * RESTART_PAGE_COPIES;
    if stream_bytes < records_start {
        return Err(invalid_log());
    }
    let [mut first, mut second] = read_restart_pair(&mut volume, data, system_bytes)?;
    let first = RestartPage::parse(&mut first, boot.bytes_per_sector)?;
    let second = RestartPage::parse(&mut second, boot.bytes_per_sector)?;
    if first.log_bytes > stream_bytes
        || first.log_bytes != second.log_bytes
        || first.system_page_bytes != second.system_page_bytes
        || first.log_page_bytes != second.log_page_bytes
        || first.record_data_offset != second.record_data_offset
        || classify_restart_pair(Ok(first), Ok(second)) == LogState::NeedsReview
    {
        return Err(invalid_log());
    }
    let restart = if first.current_lsn >= second.current_lsn { first } else { second };
    let page_bytes = u64::from(restart.log_page_bytes);
    let mut page = vec![0_u8; restart.log_page_bytes as usize];
    let mut inventory = LogInventory::default();
    if let Some(client) = restart.client {
        inventory.restart_lsn = client.restart_lsn;
        inventory.client_oldest_lsn = client.oldest_lsn;
        inventory.client_sequence = client.sequence;
        if client.restart_lsn != lfs_layout::NO_LSN {
            let position = lsn_stream_offset(client.restart_lsn, restart.sequence_bits, restart.log_bytes)?;
            let page_offset = position & !(page_bytes - 1);
            if page_offset >= records_start && page_offset + page_bytes <= restart.log_bytes {
                volume.read_attribute(data, page_offset, &mut page)?;
                if let Ok(record_page) = RecordPage::parse(&mut page, boot.bytes_per_sector, restart.record_data_offset)
                {
                    inventory.restart_page_count = record_page.page_count;
                    inventory.restart_page_position = record_page.page_position;
                    let checkpoint = record_page
                        .contained_record_at((position - page_offset) as usize)
                        .ok()
                        .filter(|record| {
                            record.this_lsn == client.restart_lsn
                                && record.client_index == client.index
                                && record.client_sequence == client.sequence
                                && record.record_type == lfs_layout::CHECKPOINT_RECORD
                        })
                        .and_then(|record| NtfsCheckpoint::parse(record.payload()).ok());
                    if checkpoint.is_some() {
                        inventory.checkpoint = checkpoint;
                        inventory.restart_record_valid = true;
                    }
                }
            }
        }
        if let Some(checkpoint) = inventory.checkpoint {
            let tables = [
                (
                    checkpoint.open_attributes_lsn,
                    checkpoint.open_attributes_bytes,
                    log_operation::OPEN_ATTRIBUTE_TABLE_DUMP,
                ),
                (checkpoint.attribute_names_lsn, checkpoint.attribute_names_bytes, log_operation::ATTRIBUTE_NAMES_DUMP),
                (checkpoint.dirty_pages_lsn, checkpoint.dirty_pages_bytes, log_operation::DIRTY_PAGE_TABLE_DUMP),
                (checkpoint.transactions_lsn, checkpoint.transactions_bytes, log_operation::TRANSACTION_TABLE_DUMP),
            ];
            for (index, (lsn, bytes, operation)) in tables.into_iter().enumerate() {
                if lsn == lfs_layout::NO_LSN {
                    continue;
                }
                inventory.checkpoint_tables_referenced += 1;
                match validate_checkpoint_table(&mut volume, data, restart, lsn, bytes, operation) {
                    Ok(()) => {
                        inventory.checkpoint_tables_validated += 1;
                        inventory.checkpoint_table_mask |= 1 << index;
                    }
                    Err(error) => eprintln!("checkpoint table {operation:#x}: {error}"),
                }
            }
        }
    }
    let mut offset = records_start;
    while offset < restart.log_bytes {
        inventory.scanned_pages += 1;
        if restart.log_bytes - offset < page_bytes {
            inventory.unresolved_pages += 1;
            break;
        }
        volume.read_attribute(data, offset, &mut page)?;
        offset += page_bytes;
        if page.iter().all(|byte| *byte == ERASED_LOG_BYTE) {
            continue;
        }
        if !page.starts_with(b"RCRD") {
            inventory.unresolved_pages += 1;
            continue;
        }
        let Ok(record_page) = RecordPage::parse(&mut page, boot.bytes_per_sector, restart.record_data_offset) else {
            inventory.invalid_pages += 1;
            continue;
        };
        inventory.record_pages += 1;
        if record_page.page_count != 1 {
            if record_page.page_position == 1 {
                inventory.multi_page_sets += 1;
            } else {
                inventory.continuation_pages += 1;
            }
            inventory.unresolved_pages += 1;
            continue;
        }
        let mut local = LogInventory::default();
        let result = record_page.visit_single_page_records(|record| {
            if inventory.restart_lsn != lfs_layout::NO_LSN && record.this_lsn == inventory.restart_lsn {
                let client = restart.client.ok_or(ntfs_rs::Error::InvalidLog)?;
                if record.record_type != lfs_layout::CHECKPOINT_RECORD
                    || record.client_index != client.index
                    || record.client_sequence != client.sequence
                    || local.checkpoint.is_some()
                {
                    return Err(ntfs_rs::Error::InvalidLog);
                }
                let found = NtfsCheckpoint::parse(record.payload())?;
                if inventory.checkpoint.is_some_and(|current| current != found) {
                    return Err(ntfs_rs::Error::InvalidLog);
                }
                local.checkpoint = Some(found);
            }
            if record.record_type == lfs_layout::CHECKPOINT_RECORD || record_action(record)? == RecordAction::Control {
                local.control_records += 1;
            } else {
                local.metadata_intents += 1;
            }
            Ok(())
        });
        match result {
            Ok(records) => {
                inventory.records += u64::from(records);
                inventory.control_records += local.control_records;
                inventory.metadata_intents += local.metadata_intents;
                if local.checkpoint.is_some() {
                    inventory.checkpoint = local.checkpoint;
                }
            }
            Err(ntfs_rs::Error::Unsupported) => inventory.unresolved_pages += 1,
            Err(_) => inventory.invalid_pages += 1,
        }
    }
    Ok(inventory)
}

/// Sizes of the unnamed $LogFile data stream, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFileSize {
    pub data_bytes: u64,
    pub allocated_bytes: u64,
    pub initialized_bytes: u64,
    pub default_bytes: u64,
    /// Separate runs the stream is stored in; one means contiguous.
    pub fragments: u64,
}

/// Default log size for a volume: one percent through 400 MiB, then
/// one eighth of one percent above that threshold, capped at 64 MiB.
/// The result has a 2 MiB minimum and is rounded upward to 16 KiB.
pub fn default_logfile_size(boot: BootSector) -> u64 {
    const SMALL_VOLUME_BYTES: u64 = 400 * MIB;
    const SMALL_VOLUME_DIVISOR: u64 = 100;
    const LARGE_VOLUME_DIVISOR: u64 = 800;
    const ROUNDING_BYTES: u64 = 16 * KIB;

    let bytes = boot.total_sectors.saturating_mul(u64::from(boot.bytes_per_sector));
    let target = if bytes <= SMALL_VOLUME_BYTES {
        bytes / SMALL_VOLUME_DIVISOR
    } else {
        SMALL_VOLUME_BYTES / SMALL_VOLUME_DIVISOR + (bytes - SMALL_VOLUME_BYTES) / LARGE_VOLUME_DIVISOR
    };
    target.clamp(2 * MIB, 64 * MIB).next_multiple_of(ROUNDING_BYTES)
}

/// Query the existing log stream without inspecting or changing its contents.
pub fn inspect_logfile_size<R: ReadAt>(reader: R, boot: BootSector) -> io::Result<LogFileSize> {
    let mut volume = Volume::new(reader, boot)?;
    let logical = log_record(&mut volume)?;
    let record = MftRecord::from_decoded(&logical)?;
    if record_flags(&record)? & (record_layout::IN_USE | record_layout::DIRECTORY) != record_layout::IN_USE {
        return Err(invalid(ntfs_rs::Error::InvalidRecord));
    }
    let data = record.stream(ATTR_DATA, &[])?;
    let mut fragments = 0;
    for run in ntfs_rs::runlist::DataRuns::new(data.data_runs()?, data.first_vcn()?) {
        run?;
        fragments += 1;
    }
    Ok(LogFileSize {
        fragments,
        data_bytes: data.data_size()?,
        allocated_bytes: data.allocated_size()?,
        initialized_bytes: data.initialized_size()?,
        default_bytes: default_logfile_size(boot),
    })
}

fn restart_within(page: ntfs_rs::Result<RestartPage>, log_bytes: u64) -> ntfs_rs::Result<RestartPage> {
    page.and_then(|page| {
        if page.chkdsk_marker || page.log_bytes <= log_bytes {
            Ok(page)
        } else {
            Err(ntfs_rs::Error::InvalidLog)
        }
    })
}

/// Inspect recovery prerequisites without opening the image for writing.
/// A valid restart pair does not prove that log records are replayed.
pub fn inspect_recovery<R: ReadAt>(reader: R, boot: BootSector) -> io::Result<RecoveryStatus> {
    let mut volume = Volume::new(reader, boot)?;
    let mft_bytes = consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&mft_bytes)?;
    let logfile_image = crate::recovery_io::checked_family_image(&mut volume, &mft, system_record::LOG)?;
    let logfile = MftRecord::from_decoded(&logfile_image)?;
    if record_flags(&logfile)? & record_layout::IN_USE == 0 {
        return Err(invalid(ntfs_rs::Error::InvalidRecord));
    }
    let data = logfile.stream(ATTR_DATA, &[])?;
    let log_bytes = data.data_size()?;
    if log_bytes < MINIMUM_LOG_BYTES {
        return Err(invalid_log());
    }
    let mut prefix = [0_u8; SECTOR_BYTES as usize];
    volume.read_attribute(data, 0, &mut prefix)?;
    let log = if prefix.iter().all(|byte| *byte == ERASED_LOG_BYTE) {
        let mut chunk = vec![0_u8; PROBE_CHUNK_BYTES];
        let mut offset = 0_u64;
        let mut erased = true;
        while erased && offset < log_bytes {
            let len = (log_bytes - offset).min(chunk.len() as u64) as usize;
            volume.read_attribute(data, offset, &mut chunk[..len])?;
            erased = chunk[..len].iter().all(|byte| *byte == ERASED_LOG_BYTE);
            offset += len as u64;
        }
        if erased {
            LogState::Uninitialized
        } else {
            LogState::NeedsReview
        }
    } else {
        match RestartPage::peek_system_page_bytes(&prefix) {
            Ok(page_bytes) if log_bytes >= u64::from(page_bytes) * RESTART_PAGE_COPIES => {
                let mut pages = [vec![0_u8; page_bytes as usize], vec![0_u8; page_bytes as usize]];
                for (index, page) in pages.iter_mut().enumerate() {
                    volume.read_attribute(data, index as u64 * u64::from(page_bytes), page)?;
                }
                let [first, second] = pages
                    .map(|mut page| restart_within(RestartPage::parse(&mut page, boot.bytes_per_sector), log_bytes));
                classify_restart_pair(first, second)
            }
            _ => LogState::NeedsReview,
        }
    };
    let mut root_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, system_record::ROOT, &mut root_bytes)?;
    // A cut write may have torn the root folder's record. Replay restores
    // it, and plan_reader looks for hiberfil.sys again in the replayed view.
    if !MftRecord::record_intact(&root_bytes, boot.bytes_per_sector) && log == LogState::ReplayRequired {
        return Ok(RecoveryStatus { log, hibernation: HibernationState::Unknown });
    }
    MftRecord::parse(&mut root_bytes, boot.bytes_per_sector)?;
    let root = MftRecord::from_decoded(&root_bytes)?;
    let hibernation = match find_hiberfile(&mut volume, &root)? {
        None => HibernationState::Absent,
        Some(reference) => {
            let record_bytes = read_record(&mut volume, &mft, reference_number(reference))?;
            let record = MftRecord::from_decoded(&record_bytes)?;
            if record.sequence_number()? != reference_sequence(reference)
                || record_flags(&record)? & record_layout::IN_USE == 0
            {
                return Err(invalid(ntfs_rs::Error::InvalidRecord));
            }
            let mut page = [0_u8; HIBERNATION_PAGE_BYTES];
            match volume.data_size(&record) {
                Ok(size) if size >= HIBERNATION_PAGE_BYTES as u64 => match volume.read_data(&record, 0, &mut page) {
                    Ok(()) => classify_header(&page),
                    Err(_) => HibernationState::Unknown,
                },
                _ => HibernationState::Unknown,
            }
        }
    };
    Ok(RecoveryStatus { log, hibernation })
}

fn record_error(number: u64) -> impl Fn(ntfs_rs::Error) -> io::Error {
    move |error| io::Error::new(io::ErrorKind::InvalidData, format!("MFT record {number}: {error}"))
}

/// Check allocated MFT records against $MFT::$BITMAP. This is one checker
/// phase, not a complete NTFS consistency check. It never changes the volume.
pub fn audit_mft_records(path: &Path, boot: BootSector) -> io::Result<MftAudit> {
    let mut volume = Volume::new(Image::open(path)?, boot)?;
    let mft_bytes = consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&mft_bytes)?;
    let stream_size = volume.data_size(&mft)?;
    let record_size = u64::from(boot.record_bytes);
    if stream_size == 0 || stream_size % record_size != 0 {
        return Err(invalid(ntfs_rs::Error::InvalidAttribute));
    }
    let record_slots = stream_size / record_size;
    let needed_bitmap_bytes = record_slots.div_ceil(BITS_PER_BYTE);
    let mut bitmap = None;
    for attribute in mft.attributes() {
        let attribute = attribute?;
        if attribute.kind == ATTR_BITMAP && attribute.name_utf16le()?.is_empty() && bitmap.replace(attribute).is_some()
        {
            return Err(invalid(ntfs_rs::Error::Unsupported));
        }
    }
    let bitmap = bitmap.ok_or(ntfs_rs::Error::InvalidAttribute)?;
    if bitmap.data_size()? < needed_bitmap_bytes {
        return Err(invalid(ntfs_rs::Error::InvalidAttribute));
    }
    let mut record_bytes = vec![0; boot.record_bytes as usize];
    let mut chunk = vec![0_u8; PROBE_CHUNK_BYTES];
    let mut audit = MftAudit { record_slots, allocated_records: 0, attributes: 0, security_references: 0 };
    for byte_offset in (0..needed_bitmap_bytes).step_by(PROBE_CHUNK_BYTES) {
        let length = (needed_bitmap_bytes - byte_offset).min(PROBE_CHUNK_BYTES as u64) as usize;
        volume.read_attribute(bitmap, byte_offset, &mut chunk[..length])?;
        for (byte_index, byte) in chunk[..length].iter().enumerate() {
            let first_record = (byte_offset + byte_index as u64) * BITS_PER_BYTE;
            for bit in 0..BITS_PER_BYTE {
                let number = first_record + bit;
                if number >= record_slots || *byte & (1_u8 << bit) == 0 {
                    continue;
                }
                volume.read_mft_record(&mft, number, &mut record_bytes).map_err(record_error(number))?;
                let record =
                    MftRecord::parse(&mut record_bytes, boot.bytes_per_sector).map_err(record_error(number))?;
                if record_flags(&record)? & record_layout::IN_USE == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("MFT record {number} is allocated in bitmap but marked free"),
                    ));
                }
                if record.security_id()?.is_some() {
                    audit.security_references += 1;
                }
                for attribute in record.attributes() {
                    let attribute = attribute.map_err(record_error(number))?;
                    if attribute.nonresident {
                        if attribute.initialized_size()? > attribute.data_size()? {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("MFT record {number}: initialized size exceeds data size"),
                            ));
                        }
                        attribute.data_runs()?;
                    } else {
                        attribute.resident_value()?;
                    }
                    audit.attributes += 1;
                }
                audit.allocated_records += 1;
            }
        }
    }
    Ok(audit)
}

/// Open read-only and validate boot geometry and backing-image length.
pub(crate) fn open_volume(path: &Path) -> io::Result<Volume<Image>> {
    let mut file = File::open(path)?;
    let mut sector = [0; SECTOR_BYTES as usize];
    file.read_exact(&mut sector)?;
    let boot = BootSector::parse(&sector)?;
    let volume_bytes =
        boot.total_sectors.checked_mul(u64::from(boot.bytes_per_sector)).ok_or(ntfs_rs::Error::Overflow)?;
    let metadata = file.metadata()?;
    if metadata.is_file() && metadata.len() < volume_bytes {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "image is shorter than the NTFS geometry"));
    }
    Volume::new(Image(file), boot).map_err(invalid)
}

/// Inspect the on-disk dirty flag; malformed records are never clean.
pub fn probe(path: &Path) -> io::Result<Probe> {
    let mut volume = open_volume(path)?;
    let boot = volume.boot;
    let mft_bytes = consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&mft_bytes)?;
    let volume_bytes = read_record(&mut volume, &mft, system_record::VOLUME)?;
    let info = VolumeInfo::from_record(&MftRecord::from_decoded(&volume_bytes)?)?;
    Ok(Probe { boot, info })
}

/// Check the metadata currently understood by the read-only Rust core.
/// This is diagnostic only; it cannot replay $LogFile or clear the dirty bit.
pub fn check_known_structures(path: &Path, boot: BootSector) -> io::Result<u32> {
    let mut volume = Volume::new(Image::open(path)?, boot)?;
    let mft_bytes = consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&mft_bytes)?;
    let root_bytes = read_record(&mut volume, &mft, system_record::ROOT)?;
    let root = MftRecord::from_decoded(&root_bytes)?;
    let directory = record_layout::IN_USE | record_layout::DIRECTORY;
    if record_flags(&root)? & directory != directory {
        return Err(invalid(ntfs_rs::Error::InvalidRecord));
    }
    let mut block = vec![0; volume.directory_scratch_bytes()];
    let mut entries = 0_u32;
    volume.visit_directory(&root, &mut block, |_| {
        entries += 1;
        Ok(())
    })?;
    Ok(entries)
}

#[cfg(test)]
#[path = "../tests/checker/scan_resources.rs"]
mod scan_resource_tests;
