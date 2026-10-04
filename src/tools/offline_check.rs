//! Module: slate_ntfs_tools::offline_check
//! Purpose: Run the complete offline check and repair of one unmounted volume.
//! Created: 2026-10-04
//! Architecture: Sequences the backend's journaled steps (replay, structural repair,
//! journal resize) as child processes of the ntfs-chkdsk command, each followed by a
//! check. ntfs-chkdsk --repair and fsck.ntfsrs share this sequence.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::recovery_journal::{self, JournalKind};
use crate::{checker, progress_display, recovery_io};

/// Journal sizes Windows' checker leaves alone when a resize is requested.
const SUPPORTED_LOG_BYTES: std::ops::Range<u64> = 2 * 1024 * 1024..4 * 1024 * 1024 * 1024;
/// First bytes of the external journal ntfs-chkdsk writes for a journal resize.
const LOG_RESIZE_MAGIC: &[u8; 8] = b"SLTLRS01";
/// Shared with the mount helper (mount.ntfs), which refuses while it is held.
const LOCK_DIRECTORY: &str = "/run/slate-ntfs";

/// One volume to check, and how.
#[derive(Debug)]
pub struct Request {
    pub device: PathBuf,
    /// External journal for repair preimages; a default path when absent.
    pub journal: Option<PathBuf>,
    /// File that receives every finding.
    pub log: Option<PathBuf>,
    /// Scan even a volume that is marked clean.
    pub force: bool,
    /// The ntfs-chkdsk command that performs each step.
    pub checker: PathBuf,
    /// Name that prefixes messages.
    pub program: &'static str,
}

fn check(request: &Request) -> io::Result<i32> {
    let Request { checker, device, program, .. } = request;
    let mut command = Command::new(checker);
    if let Some(log) = &request.log {
        command.arg("--log").arg(log);
    }
    println!("{program}: checking {}", device.display());
    let result = progress_display::run(command.arg("--progress").arg("--check").arg(device))?.code().unwrap_or(8);
    if result != 0 {
        return Ok(result);
    }
    // Structural assessment may pass while the dirty flag or recovery state
    // still needs attention. Keep that distinction in fsck's exit status.
    Ok(if requests_attention(device)? { 4 } else { 0 })
}

/// The volume's flags, journal or hibernation state ask for a check or for
/// work before it may be written. Reads a few records; scans nothing.
fn requests_attention(device: &Path) -> io::Result<bool> {
    let probe = checker::probe(device)?;
    let recovery = checker::inspect_recovery(checker::Image::open(device)?, probe.boot)?;
    // An active log client with nothing left to replay is our own durable
    // empty checkpoint, which the writer accepts.
    let unreplayed = recovery.log == ntfs_rs::logfile::LogState::ReplayRequired
        && !recovery_io::replay_is_empty(device).unwrap_or(false);
    Ok(probe.info.needs_check()
        || probe.info.has_work_requests()
        || probe.info.has_unsupported_flags()
        || unreplayed
        || recovery.log == ntfs_rs::logfile::LogState::NeedsReview
        || ntfs_rs::hibernation::write_gate(recovery.hibernation, false)
            != ntfs_rs::hibernation::HibernationWriteGate::Clear)
}

fn pending_journal(options: &Request) -> io::Result<Option<PathBuf>> {
    if let Some(journal) = &options.journal {
        return Ok(recovery_journal::exists(journal)?.then(|| journal.clone()));
    }
    use std::os::unix::fs::FileTypeExt;
    if !fs::metadata(&options.device)?.file_type().is_block_device() {
        return Ok(None);
    }
    recovery_journal::pending(&options.device, JournalKind::Repair)
}

/// Journal transactions still wait to be replayed, or an interrupted replay
/// waits to resume. Structural repair must only ever see the replayed volume.
fn replay_pending(device: &Path) -> io::Result<bool> {
    use std::os::unix::fs::FileTypeExt;
    if !fs::metadata(device)?.file_type().is_block_device() {
        return Ok(false);
    }
    if recovery_journal::pending(device, JournalKind::Replay)?.is_some() {
        return Ok(true);
    }
    let probe = checker::probe(device)?;
    let recovery = checker::inspect_recovery(checker::Image::open(device)?, probe.boot)?;
    Ok(recovery.log == ntfs_rs::logfile::LogState::ReplayRequired
        && !recovery_io::replay_is_empty(device).unwrap_or(false))
}

/// A pending external journal that belongs to a journal resize, not a repair.
fn is_log_resize_journal(journal: &Path) -> bool {
    let mut magic = [0; 8];
    fs::File::open(journal).and_then(|mut file| file.read_exact(&mut magic)).is_ok() && &magic == LOG_RESIZE_MAGIC
}

fn new_journal(options: &Request) -> io::Result<PathBuf> {
    if let Some(journal) = &options.journal {
        return Ok(journal.clone());
    }
    recovery_journal::new(&options.device, JournalKind::Repair)
}

/// Where the device is mounted, if it is.
fn mount_point(device: &Path) -> io::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;
    let target = fs::metadata(device)?.rdev();
    for line in fs::read_to_string("/proc/self/mounts")?.lines() {
        let mut fields = line.split(' ');
        let (Some(source), Some(place)) = (fields.next(), fields.next()) else {
            continue;
        };
        if source.starts_with('/') && fs::metadata(source).is_ok_and(|meta| meta.rdev() == target) {
            return Ok(Some(place.replace("\\040", " ")));
        }
    }
    Ok(None)
}

/// Keep the mount helper away from a block device for this whole run. Each
/// repair step closes the device, which makes udev offer it for mounting
/// again; the helper refuses while this lock is held, and holds it itself
/// while it mounts or recovers, so the two never work on one device at once.
fn offline_lock(device: &Path, program: &str) -> io::Result<Option<fs::File>> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::os::fd::AsRawFd;
    let metadata = fs::metadata(device)?;
    if !metadata.file_type().is_block_device() {
        return Ok(None);
    }
    let rdev = metadata.rdev();
    fs::DirBuilder::new().recursive(true).mode(0o755).create(LOCK_DIRECTORY)?;
    let name = format!("{LOCK_DIRECTORY}/offline-{:x}:{:x}.lock", libc::major(rdev), libc::minor(rdev));
    let lock = OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(name)?;
    // SAFETY: flock only needs the live descriptor owned by lock.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        eprintln!("{program}: waiting for the mount helper to finish with {}", device.display());
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Some(lock))
}

/// Check the device and, with consent, bring it to a state the driver may
/// write: resume interrupted work, replay the journal, repair structures and
/// answer Windows' requests. `consent` is absent for a read-only check;
/// otherwise it is asked once, with whether interrupted work would resume,
/// before the first write.
///
/// Returns the fsck exit status: 0 clean, 1 repaired, 4 unresolved, 8 failed.
pub fn run(mut options: Request, consent: Option<&mut dyn FnMut(&Path, bool) -> bool>) -> io::Result<i32> {
    // Callers may supply /dev/disk/by-uuid links. Resolve once; the backend
    // then claims the resulting device with O_EXCL and O_NOFOLLOW.
    options.device = fs::canonicalize(&options.device)?;
    let program = options.program;
    let _lock = offline_lock(&options.device, program)?;
    if let Some(place) = mount_point(&options.device)? {
        eprintln!("{program}: {} is mounted at {place}; unmount it first", options.device.display());
        return Ok(8);
    }
    let checker = options.checker.clone();
    let pending = pending_journal(&options)?;
    // Like other fsck programs, trust a volume that asks for nothing: Windows
    // does not scan one either. A scan remains one --force away.
    if !options.force && pending.is_none() && !requests_attention(&options.device)? {
        println!(
            "{program}: {} is marked clean and its journal is empty; not scanned (use --force for a full check)",
            options.device.display()
        );
        return Ok(0);
    }
    let Some(consent) = consent else {
        return check(&options);
    };
    // An interrupted journal resize resumes on its own path below.
    let resize_pending = pending.as_deref().is_some_and(is_log_resize_journal);
    if pending.is_none() {
        let result = check(&options)?;
        if result == 0 || result == 16 {
            return Ok(result);
        }
    }
    if !consent(&options.device, pending.is_some()) {
        return Ok(4);
    }
    if pending.is_none() && replay_pending(&options.device)? {
        println!("{program}: replaying the journal of {}", options.device.display());
        let replayed = progress_display::run(Command::new(&checker)
            .arg("--progress")
            .arg("--recover-for-mount")
            .arg(&options.device))?
            .code()
            .unwrap_or(8);
        if replayed == 0 && check(&options)? == 0 {
            return Ok(1);
        }
        // Replay alone was refused or left findings: structural repair
        // replays the journal itself before it repairs.
    }
    if !resize_pending {
        let resume = pending.is_some();
        let journal = match &pending {
            Some(journal) => journal.clone(),
            None => new_journal(&options)?,
        };
        println!(
            "{program}: {} {}; journal={}",
            if resume { "resuming repair of" } else { "repairing" },
            options.device.display(),
            journal.display()
        );
        let operation = if resume { "--resume-repair" } else { "--repair-in-place" };
        let result = progress_display::run(Command::new(&checker)
            .arg("--progress")
            .arg(operation)
            .arg(&options.device)
            .arg(&journal))?
            .code()
            .unwrap_or(8);
        if result != 0 {
            return Ok(result);
        }
    }
    // Windows asked for a journal resize (volume flag 0x0002). Its checker
    // resizes only a journal outside the supported range, to the default
    // size, and otherwise just clears the request; do the same. A journal
    // stored in several pieces is also rebuilt: our driver writes only to a
    // contiguous one.
    let probe = checker::probe(&options.device)?;
    if resize_pending || probe.info.flags & ntfs_rs::volume_info::VOLUME_RESIZE_LOG_FILE != 0 {
        let current = checker::inspect_logfile_size(checker::Image::open(&options.device)?, probe.boot)?;
        let bytes = if SUPPORTED_LOG_BYTES.contains(&current.data_bytes) && current.fragments == 1 && !resize_pending {
            current.data_bytes
        } else {
            checker::default_logfile_size(probe.boot)
        };
        let (operation, journal) = match pending.filter(|_| resize_pending) {
            Some(journal) => ("--resume-log-resize", journal),
            None => ("--resize-log-in-place", new_journal(&options)?),
        };
        println!(
            "{program}: answering the journal resize request on {} with {bytes} bytes; journal={}",
            options.device.display(),
            journal.display()
        );
        let result = progress_display::run(Command::new(&checker)
            .arg("--progress")
            .arg(operation)
            .arg(bytes.to_string())
            .arg(&options.device)
            .arg(&journal))?
            .code()
            .unwrap_or(8);
        if result != 0 {
            return Ok(result);
        }
    }
    // Only completed work followed by a successful full check reports 1.
    let checked = check(&options)?;
    Ok(if checked == 0 { 1 } else { checked })
}
