//! Module: slate_ntfs_tools::bin::fsck_ntfsrs
//! Purpose: Select read-only checking or journaled offline repair for fsck.
//! Created: 2026-10-01
//! Architecture: Owns argument, console and journal-selection policy. The sibling
//! ntfs-chkdsk command owns assessment, exclusive device claims and repair durability.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use recovery_journal::JournalKind;
use slate_ntfs_tools::{checker, recovery_journal};

const USAGE: &str = "Usage: fsck.ntfsrs [OPTIONS] DEVICE\n\n\
    --check          Check the complete volume without changing it\n\
    --repair         Check and repair an unmounted device when needed\n\
    --ask            Ask before repairing (default; 15-second console prompt)\n\
    --journal PATH   Keep repair preimages in this external journal\n\
    --log PATH       Save assessment findings to this file\n\
    --help           Show this help\n\n\
    System fsck aliases: -n = --check; -y, -a, -p = --repair.\n\
    Every invocation performs a full check; -f/--force and -T are accepted.";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Mode {
    #[default]
    Ask,
    Check,
    Repair,
}

#[derive(Debug)]
struct Options {
    device: PathBuf,
    mode: Mode,
    journal: Option<PathBuf>,
    log: Option<PathBuf>,
}

fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Options, &'static str> {
    let mut args = args.into_iter();
    let mut device = None;
    let mut selected = None;
    let mut journal = None;
    let mut log = None;
    let mut positional = false;
    while let Some(arg) = args.next() {
        let text = arg.to_str();
        if !positional && text == Some("--") {
            positional = true;
            continue;
        }
        if !positional && matches!(text, Some("--journal" | "--log")) {
            let target = if text == Some("--journal") { &mut journal } else { &mut log };
            if target.replace(PathBuf::from(args.next().ok_or(USAGE)?)).is_some() {
                return Err(USAGE);
            }
            continue;
        }
        let mode = if positional {
            None
        } else {
            match text {
                Some("--check") => Some(Mode::Check),
                Some("--repair") => Some(Mode::Repair),
                Some("--ask") => Some(Mode::Ask),
                Some("--force" | "-f" | "-T") => continue,
                Some(short) if short.len() > 1 && short.starts_with('-') && !short.starts_with("--") => {
                    for flag in short[1..].chars() {
                        let mode = match flag {
                            'n' => Mode::Check,
                            'y' | 'a' | 'p' => Mode::Repair,
                            'f' | 'T' => continue,
                            _ => return Err(USAGE),
                        };
                        if selected.is_some_and(|old| old != mode) {
                            return Err("conflicting check and repair modes");
                        }
                        selected = Some(mode);
                    }
                    continue;
                }
                Some(flag) if flag.starts_with('-') => return Err(USAGE),
                _ => None,
            }
        };
        if let Some(mode) = mode {
            if selected.is_some_and(|old| old != mode) {
                return Err("conflicting check and repair modes");
            }
            selected = Some(mode);
        } else if device.replace(PathBuf::from(arg)).is_some() {
            return Err(USAGE);
        }
    }
    Ok(Options { device: device.ok_or(USAGE)?, mode: selected.unwrap_or_default(), journal, log })
}

fn answer(byte: u8) -> Option<bool> {
    match byte {
        b'\r' | b'\n' | b'y' | b'Y' => Some(true),
        b's' | b'S' | b'n' | b'N' => Some(false),
        _ => None,
    }
}

/// An unanswered boot prompt leaves the device unchanged and reports exit 4.
fn prompt(device: &Path, resume: bool) -> bool {
    let Ok(mut console) = OpenOptions::new().read(true).write(true).open("/dev/console") else {
        eprintln!("fsck.ntfsrs: /dev/console unavailable; repair skipped");
        return false;
    };
    let Ok(mut input) = console.try_clone() else {
        return false;
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut answer = [0];
        if input.read(&mut answer).is_ok_and(|read| read == 1) {
            let _ = sender.send(answer[0]);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let remaining = left.as_secs().saturating_add(1);
        let action = if resume { "Resume journaled repair" } else { "Repair" };
        let _ = write!(
            console,
            "\r{action} {}? Preimages will be retained in an external journal. \
             Enter=yes, s+Enter=skip. Skipping in {remaining:2}s... ",
            device.display()
        );
        let _ = console.flush();
        let wait = left.min(Duration::from_secs(1));
        match receiver.recv_timeout(wait) {
            Ok(byte) => {
                if let Some(run) = answer(byte) {
                    let _ = writeln!(console);
                    return run;
                }
            }
            Err(RecvTimeoutError::Disconnected) => std::thread::sleep(wait),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    let _ = writeln!(console, "\nTimed out; repair skipped.");
    false
}

fn checker_path() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("ntfs-chkdsk")))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from("ntfs-chkdsk"))
}

fn check(checker: &Path, device: &Path, log: Option<&Path>) -> io::Result<i32> {
    let mut command = Command::new(checker);
    if let Some(log) = log {
        command.arg("--log").arg(log);
    }
    let result = command.arg("--check").arg(device).status()?.code().unwrap_or(8);
    if result != 0 {
        return Ok(result);
    }
    // Structural assessment may pass while the dirty flag or recovery state
    // still needs attention. Keep that distinction in fsck's exit status.
    let probe = checker::probe(device)?;
    let recovery = checker::inspect_recovery(checker::Image::open(device)?, probe.boot)?;
    let unresolved = probe.info.is_dirty()
        || probe.info.has_unsupported_flags()
        || matches!(recovery.log, ntfs_rs::logfile::LogState::NeedsReview | ntfs_rs::logfile::LogState::ReplayRequired)
        || ntfs_rs::hibernation::write_gate(recovery.hibernation, false)
            != ntfs_rs::hibernation::HibernationWriteGate::Clear;
    Ok(if unresolved { 4 } else { 0 })
}

fn pending_journal(options: &Options) -> io::Result<Option<PathBuf>> {
    if let Some(journal) = &options.journal {
        return Ok(recovery_journal::exists(journal)?.then(|| journal.clone()));
    }
    use std::os::unix::fs::FileTypeExt;
    if !fs::metadata(&options.device)?.file_type().is_block_device() {
        return Ok(None);
    }
    recovery_journal::pending(&options.device, JournalKind::Repair)
}

fn new_journal(options: &Options) -> io::Result<PathBuf> {
    if let Some(journal) = &options.journal {
        return Ok(journal.clone());
    }
    recovery_journal::new(&options.device, JournalKind::Repair)
}

fn run(mut options: Options) -> io::Result<i32> {
    // fsck may supply /dev/disk/by-uuid links. Resolve once; the backend then
    // claims the resulting device with O_EXCL and O_NOFOLLOW.
    options.device = fs::canonicalize(&options.device)?;
    let checker = checker_path();
    if options.mode == Mode::Check {
        return check(&checker, &options.device, options.log.as_deref());
    }
    let pending = pending_journal(&options)?;
    if pending.is_none() {
        let result = check(&checker, &options.device, options.log.as_deref())?;
        if result == 0 || result == 16 {
            return Ok(result);
        }
    }
    if options.mode == Mode::Ask && !prompt(&options.device, pending.is_some()) {
        return Ok(4);
    }
    let resume = pending.is_some();
    let journal = match pending {
        Some(journal) => journal,
        None => new_journal(&options)?,
    };
    println!(
        "fsck.ntfsrs: {} {}; journal={}",
        if resume { "resuming repair of" } else { "repairing" },
        options.device.display(),
        journal.display()
    );
    let operation = if resume { "--resume-repair" } else { "--repair-in-place" };
    let result = Command::new(&checker)
        .arg("--progress")
        .arg(operation)
        .arg(&options.device)
        .arg(&journal)
        .status()?
        .code()
        .unwrap_or(8);
    if result != 0 {
        return Ok(result);
    }
    // Only a completed repair followed by a successful full check reports 1.
    let checked = check(&checker, &options.device, options.log.as_deref())?;
    Ok(if checked == 0 { 1 } else { checked })
}

fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{USAGE}");
        return;
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("fsck.ntfsrs: {error}");
            std::process::exit(16);
        }
    };
    match run(options) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("fsck.ntfsrs: {error}");
            std::process::exit(8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(args: &[&str]) -> Result<Options, &'static str> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn repair_requires_selected_mode_or_affirmative_answer() {
        assert_eq!(options(&["device"]).unwrap().mode, Mode::Ask);
        assert_eq!(options(&["--repair", "device"]).unwrap().mode, Mode::Repair);
        assert_eq!(options(&["--check", "device"]).unwrap().mode, Mode::Check);
        assert_eq!(answer(b'\n'), Some(true));
        assert_eq!(answer(b'n'), Some(false));
        assert_eq!(answer(b's'), Some(false));
        assert_eq!(answer(b'x'), None);
    }

    #[test]
    fn system_fsck_aliases_preserve_the_write_boundary() {
        for flag in ["-y", "-a", "-p", "-fy", "-af"] {
            assert_eq!(options(&[flag, "device"]).unwrap().mode, Mode::Repair);
        }
        assert_eq!(options(&["-fn", "device"]).unwrap().mode, Mode::Check);
        for args in [["-n", "-y", "device"], ["--repair", "--check", "device"]] {
            assert!(options(&args).is_err());
        }
        assert!(options(&["-ny", "device"]).is_err());
    }

    #[test]
    fn paths_and_mode_selection_remain_unambiguous() {
        let parsed = options(&["--journal", "a path", "--repair", "--log", "log", "device"]).unwrap();
        assert_eq!(parsed.journal, Some(PathBuf::from("a path")));
        assert_eq!(parsed.log, Some(PathBuf::from("log")));
        assert!(options(&["--journal", "a", "--journal", "b", "device"]).is_err());
        assert!(options(&["--journal"]).is_err());
        assert!(options(&["device", "other"]).is_err());
        assert_eq!(options(&["--check", "--", "-device"]).unwrap().device, PathBuf::from("-device"));
    }
}
