//! Module: slate_ntfs_tools::bin::ntfs_checkfs
//! Purpose: Provide the ntfs-checkfs command-line entry point.
//! Created: 2026-10-01
//! Architecture: Userspace commands use this module with checked core formats and owned image
//! I/O.

use slate_ntfs_tools::checker;

use std::env;
use std::io::Write;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: ntfs-checkfs [--status|--if-dirty] [--log PATH] <NTFS image or device>");
    std::process::exit(16)
}

fn main() {
    let mut args = env::args_os().skip(1);
    let (mut if_dirty, mut status_only, mut path, mut log) = (false, false, None, None);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--if-dirty") if !if_dirty && !status_only => if_dirty = true,
            Some("--status") if !if_dirty && !status_only => status_only = true,
            Some("--log") if log.is_none() => log = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            Some(flag) if flag.starts_with('-') => usage(),
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => usage(),
        }
    }
    let path = path.unwrap_or_else(|| usage());
    if status_only && log.is_some() {
        usage();
    }
    slate_ntfs_tools::bitlocker_cli::refuse_encrypted("ntfs-checkfs", [path.as_os_str()]);
    let probe = match checker::probe(&path) {
        Ok(probe) => probe,
        Err(error) => {
            eprintln!("ntfs-checkfs: cannot inspect volume: {error}");
            std::process::exit(8);
        }
    };
    if status_only {
        println!("dirty={}", u8::from(probe.info.is_dirty()));
        return;
    }
    println!(
        "NTFS {}.{}: {} (flags 0x{:04x})",
        probe.info.major_version,
        probe.info.minor_version,
        if probe.info.is_dirty() { "dirty" } else { "clean" },
        probe.info.flags
    );
    if if_dirty && !probe.info.is_dirty() && log.is_none() {
        println!("ntfs-checkfs: clean volume; deeper check skipped");
        return;
    }
    let report = match checker::check_device(&path, Default::default(), log.as_deref()) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("ntfs-checkfs: check failed: {error}");
            std::process::exit(8);
        }
    };
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    if let Err(error) = report.write_report(&mut output).and_then(|()| output.flush()) {
        eprintln!("ntfs-checkfs: cannot write report: {error}");
        std::process::exit(8);
    }
    if !report.passed() {
        eprintln!(
            "ntfs-checkfs: repair or recovery remains necessary (flags 0x{:04x}, journal {}, hibernated={})",
            report.volume_flags, report.log_state, report.hibernated
        );
        std::process::exit(4);
    }
    println!("ntfs-checkfs: full check passed");
}
