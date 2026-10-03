//! Module: slate_ntfs_tools::bin::ntfs_bitlocker
//! Purpose: Inspect BitLocker metadata and verify protectors.
//! Created: 2026-10-01
//! Architecture: The command delegates checked formats and unlocking to bitlocker_cli;
//! ntfs-mount owns dm-crypt mounting.

use slate_ntfs_tools::bitlocker_cli::{self, SecretInput, USAGE};
use std::fs::File;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: ntfs-bitlocker info DEVICE");
    eprintln!("       ntfs-bitlocker verify DEVICE {USAGE}");
    std::process::exit(16);
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ntfs-bitlocker: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage();
    }
    let device = PathBuf::from(&args[1]);
    if args[0] == "info" {
        if args.len() != 2 {
            usage();
        }
        print!("{}", bitlocker_cli::describe(&device)?);
        return Ok(());
    }
    if args[0] != "verify" {
        usage();
    }
    let mut input = None;
    let mut fd = None;
    for arg in &args[2..] {
        if !SecretInput::accept(&mut input, &mut fd, arg)? {
            usage();
        }
    }
    let Some(input) = SecretInput::finish(input, fd)? else { usage() };
    let mut file = File::open(&device)?;
    let header = bitlocker_cli::probe_file(&mut file)?.ok_or("not a BitLocker volume")?;
    let (unlocked, _) = bitlocker_cli::unlock(file, header, &input)?;
    println!("unlocked=1 method={} writable={}", unlocked.key.method.name(), u8::from(unlocked.info.fully_encrypted()));
    Ok(())
}
