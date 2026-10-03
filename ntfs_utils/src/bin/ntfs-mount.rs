//! Module: ntfs_utils::bin::ntfs_mount
//! Purpose: Provide the ntfs-mount command-line entry point.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

use ntfs_utils::mount::{mount_fs_bitlocker, SecretInput};
use ntfs_utils::{mount_fs, Compatibility, OperationResult, Status};
use std::path::Path;
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = run(&args).unwrap_or_else(|| OperationResult::new(Status::InvalidArgument,
        "usage: ntfs-mount DEVICE DIRECTORY --sidmap=MAP [--compatibility=linux|ntfs] [--read-only] [--show-hidden|--show-meta] \
         [--bitlocker=password|recovery|bek=FILE|clear [--secret-fd=N]]"));
    println!("{:?}: {}", result.status, result.message);
    std::process::exit(result.status as i32);
}
fn run(a: &[String]) -> Option<OperationResult> {
    if a.len() < 3 {
        return None;
    }
    let mut compatibility = Compatibility::default();
    let mut readonly = false;
    let mut visibility = ntfs_utils::Visibility::default();
    let mut sidmap = None;
    let mut bitlocker = None;
    let mut secret_fd = None;
    for arg in &a[2..] {
        if SecretInput::accept(&mut bitlocker, &mut secret_fd, arg).ok()? {
            continue;
        }
        if let Some(value) = arg.strip_prefix("--compatibility=") {
            compatibility = Compatibility::parse(value)?;
        } else if let Some(value) = arg.strip_prefix("--sidmap=") {
            if sidmap.replace(value).is_some() {
                return None;
            }
        } else if arg == "--show-hidden" {
            visibility = ntfs_utils::Visibility::all();
        } else if arg == "--show-meta" {
            visibility.show_metadata = true;
        } else if arg == "--read-only" {
            readonly = true;
        } else {
            return None;
        }
    }
    let device = Path::new(&a[0]);
    let target = Path::new(&a[1]);
    let result = match SecretInput::finish(bitlocker, secret_fd).ok()? {
        Some(input) => mount_fs_bitlocker(device, target, sidmap?, compatibility, readonly, &input),
        None => mount_fs(device, target, sidmap?, compatibility, readonly),
    };
    if result.status == Status::Success && visibility != ntfs_utils::Visibility::default() {
        if let Err(e) = ntfs_utils::set_visibility(target, visibility) {
            return Some(OperationResult::new(Status::Failure, format!("mounted; visibility update failed: {e}")));
        }
    }
    Some(result)
}
