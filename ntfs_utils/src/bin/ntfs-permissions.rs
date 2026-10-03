//! Module: ntfs_utils::bin::ntfs_permissions
//! Purpose: Provide the ntfs-permissions command-line entry point.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

use ntfs_utils::{admin, OperationResult, Status};
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let result=run(&a).unwrap_or_else(||OperationResult::new(Status::InvalidArgument,
        "usage: ntfs-permissions device-mode DEVICE OCTAL | device-owner DEVICE UID GID | file-mode DEVICE MOUNTED_PATH OCTAL | file-owner DEVICE MOUNTED_PATH UID GID | file-acl DEVICE MOUNTED_PATH DESCRIPTOR_FILE"));
    println!("{}: {}", if result.is_success() { "SUCCESS" } else { "FAILURE" }, result.message);
    std::process::exit(result.status as i32);
}
fn run(a: &[String]) -> Option<OperationResult> {
    Some(match (a.first()?.as_str(), a.len()) {
        ("device-mode", 3) => admin::set_device_mode(&a[1], u32::from_str_radix(&a[2], 8).ok()?),
        ("device-owner", 4) => admin::set_device_owner(&a[1], a[2].parse().ok()?, a[3].parse().ok()?),
        ("file-mode", 4) => admin::set_file_mode(&a[1], &a[2], u32::from_str_radix(&a[3], 8).ok()?),
        ("file-owner", 5) => admin::set_file_owner(&a[1], &a[2], a[3].parse().ok()?, a[4].parse().ok()?),
        ("file-acl", 4) => match std::fs::read(&a[3]) {
            Ok(bytes) => admin::set_file_security(&a[1], &a[2], &bytes),
            Err(e) => OperationResult::new(Status::Failure, e.to_string()),
        },
        _ => return None,
    })
}
