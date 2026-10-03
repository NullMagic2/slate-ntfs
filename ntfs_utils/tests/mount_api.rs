//! Module: ntfs_utils.tests.mount_api
//! Purpose: Verify mount api behavior on disposable fixtures.
//! Created: 2026-10-01
//! Architecture: Disposable fixtures exercise the production core or its mounted adapter and
//! verify resulting state.

use ntfs_utils::{mount_fs, unmount_fs, Compatibility, Status};
use std::path::Path;

#[test]
fn reject_invalid_inputs_before_syscalls() {
    assert_eq!(
        mount_fs(Path::new("/dev/nonexistent"), Path::new("/media/test"), "bad-map", Compatibility::Ntfs, true).status,
        Status::InvalidArgument
    );
    assert_eq!(
        mount_fs(Path::new(""), Path::new("/media/test"), "u:0:S-1-5-18;g:0:S-1-5-32-544", Compatibility::Ntfs, true)
            .status,
        Status::InvalidArgument
    );
    assert_eq!(unmount_fs(Path::new("")).status, Status::InvalidArgument);
    assert_eq!(unmount_fs(Path::new("/media/invalid\0target")).status, Status::InvalidArgument);
}

#[test]
fn fresh_volume_has_consistent_metadata_and_admits_writer() {
    use ntfs_utils::{format_device, FormatOptions};
    let path = std::env::temp_dir().join(format!(
        "slate-fresh-{}-{}.img",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
    file.set_len(128 * 1024 * 1024).unwrap();
    drop(file);
    let result = format_device(&path, &FormatOptions { label: "SlateTest".into(), ..Default::default() });
    assert!(result.is_success(), "{}", result.message);
    let report = slate_ntfs_tools::checker::check_device(&path, Default::default(), None).unwrap();
    let mut output = Vec::new();
    report.write_report(&mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(report.passed(), "{text}");
    use std::io::Read;
    let mut file = std::fs::File::open(&path).unwrap();
    let mut boot = [0; 512];
    file.read_exact(&mut boot).unwrap();
    let boot = ntfs_rs::boot::BootSector::parse(&boot).unwrap();
    let mut scratch = vec![0; ntfs_rs::resident_writer::METADATA_SCRATCH_BYTES];
    assert!(ntfs_rs::resident_writer::Writer::prepare(&mut slate_ntfs_tools::checker::Image(file), boot, &mut scratch)
        .is_ok());
    std::fs::remove_file(path).unwrap();
}
