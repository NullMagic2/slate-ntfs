//! Module: kernel.tests.kernel_probe
//! Purpose: Verify kernel probe behavior on disposable fixtures.
//! Created: 2026-10-01
//! Architecture: Disposable fixtures exercise the production core or its mounted adapter and
//! verify resulting state.

#[path = "../ntfs_parser.rs"]
mod kernel_adapter;

// The probe-only host test links the Rust adapter without the C VFS bridge.
#[no_mangle]
pub extern "C" fn ntfs_rs_hold_at(
    _context: *mut std::ffi::c_void,
    _at: u64,
    _data: *const u8,
    _len: usize,
    _first: i32,
) -> i32 {
    -95
}

#[no_mangle]
pub extern "C" fn ntfs_rs_release_at(_context: *mut std::ffi::c_void, _at: u64, _len: usize) {}

#[no_mangle]
pub extern "C" fn ntfs_rs_write_data_at(
    _context: *mut std::ffi::c_void,
    _at: u64,
    _data: *const u8,
    _len: usize,
) -> i32 {
    -95
}

// No FPU section on the host: BitLocker paths use the portable engine.
#[no_mangle]
pub extern "C" fn ntfs_rs_simd_begin() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn ntfs_rs_simd_end() {}

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

unsafe extern "C" fn read_at(context: *mut c_void, offset: u64, output: *mut u8, length: usize) -> i32 {
    if context.is_null() || output.is_null() {
        return -22;
    }
    // SAFETY: The test passes its live File and allocated output buffer for
    // the entire synchronous call and no aliasing mutable reference exists.
    let file = unsafe { &mut *(context as *mut File) };
    let buffer = unsafe { std::slice::from_raw_parts_mut(output, length) };
    match file.seek(SeekFrom::Start(offset)).and_then(|_| file.read_exact(buffer)) {
        Ok(()) => 0,
        Err(_) => -5,
    }
}

#[test]
fn ffi_probe_reads_an_ntfs_image() {
    let Some(path) = std::env::var_os("NTFS_RS_TEST_IMAGE") else {
        return;
    };
    let mut file = File::open(path).unwrap();
    let mut boot = [0_u8; 512];
    file.read_exact(&mut boot).unwrap();
    let mut scratch = vec![0_u8; 3 * 65_536];
    // SAFETY: Pointers refer to live, non-overlapping buffers and the File
    // remains live until the synchronous probe completes.
    let status = unsafe {
        kernel_adapter::ntfs_rs_probe(
            boot.as_ptr(),
            boot.len(),
            (&mut file as *mut File).cast(),
            read_at,
            scratch.as_mut_ptr(),
            scratch.len(),
        )
    };
    assert_eq!(status, 0);
    boot[3] = 0;
    let status = unsafe {
        kernel_adapter::ntfs_rs_probe(
            boot.as_ptr(),
            boot.len(),
            (&mut file as *mut File).cast(),
            read_at,
            scratch.as_mut_ptr(),
            scratch.len(),
        )
    };
    assert_eq!(status, -22);
}

/// ntfs_rs_stat on record number of the image in file.
fn stat_record(file: &mut File, boot: &[u8; 512], number: u64) -> Option<kernel_adapter::NodeInfo> {
    let mut scratch = vec![0_u8; kernel_adapter::ntfs_rs_ea_scratch_size()];
    let mut info = kernel_adapter::NodeInfo {
        file_reference: 0,
        data_size: 0,
        flags: 0,
        mode: 0,
        links: 0,
        attributes: 0,
        times: [0; 4],
        allocated: 0,
        reparse_tag: 0,
        reserved: 0,
        linux_flags: 0,
    };
    // SAFETY: live, disjoint buffers; the File outlives the synchronous call.
    let status = unsafe {
        kernel_adapter::ntfs_rs_stat(
            boot.as_ptr(),
            boot.len(),
            (file as *mut File).cast(),
            read_at,
            scratch.as_mut_ptr(),
            scratch.len(),
            number,
            0,
            &mut info,
        )
    };
    (status == 0).then_some(info)
}

/// Add a WSL special-file reparse point (empty buffer) to record number.
fn add_lx_tag(path: &std::path::Path, boot: &[u8; 512], number: u64, tag: u32) {
    use kernel_adapter::format::{mft::MftRecord, record_edit, replay::protect_mft_record};
    use std::io::Write;
    let cluster = u64::from(u16::from_le_bytes([boot[11], boot[12]])) * u64::from(boot[13]);
    let mft = u64::from_le_bytes(boot[0x30..0x38].try_into().unwrap()) * cluster;
    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
    let mut raw = [0_u8; 1024];
    file.seek(SeekFrom::Start(mft + number * 1024)).unwrap();
    file.read_exact(&mut raw).unwrap();
    MftRecord::parse(&mut raw, 512).unwrap();
    let mut value = [0_u8; 8];
    value[..4].copy_from_slice(&tag.to_le_bytes());
    let mut attribute = [0_u8; 64];
    let n = record_edit::build_resident(0xc0, &[], &value, &mut attribute).unwrap();
    record_edit::insert(&mut raw, &attribute[..n]).unwrap();
    record_edit::validate(&raw).unwrap();
    protect_mft_record(&mut raw, 512).unwrap();
    file.seek(SeekFrom::Start(mft + number * 1024)).unwrap();
    file.write_all(&raw).unwrap();
}

/// Special files written by the engine ($LXMOD, 8-byte WSL $LXDEV) and
/// by WSL 2 / the SMB client (LX reparse tags) stat as Linux special files.
/// Set NTFS_RS_SPECIAL_IMAGE to an image kept by the writer_lifecycle test
/// special_files_and_temporary_files (SLATE_KEEP_IMAGE=1).
#[test]
fn stat_presents_special_files() {
    let Some(source) = std::env::var_os("NTFS_RS_SPECIAL_IMAGE") else {
        return;
    };
    let path = std::env::temp_dir().join(format!("slate-probe-special-{}.img", std::process::id()));
    std::fs::copy(source, &path).unwrap();
    let mut file = File::open(&path).unwrap();
    let mut boot = [0_u8; 512];
    file.read_exact(&mut boot).unwrap();
    let mut found = std::collections::BTreeMap::new();
    for number in 24..64 {
        if let Some(info) = stat_record(&mut file, &boot, number) {
            if info.mode != u32::MAX {
                found.insert(info.mode, (number, info.reserved, info.links, info.data_size));
            }
        }
    }
    // mode -> rdev (Linux MKDEV encoding), for the four special types.
    let expected = [(0o010600, 0), (0o140755, 0), (0o020666, 1 << 20 | 3), (0o060640, 259 << 20 | 0x12345)];
    for (mode, rdev) in expected {
        let (_, reserved, links, size) = found[&mode];
        assert_eq!((reserved, links, size), (rdev, 1, 0), "mode {mode:o}");
    }
    let (published, _, links, size) = found[&0o100600];
    assert_eq!((links, size), (1, 10_000));
    // WSL 2 special files: the reparse tag decides the type, $LXMOD keeps
    // the permissions; a device without $LXDEV is 0:0.
    let (socket, ..) = found[&0o140755];
    drop(file);
    add_lx_tag(&path, &boot, socket, 0x8000_0024);
    add_lx_tag(&path, &boot, published, 0x8000_0025);
    let mut file = File::open(&path).unwrap();
    let info = stat_record(&mut file, &boot, socket).unwrap();
    assert_eq!((info.mode, info.reparse_tag, info.reserved), (0o010755, 0, 0));
    let info = stat_record(&mut file, &boot, published).unwrap();
    assert_eq!((info.mode, info.reparse_tag, info.reserved), (0o020600, 0, 0));
    // An unknown non-link tag is still refused.
    drop(file);
    add_lx_tag(&path, &boot, found[&0o010600].0, 0x8000_0099);
    let mut file = File::open(&path).unwrap();
    assert!(stat_record(&mut file, &boot, found[&0o010600].0).is_none());
    std::fs::remove_file(path).unwrap();
}

#[no_mangle]
pub extern "C" fn ntfs_rs_mount_refusal(_context: *mut std::ffi::c_void, _reason: *const u8, _length: usize) {}
