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

/// Extents collected from ntfs_rs_map_file: logical, physical, length, flags.
unsafe extern "C" fn collect_extent(context: *mut c_void, logical: u64, physical: u64, length: u64, flags: u32) -> i32 {
    // SAFETY: The test passes its live extent vector for the synchronous call.
    let extents = unsafe { &mut *(context as *mut Vec<(u64, u64, u64, u32)>) };
    extents.push((logical, physical, length, flags));
    0
}

/// Readahead loads mapped pages straight from the device. Every initialized
/// extent ntfs_rs_map_file reports must hold the bytes ntfs_rs_read_file returns.
#[test]
fn mapped_extents_match_read_file() {
    const UNWRITTEN: u32 = 0x800;
    const INLINE: u32 = 0x200;
    const BATCH: usize = 4 * 65_536;
    let Some(path) = std::env::var_os("NTFS_RS_TEST_IMAGE") else {
        return;
    };
    let mut file = File::open(path).unwrap();
    let mut boot = [0_u8; 512];
    file.read_exact(&mut boot).unwrap();
    // SAFETY: boot is a live 512-byte buffer.
    let scratch_bytes = unsafe { kernel_adapter::ntfs_rs_read_scratch_size(boot.as_ptr(), boot.len()) };
    assert!(scratch_bytes > 0);
    let mut scratch = vec![0_u8; scratch_bytes as usize];
    let mut checked = 0;
    for number in 16..128 {
        let Some(info) = stat_record(&mut file, &boot, number) else {
            continue;
        };
        if info.flags & 2 != 0 || info.data_size == 0 {
            continue;
        }
        let mut data = vec![0_u8; info.data_size as usize];
        for (index, chunk) in data.chunks_mut(BATCH).enumerate() {
            // SAFETY: live, disjoint buffers; the File outlives the call.
            let status = unsafe {
                kernel_adapter::ntfs_rs_read_file(
                    boot.as_ptr(),
                    boot.len(),
                    (&mut file as *mut File).cast(),
                    read_at,
                    scratch.as_mut_ptr(),
                    scratch.len(),
                    info.file_reference,
                    (index * BATCH) as u64,
                    chunk.as_mut_ptr(),
                    chunk.len(),
                )
            };
            assert_eq!(status, 0, "read record {number}");
        }
        let mut extents: Vec<(u64, u64, u64, u32)> = Vec::new();
        // SAFETY: as above; extents outlives the synchronous callback use.
        let status = unsafe {
            kernel_adapter::ntfs_rs_map_file(
                boot.as_ptr(),
                (&mut file as *mut File).cast(),
                read_at,
                scratch.as_mut_ptr(),
                scratch.len(),
                info.file_reference,
                0,
                info.data_size,
                (&mut extents as *mut Vec<(u64, u64, u64, u32)>).cast(),
                collect_extent,
            )
        };
        assert_eq!(status, 0, "map record {number}");
        assert!(!extents.is_empty(), "record {number} has no extents");
        for (logical, physical, length, flags) in extents {
            if flags & (UNWRITTEN | INLINE) != 0 {
                continue;
            }
            let end = (logical + length).min(info.data_size);
            let mut disk = vec![0_u8; (end - logical) as usize];
            file.seek(SeekFrom::Start(physical)).unwrap();
            file.read_exact(&mut disk).unwrap();
            assert!(disk == data[logical as usize..end as usize], "record {number} extent at {logical}");
            checked += 1;
        }
    }
    assert!(checked > 0, "no nonresident extent was compared");
    // A scratch buffer smaller than the read_file layout is refused.
    let status = unsafe {
        kernel_adapter::ntfs_rs_map_file(
            boot.as_ptr(),
            (&mut file as *mut File).cast(),
            read_at,
            scratch.as_mut_ptr(),
            scratch.len() - 1,
            5,
            0,
            1,
            std::ptr::null_mut(),
            collect_extent,
        )
    };
    assert!(status < 0);
}

#[no_mangle]
pub extern "C" fn ntfs_rs_mount_refusal(_context: *mut std::ffi::c_void, _reason: *const u8, _length: usize) {}

/// Engine I/O over a test image copy. Pending metadata images stay in memory
/// until a checkpoint writes them, as the mounted adapter keeps them held.
struct HeldImage {
    file: File,
    held: Vec<(u64, Vec<u8>)>,
}

impl kernel_adapter::format::volume::ReadAt for HeldImage {
    fn read_exact_at(&mut self, offset: u64, data: &mut [u8]) -> kernel_adapter::format::Result<()> {
        use kernel_adapter::format::Error;
        self.file.seek(SeekFrom::Start(offset)).and_then(|_| self.file.read_exact(data)).map_err(|_| Error::Io)?;
        for (at, bytes) in &self.held {
            let from = offset.max(*at);
            let to = (offset + data.len() as u64).min(*at + bytes.len() as u64);
            if from < to {
                data[(from - offset) as usize..(to - offset) as usize]
                    .copy_from_slice(&bytes[(from - *at) as usize..(to - *at) as usize]);
            }
        }
        Ok(())
    }
}

impl kernel_adapter::format::resident_writer::WriteIo for HeldImage {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> kernel_adapter::format::Result<()> {
        use std::io::Write;
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.write_all(data))
            .map_err(|_| kernel_adapter::format::Error::Io)
    }

    fn flush(&mut self) -> kernel_adapter::format::Result<()> {
        self.file.sync_all().map_err(|_| kernel_adapter::format::Error::Io)
    }

    fn hold_at(&mut self, offset: u64, data: &[u8], _first: bool) -> kernel_adapter::format::Result<()> {
        match self.held.iter_mut().find(|(at, _)| *at == offset) {
            Some((_, bytes)) => {
                bytes.clear();
                bytes.extend_from_slice(data);
            }
            None => self.held.push((offset, data.to_vec())),
        }
        Ok(())
    }

    fn release_at(&mut self, offset: u64, _len: usize) {
        self.held.retain(|(at, _)| *at != offset);
    }
}

/// One getdents buffer: the names a single ntfs_rs_readdir call emitted
/// before the buffer filled, with their file references.
struct ListingBatch {
    limit: usize,
    entries: Vec<(Vec<u8>, u64)>,
}

unsafe extern "C" fn collect_name(context: *mut c_void, name: *const u8, length: usize, reference: u64, _: u64) -> i32 {
    // SAFETY: The test passes its live batch and Rust lends the name for this call.
    let batch = unsafe { &mut *(context as *mut ListingBatch) };
    if batch.entries.len() == batch.limit {
        return 1;
    }
    batch.entries.push((unsafe { std::slice::from_raw_parts(name, length) }.to_vec(), reference));
    0
}

/// rm -r reads a buffer of names, unlinks them, then reads on from its
/// cursor. Resuming after the last returned name must still reach every
/// entry; resuming by ordinal skipped as many entries as had been deleted.
#[test]
fn listing_resumes_after_deleted_names() {
    use kernel_adapter::format::{batch::BATCH_BYTES, boot::BootSector, file_lifecycle::NodeKind};
    use kernel_adapter::format::resident_writer::{Writer, METADATA_SCRATCH_BYTES};
    const ENTRIES: usize = 300;
    const BATCH: usize = 16;
    let Some(source) = std::env::var_os("SLATE_LIFECYCLE_SOURCE") else {
        return;
    };
    let path = std::env::temp_dir().join(format!("slate-probe-listing-{}.img", std::process::id()));
    std::fs::copy(source, &path).unwrap();
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let mut image = HeldImage { file, held: Vec::new() };
    let mut boot = [0_u8; 512];
    image.file.read_exact(&mut boot).unwrap();
    let parsed = BootSector::parse(&boot).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, parsed, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut sd = [0_u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    let root = (5_u64 << 48) | 5;
    let directory =
        writer.create_node(&mut image, root, "listing", NodeKind::Directory, &sd, 0, None, &[], &mut scratch).unwrap();
    for index in 0..ENTRIES {
        writer.file_lifecycle(&mut image, directory, &format!("entry-{index:03}"), None, &sd, 0, &mut scratch).unwrap();
    }
    writer.checkpoint(&mut image, &mut scratch).unwrap();

    let mut listing = vec![0_u8; 6 * 65_536];
    let mut cursor: Option<Vec<u8>> = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let mut batch = ListingBatch { limit: BATCH, entries: Vec::new() };
        let (resume, resume_length) = cursor.as_ref().map_or((std::ptr::null(), 0), |name| (name.as_ptr(), name.len()));
        let scratch_length = if resume_length == 0 { 3 * 65_536 } else { listing.len() };
        // SAFETY: Live, non-overlapping buffers; the File and batch outlive the call.
        let status = unsafe {
            kernel_adapter::ntfs_rs_readdir(
                boot.as_ptr(),
                boot.len(),
                (&mut image.file as *mut File).cast(),
                read_at,
                listing.as_mut_ptr(),
                scratch_length,
                directory,
                // As the VFS cursor does: the position after the names returned so far.
                seen.len() as u64,
                resume,
                resume_length,
                0,
                (&mut batch as *mut ListingBatch).cast(),
                collect_name,
            )
        };
        assert_eq!(status, 0);
        if batch.entries.is_empty() {
            break;
        }
        for (name, reference) in &batch.entries {
            assert!(seen.insert(name.clone()), "{} listed twice", String::from_utf8_lossy(name));
            writer.remove_node(&mut image, directory, name.as_slice(), *reference, false, &mut scratch).unwrap();
        }
        cursor = batch.entries.last().map(|(name, _)| name.clone());
        writer.checkpoint(&mut image, &mut scratch).unwrap();
    }
    assert_eq!(seen.len(), ENTRIES, "every entry must be listed before the directory is empty");
    writer.remove_node(&mut image, root, "listing", directory, false, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    std::fs::remove_file(path).unwrap();
}
