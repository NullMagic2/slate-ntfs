//! Module: surface_scan_tests
//! Purpose: Verify complete sector coverage, device failures and source stability.
//! Created: 2026-10-02
//! Architecture: Fault readers exercise the shared scanner used by diagnostics
//!     and recovery; private files exercise the public source admission boundary.

use super::*;
use std::io::Cursor;
use std::path::PathBuf;

struct FaultReader {
    source: Cursor<Vec<u8>>,
    bad: Vec<std::ops::Range<u64>>,
    bulk_error: bool,
    prefix_error: bool,
    prefix_read: bool,
    interrupts: usize,
    short_limit: usize,
    errno: Option<i32>,
    seek_error: bool,
    alignment: usize,
}

impl FaultReader {
    fn new(length: usize) -> Self {
        Self {
            source: Cursor::new((0..length).map(|i| (i % 251) as u8).collect()),
            bad: Vec::new(),
            bulk_error: false,
            prefix_error: false,
            prefix_read: false,
            interrupts: 0,
            short_limit: usize::MAX,
            errno: None,
            seek_error: false,
            alignment: 0,
        }
    }
}

impl Read for FaultReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.alignment != 0 {
            assert_eq!(buffer.as_ptr().align_offset(self.alignment), 0);
            assert_eq!(buffer.len() % 512, 0);
            assert_eq!(self.source.position() % 512, 0);
        }
        if self.interrupts != 0 {
            self.interrupts -= 1;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if let Some(errno) = self.errno {
            return Err(io::Error::from_raw_os_error(errno));
        }
        if self.prefix_read {
            self.prefix_read = false;
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        if self.prefix_error && buffer.len() > 65536 {
            self.prefix_error = false;
            self.prefix_read = true;
            return self.source.read(&mut buffer[..123]);
        }
        if self.bulk_error && buffer.len() > 65536 {
            self.bulk_error = false;
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let start = self.source.position();
        let end = start + buffer.len() as u64;
        if self.bad.iter().any(|range| start < range.end && end > range.start) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let limit = buffer.len().min(self.short_limit);
        self.source.read(&mut buffer[..limit])
    }
}

impl Seek for FaultReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.seek_error {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        self.source.seek(position)
    }
}

fn classify(
    input: &mut FaultReader,
    range: std::ops::Range<u64>,
    sector: u32,
) -> (SurfaceReport, Vec<(u64, u64)>, Vec<RepairProgress>) {
    let mut coverage = vec![false; (range.end - range.start) as usize];
    let mut bad = Vec::new();
    let mut events = Vec::new();
    let origin = range.start;
    let source = input.source.get_ref().clone();
    let coverage = std::cell::RefCell::new(&mut coverage);
    let report = scan_surface_reader(
        input,
        range,
        sector,
        &mut |offset, bytes| {
            assert_eq!(offset % u64::from(sector), 0);
            assert_eq!(bytes.len() % sector as usize, 0);
            assert_eq!(bytes, &source[offset as usize..offset as usize + bytes.len()]);
            let mut coverage = coverage.borrow_mut();
            for covered in &mut coverage[(offset - origin) as usize..(offset - origin) as usize + bytes.len()] {
                assert!(!*covered, "duplicate readable classification");
                *covered = true;
            }
            Ok(())
        },
        &mut |offset, length| {
            assert_eq!(offset % u64::from(sector), 0);
            assert_eq!(length % u64::from(sector), 0);
            bad.push((offset, length));
            let mut coverage = coverage.borrow_mut();
            for covered in &mut coverage[(offset - origin) as usize..(offset + length - origin) as usize] {
                assert!(!*covered, "duplicate unreadable classification");
                *covered = true;
            }
            Ok(())
        },
        &mut |value| events.push(value),
    )
    .unwrap();
    assert!(coverage.borrow().iter().all(|value| *value));
    assert_eq!(events.first().unwrap().completed_sectors, 0);
    assert_eq!(events.last().unwrap().completed_sectors, report.total_bytes / 512);
    assert!(events.windows(2).all(|pair| { pair[0].completed_sectors < pair[1].completed_sectors }));
    (report, bad, events)
}

#[test]
fn failures_coalesce_across_bulk_boundary_and_flush_final_sector() {
    let length = 16 * 1024 * 1024;
    let mut input = FaultReader::new(length);
    input.bad = vec![0..512, 1048064..1050112, 16776704..16777216];
    let (report, bad, _) = classify(&mut input, 0..length as u64, 512);
    assert_eq!(bad, vec![(0, 512), (1048064, 2048), (16776704, 512)]);
    assert_eq!(report.unreadable_bytes, 3072);
    assert_eq!(report.io_error_count, 9);
}

#[test]
fn supported_geometry_and_nonzero_resume_ranges_cover_exactly_once() {
    for sector in [512, 4096, 65536] {
        let length = 3 * 1024 * 1024;
        let mut input = FaultReader::new(length);
        let start = u64::from(sector);
        input.alignment = sector as usize;
        input.bad = vec![start..start + u64::from(sector), 2 * start..3 * start];
        let (report, bad, _) = classify(&mut input, start..length as u64, sector);
        assert_eq!(bad, vec![(start, 2 * u64::from(sector))]);
        assert_eq!(report.total_bytes, length as u64 - start);
        assert_eq!(report.unreadable_bytes, 2 * u64::from(sector));
    }
}

#[test]
fn transient_bulk_error_retains_history_without_unreadable_sectors() {
    for partial in [false, true] {
        let mut input = FaultReader::new(2 * 1024 * 1024);
        input.bulk_error = !partial;
        input.prefix_error = partial;
        let (report, bad, _) = classify(&mut input, 0..2 * 1024 * 1024, 512);
        assert!(bad.is_empty());
        assert_eq!(report.unreadable_bytes, 0);
        assert_eq!(report.io_error_count, 1);
    }
}

#[test]
fn interrupted_and_short_reads_do_not_skip_bytes() {
    let mut input = FaultReader::new(1048576);
    input.interrupts = 3;
    input.short_limit = 137;
    let (report, _, _) = classify(&mut input, 0..1048576, 4096);
    assert_eq!(report.io_error_count, 0);
}

#[test]
fn nonmedia_seek_and_eof_fail_without_terminal_progress() {
    for mode in 0..5 {
        let mut input = FaultReader::new(if mode == 4 { 1023 } else { 1024 });
        input.errno = match mode {
            0 => Some(libc::EACCES),
            1 => Some(libc::EINVAL),
            2 => Some(libc::ENOSPC),
            _ => None,
        };
        input.seek_error = mode == 3;
        let mut events = Vec::new();
        let result = scan_surface_reader(
            &mut input,
            0..1024,
            512,
            &mut |_, _| panic!("failed chunk published"),
            &mut |_, _| panic!("nonmedia error classified"),
            &mut |value| events.push(value),
        );
        assert!(result.is_err());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].completed_sectors, 0);
    }
}

#[test]
fn callback_failures_do_not_publish_terminal_progress() {
    for kind in [io::ErrorKind::WriteZero, io::ErrorKind::Interrupted] {
        for damaged in [false, true] {
            let mut input = FaultReader::new(1024);
            if damaged {
                input.bad.push(0..1024);
            }
            let mut events = Vec::new();
            let result = scan_surface_reader(
                &mut input,
                0..1024,
                512,
                &mut |_, _| Err(io::Error::from(kind)),
                &mut |_, _| Err(io::Error::from(kind)),
                &mut |value| events.push(value),
            );
            assert_eq!(result.unwrap_err().kind(), kind);
            assert_eq!(events.len(), 1);
        }
    }
}

#[test]
fn invalid_geometry_is_rejected_before_io_or_progress() {
    for (range, sector) in
        [(0..0, 512), (0..1023, 512), (1..1024, 512), (0..1024, 256), (0..1024, 513), (0..131072, 131072)]
    {
        let mut input = FaultReader::new(1024);
        input.seek_error = true;
        assert!(scan_surface_reader(
            &mut input,
            range,
            sector,
            &mut |_, _| panic!("readable callback"),
            &mut |_, _| panic!("unreadable callback"),
            &mut |_| panic!("progress callback"),
        )
        .is_err());
    }
}

struct PrivateImage(PathBuf);

impl PrivateImage {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("slate-surface-{}-{nonce}.img", std::process::id()));
        std::fs::write(&path, vec![0x63; 1048576]).unwrap();
        Self(path)
    }
}

impl Drop for PrivateImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn public_scan_preserves_source_and_reports_exact_completion() {
    let image = PrivateImage::new();
    let original = std::fs::read(&image.0).unwrap();
    let mut events = Vec::new();
    let report = surface_check(&image.0, &mut |value| events.push(value), &mut |_, _| {
        panic!("healthy private image unreadable")
    })
    .unwrap();
    assert_eq!(report.total_bytes, original.len() as u64);
    assert_eq!(report.unreadable_bytes, 0);
    assert_eq!(events.last().unwrap().completed_sectors, 2048);
    assert_eq!(std::fs::read(&image.0).unwrap(), original);
}

#[test]
fn public_scan_refuses_cooperating_exclusive_owner() {
    use std::os::fd::AsRawFd;
    let image = PrivateImage::new();
    let owner = File::open(&image.0).unwrap();
    assert_eq!(unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX) }, 0);
    assert!(surface_check(&image.0, &mut |_| panic!("progress"), &mut |_, _| {}).is_err());
}

#[test]
fn public_scan_detects_content_length_and_path_replacement() {
    for mode in 0..4 {
        let image = PrivateImage::new();
        let mut events = Vec::new();
        let result = surface_check(
            &image.0,
            &mut |value| {
                if value.completed_sectors == 0 {
                    match mode {
                        0 => {
                            let mut writer = OpenOptions::new().write(true).open(&image.0).unwrap();
                            writer.write_all(&[0x22]).unwrap();
                            writer.sync_all().unwrap();
                        }
                        1 => OpenOptions::new().write(true).open(&image.0).unwrap().set_len(1049088).unwrap(),
                        3 => OpenOptions::new().write(true).open(&image.0).unwrap().set_len(512).unwrap(),
                        _ => {
                            std::fs::remove_file(&image.0).unwrap();
                            std::fs::write(&image.0, vec![0x63; 1048576]).unwrap();
                        }
                    }
                }
                events.push(value);
            },
            &mut |_, _| {},
        )
        .unwrap_err();
        assert_eq!(result.kind(), if mode == 3 { io::ErrorKind::UnexpectedEof } else { io::ErrorKind::Unsupported },);
        assert!(events.iter().all(|event| event.completed_sectors < event.total_sectors));
    }
}

#[test]
fn entirely_unreadable_range_publishes_once_before_completion() {
    let mut input = FaultReader::new(1049088);
    input.bad.push(0..1049088);
    let (report, bad, events) = classify(&mut input, 0..1049088, 512);
    assert_eq!(bad, vec![(0, 1049088)]);
    assert_eq!(report.unreadable_bytes, report.total_bytes);
    assert_eq!(events.len(), 2);
}

#[test]
fn regular_image_symlink_is_refused_before_scan() {
    let image = PrivateImage::new();
    let link = image.0.with_extension("link");
    std::os::unix::fs::symlink(&image.0, &link).unwrap();
    let result = surface_check(&link, &mut |_| panic!("progress"), &mut |_, _| {});
    std::fs::remove_file(link).unwrap();
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ELOOP));
}
