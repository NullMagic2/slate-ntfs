//! Module: writer_lifecycle
//! Purpose: Exercise journal ordering, admission and file mutations on private image copies.
//! Created: 2026-10-01
//! Architecture: Host integration tests run the same writer used by the kernel adapter.

use ntfs_rs::{
    batch::BATCH_BYTES,
    boot::BootSector,
    resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES},
    volume::ReadAt,
    Error, Result,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};
struct Image {
    file: File,
    flushes: usize,
    last: (u64, usize),
    held: Vec<(u64, Vec<u8>)>,
    writes: usize,
    fail_write: Option<usize>,
    fail_flush: Option<usize>,
}
impl ReadAt for Image {
    fn read_exact_at(&mut self, offset: u64, data: &mut [u8]) -> Result<()> {
        self.last = (offset, data.len());
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
impl WriteIo for Image {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.writes += 1;
        if self.fail_write == Some(self.writes) {
            return Err(Error::Io);
        }
        self.last = (offset, data.len());
        self.file.seek(SeekFrom::Start(offset)).and_then(|_| self.file.write_all(data)).map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> Result<()> {
        self.flushes += 1;
        if self.fail_flush == Some(self.flushes) {
            return Err(Error::Io);
        }
        self.file.sync_all().map_err(|_| Error::Io)
    }
    fn hold_at(&mut self, offset: u64, data: &[u8], _first: bool) -> Result<()> {
        if let Some((_, bytes)) = self.held.iter_mut().find(|(at, _)| *at == offset) {
            bytes.clear();
            bytes.extend_from_slice(data);
        } else {
            self.held.push((offset, data.to_vec()));
        }
        Ok(())
    }
    fn release_at(&mut self, offset: u64, _len: usize) {
        self.held.retain(|(at, _)| *at != offset);
    }
}
#[test]
fn create_and_delete_on_exclusive_image_copy() {
    let source =
        std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a fresh disposable image");
    let path = std::env::temp_dir().join(format!("slate-lifecycle-{}.img", std::process::id()));
    let mut target = OpenOptions::new().create_new(true).read(true).write(true).open(&path).unwrap();
    std::io::copy(&mut File::open(source).unwrap(), &mut target).unwrap();
    let mut image = Image {
        file: target,
        flushes: 0,
        last: (0, 0),
        held: Vec::new(),
        writes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut raw = [0; 512];
    image.read_exact_at(0, &mut raw).unwrap();
    let boot = BootSector::parse(&raw).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut sd = [0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let result = writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "created.bin", None, &sd, 0, &mut scratch);
    let reference = result.unwrap_or_else(|e| {
        panic!("create {e:?}, flushes {}, last {:?}, image {}", image.flushes, image.last, path.display())
    });
    let data = vec![0x5a; 64 * 1024];
    writer.write(&mut image, reference, 0, &data, &mut scratch).unwrap();
    writer.resize(&mut image, reference, 1 << 20, &mut scratch).unwrap();
    writer.write(&mut image, reference, (1 << 20) - 4096, &data[..4096], &mut scratch).unwrap();
    assert!(writer.pending() > 0);
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(writer.pending(), 0);
    assert!(!image.held.is_empty());
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let first = writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "queued-a", None, &sd, 0, &mut scratch).unwrap();
    let second = writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "queued-b", None, &sd, 0, &mut scratch).unwrap();
    assert!(writer.pending() > 0);
    writer.drain(&mut image, &mut scratch).unwrap();
    for (name, reference) in [("queued-a", first), ("queued-b", second)] {
        writer.file_lifecycle(&mut image, (5u64 << 48) | 5, name, Some(reference), &[], 0, &mut scratch).unwrap();
    }
    writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "created.bin", Some(reference), &[], 0, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn real_batch_drain_poisoned_at_write_and_flush_boundaries() {
    let source =
        std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a fresh disposable image");
    for fail_flush in [false, true] {
        let mut point = 0;
        let mut limit = 0;
        loop {
            let path =
                std::env::temp_dir().join(format!("slate-drain-{}-{fail_flush}-{point}.img", std::process::id()));
            std::fs::copy(&source, &path).unwrap();
            let mut image = Image {
                file: OpenOptions::new().read(true).write(true).open(&path).unwrap(),
                flushes: 0,
                last: (0, 0),
                held: Vec::new(),
                writes: 0,
                fail_write: None,
                fail_flush: None,
            };
            let mut raw = [0; 512];
            image.read_exact_at(0, &mut raw).unwrap();
            let boot = BootSector::parse(&raw).unwrap();
            let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
            let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
            writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
            writer.initialize(&mut image, &mut scratch).unwrap();
            let mut sd = [0u8; 20];
            sd[0] = 1;
            sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
            writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "created.bin", None, &sd, 0, &mut scratch).unwrap();
            assert!(writer.pending() > 0);
            image.writes = 0;
            image.flushes = 0;
            let held_before = image.held.clone();
            if point == 0 {
                writer.drain(&mut image, &mut scratch).unwrap();
                limit = if fail_flush { image.flushes } else { image.writes };
                assert!(limit > 0);
            } else if fail_flush {
                image.fail_flush = Some(point);
            } else {
                image.fail_write = Some(point);
            }
            if point != 0 {
                assert_eq!(
                    writer.drain(&mut image, &mut scratch),
                    Err(Error::Io),
                    "fail_flush={fail_flush} point={point} writes={} flushes={}",
                    image.writes,
                    image.flushes
                );
                // Failed commits retain private overlays until teardown;
                // poisoning prevents them from reaching checkpoint writeback.
                assert_eq!(image.held, held_before);
                assert_eq!(writer.drain(&mut image, &mut scratch), Err(Error::Io));
                assert_eq!(writer.checkpoint(&mut image, &mut scratch), Err(Error::Io));
            }
            drop(image);
            std::fs::remove_file(path).unwrap();
            point += 1;
            if point > limit {
                break;
            }
        }
    }
}

fn open_copy(source: &str, tag: &str) -> (Image, std::path::PathBuf, BootSector) {
    let path = std::env::temp_dir().join(format!("slate-{tag}-{}.img", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::copy(source, &path).unwrap();
    let mut image = Image {
        file: OpenOptions::new().read(true).write(true).open(&path).unwrap(),
        flushes: 0,
        last: (0, 0),
        held: Vec::new(),
        writes: 0,
        fail_write: None,
        fail_flush: None,
    };
    let mut raw = [0; 512];
    image.read_exact_at(0, &mut raw).unwrap();
    let boot = BootSector::parse(&raw).unwrap();
    (image, path, boot)
}

fn start(image: &mut Image, boot: BootSector, scratch: &mut [u8]) -> Writer {
    let mut writer = Writer::prepare(&mut *image, boot, scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut *image, scratch).unwrap();
    writer
}

/// Decoded view of one MFT record: flags, header link count, $FILE_NAME
/// values and the complete EA stream.
struct Node {
    flags: u16,
    links: u16,
    names: Vec<Vec<u8>>,
    eas: Vec<u8>,
    has_attribute_list: bool,
    data_size: u64,
}

fn node(image: &mut Image, boot: BootSector, reference: u64) -> Node {
    use ntfs_rs::{ea, mft::MftRecord, volume::Volume};
    let mut zero = vec![0u8; 1024];
    let mut raw = vec![0u8; 1024];
    let mut eas = vec![0u8; ea::MAX_STREAM];
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    volume.read_mft_record(&mft, reference & 0x0000_ffff_ffff_ffff, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, 512).unwrap();
    let mut names = Vec::new();
    let mut has_attribute_list = false;
    let mut data_size = 0;
    for a in record.attributes() {
        let a = a.unwrap();
        if a.kind == 0x30 {
            names.push(a.resident_value().unwrap().to_vec());
        } else if a.kind == 0x20 {
            has_attribute_list = true;
        } else if a.kind == 0x80 && a.name_utf16le().unwrap().is_empty() {
            data_size = a.data_size().unwrap();
        }
    }
    let flags = record.flags().unwrap();
    let links = record.link_count().unwrap();
    let n = if flags & 1 != 0 { ea::read_stream(&mut volume, &record, &mut eas).unwrap() } else { 0 };
    eas.truncate(n);
    Node { flags, links, names, eas, has_attribute_list, data_size }
}

fn filename_extension_records(image: &mut Image, boot: BootSector, reference: u64) -> usize {
    use ntfs_rs::{attrlist::AttributeList, mft::MftRecord, volume::Volume};
    use std::collections::BTreeSet;

    let number = reference & 0x0000_ffff_ffff_ffff;
    let mut zero = vec![0u8; 1024];
    let mut raw = vec![0u8; 1024];
    let mut extension = vec![0u8; 1024];
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    volume.read_mft_record(&mft, number, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, 512).unwrap();
    let attr = record
        .attributes()
        .map(Result::unwrap)
        .find(|a| a.kind == 0x20)
        .expect("hard-link spill must create $ATTRIBUTE_LIST");
    let mut list = vec![0; attr.data_size().unwrap() as usize];
    volume.read_attribute(attr, 0, &mut list).unwrap();
    let mut refs = BTreeSet::new();
    for entry in AttributeList::new(&list) {
        let entry = entry.unwrap();
        if entry.kind != 0x30 || entry.file_reference & 0x0000_ffff_ffff_ffff == number {
            continue;
        }
        let ext_number = entry.file_reference & 0x0000_ffff_ffff_ffff;
        volume.read_mft_record(&mft, ext_number, &mut extension).unwrap();
        let ext = MftRecord::parse(&mut extension, 512).unwrap();
        assert_eq!(ext.base_file_reference().unwrap(), reference);
        assert_eq!(ext.sequence_number().unwrap(), (entry.file_reference >> 48) as u16);
        assert!(ext.attributes().any(|a| { a.is_ok_and(|a| a.kind == 0x30 && a.id == entry.attribute_id) }));
        refs.insert(entry.file_reference);
    }
    refs.len()
}

fn read_resolved(image: &mut Image, boot: BootSector, reference: u64) -> Vec<u8> {
    use ntfs_rs::{mft::MftRecord, volume::Volume};
    let mut zero = vec![0u8; 1024];
    let mut raw = vec![0u8; 1024];
    let mut extension = vec![0u8; 2 * ntfs_rs::tx::RECORD_IMAGE + 1024];
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    volume.read_mft_record(&mft, reference & 0x0000_ffff_ffff_ffff, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, 512).unwrap();
    let size = volume.data_size_resolved(&mft, &record, reference & 0x0000_ffff_ffff_ffff, &mut extension).unwrap();
    let mut data = vec![0u8; size as usize];
    volume.read_data_resolved(&mft, &record, reference & 0x0000_ffff_ffff_ffff, &mut extension, 0, &mut data).unwrap();
    data
}

/// Interleaved appends force hundreds of physical fragments. Verify every
/// byte after journal checkpoint and writer restart, including sparse reads
/// and later writes through the reassembled attribute family.
#[test]
fn fragmented_copy_survives_checkpoint_restart_and_sparse_overwrite() {
    let source =
        std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a fresh disposable image");
    let (mut image, path, boot) = open_copy(&source, "fragmented-copy");
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut descriptor = [0_u8; 20];
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    let mut files = Vec::new();
    for name in ["fragmented-a", "fragmented-b"] {
        files.push(
            writer.file_lifecycle(&mut image, (5_u64 << 48) | 5, name, None, &descriptor, 0, &mut scratch).unwrap(),
        );
    }

    let mut expected = [Vec::new(), Vec::new()];
    let mut block = vec![0; 64 * 1024];
    for index in 0..384 {
        for (file, &reference) in files.iter().enumerate() {
            block.fill((index * 7 + file * 31) as u8);
            writer.write(&mut image, reference, (index * block.len()) as u64, &block, &mut scratch).unwrap_or_else(
                |error| {
                    panic!("fragment {index}, file {file}: {error:?}");
                },
            );
            expected[file].extend_from_slice(&block);
        }
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let mut writer = start(&mut image, boot, &mut scratch);
    for (file, &reference) in files.iter().enumerate() {
        assert!(node(&mut image, boot, reference).has_attribute_list);
        assert_eq!(read_resolved(&mut image, boot, reference), expected[file]);
    }

    // Punch whole clusters in a split stream, read zeros, then allocate and
    // overwrite the hole. This exercises real sparse flags and bitmap edits.
    let offset = 128 * 64 * 1024;
    writer.fallocate(&mut image, files[0], offset as u64, 8192, 3, &mut scratch).unwrap();
    expected[0][offset..offset + 8192].fill(0);
    assert_eq!(read_resolved(&mut image, boot, files[0]), expected[0]);
    writer.write(&mut image, files[0], offset as u64, &block[..8192], &mut scratch).unwrap();
    expected[0][offset..offset + 8192].copy_from_slice(&block[..8192]);
    writer.finish(&mut image, &mut scratch).unwrap();
    for (file, &reference) in files.iter().enumerate() {
        assert_eq!(read_resolved(&mut image, boot, reference), expected[file]);
    }
    drop(image);
    std::fs::remove_file(path).unwrap();
}

/// Hard-link creation is not constrained by the free bytes in the base FILE
/// record.  Long names spill into multiple extension records, are described by
/// a checked resident $ATTRIBUTE_LIST, survive remount, and collapse back to
/// a base-only family when those links are removed.
#[test]
fn hard_links_spill_across_multiple_extension_records() {
    let source =
        std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a fresh disposable image");
    let root = (5u64 << 48) | 5;
    let (mut image, path, boot) = open_copy(&source, "hard-link-extensions");
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut sd = [0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let reference = writer.file_lifecycle(&mut image, root, "link-base", None, &sd, 0, &mut scratch).unwrap();

    let mut names = Vec::new();
    for i in 0..12 {
        let name = format!("hard-link-extension-{i:02}-{}", "x".repeat(180));
        writer.with_compatibility(true, |w| w.hard_link(&mut image, reference, root, &name, &mut scratch)).unwrap();
        names.push(name);
    }
    writer.drain(&mut image, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let linked = node(&mut image, boot, reference);
    assert_eq!(linked.links, 13);
    assert!(linked.has_attribute_list);
    assert!(
        filename_extension_records(&mut image, boot, reference) >= 2,
        "twelve long names must occupy multiple filename extension records"
    );

    writer.finish(&mut image, &mut scratch).unwrap();
    let mut writer = start(&mut image, boot, &mut scratch);
    assert_eq!(node(&mut image, boot, reference).links, 13);
    assert!(filename_extension_records(&mut image, boot, reference) >= 2);

    for name in names {
        writer
            .with_compatibility(true, |w| w.remove_node(&mut image, root, &name, reference, false, &mut scratch))
            .unwrap();
    }
    writer.drain(&mut image, &mut scratch).unwrap();
    let collapsed = node(&mut image, boot, reference);
    assert_eq!(collapsed.links, 1);
    assert!(!collapsed.has_attribute_list, "empty filename extension records and their list must be reclaimed");
    writer.finish(&mut image, &mut scratch).unwrap();
    drop(image);
    std::fs::remove_file(path).unwrap();
}

/// Truncation edits the base unnamed stream while a resident attribute list
/// owns filename extension records.  This is a regression test for the VFS
/// setattr path: resizing must neither discard the list nor make extension
/// hard links stale.
#[test]
fn truncate_preserves_filename_extension_records() {
    let source =
        std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a fresh disposable image");
    let root = (5u64 << 48) | 5;
    let (mut image, path, boot) = open_copy(&source, "truncate-extensions");
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut sd = [0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let reference = writer.file_lifecycle(&mut image, root, "truncate-base", None, &sd, 0, &mut scratch).unwrap();

    let mut names = Vec::new();
    for i in 0..10 {
        let name = format!("truncate-extension-{i:02}-{}", "x".repeat(180));
        writer.with_compatibility(true, |w| w.hard_link(&mut image, reference, root, &name, &mut scratch)).unwrap();
        names.push(name);
    }
    writer.drain(&mut image, &mut scratch).unwrap();
    let before = node(&mut image, boot, reference);
    assert_eq!(before.links, 11);
    assert!(before.has_attribute_list, "long hard links must create an $ATTRIBUTE_LIST");
    assert!(before.names.len() < usize::from(before.links), "at least one $FILE_NAME must live in an extension record");

    let original = vec![0x5au8; 32 * 1024];
    writer.write(&mut image, reference, 0, &original, &mut scratch).unwrap();
    writer.resize(&mut image, reference, 5000, &mut scratch).unwrap();
    writer.resize(&mut image, reference, 12_000, &mut scratch).unwrap();
    writer.write(&mut image, reference, 9000, b"extension-tail", &mut scratch).unwrap();
    writer.resize(&mut image, reference, 10_000, &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();

    let after = node(&mut image, boot, reference);
    assert_eq!(after.links, 11);
    assert!(after.has_attribute_list);
    assert_eq!(after.data_size, 10_000);
    let data = read_resolved(&mut image, boot, reference);
    assert_eq!(data.len(), 10_000);
    assert_eq!(&data[..5000], &original[..5000]);
    assert!(data[5000..9000].iter().all(|byte| *byte == 0));
    assert_eq!(&data[9000..9014], b"extension-tail");
    assert!(data[9014..].iter().all(|byte| *byte == 0));

    writer.finish(&mut image, &mut scratch).unwrap();
    let mut writer = start(&mut image, boot, &mut scratch);
    let remounted = node(&mut image, boot, reference);
    assert_eq!((remounted.links, remounted.data_size), (11, 10_000));
    assert!(remounted.has_attribute_list);
    assert_eq!(read_resolved(&mut image, boot, reference), data);

    for name in names {
        writer
            .with_compatibility(true, |w| w.remove_node(&mut image, root, &name, reference, false, &mut scratch))
            .unwrap();
    }
    writer.file_lifecycle(&mut image, root, "truncate-base", Some(reference), &[], 0, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    drop(image);
    std::fs::remove_file(path).unwrap();
}

fn ea_value(stream: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    ntfs_rs::ea::find(stream, name).unwrap().map(<[u8]>::to_vec)
}

/// mknod(2) and O_TMPFILE at the engine level: special files are ordinary
/// records typed by $LXMOD (plus the WSL 8-byte $LXDEV for devices);
/// temporary files are nameless marked orphans that hard_link publishes,
/// reclaim_orphan frees on close, and reclaim_orphans frees after a crash.
#[test]
fn special_files_and_temporary_files() {
    use ntfs_rs::{
        file_lifecycle::{NodeKind, ORPHAN},
        unix_metadata::{device_bytes, DEVICE, MODE},
    };
    let source =
        std::env::var("SLATE_LIFECYCLE_SOURCE").expect("Set SLATE_LIFECYCLE_SOURCE to a fresh disposable image");
    let root = (5u64 << 48) | 5;
    let (mut image, path, boot) = open_copy(&source, "special");
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut sd = [0u8; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());

    // Special files, Linux view.
    let specials = [
        ("fifo", 0o010600u32, 0u32, 0u32),
        ("sock", 0o140755, 0, 0),
        ("null", 0o020666, 1, 3),
        ("disk", 0o060640, 259, 0x12345),
    ];
    let mut created = Vec::new();
    for (name, mode, major, minor) in specials {
        let reference = writer
            .with_compatibility(true, |w| {
                w.create_node(
                    &mut image,
                    root,
                    name,
                    NodeKind::Special(mode, major, minor),
                    &sd,
                    0,
                    Some(mode & 0o7777),
                    &[],
                    &mut scratch,
                )
            })
            .unwrap_or_else(|e| panic!("mknod {name}: {e:?}"));
        created.push((name, mode, major, minor, reference));
    }
    // A regular type is not a special node; the native view has no special files.
    for (linux, mode) in [(true, 0o100644u32), (true, 0o040755), (false, 0o010644)] {
        let result = writer.with_compatibility(linux, |w| {
            w.create_node(&mut image, root, "refused", NodeKind::Special(mode, 0, 0), &sd, 0, None, &[], &mut scratch)
        });
        assert_eq!(result, Err(Error::Unsupported), "mode {mode:o} linux {linux}");
    }
    writer.drain(&mut image, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    for &(name, mode, major, minor, reference) in &created {
        let n = node(&mut image, boot, reference);
        assert_eq!((n.flags, n.links, n.names.len()), (1, 1, 1), "{name}");
        assert_eq!(ea_value(&n.eas, MODE), Some(mode.to_le_bytes().to_vec()), "{name}");
        let device = ea_value(&n.eas, DEVICE);
        if matches!(mode & 0o170000, 0o020000 | 0o060000) {
            assert_eq!(device, Some(device_bytes(major, minor).to_vec()), "{name}");
            assert_eq!(ntfs_rs::unix_metadata::device_from(&device.unwrap()), Some((major, minor)));
        } else {
            assert_eq!(device, None, "{name}");
        }
        assert_eq!(ea_value(&n.eas, ORPHAN), None);
    }
    // chmod keeps the special type.
    let fifo = created[0].4;
    writer.set_unix_mode(&mut image, fifo, 0o640, &mut scratch).unwrap();
    // Hard links to special files, then removal of every name.
    writer.with_compatibility(true, |w| w.hard_link(&mut image, fifo, root, "fifo-2", &mut scratch)).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    let n = node(&mut image, boot, fifo);
    assert_eq!(ea_value(&n.eas, MODE), Some(0o010640u32.to_le_bytes().to_vec()));
    assert_eq!((n.links, n.names.len()), (2, 2));
    for &(name, _, _, _, reference) in &created {
        writer
            .with_compatibility(true, |w| w.remove_node(&mut image, root, name, reference, false, &mut scratch))
            .unwrap();
    }
    assert_eq!(node(&mut image, boot, fifo).links, 1);
    writer.with_compatibility(true, |w| w.remove_node(&mut image, root, "fifo-2", fifo, false, &mut scratch)).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    for &(name, _, _, _, reference) in &created {
        assert_eq!(node(&mut image, boot, reference).flags & 1, 0, "{name} freed");
    }

    // O_TMPFILE, then linkat(AT_EMPTY_PATH).
    let temporary = |writer: &mut Writer, image: &mut Image, scratch: &mut [u8]| {
        writer
            .with_compatibility(true, |w| {
                w.create_node(&mut *image, root, "", NodeKind::Temporary, &sd, 0, Some(0o600), &[], scratch)
            })
            .unwrap()
    };
    let published = temporary(&mut writer, &mut image, &mut scratch);
    let n = node(&mut image, boot, published);
    assert_eq!((n.flags, n.links, n.names.len()), (1, 0, 0));
    assert!(ea_value(&n.eas, ORPHAN).is_some());
    assert_eq!(ea_value(&n.eas, MODE), Some(0o100600u32.to_le_bytes().to_vec()));
    let data = vec![0x6b; 10_000];
    writer.write(&mut image, published, 0, &data, &mut scratch).unwrap();
    writer.with_compatibility(true, |w| w.hard_link(&mut image, published, root, "published", &mut scratch)).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    let n = node(&mut image, boot, published);
    assert_eq!((n.flags, n.links, n.names.len()), (1, 1, 1));
    assert_eq!(ea_value(&n.eas, ORPHAN), None);
    assert_eq!(ea_value(&n.eas, MODE), Some(0o100600u32.to_le_bytes().to_vec()));
    let name = &n.names[0];
    assert_eq!(u64::from_le_bytes(name[48..56].try_into().unwrap()), 10_000);
    assert!(u64::from_le_bytes(name[40..48].try_into().unwrap()) >= 10_000);
    assert_eq!(&name[..8], &root.to_le_bytes());
    // A published file is no longer an orphan and cannot be reclaimed as one.
    assert!(writer.reclaim_orphan(&mut image, published, &mut scratch).is_err());
    writer.finish(&mut image, &mut scratch).unwrap();
    let mut writer = start(&mut image, boot, &mut scratch);

    // Final close without a name frees the record and its clusters.
    let closed = temporary(&mut writer, &mut image, &mut scratch);
    writer.write(&mut image, closed, 0, &data, &mut scratch).unwrap();
    writer.reclaim_orphan(&mut image, closed, &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(node(&mut image, boot, closed).flags & 1, 0);

    // Crash while a temporary file is open: the next mount frees it.
    let lost = temporary(&mut writer, &mut image, &mut scratch);
    writer.write(&mut image, lost, 0, &data, &mut scratch).unwrap();
    // Unmount with the handle still open. After a power cut, log replay
    // (covered by the crash suites) yields this same state: a committed,
    // nameless record carrying the orphan mark.
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(ea_value(&node(&mut image, boot, lost).eas, ORPHAN).is_some());
    let mut writer = start(&mut image, boot, &mut scratch);
    assert_eq!(writer.reclaim_orphans(&mut image, &mut scratch).unwrap(), 1);
    assert_eq!(node(&mut image, boot, lost).flags & 1, 0);
    assert_eq!(node(&mut image, boot, published).links, 1);
    // Leave one of each special type for offline checkers (SLATE_KEEP_IMAGE).
    for (name, mode, major, minor) in specials {
        writer
            .with_compatibility(true, |w| {
                w.create_node(
                    &mut image,
                    root,
                    name,
                    NodeKind::Special(mode, major, minor),
                    &sd,
                    0,
                    None,
                    &[],
                    &mut scratch,
                )
            })
            .unwrap();
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    drop(image);
    if std::env::var_os("SLATE_KEEP_IMAGE").is_some() {
        eprintln!("kept {}", path.display());
    } else {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn unsupported_geometry_reports_reason_without_io() {
    struct NoIo;
    impl ReadAt for NoIo {
        fn read_exact_at(&mut self, _: u64, _: &mut [u8]) -> Result<()> {
            panic!("unsupported geometry must be rejected before disk access")
        }
    }
    let boot = BootSector {
        bytes_per_sector: 4096,
        sectors_per_cluster: 1,
        cluster_bytes: 4096,
        total_sectors: 1024,
        mft_lcn: 4,
        mft_mirror_lcn: 8,
        record_bytes: 4096,
        index_block_bytes: 4096,
        serial_number: 1,
    };
    let mut reason = None;
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let error = Writer::prepare_with_diagnostics(&mut NoIo, boot, &mut scratch, |message| reason = Some(message))
        .err()
        .unwrap();
    assert_eq!(error, Error::Unsupported);
    assert!(reason.unwrap().starts_with("unsupported write geometry"));
}

/// Imported mappings can touch more bitmap sectors than one transaction holds.
/// Keep the logical file small and scatter its allocation across the volume.
#[test]
#[ignore = "requires SLATE_LIFECYCLE_LARGE_SOURCE with a fresh 1 GiB volume"]
fn scattered_orphan_reclamation_exceeds_one_bitmap_transaction() {
    use ntfs_rs::{
        file_lifecycle::NodeKind,
        mft::{Attribute, MftRecord, ATTR_DATA},
        record_edit,
        replay::protect_mft_record,
        runlist::{DataRuns, Extent},
        volume::Volume,
    };

    fn physical(attr: Attribute<'_>, offset: u64) -> u64 {
        for run in DataRuns::new(attr.data_runs().unwrap(), 0) {
            let run = run.unwrap();
            if offset >= run.vcn * 4096 && offset < (run.vcn + run.len) * 4096 {
                return run.lcn.unwrap() * 4096 + offset - run.vcn * 4096;
            }
        }
        panic!("fixture offset outside its mapping");
    }

    let source = std::env::var("SLATE_LIFECYCLE_LARGE_SOURCE").unwrap();
    for list_storage in [false, true] {
        let (mut image, path, boot) = open_copy(&source, "scattered-orphan");
        assert!(boot.total_sectors * 512 >= 38 * 4096 * 4096);
        let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
        let mut writer = start(&mut image, boot, &mut scratch);
        let mut sd = [0; 20];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        let reference = writer
            .with_compatibility(true, |writer| {
                writer.create_node(
                    &mut image,
                    (5u64 << 48) | 5,
                    "",
                    NodeKind::Temporary,
                    &sd,
                    0,
                    None,
                    &[],
                    &mut scratch,
                )
            })
            .unwrap();
        let extension = if list_storage {
            Some(
                writer
                    .with_compatibility(true, |writer| {
                        writer.create_node(
                            &mut image,
                            (5u64 << 48) | 5,
                            "",
                            NodeKind::Temporary,
                            &sd,
                            0,
                            None,
                            &[],
                            &mut scratch,
                        )
                    })
                    .unwrap(),
            )
        } else {
            None
        };
        writer.finish(&mut image, &mut scratch).unwrap();

        let mut data_runs: Vec<_> = (1..=20)
            .enumerate()
            .map(|(vcn, sector)| Extent { vcn: vcn as u64, len: 1, lcn: Some(sector * 4096 + 1024) })
            .collect();
        let mut list_runs: Vec<_> = if list_storage {
            (25..=37)
                .enumerate()
                .map(|(vcn, sector)| Extent { vcn: vcn as u64, len: 1, lcn: Some(sector * 4096 + 1024) })
                .collect()
        } else {
            Vec::new()
        };
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        let mut bitmap_raw = [0; 1024];
        let mut extension_raw = [0; 1024];
        let (record_offset, extension_offset, bits) = {
            let mut volume = Volume::new(&mut image, boot).unwrap();
            volume.read_mft_zero(&mut zero).unwrap();
            let mft = MftRecord::parse(&mut zero, 512).unwrap();
            let data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            let offset = physical(data, (reference & 0x0000_ffff_ffff_ffff) * 1024);
            let extension_offset = extension.map(|reference| {
                volume.read_mft_record(&mft, reference & 0x0000_ffff_ffff_ffff, &mut extension_raw).unwrap();
                physical(data, (reference & 0x0000_ffff_ffff_ffff) * 1024)
            });
            volume.read_mft_record(&mft, reference & 0x0000_ffff_ffff_ffff, &mut raw).unwrap();
            volume.read_mft_record(&mft, 6, &mut bitmap_raw).unwrap();
            let bitmap_record = MftRecord::parse(&mut bitmap_raw, 512).unwrap();
            let bitmap = bitmap_record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            for run in data_runs.iter_mut().chain(&mut list_runs) {
                let sector = run.lcn.unwrap() / 4096;
                run.lcn = (sector * 4096..(sector + 1) * 4096).find(|&lcn| {
                    let mut byte = [0];
                    volume.read_attribute(bitmap, lcn / 8, &mut byte).unwrap();
                    byte[0] & (1 << (lcn % 8)) == 0
                });
                assert!(run.lcn.is_some(), "fixture needs a free cluster in each sector");
            }
            let bits: Vec<_> = data_runs
                .iter()
                .chain(&list_runs)
                .map(|run| {
                    let lcn = run.lcn.unwrap();
                    (physical(bitmap, lcn / 8), 1u8 << (lcn % 8))
                })
                .collect();
            (offset, extension_offset, bits)
        };
        MftRecord::parse(&mut raw, 512).unwrap();
        let at = record_edit::require(&raw, ATTR_DATA, &[]).unwrap();
        record_edit::remove(&mut raw, at).unwrap();
        let mut attr = [0; 1024];
        let n = record_edit::build_nonresident(ATTR_DATA, &[], &data_runs, 20 * 4096, 20 * 4096, 20 * 4096, &mut attr)
            .unwrap();
        record_edit::insert(&mut raw, &attr[..n]).unwrap();
        if list_storage {
            // A small list may reserve many scattered clusters. Assembly must
            // account for those freed bits before choosing a data tail.
            // Put the orphan marker in an allocated extension record, so
            // mount-time discovery must resolve the family before inspecting EAs.
            let at = record_edit::require(&raw, 0xe0, &[]).unwrap();
            record_edit::remove(&mut raw, at).unwrap();
            let ext = MftRecord::parse(&mut extension_raw, 512).unwrap();
            let offsets: Vec<_> =
                ext.attributes().map(|a| a.unwrap()).filter(|a| a.kind != 0xe0).map(|a| a.record_offset()).collect();
            for at in offsets.into_iter().rev() {
                record_edit::remove(&mut extension_raw, at).unwrap();
            }
            extension_raw[32..40].copy_from_slice(&reference.to_le_bytes());
            let record = MftRecord::from_decoded(&raw).unwrap();
            let ext = MftRecord::from_decoded(&extension_raw).unwrap();
            let mut list = [0; 4096];
            let mut len = 0;
            for (owner, entry) in
                record.attributes().map(|a| (reference, a)).chain(ext.attributes().map(|a| (extension.unwrap(), a)))
            {
                let entry = entry.unwrap();
                list[len..len + 4].copy_from_slice(&entry.kind.to_le_bytes());
                list[len + 4..len + 6].copy_from_slice(&32u16.to_le_bytes());
                list[len + 16..len + 24].copy_from_slice(&owner.to_le_bytes());
                list[len + 24..len + 26].copy_from_slice(&entry.id.to_le_bytes());
                len += 32;
            }
            image.write_at(list_runs[0].lcn.unwrap() * 4096, &list).unwrap();
            let n = record_edit::build_nonresident(0x20, &[], &list_runs, 13 * 4096, len as u64, len as u64, &mut attr)
                .unwrap();
            record_edit::insert(&mut raw, &attr[..n]).unwrap();
        }
        for &(offset, mask) in &bits {
            let mut byte = [0];
            image.read_exact_at(offset, &mut byte).unwrap();
            assert_eq!(byte[0] & mask, 0, "fixture allocation must be free");
            byte[0] |= mask;
            image.write_at(offset, &byte).unwrap();
        }
        protect_mft_record(&mut raw, 512).unwrap();
        image.write_at(record_offset, &raw).unwrap();
        if let Some(offset) = extension_offset {
            protect_mft_record(&mut extension_raw, 512).unwrap();
            image.write_at(offset, &extension_raw).unwrap();
        }
        image.flush().unwrap();
        let mut writer = start(&mut image, boot, &mut scratch);
        assert_eq!(
            writer
                .reclaim_orphans(&mut image, &mut scratch)
                .unwrap_or_else(|error| panic!("list_storage={list_storage}: {error:?}")),
            1,
            "list_storage={list_storage}"
        );
        writer.finish(&mut image, &mut scratch).unwrap();
        assert_eq!(node(&mut image, boot, reference).flags & 1, 0);
        if let Some(reference) = extension {
            assert_eq!(node(&mut image, boot, reference).flags & 1, 0);
        }
        {
            let mut volume = Volume::new(&mut image, boot).unwrap();
            volume.read_mft_zero(&mut zero).unwrap();
            let mft = MftRecord::parse(&mut zero, 512).unwrap();
            let bitmap = mft.local_attribute(0xb0, &[]).unwrap().unwrap();
            for reference in std::iter::once(reference).chain(extension) {
                let number = reference & 0x0000_ffff_ffff_ffff;
                let mut byte = [0];
                volume.read_attribute(bitmap, number / 8, &mut byte).unwrap();
                assert_eq!(
                    byte[0] & (1 << (number % 8)),
                    0,
                    "base and extension records must be released in the MFT bitmap"
                );
            }
        }
        for &(offset, mask) in &bits {
            let mut byte = [0];
            image.read_exact_at(offset, &mut byte).unwrap();
            assert_eq!(byte[0] & mask, 0, "orphan allocation must be released");
        }
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}

// Locate the flags through checked MFT mapping; never assume a contiguous $MFT.
// Only test-owned copies are edited, with matching protected main/mirror records.
fn set_volume_state(image: &mut Image, boot: BootSector, flags: u16, version: (u8, u8)) {
    use ntfs_rs::{
        mft::{MftRecord, ATTR_DATA},
        replay::protect_mft_record,
        volume::Volume,
        volume_info::ATTR_VOLUME_INFORMATION,
        write_plan::plan_nonresident_overwrite,
    };
    let mut zero = [0; 1024];
    let mut raw = [0; 1024];
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    volume.read_mft_record(&mft, 3, &mut raw).unwrap();
    let data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
    let mut physical = None;
    plan_nonresident_overwrite(data, boot, 3072, 1024, |span| {
        assert_eq!(span.length, 1024);
        assert!(physical.replace(span.physical_offset).is_none());
        Ok(())
    })
    .unwrap();
    let record = MftRecord::parse(&mut raw, 512).unwrap();
    let attr = record.local_attribute(ATTR_VOLUME_INFORMATION, &[]).unwrap().unwrap();
    let at = attr.record_offset() + attr.resident_value_offset().unwrap() + 8;
    raw[at] = version.0;
    raw[at + 1] = version.1;
    raw[at + 2..at + 4].copy_from_slice(&flags.to_le_bytes());
    protect_mft_record(&mut raw, 512).unwrap();
    image.write_at(physical.unwrap(), &raw).unwrap();
    image.write_at(boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + 3072, &raw).unwrap();
    image.flush().unwrap();
}

fn assert_volume_flags(image: &mut Image, boot: BootSector, expected: u16) {
    use ntfs_rs::{mft::MftRecord, volume::Volume, volume_info::VolumeInfo};
    let mut zero = [0; 1024];
    let mut raw = [0; 1024];
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    volume.read_mft_record(&mft, 3, &mut raw).unwrap();
    assert_eq!(VolumeInfo::from_record(&MftRecord::parse(&mut raw, 512).unwrap()).unwrap().flags, expected);
    image.read_exact_at(boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + 3072, &mut raw).unwrap();
    assert_eq!(VolumeInfo::from_record(&MftRecord::parse(&mut raw, 512).unwrap()).unwrap().flags, expected);
}

#[test]
fn persistent_short_name_setting_survives_writes_and_clean_shutdown() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    let (mut image, path, boot) = open_copy(&source, "persistent-flags");
    set_volume_state(&mut image, boot, 0x0080, (3, 1));
    let before = image.writes;
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    assert_eq!(image.writes, before, "admission must not write");
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    assert_volume_flags(&mut image, boot, 0x0081);
    let mut sd = [0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    let root = (5_u64 << 48) | 5;
    let reference = writer.file_lifecycle(&mut image, root, "flag-test.bin", None, &sd, 0, &mut scratch).unwrap();
    writer.write(&mut image, reference, 0, b"persistent setting", &mut scratch).unwrap();
    writer.file_lifecycle(&mut image, root, "flag-test.bin", Some(reference), &[], 0, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    assert_volume_flags(&mut image, boot, 0x0080);
    Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn dirty_repair_unknown_flags_and_unsupported_versions_still_block_admission() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    let (mut image, path, boot) = open_copy(&source, "rejected-flags");
    let mut states: Vec<_> = (0..16).filter(|bit| *bit != 7).map(|bit| ((1 << bit) | 0x0080, (3, 1))).collect();
    states.extend([(0x0080, (3, 0)), (0x0080, (4, 1))]);
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    for (flags, version) in states {
        set_volume_state(&mut image, boot, flags, version);
        let before = image.writes;
        let mut reason = None;
        let error = Writer::prepare_with_diagnostics(&mut image, boot, &mut scratch, |message| reason = Some(message))
            .err()
            .unwrap();
        assert_eq!(error, Error::Unsupported);
        let expected = match (flags, version) {
            (_, (3, 0) | (4, 1)) => "unsupported NTFS version:",
            (0x0081, _) => "volume is dirty:",
            _ => "unsupported volume flags:",
        };
        assert!(reason.unwrap().starts_with(expected));
        assert_eq!(image.writes, before, "rejected admission must not write");
        assert_volume_flags(&mut image, boot, flags);
    }
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn standalone_names_preserve_native_case_policy() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    let (mut image, path, boot) = open_copy(&source, "native-standalone");
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let mut sd = [0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    let root = (5_u64 << 48) | 5;
    let reference = writer.file_lifecycle(&mut image, root, "native-name.txt", None, &sd, 0, &mut scratch).unwrap();
    writer.hard_link(&mut image, reference, root, "native-link.txt", &mut scratch).unwrap();
    writer.move_entry(&mut image, root, reference, "NATIVE-NAME.TXT", root, "renamed-name.txt", &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    let renamed = node(&mut image, boot, reference);
    assert_eq!(renamed.links, 2);
    assert_eq!(renamed.names.len(), 2);
    assert!(renamed.names.iter().all(|name| name[65] == 0));
    writer.remove_node(&mut image, root, "NATIVE-LINK.TXT", reference, false, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    assert_eq!(node(&mut image, boot, reference).links, 1);
    drop(image);
    std::fs::remove_file(path).unwrap();
}

// Native Windows fixtures retain compression and DOS aliases that Slate's
// formatter does not generate. Run explicitly with the VM-produced volume.
#[test]
#[ignore = "requires SLATE_WINDOWS_DELETE_SOURCE with the native Windows fixture"]
fn windows_compressed_delete_and_short_name_move() {
    use ntfs_rs::{file_lifecycle::Removal, mft::MftRecord, volume::Volume};

    fn child(image: &mut Image, boot: BootSector, parent: u64, name: &str) -> u64 {
        let mut volume = Volume::new(&mut *image, boot).unwrap();
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        let mut work = vec![0; METADATA_SCRATCH_BYTES];
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        volume.read_mft_record(&mft, parent & 0x0000_ffff_ffff_ffff, &mut raw).unwrap();
        let dir = MftRecord::parse(&mut raw, 512).unwrap();
        let mut found = None;
        volume
            .visit_directory(&dir, &mut work, |entry| {
                if entry.name.code_units().eq(name.encode_utf16()) {
                    found = Some(entry.file_reference);
                }
                Ok(())
            })
            .unwrap();
        found.unwrap_or_else(|| panic!("missing {name}"))
    }

    let source = std::env::var("SLATE_WINDOWS_DELETE_SOURCE").unwrap();
    let (mut image, path, boot) = open_copy(&source, "windows-delete");
    let root = (5_u64 << 48) | 5;
    let destination = child(&mut image, boot, root, "destination");
    let ordinary = child(&mut image, boot, root, "ordinary long filename.txt");
    assert_eq!(node(&mut image, boot, ordinary).names.len(), 2);
    let compressed = child(&mut image, boot, root, "compressed long filename.txt");
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(&mut image, boot, &mut scratch);
    let parent_sd = {
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        let mut secure = [0; 1024];
        let mut index = vec![0; METADATA_SCRATCH_BYTES];
        let mut result = vec![0; 0x20014];
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        volume.read_mft_record(&mft, 5, &mut raw).unwrap();
        let root_record = MftRecord::parse(&mut raw, 512).unwrap();
        ntfs_rs::security_store::read_descriptor(&mut volume, &mft, &root_record, &mut secure, &mut index, &mut result)
            .unwrap()
            .raw()
            .to_vec()
    };
    let owner = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
    let group = [1, 2, 0, 0, 0, 0, 0, 22, 2, 0, 0, 0, 232, 3, 0, 0];
    let mut descriptor = [0; 512];
    let n = ntfs_rs::security_create::descriptor(&parent_sd, &owner, &group, 0o40777, true, &mut descriptor)
        .expect("inherit native directory descriptor");
    let sd = &descriptor[..n];
    let mut file_sd = [0; 512];
    let file_n =
        ntfs_rs::security_create::descriptor(&parent_sd, &owner, &group, 0o100666, false, &mut file_sd).unwrap();
    let created = writer
        .create_node(
            &mut image,
            root,
            "trash-me.txt",
            ntfs_rs::file_lifecycle::NodeKind::File,
            &file_sd[..file_n],
            0,
            None,
            &[],
            &mut scratch,
        )
        .unwrap();
    writer.write(&mut image, created, 0, b"trash content", &mut scratch).unwrap();
    let trash = writer
        .create_node(
            &mut image,
            root,
            ".Trash-1000",
            ntfs_rs::file_lifecycle::NodeKind::Directory,
            &sd,
            0,
            None,
            &[],
            &mut scratch,
        )
        .expect("create native Trash directory");
    assert_eq!(node(&mut image, boot, trash).names[0][65], 0);
    writer
        .move_entry(&mut image, root, ordinary, "ordinary long filename.txt", destination, "moved.txt", &mut scratch)
        .unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(node(&mut image, boot, ordinary).names.len(), 1);
    assert_eq!(node(&mut image, boot, ordinary).names[0][65], 0);
    assert_eq!(node(&mut image, boot, ordinary).links, 1);
    writer.remove_node(&mut image, destination, "moved.txt", ordinary, false, &mut scratch).unwrap();
    writer
        .move_entry(
            &mut image,
            root,
            compressed,
            "compressed long filename.txt",
            destination,
            "moved compressed.txt",
            &mut scratch,
        )
        .unwrap();
    assert_eq!(
        writer.remove_node(&mut image, destination, "moved compressed.txt", compressed, true, &mut scratch).unwrap(),
        Removal::Orphaned
    );
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(node(&mut image, boot, compressed).links, 0);
    writer.reclaim_orphan(&mut image, compressed, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    assert_eq!(node(&mut image, boot, compressed).flags & 1, 0);
    drop(image);
    if std::env::var_os("SLATE_KEEP_IMAGE").is_some() {
        eprintln!("kept {}", path.display());
    } else {
        std::fs::remove_file(path).unwrap();
    }
}

/// Make one bitmap-free slot look like a never-used Windows MFT record.
fn zero_free_record(image: &mut Image, boot: BootSector) -> u64 {
    use ntfs_rs::{
        mft::{MftRecord, ATTR_BITMAP, ATTR_DATA},
        volume::Volume,
    };
    // Some formatters initialize only the reserved records. Establish the
    // test's free-slot prerequisite before replacing a tombstone with zeros.
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = start(image, boot, &mut scratch);
    writer.ensure_free_records(image, 1, &mut scratch).unwrap();
    writer.finish(image, &mut scratch).unwrap();
    let (number, physical) = {
        let mut volume = Volume::new(&mut *image, boot).unwrap();
        let mut zero = [0; 1024];
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        let data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        let bitmap = mft.local_attribute(ATTR_BITMAP, &[]).unwrap().unwrap();
        let mut found = None;
        for number in 24..data.initialized_size().unwrap() / 1024 {
            let mut bit = [0];
            volume.read_attribute(bitmap, number / 8, &mut bit).unwrap();
            if bit[0] & (1 << (number % 8)) == 0 {
                found = Some(number);
                break;
            }
        }
        let number = found.expect("fresh fixture has a free MFT slot");
        (number, ntfs_rs::tx::map_one(data, boot, number * 1024, 1024).unwrap())
    };
    image.write_at(physical, &[0; 1024]).unwrap();
    image.flush().unwrap();
    number
}

#[test]
fn zero_free_mft_slots_are_durable_before_allocation() {
    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    for fail_flush in [false, true] {
        let (mut image, path, boot) =
            open_copy(&source, if fail_flush { "zero-slot-flush" } else { "zero-slot-create" });
        let number = zero_free_record(&mut image, boot);
        let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
        let mut writer = start(&mut image, boot, &mut scratch);
        let before = image.flushes;
        if fail_flush {
            image.fail_flush = Some(before + 1);
        }
        let mut sd = [0; 20];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
        let root = (5_u64 << 48) | 5;
        let result = writer.create_node(
            &mut image,
            root,
            ".Trash-1000",
            ntfs_rs::file_lifecycle::NodeKind::Directory,
            &sd,
            0,
            None,
            &[],
            &mut scratch,
        );
        if fail_flush {
            assert_eq!(result, Err(Error::Io));
            assert_eq!(writer.finish(&mut image, &mut scratch), Err(Error::Io));
            assert_volume_flags(&mut image, boot, 1);
            assert_eq!(node(&mut image, boot, number).flags & 1, 0);
        } else {
            let reference = result.unwrap();
            assert_eq!(reference, (1_u64 << 48) | number);
            assert!(image.flushes > before, "blank-slot undo image must be durable");
            writer.finish(&mut image, &mut scratch).unwrap();
            assert_eq!(node(&mut image, boot, reference).flags, 3);
            assert_volume_flags(&mut image, boot, 0);
        }
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}

/// Imported DATA families can exceed the writer's edited-record cache. Moving
/// a name must preserve those physical segments, and deletion must retire them
/// through bounded transactions without leaving allocated extension records.
#[test]
fn namespace_edits_and_cleanup_stream_large_data_families() {
    use ntfs_rs::{
        file_lifecycle::{NodeKind, Removal},
        mft::{MftRecord, ATTR_DATA},
        record_edit as edit,
        replay::protect_mft_record,
        runlist::{DataRuns, Extent},
        volume::Volume,
    };

    fn physical(attribute: ntfs_rs::mft::Attribute<'_>, offset: u64) -> u64 {
        for run in DataRuns::new(attribute.data_runs().unwrap(), attribute.first_vcn().unwrap()) {
            let run = run.unwrap();
            if offset >= run.vcn * 4096 && offset < (run.vcn + run.len) * 4096 {
                return run.lcn.unwrap() * 4096 + offset - run.vcn * 4096;
            }
        }
        panic!("fixture offset is outside its allocation");
    }

    let source = std::env::var("SLATE_LIFECYCLE_SOURCE").unwrap();
    let root = (5_u64 << 48) | 5;
    for (unit, shared_record) in [(1_u64, false), (16, false), (1, true)] {
        let (mut image, path, boot) = open_copy(&source, &format!("streaming-family-{unit}-{shared_record}"));
        let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
        let mut writer = start(&mut image, boot, &mut scratch);
        let mut descriptor = [0; 20];
        descriptor[0] = 1;
        descriptor[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
        let reference =
            writer.file_lifecycle(&mut image, root, "streaming-source", None, &descriptor, 0, &mut scratch).unwrap();
        let segments = 21 + u64::from(shared_record);
        let length = segments * unit * 4096;
        let payload = vec![0x5a; length as usize];
        writer.resize(&mut image, reference, length, &mut scratch).unwrap();
        for (index, bytes) in payload.chunks(64 * 1024).enumerate() {
            writer.write(&mut image, reference, (index * 64 * 1024) as u64, bytes, &mut scratch).unwrap();
        }
        let extensions: Vec<_> = (0..20)
            .map(|_| {
                writer
                    .with_compatibility(true, |writer| {
                        writer.create_node(
                            &mut image,
                            root,
                            "",
                            NodeKind::Temporary,
                            &descriptor,
                            0,
                            None,
                            &[],
                            &mut scratch,
                        )
                    })
                    .unwrap()
            })
            .collect();
        writer.finish(&mut image, &mut scratch).unwrap();

        let mut zero = [0; 1024];
        let mut base = [0; 1024];
        let mut bitmap_raw = [0; 1024];
        let mut physical_records = Vec::new();
        let mut data_clusters = Vec::new();
        let (base_offset, list_lcn, list_bit, list_mask) = {
            let mut volume = Volume::new(&mut image, boot).unwrap();
            volume.read_mft_zero(&mut zero).unwrap();
            let mft = MftRecord::parse(&mut zero, 512).unwrap();
            let mft_data = mft.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            volume.read_mft_record(&mft, reference & 0x0000_ffff_ffff_ffff, &mut base).unwrap();
            let record = MftRecord::parse(&mut base, 512).unwrap();
            let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            for run in DataRuns::new(data.data_runs().unwrap(), 0) {
                let run = run.unwrap();
                data_clusters.extend(run.lcn.unwrap()..run.lcn.unwrap() + run.len);
            }
            for extension in &extensions {
                physical_records.push(physical(mft_data, (extension & 0x0000_ffff_ffff_ffff) * 1024));
            }
            volume.read_mft_record(&mft, 6, &mut bitmap_raw).unwrap();
            let bitmap_record = MftRecord::parse(&mut bitmap_raw, 512).unwrap();
            let bitmap = bitmap_record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
            let mut bits = vec![0; bitmap.data_size().unwrap() as usize];
            volume.read_attribute(bitmap, 0, &mut bits).unwrap();
            let list_lcn = (1..boot.total_sectors / 8)
                .find(|&cluster| bits[cluster as usize / 8] & (1 << (cluster % 8)) == 0)
                .unwrap();
            (
                physical(mft_data, (reference & 0x0000_ffff_ffff_ffff) * 1024),
                list_lcn,
                physical(bitmap, list_lcn / 8),
                1_u8 << (list_lcn % 8),
            )
        };
        assert_eq!(data_clusters.len(), (segments * unit) as usize);
        let at = edit::require(&base, ATTR_DATA, &[]).unwrap();
        edit::remove(&mut base, at).unwrap();
        let mut attribute = [0; 1024];
        let mut listed = Vec::new();
        let mut originals = Vec::new();
        for segment in 0..21 {
            let owner = if segment == 0 { reference } else { extensions[segment - 1] };
            let mut raw = if segment == 0 {
                base
            } else {
                let mut raw = [0; 1024];
                edit::format_empty(&mut raw, owner & 0x0000_ffff_ffff_ffff).unwrap();
                edit::p16(&mut raw, 16, (owner >> 48) as u16).unwrap();
                edit::p16(&mut raw, 22, 1).unwrap();
                edit::p64(&mut raw, 32, reference).unwrap();
                raw
            };
            let first = segment as u64 * unit;
            let runs: Vec<_> = (0..unit)
                .map(|n| Extent { vcn: first + n, len: 1, lcn: Some(data_clusters[(first + n) as usize]) })
                .collect();
            let n = edit::build_nonresident_at(ATTR_DATA, &[], &runs, first, length, length, length, &mut attribute)
                .unwrap();
            if unit == 16 {
                edit::p16(&mut attribute, 12, 1).unwrap();
                edit::p16(&mut attribute, 34, 4).unwrap();
                edit::p64(&mut attribute, 64, length).unwrap();
            }
            edit::insert(&mut raw, &attribute[..n]).unwrap();
            for entry in MftRecord::from_decoded(&raw).unwrap().attributes() {
                let entry = entry.unwrap();
                listed.push((
                    entry.kind,
                    entry.name_utf16le().unwrap().to_vec(),
                    if entry.nonresident { entry.first_vcn().unwrap() } else { 0 },
                    owner,
                    entry.id,
                ));
            }
            if segment == 0 {
                base = raw;
            } else {
                protect_mft_record(&mut raw, 512).unwrap();
                image.write_at(physical_records[segment - 1], &raw).unwrap();
                originals.push(raw);
            }
        }
        if shared_record {
            // Imported records may put the final continuation before the first
            // descriptor physically. Deleting that tail must relocate the head
            // by identity before updating its stream sizes.
            let first = 21 * unit;
            let n = edit::build_nonresident_at(
                ATTR_DATA,
                &[],
                &[Extent { vcn: first, len: unit, lcn: Some(data_clusters[first as usize]) }],
                first,
                length,
                length,
                length,
                &mut attribute,
            )
            .unwrap();
            let at = edit::require(&base, ATTR_DATA, &[]).unwrap();
            let used = edit::used(&base).unwrap();
            let id = ntfs_rs::bytes::u16_at(&base, 40).unwrap();
            assert!(used + n <= base.len());
            base.copy_within(at..used, at + n);
            base[at..at + n].copy_from_slice(&attribute[..n]);
            edit::p16(&mut base, at + 14, id).unwrap();
            edit::p16(&mut base, 40, id + 1).unwrap();
            edit::p32(&mut base, 24, (used + n) as u32).unwrap();
            edit::validate(&base).unwrap();
            listed.push((ATTR_DATA, Vec::new(), first, reference, id));
        }
        listed.sort();
        let mut list = vec![0; 4096];
        let mut used = 0;
        for (kind, name, vcn, owner, id) in listed {
            let n = (26 + name.len() + 7).max(32) & !7;
            edit::p32(&mut list, used, kind).unwrap();
            edit::p16(&mut list, used + 4, n as u16).unwrap();
            list[used + 6] = (name.len() / 2) as u8;
            list[used + 7] = 26;
            edit::p64(&mut list, used + 8, vcn).unwrap();
            edit::p64(&mut list, used + 16, owner).unwrap();
            edit::p16(&mut list, used + 24, id).unwrap();
            list[used + 26..used + 26 + name.len()].copy_from_slice(&name);
            used += n;
        }
        image.write_at(list_lcn * 4096, &list).unwrap();
        let mut bit = [0];
        image.read_exact_at(list_bit, &mut bit).unwrap();
        bit[0] |= list_mask;
        image.write_at(list_bit, &bit).unwrap();
        let n = edit::build_nonresident(
            0x20,
            &[],
            &[Extent { vcn: 0, len: 1, lcn: Some(list_lcn) }],
            4096,
            used as u64,
            used as u64,
            &mut attribute,
        )
        .unwrap();
        edit::insert(&mut base, &attribute[..n]).unwrap();
        protect_mft_record(&mut base, 512).unwrap();
        image.write_at(base_offset, &base).unwrap();
        image.flush().unwrap();

        let mut writer = start(&mut image, boot, &mut scratch);
        writer
            .move_entry(&mut image, root, reference, "streaming-source", root, "streaming-moved", &mut scratch)
            .unwrap();
        writer.checkpoint(&mut image, &mut scratch).unwrap();
        for (offset, before) in physical_records.iter().zip(&originals) {
            let mut after = [0; 1024];
            image.read_exact_at(*offset, &mut after).unwrap();
            assert_eq!(after, *before, "namespace edits must preserve DATA continuations");
        }
        if unit == 1 {
            assert_eq!(read_resolved(&mut image, boot, reference), payload);
        } else {
            // Fully allocated compressed units contain ordinary bytes. Check
            // those bytes directly because the generic resolved reader accepts
            // unencoded DATA only; the namespace editor never reads DATA.
            let mut stored = Vec::new();
            for cluster in &data_clusters {
                let mut bytes = [0; 4096];
                image.read_exact_at(cluster * 4096, &mut bytes).unwrap();
                stored.extend_from_slice(&bytes);
            }
            assert_eq!(stored, payload);
        }
        let removal = writer.remove_node(&mut image, root, "streaming-moved", reference, true, &mut scratch).unwrap();
        assert_eq!(removal, Removal::Orphaned);
        writer.finish(&mut image, &mut scratch).unwrap();
        let mut writer = start(&mut image, boot, &mut scratch);
        assert_eq!(writer.reclaim_orphans(&mut image, &mut scratch).unwrap(), 1);
        writer.finish(&mut image, &mut scratch).unwrap();
        for owner in std::iter::once(reference).chain(extensions.iter().copied()) {
            assert_eq!(node(&mut image, boot, owner).flags & 1, 0);
        }
        let mut volume = Volume::new(&mut image, boot).unwrap();
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        volume.read_mft_record(&mft, 6, &mut bitmap_raw).unwrap();
        let bitmap_record = MftRecord::parse(&mut bitmap_raw, 512).unwrap();
        let bitmap = bitmap_record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        for cluster in data_clusters {
            volume.read_attribute(bitmap, cluster / 8, &mut bit).unwrap();
            assert_eq!(bit[0] & (1 << (cluster % 8)), 0);
        }
        drop(volume);
        drop(image);
        std::fs::remove_file(path).unwrap();
    }
}
