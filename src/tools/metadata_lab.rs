//! Module: slate_ntfs_tools::metadata_lab
//! Purpose: Exercise the shared journaled metadata engine on new image copies.
//! Created: 2026-10-01
//! Architecture: Rename, ACL, ownership and MFT-growth experiments run the kernel's Rust
//! engine through a userspace adapter. SLATE_NTFS_TEST_STOP_AFTER_FLUSH fault injection starts
//! after journal initialization; kernel tests cover initialization failures.

use ntfs_rs::boot::BootSector;
use ntfs_rs::identity::{CompiledSidMap, MappedCaller};
use ntfs_rs::mft::reference_number;
use ntfs_rs::mft::MftRecord;
use ntfs_rs::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use ntfs_rs::security_writer::SECURITY_SCRATCH_BYTES;
use ntfs_rs::volume::{ReadAt, Volume};
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

fn invalid(error: ntfs_rs::Error) -> io::Error {
    let kind = match error {
        ntfs_rs::Error::Unsupported => io::ErrorKind::Unsupported,
        ntfs_rs::Error::AccessDenied | ntfs_rs::Error::NotPermitted => io::ErrorKind::PermissionDenied,
        ntfs_rs::Error::Exists => io::ErrorKind::AlreadyExists,
        ntfs_rs::Error::NotFound => io::ErrorKind::NotFound,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, format!("{error:?}"))
}
fn input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_owned())
}

struct FileIo {
    file: File,
    flushes: usize,
    stop_after: Option<usize>,
}
impl ReadAt for FileIo {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> ntfs_rs::Result<()> {
        self.file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.read_exact(output))
            .map_err(|_| ntfs_rs::Error::Io)
    }
}
impl WriteIo for FileIo {
    fn write_at(&mut self, offset: u64, data: &[u8]) -> ntfs_rs::Result<()> {
        self.file.seek(SeekFrom::Start(offset)).and_then(|_| self.file.write_all(data)).map_err(|_| ntfs_rs::Error::Io)
    }
    fn flush(&mut self) -> ntfs_rs::Result<()> {
        self.file.sync_data().map_err(|_| ntfs_rs::Error::Io)?;
        self.flushes += 1;
        if self.stop_after == Some(self.flushes) {
            return Err(ntfs_rs::Error::Io);
        }
        Ok(())
    }
}

fn hex(value: &str) -> io::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(input("odd hex length"));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| input("invalid hex")))
        .collect()
}

/// Resolve an absolute path to (parent reference, file reference).
fn resolve(io: &mut FileIo, boot: BootSector, path: &str) -> io::Result<(u64, u64)> {
    let mut volume = Volume::new(&mut *io, boot).map_err(invalid)?;
    let mut zero = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut zero).map_err(invalid)?;
    let mft = MftRecord::parse(&mut zero, 512).map_err(invalid)?;
    let mut raw = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 5, &mut raw).map_err(invalid)?;
    let root = MftRecord::parse(&mut raw, 512).map_err(invalid)?;
    let mut current = 5 | u64::from(root.sequence_number().map_err(invalid)?) << 48;
    let mut parent = current;
    let mut block =
        vec![0; boot.index_block_bytes as usize + 2 * ntfs_rs::tx::RECORD_IMAGE + 2 * boot.record_bytes as usize];
    for component in path.split('/').filter(|c| !c.is_empty()) {
        let wanted: Vec<u16> = component.encode_utf16().collect();
        volume.read_mft_record(&mft, reference_number(current), &mut raw).map_err(invalid)?;
        let dir = MftRecord::parse(&mut raw, 512).map_err(invalid)?;
        let mut found = None;
        volume
            .visit_directory(&dir, &mut block, |entry| {
                if entry.name.namespace != 2 && entry.name.code_units().eq(wanted.iter().copied()) {
                    found = Some(entry.file_reference);
                }
                Ok(())
            })
            .map_err(invalid)?;
        parent = current;
        current = found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, component.to_owned()))?;
    }
    Ok((parent, current))
}

fn split_path(path: &str) -> io::Result<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    let at = trimmed.rfind('/').ok_or_else(|| input("paths must be absolute"))?;
    let name = &trimmed[at + 1..];
    if name.is_empty() {
        return Err(input("missing final path component"));
    }
    Ok((if at == 0 { "/" } else { &trimmed[..at] }, name))
}

fn text(args: &[OsString], i: usize) -> io::Result<&str> {
    args.get(i).and_then(|a| a.to_str()).ok_or_else(|| input("missing or non-Unicode argument"))
}

fn caller_ids(uid: &str, gids: &str) -> io::Result<(u32, Vec<u32>)> {
    let uid = uid.parse().map_err(|_| input("invalid uid"))?;
    let gids =
        gids.split(',').map(|g| g.parse().map_err(|_| input("invalid gid"))).collect::<io::Result<Vec<u32>>>()?;
    Ok((uid, gids))
}

/// ntfs-write-lab --metadata SOURCE NEW_IMAGE [--leave-dirty] OP ARGS...
pub fn run(args: &[OsString]) -> io::Result<()> {
    const USAGE: &str = "usage: ntfs-write-lab --metadata SOURCE NEW_IMAGE [--leave-dirty] \
        OP [:: OP ...] where OP is (move OLD_PATH NEW_PATH | set-security PATH DESCRIPTOR_HEX UID GID[,GID...] SIDMAP | \
        chown PATH NEW_UID|- NEW_GID|- UID GID[,GID...] SIDMAP | grow-mft RECORDS)";
    if args.len() < 3 {
        return Err(input(USAGE));
    }
    let source = Path::new(&args[0]);
    let destination = Path::new(&args[1]);
    let mut i = 2;
    let mut leave_dirty = false;
    let mut linux_compatibility = false;
    while i < args.len() {
        match args[i].to_str() {
            Some("--leave-dirty") => leave_dirty = true,
            Some("--compatibility=linux") => linux_compatibility = true,
            Some("--compatibility=ntfs") => linux_compatibility = false,
            _ => break,
        }
        i += 1;
    }
    let stop_after = std::env::var("SLATE_NTFS_TEST_STOP_AFTER_FLUSH")
        .ok()
        .map(|s| s.parse::<usize>().map_err(|_| input("invalid flush boundary")))
        .transpose()?;
    if !File::open(source)?.metadata()?.is_file() {
        return Err(input("source must be a regular image file"));
    }
    let mut boot_bytes = [0; 512];
    File::open(source)?.read_exact(&mut boot_bytes)?;
    let boot = BootSector::parse(&boot_bytes).map_err(invalid)?;
    let mut output = OpenOptions::new().read(true).write(true).create_new(true).open(destination)?;
    io::copy(&mut File::open(source)?, &mut output)?;
    output.sync_all()?;
    let mut io = FileIo { file: output, flushes: 0, stop_after };
    let mut scratch = vec![0_u8; SECURITY_SCRATCH_BYTES.max(METADATA_SCRATCH_BYTES)];
    let mut writer = Writer::prepare(&mut io, boot, &mut scratch).map_err(invalid)?;
    writer.set_linux_compatibility(linux_compatibility).map_err(invalid)?;
    // Injected failures count only the operations' own durable flushes.
    let stop_after = io.stop_after.take();
    writer.initialize(&mut io, &mut scratch).map_err(invalid)?;
    io.flushes = 0;
    io.stop_after = stop_after;
    let mut messages = Vec::new();
    for operation in args[i..].split(|a| a == "::") {
        let op = text(operation, 0)?.to_owned();
        let rest = &operation[1..];
        messages.push(apply(&mut writer, &mut io, boot, &mut scratch, &op, rest)?);
    }
    if !leave_dirty {
        writer.finish(&mut io, &mut scratch).map_err(invalid)?;
    }
    io.file.sync_all()?;
    println!(
        "{}\noperations={}\nflushes={}\ndirty={}",
        messages.join("\n"),
        messages.len(),
        io.flushes,
        u8::from(leave_dirty)
    );
    Ok(())
}

fn apply(
    writer: &mut Writer,
    io: &mut FileIo,
    boot: BootSector,
    scratch: &mut [u8],
    op: &str,
    rest: &[OsString],
) -> io::Result<String> {
    const USAGE: &str = "unknown metadata operation";
    let result = (|| -> io::Result<String> {
        match op {
            "move" => {
                let (old_parent, reference) = resolve(io, boot, text(rest, 0)?)?;
                let (_, old_name) = split_path(text(rest, 0)?)?;
                let (new_dir, new_name) = split_path(text(rest, 1)?)?;
                let (_, new_parent) = resolve(io, boot, new_dir)?;
                writer
                    .move_entry(io, old_parent, reference, old_name, new_parent, new_name, scratch)
                    .map_err(invalid)?;
                Ok(format!("moved_reference={reference:#x}"))
            }
            "set-security" | "chown" => {
                let (_, reference) = resolve(io, boot, text(rest, 0)?)?;
                let base = if op == "chown" { 3 } else { 2 };
                let (uid, gids) = caller_ids(text(rest, base)?, text(rest, base + 1)?)?;
                let mut map = Box::new(CompiledSidMap::empty());
                map.initialize(text(rest, base + 2)?).map_err(invalid)?;
                let policy = MappedCaller { map: &map, uid, gids: &gids };
                if op == "set-security" {
                    let descriptor = hex(text(rest, 1)?)?;
                    writer.set_security(io, reference, &descriptor, &policy, scratch).map_err(invalid)?;
                } else {
                    let id = |t: &str, group: bool| -> io::Result<Option<Vec<u8>>> {
                        if t == "-" {
                            return Ok(None);
                        }
                        let id = t.parse().map_err(|_| input("invalid new id"))?;
                        Ok(Some(map.sid_for(group, id).map_err(invalid)?.to_vec()))
                    };
                    let owner = id(text(rest, 1)?, false)?;
                    let group = id(text(rest, 2)?, true)?;
                    writer
                        .set_owner(io, reference, owner.as_deref(), group.as_deref(), &policy, scratch)
                        .map_err(invalid)?;
                }
                Ok(format!("security_reference={reference:#x}"))
            }
            "grow-mft" => {
                let records = text(rest, 0)?.parse().map_err(|_| input("invalid record count"))?;
                let total = writer.extend_mft(io, records, scratch).map_err(invalid)?;
                Ok(format!("mft_records={total}"))
            }
            _ => Err(input(USAGE)),
        }
    })();
    result
}
