//! Module: kernel::ntfs_parser
//! Purpose: Expose checked NTFS parsing through the kernel C ABI.
//! Created: 2026-10-01
//! Architecture: The VFS bridge calls this freestanding Rust adapter over the shared core.

// SPDX-License-Identifier: MIT OR GPL-2.0-only
#[path = "../src/format.rs"]
pub mod format;
#[path = "writer.rs"]
mod writer;

use core::ffi::{c_int, c_void};
use format::boot::BootSector;
use format::mft::{file_reference, reference_number, reference_sequence, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_DATA, ATTR_SECURITY_DESCRIPTOR};
use format::upcase::{UpcaseTable, UPCASE_BYTES};
use format::volume::{mft_space_bytes, ReadAt, Volume};
use format::{Error, Result};

type ReadCallback = unsafe extern "C" fn(*mut c_void, u64, *mut u8, usize) -> c_int;
const BUFFER_BYTES: usize = 65_536;
const SCRATCH_BYTES: usize = 3 * BUFFER_BYTES;
const LOOKUP_SCRATCH_BYTES: usize = 6 * BUFFER_BYTES;
const SECURITY_SCRATCH_BYTES: usize = 8 * BUFFER_BYTES;

#[repr(C)]
pub struct NodeInfo {
    pub file_reference: u64,
    pub data_size: u64,
    pub flags: u32,
    pub mode: u32,
    pub links: u32,
    /// Windows file attributes from $STANDARD_INFORMATION.
    pub attributes: u32,
    /// Creation, modification, MFT change and access times (NTFS units).
    pub times: [u64; 4],
    /// Allocated bytes of the unnamed stream (for st_blocks).
    pub allocated: u64,
    /// Reparse tag of a supported symbolic link or junction, else zero.
    pub reparse_tag: u32,
    pub reserved: u32,
    pub linux_flags: u32,
    /// The $Secure ID that alone determines the descriptor, else zero: a
    /// caller may then share one loaded descriptor among the files using it.
    pub security_id: u32,
}

/// Scratch for EA and link reads: three records plus one complete EA stream.
const EA_SCRATCH_BYTES: usize = 3 * BUFFER_BYTES + format::ea::MAX_STREAM;

/// A listed name: bytes, length, file reference, ordinal and the entry's
/// Linux file type (S_IFMT bits) as far as the index alone tells it, else 0.
type EmitCallback = unsafe extern "C" fn(*mut c_void, *const u8, usize, u64, u64, u32) -> c_int;

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
/// Offset of the reparse tag in a FILE_NAME value whose attributes carry
/// REPARSE_POINT.
const FILE_NAME_REPARSE_TAG: usize = 60;

/// The type a listing may state without reading the record. A system file
/// may be an older-style link, and an unrecognised reparse tag says nothing:
/// those stay unknown and the caller asks stat.
fn listed_type(file_name_value: &[u8], attributes: u32) -> Result<u32> {
    if attributes & format::std_info::REPARSE_POINT != 0 {
        let tag = format::bytes::u32_at(file_name_value, FILE_NAME_REPARSE_TAG)?;
        return Ok(if format::reparse::is_link_tag(tag) { S_IFLNK } else { format::reparse::special_type(tag).unwrap_or(0) });
    }
    Ok(if attributes & format::std_info::SYSTEM != 0 {
        0
    } else if attributes & format::std_info::DUP_INDEX_PRESENT != 0 {
        S_IFDIR
    } else {
        S_IFREG
    })
}

/// Caller holds the volume read lock; all output words are copied synchronously.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_space(
    boot: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    output: *mut u64,
) -> c_int {
    if boot.is_null() || scratch.is_null() || output.is_null() {
        return -22;
    }
    let action = (|| {
        let boot = BootSector::parse(unsafe { core::slice::from_raw_parts(boot, 512) })?;
        let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, 4 * BUFFER_BYTES) };
        let (zero, rest) = scratch.split_at_mut(boot.record_bytes as usize);
        let (bitmap, rest) = rest.split_at_mut(boot.record_bytes as usize);
        let (extension, chunk) = rest.split_at_mut(boot.record_bytes as usize);
        let mut volume = Volume::new(Device { context, callback }, boot)?;
        let used = volume.allocated_clusters(zero, bitmap, extension, chunk)?;
        let total = boot.total_sectors / u64::from(boot.sectors_per_cluster);
        let free = total.checked_sub(used).ok_or(Error::InvalidAttribute)?;
        unsafe { core::slice::from_raw_parts_mut(output, 3) }.copy_from_slice(&[
            total,
            free,
            u64::from(boot.cluster_bytes),
        ]);
        Ok(())
    })();
    action.map_or_else(ffi_error, |_| 0)
}

/// Read standard NTFS volume identity; UUID bytes match blkid's serial order.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_volume_identity(
    boot: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    label: *mut u8,
    uuid: *mut u8,
) -> c_int {
    if boot.is_null() || scratch.is_null() || label.is_null() || uuid.is_null() {
        return -22;
    }
    let action = (|| {
        let boot = BootSector::parse(unsafe { core::slice::from_raw_parts(boot, 512) })?;
        unsafe { core::slice::from_raw_parts_mut(uuid, 8) }.copy_from_slice(&boot.serial_number.to_be_bytes());
        let out = unsafe { core::slice::from_raw_parts_mut(label, 256) };
        out.fill(0);
        let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, EA_SCRATCH_BYTES) };
        let (zero, rest) = scratch.split_at_mut(boot.record_bytes as usize);
        let (raw, rest) = rest.split_at_mut(boot.record_bytes as usize);
        let (resolved, rest) = rest.split_at_mut(format::tx::RECORD_IMAGE);
        let mut volume = Volume::new(Device { context, callback }, boot)?;
        volume.read_mft_zero(zero)?;
        let mft = MftRecord::parse(zero, boot.bytes_per_sector)?;
        volume.read_mft_record(&mft, 3, raw)?;
        let record = MftRecord::parse(raw, boot.bytes_per_sector)?;
        volume.resolve_record(&mft, &record, resolved, rest)?;
        let record = MftRecord::from_decoded(resolved)?;
        let mut found = false;
        for a in record.attributes() {
            let a = a?;
            if a.kind != 0x60 {
                continue;
            }
            if found || !a.name_utf16le()?.is_empty() {
                return Err(Error::InvalidAttribute);
            }
            found = true;
            let value = a.resident_value()?;
            if value.len() % 2 != 0 {
                return Err(Error::InvalidAttribute);
            }
            let mut at = 0;
            for ch in core::char::decode_utf16(value.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]]))) {
                let ch = ch.map_err(|_| Error::InvalidAttribute)?;
                let mut bytes = [0u8; 4];
                let value = ch.encode_utf8(&mut bytes).as_bytes();
                if ch == '\0' || at + value.len() >= out.len() {
                    return Err(Error::Unsupported);
                }
                out[at..at + value.len()].copy_from_slice(value);
                at += value.len();
            }
        }
        Ok(())
    })();
    action.map_or_else(ffi_error, |_| 0)
}

/// Enumerate only free bitmap runs after C checkpointed and locked the writer.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_trim_free(
    boot: *const u8,
    context: *mut c_void,
    read: ReadCallback,
    scratch: *mut u8,
    start: u64,
    length: u64,
    minlen: u64,
    discard: unsafe extern "C" fn(*mut c_void, u64, u64) -> c_int,
    total: *mut u64,
) -> c_int {
    if boot.is_null() || scratch.is_null() || total.is_null() {
        return -22;
    }
    let action = (|| {
        let boot = BootSector::parse(unsafe { core::slice::from_raw_parts(boot, 512) })?;
        let cb = u64::from(boot.cluster_bytes);
        let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
        let from = start.div_ceil(cb);
        let to = start.saturating_add(length).min(clusters * cb) / cb;
        unsafe { *total = 0 };
        if from >= to {
            return Ok(());
        }
        let scratch = unsafe { core::slice::from_raw_parts_mut(scratch, EA_SCRATCH_BYTES) };
        let (zero, rest) = scratch.split_at_mut(boot.record_bytes as usize);
        let (raw, rest) = rest.split_at_mut(boot.record_bytes as usize);
        let (family, rest) = rest.split_at_mut(format::tx::RECORD_IMAGE);
        let mut volume = Volume::new(Device { context, callback: read }, boot)?;
        volume.read_mft_zero(zero)?;
        let mft = MftRecord::parse(zero, boot.bytes_per_sector)?;
        volume.read_mft_record(&mft, 6, raw)?;
        let record = MftRecord::parse(raw, boot.bytes_per_sector)?;
        volume.resolve_record(&mft, &record, family, rest)?;
        let bitmap = MftRecord::from_decoded(family)?;
        let data = bitmap.local_attribute(ATTR_DATA, &[])?.ok_or(Error::InvalidAttribute)?;
        if data.data_size()? < clusters.div_ceil(8) || data.initialized_size()? < clusters.div_ceil(8) {
            return Err(Error::InvalidAttribute);
        }
        let mut run = None;
        let mut at = from;
        let mut bytes = [0u8; 4096];
        while at < to {
            let first = at / 8;
            let n = ((to.div_ceil(8) - first) as usize).min(bytes.len());
            volume.read_attribute(data, first, &mut bytes[..n])?;
            let end = to.min((first + n as u64) * 8);
            while at < end {
                // Boot and backup-boot clusters are never discard candidates.
                let free = at != 0 && at + 1 != clusters && bytes[(at / 8 - first) as usize] & (1 << (at % 8)) == 0;
                if free {
                    if run.is_none() {
                        run = Some(at);
                    }
                } else if let Some(begin) = run.take() {
                    let len = (at - begin) * cb;
                    if len >= minlen {
                        if unsafe { discard(context, begin * cb, len) } != 0 {
                            return Err(Error::Io);
                        }
                        unsafe { *total += len };
                    }
                }
                at += 1;
            }
        }
        if let Some(begin) = run {
            let len = (to - begin) * cb;
            if len >= minlen {
                if unsafe { discard(context, begin * cb, len) } != 0 {
                    return Err(Error::Io);
                }
                unsafe { *total += len };
            }
        }
        Ok(())
    })();
    action.map_or_else(ffi_error, |_| 0)
}

struct Device {
    context: *mut c_void,
    callback: ReadCallback,
}

impl ReadAt for Device {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        // SAFETY: context is the live superblock for the duration of the
        // synchronous probe. C copies into this caller-owned slice and keeps
        // neither the pointer nor a reference to it.
        let status = unsafe { (self.callback)(self.context, offset, output.as_mut_ptr(), output.len()) };
        if status == 0 {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }

    // The mount keeps the decoded file-table map: C holds the copy and voids
    // it when a write reaches the records it was built from.
    fn cached_table(&mut self, space: &mut [u8]) -> Option<usize> {
        // SAFETY: C copies at most space.len() bytes into this live slice.
        let length = unsafe { ntfs_rs_table_copy(self.context, space.as_mut_ptr(), space.len()) };
        (length != 0).then_some(length)
    }
    fn table_epoch(&mut self) -> u64 {
        // SAFETY: context is the live superblock.
        unsafe { ntfs_rs_table_epoch(self.context) }
    }
    fn store_table(&mut self, table: &[u8], guard: core::ops::Range<u64>, epoch: u64) {
        // SAFETY: C copies the live slice before returning.
        unsafe { ntfs_rs_table_store(self.context, table.as_ptr(), table.len(), guard.start, guard.end, epoch) }
    }
    fn drop_table(&mut self) {
        // SAFETY: context is the live superblock.
        unsafe { ntfs_rs_table_drop(self.context) }
    }
}

extern "C" {
    fn ntfs_rs_table_copy(context: *mut c_void, output: *mut u8, capacity: usize) -> usize;
    fn ntfs_rs_table_epoch(context: *mut c_void) -> u64;
    fn ntfs_rs_table_drop(context: *mut c_void);
    fn ntfs_rs_table_store(context: *mut c_void, table: *const u8, length: usize, start: u64, end: u64, epoch: u64);
}

/// Scratch kept behind a directory walk for loading the upcase table: its
/// record with any extensions, and the table itself.
const UPCASE_RESERVE: usize = BUFFER_BYTES + UPCASE_BYTES;

/// Split a directory walk's scratch into the space for the table map, the
/// directory's record, and the rest: the walk's own space, which must hold
/// a listed family, followed by the reserve asked for.
fn walk_spaces(scratch: &mut [u8], boot: BootSector, reserve: usize) -> Result<(&mut [u8], &mut [u8], &mut [u8])> {
    let record_bytes = boot.record_bytes as usize;
    if scratch.len() < mft_space_bytes(record_bytes) + record_bytes + reserve {
        return Err(Error::Truncated);
    }
    let (mft_space, rest) = scratch.split_at_mut(mft_space_bytes(record_bytes));
    let (record_space, rest) = rest.split_at_mut(record_bytes);
    Ok((mft_space, record_space, rest))
}

fn probe(boot_bytes: &[u8], context: *mut c_void, callback: ReadCallback, scratch: &mut [u8]) -> Result<()> {
    let boot = BootSector::parse(boot_bytes)?;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let (mft_space, root_space, index_space) = walk_spaces(scratch, boot, 0)?;
    let mft = volume.load_mft(mft_space)?;
    let root_bytes = &mut root_space[..boot.record_bytes as usize];
    volume.read_mft_record(&mft, 5, root_bytes)?;
    let root = MftRecord::parse(root_bytes, boot.bytes_per_sector)?;
    if root.flags()? & 3 != 3 {
        return Err(Error::InvalidRecord);
    }
    let block_bytes = &mut index_space[..];
    volume.visit_directory(&root, block_bytes, |_| Ok(()))?;
    Ok(())
}

fn node_info(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &mut [u8],
    number: u64,
    expected_sequence: u16,
) -> Result<NodeInfo> {
    let boot = BootSector::parse(boot_bytes)?;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let (mft_space, rest) = scratch.split_at_mut(BUFFER_BYTES);
    let (record_space, extension_space) = rest.split_at_mut(BUFFER_BYTES);
    let mft = volume.load_mft(mft_space)?;
    let (record_bytes, resolved) = record_space.split_at_mut(boot.record_bytes as usize);
    volume.read_mft_record(&mft, number, record_bytes)?;
    let record = MftRecord::parse(record_bytes, boot.bytes_per_sector)?;
    let listed = record.attributes().any(|a| a.is_ok_and(|a| a.kind == ATTR_ATTRIBUTE_LIST));
    // The names and mapping continuations in extension records are not
    // needed here, and a file with many of either exceeds one assembled record.
    volume.resolve_record_attributes(&mft, &record, &mut resolved[..format::tx::RECORD_IMAGE], extension_space)?;
    let record = MftRecord::from_decoded(&resolved[..format::tx::RECORD_IMAGE])?;
    let sequence = record.sequence_number()?;
    let flags = record.flags()?;
    if flags & 1 == 0 || (expected_sequence != 0 && sequence != expected_sequence) {
        return Err(Error::InvalidRecord);
    }
    let mut has_unnamed_data = false;
    let mut has_attribute_list = false;
    let mut first_segment_size = None;
    let mut inline_descriptor = false;
    let mut allocated = 0;
    let mut names = 0u32;
    let mut dos_names = 0u32;
    for item in record.attributes() {
        let attribute = item?;
        if attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() {
            has_unnamed_data = true;
            if !attribute.nonresident || attribute.first_vcn()? == 0 {
                let size = attribute.data_size()?;
                if attribute.nonresident && attribute.initialized_size()? > size {
                    return Err(Error::InvalidAttribute);
                }
                first_segment_size = Some(size);
            }
            if attribute.nonresident && attribute.first_vcn()? == 0 {
                allocated = if attribute.flags()? & 0x8000 != 0 {
                    format::bytes::u64_at(attribute.raw(), 64)?
                } else {
                    attribute.allocated_size()?
                };
            } else if !attribute.nonresident {
                allocated = (attribute.resident_value()?.len() as u64 + 7) & !7;
            }
        }
        if attribute.kind == ATTR_ATTRIBUTE_LIST {
            has_attribute_list = true;
        }
        if attribute.kind == ATTR_SECURITY_DESCRIPTOR {
            inline_descriptor = true;
        }
        if attribute.kind == 0x30 {
            names += 1;
            let value = attribute.resident_value()?;
            if value.get(65) == Some(&2) {
                dos_names += 1;
            }
        }
    }
    let info = format::std_info::read(&record)?;
    // Symlinks may be reparse points or the older ntfs-3g/Interix DATA form.
    let (link_bytes, rest) = extension_space.split_at_mut(format::reparse::MAX_CREATE);
    let link = format::reparse::data(&mut volume, &record, link_bytes)?;
    let interix_len = if link.is_none() && info.attributes & 0x4 != 0 {
        format::reparse::interix_target(&mut volume, &record, link_bytes, rest)?
    } else {
        None
    };
    let mut special_type = None;
    let reparse_tag = match link {
        Some((tag, _)) if format::reparse::is_link_tag(tag) => tag,
        Some((tag, _)) => {
            special_type = Some(format::reparse::special_type(tag).ok_or(Error::Unsupported)?);
            0
        }
        None => {
            if interix_len.is_some() {
                format::reparse::INTERIX_SYMLINK
            } else {
                0
            }
        }
    };
    let data_size = if let Some(n) = interix_len {
        n as u64
    } else if reparse_tag != 0 {
        let mut parent = None;
        for a in record.attributes() {
            let a = a?;
            if a.kind == 0x30 {
                parent = Some(format::bytes::u64_at(a.resident_value()?, 0)?);
                break;
            }
        }
        let (temp, target) = rest.split_at_mut(BUFFER_BYTES);
        let depth = directory_depth(&mut volume, &mft, parent.unwrap_or(5), temp)?;
        format::reparse::target(&link_bytes[..link.unwrap().1], depth, target)? as u64
    } else if flags & 2 != 0 {
        0
    } else if !has_unnamed_data && !has_attribute_list {
        // A file with only named streams has an empty default stream.
        0
    } else if listed {
        // Resolved without its mapping continuations: the first segment
        // carries the sizes of the whole stream.
        first_segment_size.ok_or(Error::InvalidAttribute)?
    } else {
        volume.data_size_resolved(&mft, &record, number, &mut extension_space[..boot.record_bytes as usize])?
    };
    let ea_len = format::ea::read_stream(&mut volume, &record, &mut extension_space[..])?;
    let mode = format::unix_metadata::mode_in(&extension_space[..ea_len], flags & 2 != 0)?;
    let mode = match special_type {
        // The tag decides the type; $LXMOD supplies permissions when present.
        Some(kind) if flags & 2 == 0 => Some(kind | mode.map_or(0o644, |m| m & 0o7777)),
        Some(_) => return Err(Error::Unsupported),
        None => mode,
    };
    // DOS 8.3 aliases are listed in the header count but are not Linux links.
    let header_links = u32::from(record.link_count()?);
    let links = if has_attribute_list || names != header_links {
        header_links
    } else {
        (names - dos_names).max(u32::from(names != 0))
    };
    Ok(NodeInfo {
        file_reference: file_reference(number, sequence)?,
        data_size,
        flags: u32::from(flags),
        mode: mode.unwrap_or(u32::MAX),
        links,
        attributes: info.attributes,
        linux_flags: format::unix_metadata::flags_in(&extension_space[..ea_len])?,
        security_id: if inline_descriptor { 0 } else { record.security_id()?.unwrap_or(0) },
        times: info.times,
        allocated,
        reparse_tag,
        // Linux dev_t for character and block devices (MKDEV encoding:
        // 12-bit major, 20-bit minor). Numbers outside that range, and a
        // missing or malformed $LXDEV, present as device 0:0.
        reserved: match mode.map(|m| m & 0o170000) {
            Some(0o020000 | 0o060000) => match format::unix_metadata::device_in(&extension_space[..ea_len])? {
                Some((major, minor)) if major < 1 << 12 && minor < 1 << 20 => major << 20 | minor,
                _ => 0,
            },
            _ => 0,
        },
    })
}

/// Resolve one directory parent using the shared full-family validator.
fn directory_parent(
    volume: &mut Volume<Device>,
    mft: &MftRecord<'_>,
    reference: u64,
    scratch: &mut [u8],
) -> Result<u64> {
    let number = reference_number(reference);
    let n = volume.boot.record_bytes as usize;
    let needed = n + 2 * format::tx::RECORD_IMAGE + n;
    if scratch.len() < needed {
        return Err(Error::Truncated);
    }
    let (raw, rest) = scratch.split_at_mut(n);
    let (resolved, work) = rest.split_at_mut(format::tx::RECORD_IMAGE);
    volume.read_mft_record(mft, number, raw)?;
    let record = MftRecord::parse(raw, volume.boot.bytes_per_sector)?;
    if record.flags()? & 3 != 3
        || (reference_sequence(reference) != 0 && record.sequence_number()? != reference_sequence(reference))
    {
        return Err(Error::InvalidRecord);
    }
    if number == 5 {
        return file_reference(number, record.sequence_number()?);
    }
    volume.resolve_record(mft, &record, resolved, work)?;
    let record = MftRecord::from_decoded(resolved)?;
    let mut parent = None;
    for a in record.attributes() {
        let a = a?;
        if a.kind != 0x30 {
            continue;
        }
        let candidate = format::bytes::u64_at(a.resident_value()?, 0)?;
        if parent.is_some_and(|old| old != candidate) {
            return Err(Error::InvalidAttributeList);
        }
        parent = Some(candidate);
    }
    parent.ok_or(Error::InvalidRecord)
}

/// Walk checked parent references to the root with a bounded cycle guard.
fn directory_depth(
    volume: &mut Volume<Device>,
    mft: &MftRecord<'_>,
    mut directory: u64,
    scratch: &mut [u8],
) -> Result<u32> {
    for depth in 0..1024 {
        let number = reference_number(directory);
        if number == 5 {
            return Ok(depth);
        }
        let next = directory_parent(volume, mft, directory, scratch)?;
        if reference_number(next) == number {
            return Err(Error::InvalidRecord);
        }
        directory = next;
    }
    Err(Error::Unsupported)
}

fn read_link(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &mut [u8],
    reference: u64,
    parent: u64,
    output: &mut [u8],
) -> Result<usize> {
    let boot = BootSector::parse(boot_bytes)?;
    let record_size = boot.record_bytes as usize;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let (mft_space, rest) = scratch.split_at_mut(BUFFER_BYTES);
    let (record_space, rest) = rest.split_at_mut(BUFFER_BYTES);
    let mft = volume.load_mft(mft_space)?;
    let (record_bytes, resolved) = record_space.split_at_mut(record_size);
    volume.read_mft_record(&mft, reference_number(reference), record_bytes)?;
    let record = MftRecord::parse(record_bytes, boot.bytes_per_sector)?;
    volume.resolve_record_attributes(&mft, &record, &mut resolved[..format::tx::RECORD_IMAGE], rest)?;
    let record = MftRecord::from_decoded(&resolved[..format::tx::RECORD_IMAGE])?;
    if record.sequence_number()? != reference_sequence(reference) || record.flags()? & 1 == 0 {
        return Err(Error::InvalidRecord);
    }
    let (raw, work) = rest.split_at_mut(format::reparse::MAX_CREATE);
    if let Some((_, length)) = format::reparse::data(&mut volume, &record, raw)? {
        let depth = directory_depth(&mut volume, &mft, parent, work)?;
        format::reparse::target(&raw[..length], depth, output)
    } else if format::std_info::read(&record)?.attributes & 0x4 != 0 {
        format::reparse::interix_target(&mut volume, &record, raw, output)?.ok_or(Error::InvalidAttribute)
    } else {
        Err(Error::InvalidAttribute)
    }
}

/// Read the whole EA stream of a checked base record into stream.
fn read_eas<'a>(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &'a mut [u8],
    reference: u64,
) -> Result<&'a [u8]> {
    let boot = BootSector::parse(boot_bytes)?;
    let record_size = boot.record_bytes as usize;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let (mft_space, rest) = scratch.split_at_mut(BUFFER_BYTES);
    let (record_space, rest) = rest.split_at_mut(BUFFER_BYTES);
    let (_, stream) = rest.split_at_mut(BUFFER_BYTES);
    let mft = volume.load_mft(mft_space)?;
    let (record_bytes, resolved) = record_space.split_at_mut(record_size);
    volume.read_mft_record(&mft, reference_number(reference), record_bytes)?;
    let record = MftRecord::parse(record_bytes, boot.bytes_per_sector)?;
    volume.resolve_record_attributes(&mft, &record, &mut resolved[..format::tx::RECORD_IMAGE], stream)?;
    let record = MftRecord::from_decoded(&resolved[..format::tx::RECORD_IMAGE])?;
    if record.sequence_number()? != reference_sequence(reference)
        || record.flags()? & 1 == 0
        || record.base_file_reference()? != 0
    {
        return Err(Error::InvalidRecord);
    }
    let n = format::ea::read_stream(&mut volume, &record, stream)?;
    Ok(&stream[..n])
}

/// Scratch of the read_file layout: the table's map, the file's record, its
/// assembled image, and the list and extension record read while assembling.
const fn read_scratch_bytes(record_size: usize) -> usize {
    mft_space_bytes(record_size) + 2 * record_size + 2 * format::tx::RECORD_IMAGE
}

fn read_file(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &mut [u8],
    reference: u64,
    offset: u64,
    output: &mut [u8],
) -> Result<()> {
    let boot = BootSector::parse(boot_bytes)?;
    let record_size = boot.record_bytes as usize;
    if scratch.len() < read_scratch_bytes(record_size) || scratch.len() > SCRATCH_BYTES {
        return Err(Error::InvalidRecord);
    }
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let (mft_space, rest) = scratch.split_at_mut(mft_space_bytes(record_size));
    let (record_space, extension_space) = rest.split_at_mut(record_size);
    let mft = volume.load_mft(mft_space)?;
    let number = reference_number(reference);
    let record_bytes = &mut record_space[..boot.record_bytes as usize];
    volume.read_mft_record(&mft, number, record_bytes)?;
    let record = MftRecord::parse(record_bytes, boot.bytes_per_sector)?;
    let (resolved, extension_space) = extension_space.split_at_mut(format::tx::RECORD_IMAGE);
    volume.resolve_record_streams(&mft, &record, resolved, extension_space)?;
    let record = MftRecord::from_decoded(resolved)?;
    if record.sequence_number()? != reference_sequence(reference) || record.flags()? & 3 != 1 {
        return Err(Error::InvalidRecord);
    }
    volume.read_data_resolved(&mft, &record, number, &mut extension_space[..boot.record_bytes as usize], offset, output)
}

fn lookup_name(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &mut [u8],
    parent_reference: u64,
    requested: &[u8],
    linux_compatibility: bool,
    escaped: bool,
    cached_upcase: Option<&[u8]>,
) -> Result<Option<u64>> {
    let mut requested_units = [0_u16; format::linux_names::MAX_UNITS];
    let mut encoded = [0_u8; format::filename_metadata::MAX_NAME_BYTES];
    let unit_count = if escaped {
        format::linux_names::encode_linux(requested, &mut encoded)?
    } else {
        format::linux_names::encode(requested, &mut encoded)?
    } / 2;
    for (unit, value) in requested_units.iter_mut().zip(format::bytes::units(&encoded[..unit_count * 2])) {
        *unit = value;
    }
    let boot = BootSector::parse(boot_bytes)?;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let reserve = if cached_upcase.is_some() { 0 } else { UPCASE_RESERVE };
    let (mft_space, parent_space, rest) = walk_spaces(scratch, boot, reserve)?;
    let (index_space, rest) = rest.split_at_mut(rest.len() - reserve);
    let (upcase_record_space, upcase_space) = rest.split_at_mut(rest.len().min(BUFFER_BYTES));
    let mft = volume.load_mft(mft_space)?;
    let parent_number = reference_number(parent_reference);
    let parent_bytes = &mut parent_space[..boot.record_bytes as usize];
    volume.read_mft_record(&mft, parent_number, parent_bytes)?;
    let parent = MftRecord::parse(parent_bytes, boot.bytes_per_sector)?;
    if parent.flags()? & 3 != 3 || parent.sequence_number()? != reference_sequence(parent_reference) {
        return Err(Error::InvalidRecord);
    }
    // $I30 collates case-insensitively in both views, so the B+ tree
    // search always needs the volume's mapping; only native lookups fold.
    let table = UpcaseTable::parse(match cached_upcase {
        Some(table) => table,
        None => {
            load_upcase(&mut volume, &mft, upcase_record_space, &mut index_space[..], upcase_space)?;
            &upcase_space[..UPCASE_BYTES]
        }
    })?;
    let upcase = if linux_compatibility { None } else { Some(&table) };
    let requested_units = &requested_units[..unit_count];
    let mut exact = None;
    let mut found = None;
    // Every spelling either view can accept collates Equal, so the search
    // still sees each candidate and each conflicting duplicate.
    let order = |entry: &format::index::IndexEntry<'_>| Ok(table.collate(requested_units, entry.name));
    volume.search_directory(&parent, &mut index_space[..], order, |entry| {
        if entry.name.code_units().eq(requested_units.iter().copied()) {
            if exact.replace(entry.file_reference).is_some() {
                return Err(Error::InvalidIndex);
            }
        }
        if upcase.as_ref().is_some_and(|u| {
            // Native view folds every legal name, including standalone
            // POSIX names written without generating a DOS alias.
            let name =
                format::index::FileName { namespace: format::filename_metadata::WIN32, utf16le: entry.name.utf16le };
            u.matches(name, requested_units)
        }) {
            match found {
                Some(previous) if previous != entry.file_reference => {
                    return Err(Error::InvalidIndex);
                }
                _ => found = Some(entry.file_reference),
            }
        }
        Ok(())
    })?;
    Ok(exact.or(found))
}

/// The caller's in-memory copy of $UpCase, if it keeps one.
unsafe fn cached_upcase<'a>(upcase: *const u8) -> Option<&'a [u8]> {
    // SAFETY: the caller passes null or UPCASE_BYTES readable bytes.
    (!upcase.is_null()).then(|| unsafe { core::slice::from_raw_parts(upcase, UPCASE_BYTES) })
}

/// Load and validate $UpCase into `output` (UPCASE_BYTES), for a caller that
/// keeps the table in memory and passes it to lookups and listings.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_read_upcase(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    output: *mut u8,
) -> c_int {
    if data.is_null() || context.is_null() || scratch.is_null() || output.is_null() || length != 512
        || scratch_length != LOOKUP_SCRATCH_BYTES
    {
        return -22;
    }
    // SAFETY: C lends live, non-overlapping buffers for this synchronous call.
    let boot = unsafe { core::slice::from_raw_parts(data, length) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    let output = unsafe { core::slice::from_raw_parts_mut(output, UPCASE_BYTES) };
    let result = (|| {
        let boot = BootSector::parse(boot)?;
        let mut volume = Volume::new(Device { context, callback }, boot)?;
        let (mft_space, rest) = space.split_at_mut(BUFFER_BYTES);
        let (record_space, work) = rest.split_at_mut(BUFFER_BYTES);
        let mft = volume.load_mft(mft_space)?;
        load_upcase(&mut volume, &mft, record_space, work, output)?;
        UpcaseTable::parse(output).map(|_| ())
    })();
    result.map_or_else(ffi_error, |()| 0)
}

/// Read $UpCase (record 10) into upcase_space; record_space and work hold
/// its record and any attribute-list continuation while resolving the stream.
fn load_upcase<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    record_space: &mut [u8],
    work: &mut [u8],
    upcase_space: &mut [u8],
) -> Result<()> {
    let record_bytes = volume.boot.record_bytes as usize;
    let raw = &mut record_space[..record_bytes];
    volume.read_mft_record(mft, 10, raw)?;
    let record = MftRecord::parse(raw, volume.boot.bytes_per_sector)?;
    volume.read_data_resolved(mft, &record, 10, &mut work[..record_bytes], 0, &mut upcase_space[..UPCASE_BYTES])?;
    Ok(())
}

/// Linux bytes for a listed name, or None when the entry is only a DOS 8.3
/// alias or cannot be represented as one Linux path component.
fn linux_name(name: format::index::FileName<'_>, output: &mut [u8; 1024]) -> Option<usize> {
    if name.namespace == format::filename_metadata::DOS {
        return None;
    }
    // Most names are plain ASCII, which is its own UTF-8; anything else,
    // and whatever the full decoder would refuse, takes the general path.
    let units = name.utf16le.len() / 2;
    if units != 0
        && units <= 255
        && name.code_units().zip(output.iter_mut()).all(|(unit, byte)| {
            *byte = unit as u8;
            (0x20..0x7f).contains(&unit) && unit != u16::from(b'/')
        })
    {
        return Some(units);
    }
    match format::linux_names::decode_linux(name.code_units(), &mut output[..]) {
        Ok(n) if n != 0 && n <= 255 => Some(n),
        _ => None,
    }
}

fn enumerate_directory(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &mut [u8],
    parent_reference: u64,
    start: u64,
    resume: Option<&[u8]>,
    visibility: u32,
    cached_upcase: Option<&[u8]>,
    emit_context: *mut c_void,
    emit: EmitCallback,
) -> Result<()> {
    let boot = BootSector::parse(boot_bytes)?;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    // The table is loaded for a resumed listing only when it is not kept.
    let reserve = if cached_upcase.is_some() || resume.is_none() { 0 } else { UPCASE_RESERVE };
    let (mft_space, parent_space, rest) = walk_spaces(scratch, boot, reserve)?;
    let (index_space, rest) = rest.split_at_mut(rest.len() - reserve);
    let mft = volume.load_mft(mft_space)?;
    let parent_number = reference_number(parent_reference);
    let parent_bytes = &mut parent_space[..boot.record_bytes as usize];
    volume.read_mft_record(&mft, parent_number, parent_bytes)?;
    let parent = MftRecord::parse(parent_bytes, boot.bytes_per_sector)?;
    if parent.flags()? & 3 != 3 || parent.sequence_number()? != reference_sequence(parent_reference) {
        return Err(Error::InvalidRecord);
    }
    // Resuming after a name keeps a reader's place when earlier entries were
    // deleted meanwhile (rm -r unlinks each batch before reading the next);
    // an ordinal would then skip as many entries as were removed.
    let mut resume_key = [0_u8; format::filename_metadata::MAX_NAME_BYTES];
    let resume = match resume {
        Some(name) => {
            let table = match cached_upcase {
                Some(table) => table,
                None => {
                    if rest.len() < BUFFER_BYTES + UPCASE_BYTES {
                        return Err(Error::Truncated);
                    }
                    let (upcase_record_space, upcase_space) = rest.split_at_mut(BUFFER_BYTES);
                    load_upcase(&mut volume, &mft, upcase_record_space, &mut index_space[..], upcase_space)?;
                    &upcase_space[..UPCASE_BYTES]
                }
            };
            let length = format::linux_names::encode_linux(name, &mut resume_key)?;
            Some((&resume_key[..length], table))
        }
        None => None,
    };
    let mut ordinal = 0_u64;
    let mut full = false;
    // A resumed listing descends to its place in the tree: an entry at or
    // before the resume key sorts before what is sought, with its subtree.
    let order = |entry: &format::index::IndexEntry<'_>| {
        Ok(match resume {
            Some((key, table))
                if format::index_tree::compare_names(table, entry.name.utf16le, key) != core::cmp::Ordering::Greater =>
            {
                core::cmp::Ordering::Greater
            }
            _ => core::cmp::Ordering::Equal,
        })
    };
    let mut name = [0_u8; 1024];
    volume.search_directory(&parent, &mut index_space[..], order, |entry| {
        // Ordinals count representable names, including hidden entries.
        let Some(length) = linux_name(entry.name, &mut name) else {
            return Ok(());
        };
        // Keep cursor ordinals independent of visibility, including live changes.
        let number = reference_number(entry.file_reference);
        let metadata = number < 16 || (parent_number == 11 && entry.name.code_units().next() == Some(u16::from(b'$')));
        let attributes = format::bytes::u32_at(entry.file_name_value, 56)?;
        // VFS supplies these entries. A canonical on-disk root name must not
        // duplicate them when metadata visibility is enabled.
        let dot_entry = matches!(&name[..length], b"." | b"..");
        let visible = !dot_entry
            && if metadata {
                visibility & 4 != 0
            } else {
                (attributes & 2 == 0 || visibility & 1 != 0) && (attributes & 4 == 0 || visibility & 2 != 0)
            };
        let pending = match resume {
            Some((key, table)) => {
                format::index_tree::compare_names(table, entry.name.utf16le, key) == core::cmp::Ordering::Greater
            }
            None => ordinal >= start,
        };
        if visible && pending && !full {
            // SAFETY: name is live for the synchronous C callback,
            // which copies it into the VFS directory context.
            let kind = listed_type(entry.file_name_value, attributes)?;
            let result = unsafe { emit(emit_context, name.as_ptr(), length, entry.file_reference, ordinal, kind) };
            if result > 0 {
                full = true;
            } else if result < 0 {
                return Err(Error::Io);
            }
        }
        ordinal = ordinal.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    })
}

fn ffi_error(error: Error) -> c_int {
    match error {
        Error::NotEmpty => -39,     // ENOTEMPTY
        Error::Io => -5,            // EIO
        Error::NoSpace => -28,      // ENOSPC
        Error::Unsupported => -95,  // EOPNOTSUPP
        Error::AccessDenied => -13, // EACCES
        Error::Exists => -17,       // EEXIST
        Error::NotFound => -2,      // ENOENT
        Error::NotPermitted => -1,  // EPERM
        _ => -22,                   // EINVAL
    }
}

fn load_security<'a>(
    boot_bytes: &[u8],
    context: *mut c_void,
    callback: ReadCallback,
    scratch: &'a mut [u8],
    reference: u64,
) -> Result<&'a [u8]> {
    let boot = BootSector::parse(boot_bytes)?;
    let mut volume = Volume::new(Device { context, callback }, boot)?;
    let (mft_space, rest) = scratch.split_at_mut(BUFFER_BYTES);
    let (file_space, rest) = rest.split_at_mut(BUFFER_BYTES);
    let (secure_space, rest) = rest.split_at_mut(BUFFER_BYTES);
    let (index_space, rest) = rest.split_at_mut(BUFFER_BYTES);
    let (descriptor_space, _) = rest.split_at_mut(0x20014);
    let mft = volume.load_mft(mft_space)?;
    let number = reference_number(reference);
    let mut bitmap = None;
    for attr in mft.attributes() {
        let attr = attr?;
        if attr.kind == format::mft::ATTR_BITMAP && attr.name_utf16le()?.is_empty() && bitmap.replace(attr).is_some() {
            return Err(Error::InvalidRecord);
        }
    }
    let mut bit = [0];
    volume.read_attribute(bitmap.ok_or(Error::Unsupported)?, number / 8, &mut bit)?;
    if bit[0] & (1 << (number % 8)) == 0 {
        return Err(Error::InvalidRecord);
    }
    let (raw, resolved) = file_space.split_at_mut(boot.record_bytes as usize);
    volume.read_mft_record(&mft, number, raw)?;
    let record = MftRecord::parse(raw, boot.bytes_per_sector)?;
    volume.resolve_record_attributes(&mft, &record, &mut resolved[..format::tx::RECORD_IMAGE], index_space)?;
    let record = MftRecord::from_decoded(&resolved[..format::tx::RECORD_IMAGE])?;
    if record.sequence_number()? != reference_sequence(reference) {
        return Err(Error::InvalidRecord);
    }
    let descriptor = format::security_store::read_descriptor(
        &mut volume,
        &mft,
        &record,
        &mut secure_space[..boot.record_bytes as usize],
        index_space,
        descriptor_space,
    )?;
    Ok(descriptor.raw())
}

/// Validate immutable mount mapping. C retains the original text.
// SAFETY: C supplies length readable bytes for this synchronous call.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_validate_sidmap(data: *const u8, length: usize) -> c_int {
    if data.is_null() || length == 0 || length > format::identity::MAX_MAP_BYTES {
        return -22;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    match core::str::from_utf8(bytes).ok().and_then(|text| format::identity::validate_sidmap(text).ok()) {
        Some(_) => 0,
        None => -22,
    }
}

#[no_mangle]
pub extern "C" fn ntfs_rs_sidmap_size() -> usize {
    core::mem::size_of::<format::identity::CompiledSidMap>()
}

/// Initialize an opaque compiled map in C-owned, naturally aligned storage.
// SAFETY: output has capacity output_length and alignment of at least eight;
// input is a disjoint readable string. C publishes only after success and
// never modifies this storage until all inodes are destroyed at unmount.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_compile_sidmap(
    data: *const u8,
    length: usize,
    output: *mut c_void,
    output_length: usize,
) -> c_int {
    use format::identity::CompiledSidMap;
    const {
        assert!(core::mem::align_of::<CompiledSidMap>() <= 8);
    }
    if data.is_null()
        || output.is_null()
        || length == 0
        || length > format::identity::MAX_MAP_BYTES
        || output_length != core::mem::size_of::<CompiledSidMap>()
        || output as usize % core::mem::align_of::<CompiledSidMap>() != 0
    {
        return -22;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    let text = match core::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return -22,
    };
    // All fields are integers, bools and integer arrays; zero is a valid empty
    // map. In-place initialization avoids a >5 KiB temporary on kernel stack.
    unsafe {
        core::ptr::write_bytes(output.cast::<u8>(), 0, output_length);
    }
    let map = unsafe { &mut *output.cast::<CompiledSidMap>() };
    match map.initialize(text) {
        Ok(()) => 0,
        Err(error) => ffi_error(error),
    }
}

/// Resolve and validate once for an immutable read-only inode. Return byte
/// length with the exact descriptor at the start of scratch, or negative errno.
// SAFETY: C lends disjoint live boot/scratch buffers and a synchronous reader.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_load_security(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    reference: u64,
) -> c_int {
    if data.is_null()
        || context.is_null()
        || scratch.is_null()
        || length != 512
        || scratch_length != SECURITY_SCRATCH_BYTES
    {
        return -22;
    }
    let boot = unsafe { core::slice::from_raw_parts(data, length) };
    let bytes = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    match load_security(boot, context, callback, bytes, reference) {
        Ok(descriptor) => {
            let start = descriptor.as_ptr() as usize - scratch as usize;
            let size = descriptor.len();
            bytes.copy_within(start..start + size, 0);
            size as c_int
        }
        Err(error) => ffi_error(error),
    }
}

/// Evaluate cached descriptor bytes against the current credentials, never a
/// cached grant. requested=0 only returns reverse-mapped inode ownership.
// SAFETY: All pointers refer to live disjoint buffers for this call. gids and
// owners are aligned group_count/two-element u32 arrays. mapping is an aligned
// compiled map initialized by ntfs_rs_compile_sidmap. No pointers are retained.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_check_security(
    data: *const u8,
    length: usize,
    mapping: *const c_void,
    uid: u32,
    gids: *const u32,
    group_count: usize,
    requested: u32,
    owners: *mut u32,
) -> c_int {
    if data.is_null()
        || mapping.is_null()
        || gids.is_null()
        || owners.is_null()
        || length < 20
        || length > format::security::MAX_STORED_DESCRIPTOR
        || group_count > format::identity::MAX_GROUPS
    {
        return -22;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    let map = unsafe { &*mapping.cast::<format::identity::CompiledSidMap>() };
    let gids = unsafe { core::slice::from_raw_parts(gids, group_count) };
    let check = || -> Result<(bool, u32, u32)> {
        let descriptor = format::security::SecurityDescriptor::parse(bytes)?;
        if requested != 0 {
            return Ok((map.check_access(descriptor, uid, gids, requested)?, u32::MAX, u32::MAX));
        }
        let user = descriptor.owner.and_then(|sid| map.linux_id(false, sid.raw())).unwrap_or(u32::MAX);
        let group = descriptor.group.and_then(|sid| map.linux_id(true, sid.raw())).unwrap_or(u32::MAX);
        Ok((true, user, group))
    };
    match check() {
        Ok((allowed, user, group)) => {
            unsafe {
                owners.write(user);
                owners.add(1).write(group);
            }
            if allowed {
                0
            } else {
                -13
            }
        }
        Err(error) => ffi_error(error),
    }
}

/// Probe the NTFS boot sector, MFT record zero, root record, and reachable
/// root index tree. The caller keeps the superblock and boot buffer live and the
/// read callback performs only synchronous reads. scratch points to three
/// live 64-KiB caller-owned buffers.
// SAFETY: data must point to a live 512-byte boot-sector buffer. context
// callback, and scratch must remain valid throughout this synchronous call.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_probe(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
) -> c_int {
    if data.is_null() || context.is_null() || scratch.is_null() || length != 512 || scratch_length != SCRATCH_BYTES {
        return -22; // EINVAL
    }
    // SAFETY: The C bridge passes its mount-owned 512-byte boot buffer.
    let boot_bytes = unsafe { core::slice::from_raw_parts(data, length) };
    // SAFETY: C allocates and exclusively lends this buffer for the duration
    // of this call, then frees it only after the probe returns.
    let scratch_bytes = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    match probe(boot_bytes, context, callback, scratch_bytes) {
        Ok(()) => 0,
        Err(error) => ffi_error(error),
    }
}

/// Return checked inode identity, size, times, attributes and link type for
/// one MFT record.
// SAFETY: The caller lends a live 512-byte boot buffer, a synchronous read
// callback, ntfs_rs_ea_scratch_size() exclusive scratch bytes, and a
// writable NodeInfo.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_stat(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    number: u64,
    expected_sequence: u16,
    output: *mut NodeInfo,
) -> c_int {
    if data.is_null()
        || context.is_null()
        || scratch.is_null()
        || output.is_null()
        || length != 512
        || scratch_length != EA_SCRATCH_BYTES
    {
        return -22;
    }
    // SAFETY: C keeps these disjoint buffers live until the call returns.
    let boot = unsafe { core::slice::from_raw_parts(data, length) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    match node_info(boot, context, callback, space, number, expected_sequence) {
        Ok(info) => {
            // SAFETY: C supplied a writable, properly aligned NodeInfo.
            unsafe { output.write(info) };
            0
        }
        Err(error) => ffi_error(error),
    }
}

/// Workspace needed for three actual MFT records, not three maximum records.
// SAFETY: data is a live length-byte boot buffer for this synchronous call.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_read_scratch_size(data: *const u8, length: usize) -> c_int {
    if data.is_null() || length != 512 {
        return -22;
    }
    let bytes = unsafe { core::slice::from_raw_parts(data, length) };
    match BootSector::parse(bytes) {
        Ok(boot) => read_scratch_bytes(boot.record_bytes as usize) as c_int,
        Err(error) => ffi_error(error),
    }
}

/// Read up to one 256-KiB batch from a checked regular-file reference.
// SAFETY: The caller lends live disjoint boot, scratch, and output buffers
// for the duration of the synchronous call.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_read_file(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    reference: u64,
    offset: u64,
    output: *mut u8,
    output_length: usize,
) -> c_int {
    if data.is_null()
        || context.is_null()
        || scratch.is_null()
        || output.is_null()
        || length != 512
        || scratch_length > SCRATCH_BYTES
        || output_length > 4 * BUFFER_BYTES
    {
        return -22;
    }
    // SAFETY: C keeps all three buffers live and non-overlapping.
    let boot = unsafe { core::slice::from_raw_parts(data, length) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    let bytes = unsafe { core::slice::from_raw_parts_mut(output, output_length) };
    match read_file(boot, context, callback, space, reference, offset, bytes) {
        Ok(()) => 0,
        Err(error) => ffi_error(error),
    }
}

/// Find one UTF-8 name in a checked NTFS directory index.
// SAFETY: C supplies live disjoint boot, name, scratch, and output buffers.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_lookup_name(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    parent_reference: u64,
    name: *const u8,
    name_length: usize,
    output_reference: *mut u64,
    linux_compatibility: c_int,
    upcase: *const u8,
) -> c_int {
    if data.is_null()
        || context.is_null()
        || scratch.is_null()
        || name.is_null()
        || output_reference.is_null()
        || length != 512
        || scratch_length != LOOKUP_SCRATCH_BYTES
        || name_length == 0
        || name_length > 255
    {
        return -22;
    }
    // SAFETY: These pointers remain live and do not overlap during the call.
    let boot = unsafe { core::slice::from_raw_parts(data, length) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    let requested = unsafe { core::slice::from_raw_parts(name, name_length) };
    let linux = linux_compatibility != 0;
    // SAFETY: a non-null table is the caller's validated copy, live for the call.
    let cached = unsafe { cached_upcase(upcase) };
    // Win32-forbidden characters are stored escaped. A name stored before
    // that convention holds them unchanged: find it too.
    let found = match lookup_name(boot, context, callback, space, parent_reference, requested, linux, true, cached) {
        Ok(None) => lookup_name(boot, context, callback, space, parent_reference, requested, linux, false, cached),
        found => found,
    };
    match found {
        Ok(Some(reference)) => {
            // SAFETY: C provided a writable, aligned u64.
            unsafe { output_reference.write(reference) };
            0
        }
        Ok(None) => -2, // ENOENT
        Err(error) => ffi_error(error),
    }
}

/// Enumerate directory entries from a stable ordinal. The callback receives
/// that ordinal so VFS resume positions include skipped hidden entries.
// SAFETY: C supplies live boot/scratch and a synchronous callback. The
// callback does not retain any Rust name pointer.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_readdir(
    data: *const u8,
    length: usize,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    parent_reference: u64,
    start: u64,
    resume: *const u8,
    resume_length: usize,
    visibility: u32,
    upcase: *const u8,
    emit_context: *mut c_void,
    emit: EmitCallback,
) -> c_int {
    // Resuming after a name also needs room for $UpCase.
    let needed = if resume_length == 0 { SCRATCH_BYTES } else { LOOKUP_SCRATCH_BYTES };
    if data.is_null()
        || context.is_null()
        || scratch.is_null()
        || emit_context.is_null()
        || length != 512
        || (scratch_length != needed && scratch_length != LOOKUP_SCRATCH_BYTES)
        || (resume_length != 0 && resume.is_null())
    {
        return -22;
    }
    // SAFETY: C lends these buffers exclusively for this synchronous call.
    let boot = unsafe { core::slice::from_raw_parts(data, length) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
    let resume = (resume_length != 0).then(|| unsafe { core::slice::from_raw_parts(resume, resume_length) });
    match enumerate_directory(
        boot,
        context,
        callback,
        space,
        parent_reference,
        start,
        resume,
        visibility,
        // SAFETY: a non-null table is the caller's validated copy, live for the call.
        unsafe { cached_upcase(upcase) },
        emit_context,
        emit,
    ) {
        Ok(()) => 0,
        Err(error) => ffi_error(error),
    }
}

#[no_mangle]
pub extern "C" fn ntfs_rs_ea_scratch_size() -> usize {
    EA_SCRATCH_BYTES
}

/// Present a symbolic link target. parent is the directory the link was
/// reached through; absolute Windows targets are made relative to it.
// SAFETY: C lends live disjoint boot, scratch and output buffers.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_read_link(
    data: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    reference: u64,
    parent: u64,
    output: *mut u8,
    output_length: usize,
) -> c_int {
    if data.is_null() || context.is_null() || scratch.is_null() || output.is_null() {
        return -22;
    }
    let boot = unsafe { core::slice::from_raw_parts(data, 512) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, EA_SCRATCH_BYTES) };
    let out = unsafe { core::slice::from_raw_parts_mut(output, output_length) };
    match read_link(boot, context, callback, space, reference, parent, out) {
        Ok(n) => n as c_int,
        Err(error) => ffi_error(error),
    }
}

/// Copy one EA value. Returns its length, -61 (ENODATA) when absent, or
/// -34 (ERANGE) when output_length is nonzero but too small.
// SAFETY: C lends live disjoint boot, scratch, name and output buffers.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_get_ea(
    data: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    reference: u64,
    name: *const u8,
    name_length: usize,
    output: *mut u8,
    output_length: usize,
) -> c_int {
    if data.is_null() || context.is_null() || scratch.is_null() || name.is_null() {
        return -22;
    }
    let boot = unsafe { core::slice::from_raw_parts(data, 512) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, EA_SCRATCH_BYTES) };
    let name = unsafe { core::slice::from_raw_parts(name, name_length) };
    let stream = match read_eas(boot, context, callback, space, reference) {
        Ok(stream) => stream,
        Err(error) => return ffi_error(error),
    };
    match format::ea::find(stream, name) {
        Ok(Some(value)) => {
            if output_length != 0 {
                if output.is_null() || output_length < value.len() {
                    return -34;
                }
                unsafe { core::slice::from_raw_parts_mut(output, value.len()) }.copy_from_slice(value);
            }
            value.len() as c_int
        }
        Ok(None) => -61,
        Err(error) => ffi_error(error),
    }
}

/// NUL-separated EA names. Returns the total length (ERANGE as above).
// SAFETY: C lends live disjoint boot, scratch and output buffers.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_list_ea(
    data: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    reference: u64,
    output: *mut u8,
    output_length: usize,
) -> c_int {
    if data.is_null() || context.is_null() || scratch.is_null() {
        return -22;
    }
    let boot = unsafe { core::slice::from_raw_parts(data, 512) };
    let space = unsafe { core::slice::from_raw_parts_mut(scratch, EA_SCRATCH_BYTES) };
    let stream = match read_eas(boot, context, callback, space, reference) {
        Ok(stream) => stream,
        Err(error) => return ffi_error(error),
    };
    let out: &mut [u8] = if output_length == 0 || output.is_null() {
        &mut []
    } else {
        unsafe { core::slice::from_raw_parts_mut(output, output_length) }
    };
    match format::ea::list(stream, out) {
        Ok(n) => n as c_int,
        Err(Error::NoSpace) => -34,
        Err(error) => ffi_error(error),
    }
}

/// Resolve a directory's parent for reconnecting exported file handles.
/// C supplies EA_SCRATCH_BYTES and holds the volume read lock.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_parent(
    boot: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    reference: u64,
    output: *mut u64,
) -> c_int {
    if boot.is_null() || scratch.is_null() || output.is_null() {
        return -22;
    }
    let action = || -> Result<u64> {
        let boot = BootSector::parse(unsafe { core::slice::from_raw_parts(boot, 512) })?;
        let space = unsafe { core::slice::from_raw_parts_mut(scratch, EA_SCRATCH_BYTES) };
        let (zero, rest) = space.split_at_mut(BUFFER_BYTES);
        let mut volume = Volume::new(Device { context, callback }, boot)?;
        let mft = volume.load_mft(zero)?;
        directory_parent(&mut volume, &mft, reference, rest)
    };
    match action() {
        Ok(parent) => {
            unsafe {
                *output = parent;
            }
            0
        }
        Err(e) => ffi_error(e),
    }
}

/// Enumerate checked data extents, including attribute-list extensions.
/// The callback returns positive when full, negative on an output error.
/// Scratch uses the read_file layout, sized by ntfs_rs_read_scratch_size.
#[no_mangle]
pub unsafe extern "C" fn ntfs_rs_map_file(
    boot: *const u8,
    context: *mut c_void,
    callback: ReadCallback,
    scratch: *mut u8,
    scratch_length: usize,
    reference: u64,
    start: u64,
    length: u64,
    emit_context: *mut c_void,
    emit: unsafe extern "C" fn(*mut c_void, u64, u64, u64, u32) -> c_int,
) -> c_int {
    if boot.is_null() || scratch.is_null() || scratch_length > SCRATCH_BYTES {
        return -22;
    }
    let mut status = 0;
    let mut action = || -> Result<()> {
        let boot = BootSector::parse(unsafe { core::slice::from_raw_parts(boot, 512) })?;
        let n = boot.record_bytes as usize;
        if scratch_length < read_scratch_bytes(n) {
            return Err(Error::Truncated);
        }
        // SAFETY: C lends scratch_length live bytes, disjoint from boot.
        let space = unsafe { core::slice::from_raw_parts_mut(scratch, scratch_length) };
        let (zero, rest) = space.split_at_mut(mft_space_bytes(n));
        let (raw, rest) = rest.split_at_mut(n);
        let (resolved, extension) = rest.split_at_mut(format::tx::RECORD_IMAGE);
        let mut volume = Volume::new(Device { context, callback }, boot)?;
        let mft = volume.load_mft(zero)?;
        volume.read_mft_record(&mft, reference_number(reference), raw)?;
        let record = MftRecord::parse(raw, boot.bytes_per_sector)?;
        volume.resolve_record_streams(&mft, &record, resolved, extension)?;
        let record = MftRecord::from_decoded(resolved)?;
        if record.flags()? & 1 == 0 || record.sequence_number()? != reference_sequence(reference) {
            return Err(Error::InvalidRecord);
        }
        let end = start.checked_add(length).ok_or(Error::Overflow)?;
        let (mut allocation, mut initialized) = (0, 0);
        volume.visit_unnamed_data(&mft, &record, reference_number(reference), &mut extension[..n], |_, attr| {
            if status != 0 {
                return Ok(());
            }
            if !attr.nonresident {
                let stop = attr.data_size()?.min(end);
                if start < stop {
                    status = unsafe { emit(emit_context, start, 0, stop - start, 1 | 2 | 0x100 | 0x200) };
                }
                return Ok(());
            }
            if attr.flags()? & !0x8000 != 0 {
                return Err(Error::Unsupported);
            }
            if attr.first_vcn()? == 0 {
                allocation = attr.allocated_size()?;
                initialized = attr.initialized_size()?;
            }
            let cluster = u64::from(boot.cluster_bytes);
            for run in format::runlist::DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
                let run = run?;
                let Some(lcn) = run.lcn else {
                    continue;
                };
                let logical = run.vcn.checked_mul(cluster).ok_or(Error::Overflow)?;
                let stop = (run.vcn + run.len).checked_mul(cluster).ok_or(Error::Overflow)?.min(end);
                let mut from = logical.max(start);
                while from < stop && status == 0 {
                    let to = if from < initialized { stop.min(initialized) } else { stop };
                    let flags = u32::from(to == allocation) | if from >= initialized { 0x800 } else { 0 };
                    status = unsafe { emit(emit_context, from, lcn * cluster + from - logical, to - from, flags) };
                    from = to;
                }
            }
            Ok(())
        })
    };
    match action() {
        Ok(()) => status.min(0),
        Err(e) => ffi_error(e),
    }
}
