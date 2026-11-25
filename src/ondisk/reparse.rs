//! Module: ntfs_rs::reparse
//! Purpose: Validate reparse records and read or encode supported link targets.
//! Created: 2026-10-01
//! Architecture: Volume readers and namespace writers share Windows symlink, mount-point
//! and LX-symlink formats. Relative representable Unicode uses Windows links;
//! other Linux targets use LX bytes losslessly. Absolute Windows targets are
//! presented relative to the containing volume, matching Linux ntfs3 behavior.

use super::bytes::{u16_at, u32_at};
use super::mft::MftRecord;
use super::{Error, Result};

pub const ATTR_REPARSE: u32 = 0xc0;
pub const TAG_SYMLINK: u32 = 0xa000_000c;
pub const TAG_MOUNT_POINT: u32 = 0xa000_0003;
pub const TAG_LX_SYMLINK: u32 = 0xa000_001d;
/// Internal inode marker for the older ntfs-3g/Interix DATA symlink form.
pub const INTERIX_SYMLINK: u32 = 1;
pub const HEADER_BYTES: usize = 8;
pub const GUID_BYTES: usize = 16;
pub const GUID_HEADER_BYTES: usize = HEADER_BYTES + GUID_BYTES;
pub const LENGTH_OFFSET: usize = 4;
pub const LENGTH_BYTES: usize = core::mem::size_of::<u16>();
pub const MICROSOFT_TAG: u32 = 0x8000_0000;
const RESERVED_TAG_MAX: u32 = 1;
const RESERVED_TAG_BITS: u32 = 0x0fff_0000;
const SYMLINK_RELATIVE: u32 = 1;
const PATH_FIELD_BYTES: usize = core::mem::size_of::<u16>();
const SUBSTITUTE_OFFSET: usize = 0;
const SUBSTITUTE_LENGTH: usize = SUBSTITUTE_OFFSET + PATH_FIELD_BYTES;
const PRINT_OFFSET: usize = SUBSTITUTE_LENGTH + PATH_FIELD_BYTES;
const PRINT_LENGTH: usize = PRINT_OFFSET + PATH_FIELD_BYTES;
const LINK_FLAGS_OFFSET: usize = PRINT_LENGTH + PATH_FIELD_BYTES;
const MOUNT_HEADER_BYTES: usize = LINK_FLAGS_OFFSET;
const LINK_HEADER_BYTES: usize = LINK_FLAGS_OFFSET + core::mem::size_of::<u32>();
const LX_VERSION_BYTES: usize = core::mem::size_of::<u32>();
const LX_SYMLINK_VERSION: u32 = 2;
/// NTFS maximum reparse buffer, including its header.
pub const MAX_CREATE: usize = 16 * 1024;
/// Linux PATH_MAX, the largest symlink target presented.
pub const MAX_TARGET: usize = 4096;

pub fn is_link_tag(tag: u32) -> bool {
    matches!(tag, TAG_SYMLINK | TAG_MOUNT_POINT | TAG_LX_SYMLINK)
}

/// WSL special-file reparse tags (written by WSL 2 and the Linux SMB client).
/// Their reparse buffer carries no data; the device number, when there is
/// one, is in the $LXDEV EA.
pub const TAG_AF_UNIX: u32 = 0x8000_0023;
pub const TAG_LX_FIFO: u32 = 0x8000_0024;
pub const TAG_LX_CHR: u32 = 0x8000_0025;
pub const TAG_LX_BLK: u32 = 0x8000_0026;

/// Linux file type (S_IFMT bits) of a WSL special-file reparse tag.
pub fn special_type(tag: u32) -> Option<u32> {
    match tag {
        TAG_AF_UNIX => Some(0o140000),
        TAG_LX_FIFO => Some(0o010000),
        TAG_LX_CHR => Some(0o020000),
        TAG_LX_BLK => Some(0o060000),
        _ => None,
    }
}

/// Validate storage framing independently of Linux target translation.
/// Unknown valid tags and nonlocal Windows targets keep their exact payload.
pub fn validate(buffer: &[u8]) -> Result<u32> {
    if !(HEADER_BYTES..=MAX_CREATE).contains(&buffer.len()) {
        return Err(Error::InvalidAttribute);
    }
    let tag = u32_at(buffer, 0)?;
    if tag <= RESERVED_TAG_MAX || tag & RESERVED_TAG_BITS != 0 {
        return Err(Error::InvalidAttribute);
    }
    let header = if tag & MICROSOFT_TAG == 0 { GUID_HEADER_BYTES } else { HEADER_BYTES };
    if usize::from(u16_at(buffer, LENGTH_OFFSET)?) + header != buffer.len() {
        return Err(Error::InvalidAttribute);
    }
    if header == GUID_HEADER_BYTES && buffer[HEADER_BYTES..GUID_HEADER_BYTES].iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidAttribute);
    }
    let body = &buffer[header..];
    match tag {
        TAG_SYMLINK | TAG_MOUNT_POINT => {
            let length = if tag == TAG_SYMLINK { LINK_HEADER_BYTES } else { MOUNT_HEADER_BYTES };
            if body.len() < length || (tag == TAG_SYMLINK && u32_at(body, LINK_FLAGS_OFFSET)? & !SYMLINK_RELATIVE != 0)
            {
                return Err(Error::InvalidAttribute);
            }
            let mut nonempty = false;
            for (offset, size) in [(SUBSTITUTE_OFFSET, SUBSTITUTE_LENGTH), (PRINT_OFFSET, PRINT_LENGTH)] {
                let offset = usize::from(u16_at(body, offset)?);
                let size = usize::from(u16_at(body, size)?);
                if offset % PATH_FIELD_BYTES != 0 || size % PATH_FIELD_BYTES != 0 {
                    return Err(Error::InvalidAttribute);
                }
                let path = body[length..]
                    .get(offset..offset.checked_add(size).ok_or(Error::Overflow)?)
                    .ok_or(Error::InvalidAttribute)?;
                if path.chunks_exact(PATH_FIELD_BYTES).any(|unit| unit == [0, 0]) {
                    return Err(Error::InvalidAttribute);
                }
                nonempty |= !path.is_empty();
            }
            if !nonempty {
                return Err(Error::InvalidAttribute);
            }
        }
        TAG_LX_SYMLINK => {
            if body.len() <= LX_VERSION_BYTES
                || u32_at(body, 0)? != LX_SYMLINK_VERSION
                || body[LX_VERSION_BYTES..].contains(&0)
            {
                return Err(Error::InvalidAttribute);
            }
        }
        _ if special_type(tag).is_some() && !body.is_empty() => return Err(Error::InvalidAttribute),
        _ => {}
    }
    Ok(tag)
}

/// Read either resident or nonresident reparse data into caller scratch.
pub fn data<R: super::volume::ReadAt>(
    volume: &mut super::volume::Volume<R>,
    record: &MftRecord<'_>,
    out: &mut [u8],
) -> Result<Option<(u32, usize)>> {
    let mut found = None;
    for a in record.attributes() {
        let a = a?;
        if a.kind != ATTR_REPARSE {
            continue;
        }
        if found.is_some() || a.flags()? != 0 || !a.name_utf16le()?.is_empty() || (a.nonresident && a.first_vcn()? != 0)
        {
            return Err(Error::InvalidAttribute);
        }
        let n = usize::try_from(a.data_size()?).map_err(|_| Error::Overflow)?;
        if !(HEADER_BYTES..=MAX_CREATE).contains(&n) || n > out.len() {
            return Err(Error::InvalidAttribute);
        }
        volume.read_attribute(a, 0, &mut out[..n])?;
        found = Some((validate(&out[..n])?, n));
    }
    Ok(found)
}

/// ntfs-3g can store a Linux symlink as SYSTEM-marked unnamed DATA beginning
/// with IntxLNK\x01, followed by its UTF-16LE target. This is not a reparse
/// point, so it needs a separate read path.
pub fn interix_target<R: super::volume::ReadAt>(
    volume: &mut super::volume::Volume<R>,
    record: &MftRecord<'_>,
    raw: &mut [u8],
    out: &mut [u8],
) -> Result<Option<usize>> {
    for item in record.attributes() {
        let a = item?;
        if a.kind != 0x80 || !a.name_utf16le()?.is_empty() || (a.nonresident && a.first_vcn()? != 0) {
            continue;
        }
        let n = usize::try_from(a.data_size()?).map_err(|_| Error::Overflow)?;
        if !(10..=8 + 2 * MAX_TARGET).contains(&n) || n % 2 != 0 || n > raw.len() {
            return Ok(None);
        }
        volume.read_attribute(a, 0, &mut raw[..n])?;
        if !raw[..n].starts_with(b"IntxLNK\x01") {
            return Ok(None);
        }
        let len = super::linux_names::decode_path(super::bytes::units(&raw[8..n]), out)?;
        if len == 0 {
            return Err(Error::InvalidAttribute);
        }
        return Ok(Some(len));
    }
    Ok(None)
}

fn windows_char_ok(c: char) -> bool {
    c >= ' ' && !super::linux_names::WINDOWS_RESERVED_CHARS.contains(&c)
}

/// Build a reparse buffer for Linux target. Returns its length and tag.
pub fn build(target: &[u8], out: &mut [u8]) -> Result<(usize, u32)> {
    if target.is_empty() || target.len() > MAX_TARGET || target.contains(&0) {
        return Err(Error::Unsupported);
    }
    if let Some(n) = build_windows_relative(target, out)? {
        return Ok((n, TAG_SYMLINK));
    }
    let n = HEADER_BYTES + LX_VERSION_BYTES + target.len();
    let buffer = out.get_mut(..n).ok_or(Error::NoSpace)?;
    buffer.fill(0);
    buffer[..4].copy_from_slice(&TAG_LX_SYMLINK.to_le_bytes());
    buffer[LENGTH_OFFSET..LENGTH_OFFSET + LENGTH_BYTES]
        .copy_from_slice(&((LX_VERSION_BYTES + target.len()) as u16).to_le_bytes());
    buffer[HEADER_BYTES..HEADER_BYTES + LX_VERSION_BYTES].copy_from_slice(&LX_SYMLINK_VERSION.to_le_bytes());
    buffer[HEADER_BYTES + LX_VERSION_BYTES..].copy_from_slice(target);
    Ok((n, TAG_LX_SYMLINK))
}

fn build_windows_relative(target: &[u8], out: &mut [u8]) -> Result<Option<usize>> {
    let Ok(text) = core::str::from_utf8(target) else {
        return Ok(None);
    };
    if text.starts_with('/') || !text.chars().all(|c| c == '/' || windows_char_ok(c)) {
        return Ok(None);
    }
    // Windows strips trailing dots/spaces from components; keep exact bytes.
    if text.split('/').any(|part| part != "." && part != ".." && part.ends_with(['.', ' '])) {
        return Ok(None);
    }
    let units = text.encode_utf16().count();
    let path_bytes = units * 2;
    let n = 20 + 2 * path_bytes;
    if n > MAX_CREATE || n > out.len() {
        return Ok(None);
    }
    let buffer = &mut out[..n];
    buffer.fill(0);
    buffer[..4].copy_from_slice(&TAG_SYMLINK.to_le_bytes());
    buffer[4..6].copy_from_slice(&((n - 8) as u16).to_le_bytes());
    // Substitute name first, then an identical print name.
    buffer[8..10].copy_from_slice(&0u16.to_le_bytes());
    buffer[10..12].copy_from_slice(&(path_bytes as u16).to_le_bytes());
    buffer[12..14].copy_from_slice(&(path_bytes as u16).to_le_bytes());
    buffer[14..16].copy_from_slice(&(path_bytes as u16).to_le_bytes());
    buffer[16..20].copy_from_slice(&SYMLINK_RELATIVE.to_le_bytes());
    for (copy, base) in [(0, 20), (1, 20 + path_bytes)] {
        let _ = copy;
        for (i, unit) in text.encode_utf16().enumerate() {
            let unit = if unit == u16::from(b'/') { u16::from(b'\\') } else { unit };
            buffer[base + 2 * i..base + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(Some(n))
}

fn utf16_path(buffer: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    if length % 2 != 0 {
        return Err(Error::InvalidAttribute);
    }
    buffer.get(offset..offset + length).ok_or(Error::InvalidAttribute)
}

/// Present the target of a link reparse buffer as Linux bytes. depth is
/// the number of directories between the volume root and the link's parent.
pub fn target(buffer: &[u8], depth: u32, out: &mut [u8]) -> Result<usize> {
    if buffer.len() < HEADER_BYTES {
        return Err(Error::InvalidAttribute);
    }
    let tag = u32_at(buffer, 0)?;
    let body = &buffer[HEADER_BYTES..];
    match tag {
        TAG_LX_SYMLINK => {
            if body.len() < LX_VERSION_BYTES || u32_at(body, 0)? != LX_SYMLINK_VERSION {
                return Err(Error::Unsupported);
            }
            let bytes = &body[LX_VERSION_BYTES..];
            if bytes.is_empty() || bytes.contains(&0) || bytes.len() > out.len() {
                return Err(Error::Unsupported);
            }
            out[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        TAG_SYMLINK | TAG_MOUNT_POINT => {
            let header = if tag == TAG_SYMLINK { LINK_HEADER_BYTES } else { MOUNT_HEADER_BYTES };
            if body.len() < header {
                return Err(Error::InvalidAttribute);
            }
            let relative = tag == TAG_SYMLINK && u32_at(body, LINK_FLAGS_OFFSET)? & SYMLINK_RELATIVE != 0;
            let paths = &body[header..];
            let substitute = utf16_path(
                paths,
                usize::from(u16_at(body, SUBSTITUTE_OFFSET)?),
                usize::from(u16_at(body, SUBSTITUTE_LENGTH)?),
            )?;
            let print =
                utf16_path(paths, usize::from(u16_at(body, PRINT_OFFSET)?), usize::from(u16_at(body, PRINT_LENGTH)?))?;
            let mut path = if substitute.is_empty() { print } else { substitute };
            if path.is_empty() {
                return Err(Error::InvalidAttribute);
            }
            let unit = |p: &[u8], i: usize| u16::from_le_bytes([p[2 * i], p[2 * i + 1]]);
            let mut n = 0;
            if !relative {
                // "\??\C:\dir" or "C:\dir": drop the NT prefix and drive,
                // then walk up from the link's directory to the volume root.
                if path.len() >= 8 && (0..4).all(|i| unit(path, i) == [92, 63, 63, 92][i]) {
                    path = &path[8..];
                }
                let drive = path.len() >= 4
                    && unit(path, 1) == u16::from(b':')
                    && (u16::from(b'A')..=u16::from(b'Z')).contains(&(unit(path, 0) & !0x20));
                if !drive {
                    // UNC or volume-GUID targets cannot be resolved locally.
                    return Err(Error::Unsupported);
                }
                path = &path[4..];
                while path.len() >= 2 && unit(path, 0) == 92 {
                    path = &path[2..];
                }
                if depth == 0 {
                    out.get_mut(..2).ok_or(Error::NoSpace)?.copy_from_slice(b"./");
                    n = 2;
                }
                for _ in 0..depth {
                    out.get_mut(n..n + 3).ok_or(Error::NoSpace)?.copy_from_slice(b"../");
                    n += 3;
                }
                if path.is_empty() {
                    // The target is the volume root itself.
                    return Ok(n - 1);
                }
            }
            let slash = path.chunks_exact(2).map(|c| match u16::from_le_bytes([c[0], c[1]]) {
                92 => 47,
                u => u,
            });
            let m = super::linux_names::decode_path(slash, &mut out[n..])?;
            Ok(n + m)
        }
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
#[path = "../tests/core/reparse.rs"]
mod tests;
