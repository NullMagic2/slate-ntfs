//! Module: ntfs_rs::reparse
//! Purpose: Read NTFS symbolic links and junctions and encode new link targets.
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
const SYMLINK_RELATIVE: u32 = 1;
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
        if !(8..=MAX_CREATE).contains(&n) || n > out.len() {
            return Err(Error::InvalidAttribute);
        }
        volume.read_attribute(a, 0, &mut out[..n])?;
        if usize::from(u16_at(out, 4)?) + 8 != n {
            return Err(Error::InvalidAttribute);
        }
        found = Some((u32_at(out, 0)?, n));
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
    let n = 8 + 4 + target.len();
    let buffer = out.get_mut(..n).ok_or(Error::NoSpace)?;
    buffer.fill(0);
    buffer[..4].copy_from_slice(&TAG_LX_SYMLINK.to_le_bytes());
    buffer[4..6].copy_from_slice(&((4 + target.len()) as u16).to_le_bytes());
    buffer[8..12].copy_from_slice(&2u32.to_le_bytes());
    buffer[12..].copy_from_slice(target);
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
    if buffer.len() < 8 {
        return Err(Error::InvalidAttribute);
    }
    let tag = u32_at(buffer, 0)?;
    let body = &buffer[8..];
    match tag {
        TAG_LX_SYMLINK => {
            if body.len() < 4 || u32_at(body, 0)? != 2 {
                return Err(Error::Unsupported);
            }
            let bytes = &body[4..];
            if bytes.is_empty() || bytes.contains(&0) || bytes.len() > out.len() {
                return Err(Error::Unsupported);
            }
            out[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        TAG_SYMLINK | TAG_MOUNT_POINT => {
            let header = if tag == TAG_SYMLINK { 12 } else { 8 };
            if body.len() < header {
                return Err(Error::InvalidAttribute);
            }
            let relative = tag == TAG_SYMLINK && u32_at(body, 8)? & SYMLINK_RELATIVE != 0;
            let paths = &body[header..];
            let substitute = utf16_path(paths, usize::from(u16_at(body, 0)?), usize::from(u16_at(body, 2)?))?;
            let print = utf16_path(paths, usize::from(u16_at(body, 4)?), usize::from(u16_at(body, 6)?))?;
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
mod tests {
    use super::*;

    fn read(target_bytes: &[u8], depth: u32) -> std::vec::Vec<u8> {
        let mut data = [0u8; MAX_TARGET + 64];
        let (n, _) = build(target_bytes, &mut data).unwrap();
        let mut out = [0u8; MAX_TARGET];
        let m = target(&data[..n], depth, &mut out).unwrap();
        out[..m].to_vec()
    }

    #[test]
    fn link_targets_round_trip() {
        for t in [
            &b"../drive_c"[..],
            b"dir/file.txt",
            b"/",
            b"/usr/lib/libc.so.6",
            b"c:",
            b"a\\b",
            b"\xff\xfe",
            b"trailing./x",
            b"caf\xc3\xa9",
        ] {
            assert_eq!(read(t, 3), t, "{t:?}");
        }
        let mut data = [0u8; 256];
        assert_eq!(build(b"../x", &mut data).unwrap().1, TAG_SYMLINK);
        assert_eq!(build(b"/x", &mut data).unwrap().1, TAG_LX_SYMLINK);
        assert!(build(b"", &mut data).is_err());
    }

    #[test]
    fn absolute_windows_links_become_volume_relative() {
        let path: std::vec::Vec<u16> = "\\??\\C:\\Users\\me".encode_utf16().collect();
        let bytes = path.len() * 2;
        let mut data = std::vec![0u8; 20 + bytes];
        data[..4].copy_from_slice(&TAG_SYMLINK.to_le_bytes());
        data[4..6].copy_from_slice(&((12 + bytes) as u16).to_le_bytes());
        data[10..12].copy_from_slice(&(bytes as u16).to_le_bytes());
        for (i, u) in path.iter().enumerate() {
            data[20 + 2 * i..22 + 2 * i].copy_from_slice(&u.to_le_bytes());
        }
        let mut out = [0u8; 256];
        let n = target(&data, 2, &mut out).unwrap();
        assert_eq!(&out[..n], b"../../Users/me");
        let n = target(&data, 0, &mut out).unwrap();
        assert_eq!(&out[..n], b"./Users/me");
    }
}
