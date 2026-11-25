//! Module: ntfs_rs::reparse::tests
//! Purpose: Check reparse framing, target translation and opaque payload preservation.
//! Created: 2026-11-25
//! Architecture: Independent buffers exercise the shared parser and link encoder.

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

#[test]
fn framing_keeps_nonlocal_windows_targets_separate_from_translation() {
    for path in [r"\??\UNC\server\share\file", r"\??\Volume{11111111-1111-1111-1111-111111111111}\file"] {
        let path: std::vec::Vec<_> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut value = std::vec![0; HEADER_BYTES + LINK_HEADER_BYTES + path.len()];
        value[..core::mem::size_of::<u32>()].copy_from_slice(&TAG_SYMLINK.to_le_bytes());
        let payload_length = (value.len() - HEADER_BYTES) as u16;
        value[LENGTH_OFFSET..LENGTH_OFFSET + LENGTH_BYTES].copy_from_slice(&payload_length.to_le_bytes());
        let length_at = HEADER_BYTES + SUBSTITUTE_LENGTH;
        value[length_at..length_at + PATH_FIELD_BYTES].copy_from_slice(&(path.len() as u16).to_le_bytes());
        value[HEADER_BYTES + LINK_HEADER_BYTES..].copy_from_slice(&path);
        assert_eq!(validate(&value), Ok(TAG_SYMLINK));
        assert_eq!(target(&value, 0, &mut [0; MAX_TARGET]), Err(Error::Unsupported));
        value[HEADER_BYTES + SUBSTITUTE_OFFSET] = 1;
        assert_eq!(validate(&value), Err(Error::InvalidAttribute));
    }
}

#[test]
fn opaque_guid_payloads_and_known_link_bounds_are_checked_without_rewriting() {
    const VENDOR_TAG: u32 = 0x42;
    let mut value = std::vec![0; GUID_HEADER_BYTES + 3];
    value[..core::mem::size_of::<u32>()].copy_from_slice(&VENDOR_TAG.to_le_bytes());
    value[LENGTH_OFFSET..LENGTH_OFFSET + LENGTH_BYTES].copy_from_slice(&3_u16.to_le_bytes());
    value[HEADER_BYTES] = 1;
    value[GUID_HEADER_BYTES..].copy_from_slice(b"raw");
    let original = value.clone();
    assert_eq!(validate(&value), Ok(VENDOR_TAG));
    assert_eq!(value, original);
    value[HEADER_BYTES] = 0;
    assert_eq!(validate(&value), Err(Error::InvalidAttribute));
    let mut link = [0; MAX_CREATE];
    let (length, tag) = build(b"../target", &mut link).unwrap();
    assert_eq!(validate(&link[..length]), Ok(tag));
    link[HEADER_BYTES + LINK_FLAGS_OFFSET] = 2;
    assert_eq!(validate(&link[..length]), Err(Error::InvalidAttribute));
    link[HEADER_BYTES + LINK_FLAGS_OFFSET] = SYMLINK_RELATIVE as u8;
    link[LENGTH_OFFSET] ^= 1;
    assert_eq!(validate(&link[..length]), Err(Error::InvalidAttribute));
}
