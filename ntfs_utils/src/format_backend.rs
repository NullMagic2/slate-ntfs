//! Module: ntfs_utils::format_backend
//! Purpose: Native Rust NTFS 3.1 creation.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

//! Native Rust NTFS 3.1 creation. Build and validate the entire metadata plan
//! before the first write. Publish the primary boot sector last, after flush.
//! This is a data-volume formatter, not a partitioner or bootloader installer.
use ntfs_rs::mft::MftRecord;
use ntfs_rs::{bytes, filename_metadata};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::time::{SystemTime, UNIX_EPOCH};

fn p16(b: &mut [u8], o: usize, v: u16) {
    bytes::p16(b, o, v).expect("preallocated formatter image contains the integer field");
}
fn p32(b: &mut [u8], o: usize, v: u32) {
    bytes::p32(b, o, v).expect("preallocated formatter image contains the integer field");
}
fn p64(b: &mut [u8], o: usize, v: u64) {
    bytes::p64(b, o, v).expect("preallocated formatter image contains the integer field");
}
fn align(n: usize) -> usize {
    (n + 7) & !7
}
fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn sequence(n: usize) -> u16 {
    if n == 0 || n >= 24 {
        1
    } else {
        n as u16
    }
}
fn reference(n: usize) -> u64 {
    n as u64 | ((sequence(n) as u64) << 48)
}

fn resident(kind: u32, name: &str, value: &[u8]) -> Vec<u8> {
    let name = utf16(name);
    let at = align(24 + name.len());
    let mut a = vec![0; align(at + value.len())];
    let len = a.len();
    p32(&mut a, 0, kind);
    p32(&mut a, 4, len as u32);
    a[9] = (name.len() / 2) as u8;
    p16(&mut a, 10, 24);
    p32(&mut a, 16, value.len() as u32);
    p16(&mut a, 20, at as u16);
    a[22] = u8::from(kind == 0x30); // indexed FILE_NAME attribute
    a[24..24 + name.len()].copy_from_slice(&name);
    a[at..at + value.len()].copy_from_slice(value);
    a
}
fn nonresident(
    kind: u32,
    name: &str,
    lcn: Option<u64>,
    clusters: u64,
    size: u64,
    initialized: u64,
    cluster: u64,
) -> Vec<u8> {
    let name = utf16(name);
    let at = align(64 + name.len());
    let mut runs = Vec::new();
    if clusters != 0 {
        let count = (65 - clusters.leading_zeros()).div_ceil(8) as usize;
        let width = lcn.map(|n| ((65 - n.leading_zeros()).div_ceil(8)) as usize).unwrap_or(0);
        runs.push((width * 16 + count) as u8);
        runs.extend_from_slice(&clusters.to_le_bytes()[..count]);
        if let Some(lcn) = lcn {
            runs.extend_from_slice(&lcn.to_le_bytes()[..width]);
        }
    }
    runs.push(0);
    let mut a = vec![0; align(at + runs.len())];
    let len = a.len();
    p32(&mut a, 0, kind);
    p32(&mut a, 4, len as u32);
    a[8] = 1;
    a[9] = (name.len() / 2) as u8;
    p16(&mut a, 10, 64);
    p64(&mut a, 24, clusters.wrapping_sub(1));
    p16(&mut a, 32, at as u16);
    p64(&mut a, 40, clusters * cluster);
    p64(&mut a, 48, size);
    p64(&mut a, 56, initialized);
    a[64..64 + name.len()].copy_from_slice(&name);
    a[at..at + runs.len()].copy_from_slice(&runs);
    a
}
fn standard(flags: u32, time: u64, security_id: u32) -> Vec<u8> {
    let mut b = vec![0; 72];
    for at in [0, 8, 16, 24] {
        p64(&mut b, at, time);
    }
    p32(&mut b, 32, flags);
    p32(&mut b, 52, security_id);
    b
}
fn filename(name: &str, parent: usize, flags: u32, time: u64, size: u64, allocated: u64) -> Vec<u8> {
    let name = utf16(name);
    let mut b = vec![0; filename_metadata::HEADER_BYTES + name.len()];
    p64(&mut b, filename_metadata::PARENT_REFERENCE_OFFSET, reference(parent));
    for at in [8, 16, 24, 32] {
        p64(&mut b, at, time);
    }
    p64(&mut b, 40, allocated);
    p64(&mut b, 48, size);
    p32(&mut b, 56, flags);
    b[filename_metadata::NAME_LENGTH_OFFSET] = (name.len() / filename_metadata::CODE_UNIT_BYTES) as u8;
    b[filename_metadata::NAMESPACE_OFFSET] = filename_metadata::WIN32_AND_DOS;
    b[filename_metadata::HEADER_BYTES..].copy_from_slice(&name);
    b
}
fn end_entry(child: bool) -> Vec<u8> {
    let mut b = vec![0; if child { 24 } else { 16 }];
    let n = b.len();
    p16(&mut b, 8, n as u16);
    p16(&mut b, 12, if child { 3 } else { 2 });
    b
}
fn directory_entry(reference: u64, name: &[u8]) -> Vec<u8> {
    const INDEX_ENTRY_HEADER_BYTES: usize = 16;
    let mut b = vec![0; align(INDEX_ENTRY_HEADER_BYTES + name.len())];
    let length = ntfs_rs::index_tree::directory_entry(reference, name, &mut b)
        .expect("formatter FILE_NAME values fit their preallocated index entry");
    b.truncate(length);
    b
}
fn index_entry(key: &[u8], data: &[u8]) -> Vec<u8> {
    let at = 16 + key.len();
    let mut b = vec![0; align(at + data.len())];
    let n = b.len();
    p16(&mut b, 0, at as u16);
    p16(&mut b, 2, data.len() as u16);
    p16(&mut b, 8, n as u16);
    p16(&mut b, 10, key.len() as u16);
    b[16..at].copy_from_slice(key);
    b[at..at + data.len()].copy_from_slice(data);
    b
}
fn index_root(kind: u32, collation: u32, entries: &[u8], child: bool, cluster: u64) -> Vec<u8> {
    let mut b = vec![0; 32];
    p32(&mut b, 0, kind);
    p32(&mut b, 4, collation);
    p32(&mut b, 8, 4096);
    b[12] = if cluster <= 4096 { (4096 / cluster) as u8 } else { 8 };
    p32(&mut b, 16, 16);
    b[28] = u8::from(child);
    b.extend_from_slice(entries);
    b.extend_from_slice(&end_entry(child));
    let n = b.len() - 16;
    p32(&mut b, 20, n as u32);
    p32(&mut b, 24, n as u32);
    b
}
fn index_block(entries: &[u8]) -> io::Result<Vec<u8>> {
    let mut b = vec![0; 4096];
    b[..4].copy_from_slice(b"INDX");
    p16(&mut b, 4, 40);
    p16(&mut b, 6, 9);
    let n = 64 + entries.len();
    if n + 16 > 4096 {
        return Err(invalid("root index too large"));
    }
    p32(&mut b, 24, 40);
    p32(&mut b, 28, (n + 16 - 24) as u32);
    p32(&mut b, 32, 4096 - 24);
    b[64..n].copy_from_slice(entries);
    b[n..n + 16].copy_from_slice(&end_entry(false));
    p16(&mut b, 40, 1);
    for i in 0..8 {
        let tail = (i + 1) * 512 - 2;
        let old = [b[tail], b[tail + 1]];
        b[42 + i * 2..44 + i * 2].copy_from_slice(&old);
        p16(&mut b, tail, 1);
    }
    Ok(b)
}
fn record(
    number: usize,
    flags: u16,
    linked: bool,
    mut attrs: Vec<Vec<u8>>,
    record_bytes: usize,
) -> io::Result<Vec<u8>> {
    // Attribute order is by type then case-sensitive UTF-16 attribute name.
    attrs.sort_by_key(|a| {
        let kind = u32::from_le_bytes(a[..4].try_into().unwrap());
        let at = u16::from_le_bytes(a[10..12].try_into().unwrap()) as usize;
        (kind, a[at..at + usize::from(a[9]) * 2].to_vec())
    });
    let mut b = vec![0; record_bytes];
    let first_attribute = align(48 + (record_bytes / 512 + 1) * 2);
    b[..4].copy_from_slice(b"FILE");
    p16(&mut b, 4, 48);
    p16(&mut b, 6, (record_bytes / 512 + 1) as u16);
    p16(&mut b, 16, sequence(number));
    p16(&mut b, 18, u16::from(linked));
    p16(&mut b, 20, first_attribute as u16);
    p16(&mut b, 22, flags);
    p32(&mut b, 28, record_bytes as u32);
    p16(&mut b, 40, attrs.len() as u16);
    p32(&mut b, 44, number as u32);
    let mut at = first_attribute;
    for (id, mut a) in attrs.into_iter().enumerate() {
        p16(&mut a, 14, id as u16);
        if at + a.len() + 8 > record_bytes {
            return Err(invalid("MFT record overflow"));
        }
        b[at..at + a.len()].copy_from_slice(&a);
        at += a.len();
    }
    p32(&mut b, at, u32::MAX);
    p32(&mut b, 24, (at + 8) as u32);
    ntfs_rs::replay::protect_mft_record(&mut b, 512).map_err(|_| invalid("fixup encoding"))?;
    let mut test = b.clone();
    let parsed = MftRecord::parse(&mut test, 512).map_err(|_| invalid("MFT encoding"))?;
    for a in parsed.attributes() {
        a.map_err(|_| invalid("attribute encoding"))?;
    }
    Ok(b)
}
fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
    let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
    for n in subs {
        b.extend_from_slice(&n.to_le_bytes());
    }
    b
}
fn descriptor(inherit: bool) -> Vec<u8> {
    // Administrators and SYSTEM full control; Everyone read/execute.
    let admin = sid(5, &[32, 544]);
    let system = sid(5, &[18]);
    let everyone = sid(1, &[0]);
    let mut b = vec![0; 20];
    b[0] = 1;
    p16(&mut b, 2, 0x8004);
    p32(&mut b, 4, 20);
    b.extend_from_slice(&admin);
    let at = b.len();
    p32(&mut b, 8, at as u32);
    b.extend_from_slice(&system);
    let at = b.len();
    p32(&mut b, 16, at as u32);
    let mut acl = vec![2, 0, 0, 0, 3, 0, 0, 0];
    for (s, mask) in [(admin, 0x1f01ff_u32), (system, 0x1f01ff), (everyone, 0x1200a9)] {
        let mut ace = vec![0; 8];
        ace[1] = if inherit { 3 } else { 0 };
        p16(&mut ace, 2, (8 + s.len()) as u16);
        p32(&mut ace, 4, mask);
        ace.extend_from_slice(&s);
        acl.extend_from_slice(&ace);
    }
    let n = acl.len();
    p16(&mut acl, 2, n as u16);
    b.extend_from_slice(&acl);
    b
}
fn security_store(cluster: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut sds = vec![0; 0x40000];
    let mut at = 0;
    let mut sii = Vec::new();
    let mut hashes = Vec::new();
    for (id, inherit) in [(256_u32, false), (257, true)] {
        let descriptor = descriptor(inherit);
        let hash = ntfs_rs::security::security_hash(&descriptor);
        let mut h = vec![0; 20];
        p32(&mut h, 0, hash);
        p32(&mut h, 4, id);
        p64(&mut h, 8, at as u64);
        p32(&mut h, 16, (20 + descriptor.len()) as u32);
        sds[at..at + 20].copy_from_slice(&h);
        sds[at + 20..at + 20 + descriptor.len()].copy_from_slice(&descriptor);
        at = (at + 20 + descriptor.len() + 15) & !15;
        sii.extend_from_slice(&index_entry(&id.to_le_bytes(), &h));
        let mut key = hash.to_le_bytes().to_vec();
        key.extend_from_slice(&id.to_le_bytes());
        hashes.push((hash, id, index_entry(&key, &h)));
    }
    sds.extend_from_within(..at);
    hashes.sort_by_key(|(h, id, _)| (*h, *id));
    let sdh = hashes.into_iter().flat_map(|(_, _, b)| b).collect::<Vec<_>>();
    (sds, index_root(0, 0x10, &sii, false, cluster), index_root(0, 0x12, &sdh, false, cluster))
}
fn attrdef() -> Vec<u8> {
    use ntfs_rs::mft::attribute_definition;

    let mut bytes = vec![0; attribute_definition::STANDARD_STREAM_BYTES];
    for (index, definition) in attribute_definition::STANDARD.iter().enumerate() {
        let start = index * attribute_definition::ROW_BYTES;
        bytes[start..start + attribute_definition::ROW_BYTES].copy_from_slice(&definition.encode());
    }
    bytes
}

pub struct Plan {
    size: u64,
    sector: u64,
    cluster: u64,
    boot: Vec<u8>,
    writes: Vec<(u64, Vec<u8>)>,
}
impl Plan {
    pub fn summary(&self) -> String {
        format!(
            "dry run: {} bytes, {}-byte sectors, {}-byte clusters, {} metadata extents; no writes performed",
            self.size,
            self.sector,
            self.cluster,
            self.writes.len()
        )
    }
    pub fn new(target_size: u64, options: &super::admin::FormatOptions, device_sector: u32) -> io::Result<Self> {
        let sector = u64::from(if options.sector_size == 0 { device_sector } else { options.sector_size });
        if !(512..=4096).contains(&sector)
            || !sector.is_power_of_two()
            || !(1..=4).contains(&options.mft_zone_multiplier)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let size = if options.sectors == 0 {
            target_size / sector * sector
        } else {
            options.sectors.checked_mul(sector).ok_or_else(|| invalid("volume size overflow"))?
        };
        if size > target_size || size < 1024 * 1024 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut cluster = u64::from(options.cluster_size);
        if cluster == 0 {
            cluster = 4096.max(sector);
            while size / cluster > u32::MAX as u64 && cluster < 2 * 1024 * 1024 {
                cluster *= 2;
            }
        }
        if !cluster.is_power_of_two()
            || cluster < sector
            || cluster > 2 * 1024 * 1024
            || cluster / sector > 4096
            || size / cluster > u32::MAX as u64
            || (options.compression && cluster > 4096)
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let clusters = (size - sector) / cluster;
        let record_bytes = sector.max(1024) as usize;
        let mft_bytes = (64 * record_bytes as u64).max(cluster);
        let mft_clusters = mft_bytes.div_ceil(cluster);
        let mirror_bytes = (4 * record_bytes as u64).max(cluster);
        let mirror_clusters = mirror_bytes.div_ceil(cluster);
        let boot_clusters = 8192_u64.div_ceil(cluster);
        let mft_lcn = boot_clusters.max(16384 / cluster);
        let mft_bitmap_lcn = mft_lcn + mft_clusters;
        let mft_bitmap_size = (mft_bytes / record_bytes as u64).div_ceil(64) * 8;
        let mft_bitmap_clusters = mft_bitmap_size.div_ceil(cluster);
        let bitmap_size = clusters.div_ceil(64) * 8;
        let bitmap_clusters = bitmap_size.div_ceil(cluster);
        let attrdef_clusters = 2560_u64.div_ceil(cluster);
        let upcase_clusters = 131072_u64.div_ceil(cluster);
        let (sds, sii, sdh) = security_store(cluster);
        let secure_clusters = (sds.len() as u64).div_ceil(cluster);
        let index_clusters = 4096_u64.div_ceil(cluster);
        let log_bytes = if size < 2 * 1024 * 1024 {
            256 * 1024
        } else if size < 4000000 {
            512 * 1024
        } else if size <= 200 * 1024 * 1024 {
            2 * 1024 * 1024
        } else {
            (size / 200).min(64 * 1024 * 1024).max(2 * 1024 * 1024)
        };
        let log_clusters = log_bytes.div_ceil(cluster);
        let mirror = clusters.checked_sub(mirror_clusters).ok_or_else(|| invalid("mirror does not fit"))?;
        let needed =
            log_clusters + bitmap_clusters + attrdef_clusters + upcase_clusters + secure_clusters + index_clusters;
        let first_free = mft_bitmap_lcn + mft_bitmap_clusters;
        let zone_end = clusters * u64::from(options.mft_zone_multiplier) / 8;
        let log_lcn = if zone_end.max(first_free) + needed <= mirror { zone_end.max(first_free) } else { first_free };
        let bitmap_lcn = log_lcn + log_clusters;
        let attrdef_lcn = bitmap_lcn + bitmap_clusters;
        let upcase_lcn = attrdef_lcn + attrdef_clusters;
        let secure_lcn = upcase_lcn + upcase_clusters;
        let index_lcn = secure_lcn + secure_clusters;
        if index_lcn + index_clusters > mirror {
            return Err(invalid("metadata does not fit selected volume/cluster size"));
        }
        let nonresident = |kind, name: &str, lcn, count, size, initialized| {
            nonresident(kind, name, lcn, count, size, initialized, cluster)
        };
        let index_root = |kind, collation, entries: &[u8], child| index_root(kind, collation, entries, child, cluster);
        let mut bitmap = vec![0; bitmap_size as usize];
        for (lcn, len) in [
            (0, boot_clusters),
            (mft_lcn, mft_clusters),
            (mft_bitmap_lcn, mft_bitmap_clusters),
            (log_lcn, index_lcn + index_clusters - log_lcn),
            (mirror, mirror_clusters),
            (clusters, bitmap_size * 8 - clusters),
        ] {
            for n in lcn..lcn + len {
                bitmap[n as usize / 8] |= 1 << (n % 8);
            }
        }
        let time = if options.epoch_time {
            116444736000000000
        } else {
            (SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| invalid("clock before Unix epoch"))?.as_nanos()
                / 100
                + 116444736000000000) as u64
        };
        let mut serial = [0; 8];
        File::open("/dev/urandom")?.read_exact(&mut serial)?;
        let mut boot = vec![0; (boot_clusters * cluster) as usize];
        boot[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        boot[3..11].copy_from_slice(b"NTFS    ");
        p16(&mut boot, 11, sector as u16);
        let spc = cluster / sector;
        boot[13] = if spc <= 128 { spc as u8 } else { (256 - spc.ilog2()) as u8 };
        boot[21] = 0xf8;
        p16(&mut boot, 24, options.sectors_per_track);
        p16(&mut boot, 26, options.heads);
        p32(&mut boot, 28, options.partition_start);
        boot[36] = 0x80;
        boot[38] = 0x80;
        p64(&mut boot, 40, size / sector - 1);
        p64(&mut boot, 48, mft_lcn);
        p64(&mut boot, 56, mirror);
        boot[64] = (256 - record_bytes.ilog2()) as u8;
        boot[68] = 244;
        boot[72..80].copy_from_slice(&serial);
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        // No operating-system boot code; halt if firmware attempts legacy boot.
        boot[84..88].copy_from_slice(&[0xfa, 0xf4, 0xeb, 0xfd]);
        let names = [
            "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot", "$BadClus", "$Secure",
            "$UpCase", "$Extend",
        ];
        let mut sizes = [0_u64; 27];
        let mut allocated = [0_u64; 27];
        for (n, size, alloc) in [
            (0, mft_bytes, mft_clusters * cluster),
            (1, mirror_bytes, mirror_clusters * cluster),
            (2, log_clusters * cluster, log_clusters * cluster),
            (4, 2560, attrdef_clusters * cluster),
            (6, bitmap_size, bitmap_clusters * cluster),
            (7, 8192, boot_clusters * cluster),
            (10, 131072, upcase_clusters * cluster),
        ] {
            sizes[n] = size;
            allocated[n] = alloc;
        }
        let root_flags =
            if options.compression { 0x800 } else { 0 } | if options.disable_indexing { 0x2000 } else { 0 };
        let mut filenames = Vec::new();
        let mut root_entries = Vec::new();
        let mut extend_entries = Vec::new();
        for n in 0..27 {
            let name = if n < 12 {
                names[n]
            } else {
                match n {
                    24 => "$Quota",
                    25 => "$ObjId",
                    26 => "$Reparse",
                    _ => "",
                }
            };
            let flags = 6
                | if n == 5 { root_flags } else { 0 }
                | if n == 5 || n == 11 {
                    0x10000000
                } else if n >= 24 {
                    // Match STANDARD_INFORMATION, including FILE_ATTRIBUTE_ARCHIVE.
                    0x20000020
                } else if n == 9 {
                    0x20000000
                } else {
                    0
                };
            let value = filename(name, if n >= 24 { 11 } else { 5 }, flags, time, sizes[n], allocated[n]);
            if !name.is_empty() {
                let entry = directory_entry(reference(n), &value);
                if n >= 24 {
                    extend_entries.push((name.to_ascii_uppercase(), entry));
                } else {
                    root_entries.push((name.to_ascii_uppercase(), entry));
                }
            }
            filenames.push(value);
        }
        root_entries.sort_by(|a, b| a.0.cmp(&b.0));
        extend_entries.sort_by(|a, b| a.0.cmp(&b.0));
        let root_entries = root_entries.into_iter().flat_map(|(_, b)| b).collect::<Vec<_>>();
        let extend_entries = extend_entries.into_iter().flat_map(|(_, b)| b).collect::<Vec<_>>();
        let mut uuid = [0_u8; 16];
        if options.with_uuid {
            File::open("/dev/urandom")?.read_exact(&mut uuid)?;
            uuid[7] = (uuid[7] & 15) | 0x40;
            uuid[8] = (uuid[8] & 63) | 0x80;
        }
        let mut mft = Vec::new();
        let upcase = super::format_tables::upcase();
        for n in 0..(mft_bytes / record_bytes as u64) as usize {
            let used = n < 16 || (24..27).contains(&n);
            let linked = n < 12 || (24..27).contains(&n);
            let directory = n == 5 || n == 11;
            let flags = if directory {
                3
            } else if n == 9 {
                9
            } else if (24..27).contains(&n) {
                13
            } else {
                u16::from(used)
            };
            let mut attrs = Vec::new();
            if used {
                attrs.push(resident(
                    0x10,
                    "",
                    &standard(
                        6 | if n == 5 { root_flags } else { 0 }
                            | if n >= 24 {
                                0x20000020
                            } else if n == 9 {
                                0x20000000
                            } else {
                                0
                            },
                        time,
                        if directory { 257 } else { 256 },
                    ),
                ));
                if linked {
                    attrs.push(resident(0x30, "", &filenames[n]));
                }
            }
            let data = |lcn, count, size| nonresident(0x80, "", Some(lcn), count, size, size);
            match n {
                0 => {
                    attrs.push(data(mft_lcn, mft_clusters, mft_bytes));
                    attrs.push(nonresident(
                        0xb0,
                        "",
                        Some(mft_bitmap_lcn),
                        mft_bitmap_clusters,
                        mft_bitmap_size,
                        mft_bitmap_size,
                    ));
                }
                1 => attrs.push(data(mirror, mirror_clusters, mirror_bytes)),
                2 => attrs.push(data(log_lcn, log_clusters, log_clusters * cluster)),
                3 => {
                    if options.with_uuid {
                        attrs.push(resident(0x40, "", &uuid));
                    }
                    attrs.push(resident(0x60, "", &utf16(&options.label)));
                    let mut info = [0; 12];
                    info[8] = 3;
                    info[9] = 1;
                    attrs.push(resident(0x70, "", &info));
                    attrs.push(resident(0x80, "", &[]));
                }
                4 => attrs.push(data(attrdef_lcn, attrdef_clusters, 2560)),
                5 => {
                    let mut root = resident(0x90, "$I30", &index_root(0x30, 1, &[], true));
                    if options.compression {
                        p16(&mut root, 12, 1);
                    }
                    attrs.push(root);
                    attrs.push(nonresident(0xa0, "$I30", Some(index_lcn), index_clusters, 4096, 4096));
                    attrs.push(resident(0xb0, "$I30", &[1, 0, 0, 0, 0, 0, 0, 0]));
                }
                6 => attrs.push(data(bitmap_lcn, bitmap_clusters, bitmap_size)),
                7 => attrs.push(data(0, boot_clusters, 8192)),
                8 => {
                    attrs.push(resident(0x80, "", &[]));
                    attrs.push(nonresident(0x80, "$Bad", None, clusters, clusters * cluster, 0));
                }
                9 => {
                    attrs.push(nonresident(
                        0x80,
                        "$SDS",
                        Some(secure_lcn),
                        secure_clusters,
                        sds.len() as u64,
                        sds.len() as u64,
                    ));
                    attrs.push(resident(0x90, "$SDH", &sdh));
                    attrs.push(resident(0x90, "$SII", &sii));
                }
                10 => {
                    attrs.push(data(upcase_lcn, upcase_clusters, 131072));
                    attrs.push(resident(0x80, "$Info", &ntfs_rs::upcase::build_information(&upcase)));
                }
                11 => attrs.push(resident(0x90, "$I30", &index_root(0x30, 1, &extend_entries, false))),
                12..=15 => attrs.push(resident(0x80, "", &[])),
                24 => {
                    let mut q = Vec::new();
                    for id in [1_u32, 256] {
                        let mut value = vec![0; 48];
                        p32(&mut value, 0, 2);
                        p32(&mut value, 4, 1);
                        p64(&mut value, 16, time);
                        p64(&mut value, 24, u64::MAX);
                        p64(&mut value, 32, u64::MAX);
                        if id == 256 {
                            value.extend_from_slice(&sid(5, &[32, 544]));
                        }
                        q.extend_from_slice(&index_entry(&id.to_le_bytes(), &value));
                    }
                    let o = index_entry(&sid(5, &[32, 544]), &256_u32.to_le_bytes());
                    attrs.push(resident(0x90, "$O", &index_root(0, 0x11, &o, false)));
                    attrs.push(resident(0x90, "$Q", &index_root(0, 0x10, &q, false)));
                }
                25 => {
                    let mut entries = Vec::new();
                    if options.with_uuid {
                        let mut data = [0; 56];
                        p64(&mut data, 0, reference(3));
                        entries = index_entry(&uuid, &data);
                    }
                    attrs.push(resident(0x90, "$O", &index_root(0, 0x13, &entries, false)));
                }
                26 => attrs.push(resident(0x90, "$R", &index_root(0, 0x13, &[], false))),
                _ => (),
            }
            mft.extend_from_slice(&record(n, flags, linked, attrs, record_bytes)?);
        }
        let mut mft_bitmap = vec![0; mft_bitmap_size as usize];
        mft_bitmap[..4].copy_from_slice(&[255, 255, 0, 7]);
        let writes = vec![
            (mft_bitmap_lcn * cluster, mft_bitmap),
            (mft_lcn * cluster, mft.clone()),
            (mirror * cluster, mft[..mirror_bytes as usize].to_vec()),
            (log_lcn * cluster, vec![255; (log_clusters * cluster) as usize]),
            (bitmap_lcn * cluster, bitmap),
            (attrdef_lcn * cluster, attrdef()),
            (upcase_lcn * cluster, upcase),
            (secure_lcn * cluster, sds),
            (index_lcn * cluster, index_block(&root_entries)?),
        ];
        // Prove every planned extent is disjoint and fits before touching media.
        for (i, (offset, bytes)) in writes.iter().enumerate() {
            let end = offset + (bytes.len() as u64).div_ceil(cluster) * cluster;
            if *offset < 8192
                || end > size - sector
                || writes[..i]
                    .iter()
                    .any(|(p, b)| *offset < p + (b.len() as u64).div_ceil(cluster) * cluster && *p < end)
            {
                return Err(invalid("overlapping metadata plan"));
            }
        }
        Ok(Self { size, sector, cluster, boot, writes })
    }

    /// Failure after the first write may destroy the old filesystem. A format
    /// is not an atomic replacement of a previous volume and has no rollback.
    pub fn apply(&self, file: &File, quick: bool) -> io::Result<()> {
        file.write_all_at(&vec![0; self.sector as usize], 0)?;
        file.write_all_at(&vec![0; self.sector as usize], self.size - self.sector)?;
        file.sync_all()?;
        if !quick {
            let zero = vec![0; 1024 * 1024];
            let mut at = self.sector;
            while at < self.size {
                let n = (self.size - at).min(zero.len() as u64) as usize;
                file.write_all_at(&zero[..n], at)?;
                at += n as u64;
            }
        }
        for (at, bytes) in &self.writes {
            let mut padded = bytes.clone();
            padded.resize((bytes.len() as u64).div_ceil(self.cluster) as usize * self.cluster as usize, 0);
            file.write_all_at(&padded, *at)?;
        }
        file.write_all_at(&self.boot[self.sector as usize..], self.sector)?;
        file.sync_all()?;
        // Exact readback of all metadata, then boot publication. A separate
        // filesystem probe is performed by the administration layer as well.
        for (at, bytes) in &self.writes {
            let mut actual = vec![0; bytes.len()];
            file.read_exact_at(&mut actual, *at)?;
            if actual != *bytes {
                return Err(invalid("metadata readback mismatch"));
            }
        }
        file.write_all_at(&self.boot[..self.sector as usize], self.size - self.sector)?;
        file.sync_all()?;
        file.write_all_at(&self.boot[..self.sector as usize], 0)?;
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_entry_matches_original_golden_bytes() {
        const REFERENCE: u64 = 0x1234_5678_9abc_def0;
        // Fixed filename and padded entry bytes from the original encoder.
        const FILE_NAME: [u8; 68] = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0x01, 0xa7, 0x41, 0x00,
        ];
        const GOLDEN_ENTRY: [u8; 88] = [
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x58, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x32,
            0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0x01, 0xa7, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(directory_entry(REFERENCE, &FILE_NAME), GOLDEN_ENTRY);
    }

    #[test]
    fn directory_entry_retains_empty_and_maximal_raw_names() {
        const REFERENCE: u64 = 0x1234_5678_9abc_def0;
        const ENTRY_HEADER_BYTES: usize = 16;
        const EMPTY_ENTRY_BYTES: usize = 88;
        const EMPTY_ENTRY_HEADER: [u8; ENTRY_HEADER_BYTES] =
            [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x58, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00];
        const MAXIMAL_ENTRY_HEADER: [u8; ENTRY_HEADER_BYTES] =
            [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x50, 0x02, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00];
        let mut value = vec![0; filename_metadata::HEADER_BYTES];
        let actual = directory_entry(REFERENCE, &value);
        let mut expected = vec![0; EMPTY_ENTRY_BYTES];
        expected[..ENTRY_HEADER_BYTES].copy_from_slice(&EMPTY_ENTRY_HEADER);
        assert_eq!(actual, expected);

        value.resize(filename_metadata::MAX_VALUE_BYTES, 0xff);
        value[filename_metadata::NAME_LENGTH_OFFSET] = u8::MAX;
        let actual = directory_entry(REFERENCE, &value);
        let mut expected = MAXIMAL_ENTRY_HEADER.to_vec();
        expected.extend_from_slice(&value);
        assert_eq!(actual, expected);
    }
}

#[cfg(test)]
#[path = "../tests/unit/format_attribute_definitions.rs"]
mod attribute_definition_tests;
