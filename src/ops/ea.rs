//! Module: ntfs_rs::ea
//! Purpose: Read and journal native NTFS EA and EA_INFORMATION streams.
//! Created: 2026-10-01
//! Architecture: Linux xattrs retain their complete names; internal LX entries are ordinary
//! EAs. Operations rebuild caller scratch while preserving unrelated entries,
//! flags and values. Large streams are staged in new clusters before one Tx
//! publication, so live EA storage is never overwritten in place.

use super::bytes::{u16_at, u32_at, u64_at};
use super::mft::{reference_number, reference_sequence};
use super::mft::{Attribute, MftRecord};
use super::record_edit::{self, p16, p32};
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::runlist::Extent;
use super::tx::{Tx, BLOCK};
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

pub const EA: u32 = 0xe0;
pub const EA_INFO: u32 = 0xd0;
/// Largest EA stream this engine reads or writes. NTFS limits the packed
/// size to 64 KiB; the unpacked stream adds per-entry alignment.
pub const MAX_STREAM: usize = 0x10000 + 0x4000;
/// Largest value accepted for one entry (Linux XATTR_SIZE_MAX is larger;
/// NTFS entry value lengths are 16-bit).
pub const MAX_VALUE: usize = 0xffff;
pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;
/// Removal of an absent entry is a successful no-op (POSIX ACL removal).
pub const IGNORE_MISSING: u32 = 4;
const NEED_EA: u8 = 0x80;

/// Visit a complete EA chain, validating every entry, including entries
/// following a match. The callback receives (name, value, flags).
pub fn visit<'a>(data: &'a [u8], mut f: impl FnMut(&'a [u8], &'a [u8], u8) -> Result<()>) -> Result<()> {
    let mut at = 0;
    while at < data.len() {
        let head = data.get(at..at + 8).ok_or(Error::InvalidAttribute)?;
        let next = u32_at(head, 0)? as usize;
        let name_len = head[5] as usize;
        let value_len = u16_at(head, 6)? as usize;
        let size = 9 + name_len + value_len;
        let stride = if next == 0 { (size + 3) & !3 } else { next };
        if name_len == 0
            || stride < size
            || stride % 4 != 0
            || at + size > data.len()
            || head[4] & !NEED_EA != 0
            || data[at + 8 + name_len] != 0
        {
            return Err(Error::InvalidAttribute);
        }
        f(&data[at + 8..at + 8 + name_len], &data[at + 9 + name_len..at + size], head[4])?;
        if next == 0 {
            // A zero offset terminates the chain; trailing bytes are padding.
            if data[at + size..].iter().any(|b| *b != 0) {
                return Err(Error::InvalidAttribute);
            }
            return Ok(());
        }
        if at + stride > data.len() {
            return Err(Error::InvalidAttribute);
        }
        at += stride;
    }
    Ok(())
}

/// Locate the single $EA attribute of a base record, refusing duplicates.
pub fn attribute<'a>(record: &MftRecord<'a>) -> Result<Option<Attribute<'a>>> {
    let mut found = None;
    for a in record.attributes() {
        let a = a?;
        if a.kind == EA && found.replace(a).is_some() {
            return Err(Error::InvalidAttribute);
        }
    }
    Ok(found)
}

/// Copy the complete EA stream of record into out, resident or not.
/// Returns its length (zero when the file has no EAs).
pub fn read_stream<R: ReadAt>(volume: &mut Volume<R>, record: &MftRecord<'_>, out: &mut [u8]) -> Result<usize> {
    let Some(attr) = attribute(record)? else {
        return Ok(0);
    };
    if attr.nonresident && attr.flags()? != 0 {
        return Err(Error::Unsupported);
    }
    let size = usize::try_from(attr.data_size()?).map_err(|_| Error::Overflow)?;
    if size > MAX_STREAM || size > out.len() {
        return Err(Error::Unsupported);
    }
    volume.read_attribute(attr, 0, &mut out[..size])?;
    visit(&out[..size], |_, _, _| Ok(()))?;
    Ok(size)
}

/// Find one entry by exact name.
pub fn find<'a>(stream: &'a [u8], name: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut found = None;
    visit(stream, |n, v, _| {
        if n == name && found.replace(v).is_some() {
            return Err(Error::InvalidAttribute);
        }
        Ok(())
    })?;
    Ok(found)
}

/// Write NUL-terminated entry names into out; returns the byte length.
/// When out is empty, only the required size is computed.
pub fn list(stream: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    visit(stream, |name, _, _| {
        let end = n + name.len() + 1;
        if !out.is_empty() {
            let dest = out.get_mut(n..end).ok_or(Error::NoSpace)?;
            dest[..name.len()].copy_from_slice(name);
            dest[name.len()] = 0;
        }
        n = end;
        Ok(())
    })?;
    Ok(n)
}

/// Incremental builder of a packed EA stream and its $EA_INFORMATION.
pub struct Builder<'a> {
    out: &'a mut [u8],
    used: usize,
    packed: u32,
    needed: u16,
}

impl<'a> Builder<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, used: 0, packed: 0, needed: 0 }
    }
    pub fn push(&mut self, name: &[u8], value: &[u8], flags: u8) -> Result<()> {
        if name.is_empty() || name.len() > 255 || name.contains(&0) || value.len() > MAX_VALUE {
            return Err(Error::Unsupported);
        }
        if flags & !NEED_EA != 0 {
            return Err(Error::InvalidAttribute);
        }
        let size = 9 + name.len() + value.len();
        let stride = (size + 3) & !3;
        if self.used + stride > MAX_STREAM {
            return Err(Error::NoSpace);
        }
        let dest = self.out.get_mut(self.used..self.used + stride).ok_or(Error::NoSpace)?;
        dest.fill(0);
        p32(dest, 0, stride as u32)?;
        dest[4] = flags;
        dest[5] = name.len() as u8;
        p16(dest, 6, value.len() as u16)?;
        dest[8..8 + name.len()].copy_from_slice(name);
        dest[9 + name.len()..size].copy_from_slice(value);
        self.packed += (size - 4) as u32;
        if self.packed > 0xffff {
            return Err(Error::NoSpace);
        }
        self.needed += u16::from(flags & NEED_EA != 0);
        self.used += stride;
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.used
    }
    pub fn info(&self) -> [u8; 8] {
        let mut info = [0u8; 8];
        info[..2].copy_from_slice(&(self.packed as u16).to_le_bytes());
        info[2..4].copy_from_slice(&self.needed.to_le_bytes());
        info[4..8].copy_from_slice(&(self.used as u32).to_le_bytes());
        info
    }
    pub fn bytes(&self) -> &[u8] {
        &self.out[..self.used]
    }
}

/// One requested change to a named entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Edit<'e> {
    pub name: &'e [u8],
    /// None removes the entry.
    pub value: Option<&'e [u8]>,
    /// XATTR_CREATE / XATTR_REPLACE semantics; 0 means upsert.
    pub flags: u32,
}

/// Rebuild old into builder, applying edits in order. Unrelated
/// entries keep their order, flags and bytes. New entries are appended.
pub fn apply(old: &[u8], edits: &[Edit<'_>], builder: &mut Builder<'_>) -> Result<()> {
    let mut present = [false; 4];
    if edits.len() > present.len() {
        return Err(Error::Unsupported);
    }
    visit(old, |name, _, _| {
        for (i, edit) in edits.iter().enumerate() {
            if edit.name == name {
                if present[i] {
                    return Err(Error::InvalidAttribute);
                }
                present[i] = true;
            }
        }
        Ok(())
    })?;
    for (i, edit) in edits.iter().enumerate() {
        if edit.flags & XATTR_CREATE != 0 && present[i] {
            return Err(Error::Exists);
        }
        let removal = edit.value.is_none() && edit.flags & IGNORE_MISSING == 0;
        if (edit.flags & XATTR_REPLACE != 0 || removal) && !present[i] {
            return Err(Error::NotFound);
        }
    }
    let mut result = Ok(());
    visit(old, |name, value, flags| {
        match edits.iter().find(|e| e.name == name) {
            Some(edit) => {
                if let Some(value) = edit.value {
                    // Keep the entry's native flags when replacing its value.
                    if let Err(e) = builder.push(name, value, flags) {
                        result = Err(e);
                    }
                }
            }
            None => {
                if let Err(e) = builder.push(name, value, flags) {
                    result = Err(e);
                }
            }
        }
        Ok(())
    })?;
    result?;
    for (i, edit) in edits.iter().enumerate() {
        if !present[i] {
            if let Some(value) = edit.value {
                builder.push(edit.name, value, 0)?;
            }
        }
    }
    Ok(())
}

/// Scratch consumed by Writer::edit_eas beyond the shared transaction.
const EA_WORK: usize = 2 * MAX_STREAM + 3 * BLOCK + 64 * 1024;

impl Writer {
    /// Resolve a numbered base record under the frozen-volume writer lock.
    /// The sequence is read from the current MFT rather than supplied by a
    /// possibly stale userspace scan.
    pub fn repair_ea_summary_number<I: WriteIo>(
        &mut self,
        io: &mut I,
        number: u64,
        scratch: &mut [u8],
    ) -> Result<bool> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if (number != 5 && number < 24) || number >= 0x0001_0000_0000_0000 {
            return Err(Error::Unsupported);
        }
        let bytes = self.boot.record_bytes as usize;
        if scratch.len() < METADATA_SCRATCH_BYTES || bytes.checked_mul(2).is_none_or(|n| n > scratch.len()) {
            return Err(Error::Truncated);
        }
        let reference = {
            let mut volume = Volume::new(&mut *io, self.boot)?;
            let (zero, rest) = scratch.split_at_mut(super::volume::mft_space_bytes(bytes));
            let (raw, _) = rest.split_at_mut(bytes);
            let mft = volume.load_mft(zero)?;
            volume.read_mft_record(&mft, number, raw)?;
            let record = MftRecord::parse(raw, self.boot.bytes_per_sector)?;
            if record.flags()? & 1 == 0 || record.base_file_reference()? != 0 {
                return Err(Error::InvalidRecord);
            }
            number | (u64::from(record.sequence_number()?) << 48)
        };
        self.repair_ea_summary(io, reference, scratch)
    }

    /// Recompute only the derived EA summary from the current validated EA
    /// stream. Caller holds the inode and writer locks. No user-supplied disk
    /// image is accepted, and EA values (including security labels) stay intact.
    pub fn repair_ea_summary<I: WriteIo>(&mut self, io: &mut I, reference: u64, scratch: &mut [u8]) -> Result<bool> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let number = reference_number(reference);
        if (number != 5 && number < 24) || reference_sequence(reference) == 0 {
            return Err(Error::Unsupported);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        if rest.len() < 64 * 1024 + 2 * MAX_STREAM {
            return Err(Error::Truncated);
        }
        let (journal, rest) = rest.split_at_mut(64 * 1024);
        let (old, rest) = rest.split_at_mut(MAX_STREAM);
        let file = tx.load_record(&mut volume, reference)?;
        let record = MftRecord::from_decoded(tx.record(file))?;
        if record.base_file_reference()? != 0
            || u64_at(tx.record(file), 8)? > self.current_lsn
            || record.local_attribute(super::mft::ATTR_ATTRIBUTE_LIST, &[])?.is_some()
        {
            return Err(Error::Unsupported);
        }
        let info = record.local_attribute(EA_INFO, &[])?;
        if attribute(&record)?.is_none() {
            let Some(at) = info.map(|attr| attr.record_offset()) else {
                return Ok(false);
            };
            // With no attribute list or EA stream, EA_INFO is only a stale
            // derived summary. Removing it does not discard EA values.
            record_edit::remove(tx.record_mut(file), at)?;
            record_edit::validate(tx.record(file))?;
            drop(volume);
            tx.commit(self, io, journal)?;
            self.drain(io, scratch)?;
            return Ok(true);
        }
        let length = read_stream(&mut volume, &record, old)?;
        let mut builder = Builder::new(&mut rest[..MAX_STREAM]);
        visit(&old[..length], |name, value, flags| {
            if find(builder.bytes(), name)?.is_some() {
                return Err(Error::InvalidAttribute);
            }
            builder.push(name, value, flags)
        })?;
        if builder.len() != length {
            return Err(Error::Unsupported);
        }
        let expected = builder.info();
        let at = match info {
            Some(info) => {
                let value = info.resident_value()?;
                if value == expected {
                    return Ok(false);
                }
                if value.len() != 8 {
                    return Err(Error::Unsupported);
                }
                Some(info.record_offset())
            }
            None => None,
        };
        if let Some(at) = at {
            record_edit::set_resident_value(tx.record_mut(file), at, &expected)?;
        } else {
            let mut image = [0; 32];
            let n = record_edit::build_resident(EA_INFO, &[], &expected, &mut image)?;
            record_edit::insert(tx.record_mut(file), &image[..n])?;
        }
        // This repair must not allocate extension records or change mappings.
        if u32_at(tx.record(file), 24)? as usize > tx.record_bytes() {
            return Err(Error::NoSpace);
        }
        record_edit::validate(tx.record(file))?;
        drop(volume);
        tx.commit(self, io, journal)?;
        self.drain(io, scratch)?;
        Ok(true)
    }

    /// Apply EA edits to one base record in a single journaled transaction.
    /// mode optionally replaces $LXMOD (Linux type bits added here) in the
    /// same transaction, so POSIX ACL/mode pairs change atomically.
    pub fn edit_eas<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        edits: &[Edit<'_>],
        mode: Option<u32>,
        scratch: &mut [u8],
    ) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        if rest.len() < EA_WORK {
            return Err(Error::Truncated);
        }
        let (journal, rest) = rest.split_at_mut(64 * 1024);
        let (old, rest) = rest.split_at_mut(MAX_STREAM);
        let (new, rest) = rest.split_at_mut(MAX_STREAM + BLOCK);
        let (work, _) = rest.split_at_mut(2 * BLOCK);
        let file = tx.load_family(&mut volume, reference)?;
        let number = reference_number(reference);
        if (number != 5 && number < 24)
            || reference_sequence(reference) == 0
            || MftRecord::from_decoded(tx.record(file))?.base_file_reference()? != 0
            || u64_at(tx.record(file), 8)? > self.current_lsn
        {
            return Err(Error::Unsupported);
        }
        let old_len = {
            let record = MftRecord::from_decoded(tx.record_before(file))?;
            read_stream(&mut volume, &record, old)?
        };
        let directory = MftRecord::from_decoded(tx.record(file))?.flags()? & 2 != 0;
        let mode_bytes;
        let mut list = [Edit { name: &[], value: None, flags: 0 }; 4];
        let mut count = 0;
        for edit in edits {
            if count == 3 {
                return Err(Error::Unsupported);
            }
            list[count] = *edit;
            count += 1;
        }
        if let Some(mode) = mode {
            if mode & !0o7777 != 0 {
                return Err(Error::Unsupported);
            }
            let kind = super::unix_metadata::mode_in(&old[..old_len], directory)?
                .map(|m| m & 0o170000)
                .unwrap_or(if directory { 0o040000 } else { 0o100000 });
            mode_bytes = (kind | mode).to_le_bytes();
            list[count] = Edit { name: super::unix_metadata::MODE, value: Some(&mode_bytes), flags: 0 };
            count += 1;
        }
        let mut builder = Builder::new(&mut new[..MAX_STREAM]);
        apply(&old[..old_len], &list[..count], &mut builder)?;
        let info = builder.info();
        let length = builder.len();
        store(&mut tx, &mut volume, self, file, &new[..length], &info, work)?;
        drop(volume);
        tx.commit(self, io, journal)
    }
}

/// Replace the $EA/$EA_INFORMATION pair of file with stream.
pub(crate) fn store<R: WriteIo>(
    tx: &mut Tx<'_>,
    volume: &mut Volume<&mut R>,
    writer: &mut Writer,
    file: usize,
    stream: &[u8],
    info: &[u8; 8],
    work: &mut [u8],
) -> Result<()> {
    if work.len() < 2 * BLOCK {
        return Err(Error::Truncated);
    }
    // Release a previous nonresident stream; its clusters are freed only by
    // this transaction's bitmap commit, after the new mapping is durable.
    if let Some(at) = record_edit::find(tx.record(file), EA, &[])? {
        if record_edit::is_nonresident(tx.record(file), at)? {
            tx.free_attribute_runs(volume, file, at)?;
        }
        record_edit::remove(tx.record_mut(file), at)?;
    }
    if let Some(at) = record_edit::find(tx.record(file), EA_INFO, &[])? {
        record_edit::remove(tx.record_mut(file), at)?;
    }
    if stream.is_empty() {
        return record_edit::validate(tx.record(file));
    }
    let mut image = [0u8; 1024];
    let n = record_edit::build_resident(EA_INFO, &[], info, &mut image)?;
    insert_attribute(tx, volume, file, &image[..n])?;
    if stream.len() <= 1024 - 24 {
        let n = record_edit::build_resident(EA, &[], stream, &mut image)?;
        match insert_attribute(tx, volume, file, &image[..n]) {
            Ok(()) => return record_edit::validate(tx.record(file)),
            Err(Error::NoSpace) => {}
            Err(e) => return Err(e),
        }
    }
    // Nonresident: stage the whole stream in fresh clusters before the
    // transaction publishes a mapping that references them.
    let cluster = tx.cluster_bytes();
    let clusters = (stream.len() as u64).div_ceil(cluster);
    let lcn = tx.allocate_clusters(volume, clusters, None)?;
    let physical = lcn.checked_mul(cluster).ok_or(Error::Overflow)?;
    super::tx::stage_bytes(writer, &mut **volume.reader_mut(), physical, stream, &mut work[..BLOCK])?;
    let runs = [Extent { vcn: 0, len: clusters, lcn: Some(lcn) }];
    let mut attr = [0u8; 160];
    let n = record_edit::build_nonresident(
        EA,
        &[],
        &runs,
        clusters * cluster,
        stream.len() as u64,
        stream.len() as u64,
        &mut attr,
    )?;
    insert_attribute(tx, volume, file, &attr[..n])?;
    record_edit::validate(tx.record(file))
}

/// A selective family can move a new marker into a metadata extension without
/// repacking its unchanged DATA mapping pairs.
fn insert_attribute<R: ReadAt>(tx: &mut Tx<'_>, volume: &mut Volume<R>, file: usize, image: &[u8]) -> Result<()> {
    if tx.preserved_family(file) {
        tx.insert_family_attribute(volume, file, image)
    } else {
        record_edit::insert(tx.record_mut(file), image).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_preserve_unrelated_entries_and_check_flags() {
        let mut first = [0u8; 256];
        let mut b = Builder::new(&mut first);
        b.push(b"$LXMOD", &0o100644u32.to_le_bytes(), 0).unwrap();
        b.push(b"WINDOWS", b"keep", NEED_EA).unwrap();
        let len = b.len();
        let old = first;
        let mut second = [0u8; 512];
        let mut b = Builder::new(&mut second);
        apply(&old[..len], &[Edit { name: b"user.a", value: Some(b"1"), flags: XATTR_CREATE }], &mut b).unwrap();
        let stream = b.bytes();
        assert_eq!(find(stream, b"WINDOWS").unwrap(), Some(&b"keep"[..]));
        assert_eq!(find(stream, b"user.a").unwrap(), Some(&b"1"[..]));
        assert_eq!(b.info()[2], 1);
        let mut names = [0u8; 64];
        let n = list(stream, &mut names).unwrap();
        assert_eq!(&names[..n], b"$LXMOD\0WINDOWS\0user.a\0");
        let copy = [0u8; 512];
        let mut copy = copy;
        copy[..stream.len()].copy_from_slice(stream);
        let size = stream.len();
        let mut third = [0u8; 512];
        let mut b = Builder::new(&mut third);
        assert_eq!(
            apply(&copy[..size], &[Edit { name: b"user.a", value: Some(b"2"), flags: XATTR_CREATE }], &mut b,),
            Err(Error::Exists)
        );
        let mut b = Builder::new(&mut third);
        assert_eq!(
            apply(&copy[..size], &[Edit { name: b"user.b", value: None, flags: 0 }], &mut b,),
            Err(Error::NotFound)
        );
        let mut b = Builder::new(&mut third);
        apply(&copy[..size], &[Edit { name: b"user.a", value: None, flags: 0 }], &mut b).unwrap();
        assert_eq!(find(b.bytes(), b"user.a").unwrap(), None);
        assert_eq!(find(b.bytes(), b"WINDOWS").unwrap(), Some(&b"keep"[..]));
    }

    #[test]
    fn malformed_chains_are_refused() {
        let mut data = [0u8; 32];
        let mut b = Builder::new(&mut data);
        b.push(b"x", b"y", 0).unwrap();
        let n = b.len();
        let mut broken = data;
        broken[0] = 3;
        assert!(visit(&broken[..n], |_, _, _| Ok(())).is_err());
        let mut broken = data;
        broken[4] = 1;
        assert!(visit(&broken[..n], |_, _, _| Ok(())).is_err());
    }
}
