//! Module: ntfs_rs::file_lifecycle
//! Purpose: Create namespace objects and reclaim marked orphan allocations.
//! Created: 2026-10-01
//! Architecture: Namespace operations atomically edit names, links and allocations through
//! Tx. Last-name removal marks open files with SLATE_ORPHAN and retains their
//! storage until bounded final-close or writable-mount reclamation.
//! Unmarked nameless records are never reclaimed as our orphans.

use super::allocation::{SectorBudget, BITMAP_PATCHES, CLUSTERS_PER_BITMAP_SECTOR};
use super::bytes::{self, u16_at, u64_at};
use super::ea::{self, Builder, Edit};
use super::index_tree::{directory_entry, reparse_entry, IndexKind, Tree, T_NEW};
use super::mft::{attribute_layout as af, MftRecord};
use super::mft::{reference_number, reference_sequence};
use super::namespace_writer::{existing_name, policy_name};
use super::record_edit;
use super::reparse;
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::std_info;
use super::tx::{Tx, BLOCK};
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

pub const ORPHAN: &[u8] = b"$SLATE_ORPHAN";
const FILE_NAME: u32 = 0x30;
const DATA: u32 = 0x80;
const INDEX_ROOT: u32 = 0x90;
use super::std_info::DUP_INDEX_PRESENT;
/// Scratch after Tx for journal, EA rebuild and index visits.
const WORK: usize = 64 * 1024 + 2 * ea::MAX_STREAM + 64 * 1024;
const RECORD_SEQUENCE_OFFSET: usize = 16;
const RECORD_CAPACITY_OFFSET: usize = 28;

fn p16(b: &mut [u8], a: usize, v: u16) {
    bytes::p16(b, a, v).expect("preallocated lifecycle image contains the integer field");
}
fn p32(b: &mut [u8], a: usize, v: u32) {
    bytes::p32(b, a, v).expect("preallocated lifecycle image contains the integer field");
}
fn p64(b: &mut [u8], a: usize, v: u64) {
    bytes::p64(b, a, v).expect("preallocated lifecycle image contains the integer field");
}
fn empty_record(b: &mut [u8], record_bytes: usize, number: u64, sequence: u16) -> Result<()> {
    if b.len() < record_bytes {
        return Err(Error::InvalidRecord);
    }
    let capacity = u32::try_from(b.len()).map_err(|_| Error::Overflow)?;
    b.fill(0);
    // USA geometry belongs to the physical record; the assembled family has
    // additional editing capacity that must not move the first attribute.
    record_edit::format_empty(&mut b[..record_bytes], number)?;
    bytes::p32(b, RECORD_CAPACITY_OFFSET, capacity)?;
    bytes::p16(b, RECORD_SEQUENCE_OFFSET, sequence.max(1))
}
fn insert_resident(rec: &mut [u8], kind: u32, name: &[u8], value: &[u8]) -> Result<()> {
    let mut image = [0u8; 1024];
    let n = record_edit::build_resident(kind, name, value, &mut image)?;
    record_edit::insert(rec, &image[..n])?;
    Ok(())
}

/// What a new namespace object is.
#[derive(Clone, Copy)]
pub enum NodeKind<'a> {
    File,
    /// Nameless file created already marked for orphan reclamation.
    Temporary,
    Directory,
    /// A symbolic link whose reparse buffer is built from this Linux target.
    Symlink(&'a [u8]),
    /// Linux special file: full mode (type and permission bits), then the
    /// device major and minor numbers. Stored as WSL metadata EAs: $LXMOD
    /// and, for character and block devices, the 8-byte $LXDEV.
    Special(u32, u32, u32),
}

/// Result of removing one name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Removal {
    /// Other names remain; the file is unchanged otherwise.
    Unlinked,
    /// The last name was removed and the record and clusters were freed.
    Freed,
    /// The last name was removed; the record is a marked orphan awaiting
    /// reclaim_orphan (open file, preserved family, or clusters too many for
    /// one transaction).
    Orphaned,
}

/// Find $Extend\$Reparse by exact name through a read-only index walk.
fn reparse_index_reference<R: ReadAt>(volume: &mut Volume<R>, mft_zero: &[u8], work: &mut [u8]) -> Result<u64> {
    let (raw, rest) = work.split_at_mut(volume.boot.record_bytes as usize);
    let block = &mut rest[..];
    let mft = MftRecord::from_decoded(mft_zero)?;
    volume.read_mft_record(&mft, 11, raw)?;
    let extend = MftRecord::parse(raw, 512)?;
    if extend.flags()? & 3 != 3 {
        return Err(Error::Unsupported);
    }
    let wanted = "$Reparse".encode_utf16();
    let mut found = None;
    volume.visit_directory(&extend, block, |entry| {
        if entry.name.code_units().eq(wanted.clone()) && found.replace(entry.file_reference).is_some() {
            return Err(Error::InvalidIndex);
        }
        Ok(())
    })?;
    found.ok_or(Error::Unsupported)
}

/// Insert or delete one $Reparse:$R key in the pending transaction.
fn edit_reparse_index<R: ReadAt>(
    tx: &mut Tx<'_>,
    volume: &mut Volume<R>,
    tag: u32,
    reference: u64,
    insert: bool,
    work: &mut [u8],
    current_lsn: u64,
) -> Result<()> {
    let index = reparse_index_reference(volume, tx.mft_zero(), work)?;
    let slot = tx.load_family(volume, index)?;
    if u64_at(tx.record(slot), 8)? > current_lsn {
        return Err(Error::Unsupported);
    }
    let tree = tx.open_tree(slot, IndexKind::Reparse)?;
    reparse_entry(tag, reference, tx.temp_mut(T_NEW))?;
    if insert {
        tx.tree_insert(volume, &tree, T_NEW)?;
    } else if tx.tree_lookup(volume, &tree, T_NEW)? {
        reparse_entry(tag, reference, tx.temp_mut(T_NEW))?;
        tx.tree_delete(volume, &tree, T_NEW)?;
    }
    // A missing key on deletion is tolerated: chkdsk rebuilds $R entries,
    // and refusing would leave the file impossible to delete.
    tx.tree_check(&tree)
}

/// Count visible entries of a directory image through the read-only walker.
fn directory_is_empty<R: ReadAt>(volume: &mut Volume<R>, record: &[u8], work: &mut [u8]) -> Result<bool> {
    let record = MftRecord::from_decoded(record)?;
    let mut empty = true;
    volume.visit_directory(&record, &mut work[..BLOCK], |_| {
        empty = false;
        Ok(())
    })?;
    Ok(empty)
}

impl Writer {
    /// VFS holds parent/victim locks and refuses deletion with live handles.
    /// MFT capacity is a separate, durable reservation. A failed create may
    /// leave additional free records, but never a half-created namespace entry.
    pub fn file_lifecycle<I: WriteIo>(
        &mut self,
        io: &mut I,
        parent: u64,
        name: &(impl AsRef<[u8]> + ?Sized),
        remove: Option<u64>,
        descriptor: &[u8],
        timestamp: u64,
        scratch: &mut [u8],
    ) -> Result<u64> {
        let name = name.as_ref();
        self.file_lifecycle_mode(io, parent, name, remove, descriptor, timestamp, None, scratch)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn file_lifecycle_mode<I: WriteIo>(
        &mut self,
        io: &mut I,
        parent: u64,
        name: &(impl AsRef<[u8]> + ?Sized),
        remove: Option<u64>,
        descriptor: &[u8],
        timestamp: u64,
        mode: Option<u32>,
        scratch: &mut [u8],
    ) -> Result<u64> {
        let name = name.as_ref();
        match remove {
            Some(reference) => {
                self.remove_node(io, parent, name, reference, false, scratch)?;
                Ok(reference)
            }
            None => self.create_node(io, parent, name, NodeKind::File, descriptor, timestamp, mode, &[], scratch),
        }
    }

    /// Create one regular file, directory or symbolic link in parent,
    /// including its $Reparse index key, Linux mode and initial EAs (for
    /// example inherited POSIX ACLs), in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn create_node<I: WriteIo>(
        &mut self,
        io: &mut I,
        parent: u64,
        name: &(impl AsRef<[u8]> + ?Sized),
        kind: NodeKind<'_>,
        descriptor: &[u8],
        timestamp: u64,
        mode: Option<u32>,
        eas: &[Edit<'_>],
        scratch: &mut [u8],
    ) -> Result<u64> {
        let name = name.as_ref();
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        self.ensure_free_records(io, super::tx::MAX_RECORDS as u64, scratch)?;
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, work) = rest.split_at_mut(64 * 1024);
        let reference =
            self.create_in_tx(&mut tx, &mut volume, parent, name, kind, descriptor, timestamp, mode, eas, work)?;
        drop(volume);
        tx.commit(self, io, journal)?;
        Ok(reference)
    }

    /// Shared by ordinary creation and atomic rename-with-whiteout.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_in_tx<I: WriteIo>(
        &mut self,
        tx: &mut Tx<'_>,
        volume: &mut Volume<&mut I>,
        parent: u64,
        name: &[u8],
        kind: NodeKind<'_>,
        descriptor: &[u8],
        timestamp: u64,
        mode: Option<u32>,
        eas: &[Edit<'_>],
        rest: &mut [u8],
    ) -> Result<u64> {
        let current_lsn = self.current_lsn;
        let linux = self.linux_compatibility;
        let mut utf = [0u8; 510];
        let temporary = matches!(kind, NodeKind::Temporary);
        let name_len = if temporary { 0 } else { policy_name(name, &mut utf, self.linux_compatibility)? };
        super::security::SecurityDescriptor::parse(descriptor)?;
        if let NodeKind::Symlink(target) = kind {
            if target.is_empty() || target.len() > reparse::MAX_TARGET {
                return Err(Error::Unsupported);
            }
        }
        let (fname, rest) = rest.split_at_mut(576);
        let (link_buffer, rest) = rest.split_at_mut(reparse::MAX_CREATE);
        let (work, rest) = rest.split_at_mut(64 * 1024);
        let (stream, _) = rest.split_at_mut(ea::MAX_STREAM);
        let link = match kind {
            NodeKind::Symlink(target) => {
                let (n, tag) = reparse::build(target, link_buffer)?;
                Some((tag, &link_buffer[..n]))
            }
            _ => None,
        };
        let dir = tx.load_family(volume, parent)?;
        if u16_at(tx.record(dir), 22)? != 3 || reference_sequence(parent) == 0 {
            return Err(Error::InvalidRecord);
        }
        tx.load_upcase(volume)?;
        let tree = tx.open_tree(dir, IndexKind::Directory)?;
        let (record_flags, attributes) = match kind {
            NodeKind::File | NodeKind::Temporary | NodeKind::Special(..) => (1u16, std_info::ARCHIVE),
            NodeKind::Directory => (3u16, 0),
            NodeKind::Symlink(_) => (1u16, std_info::ARCHIVE | std_info::REPARSE_POINT),
        };
        fname.fill(0);
        p64(fname, 0, parent);
        for at in [8, 16, 24, 32] {
            p64(fname, at, timestamp);
        }
        p32(fname, 56, if record_flags == 3 { DUP_INDEX_PRESENT } else { attributes });
        if let Some((tag, _)) = link {
            p32(fname, 60, tag);
        }
        fname[64] = (name_len / 2) as u8;
        // Encode a name without a generated DOS partner as standalone POSIX.
        // Native naming and case-folding policy is enforced independently.
        fname[65] = 0;
        fname[66..66 + name_len].copy_from_slice(&utf[..name_len]);
        let fname_len = 66 + name_len;
        directory_entry(0, &fname[..fname_len], tx.temp_mut(T_NEW))?;
        if !temporary && tx.tree_name_taken(volume, &tree, T_NEW)? {
            return Err(Error::Exists);
        }
        let file = tx.allocate_record(volume)?;
        let reference = tx.record_reference(file)?;
        let number = tx.record_number(file);
        let (record_bytes, block_vcns) = (tx.record_bytes(), tx.index_block_vcns());
        {
            let rec = tx.record_mut(file);
            empty_record(rec, record_bytes, number, (reference >> 48) as u16)?;
            p16(rec, 18, u16::from(!temporary));
            p16(rec, 22, record_flags);
            let mut si = [0u8; 48];
            for at in [0, 8, 16, 24] {
                p64(&mut si, at, timestamp);
            }
            p32(&mut si, 32, attributes);
            insert_resident(rec, std_info::SI, &[], &si)?;
            if !temporary {
                insert_resident(rec, FILE_NAME, &[], &fname[..fname_len])?;
            }
            insert_resident(rec, 0x50, &[], descriptor)?;
            match kind {
                NodeKind::Directory => {
                    let mut root = [0u8; 48];
                    p32(&mut root, 0, FILE_NAME);
                    p32(&mut root, 4, 1); // COLLATION_FILE_NAME
                    p32(&mut root, 8, BLOCK as u32);
                    root[12] = block_vcns as u8;
                    p32(&mut root, 16, 16);
                    p32(&mut root, 20, 32);
                    p32(&mut root, 24, 32);
                    p16(&mut root, 32 + 8, 16);
                    p16(&mut root, 32 + 12, 2);
                    insert_resident(rec, INDEX_ROOT, super::index_tree::I30, &root)?;
                }
                _ => insert_resident(rec, DATA, &[], &[])?,
            }
            record_edit::validate(rec)?;
        }
        if let Some((_, data)) = link {
            let resident = if data.len() <= 700 {
                match insert_resident(tx.record_mut(file), reparse::ATTR_REPARSE, &[], data) {
                    Ok(()) => true,
                    Err(Error::NoSpace) => false,
                    Err(e) => return Err(e),
                }
            } else {
                false
            };
            if !resident {
                let cluster = tx.cluster_bytes();
                let count = (data.len() as u64).div_ceil(cluster);
                let lcn = tx.allocate_clusters(volume, count, None)?;
                super::tx::stage_bytes(self, &mut **volume.reader_mut(), lcn * cluster, data, &mut work[..BLOCK])?;
                let run = super::runlist::Extent { vcn: 0, len: count, lcn: Some(lcn) };
                let n = record_edit::build_nonresident(
                    reparse::ATTR_REPARSE,
                    &[],
                    &[run],
                    count * cluster,
                    data.len() as u64,
                    data.len() as u64,
                    work,
                )?;
                record_edit::insert(tx.record_mut(file), &work[..n])?;
            }
        }
        let mode = mode.filter(|_| linux && link.is_none() && !matches!(kind, NodeKind::Special(..)));
        if temporary || mode.is_some() || !eas.is_empty() || matches!(kind, NodeKind::Special(..)) {
            let mut builder = Builder::new(stream);
            if temporary {
                builder.push(ORPHAN, &[], 0)?;
            }
            if let Some(mode) = mode {
                if mode & !0o7777 != 0 {
                    return Err(Error::Unsupported);
                }
                let kind = if record_flags == 3 { 0o040000 } else { 0o100000 };
                builder.push(super::unix_metadata::MODE, &(kind | mode).to_le_bytes(), 0)?;
            }
            if let NodeKind::Special(type_mode, major, minor) = kind {
                if !linux
                    || type_mode & !0o177777 != 0
                    || !matches!(type_mode & 0o170000, 0o010000 | 0o020000 | 0o060000 | 0o140000)
                {
                    return Err(Error::Unsupported);
                }
                builder.push(super::unix_metadata::MODE, &type_mode.to_le_bytes(), 0)?;
                if matches!(type_mode & 0o170000, 0o020000 | 0o060000) {
                    builder.push(super::unix_metadata::DEVICE, &super::unix_metadata::device_bytes(major, minor), 0)?;
                }
            }
            for edit in eas {
                if edit.name == super::unix_metadata::MODE
                    || edit.name == super::unix_metadata::DEVICE
                    || edit.name == ORPHAN
                {
                    return Err(Error::NotPermitted);
                }
                if let Some(value) = edit.value {
                    builder.push(edit.name, value, 0)?;
                }
            }
            let info = builder.info();
            let len = builder.len();
            ea::store(tx, volume, self, file, &stream[..len], &info, work)?;
        }
        if !temporary {
            directory_entry(reference, &fname[..fname_len], tx.temp_mut(T_NEW))?;
            tx.tree_insert(volume, &tree, T_NEW)?;
            tx.tree_check(&tree)?;
        }
        if let Some((tag, _)) = link {
            edit_reparse_index(tx, volume, tag, reference, true, work, current_lsn)?;
        }
        for slot in [dir, file] {
            if u64_at(tx.record_before(slot), 8)? > current_lsn {
                return Err(Error::Unsupported);
            }
        }
        Ok(reference)
    }

    /// Remove one name of reference from parent. The last name frees the
    /// file (in bounded steps when it is large), or orphans it when orphan is
    /// set (the file is still open). Directories must be empty. Removing a
    /// Win32 name also removes its DOS alias, as Windows does.
    pub fn remove_node<I: WriteIo>(
        &mut self,
        io: &mut I,
        parent: u64,
        name: &(impl AsRef<[u8]> + ?Sized),
        reference: u64,
        orphan: bool,
        scratch: &mut [u8],
    ) -> Result<Removal> {
        let name = name.as_ref();
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        if reference_number(reference) < 24 || reference_sequence(reference) == 0 || reference_sequence(parent) == 0 {
            return Err(Error::Unsupported);
        }
        let mut utf = [0u8; 512];
        let name_len = existing_name(name, &mut utf[..510])?;
        let current_lsn = self.current_lsn;
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        if rest.len() < WORK {
            return Err(Error::Truncated);
        }
        let (journal, work) = rest.split_at_mut(64 * 1024);
        let dir = tx.load_family(&mut volume, parent)?;
        if u16_at(tx.record(dir), 22)? != 3 {
            return Err(Error::InvalidRecord);
        }
        tx.load_upcase(&mut volume)?;
        let tree = tx.open_tree(dir, IndexKind::Directory)?;
        let file = tx.load_namespace_family(&mut volume, reference, Some((parent, &utf[..name_len])))?;
        for slot in [dir, file] {
            if u64_at(tx.record_before(slot), 8)? > current_lsn {
                return Err(Error::Unsupported);
            }
        }
        let removal =
            self.unlink_in_tx(&mut tx, &mut volume, &tree, parent, file, reference, &utf[..name_len], orphan, work)?;
        tx.tree_check(&tree)?;
        drop(volume);
        tx.commit(self, io, journal)?;
        if !orphan && matches!(removal, Removal::Orphaned) {
            self.reclaim_orphan(io, reference, scratch)?;
            return Ok(Removal::Freed);
        }
        Ok(removal)
    }

    /// Remove a name inside an open transaction. Shared with rename, which
    /// orphans a replaced destination atomically with the move. Large files
    /// are orphaned too, so the caller can reclaim them in bounded steps.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn unlink_in_tx<W: WriteIo>(
        &mut self,
        tx: &mut Tx<'_>,
        volume: &mut Volume<&mut W>,
        tree: &Tree,
        parent: u64,
        file: usize,
        reference: u64,
        name: &[u8],
        orphan: bool,
        work: &mut [u8],
    ) -> Result<Removal> {
        let record = MftRecord::from_decoded(tx.record(file))?;
        let flags = record.flags()?;
        if flags & 1 == 0 || record.link_count()? == 0 || record.base_file_reference()? != 0 {
            return Err(Error::Unsupported);
        }
        let links = record.link_count()?;
        let names = tx.namespace_name_count(file)?;
        if names != usize::from(links) {
            return Err(Error::InvalidAttributeList);
        }
        let (name_slot, at) = tx.name_location(file, parent, name, !self.linux_compatibility)?;
        let partner = tx.name_partner(file, name_slot, at)?;
        let removed = 1 + u16::from(partner.is_some());
        let last = links == removed;
        if last && flags & 2 != 0 && !directory_is_empty(volume, tx.record(file), work)? {
            return Err(Error::NotEmpty);
        }
        // Delete the index entries of the name and its partner.
        let mut value = [0u8; 576];
        for (slot, offset) in [Some((name_slot, at)), partner].into_iter().flatten() {
            let v = record_edit::resident_value(tx.record(slot), offset)?;
            let len = v.len();
            value[..len].copy_from_slice(v);
            directory_entry(reference, &value[..len], tx.temp_mut(T_NEW))?;
            if !tx.tree_lookup(volume, tree, T_NEW)? || u64_at(tx.temp(T_NEW), 0)? != reference {
                return Err(Error::InvalidIndex);
            }
            directory_entry(reference, &value[..len], tx.temp_mut(T_NEW))?;
            tx.tree_delete(volume, tree, T_NEW)?;
        }
        // Remove the attributes, later offset first so the other stays valid.
        if let Some((slot, offset)) = partner {
            if slot == name_slot && offset > at {
                record_edit::remove(tx.record_mut(slot), offset)?;
                record_edit::remove(tx.record_mut(name_slot), at)?;
            } else if slot == name_slot {
                record_edit::remove(tx.record_mut(name_slot), at)?;
                record_edit::remove(tx.record_mut(slot), offset)?;
            } else {
                record_edit::remove(tx.record_mut(name_slot), at)?;
                record_edit::remove(tx.record_mut(slot), offset)?;
            }
        } else {
            record_edit::remove(tx.record_mut(name_slot), at)?;
        }
        p16(tx.record_mut(file), 18, links - removed);
        if !last {
            return Ok(Removal::Unlinked);
        }
        // A file whose runs exceed one transaction's bitmap budget (about
        // 256 MiB contiguous, less when fragmented) is orphaned and then
        // reclaimed in bounded steps; freeing it here would fail with NoSpace.
        if orphan || tx.preserved_family(file) || !reclaim_fits(tx, file)? {
            self.mark_orphan(tx, volume, file, work)?;
            if tx.preserved_family(file) {
                namespace_reclaim_budget(tx, file)?;
            }
            return Ok(Removal::Orphaned);
        }
        self.free_record_in_tx(tx, volume, file, reference, work)?;
        Ok(Removal::Freed)
    }

    fn mark_orphan<W: WriteIo>(
        &mut self,
        tx: &mut Tx<'_>,
        volume: &mut Volume<&mut W>,
        file: usize,
        work: &mut [u8],
    ) -> Result<()> {
        let (old, rest) = work.split_at_mut(ea::MAX_STREAM);
        let (new, rest) = rest.split_at_mut(ea::MAX_STREAM);
        let old_len = tx.with_namespace_eas(volume, file, |volume, bytes| {
            ea::read_stream(volume, &MftRecord::from_decoded(bytes)?, old)
        })?;
        let mut builder = Builder::new(new);
        ea::apply(&old[..old_len], &[Edit { name: ORPHAN, value: Some(&[]), flags: 0 }], &mut builder)?;
        let info = builder.info();
        let len = builder.len();
        tx.remove_namespace_eas(volume, file)?;
        ea::store(tx, volume, self, file, &new[..len], &info, rest)
    }

    /// Free a nameless record: its clusters, $Reparse key, MFT bit and a
    /// new sequence number, all in the pending transaction.
    fn free_record_in_tx<R: ReadAt>(
        &mut self,
        tx: &mut Tx<'_>,
        volume: &mut Volume<R>,
        file: usize,
        reference: u64,
        work: &mut [u8],
    ) -> Result<()> {
        for w in &mut self.windows {
            if w.0 == reference {
                w.1 = 0;
                w.2 = 0;
            }
        }
        let tag = {
            let record = MftRecord::from_decoded(tx.record(file))?;
            reparse::data(volume, &record, work)?.map(|(tag, _)| tag)
        };
        if let Some(tag) = tag {
            edit_reparse_index(tx, volume, tag, reference, false, work, self.current_lsn)?;
        }
        let mut cursor = 0;
        loop {
            let mut next = None;
            for a in MftRecord::from_decoded(tx.record(file))?.attributes() {
                let a = a?;
                if a.nonresident && a.record_offset() >= cursor {
                    check_reclaim_attribute(a)?;
                    next = Some(a.record_offset());
                    break;
                }
            }
            let Some(at) = next else {
                break;
            };
            tx.free_attribute_runs(volume, file, at)?;
            cursor = at + 1;
        }
        let sequence = super::mft::next_sequence(tx.record(file))?;
        let rec = tx.record_mut(file);
        p16(rec, 22, 0);
        p16(rec, 18, 0);
        p16(rec, 16, sequence);
        tx.set_record_allocated(volume, reference_number(reference), false)
    }

    /// Reclaim a marked orphan in bounded transactions. Every step retains
    /// its marker and journals the shortened mapping together with freed bits;
    /// a crash leaves a valid remaining family for the next mount to resume.
    pub fn reclaim_orphan<I: WriteIo>(&mut self, io: &mut I, reference: u64, scratch: &mut [u8]) -> Result<()> {
        while !self.reclaim_orphan_step(io, reference, scratch)? {}
        Ok(())
    }

    /// One bounded transaction of reclaim_orphan. Returns true once the record
    /// is freed. Callers may release their locks between steps.
    pub fn reclaim_orphan_step<I: WriteIo>(&mut self, io: &mut I, reference: u64, scratch: &mut [u8]) -> Result<bool> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        if reference_number(reference) < 24 || reference_sequence(reference) == 0 {
            return Err(Error::Unsupported);
        }
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        if rest.len() < WORK {
            return Err(Error::Truncated);
        }
        let (journal, work) = rest.split_at_mut(64 * 1024);
        let file = tx.load_namespace_family(&mut volume, reference, None)?;
        if u64_at(tx.record(file), 8)? > self.current_lsn {
            return Err(Error::Unsupported);
        }
        if tx.namespace_name_count(file)? != 0
            || !tx.with_namespace_eas(&mut volume, file, |volume, bytes| is_marked_orphan(volume, bytes, work))?
        {
            return Err(Error::InvalidRecord);
        }
        if let Some((mut tail, mut at, first, first_at)) = tx.namespace_tail(&mut volume, file, None)? {
            let removable = MftRecord::from_decoded(tx.record(tail))?
                .attributes()
                .find_map(|a| match a {
                    Ok(a) if a.record_offset() == at => Some(Ok(a)),
                    Err(e) => Some(Err(e)),
                    _ => None,
                })
                .ok_or(Error::InvalidAttribute)??;
            if !removable.nonresident || removable.last_vcn()? == u64::MAX {
                namespace_reclaim_budget(&mut tx, file)?;
                record_edit::remove(tx.record_mut(tail), at)?;
                drop(volume);
                tx.commit(self, io, journal)?;
                return Ok(false);
            }
            let flags = u16_at(tx.record(first), first_at + af::FLAGS_OFFSET)?;
            let physical = if flags & (af::SPARSE | af::COMPRESSED) != 0 {
                Some(u64_at(tx.record(first), first_at + af::COMPRESSED_SIZE_OFFSET)?)
            } else {
                None
            };
            let first_id = u16_at(tx.record(first), first_at + af::ID_OFFSET)?;
            let (_, size, initialized) = record_edit::sizes(tx.record(first), first_at)?;
            let mut released = 0_u64;
            let keep = loop {
                let budget = namespace_reclaim_budget(&mut tx, file)?;
                let attr = MftRecord::from_decoded(tx.record(tail))?
                    .attributes()
                    .find_map(|a| match a {
                        Ok(a) if a.record_offset() == at => Some(Ok(a)),
                        Err(e) => Some(Err(e)),
                        _ => None,
                    })
                    .ok_or(Error::InvalidAttribute)??;
                check_reclaim_segment(attr)?;
                let first_vcn = attr.first_vcn()?;
                let aligned = reclaim_tail(attr, budget)?;
                // One compression unit may span physical attribute records.
                // Retire those tails together; no shortened unit is published.
                let keep = match aligned {
                    Some(keep) => keep,
                    None if reclaim_tail_start(attr, budget)? == Some(first_vcn) => first_vcn,
                    None => return Err(Error::NoSpace),
                };
                let mut name = [0; super::filename::MAX_NAME_BYTES];
                let name_len = attr.name_utf16le()?.len();
                name[..name_len].copy_from_slice(attr.name_utf16le()?);
                for r in super::runlist::DataRuns::new(attr.data_runs()?, first_vcn) {
                    let r = r?;
                    if r.lcn.is_some() {
                        released = released
                            .checked_add(r.len - keep.saturating_sub(r.vcn).min(r.len))
                            .ok_or(Error::Overflow)?;
                    }
                }
                tx.free_attribute_tail(&mut volume, tail, at, keep)?;
                if keep == first_vcn && first_vcn != 0 {
                    record_edit::remove(tx.record_mut(tail), at)?;
                } else {
                    record_edit::truncate_runs(tx.record_mut(tail), at, keep)?;
                }
                if aligned.is_some() {
                    break keep;
                }
                let previous = tx
                    .namespace_tail(&mut volume, file, Some((&name[..name_len], first_vcn)))?
                    .ok_or(Error::InvalidAttributeList)?;
                tail = previous.0;
                at = previous.1;
            };
            // Editing a preceding segment can move the first descriptor
            // within this same physical record. Attribute identity survives
            // that edit; its old byte offset does not.
            let mut first_after = None;
            for candidate in MftRecord::from_decoded(tx.record(first))?.attributes() {
                let candidate = candidate?;
                if candidate.id == first_id && candidate.kind == 0x80 {
                    if candidate.first_vcn()? != 0 || first_after.replace(candidate.record_offset()).is_some() {
                        return Err(Error::InvalidAttributeList);
                    }
                }
            }
            let first_at = first_after.ok_or(Error::InvalidAttributeList)?;
            let allocated = keep.checked_mul(tx.cluster_bytes()).ok_or(Error::Overflow)?;
            let size = size.min(allocated);
            record_edit::set_sizes(tx.record_mut(first), first_at, allocated, size, initialized.min(size))?;
            if let Some(physical) = physical {
                let freed_bytes = released.checked_mul(tx.cluster_bytes()).ok_or(Error::Overflow)?;
                record_edit::p64(
                    tx.record_mut(first),
                    first_at + af::COMPRESSED_SIZE_OFFSET,
                    physical.checked_sub(freed_bytes).ok_or(Error::InvalidRunlist)?,
                )?;
            }
            drop(volume);
            tx.commit(self, io, journal)?;
            return Ok(false);
        }
        tx.load_remaining_family(&mut volume, file)?;
        let done = reclaim_fits(&tx, file)?;
        if done {
            self.free_record_in_tx(&mut tx, &mut volume, file, reference, work)?;
        } else {
            // Preserve the EA containing the orphan marker and the reparse
            // header until final deletion. Other streams can lose their
            // tails because no live handle or namespace refers to this file.
            let record = MftRecord::from_decoded(tx.record(file))?;
            let mut tail = None;
            // Family assembly may already have released scattered list storage.
            // The commit may publish the family's list anew in fresh clusters.
            let taken = tx.clusters.count + LIST_SECTORS;
            let sectors = reclaim_sector_limit(&tx).saturating_sub(taken).min(RECLAIM_STEP_SECTORS);
            for attr in record.attributes() {
                let attr = attr?;
                if !attr.nonresident || matches!(attr.kind, 0xe0 | 0xc0) {
                    continue;
                }
                if let Some(keep) = reclaim_tail(attr, sectors)? {
                    tail = Some((attr.record_offset(), keep));
                    break;
                }
            }
            let (at, keep) = tail.ok_or(Error::NoSpace)?;
            let (_, size, initialized) = record_edit::sizes(tx.record(file), at)?;
            tx.free_attribute_tail(&mut volume, file, at, keep)?;
            record_edit::truncate_runs(tx.record_mut(file), at, keep)?;
            let allocated = keep.checked_mul(tx.cluster_bytes()).ok_or(Error::Overflow)?;
            let size = size.min(allocated);
            record_edit::set_sizes(tx.record_mut(file), at, allocated, size, initialized.min(size))?;
        }
        drop(volume);
        tx.commit(self, io, journal)?;
        Ok(done)
    }

    /// Reclaim every marked orphan (crash recovery at writable mount).
    /// Returns the number of records freed.
    pub fn reclaim_orphans<I: WriteIo>(&mut self, io: &mut I, scratch: &mut [u8]) -> Result<u64> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let mut freed = 0;
        let mut next = super::mft_growth::FIRST_USER_RECORD;
        loop {
            let found = {
                let record_bytes = self.boot.record_bytes as usize;
                let (zero, rest) = scratch.split_at_mut(super::volume::mft_space_bytes(record_bytes));
                let (raw, rest) = rest.split_at_mut(record_bytes);
                let (span, rest) = rest.split_at_mut(super::resident_writer::SCAN_SPAN_BYTES);
                let mut volume = Volume::new(&mut *io, self.boot)?;
                let mft = volume.load_mft(zero)?;
                let mut found = None;
                loop {
                    // A base record without a name is the only candidate;
                    // the scan stops at each one for the closer look below.
                    let mut candidate = None;
                    next = volume.scan_mft_records(&mft, next, span, |number, bytes| {
                        let record = MftRecord::parse(bytes, 512)?;
                        if record.flags()? & 1 == 0 || record.base_file_reference()? != 0 || record.link_count()? != 0 {
                            return Ok(true);
                        }
                        candidate = Some(number);
                        Ok(false)
                    })?;
                    let Some(number) = candidate else {
                        break;
                    };
                    volume.read_mft_record(&mft, number, raw)?;
                    let record = MftRecord::parse(raw, 512)?;
                    let sequence = record.sequence_number()?;
                    // A physical base record may carry an attribute list and
                    // place its marker in an extension. Validate and assemble
                    // the complete family before recognizing our orphan.
                    let (logical, work) = rest.split_at_mut(super::tx::RECORD_IMAGE);
                    volume.resolve_record_metadata(&mft, &record, logical, work)?;
                    if is_marked_orphan(&mut volume, logical, work)? {
                        found = Some(number | u64::from(sequence) << 48);
                        break;
                    }
                }
                found
            };
            let Some(reference) = found else {
                return Ok(freed);
            };
            self.reclaim_orphan(io, reference, scratch)?;
            freed += 1;
        }
    }

    /// Add a standalone POSIX name referring to the same file record.
    /// Namespace insertion and link count publication share one transaction.
    pub fn hard_link<I: WriteIo>(
        &mut self,
        io: &mut I,
        reference: u64,
        parent: u64,
        name: &(impl AsRef<[u8]> + ?Sized),
        scratch: &mut [u8],
    ) -> Result<()> {
        let name = name.as_ref();
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        if reference_number(reference) < 24 || reference_sequence(reference) == 0 || reference_sequence(parent) == 0 {
            return Err(Error::Unsupported);
        }
        self.ensure_free_records(io, super::tx::MAX_RECORDS as u64, scratch)?;
        let mut volume = Volume::new(&mut *io, self.boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (value, rest) = rest.split_at_mut(576);
        let (image, rest) = rest.split_at_mut(1024);
        let (journal, work) = rest.split_at_mut(64 * 1024);
        // Only the records a link changes join the transaction: a file with
        // hundreds of names would not fit its record bound as a whole family.
        let file = tx.load_namespace_family(&mut volume, reference, None)?;
        let dir = tx.load_family(&mut volume, parent)?;
        for slot in [file, dir] {
            if u64_at(tx.record(slot), 8)? > self.current_lsn {
                return Err(Error::Unsupported);
            }
        }
        let rec = MftRecord::from_decoded(tx.record(file))?;
        /* The FILE header stores the link count as u16.  Do not impose the old
         * base-record-era 1024-link ceiling: filename attributes may spill to
         * validated extension records.  The bounded resident $ATTRIBUTE_LIST
         * / transaction capacity remains the real limit and fails atomically. */
        if rec.flags()? != 1 || rec.base_file_reference()? != 0 || rec.link_count()? == u16::MAX {
            return Err(Error::Unsupported);
        }
        let links = rec.link_count()?;
        if tx.namespace_name_count(file)? != usize::from(links) {
            return Err(Error::InvalidAttributeList);
        }
        let (named, last_owner) = name_template(&tx, &mut volume, file, value, work)?;
        if !named {
            // Publishing a nameless file reads its whole metadata below.
            tx.load_remaining_family(&mut volume, file)?;
            if links != 0 || !is_marked_orphan(&mut volume, tx.record(file), work)? {
                return Err(Error::InvalidAttribute);
            }
            value[..66].fill(0);
            let info = std_info::read(&MftRecord::from_decoded(tx.record(file))?)?;
            for (i, time) in info.times.iter().enumerate() {
                p64(value, 8 + 8 * i, *time);
            }
            p32(value, 56, info.attributes);
            // Publishing an O_TMPFILE file: the duplicated sizes describe the
            // data already written through the nameless handle.
            for a in MftRecord::from_decoded(tx.record(file))?.attributes() {
                let a = a?;
                if a.kind != DATA || !a.name_utf16le()?.is_empty() {
                    continue;
                }
                let (allocated, size) = if !a.nonresident {
                    let n = a.resident_value()?.len() as u64;
                    ((n + 7) & !7, n)
                } else if a.first_vcn()? == 0 {
                    (a.allocated_size()?, a.data_size()?)
                } else {
                    continue;
                };
                p64(value, 40, allocated);
                p64(value, 48, size);
            }
            let (old, rest) = work.split_at_mut(ea::MAX_STREAM);
            let (new, rest) = rest.split_at_mut(ea::MAX_STREAM);
            let n = ea::read_stream(&mut volume, &MftRecord::from_decoded(tx.record(file))?, old)?;
            let mut builder = Builder::new(new);
            ea::apply(&old[..n], &[Edit { name: ORPHAN, value: None, flags: 0 }], &mut builder)?;
            let info = builder.info();
            let n = builder.len();
            ea::store(&mut tx, &mut volume, self, file, &new[..n], &info, rest)?;
        }
        let n = policy_name(name, &mut value[66..], self.linux_compatibility)?;
        value[64] = (n / 2) as u8;
        value[65] = 0; // No DOS alias is generated for a new hard link.
        p64(value, 0, parent);
        if u16_at(tx.record(dir), 22)? != 3 {
            return Err(Error::InvalidRecord);
        }
        let n = record_edit::build_resident(FILE_NAME, &[], &value[..66 + n], image)?;
        insert_link_name(&mut tx, &mut volume, file, last_owner, &image[..n])?;
        p16(tx.record_mut(file), 18, links + 1);
        tx.load_upcase(&mut volume)?;
        let tree = tx.open_tree(dir, IndexKind::Directory)?;
        let n = 66 + usize::from(value[64]) * 2;
        directory_entry(reference, &value[..n], tx.temp_mut(T_NEW))?;
        tx.tree_insert(&mut volume, &tree, T_NEW)?;
        tx.tree_check(&tree)?;
        drop(volume);
        tx.commit(self, io, journal)
    }
}

/// Copy the duplicated information of the file's first name into value and
/// return whether it has one, with the newest extension record holding a
/// name: records are allocated in rising order, so only it may have room.
fn name_template<R: ReadAt>(
    tx: &Tx<'_>,
    volume: &mut Volume<R>,
    file: usize,
    value: &mut [u8],
    work: &mut [u8],
) -> Result<(bool, Option<u64>)> {
    let base = tx.record_reference(file)?;
    let mut named = false;
    let mut last_owner = None;
    let mut take = |owner: u64, attribute: super::mft::Attribute<'_>| -> Result<()> {
        if attribute.kind != FILE_NAME {
            return Ok(());
        }
        let original = attribute.resident_value()?;
        if original.len() < 66 {
            return Err(Error::InvalidAttribute);
        }
        if !named {
            value[..66].copy_from_slice(&original[..66]);
            named = true;
        }
        if owner != base && last_owner.is_none_or(|last| reference_number(owner) > reference_number(last)) {
            last_owner = Some(owner);
        }
        Ok(())
    };
    if tx.preserved_family(file) {
        let mft = MftRecord::from_decoded(tx.mft_zero())?;
        let record = MftRecord::from_decoded(tx.record_before(file))?;
        volume.visit_record_family(&mft, &record, work, |owner, attribute| take(owner, attribute))?;
    } else {
        for slot in 0..super::tx::MAX_RECORDS {
            if !tx.family_member(file, slot)? {
                continue;
            }
            let owner = tx.record_reference(slot)?;
            for attribute in MftRecord::from_decoded(tx.record(slot))?.attributes() {
                take(owner, attribute?)?;
            }
        }
    }
    Ok((named, last_owner))
}

/// Place a new name in the base record, else in the newest extension record
/// holding names, else in a new extension record, so names fill records
/// densely instead of taking one extension record each.
fn insert_link_name<R: ReadAt>(
    tx: &mut Tx<'_>,
    volume: &mut Volume<R>,
    file: usize,
    last_owner: Option<u64>,
    attribute: &[u8],
) -> Result<()> {
    if tx.preserved_family(file) {
        match record_edit::insert(tx.record_mut(file), attribute) {
            Ok(_) => return Ok(()),
            Err(Error::NoSpace) => {}
            Err(e) => return Err(e),
        }
        if let Some(owner) = last_owner {
            let slot = tx.load_record(volume, owner)?;
            tx.rec_slot_mut(slot)[super::tx::FAMILY_STATE] = super::tx::FAMILY_SELECTIVE;
            tx.limit_record(slot, 0)?;
            match record_edit::insert(tx.record_mut(slot), attribute) {
                Ok(_) => return Ok(()),
                Err(Error::NoSpace) => {}
                Err(e) => return Err(e),
            }
        }
    }
    tx.insert_family_name(volume, file, attribute, false)
}

/// Bitmap sectors one orphan-reclaim step may free. Each step is a separate
/// journaled transaction, so larger steps mean fewer commits for big files.
const RECLAIM_STEP_SECTORS: usize = BITMAP_PATCHES;
/// Bitmap sectors a newly published attribute list can touch: its
/// contiguous clusters straddle at most two.
const LIST_SECTORS: usize = super::allocation::LIST_BITMAP_SECTORS;

/// Reserve transaction patches for records, the reparse index and MFT bits.
fn reclaim_sector_limit(tx: &Tx<'_>) -> usize {
    let records = (0..super::tx::MAX_RECORDS).filter(|&slot| tx.rec_slot(slot)[24] & super::tx::R_USED != 0).count();
    super::allocation::BITMAP_PATCHES.min(super::metadata_tx::MAX_PATCHES.saturating_sub(records + 8))
}

/// Keep list retirement and replacement allocation inside the same bitmap
/// patch budget as the DATA tail. A new contiguous list can straddle two
/// bitmap sectors; old list runs may occupy many unrelated sectors.
fn namespace_reclaim_budget(tx: &mut Tx<'_>, file: usize) -> Result<usize> {
    let limit = reclaim_sector_limit(tx);
    let mut budget = SectorBudget::new(&tx.clusters, limit)?.ok_or(Error::NoSpace)?;
    let record = MftRecord::from_decoded(tx.record_before(file))?;
    let list = record
        .attributes()
        .find_map(|attribute| match attribute {
            Ok(attribute) if attribute.kind == super::mft::ATTR_ATTRIBUTE_LIST => Some(Ok(attribute)),
            Err(error) => Some(Err(error)),
            _ => None,
        })
        .ok_or(Error::InvalidAttributeList)??;
    // A contiguous list fits within two bitmap sectors even at the smallest
    // supported cluster size. Fragmented old storage can stay owned by an
    // ordinary orphan stream until later bounded cleanup.
    if list.data_size()?.checked_add(super::tx::RECORD_IMAGE as u64).ok_or(Error::Overflow)?
        > CLUSTERS_PER_BITMAP_SECTOR * super::allocation::BITMAP_SECTOR_BYTES
    {
        return Err(Error::NoSpace);
    }
    let mut retain = tx.rec_slot(file)[super::tx::RETAIN_LIST_ALLOCATION] != 0;
    if list.nonresident {
        for run in super::runlist::DataRuns::new(list.data_runs()?, list.first_vcn()?) {
            let run = run?;
            let lcn = run.lcn.ok_or(Error::InvalidAttributeList)?;
            if !retain && !budget.add_run(lcn, run.len)? {
                retain = true;
            }
        }
        retain |= budget.count() + LIST_SECTORS + af::COMPRESSION_UNIT_CLUSTERS as usize > limit;
    }
    if retain {
        tx.retain_namespace_list(file);
        return Ok(limit.saturating_sub(tx.clusters.count + LIST_SECTORS).min(RECLAIM_STEP_SECTORS));
    }
    Ok(limit.saturating_sub(budget.count() + LIST_SECTORS).min(RECLAIM_STEP_SECTORS))
}

/// Count actual bitmap sectors, including preallocated list storage released
/// during assembly. Logical file length cannot bound scattered bitmap edits.
fn reclaim_fits(tx: &Tx<'_>, file: usize) -> Result<bool> {
    let Some(mut budget) = SectorBudget::new(&tx.clusters, reclaim_sector_limit(tx))? else {
        return Ok(false);
    };
    for attr in MftRecord::from_decoded(tx.record(file))?.attributes() {
        let attr = attr?;
        if !attr.nonresident {
            continue;
        }
        check_reclaim_attribute(attr)?;
        for run in super::runlist::DataRuns::new(attr.data_runs()?, 0) {
            let run = run?;
            let Some(lcn) = run.lcn else { continue };
            if !budget.add_run(lcn, run.len)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Select the final group of runs within the remaining bitmap-sector budget.
/// Bound physical bitmap edits rather than VCN count: even a tiny logical
/// tail can touch many sectors on an imported, heavily fragmented volume.
fn reclaim_tail(attr: super::mft::Attribute<'_>, budget: usize) -> Result<Option<u64>> {
    let Some(mut keep) = reclaim_tail_start(attr, budget)? else {
        return Ok(None);
    };
    // Rounding forward reduces the selected bitmap edits and preserves units.
    if attr.flags()? & af::COMPRESSED != 0 {
        let unit = 1_u64 << u16_at(attr.raw(), af::COMPRESSION_UNIT_OFFSET)?;
        keep = keep.checked_add(unit - 1).ok_or(Error::Overflow)? / unit * unit;
        if keep > attr.last_vcn()? {
            return Ok(None);
        }
    }
    Ok(Some(keep))
}

fn reclaim_tail_start(attr: super::mft::Attribute<'_>, budget: usize) -> Result<Option<u64>> {
    check_reclaim_segment(attr)?;
    if budget == 0 {
        return Ok(None);
    }
    let mut sectors = [0_u64; RECLAIM_STEP_SECTORS];
    let mut count = 0;
    let mut keep = attr.first_vcn()?;
    for run in super::runlist::DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
        let run = run?;
        let Some(start) = run.lcn else { continue };
        let end = start.checked_add(run.len).ok_or(Error::Overflow)?;
        let mut lcn = start;
        while lcn < end {
            let sector = lcn / CLUSTERS_PER_BITMAP_SECTOR;
            if !sectors[..count].contains(&sector) {
                if count == sectors.len().min(budget) {
                    keep = run.vcn.checked_add(lcn - start).ok_or(Error::Overflow)?;
                    count = 0;
                }
                sectors[count] = sector;
                count += 1;
            }
            lcn = end.min(
                sector.checked_add(1).and_then(|n| n.checked_mul(CLUSTERS_PER_BITMAP_SECTOR)).ok_or(Error::Overflow)?,
            );
        }
    }
    let first = attr.first_vcn()?;
    let mapped = attr.last_vcn()?.checked_add(1).is_some_and(|end| end > first);
    Ok((count != 0 || first != 0 || mapped).then_some(keep))
}

/// Reclamation edits allocation, never stream contents. Compression and EFS
/// do not prevent freeing physical runs; holes still own no clusters. Unknown
/// encodings remain unsupported; continuation cleanup preserves unit boundaries.
fn check_reclaim_attribute(attr: super::mft::Attribute<'_>) -> Result<()> {
    check_reclaim_segment(attr)?;
    if attr.first_vcn()? != 0 {
        return Err(Error::Unsupported);
    }
    Ok(())
}

fn check_reclaim_segment(attr: super::mft::Attribute<'_>) -> Result<()> {
    let flags = attr.flags()?;
    if flags & !(af::COMPRESSED | af::ENCRYPTED | af::SPARSE) != 0 {
        return Err(Error::Unsupported);
    }
    if flags & af::COMPRESSED != 0 {
        if flags & af::ENCRYPTED != 0 || u16_at(attr.raw(), af::COMPRESSION_UNIT_OFFSET)? != af::COMPRESSION_UNIT_SHIFT
        {
            return Err(Error::Unsupported);
        }
        if usize::from(u16_at(attr.raw(), af::MAPPING_PAIRS_OFFSET)?) < af::EXTENDED_HEADER_BYTES {
            return Err(Error::InvalidAttribute);
        }
    }
    Ok(())
}

/// A marked assembled orphan: in use, base, zero links, no names and our EA.
fn is_marked_orphan<R: ReadAt>(volume: &mut Volume<R>, record: &[u8], work: &mut [u8]) -> Result<bool> {
    let record = MftRecord::from_decoded(record)?;
    if record.flags()? & 1 == 0 || record.base_file_reference()? != 0 || record.link_count()? != 0 {
        return Ok(false);
    }
    for a in record.attributes() {
        let a = a?;
        if a.kind == FILE_NAME || a.kind == 0x20 {
            return Ok(false);
        }
    }
    let n = match ea::read_stream(volume, &record, work) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    Ok(ea::find(&work[..n], ORPHAN)?.is_some())
}

#[cfg(test)]
#[path = "../tests/core/file_lifecycle.rs"]
mod tests;
