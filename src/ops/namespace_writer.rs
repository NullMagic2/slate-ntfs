//! Module: ntfs_rs::namespace_writer
//! Purpose: Publish journaled namespace mutations.
//! Created: 2026-10-01
//! Architecture: Rename edits both directory trees through index_tree; filename attributes
//! and every allocation change commit together through the shared Tx engine.

use super::bytes::{u16_at, u64_at};
use super::filename::{FileNameValue, DOS, POSIX, WIN32, WIN32_AND_DOS};
use super::index_tree::{directory_entry, IndexKind, Tree, T_NEW};
use super::mft::{reference_number, reference_sequence};
use super::mft::{MftRecord, ATTR_FILE_NAME as FILE_NAME};
use super::record_edit;
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::tx::Tx;
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

/// Validate a Linux-compatible POSIX namespace name and encode it as UTF-16LE.
/// Arbitrary non-UTF-8 bytes use the reversible linux_names policy.
pub(super) fn name_bytes(name: &[u8], out: &mut [u8]) -> Result<usize> {
    let n = super::linux_names::encode(name, out)?;
    if n > 510 {
        return Err(Error::Unsupported);
    }
    Ok(n)
}
/// Native mode keeps Win32 naming rules for new names: valid Unicode, no
/// Windows-reserved punctuation, trailing dot/space or reserved device names.
pub(super) fn policy_name(name: &[u8], out: &mut [u8], linux: bool) -> Result<usize> {
    if !linux {
        let text = core::str::from_utf8(name).map_err(|_| Error::Unsupported)?;
        if text.ends_with([' ', '.'])
            || text.chars().any(|c| c < ' ' || super::linux_names::WINDOWS_RESERVED_CHARS.contains(&c))
            || super::linux_names::windows_reserved(text)
        {
            return Err(Error::Unsupported);
        }
    }
    name_bytes(name, out)
}
/// Existing names are matched exactly after the same reversible encoding.
pub(super) fn existing_name(name: &[u8], out: &mut [u8]) -> Result<usize> {
    let n = super::linux_names::encode(name, out).map_err(|_| Error::InvalidAttribute)?;
    if n == 0 || n > 510 {
        return Err(Error::InvalidAttribute);
    }
    Ok(n)
}

/// Offset of the resident $FILE_NAME in parent named exactly name,
/// or (when name is None) of the DOS-namespace alias in parent.
pub(super) fn find_name(rec: &[u8], parent: u64, name: Option<&[u8]>) -> Result<Option<usize>> {
    let mut found = None;
    for a in MftRecord::from_decoded(rec)?.attributes() {
        let a = a?;
        if a.kind != FILE_NAME {
            continue;
        }
        let value = FileNameValue::parse(a.resident_value()?)?;
        let matches = value.parent_reference == parent
            && match name {
                Some(name) => value.name.utf16le == name && value.name.namespace != DOS,
                None => value.name.namespace == DOS,
            };
        if matches && found.replace(a.record_offset()).is_some() {
            return Err(Error::InvalidAttribute);
        }
    }
    Ok(found)
}

/// Offset of a non-DOS $FILE_NAME of rec in parent naming name.
/// Exact matches win. Native mode resolves names case-insensitively, so it
/// then accepts exactly one match under the volume's $UpCase table.
pub(super) fn find_linked_name(
    tx: &Tx<'_>,
    rec: &[u8],
    parent: u64,
    name: &[u8],
    native: bool,
) -> Result<Option<usize>> {
    if let Some(at) = find_name(rec, parent, Some(name))? {
        return Ok(Some(at));
    }
    if !native || !tx.upcase_loaded {
        return Ok(None);
    }
    let mut found = None;
    for a in MftRecord::from_decoded(rec)?.attributes() {
        let a = a?;
        if a.kind != FILE_NAME {
            continue;
        }
        let value = FileNameValue::parse(a.resident_value()?)?;
        if value.parent_reference == parent
            && value.name.namespace != DOS
            && super::index_tree::names_equal_ignoring_case(tx.upcase, value.name.utf16le, name)
            && found.replace(a.record_offset()).is_some()
        {
            return Err(Error::InvalidAttribute);
        }
    }
    Ok(found)
}

fn is_directory(tx: &Tx<'_>, slot: usize) -> Result<bool> {
    Ok(u16_at(tx.record(slot), 22)? & 3 == 3)
}

impl Writer {
    /// Rename or move one name of a file or directory. The destination name
    /// must not exist in the target directory (case-insensitively in native
    /// mode). A Win32 name's paired DOS 8.3 alias is removed, as Windows does
    /// when it renames a long name without generating a new short name.
    #[allow(clippy::too_many_arguments)]
    pub fn move_entry<I: WriteIo>(
        &mut self,
        io: &mut I,
        old_parent: u64,
        reference: u64,
        old: &(impl AsRef<[u8]> + ?Sized),
        new_parent: u64,
        new: &(impl AsRef<[u8]> + ?Sized),
        scratch: &mut [u8],
    ) -> Result<()> {
        self.rename_ex(io, old_parent, reference, old, new_parent, new, RenameTarget::None, scratch).map(|_| ())
    }

    /// Rename with POSIX destination semantics, as one transaction:
    /// * Replace(victim): the existing destination name is removed; if it
    ///   was the victim's last name the victim becomes a marked orphan, which
    ///   the caller reclaims once no handle remains (reclaim_orphan).
    /// * Exchange(other): both names are swapped atomically
    ///   (RENAME_EXCHANGE); both rewritten names are standalone POSIX names.
    ///
    /// Returns the victim's removal outcome for Replace.
    #[allow(clippy::too_many_arguments)]
    pub fn rename_ex<I: WriteIo>(
        &mut self,
        io: &mut I,
        old_parent: u64,
        reference: u64,
        old: &(impl AsRef<[u8]> + ?Sized),
        new_parent: u64,
        new: &(impl AsRef<[u8]> + ?Sized),
        target: RenameTarget<'_>,
        scratch: &mut [u8],
    ) -> Result<Option<super::file_lifecycle::Removal>> {
        let (old, new) = (old.as_ref(), new.as_ref());
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let number = reference_number(reference);
        if number < 16
            || reference_sequence(reference) == 0
            || reference_sequence(old_parent) == 0
            || reference_sequence(new_parent) == 0
            || number == reference_number(new_parent)
            || number == reference_number(old_parent)
        {
            return Err(Error::Unsupported);
        }
        let other = match target {
            RenameTarget::None | RenameTarget::Whiteout { destination: None, .. } => None,
            RenameTarget::Replace(r)
            | RenameTarget::Exchange(r)
            | RenameTarget::Whiteout { destination: Some(r), .. } => {
                let n = reference_number(r);
                if n < 16
                    || reference_sequence(r) == 0
                    || n == number
                    || n == reference_number(new_parent)
                    || n == reference_number(old_parent)
                {
                    return Err(Error::Unsupported);
                }
                Some(r)
            }
        };
        let exchange = matches!(target, RenameTarget::Exchange(_));
        if matches!(target, RenameTarget::Whiteout { .. }) && !self.linux_compatibility {
            return Err(Error::Unsupported);
        }
        let native = !self.linux_compatibility;
        self.ensure_free_records(io, super::tx::MAX_RECORDS as u64, scratch)?;
        let current_lsn = self.current_lsn;
        let boot = self.boot;
        let mut volume = Volume::new(&mut *io, boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        // Large locals live in scratch to keep kernel stack usage small.
        let (journal, rest) = rest.split_at_mut(64 * 1024);
        let (old_utf, rest) = rest.split_at_mut(512);
        let (new_utf, rest) = rest.split_at_mut(512);
        let (value, rest) = rest.split_at_mut(576);
        let (key, rest) = rest.split_at_mut(576);
        let (alias, rest) = rest.split_at_mut(576);
        let (other_value, rest) = rest.split_at_mut(576);
        let (duplicated, rest) = rest.split_at_mut(56);
        let (other_duplicated, work) = rest.split_at_mut(56);
        let old_n = existing_name(old, &mut old_utf[..510])?;
        let new_n = if exchange {
            existing_name(new, &mut new_utf[..510])?
        } else {
            policy_name(new, &mut new_utf[..510], self.linux_compatibility)?
        };
        tx.load_upcase(&mut volume)?;
        let file = tx.load_namespace_family(&mut volume, reference, Some((old_parent, &old_utf[..old_n])))?;
        let old_dir = tx.load_family(&mut volume, old_parent)?;
        let new_dir = tx.load_family(&mut volume, new_parent)?;
        let other_slot = match other {
            Some(r) => Some(tx.load_namespace_family(&mut volume, r, Some((new_parent, &new_utf[..new_n])))?),
            None => None,
        };
        for slot in [Some(file), Some(old_dir), Some(new_dir), other_slot].into_iter().flatten() {
            if u64_at(tx.record(slot), 8)? > current_lsn {
                return Err(Error::Unsupported);
            }
            if MftRecord::from_decoded(tx.record(slot))?.base_file_reference()? != 0 {
                return Err(Error::Unsupported);
            }
        }
        if !is_directory(&tx, old_dir)? || !is_directory(&tx, new_dir)? {
            return Err(Error::InvalidRecord);
        }
        if is_directory(&tx, file)? && old_parent != new_parent {
            check_ancestry(&tx, &mut volume, number, new_parent, journal)?;
        }
        if let (true, Some(slot), Some(r)) = (exchange, other_slot, other) {
            if is_directory(&tx, slot)? && old_parent != new_parent {
                check_ancestry(&tx, &mut volume, reference_number(r), old_parent, journal)?;
            }
        }
        let (name_slot, at) = tx.name_location(file, old_parent, &old_utf[..old_n], native)?;
        let old_value = record_edit::resident_value(tx.record(name_slot), at)?;
        let old_len = old_value.len();
        value[..old_len].copy_from_slice(old_value);
        let namespace = value[65];
        if !matches!(namespace, POSIX | WIN32 | WIN32_AND_DOS) {
            return Err(Error::Unsupported);
        }
        let dos = tx.name_partner(file, name_slot, at)?;
        let old_tree = tx.open_tree(old_dir, IndexKind::Directory)?;
        let new_tree = if new_dir == old_dir { old_tree } else { tx.open_tree(new_dir, IndexKind::Directory)? };
        // Remove the old directory entry after checking that it names this file.
        remove_entry(&mut tx, &mut volume, &old_tree, reference, &value[..old_len], duplicated)?;
        if let Some((dos_slot, dos_at)) = dos {
            let v = record_edit::resident_value(tx.record(dos_slot), dos_at)?;
            let alias_len = v.len();
            alias[..alias_len].copy_from_slice(v);
            let mut ignored = [0u8; 56];
            remove_entry(&mut tx, &mut volume, &old_tree, reference, &alias[..alias_len], &mut ignored)?;
        }
        let mut victim = None;
        let mut other_len = 0;
        if let (Some(slot), Some(r)) = (other_slot, other) {
            if exchange {
                let (other_name_slot, at2) = tx.name_location(slot, new_parent, &new_utf[..new_n], native)?;
                let v = record_edit::resident_value(tx.record(other_name_slot), at2)?;
                other_len = v.len();
                other_value[..other_len].copy_from_slice(v);
                let other_namespace = other_value[65];
                if !matches!(other_namespace, POSIX | WIN32 | WIN32_AND_DOS) {
                    return Err(Error::Unsupported);
                }
                // The exchanged names keep their exact on-disk spelling.
                new_utf[..other_len - 66].copy_from_slice(&other_value[66..other_len]);
                let dos2 = tx.name_partner(slot, other_name_slot, at2)?;
                remove_entry(&mut tx, &mut volume, &new_tree, r, &other_value[..other_len], other_duplicated)?;
                if let Some((dos_slot, dos_at)) = dos2 {
                    let v = record_edit::resident_value(tx.record(dos_slot), dos_at)?;
                    let alias_len = v.len();
                    alias[..alias_len].copy_from_slice(v);
                    let mut ignored = [0u8; 56];
                    remove_entry(&mut tx, &mut volume, &new_tree, r, &alias[..alias_len], &mut ignored)?;
                }
                rewrite_name(
                    &mut tx,
                    &mut volume,
                    slot,
                    other_name_slot,
                    at2,
                    dos2,
                    old_parent,
                    &value[66..old_len],
                    POSIX,
                )?;
            } else {
                victim = Some(self.unlink_in_tx(
                    &mut tx,
                    &mut volume,
                    &new_tree,
                    new_parent,
                    slot,
                    r,
                    &new_utf[..new_n],
                    true,
                    work,
                )?);
            }
        }
        // Rewrite the file's $FILE_NAME in place, then drop the DOS alias.
        // Removing a DOS partner leaves a standalone name, encoded in
        // POSIX namespace. The native view still enforces Win32 naming and
        // case-insensitive collision/lookup policy independently of this tag.
        let name_units = if exchange { &new_utf[..other_len - 66] } else { &new_utf[..new_n] };
        let name_namespace = POSIX;
        let new_len = 66 + name_units.len();
        key[..66].copy_from_slice(&value[..66]);
        key[..8].copy_from_slice(&new_parent.to_le_bytes());
        key[64] = (name_units.len() / 2) as u8;
        key[65] = name_namespace;
        key[66..new_len].copy_from_slice(name_units);
        rewrite_name(&mut tx, &mut volume, file, name_slot, at, dos, new_parent, name_units, name_namespace)?;
        key[8..64].copy_from_slice(duplicated);
        directory_entry(reference, &key[..new_len], tx.temp_mut(T_NEW))?;
        tx.tree_insert(&mut volume, &new_tree, T_NEW)?;
        if let (true, Some(r)) = (exchange, other) {
            let len = old_len;
            key[..66].copy_from_slice(&other_value[..66]);
            key[..8].copy_from_slice(&old_parent.to_le_bytes());
            key[64] = value[64];
            key[65] = POSIX;
            key[66..len].copy_from_slice(&value[66..old_len]);
            key[8..64].copy_from_slice(other_duplicated);
            directory_entry(r, &key[..len], tx.temp_mut(T_NEW))?;
            tx.tree_insert(&mut volume, &old_tree, T_NEW)?;
        }
        tx.tree_check(&old_tree)?;
        tx.tree_check(&new_tree)?;
        if let RenameTarget::Whiteout { descriptor, timestamp, eas, .. } = target {
            // Reuse the create engine inside this transaction: a crash can
            // expose neither half of a moved name plus its whiteout.
            self.create_in_tx(
                &mut tx,
                &mut volume,
                old_parent,
                old,
                super::file_lifecycle::NodeKind::Special(0o020000, 0, 0),
                descriptor,
                timestamp,
                Some(0),
                eas,
                work,
            )?;
        }
        drop(volume);
        tx.commit(self, io, journal)?;
        Ok(victim)
    }
}

/// Destination handling for rename_ex.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameTarget<'a> {
    /// The destination must not exist.
    None,
    /// Replace the existing destination file or empty directory.
    Replace(u64),
    /// Swap with the existing destination (RENAME_EXCHANGE).
    Exchange(u64),
    /// Move the name and create a standard Linux character-device 0:0 at
    /// the source, atomically. The descriptor belongs to the new whiteout.
    Whiteout {
        destination: Option<u64>,
        descriptor: &'a [u8],
        timestamp: u64,
        /// Initial security labels, published in the rename transaction.
        eas: &'a [super::ea::Edit<'a>],
    },
}

/// Delete the directory entry for file_name after checking that it refers
/// to reference; copy its duplicated information into duplicated.
fn remove_entry<R: ReadAt>(
    tx: &mut Tx<'_>,
    volume: &mut Volume<R>,
    tree: &Tree,
    reference: u64,
    file_name: &[u8],
    duplicated: &mut [u8],
) -> Result<()> {
    directory_entry(reference, file_name, tx.temp_mut(T_NEW))?;
    if !tx.tree_lookup(volume, tree, T_NEW)? || u64_at(tx.temp(T_NEW), 0)? != reference {
        return Err(Error::InvalidIndex);
    }
    // Directory entries carry the duplicated information (times, sizes,
    // attributes) that listings use; keep the index copy for the new key.
    duplicated.copy_from_slice(&tx.temp(T_NEW)[16 + 8..16 + 64]);
    tx.tree_delete(volume, tree, T_NEW)
}

/// Point the $FILE_NAME at at to parent/name and remove its DOS
/// partner (decrementing the link count), in the pending record image.
fn rewrite_name<R: ReadAt>(
    tx: &mut Tx<'_>,
    volume: &mut Volume<R>,
    base: usize,
    slot: usize,
    at: usize,
    dos: Option<(usize, usize)>,
    parent: u64,
    name: &[u8],
    namespace: u8,
) -> Result<()> {
    let mut value = [0u8; 576];
    let old = record_edit::resident_value(tx.record(slot), at)?;
    value[..66].copy_from_slice(&old[..66]);
    value[..8].copy_from_slice(&parent.to_le_bytes());
    value[64] = (name.len() / 2) as u8;
    value[65] = namespace;
    value[66..66 + name.len()].copy_from_slice(name);
    // Remove the alias first when it follows the name, so at stays valid.
    let mut at = at;
    if let Some((dos_slot, dos_at)) = dos {
        let alias_len = record_edit::attr_len(tx.record(dos_slot), dos_at)?;
        record_edit::remove(tx.record_mut(dos_slot), dos_at)?;
        if dos_slot == slot && dos_at < at {
            at -= alias_len;
        }
        let links = u16_at(tx.record(base), 18)?.checked_sub(1).ok_or(Error::InvalidRecord)?;
        if links == 0 {
            return Err(Error::InvalidRecord);
        }
        record_edit::p16(tx.record_mut(base), 18, links)?;
    }
    match record_edit::set_resident_value(tx.record_mut(slot), at, &value[..66 + name.len()]) {
        Err(Error::NoSpace) => {
            let mut image = [0u8; 1024];
            let n = record_edit::build_resident(FILE_NAME, &[], &value[..66 + name.len()], &mut image)?;
            record_edit::remove(tx.record_mut(slot), at)?;
            tx.insert_family_name(volume, base, &image[..n], false)
        }
        result => result,
    }
}

/// Refuse moving directory number below itself. VFS rejects descendant
/// moves, but the shared engine is also called directly by tools.
fn check_ancestry<R: ReadAt>(
    tx: &Tx<'_>,
    volume: &mut Volume<R>,
    number: u64,
    new_parent: u64,
    buffer: &mut [u8],
) -> Result<()> {
    let mft = MftRecord::from_decoded(tx.mft_zero())?;
    let mut ancestor = new_parent;
    for _ in 0..1024 {
        let id = reference_number(ancestor);
        if id == number {
            return Err(Error::InvalidIndex);
        }
        volume.read_mft_record(&mft, id, &mut buffer[..1024])?;
        let dir = MftRecord::parse(&mut buffer[..1024], 512)?;
        if dir.flags()? != 3 || u64::from(dir.sequence_number()?) != ancestor >> 48 {
            return Err(Error::InvalidRecord);
        }
        if id == 5 {
            return Ok(());
        }
        let mut parent = None;
        for attr in dir.attributes() {
            let attr = attr?;
            if attr.kind == 0x20 {
                return Err(Error::Unsupported);
            }
            if attr.kind == FILE_NAME {
                let p = u64_at(attr.resident_value()?, 0)?;
                if parent.is_some_and(|old| old != p) {
                    return Err(Error::InvalidIndex);
                }
                parent = Some(p);
            }
        }
        let next = parent.ok_or(Error::InvalidIndex)?;
        if next == ancestor {
            return Err(Error::InvalidIndex);
        }
        ancestor = next;
    }
    Err(Error::Unsupported)
}
