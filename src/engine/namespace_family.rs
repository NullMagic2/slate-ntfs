//! Module: ntfs_rs::namespace_family
//! Purpose: Edit names without assembling or rewriting unchanged data segments.
//! Created: 2026-10-01
//! Architecture: The checked family visitor reads one physical record at a time;
//! Tx retains only metadata records that change and republishes their list entries.

use super::attrlist::{AttributeList, ListEntry};
use super::bytes::{u16_at, u64_at};
use super::filename::{FileNameValue, DOS, WIN32};
use super::mft::reference_number;
use super::mft::{Attribute, MftRecord};
use super::record_edit as edit;
use super::resident_writer::{WriteIo, Writer};
use super::runlist::Extent;
use super::tx::{
    Tx, BLOCK, FAMILY_PACKED, FAMILY_SELECTIVE, FAMILY_STATE, MAX_RECORDS, RECORD, R_DIRTY, R_USED,
    SKIP_FILENAME_REFRESH,
};
use super::upcase::fold_unit;
use super::volume::{ReadAt, Volume};
use super::{Error, Result};

fn raw_attribute(record: &[u8], kind: u32) -> Result<Option<Attribute<'_>>> {
    let mut found = None;
    for a in MftRecord::from_decoded(record)?.attributes() {
        let a = a?;
        if a.kind == kind && found.replace(a).is_some() {
            return Err(Error::InvalidAttribute);
        }
    }
    Ok(found)
}

impl Tx<'_> {
    pub(crate) fn preserved_family(&self, base: usize) -> bool {
        self.rec_slot(base)[FAMILY_STATE] == FAMILY_SELECTIVE
    }

    /// The transaction cache is for records being edited, not every data
    /// continuation in a file. Directory families use the existing tree editor.
    pub(crate) fn load_namespace_family<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        reference: u64,
        selection: Option<(u64, &[u8])>,
    ) -> Result<usize> {
        let base = self.load_record(volume, reference)?;
        if self.rec_slot(base)[FAMILY_STATE] != 0 {
            return Ok(base);
        }
        if u16_at(self.record(base), 22)? & 2 != 0 || raw_attribute(self.record(base), 0x20)?.is_none() {
            return self.load_family(volume, reference);
        }
        self.load_upcase(volume)?;
        let work = core::mem::take(&mut self.namespace_work);
        let result = (|| {
            let mft = MftRecord::from_decoded(self.mft_zero())?;
            let record = MftRecord::from_decoded(self.record(base))?;
            let mut names = 0_u64;
            let mut exact = None;
            let mut folded = None;
            let mut ambiguous = false;
            let mut dos = None;
            let mut dos_ambiguous = false;
            let mut ea_owners = [0_u64; MAX_RECORDS];
            let mut ea_count = 0;
            let mut previous_kind = 0;
            let mut previous_vcn = 0;
            let mut previous_name = [0; 510];
            let mut previous_len = 0;
            volume.visit_record_family(&mft, &record, work, |owner, a| {
                let name = a.name_utf16le()?;
                let vcn = if a.nonresident { a.first_vcn()? } else { 0 };
                let key = ListEntry {
                    kind: a.kind,
                    first_vcn: vcn,
                    file_reference: owner,
                    attribute_id: a.id,
                    name_utf16le: name,
                };
                let previous = ListEntry {
                    kind: previous_kind,
                    first_vcn: previous_vcn,
                    file_reference: 0,
                    attribute_id: 0,
                    name_utf16le: &previous_name[..previous_len],
                };
                if name.len() > previous_name.len()
                    || entry_order(key, previous, self.upcase) == core::cmp::Ordering::Less
                {
                    return Err(Error::InvalidAttributeList);
                }
                previous_kind = a.kind;
                previous_vcn = vcn;
                previous_name[..name.len()].copy_from_slice(name);
                previous_len = name.len();
                if matches!(a.kind, super::ea::EA | super::ea::EA_INFO)
                    && owner != reference
                    && !ea_owners[..ea_count].contains(&owner)
                {
                    if ea_count == ea_owners.len() {
                        return Err(Error::NoSpace);
                    }
                    ea_owners[ea_count] = owner;
                    ea_count += 1;
                }
                if a.kind == 0x30 {
                    names = names.checked_add(1).ok_or(Error::Overflow)?;
                    let value = FileNameValue::parse(a.resident_value()?)?;
                    if let Some((parent, requested)) = selection {
                        if value.parent_reference != parent {
                            return Ok(());
                        }
                        if value.name.namespace == DOS {
                            if dos.replace(owner).is_some() {
                                dos_ambiguous = true;
                            }
                        } else if value.name.utf16le == requested {
                            if exact.replace((owner, value.name.namespace)).is_some() {
                                return Err(Error::InvalidAttribute);
                            }
                        } else if !self.linux_compatibility
                            && super::index_tree::names_equal_ignoring_case(self.upcase, value.name.utf16le, requested)
                        {
                            if folded.replace((owner, value.name.namespace)).is_some() {
                                ambiguous = true;
                            }
                        }
                    }
                }
                Ok(())
            })?;
            let chosen = if let Some(exact) = exact {
                Some(exact)
            } else if ambiguous {
                return Err(Error::InvalidAttribute);
            } else {
                folded
            };
            if selection.is_some() && chosen.is_none() {
                return Err(Error::NotFound);
            }
            Ok((names, chosen, dos, dos_ambiguous, ea_owners, ea_count))
        })();
        self.namespace_work = work;
        let (names, chosen, dos, dos_ambiguous, ea_owners, ea_count) = result?;
        for owner in &ea_owners[..ea_count] {
            let slot = self.load_record(volume, *owner)?;
            self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_SELECTIVE;
            edit::p32(self.record_mut(slot), 28, RECORD as u32)?;
        }
        self.rec_slot_mut(base)[16..24].copy_from_slice(&names.to_le_bytes());
        if let Some((owner, namespace)) = chosen {
            if owner != reference {
                let slot = self.load_record(volume, owner)?;
                self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_SELECTIVE;
                edit::p32(self.record_mut(slot), 28, RECORD as u32)?;
            }
            if namespace == 1 {
                if dos_ambiguous {
                    return Err(Error::Unsupported);
                }
                if let Some(owner) = dos {
                    let slot = self.load_record(volume, owner)?;
                    self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_SELECTIVE;
                    edit::p32(self.record_mut(slot), 28, RECORD as u32)?;
                }
            }
        }
        // The original list remains in the undo image. Namespace consumers see
        // checked local metadata without mistaking a partial DATA mapping for an
        // assembled stream. Commit restores or updates the physical list.
        let at = raw_attribute(self.record(base), 0x20)?.ok_or(Error::InvalidAttributeList)?.record_offset();
        edit::remove(self.record_mut(base), at)?;
        // Reserve a compact list descriptor while metadata is edited.
        edit::p32(self.record_mut(base), 28, (RECORD - 96) as u32)?;
        self.rec_slot_mut(base)[FAMILY_STATE] = FAMILY_SELECTIVE;
        Ok(base)
    }

    /// Assemble only EA metadata for marker edits and validation. DATA mappings
    /// remain physical segments and never fill the logical record workspace.
    pub(crate) fn with_namespace_eas<R: ReadAt, T>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
        operation: impl FnOnce(&mut Volume<R>, &[u8]) -> Result<T>,
    ) -> Result<T> {
        if !self.preserved_family(base) {
            return operation(volume, self.record(base));
        }
        let buffers = core::mem::take(&mut self.family);
        let entries = core::mem::take(&mut self.namespace_work);
        let result = (|| {
            let image = &mut buffers[..super::tx::RECORD_IMAGE];
            image.copy_from_slice(self.record(base));
            edit::p32(image, 28, image.len() as u32)?;
            for kind in [super::ea::EA, super::ea::EA_INFO] {
                while let Some(at) = edit::find(image, kind, &[])? {
                    edit::remove(image, at)?;
                }
            }
            let list = raw_attribute(self.record_before(base), 0x20)?.ok_or(Error::InvalidAttributeList)?;
            let n = usize::try_from(list.data_size()?).map_err(|_| Error::Overflow)?;
            let entries = entries.get_mut(..n).ok_or(Error::Truncated)?;
            volume.read_attribute(list, 0, entries)?;
            // EA_INFORMATION may share a record with a later EA segment.
            // List order, rather than cache insertion order, joins VCNs.
            for entry in AttributeList::new(entries) {
                let entry = entry?;
                if !matches!(entry.kind, super::ea::EA | super::ea::EA_INFO) {
                    continue;
                }
                let slot = (0..MAX_RECORDS)
                    .find(|&s| {
                        self.family_member(base, s).unwrap_or(false)
                            && self.record_reference(s).ok() == Some(entry.file_reference)
                    })
                    .ok_or(Error::InvalidAttributeList)?;
                let a = MftRecord::from_decoded(self.record(slot))?
                    .attributes()
                    .find_map(|a| match a {
                        Ok(a) if a.id == entry.attribute_id && a.kind == entry.kind => Some(Ok(a)),
                        Err(e) => Some(Err(e)),
                        _ => None,
                    })
                    .ok_or(Error::InvalidAttributeList)??;
                edit::merge_attribute(image, a.raw())?;
            }
            operation(volume, image)
        })();
        self.family = buffers;
        self.namespace_work = entries;
        result
    }

    /// Replace the original EA descriptors wherever they live. Their record
    /// identities and allocation changes join the same marker transaction.
    pub(crate) fn remove_namespace_eas<R: ReadAt>(&mut self, volume: &mut Volume<R>, base: usize) -> Result<()> {
        if !self.preserved_family(base) {
            return Ok(());
        }
        for slot in 0..MAX_RECORDS {
            if !self.family_member(base, slot)? {
                continue;
            }
            loop {
                let mut next = None;
                for a in MftRecord::from_decoded(self.record(slot))?.attributes() {
                    let a = a?;
                    if matches!(a.kind, super::ea::EA | super::ea::EA_INFO) {
                        next = Some((a.record_offset(), a.nonresident));
                        break;
                    }
                }
                let Some((at, nonresident)) = next else {
                    break;
                };
                if nonresident {
                    self.free_attribute_runs(volume, slot, at)?;
                }
                edit::remove(self.record_mut(slot), at)?;
            }
        }
        Ok(())
    }

    /// Once DATA continuations are gone, use the existing metadata packer for
    /// final EA/reparse cleanup and all remaining metadata extension records.
    pub(crate) fn load_remaining_family<R: ReadAt>(&mut self, volume: &mut Volume<R>, base: usize) -> Result<()> {
        if !self.preserved_family(base) {
            return Ok(());
        }
        let buffers = core::mem::take(&mut self.family);
        let result = (|| {
            let old = raw_attribute(self.record_before(base), 0x20)?.ok_or(Error::InvalidAttributeList)?;
            let n = old.raw().len();
            buffers[..n].copy_from_slice(old.raw());
            edit::p32(self.record_mut(base), 28, super::tx::RECORD_IMAGE as u32)?;
            edit::insert(self.record_mut(base), &buffers[..n])?;
            self.rec_slot_mut(base)[FAMILY_STATE] = 0;
            Ok(())
        })();
        self.family = buffers;
        result?;
        self.load_family(volume, self.record_reference(base)?)?;
        Ok(())
    }

    pub(crate) fn namespace_name_count(&self, base: usize) -> Result<usize> {
        if self.preserved_family(base) {
            return usize::try_from(u64_at(self.rec_slot(base), 16)?).map_err(|_| Error::Overflow);
        }
        let mut count = 0;
        for slot in 0..MAX_RECORDS {
            if !self.family_member(base, slot)? {
                continue;
            }
            for a in MftRecord::from_decoded(self.record(slot))?.attributes() {
                if a?.kind == 0x30 {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    pub(crate) fn name_partner(&self, base: usize, slot: usize, at: usize) -> Result<Option<(usize, usize)>> {
        let v = edit::resident_value(self.record(slot), at)?;
        let parent = u64_at(v, 0)?;
        let wanted = match v[65] {
            WIN32 => DOS,
            DOS => WIN32,
            _ => return Ok(None),
        };
        let mut found = None;
        for member in 0..MAX_RECORDS {
            if !self.family_member(base, member)? {
                continue;
            }
            for a in MftRecord::from_decoded(self.record(member))?.attributes() {
                let a = a?;
                if a.kind != 0x30 || (member == slot && a.record_offset() == at) {
                    continue;
                }
                let v = a.resident_value()?;
                if v.len() >= 66
                    && u64_at(v, 0)? == parent
                    && v[65] == wanted
                    && found.replace((member, a.record_offset())).is_some()
                {
                    return Err(Error::Unsupported);
                }
            }
        }
        Ok(found)
    }

    /// Load one remaining DATA continuation for bounded orphan reclamation.
    /// No other DATA record enters the transaction cache.
    pub(crate) fn namespace_tail<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        base: usize,
    ) -> Result<Option<(usize, usize, usize, usize)>> {
        if !self.preserved_family(base) {
            return Ok(None);
        }
        let buffers = core::mem::take(&mut self.namespace_work);
        let result = (|| {
            let list = raw_attribute(self.record_before(base), 0x20)?.ok_or(Error::InvalidAttributeList)?;
            let n = usize::try_from(list.data_size()?).map_err(|_| Error::Overflow)?;
            if n > buffers.len() {
                return Err(Error::Truncated);
            }
            volume.read_attribute(list, 0, &mut buffers[..n])?;
            let mut tail = None;
            for entry in AttributeList::new(&buffers[..n]) {
                let entry = entry?;
                if entry.kind == 0x80 && entry.first_vcn != 0 {
                    tail = Some(entry);
                }
            }
            let Some(tail) = tail else {
                return Ok(None);
            };
            let first = AttributeList::new(&buffers[..n])
                .find_map(|entry| match entry {
                    Ok(e) if e.kind == tail.kind && e.name_utf16le == tail.name_utf16le && e.first_vcn == 0 => {
                        Some(Ok(e))
                    }
                    Err(e) => Some(Err(e)),
                    _ => None,
                })
                .ok_or(Error::InvalidAttributeList)??;
            let first_slot = self.load_record(volume, first.file_reference)?;
            let tail_slot = self.load_record(volume, tail.file_reference)?;
            for slot in [first_slot, tail_slot] {
                self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_SELECTIVE;
                edit::p32(self.record_mut(slot), 28, RECORD as u32)?;
            }
            let locate = |record: &[u8], entry: ListEntry<'_>| -> Result<usize> {
                MftRecord::from_decoded(record)?
                    .attributes()
                    .find_map(|a| match a {
                        Ok(a)
                            if a.id == entry.attribute_id
                                && a.kind == entry.kind
                                && a.name_utf16le().is_ok_and(|n| n == entry.name_utf16le) =>
                        {
                            Some(Ok(a.record_offset()))
                        }
                        Err(e) => Some(Err(e)),
                        _ => None,
                    })
                    .ok_or(Error::InvalidAttributeList)?
            };
            Ok(Some((
                tail_slot,
                locate(self.record(tail_slot), tail)?,
                first_slot,
                locate(self.record(first_slot), first)?,
            )))
        })();
        self.namespace_work = buffers;
        result
    }

    pub(crate) fn finish_namespace_families<I: WriteIo>(
        &mut self,
        writer: &mut Writer,
        volume: &mut Volume<&mut I>,
    ) -> Result<()> {
        for base in 0..MAX_RECORDS {
            if self.rec_slot(base)[24] & (R_USED | R_DIRTY) == (R_USED | R_DIRTY)
                && self.preserved_family(base)
                && u64_at(self.record(base), 32)? == 0
            {
                let buffers = core::mem::take(&mut self.namespace_work);
                let family = core::mem::take(&mut self.family);
                let result = self.finish_namespace_family(writer, volume, base, buffers, family);
                self.namespace_work = buffers;
                self.family = family;
                result?;
            }
        }
        Ok(())
    }

    fn finish_namespace_family<I: WriteIo>(
        &mut self,
        writer: &mut Writer,
        volume: &mut Volume<&mut I>,
        base: usize,
        buffers: &mut [u8],
        family: &mut [u8],
    ) -> Result<()> {
        let (before, staging) = family.split_at_mut(RECORD);
        before.copy_from_slice(self.record_before(base));
        let old = raw_attribute(before, 0x20)?.ok_or(Error::InvalidAttributeList)?;
        let n = usize::try_from(old.data_size()?).map_err(|_| Error::Overflow)?;
        if buffers.len() < n * 2 + 8192 {
            return Err(Error::Truncated);
        }
        let (input, output) = buffers.split_at_mut(n);
        volume.read_attribute(old, 0, input)?;
        let mut used = 0;
        let mut external = false;
        let changed = &mut staging[..];
        let mut changed_used = 0;
        for slot in 0..MAX_RECORDS {
            if slot != base && !self.family_member(base, slot)? {
                continue;
            }
            let mut count = 0;
            for a in MftRecord::from_decoded(self.record(slot))?.attributes() {
                let a = a?;
                if a.kind == 0x20 {
                    continue;
                }
                count += 1;
                insert_entry(
                    changed,
                    &mut changed_used,
                    a.kind,
                    a.name_utf16le()?,
                    if a.nonresident { a.first_vcn()? } else { 0 },
                    self.record_reference(slot)?,
                    a.id,
                    self.upcase,
                )?;
            }
            if slot != base && count == 0 {
                let sequence = super::mft::next_sequence(self.record(slot))?;
                let number = self.record_number(slot);
                edit::format_empty(&mut self.record_mut(slot)[..RECORD], number)?;
                edit::p32(self.record_mut(slot), 28, RECORD as u32)?;
                edit::p16(self.record_mut(slot), 16, sequence)?;
                self.set_record_allocated(volume, self.record_number(slot), false)?;
            } else if slot != base {
                external = true;
            }
            self.rec_slot_mut(slot)[FAMILY_STATE] = FAMILY_PACKED;
        }
        // Both inputs are ordered. Copy untouched descriptors and merge the
        // bounded changed set in one pass, rather than sorting all DATA entries.
        let mut changes = AttributeList::new(&changed[..changed_used]);
        let mut next_change = changes.next().transpose()?;
        for entry in AttributeList::new(input) {
            let entry = entry?;
            let loaded = (0..MAX_RECORDS).any(|s| {
                self.rec_slot(s)[24] & R_USED != 0
                    && self.record_number(s) == reference_number(entry.file_reference)
                    && u16_at(self.record_before(s), 16).is_ok_and(|seq| seq == (entry.file_reference >> 48) as u16)
            });
            if loaded {
                continue;
            }
            while next_change.is_some_and(|e| entry_order(e, entry, self.upcase) != core::cmp::Ordering::Greater) {
                append_entry(output, &mut used, next_change.take().unwrap())?;
                next_change = changes.next().transpose()?;
            }
            append_entry(output, &mut used, entry)?;
            external = true;
        }
        while let Some(entry) = next_change {
            append_entry(output, &mut used, entry)?;
            next_change = changes.next().transpose()?;
        }
        let live = u16_at(self.record(base), 22)? & 1 != 0;
        if !live && external {
            return Err(Error::InvalidAttributeList);
        }
        if live && external {
            edit::p32(self.record_mut(base), 28, RECORD as u32)?;
            if input == &output[..used] && edit::used(self.record(base))? + old.raw().len() <= RECORD {
                edit::insert(self.record_mut(base), old.raw())?;
            } else {
                let clusters = (used as u64).div_ceil(BLOCK as u64);
                let lcn = self.allocate_clusters(volume, clusters, None)?;
                let block = &mut staging[..BLOCK];
                for i in 0..clusters as usize {
                    block.fill(0);
                    let from = i * BLOCK;
                    let to = used.min(from + BLOCK);
                    block[..to - from].copy_from_slice(&output[from..to]);
                    super::tx::stage(
                        writer,
                        &mut **volume.reader_mut(),
                        &[(lcn * BLOCK as u64 + from as u64, &*block)],
                        true,
                    )?;
                }
                let attr = &mut staging[BLOCK..BLOCK + RECORD];
                let len = edit::build_nonresident(
                    0x20,
                    &[],
                    &[Extent { vcn: 0, len: clusters, lcn: Some(lcn) }],
                    clusters * BLOCK as u64,
                    used as u64,
                    used as u64,
                    attr,
                )?;
                edit::insert(self.record_mut(base), &attr[..len])?;
                free_list(self, volume, old)?;
            }
        } else {
            free_list(self, volume, old)?;
        }
        // The list was checked before editing; untouched DATA members retain
        // their identities. Only the new metadata descriptors are published.
        edit::p32(self.record_mut(base), 28, RECORD as u32)?;
        edit::validate(self.record(base))?;
        self.rec_slot_mut(base)[FAMILY_STATE] = FAMILY_PACKED;
        // Keep namespace-only changes out of full stream-size refresh.
        self.rec_slot_mut(base)[SKIP_FILENAME_REFRESH] = 1;
        Ok(())
    }
}

fn free_list<R: ReadAt>(tx: &mut Tx<'_>, volume: &mut Volume<R>, attr: Attribute<'_>) -> Result<()> {
    if attr.nonresident {
        for r in super::runlist::DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
            let r = r?;
            if let Some(lcn) = r.lcn {
                tx.free_clusters(volume, lcn, r.len)?;
            }
        }
    }
    Ok(())
}

fn entry_order(a: ListEntry<'_>, b: ListEntry<'_>, upcase: &[u8]) -> core::cmp::Ordering {
    a.kind
        .cmp(&b.kind)
        .then_with(|| {
            a.name_utf16le
                .chunks_exact(2)
                .map(|b| fold_unit(upcase, u16::from_le_bytes([b[0], b[1]])))
                .cmp(b.name_utf16le.chunks_exact(2).map(|b| fold_unit(upcase, u16::from_le_bytes([b[0], b[1]]))))
        })
        .then(a.first_vcn.cmp(&b.first_vcn))
}

fn append_entry(out: &mut [u8], used: &mut usize, entry: ListEntry<'_>) -> Result<()> {
    *used += entry.encode(out.get_mut(*used..).ok_or(Error::Truncated)?)?;
    Ok(())
}

fn insert_entry(
    out: &mut [u8],
    used: &mut usize,
    kind: u32,
    name: &[u8],
    vcn: u64,
    reference: u64,
    id: u16,
    upcase: &[u8],
) -> Result<()> {
    let entry = ListEntry { kind, first_vcn: vcn, file_reference: reference, attribute_id: id, name_utf16le: name };
    let n = entry.encoded_len()?;
    if *used + n > out.len() {
        return Err(Error::Truncated);
    }
    let mut at = 0;
    for e in AttributeList::new(&out[..*used]) {
        let e = e?;
        if entry_order(entry, e, upcase) == core::cmp::Ordering::Less {
            break;
        }
        at += e.encoded_len()?;
    }
    out.copy_within(at..*used, at + n);
    let mut length = 0;
    append_entry(&mut out[at..at + n], &mut length, entry)?;
    *used += n;
    Ok(())
}

#[cfg(test)]
#[path = "../tests/core/namespace_family.rs"]
mod tests;
