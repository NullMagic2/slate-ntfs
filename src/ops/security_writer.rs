//! Module: ntfs_rs::security_writer
//! Purpose: Replace file security descriptors through the journal.
//! Created: 2026-10-01
//! Architecture: Writers reuse identical Secure entries or stage new SDS bytes and their
//! mirror before publishing SII/SDH indexes, Secure sizes/runs, bitmap changes
//! and the file's security ID together. Shared descriptors are never edited.

use super::bytes::{u16_at, u32_at, u64_at};
use super::index_tree::{IndexKind, T_NEW};
use super::mft::{reference_number, reference_sequence};
use super::mft::{Attribute, MftRecord};
use super::record_edit::{self, p16, p32, p64};
use super::resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES};
use super::security::{replacement_rights, security_hash, validate_storable, SdsEntry, SecurityDescriptor};
use super::tx::{stage, Tx, BLOCK};
use super::volume::{ReadAt, Volume};
use super::write_plan::plan_nonresident_recovery;
use super::{Error, Result};

const SDS: &[u8] = b"$\0S\0D\0S\0";
const SDS_BLOCK: u64 = 0x40000;
const FIRST_SECURITY_ID: u32 = 0x100;
const MAX_SCAN_NODES: usize = 65536;
const STACK_ENTRIES: usize = 4096;
const SECURE: u64 = 9;
/// Scratch for set_owner (and therefore any descriptor replacement).
pub const SECURITY_SCRATCH_BYTES: usize = METADATA_SCRATCH_BYTES + 0x20000 + 4096;

/// Caller identity used for authorization of a descriptor replacement.
pub trait SecurityPolicy {
    /// Ordered DACL check of rights against the file's current descriptor.
    fn allowed(&self, current: SecurityDescriptor<'_>, rights: u32) -> Result<bool>;
    /// The caller's user SID: the only owner assignable without privileges.
    fn user_sid(&self) -> Result<&[u8]>;
    /// Explicitly enabled native privileges, supplied by the trusted adapter.
    /// Defaults grant nothing, including to root or Administrators.
    fn privileges(&self) -> SecurityPrivileges {
        SecurityPrivileges::default()
    }
}

#[derive(Clone, Copy, Default)]
pub struct SecurityPrivileges {
    pub security: bool,
    pub restore: bool,
    pub take_ownership: bool,
    /// Mandatory integrity RID of the mapped token; 0 means the default
    /// medium level (S-1-16-8192).
    pub integrity: u32,
}

impl SecurityPrivileges {
    pub fn integrity_level(&self) -> u32 {
        if self.integrity == 0 {
            super::security::INTEGRITY_MEDIUM
        } else {
            self.integrity
        }
    }
}

/// Authorize each changed component independently. Restore does not imply
/// SeSecurityPrivilege; take-ownership never permits assigning a foreign SID.
pub fn authorize_replacement<P: SecurityPolicy>(
    old: SecurityDescriptor<'_>,
    new: SecurityDescriptor<'_>,
    policy: &P,
) -> Result<u32> {
    use super::security::{ACCESS_SYSTEM_SECURITY, WRITE_DAC, WRITE_OWNER};
    let requested = replacement_rights(old, new)?;
    let mut rights = requested;
    let grants = policy.privileges();
    if rights & ACCESS_SYSTEM_SECURITY != 0 {
        if !grants.security {
            return Err(Error::NotPermitted);
        }
        rights &= !ACCESS_SYSTEM_SECURITY;
    }
    if grants.restore {
        rights &= !(WRITE_DAC | WRITE_OWNER);
    }
    if grants.take_ownership {
        rights &= !WRITE_OWNER;
    }
    if rights != 0 && !policy.allowed(old, rights)? {
        return Err(Error::AccessDenied);
    }
    if old.owner.map(|s| s.raw()) != new.owner.map(|s| s.raw())
        && new.owner.map(|s| s.raw()) != Some(policy.user_sid()?)
        && !grants.restore
    {
        return Err(Error::NotPermitted);
    }
    Ok(requested)
}

struct Scan {
    max_id: u32,
    max_end: u64,
    found: Option<u32>,
}

/// Visit every $SII entry through the resident root and allocated blocks.
/// Collects the largest ID and SDS end, and finds an identical descriptor
/// whose primary and mirror copies both verify.
#[allow(clippy::too_many_arguments)]
fn scan_sii<R: ReadAt>(
    volume: &mut Volume<R>,
    secure: &[u8],
    descriptor: &[u8],
    hash: u32,
    block: &mut [u8],
    compare: &mut [u8],
    chunk: &mut [u8],
    stack: &mut [u8],
) -> Result<Scan> {
    let mut scan = Scan { max_id: 0, max_end: 0, found: None };
    let sds_at = record_edit::require(secure, 0x80, SDS)?;
    let sds = MftRecord::from_decoded(secure)?.attribute_at(sds_at)?;
    let root_at = record_edit::require(secure, 0x90, IndexKind::SecurityId.name())?;
    let root = record_edit::resident_value(secure, root_at)?;
    let alloc = record_edit::find(secure, 0xa0, IndexKind::SecurityId.name())?;
    let bitmap = record_edit::find(secure, 0xb0, IndexKind::SecurityId.name())?;
    let mut depth = 0_usize;
    let mut visit = |data: &[u8],
                     h: usize,
                     stack: &mut [u8],
                     depth: &mut usize,
                     scan: &mut Scan,
                     volume: &mut Volume<R>|
     -> Result<()> {
        let mut at = h + u32_at(data, h)? as usize;
        let end = h + u32_at(data, h + 4)? as usize;
        let node_large = data[h + 12] & 1 != 0;
        loop {
            let len = usize::from(u16_at(data, at + 8)?);
            let flags = u16_at(data, at + 12)?;
            if len < 16 || at + len > end || (flags & 1 != 0) != node_large {
                return Err(Error::InvalidIndex);
            }
            if flags & 1 != 0 {
                if *depth == STACK_ENTRIES {
                    return Err(Error::Unsupported);
                }
                let vcn = u64_at(data, at + len - 8)?;
                stack[*depth * 8..*depth * 8 + 8].copy_from_slice(&vcn.to_le_bytes());
                *depth += 1;
            }
            if flags & 2 != 0 {
                return Ok(());
            }
            let key_len = usize::from(u16_at(data, at + 10)?);
            let offset = usize::from(u16_at(data, at)?);
            let size = usize::from(u16_at(data, at + 2)?);
            if key_len != 4 || size != 20 || offset < 20 || offset + 20 > len {
                return Err(Error::InvalidSecurity);
            }
            let id = u32_at(data, at + 16)?;
            let header = &data[at + offset..at + offset + 20];
            let entry_offset = u64_at(header, 8)?;
            let entry_size = u32_at(header, 16)? as u64;
            if u32_at(header, 4)? != id || entry_offset % 16 != 0 || entry_size < 40 {
                return Err(Error::InvalidSecurity);
            }
            scan.max_id = scan.max_id.max(id);
            scan.max_end = scan.max_end.max((entry_offset + entry_size + 15) & !15);
            if scan.found.is_none() && u32_at(header, 0)? == hash && entry_size as usize == 20 + descriptor.len() {
                let n = entry_size as usize;
                let candidate = &mut compare[..n];
                let ok = volume.read_attribute(sds, entry_offset, candidate).is_ok()
                    && SdsEntry::parse(candidate, entry_offset).is_ok_and(|e| e.matches_index_header(header))
                    && &candidate[20..] == descriptor;
                if ok {
                    // Reuse only an entry whose mirror copy is byte-identical.
                    let mut same = true;
                    for (i, expected) in compare[..n].chunks(chunk.len()).enumerate() {
                        let bytes = &mut chunk[..expected.len()];
                        let at = entry_offset + SDS_BLOCK + (i * bytes.len()) as u64;
                        if volume.read_attribute(sds, at, bytes).is_err() || bytes != expected {
                            same = false;
                            break;
                        }
                    }
                    if same {
                        scan.found = Some(id);
                    }
                }
            }
            at += len;
        }
    };
    visit(root, 16, stack, &mut depth, &mut scan, volume)?;
    let mut visited = 0;
    while depth > 0 {
        depth -= 1;
        let vcn = u64_at(stack, depth * 8)?;
        visited += 1;
        if visited > MAX_SCAN_NODES {
            return Err(Error::Unsupported);
        }
        let alloc_at = alloc.ok_or(Error::InvalidIndex)?;
        let alloc = MftRecord::from_decoded(secure)?.attribute_at(alloc_at)?;
        let bitmap_at = bitmap.ok_or(Error::InvalidIndex)?;
        let bitmap = MftRecord::from_decoded(secure)?.attribute_at(bitmap_at)?;
        let mut bit = [0];
        volume.read_attribute(bitmap, vcn / 8, &mut bit)?;
        if bit[0] & (1 << (vcn % 8)) == 0 {
            return Err(Error::InvalidIndex);
        }
        volume.read_attribute(alloc, vcn * BLOCK as u64, &mut block[..BLOCK])?;
        super::index::IndexBlock::parse(&mut block[..BLOCK], 512, vcn)?;
        visit(&block[..BLOCK], 24, stack, &mut depth, &mut scan, volume)?;
    }
    Ok(scan)
}

/// Write data at offset of a nonresident stream through its mapping.
/// The complete mapping is validated before the first write.
fn stage_stream<I: WriteIo>(
    writer: &mut Writer,
    io: &mut I,
    attr: Attribute<'_>,
    boot: super::boot::BootSector,
    offset: u64,
    data: &[u8],
) -> Result<()> {
    plan_nonresident_recovery(attr, boot, offset, data.len() as u64, |_| Ok(()))?;
    plan_nonresident_recovery(attr, boot, offset, data.len() as u64, |s| {
        let from = s.source_offset as usize;
        let to = from + s.length as usize;
        stage(writer, io, &[(s.physical_offset, &data[from..to])], true)
    })?;
    Ok(())
}

impl Writer {
    /// Replace the security descriptor of one base record. policy decides
    /// access against the current descriptor; the whole change is one
    /// journaled transaction. Identical bytes are a successful no-op.
    pub fn set_security<I: WriteIo, P: SecurityPolicy>(
        &mut self,
        io: &mut I,
        reference: u64,
        descriptor: &[u8],
        policy: &P,
        scratch: &mut [u8],
    ) -> Result<()> {
        if !self.initialized || self.failed {
            return Err(Error::Io);
        }
        if scratch.len() < METADATA_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let number = reference_number(reference);
        if reference_sequence(reference) == 0 || !(number == 5 || number >= 16) {
            return Err(Error::Unsupported);
        }
        let new = validate_storable(descriptor)?;
        let boot = self.boot;
        let mut volume = Volume::new(&mut *io, boot)?;
        let (mut tx, rest) = Tx::new(self, &mut volume, scratch)?;
        let (journal, rest) = rest.split_at_mut(64 * 1024);
        let (current, rest) = rest.split_at_mut(0x20014 + 12);
        let (compare, rest) = rest.split_at_mut(0x20014 + 12);
        let (chunk, rest) = rest.split_at_mut(BLOCK);
        let (secure_buf, rest) = rest.split_at_mut(1024);
        let (block, rest) = rest.split_at_mut(BLOCK);
        let (stack, _) = rest.split_at_mut_checked(STACK_ENTRIES * 8).ok_or(Error::Truncated)?;
        let file = tx.load_family(&mut volume, reference)?;
        if u64_at(tx.record(file), 8)? > self.current_lsn {
            return Err(Error::Unsupported);
        }
        // Authorize against the current descriptor, resolved exactly as reads are.
        {
            let mft = MftRecord::from_decoded(tx.mft_zero())?;
            let record = MftRecord::from_decoded(tx.record(file))?;
            let old = super::security_store::read_descriptor(&mut volume, &mft, &record, secure_buf, block, current)?;
            let rights = authorize_replacement(old, new, policy)?;
            if rights == 0 {
                return Ok(());
            }
        }
        let secure = tx.load_family(&mut volume, SECURE)?;
        if u64_at(tx.record(secure), 8)? > self.current_lsn {
            return Err(Error::Unsupported);
        }
        let hash = security_hash(descriptor);
        let scan = scan_sii(&mut volume, tx.record(secure), descriptor, hash, block, compare, chunk, stack)?;
        let id = match scan.found {
            Some(id) => id,
            None => {
                let id = scan.max_id.checked_add(1).ok_or(Error::NoSpace)?.max(FIRST_SECURITY_ID);
                self.append_descriptor(&mut tx, &mut volume, secure, id, hash, descriptor, scan.max_end, current)?;
                id
            }
        };
        // Point the file at the descriptor; drop any legacy inline copy.
        if let Some(at) = record_edit::find(tx.record(file), 0x50, &[])? {
            if record_edit::is_nonresident(tx.record(file), at)? {
                tx.free_attribute_runs(&mut volume, file, at)?;
            }
            record_edit::remove(tx.record_mut(file), at)?;
        }
        let si = record_edit::require(tx.record(file), 0x10, &[])?;
        let value = record_edit::resident_value(tx.record(file), si)?;
        if value.len() >= 72 {
            let offset = record_edit::resident_value_offset(tx.record(file), si)?;
            p32(tx.record_mut(file), offset + 0x34, id)?;
        } else if value.len() == 48 {
            let mut upgraded = [0_u8; 72];
            upgraded[..48].copy_from_slice(value);
            upgraded[0x34..0x38].copy_from_slice(&id.to_le_bytes());
            record_edit::set_resident_value(tx.record_mut(file), si, &upgraded)?;
        } else {
            return Err(Error::InvalidAttribute);
        }
        drop(volume);
        tx.commit(self, io, journal)
    }

    /// Replace only the owner and/or primary group of the current descriptor,
    /// preserving its control word, SACL and DACL bytes (Linux chown).
    pub fn set_owner<I: WriteIo, P: SecurityPolicy>(
        &mut self,
        io: &mut I,
        reference: u64,
        owner: Option<&[u8]>,
        group: Option<&[u8]>,
        policy: &P,
        scratch: &mut [u8],
    ) -> Result<()> {
        if scratch.len() < SECURITY_SCRATCH_BYTES {
            return Err(Error::Truncated);
        }
        let (work, rest) = scratch.split_at_mut(METADATA_SCRATCH_BYTES);
        let (descriptor, rest) = rest.split_at_mut(0x20000);
        let (record, _) = rest.split_at_mut(4096);
        let length = {
            let mut volume = Volume::new(&mut *io, self.boot)?;
            let (zero, rest) = record.split_at_mut(1024);
            let (file_buf, rest) = rest.split_at_mut(1024);
            let (secure_buf, _) = rest.split_at_mut(1024);
            volume.read_mft_zero(zero)?;
            let mft = MftRecord::parse(zero, 512)?;
            volume.read_mft_record(&mft, reference_number(reference), file_buf)?;
            let file = MftRecord::parse(file_buf, 512)?;
            if u64::from(file.sequence_number()?) != reference >> 48 {
                return Err(Error::InvalidRecord);
            }
            let (index, current) = work.split_at_mut(BLOCK);
            let old = super::security_store::read_descriptor(
                &mut volume,
                &mft,
                &file,
                secure_buf,
                index,
                &mut current[..0x20014 + 12],
            )?;
            let unchanged = |new: Option<&[u8]>, old: Option<super::security::Sid<'_>>| {
                new.is_none() || new == old.map(|s| s.raw())
            };
            if unchanged(owner, old.owner) && unchanged(group, old.group) {
                return Ok(());
            }
            super::security::replace_owner_group(old, owner, group, descriptor)?
        };
        self.set_security(io, reference, &descriptor[..length], policy, work)
    }

    /// Stage a new $SDS entry and its mirror, grow $SDS if needed, and
    /// insert matching $SII/$SDH entries in the pending transaction.
    #[allow(clippy::too_many_arguments)]
    fn append_descriptor<R: WriteIo>(
        &mut self,
        tx: &mut Tx<'_>,
        volume: &mut Volume<&mut R>,
        secure: usize,
        id: u32,
        hash: u32,
        descriptor: &[u8],
        max_end: u64,
        entry: &mut [u8],
    ) -> Result<()> {
        let boot = self.boot;
        let sds_at = record_edit::require(tx.record(secure), 0x80, SDS)?;
        let (allocated, data, initialized) = record_edit::sizes(tx.record(secure), sds_at)?;
        if data != initialized || allocated % BLOCK as u64 != 0 {
            return Err(Error::Unsupported);
        }
        let size = 20 + descriptor.len();
        let aligned = ((size + 15) & !15) as u64;
        let mut next = max_end.max(data.saturating_sub(SDS_BLOCK).div_ceil(16) * 16);
        if next % (2 * SDS_BLOCK) >= SDS_BLOCK {
            next = next / (2 * SDS_BLOCK) * (2 * SDS_BLOCK) + 2 * SDS_BLOCK;
        }
        let left = SDS_BLOCK - next % SDS_BLOCK;
        if left < size as u64 {
            next += left + SDS_BLOCK;
        }
        let mirror = next + SDS_BLOCK;
        let needed = mirror + aligned;
        if needed > data {
            let mut allocated = allocated;
            if needed > allocated {
                let clusters = (needed - allocated).div_ceil(BLOCK as u64);
                let hint = record_edit::last_run_end(tx.record(secure), sds_at)?;
                let lcn = tx.allocate_clusters(volume, clusters, hint)?;
                record_edit::append_run(tx.record_mut(secure), sds_at, lcn, clusters)?;
                allocated += clusters * BLOCK as u64;
            }
            let sds_at = record_edit::require(tx.record(secure), 0x80, SDS)?;
            record_edit::set_sizes(tx.record_mut(secure), sds_at, allocated, needed, needed)?;
        }
        // Build the entry: header, descriptor, zero padding to 16 bytes.
        let entry = entry.get_mut(..aligned as usize).ok_or(Error::Truncated)?;
        entry.fill(0);
        p32(entry, 0, hash)?;
        p32(entry, 4, id)?;
        p64(entry, 8, next)?;
        p32(entry, 16, size as u32)?;
        entry[20..size].copy_from_slice(descriptor);
        SdsEntry::parse(&entry[..size], next)?;
        {
            let sds_at = record_edit::require(tx.record(secure), 0x80, SDS)?;
            let sds = MftRecord::from_decoded(tx.record(secure))?.attribute_at(sds_at)?;
            if needed > data {
                // Newly valid bytes read as zeros, never as stale disk data.
                let zeros = [0_u8; 4096];
                let mut at = data;
                while at < needed {
                    let n = (needed - at).min(zeros.len() as u64 - at % zeros.len() as u64);
                    stage_stream(self, &mut **volume.reader_mut(), sds, boot, at, &zeros[..n as usize])?;
                    at += n;
                }
            }
            stage_stream(self, &mut **volume.reader_mut(), sds, boot, next, entry)?;
            stage_stream(self, &mut **volume.reader_mut(), sds, boot, mirror, entry)?;
        }
        // Index both keys. $SII: key ID, data = SDS header.
        let header = [0_u8; 20];
        let _ = header;
        {
            let e = tx.temp_mut(T_NEW);
            e[..40].fill(0);
            p16(e, 0, 20)?;
            p16(e, 2, 20)?;
            p16(e, 8, 40)?;
            p16(e, 10, 4)?;
            p32(e, 16, id)?;
            e[20..40].copy_from_slice(&entry[..20]);
        }
        let sii = tx.open_tree(secure, IndexKind::SecurityId)?;
        tx.tree_insert(volume, &sii, T_NEW)?;
        // $SDH: key (hash, ID), data = SDS header, then the "II" padding.
        {
            let e = tx.temp_mut(T_NEW);
            e[..48].fill(0);
            p16(e, 0, 24)?;
            p16(e, 2, 20)?;
            p16(e, 8, 48)?;
            p16(e, 10, 8)?;
            p32(e, 16, hash)?;
            p32(e, 20, id)?;
            e[24..44].copy_from_slice(&entry[..20]);
            e[44..48].copy_from_slice(b"I\0I\0");
        }
        let sdh = tx.open_tree(secure, IndexKind::SecurityHash)?;
        tx.tree_insert(volume, &sdh, T_NEW)?;
        tx.tree_check(&sii)?;
        tx.tree_check(&sdh)
    }
}
