//! Module: ntfs_rs::index_tree
//! Purpose: Edit directory and Secure index B-trees over transaction images.
//! Created: 2026-10-01
//! Architecture: I30, SII and SDH operations search, split, replace, remove and collapse nodes;
//! index allocation and bitmap growth share the transaction. Adapters provide
//! 4 KiB index blocks equal to cluster size. Only Tx commit publishes edits.

use super::bytes::{u16_at, u32_at, u64_at, units};
use super::index::IndexBlock;
use super::mft::MftRecord;
use super::record_edit::{self, p16, p32, p64};
use super::runlist::Extent;
use super::tx::*;
use super::upcase::fold_unit;
use super::volume::{ReadAt, Volume};
use super::{Error, Result};
use core::cmp::Ordering;

pub const I30: &[u8] = b"$\0I\x003\x000\0";
pub const SII: &[u8] = b"$\0S\0I\0I\0";
pub const SDH: &[u8] = b"$\0S\0D\0H\0";
pub const R: &[u8] = b"$\0R\0";
const MAX_DEPTH: usize = 32;
const BLOCK_TOTAL: usize = BLOCK - 24;
/// Temporary entry buffers inside Tx.
pub const T_NEW: usize = 0;
const T_UP: usize = 1;
const T_RE: usize = 2;
const T_ME: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexKind {
    Directory,
    SecurityId,
    SecurityHash,
    /// $Extend\$Reparse:$R: key {reparse tag, file reference}, no data.
    Reparse,
}

impl IndexKind {
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Directory => I30,
            Self::SecurityId => SII,
            Self::SecurityHash => SDH,
            Self::Reparse => R,
        }
    }
    fn code(self) -> u8 {
        match self {
            Self::Directory => 0,
            Self::SecurityId => 1,
            Self::SecurityHash => 2,
            Self::Reparse => 3,
        }
    }
    pub(crate) fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Directory),
            1 => Ok(Self::SecurityId),
            2 => Ok(Self::SecurityHash),
            3 => Ok(Self::Reparse),
            _ => Err(Error::InvalidIndex),
        }
    }
    fn indexed_type(self) -> u32 {
        match self {
            Self::Directory => 0x30,
            _ => 0,
        }
    }
    fn collation(self) -> u32 {
        match self {
            Self::Directory => 1,
            Self::SecurityId => 0x10,
            Self::SecurityHash => 0x12,
            Self::Reparse => 0x13,
        }
    }
}

/// An index opened in a loaded record slot. The root lives in a node slot and
/// is written back into the record after every structural change.
#[derive(Clone, Copy, Debug)]
pub struct Tree {
    pub kind: IndexKind,
    pub record: usize,
    root: usize,
}
impl Tree {
    fn id(&self) -> u8 {
        ((self.record as u8) << 2) | self.kind.code()
    }
}

struct Path {
    node: [u8; MAX_DEPTH + 2],
    at: [u16; MAX_DEPTH + 2],
    depth: usize,
    found: bool,
    collision: bool,
}

// ----- Entry and node helpers on decoded buffers ---------------------------

fn first(w: &[u8], h: usize) -> Result<usize> {
    Ok(h + u32_at(w, h)? as usize)
}
fn end(w: &[u8], h: usize) -> Result<usize> {
    Ok(h + u32_at(w, h + 4)? as usize)
}
fn elen(w: &[u8], at: usize) -> Result<usize> {
    Ok(usize::from(u16_at(w, at + 8)?))
}
fn eflags(w: &[u8], at: usize) -> Result<u16> {
    u16_at(w, at + 12)
}
fn is_last(w: &[u8], at: usize) -> Result<bool> {
    Ok(eflags(w, at)? & 2 != 0)
}
fn has_child(w: &[u8], at: usize) -> Result<bool> {
    Ok(eflags(w, at)? & 1 != 0)
}
fn child(w: &[u8], at: usize) -> Result<u64> {
    if !has_child(w, at)? {
        return Err(Error::InvalidIndex);
    }
    u64_at(w, at + elen(w, at)? - 8)
}
fn set_child(w: &mut [u8], at: usize, vcn: u64) -> Result<()> {
    if !has_child(w, at)? {
        return Err(Error::InvalidIndex);
    }
    let n = elen(w, at)?;
    p64(w, at + n - 8, vcn)
}
fn key(w: &[u8], at: usize) -> Result<&[u8]> {
    let n = usize::from(u16_at(w, at + 10)?);
    w.get(at + 16..at + 16 + n).ok_or(Error::InvalidIndex)
}
fn large(w: &[u8], h: usize) -> bool {
    w[h + 12] & 1 != 0
}

/// Structural validation of one node's index header and entry chain.
fn validate_node(w: &[u8], h: usize, block: bool) -> Result<()> {
    let first_off = u32_at(w, h)? as usize;
    let used = u32_at(w, h + 4)? as usize;
    let total = u32_at(w, h + 8)? as usize;
    let flags = *w.get(h + 12).ok_or(Error::Truncated)?;
    if first_off < 16
        || first_off % 8 != 0
        || first_off > used
        || used > total
        || h + total > w.len()
        || flags > 1
        || (block && total != BLOCK_TOTAL)
    {
        return Err(Error::InvalidIndex);
    }
    let mut at = h + first_off;
    let stop = h + used;
    loop {
        let n = elen(w, at)?;
        let f = eflags(w, at)?;
        let k = usize::from(u16_at(w, at + 10)?);
        let with_child = f & 1 != 0;
        if n < 16
            || n % 8 != 0
            || at + n > stop
            || f & !3 != 0
            || with_child != (flags == 1)
            || 16 + k + if with_child { 8 } else { 0 } > n
        {
            return Err(Error::InvalidIndex);
        }
        if f & 2 != 0 {
            return if at + n == stop { Ok(()) } else { Err(Error::InvalidIndex) };
        }
        at += n;
    }
}

/// Validate a decoded, unprotected 4 KiB INDX image before publication.
pub fn validate_block(b: &[u8]) -> Result<()> {
    if b.len() != BLOCK
        || b.get(..4) != Some(b"INDX")
        || u16_at(b, 4)? != 0x28
        || u16_at(b, 6)? != 9
        || u32_at(b, 24)? < 0x28
    {
        return Err(Error::InvalidIndex);
    }
    validate_node(b, 24, true)
}

fn format_block(w: &mut [u8], vcn: u64, large_node: bool) -> Result<()> {
    w[..NODE_WORK].fill(0);
    w[..4].copy_from_slice(b"INDX");
    p16(w, 4, 0x28)?;
    p16(w, 6, 9)?;
    p64(w, 16, vcn)?;
    let end_len = if large_node { 24 } else { 16 };
    p32(w, 24, 0x28)?;
    p32(w, 28, (0x28 + end_len) as u32)?;
    p32(w, 32, BLOCK_TOTAL as u32)?;
    w[36] = u8::from(large_node);
    p16(w, 0x40 + 8, end_len as u16)?;
    p16(w, 0x40 + 12, if large_node { 3 } else { 2 })?;
    Ok(())
}

fn file_name(k: &[u8]) -> Result<&[u8]> {
    super::filename::FileNameValue::parse_prefix(k).map(|value| value.name.utf16le).map_err(|_| Error::InvalidIndex)
}
/// NTFS file-name collation: upcased code units, then length, then the
/// first exact code-unit difference (ntfs3 ntfs_cmp_names with both cases).
pub fn compare_names(table: &[u8], a: &[u8], b: &[u8]) -> Ordering {
    for (x, y) in units(a).zip(units(b)) {
        let (ux, uy) = (fold_unit(table, x), fold_unit(table, y));
        if ux != uy {
            return ux.cmp(&uy);
        }
    }
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for (x, y) in units(a).zip(units(b)) {
        if x != y {
            return x.cmp(&y);
        }
    }
    Ordering::Equal
}
pub fn names_equal_ignoring_case(table: &[u8], a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && units(a).zip(units(b)).all(|(x, y)| fold_unit(table, x) == fold_unit(table, y))
}
fn compare(kind: IndexKind, table: &[u8], a: &[u8], b: &[u8]) -> Result<Ordering> {
    Ok(match kind {
        IndexKind::Directory => compare_names(table, file_name(a)?, file_name(b)?),
        IndexKind::SecurityId => {
            if a.len() != 4 || b.len() != 4 {
                return Err(Error::InvalidIndex);
            }
            u32_at(a, 0)?.cmp(&u32_at(b, 0)?)
        }
        IndexKind::SecurityHash => {
            if a.len() != 8 || b.len() != 8 {
                return Err(Error::InvalidIndex);
            }
            (u32_at(a, 0)?, u32_at(a, 4)?).cmp(&(u32_at(b, 0)?, u32_at(b, 4)?))
        }
        // COLLATION_NTOFS_ULONGS: little-endian 32-bit words, first to last.
        IndexKind::Reparse => {
            if a.len() != 12 || b.len() != 12 {
                return Err(Error::InvalidIndex);
            }
            (u32_at(a, 0)?, u32_at(a, 4)?, u32_at(a, 8)?).cmp(&(u32_at(b, 0)?, u32_at(b, 4)?, u32_at(b, 8)?))
        }
    })
}

/// Build a $Reparse:$R view-index entry (ntfs-3g/Windows layout).
pub fn reparse_entry(tag: u32, reference: u64, out: &mut [u8]) -> Result<usize> {
    let e = out.get_mut(..32).ok_or(Error::Truncated)?;
    e.fill(0);
    p16(e, 0, 28)?; // data offset: header + key
    p16(e, 8, 32)?;
    p16(e, 10, 12)?;
    p32(e, 16, tag)?;
    p64(e, 20, reference)?;
    Ok(32)
}

/// Build a directory index entry from a $FILE_NAME value.
pub fn directory_entry(reference: u64, file_name_value: &[u8], out: &mut [u8]) -> Result<usize> {
    let k = file_name_value.len();
    if !(super::filename::HEADER_BYTES..=super::filename::MAX_VALUE_BYTES).contains(&k)
        || file_name(file_name_value)?.len() + super::filename::HEADER_BYTES != k
    {
        return Err(Error::InvalidAttribute);
    }
    let n = (16 + k + 7) & !7;
    let e = out.get_mut(..n).ok_or(Error::Truncated)?;
    e.fill(0);
    p64(e, 0, reference)?;
    p16(e, 8, n as u16)?;
    p16(e, 10, k as u16)?;
    e[16..16 + k].copy_from_slice(file_name_value);
    Ok(n)
}

impl<'s> Tx<'s> {
    // ----- Node slot access ------------------------------------------------
    fn nhead(&self, i: usize) -> &[u8] {
        &self.nodes[i * NODE_SLOT..i * NODE_SLOT + NODE_HEAD]
    }
    fn nflags(&self, i: usize) -> u8 {
        self.nhead(i)[0]
    }
    fn set_nflags(&mut self, i: usize, flags: u8) {
        self.nodes[i * NODE_SLOT] = flags;
    }
    fn nvcn(&self, i: usize) -> u64 {
        u64_at(self.nhead(i), 8).unwrap_or(u64::MAX)
    }
    fn nw(&self, i: usize) -> &[u8] {
        let base = i * NODE_SLOT + NODE_HEAD + BLOCK;
        &self.nodes[base..base + NODE_WORK]
    }
    fn nw_mut(&mut self, i: usize) -> &mut [u8] {
        self.nodes[i * NODE_SLOT] |= N_DIRTY;
        let base = i * NODE_SLOT + NODE_HEAD + BLOCK;
        &mut self.nodes[base..base + NODE_WORK]
    }
    fn nh(&self, i: usize) -> usize {
        if self.nflags(i) & N_ROOT != 0 {
            16
        } else {
            24
        }
    }
    fn tmp(&self, t: usize) -> &[u8] {
        &self.temp[t * TEMP..(t + 1) * TEMP]
    }
    pub fn temp_mut(&mut self, t: usize) -> &mut [u8] {
        &mut self.temp[t * TEMP..(t + 1) * TEMP]
    }
    pub fn temp(&self, t: usize) -> &[u8] {
        self.tmp(t)
    }
    fn new_slot(&mut self) -> Result<usize> {
        (0..MAX_NODES).find(|&i| self.nflags(i) == 0).ok_or(Error::Unsupported)
    }
    fn is_empty_node(&self, i: usize) -> Result<bool> {
        let (w, h) = (self.nw(i), self.nh(i));
        is_last(w, first(w, h)?)
    }

    fn insert_raw(&mut self, n: usize, at: usize, t: usize) -> Result<()> {
        let len = elen(self.tmp(t), 0)?;
        let h = self.nh(n);
        let (temp, nodes) = (&self.temp[t * TEMP..t * TEMP + len], &mut self.nodes);
        nodes[n * NODE_SLOT] |= N_DIRTY;
        let base = n * NODE_SLOT + NODE_HEAD + BLOCK;
        let w = &mut nodes[base..base + NODE_WORK];
        let stop = end(w, h)?;
        if at < first(w, h)? || at > stop || stop + len > NODE_WORK {
            return Err(Error::InvalidIndex);
        }
        w.copy_within(at..stop, at + len);
        w[at..at + len].copy_from_slice(temp);
        let used = u32_at(w, h + 4)? + len as u32;
        p32(w, h + 4, used)?;
        if h == 16 {
            p32(w, h + 8, used)?;
        }
        Ok(())
    }

    /// Remove the entry at at, copying it into temp buffer save if given.
    fn remove_raw(&mut self, n: usize, at: usize, save: Option<usize>) -> Result<()> {
        let h = self.nh(n);
        let len = elen(self.nw(n), at)?;
        if len > TEMP || is_last(self.nw(n), at)? {
            return Err(Error::InvalidIndex);
        }
        if let Some(t) = save {
            let base = n * NODE_SLOT + NODE_HEAD + BLOCK;
            self.temp[t * TEMP..t * TEMP + len].copy_from_slice(&self.nodes[base + at..base + at + len]);
        }
        let w = self.nw_mut(n);
        let stop = end(w, h)?;
        w.copy_within(at + len..stop, at);
        w[stop - len..stop].fill(0);
        let used = u32_at(w, h + 4)? - len as u32;
        p32(w, h + 4, used)?;
        if h == 16 {
            p32(w, h + 8, used)?;
        }
        Ok(())
    }

    fn find_child_entry(&self, n: usize, vcn: u64) -> Result<usize> {
        let (w, h) = (self.nw(n), self.nh(n));
        let mut at = first(w, h)?;
        loop {
            if has_child(w, at)? && child(w, at)? == vcn {
                return Ok(at);
            }
            if is_last(w, at)? {
                return Err(Error::InvalidIndex);
            }
            at += elen(w, at)?;
        }
    }

    // ----- Opening and loading ---------------------------------------------

    /// Open the named index of a loaded record. The root header must describe
    /// the supported collation and 4 KiB block geometry.
    pub fn open_tree(&mut self, record: usize, kind: IndexKind) -> Result<Tree> {
        if kind == IndexKind::Directory && !self.upcase_loaded {
            return Err(Error::Unsupported);
        }
        for i in 0..MAX_NODES {
            if self.nflags(i) & N_ROOT != 0 && self.nhead(i)[1] == (((record as u8) << 2) | kind.code()) {
                return Ok(Tree { kind, record, root: i });
            }
        }
        let rec = self.record(record);
        let at = record_edit::require(rec, 0x90, kind.name())?;
        let value = record_edit::resident_value(rec, at)?;
        if value.len() < 32
            || value.len() > NODE_WORK
            || u32_at(value, 0)? != kind.indexed_type()
            || u32_at(value, 4)? != kind.collation()
            || u32_at(value, 8)? as usize != BLOCK
            || value[12] != 1
        {
            return Err(Error::Unsupported);
        }
        let len = value.len();
        let slot = self.new_slot()?;
        let base = slot * NODE_SLOT;
        let (records, nodes) = (&self.records, &mut self.nodes);
        let rec = &records[record * REC_SLOT + REC_HEAD + RECORD..(record + 1) * REC_SLOT];
        let value = record_edit::resident_value(rec, at)?;
        nodes[base..base + NODE_SLOT].fill(0);
        nodes[base] = N_USED | N_ROOT;
        nodes[base + 1] = ((record as u8) << 2) | kind.code();
        nodes[base + NODE_HEAD + BLOCK..base + NODE_HEAD + BLOCK + len].copy_from_slice(value);
        let w = self.nw(slot);
        if 16 + u32_at(w, 16 + 8)? as usize > len {
            return Err(Error::InvalidIndex);
        }
        validate_node(w, 16, false)?;
        // Keep the root tight: its allocated size always equals its used size.
        let used = u32_at(w, 16 + 4)?;
        p32(self.nw_mut(slot), 16 + 8, used)?;
        let f = self.nflags(slot);
        self.set_nflags(slot, f & !N_DIRTY);
        Ok(Tree { kind, record, root: slot })
    }

    fn index_bit<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, bit: u64) -> Result<bool> {
        let rec = self.record(tree.record);
        let at = record_edit::require(rec, 0xb0, tree.kind.name())?;
        if !record_edit::is_nonresident(rec, at)? {
            let value = record_edit::resident_value(rec, at)?;
            return Ok(value.get((bit / 8) as usize).is_some_and(|b| b & (1 << (bit % 8)) != 0));
        }
        self.claim_aux(tree)?;
        let rec = &self.records[tree.record * REC_SLOT + REC_HEAD + RECORD..(tree.record + 1) * REC_SLOT];
        let attr = MftRecord::from_decoded(rec)?.attribute_at(at)?;
        if bit >= attr.data_size()? * 8 {
            return Ok(false);
        }
        self.aux_bits.is_set(volume, attr, bit)
    }

    fn claim_aux(&mut self, tree: &Tree) -> Result<()> {
        match self.aux_owner {
            None => {
                self.aux_owner = Some((tree.record, tree.kind.code()));
                Ok(())
            }
            Some(owner) if owner == (tree.record, tree.kind.code()) => Ok(()),
            _ => Err(Error::Unsupported),
        }
    }

    fn set_index_bit<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, bit: u64, on: bool) -> Result<()> {
        let rec = self.record(tree.record);
        let at = record_edit::require(rec, 0xb0, tree.kind.name())?;
        if record_edit::is_nonresident(rec, at)? {
            self.claim_aux(tree)?;
            let rec = &self.records[tree.record * REC_SLOT + REC_HEAD + RECORD..(tree.record + 1) * REC_SLOT];
            let attr = MftRecord::from_decoded(rec)?.attribute_at(at)?;
            let limit = attr.data_size()? * 8;
            return self.aux_bits.change(volume, attr, bit, 1, on, limit);
        }
        let old = record_edit::resident_value(rec, at)?;
        let mut value = [0_u8; 512];
        let byte = (bit / 8) as usize;
        let len = if byte < old.len() {
            old.len()
        } else if on {
            (byte + 8) & !7
        } else {
            return Err(Error::InvalidIndex);
        };
        if len > value.len() {
            return Err(Error::NoSpace);
        }
        value[..old.len()].copy_from_slice(old);
        let mask = 1 << (bit % 8);
        if (value[byte] & mask != 0) == on {
            return Err(Error::InvalidIndex);
        }
        if on {
            value[byte] |= mask;
        } else {
            value[byte] &= !mask;
        }
        record_edit::set_resident_value(self.record_mut(tree.record), at, &value[..len])
    }

    fn map_block(&self, tree: &Tree, vcn: u64) -> Result<u64> {
        let rec = self.record(tree.record);
        let at = record_edit::require(rec, 0xa0, tree.kind.name())?;
        let attr = MftRecord::from_decoded(rec)?.attribute_at(at)?;
        let offset = vcn.checked_mul(BLOCK as u64).ok_or(Error::Overflow)?;
        if offset + BLOCK as u64 > attr.initialized_size()? {
            return Err(Error::InvalidIndex);
        }
        map_one(attr, self.boot, offset, BLOCK as u64)
    }

    fn load_node<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, vcn: u64) -> Result<usize> {
        let id = tree.id();
        for i in 0..MAX_NODES {
            let f = self.nflags(i);
            if f & N_USED != 0 && f & N_ROOT == 0 && self.nhead(i)[1] == id && self.nvcn(i) == vcn {
                if f & N_FREED != 0 {
                    return Err(Error::InvalidIndex);
                }
                return Ok(i);
            }
        }
        if !self.index_bit(volume, tree, vcn)? {
            return Err(Error::InvalidIndex);
        }
        let physical = self.map_block(tree, vcn)?;
        let slot = self.new_slot()?;
        let base = slot * NODE_SLOT;
        let s = &mut self.nodes[base..base + NODE_SLOT];
        s.fill(0);
        let (head, rest) = s.split_at_mut(NODE_HEAD);
        let (before, work) = rest.split_at_mut(BLOCK);
        volume.reader_mut().read_exact_at(physical, &mut work[..BLOCK])?;
        IndexBlock::parse(&mut work[..BLOCK], 512, vcn)?;
        validate_block(&work[..BLOCK])?;
        before.copy_from_slice(&work[..BLOCK]);
        head[0] = N_USED;
        head[1] = id;
        head[8..16].copy_from_slice(&vcn.to_le_bytes());
        head[16..24].copy_from_slice(&physical.to_le_bytes());
        Ok(slot)
    }

    /// Allocate and format a new index block, creating or growing
    /// $INDEX_ALLOCATION and its $BITMAP as needed.
    fn alloc_block<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, large_node: bool) -> Result<usize> {
        let name = tree.kind.name();
        let r = tree.record;
        let bit = match record_edit::find(self.record(r), 0xa0, name)? {
            None => {
                let lcn = self.allocate_clusters(volume, 1, None)?;
                let mut image = [0_u8; 160];
                let run = [Extent { vcn: 0, len: 1, lcn: Some(lcn) }];
                let n = record_edit::build_nonresident(0xa0, name, &run, 4096, 4096, 4096, &mut image)?;
                record_edit::insert(self.record_mut(r), &image[..n])?;
                match record_edit::find(self.record(r), 0xb0, name)? {
                    Some(at) => {
                        if record_edit::is_nonresident(self.record(r), at)? {
                            return Err(Error::Unsupported);
                        }
                        record_edit::set_resident_value(self.record_mut(r), at, &[0; 8])?;
                    }
                    None => {
                        let n = record_edit::build_resident(0xb0, name, &[0; 8], &mut image)?;
                        record_edit::insert(self.record_mut(r), &image[..n])?;
                    }
                }
                0
            }
            Some(at) => {
                let (allocated, data, initialized) = record_edit::sizes(self.record(r), at)?;
                if data != initialized || data % BLOCK as u64 != 0 || allocated < data {
                    return Err(Error::Unsupported);
                }
                let blocks = data / BLOCK as u64;
                let mut found = None;
                for b in 0..blocks {
                    if !self.index_bit(volume, tree, b)? {
                        found = Some(b);
                        break;
                    }
                }
                match found {
                    Some(b) => b,
                    None => {
                        let mut allocated = allocated;
                        if data + BLOCK as u64 > allocated {
                            let hint = record_edit::last_run_end(self.record(r), at)?;
                            let lcn = self.allocate_clusters(volume, 1, hint)?;
                            record_edit::append_run(self.record_mut(r), at, lcn, 1)?;
                            allocated += BLOCK as u64;
                        }
                        let at = record_edit::require(self.record(r), 0xa0, name)?;
                        record_edit::set_sizes(
                            self.record_mut(r),
                            at,
                            allocated,
                            data + BLOCK as u64,
                            data + BLOCK as u64,
                        )?;
                        blocks
                    }
                }
            }
        };
        self.set_index_bit(volume, tree, bit, true)?;
        let physical = self.map_block(tree, bit)?;
        let id = tree.id();
        // A block freed earlier in this transaction keeps its original
        // preimage: if it was live when the transaction began, rollback must
        // restore it, so it is not a fresh (Noop-undo) target.
        let reused = (0..MAX_NODES).find(|&i| {
            let f = self.nflags(i);
            f & N_FREED != 0 && f & N_ROOT == 0 && self.nhead(i)[1] == id && self.nvcn(i) == bit
        });
        if let Some(slot) = reused {
            if u64_at(self.nhead(slot), 16)? != physical {
                return Err(Error::InvalidIndex);
            }
            let fresh = self.nflags(slot) & N_FRESH;
            self.set_nflags(slot, N_USED | N_DIRTY | fresh);
            format_block(self.nw_mut(slot), bit, large_node)?;
            return Ok(slot);
        }
        let slot = self.new_slot()?;
        let base = slot * NODE_SLOT;
        let s = &mut self.nodes[base..base + NODE_SLOT];
        s.fill(0);
        let (head, rest) = s.split_at_mut(NODE_HEAD);
        let (before, work) = rest.split_at_mut(BLOCK);
        volume.reader_mut().read_exact_at(physical, before)?;
        format_block(work, bit, large_node)?;
        head[0] = N_USED | N_DIRTY | N_FRESH;
        head[1] = id;
        head[8..16].copy_from_slice(&bit.to_le_bytes());
        head[16..24].copy_from_slice(&physical.to_le_bytes());
        Ok(slot)
    }

    fn free_block<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, slot: usize) -> Result<()> {
        let vcn = self.nvcn(slot);
        self.set_index_bit(volume, tree, vcn, false)?;
        let f = self.nflags(slot);
        self.set_nflags(slot, (f | N_FREED) & !N_DIRTY);
        Ok(())
    }

    /// Free an already empty chain of blocks: each node contains only its
    /// end entry, optionally pointing at the next empty node.
    fn free_chain<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, mut vcn: u64) -> Result<()> {
        for _ in 0..=MAX_DEPTH {
            let n = self.load_node(volume, tree, vcn)?;
            if !self.is_empty_node(n)? {
                return Err(Error::InvalidIndex);
            }
            let (w, h) = (self.nw(n), self.nh(n));
            let at = first(w, h)?;
            let next = if has_child(w, at)? { Some(child(w, at)?) } else { None };
            self.free_block(volume, tree, n)?;
            match next {
                Some(v) => vcn = v,
                None => return Ok(()),
            }
        }
        Err(Error::InvalidIndex)
    }

    /// Write the root back into its record. NoSpace means push-down is due.
    fn sync_root(&mut self, tree: &Tree) -> Result<()> {
        let root = tree.root;
        let w = self.nw(root);
        let used = u32_at(w, 16 + 4)? as usize;
        let len = 16 + used;
        if len > 640 {
            return Err(Error::NoSpace);
        }
        let r = tree.record;
        let at = record_edit::require(self.record(r), 0x90, tree.kind.name())?;
        let base = root * NODE_SLOT + NODE_HEAD + BLOCK;
        self.records[r * REC_SLOT + 24] |= R_DIRTY;
        let (records, nodes) = (&mut self.records, &self.nodes);
        let rec = &mut records[r * REC_SLOT + REC_HEAD + RECORD..(r + 1) * REC_SLOT];
        record_edit::set_resident_value(rec, at, &nodes[base..base + len])
    }

    // ----- Search ----------------------------------------------------------

    /// Descend for the key of temp entry t. For directories, every visited
    /// entry whose name matches ignoring case is reported as a collision.
    fn search<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, t: usize) -> Result<Path> {
        let mut path =
            Path { node: [0; MAX_DEPTH + 2], at: [0; MAX_DEPTH + 2], depth: 0, found: false, collision: false };
        let mut n = tree.root;
        loop {
            path.node[path.depth] = n as u8;
            let next;
            {
                let (w, h) = (self.nw(n), self.nh(n));
                let wanted = key(self.tmp(t), 0)?;
                let mut at = first(w, h)?;
                loop {
                    if is_last(w, at)? {
                        break;
                    }
                    let k = key(w, at)?;
                    if tree.kind == IndexKind::Directory
                        && !self.linux_compatibility
                        && names_equal_ignoring_case(self.upcase, file_name(wanted)?, file_name(k)?)
                    {
                        path.collision = true;
                    }
                    match compare(tree.kind, self.upcase, wanted, k)? {
                        Ordering::Greater => at += elen(w, at)?,
                        Ordering::Equal => {
                            path.at[path.depth] = at as u16;
                            path.found = true;
                            return Ok(path);
                        }
                        Ordering::Less => break,
                    }
                }
                path.at[path.depth] = at as u16;
                next = if has_child(w, at)? { Some(child(w, at)?) } else { None };
            }
            match next {
                None => return Ok(path),
                Some(vcn) => {
                    if path.depth == MAX_DEPTH {
                        return Err(Error::InvalidIndex);
                    }
                    n = self.load_node(volume, tree, vcn)?;
                    path.depth += 1;
                }
            }
        }
    }

    /// Copy the entry matching temp key t into t and report presence.
    pub fn tree_lookup<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, t: usize) -> Result<bool> {
        let path = self.search(volume, tree, t)?;
        if !path.found {
            return Ok(false);
        }
        let n = usize::from(path.node[path.depth]);
        let at = usize::from(path.at[path.depth]);
        let len = elen(self.nw(n), at)?;
        let base = n * NODE_SLOT + NODE_HEAD + BLOCK;
        let (nodes, temp) = (&self.nodes, &mut self.temp);
        temp[t * TEMP..t * TEMP + len].copy_from_slice(&nodes[base + at..base + at + len]);
        Ok(true)
    }

    /// Update a filename's duplicated payload without changing its collation
    /// key or child pointer. The caller journals the file and index together.
    pub(crate) fn tree_update_filename<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        tree: &Tree,
        t: usize,
        reference: u64,
        info: &[u8; 56],
    ) -> Result<()> {
        if tree.kind != IndexKind::Directory {
            return Err(Error::InvalidIndex);
        }
        let path = self.search(volume, tree, t)?;
        if !path.found {
            return Err(Error::InvalidIndex);
        }
        let node = usize::from(path.node[path.depth]);
        let at = usize::from(path.at[path.depth]);
        if u64_at(self.nw(node), at)? != reference || key(self.nw(node), at)?.len() < 66 {
            return Err(Error::InvalidIndex);
        }
        self.nw_mut(node)[at + 24..at + 80].copy_from_slice(info);
        if node == tree.root {
            self.sync_root(tree)
        } else {
            Ok(())
        }
    }

    /// Report whether any visited entry equals temp key t ignoring case.
    pub fn tree_name_taken<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, t: usize) -> Result<bool> {
        let path = self.search(volume, tree, t)?;
        Ok(path.found || path.collision)
    }

    // ----- Insertion -------------------------------------------------------

    /// Insert temp entry t (a leaf entry without a child pointer).
    pub fn tree_insert<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, t: usize) -> Result<()> {
        let e = self.tmp(t);
        let len = elen(e, 0)?;
        if len < 16 || len % 8 != 0 || len > 1024 - 8 || u16_at(e, 12)? != 0 {
            return Err(Error::InvalidIndex);
        }
        let path = self.search(volume, tree, t)?;
        if path.found || path.collision {
            return Err(Error::Exists);
        }
        let n = usize::from(path.node[path.depth]);
        self.insert_raw(n, usize::from(path.at[path.depth]), t)?;
        self.fix_overflow(volume, tree, &path.node, path.depth)
    }

    fn fix_overflow<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        tree: &Tree,
        nodes: &[u8; MAX_DEPTH + 2],
        depth: usize,
    ) -> Result<()> {
        let mut path = *nodes;
        let mut d = depth;
        for _ in 0..4 * (MAX_DEPTH + 2) {
            let n = usize::from(path[d]);
            if n == tree.root {
                match self.sync_root(tree) {
                    Ok(()) => return Ok(()),
                    Err(Error::NoSpace) => {}
                    Err(e) => return Err(e),
                }
                let b = self.push_down(volume, tree)?;
                path[0] = tree.root as u8;
                path[1] = b as u8;
                d = 1;
                continue;
            }
            let w = self.nw(n);
            if u32_at(w, 24 + 4)? as usize <= BLOCK_TOTAL {
                return self.settle_root(volume, tree);
            }
            if d == 0 {
                return Err(Error::InvalidIndex);
            }
            self.split(volume, tree, n, usize::from(path[d - 1]))?;
            d -= 1;
        }
        Err(Error::InvalidIndex)
    }

    /// Ensure the root has been written back, pushing it down when the
    /// record lacks room (for example after $BITMAP growth).
    fn settle_root<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree) -> Result<()> {
        let mut path = [0_u8; MAX_DEPTH + 2];
        path[0] = tree.root as u8;
        match self.sync_root(tree) {
            Ok(()) => Ok(()),
            Err(Error::NoSpace) => self.fix_overflow(volume, tree, &path, 0),
            Err(e) => Err(e),
        }
    }

    /// Move every root entry into a new block; the root keeps one end entry
    /// pointing at it (ntfs3 indx_insert_into_root).
    fn push_down<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree) -> Result<usize> {
        let root = tree.root;
        let root_large = large(self.nw(root), 16);
        // Publish a minimal root first so the record has room for the new
        // $INDEX_ALLOCATION/$BITMAP attributes; the arena keeps the entries.
        {
            let w = self.nw(root);
            let fst = first(w, 16)?;
            let mut tiny = [0_u8; 128];
            if fst + 24 > tiny.len() {
                return Err(Error::InvalidIndex);
            }
            tiny[..fst].copy_from_slice(&w[..fst]);
            p16(&mut tiny, fst + 8, 24)?;
            p16(&mut tiny, fst + 12, 3)?;
            let used = (fst - 16 + 24) as u32;
            p32(&mut tiny, 20, used)?;
            p32(&mut tiny, 24, used)?;
            tiny[28] = 1;
            let r = tree.record;
            let at = record_edit::require(self.record(r), 0x90, tree.kind.name())?;
            record_edit::set_resident_value(self.record_mut(r), at, &tiny[..fst + 24])?;
        }
        let b = self.alloc_block(volume, tree, root_large)?;
        let rbase = root * NODE_SLOT + NODE_HEAD + BLOCK;
        let bbase = b * NODE_SLOT + NODE_HEAD + BLOCK;
        let (rfirst, rend) = {
            let w = self.nw(root);
            (first(w, 16)?, end(w, 16)?)
        };
        let moved = rend - rfirst;
        if 0x40 + moved > BLOCK || moved > NODE_WORK {
            return Err(Error::InvalidIndex);
        }
        // Block entries = all root entries, including the root's end entry
        // (which carries the old root child pointer for large roots).
        self.nodes.copy_within(rbase + rfirst..rbase + rend, bbase + 0x40);
        {
            let w = self.nw_mut(b);
            w[0x40 + moved..BLOCK].fill(0);
            p32(w, 28, (0x28 + moved) as u32)?;
            w[36] = u8::from(root_large);
        }
        let vcn = self.nvcn(b);
        let w = self.nw_mut(root);
        w[rfirst..rend].fill(0);
        p16(w, rfirst + 8, 24)?;
        p16(w, rfirst + 10, 0)?;
        p16(w, rfirst + 12, 3)?;
        p64(w, rfirst, 0)?;
        p64(w, rfirst + 16, vcn)?;
        let used = (rfirst - 16 + 24) as u32;
        p32(w, 16 + 4, used)?;
        p32(w, 16 + 8, used)?;
        w[16 + 12] = 1;
        Ok(b)
    }

    /// Split an overflowing block around a byte-balanced median. Entries
    /// below the median move to a new left block, which the promoted median
    /// entry points to (ntfs3 indx_insert_into_buffer).
    fn split<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, n: usize, parent: usize) -> Result<()> {
        let (fst, stop, node_large) = {
            let w = self.nw(n);
            (first(w, 24)?, end(w, 24)?, large(w, 24))
        };
        // Choose the split entry: never the first or the end entry.
        let half = fst + (stop - fst) / 2;
        let mut at = fst;
        let mut sp = None;
        loop {
            let w = self.nw(n);
            if is_last(w, at)? {
                break;
            }
            if at != fst && at + elen(w, at)? > half {
                sp = Some(at);
                break;
            }
            if at != fst {
                sp = Some(at);
            }
            at += elen(w, at)?;
        }
        let sp = sp.ok_or(Error::InvalidIndex)?;
        let sp_len = elen(self.nw(n), sp)?;
        let left = self.alloc_block(volume, tree, node_large)?;
        let left_vcn = self.nvcn(left);
        // Promoted entry.
        self.remove_raw(n, sp, Some(T_UP))?;
        let sp_child = if node_large { Some(child(self.tmp(T_UP), 0)?) } else { None };
        {
            let e = self.temp_mut(T_UP);
            if node_large {
                set_child(e, 0, left_vcn)?;
            } else {
                let len = sp_len + 8;
                p16(e, 8, len as u16)?;
                p16(e, 12, 1)?;
                p64(e, len - 8, left_vcn)?;
            }
        }
        // Move entries [fst, sp) to the left block, ahead of its end entry.
        let moved = sp - fst;
        let nbase = n * NODE_SLOT + NODE_HEAD + BLOCK;
        let lbase = left * NODE_SLOT + NODE_HEAD + BLOCK;
        {
            let lw = self.nw(left);
            if first(lw, 24)? != 0x40 {
                return Err(Error::InvalidIndex);
            }
        }
        let end_len = if node_large { 24 } else { 16 };
        // Left end entry currently at 0x40; shift it after the moved entries.
        self.nodes.copy_within(lbase + 0x40..lbase + 0x40 + end_len, lbase + 0x40 + moved);
        self.nodes.copy_within(nbase + fst..nbase + sp, lbase + 0x40);
        {
            let lw = self.nw_mut(left);
            p32(lw, 28, (0x28 + moved + end_len) as u32)?;
            if let Some(c) = sp_child {
                set_child(lw, 0x40 + moved, c)?;
            }
        }
        {
            let w = self.nw_mut(n);
            let stop = end(w, 24)?;
            w.copy_within(fst + moved..stop, fst);
            w[stop - moved..stop].fill(0);
            let used = u32_at(w, 28)? - moved as u32;
            p32(w, 28, used)?;
        }
        let n_vcn = self.nvcn(n);
        let at = self.find_child_entry(parent, n_vcn)?;
        self.insert_raw(parent, at, T_UP)
    }

    // ----- Deletion --------------------------------------------------------

    /// Delete the entry whose key equals temp entry t's key.
    pub fn tree_delete<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, t: usize) -> Result<()> {
        let path = self.search(volume, tree, t)?;
        if !path.found {
            return Err(Error::NotFound);
        }
        let d = path.depth;
        let n = usize::from(path.node[d]);
        let at = usize::from(path.at[d]);
        if !has_child(self.nw(n), at)? {
            self.remove_raw(n, at, None)?;
            if n != tree.root && self.is_empty_node(n)? {
                self.remove_empty_branch(volume, tree, &path.node, d)?;
            }
            return self.settle_root(volume, tree);
        }
        let e_child = child(self.nw(n), at)?;
        let next_at = at + elen(self.nw(n), at)?;
        let next_child = child(self.nw(n), next_at)?;
        match self.take_replacement(volume, tree, next_child)? {
            Some(emptied) => {
                set_child(self.temp_mut(T_RE), 0, e_child)?;
                self.remove_raw(n, at, None)?;
                self.insert_raw(n, at, T_RE)?;
                self.fix_overflow(volume, tree, &path.node, d)?;
                if emptied {
                    let branch = self.path_after(volume, tree, T_RE)?;
                    self.remove_empty_branch(volume, tree, &branch.node, branch.depth)?;
                }
            }
            None => {
                // The whole subtree after the deleted entry is empty.
                self.free_chain(volume, tree, next_child)?;
                set_child(self.nw_mut(n), next_at, e_child)?;
                self.remove_raw(n, at, None)?;
            }
        }
        self.settle_root(volume, tree)
    }

    /// Take the first entry of the deepest non-empty node on the leftmost
    /// descent from vcn into T_RE with a child slot. Returns None if the
    /// whole subtree is empty, else whether a leaf was emptied.
    fn take_replacement<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, vcn: u64) -> Result<Option<bool>> {
        let mut chain = [0_u8; MAX_DEPTH + 1];
        let mut count = 0;
        let mut deepest = None;
        let mut next = vcn;
        loop {
            if count > MAX_DEPTH {
                return Err(Error::InvalidIndex);
            }
            let n = self.load_node(volume, tree, next)?;
            chain[count] = n as u8;
            count += 1;
            let (w, h) = (self.nw(n), self.nh(n));
            let at = first(w, h)?;
            if !is_last(w, at)? {
                deepest = Some(n);
            }
            if !has_child(w, at)? {
                break;
            }
            next = child(w, at)?;
        }
        let Some(n) = deepest else {
            return Ok(None);
        };
        let at = first(self.nw(n), 24)?;
        let te_child = if has_child(self.nw(n), at)? { Some(child(self.nw(n), at)?) } else { None };
        self.remove_raw(n, at, Some(T_RE))?;
        match te_child {
            Some(c) => self.free_chain(volume, tree, c)?,
            None => {
                let e = self.temp_mut(T_RE);
                let len = elen(e, 0)? + 8;
                p16(e, 8, len as u16)?;
                p16(e, 12, 1)?;
                p64(e, len - 8, 0)?;
            }
        }
        let leaf_emptied = te_child.is_none() && self.is_empty_node(n)?;
        Ok(Some(leaf_emptied))
    }

    /// Path from the root to the leftmost leaf following the entry equal to
    /// temp key t (the in-order successor position).
    fn path_after<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree, t: usize) -> Result<Path> {
        let mut path = self.search(volume, tree, t)?;
        if !path.found {
            return Err(Error::InvalidIndex);
        }
        let mut n = usize::from(path.node[path.depth]);
        let mut at = usize::from(path.at[path.depth]);
        at += elen(self.nw(n), at)?;
        loop {
            path.at[path.depth] = at as u16;
            let w = self.nw(n);
            if !has_child(w, at)? {
                return Ok(path);
            }
            let vcn = child(w, at)?;
            if path.depth == MAX_DEPTH {
                return Err(Error::InvalidIndex);
            }
            n = self.load_node(volume, tree, vcn)?;
            path.depth += 1;
            path.node[path.depth] = n as u8;
            at = first(self.nw(n), 24)?;
        }
    }

    /// Remove an empty leaf and every empty ancestor above it, then reinsert
    /// the separator entry from the lowest non-empty ancestor (ntfs3
    /// indx_delete_entry branch deletion).
    fn remove_empty_branch<R: ReadAt>(
        &mut self,
        volume: &mut Volume<R>,
        tree: &Tree,
        nodes: &[u8; MAX_DEPTH + 2],
        depth: usize,
    ) -> Result<()> {
        let mut top = depth;
        while top > 1 && self.is_empty_node(usize::from(nodes[top - 1]))? {
            top -= 1;
        }
        let a = usize::from(nodes[top - 1]);
        let chain_vcn = self.nvcn(usize::from(nodes[top]));
        let ah = self.nh(a);
        if a == tree.root && self.is_empty_node(a)? {
            return self.collapse(volume, tree);
        }
        let at = self.find_child_entry(a, chain_vcn)?;
        if is_last(self.nw(a), at)? {
            // The end entry cannot be removed: remove its predecessor and let
            // the end entry inherit the predecessor's child.
            let (w, h) = (self.nw(a), ah);
            let mut prev = None;
            let mut cursor = first(w, h)?;
            while cursor < at {
                prev = Some(cursor);
                cursor += elen(w, cursor)?;
            }
            let prev = prev.ok_or(Error::InvalidIndex)?;
            let prev_child = child(w, prev)?;
            self.remove_raw(a, prev, Some(T_ME))?;
            let end_at = at - elen(self.tmp(T_ME), 0)?;
            set_child(self.nw_mut(a), end_at, prev_child)?;
        } else {
            self.remove_raw(a, at, Some(T_ME))?;
        }
        {
            let e = self.temp_mut(T_ME);
            let len = elen(e, 0)? - 8;
            e[len..len + 8].fill(0);
            p16(e, 8, len as u16)?;
            p16(e, 12, 0)?;
        }
        self.free_chain(volume, tree, chain_vcn)?;
        if a == tree.root {
            self.sync_root(tree).or_else(|e| if e == Error::NoSpace { Ok(()) } else { Err(e) })?;
        }
        self.tree_insert(volume, tree, T_ME)
    }

    /// Return an entirely empty index to a resident leaf root and release
    /// $INDEX_ALLOCATION and $BITMAP (ntfs3 empty-root collapse), unless that
    /// release exceeds the bitmap budget; the empty allocation is then kept.
    fn collapse<R: ReadAt>(&mut self, volume: &mut Volume<R>, tree: &Tree) -> Result<()> {
        if self.aux_owner == Some((tree.record, tree.kind.code())) {
            return Err(Error::Unsupported);
        }
        let id = tree.id();
        let r = tree.record;
        let name = tree.kind.name();
        // Releasing a large, scattered allocation can exceed this transaction's
        // bitmap budget. Keep it then, with every block free; alloc_block
        // reuses it and orphan reclaim releases it in bounded steps.
        let release = match record_edit::find(self.record(r), 0xa0, name)? {
            Some(at) => self.release_fits(r, at)?,
            None => true,
        };
        for i in 0..MAX_NODES {
            let f = self.nflags(i);
            if f & N_USED != 0 && f & N_ROOT == 0 && self.nhead(i)[1] == id {
                if f & N_FREED == 0 && !self.is_empty_node(i)? {
                    return Err(Error::InvalidIndex);
                }
                if !release {
                    if f & N_FREED == 0 {
                        self.free_block(volume, tree, i)?;
                    }
                    continue;
                }
                // The whole stream disappears: release the slot entirely so a
                // recreated allocation never aliases these old blocks.
                self.set_nflags(i, 0);
            }
        }
        if release {
            if let Some(at) = record_edit::find(self.record(r), 0xa0, name)? {
                self.free_attribute_runs(volume, r, at)?;
                record_edit::remove(self.record_mut(r), at)?;
            }
            if let Some(at) = record_edit::find(self.record(r), 0xb0, name)? {
                if record_edit::is_nonresident(self.record(r), at)? {
                    self.free_attribute_runs(volume, r, at)?;
                }
                record_edit::remove(self.record_mut(r), at)?;
            }
        }
        let w = self.nw_mut(tree.root);
        let fst = first(w, 16)?;
        let stop = end(w, 16)?;
        w[fst..stop].fill(0);
        p16(w, fst + 8, 16)?;
        p16(w, fst + 12, 2)?;
        let used = (fst - 16 + 16) as u32;
        p32(w, 20, used)?;
        p32(w, 24, used)?;
        w[28] = 0;
        self.sync_root(tree)
    }

    /// Whether freeing every run of the attribute at offset at fits the bitmap
    /// sectors this transaction may still edit, keeping a reserve for the
    /// rest of the operation.
    fn release_fits(&self, r: usize, at: usize) -> Result<bool> {
        use super::allocation::{SectorBudget, BITMAP_PATCHES};
        // Bitmap sectors kept for the rest of the unlink or rename.
        const RESERVE: usize = 4;
        let Some(mut budget) = SectorBudget::new(&self.clusters, BITMAP_PATCHES - RESERVE)? else {
            return Ok(false);
        };
        let record = MftRecord::from_decoded(self.record(r))?;
        let attr = record
            .attributes()
            .find_map(|a| match a {
                Ok(a) if a.record_offset() == at => Some(Ok(a)),
                Err(e) => Some(Err(e)),
                _ => None,
            })
            .ok_or(Error::InvalidAttribute)??;
        for run in super::runlist::DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
            let run = run?;
            let Some(lcn) = run.lcn else { continue };
            if !budget.add_run(lcn, run.len)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check key order within every changed node of a tree before commit.
    pub fn tree_check(&self, tree: &Tree) -> Result<()> {
        let id = tree.id();
        for i in 0..MAX_NODES {
            let f = self.nflags(i);
            if f & N_USED == 0 || f & N_FREED != 0 || self.nhead(i)[1] != id {
                continue;
            }
            let (w, h) = (self.nw(i), self.nh(i));
            validate_node(w, h, h == 24)?;
            let mut at = first(w, h)?;
            let mut previous: Option<usize> = None;
            while !is_last(w, at)? {
                if let Some(p) = previous {
                    if compare(tree.kind, self.upcase, key(w, p)?, key(w, at)?)? != Ordering::Less {
                        return Err(Error::InvalidIndex);
                    }
                }
                previous = Some(at);
                at += elen(w, at)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filename_collation_orders_case_insensitively_then_exactly() {
        let mut table = [0_u8; 131072];
        for c in 0..65536_usize {
            let u = if (97..=122).contains(&c) { c - 32 } else { c } as u16;
            table[c * 2..c * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let n = |s: &str| s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<std::vec::Vec<u8>>();
        assert_eq!(compare_names(&table, &n("abc"), &n("ABD")), Ordering::Less);
        assert_eq!(compare_names(&table, &n("ab"), &n("ABC")), Ordering::Less);
        assert_eq!(compare_names(&table, &n("ABC"), &n("abc")), Ordering::Less);
        assert_eq!(compare_names(&table, &n("abc"), &n("abc")), Ordering::Equal);
        assert!(names_equal_ignoring_case(&table, &n("aBc"), &n("AbC")));
    }
    #[test]
    fn formatted_blocks_validate() {
        let mut w = [0_u8; NODE_WORK];
        format_block(&mut w, 7, true).unwrap();
        validate_block(&w[..BLOCK]).unwrap();
        format_block(&mut w, 7, false).unwrap();
        validate_block(&w[..BLOCK]).unwrap();
    }
}
