//! Module: slate_ntfs_tools::checker::consistency::index_check
//! Purpose: Apply full or reduced entry checks with bounded caches and fallback.
//! Created: 2026-10-01
//! Architecture: Consistency checks index structure before spooling entries here;
//!     this module reconciles references and supplies edges to graph validation.

use super::*;
use ntfs_rs::mft::reference_number;
use std::collections::BTreeMap;
use std::io::Read;

#[cfg(test)]
const CACHE_BYTES: u64 = INDEX_CACHE_BYTES;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IndexCheck {
    #[default]
    Full,
    Quick,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IndexCachePasses {
    #[default]
    Auto,
    Streaming,
    Count(std::num::NonZeroU16),
}

impl IndexCachePasses {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "0" => Some(Self::Streaming),
            _ => value
                .parse::<u16>()
                .ok()
                .filter(|n| *n != u16::MAX)
                .and_then(std::num::NonZeroU16::new)
                .map(Self::Count),
        }
    }
}

pub(super) struct Entries {
    catalog: DiskInventory,
    data: File,
}

struct Entry {
    owner: u64,
    reference: u64,
    name: Name,
}

impl Entries {
    pub(super) fn new() -> io::Result<Self> {
        Ok(Self { catalog: DiskInventory::new(), data: scratch_file()? })
    }

    pub(super) fn push(&mut self, owner: u64, entry: IndexEntry<'_>) -> io::Result<()> {
        let offset = self.data.seek(SeekFrom::End(0))?;
        self.data.write_all(&owner.to_le_bytes())?;
        self.data.write_all(&entry.file_reference.to_le_bytes())?;
        self.data.write_all(&entry.file_name_value[..64])?;
        self.data.write_all(&[entry.name.namespace])?;
        self.data.write_all(&(entry.name.utf16le.len() as u16).to_le_bytes())?;
        self.data.write_all(entry.name.utf16le)?;
        self.catalog.push([reference_number(entry.file_reference), owner, offset, 0])
    }

    fn entry(&mut self, offset: u64) -> io::Result<Entry> {
        self.data.seek(SeekFrom::Start(offset))?;
        let mut header = [0; 83];
        self.data.read_exact(&mut header)?;
        let length = u16_at(&header, 81)? as usize;
        if length > 510 || length % 2 != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut text = vec![0; length];
        self.data.read_exact(&mut text)?;
        Ok(Entry {
            owner: u64_at(&header, 0)?,
            reference: u64_at(&header, 8)?,
            name: Name {
                parent: u64_at(&header, 16)?,
                duplicate: header[24..80].try_into().unwrap(),
                namespace: header[80],
                text,
            },
        })
    }

    pub(super) fn finish(
        mut self,
        records: &RecordStore,
        links: &mut DiskInventory,
        out: &mut Audit,
        options: AuditOptions,
        budget: u64,
    ) -> io::Result<()> {
        let catalog = std::mem::replace(&mut self.catalog, DiskInventory::new()).finish()?;
        if options.index_check == IndexCheck::Quick {
            out.index_cache_passes = 0;
            return self.quick(catalog, records, links, out);
        }
        // Cache partitions change the working set, never the set of entries checked.
        // Explicit requests still fall back to streaming if a partition cannot fit.
        let estimate = records
            .files
            .borrow()
            .1
            .metadata()?
            .len()
            .saturating_mul(4)
            .saturating_add(records.slots.saturating_mul(64));
        let passes = match options.index_cache_passes {
            IndexCachePasses::Streaming => 0,
            IndexCachePasses::Count(n) => u64::from(n.get()).min(records.slots),
            IndexCachePasses::Auto if budget == 0 => 0,
            IndexCachePasses::Auto => {
                let n = estimate.div_ceil(budget).max(1);
                if n <= 10 {
                    n
                } else {
                    0
                }
            }
        };
        out.index_cache_passes = passes;
        let mut catalog = std::io::BufReader::new(catalog);
        let mut pending = inventory_next(&mut catalog)?;
        for pass in 0..passes.max(1) {
            let start = if passes == 0 { 0 } else { records.slots * pass / passes };
            let end = if passes == 0 { records.slots } else { records.slots * (pass + 1) / passes };
            let cache = if passes == 0 { None } else { cache(records, start, end, budget)? };
            if passes != 0 && cache.is_none() {
                out.index_cache_fallback = true;
            }
            while let Some(row) = pending {
                // References beyond the catalog are still diagnosed in the final pass.
                if row[0] >= end && pass + 1 < passes {
                    break;
                }
                let owned = if cache.is_none() { records.get(&row[0])? } else { None };
                let record = cache.as_ref().and_then(|c| c.get(&row[0])).or(owned.as_ref());
                check_entry(self.entry(row[2])?, record, links, out)?;
                pending = inventory_next(&mut catalog)?;
            }
        }
        Ok(())
    }

    fn quick(
        &mut self,
        mut catalog: File,
        records: &RecordStore,
        links: &mut DiskInventory,
        out: &mut Audit,
    ) -> io::Result<()> {
        while let Some(first) = inventory_next(&mut catalog)? {
            let target = first[0];
            let start = catalog.stream_position()? - 32;
            let summary = records.summary(target)?;
            let expected = summary.filter(|(_, base, _)| *base == 0).map_or(0, |(_, _, count)| count);
            let mut remaining = expected;
            let mut fallback = false;
            let mut row = Some(first);
            // A depleted name count triggers a complete recheck of every reference
            // to this target, including entries accepted earlier in the reduced pass.
            while let Some(item) = row {
                let entry = self.entry(item[2])?;
                if remaining == 0 {
                    fallback = true;
                } else if entry.name.parent == entry.owner {
                    remaining -= 1;
                }
                row = inventory_next(&mut catalog)?;
                if row.is_none_or(|next| next[0] != target) {
                    break;
                }
            }
            let end = catalog.stream_position()? - u64::from(row.is_some()) * 32;
            let record = if fallback { records.get(&target)? } else { None };
            if target < records.slots {
                audit_slot(out.index_full_targets.as_mut().unwrap(), target, Some(Some(if fallback { 1 } else { 2 })))?;
            }
            if fallback {
                out.index_rechecked_records += 1;
            }
            catalog.seek(SeekFrom::Start(start))?;
            let mut ordinal = 0;
            while catalog.stream_position()? < end {
                let item = inventory_next(&mut catalog)?.ok_or(io::ErrorKind::UnexpectedEof)?;
                let entry = self.entry(item[2])?;
                if fallback {
                    check_entry(entry, record.as_ref(), links, out)?;
                } else if entry.name.parent != entry.owner {
                    bad_parent(&entry, out)?;
                } else {
                    links.push([target, ordinal, reference_number(entry.owner), 0])?;
                    ordinal += 1;
                    out.index_entries_reduced += 1;
                }
            }
            catalog.seek(SeekFrom::Start(end))?;
            if !fallback && remaining != 0 {
                missing_count(records, target, remaining, out)?;
            }
        }
        Ok(())
    }
}

fn cache(records: &RecordStore, start: u64, end: u64, budget: u64) -> io::Result<Option<BTreeMap<u64, Record>>> {
    let mut bytes = 0_u64;
    let mut cache = BTreeMap::new();
    for number in start..end {
        if let Some(record) = records.get(&number)? {
            bytes = bytes
                .saturating_add(128 + record.names.iter().map(|name| 128 + name.text.capacity() as u64).sum::<u64>());
            if bytes > budget {
                return Ok(None);
            }
            cache.insert(number, record);
        }
    }
    Ok(Some(cache))
}

fn bad_parent(entry: &Entry, out: &mut Audit) -> io::Result<()> {
    let owner = reference_number(entry.owner);
    out.finding("index-parent-reference", Some(owner), "index key parent does not match its owning directory");
    out.index_needs_repair(owner)
}

fn check_entry(entry: Entry, record: Option<&Record>, links: &mut DiskInventory, out: &mut Audit) -> io::Result<()> {
    out.index_entries_full += 1;
    let target = reference_number(entry.reference);
    let owner = reference_number(entry.owner);
    if entry.name.parent != entry.owner {
        return bad_parent(&entry, out);
    }
    match record {
        None => out.finding(
            "dangling-index-reference",
            Some(owner),
            format!("target record {target} is not allocated/valid"),
        ),
        Some(record) if record.reference != entry.reference => {
            out.finding("stale-index-reference", Some(owner), format!("sequence mismatch for record {target}"))
        }
        Some(record) if record.base == 0 => {
            if let Some(index) = record.names.iter().position(|name| {
                name.parent == entry.owner && name.namespace == entry.name.namespace && name.text == entry.name.text
            }) {
                if target > 15
                    && record.canonical.is_some_and(|canonical| {
                        !super::super::super::recovery_io::duplicated_name_equal(&canonical, &entry.name.duplicate)
                    })
                {
                    out.report(
                        "index-duplicate-information",
                        Some(target),
                        format!("parent {owner} index metadata differs from current file metadata"),
                        false,
                    );
                    // Cached metadata can legitimately lag the owning file.
                    // Report its freshness without scheduling an index rebuild.
                }
                links.push([target, index as u64, owner, 0])?;
                return Ok(());
            }
            if let Some(index) =
                record.names.iter().position(|name| name.parent == entry.owner && name.text == entry.name.text)
            {
                // Namespace correction changes a derived key, not the path's
                // proven object, parent generation or exact filename spelling.
                out.finding(
                    "index-filename-namespace",
                    Some(target),
                    format!(
                        "parent {owner} index namespace {} differs from effective filename namespace {}",
                        entry.name.namespace, record.names[index].namespace,
                    ),
                );
                out.index_needs_repair(owner)?;
                links.push([target, index as u64, owner, 0])?;
                return Ok(());
            }
            out.finding("index-filename-mismatch", Some(target), format!("no matching FILE_NAME for parent {owner}"));
        }
        Some(_) => {
            out.finding("index-extension-reference", Some(owner), format!("target record {target} is an extension"))
        }
    }
    out.index_needs_repair(owner)
}

pub(super) fn missing_count(records: &RecordStore, target: u64, count: u64, out: &mut Audit) -> io::Result<()> {
    out.finding(
        "missing-directory-link",
        Some(target),
        format!("{count} FILE_NAME references are absent from directory indexes"),
    );
    if let Some(record) = records.get(&target)? {
        for name in record.names {
            out.index_needs_repair(reference_number(name.parent))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/checker/index_check.rs"]
mod tests;
