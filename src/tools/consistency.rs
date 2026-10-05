//! Module: slate_ntfs_tools::checker::consistency
//! Purpose: Audit metadata families, directory relationships and allocation
//!     ownership.
//! Created: 2026-09-30
//! Architecture: The checker supplies read-only images; findings inform recovery
//!     planning but never authorize writes or dirty-bit clearing. Disk-backed
//!     inventories here are shared with recovery_io planners.

use super::super::recovery_io::{self as recovery, FamilyKey, FamilyKeysBuilder, Phase, RepairProgress};
use super::{invalid, Image};
use ntfs_rs::attrlist::AttributeList;
use ntfs_rs::boot::BootSector;
use ntfs_rs::bytes::{u16_at, u64_at};
use ntfs_rs::filename_metadata as filename;
use ntfs_rs::index::IndexEntry;
use ntfs_rs::index_tree::compare_names;
use ntfs_rs::mft::{
    record_layout, reference_number, system_record, Attribute, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA,
    ATTR_FILE_NAME, ATTR_INDEX_ALLOCATION, ATTR_INDEX_ROOT, ATTR_SECURITY_DESCRIPTOR,
};
use ntfs_rs::runlist::DataRuns;
use ntfs_rs::upcase::UPCASE_BYTES;
use ntfs_rs::volume::{ReadAt, Volume};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[path = "consistency_index.rs"]
mod index_check;
pub use index_check::{IndexCachePasses, IndexCheck};

pub(crate) const INDEX_CACHE_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const INVENTORY_WORDS: usize = 4;
pub(crate) const INVENTORY_WORD_BYTES: usize = std::mem::size_of::<u64>();
pub(crate) const INVENTORY_BYTES: usize = INVENTORY_WORDS * INVENTORY_WORD_BYTES;
const INVENTORY_SPILL_ROWS: usize = 65536;
const SCRATCH_ATTEMPTS: usize = 1000;
use crate::linux::PRIVATE_FILE_MODE;
/// Sparse slot rows: a presence byte, padding, then one little-endian value.
const SLOT_BYTES: u64 = 16;
const SLOT_VALUE_OFFSET: usize = 8;
const SLOT_PRESENT: u8 = 1;
/// Finding spool rows: code length, severity, record, detail length, code, detail.
const FINDING_HEADER_BYTES: usize = 14;
const FINDING_RECORD_OFFSET: usize = 2;
const FINDING_DETAIL_LENGTH_OFFSET: usize = 10;
const NO_RECORD: u64 = u64::MAX;
const BITS_PER_BYTE: u64 = u8::BITS as u64;
const BITMAP_READ_BYTES: usize = 8192;
/// MFT bitmap streams consist of quadwords, each covering 64 records.
const BITMAP_WORD_BYTES: u64 = std::mem::size_of::<u64>() as u64;
const BITMAP_WORD_BITS: u64 = u64::BITS as u64;
const LIST_READ_BYTES: usize = 1024 * 1024;
/// Upper bound of one self-relative descriptor read through $SDS, plus its header.
const SECURITY_DESCRIPTOR_SCRATCH: usize = 0x20014;
const FIRST_SHARED_SECURITY_ID: u32 = 256;
/// Smallest attribute-list entry, and the per-entry scratch for family assembly.
const LIST_ENTRY_MIN_BYTES: usize = 26;
const FAMILY_SCRATCH_PER_ENTRY: usize = 24;
const FILENAME_INDEXED: u8 = 1;
const VISITING: u64 = 1;
const VISITED: u64 = 2;
const MARKED: Option<Option<u64>> = Some(Some(1));
const I30_NAME_UTF16LE: &[u8] = &[b'$', 0, b'I', 0, b'3', 0, b'0', 0];
const UPCASE_INFO_NAME: &[u8] = b"$\0I\0n\0f\0o\0";

pub(crate) type Row = [u64; INVENTORY_WORDS];
type RowOrder = Box<dyn Fn(&Row, &Row) -> io::Result<Ordering>>;

pub(crate) fn scratch_file() -> io::Result<File> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    for _ in 0..SCRATCH_ATTEMPTS {
        let name = format!("slate-audit-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
        let path = std::env::temp_dir().join(name);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true).mode(PRIVATE_FILE_MODE);
        match options.open(&path) {
            Ok(file) => {
                std::fs::remove_file(path)?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "cannot create private audit scratch"))
}

/// Read one row; a clean end of stream before its first byte returns None.
pub(crate) fn inventory_next(reader: &mut impl Read) -> io::Result<Option<Row>> {
    let mut bytes = [0; INVENTORY_BYTES];
    loop {
        match reader.read(&mut bytes[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut bytes[1..])?;
    Ok(Some(std::array::from_fn(|i| {
        u64::from_le_bytes(bytes[i * INVENTORY_WORD_BYTES..][..INVENTORY_WORD_BYTES].try_into().unwrap())
    })))
}

pub(crate) fn inventory_write(writer: &mut impl Write, row: Row) -> io::Result<()> {
    for word in row {
        writer.write_all(&word.to_le_bytes())?;
    }
    Ok(())
}

// Sparse slot map for volume-wide family relationships. A separate presence
// word allows every u64 file reference, including zero, to remain representable.
pub(crate) fn audit_slot(file: &mut File, number: u64, write: Option<Option<u64>>) -> io::Result<Option<u64>> {
    let at = number
        .checked_mul(SLOT_BYTES)
        .filter(|at| *at <= u64::MAX - SLOT_BYTES)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let mut row = [0; SLOT_BYTES as usize];
    if at < file.metadata()?.len() {
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut row)?;
    }
    let old = (row[0] != 0).then(|| u64::from_le_bytes(row[SLOT_VALUE_OFFSET..].try_into().unwrap()));
    if let Some(value) = write {
        row.fill(0);
        if let Some(value) = value {
            row[0] = SLOT_PRESENT;
            row[SLOT_VALUE_OFFSET..].copy_from_slice(&value.to_le_bytes());
        }
        file.seek(SeekFrom::Start(at))?;
        file.write_all(&row)?;
    }
    Ok(old)
}

/// Index of the first sorted row whose key is not below key; the file cursor
/// is left at that row.
pub(crate) fn inventory_lower_bound(mut file: &File, key: u64) -> io::Result<u64> {
    use std::os::unix::fs::FileExt;

    let (mut lo, mut hi) = (0, file.metadata()?.len() / INVENTORY_BYTES as u64);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mut first = [0; INVENTORY_WORD_BYTES];
        file.read_exact_at(&mut first, mid * INVENTORY_BYTES as u64)?;
        if u64::from_le_bytes(first) < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    file.seek(SeekFrom::Start(lo * INVENTORY_BYTES as u64))?;
    Ok(lo)
}

pub(crate) fn inventory_find(file: &mut File, key: u64) -> io::Result<Option<Row>> {
    inventory_lower_bound(file, key)?;
    Ok(inventory_next(file)?.filter(|row| row[0] == key))
}

/// Rewind a finished scratch writer for reading.
fn finish_writer(output: BufWriter<File>) -> io::Result<File> {
    let mut file = output.into_inner().map_err(|error| error.into_error())?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

// Fixed-width ownership records are externally sorted. A merge level holds
// one file, so RAM and open descriptors do not grow with the extent count.
pub(crate) struct DiskInventory {
    pending: Vec<Row>,
    levels: Vec<Option<File>>,
    order: Option<RowOrder>,
}

impl DiskInventory {
    pub(crate) fn new() -> Self {
        Self { pending: Vec::new(), levels: Vec::new(), order: None }
    }

    pub(crate) fn ordered(order: impl Fn(&Row, &Row) -> io::Result<Ordering> + 'static) -> Self {
        Self { order: Some(Box::new(order)), ..Self::new() }
    }

    pub(crate) fn push(&mut self, row: Row) -> io::Result<()> {
        self.pending.push(row);
        if self.pending.len() == INVENTORY_SPILL_ROWS {
            self.spill()?;
        }
        Ok(())
    }

    fn compare(order: &Option<RowOrder>, a: &Row, b: &Row) -> io::Result<Ordering> {
        match order {
            Some(compare) => compare(a, b),
            None => Ok(a.cmp(b)),
        }
    }

    fn merge(a: File, b: File, order: &Option<RowOrder>) -> io::Result<File> {
        let (mut a, mut b) = (BufReader::new(a), BufReader::new(b));
        let (mut left, mut right) = (inventory_next(&mut a)?, inventory_next(&mut b)?);
        let mut output = BufWriter::new(scratch_file()?);
        loop {
            let take_left = match (&left, &right) {
                (Some(l), Some(r)) => Self::compare(order, l, r)? != Ordering::Greater,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return finish_writer(output),
            };
            if take_left {
                inventory_write(&mut output, left.unwrap())?;
                left = inventory_next(&mut a)?;
            } else {
                inventory_write(&mut output, right.unwrap())?;
                right = inventory_next(&mut b)?;
            }
        }
    }

    fn spill(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        if self.order.is_some() {
            // Fallible merge sort: a scratch read error must propagate, not
            // turn a comparison into a fabricated ordering or a sort panic.

            let rows = self.pending.len();
            let mut work = self.pending.clone();
            let mut width = 1;
            while width < rows {
                for start in (0..rows).step_by(width * 2) {
                    let mid = (start + width).min(rows);
                    let end = (mid + width).min(rows);
                    let (mut left, mut right) = (start, mid);
                    for out in &mut work[start..end] {
                        let take_left = left < mid
                            && (right == end
                                || Self::compare(&self.order, &self.pending[left], &self.pending[right])?
                                    != Ordering::Greater);
                        if take_left {
                            *out = self.pending[left];
                            left += 1;
                        } else {
                            *out = self.pending[right];
                            right += 1;
                        }
                    }
                }
                self.pending.copy_from_slice(&work);
                width *= 2;
            }
        } else {
            self.pending.sort_unstable();
        }
        let mut output = BufWriter::new(scratch_file()?);
        for row in self.pending.drain(..) {
            inventory_write(&mut output, row)?;
        }
        let mut file = finish_writer(output)?;
        for level in 0.. {
            if level == self.levels.len() {
                self.levels.push(None);
            }
            match self.levels[level].take() {
                Some(previous) => file = Self::merge(previous, file, &self.order)?,
                None => {
                    self.levels[level] = Some(file);
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> io::Result<File> {
        self.spill()?;
        let mut result = None;
        for file in self.levels.into_iter().flatten() {
            result = Some(match result {
                None => file,
                Some(previous) => Self::merge(previous, file, &self.order)?,
            });
        }
        result.map_or_else(scratch_file, Ok)
    }
}

#[derive(Debug)]
pub struct Finding {
    pub code: String,
    pub record: Option<u64>,
    pub detail: String,
    pub is_error: bool,
}

#[derive(Default)]
pub struct Findings {
    map: Option<memmap2::Mmap>,
    count: usize,
}

pub struct FindingIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: usize,
}

fn finding_row(bytes: &[u8], offset: usize) -> io::Result<(&str, Option<u64>, bool, &str, usize)> {
    let truncated = || io::Error::other("truncated finding");
    let header = bytes.get(offset..offset + FINDING_HEADER_BYTES).ok_or_else(truncated)?;
    if header[1] > 1 {
        return Err(io::Error::other("invalid finding severity"));
    }
    let detail_len = ntfs_rs::bytes::u32_at(header, FINDING_DETAIL_LENGTH_OFFSET)? as usize;
    let code_start = offset + FINDING_HEADER_BYTES;
    let detail_start = code_start + usize::from(header[0]);
    let end = detail_start + detail_len;
    let text = |range: std::ops::Range<usize>| {
        std::str::from_utf8(bytes.get(range).ok_or_else(truncated)?).map_err(io::Error::other)
    };
    let record = u64_at(header, FINDING_RECORD_OFFSET)?;
    Ok((
        text(code_start..detail_start)?,
        (record != NO_RECORD).then_some(record),
        header[1] == 1,
        text(detail_start..end)?,
        end,
    ))
}

impl Findings {
    fn open(file: &File, count: u64) -> io::Result<Self> {
        let count = count as usize;
        if file.metadata()?.len() == 0 {
            if count != 0 {
                return Err(io::Error::other("missing findings"));
            }
            return Ok(Self::default());
        }
        let map = unsafe { memmap2::Mmap::map(file)? };
        let mut offset = 0;
        for _ in 0..count {
            offset = finding_row(&map, offset)?.4;
        }
        if offset != map.len() {
            return Err(io::Error::other("finding count or length mismatch"));
        }
        Ok(Self { map: Some(map), count })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> FindingIter<'_> {
        FindingIter { bytes: self.map.as_deref().unwrap_or(&[]), offset: 0, remaining: self.count }
    }
}

impl Iterator for FindingIter<'_> {
    type Item = Finding;

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }

    fn next(&mut self) -> Option<Finding> {
        if self.remaining == 0 {
            return None;
        }
        // Findings::open validated every row before exposing this iterator.

        let (code, record, is_error, detail, end) =
            finding_row(self.bytes, self.offset).expect("validated finding spool changed");
        self.offset = end;
        self.remaining -= 1;
        Some(Finding { code: code.to_owned(), record, is_error, detail: detail.to_owned() })
    }
}

impl ExactSizeIterator for FindingIter<'_> {}

impl<'a> IntoIterator for &'a Findings {
    type Item = Finding;
    type IntoIter = FindingIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::fmt::Debug for Findings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Outcome of an online scan. Automatic repair mode publishes a queue only
/// when the complete offline plan passes an audit of its proposed image.
/// Forced offline mode also queues unsupported defects, preserving the
/// planner's blocker and unresolved count for the subsequent offline repair.
#[derive(Debug, Default)]
pub struct OnlineRepairStatus {
    pub scan_resources: super::ScanResources,
    pub scan_memory_percent: Option<u8>,
    pub scan_io_priority: Option<super::ScanIoPriority>,
    pub scan_write_cache_bytes: Option<u64>,
    pub(crate) scan_budget: super::ScanBudget,
    pub(crate) write_views: Option<crate::recovery_io::WriteViewStats>,
    pub online_repairs_bypassed: bool,
    pub ea_repairs: u64,
    pub data_repairs: u64,
    pub allocation_repairs: u64,
    pub queued_findings: u64,
    pub unresolved_findings: u64,
    pub queue_written: bool,
    pub blocker: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditOptions {
    pub skip_directory_cycles: bool,
    pub index_check: IndexCheck,
    pub index_cache_passes: IndexCachePasses,
}

/// Queue policy word: cache passes in the low 16 bits (all ones means auto),
/// and the quick-check flag in bit 16.
const POLICY_AUTO_PASSES: u16 = u16::MAX;
const POLICY_QUICK_SHIFT: u32 = u16::BITS;
const POLICY_KNOWN_BITS: u64 = (1 << (POLICY_QUICK_SHIFT + 1)) - 1;

impl AuditOptions {
    pub(crate) fn index_policy_word(self) -> u64 {
        let passes = match self.index_cache_passes {
            IndexCachePasses::Auto => POLICY_AUTO_PASSES,
            IndexCachePasses::Streaming => 0,
            IndexCachePasses::Count(n) => n.get(),
        };
        u64::from(passes) | (u64::from(self.index_check == IndexCheck::Quick) << POLICY_QUICK_SHIFT)
    }

    pub(crate) fn from_index_policy_word(word: u64) -> Option<Self> {
        if word & !POLICY_KNOWN_BITS != 0 {
            return None;
        }
        let index_cache_passes = match word as u16 {
            POLICY_AUTO_PASSES => IndexCachePasses::Auto,
            0 => IndexCachePasses::Streaming,
            count => IndexCachePasses::Count(std::num::NonZeroU16::new(count)?),
        };
        let index_check = if word >> POLICY_QUICK_SHIFT == 0 { IndexCheck::Full } else { IndexCheck::Quick };
        Some(Self { skip_directory_cycles: false, index_check, index_cache_passes })
    }
}

#[derive(Debug, Default)]
pub struct Audit {
    pub directory_cycles_checked: bool,
    pub index_check: IndexCheck,
    pub index_cache_passes: u64,
    pub index_cache_fallback: bool,
    pub index_entries_full: u64,
    pub index_entries_reduced: u64,
    pub index_rechecked_records: u64,
    index_slots: u64,
    index_full_targets: Option<File>,
    index_repair_directories: Option<File>,
    pub allocated_records: u64,
    pub directories: u64,
    pub directory_entries: u64,
    pub referenced_clusters: u64,
    pub allocated_clusters: u64,
    pub missing_clusters: u64,
    pub cross_linked_clusters: u64,
    pub descriptors: u64,
    pub complete: bool,
    /// Complete findings backed by a private file; iteration loads one row.
    pub findings: Findings,
    pub finding_count: u64,
    pub errors: u64,
    pub online_repair: Option<OnlineRepairStatus>,
    /// Rolling digest of every finding. Used to bind a queued spot fix to its scan.
    pub fingerprint: u64,
    pub(crate) worklist: Option<File>,
    worklist_error: Option<io::Error>,
    report_file: Option<File>,
    report_error: Option<io::Error>,
}

pub(crate) fn json_string(output: &mut impl Write, value: &str) -> io::Result<()> {
    output.write_all(b"\"")?;
    for c in value.chars() {
        match c {
            '"' => output.write_all(b"\\\"")?,
            '\\' => output.write_all(b"\\\\")?,
            c if c < ' ' => write!(output, "\\u{:04x}", c as u32)?,
            c => write!(output, "{c}")?,
        }
    }
    output.write_all(b"\"")
}

/// Render an optional count as JSON or as the report's placeholder word.
fn optional(value: Option<impl ToString>, absent: &str) -> String {
    value.map_or_else(|| absent.to_owned(), |value| value.to_string())
}

impl Audit {
    fn index_name(&self) -> &'static str {
        match self.index_check {
            IndexCheck::Full => "full",
            IndexCheck::Quick => "quick",
        }
    }

    fn index_needs_repair(&mut self, number: u64) -> io::Result<()> {
        if number < self.index_slots {
            if let Some(file) = self.index_repair_directories.as_mut() {
                audit_slot(file, number, MARKED)?;
            }
        }
        Ok(())
    }

    pub(crate) fn index_directory_needs_repair(&mut self, number: u64) -> io::Result<bool> {
        match self.index_repair_directories.as_mut() {
            Some(file) => Ok(audit_slot(file, number, None)?.is_some()),
            None => Ok(true),
        }
    }

    fn index_target_checked_fully(&mut self, number: u64) -> io::Result<bool> {
        if self.index_check == IndexCheck::Full {
            return Ok(true);
        }
        Ok(audit_slot(self.index_full_targets.as_mut().unwrap(), number, None)? == Some(1))
    }

    /// Stream all findings, counters and the online repair assessment as JSON.
    pub fn write_json(&self, output: &mut impl Write) -> io::Result<()> {
        write!(output, "{{\"schema_version\":1,\"passed\":{},", self.passed())?;
        self.write_json_fields(output)?;
        output.write_all(b"}")
    }

    pub(crate) fn write_json_fields(&self, output: &mut impl Write) -> io::Result<()> {
        write!(
            output,
            "\"complete\":{},\"errors\":{},\"finding_count\":{},\"omitted_findings\":0,\"directory_cycles_checked\":{},",
            self.complete, self.errors, self.finding_count, self.directory_cycles_checked
        )?;
        write!(
            output,
            concat!(
                "\"index_check\":\"{}\",\"index_cache_passes\":{},\"index_cache_fallback\":{},",
                "\"index_entries_full\":{},\"index_entries_reduced\":{},\"index_rechecked_records\":{},"
            ),
            self.index_name(),
            self.index_cache_passes,
            self.index_cache_fallback,
            self.index_entries_full,
            self.index_entries_reduced,
            self.index_rechecked_records
        )?;
        write!(
            output,
            concat!(
                "\"allocated_records\":{},\"directories\":{},\"directory_entries\":{},\"referenced_clusters\":{},",
                "\"allocated_clusters\":{},\"missing_clusters\":{},\"cross_linked_clusters\":{},\"descriptors\":{},",
                "\"coverage\":\"implemented-structural-and-system-metadata-audit\",\"online_repair\":"
            ),
            self.allocated_records,
            self.directories,
            self.directory_entries,
            self.referenced_clusters,
            self.allocated_clusters,
            self.missing_clusters,
            self.cross_linked_clusters,
            self.descriptors
        )?;
        if let Some(status) = &self.online_repair {
            write!(
                output,
                concat!(
                    "{{\"online_repairs_bypassed\":{},\"ea_repairs\":{},\"data_repairs\":{},\"allocation_repairs\":{},",
                    "\"queue_written\":{},\"queued_findings\":{},\"unresolved_findings\":{},\"blocker\":"
                ),
                status.online_repairs_bypassed,
                status.ea_repairs,
                status.data_repairs,
                status.allocation_repairs,
                status.queue_written,
                status.queued_findings,
                status.unresolved_findings
            )?;
            match &status.blocker {
                Some(reason) => json_string(output, reason)?,
                None => output.write_all(b"null")?,
            }
            // A failed preflight cannot provide complete cache measurements.

            let views = status.write_views;
            write!(
                output,
                concat!(
                    ",\"scan_resources\":\"{}\",\"scan_read_buffer_bytes\":{},\"scan_index_cache_bytes\":{}",
                    ",\"scan_write_view_cache_bytes\":{},\"scan_write_cache_requested_bytes\":{}",
                    ",\"scan_write_view_peak_bytes\":{},\"scan_write_view_hits\":{},\"scan_write_view_spills\":{}",
                    ",\"scan_memory_percent\":{},\"scan_io_priority\":"
                ),
                status.scan_resources.name(),
                status.scan_budget.read_buffer_bytes,
                status.scan_budget.index_cache_bytes,
                status.scan_budget.write_view_cache_bytes,
                optional(status.scan_write_cache_bytes, "null"),
                optional(views.map(|stats| stats.peak_bytes), "null"),
                optional(views.map(|stats| stats.hits), "null"),
                optional(views.map(|stats| stats.spills), "null"),
                optional(status.scan_memory_percent, "null"),
            )?;
            match status.scan_io_priority {
                Some(priority) => json_string(output, priority.name())?,
                None => output.write_all(b"null")?,
            }
            output.write_all(b"}")?;
        } else {
            output.write_all(b"null")?;
        }
        output.write_all(b",\"findings\":[")?;
        let mut first = true;
        self.for_each_finding(|code, record, is_error, detail| {
            if !first {
                output.write_all(b",")?;
            }
            first = false;
            output.write_all(b"{\"code\":")?;
            json_string(output, code)?;
            write!(output, ",\"record\":{},\"detail\":", optional(record, "null"))?;
            json_string(output, detail)?;
            write!(output, ",\"is_error\":{is_error}")?;
            if let Some(status) = &self.online_repair {
                let disposition = match (is_error, status.queue_written) {
                    (false, _) => "informational",
                    (true, true) => "queued",
                    (true, false) => "unresolved",
                };
                output.write_all(b",\"repair_disposition\":")?;
                json_string(output, disposition)?;
            }
            output.write_all(b"}")
        })?;
        output.write_all(b"]")
    }

    pub fn save_report(&self, path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(PRIVATE_FILE_MODE).open(path)?;
        self.write_report(&mut file)?;
        file.sync_all()
    }

    /// Stream the complete human-readable finding report to a caller-owned
    /// destination. The caller decides whether to persist it.
    pub fn write_report(&self, output: &mut impl Write) -> io::Result<()> {
        writeln!(output, "directory_cycles_checked={}", u8::from(self.directory_cycles_checked))?;
        writeln!(
            output,
            "index_check={} index_cache_passes={} index_cache_fallback={} index_entries_full={} \
             index_entries_reduced={} index_rechecked_records={}",
            self.index_name(),
            self.index_cache_passes,
            u8::from(self.index_cache_fallback),
            self.index_entries_full,
            self.index_entries_reduced,
            self.index_rechecked_records
        )?;
        self.for_each_finding(|code, record, is_error, detail| {
            writeln!(
                output,
                "finding={code} record={} severity={} detail={detail}",
                optional(record, "-"),
                if is_error { "error" } else { "info" },
            )
        })?;
        if let Some(status) = &self.online_repair {
            let views = status.write_views;
            writeln!(
                output,
                "scan_resources={} scan_read_buffer_bytes={} scan_index_cache_bytes={}",
                status.scan_resources.name(),
                status.scan_budget.read_buffer_bytes,
                status.scan_budget.index_cache_bytes
            )?;
            writeln!(
                output,
                "scan_write_view_cache_bytes={} scan_write_view_peak_bytes={} scan_write_view_hits={} \
                 scan_write_view_spills={} scan_write_cache_requested_bytes={}",
                status.scan_budget.write_view_cache_bytes,
                optional(views.map(|stats| stats.peak_bytes), "unavailable"),
                optional(views.map(|stats| stats.hits), "unavailable"),
                optional(views.map(|stats| stats.spills), "unavailable"),
                optional(status.scan_write_cache_bytes, "default"),
            )?;
            writeln!(
                output,
                "scan_memory_percent={} scan_io_priority={}",
                optional(status.scan_memory_percent, "default"),
                status.scan_io_priority.map_or("inherited", |priority| priority.name())
            )?;
            writeln!(
                output,
                "online_repair ea={} data={} allocation={} queued={} queued_findings={} unresolved_findings={}",
                status.ea_repairs,
                status.data_repairs,
                status.allocation_repairs,
                u8::from(status.queue_written),
                status.queued_findings,
                status.unresolved_findings
            )?;
            if let Some(reason) = &status.blocker {
                writeln!(output, "spotfix_unresolved_reason={reason}")?;
            }
        }
        Ok(())
    }

    pub fn for_each_finding(
        &self,
        mut emit: impl FnMut(&str, Option<u64>, bool, &str) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.report_error.is_some() {
            return Err(io::Error::other("audit report spool failed"));
        }
        for finding in self.findings.iter() {
            emit(&finding.code, finding.record, finding.is_error, &finding.detail)?;
        }
        Ok(())
    }

    pub(crate) fn worklist_file(&mut self) -> io::Result<&mut File> {
        if let Some(error) = self.worklist_error.take() {
            return Err(error);
        }
        let file = self.worklist.as_mut().ok_or_else(|| io::Error::other("missing audit worklist"))?;
        file.seek(SeekFrom::Start(0))?;
        Ok(file)
    }

    fn finding(&mut self, code: &'static str, record: Option<u64>, detail: impl Into<String>) {
        self.report(code, record, detail, true);
    }

    /// Record an error finding that also prevents a complete assessment.
    fn incomplete(&mut self, code: &'static str, record: Option<u64>, detail: impl Into<String>) {
        self.finding(code, record, detail);
        self.complete = false;
    }

    fn report(&mut self, code: &'static str, record: Option<u64>, detail: impl Into<String>, is_error: bool) {
        let detail = detail.into();
        let record = record.unwrap_or(NO_RECORD).to_le_bytes();
        let severity = [u8::from(is_error)];
        let mut hash = if self.fingerprint == 0 { super::FNV1A64_OFFSET_BASIS } else { self.fingerprint };
        for bytes in [code.as_bytes(), &record, &severity, detail.as_bytes()] {
            hash = super::fnv1a64_update(hash, bytes);
        }
        self.fingerprint = hash;
        self.errors += u64::from(is_error);
        self.finding_count += 1;
        let code_len = u8::try_from(code.len()).map_err(|_| io::Error::other("finding code too long"));
        // Spool failures are retained and surfaced once the audit finishes.

        if let (None, Some(file)) = (&self.worklist_error, self.worklist.as_mut()) {
            let write = code_len.as_ref().map_err(|error| io::Error::other(error.to_string())).and_then(|&n| {
                file.write_all(&[n, severity[0]])?;
                file.write_all(&record)?;
                file.write_all(code.as_bytes())
            });
            self.worklist_error = write.err();
        }
        if let (None, Some(file)) = (&self.report_error, self.report_file.as_mut()) {
            let detail_len = u32::try_from(detail.len()).map_err(|_| io::Error::other("finding detail too long"));
            let write = code_len.and_then(|n| {
                file.write_all(&[n, severity[0]])?;
                file.write_all(&record)?;
                file.write_all(&detail_len?.to_le_bytes())?;
                file.write_all(code.as_bytes())?;
                file.write_all(detail.as_bytes())
            });
            self.report_error = write.err();
        }
    }

    fn unsupported(&mut self, record: u64, detail: impl Into<String>) {
        self.incomplete("unsupported", Some(record), detail);
    }

    pub fn passed(&self) -> bool {
        self.complete && self.errors == 0
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Name {
    duplicate: [u8; filename::DUPLICATED_INFORMATION_BYTES],
    parent: u64,
    namespace: u8,
    text: Vec<u8>,
}

impl Name {
    /// Copy the indexed fields of a validated FILE_NAME value.
    fn from_value(value: &[u8]) -> Self {
        let duplicate = &value[filename::DUPLICATED_INFORMATION_OFFSET..][..filename::DUPLICATED_INFORMATION_BYTES];
        Self {
            duplicate: duplicate.try_into().unwrap(),
            parent: u64_at(value, filename::PARENT_REFERENCE_OFFSET).unwrap(),
            namespace: value[filename::NAMESPACE_OFFSET],
            text: value[filename::HEADER_BYTES..].to_vec(),
        }
    }
}

struct Record {
    reference: u64,
    base: u64,
    directory: bool,
    names: Vec<Name>,
    has_attribute_list: bool,
    canonical: Option<[u8; filename::DUPLICATED_INFORMATION_BYTES]>,
}

/// RecordStore row layout: reference, base, directory, list, canonical flag,
/// padding, name count, canonical duplicated information.
const STORE_HEADER_BYTES: usize = 80;
const STORE_SUMMARY_BYTES: usize = 24;
const STORE_DIRECTORY: usize = 16;
const STORE_LIST: usize = 17;
const STORE_CANONICAL_FLAG: usize = 18;
const STORE_COUNT: usize = 20;
const STORE_CANONICAL: usize = 24;
/// Name rows: parent, namespace, text length, text, duplicated information.
const STORE_NAME_HEADER_BYTES: usize = 11;
const STORE_NAME_NAMESPACE: usize = 8;
const STORE_NAME_LENGTH: usize = 9;
const STORE_OFFSET_BYTES: u64 = std::mem::size_of::<u64>() as u64;

// The slot table is sparse and file-backed; variable-size names live in a
// separate append-only scratch file. Only the record being used is decoded.
struct RecordStore {
    slots: u64,
    files: std::cell::RefCell<(File, File)>,
}

impl RecordStore {
    fn new(slots: u64) -> io::Result<Self> {
        let index = scratch_file()?;
        index.set_len(slots * STORE_OFFSET_BYTES)?;
        Ok(Self { slots, files: std::cell::RefCell::new((index, scratch_file()?)) })
    }

    /// Position the data file at a stored row; absent slots return false.
    fn seek_row(index: &mut File, data: &mut File, slots: u64, number: u64) -> io::Result<bool> {
        if number >= slots {
            return Ok(false);
        }
        index.seek(SeekFrom::Start(number * STORE_OFFSET_BYTES))?;
        let mut word = [0; STORE_OFFSET_BYTES as usize];
        index.read_exact(&mut word)?;
        let offset = u64::from_le_bytes(word);
        if offset == 0 {
            return Ok(false);
        }
        data.seek(SeekFrom::Start(offset - 1))?;
        Ok(true)
    }

    /// Reference, base reference and name count without decoding names.
    fn summary(&self, number: u64) -> io::Result<Option<(u64, u64, u64)>> {
        let (index, data) = &mut *self.files.borrow_mut();
        if !Self::seek_row(index, data, self.slots, number)? {
            return Ok(None);
        }
        let mut header = [0; STORE_SUMMARY_BYTES];
        data.read_exact(&mut header)?;
        let count = ntfs_rs::bytes::u32_at(&header, STORE_COUNT)?;
        Ok(Some((u64_at(&header, 0)?, u64_at(&header, 8)?, u64::from(count))))
    }

    fn get(&self, number: &u64) -> io::Result<Option<Record>> {
        let (index, data) = &mut *self.files.borrow_mut();
        if !Self::seek_row(index, data, self.slots, *number)? {
            return Ok(None);
        }
        let mut header = [0; STORE_HEADER_BYTES];
        data.read_exact(&mut header)?;
        let count = ntfs_rs::bytes::u32_at(&header, STORE_COUNT)?;
        let mut names = Vec::new();
        for _ in 0..count {
            let mut name_header = [0; STORE_NAME_HEADER_BYTES];
            data.read_exact(&mut name_header)?;
            let length = usize::from(u16_at(&name_header, STORE_NAME_LENGTH)?);
            if length > filename::MAX_NAME_BYTES || length % filename::CODE_UNIT_BYTES != 0 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let mut text = vec![0; length];
            data.read_exact(&mut text)?;
            let mut duplicate = [0; filename::DUPLICATED_INFORMATION_BYTES];
            data.read_exact(&mut duplicate)?;
            names.push(Name {
                duplicate,
                parent: u64_at(&name_header, 0)?,
                namespace: name_header[STORE_NAME_NAMESPACE],
                text,
            });
        }
        Ok(Some(Record {
            reference: u64_at(&header, 0)?,
            base: u64_at(&header, 8)?,
            names,
            directory: header[STORE_DIRECTORY] != 0,
            has_attribute_list: header[STORE_LIST] != 0,
            canonical: (header[STORE_CANONICAL_FLAG] != 0).then(|| header[STORE_CANONICAL..].try_into().unwrap()),
        }))
    }

    fn insert(&self, number: u64, record: Record) -> io::Result<()> {
        if number >= self.slots {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let (index, data) = &mut *self.files.borrow_mut();
        let offset = data.seek(SeekFrom::End(0))? + 1;
        let mut header = [0; STORE_HEADER_BYTES];
        header[..8].copy_from_slice(&record.reference.to_le_bytes());
        header[8..16].copy_from_slice(&record.base.to_le_bytes());
        header[STORE_DIRECTORY] = u8::from(record.directory);
        header[STORE_LIST] = u8::from(record.has_attribute_list);
        header[STORE_COUNT..STORE_CANONICAL].copy_from_slice(&(record.names.len() as u32).to_le_bytes());
        if let Some(canonical) = record.canonical {
            header[STORE_CANONICAL_FLAG] = 1;
            header[STORE_CANONICAL..].copy_from_slice(&canonical);
        }
        data.write_all(&header)?;
        for name in record.names {
            data.write_all(&name.parent.to_le_bytes())?;
            data.write_all(&[name.namespace])?;
            data.write_all(&(name.text.len() as u16).to_le_bytes())?;
            data.write_all(&name.text)?;
            data.write_all(&name.duplicate)?;
        }
        index.seek(SeekFrom::Start(number * STORE_OFFSET_BYTES))?;
        index.write_all(&offset.to_le_bytes())
    }

    fn iter(&self) -> impl Iterator<Item = io::Result<(u64, Record)>> + '_ {
        (0..self.slots).filter_map(|number| self.get(&number).transpose().map(|record| record.map(|r| (number, r))))
    }
}

// Iterative DFS with disk-backed colors and stack frames. Namespace aliases
// and regular-file hardlinks are edges, but only directory backedges are cycles.
fn audit_directory_cycles(
    records: &RecordStore,
    children: &mut File,
    out: &mut Audit,
    options: AuditOptions,
) -> io::Result<()> {
    const FRAME_BYTES: u64 = 2 * std::mem::size_of::<u64>() as u64;

    out.directory_cycles_checked = !options.skip_directory_cycles;
    if options.skip_directory_cycles {
        return Ok(());
    }
    let mut colors = scratch_file()?;
    let mut stack = scratch_file()?;
    let push = |stack: &mut File, children: &mut File, depth: u64, node: u64| -> io::Result<()> {
        let first = inventory_lower_bound(children, node)?;
        stack.seek(SeekFrom::Start(depth * FRAME_BYTES))?;
        stack.write_all(&node.to_le_bytes())?;
        stack.write_all(&first.to_le_bytes())
    };
    for item in records.iter() {
        let (root, record) = item?;
        if !record.directory || record.base != 0 || audit_slot(&mut colors, root, None)?.is_some() {
            continue;
        }
        audit_slot(&mut colors, root, Some(Some(VISITING)))?;
        push(&mut stack, children, 0, root)?;
        let mut depth = 1_u64;
        while depth != 0 {
            let frame = (depth - 1) * FRAME_BYTES;
            stack.seek(SeekFrom::Start(frame))?;
            let mut bytes = [0; FRAME_BYTES as usize];
            stack.read_exact(&mut bytes)?;
            let node = u64_at(&bytes, 0)?;
            let next = u64_at(&bytes, 8)?;
            children.seek(SeekFrom::Start(next * INVENTORY_BYTES as u64))?;
            let Some([owner, child, _, _]) = inventory_next(children)?.filter(|edge| edge[0] == node) else {
                audit_slot(&mut colors, node, Some(Some(VISITED)))?;
                depth -= 1;
                continue;
            };
            stack.seek(SeekFrom::Start(frame + STORE_OFFSET_BYTES))?;
            stack.write_all(&(next + 1).to_le_bytes())?;
            // The root's conventional reference to itself is not a folder cycle.

            if owner == system_record::ROOT && child == system_record::ROOT {
                continue;
            }
            if !records.get(&child)?.is_some_and(|record| record.directory && record.base == 0) {
                continue;
            }
            match audit_slot(&mut colors, child, None)? {
                Some(VISITING) => out.finding(
                    "directory-cycle",
                    Some(child),
                    format!("directory index edge {owner} -> {child} closes a folder cycle"),
                ),
                Some(_) => {}
                None => {
                    audit_slot(&mut colors, child, Some(Some(VISITING)))?;
                    push(&mut stack, children, depth, child)?;
                    depth += 1;
                }
            }
        }
    }
    Ok(())
}

struct DirectoryAuditState<'a> {
    number: u64,
    parent: u64,
    upcase: Option<&'a [u8]>,
    entries: &'a mut index_check::Entries,
    previous_name: Option<Vec<u8>>,
    position: u64,
    out: &'a mut Audit,
}

impl DirectoryAuditState<'_> {
    fn visit(&mut self, entry: IndexEntry<'_>) -> ntfs_rs::Result<()> {
        self.out.directory_entries += 1;
        self.position += 1;
        if let Some(upcase) = self.upcase {
            let out_of_order = self
                .previous_name
                .as_deref()
                .is_some_and(|previous| compare_names(upcase, previous, entry.name.utf16le) != Ordering::Less);
            if out_of_order {
                self.out.index_needs_repair(self.number).map_err(|_| ntfs_rs::Error::Io)?;
                self.out.finding(
                    "directory-index-order",
                    Some(self.number),
                    format!("in-order entry {} does not collate strictly after its predecessor", self.position),
                );
            }
            self.previous_name = Some(entry.name.utf16le.to_vec());
        }
        self.entries.push(self.parent, entry).map_err(|_| ntfs_rs::Error::Io)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct OwnedAttribute {
    file_reference: u64,
    kind: u32,
    first_vcn: u64,
    attribute_id: u16,
    name: Vec<u8>,
}

impl OwnedAttribute {
    fn new(reference: u64, attribute: Attribute<'_>) -> io::Result<Self> {
        Ok(Self {
            file_reference: reference,
            kind: attribute.kind,
            first_vcn: if attribute.nonresident { attribute.first_vcn()? } else { 0 },
            attribute_id: attribute.id,
            name: attribute.name_utf16le()?.to_vec(),
        })
    }

    fn key(&self) -> FamilyKey {
        FamilyKey {
            kind: self.kind,
            name: self.name.clone(),
            vcn: self.first_vcn,
            reference: self.file_reference,
            id: self.attribute_id,
        }
    }

    fn is_i30(&self) -> bool {
        matches!(self.kind, ATTR_INDEX_ROOT | ATTR_INDEX_ALLOCATION | ATTR_BITMAP)
            && self.name.as_slice() == I30_NAME_UTF16LE
    }

    fn describe(&self) -> String {
        format!("type=0x{:x} id={} first_vcn={}", self.kind, self.attribute_id, self.first_vcn)
    }

    /// Count physical attributes in record carrying this list identity.
    fn matches_in(&self, record: &MftRecord<'_>) -> io::Result<usize> {
        let mut matches = 0;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.id == self.attribute_id
                && attribute.kind == self.kind
                && OwnedAttribute::new(self.file_reference, attribute)? == *self
            {
                matches += 1;
            }
        }
        Ok(matches)
    }
}

fn unnamed<'a>(record: &MftRecord<'a>, kind: u32) -> io::Result<Attribute<'a>> {
    let mut found = None;
    for attribute in record.attributes() {
        let attribute = attribute?;
        if attribute.kind == kind && attribute.name_utf16le()?.is_empty() && found.replace(attribute).is_some() {
            return Err(invalid(ntfs_rs::Error::InvalidAttribute));
        }
    }
    found.ok_or_else(|| invalid(ntfs_rs::Error::InvalidAttribute))
}

/// Visit each distinct row key of a sorted inventory.
fn for_each_distinct(rows: &mut BufReader<File>, mut visit: impl FnMut(u64) -> io::Result<()>) -> io::Result<()> {
    rows.seek(SeekFrom::Start(0))?;
    let mut previous = None;
    while let Some([key, ..]) = inventory_next(rows)? {
        if previous.replace(key) != Some(key) {
            visit(key)?;
        }
    }
    Ok(())
}

fn audit_attribute_lists<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    records: &RecordStore,
    base_buffer: &mut [u8],
    extension_buffer: &mut [u8],
    out: &mut Audit,
) -> io::Result<(File, File)> {
    let mut claimed_extensions = scratch_file()?;
    let mut incomplete_bases = scratch_file()?;
    let mut directory_lists_in_base = scratch_file()?;
    let mut validated_extensions = scratch_file()?;
    let sector = volume.boot.bytes_per_sector;
    let volume_bytes = volume.boot.total_sectors.saturating_mul(u64::from(sector));
    for item in records.iter() {
        let (number, metadata) = item?;
        if !metadata.has_attribute_list {
            continue;
        }
        volume.read_mft_record(mft, number, base_buffer)?;
        let record = match MftRecord::parse(base_buffer, sector) {
            Ok(record) => record,
            Err(error) => {
                out.incomplete("attribute-list-invalid", Some(number), error.to_string());
                continue;
            }
        };
        let reference = metadata.reference;
        let mut list = None;
        let mut list_valid = true;
        for attribute in record.attributes() {
            match attribute {
                Ok(attribute) if attribute.kind == ATTR_ATTRIBUTE_LIST => {
                    list_valid &= list.replace(attribute).is_none();
                }
                Ok(_) => {}
                Err(error) => {
                    out.incomplete("attribute-list-invalid", Some(number), error.to_string());
                    list_valid = false;
                    break;
                }
            }
        }
        if !list_valid {
            out.incomplete(
                "attribute-list-invalid",
                Some(number),
                "record contains multiple or structurally invalid attribute lists",
            );
            continue;
        }
        let Some(list) = list else {
            continue;
        };
        if record.base_file_reference()? != 0 {
            out.incomplete(
                "attribute-list-on-extension",
                Some(number),
                "extension record owns an $ATTRIBUTE_LIST instead of its base record",
            );
            continue;
        }
        if !list.name_utf16le()?.is_empty() || list.flags()? != 0 {
            out.finding("attribute-list-invalid", Some(number), "$ATTRIBUTE_LIST must be unnamed and unflagged");
            list_valid = false;
        }
        let mut listed = FamilyKeysBuilder::new()?;
        let mut extension_numbers = DiskInventory::new();
        let mut external_i30 = false;
        let list_size = list.data_size()?;
        if list_size == 0 || list_size > volume_bytes {
            audit_slot(&mut incomplete_bases, number, MARKED)?;
            out.unsupported(number, "attribute list exceeds volume size");
            continue;
        }
        let list_len = list_size as usize;
        let list_backing = scratch_file()?;
        list_backing.set_len(list_size)?;
        let mut list_bytes = unsafe { memmap2::MmapMut::map_mut(&list_backing)? };
        let read = (0..list_len).step_by(LIST_READ_BYTES).try_for_each(|at| {
            let end = (at + LIST_READ_BYTES).min(list_len);
            volume.read_attribute(list, at as u64, &mut list_bytes[at..end])
        });
        if let Err(error) = read {
            audit_slot(&mut incomplete_bases, number, MARKED)?;
            out.incomplete("attribute-list-invalid", Some(number), error.to_string());
            continue;
        }
        let mut parsed_all = true;
        for entry in AttributeList::new(&list_bytes) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    out.incomplete("attribute-list-invalid", Some(number), error.to_string());
                    parsed_all = false;
                    list_valid = false;
                    break;
                }
            };
            let owned = OwnedAttribute {
                file_reference: entry.file_reference,
                kind: entry.kind,
                first_vcn: entry.first_vcn,
                attribute_id: entry.attribute_id,
                name: entry.name_utf16le.to_vec(),
            };
            if owned.kind == ATTR_ATTRIBUTE_LIST {
                out.finding("attribute-list-self-entry", Some(number), "$ATTRIBUTE_LIST must not list itself");
                list_valid = false;
            }
            listed.push(owned.key())?;
            let target_number = reference_number(owned.file_reference);
            let Some(target_meta) = records.get(&target_number)? else {
                out.finding(
                    "attribute-list-reference",
                    Some(number),
                    format!("entry references missing record {target_number}"),
                );
                list_valid = false;
                continue;
            };
            if target_meta.reference != owned.file_reference {
                out.finding(
                    "attribute-list-reference",
                    Some(number),
                    format!("entry has stale sequence for record {target_number}"),
                );
                list_valid = false;
                continue;
            }
            let matches = if target_number == number {
                if target_meta.base != 0 {
                    out.finding(
                        "attribute-list-owner",
                        Some(number),
                        "base-list entry points at a record that is itself an extension",
                    );
                    list_valid = false;
                }
                owned.matches_in(&record)?
            } else {
                if target_meta.base != reference {
                    out.finding(
                        "attribute-list-owner",
                        Some(target_number),
                        format!("extension does not point back to base record {number}"),
                    );
                    list_valid = false;
                    continue;
                }
                extension_numbers.push([target_number, 0, 0, 0])?;
                external_i30 |= owned.is_i30();
                let previous = audit_slot(&mut claimed_extensions, target_number, Some(Some(reference)))?;
                if previous.is_some_and(|previous| previous != reference) {
                    out.finding(
                        "attribute-list-owner",
                        Some(target_number),
                        "extension record is claimed by more than one base record",
                    );
                    list_valid = false;
                }
                volume.read_mft_record(mft, target_number, extension_buffer)?;
                match MftRecord::parse(extension_buffer, sector) {
                    Ok(extension) => owned.matches_in(&extension)?,
                    Err(error) => {
                        out.incomplete("attribute-list-reference", Some(target_number), error.to_string());
                        list_valid = false;
                        continue;
                    }
                }
            };
            if matches != 1 {
                out.finding(
                    "attribute-list-entry-mismatch",
                    Some(number),
                    format!("entry {} matches {matches} attributes in record {target_number}", owned.describe()),
                );
                list_valid = false;
            }
        }
        if !parsed_all {
            audit_slot(&mut incomplete_bases, number, MARKED)?;
            continue;
        }
        let mut listed = listed.finish()?;
        let mut previous_key = None;
        while let Some(key) = listed.next()? {
            if previous_key.as_ref() == Some(&key) {
                out.finding(
                    "attribute-list-duplicate",
                    Some(number),
                    format!("duplicate entry type=0x{:x} id={} first_vcn={}", key.kind, key.id, key.vcn),
                );
                list_valid = false;
            }
            previous_key = Some(key);
        }
        listed.rewind()?;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind == ATTR_ATTRIBUTE_LIST {
                continue;
            }
            let owned = OwnedAttribute::new(reference, attribute)?;
            if !listed.contains(&owned.key())? {
                out.finding(
                    "attribute-list-missing-attribute",
                    Some(number),
                    format!("base attribute {} is absent from the list", owned.describe()),
                );
                list_valid = false;
            }
        }
        let mut extension_numbers = BufReader::new(extension_numbers.finish()?);
        for_each_distinct(&mut extension_numbers, |extension_number| {
            volume.read_mft_record(mft, extension_number, extension_buffer)?;
            let extension = MftRecord::parse(extension_buffer, sector)?;
            let extension_reference =
                records.get(&extension_number)?.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?.reference;
            for attribute in extension.attributes() {
                let attribute = attribute?;
                if attribute.kind == ATTR_ATTRIBUTE_LIST {
                    out.finding(
                        "attribute-list-on-extension",
                        Some(extension_number),
                        "extension record contains an $ATTRIBUTE_LIST",
                    );
                    list_valid = false;
                    continue;
                }
                let owned = OwnedAttribute::new(extension_reference, attribute)?;
                external_i30 |= owned.is_i30();
                if !listed.contains(&owned.key())? {
                    out.finding(
                        "attribute-list-missing-attribute",
                        Some(extension_number),
                        format!("extension attribute {} is absent from base record {number}'s list", owned.describe()),
                    );
                    list_valid = false;
                }
            }
            Ok(())
        })?;
        if !list_valid {
            out.complete = false;
            continue;
        }
        for_each_distinct(&mut extension_numbers, |extension_number| {
            audit_slot(&mut validated_extensions, extension_number, Some(Some(number))).map(|_| ())
        })?;
        if metadata.directory && !external_i30 {
            audit_slot(&mut directory_lists_in_base, number, MARKED)?;
        }
    }
    for item in records.iter() {
        let (number, record) = item?;
        if record.base == 0 {
            continue;
        }
        let base_number = reference_number(record.base);
        let Some(base_meta) = records.get(&base_number)? else {
            out.finding(
                "extension-base-reference",
                Some(number),
                format!("extension points to missing base record {base_number}"),
            );
            continue;
        };
        if base_meta.reference != record.base {
            out.finding(
                "extension-base-reference",
                Some(number),
                format!("extension has a stale sequence reference to base record {base_number}"),
            );
            continue;
        }
        if audit_slot(&mut incomplete_bases, base_number, None)?.is_some()
            || audit_slot(&mut claimed_extensions, number, None)? == Some(record.base)
        {
            continue;
        }
        let detail = if base_meta.has_attribute_list {
            format!("extension is not owned by base record {base_number}'s attribute list")
        } else {
            format!("extension points to base record {base_number}, which has no attribute list")
        };
        out.finding("unlisted-extension-record", Some(number), detail);
        audit_slot(&mut directory_lists_in_base, base_number, Some(None))?;
    }
    Ok((directory_lists_in_base, validated_extensions))
}

/// Audit a volume image, optionally limited by the selected index policy.
pub fn audit(path: &Path, boot: BootSector, options: AuditOptions) -> io::Result<Audit> {
    audit_with_progress(path, boot, options, &mut |_| {})
}

/// `audit`, reporting how far its record and directory scans have come.
pub fn audit_with_progress(
    path: &Path,
    boot: BootSector,
    options: AuditOptions,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<Audit> {
    audit_reader_with_progress(
        Image::open(path)?,
        boot,
        |_, _, _| Ok(()),
        |_| Ok(()),
        options,
        INDEX_CACHE_BYTES,
        progress,
    )
}

/// Records between two progress reports of a scan over the MFT.
const PROGRESS_RECORD_INTERVAL: u64 = 256;

/// Report a scan's position at record `number` of `slots`, in the sector
/// units every phase uses.
pub(crate) fn scan_progress(progress: &mut dyn FnMut(RepairProgress), phase: Phase, boot: BootSector, number: u64, slots: u64) {
    if number % PROGRESS_RECORD_INTERVAL == 0 {
        let sectors = |records: u64| records * u64::from(boot.record_bytes) / u64::from(boot.bytes_per_sector);
        progress(RepairProgress::new(phase, sectors(number), sectors(slots)));
    }
}

/// Read up to one bitmap chunk containing the MFT bit for number.
fn mft_bit<R: ReadAt>(
    volume: &mut Volume<R>,
    bitmap: Attribute<'_>,
    bits: &mut [u8; BITMAP_READ_BYTES],
    slots: u64,
    number: u64,
) -> io::Result<bool> {
    let byte = number / BITS_PER_BYTE;
    if number % (BITMAP_READ_BYTES as u64 * BITS_PER_BYTE) == 0 {
        let n = (slots.div_ceil(BITS_PER_BYTE) - byte).min(BITMAP_READ_BYTES as u64) as usize;
        volume.read_attribute(bitmap, byte, &mut bits[..n])?;
    }
    Ok(bits[(byte % BITMAP_READ_BYTES as u64) as usize] & (1 << (number % BITS_PER_BYTE)) != 0)
}

/// Report MFT bitmap bits beyond a complete, dense $MFT mapping.
fn audit_mft_bitmap_padding<R: ReadAt>(
    volume: &mut Volume<R>,
    data: Attribute<'_>,
    bitmap: Attribute<'_>,
    end: u64,
    out: &mut Audit,
) -> io::Result<()> {
    // Only a complete dense mapping proves that trailing bits cannot name
    // physical records. A shorter initialized length alone is insufficient.

    let boot = volume.boot;
    let mut mapped_clusters = 0_u64;
    for run in DataRuns::new(data.data_runs()?, 0) {
        let run = run?;
        if run.vcn != mapped_clusters || run.lcn.is_none() {
            return Ok(());
        }
        mapped_clusters += run.len;
    }
    let mapped_slots = mapped_clusters * u64::from(boot.cluster_bytes) / u64::from(boot.record_bytes);
    let mut bits = [0; BITMAP_READ_BYTES];
    let mut extra_bits = 0_u64;
    let mut first_extra = None;
    for offset in (mapped_slots / BITS_PER_BYTE..end).step_by(BITMAP_READ_BYTES) {
        let n = (end - offset).min(BITMAP_READ_BYTES as u64) as usize;
        volume.read_attribute(bitmap, offset, &mut bits[..n])?;
        for (index, &value) in bits[..n].iter().enumerate() {
            let first = (offset + index as u64) * BITS_PER_BYTE;
            let skip = mapped_slots.saturating_sub(first).min(BITS_PER_BYTE) as u32;
            let value = value & ((u16::from(u8::MAX) << skip) as u8);
            if value != 0 {
                first_extra.get_or_insert(first + u64::from(value.trailing_zeros()));
                extra_bits += u64::from(value.count_ones());
            }
        }
    }
    if let Some(first) = first_extra {
        out.finding(
            "mft-bitmap-padding",
            Some(system_record::MFT),
            format!("{extra_bits} allocation bits beyond {mapped_slots} mapped MFT records; first={first}"),
        );
    }
    Ok(())
}

/// Validate one nonresident mapping and spool its physical extents.
fn inventory_runs(
    attribute: Attribute<'_>,
    number: u64,
    clusters: u64,
    extents: &mut DiskInventory,
) -> io::Result<ntfs_rs::Result<()>> {
    let mut inventory_error = None;
    let result = (|| {
        let first = attribute.first_vcn()?;
        let mut next = first;
        if first == 0 && attribute.initialized_size()? > attribute.data_size()? {
            return Err(ntfs_rs::Error::InvalidAttribute);
        }
        for run in DataRuns::new(attribute.data_runs()?, first) {
            let run = run?;
            if run.vcn != next {
                return Err(ntfs_rs::Error::InvalidRunlist);
            }
            next = next.checked_add(run.len).ok_or(ntfs_rs::Error::Overflow)?;
            if let Some(lcn) = run.lcn {
                let end = lcn.checked_add(run.len).ok_or(ntfs_rs::Error::Overflow)?;
                if end > clusters {
                    return Err(ntfs_rs::Error::InvalidRunlist);
                }
                if let Err(error) = extents.push([lcn, end, number, u64::from(attribute.id)]) {
                    inventory_error = Some(error);
                    return Err(ntfs_rs::Error::Io);
                }
            }
        }
        if next.wrapping_sub(1) != attribute.last_vcn()? {
            return Err(ntfs_rs::Error::InvalidRunlist);
        }
        Ok(())
    })();
    match inventory_error {
        Some(error) => Err(error),
        None => Ok(result),
    }
}

/// Compare the stored EA_INFORMATION with a canonical summary of the EA stream.
fn audit_ea<R: ReadAt>(
    volume: &mut Volume<R>,
    record: &MftRecord<'_>,
    number: u64,
    stream: &mut [u8],
    canonical: &mut [u8],
    out: &mut Audit,
    ea_candidate: &mut impl FnMut(u64) -> io::Result<()>,
) -> io::Result<()> {
    use ntfs_rs::ea;

    let info = record.local_attribute(ea::EA_INFO, &[])?;
    if ea::attribute(record)?.is_none() {
        if info.is_some() {
            out.finding("ea-info-orphan", Some(number), "EA_INFORMATION has no EA stream");
            ea_candidate(number)?;
        }
        return Ok(());
    }
    let length = match ea::read_stream(volume, record, stream) {
        Ok(length) => length,
        Err(ntfs_rs::Error::Unsupported) => {
            out.unsupported(number, "unsupported EA stream layout");
            return Ok(());
        }
        Err(error) => {
            out.finding("ea-invalid", Some(number), error.to_string());
            return Ok(());
        }
    };
    let mut builder = ea::Builder::new(canonical);
    let rebuilt = ea::visit(&stream[..length], |name, value, flags| {
        if ea::find(builder.bytes(), name)?.is_some() {
            return Err(ntfs_rs::Error::InvalidAttribute);
        }
        builder.push(name, value, flags)
    });
    if rebuilt.is_err() || builder.len() != length {
        out.finding("ea-invalid", Some(number), "EA entries cannot be safely summarized");
    } else if info.is_none_or(|attr| attr.resident_value().ok() != Some(builder.info().as_slice())) {
        out.finding("ea-summary-invalid", Some(number), "EA_INFORMATION differs from validated EA entries");
        ea_candidate(number)?;
    }
    Ok(())
}

/// Disk-backed arena for assembling one listed family; the image comes first.
fn family_arena(list: Attribute<'_>, record_bytes: usize) -> io::Result<(memmap2::MmapMut, usize)> {
    // Each list entry names at most one on-disk attribute. The logical output
    // can therefore be bounded without a fixed 16 KiB arena.

    let list_len = list.data_size()? as usize;
    let entries = list_len / LIST_ENTRY_MIN_BYTES + 1;
    let output_len = (entries + 1)
        .checked_mul(record_bytes)
        .filter(|n| u32::try_from(*n).is_ok())
        .ok_or_else(|| io::Error::other("family assembly exceeds record address space"))?;
    let scratch_len = entries * FAMILY_SCRATCH_PER_ENTRY + record_bytes + list_len;
    let backing = scratch_file()?;
    backing.set_len((output_len + scratch_len) as u64)?;
    Ok((unsafe { memmap2::MmapMut::map_mut(&backing)? }, output_len))
}

/// Scratch buffers reused by every audit phase.
struct Buffers {
    raw: Vec<u8>,
    secure: Vec<u8>,
    extension: Vec<u8>,
    index: Vec<u8>,
    security_lookup: Vec<u8>,
    descriptor: Vec<u8>,
    ea_stream: Vec<u8>,
    ea_canonical: Vec<u8>,
}

// Candidate bitmap edits are evidence only. The caller must finish the whole
// audit and reject every other error before considering any candidate writable.
pub(crate) fn audit_reader(
    source: impl ReadAt,
    boot: BootSector,
    candidate: impl FnMut(u64, u8, u8) -> io::Result<()>,
    ea_candidate: impl FnMut(u64) -> io::Result<()>,
    options: AuditOptions,
    index_cache_bytes: u64,
) -> io::Result<Audit> {
    audit_reader_with_progress(source, boot, candidate, ea_candidate, options, index_cache_bytes, &mut |_| {})
}

pub(crate) fn audit_reader_with_progress(
    mut source: impl ReadAt,
    boot: BootSector,
    mut candidate: impl FnMut(u64, u8, u8) -> io::Result<()>,
    mut ea_candidate: impl FnMut(u64) -> io::Result<()>,
    options: AuditOptions,
    index_cache_bytes: u64,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<Audit> {
    let mut volume = Volume::new(&mut source, boot)?;
    let zero = mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let data = unnamed(&mft, ATTR_DATA)?;
    let bitmap = unnamed(&mft, ATTR_BITMAP)?;
    let initialized = data.initialized_size()?;
    let slots = initialized / u64::from(boot.record_bytes);
    if initialized % u64::from(boot.record_bytes) != 0
        || slots > ntfs_rs::mft::FILE_REFERENCE_NUMBER_MASK
        || slots < system_record::RESERVED
    {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "invalid MFT record count"));
    }
    let mut out = Audit {
        complete: true,
        index_check: options.index_check,
        index_slots: slots,
        index_full_targets: Some(scratch_file()?),
        index_repair_directories: Some(scratch_file()?),
        worklist: Some(scratch_file()?),
        report_file: Some(scratch_file()?),
        ..Default::default()
    };
    // Uninitialized allocation may remain reserved, but it cannot contribute
    // logical records to the MFT stream.

    let data_bytes = data.data_size()?;
    if data_bytes != initialized {
        out.finding(
            "mft-data-size",
            Some(system_record::MFT),
            format!(
                "data_size={data_bytes} initialized_size={initialized}; MFT logical length must match initialized \
                 records",
            ),
        );
    }
    // The logical bitmap consists of quadwords. Initialized bytes need only
    // cover complete groups of 64 records; extra initialized bytes need not
    // themselves be aligned. Reserve larger valid streams unchanged.

    let bitmap_bytes = bitmap.data_size()?;
    let bitmap_initialized = bitmap.initialized_size()?;
    let bitmap_required = slots.div_ceil(BITMAP_WORD_BITS) * BITMAP_WORD_BYTES;
    if bitmap_bytes < bitmap_required || bitmap_bytes % BITMAP_WORD_BYTES != 0 || bitmap_initialized < bitmap_required {
        out.finding(
            "mft-bitmap-size",
            Some(system_record::MFT),
            format!(
                "data_size={bitmap_bytes} initialized_size={bitmap_initialized} minimum={bitmap_required}; MFT \
                 bitmap data must use complete quadwords and initialized bytes must cover 64-record groups",
            ),
        );
    }
    audit_mft_bitmap_padding(&mut volume, data, bitmap, bitmap_bytes.min(bitmap_initialized), &mut out)?;
    let records = RecordStore::new(slots)?;
    let mut extents = DiskInventory::new();
    let record_bytes = boot.record_bytes as usize;
    let mut buffers = Buffers {
        raw: vec![0; record_bytes],
        secure: vec![0; record_bytes],
        extension: vec![0; record_bytes],
        index: vec![0; volume.directory_scratch_bytes()],
        security_lookup: vec![0; volume.directory_scratch_bytes()],
        descriptor: vec![0; SECURITY_DESCRIPTOR_SCRATCH],
        ea_stream: vec![0; ntfs_rs::ea::MAX_STREAM],
        ea_canonical: vec![0; ntfs_rs::ea::MAX_STREAM],
    };
    let mut mft_bits = [0; BITMAP_READ_BYTES];
    let mut security_references = DiskInventory::new();
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    for number in 0..slots {
        scan_progress(progress, Phase::ScanMft, boot, number, slots);
        let raw = &mut buffers.raw;
        volume.read_mft_record(&mft, number, raw)?;
        if !mft_bit(&mut volume, bitmap, &mut mft_bits, slots, number)? {
            let in_use =
                raw.starts_with(b"FILE") && u16_at(raw, record_layout::FLAGS_OFFSET)? & record_layout::IN_USE != 0;
            if in_use {
                // Its untrusted runs cannot prove cluster leaks.

                out.incomplete("mft-bitmap-free", Some(number), "record is in use but its MFT bitmap bit is clear");
            }
            continue;
        }
        out.allocated_records += 1;
        let next_id = u16_at(raw, record_layout::NEXT_ATTRIBUTE_ID_OFFSET)?;
        let record = match MftRecord::parse(raw, boot.bytes_per_sector) {
            Ok(record) => record,
            Err(error) => {
                out.incomplete("mft-invalid", Some(number), error.to_string());
                continue;
            }
        };
        let flags = record.flags()?;
        if flags & record_layout::IN_USE == 0 {
            out.finding("mft-bitmap-used", Some(number), "bitmap allocates a free record");
        }
        let base = record.base_file_reference()?;
        let reference = ntfs_rs::mft::file_reference(number, record.sequence_number()?)?;
        let mut directory = flags & record_layout::DIRECTORY != 0;
        let mut names = Vec::new();
        let mut has_list = false;
        let mut framing_valid = true;
        let mut attribute_ids = BTreeSet::new();
        let mut previous_type = 0;
        for attribute in record.attributes() {
            let attribute = match attribute {
                Ok(attribute) => attribute,
                Err(error) => {
                    out.incomplete("attribute-invalid", Some(number), error.to_string());
                    framing_valid = false;
                    break;
                }
            };
            if !attribute.nonresident {
                if let Err(error) = attribute.resident_value() {
                    out.incomplete("attribute-invalid", Some(number), error.to_string());
                    framing_valid = false;
                    continue;
                }
            }
            if attribute.kind < previous_type {
                out.finding("attribute-order-invalid", Some(number), "attribute types are not ordered");
            }
            previous_type = attribute.kind;
            if !attribute_ids.insert(attribute.id) {
                out.incomplete(
                    "attribute-id-duplicate",
                    Some(number),
                    format!("attribute ID {} is reused", attribute.id),
                );
            }
            if attribute.id == next_id {
                out.finding(
                    "attribute-next-id-invalid",
                    Some(number),
                    "next attribute ID collides with an existing attribute",
                );
            }
            has_list |= attribute.kind == ATTR_ATTRIBUTE_LIST;
            if attribute.kind == ATTR_FILE_NAME && attribute.nonresident {
                out.finding(
                    "filename-nonresident",
                    Some(number),
                    "$FILE_NAME must be resident; its mapping is not filename evidence",
                );
            }
            if attribute.nonresident {
                if let Err(error) = inventory_runs(attribute, number, clusters, &mut extents)? {
                    if error == ntfs_rs::Error::Unsupported {
                        out.unsupported(number, "extent inventory limit reached");
                    } else {
                        out.incomplete("runlist-invalid", Some(number), error.to_string());
                    }
                }
            } else if attribute.kind == ATTR_FILE_NAME {
                let indexed = attribute.resident_flags()? & FILENAME_INDEXED != 0;
                if !indexed {
                    out.finding(
                        "filename-not-indexed",
                        Some(number),
                        "$FILE_NAME must have RESIDENT_ATTR_IS_INDEXED set",
                    );
                }
                let value = attribute.resident_value()?;
                if let Some(reason) = recovery::filename_value_error(value) {
                    out.finding("filename-invalid", Some(number), reason);
                    if ntfs_rs::filename::FileNameValue::parse(value).is_err() {
                        out.complete = false;
                    }
                } else if indexed {
                    names.push(Name::from_value(value));
                }
            }
        }
        if base == 0 && !has_list && framing_valid {
            audit_ea(
                &mut volume,
                &record,
                number,
                &mut buffers.ea_stream,
                &mut buffers.ea_canonical,
                &mut out,
                &mut ea_candidate,
            )?;
        }
        if base == 0 && framing_valid {
            // Inline security may live in an extension. Inventory physical
            // records above, but validate security against the complete family.

            let mut mapped_family = None;
            if has_list {
                let mut lists = record.attributes().filter(|attribute| {
                    attribute.as_ref().is_ok_and(|attribute| attribute.kind == ATTR_ATTRIBUTE_LIST)
                });
                match (lists.next(), lists.next()) {
                    (Some(Ok(list)), None) => mapped_family = Some(family_arena(list, record_bytes)?),
                    (Some(_), Some(_)) => {
                        out.incomplete("attribute-list-invalid", Some(number), "duplicate family list")
                    }
                    _ => return Err(io::Error::other("missing family list")),
                }
            }
            let resolved = match mapped_family {
                Some((ref mut mapping, output_len)) => {
                    let (image, work) = mapping.split_at_mut(output_len);
                    // Security and directory type need every stream, not the
                    // names in extension records: a file may have more hard
                    // links than one assembled record can hold.
                    match volume
                        .resolve_record_streams(&mft, &record, image, work)
                        .and_then(|()| MftRecord::from_decoded(image))
                    {
                        Ok(record) => Some(record),
                        Err(ntfs_rs::Error::Io) => return Err(invalid(ntfs_rs::Error::Io)),
                        Err(error) => {
                            // Retain the physical record catalog so the family
                            // audit can diagnose exact references and ownership.
                            // An ambiguous family cannot establish its security ID.

                            out.incomplete("attribute-list-invalid", Some(number), error.to_string());
                            None
                        }
                    }
                }
                None => None,
            };
            let security_record = if has_list { resolved.as_ref() } else { Some(&record) };
            if let Some(record) = security_record {
                // Only the complete ordinary family can establish directory
                // type; an extension's local absence of an index proves nothing.

                if number >= system_record::RESERVED {
                    if let Some(proven) = recovery::filename_directory_type(record)? {
                        if directory != proven {
                            out.finding(
                                "mft-directory-flag-mismatch",
                                Some(number),
                                "file record directory flag disagrees with its index root",
                            );
                            directory = proven;
                        }
                    }
                }
                let sid = record.security_id()?;
                let inline = record.attributes().any(|a| a.is_ok_and(|a| a.kind == ATTR_SECURITY_DESCRIPTOR));
                if number < system_record::RESERVED && sid == Some(0) && !inline {
                    out.unsupported(
                        number,
                        "system record has security ID zero and no inline descriptor; native permissions cannot \
                         be assessed",
                    );
                } else if let Some(id) = sid.filter(|id| *id >= FIRST_SHARED_SECURITY_ID && !inline) {
                    security_references.push([u64::from(id), number, 0, 0])?;
                } else {
                    // Legacy/inline descriptors are record-local and therefore
                    // cannot be validated by the shared $Secure inventory below.

                    match ntfs_rs::security_store::read_descriptor(
                        &mut volume,
                        &mft,
                        record,
                        &mut buffers.secure,
                        &mut buffers.index,
                        &mut buffers.descriptor,
                    ) {
                        Ok(_) => out.descriptors += 1,
                        Err(ntfs_rs::Error::Unsupported) => {
                            out.unsupported(number, "unsupported security descriptor layout")
                        }
                        Err(error) => {
                            out.finding("security-invalid", Some(number), format!("security_id={sid:?}: {error}"))
                        }
                    }
                }
            }
        }
        let has_attribute_list = has_list;
        records.insert(number, Record { reference, base, directory, names, has_attribute_list, canonical: None })?;
    }
    let (mut directory_lists_in_base, mut validated_extensions) =
        audit_attribute_lists(&mut volume, &mft, &records, &mut buffers.raw, &mut buffers.extension, &mut out)?;

    // FILE_NAME attributes may live in validated extension records. Directory
    // entries still identify the base record, so compare against that identity.
    let missing = || io::Error::from(io::ErrorKind::InvalidData);
    for extension_number in 0..slots {
        let Some(base_number) = audit_slot(&mut validated_extensions, extension_number, None)? else {
            continue;
        };
        let names = records.get(&extension_number)?.ok_or_else(missing)?.names;
        let mut base = records.get(&base_number)?.ok_or_else(missing)?;
        base.names.extend(names);
        records.insert(base_number, base)?;
    }

    // Root names can live in validated extensions. Check the assembled family
    // so a framed index cannot hide a missing or displaced reserved name.
    let root = system_record::ROOT;
    let root_name = match records.get(&root)? {
        Some(record) if record.base == 0 && record.directory => recovery::checked_family_image(&mut volume, &mft, root)
            .and_then(|family| {
                let family = MftRecord::from_decoded(&family)?;
                recovery::root_filename_valid(&family, record.reference)
            }),
        _ => Ok(false),
    };
    match root_name {
        Ok(true) => {}
        Ok(false) => {
            out.finding(
                "root-filename-invalid",
                Some(root),
                "root requires one combined-namespace name '.' referring to itself",
            );
            out.index_needs_repair(root)?;
        }
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            out.unsupported(root, "unsupported complete root filename layout");
        }
        Err(error) => {
            out.incomplete("root-filename-invalid", Some(root), error.to_string());
            out.index_needs_repair(root)?;
        }
    }

    // Effective alias identities and directory collation share one validated table.
    let mut upcase_bytes = vec![0_u8; UPCASE_BYTES];
    let upcase_result = (|| -> io::Result<()> {
        let family = recovery::checked_family_image(&mut volume, &mft, system_record::UPCASE)?;
        let upcase_record = MftRecord::from_decoded(&family)?;
        if upcase_record.flags()? & record_layout::IN_USE == 0 || upcase_record.base_file_reference()? != 0 {
            return Err(invalid(ntfs_rs::Error::InvalidRecord));
        }
        let data = unnamed(&upcase_record, ATTR_DATA)?;
        if data.data_size()? != UPCASE_BYTES as u64 {
            return Err(invalid(ntfs_rs::Error::InvalidAttribute));
        }
        volume.read_attribute(data, 0, &mut upcase_bytes)?;
        ntfs_rs::upcase::validate_mapping(&upcase_bytes)?;
        let information =
            upcase_record.local_attribute(ATTR_DATA, UPCASE_INFO_NAME)?.ok_or(ntfs_rs::Error::InvalidAttribute)?;
        let mut header = [0; ntfs_rs::upcase::INFORMATION_BYTES];
        volume.read_attribute(information, 0, &mut header)?;
        ntfs_rs::upcase::validate_information(&upcase_bytes, &header, information.data_size()?).map_err(invalid)
    })();
    let upcase_ready = match upcase_result {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            out.unsupported(
                system_record::UPCASE,
                "unsupported $UpCase layout prevents complete directory collation checks",
            );
            false
        }
        Err(error) => {
            out.incomplete(
                "upcase-invalid",
                Some(system_record::UPCASE),
                format!("cannot load the volume $UpCase table: {error}"),
            );
            false
        }
    };
    let upcase = upcase_ready.then_some(upcase_bytes.as_slice());

    for number in system_record::RESERVED..slots {
        scan_progress(progress, Phase::Directories, boot, number, slots);
        let Some(mut record) = records.get(&number)? else {
            continue;
        };
        if record.base != 0 || record.names.is_empty() {
            continue;
        }
        match recovery::filename_index_information(&mut volume, &mft, number, upcase) {
            Ok((canonical, projected)) => {
                record.canonical = Some(canonical);
                if let Some(names) = projected {
                    record.names = names.iter().map(|value| Name::from_value(value)).collect();
                }
            }
            Err(error) => out.incomplete("index-metadata-unavailable", Some(number), error.to_string()),
        }
        records.insert(number, record)?;
    }

    let mut security_references = security_references.finish()?;
    audit_security_inventory(&mut volume, &mft, &mut security_references, &mut buffers, &mut out)?;
    audit_allocation(&mut volume, &mft, extents, clusters, &mut candidate, &mut out)?;

    let mut links = DiskInventory::new();
    let mut entries = index_check::Entries::new()?;
    for item in records.iter() {
        let (number, metadata) = item?;
        if metadata.base != 0 || !metadata.directory {
            continue;
        }
        volume.read_mft_record(&mft, number, &mut buffers.raw)?;
        let directory = MftRecord::parse(&mut buffers.raw, boot.bytes_per_sector)?;
        out.directories += 1;
        let validated_list =
            metadata.has_attribute_list && audit_slot(&mut directory_lists_in_base, number, None)?.is_some();
        let mut state = DirectoryAuditState {
            number,
            parent: metadata.reference,
            upcase,
            entries: &mut entries,
            previous_name: None,
            position: 0,
            out: &mut out,
        };
        let result = volume.audit_directory(&directory, &mut buffers.index, validated_list, |entry| state.visit(entry));
        if let Err(error) = result {
            if error == ntfs_rs::Error::Unsupported {
                out.unsupported(number, "unsupported directory index layout");
            } else {
                out.incomplete("directory-invalid", Some(number), error.to_string());
            }
            out.index_needs_repair(number)?;
        }
    }
    entries.finish(&records, &mut links, &mut out, options, index_cache_bytes)?;
    let mut children = audit_links(&records, links, &mut out)?;
    audit_directory_cycles(&records, &mut children, &mut out, options)?;
    audit_reachability(&records, &mut children, slots, &mut out)?;
    if out.complete {
        recovery::audit_system_metadata_with_index_check(
            &mut volume,
            &mft,
            options.index_check,
            upcase,
            &mut |code, record, detail, is_error| out.report(code, record, detail, is_error),
        )?;
    }
    drop(volume);
    audit_mirrors(&mut source, boot, &mft, slots, &mut out)?;
    if let Some(error) = out.worklist_error.take().or_else(|| out.report_error.take()) {
        return Err(error);
    }
    let report = out.report_file.as_ref().ok_or_else(|| io::Error::other("missing audit report"))?;
    out.findings = Findings::open(report, out.finding_count)?;
    Ok(out)
}

/// Cross-check shared security IDs with the complete $Secure index inventory.
fn audit_security_inventory<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    references: &mut File,
    buffers: &mut Buffers,
    out: &mut Audit,
) -> io::Result<()> {
    let secure = system_record::SECURE;
    let mut indexed = DiskInventory::new();
    let family = recovery::checked_family_image(volume, mft, secure)?;
    let secure_record = MftRecord::from_decoded(&family)?;
    let mut inventory = ntfs_rs::security_store::visit_record_descriptors(
        volume,
        &secure_record,
        &mut buffers.index,
        &mut buffers.security_lookup,
        &mut buffers.descriptor,
        |entry| {
            let id = u64::from(entry.security_id);
            indexed.push([id, 0, 0, 0]).map_err(|_| ntfs_rs::Error::Io)?;
            out.descriptors += 1;
            if inventory_find(references, id).map_err(|_| ntfs_rs::Error::Io)?.is_none() {
                // Descriptors are shared and retained after ACL replacement;
                // no live reference alone is not evidence of corruption.

                out.report(
                    "unreferenced-security-descriptor",
                    Some(secure),
                    format!(
                        "security_id={} hash=0x{:08x} offset={} is indexed but no live base record references it",
                        entry.security_id, entry.hash, entry.offset
                    ),
                    false,
                );
            }
            Ok(())
        },
    );
    let mut indexed = indexed.finish()?;
    if inventory.is_ok() {
        let mut previous = None;
        while let Some([id, ..]) = inventory_next(&mut indexed)? {
            if previous.replace(id) == Some(id) {
                inventory = Err(ntfs_rs::Error::InvalidSecurity);
                break;
            }
        }
    }
    match inventory {
        Ok(()) => {
            references.seek(SeekFrom::Start(0))?;
            let mut previous = None;
            while let Some([security_id, record, _, _]) = inventory_next(references)? {
                if previous.replace(security_id) != Some(security_id)
                    && inventory_find(&mut indexed, security_id)?.is_none()
                {
                    out.finding(
                        "security-invalid",
                        Some(record),
                        format!("security_id={security_id} is absent from the complete $SII/$SDH inventory"),
                    );
                }
            }
        }
        Err(ntfs_rs::Error::Unsupported) => out.unsupported(secure, "unsupported complete $Secure index layout"),
        Err(error) => out.incomplete(
            "security-invalid",
            Some(secure),
            format!("complete $SII/$SDH/$SDS inventory failed: {error}"),
        ),
    }
    Ok(())
}

/// Reconcile spooled run extents with $Bitmap; overlaps are errors even if allocated.
fn audit_allocation<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    extents: DiskInventory,
    clusters: u64,
    candidate: &mut impl FnMut(u64, u8, u8) -> io::Result<()>,
    out: &mut Audit,
) -> io::Result<()> {
    let mut extents = BufReader::new(extents.finish()?);
    let (mut active_end, mut active_owner) = (0, 0);
    let mut ranges = DiskInventory::new();
    let mut merged: Option<(u64, u64)> = None;
    let mut flush = |range: (u64, u64), out: &mut Audit| {
        out.referenced_clusters += range.1 - range.0;
        ranges.push([range.0, range.1, 0, 0])
    };
    while let Some([start, end, number, _]) = inventory_next(&mut extents)? {
        if start < active_end {
            out.cross_linked_clusters += end.min(active_end) - start;
            out.finding("cross-linked-clusters", Some(number), format!("LCN {start} overlaps record {active_owner}"));
        }
        if end > active_end {
            (active_end, active_owner) = (end, number);
        }
        match merged {
            Some((a, b)) if b >= start => merged = Some((a, b.max(end))),
            previous => {
                if let Some(previous) = previous {
                    flush(previous, out)?;
                }
                merged = Some((start, end));
            }
        }
    }
    if let Some(range) = merged {
        flush(range, out)?;
    }
    let mut ranges = BufReader::new(ranges.finish()?);
    let mut range = inventory_next(&mut ranges)?;
    let family = recovery::checked_family_image(volume, mft, system_record::BITMAP)?;
    let bitmap_record = MftRecord::from_decoded(&family)?;
    let allocation = unnamed(&bitmap_record, ATTR_DATA)?;
    let bytes = clusters.div_ceil(BITS_PER_BYTE);
    let mut buffer = [0; BITMAP_READ_BYTES];
    let (mut missing, mut leaked) = (0, 0);
    let bits = |count: u64| ((1_u16 << count) - 1) as u8;
    for offset in (0..bytes).step_by(buffer.len()) {
        let n = (bytes - offset).min(buffer.len() as u64) as usize;
        volume.read_attribute(allocation, offset, &mut buffer[..n])?;
        for (i, byte) in buffer[..n].iter().enumerate() {
            let first = (offset + i as u64) * BITS_PER_BYTE;
            let end = (first + BITS_PER_BYTE).min(clusters);
            let mask = bits(end - first);
            while range.is_some_and(|r| r[1] <= first) {
                range = inventory_next(&mut ranges)?;
            }
            let mut referenced = 0_u8;
            while let Some([lo, hi, _, _]) = range.filter(|r| r[0] < end) {
                let (a, b) = (lo.max(first), hi.min(end));
                referenced |= bits(b - a) << (a - first);
                if hi > end {
                    break;
                }
                range = inventory_next(&mut ranges)?;
            }
            let absent = referenced & !byte;
            out.allocated_clusters += u64::from((byte & mask).count_ones());
            for bit in (0..BITS_PER_BYTE).filter(|bit| absent & (1 << bit) != 0) {
                out.finding("cluster-marked-free", None, format!("referenced LCN {} is free in $Bitmap", first + bit));
            }
            missing += u64::from(absent.count_ones());
            leaked += u64::from((byte & mask & !referenced).count_ones());
            let allocated = (byte & !mask) | referenced;
            if allocated != *byte {
                candidate(offset + i as u64, *byte, allocated)?;
            }
        }
    }
    out.missing_clusters = missing;
    if leaked > 0 {
        let code = if out.complete { "unreferenced-clusters" } else { "allocation-unresolved" };
        out.finding(code, None, format!("{leaked} allocated clusters have no validated owning run"));
    }
    Ok(())
}

/// Match each record's names with directory index links; returns child edges.
fn audit_links(records: &RecordStore, links: DiskInventory, out: &mut Audit) -> io::Result<File> {
    let mut links = BufReader::new(links.finish()?);
    let mut link = inventory_next(&mut links)?;
    let mut children = DiskInventory::new();
    for item in records.iter() {
        let (number, record) = item?;
        if record.base != 0 {
            let base = reference_number(record.base);
            if !records.get(&base)?.is_some_and(|r| r.reference == record.base && r.base == 0) {
                out.finding("invalid-base-reference", Some(number), format!("invalid extension base {base}"));
            }
            continue;
        }
        let fully_checked = out.index_target_checked_fully(number)?;
        // Reduced checking reconciles reference counts, rather than each name key.

        let mut observed = 0;
        for (name_index, name) in record.names.iter().enumerate() {
            let parent = reference_number(name.parent);
            if !records.get(&parent)?.is_some_and(|r| r.reference == name.parent && r.directory) {
                out.finding("invalid-parent-reference", Some(number), format!("invalid parent {parent}"));
            }
            let key = (number, name_index as u64);
            while let Some(edge) = link.filter(|l| (l[0], l[1]) < key) {
                children.push([edge[2], edge[0], 0, 0])?;
                link = inventory_next(&mut links)?;
            }
            let linked = link.is_some_and(|l| (l[0], l[1]) == key);
            observed += usize::from(linked);
            if fully_checked && !linked {
                out.finding(
                    "missing-directory-link",
                    Some(number),
                    format!("FILE_NAME absent from parent {parent} index"),
                );
                out.index_needs_repair(parent)?;
            }
        }
        if !fully_checked
            && observed == 0
            && !record.names.is_empty()
            && audit_slot(out.index_full_targets.as_mut().unwrap(), number, None)?.is_none()
        {
            index_check::missing_count(records, number, record.names.len() as u64, out)?;
        }
    }
    while let Some(edge) = link {
        children.push([edge[2], edge[0], 0, 0])?;
        link = inventory_next(&mut links)?;
    }
    children.finish()
}

/// Breadth-first reachability from the root with disk-backed bits and queue.
fn audit_reachability(records: &RecordStore, children: &mut File, slots: u64, out: &mut Audit) -> io::Result<()> {
    const QUEUE_ROW_BYTES: u64 = std::mem::size_of::<u64>() as u64;

    let mut reached = scratch_file()?;
    reached.set_len(slots.div_ceil(BITS_PER_BYTE))?;
    let bit = |reached: &mut File, number: u64, set: bool| -> io::Result<bool> {
        let mut byte = [0];
        reached.seek(SeekFrom::Start(number / BITS_PER_BYTE))?;
        reached.read_exact(&mut byte)?;
        let mask = 1 << (number % BITS_PER_BYTE);
        let was_set = byte[0] & mask != 0;
        if set && !was_set {
            reached.seek(SeekFrom::Start(number / BITS_PER_BYTE))?;
            reached.write_all(&[byte[0] | mask])?;
        }
        Ok(was_set)
    };
    let root = system_record::ROOT;
    let mut queue = scratch_file()?;
    queue.write_all(&root.to_le_bytes())?;
    bit(&mut reached, root, true)?;
    let (mut head, mut tail) = (0_u64, QUEUE_ROW_BYTES);
    while head < tail {
        let mut word = [0; QUEUE_ROW_BYTES as usize];
        queue.seek(SeekFrom::Start(head))?;
        queue.read_exact(&mut word)?;
        head += QUEUE_ROW_BYTES;
        let parent = u64::from_le_bytes(word);
        inventory_lower_bound(children, parent)?;
        while let Some([owner, child, _, _]) = inventory_next(children)? {
            if owner != parent {
                break;
            }
            if child >= slots {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if bit(&mut reached, child, true)? {
                continue;
            }
            if records.get(&child)?.is_some_and(|r| r.directory) {
                queue.seek(SeekFrom::Start(tail))?;
                queue.write_all(&child.to_le_bytes())?;
                tail += QUEUE_ROW_BYTES;
            }
        }
    }
    for item in records.iter() {
        let (number, record) = item?;
        if number >= system_record::RESERVED && record.base == 0 && !bit(&mut reached, number, false)? {
            out.finding(
                "unreachable-record",
                Some(number),
                "allocated base record has no validated path from the root",
            );
        }
    }
    Ok(())
}

/// Compare decoded mirror records and the backup boot sector with their primaries.
fn audit_mirrors(
    source: &mut impl ReadAt,
    boot: BootSector,
    mft: &MftRecord<'_>,
    slots: u64,
    out: &mut Audit,
) -> io::Result<()> {
    let record_bytes = u64::from(boot.record_bytes);
    // Windows verifies the first four records, whatever else a larger
    // mirror cluster holds.
    let mirror_records = system_record::MIRRORED;
    let mut primary = vec![0; record_bytes as usize];
    let mut mirror = primary.clone();
    for number in 0..mirror_records.min(slots) {
        Volume::new(&mut *source, boot)?.read_mft_record(mft, number, &mut primary)?;
        let at = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + number * record_bytes;
        source.read_exact_at(at, &mut mirror)?;
        // USA tokens may differ; compare records after clearing their decoded arrays.

        let decoded = MftRecord::parse(&mut primary, boot.bytes_per_sector).is_ok()
            && MftRecord::parse(&mut mirror, boot.bytes_per_sector).is_ok();
        if decoded {
            for bytes in [&mut primary, &mut mirror] {
                let at = usize::from(u16_at(bytes, record_layout::USA_OFFSET)?);
                let count = usize::from(u16_at(bytes, record_layout::USA_COUNT_OFFSET)?);
                bytes[at..at + filename::CODE_UNIT_BYTES * count].fill(0);
            }
        }
        if !decoded || primary != mirror {
            out.finding("mft-mirror-mismatch", Some(number), "MFT and mirror differ after fixup decoding");
        }
    }
    let sector = ntfs_rs::boot::BOOT_SECTOR_BYTES;
    let mut primary = vec![0; sector];
    let mut backup = vec![0; sector];
    source.read_exact_at(0, &mut primary)?;
    // The backup lies just beyond the volume's addressable sector count.

    source.read_exact_at(boot.total_sectors * u64::from(boot.bytes_per_sector), &mut backup)?;
    if primary != backup {
        let same_geometry = BootSector::parse(&backup).is_ok_and(|mut backup_boot| {
            backup_boot.serial_number = boot.serial_number;
            backup_boot == boot
        });
        out.report("boot-mirror-mismatch", None, "primary and backup boot sectors differ", !same_geometry);
    }
    Ok(())
}

// Build an in-memory MFT mapping from sequence-checked extension records.
// Bootstrap only through already verified DATA runs; never scan arbitrary
// clusters for a plausible FILE signature. This image is NEVER published.
pub(crate) fn mft_image<R: ReadAt>(volume: &mut Volume<R>) -> io::Result<Vec<u8>> {
    use ntfs_rs::record_edit as e;

    let boot = volume.boot;
    let mut base = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut base)?;
    MftRecord::parse(&mut base, boot.bytes_per_sector)?;
    let record = MftRecord::from_decoded(&base)?;
    let bad_list = || invalid(ntfs_rs::Error::InvalidAttributeList);
    let mut list = None;
    for attribute in record.attributes() {
        let attribute = attribute?;
        if attribute.kind == ATTR_ATTRIBUTE_LIST && list.replace(attribute).is_some() {
            return Err(bad_list());
        }
    }
    let Some(list) = list else {
        return Ok(base);
    };
    let reference = ntfs_rs::mft::file_reference(system_record::MFT, record.sequence_number()?)?;
    if reference == 0 || record.base_file_reference()? != 0 || list.flags()? != 0 {
        return Err(bad_list());
    }
    let size = list.data_size()? as usize;
    let mut entries = Vec::new();
    entries.try_reserve_exact(size).map_err(io::Error::other)?;
    entries.resize(size, 0);
    volume.read_attribute(list, 0, &mut entries)?;
    let mut mapping = base.clone();
    e::remove(&mut mapping, list.record_offset())?;
    let mut claimed = BTreeSet::new();
    let mut members = BTreeSet::from([reference]);
    let grow = |image: &mut Vec<u8>, extra: usize| -> io::Result<()> {
        let required = e::used(image)? + extra;
        if required > image.len() {
            image.try_reserve(required - image.len()).map_err(io::Error::other)?;
            image.resize(required, 0);
            let capacity = u32::try_from(required).map_err(io::Error::other)?;
            e::p32(image, record_layout::CAPACITY_OFFSET, capacity)?;
        }
        Ok(())
    };
    // Read through an incomplete prefix without treating its current coverage
    // as the final stream size. Every requested byte must already be mapped.

    let read_member = |volume: &mut Volume<R>, map: &[u8], reference: u64| -> io::Result<Vec<u8>> {
        let mft = MftRecord::from_decoded(map)?;
        let data = unnamed(&mft, ATTR_DATA)?;
        let mut raw = vec![0; boot.record_bytes as usize];
        let offset = reference_number(reference) * u64::from(boot.record_bytes);
        ntfs_rs::write_plan::plan_nonresident_recovery(data, boot, offset, raw.len() as u64, |s| {
            let start = s.source_offset as usize;
            volume.read_physical(s.physical_offset, &mut raw[start..start + s.length as usize])
        })?;
        MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        Ok(raw)
    };
    // Find a member's listed attribute and check its type, name and first VCN.

    let listed_attribute = |raw: &[u8], entry: &ntfs_rs::attrlist::ListEntry<'_>, expected_base: u64| {
        let member = MftRecord::from_decoded(raw)?;
        if u64::from(member.sequence_number()?) != entry.file_reference >> ntfs_rs::mft::FILE_REFERENCE_SEQUENCE_SHIFT
            || member.base_file_reference()? != expected_base
            || member.flags()? & record_layout::IN_USE == 0
        {
            return Err(bad_list());
        }
        let attributes = member.attributes().collect::<ntfs_rs::Result<Vec<_>>>()?;
        let attribute = attributes.into_iter().find(|a| a.id == entry.attribute_id).ok_or_else(bad_list)?;
        let first_vcn = if attribute.nonresident { attribute.first_vcn()? } else { 0 };
        if attribute.kind != entry.kind
            || attribute.name_utf16le()? != entry.name_utf16le
            || first_vcn != entry.first_vcn
        {
            return Err(bad_list());
        }
        let at = attribute.record_offset();
        Ok((at, e::attr_len(raw, at)?, attribute.nonresident))
    };
    for entry in AttributeList::new(&entries) {
        let entry = entry?;
        if entry.kind == ATTR_ATTRIBUTE_LIST || !claimed.insert((entry.file_reference, entry.attribute_id)) {
            return Err(bad_list());
        }
        members.insert(entry.file_reference);
        if entry.kind != ATTR_DATA || !entry.name_utf16le.is_empty() || entry.file_reference == reference {
            continue;
        }
        let raw = read_member(volume, &mapping, entry.file_reference)?;
        let (at, n, nonresident) = listed_attribute(&raw, &entry, reference)?;
        if !nonresident {
            return Err(bad_list());
        }
        grow(&mut mapping, n)?;
        e::merge_attribute(&mut mapping, &raw[at..at + n])?;
    }
    let mut result = base.clone();
    let start = usize::from(u16_at(&result, record_layout::FIRST_ATTRIBUTE_OFFSET)?);
    result[start..].fill(0);
    e::p32(&mut result, start, record_layout::END_MARKER)?;
    e::p32(&mut result, record_layout::USED_OFFSET, (start + record_layout::END_MARKER_BYTES) as u32)?;
    e::p16(&mut result, record_layout::NEXT_ATTRIBUTE_ID_OFFSET, 0)?;
    for entry in AttributeList::new(&entries) {
        let entry = entry?;
        let (raw, expected_base) = if entry.file_reference == reference {
            (base.clone(), 0)
        } else {
            (read_member(volume, &mapping, entry.file_reference)?, reference)
        };
        let (at, n, _) = listed_attribute(&raw, &entry, expected_base)?;
        grow(&mut result, n)?;
        e::merge_attribute(&mut result, &raw[at..at + n])?;
    }
    for member in members {
        let raw = if member == reference { base.clone() } else { read_member(volume, &mapping, member)? };
        for attribute in MftRecord::from_decoded(&raw)?.attributes() {
            let attribute = attribute?;
            if attribute.kind != ATTR_ATTRIBUTE_LIST && !claimed.contains(&(member, attribute.id)) {
                return Err(bad_list());
            }
        }
    }
    e::validate(&result)?;
    Ok(result)
}

#[cfg(test)]
#[path = "../tests/checker/consistency_tests.rs"]
mod tests;
