//! Module: slate_ntfs_tools::recovery_io
//! Purpose: Coordinate and apply guarded offline recovery and durable repair operations.
//! Created: 2026-09-30
//! Architecture: The CLI calls this userspace layer; checker and core parsers
//!     validate inputs while repair journals order and preserve disk writes.

use crate::checker::{self, invalid, Image};
use crate::linux::PRIVATE_FILE_MODE;
use ntfs_rs::boot::BootSector;
use ntfs_rs::bytes::{u32_at, u64_at};
use ntfs_rs::hibernation::{write_gate, HibernationWriteGate};
use ntfs_rs::logfile::RestartPage;
use ntfs_rs::mft::{reference_number, reference_sequence};
use ntfs_rs::mft::{Attribute, MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_BITMAP, ATTR_DATA};
use ntfs_rs::replay::protect_mft_record;
use ntfs_rs::volume::{ReadAt, Volume};
use ntfs_rs::write_plan::{plan_nonresident_overwrite, WriteSpan};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
#[path = "recovery.rs"]
mod models;
use family::{RepairFamily, RepairSpace, StreamChange};
pub use models::journal as recovery_journal;
pub(crate) use models::plan::WriteViewStats;
pub(crate) use models::plan::WRITE_VIEW_BYTES;
use models::plan::{Patch, PatchSet, PlannedImage, RepairPlan, ReplayPlan};
use models::{completion, family, growth, log, log_resize, metadata, relocation, replay, reserved, semantic, widths};
#[cfg(test)]
#[path = "../tests/recovery/planner.rs"]
mod recovery_semantic_checks;

pub(crate) fn checked_family_image<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    number: u64,
) -> io::Result<Vec<u8>> {
    Ok(RepairFamily::load(volume, mft, number)?.logical)
}

fn reject(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

/// Repair phases reported to the CLI and the C and Python bindings; the
/// numeric values are part of that interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Phase {
    Planning = 0,
    ScanMft = 1,
    Families = 2,
    Directories = 3,
    Allocation = 4,
    Security = 5,
    Audit = 6,
    Copy = 7,
    Replay = 8,
    Journal = 9,
    Repair = 10,
    Verification = 11,
    Publication = 12,
    Complete = 13,
    Failed = 14,
}

/// Live, phase-relative work coverage in 512-byte sectors. Repeated phases
/// (for revalidation) restart their counters. This is not an I/O traffic meter
/// or an invented overall percentage. Unknown phase totals use percentage -1.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RepairProgress {
    pub phase: u32,
    pub sector_bytes: u32,
    pub completed_sectors: u64,
    pub total_sectors: u64,
    pub percentage: f64,
}

impl RepairProgress {
    pub fn new(phase: Phase, completed_sectors: u64, total_sectors: u64) -> Self {
        const COMPLETE: f64 = 100.0;
        const UNKNOWN: f64 = -1.0;

        let percentage = match (phase, total_sectors) {
            (Phase::Complete, _) => COMPLETE,
            (_, 0) => UNKNOWN,
            _ => (completed_sectors as f64 / total_sectors as f64 * COMPLETE).min(COMPLETE),
        };
        Self {
            phase: phase as u32,
            sector_bytes: NTFS_SECTOR_BYTES as u32,
            completed_sectors,
            total_sectors,
            percentage,
        }
    }
}

use crate::linux::image_length;

// Strict legacy history and expanded LFS discovery share the copy-only adapter.
use log::History;
use models::NTFS_SECTOR_BYTES;
use ntfs_rs::mft::{record_layout, system_record};
const IMAGE_COPY_BUFFER_BYTES: usize = 1024 * 1024;
/// Smallest log stream a supported restart pair and record area can occupy.
const MINIMUM_REPLAY_LOG_BYTES: u64 = 16 * 1024;

#[cfg(test)]
#[path = "../tests/writer/crash.rs"]
mod writer_crash;

fn plan(path: &Path) -> io::Result<ReplayPlan> {
    let boot = checker::open_volume(path)?.boot;
    if checker::probe(path).is_ok_and(|probe| probe.info.has_unsupported_flags()) {
        return Err(reject("replay requires supported volume flags; dirty state is permitted for recovery"));
    }
    plan_reader(|| Ok(Image(File::open(path)?)), boot)
}

// Recovery and write admission must inspect the same projected bytes. Reuse
// the ordinary replay planner rather than copying an entire volume to scratch.
fn plan_reader<R: ReadAt>(
    reader: impl Fn() -> io::Result<R>,
    boot: ntfs_rs::boot::BootSector,
) -> io::Result<ReplayPlan> {
    let mut volume = Volume::new(reader()?, boot)?;
    if let Ok(status) = checker::inspect_recovery(reader()?, boot) {
        if write_gate(status.hibernation, false) != HibernationWriteGate::Clear {
            return Err(reject("hibernation blocks replay writes"));
        }
    }
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let log_image = checked_family_image(&mut volume, &mft, system_record::LOG)?;
    let log_record = MftRecord::from_decoded(&log_image)?;
    let data = log_record.stream(ATTR_DATA, &[])?;
    let size = data.data_size()?;
    if size < MINIMUM_REPLAY_LOG_BYTES {
        return Err(reject("invalid log size for replay"));
    }
    let spool = checker::consistency::scratch_file()?;
    spool.set_len(size)?;
    // The private, unlinked file backs the virtual range. Read the NTFS
    // stream in bounded windows so a large native log needs no matching heap
    // allocation. history still validates the complete immutable snapshot.
    let mut log = unsafe { memmap2::MmapMut::map_mut(&spool)? };
    for at in (0..size).step_by(IMAGE_COPY_BUFFER_BYTES) {
        let end = (at + IMAGE_COPY_BUFFER_BYTES as u64).min(size);
        volume.read_attribute(data, at, &mut log[at as usize..end as usize])?;
    }
    let history: History = log::discover(&mut log, boot.bytes_per_sector)?;
    let mut planned = replay::plan(volume, reader()?, &history)?;
    planned.patches.build_index()?;
    let mut view = PlannedImage { image: reader()?, patches: &planned.patches };
    // A torn $Volume record must be restored by a checked logged image;
    // never infer a clean state from a failed parse or from the mirror alone.
    let mut recovered = Volume::new(&mut view, boot)?;
    let mapping = checker::consistency::mft_image(&mut recovered)?;
    let mapping = MftRecord::from_decoded(&mapping)?;
    let mut raw = vec![0; boot.record_bytes as usize];
    recovered.read_mft_record(&mapping, system_record::VOLUME, &mut raw)?;
    let info = ntfs_rs::volume_info::VolumeInfo::from_record(&MftRecord::parse(&mut raw, boot.bytes_per_sector)?)?;
    if info.has_unsupported_flags() {
        return Err(reject("unsupported recovered volume flags"));
    }
    drop(recovered);
    let status = checker::inspect_recovery(view, boot)?;
    if write_gate(status.hibernation, false) != HibernationWriteGate::Clear {
        return Err(reject("hibernation blocks replay writes"));
    }
    Ok(planned)
}

pub(crate) fn flush(file: &mut File, count: &mut usize, stop_after: Option<usize>) -> io::Result<()> {
    file.sync_all()?;
    *count += 1;
    if stop_after == Some(*count) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            format!("injected stop after durable boundary {}; output remains dirty", count),
        ));
    }
    Ok(())
}

/// Validate the complete executable plan without creating or changing a file.
pub fn describe_plan(source: &Path) -> io::Result<()> {
    let planned = plan(source)?;
    println!(
        "replay_supported=1\nmetadata_patches={}\npublication_patches={}\ncompensation_patches={}\ntail_pages={}\ntransaction_instances={}\ncompensation_records={}\nwrite_mount_ready=0",
        planned.patches.len(),
        planned.publication.len(),
        planned.preparation.len(),
        planned.tail_pages,
        planned.transaction_instances,
        planned.compensation_records
    );
    for patch in planned.patches.iter() {
        let patch = patch?;
        println!(
            "action={} physical_offset={} bytes={}",
            if patch.undo { "undo" } else { "redo" },
            patch.physical,
            patch.after.len()
        );
    }
    Ok(())
}

const SECTOR_BYTES: usize = NTFS_SECTOR_BYTES;
/// Each protected 512-byte stride ends with one update-sequence word.
const USA_WORD_BYTES: usize = std::mem::size_of::<u16>();
const SECTOR_TAIL: usize = SECTOR_BYTES - USA_WORD_BYTES;
/// Logical sector sizes probed for a terminal backup boot sector.
const BACKUP_SECTOR_SIZES: [u64; 4] = [512, 1024, 2048, 4096];
const ATTRIBUTE_ALIGNMENT: usize = ntfs_rs::mft::attribute_layout::ALIGNMENT;

fn u16_field(raw: &[u8], at: usize) -> io::Result<u16> {
    Ok(ntfs_rs::bytes::u16_at(raw, at)?)
}

/// Reserved records carry the sequence of their checked slot, minimum one.
fn reserved_sequence(number: u64) -> u16 {
    number.max(1) as u16
}

fn put_u16(raw: &mut [u8], at: usize, value: u16) {
    raw[at..at + USA_WORD_BYTES].copy_from_slice(&value.to_le_bytes());
}

/// Bytes [at, at + count words) of the update-sequence array, cleared for comparison.
fn clear_usa(raw: &mut [u8]) -> ntfs_rs::Result<()> {
    let at = usize::from(ntfs_rs::bytes::u16_at(raw, record_layout::USA_OFFSET)?);
    let count = usize::from(ntfs_rs::bytes::u16_at(raw, record_layout::USA_COUNT_OFFSET)?);
    raw[at..at + USA_WORD_BYTES * count].fill(0);
    Ok(())
}

// Conflicting valid copies have no established authority and must be refused.
// Complementary sectors can recover a record even when neither copy is intact,
// but generation, LSN, sequence and USA evidence must agree. Never combine
// two valid but different versions of a sector.
fn reconstruct_mirror_sectors(primary: &[u8], mirror: &[u8], sector: u16) -> io::Result<Vec<u8>> {
    if primary.len() != mirror.len() || primary.len() % SECTOR_BYTES != 0 {
        return Err(reject("mirror geometry differs"));
    }
    let first = usize::from(u16_field(primary, record_layout::FIRST_ATTRIBUTE_OFFSET)?);
    let usa = usize::from(u16_field(primary, record_layout::USA_OFFSET)?);
    let count = usize::from(u16_field(primary, record_layout::USA_COUNT_OFFSET)?);
    if first < record_layout::HEADER_BYTES
        || first > SECTOR_TAIL
        || count != primary.len() / SECTOR_BYTES + 1
        || usa < record_layout::HEADER_BYTES
        || usa + count * USA_WORD_BYTES > first
        || primary.get(..first) != mirror.get(..first)
        || !primary.starts_with(b"FILE")
    {
        return Err(reject("damaged mirror copies lack matching generation and fixup evidence"));
    }
    let token = &primary[usa..usa + USA_WORD_BYTES];
    let mut result = primary.to_vec();
    for at in (0..primary.len()).step_by(SECTOR_BYTES) {
        let a = &primary[at..at + SECTOR_BYTES];
        let b = &mirror[at..at + SECTOR_BYTES];
        match (&a[SECTOR_TAIL..] == token, &b[SECTOR_TAIL..] == token) {
            (true, true) if a != b => return Err(reject("surviving mirrored sectors disagree")),
            (true, _) => {}
            (false, true) => result[at..at + SECTOR_BYTES].copy_from_slice(b),
            (false, false) => return Err(reject("both copies lost the same MFT sector; evidence preserved")),
        }
    }
    let mut decoded = result.clone();
    MftRecord::parse(&mut decoded, sector)?;
    ntfs_rs::record_edit::validate(&decoded)?;
    Ok(result)
}

// Valid redundant records may differ in publication LSN and cached times.
// Every other header, attribute and value byte must still agree.
fn bootstrap_metadata_matches(primary: &[u8], mirror: &[u8]) -> io::Result<bool> {
    use ntfs_rs::std_info;

    if primary.len() != mirror.len() {
        return Ok(false);
    }
    let times = |raw: &[u8]| -> io::Result<Option<std::ops::Range<usize>>> {
        let record = MftRecord::from_decoded(raw)?;
        let Some(attribute) = record.local_attribute(std_info::SI, &[])? else {
            return Ok(None);
        };
        let length = attribute.resident_value().map(|value| value.len());
        if attribute.nonresident || !matches!(length?, std_info::LEGACY_BYTES | std_info::CURRENT_BYTES) {
            return Ok(None);
        }
        let start = attribute.record_offset() + attribute.resident_value_offset()?;
        Ok(Some(start..start + std_info::TIMES_BYTES))
    };
    let (Some(primary_times), Some(mirror_times)) = (times(primary)?, times(mirror)?) else {
        return Ok(false);
    };
    if primary_times != mirror_times {
        return Ok(false);
    }
    let lsn = record_layout::LSN_OFFSET..record_layout::LSN_END;
    Ok(primary
        .iter()
        .zip(mirror)
        .enumerate()
        .all(|(offset, (a, b))| a == b || lsn.contains(&offset) || primary_times.contains(&offset)))
}

// Resolve boot authority independently of mutable MFT publication during resume.
fn bootstrap_boot(source: &Path) -> io::Result<(ntfs_rs::boot::BootSector, Vec<Patch>)> {
    use ntfs_rs::boot::{BootSector, BOOT_SECTOR_BYTES};

    let file = File::open(source)?;
    let length = image_length(&file)?;
    let mut image = Image(file);
    let mut primary = vec![0; BOOT_SECTOR_BYTES];
    image.read_exact_at(0, &mut primary)?;
    if let Ok(boot) = BootSector::parse(&primary) {
        let sector = u64::from(boot.bytes_per_sector);
        let backup_at = boot.total_sectors.checked_mul(sector).ok_or_else(|| reject("boot geometry overflow"))?;
        if backup_at.checked_add(sector) != Some(length) {
            return Err(reject("repair requires an exact volume image including its backup boot sector"));
        }
        primary.resize(sector as usize, 0);
        image.read_exact_at(0, &mut primary)?;
        let mut backup = vec![0; primary.len()];
        image.read_exact_at(backup_at, &mut backup)?;
        if primary == backup {
            return Ok((boot, Vec::new()));
        }
        if let Ok(mut backup_boot) = BootSector::parse(&backup) {
            // The primary owns its serial and boot code when both copies
            // describe the same geometry and metadata locations.

            backup_boot.serial_number = boot.serial_number;
            if backup_boot != boot {
                return Err(reject("valid boot sectors describe different geometry or metadata locations"));
            }
        }
        return Ok((boot, vec![Patch::new(backup_at, backup, primary)]));
    }
    let mut found = None;
    for sector in BACKUP_SECTOR_SIZES {
        let Some(at) = length.checked_sub(sector) else {
            continue;
        };
        let mut backup = vec![0; sector as usize];
        image.read_exact_at(at, &mut backup)?;
        let Ok(boot) = BootSector::parse(&backup) else {
            continue;
        };
        if u64::from(boot.bytes_per_sector) != sector || boot.total_sectors.checked_mul(sector) != Some(at) {
            continue;
        }
        if found.is_some() {
            return Err(reject("multiple backup boot geometries validate"));
        }
        primary.resize(sector as usize, 0);
        image.read_exact_at(0, &mut primary)?;
        found = Some((boot, vec![Patch::new(0, primary.clone(), backup)]));
    }
    found.ok_or_else(|| reject("no valid primary or terminal backup boot sector"))
}

/// Inspect the $MFT base record's own mapping and bitmap descriptors.
fn mft_base_needs_family_rebuild(record: &MftRecord<'_>, record_bytes: u64) -> io::Result<bool> {
    let mut minimum_bitmap = 0;
    let mut minimum_actual_bitmap = 0;
    let mut mft_size_mismatch = false;
    for attribute in record.attributes() {
        let attribute = attribute?;
        if attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() {
            mft_size_mismatch |= attribute.data_size()? != attribute.initialized_size()?;
            let slots = attribute.initialized_size()? / record_bytes;
            minimum_bitmap = slots.div_ceil(u64::BITS.into()) * std::mem::size_of::<u64>() as u64;
            minimum_actual_bitmap = slots.div_ceil(u8::BITS.into());
        }
    }
    let (mut has_list, mut has_bitmap, mut resident_bitmap) = (false, false, false);
    let (mut bitmap_size_invalid, mut bitmap_actual_missing) = (false, false);
    for attribute in record.attributes() {
        let attribute = attribute?;
        has_list |= attribute.kind == ATTR_ATTRIBUTE_LIST;
        if attribute.kind != ATTR_BITMAP || !attribute.name_utf16le()?.is_empty() {
            continue;
        }
        has_bitmap = true;
        resident_bitmap |= !attribute.nonresident;
        let (size, initialized) = (attribute.data_size()?, attribute.initialized_size()?);
        bitmap_size_invalid |=
            size % std::mem::size_of::<u64>() as u64 != 0 || size < minimum_bitmap || initialized < minimum_bitmap;
        bitmap_actual_missing |= initialized < minimum_actual_bitmap;
    }
    // Missing real bits need checked record-state derivation;
    // reserved resident padding alone can grow locally.

    Ok(has_list
        || mft_size_mismatch
        || bitmap_actual_missing
        || (bitmap_size_invalid && !resident_bitmap)
        || !has_bitmap)
}

fn bootstrap_repairs(source: &Path) -> io::Result<(ntfs_rs::boot::BootSector, Vec<Patch>)> {
    use family::MftMappingState;

    let (boot, mut patches) = bootstrap_boot(source)?;
    let mut image = Image::open(source)?;
    let record_bytes = u64::from(boot.record_bytes);
    let sector = u64::from(boot.bytes_per_sector);
    let mirror_at = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes);
    let mirror_slots = system_record::MIRRORED.max(u64::from(boot.cluster_bytes / boot.record_bytes));
    let bytes = mirror_slots * record_bytes;
    let main_at = boot.mft_byte_offset()?;
    let volume_end = boot.total_sectors * sector;
    if main_at < sector
        || mirror_at < sector
        || main_at.checked_add(bytes).is_none_or(|end| end > volume_end)
        || mirror_at.checked_add(bytes).is_none_or(|end| end > volume_end)
        || (main_at < mirror_at + bytes && mirror_at < main_at + bytes)
    {
        return Err(reject("invalid or overlapping MFT bootstrap locations"));
    }
    let ready = |raw: &mut [u8]| -> io::Result<bool> {
        let record = MftRecord::parse(raw, boot.bytes_per_sector)?;
        Ok(family::mft_mapping_state(&record, boot)? == MftMappingState::Ready)
    };
    // The mirror reserves at least one cluster, but only the first four
    // critical records are required for bootstrap. Spare slots may be unused.

    for number in 0..system_record::MIRRORED {
        let mut original = vec![0; record_bytes as usize];
        let mut mirror = original.clone();
        let mut fragments = Vec::new();
        if number == system_record::MFT {
            image.read_exact_at(main_at, &mut original)?;
            fragments.push((main_at, 0, record_bytes as usize));
        } else {
            let mut volume = PlannedImage::volume(source, &patches, boot)?;
            let zero = checker::consistency::mft_image(&mut volume)?;
            let mft = MftRecord::from_decoded(&zero)?;
            let data = mft.stream(ATTR_DATA, &[])?;
            plan_nonresident_overwrite(data, boot, number * record_bytes, record_bytes, |span| {
                fragments.push((span.physical_offset, span.source_offset as usize, span.length as usize));
                Ok(())
            })?;
            volume.read_mft_record(&mft, number, &mut original)?;
        }
        let mirror_offset = mirror_at + number * record_bytes;
        image.read_exact_at(mirror_offset, &mut mirror)?;
        let normalize = |raw: &[u8]| -> ntfs_rs::Result<Vec<u8>> {
            let mut raw = raw.to_vec();
            let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            if record.flags()? & record_layout::IN_USE == 0
                || record.base_file_reference()? != 0
                || (number >= system_record::RESERVED && record.sequence_number()? == 0)
            {
                return Err(ntfs_rs::Error::InvalidRecord);
            }
            record.attributes().try_for_each(|attribute| attribute.map(|_| ()))?;
            let identity = record.physical_record_number()?;
            if identity.is_some_and(|identity| identity as u32 != number as u32) {
                return Err(ntfs_rs::Error::InvalidRecord);
            }
            // Reserved identities are determined by their checked slot.

            if number < system_record::RESERVED {
                put_u16(&mut raw, record_layout::SEQUENCE_OFFSET, reserved_sequence(number));
            }
            if identity.is_some() {
                put_u16(&mut raw, record_layout::NUMBER_HIGH_OFFSET, (number >> u32::BITS) as u16);
            }
            clear_usa(&mut raw)?;
            Ok(raw)
        };
        let primary_record = normalize(&original);
        let mirror_record = normalize(&mirror);
        if let (true, Ok(primary), Ok(backup)) = (number == system_record::MFT, &primary_record, &mirror_record) {
            if primary == backup {
                let record = MftRecord::from_decoded(primary)?;
                let state = family::mft_mapping_state(&record, boot)?;
                let needs_family = mft_base_needs_family_rebuild(&record, record_bytes)?;
                let canonical = || -> io::Result<Vec<u8>> {
                    let mut canonical = primary.clone();
                    protect_mft_record(&mut canonical, boot.bytes_per_sector)?;
                    Ok(canonical)
                };
                let family_rebuild =
                    state == MftMappingState::Reconstruct || (state == MftMappingState::Ready && needs_family);
                if family_rebuild {
                    // Validate the family before dependent reads. Already
                    // canonical descriptors need no family publication.

                    let restored = family::reconstruct_mft_family(source, boot, &patches, &canonical()?)?;
                    if !restored.is_empty() {
                        let mut reader =
                            PlannedImage { image: PlannedImage::open(source, &patches)?, patches: &restored };
                        let mut raw = vec![0; record_bytes as usize];
                        reader.read_exact_at(main_at, &mut raw)?;
                        if !ready(&mut raw)? {
                            return Err(reject("consolidated MFT lacks its critical anchor"));
                        }
                        patches.extend(restored);
                        continue;
                    }
                }
                match state {
                    MftMappingState::Ready => {}
                    MftMappingState::WrongAnchor => {
                        return Err(reject("MFT mapping contradicts its critical-record anchor"));
                    }
                    MftMappingState::Reconstruct => {
                        // Intact redundant bases retain their other metadata.
                        // Rebuild a lost mapping before any dependent record read.

                        let mut reader = PlannedImage::open(source, &patches)?;
                        let mut restored = family::reconstruct_mft_data(&mut reader, boot, &canonical()?)?;
                        put_u16(&mut restored, record_layout::SEQUENCE_OFFSET, reserved_sequence(number));
                        put_u16(&mut restored, record_layout::NUMBER_HIGH_OFFSET, 0);
                        if !ready(&mut restored.clone())? {
                            return Err(reject("reconstructed MFT mapping lacks its critical anchor"));
                        }
                        patches.push(Patch::new(main_at, original, restored.clone()));
                        patches.push(Patch::new(mirror_offset, mirror, restored));
                        continue;
                    }
                }
            }
        }
        let canonical_identity = |raw: &[u8]| -> io::Result<bool> {
            Ok((number >= system_record::RESERVED
                || u16_field(raw, record_layout::SEQUENCE_OFFSET)? == reserved_sequence(number))
                && (u16_field(raw, record_layout::USA_OFFSET)? == record_layout::LEGACY_USA
                    || u16_field(raw, record_layout::NUMBER_HIGH_OFFSET)? == (number >> u32::BITS) as u16))
        };
        let restored = match (primary_record, mirror_record) {
            (Ok(a), Ok(b)) if a == b => {
                if canonical_identity(&original)? && canonical_identity(&mirror)? {
                    None
                } else {
                    Some(original.clone())
                }
            }
            (Ok(primary), Ok(backup)) => {
                if !bootstrap_metadata_matches(&primary, &backup)? {
                    return Err(reject("valid MFT/mirror records disagree; authority is ambiguous"));
                }
                if number == system_record::MFT {
                    let record = MftRecord::from_decoded(&primary)?;
                    if family::mft_mapping_state(&record, boot)? != MftMappingState::Ready {
                        return Err(reject("primary MFT lacks a validated critical-record mapping"));
                    }
                    let mut volume = PlannedImage::volume(source, &patches, boot)?;
                    let raw = checker::read_record(&mut volume, &record, system_record::VOLUME)?;
                    ntfs_rs::volume_info::VolumeInfo::from_record(&MftRecord::from_decoded(&raw)?)?;
                }
                Some(original.clone())
            }
            (Err(_), Err(_)) => {
                let restored = reconstruct_mirror_sectors(&original, &mirror, boot.bytes_per_sector)?;
                normalize(&restored)?;
                Some(restored)
            }
            (Ok(_), Err(_)) => Some(original.clone()),
            (Err(_), Ok(_)) => Some(mirror.clone()),
        };
        if let Some(mut restored) = restored {
            // These fields precede every protected sector tail, so correcting
            // them preserves the validated update-sequence protection.

            if number < system_record::RESERVED {
                put_u16(&mut restored, record_layout::SEQUENCE_OFFSET, reserved_sequence(number));
            }
            // On the legacy layout these bytes hold USA, not an identity.

            if u16_field(&restored, record_layout::USA_OFFSET)? != record_layout::LEGACY_USA {
                put_u16(&mut restored, record_layout::NUMBER_HIGH_OFFSET, (number >> u32::BITS) as u16);
            }
            for (physical, start, length) in fragments {
                let range = start..start + length;
                if original[range.clone()] != restored[range.clone()] {
                    patches.push(Patch::new(physical, original[range.clone()].to_vec(), restored[range].to_vec()));
                }
            }
            if mirror != restored {
                patches.push(Patch::new(mirror_offset, mirror, restored));
            }
        }
    }
    // Confirm both bootstrap addresses against the restored stream mappings.
    // The physical mirror was validated above; its derived stream mapping is
    // repaired against that evidence by canonical_streams.

    let mut volume = PlannedImage::volume(source, &patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    checker::read_record(&mut volume, &mft, system_record::MFT_MIRROR)?;
    plan_nonresident_overwrite(mft.stream(ATTR_DATA, &[])?, boot, 0, record_bytes, |span| {
        if span.physical_offset != main_at + span.source_offset {
            return Err(ntfs_rs::Error::InvalidRunlist);
        }
        Ok(())
    })?;
    Ok((boot, patches))
}

// Recover only header fields derived from the surviving, fixup-validated
// attribute chain. Neither sequence numbers nor missing attribute contents
// can be inferred from a directory name or a plausible-looking raw sector.
fn decode_repair_record(raw: &[u8], sector: u16) -> io::Result<(Vec<u8>, bool)> {
    use ntfs_rs::record_edit::{attr_len, p16, p32, validate};

    let mut decoded = raw.to_vec();
    if MftRecord::parse(&mut decoded, sector).is_ok() && validate(&decoded).is_ok() {
        let next = u16_field(&decoded, record_layout::NEXT_ATTRIBUTE_ID_OFFSET)?;
        if !MftRecord::from_decoded(&decoded)?.attributes().any(|a| a.is_ok_and(|a| a.id == next)) {
            return Ok((decoded, false));
        }
    }
    let capacity = u32::try_from(decoded.len()).map_err(|_| reject("record too large"))?;
    let reset = |decoded: &mut Vec<u8>| -> io::Result<()> {
        decoded.copy_from_slice(raw);
        p32(decoded, record_layout::USED_OFFSET, capacity)?;
        p32(decoded, record_layout::CAPACITY_OFFSET, capacity)?;
        Ok(())
    };
    reset(&mut decoded)?;
    if MftRecord::parse(&mut decoded, sector).is_err() {
        // The canonical first attribute follows the complete USA. Its offset
        // is derivable; record contents and sequence numbers are not. Sector
        // tail mismatches still fail parse, so this never bypasses torn writes.

        reset(&mut decoded)?;
        let usa = usize::from(u16_field(raw, record_layout::USA_OFFSET)?);
        let count = usize::from(u16_field(raw, record_layout::USA_COUNT_OFFSET)?);
        let first = (usa + count * USA_WORD_BYTES).next_multiple_of(ATTRIBUTE_ALIGNMENT);
        if first < record_layout::HEADER_BYTES || first + record_layout::END_MARKER_BYTES > raw.len() {
            return Err(reject("no derivable record framing"));
        }
        p16(&mut decoded, record_layout::FIRST_ATTRIBUTE_OFFSET, first as u16)?;
        MftRecord::parse(&mut decoded, sector)?;
    }
    let first = usize::from(u16_field(&decoded, record_layout::FIRST_ATTRIBUTE_OFFSET)?);
    let mut end = first;
    for attribute in MftRecord::from_decoded(&decoded)?.attributes() {
        let at = attribute?.record_offset();
        end = at + attr_len(&decoded, at)?;
    }
    if u32_at(&decoded, end)? != record_layout::END_MARKER || end + record_layout::END_MARKER_BYTES > decoded.len() {
        return Err(reject("damaged attribute chain has no authoritative end marker"));
    }
    p32(&mut decoded, record_layout::USED_OFFSET, (end + record_layout::END_MARKER_BYTES) as u32)?;
    // Reordering an intact chain changes no attribute ID, value or mapping.
    // Keep order within each type, including multiple FILE_NAME attributes.

    let mut attributes = Vec::new();
    let mut ids = BTreeSet::new();
    for attribute in MftRecord::from_decoded(&decoded)?.attributes() {
        let attribute = attribute?;
        if !ids.insert(attribute.id) {
            return Err(reject("duplicate attribute IDs require unambiguous family evidence"));
        }
        let start = attribute.record_offset();
        attributes.push((attribute.kind, decoded[start..start + attr_len(&decoded, start)?].to_vec()));
    }
    attributes.sort_by_key(|attribute| attribute.0);
    let mut cursor = first;
    for (_, attribute) in attributes {
        decoded[cursor..cursor + attribute.len()].copy_from_slice(&attribute);
        cursor += attribute.len();
    }
    if ids.contains(&u16_field(&decoded, record_layout::NEXT_ATTRIBUTE_ID_OFFSET)?) {
        let next = ids.last().copied().unwrap_or(0).checked_add(1);
        let next = next.ok_or_else(|| reject("attribute identifier space is exhausted"))?;
        p16(&mut decoded, record_layout::NEXT_ATTRIBUTE_ID_OFFSET, next)?;
    }
    validate(&decoded)?;
    Ok((decoded, true))
}

const BITMAP_CACHE_BYTES: usize = 8192;
type BitmapCache = (u64, [u8; BITMAP_CACHE_BYTES]);

fn bitmap_byte<R: ReadAt>(
    volume: &mut Volume<R>,
    attribute: Attribute<'_>,
    offset: u64,
    bytes: u64,
    cache: &mut BitmapCache,
) -> io::Result<u8> {
    if offset >= bytes {
        return Err(reject("bitmap index outside stream"));
    }
    let window = offset / BITMAP_CACHE_BYTES as u64 * BITMAP_CACHE_BYTES as u64;
    if cache.0 != window {
        let n = (bytes - window).min(BITMAP_CACHE_BYTES as u64) as usize;
        volume.read_attribute(attribute, window, &mut cache.1[..n])?;
        cache.0 = window;
    }
    Ok(cache.1[(offset - window) as usize])
}

/// Whether bit is set in a bitmap stream holding bits entries.
fn bitmap_bit<R: ReadAt>(
    volume: &mut Volume<R>,
    attribute: Attribute<'_>,
    bit: u64,
    bits: u64,
    cache: &mut BitmapCache,
) -> io::Result<bool> {
    Ok(bitmap_byte(volume, attribute, bit / 8, bits.div_ceil(8), cache)? & (1 << (bit % 8)) != 0)
}

/// Index root value: attribute type, collation and sizes, then the index header.
const INDEX_HEADER_OFFSET: usize = 16;
const INDEX_HEADER_BYTES: usize = 16;
const INDEX_ROOT_MIN_BYTES: usize = 48;
/// Index header fields relative to the header, and entry fields relative to an entry.
const HEADER_FIRST_ENTRY: usize = 0;
const HEADER_ENTRIES_END: usize = 4;
const HEADER_ALLOCATED: usize = 8;
const HEADER_FLAGS: usize = 12;
const ENTRY_LENGTH: usize = 8;
const ENTRY_KEY_LENGTH: usize = 10;
const ENTRY_FLAGS: usize = 12;
const ENTRY_HEADER_BYTES: usize = 16;
const ENTRY_HAS_CHILD: u16 = 1;
const ENTRY_LAST: u16 = 2;
const CHILD_VCN_BYTES: usize = std::mem::size_of::<u64>();

// Index framing is common to $I30, $SII/$SDH, $R, $ObjId:$O and $Quota's
// indexes. Reconstruct only derived header lengths/child flags from a complete
// entry chain. Keys, values, quota limits, IDs and permissions are untouched.
fn repaired_index_header(value: &[u8]) -> io::Result<Option<[u8; INDEX_HEADER_BYTES]>> {
    if value.len() < INDEX_ROOT_MIN_BYTES {
        return Err(reject("truncated index root"));
    }
    let first = u32_at(value, INDEX_HEADER_OFFSET + HEADER_FIRST_ENTRY)? as usize;
    if first < INDEX_HEADER_BYTES || first % ATTRIBUTE_ALIGNMENT != 0 || first + INDEX_HEADER_OFFSET > value.len() {
        return Err(reject("unknown index entry start"));
    }
    let mut at = INDEX_HEADER_OFFSET + first;
    let mut children = None;
    loop {
        if at + ENTRY_HEADER_BYTES > value.len() {
            return Err(reject("index root has no terminal entry"));
        }
        let n = usize::from(u16_field(value, at + ENTRY_LENGTH)?);
        let key = usize::from(u16_field(value, at + ENTRY_KEY_LENGTH)?);
        let flags = u16_field(value, at + ENTRY_FLAGS)?;
        let child = flags & ENTRY_HAS_CHILD != 0;
        let fixed = ENTRY_HEADER_BYTES + usize::from(child) * CHILD_VCN_BYTES;
        if flags & !(ENTRY_HAS_CHILD | ENTRY_LAST) != 0
            || n < fixed
            || n % ATTRIBUTE_ALIGNMENT != 0
            || at + n > value.len()
            || key > n - fixed
            || children.is_some_and(|old| old != child)
        {
            return Err(reject("damaged index entries cannot be inferred from the header"));
        }
        children = Some(child);
        at += n;
        if flags & ENTRY_LAST != 0 {
            if key != 0 || n != fixed {
                return Err(reject("invalid index terminator"));
            }
            break;
        }
    }
    // An existing allocated tail is not evidence of another live entry.
    // Nonzero unknown tail data remains unresolved rather than being dropped.

    if value[at..].iter().any(|b| *b != 0) {
        return Ok(None);
    }
    let current = &value[INDEX_HEADER_OFFSET..INDEX_HEADER_OFFSET + INDEX_HEADER_BYTES];
    let mut head: [u8; INDEX_HEADER_BYTES] = current.try_into().unwrap();
    head[HEADER_ENTRIES_END..HEADER_ALLOCATED].copy_from_slice(&((at - INDEX_HEADER_OFFSET) as u32).to_le_bytes());
    head[HEADER_ALLOCATED..HEADER_FLAGS].copy_from_slice(&((value.len() - INDEX_HEADER_OFFSET) as u32).to_le_bytes());
    head[HEADER_FLAGS] = u8::from(children == Some(true));
    Ok((head != current).then_some(head))
}

// Restoring an MFT allocation bit is provisional: the subsequent complete
// graph, sequence, ownership and security audit must validate the revived
// record. Only an exact framed empty placeholder can lose a stale claim;
// a name alone cannot authorize clearing or reviving a record.
fn record_repairs(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<()> {
    let reader = PlannedImage { image: Image(File::open(source)?), patches };
    let mut volume = Volume::new(reader, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let data = mft.stream(ATTR_DATA, &[])?;
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let initialized = data.initialized_size()?;
    let slots = initialized / u64::from(boot.record_bytes);
    if initialized % u64::from(boot.record_bytes) != 0 || !(16..=0x0000_ffff_ffff_ffff).contains(&slots) {
        return Err(reject("invalid MFT repair record count"));
    }
    let mut bits = (u64::MAX, [0; 8192]);
    let mut extra = RepairPlan::new(patches.length)?;
    let mut original = vec![0; boot.record_bytes as usize];
    let mirror_count = 4.max(boot.cluster_bytes / boot.record_bytes) as u64;
    for number in 0..slots {
        if number % 256 == 0 {
            progress(RepairProgress::new(
                Phase::ScanMft,
                number * u64::from(boot.record_bytes) / 512,
                slots * u64::from(boot.record_bytes) / 512,
            ));
        }
        volume.read_mft_record(&mft, number, &mut original).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MFT record {number} has no readable mapped copy: {error}; source bytes preserved"),
            )
        })?;
        let allocated = bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)?;
        let in_use = original.get(..4) == Some(b"FILE") && ntfs_rs::bytes::u16_at(&original, 22)? & 1 != 0;
        if !allocated && !in_use {
            continue;
        }
        if !in_use {
            let mut decoded = original.clone();
            let record = MftRecord::parse(&mut decoded, boot.bytes_per_sector)?;
            if !family::mft_empty_free_slot(&record, number)?
                || !family::mft_empty_slot_unowned(&mut volume, &mft, &record, number)?
            {
                return Err(reject("allocated MFT slot has no in-use record; ownership is ambiguous"));
            }
            if bitmap.nonresident {
                repair_record_bit(&mut volume, &mft, number, false, &mut extra)?;
            } else {
                // Read every earlier record edit before changing this resident
                // byte, and compose its true preimage only after the view drops.
                let mut current = Volume::new(
                    PlannedImage {
                        image: PlannedImage { image: Image(File::open(source)?), patches },
                        patches: &extra,
                    },
                    boot,
                )?;
                let family = family::RepairFamily::load(&mut current, &mft, 0)?;
                let mut stage = RepairPlan::new(patches.length)?;
                family.patch_resident_values(
                    &mut current,
                    &mft,
                    ATTR_BITMAP,
                    &[],
                    &mut |value| {
                        let byte = value
                            .get_mut((number / 8) as usize)
                            .ok_or_else(|| reject("resident MFT bit exceeds its checked value"))?;
                        *byte &= !(1 << (number % 8));
                        Ok(())
                    },
                    &mut stage,
                )?;
                drop(current);
                for patch in stage.iter() {
                    extra.compose(patch?)?;
                }
            }
            bits.0 = u64::MAX;
            continue;
        }
        let (mut after, mut changed) = decode_repair_record(&original, boot.bytes_per_sector)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData,
                format!("MFT record {number} has no trustworthy decoded copy (source checksum {:016x}): {error}; source bytes preserved",
                    repair_checksum(0, &original))))?;
        let record = MftRecord::from_decoded(&after)?;
        let sequence = record.sequence_number()?;
        if number >= 16 && sequence == 0 {
            return Err(reject("in-use record has a zero sequence number"));
        }
        let mut fields = Vec::new();
        if number < 16 && sequence != number.max(1) as u16 {
            fields.push((16, (number.max(1) as u16).to_le_bytes().to_vec()));
        }
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind == ntfs_rs::mft::ATTR_FILE_NAME {
                if attribute.nonresident {
                    if (12..16).contains(&number) {
                        return Err(reject("nonresident system FILE_NAME requires reconstruction"));
                    }
                    // FILE_NAME must be resident. Namespace repair removes this
                    // framed claim without reading its mapped value.
                } else {
                    // The indexed bit governs name admission. Keep every other
                    // resident bit and leave unindexed claims for semantic removal.
                    attribute.resident_flags()?;
                }
            }
            if attribute.kind == ntfs_rs::mft::ATTR_INDEX_ROOT && !attribute.nonresident {
                // A completely damaged directory tree is rebuilt separately;
                // framing repair is used only when the entire chain validates.
                if let Ok(Some(header)) = repaired_index_header(attribute.resident_value()?) {
                    fields.push((attribute.record_offset() + attribute.resident_value_offset()? + 16, header.to_vec()));
                }
            }
            if attribute.kind == ntfs_rs::reparse::ATTR_REPARSE {
                let size = attribute.data_size()?;
                if (8..=ntfs_rs::reparse::MAX_CREATE as u64).contains(&size) {
                    let mut value = vec![0; size as usize];
                    volume.read_attribute(attribute, 0, &mut value)?;
                    let tag = u32_at(&value, 0)?;
                    if ntfs_rs::reparse::is_link_tag(tag)
                        && usize::from(ntfs_rs::bytes::u16_at(&value, 4)?) + 8 != value.len()
                    {
                        let length = ((value.len() - 8) as u16).to_le_bytes();
                        let before = value[4..6].to_vec();
                        value[4..6].copy_from_slice(&length);
                        ntfs_rs::reparse::target(&value, 0, &mut vec![0; ntfs_rs::reparse::MAX_TARGET])?;
                        if attribute.nonresident {
                            stage_change(attribute, boot, 4, 2, &before, &length, &mut extra)?;
                        } else {
                            fields.push((
                                attribute.record_offset() + attribute.resident_value_offset()? + 4,
                                length.to_vec(),
                            ));
                        }
                    }
                }
            }
        }
        // Complete-family EA summaries are repaired after family assembly.
        // They may require an extension record rather than base-local space.
        let identity = MftRecord::from_decoded(&after)?.physical_record_number()?;
        // A legacy header has no physical identity field. Preserve its USA;
        // modern records can be corrected against the validated owning slot.
        if identity.is_some_and(|identity| identity != number) {
            ntfs_rs::record_edit::p32(&mut after, 44, number as u32)?;
            ntfs_rs::record_edit::p16(&mut after, 42, (number >> 32) as u16)?;
            changed = true;
        }
        if !allocated {
            let offset = number / 8;
            let before = bitmap_byte(&mut volume, bitmap, offset, slots.div_ceil(8), &mut bits)?;
            let after = before | (1 << (number % 8));
            plan_nonresident_overwrite(bitmap, boot, offset, 1, |span| {
                extra
                    .push(Patch::new(span.physical_offset, vec![before], vec![after]))
                    .map_err(|_| ntfs_rs::Error::Io)?;
                Ok(())
            })?;
            bits.1[(offset - bits.0) as usize] = after;
        }
        changed |= !fields.is_empty();
        if !changed {
            continue;
        }
        for (at, value) in fields {
            after[at..at + value.len()].copy_from_slice(&value);
        }
        ntfs_rs::record_edit::validate(&after)?;
        protect_mft_record(&mut after, boot.bytes_per_sector)?;
        stage_change(
            data,
            boot,
            number * u64::from(boot.record_bytes),
            after.len() as u64,
            &original,
            &after,
            &mut extra,
        )?;
        if number < mirror_count {
            let physical = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + number * u64::from(boot.record_bytes);
            let mut before = vec![0; after.len()];
            PlannedImage { image: Image(File::open(source)?), patches }.read_exact_at(physical, &mut before)?;
            extra.push(Patch::new(physical, before, after))?;
        }
    }
    progress(RepairProgress::new(
        Phase::ScanMft,
        slots * u64::from(boot.record_bytes) / 512,
        slots * u64::from(boot.record_bytes) / 512,
    ));
    drop(volume);
    for patch in extra.iter() {
        patches.compose(patch?)?;
    }
    Ok(())
}

// Construct ordinary NTFS B-tree pages; separator entries are promoted, not
// duplicated in leaves. Reuse validated allocation without guessing new runs.
fn repair_entry_next(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut header[1..])?;
    let n = u32::from_le_bytes(header) as usize;
    if !(16..=65536).contains(&n) {
        return Err(reject("invalid scratch index entry"));
    }
    let mut entry = vec![0; n];
    reader.read_exact(&mut entry)?;
    Ok(Some(entry))
}
fn repair_entry_write(writer: &mut impl Write, entry: &[u8]) -> io::Result<()> {
    writer.write_all(&(entry.len() as u32).to_le_bytes())?;
    writer.write_all(entry)
}

fn rebuilt_index(
    boot: ntfs_rs::boot::BootSector,
    mut entries: File,
    mut count: u64,
    mut entry_bytes: u64,
    root_room: usize,
    key_kind: u32,
    collation: u32,
) -> io::Result<(Vec<u8>, File, u64)> {
    use ntfs_rs::record_edit::{p16, p32, p64};
    let bytes = boot.index_block_bytes as usize;
    let unit = if bytes < boot.cluster_bytes as usize { 512 } else { boot.cluster_bytes as usize };
    if bytes % unit != 0 || bytes / unit > 255 {
        return Err(reject("invalid index VCN geometry"));
    }
    let first = (40 + (bytes / 512 + 1) * 2 + 7) & !7;
    let mut pages = checker::consistency::scratch_file()?;
    let mut page_count = 0_u64;
    let mut tail = None;
    let encode = |entries: &[Vec<u8>], tail: Option<u64>, block: Option<u64>| -> io::Result<Vec<u8>> {
        let start = if block.is_some() { first } else { 32 };
        let end = start + entries.iter().map(Vec::len).sum::<usize>() + if tail.is_some() { 24 } else { 16 };
        let mut out = vec![0; if block.is_some() { bytes } else { end }];
        if end > out.len() {
            return Err(reject("index node does not fit"));
        }
        let head = if let Some(vcn) = block {
            out[..4].copy_from_slice(b"INDX");
            p16(&mut out, 4, 40)?;
            p16(&mut out, 6, (bytes / 512 + 1) as u16)?;
            p64(&mut out, 16, vcn)?;
            24
        } else {
            p32(&mut out, 0, key_kind)?;
            p32(&mut out, 4, collation)?;
            p32(&mut out, 8, bytes as u32)?;
            out[12] = (bytes / unit) as u8;
            16
        };
        p32(&mut out, head, (start - head) as u32)?;
        p32(&mut out, head + 4, (end - head) as u32)?;
        let allocation = (out.len() - head) as u32;
        p32(&mut out, head + 8, allocation)?;
        out[head + 12] = u8::from(tail.is_some());
        let mut at = start;
        for entry in entries {
            out[at..at + entry.len()].copy_from_slice(entry);
            at += entry.len();
        }
        p16(&mut out, at + 8, if tail.is_some() { 24 } else { 16 })?;
        p16(&mut out, at + 12, if tail.is_some() { 3 } else { 2 })?;
        if let Some(vcn) = tail {
            p64(&mut out, at + 16, vcn)?;
        }
        if let Some(vcn) = block {
            ntfs_rs::mft::protect_fixups(&mut out)?;
            ntfs_rs::index::IndexBlock::parse(&mut out.clone(), boot.bytes_per_sector, vcn)?;
        } else if key_kind == 0x30 && collation == 1 {
            ntfs_rs::index::IndexRoot::parse(&out)?;
        } else if !matches!((key_kind, collation), (0, 16 | 17 | 18 | 19)) {
            return Err(reject("unsupported repaired index collation"));
        }
        Ok(out)
    };
    loop {
        entries.seek(SeekFrom::Start(0))?;
        let mut input = std::io::BufReader::new(entries);
        if 32 + entry_bytes + if tail.is_some() { 24 } else { 16 } <= root_room as u64 {
            let mut group = Vec::new();
            while let Some(entry) = repair_entry_next(&mut input)? {
                group.push(entry);
            }
            pages.seek(SeekFrom::Start(0))?;
            return Ok((encode(&group, tail, None)?, pages, page_count));
        }
        let mut pending = repair_entry_next(&mut input)?;
        let mut remaining = count;
        let mut parents = checker::consistency::scratch_file()?;
        let mut parent_count = 0_u64;
        let mut parent_bytes = 0_u64;
        let last;
        loop {
            let mut group = Vec::new();
            let mut size = first + if tail.is_some() { 24 } else { 16 };
            while pending.as_ref().is_some_and(|e| size + e.len() <= bytes) {
                let entry = pending.take().unwrap();
                size += entry.len();
                group.push(entry);
                remaining = remaining.checked_sub(1).ok_or_else(|| reject("index input count mismatch"))?;
                pending = repair_entry_next(&mut input)?;
            }
            if group.is_empty() {
                return Err(reject("directory key does not fit index page"));
            }
            let vcn = page_count.checked_mul((bytes / unit) as u64).ok_or_else(|| reject("index VCN overflow"))?;
            if pending.is_none() {
                if remaining != 0 {
                    return Err(reject("truncated index input"));
                }
                pages.write_all(&encode(&group, tail, Some(vcn))?)?;
                page_count += 1;
                last = vcn;
                break;
            }
            let mut separator = if remaining == 1 && group.len() > 1 {
                group.pop().unwrap()
            } else {
                let entry = pending.take().unwrap();
                pending = repair_entry_next(&mut input)?;
                remaining = remaining.checked_sub(1).ok_or_else(|| reject("index input count mismatch"))?;
                entry
            };
            let end_child = if tail.is_some() { Some(u64_at(&separator, separator.len() - 8)?) } else { None };
            pages.write_all(&encode(&group, end_child, Some(vcn))?)?;
            page_count += 1;
            if tail.is_none() {
                separator.resize(separator.len() + 8, 0);
            }
            let n = separator.len();
            p16(&mut separator, 8, n as u16)?;
            p16(&mut separator, 12, 1)?;
            p64(&mut separator, n - 8, vcn)?;
            repair_entry_write(&mut parents, &separator)?;
            parent_count += 1;
            parent_bytes += n as u64;
            if pending.is_none() {
                return Err(reject("cannot build an empty right index branch"));
            }
        }
        entries = parents;
        count = parent_count;
        entry_bytes = parent_bytes;
        tail = Some(last);
    }
}

// Reuse the same physical ownership inventory for allocations by directory
// rebuilding and cross-link relocation. Bitmap-free alone is never authority.
fn repair_owned_ranges<R: ReadAt>(volume: &mut Volume<R>, mft: &MftRecord<'_>) -> io::Result<File> {
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let slots = mft.stream(ATTR_DATA, &[])?.initialized_size()? / u64::from(volume.boot.record_bytes);
    let mut bits = (u64::MAX, [0; 8192]);
    repair_owned_ranges_with_bits(volume, mft, |volume, number| {
        Ok(bitmap_bit(volume, bitmap, number, slots, &mut bits)?)
    })
}
fn repair_owned_ranges_with_bits<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    mut allocated: impl FnMut(&mut Volume<R>, u64) -> io::Result<bool>,
) -> io::Result<File> {
    let boot = volume.boot;
    let data = mft.stream(ATTR_DATA, &[])?;
    let slots = data.initialized_size()? / u64::from(boot.record_bytes);
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut inventory = checker::consistency::DiskInventory::new();
    // Bootstrap anchors remain occupied when their derived descriptors are
    // missing. Reconstruction must never allocate over the surviving evidence.
    inventory.push([0, 1, 7, 0])?;
    let mirror_clusters =
        u64::from(boot.cluster_bytes).max(4 * u64::from(boot.record_bytes)).div_ceil(u64::from(boot.cluster_bytes));
    let mirror_end = boot
        .mft_mirror_lcn
        .checked_add(mirror_clusters)
        .filter(|&n| n <= clusters)
        .ok_or_else(|| reject("mirror anchor exceeds volume"))?;
    inventory.push([boot.mft_mirror_lcn, mirror_end, 1, 0])?;
    for number in 0..slots {
        if !allocated(volume, number)? {
            continue;
        }
        volume.read_mft_record(mft, number, &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        for a in record.attributes() {
            let a = a?;
            if !a.nonresident {
                continue;
            }
            for run in ntfs_rs::runlist::DataRuns::new(a.data_runs()?, a.first_vcn()?) {
                let run = run?;
                if let Some(lcn) = run.lcn {
                    let end = lcn
                        .checked_add(run.len)
                        .filter(|n| *n <= clusters)
                        .ok_or_else(|| reject("invalid allocation owner"))?;
                    inventory.push([lcn, end, number, u64::from(a.id)])?;
                }
            }
        }
    }
    inventory.finish()
}
// Scan bitmap and ownership together. A bitmap-free cluster with a surviving
// owner is unavailable, as is any cluster already reserved by this plan.
fn repair_reserve_fragments<R: ReadAt>(
    volume: &mut Volume<R>,
    allocation: Attribute<'_>,
    owned: &mut (impl Read + Seek),
    reserved: &mut File,
    count: u64,
    cursor: &mut u64,
) -> io::Result<Vec<ntfs_rs::runlist::Extent>> {
    use checker::consistency::inventory_next;
    use ntfs_rs::runlist::Extent;
    if count == 0 {
        return Err(reject("empty repair allocation"));
    }
    let clusters = volume.boot.total_sectors / u64::from(volume.boot.sectors_per_cluster);
    owned.seek(SeekFrom::Start(0))?;
    reserved.seek(SeekFrom::Start(0))?;
    let mut owner = inventory_next(owned)?;
    let mut reservation = inventory_next(reserved)?;
    let mut cache = (u64::MAX, [0; 8192]);
    let mut at = (*cursor).max(1);
    let mut remaining = count;
    let mut extents: Vec<Extent> = Vec::new();
    while at < clusters && remaining != 0 {
        while owner.is_some_and(|r| r[1] <= at) {
            owner = inventory_next(owned)?;
        }
        while reservation.is_some_and(|r| r[1] <= at) {
            reservation = inventory_next(reserved)?;
        }
        if let Some(row) = owner.filter(|r| r[0] <= at) {
            at = row[1];
            continue;
        }
        if let Some(row) = reservation.filter(|r| r[0] <= at) {
            at = row[1];
            continue;
        }
        let byte = bitmap_byte(volume, allocation, at / 8, clusters.div_ceil(8), &mut cache)?;
        if byte & (1 << (at % 8)) == 0 {
            if let Some(last) = extents.last_mut().filter(|r| r.lcn.unwrap() + r.len == at) {
                last.len += 1;
            } else {
                extents.push(Extent { vcn: count - remaining, lcn: Some(at), len: 1 });
            }
            remaining -= 1;
        }
        at += 1;
    }
    if remaining != 0 {
        return Err(reject("insufficient unowned free clusters for relocation"));
    }
    reserved.seek(SeekFrom::End(0))?;
    for run in &extents {
        checker::consistency::inventory_write(reserved, [run.lcn.unwrap(), run.lcn.unwrap() + run.len, 0, 0])?;
    }
    *cursor = at;
    Ok(extents)
}

fn repair_reserve<R: ReadAt>(
    volume: &mut Volume<R>,
    allocation: Attribute<'_>,
    owned: &mut (impl Read + Seek),
    reserved: &mut File,
    count: u64,
    cursor: &mut u64,
) -> io::Result<u64> {
    use checker::consistency::inventory_next;
    use ntfs_rs::allocation::{find_free_run_planned, BitmapPlan, BITMAP_PLAN_BYTES};
    if count == 0 {
        return Err(reject("empty repair allocation"));
    }
    let clusters = volume.boot.total_sectors / u64::from(volume.boot.sectors_per_cluster);
    let mut storage = vec![0; BITMAP_PLAN_BYTES];
    let plan = BitmapPlan::new(&mut storage)?;
    let mut scan = [0; 512];
    let mut blocked = Vec::new();
    let length = reserved.metadata()?.len();
    if length != 0 {
        reserved.seek(SeekFrom::Start(length - 32))?;
        let row = inventory_next(reserved)?.ok_or_else(|| reject("truncated reservations"))?;
        blocked.push((row[0], row[1] - row[0]));
    }
    let lcn = loop {
        let candidate =
            find_free_run_planned(volume, allocation, &plan, &blocked, count, clusters, None, *cursor, &mut scan)?;
        if candidate < *cursor {
            return Err(reject("no unowned repair allocation remains"));
        }
        let end = candidate
            .checked_add(count)
            .filter(|n| *n <= clusters)
            .ok_or_else(|| reject("repair allocation overflow"))?;
        let mut conflict = None;
        owned.seek(SeekFrom::Start(0))?;
        while let Some(row) = inventory_next(owned)? {
            if row[0] >= end {
                break;
            }
            if row[1] > candidate {
                conflict = Some(row[1]);
                break;
            }
        }
        reserved.seek(SeekFrom::Start(0))?;
        while let Some(row) = inventory_next(reserved)? {
            if row[0] >= end {
                break;
            }
            if row[1] > candidate {
                conflict = Some(conflict.unwrap_or(0).max(row[1]));
            }
        }
        match conflict {
            Some(next) => *cursor = next,
            None => break candidate,
        }
    };
    *cursor = lcn + count;
    reserved.seek(SeekFrom::End(0))?;
    checker::consistency::inventory_write(reserved, [lcn, *cursor, 0, 0])?;
    Ok(lcn)
}
// Keep the original attribute ID when replacing a stream. Family-list entries
// remain valid; newly inserted attributes are added by the next family pass.
fn repair_replace(record: &mut [u8], attribute: &[u8]) -> io::Result<()> {
    use ntfs_rs::record_edit as e;
    let kind = u32_at(attribute, 0)?;
    let name = e::attr_name(attribute, 0)?;
    let old = e::find(record, kind, name)?;
    let id = old.map(|at| ntfs_rs::bytes::u16_at(record, at + 14)).transpose()?;
    if let Some(at) = old {
        e::remove(record, at)?;
    }
    let at = e::insert(record, attribute)?;
    if let Some(id) = id {
        e::p16(record, at + 14, id)?;
    }
    Ok(())
}

fn repair_members<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    reference: u64,
) -> io::Result<BTreeMap<u64, (Vec<u8>, Vec<u8>)>> {
    let boot = volume.boot;
    let mut raw = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(mft, reference_number(reference), &mut raw)?;
    let before = raw.clone();
    let base = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
    if u64::from(base.sequence_number()?) != reference >> 48 || base.base_file_reference()? != 0 {
        return Err(reject("invalid family base"));
    }
    let mut refs = BTreeSet::new();
    for a in base.attributes() {
        let a = a?;
        if a.kind != ATTR_ATTRIBUTE_LIST {
            continue;
        }
        let n = a.data_size()? as usize;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(n).map_err(io::Error::other)?;
        bytes.resize(n, 0);
        volume.read_attribute(a, 0, &mut bytes)?;
        for entry in ntfs_rs::attrlist::AttributeList::new(&bytes) {
            refs.insert(entry?.file_reference);
        }
    }
    let mut members = BTreeMap::from([(reference, (before, raw))]);
    for member in refs {
        if member == reference {
            continue;
        }
        let mut raw = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(mft, reference_number(member), &mut raw)?;
        let before = raw.clone();
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        if u64::from(record.sequence_number()?) != member >> 48
            || record.base_file_reference()? != reference
            || record.flags()? & 1 == 0
        {
            return Err(reject("stale or foreign directory family member"));
        }
        members.insert(member, (before, raw));
    }
    Ok(members)
}

fn repair_record_bit<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    number: u64,
    allocated: bool,
    extra: &mut RepairPlan,
) -> io::Result<()> {
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let mut error = None;
    plan_nonresident_overwrite(bitmap, volume.boot, number / 8, 1, |span| {
        let result = (|| -> io::Result<()> {
            let mut old = vec![0; 1];
            volume.read_physical(span.physical_offset, &mut old)?;
            extra.overlay(span.physical_offset, &mut old)?;
            let mask = 1 << (number % 8);
            if (old[0] & mask != 0) == allocated {
                return Err(reject("MFT reservation collision"));
            }
            let new = vec![if allocated { old[0] | mask } else { old[0] & !mask }];
            extra.push(Patch::new(span.physical_offset, old, new))
        })();
        if let Err(e) = result {
            error = Some(e);
            return Err(ntfs_rs::Error::Io);
        }
        Ok(())
    })
    .map_err(|e| error.unwrap_or_else(|| invalid(e)))?;
    Ok(())
}

fn repair_new_extension<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    base: u64,
    cursor: &mut u64,
    extra: &mut RepairPlan,
    limit: u64,
) -> io::Result<(u64, (Vec<u8>, Vec<u8>))> {
    use ntfs_rs::record_edit as e;
    let boot = volume.boot;
    let data = mft.stream(ATTR_DATA, &[])?;
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    if !bitmap.nonresident {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "MFT bitmap must be externalized before reserving extension slots",
        ));
    }
    let slots = (data.initialized_size()? / u64::from(boot.record_bytes)).min(limit);
    let mut bits = (u64::MAX, [0; 8192]);
    while *cursor < slots {
        let number = *cursor;
        *cursor += 1;
        let reserved_mft = reference_number(base) == 0 && (16..24).contains(&number);
        if bitmap_bit(volume, bitmap, number, slots, &mut bits)? && !reserved_mft {
            continue;
        }
        // Earlier family updates in the same stage may already own this slot.
        let mut staged = [0_u8];
        volume.read_attribute(bitmap, number / 8, &mut staged)?;
        for span in overwrite_spans(bitmap, boot, number / 8, 1)? {
            extra.overlay(span.physical_offset, &mut staged)?;
        }
        let already_allocated = staged[0] & (1 << (number % 8)) != 0;
        if already_allocated && !reserved_mft {
            continue;
        }
        let mut before = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(mft, number, &mut before)?;
        let mut decoded = before.clone();
        let Ok(record) = MftRecord::parse(&mut decoded, boot.bytes_per_sector) else {
            continue;
        };
        if record.flags()? & 1 != 0 || record.sequence_number()? == 0 {
            continue;
        }
        if reserved_mft && record.attributes().next().is_some() {
            continue;
        }
        let sequence = record.sequence_number()?;
        let mut after = vec![0; boot.record_bytes as usize];
        e::format_empty(&mut after, number)?;
        e::p16(&mut after, 16, sequence)?;
        e::p16(&mut after, 22, 1)?;
        e::p64(&mut after, 32, base)?;
        if !already_allocated {
            repair_record_bit(volume, mft, number, true, extra)?;
        }
        return Ok((number | (u64::from(sequence) << 48), (before, after)));
    }
    Err(io::Error::new(io::ErrorKind::OutOfMemory,
        format!("file family {base:016x} needs an extension but all {slots} initialized MFT slots are unavailable; source and planned preimages preserved")))
}

// Grow an $MFT mapping when initialized record slots are exhausted.
// New FILE images and zeroed allocation bits precede publication of record
// zero; the final complete allocation audit claims newly reserved clusters.
fn repair_mft_growth(source: &Path, boot: ntfs_rs::boot::BootSector, patches: &mut RepairPlan) -> io::Result<()> {
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let logical = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&logical)?;
    let resident_bitmap = !mft.stream(ATTR_BITMAP, &[])?.nonresident;
    drop(volume);
    if resident_bitmap {
        return growth::repack(source, boot, patches);
    }
    match repair_mft_growth_in_place(source, boot, patches) {
        Ok(()) => Ok(()),
        Err(first) => growth::repack(source, boot, patches)
            .map_err(|second| io::Error::new(second.kind(), format!("MFT growth: {first}; family repack: {second}"))),
    }
}

fn repair_mft_growth_in_place(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
) -> io::Result<()> {
    use ntfs_rs::record_edit as edit;
    let reader = PlannedImage { image: Image(File::open(source)?), patches };
    let mut volume = Volume::new(reader, boot)?;
    let mut original = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut original)?;
    let mut after = original.clone();
    MftRecord::parse(&mut after, boot.bytes_per_sector)?;
    // A complete, sequence-checked logical MFT image supplies the physical
    // mapping of a split stream. Never publish that synthetic image: only
    // record zero and the checked final extension are written below.
    let logical_before = checker::consistency::mft_image(&mut volume)?;
    let logical_mft = MftRecord::from_decoded(&logical_before)?;
    let logical_data = logical_mft.stream(ATTR_DATA, &[])?;
    let base = MftRecord::from_decoded(&after)?;
    let split_data = base.local_attribute(ATTR_DATA, &[]).is_err();
    if !split_data {
        base.stream(ATTR_DATA, &[])?;
    }
    base.stream(ATTR_BITMAP, &[])?;
    let data_at = if split_data {
        let mut found = None;
        for item in base.attributes() {
            let attr = item?;
            if attr.kind == ATTR_DATA && attr.name_utf16le()?.is_empty() {
                if attr.first_vcn()? != 0 || found.replace(attr.record_offset()).is_some() {
                    return Err(reject("split MFT base data attribute is ambiguous"));
                }
            }
        }
        found.ok_or_else(|| reject("split MFT has no base data attribute"))?
    } else {
        edit::require(&after, ATTR_DATA, &[])?
    };
    let (allocated, data, initialized) = edit::sizes(&after, data_at)?;
    let record_bytes = u64::from(boot.record_bytes);
    let old_slots = initialized / record_bytes;
    let capacity = allocated / record_bytes;
    if initialized != data
        || initialized % record_bytes != 0
        || allocated % u64::from(boot.cluster_bytes) != 0
        || old_slots >= u64::from(u32::MAX)
    {
        return Err(reject("MFT size geometry cannot be grown without guessing"));
    }
    let new_slots = if capacity > old_slots {
        capacity.min(old_slots + 64)
    } else {
        old_slots
            .checked_add(64)
            .filter(|n| *n <= u64::from(u32::MAX))
            .ok_or_else(|| reject("MFT slot number overflow"))?
    };
    let new_bytes = new_slots.checked_mul(record_bytes).ok_or_else(|| reject("MFT size overflow"))?;
    if split_data
        && logical_data.last_vcn()?.checked_add(1).and_then(|n| n.checked_mul(u64::from(boot.cluster_bytes)))
            != Some(allocated)
    {
        return Err(reject("split MFT allocation does not match its complete extent family"));
    }
    let mut stage = RepairPlan::new(patches.length)?;
    let mut owned = std::io::BufReader::new(repair_owned_ranges(&mut volume, &logical_mft)?);
    let mut reserved = checker::consistency::scratch_file()?;
    let allocation_raw = checked_family_image(&mut volume, &logical_mft, 6)?;
    let allocation_record = MftRecord::from_decoded(&allocation_raw)?;
    let allocation = allocation_record.stream(ATTR_DATA, &[])?;
    let mut cursor = 1;
    let mut split_run = None;
    let mut split_tail = None;
    let new_allocated = if new_bytes > allocated {
        let clusters = (new_bytes - allocated).div_ceil(u64::from(boot.cluster_bytes));
        let lcn = repair_reserve(&mut volume, allocation, &mut owned, &mut reserved, clusters, &mut cursor)?;
        if split_data {
            let list = base
                .attributes()
                .collect::<ntfs_rs::Result<Vec<_>>>()?
                .into_iter()
                .find(|a| a.kind == ATTR_ATTRIBUTE_LIST)
                .ok_or_else(|| reject("split MFT list disappeared"))?;
            if list.nonresident {
                return Err(reject("split MFT list needs an independently mapped resident prefix"));
            }
            let mut tail = None;
            for item in ntfs_rs::attrlist::AttributeList::new(list.resident_value()?) {
                let entry = item?;
                if entry.kind == ATTR_DATA
                    && entry.name_utf16le.is_empty()
                    && tail.is_none_or(|(vcn, _, _)| entry.first_vcn > vcn)
                {
                    tail = Some((entry.first_vcn, entry.file_reference, entry.attribute_id));
                }
            }
            let (first_vcn, reference, id) = tail.ok_or_else(|| reject("split MFT has no listed final extent"))?;
            let number = reference_number(reference);
            if first_vcn == 0 || number == 0 || number >= old_slots {
                return Err(reject("split MFT final extent is not bootstrappable from initialized records"));
            }
            let mut before = vec![0; boot.record_bytes as usize];
            volume.read_mft_record(&logical_mft, number, &mut before)?;
            let mut extension = before.clone();
            let record = MftRecord::parse(&mut extension, boot.bytes_per_sector)?;
            if u64::from(record.sequence_number()?) != reference >> 48
                || record.base_file_reference()? != (u64::from(base.sequence_number()?) << 48)
                || record.flags()? & 1 == 0
            {
                return Err(reject("split MFT final extension has a conflicting identity"));
            }
            let mut at = None;
            for item in record.attributes() {
                let attr = item?;
                if attr.id == id {
                    if attr.kind != ATTR_DATA
                        || !attr.nonresident
                        || !attr.name_utf16le()?.is_empty()
                        || attr.first_vcn()? != first_vcn
                        || attr.last_vcn()? != logical_data.last_vcn()?
                    {
                        return Err(reject("split MFT final extent disagrees with its validated mapping"));
                    }
                    at = Some(attr.record_offset());
                }
            }
            let at = at.ok_or_else(|| reject("split MFT final extension attribute is absent"))?;
            edit::append_run(&mut extension, at, lcn, clusters)?;
            edit::validate(&extension)?;
            protect_mft_record(&mut extension, boot.bytes_per_sector)?;
            split_run = Some((lcn, clusters));
            split_tail = Some((number, before, extension));
        } else {
            edit::append_run(&mut after, data_at, lcn, clusters)?;
        }
        allocated
            .checked_add(clusters * u64::from(boot.cluster_bytes))
            .ok_or_else(|| reject("MFT allocation size overflow"))?
    } else {
        allocated
    };
    edit::set_sizes(&mut after, data_at, new_allocated, new_bytes, new_bytes)?;
    let bitmap_at = edit::require(&after, ATTR_BITMAP, &[])?;
    let bitmap_bytes = new_slots.div_ceil(64) * 8;
    let bitmap_resident = !edit::is_nonresident(&after, bitmap_at)?;
    if split_data && !bitmap_resident {
        let (bitmap_allocated, _, _) = edit::sizes(&after, bitmap_at)?;
        if bitmap_bytes > bitmap_allocated {
            return Err(reject("split MFT bitmap needs another extent; existing mapping is preserved"));
        }
    }
    if bitmap_resident {
        let old = edit::resident_value(&after, bitmap_at)?;
        if old.len() as u64 * 8 < old_slots {
            return Err(reject("MFT bitmap is shorter than initialized records"));
        }
        let mut value = vec![0; old.len().max(bitmap_bytes as usize)];
        value[..old.len()].copy_from_slice(old);
        for slot in old_slots..new_slots {
            value[(slot / 8) as usize] &= !(1 << (slot % 8));
        }
        edit::set_resident_value(&mut after, bitmap_at, &value)?;
    } else {
        let (b_alloc, b_data, b_init) = edit::sizes(&after, bitmap_at)?;
        if b_init != b_data || b_data * 8 < old_slots {
            return Err(reject("MFT bitmap size evidence is inconsistent"));
        }
        let mut b_alloc = b_alloc;
        if bitmap_bytes > b_alloc {
            let clusters = (bitmap_bytes - b_alloc).div_ceil(u64::from(boot.cluster_bytes));
            let lcn = repair_reserve(&mut volume, allocation, &mut owned, &mut reserved, clusters, &mut cursor)?;
            edit::append_run(&mut after, bitmap_at, lcn, clusters)?;
            b_alloc = b_alloc
                .checked_add(clusters * u64::from(boot.cluster_bytes))
                .ok_or_else(|| reject("MFT bitmap allocation overflow"))?;
        }
        let bitmap_at = edit::require(&after, ATTR_BITMAP, &[])?;
        edit::set_sizes(&mut after, bitmap_at, b_alloc, bitmap_bytes.max(b_data), bitmap_bytes.max(b_data))?;
    }
    edit::validate(&after)?;
    let mut logical_after = logical_before.clone();
    let logical_data_at = edit::require(&logical_after, ATTR_DATA, &[])?;
    if split_data {
        if let Some((lcn, clusters)) = split_run {
            edit::append_run(&mut logical_after, logical_data_at, lcn, clusters)?;
        }
        edit::set_sizes(&mut logical_after, logical_data_at, new_allocated, new_bytes, new_bytes)?;
        if !bitmap_resident {
            let at = edit::require(&after, ATTR_BITMAP, &[])?;
            let (allocated, data, initialized) = edit::sizes(&after, at)?;
            let logical_at = edit::require(&logical_after, ATTR_BITMAP, &[])?;
            edit::set_sizes(&mut logical_after, logical_at, allocated, data, initialized)?;
        }
    } else {
        logical_after = after.clone();
    }
    edit::validate(&logical_after)?;
    let new_mft = MftRecord::from_decoded(&logical_after)?;
    let new_data = new_mft.stream(ATTR_DATA, &[])?;
    for number in old_slots..new_slots {
        let mut record = vec![0; boot.record_bytes as usize];
        edit::format_empty(&mut record, number)?;
        protect_mft_record(&mut record, boot.bytes_per_sector)?;
        stage_overwrite(&mut volume, new_data, number * record_bytes, &record, &mut stage)?;
    }
    if !bitmap_resident {
        let bitmap = new_mft.stream(ATTR_BITMAP, &[])?;
        let first = old_slots / 8;
        let end = new_slots.div_ceil(8);
        for span in overwrite_spans(bitmap, boot, first, end - first)? {
            let mut before = vec![0; span.length as usize];
            volume.read_physical(span.physical_offset, &mut before)?;
            let mut changed = before.clone();
            for (i, byte) in changed.iter_mut().enumerate() {
                let logical = first + span.source_offset + i as u64;
                let bit_start = (logical * 8).max(old_slots);
                let bit_end = ((logical + 1) * 8).min(new_slots);
                for slot in bit_start..bit_end {
                    *byte &= !(1 << (slot % 8));
                }
            }
            if changed != before {
                stage.push(Patch::new(span.physical_offset, before, changed))?;
            }
        }
    }
    if let Some((number, before, changed)) = split_tail {
        repair_record_patch(&mut volume, logical_data, number, &before, &changed, &mut stage)?;
    }
    protect_mft_record(&mut after, boot.bytes_per_sector)?;
    repair_record_patch(&mut volume, logical_data, 0, &original, &after, &mut stage)?;
    drop(volume);
    for patch in stage.iter() {
        patches.compose(patch?)?;
    }
    Ok(())
}
/// Physical spans of a nonresident overwrite, so callers can act with io errors.
fn overwrite_spans(data: Attribute<'_>, boot: BootSector, offset: u64, length: u64) -> io::Result<Vec<WriteSpan>> {
    let mut spans = Vec::new();
    plan_nonresident_overwrite(data, boot, offset, length, |span| {
        spans.push(span);
        Ok(())
    })?;
    Ok(spans)
}

/// Stage after at a stream offset; each preimage is read from its physical span.
fn stage_overwrite<R: ReadAt>(
    volume: &mut Volume<R>,
    data: Attribute<'_>,
    offset: u64,
    after: &[u8],
    stage: &mut RepairPlan,
) -> io::Result<()> {
    for span in overwrite_spans(data, volume.boot, offset, after.len() as u64)? {
        let start = span.source_offset as usize;
        let mut before = vec![0; span.length as usize];
        volume.read_physical(span.physical_offset, &mut before)?;
        stage.push(Patch::new(span.physical_offset, before, after[start..start + span.length as usize].to_vec()))?;
    }
    Ok(())
}

/// Stage before to after over length stream bytes, one patch per physical span.
fn stage_change(
    data: Attribute<'_>,
    boot: BootSector,
    offset: u64,
    length: u64,
    before: &[u8],
    after: &[u8],
    extra: &mut RepairPlan,
) -> io::Result<()> {
    for span in overwrite_spans(data, boot, offset, length)? {
        let (start, end) = (span.source_offset as usize, (span.source_offset + span.length) as usize);
        extra.push(Patch::new(span.physical_offset, before[start..end].to_vec(), after[start..end].to_vec()))?;
    }
    Ok(())
}

fn repair_record_patch<R: ReadAt>(
    volume: &mut Volume<R>,
    data: Attribute<'_>,
    number: u64,
    before: &[u8],
    after: &[u8],
    extra: &mut RepairPlan,
) -> io::Result<()> {
    let boot = volume.boot;
    stage_change(data, boot, number * u64::from(boot.record_bytes), after.len() as u64, before, after, extra)?;
    if number < u64::from(4.max(boot.cluster_bytes / boot.record_bytes)) {
        let physical = boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + number * u64::from(boot.record_bytes);
        let mut original = vec![0; after.len()];
        volume.read_physical(physical, &mut original)?;
        extra.push(Patch::new(physical, original, after.to_vec()))?;
    }
    Ok(())
}

// A removed partner leaves an ordinary name. DOS aliases are paired with
// surviving Win32 names under the same parent, independently of other links.
fn normalize_surviving_aliases(changes: &mut [StreamChange]) -> io::Result<bool> {
    let mut long_parents = std::collections::BTreeSet::new();
    for change in changes.iter() {
        let attribute = change.attribute.as_ref().unwrap();
        let at = usize::from(ntfs_rs::bytes::u16_at(attribute, 20)?);
        if attribute[at + 65] & 1 != 0 {
            long_parents.insert(u64_at(attribute, at)?);
        }
    }
    let single = changes.len() == 1;
    let mut changed = false;
    for change in changes {
        let attribute = change.attribute.as_mut().unwrap();
        let at = usize::from(ntfs_rs::bytes::u16_at(attribute, 20)?);
        let namespace = attribute[at + 65];
        if (single && matches!(namespace & 3, 1 | 2))
            || (namespace & 3 == 2 && !long_parents.contains(&u64_at(attribute, at)?))
        {
            attribute[at + 65] &= !3;
            changed = true;
        }
    }
    Ok(changed)
}

// Drop the later colliding claim across its complete family. A remaining alias
// becomes an ordinary name; an object without names keeps its data and receives
// a generated name under the fresh recovery folder.
fn remove_colliding_filename(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    reference: u64,
    owner: u64,
    id: u16,
) -> io::Result<()> {
    let mut recovery_names = None;
    loop {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let family = RepairFamily::load(&mut volume, &mft, reference_number(reference))?;
        if family.reference != reference {
            return Err(reject("colliding filename base identity changed"));
        }
        let record = MftRecord::from_decoded(&family.logical)?;
        let mut changes = Vec::new();
        let mut preferred = None;
        for (member, (_, image)) in repair_members(&mut volume, &mft, reference)? {
            for attr in MftRecord::from_decoded(&image)?.attributes() {
                let attr = attr?;
                if attr.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                    continue;
                }
                let value = attr.resident_value()?;
                if value.len() < 66 || value.len() != 66 + usize::from(value[64]) * 2 {
                    return Err(reject("invalid colliding filename length"));
                }
                if member == owner && attr.id == id {
                    preferred = Some(value[66..].to_vec());
                    continue;
                }
                let mut change = StreamChange::resident(attr.kind, &[], value)?;
                change.attribute.as_mut().unwrap()[22] = attr.resident_flags()?;
                changes.push(change);
            }
        }
        let preferred = preferred.ok_or_else(|| reject("colliding filename family changed before repacking"))?;
        normalize_surviving_aliases(&mut changes)?;
        let recovered = changes.is_empty();
        if recovered {
            let Some(names) = recovery_names.as_ref() else {
                drop(volume);
                recovery_names = Some(recovery_name_ordinals(source, boot, patches)?);
                continue;
            };
            let value =
                metadata::orphan_filename(&mut volume, &record, names.parent, names.next_file, Some(&preferred))?;
            let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
            change.attribute.as_mut().unwrap()[22] = 1;
            changes.push(change);
        }
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut extra = RepairPlan::new(patches.length)?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if !commit_store(result, extra, source, boot, patches)? {
            continue;
        }
        return Ok(());
    }
}

/// Compose a family store into the plan. MFT exhaustion instead grows the
/// MFT; false asks the caller to rebuild its view and retry the store.
fn commit_store(
    result: io::Result<()>,
    extra: RepairPlan,
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
) -> io::Result<bool> {
    if result.as_ref().is_err_and(|error| error.kind() == io::ErrorKind::OutOfMemory) {
        repair_mft_growth(source, boot, patches)?;
        return Ok(false);
    }
    result?;
    extra.iter().try_for_each(|patch| patches.compose(patch?))?;
    Ok(true)
}

// Group only distinct objects without a valid link. Parent sequences do not
// identify a missing directory, but its low32 number must fit the MFT slots.
// Sorted disk catalogs keep this decision bounded by the existing spool limit.
fn missing_parent_groups(filename_owners: &mut File, directories: &mut File, slots: u64) -> io::Result<File> {
    use checker::consistency::{inventory_find, inventory_next, DiskInventory};
    filename_owners.seek(SeekFrom::Start(0))?;
    let mut eligible = DiskInventory::new();
    let mut previous = None;
    let mut valid_link = false;
    while let Some([reference, _, parent, _]) = inventory_next(filename_owners)? {
        if previous != Some(reference) {
            if let Some(reference) = previous.filter(|_| !valid_link) {
                eligible.push([reference, 0, 0, 0])?;
            }
            previous = Some(reference);
            valid_link = false;
        }
        valid_link |= inventory_find(directories, parent)?.is_some();
    }
    if let Some(reference) = previous.filter(|_| !valid_link) {
        eligible.push([reference, 0, 0, 0])?;
    }
    let mut eligible = eligible.finish()?;
    let mut candidates = DiskInventory::new();
    filename_owners.seek(SeekFrom::Start(0))?;
    while let Some([reference, _, parent, _]) = inventory_next(filename_owners)? {
        let number = reference_number(parent);
        if number <= u64::from(u32::MAX) && number < slots && inventory_find(&mut eligible, reference)?.is_some() {
            candidates.push([number, reference, 0, 0])?;
        }
    }
    let mut candidates = candidates.finish()?;
    // Earlier groups consume their objects. Re-count each later parent before
    // allocating a folder, so an overlapping claim cannot leave an empty group.
    let mut assigned = checker::consistency::scratch_file()?;
    let mut groups = DiskInventory::new();
    let length = candidates.metadata()?.len();
    while candidates.stream_position()? < length {
        let start = candidates.stream_position()?;
        let parent = inventory_next(&mut candidates)?.ok_or_else(|| reject("missing-parent catalog ended early"))?[0];
        candidates.seek(SeekFrom::Start(start))?;
        let mut count = 0u64;
        let mut previous = None;
        while let Some(row) = inventory_next(&mut candidates)? {
            if row[0] != parent {
                candidates.seek(SeekFrom::Current(-32))?;
                break;
            }
            if previous != Some(row[1])
                && checker::consistency::audit_slot(&mut assigned, reference_number(row[1]), None)?.is_none()
            {
                count += 1;
            }
            previous = Some(row[1]);
        }
        let end = candidates.stream_position()?;
        if count < 2 {
            continue;
        }
        candidates.seek(SeekFrom::Start(start))?;
        while candidates.stream_position()? < end {
            let row = inventory_next(&mut candidates)?.ok_or_else(|| reject("missing-parent catalog ended early"))?;
            let number = reference_number(row[1]);
            if checker::consistency::audit_slot(&mut assigned, number, None)?.is_none() {
                checker::consistency::audit_slot(&mut assigned, number, Some(Some(parent)))?;
                groups.push(row)?;
            }
        }
    }
    groups.finish()
}

// Reuse one recovery folder and its ordinals across an orphan batch.
struct RecoveryNames {
    parent: u64,
    next_file: u32,
    next_directory: u32,
}

// Seed a recovery batch from names already published in this repair plan.
fn recovery_name_ordinals(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
) -> io::Result<RecoveryNames> {
    let parent = metadata::recovery_directory(source, boot, patches)?;
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let logical = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&logical)?;
    Ok(RecoveryNames {
        parent,
        next_file: metadata::next_recovery_ordinal(&mut volume, &mft, parent, false)?,
        next_directory: metadata::next_recovery_ordinal(&mut volume, &mft, parent, true)?,
    })
}

// Remove invalid parent claims across the complete family. A surviving valid
// link keeps the object reachable; missing-parent groups retain their names,
// while isolated objects receive one generated name in the fresh found folder.
fn reconnect_orphan(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    reference: u64,
    directories: &mut File,
    dropped_parent: Option<u64>,
    group: Option<(u64, u64)>,
    recovery_names: &mut Option<RecoveryNames>,
) -> io::Result<()> {
    loop {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let family = RepairFamily::load(&mut volume, &mft, reference_number(reference))?;
        if family.reference != reference || reference_number(reference) < 16 {
            return Err(reject("orphan base identity is unavailable"));
        }
        let record = MftRecord::from_decoded(&family.logical)?;
        let mut changes = Vec::new();
        let mut preferred = None;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            let value = attribute.resident_value()?;
            if value.len() < 66 || value.len() != 66 + usize::from(value[64]) * 2 {
                return Err(reject("invalid orphan filename length"));
            }
            let parent = u64_at(value, 0)?;
            let grouped = group.filter(|(number, _)| reference_number(parent) == *number);
            let valid =
                dropped_parent != Some(parent) && checker::consistency::inventory_find(directories, parent)?.is_some();
            if valid || grouped.is_some() {
                let mut value = value.to_vec();
                if let Some((_, parent)) = grouped {
                    value[..8].copy_from_slice(&parent.to_le_bytes());
                }
                let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
                change.attribute.as_mut().unwrap()[22] = attribute.resident_flags()?;
                changes.push(change);
            } else {
                let units: Vec<_> = ntfs_rs::bytes::units(&value[66..]).collect();
                if String::from_utf16(&units).is_ok_and(|name| name.eq_ignore_ascii_case("hiberfil.sys")) {
                    return Err(reject("orphaned hibernation file must be resolved before repair"));
                }
                if dropped_parent.is_none() && !units.is_empty() && (preferred.is_none() || value[65] & 1 != 0) {
                    preferred = Some(value[66..].to_vec());
                }
            }
        }
        let recovered = changes.is_empty();
        if group.is_none() && dropped_parent.is_none() {
            normalize_surviving_aliases(&mut changes)?;
        }
        if recovered {
            let Some(names) = recovery_names.as_mut() else {
                drop(volume);
                *recovery_names = Some(recovery_name_ordinals(source, boot, patches)?);
                continue;
            };
            let ordinal =
                if preferred.is_none() && record.flags()? & 2 != 0 { names.next_directory } else { names.next_file };
            let value = metadata::orphan_filename(&mut volume, &record, names.parent, ordinal, preferred.as_deref())?;
            let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
            change.attribute.as_mut().unwrap()[22] = 1;
            changes.push(change);
        }
        let directory_fallback = preferred.is_none() && record.flags()? & 2 != 0;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut extra = RepairPlan::new(patches.length)?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if !commit_store(result, extra, source, boot, patches)? {
            continue;
        }
        if recovered {
            let names = recovery_names.as_mut().unwrap();
            let counter = if directory_fallback { &mut names.next_directory } else { &mut names.next_file };
            *counter += 1;
        }
        return Ok(());
    }
}

// Split directory aliases retain their actual valid parents. An indexed DOS
// claim survives as an ordinary link; an unindexed DOS partner is discarded.
// POSIX links may form a multi-parent DAG, and cycle repair remains separate.
fn reconnect_directory(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    reference: u64,
) -> io::Result<()> {
    loop {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let family = RepairFamily::load(&mut volume, &mft, reference_number(reference))?;
        if family.reference != reference {
            return Err(reject("conflicting directory identity changed"));
        }
        let record = MftRecord::from_decoded(&family.logical)?;
        let mut values = Vec::new();
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind == ntfs_rs::mft::ATTR_FILE_NAME {
                let value = attribute.resident_value()?;
                if value.len() < 66 || value.len() != 66 + usize::from(value[64]) * 2 {
                    return Err(reject("invalid directory alias length"));
                }
                values.push((value.to_vec(), attribute.resident_flags()?));
            }
        }
        if values.is_empty() {
            return Err(reject("conflicting directory has no filename"));
        }
        if values.iter().all(|(value, _)| value[65] & 3 == 0) {
            return Ok(());
        }
        let mut changes = Vec::new();
        for (mut value, resident_flags) in values {
            let parent = u64_at(&value, 0)?;
            let family = RepairFamily::load(&mut volume, &mft, reference_number(parent))?;
            let directory = MftRecord::from_decoded(&family.logical)?;
            if family.reference != parent || directory.flags()? & 2 == 0 {
                return Err(reject("directory alias parent identity changed"));
            }
            if value[65] & 3 == 2 {
                let mut indexed = false;
                let mut buffer = vec![0; boot.index_block_bytes as usize];
                let valid_index = volume
                    .visit_directory(&directory, &mut buffer, |key| {
                        indexed |= key.file_reference == reference
                            && key.name.namespace == value[65]
                            && key.name.utf16le == &value[66..]
                            && u64_at(key.file_name_value, 0)? == parent;
                        Ok(())
                    })
                    .is_ok();
                if !valid_index || !indexed {
                    continue;
                }
            }
            value[65] &= !3;
            let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
            change.attribute.as_mut().unwrap()[22] = resident_flags;
            changes.push(change);
        }
        if changes.is_empty() {
            return Err(reject("directory has no surviving parent claim"));
        }
        let mut extra = RepairPlan::new(patches.length)?;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if !commit_store(result, extra, source, boot, patches)? {
            continue;
        }
        return Ok(());
    }
}

// Root has one conventional self-parent combined-name key. Drop other claims
// and restore that required key when its text, namespace or parent was displaced.
// Family publication retains the existing root index and all other metadata.
fn repair_system_filename(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    reference: u64,
    name: &str,
    parent: u64,
) -> io::Result<()> {
    let number = reference_number(reference);
    let text: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    loop {
        let mut volume = PlannedImage::volume(source, patches, boot)?;
        let logical = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&logical)?;
        let family = RepairFamily::load(&mut volume, &mft, number)?;
        if family.reference != reference {
            return Err(reject("system filename identity changed"));
        }
        let record = MftRecord::from_decoded(&family.logical)?;
        let mut changes = Vec::new();
        let mut conventional = false;
        let mut external = false;
        for attribute in record.attributes() {
            let attribute = attribute?;
            if attribute.kind != ntfs_rs::mft::ATTR_FILE_NAME {
                continue;
            }
            if attribute.nonresident {
                external = true;
                continue;
            }
            let value = attribute.resident_value()?;
            if attribute.resident_flags()? & 1 == 0
                || value.len() < 66
                || value.len() != 66 + usize::from(value[64]) * 2
            {
                external = true;
                continue;
            }
            if (number == 5 && u64_at(value, 0)? != reference)
                || value[65] & 3 != 3
                || value[66..] != text
                || conventional
            {
                external = true;
                continue;
            }
            conventional = true;
            let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], value)?;
            change.attribute.as_mut().unwrap()[22] = attribute.resident_flags()?;
            changes.push(change);
        }
        if conventional && !external {
            return Ok(());
        }
        if !conventional {
            let mut value = vec![0; 66 + text.len()];
            value[..8].copy_from_slice(&parent.to_le_bytes());
            value[8..64].copy_from_slice(&ntfs_rs::filename_metadata::duplicated_information(&mut volume, &record)?);
            value[64] = (text.len() / 2) as u8;
            value[65] = 3;
            value[66..].copy_from_slice(&text);
            let mut change = StreamChange::resident(ntfs_rs::mft::ATTR_FILE_NAME, &[], &value)?;
            change.attribute.as_mut().unwrap()[22] = 1;
            changes.push(change);
        }
        let mut extra = RepairPlan::new(patches.length)?;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
        drop(volume);
        if !commit_store(result, extra, source, boot, patches)? {
            continue;
        }
        return Ok(());
    }
}

// Walk FILE_NAME parent edges before publishing indexes. Several valid POSIX
// parents form a DAG; a single-parent lookup would miss cycles in other edges.
// Colors and DFS frames are disk-backed, bounded by the allocated MFT slots.
fn directory_parent_cycle(
    directories: &mut File,
    parents: &mut File,
    slots: u64,
    changed: &mut File,
) -> io::Result<Option<(u64, u64)>> {
    use checker::consistency::{audit_slot, inventory_next, scratch_file, DiskInventory};
    let edges = parents.metadata()?.len() / 32;
    let first = |parents: &mut File, reference: u64| -> io::Result<u64> {
        let (mut left, mut right) = (0, edges);
        while left < right {
            let middle = left + (right - left) / 2;
            parents.seek(SeekFrom::Start(middle * 32))?;
            let row = inventory_next(parents)?.ok_or_else(|| reject("directory parent catalog ended early"))?;
            if row[0] < reference {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        Ok(left)
    };
    let mut colors = scratch_file()?;
    let mut stack = scratch_file()?;
    // Sequence bits validate identities; they must not choose which directory
    // loses a cyclic link. Keep the lookup catalog intact and order DFS roots
    // separately by their MFT numbers.
    let mut roots = DiskInventory::new();
    directories.seek(SeekFrom::Start(0))?;
    while let Some([reference, _, _, _]) = inventory_next(directories)? {
        roots.push([reference_number(reference), reference, 0, 0])?;
    }
    let mut roots = roots.finish()?;
    while let Some([_, reference, _, _]) = inventory_next(&mut roots)? {
        let number = reference_number(reference);
        if number >= slots {
            return Err(reject("directory reference exceeds MFT slots"));
        }
        if audit_slot(&mut colors, number, None)?.is_some() {
            continue;
        }
        audit_slot(&mut colors, number, Some(Some(1)))?;
        stack.seek(SeekFrom::Start(0))?;
        stack.write_all(&reference.to_le_bytes())?;
        stack.write_all(&first(parents, reference)?.to_le_bytes())?;
        let mut depth = 1u64;
        while depth != 0 {
            let frame = (depth - 1) * 16;
            stack.seek(SeekFrom::Start(frame))?;
            let mut bytes = [0; 16];
            stack.read_exact(&mut bytes)?;
            let node = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let next = u64::from_le_bytes(bytes[8..].try_into().unwrap());
            parents.seek(SeekFrom::Start(next * 32))?;
            let edge = inventory_next(parents)?;
            let Some([_, parent, _, _]) = edge.filter(|row| row[0] == node) else {
                audit_slot(&mut colors, reference_number(node), Some(Some(2)))?;
                depth -= 1;
                continue;
            };
            stack.seek(SeekFrom::Start(frame + 8))?;
            stack.write_all(&(next + 1).to_le_bytes())?;
            let number = reference_number(parent);
            if number >= slots {
                return Err(reject("directory parent exceeds MFT slots"));
            }
            match audit_slot(&mut colors, number, None)? {
                Some(1) => {
                    // Remove the ancestor's edge into this cycle. Other parent
                    // claims retain valid paths, including Win32/DOS partners.
                    // Mark every cycle member so reduced checking also rebuilds
                    // balanced stale keys along these affected paths.
                    let mut selected = None;
                    for ancestor in 0..depth {
                        stack.seek(SeekFrom::Start(ancestor * 16))?;
                        stack.read_exact(&mut bytes)?;
                        let reference = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                        if reference == parent {
                            let next = u64::from_le_bytes(bytes[8..].try_into().unwrap());
                            parents.seek(SeekFrom::Start((next - 1) * 32))?;
                            let edge =
                                inventory_next(parents)?.ok_or_else(|| reject("cyclic directory edge disappeared"))?;
                            selected = Some((parent, edge[1]));
                        }
                        if selected.is_some() {
                            audit_slot(changed, reference_number(reference), Some(Some(reference)))?;
                        }
                    }
                    return selected.map(Some).ok_or_else(|| reject("cyclic directory ancestor is absent"));
                }
                Some(_) => {}
                None => {
                    if depth >= slots {
                        return Err(reject("directory graph exceeds MFT slots"));
                    }
                    audit_slot(&mut colors, number, Some(Some(1)))?;
                    stack.seek(SeekFrom::Start(depth * 16))?;
                    stack.write_all(&parent.to_le_bytes())?;
                    stack.write_all(&first(parents, parent)?.to_le_bytes())?;
                    depth += 1;
                }
            }
        }
    }
    Ok(None)
}

fn directory_repairs_with_options(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    options: checker::consistency::AuditOptions,
    mut changed: File,
) -> io::Result<()> {
    use ntfs_rs::mft::{ATTR_FILE_NAME, ATTR_INDEX_ALLOCATION, ATTR_INDEX_ROOT};
    use ntfs_rs::record_edit;
    const I30: &[u8] = b"$\0I\x003\x000\0";
    // Earlier namespace repairs can leave balanced counts in their old indexes.
    // Retain their bounded slot marks and all later marks across directory retries.
    // Rebuild inventories after each structural edit without retaining one
    // stack frame per damaged directory or exhausted allocation attempt.
    'retry: loop {
        let reader = PlannedImage { image: Image(File::open(source)?), patches };
        // Keep balanced indexes in reduced mode. Structural failures and depleted
        // references are marked by the shared checker and rebuilt from their owners.
        let mut reduced = if options.index_check == checker::consistency::IndexCheck::Quick {
            Some(checker::consistency::audit_reader(
                PlannedImage { image: Image(File::open(source)?), patches },
                boot,
                |_, _, _| Ok(()),
                |_| Ok(()),
                options,
                patches.index_cache_bytes,
            )?)
        } else {
            None
        };
        let mut volume = Volume::new(reader, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let data = mft.stream(ATTR_DATA, &[])?;
        let slots = data.initialized_size()? / u64::from(boot.record_bytes);
        let bitmap = mft.stream(ATTR_BITMAP, &[])?;
        let mut bits = (u64::MAX, [0; 8192]);
        let mut raw = vec![0; boot.record_bytes as usize];
        use checker::consistency::{inventory_find, inventory_next, scratch_file, DiskInventory};
        volume.read_mft_record(&mft, 10, &mut raw)?;
        let upcase_record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let mut upcase = vec![0; ntfs_rs::upcase::UPCASE_BYTES];
        volume.read_attribute(upcase_record.stream(ATTR_DATA, &[])?, 0, &mut upcase)?;
        let upcase = std::rc::Rc::new(upcase);
        let values = std::rc::Rc::new(std::cell::RefCell::new(scratch_file()?));
        fn value(file: &mut File, row: [u64; 4]) -> io::Result<Vec<u8>> {
            if !(82..=608).contains(&row[3]) {
                return Err(reject("invalid directory work entry"));
            }
            let mut entry = vec![0; row[3] as usize];
            file.seek(SeekFrom::Start(row[2]))?;
            file.read_exact(&mut entry)?;
            Ok(entry)
        }
        let order_values = values.clone();
        let order_upcase = upcase.clone();
        let mut names = DiskInventory::ordered(move |a, b| {
            if a[0] != b[0] {
                return Ok(a[0].cmp(&b[0]));
            }
            let mut file = order_values.borrow_mut();
            let left = value(&mut file, *a)?;
            let right = value(&mut file, *b)?;
            let order = ntfs_rs::index_tree::compare_names(
                &order_upcase,
                &left[82..82 + left[80] as usize * 2],
                &right[82..82 + right[80] as usize * 2],
            );
            Ok(order.then_with(|| (reference_number(a[1])).cmp(&(reference_number(b[1])))).then_with(|| a.cmp(b)))
        });
        let mut directories = DiskInventory::new();
        let mut references = DiskInventory::new();
        let mut name_owners = DiskInventory::new();
        let mut filename_owners = DiskInventory::new();
        let mut root_reference = None;
        for number in 0..slots {
            if !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
                continue;
            }
            volume.read_mft_record(&mft, number, &mut raw)?;
            let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            let own = number | (u64::from(record.sequence_number()?) << 48);
            let base = record.base_file_reference()?;
            let reference = if base == 0 { own } else { base };
            if base == 0 {
                references.push([own, 0, 0, 0])?;
            }
            if base == 0 && record.flags()? & 2 != 0 {
                directories.push([own, 0, 0, 0])?;
                if number == 5 {
                    root_reference = Some(own);
                    let logical = checked_family_image(&mut volume, &mft, 5)?;
                    let root = MftRecord::from_decoded(&logical)?;
                    if !metadata::root_filename_valid(&root, own)? {
                        drop(volume);
                        checker::consistency::audit_slot(&mut changed, 5, Some(Some(own)))?;
                        repair_system_filename(source, boot, patches, own, ".", own)?;
                        continue 'retry;
                    }
                }
            }
            for attr in record.attributes() {
                let attr = attr?;
                if attr.kind != ATTR_FILE_NAME {
                    continue;
                }
                let filename = attr.resident_value()?;
                let mut entry = [0; 608];
                let n = ntfs_rs::index_tree::directory_entry(reference, filename, &mut entry)?;
                let offset = {
                    let mut file = values.borrow_mut();
                    let at = file.seek(SeekFrom::End(0))?;
                    file.write_all(&entry[..n])?;
                    at
                };
                names.push([u64_at(filename, 0)?, reference, offset, n as u64])?;
                name_owners.push([offset, own, u64::from(attr.id), 0])?;
                filename_owners.push([reference, own, u64_at(filename, 0)?, 0])?;
            }
        }
        let root_reference = root_reference.ok_or_else(|| reject("root directory identity is unavailable"))?;
        let mut directories = directories.finish()?;
        let mut references = references.finish()?;
        let mut name_owners = name_owners.finish()?;
        let mut names = std::io::BufReader::new(names.finish()?);
        let mut orphans = DiskInventory::ordered(|a, b| {
            Ok((reference_number(a[0])).cmp(&(reference_number(b[0]))).then_with(|| a.cmp(b)))
        });
        let mut filename_owners = filename_owners.finish()?;
        filename_owners.seek(SeekFrom::Start(0))?;
        while let Some(row) = inventory_next(&mut filename_owners)? {
            if inventory_find(&mut directories, row[2])?.is_none() {
                orphans.push([row[0], 0, 0, 0])?;
            }
        }
        while let Some(row) = inventory_next(&mut names)? {
            if inventory_find(&mut references, row[1])?.is_none() {
                return Err(reject("extension names have no validated base; bytes preserved"));
            }
        }
        let mut orphans = std::io::BufReader::new(orphans.finish()?);
        if orphans.get_ref().metadata()?.len() != 0 {
            drop(volume);
            let mut groups = missing_parent_groups(&mut filename_owners, &mut directories, slots)?;
            let mut grouped = DiskInventory::new();
            let mut current = None;
            let mut enclosing = None;
            let mut ordinal = 0;
            while let Some([parent, reference, _, _]) = inventory_next(&mut groups)? {
                let folder = if let Some((_, folder)) = current.filter(|(prior, _)| *prior == parent) {
                    folder
                } else {
                    let enclosing = if let Some(enclosing) = enclosing {
                        enclosing
                    } else {
                        let parent = metadata::recovery_directory(source, boot, patches)?;
                        let mut volume = PlannedImage::volume(source, patches, boot)?;
                        let logical = checker::consistency::mft_image(&mut volume)?;
                        let mft = MftRecord::from_decoded(&logical)?;
                        ordinal = metadata::next_recovery_ordinal(&mut volume, &mft, parent, true)?;
                        enclosing = Some(parent);
                        checker::consistency::audit_slot(&mut changed, reference_number(parent), Some(Some(parent)))?;
                        parent
                    };
                    let folder = metadata::recovery_subdirectory(source, boot, patches, enclosing, ordinal)?;
                    ordinal += 1;
                    current = Some((parent, folder));
                    checker::consistency::audit_slot(&mut changed, reference_number(folder), Some(Some(folder)))?;
                    folder
                };
                grouped.push([reference, parent, folder, 0])?;
            }
            let mut grouped = grouped.finish()?;
            let mut previous = None;
            let mut recovery_names = None;
            while let Some([reference, _, _, _]) = inventory_next(&mut orphans)? {
                if previous == Some(reference) {
                    continue;
                }
                previous = Some(reference);
                checker::consistency::audit_slot(&mut changed, reference_number(reference), Some(Some(reference)))?;
                reconnect_orphan(
                    source,
                    boot,
                    patches,
                    reference,
                    &mut directories,
                    None,
                    inventory_find(&mut grouped, reference)?.map(|row| (row[1], row[2])),
                    &mut recovery_names,
                )?;
            }
            continue 'retry;
        }
        // A directory key must have one owner. Remove only an exact competing
        // FILE_NAME claim; its preimage remains in the source or repair journal.
        names.seek(SeekFrom::Start(0))?;
        let mut previous: Option<([u64; 4], Vec<u8>)> = None;
        let mut collision = None;
        while let Some(row) = inventory_next(&mut names)? {
            let entry = value(&mut values.borrow_mut(), row)?;
            let text = &entry[82..82 + entry[80] as usize * 2];
            if let Some((prior, prior_text)) = &previous {
                if prior[0] == row[0]
                    && ntfs_rs::index_tree::compare_names(&upcase, prior_text, text) == std::cmp::Ordering::Equal
                {
                    // An existing valid key has priority. Without one, retain
                    // the earlier object number independently of its sequence.
                    let prior_entry = value(&mut values.borrow_mut(), *prior)?;
                    let logical = checked_family_image(&mut volume, &mft, reference_number(row[0]))?;
                    let directory = MftRecord::from_decoded(&logical)?;
                    let mut indexed = [false; 2];
                    let mut buffer = vec![0; boot.index_block_bytes as usize];
                    let valid_index = volume
                        .visit_directory(&directory, &mut buffer, |key| {
                            for (index, (candidate, expected)) in
                                [(*prior, &prior_entry), (row, &entry)].iter().enumerate()
                            {
                                if key.file_reference == candidate[1]
                                    && key.name.namespace == expected[81]
                                    && key.name.utf16le == &expected[82..82 + expected[80] as usize * 2]
                                    && u64_at(key.file_name_value, 0)? == candidate[0]
                                {
                                    indexed[index] = true;
                                }
                            }
                            Ok(())
                        })
                        .is_ok();
                    collision = Some(if valid_index && indexed == [false, true] { *prior } else { row });
                    break;
                }
            }
            previous = Some((row, text.to_vec()));
        }
        if let Some(row) = collision {
            checker::consistency::audit_slot(&mut changed, reference_number(row[1]), Some(Some(row[1])))?;
            let owner = inventory_find(&mut name_owners, row[2])?
                .ok_or_else(|| reject("colliding name has no attribute owner"))?;
            let number = reference_number(owner[1]);
            if number < 16 {
                return Err(reject("system filename collision requires independent reconstruction"));
            }
            volume.read_mft_record(&mft, number, &mut raw)?;
            MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            let record = MftRecord::from_decoded(&raw)?;
            if u64::from(record.sequence_number()?) != owner[1] >> 48 {
                return Err(reject("colliding filename owner changed"));
            }
            let entry = value(&mut values.borrow_mut(), row)?;
            let mut found = false;
            for attr in record.attributes() {
                let attr = attr?;
                if attr.kind != ATTR_FILE_NAME || u64::from(attr.id) != owner[2] {
                    continue;
                }
                let old = attr.resident_value()?;
                if old.len() < 66
                    || old[65] != entry[81]
                    || u64_at(old, 0)? != row[0]
                    || old[66..] != entry[82..82 + entry[80] as usize * 2]
                {
                    return Err(reject("colliding filename identity disagrees with index key"));
                }
                found = true;
            }
            if !found {
                return Err(reject("colliding filename attribute is absent"));
            }
            drop(volume);
            remove_colliding_filename(source, boot, patches, row[1], owner[1], owner[2] as u16)?;
            continue 'retry;
        }
        // Reconcile split aliases while preserving native-valid POSIX links.
        // All parent edges remain available for the separate cycle walk.
        let mut parent_claims = DiskInventory::ordered(|a, b| {
            Ok(a[0]
                .cmp(&b[0])
                .then_with(|| (reference_number(a[1])).cmp(&(reference_number(b[1]))))
                .then_with(|| a.cmp(b)))
        });
        names.seek(SeekFrom::Start(0))?;
        while let Some(row) = inventory_next(&mut names)? {
            if row[1] == root_reference || inventory_find(&mut directories, row[1])?.is_none() {
                continue;
            }
            let entry = value(&mut values.borrow_mut(), row)?;
            parent_claims.push([row[1], row[0], u64::from(entry[81]), 0])?;
        }
        let mut parents = parent_claims.finish()?;
        let mut conflict = None;
        let mut previous = None;
        let mut alias_parent = None;
        let mut different_aliases = false;
        while let Some(row) = inventory_next(&mut parents)? {
            if previous != Some(row[0]) {
                if different_aliases {
                    conflict = previous;
                    break;
                }
                previous = Some(row[0]);
                alias_parent = None;
                different_aliases = false;
            }
            if row[2] & 3 != 0 {
                if let Some(parent) = alias_parent {
                    different_aliases |= row[1] != parent;
                } else {
                    alias_parent = Some(row[1]);
                }
            }
        }
        if conflict.is_none() && different_aliases {
            conflict = previous;
        }
        if let Some(reference) = conflict {
            drop(volume);
            checker::consistency::audit_slot(&mut changed, reference_number(reference), Some(Some(reference)))?;
            reconnect_directory(source, boot, patches, reference)?;
            continue 'retry;
        }
        let cycle = directory_parent_cycle(&mut directories, &mut parents, slots, &mut changed)?;
        if let Some((reference, parent)) = cycle {
            drop(volume);
            checker::consistency::audit_slot(&mut changed, reference_number(reference), Some(Some(reference)))?;
            reconnect_orphan(source, boot, patches, reference, &mut directories, Some(parent), None, &mut None)?;
            continue 'retry;
        }
        let mut scratch = vec![0; boot.index_block_bytes as usize + 4 * ntfs_rs::tx::RECORD_IMAGE];
        let mut extra = RepairPlan::new(patches.length)?;
        let mut owned = std::io::BufReader::new(repair_owned_ranges(&mut volume, &mft)?);
        let mut reserved = scratch_file()?;
        let mut cursor = 1;
        let mut record_cursor = 24;
        let bitmap_image = checked_family_image(&mut volume, &mft, 6)?;
        let bitmap_record = MftRecord::from_decoded(&bitmap_image)?;
        let allocation_map = bitmap_record.stream(ATTR_DATA, &[])?;
        let mut changed_parents = DiskInventory::new();
        if reduced.is_some() && changed.metadata()?.len() != 0 {
            names.seek(SeekFrom::Start(0))?;
            while let Some(row) = inventory_next(&mut names)? {
                if checker::consistency::audit_slot(&mut changed, reference_number(row[1]), None)?.is_some() {
                    changed_parents.push([row[0], 0, 0, 0])?;
                }
            }
        }
        let mut changed_parents = changed_parents.finish()?;
        names.seek(SeekFrom::Start(0))?;
        directories.seek(SeekFrom::Start(0))?;
        let mut pending = inventory_next(&mut names)?;
        while let Some([reference, _, _, _]) = inventory_next(&mut directories)? {
            let number = reference & 0x0000ffffffffffff;
            if let Some(audit) = reduced.as_mut() {
                let mut needs_repair = audit.index_directory_needs_repair(number)?
                    || inventory_find(&mut changed_parents, reference)?.is_some();
                // A moved name can retain the same global count. Rebuild its
                // old index even when the reduced audit considers it balanced.
                if !needs_repair && changed.metadata()?.len() != 0 {
                    let logical = checked_family_image(&mut volume, &mft, number)?;
                    let directory = MftRecord::from_decoded(&logical)?;
                    volume.visit_directory(&directory, &mut scratch[..boot.index_block_bytes as usize], |entry| {
                        let number = reference_number(entry.file_reference);
                        if number < slots
                            && checker::consistency::audit_slot(&mut changed, number, None)
                                .map_err(|_| ntfs_rs::Error::Io)?
                                .is_some()
                        {
                            needs_repair = true;
                        }
                        Ok(())
                    })?;
                }
                if needs_repair {
                    // Rebuilding this parent can publish other moved keys whose
                    // old indexes still have balanced counts. Include those
                    // objects before choosing which source indexes to retain.
                    let position = names.stream_position()?;
                    let mut candidate = pending;
                    let mut expanded = false;
                    while let Some(row) = candidate.filter(|row| row[0] == reference) {
                        let number = reference_number(row[1]);
                        if number < slots && checker::consistency::audit_slot(&mut changed, number, None)?.is_none() {
                            checker::consistency::audit_slot(&mut changed, number, Some(Some(row[1])))?;
                            expanded = true;
                        }
                        candidate = inventory_next(&mut names)?;
                    }
                    names.seek(SeekFrom::Start(position))?;
                    if expanded {
                        // Retries only add bounded slot marks, so this closure
                        // converges without republishing an unchanged index.
                        continue 'retry;
                    }
                }
                if !needs_repair {
                    while pending.is_some_and(|row| row[0] == reference) {
                        pending = inventory_next(&mut names)?;
                    }
                    if pending.is_some_and(|row| row[0] < reference) {
                        return Err(reject("directory work order mismatch"));
                    }
                    continue;
                }
            }
            let mut expected = scratch_file()?;
            let mut count = 0_u64;
            let mut entry_bytes = 0_u64;
            let mut previous: Option<Vec<u8>> = None;
            while let Some(row) = pending.filter(|r| r[0] == reference) {
                let entry = value(&mut values.borrow_mut(), row)?;
                let text = &entry[82..82 + entry[80] as usize * 2];
                if previous
                    .as_ref()
                    .is_some_and(|p| ntfs_rs::index_tree::compare_names(&upcase, p, text) != std::cmp::Ordering::Less)
                {
                    return Err(reject("colliding directory names are ambiguous; no name discarded"));
                }
                previous = Some(text.to_vec());
                repair_entry_write(&mut expected, &entry)?;
                count += 1;
                entry_bytes += entry.len() as u64;
                pending = inventory_next(&mut names)?;
            }
            if pending.is_some_and(|r| r[0] < reference) {
                return Err(reject("directory work order mismatch"));
            }
            volume.read_mft_record(&mft, number, &mut raw)?;
            MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            let record = MftRecord::from_decoded(&raw)?;
            expected.seek(SeekFrom::Start(0))?;
            let mut scratch_error = None;
            let good = volume
                .audit_directory(&record, &mut scratch, false, |e| {
                    let wanted = match repair_entry_next(&mut expected) {
                        Ok(Some(entry)) => entry,
                        Ok(None) => return Err(ntfs_rs::Error::InvalidIndex),
                        Err(error) => {
                            scratch_error = Some(error);
                            return Err(ntfs_rs::Error::Io);
                        }
                    };
                    // Match authoritative namespace identity. Cached times,
                    // sizes and flags may differ without invalidating the key.
                    if e.file_reference != u64_at(&wanted, 0)?
                        || e.file_name_value[..8] != wanted[16..24]
                        || e.name.namespace != wanted[81]
                        || e.name.utf16le != &wanted[82..82 + wanted[80] as usize * 2]
                    {
                        return Err(ntfs_rs::Error::InvalidIndex);
                    }
                    Ok(())
                })
                .is_ok();
            if let Some(error) = scratch_error {
                return Err(error);
            }
            if good && repair_entry_next(&mut expected)?.is_none() {
                continue;
            }
            let mut members = repair_members(&mut volume, &mft, reference)?;
            let mut ids = BTreeMap::new();
            for (&member, (_, image)) in &mut members {
                let mut remove = Vec::new();
                for a in MftRecord::from_decoded(image)?.attributes() {
                    let a = a?;
                    if matches!(a.kind, ATTR_INDEX_ROOT | ATTR_INDEX_ALLOCATION | ATTR_BITMAP)
                        && a.name_utf16le()? == I30
                    {
                        ids.entry((member, a.kind)).or_insert(a.id);
                        remove.push(a.record_offset());
                    }
                }
                for at in remove.into_iter().rev() {
                    record_edit::remove(image, at)?;
                }
            }
            let (&mut_owner, _) = members
                .iter()
                .max_by_key(|(_, (_, image))| {
                    record_edit::capacity(image)
                        .unwrap_or(0)
                        .saturating_sub(record_edit::used(image).unwrap_or(usize::MAX))
                })
                .ok_or_else(|| reject("empty directory family"))?;
            let mut owner = mut_owner;
            let room = |image: &[u8]| -> io::Result<usize> {
                Ok(record_edit::capacity(image)?.saturating_sub(record_edit::used(image)?).saturating_sub(256))
            };
            if room(&members[&owner].1)? < 56 {
                let (new, image) = match repair_new_extension(
                    &mut volume,
                    &mft,
                    reference,
                    &mut record_cursor,
                    &mut extra,
                    u64::MAX,
                ) {
                    Ok(extension) => extension,
                    Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                        drop(volume);
                        for patch in extra.iter() {
                            patches.compose(patch?)?;
                        }
                        repair_mft_growth(source, boot, patches)?;
                        continue 'retry;
                    }
                    Err(error) => return Err(error),
                };
                members.insert(new, image);
                owner = new;
            }
            let mut raw = members[&owner].1.clone();
            let (value, mut pages, page_count) =
                rebuilt_index(boot, expected, count, entry_bytes, room(&raw)?, 0x30, 1)?;
            let root_id = ids.get(&(owner, ATTR_INDEX_ROOT)).copied();
            let allocation_id = ids.get(&(owner, ATTR_INDEX_ALLOCATION)).copied();
            let bitmap_id = ids.get(&(owner, ATTR_BITMAP)).copied();
            let mut attribute = vec![0; boot.record_bytes as usize];
            let n = record_edit::build_resident(ATTR_INDEX_ROOT, I30, &value, &mut attribute)?;
            let at = record_edit::insert(&mut raw, &attribute[..n])?;
            if let Some(id) = root_id {
                record_edit::p16(&mut raw, at + 14, id)?;
            }
            if page_count != 0 {
                let bytes = page_count
                    .checked_mul(u64::from(boot.index_block_bytes))
                    .ok_or_else(|| reject("index size overflow"))?;
                let clusters = bytes.div_ceil(u64::from(boot.cluster_bytes));
                let lcn =
                    repair_reserve(&mut volume, allocation_map, &mut owned, &mut reserved, clusters, &mut cursor)?;
                let allocated = clusters * u64::from(boot.cluster_bytes);
                let mut offset = 0;
                while offset < allocated {
                    let n = (allocated - offset).min(65536) as usize;
                    let mut after = vec![0; n];
                    let valid = bytes.saturating_sub(offset).min(n as u64) as usize;
                    pages.read_exact(&mut after[..valid])?;
                    let physical = lcn * u64::from(boot.cluster_bytes) + offset;
                    let mut before = vec![0; n];
                    volume.read_physical(physical, &mut before)?;
                    extra.push(Patch::new(physical, before, after))?;
                    offset += n as u64;
                }
                let n = record_edit::build_nonresident(
                    ATTR_INDEX_ALLOCATION,
                    I30,
                    &[ntfs_rs::runlist::Extent { vcn: 0, lcn: Some(lcn), len: clusters }],
                    allocated,
                    bytes,
                    bytes,
                    &mut attribute,
                )?;
                let at = record_edit::insert(&mut raw, &attribute[..n])?;
                if let Some(id) = allocation_id {
                    record_edit::p16(&mut raw, at + 14, id)?;
                }
                let size = page_count.div_ceil(8).div_ceil(8) * 8;
                let count = size.div_ceil(u64::from(boot.cluster_bytes));
                let lcn = repair_reserve(&mut volume, allocation_map, &mut owned, &mut reserved, count, &mut cursor)?;
                let allocated = count * u64::from(boot.cluster_bytes);
                let mut offset = 0;
                while offset < allocated {
                    let n = (allocated - offset).min(65536) as usize;
                    let mut after = vec![0; n];
                    for (i, b) in after.iter_mut().enumerate() {
                        let bits = page_count.saturating_sub((offset + i as u64) * 8).min(8);
                        *b = ((1u16 << bits) - 1) as u8;
                    }
                    let physical = lcn * u64::from(boot.cluster_bytes) + offset;
                    let mut before = vec![0; n];
                    volume.read_physical(physical, &mut before)?;
                    extra.push(Patch::new(physical, before, after))?;
                    offset += n as u64;
                }
                let n = record_edit::build_nonresident(
                    ATTR_BITMAP,
                    I30,
                    &[ntfs_rs::runlist::Extent { vcn: 0, lcn: Some(lcn), len: count }],
                    allocated,
                    size,
                    size,
                    &mut attribute,
                )?;
                let at = record_edit::insert(&mut raw, &attribute[..n])?;
                if let Some(id) = bitmap_id {
                    record_edit::p16(&mut raw, at + 14, id)?;
                }
            }
            members.get_mut(&owner).unwrap().1 = raw;
            for (member, (before, mut after)) in members {
                if member != reference
                    && member != owner
                    && MftRecord::from_decoded(&after)?.attributes().next().is_none()
                {
                    retire_empty_extension(&mut volume, &mft, member, &before, &mut after, &mut extra, false)?;
                }
                let mut original = before.clone();
                if MftRecord::parse(&mut original, boot.bytes_per_sector).is_ok() && original == after {
                    continue;
                }
                record_edit::validate(&after)?;
                protect_mft_record(&mut after, boot.bytes_per_sector)?;
                repair_record_patch(&mut volume, data, reference_number(member), &before, &after, &mut extra)?;
            }
        }
        if pending.is_some() {
            return Err(reject("directory work has no owning directory"));
        }
        drop(volume);
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        return Ok(());
    }
}

// Separate competing data owners by cloning surviving bytes. $BadClus runs
// participate in ownership too: readable data overlapping one is relocated,
// while the bad-cluster reservation stays allocated. Unreadable bytes abort
// the plan; neither zero filling nor choosing one owner's content is allowed.
const RUN_SPOOL_WORDS: usize = 3;
const RUN_SPOOL_BYTES: u64 = (RUN_SPOOL_WORDS * models::storage::WORD_BYTES) as u64;

struct RunSpool {
    file: std::sync::Mutex<File>,
    count: u64,
    last: Option<ntfs_rs::runlist::Extent>,
}
impl RunSpool {
    fn new() -> io::Result<Self> {
        Ok(Self { file: std::sync::Mutex::new(checker::consistency::scratch_file()?), count: 0, last: None })
    }
    fn len(&self) -> u64 {
        self.count
    }
    fn write_at(&mut self, number: u64, run: ntfs_rs::runlist::Extent) -> io::Result<()> {
        let at = number.checked_mul(RUN_SPOOL_BYTES).ok_or_else(|| reject("run spool offset overflow"))?;
        let file = self.file.get_mut().map_err(|_| io::Error::other("run spool poisoned"))?;
        models::storage::write_words(file, at, [run.vcn, run.len, run.lcn.unwrap_or(u64::MAX)])
    }
    fn push(&mut self, run: ntfs_rs::runlist::Extent) -> io::Result<()> {
        if let Some(mut last) = self.last {
            let contiguous = last.vcn.checked_add(last.len) == Some(run.vcn);
            let physical = match (last.lcn, run.lcn) {
                (None, None) => true,
                (Some(a), Some(b)) => a.checked_add(last.len) == Some(b),
                _ => false,
            };
            if contiguous && physical {
                last.len = last.len.checked_add(run.len).ok_or_else(|| reject("run length overflow"))?;
                self.write_at(self.count - 1, last)?;
                self.last = Some(last);
                return Ok(());
            }
        }
        self.write_at(self.count, run)?;
        self.count += 1;
        self.last = Some(run);
        Ok(())
    }
    fn get(&self, number: u64) -> io::Result<ntfs_rs::runlist::Extent> {
        if number >= self.count {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let at = number.checked_mul(RUN_SPOOL_BYTES).ok_or_else(|| reject("run spool offset overflow"))?;
        let mut file = self.file.lock().map_err(|_| io::Error::other("run spool poisoned"))?;
        let [vcn, len, lcn] = models::storage::read_words(&mut *file, at)?;
        Ok(ntfs_rs::runlist::Extent { vcn, len, lcn: if lcn == u64::MAX { None } else { Some(lcn) } })
    }
    fn mapped_clusters(&self) -> io::Result<u64> {
        let mut total = 0_u64;
        let mut file = self.file.lock().map_err(|_| io::Error::other("run spool poisoned"))?;
        file.seek(SeekFrom::Start(0))?;
        for _ in 0..self.count {
            let mut row = [0_u8; 24];
            file.read_exact(&mut row)?;
            if u64::from_le_bytes(row[16..24].try_into().unwrap()) != u64::MAX {
                let length = u64::from_le_bytes(row[8..16].try_into().unwrap());
                total = total.checked_add(length).ok_or_else(|| reject("run allocation overflow"))?;
            }
        }
        Ok(total)
    }
}

fn badclus_repairs(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    bad: &File,
    rescan: bool,
) -> io::Result<()> {
    use checker::consistency::inventory_next;
    use ntfs_rs::runlist::{DataRuns, Extent};
    let mut targets = bad.try_clone()?;
    targets.seek(SeekFrom::Start(0))?;
    let mut next = inventory_next(&mut targets)?.map(|row| row[0]);
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let family = RepairFamily::load(&mut volume, &mft, 8)?;
    let mut decoded = family.logical.clone();
    let record = MftRecord::from_decoded(&decoded)?;
    let attr =
        record.local_attribute(ATTR_DATA, b"$\0B\0a\0d\0")?.ok_or_else(|| reject("missing $BadClus:$Bad authority"))?;
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    if !attr.nonresident || attr.first_vcn()? != 0 {
        return Err(reject("unsupported $BadClus:$Bad geometry"));
    }
    let at = attr.record_offset();
    let mut replacement = RunSpool::new()?;
    let logical_bytes = clusters * u64::from(boot.cluster_bytes);
    let mut changed = attr.data_size()? != logical_bytes
        || attr.allocated_size()? != logical_bytes
        || attr.initialized_size()? > logical_bytes;
    let mut end = 0;
    for run in DataRuns::new(attr.data_runs()?, 0) {
        let mut run = run?;
        if run.vcn != end {
            return Err(reject("$BadClus mapping has a gap"));
        }
        if run.lcn.is_some_and(|lcn| lcn != run.vcn) {
            return Err(reject("$BadClus has a nonidentity physical mapping"));
        }
        end = run.vcn.checked_add(run.len).ok_or_else(|| reject("$BadClus mapping overflow"))?;
        if rescan && run.lcn.is_some() {
            run.lcn = None;
            changed = true;
        }
        let mut cursor = run.vcn;
        while let Some(cluster) = next.filter(|cluster| *cluster < end) {
            if cluster < cursor || cluster >= clusters {
                return Err(reject("invalid rescue bad-cluster order"));
            }
            if cluster > cursor {
                replacement.push(Extent {
                    vcn: cursor,
                    len: cluster - cursor,
                    lcn: run.lcn.map(|lcn| lcn + cursor - run.vcn),
                })?;
            }
            if run.lcn.is_some_and(|lcn| lcn + cluster - run.vcn != cluster) {
                return Err(reject("$BadClus maps a different physical cluster"));
            }
            if run.lcn.is_none() {
                changed = true;
            }
            replacement.push(Extent { vcn: cluster, len: 1, lcn: Some(cluster) })?;
            cursor = cluster + 1;
            next = inventory_next(&mut targets)?.map(|row| row[0]);
            while next == Some(cluster) {
                next = inventory_next(&mut targets)?.map(|row| row[0]);
            }
        }
        if cursor < end {
            replacement.push(Extent {
                vcn: cursor,
                len: end - cursor,
                lcn: run.lcn.map(|lcn| lcn + cursor - run.vcn),
            })?;
        }
    }
    if end != clusters || next.is_some() {
        return Err(reject("$BadClus does not span the volume"));
    }
    let physical_bytes = replacement
        .mapped_clusters()?
        .checked_mul(u64::from(boot.cluster_bytes))
        .ok_or_else(|| reject("$BadClus allocation overflow"))?;
    let flags = attr.flags()?;
    let header_bytes = ntfs_rs::bytes::u16_at(&decoded, at + 32)? as usize;
    if flags & 0x8001 != 0 && header_bytes >= 72 {
        changed |= u64_at(&decoded, at + 64)? != physical_bytes;
    }
    if !changed {
        return Ok(());
    }
    ntfs_rs::record_edit::p64(&mut decoded, at + 40, logical_bytes)?;
    ntfs_rs::record_edit::p64(&mut decoded, at + 48, logical_bytes)?;
    if u64_at(&decoded, at + 56)? > logical_bytes {
        ntfs_rs::record_edit::p64(&mut decoded, at + 56, 0)?;
    }
    if flags & 0x8001 != 0 && header_bytes >= 72 {
        ntfs_rs::record_edit::p64(&mut decoded, at + 64, physical_bytes)?;
    }
    let changes = relocation::mapping_descriptors(
        &decoded[at..at + ntfs_rs::record_edit::attr_len(&decoded, at)?],
        replacement.len() as usize,
        |i| replacement.get(i as u64),
        (boot.record_bytes as usize).saturating_sub(384),
        relocation::DESCRIPTOR_CAPACITY,
    )?;
    let mut extra = RepairPlan::new(patches.length)?;
    let mut space = RepairSpace::new(&mut volume, &mft)?;
    space.protect_extents(&replacement)?;
    let result = family.store(&mut volume, &mft, changes, &mut space, &mut extra);
    drop(volume);
    if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
        repair_mft_growth(source, boot, patches)?;
        return badclus_repairs(source, boot, patches, bad, rescan);
    }
    result?;
    for patch in extra.iter() {
        patches.compose(patch?)?;
    }
    Ok(())
}

fn crosslink_repairs(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    unresolved: Option<&File>,
) -> io::Result<()> {
    while crosslink_repair_one(source, boot, patches, unresolved)? {}
    Ok(())
}
fn crosslink_repair_one(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    unresolved: Option<&File>,
) -> io::Result<bool> {
    use checker::consistency::{inventory_next, DiskInventory};
    use ntfs_rs::runlist::DataRuns;
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let data = mft.stream(ATTR_DATA, &[])?;
    let slots = data.initialized_size()? / u64::from(boot.record_bytes);
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let mut bits = (u64::MAX, [0; 8192]);
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut runs = DiskInventory::new();
    for number in 0..slots {
        if !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
            continue;
        }
        volume.read_mft_record(&mft, number, &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        for attr in record.attributes() {
            let attr = attr?;
            if !attr.nonresident {
                continue;
            }
            let owner = if record.base_file_reference()? == 0 {
                number
            } else {
                reference_number(record.base_file_reference()?)
            };
            let eligible = !matches!(owner, 0 | 1 | 2 | 6 | 7 | 8) && attr.flags()? & !0xc001 == 0;
            for run in DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
                let run = run?;
                if let Some(lcn) = run.lcn {
                    let end = lcn
                        .checked_add(run.len)
                        .filter(|end| *end <= clusters)
                        .ok_or_else(|| reject("out-of-volume ownership cannot be repaired by cloning"))?;
                    runs.push([lcn, end, number, u64::from(attr.id) | (u64::from(eligible) << 16)])?;
                }
            }
        }
    }
    let mut runs = std::io::BufReader::new(runs.finish()?);
    let mut affected = DiskInventory::new();
    let mut active = [0; 4];
    while let Some(run) = inventory_next(&mut runs)? {
        if run[0] < active[1] {
            if run[3] >> 16 != 0 {
                affected.push([run[2], u64::from(run[3] as u16), 0, 0])?;
            } else if active[3] >> 16 != 0 {
                affected.push([active[2], u64::from(active[3] as u16), 0, 0])?;
            } else {
                let mut rebuild_bitmap = false;
                let mut relocate_log = None;
                for claim in [active, run] {
                    volume.read_mft_record(&mft, claim[2], &mut raw)?;
                    let owner = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
                    let base = owner.base_file_reference()?;
                    let number = if base == 0 { claim[2] } else { reference_number(base) };
                    if !matches!(number, 2 | 6) {
                        continue;
                    }
                    for a in owner.attributes() {
                        let a = a?;
                        if a.id == claim[3] as u16 && a.kind == ATTR_DATA && a.name_utf16le()?.is_empty() {
                            if number == 6 {
                                rebuild_bitmap = true;
                            } else {
                                relocate_log = Some((claim[2], a.id));
                            }
                        }
                    }
                }
                if rebuild_bitmap {
                    drop(volume);
                    reserved::bitmap(source, boot, patches)?;
                    return Ok(true);
                }
                if let Some((number, id)) = relocate_log {
                    if reserved::inactive_log(&mut volume, &mft)? {
                        drop(volume);
                        relocation::relocate(source, boot, patches, number, id, None)?;
                        return Ok(true);
                    }
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("reserved system-file cross-link at LCNs {}..{}: record {} attribute {} and record {} attribute {} claim the same bytes; independent content evidence is absent and source bytes are preserved",
                    run[0], run[1].min(active[1]), active[2], active[3] as u16,
                    run[2], run[3] as u16)));
            }
        }
        if run[1] > active[1] {
            active = run;
        }
    }
    let mut affected = std::io::BufReader::new(affected.finish()?);
    let Some(row) = inventory_next(&mut affected)? else {
        return Ok(false);
    };
    drop(volume);
    relocation::relocate(source, boot, patches, row[0], row[1] as u16, unresolved)?;
    Ok(true)
}
// $SDS duplicates descriptors in alternating 256-KiB blocks. Only a complete
// hash-valid descriptor is authority; final $SII/$SDH auditing must agree with
// its identity/header before a restored counterpart can be published.
fn security_repairs(source: &Path, boot: ntfs_rs::boot::BootSector, patches: &mut RepairPlan) -> io::Result<()> {
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let raw = checked_family_image(&mut volume, &mft, 9)?;
    let secure = MftRecord::from_decoded(&raw)?;
    let sds = secure.local_attribute(ATTR_DATA, b"$\0S\0D\0S\0")?.ok_or_else(|| reject("missing $SDS authority"))?;
    let size = sds.data_size()?;
    let mut extra = RepairPlan::new(patches.length)?;
    let mut headers = checker::consistency::scratch_file()?;
    let mut by_id = checker::consistency::DiskInventory::new();
    let mut by_hash = checker::consistency::DiskInventory::new();
    let mut descriptor_count = 0_u64;
    for block in (0..size).step_by(0x80000) {
        let mut at = 0_u64;
        while at + 20 <= 0x40000 && block + 0x40000 + at + 20 <= size {
            let offset = block + at;
            let mut heads = [[0; 20]; 2];
            for (i, head) in heads.iter_mut().enumerate() {
                volume.read_attribute(sds, offset + i as u64 * 0x40000, head)?;
            }
            if heads.iter().all(|h| h.iter().all(|b| *b == 0)) {
                break;
            }
            let mut copies = [None, None];
            for i in 0..2 {
                let n = u32_at(&heads[i], 16)? as usize;
                if !(40..=0x20014).contains(&n) || at + n as u64 > 0x40000 || offset + 0x40000 + n as u64 > size {
                    continue;
                }
                let mut bytes = vec![0; n];
                volume.read_attribute(sds, offset + i as u64 * 0x40000, &mut bytes)?;
                if ntfs_rs::security::SdsEntry::parse(&bytes, offset).is_ok_and(|e| e.security_id >= 256) {
                    copies[i] = Some(bytes);
                }
            }
            let (bytes, damaged) = match (&copies[0], &copies[1]) {
                (Some(a), Some(b)) if a == b => (a, None),
                (Some(_), Some(_)) => {
                    return Err(reject("valid security descriptor copies disagree; permissions not guessed"))
                }
                (Some(a), None) => (a, Some(1)),
                (None, Some(b)) => (b, Some(0)),
                _ => return Err(reject("neither security descriptor copy validates; original permissions preserved")),
            };
            let entry = ntfs_rs::security::SdsEntry::parse(bytes, offset)?;
            let header_at = headers.seek(SeekFrom::End(0))?;
            headers.write_all(&bytes[..20])?;
            by_id.push([u64::from(entry.security_id), u64::from(entry.hash), header_at, 0])?;
            by_hash.push([u64::from(entry.hash), u64::from(entry.security_id), header_at, 0])?;
            descriptor_count += 1;
            if let Some(i) = damaged {
                let logical = offset + i * 0x40000;
                let mut before = vec![0; bytes.len()];
                volume.read_attribute(sds, logical, &mut before)?;
                stage_change(sds, boot, logical, bytes.len() as u64, &before, &bytes, &mut extra)?;
            }
            at += (bytes.len() as u64 + 15) & !15;
        }
    }
    drop(volume);
    for patch in extra.iter() {
        patches.compose(patch?)?;
    }
    // $SDS is the independent authority. A missing or damaged index can be
    // reconstructed from every validated descriptor header without changing
    // any descriptor or guessing among conflicting copies.
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let raw = checked_family_image(&mut volume, &mft, 9)?;
    let secure = MftRecord::from_decoded(&raw)?;
    let mut rebuild = [false; 2];
    let mut walk = vec![0; boot.index_block_bytes as usize];
    let mut descriptor = vec![0; ntfs_rs::security::MAX_STORED_DESCRIPTOR + 20];
    for (index, name) in [b"$\0S\0I\0I\0".as_slice(), b"$\0S\0D\0H\0".as_slice()].into_iter().enumerate() {
        rebuild[index] = if secure.local_attribute(0x90, name)?.is_none() {
            true
        } else {
            match ntfs_rs::security_store::validate_index_against_sds(
                &mut volume,
                &secure,
                index == 1,
                &mut walk,
                &mut descriptor,
            ) {
                Ok(count) => count != descriptor_count,
                Err(ntfs_rs::Error::Io | ntfs_rs::Error::Overflow) => {
                    return Err(reject("cannot read or size $Secure index safely"))
                }
                Err(_) => true,
            }
        };
    }
    if !rebuild[0] && !rebuild[1] {
        return Ok(());
    }
    if descriptor_count == 0 {
        return Err(reject("$Secure indexes have no authoritative descriptors"));
    }
    for (index, inventory) in [by_id, by_hash].into_iter().enumerate() {
        if !rebuild[index] {
            continue;
        }
        let name: &[u8] = if index == 0 { b"$\0S\0I\0I\0" } else { b"$\0S\0D\0H\0" };
        let mut rows = std::io::BufReader::new(inventory.finish()?);
        let mut entries = Vec::new();
        let mut previous = None;
        while let Some([primary, secondary, offset, _]) = checker::consistency::inventory_next(&mut rows)? {
            if previous == Some((primary, secondary)) {
                return Err(reject("duplicate $SDS index key"));
            }
            previous = Some((primary, secondary));
            let mut header = [0_u8; 20];
            headers.seek(SeekFrom::Start(offset))?;
            headers.read_exact(&mut header)?;
            let mut item = [0_u8; 48];
            item[0..2].copy_from_slice(&24_u16.to_le_bytes());
            item[2..4].copy_from_slice(&20_u16.to_le_bytes());
            item[8..10].copy_from_slice(&48_u16.to_le_bytes());
            item[10..12].copy_from_slice(&(if index == 0 { 4_u16 } else { 8_u16 }).to_le_bytes());
            item[16..20].copy_from_slice(&(primary as u32).to_le_bytes());
            if index == 1 {
                item[20..24].copy_from_slice(&(secondary as u32).to_le_bytes());
            }
            item[24..44].copy_from_slice(&header);
            entries.push(item.to_vec());
        }
        let family = RepairFamily::load(&mut volume, &mft, 9)?;
        let mut space = RepairSpace::new(&mut volume, &mft)?;
        let mut updates = RepairPlan::new(patches.length)?;
        let result = family::install_view(
            &mut volume,
            &mft,
            family,
            name,
            if index == 0 { 16 } else { 18 },
            &entries,
            &mut space,
            &mut updates,
        );
        drop(volume);
        if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
            repair_mft_growth(source, boot, patches)?;
            return security_repairs(source, boot, patches);
        }
        result?;
        for patch in updates.iter() {
            patches.compose(patch?)?;
        }
        // Reload after publication so a second index uses the updated family
        // and cannot reserve the same MFT extension as the first index.
        return security_repairs(source, boot, patches);
    }
    Ok(())
}

fn view_node_slots(value: &[u8], head: usize) -> io::Result<Vec<(Option<Vec<u8>>, Option<u64>)>> {
    use ntfs_rs::bytes::u16_at;
    if head + 16 > value.len() {
        return Err(reject("truncated view index node"));
    }
    let first = u32_at(value, head)? as usize;
    let used = u32_at(value, head + 4)? as usize;
    let allocated = u32_at(value, head + 8)? as usize;
    let children = value[head + 12];
    if !matches!(children, 0 | 1)
        || first < 16
        || used < first + 16
        || allocated < used
        || head.checked_add(allocated).is_none_or(|n| n > value.len())
    {
        return Err(reject("invalid view index node bounds"));
    }
    let mut at = head + first;
    let end = head + used;
    let mut slots = Vec::new();
    while at < end {
        if at + 16 > end {
            return Err(reject("truncated view index slot"));
        }
        let size = u16_at(value, at + 8)? as usize;
        let flags = u16_at(value, at + 12)?;
        let key = u16_at(value, at + 10)? as usize;
        if size < 16
            || size % 8 != 0
            || at + size > end
            || flags & !3 != 0
            || usize::from(flags & 1) != usize::from(children)
        {
            return Err(reject("damaged view index slot"));
        }
        let child = if flags & 1 != 0 {
            if size < 24 {
                return Err(reject("short view index child pointer"));
            }
            Some(u64_at(value, at + size - 8)?)
        } else {
            None
        };
        if flags & 2 != 0 {
            if key != 0 || size != if child.is_some() { 24 } else { 16 } || at + size != end {
                return Err(reject("damaged view index terminator"));
            }
            slots.push((None, child));
            return Ok(slots);
        }
        let data = u16_at(value, at)? as usize;
        let data_size = u16_at(value, at + 2)? as usize;
        let available = size - if child.is_some() { 8 } else { 0 };
        if key == 0
            || 16 + key > available
            || (data_size == 0 && data != 0 && data < 16 + key)
            || (data_size != 0 && (data < 16 + key || data.checked_add(data_size).is_none_or(|n| n > available)))
        {
            return Err(reject("view index key/data bounds are damaged"));
        }
        slots.push((Some(value[at..at + size].to_vec()), child));
        at += size;
    }
    Err(reject("view index has no terminal slot"))
}

fn visit_view_index<R: ReadAt>(
    volume: &mut Volume<R>,
    root: &[u8],
    allocation: Option<Attribute<'_>>,
    bitmap: Option<Attribute<'_>>,
    kind: u32,
    collation: u32,
    visitor: &mut impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    if root.len() < 48
        || u32_at(root, 0)? != kind
        || u32_at(root, 4)? != collation
        || u32_at(root, 8)? != volume.boot.index_block_bytes
    {
        return Err(reject("view index root geometry or identity is invalid"));
    }
    let block_bytes = u64::from(volume.boot.index_block_bytes);
    let unit = if volume.boot.index_block_bytes < volume.boot.cluster_bytes {
        512_u64
    } else {
        u64::from(volume.boot.cluster_bytes)
    };
    if block_bytes % unit != 0 || u64::from(root[12]) != block_bytes / unit {
        return Err(reject("view index VCN unit is inconsistent"));
    }
    let root_slots = view_node_slots(root, 16)?;
    let has_children = root[28] == 1;
    if !has_children {
        if allocation.is_some() || bitmap.is_some() {
            return Err(reject("leaf view index has unexplained allocation"));
        }
        for (row, _) in root_slots {
            if let Some(row) = row {
                visitor(&row)?;
            }
        }
        return Ok(());
    }
    let allocation = allocation.ok_or_else(|| reject("view index allocation is missing"))?;
    let bitmap = bitmap.ok_or_else(|| reject("view index bitmap is missing"))?;
    let allocated = allocation.data_size()?;
    if allocated % block_bytes != 0 {
        return Err(reject("view index allocation has a partial page"));
    }
    let max_blocks = allocated / block_bytes;
    let mut visited = BTreeSet::new();
    fn descend<R: ReadAt>(
        volume: &mut Volume<R>,
        allocation: Attribute<'_>,
        bitmap: Attribute<'_>,
        vcn: u64,
        depth: usize,
        unit: u64,
        max_blocks: u64,
        visited: &mut BTreeSet<u64>,
        visitor: &mut impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if depth >= 64 {
            return Err(reject("view index exceeds supported depth"));
        }
        let vcn_per_block = u64::from(volume.boot.index_block_bytes) / unit;
        if vcn % vcn_per_block != 0 || vcn / vcn_per_block >= max_blocks || !visited.insert(vcn) {
            return Err(reject("view index child is repeated or out of bounds"));
        }
        let bit = vcn / vcn_per_block;
        let mut mark = [0_u8; 1];
        volume.read_attribute(bitmap, bit / 8, &mut mark)?;
        if mark[0] & (1 << (bit % 8)) == 0 {
            return Err(reject("view index child has no allocation bit"));
        }
        let mut page = vec![0; volume.boot.index_block_bytes as usize];
        volume.read_nonresident(allocation, vcn * unit, &mut page)?;
        ntfs_rs::index::IndexBlock::parse(&mut page, volume.boot.bytes_per_sector, vcn)?;
        let slots = view_node_slots(&page, 24)?;
        for (row, child) in slots {
            if let Some(child) = child {
                descend(volume, allocation, bitmap, child, depth + 1, unit, max_blocks, visited, visitor)?;
            }
            if let Some(row) = row {
                visitor(&row)?;
            }
        }
        Ok(())
    }
    for (row, child) in root_slots {
        if let Some(child) = child {
            descend(volume, allocation, bitmap, child, 1, unit, max_blocks, &mut visited, visitor)?;
        }
        if let Some(row) = row {
            visitor(&row)?;
        }
    }
    volume.validate_index_bitmap(bitmap, max_blocks, visited.len() as u64)?;
    Ok(())
}

fn extend_metadata_file<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    wanted: &str,
) -> io::Result<Option<u64>> {
    let mut extend_raw = vec![0; volume.boot.record_bytes as usize];
    volume.read_mft_record(mft, 11, &mut extend_raw)?;
    let extend = MftRecord::parse(&mut extend_raw, volume.boot.bytes_per_sector)?;
    let parent = 11 | (u64::from(extend.sequence_number()?) << 48);
    let name: Vec<u8> = wanted.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let data = mft.stream(ATTR_DATA, &[])?;
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let slots = data.initialized_size()? / u64::from(volume.boot.record_bytes);
    let mut bits = (u64::MAX, [0; 8192]);
    let mut raw = vec![0; volume.boot.record_bytes as usize];
    let mut result = None;
    for number in 16..slots {
        if !bitmap_bit(volume, bitmap, number, slots, &mut bits)? {
            continue;
        }
        volume.read_mft_record(mft, number, &mut raw)?;
        let record = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
        if record.base_file_reference()? != 0 {
            continue;
        }
        let logical;
        let record = if record.attributes().any(|a| a.is_ok_and(|a| a.kind == ATTR_ATTRIBUTE_LIST)) {
            logical = RepairFamily::load(volume, mft, number)?.logical;
            MftRecord::from_decoded(&logical)?
        } else {
            record
        };
        for attr in record.attributes() {
            let attr = attr?;
            if attr.kind != ntfs_rs::mft::ATTR_FILE_NAME || attr.nonresident {
                continue;
            }
            let value = attr.resident_value()?;
            if value.len() < 66
                || u64_at(value, 0)? != parent
                || value[64] as usize * 2 != name.len()
                || &value[66..] != name
            {
                continue;
            }
            if result.replace(number).is_some_and(|old| old != number) {
                return Err(reject("duplicate $Extend system-file identity"));
            }
        }
    }
    Ok(result)
}

pub(crate) use metadata::{filename_directory_type, filename_value_error, root_filename_valid};
#[cfg(test)]
use semantic::object_id_repairs;
use semantic::quota_repairs;

// Compare cached values for informational freshness reporting only. Differences
// do not establish structural damage; last-access timestamps are lazy too.
pub(crate) fn duplicated_name_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == 56
        && b.len() == 56
        && a[..24] == b[..24]
        && a[32..54] == b[32..54]
        && (u32_at(a, 48).unwrap_or(0) & 0x400 == 0 || a[52..56] == b[52..56])
}

/// Resolve the live duplicated metadata through the validated base family.
/// Cached FILE_NAME values are unsuitable because data and timestamp changes
/// can legitimately leave them stale until the next namespace operation.
pub(crate) fn filename_index_information<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    number: u64,
    upcase: Option<&[u8]>,
) -> io::Result<([u8; 56], Option<Vec<Vec<u8>>>)> {
    let family = RepairFamily::load(volume, mft, number)?;
    let record = MftRecord::from_decoded(&family.logical)?;
    if record.local_attribute(0x10, &[])?.is_none() {
        return Err(reject("file has no standard information for index metadata"));
    }
    let projected = if number >= 16 && record.flags()? & 2 == 0 {
        metadata::filename_alias_projection(&record, upcase)?
    } else {
        None
    };
    Ok((ntfs_rs::filename_metadata::duplicated_information(volume, &record)?, projected))
}

pub(crate) fn audit_system_metadata_with_index_check<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    mode: checker::consistency::IndexCheck,
    upcase: Option<&[u8]>,
    emit: &mut impl FnMut(&'static str, Option<u64>, String, bool),
) -> io::Result<()> {
    // Physical reference counts and alias normalization can be informational.
    // Index keys are still checked against the effective family identities.
    metadata::audit(volume, mft, mode, upcase, &mut |code, number, detail| {
        let is_error = !matches!(code, "hardlink-count-invalid" | "filename-alias-invalid");
        emit(code, number, detail, is_error)
    })
}

fn usn_damaged<R: ReadAt>(volume: &mut Volume<R>, j: Attribute<'_>, config: &[u8; 32]) -> io::Result<bool> {
    use ntfs_rs::runlist::DataRuns;
    let end = j.data_size()?;
    let low = u64_at(config, 24)?;
    let id = u64_at(config, 16)?;
    let mut damaged = id == 0 || low > end || low % 8 != 0;
    if !damaged && low < end {
        let mut expected = low;
        let mut spanning_until = 0_u64;
        let cluster = u64::from(volume.boot.cluster_bytes);
        for run in DataRuns::new(j.data_runs()?, j.first_vcn()?) {
            let run = run?;
            let start = run.vcn.checked_mul(cluster).ok_or_else(|| reject("USN run offset overflow"))?;
            let run_end = run
                .vcn
                .checked_add(run.len)
                .and_then(|vcn| vcn.checked_mul(cluster))
                .ok_or_else(|| reject("USN run end overflow"))?
                .min(end);
            if run_end <= low {
                continue;
            }
            if run.lcn.is_none() {
                if expected < run_end || (spanning_until > start && start < run_end) {
                    damaged = true;
                    break;
                }
                continue;
            }
            if expected < start {
                damaged = true;
                break;
            }
            if spanning_until != 0 && run_end >= spanning_until {
                spanning_until = 0;
            }
            while expected < run_end {
                if expected + 4 > end {
                    damaged = true;
                    break;
                }
                let mut word = [0_u8; 4];
                volume.read_attribute(j, expected, &mut word)?;
                let length = u32::from_le_bytes(word) as u64;
                if length == 0 {
                    let next = (expected / cluster + 1) * cluster;
                    let mut zeros = vec![0; (next.min(run_end) - expected) as usize];
                    volume.read_attribute(j, expected, &mut zeros)?;
                    if zeros.iter().any(|byte| *byte != 0) {
                        damaged = true;
                        break;
                    }
                    expected = next.min(run_end);
                    continue;
                }
                let mut common = [0_u8; 8];
                volume.read_attribute(j, expected, &mut common)?;
                let major = ntfs_rs::bytes::u16_at(&common, 4)?;
                let minimum = match major {
                    2 => 60_u64,
                    3 => 76,
                    4 => 64,
                    _ => return Err(reject("USN record version is not supported; history preserved")),
                };
                if length < minimum
                    || length % 8 != 0
                    || expected.checked_add(length).is_none_or(|n| n > end)
                    || ntfs_rs::bytes::u16_at(&common, 6)? != 0
                {
                    damaged = true;
                    break;
                }
                let mut head = vec![0; minimum as usize];
                volume.read_attribute(j, expected, &mut head)?;
                let usn_at = if major == 2 { 0x18 } else { 0x28 };
                if u64_at(&head, usn_at)? != expected {
                    damaged = true;
                    break;
                }
                if major == 4 {
                    let count = u64::from(ntfs_rs::bytes::u16_at(&head, 0x3c)?);
                    let width = u64::from(ntfs_rs::bytes::u16_at(&head, 0x3e)?);
                    if count == 0
                        || width != 16
                        || count.checked_mul(width).and_then(|n| n.checked_add(64)).is_none_or(|n| n > length)
                    {
                        damaged = true;
                        break;
                    }
                    for i in 0..count {
                        let mut extent = [0_u8; 16];
                        volume.read_attribute(j, expected + 64 + i * width, &mut extent)?;
                        let offset = i64::from_le_bytes(extent[..8].try_into().unwrap());
                        let span = i64::from_le_bytes(extent[8..].try_into().unwrap());
                        if offset < 0 || span <= 0 || offset.checked_add(span).is_none() {
                            damaged = true;
                            break;
                        }
                    }
                    if damaged {
                        break;
                    }
                } else {
                    let (length_at, offset_at) = if major == 2 { (0x38, 0x3a) } else { (0x48, 0x4a) };
                    let name_len = u64::from(ntfs_rs::bytes::u16_at(&head, length_at)?);
                    let name_at = u64::from(ntfs_rs::bytes::u16_at(&head, offset_at)?);
                    if name_len % 2 != 0
                        || name_at < minimum
                        || name_at.checked_add(name_len).is_none_or(|n| n > length)
                    {
                        damaged = true;
                        break;
                    }
                    let mut name = vec![0; name_len as usize];
                    volume.read_attribute(j, expected + name_at, &mut name)?;
                }
                expected += length;
                if expected > run_end {
                    spanning_until = expected;
                }
            }
            if damaged {
                break;
            }
        }
        if expected != end {
            damaged = true;
        }
    }
    Ok(damaged)
}

// A damaged change journal has no authoritative replacement history. Keep
// $J's bytes intact and advance $Max to a new journal generation only after
// checking every supported record in the currently valid allocated suffix.
fn usn_repairs(source: &Path, boot: ntfs_rs::boot::BootSector, patches: &mut RepairPlan) -> io::Result<()> {
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let Some(number) = extend_metadata_file(&mut volume, &mft, "$UsnJrnl")? else {
        return Ok(());
    };
    let family = RepairFamily::load(&mut volume, &mft, number)?;
    let record = MftRecord::from_decoded(&family.logical)?;
    let max = record
        .local_attribute(ATTR_DATA, b"$\0M\0a\0x\0")?
        .ok_or_else(|| reject("USN journal has no $Max authority"))?;
    let j = record.local_attribute(ATTR_DATA, b"$\0J\0")?.ok_or_else(|| reject("USN journal has no $J stream"))?;
    if max.data_size()? != 32 || !j.nonresident || j.flags()? & !0x8000 != 0 {
        return Err(reject("unsupported USN journal metadata layout"));
    }
    let mut config = [0; 32];
    volume.read_attribute(max, 0, &mut config)?;
    let end = j.data_size()?;
    let id = u64_at(&config, 16)?;
    let damaged = usn_damaged(&mut volume, j, &config)?;
    if !damaged {
        return Ok(());
    }
    let mut value = config.to_vec();
    value[16..24].copy_from_slice(&id.wrapping_add(1).max(1).to_le_bytes());
    value[24..32].copy_from_slice(&end.to_le_bytes());
    let mut extra = RepairPlan::new(patches.length)?;
    let mut space = RepairSpace::new(&mut volume, &mft)?;
    let result = family.store(
        &mut volume,
        &mft,
        vec![StreamChange::resident(ATTR_DATA, b"$\0M\0a\0x\0", &value)?],
        &mut space,
        &mut extra,
    );
    drop(volume);
    if result.as_ref().is_err_and(|e| e.kind() == io::ErrorKind::OutOfMemory) {
        repair_mft_growth(source, boot, patches)?;
        return usn_repairs(source, boot, patches);
    }
    result?;
    for patch in extra.iter() {
        patches.compose(patch?)?;
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct FamilyKey {
    pub(crate) kind: u32,
    pub(crate) name: Vec<u8>,
    pub(crate) vcn: u64,
    pub(crate) reference: u64,
    pub(crate) id: u16,
}

pub(crate) fn family_key_order(a: &FamilyKey, b: &FamilyKey) -> std::cmp::Ordering {
    a.kind
        .cmp(&b.kind)
        .then_with(|| ntfs_rs::bytes::units(&a.name).cmp(ntfs_rs::bytes::units(&b.name)))
        .then_with(|| a.vcn.cmp(&b.vcn))
        .then_with(|| a.reference.cmp(&b.reference))
        .then_with(|| a.id.cmp(&b.id))
}

fn read_family_key(spool: &std::sync::Mutex<File>, row: &[u64; 4]) -> io::Result<FamilyKey> {
    let n = row[2] as usize;
    if !(20..=532).contains(&n) {
        return Err(reject("invalid family key length"));
    }
    let mut bytes = vec![0; n];
    let mut file = spool.lock().map_err(|_| reject("family key spool poisoned"))?;
    file.seek(SeekFrom::Start(row[1]))?;
    file.read_exact(&mut bytes)?;
    let name_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    if name_len % 2 != 0 || name_len + 20 != n {
        return Err(reject("invalid family key name"));
    }
    let tail = 2 + name_len;
    Ok(FamilyKey {
        kind: u32::try_from(row[0]).map_err(|_| reject("invalid family kind"))?,
        name: bytes[2..tail].to_vec(),
        vcn: u64::from_le_bytes(bytes[tail..tail + 8].try_into().unwrap()),
        reference: u64::from_le_bytes(bytes[tail + 8..tail + 16].try_into().unwrap()),
        id: u16::from_le_bytes(bytes[tail + 16..tail + 18].try_into().unwrap()),
    })
}

pub(crate) struct FamilyKeys {
    rows: File,
    spool: std::sync::Arc<std::sync::Mutex<File>>,
    previous: Option<FamilyKey>,
}
impl FamilyKeys {
    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        self.rows.seek(SeekFrom::Start(0))?;
        self.previous = None;
        Ok(())
    }
    pub(crate) fn next(&mut self) -> io::Result<Option<FamilyKey>> {
        checker::consistency::inventory_next(&mut self.rows)?.map(|row| read_family_key(&self.spool, &row)).transpose()
    }
    pub(crate) fn next_unique(&mut self) -> io::Result<Option<FamilyKey>> {
        while let Some(key) = self.next()? {
            if self.previous.as_ref() == Some(&key) {
                continue;
            }
            self.previous = Some(key.clone());
            return Ok(Some(key));
        }
        Ok(None)
    }
    pub(crate) fn contains(&mut self, key: &FamilyKey) -> io::Result<bool> {
        let saved = self.rows.stream_position()?;
        let (mut low, mut high) = (0, self.rows.metadata()?.len() / 32);
        while low < high {
            let mid = low + (high - low) / 2;
            self.rows.seek(SeekFrom::Start(mid * 32))?;
            let row = checker::consistency::inventory_next(&mut self.rows)?
                .ok_or_else(|| reject("short family key inventory"))?;
            match family_key_order(&read_family_key(&self.spool, &row)?, key) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Equal => {
                    self.rows.seek(SeekFrom::Start(saved))?;
                    return Ok(true);
                }
                std::cmp::Ordering::Greater => high = mid,
            }
        }
        self.rows.seek(SeekFrom::Start(saved))?;
        Ok(false)
    }
}

pub(crate) struct FamilyKeysBuilder {
    rows: checker::consistency::DiskInventory,
    spool: std::sync::Arc<std::sync::Mutex<File>>,
}
impl FamilyKeysBuilder {
    pub(crate) fn new() -> io::Result<Self> {
        let spool = std::sync::Arc::new(std::sync::Mutex::new(checker::consistency::scratch_file()?));
        let lookup = spool.clone();
        let rows = checker::consistency::DiskInventory::ordered(move |a, b| {
            if a[0] != b[0] {
                return Ok(a[0].cmp(&b[0]));
            }
            Ok(family_key_order(&read_family_key(&lookup, a)?, &read_family_key(&lookup, b)?))
        });
        Ok(Self { rows, spool })
    }
    pub(crate) fn push(&mut self, key: FamilyKey) -> io::Result<()> {
        if key.name.len() > 510 || key.name.len() % 2 != 0 {
            return Err(reject("invalid family key name"));
        }
        let mut file = self.spool.lock().map_err(|_| reject("family key spool poisoned"))?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&(key.name.len() as u16).to_le_bytes())?;
        file.write_all(&key.name)?;
        file.write_all(&key.vcn.to_le_bytes())?;
        file.write_all(&key.reference.to_le_bytes())?;
        file.write_all(&key.id.to_le_bytes())?;
        drop(file);
        self.rows.push([u64::from(key.kind), offset, (key.name.len() + 20) as u64, 0])
    }
    pub(crate) fn finish(self) -> io::Result<FamilyKeys> {
        Ok(FamilyKeys { rows: self.rows.finish()?, spool: self.spool, previous: None })
    }
}

// Retire only an authenticated empty extension. Its caller still publishes the
// protected record against the original preimage through the existing plan.
fn retire_empty_extension<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    reference: u64,
    before: &[u8],
    after: &mut [u8],
    extra: &mut RepairPlan,
    preserve_identity: bool,
) -> io::Result<()> {
    let record = MftRecord::from_decoded(after)?;
    if record.flags()? & 1 == 0
        || u64::from(record.sequence_number()?) != reference >> 48
        || record.attributes().next().is_some()
    {
        return Err(reject("extension retirement requires an intact empty current record"));
    }
    repair_record_bit(volume, mft, ntfs_rs::mft::reference_number(reference), false, extra)?;
    if !preserve_identity {
        ntfs_rs::record_edit::p16(after, 16, ntfs_rs::mft::next_sequence(before)?)?;
        ntfs_rs::record_edit::p64(after, 32, 0)?;
    }
    let flags = ntfs_rs::bytes::u16_at(after, 22)?;
    ntfs_rs::record_edit::p16(after, 22, flags & !1).map_err(invalid)
}

// An index-only record has no independent file identity or critical payload.
// Header ownership may be recovered only through a qualified directory claim.
fn index_only_extension(record: &MftRecord<'_>, reference: u64) -> io::Result<bool> {
    if (reference_number(reference)) < 24 || record.flags()? & 1 == 0 || record.link_count()? != 0 {
        return Ok(false);
    }
    let mut count = 0;
    for attribute in record.attributes() {
        let attribute = attribute?;
        if !matches!(attribute.kind, 0x90 | 0xa0 | 0xb0) || attribute.name_utf16le()? != b"$\0I\x003\x000\0" {
            return Ok(false);
        }
        count += 1;
    }
    Ok(count != 0)
}

// Unreadable allocated records retain authority. Only absence or a different
// decoded generation proves that an old back-reference no longer names a base.
fn family_reference_live<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    reference: u64,
    slots: u64,
    bitmap: Attribute<'_>,
    bits: &mut (u64, [u8; 8192]),
) -> io::Result<bool> {
    let number = reference_number(reference);
    if reference_sequence(reference) == 0 || number >= slots || !bitmap_bit(volume, bitmap, number, slots, bits)? {
        return Ok(false);
    }
    let mut raw = vec![0; volume.boot.record_bytes as usize];
    volume.read_mft_record(mft, number, &mut raw)?;
    let record = MftRecord::parse(&mut raw, volume.boot.bytes_per_sector)?;
    Ok(u64::from(record.sequence_number()?) == reference >> 48)
}

// The allocated base generation, directory flag and one intact local standard
// information value establish identity without inventing a missing pathname.
fn directory_base_authority(record: &MftRecord<'_>, reference: u64) -> io::Result<bool> {
    if reference_sequence(reference) == 0
        || record.flags()? & 3 != 3
        || record.base_file_reference()? != 0
        || u64::from(record.sequence_number()?) != reference >> 48
        || record.physical_record_number()?.is_some_and(|number| number != (reference_number(reference)))
    {
        return Ok(false);
    }
    let mut standard = 0;
    for attribute in record.attributes() {
        let attribute = attribute?;
        if attribute.kind == 0x10 {
            if attribute.nonresident || !attribute.name_utf16le()?.is_empty() || attribute.resident_value()?.len() < 48
            {
                return Ok(false);
            }
            standard += 1;
        }
    }
    Ok(standard == 1)
}

// Root framing, geometry and full parent identities establish a usable local
// derivation target; allocation pages need not be trusted to replace membership.
fn directory_root_authority(value: &[u8], reference: u64, boot: ntfs_rs::boot::BootSector) -> io::Result<bool> {
    let index = match ntfs_rs::index::IndexRoot::parse(value) {
        Ok(index) => index,
        Err(_) => return Ok(false),
    };
    if index.index_block_bytes() != boot.index_block_bytes || index.vcn_unit_bytes(boot.cluster_bytes).is_err() {
        return Ok(false);
    }
    let mut offset = index.first_entry_offset();
    loop {
        let slot = match index.slot_at(offset) {
            Ok(slot) => slot,
            Err(_) => return Ok(false),
        };
        if slot.child_vcn.is_some() != index.has_children() {
            return Ok(false);
        }
        if let Some(entry) = slot.entry {
            if !metadata::filename_value_valid(entry.file_name_value) || u64_at(entry.file_name_value, 0)? != reference
            {
                return Ok(false);
            }
        } else {
            return Ok(true);
        }
        offset = slot.next_offset;
    }
}

fn directory_family_authority<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    record: &MftRecord<'_>,
    reference: u64,
    bytes: &[u8],
    slots: u64,
    bitmap: Attribute<'_>,
    bits: &mut (u64, [u8; 8192]),
    raw: &mut [u8],
) -> io::Result<bool> {
    if !directory_base_authority(record, reference)? {
        return Ok(false);
    }
    let mut selected = None;
    for attribute in record.attributes() {
        let attribute = attribute?;
        if attribute.kind != 0x90
            || attribute.name_utf16le()? != b"$\0I\x003\x000\0"
            || attribute.nonresident
            || !attribute
                .resident_value()
                .ok()
                .map(|value| directory_root_authority(value, reference, volume.boot))
                .transpose()?
                .unwrap_or(false)
        {
            continue;
        }
        let key = FamilyKey { kind: 0x90, name: b"$\0I\x003\x000\0".to_vec(), vcn: 0, reference, id: attribute.id };
        if selected.as_ref().is_some_and(|previous| previous != &key) {
            return Ok(false);
        }
        selected = Some(key);
    }
    // Local and extension roots share one authority decision. Every original
    // row must be framed before it can prove the absence of a second root.
    for entry in ntfs_rs::attrlist::AttributeList::new(bytes) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return Ok(false),
        };
        if entry.kind != 0x90 || entry.name_utf16le != b"$\0I\x003\x000\0" || entry.first_vcn != 0 {
            continue;
        }
        let key = FamilyKey {
            kind: entry.kind,
            name: entry.name_utf16le.to_vec(),
            vcn: entry.first_vcn,
            reference: entry.file_reference,
            id: entry.attribute_id,
        };
        if !derived_family_key_valid(volume, mft, &key, reference, false, slots, bitmap, bits, raw)? {
            continue;
        }
        let member = MftRecord::from_decoded(raw)?;
        for attribute in member.attributes() {
            let attribute = attribute?;
            if attribute.kind != key.kind || attribute.id != key.id || attribute.name_utf16le()? != key.name {
                continue;
            }
            if attribute.nonresident
                || !attribute
                    .resident_value()
                    .ok()
                    .map(|value| directory_root_authority(value, reference, volume.boot))
                    .transpose()?
                    .unwrap_or(false)
            {
                continue;
            }
            if selected.as_ref().is_some_and(|previous| previous != &key) {
                return Ok(false);
            }
            selected = Some(key.clone());
        }
    }
    Ok(selected.is_some())
}

// Generation-bearing physical identity and exact attribute coordinates must
// agree before a derived row can contribute directory-family ownership.
fn derived_family_key_valid<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    key: &FamilyKey,
    base: u64,
    directory_authority: bool,
    slots: u64,
    bitmap: Attribute<'_>,
    bits: &mut (u64, [u8; 8192]),
    raw: &mut [u8],
) -> io::Result<bool> {
    let member = reference_number(key.reference);
    if member >= slots || reference_sequence(key.reference) == 0 || !bitmap_bit(volume, bitmap, member, slots, bits)? {
        return Ok(false);
    }
    volume.read_mft_record(mft, member, raw)?;
    let physical = MftRecord::parse(raw, volume.boot.bytes_per_sector)?;
    let expected_parent = if key.reference == base { 0 } else { base };
    if physical.flags()? & 1 == 0
        || physical.physical_record_number()?.is_some_and(|n| n != member)
        || u64::from(physical.sequence_number()?) != key.reference >> 48
    {
        return Ok(false);
    }
    let parent = physical.base_file_reference()?;
    if parent != expected_parent
        && (!directory_authority
            || key.reference == base
            || !index_only_extension(&physical, key.reference)?
            || family_reference_live(volume, mft, parent, slots, bitmap, bits)?)
    {
        return Ok(false);
    }
    let mut matches = 0;
    for attribute in physical.attributes() {
        let attribute = attribute?;
        let vcn = if attribute.nonresident { attribute.first_vcn()? } else { 0 };
        if attribute.kind == key.kind
            && attribute.id == key.id
            && attribute.name_utf16le()? == key.name
            && vcn == key.vcn
        {
            matches += 1;
        }
    }
    if matches > 1 {
        return Err(reject("derived index list has competing attribute owners"));
    }
    Ok(matches == 1)
}

// A damaged derived length has one boundary only when its known name and zero
// padding end at a fully framed suffix whose keys still match physical owners.
// The suffix proof includes critical streams; a later damaged row stays strict.
fn derived_list_boundary<R: ReadAt>(
    volume: &mut Volume<R>,
    mft: &MftRecord<'_>,
    bytes: &[u8],
    offset: usize,
    base: u64,
    slots: u64,
    bitmap: Attribute<'_>,
    bits: &mut (u64, [u8; 8192]),
    raw: &mut [u8],
) -> io::Result<Option<usize>> {
    let header = bytes.get(offset..offset + 26).ok_or_else(|| reject("truncated family list header"))?;
    let kind = u32_at(header, 0)?;
    if !matches!(kind, 0x90 | 0xa0 | 0xb0) || header[6] != 4 || header[7] < 26 || header[7] % 2 != 0 {
        return Ok(None);
    }
    let name_start = offset + usize::from(header[7]);
    let name_end = name_start + 8;
    if bytes.get(name_start..name_end) != Some(b"$\0I\x003\x000\0".as_slice()) {
        return Ok(None);
    }
    let key = FamilyKey {
        kind,
        name: b"$\0I\x003\x000\0".to_vec(),
        vcn: u64_at(header, 8)?,
        reference: u64_at(header, 16)?,
        id: ntfs_rs::bytes::u16_at(header, 24)?,
    };
    if !derived_family_key_valid(volume, mft, &key, base, false, slots, bitmap, bits, raw)? {
        return Ok(None);
    }
    // A framed row cannot start inside zero padding. The first nonzero byte
    // identifies its aligned start; an all-zero remainder ends at the list end.
    let next = match bytes[name_end..].iter().position(|byte| *byte != 0) {
        Some(nonzero) => (name_end + nonzero) & !7,
        None => bytes.len(),
    };
    let minimum_boundary = (name_end + 7) & !7;
    if next < minimum_boundary
        || next % 8 != 0
        || next - offset > u16::MAX as usize
        || bytes[name_end..next].iter().any(|byte| *byte != 0)
    {
        return Ok(None);
    }
    for entry in ntfs_rs::attrlist::AttributeList::new(&bytes[next..]) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        if entry.kind == ATTR_ATTRIBUTE_LIST || reference_sequence(entry.file_reference) == 0 {
            return Ok(None);
        }
        let key = FamilyKey {
            kind: entry.kind,
            name: entry.name_utf16le.to_vec(),
            vcn: entry.first_vcn,
            reference: entry.file_reference,
            id: entry.attribute_id,
        };
        if !derived_family_key_valid(volume, mft, &key, base, false, slots, bitmap, bits, raw)? {
            return Ok(None);
        }
    }
    Ok(Some(next))
}

// Reconstruct list bytes from a qualified key. Physical attribute contents and
// IDs remain untouched; only the derived membership descriptor is republished.
fn family_key_bytes(key: &FamilyKey) -> io::Result<Vec<u8>> {
    if key.name.len() > 510 || key.name.len() % 2 != 0 {
        return Err(reject("invalid reconstructed family name"));
    }
    let descriptor = ntfs_rs::attrlist::ListEntry {
        kind: key.kind,
        first_vcn: key.vcn,
        file_reference: key.reference,
        attribute_id: key.id,
        name_utf16le: &key.name,
    };
    let mut entry = vec![0; descriptor.encoded_len()?];
    descriptor.encode(&mut entry)?;
    Ok(entry)
}

// Intact attribute coordinates and physical generations establish membership.
// Unique directory authority can restore index-only headers; competing live
// payload owners and missing critical attribute contents remain protected.
fn family_repairs(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    progress: &mut dyn FnMut(RepairProgress),
    rebuilt_directories: bool,
) -> io::Result<()> {
    // A retry removes unusable derived attributes; it never adds an index.
    // Rebuild the ownership catalogs before allocating or following their runs.
    while family_repairs_pass(source, boot, patches, progress, rebuilt_directories)? {}
    Ok(())
}

fn family_repairs_pass(
    source: &Path,
    boot: ntfs_rs::boot::BootSector,
    patches: &mut RepairPlan,
    progress: &mut dyn FnMut(RepairProgress),
    rebuilt_directories: bool,
) -> io::Result<bool> {
    use ntfs_rs::attrlist::AttributeList;
    use ntfs_rs::record_edit as edit;
    // Physical list offsets fit a record. The high bit records derived rows
    // removed from the retained list without changing its original preimage.
    const REMOVED_INDEX_ROWS: u64 = 1 << 63;
    let mut volume = PlannedImage::volume(source, patches, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let data = mft.stream(ATTR_DATA, &[])?;
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let slots = data.initialized_size()? / u64::from(boot.record_bytes);
    let mut bits = (u64::MAX, [0; 8192]);
    let mut raw = vec![0; boot.record_bytes as usize];
    let mut member_raw = vec![0; boot.record_bytes as usize];
    let mut families = checker::consistency::DiskInventory::new();
    let mut owners = checker::consistency::DiskInventory::new();
    let mut children = checker::consistency::DiskInventory::new();
    let mut directory_bases = checker::consistency::DiskInventory::new();
    let mut usable_roots = checker::consistency::DiskInventory::new();
    let mut physical_members = checker::consistency::DiskInventory::new();
    let mut names_complete = true;
    let mut lists = checker::consistency::scratch_file()?;
    for number in 0..slots {
        if number % 256 == 0 {
            progress(RepairProgress::new(
                Phase::Families,
                number * u64::from(boot.record_bytes) / 512,
                slots * u64::from(boot.record_bytes) / 512,
            ));
        }
        if !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
            continue;
        }
        volume.read_mft_record(&mft, number, &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let reference = number | (u64::from(record.sequence_number()?) << 48);
        let parent = record.base_file_reference()?;
        let weak_owner = index_only_extension(&record, reference)?
            && (parent == 0 || !family_reference_live(&mut volume, &mft, parent, slots, bitmap, &mut bits)?);
        if parent != 0 {
            children.push([parent, reference, 0, 0])?;
            owners.push([reference, parent, u64::from(weak_owner), 0])?;
        }
        let strong_directory = directory_base_authority(&record, reference)?;
        if strong_directory {
            directory_bases.push([reference, 0, 0, 0])?;
        }
        let owner = if parent == 0 { reference } else { parent };
        let mut has_index = false;
        let mut list = None;
        for attr in record.attributes() {
            let attr = attr?;
            if matches!(attr.kind, 0x90 | 0xa0 | 0xb0) && attr.name_utf16le()? == b"$\0I\x003\x000\0" {
                has_index = true;
                if attr.kind == 0x90
                    && !attr.nonresident
                    && record.flags()? & 1 != 0
                    && record.physical_record_number()?.is_none_or(|physical| physical == number)
                {
                    if let Ok(value) = attr.resident_value() {
                        if directory_root_authority(value, owner, boot)? {
                            usable_roots.push([owner, reference, u64::from(attr.id), 0])?;
                        }
                    }
                }
            }
            if attr.kind == ntfs_rs::mft::ATTR_FILE_NAME && !attr.nonresident {
                names_complete &=
                    attr.resident_value().is_ok_and(|v| ntfs_rs::filename::FileNameValue::parse(v).is_ok());
            }
            if attr.kind == ATTR_ATTRIBUTE_LIST && list.replace(attr).is_some() {
                return Err(reject("duplicate family list"));
            }
        }
        physical_members.push([owner, reference, u64::from(has_index), 0])?;
        let Some(list) = list else {
            if parent == 0 {
                families.push([reference, 0, 0, u64::MAX])?;
                owners.push([reference, reference, u64::from(weak_owner), 0])?;
            }
            continue;
        };
        if record.base_file_reference()? != 0 || list.flags()? != 0 || !list.name_utf16le()?.is_empty() {
            return Err(reject("invalid family list authority"));
        }
        let size = list.data_size()? as usize;
        let list_flags = (list.record_offset() as u64) * 2 + u64::from(list.nonresident);
        if size == 0 || size as u64 > patches.length {
            return Err(reject("invalid family list size"));
        }
        let backing = checker::consistency::scratch_file()?;
        backing.set_len(size as u64)?;
        let mut bytes = unsafe { memmap2::MmapMut::map_mut(&backing)? };
        for at in (0..size).step_by(1024 * 1024) {
            let end = at.saturating_add(1024 * 1024).min(size);
            volume.read_attribute(list, at as u64, &mut bytes[at..end])?;
        }
        let directory_authority = directory_family_authority(
            &mut volume,
            &mft,
            &record,
            reference,
            &bytes,
            slots,
            bitmap,
            &mut bits,
            &mut member_raw,
        )?;
        let offset = lists.stream_position()?;
        let mut retained_size = 0_u64;
        let mut entry_offset = 0;
        let mut removed_index_rows = false;
        while entry_offset < bytes.len() {
            let header =
                bytes.get(entry_offset..entry_offset + 26).ok_or_else(|| reject("truncated family list header"))?;
            let declared = usize::from(ntfs_rs::bytes::u16_at(header, 4)?);
            let mut framed = declared >= 32 && declared % 8 == 0 && declared <= bytes.len() - entry_offset;
            let raw_kind = u32_at(header, 0)?;
            if framed
                && matches!(raw_kind, 0x90 | 0xa0 | 0xb0)
                && header[6] == 4
                && header[7] >= 26
                && header[7] % 2 == 0
            {
                let name_start = entry_offset + usize::from(header[7]);
                let name_end = name_start + 8;
                if bytes.get(name_start..name_end) == Some(b"$\0I\x003\x000\0".as_slice()) {
                    // A shortened row cannot contain its known physical name.
                    // Otherwise retain valid framing, including arbitrary padding;
                    // the physical-key merge restores omitted strong members.
                    framed = name_end <= entry_offset + declared;
                }
            }
            let next_offset = if framed {
                entry_offset + declared
            } else if (directory_authority || strong_directory)
                && matches!(raw_kind, 0x90 | 0xa0 | 0xb0)
                && bytes.len() - entry_offset == 40
            {
                // The retained single-row case needs no following boundary.
                // Its full physical key is still checked before reconstruction.
                bytes.len()
            } else if directory_authority || strong_directory {
                derived_list_boundary(
                    &mut volume,
                    &mft,
                    &bytes,
                    entry_offset,
                    reference,
                    slots,
                    bitmap,
                    &mut bits,
                    &mut member_raw,
                )?
                .ok_or_else(|| reject("family list boundaries cannot establish membership"))?
            } else {
                return Err(reject("family list boundaries cannot establish membership"));
            };
            let parsed = if framed {
                AttributeList::new(&bytes[entry_offset..next_offset])
                    .next()
                    .ok_or_else(|| reject("empty family list row"))?
            } else {
                Err(ntfs_rs::Error::InvalidAttributeList)
            };
            let (key, reconstructed) = match parsed {
                Ok(entry) => (
                    FamilyKey {
                        kind: entry.kind,
                        name: entry.name_utf16le.to_vec(),
                        vcn: entry.first_vcn,
                        reference: entry.file_reference,
                        id: entry.attribute_id,
                    },
                    false,
                ),
                Err(_) if (directory_authority || strong_directory) && matches!(raw_kind, 0x90 | 0xa0 | 0xb0) => {
                    let key = FamilyKey {
                        kind: raw_kind,
                        name: b"$\0I\x003\x000\0".to_vec(),
                        vcn: u64_at(header, 8)?,
                        reference: u64_at(header, 16)?,
                        id: ntfs_rs::bytes::u16_at(header, 24)?,
                    };
                    if !derived_family_key_valid(
                        &mut volume,
                        &mft,
                        &key,
                        reference,
                        directory_authority,
                        slots,
                        bitmap,
                        &mut bits,
                        &mut member_raw,
                    )? {
                        return Err(reject("malformed index list row lacks physical authority"));
                    }
                    (key, true)
                }
                Err(error) => return Err(invalid(error)),
            };
            let derived_index = matches!(key.kind, 0x90 | 0xa0 | 0xb0) && key.name == b"$\0I\x003\x000\0";
            if key.kind == ATTR_ATTRIBUTE_LIST || (!derived_index && reference_sequence(key.reference) == 0) {
                return Err(reject("ambiguous family list entry"));
            }
            if derived_index
                && !derived_family_key_valid(
                    &mut volume,
                    &mft,
                    &key,
                    reference,
                    directory_authority,
                    slots,
                    bitmap,
                    &mut bits,
                    &mut member_raw,
                )?
            {
                removed_index_rows = true;
                entry_offset = next_offset;
                continue;
            }
            owners.push([key.reference, reference, 0, 0])?;
            if reconstructed {
                let row = family_key_bytes(&key)?;
                lists.write_all(&row)?;
                retained_size += row.len() as u64;
                removed_index_rows = true;
            } else {
                lists.write_all(&bytes[entry_offset..next_offset])?;
                retained_size += (next_offset - entry_offset) as u64;
            }
            entry_offset = next_offset;
        }
        owners.push([reference, reference, 0, 0])?;
        families.push([
            reference,
            offset,
            retained_size,
            list_flags | if removed_index_rows { REMOVED_INDEX_ROWS } else { 0 },
        ])?;
    }
    progress(RepairProgress::new(
        Phase::Families,
        slots * u64::from(boot.record_bytes) / 512,
        slots * u64::from(boot.record_bytes) / 512,
    ));
    let mut usable_roots = usable_roots.finish()?;
    let mut directory_bases = directory_bases.finish()?;
    let mut rootless = checker::consistency::DiskInventory::new();
    while let Some([reference, _, _, _]) = checker::consistency::inventory_next(&mut directory_bases)? {
        if checker::consistency::inventory_find(&mut usable_roots, reference)?.is_none() {
            rootless.push([reference, 0, 0, 0])?;
        }
    }
    let mut rootless = rootless.finish()?;
    let mut physical_members = physical_members.finish()?;
    let mut clearing = checker::consistency::DiskInventory::new();
    while let Some([owner, _, has_index, _]) = checker::consistency::inventory_next(&mut physical_members)? {
        if has_index != 0 && checker::consistency::inventory_find(&mut rootless, owner)?.is_some() {
            clearing.push([owner, 0, 0, 0])?;
        }
    }
    let mut clearing = clearing.finish()?;
    if clearing.metadata()?.len() != 0 {
        if !names_complete {
            return Err(reject("rootless directory needs a complete decoded filename inventory"));
        }
        // Every retained critical row must agree with its physical owner before
        // derived descriptors are removed. Header-only DATA reassignment is forbidden.
        let mut family_rows = families.finish()?;
        let list_map = if lists.metadata()?.len() == 0 { None } else { Some(unsafe { memmap2::Mmap::map(&lists)? }) };
        while let Some([base, offset, size, _]) = checker::consistency::inventory_next(&mut family_rows)? {
            if checker::consistency::inventory_find(&mut clearing, base)?.is_none() || size == 0 {
                continue;
            }
            let bytes = list_map
                .as_ref()
                .ok_or_else(|| reject("missing critical list spool"))?
                .get(offset as usize..(offset + size) as usize)
                .ok_or_else(|| reject("critical list spool range"))?;
            for entry in AttributeList::new(bytes) {
                let entry = entry?;
                if matches!(entry.kind, 0x90 | 0xa0 | 0xb0) && entry.name_utf16le == b"$\0I\x003\x000\0" {
                    continue;
                }
                let key = FamilyKey {
                    kind: entry.kind,
                    name: entry.name_utf16le.to_vec(),
                    vcn: entry.first_vcn,
                    reference: entry.file_reference,
                    id: entry.attribute_id,
                };
                if !derived_family_key_valid(
                    &mut volume,
                    &mft,
                    &key,
                    base,
                    false,
                    slots,
                    bitmap,
                    &mut bits,
                    &mut member_raw,
                )? {
                    return Err(reject("rootless directory has unaccounted critical stream membership"));
                }
            }
        }
        physical_members.seek(SeekFrom::Start(0))?;
        let mut extra = RepairPlan::new(patches.length)?;
        while let Some([owner, reference, _, _]) = checker::consistency::inventory_next(&mut physical_members)? {
            if checker::consistency::inventory_find(&mut clearing, owner)?.is_none() {
                continue;
            }
            let number = reference_number(reference);
            volume.read_mft_record(&mft, number, &mut raw)?;
            let before = raw.clone();
            let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            if record.flags()? & 1 == 0
                || record.physical_record_number()?.is_some_and(|physical| physical != number)
                || u64::from(record.sequence_number()?) != reference >> 48
                || record.base_file_reference()? != if owner == reference { 0 } else { owner }
            {
                return Err(reject("rootless directory member identity changed"));
            }
            let mut remove = Vec::new();
            for attr in record.attributes() {
                let attr = attr?;
                if (matches!(attr.kind, 0x90 | 0xa0 | 0xb0) && attr.name_utf16le()? == b"$\0I\x003\x000\0")
                    || (owner == reference && attr.kind == ATTR_ATTRIBUTE_LIST)
                {
                    remove.push(attr.record_offset());
                }
            }
            if remove.is_empty() {
                continue;
            }
            for at in remove.into_iter().rev() {
                edit::remove(&mut raw, at)?;
            }
            if owner != reference && MftRecord::from_decoded(&raw)?.attributes().next().is_none() {
                retire_empty_extension(&mut volume, &mft, reference, &before, &mut raw, &mut extra, true)?;
            }
            edit::validate(&raw)?;
            protect_mft_record(&mut raw, boot.bytes_per_sector)?;
            repair_record_patch(&mut volume, data, number, &before, &raw, &mut extra)?;
        }
        drop(volume);
        for patch in extra.iter() {
            patches.compose(patch?)?;
        }
        return Ok(true);
    }
    let mut owners = std::io::BufReader::new(owners.finish()?);
    let mut transfers = checker::consistency::DiskInventory::new();
    let mut pending_owner = checker::consistency::inventory_next(&mut owners)?;
    while let Some(first) = pending_owner {
        let mut selected = None;
        let mut weak = None;
        while let Some(row) = pending_owner.filter(|r| r[0] == first[0]) {
            if row[2] == 0 {
                if selected.is_some_and(|owner| owner != row[1]) {
                    return Err(reject("record claimed by competing live families"));
                }
                selected = Some(row[1]);
            } else {
                weak = Some(row[1]);
            }
            pending_owner = checker::consistency::inventory_next(&mut owners)?;
        }
        if let (Some(base), Some(old)) = (selected, weak) {
            if base != old {
                // Only qualified derived rows can replace weak index-only
                // header ownership. Real file bases and payload owners stay strict.
                transfers.push([first[0], base, 0, 0])?;
                children.push([base, first[0], 0, 0])?;
            }
        }
    }
    let mut transfers = transfers.finish()?;
    let mut children = std::io::BufReader::new(children.finish()?);
    let mut child = checker::consistency::inventory_next(&mut children)?;
    let mut families = std::io::BufReader::new(families.finish()?);
    let lists_map = if lists.metadata()?.len() == 0 { None } else { Some(unsafe { memmap2::Mmap::map(&lists)? }) };
    let mut owned = std::io::BufReader::new(repair_owned_ranges(&mut volume, &mft)?);
    let mut reserved = checker::consistency::scratch_file()?;
    let mut cursor = 1;
    let allocation_raw = checked_family_image(&mut volume, &mft, 6)?;
    let allocation_record = MftRecord::from_decoded(&allocation_raw)?;
    let allocation_map = allocation_record.stream(ATTR_DATA, &[])?;
    let mut extra = RepairPlan::new(patches.length)?;
    while let Some([base, offset, size, flags]) = checker::consistency::inventory_next(&mut families)? {
        if checker::consistency::inventory_find(&mut transfers, base)?.is_some_and(|row| row[1] != base) {
            continue;
        }
        let absent = flags == u64::MAX;
        let external = !absent && flags & 1 != 0;
        let list_at = ((flags & !REMOVED_INDEX_ROWS) / 2) as usize;
        let bytes: &[u8] = if size == 0 {
            &[]
        } else {
            lists_map
                .as_ref()
                .ok_or_else(|| reject("missing family list spool"))?
                .get(offset as usize..(offset + size) as usize)
                .ok_or_else(|| reject("family list spool range"))?
        };
        let mut listed = FamilyKeysBuilder::new()?;
        let mut members = checker::consistency::DiskInventory::new();
        members.push([base, 0, 0, 0])?;
        let mut removed_index_entries = !absent && flags & REMOVED_INDEX_ROWS != 0;
        for entry in AttributeList::new(&bytes) {
            let entry = entry?;
            let number = reference_number(entry.file_reference);
            if rebuilt_directories
                && matches!(entry.kind, 0x90 | 0xa0 | 0xb0)
                && entry.name_utf16le == b"$\0I\x003\x000\0"
                && number < slots
                && !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)?
            {
                removed_index_entries = true;
                continue;
            }
            listed.push(FamilyKey {
                kind: entry.kind,
                name: entry.name_utf16le.to_vec(),
                vcn: entry.first_vcn,
                reference: entry.file_reference,
                id: entry.attribute_id,
            })?;
            members.push([entry.file_reference, 0, 0, 0])?;
        }
        while let Some(row) = child.filter(|r| r[0] < base) {
            let _ = row;
            child = checker::consistency::inventory_next(&mut children)?;
        }
        while let Some(row) = child.filter(|r| r[0] == base) {
            members.push([row[1], 0, 0, 0])?;
            child = checker::consistency::inventory_next(&mut children)?;
        }
        let mut members = std::io::BufReader::new(members.finish()?);
        if absent {
            let first = checker::consistency::inventory_next(&mut members)?;
            let second = checker::consistency::inventory_next(&mut members)?;
            if first == Some([base, 0, 0, 0]) && second.is_none() {
                continue;
            }
            members.seek(SeekFrom::Start(0))?;
        }
        let mut listed = listed.finish()?;
        let mut previous_key = None;
        while let Some(key) = listed.next()? {
            if previous_key.as_ref() == Some(&key) {
                if !matches!(key.kind, 0x90 | 0xa0 | 0xb0) || key.name != b"$\0I\x003\x000\0" {
                    return Err(reject("ambiguous non-index family list entry"));
                }
                removed_index_entries = true;
            }
            previous_key = Some(key);
        }
        listed.rewind()?;
        volume.read_mft_record(&mft, reference_number(base), &mut member_raw)?;
        let base_record = MftRecord::parse(&mut member_raw, boot.bytes_per_sector)?;
        let cleanup_derived = removed_index_entries
            && directory_family_authority(
                &mut volume,
                &mft,
                &base_record,
                base,
                bytes,
                slots,
                bitmap,
                &mut bits,
                &mut raw,
            )?;
        let mut expected = FamilyKeysBuilder::new()?;
        let mut previous_member = None;
        while let Some([reference, _, _, _]) = checker::consistency::inventory_next(&mut members)? {
            if previous_member == Some(reference) {
                continue;
            }
            previous_member = Some(reference);
            let number = reference_number(reference);
            if number >= slots || !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
                return Err(reject("family refers to unallocated record"));
            }
            volume.read_mft_record(&mft, number, &mut raw)?;
            let before = raw.clone();
            MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            let record = MftRecord::from_decoded(&raw)?;
            if u64::from(record.sequence_number()?) != reference >> 48 {
                return Err(reject("stale family sequence"));
            }
            let parent = record.base_file_reference()?;
            let mut has_standard = false;
            let mut remove = Vec::new();
            for attr in record.attributes() {
                let attr = attr?;
                has_standard |= attr.kind == 0x10;
                if attr.kind == ATTR_ATTRIBUTE_LIST {
                    if reference != base {
                        return Err(reject("extension owns another list"));
                    }
                    continue;
                }
                let key = FamilyKey {
                    kind: attr.kind,
                    name: attr.name_utf16le()?.to_vec(),
                    vcn: if attr.nonresident { attr.first_vcn()? } else { 0 },
                    reference,
                    id: ntfs_rs::bytes::u16_at(&raw, attr.record_offset() + 14)?,
                };
                if cleanup_derived
                    && reference != base
                    && matches!(key.kind, 0x90 | 0xa0 | 0xb0)
                    && key.name == b"$\0I\x003\x000\0"
                    && !listed.contains(&key)?
                {
                    // Header membership alone cannot restore a rejected derived
                    // descriptor. Retain mixed-member payloads and rebuild names.
                    remove.push(attr.record_offset());
                    removed_index_entries = true;
                } else {
                    expected.push(key)?;
                }
            }
            if reference != base && parent != base {
                let transferred =
                    checker::consistency::inventory_find(&mut transfers, reference)?.is_some_and(|row| row[1] == base);
                if number < 24
                    || (parent != 0 && !transferred)
                    || has_standard
                    || ntfs_rs::bytes::u16_at(&raw, 18)? != 0
                {
                    return Err(reject("extension identity conflicts with family authority"));
                }
                edit::p64(&mut raw, 32, base)?;
            }
            if reference != base {
                for at in remove.into_iter().rev() {
                    edit::remove(&mut raw, at)?;
                }
                if MftRecord::from_decoded(&raw)?.attributes().next().is_none() {
                    retire_empty_extension(&mut volume, &mft, reference, &before, &mut raw, &mut extra, true)?;
                }
                let mut original = before.clone();
                MftRecord::parse(&mut original, boot.bytes_per_sector)?;
                if original != raw {
                    edit::validate(&raw)?;
                    protect_mft_record(&mut raw, boot.bytes_per_sector)?;
                    repair_record_patch(&mut volume, data, number, &before, &raw, &mut extra)?;
                }
            }
        }
        listed.rewind()?;
        let mut expected = expected.finish()?;
        let (mut left, mut right) = (listed.next_unique()?, expected.next_unique()?);
        let mut different = removed_index_entries;
        while left.is_some() || right.is_some() {
            match (&left, &right) {
                (Some(a), Some(b)) if family_key_order(a, b) == std::cmp::Ordering::Equal => {
                    left = listed.next_unique()?;
                    right = expected.next_unique()?;
                }
                (Some(a), Some(b)) if family_key_order(a, b) == std::cmp::Ordering::Greater => {
                    different = true;
                    right = expected.next_unique()?;
                }
                (Some(a), _) => {
                    if !rebuilt_directories || !matches!(a.kind, 0x90 | 0xa0 | 0xb0) || a.name != b"$\0I\x003\x000\0" {
                        return Err(reject("listed attribute contents are missing; originals preserved"));
                    }
                    different = true;
                    left = listed.next_unique()?;
                }
                (None, Some(_)) => {
                    different = true;
                    right = expected.next_unique()?;
                }
                (None, None) => break,
            }
        }
        if different {
            let number = reference_number(base);

            let mut value_file = checker::consistency::scratch_file()?;
            expected.rewind()?;
            while let Some(key) = expected.next_unique()? {
                value_file.write_all(&family_key_bytes(&key)?)?;
            }
            let value_size = value_file.metadata()?.len();
            if value_size == 0 {
                return Err(reject("empty reconstructed family list"));
            }
            let value_map = unsafe { memmap2::Mmap::map(&value_file)? };
            let value: &[u8] = &value_map;
            volume.read_mft_record(&mft, number, &mut raw)?;
            let before = raw.clone();
            MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
            if !external && !absent && edit::set_resident_value(&mut raw, list_at, &value).is_ok() {
                // Resident list still fits, with its original ID and owner.
            } else {
                // Retry from the untouched image: failed sizing must not become a
                // partial publication. Spill a growing list into ordinary NTFS runs.
                raw = before.clone();
                MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
                let mut attribute = vec![0; boot.record_bytes as usize];
                let resident = edit::build_resident(ATTR_ATTRIBUTE_LIST, &[], &value, &mut attribute);
                let mut candidate = raw.clone();
                let resident = resident.ok().filter(|&n| repair_replace(&mut candidate, &attribute[..n]).is_ok());
                if resident.is_some() {
                    raw = candidate;
                } else {
                    let bytes = value.len() as u64;
                    let clusters = bytes.div_ceil(u64::from(boot.cluster_bytes));
                    let lcn =
                        repair_reserve(&mut volume, allocation_map, &mut owned, &mut reserved, clusters, &mut cursor)?;
                    let allocated = clusters * u64::from(boot.cluster_bytes);
                    let mut offset = 0;
                    while offset < allocated {
                        let n = (allocated - offset).min(65536) as usize;
                        let mut after = vec![0; n];
                        let valid = bytes.saturating_sub(offset).min(n as u64) as usize;
                        if valid != 0 {
                            after[..valid].copy_from_slice(&value[offset as usize..offset as usize + valid]);
                        }
                        let physical = lcn * u64::from(boot.cluster_bytes) + offset;
                        let mut before = vec![0; n];
                        volume.read_physical(physical, &mut before)?;
                        extra.push(Patch::new(physical, before, after))?;
                        offset += n as u64;
                    }
                    let n = edit::build_nonresident(
                        ATTR_ATTRIBUTE_LIST,
                        &[],
                        &[ntfs_rs::runlist::Extent { vcn: 0, lcn: Some(lcn), len: clusters }],
                        allocated,
                        bytes,
                        bytes,
                        &mut attribute,
                    )?;
                    repair_replace(&mut raw, &attribute[..n])?;
                }
            }
            edit::validate(&raw)?;
            protect_mft_record(&mut raw, boot.bytes_per_sector)?;
            repair_record_patch(&mut volume, data, number, &before, &raw, &mut extra)?;
        }
    }
    drop(volume);
    for patch in extra.iter() {
        patches.compose(patch?)?;
    }
    Ok(false)
}
/// Optional offline maintenance. Defaults preserve bad-cluster declarations
/// and unused descriptors. Existing C/Python APIs keep these defaults.
#[derive(Clone, Copy, Debug, Default)]
pub struct RepairOptions {
    pub rescan_bad_clusters: bool,
    pub cleanup_security: bool,
    pub index_audit: checker::consistency::AuditOptions,
}

/// Validate a frozen mounted scan without granting write authority.
pub(crate) fn preflight_frozen_repairs(
    source: &Path,
    index_audit: checker::consistency::AuditOptions,
    budget: checker::ScanBudget,
) -> io::Result<WriteViewStats> {
    structural_repair_plan(
        source,
        &mut |_| {},
        PlanInputs {
            frozen_preflight: true,
            options: RepairOptions { index_audit, ..Default::default() },
            budget: Some(budget),
            ..Default::default()
        },
    )
    .map(|plan| plan.write_view_stats())
}

/// Optional inputs of a structural repair plan; defaults describe a plain copy repair.
#[derive(Default)]
pub(crate) struct PlanInputs<'a> {
    pub(crate) bad: Option<&'a File>,
    pub(crate) frozen_preflight: bool,
    pub(crate) options: RepairOptions,
    pub(crate) recovery_created: Option<u64>,
    pub(crate) budget: Option<checker::ScanBudget>,
    pub(crate) unresolved: Option<&'a File>,
}

fn structural_repair_plan(
    source: &Path,
    progress: &mut dyn FnMut(RepairProgress),
    inputs: PlanInputs<'_>,
) -> io::Result<RepairPlan> {
    let PlanInputs { bad, frozen_preflight, options, recovery_created, budget, unresolved } = inputs;
    if options.index_audit.skip_directory_cycles {
        return Err(reject("offline repair requires directory cycle checking"));
    }
    progress(RepairProgress::new(Phase::Planning, 0, 0));
    let (boot, initial) = bootstrap_repairs(source)?;
    // Only this primary plan receives the auxiliary allowance. Nested staging
    // plans remain file backed, so concurrent plans cannot multiply the budget.
    let mut patches = RepairPlan::with_scan_budget(image_length(&File::open(source)?)?, budget)?;
    if let Some(created) = recovery_created {
        patches.recovery_created = created;
    }

    for patch in initial {
        patches.push(patch)?;
    }
    let mut resident_bitmap = RepairPlan::new(patches.length)?;
    {
        let mut volume = PlannedImage::volume(source, &patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        family::mft_resident_bitmap_repairs(&mut volume, &mft, false, |patch| resident_bitmap.push(patch))?;
    }
    for patch in resident_bitmap.iter() {
        patches.compose(patch?)?;
    }
    record_repairs(source, boot, &mut patches, progress)?;
    reserved::ensure_bitmap(source, boot, &mut patches)?;
    family_repairs(source, boot, &mut patches, progress, false)?;
    reserved::canonical_streams(source, boot, &mut patches)?;
    progress(RepairProgress::new(Phase::Allocation, 0, 0));
    let no_bad = checker::consistency::scratch_file()?;
    badclus_repairs(source, boot, &mut patches, bad.unwrap_or(&no_bad), options.rescan_bad_clusters)?;
    crosslink_repairs(source, boot, &mut patches, unresolved)?;
    reserved::restart_copies(source, boot, &mut patches)?;
    progress(RepairProgress::new(Phase::Directories, 0, 0));
    metadata::system_table_repairs(source, boot, &mut patches)?;
    let mut changed_names = checker::consistency::scratch_file()?;
    metadata::namespace_repairs(source, boot, &mut patches, &mut changed_names)?;
    metadata::file_repairs(source, boot, &mut patches)?;
    directory_repairs_with_options(source, boot, &mut patches, options.index_audit, changed_names)?;
    // Reconnection can remove aliases after the first metadata pass. Publish
    // their final link counts before validating the completed repair plan.
    metadata::file_repairs(source, boot, &mut patches)?;
    family_repairs(source, boot, &mut patches, progress, true)?;
    progress(RepairProgress::new(Phase::Security, 0, 0));
    security_repairs(source, boot, &mut patches)?;
    if options.cleanup_security {
        metadata::security_cleanup(source, boot, &mut patches)?;
    }
    metadata::reparse_repairs(source, boot, &mut patches)?;
    semantic::object_id_repairs(source, boot, &mut patches, options.index_audit.index_check)?;
    quota_repairs(source, boot, &mut patches)?;
    usn_repairs(source, boot, &mut patches)?;
    // Allocation may grow the MFT during earlier phases. Clear only bits
    // beyond its final checked physical mapping, retaining every real slot.
    let mut padding = RepairPlan::new(patches.length)?;
    {
        let mut volume = PlannedImage::volume(source, &patches, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        family::mft_bitmap_padding_repairs(&mut volume, &mft, |patch| padding.push(patch))?;
    }
    for patch in padding.iter() {
        patches.compose(patch?)?;
    }
    progress(RepairProgress::new(Phase::Audit, 0, 0));
    let reader = || -> io::Result<_> { Ok(PlannedImage::open(source, &patches)?) };
    let mut volume = Volume::new(reader()?, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let mut raw = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 3, &mut raw)?;
    let info = ntfs_rs::volume_info::VolumeInfo::from_record(&MftRecord::parse(&mut raw, boot.bytes_per_sector)?)?;
    if info.has_unsupported_flags() || (info.major_version, info.minor_version) != (3, 1) {
        return Err(reject(
            "structural repair requires NTFS 3.1 with supported volume flags; dirty state is permitted for recovery",
        ));
    }
    drop(volume);
    let mut recovery = checker::inspect_recovery(reader()?, boot)?;
    let mut clean_checkpoint_complete = false;
    if recovery.log == ntfs_rs::logfile::LogState::CleanShutdown {
        // Retained clean history is safe for structural writes only after the
        // validated replay plan needs no metadata or compensation writes.
        let checkpoint = plan_reader(reader, boot)?;
        if !checkpoint.preparation.is_empty() || !checkpoint.patches.is_empty() {
            return Err(reject("clean journal checkpoint requires metadata recovery"));
        }
        for patch in checkpoint.publication.iter() {
            patches.compose(patch?)?;
        }
        let projected = || Ok(PlannedImage::open(source, &patches)?);
        let remaining = plan_reader(projected, boot)?;
        clean_checkpoint_complete =
            remaining.preparation.is_empty() && remaining.patches.is_empty() && remaining.publication.is_empty();
        recovery = checker::inspect_recovery(projected()?, boot)?;
    }
    let reader = || -> io::Result<_> { Ok(PlannedImage::open(source, &patches)?) };
    let log_complete = matches!(
        recovery.log,
        ntfs_rs::logfile::LogState::Uninitialized
            | ntfs_rs::logfile::LogState::NoActiveClients
            | ntfs_rs::logfile::LogState::CheckedVolume
    ) || clean_checkpoint_complete
        || (recovery.log == ntfs_rs::logfile::LogState::ReplayRequired
            && (frozen_preflight
                || plan_reader(reader, boot)
                    .is_ok_and(|p| p.preparation.is_empty() && p.patches.is_empty() && p.publication.is_empty())));
    if !log_complete || write_gate(recovery.hibernation, false) != HibernationWriteGate::Clear {
        return Err(reject("allocation repair requires an inactive journal and no hibernation"));
    }
    let mut volume = Volume::new(reader()?, boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let mut candidates = checker::consistency::DiskInventory::new();
    let audit = checker::consistency::audit_reader(
        reader()?,
        boot,
        |offset, before, after| {
            candidates.push([offset, u64::from(before), u64::from(after), 0])?;
            Ok(())
        },
        |_| Ok(()),
        options.index_audit,
        patches.index_cache_bytes,
    )?;
    if !audit.complete
        || audit.errors
            != audit
                .findings
                .iter()
                .filter(|f| {
                    f.is_error
                        && matches!(
                            f.code.as_str(),
                            "cluster-marked-free" | "cluster-marked-free-count" | "unreferenced-clusters"
                        )
                })
                .count() as u64
    {
        return Err(reject("audit has unsupported layouts or errors beyond allocation/mirror repair; run --audit"));
    }
    let allocation_image = checked_family_image(&mut volume, &mft, 6)?;
    let record = MftRecord::from_decoded(&allocation_image)?;
    let allocation = record.stream(ATTR_DATA, &[])?;
    drop(volume);
    let mut candidates = std::io::BufReader::new(candidates.finish()?);
    let mut pending: Option<Patch> = None;
    while let Some([offset, before, after, _]) = checker::consistency::inventory_next(&mut candidates)? {
        plan_nonresident_overwrite(allocation, boot, offset, 1, |span| {
            if pending
                .as_ref()
                .is_some_and(|p| p.physical + p.after.len() as u64 != span.physical_offset || p.after.len() == 65536)
            {
                patches.compose(pending.take().unwrap()).map_err(|_| ntfs_rs::Error::Io)?;
            }
            let p = pending.get_or_insert_with(|| Patch::new(span.physical_offset, Vec::new(), Vec::new()));
            p.before.push(before as u8);
            p.after.push(after as u8);
            Ok(())
        })?;
    }
    if let Some(patch) = pending {
        patches.compose(patch)?;
    }
    let proposed = PlannedImage::open(source, &patches)?;
    if !checker::consistency::audit_reader(
        proposed,
        boot,
        |_, _, _| Ok(()),
        |_| Ok(()),
        options.index_audit,
        patches.index_cache_bytes,
    )?
    .passed()
    {
        return Err(reject("proposed structural repair does not pass the selected checking mode"));
    }
    Ok(patches)
}

/// Confirm that recovery has no pending preparation, redo or publication writes.
pub(crate) fn replay_is_empty(source: &Path) -> io::Result<bool> {
    let plan = plan(source)?;
    Ok(plan.preparation.is_empty() && plan.patches.is_empty() && plan.publication.is_empty())
}

/// Print exact physical edits without creating or writing an image.
pub fn describe_repair(source: &Path, options: RepairOptions) -> io::Result<()> {
    let plan = structural_repair_plan(source, &mut |_| {}, PlanInputs { options, ..Default::default() })?;
    let bytes = plan.iter().try_fold(0_u64, |sum, p| -> io::Result<u64> {
        sum.checked_add(p?.after.len() as u64).ok_or_else(|| reject("repair size overflow"))
    })?;
    println!("repair_supported=1 ranges={} bytes={bytes}", plan.len());
    for patch in plan.iter() {
        let patch = patch?;
        println!(
            "physical={} length={} set_bits={} cleared_bits={}",
            patch.physical,
            patch.after.len(),
            patch.before.iter().zip(&patch.after).map(|(a, b)| (b & !a).count_ones()).sum::<u32>(),
            patch.before.iter().zip(&patch.after).map(|(a, b)| (a & !b).count_ones()).sum::<u32>()
        );
    }
    Ok(())
}

struct EvidenceSpan {
    label: String,
    physical: u64,
    length: u64,
}

struct UnrecoverableEvidence {
    code: &'static str,
    detail: String,
    spans: Vec<EvidenceSpan>,
}

fn mft_evidence_spans(
    data: Attribute<'_>,
    boot: ntfs_rs::boot::BootSector,
    number: u64,
    label: &str,
    spans: &mut Vec<EvidenceSpan>,
) -> io::Result<()> {
    plan_nonresident_overwrite(
        data,
        boot,
        number.checked_mul(u64::from(boot.record_bytes)).ok_or_else(|| reject("evidence offset overflow"))?,
        u64::from(boot.record_bytes),
        |span| {
            spans.push(EvidenceSpan { label: label.to_owned(), physical: span.physical_offset, length: span.length });
            Ok(())
        },
    )
    .map(|_| ())
    .map_err(invalid)
}

// Produce evidence for the first issue which has no unique reconstruction.
// The physical bytes stay on the source; this report is an external copy with
// exact offsets, so a later recovery attempt can revisit the refused choice.
fn unrecoverable_evidence(source: &Path) -> io::Result<UnrecoverableEvidence> {
    use ntfs_rs::runlist::DataRuns;
    let mut volume = checker::open_volume(source)?;
    let boot = volume.boot;
    let source_bytes = File::open(source)?.metadata()?.len();
    let logical = match checker::consistency::mft_image(&mut volume) {
        Ok(image) => image,
        Err(error) => {
            let mut spans = Vec::new();
            for (label, lcn) in [("mft-zero", boot.mft_lcn), ("mft-zero-mirror", boot.mft_mirror_lcn)] {
                let physical =
                    lcn.checked_mul(u64::from(boot.cluster_bytes)).ok_or_else(|| reject("evidence offset overflow"))?;
                if physical.checked_add(u64::from(boot.record_bytes)).is_some_and(|end| end <= source_bytes) {
                    spans.push(EvidenceSpan {
                        label: label.to_owned(),
                        physical,
                        length: u64::from(boot.record_bytes),
                    });
                }
            }
            return Ok(UnrecoverableEvidence {
                code: "unresolved-mft-bootstrap",
                detail: format!("validated MFT mapping unavailable: {error}"),
                spans,
            });
        }
    };
    let mft = MftRecord::from_decoded(&logical)?;
    let data = mft.stream(ATTR_DATA, &[])?;
    let bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let initialized = data.initialized_size()?;
    if initialized % u64::from(boot.record_bytes) != 0 {
        return Err(reject("MFT record count is not integral"));
    }
    let slots = initialized / u64::from(boot.record_bytes);
    let mut bits = (u64::MAX, [0; 8192]);
    let mut raw = vec![0; boot.record_bytes as usize];
    for number in 0..slots {
        if !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
            continue;
        }
        let read = volume.read_mft_record(&mft, number, &mut raw);
        let in_use = read.is_ok() && raw.get(..4) == Some(b"FILE") && ntfs_rs::bytes::u16_at(&raw, 22)? & 1 != 0;
        let decoded = if read.is_ok() && in_use {
            decode_repair_record(&raw, boot.bytes_per_sector).map(|_| ())
        } else {
            Err(reject("allocated record is unreadable or not in use"))
        };
        if let Err(error) = decoded {
            let mut spans = Vec::new();
            mft_evidence_spans(data, boot, number, &format!("mft-record-{number}"), &mut spans)?;
            let mirror_count = 4.max(boot.cluster_bytes / boot.record_bytes) as u64;
            if number < mirror_count {
                let physical =
                    boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + number * u64::from(boot.record_bytes);
                spans.push(EvidenceSpan {
                    label: format!("mft-mirror-record-{number}"),
                    physical,
                    length: u64::from(boot.record_bytes),
                });
            }
            return Ok(UnrecoverableEvidence {
                code: "unrecoverable-mft-record",
                detail: format!("allocated record {number} has no trustworthy decoded contents: {error}"),
                spans,
            });
        }
    }
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let mut runs = checker::consistency::DiskInventory::new();
    for number in 0..slots {
        if !bitmap_bit(&mut volume, bitmap, number, slots, &mut bits)? {
            continue;
        }
        volume.read_mft_record(&mft, number, &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let owner =
            if record.base_file_reference()? == 0 { number } else { reference_number(record.base_file_reference()?) };
        if !matches!(owner, 0 | 1 | 2 | 6 | 7 | 8) {
            continue;
        }
        for item in record.attributes() {
            let attr = item?;
            if !attr.nonresident {
                continue;
            }
            for run in DataRuns::new(attr.data_runs()?, attr.first_vcn()?) {
                let run = run?;
                if let Some(lcn) = run.lcn {
                    let end = lcn
                        .checked_add(run.len)
                        .filter(|end| *end <= clusters)
                        .ok_or_else(|| reject("reserved evidence extent lies outside volume"))?;
                    runs.push([lcn, end, number, u64::from(attr.id)])?;
                }
            }
        }
    }
    let mut runs = std::io::BufReader::new(runs.finish()?);
    let mut active = None::<[u64; 4]>;
    while let Some(run) = checker::consistency::inventory_next(&mut runs)? {
        if let Some(previous) = active {
            if run[0] < previous[1] {
                let start = run[0] * u64::from(boot.cluster_bytes);
                let length = (run[1].min(previous[1]) - run[0]) * u64::from(boot.cluster_bytes);
                let mut spans = vec![EvidenceSpan { label: "shared-clusters".to_owned(), physical: start, length }];
                mft_evidence_spans(data, boot, previous[2], "first-owner-record", &mut spans)?;
                if run[2] != previous[2] {
                    mft_evidence_spans(data, boot, run[2], "second-owner-record", &mut spans)?;
                }
                return Ok(UnrecoverableEvidence { code: "unresolved-reserved-crosslink",
                    detail: format!("LCNs {}..{} are claimed by record {} attribute {} and record {} attribute {}; no independent contents establish both owners",
                        run[0], run[1].min(previous[1]), previous[2], previous[3], run[2], run[3]), spans });
            }
            if run[1] > previous[1] {
                active = Some(run);
            }
        } else {
            active = Some(run);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no unrecoverable MFT record or reserved system-file cross-link was found",
    ))
}

/// Copy the first unrecoverable issue's exact raw evidence to a new text file.
/// This never changes the source image or calls the repair writer.
pub fn export_repair_evidence(source: &Path, destination: &Path) -> io::Result<()> {
    let initial = std::fs::metadata(source)?;
    if !initial.is_file() {
        return Err(reject("evidence export requires an offline regular image"));
    }
    let issue = unrecoverable_evidence(source)?;
    let mut input = File::open(source)?;
    let identity = input.metadata()?;
    if identity.len() != initial.len() || identity.modified()? != initial.modified()? {
        return Err(reject("source changed during evidence scan"));
    }
    for span in &issue.spans {
        if span.physical.checked_add(span.length).is_none_or(|end| end > identity.len()) {
            return Err(reject("evidence span lies outside the source"));
        }
    }
    let mut output = OpenOptions::new().write(true).create_new(true).open(destination)?;
    writeln!(output, "slate_ntfs_evidence_version=1")?;
    writeln!(output, "source_bytes={}", identity.len())?;
    writeln!(output, "issue={}", issue.code)?;
    writeln!(output, "detail={}", issue.detail)?;
    for span in issue.spans {
        writeln!(output, "span={} physical={} length={}", span.label, span.physical, span.length)?;
        input.seek(SeekFrom::Start(span.physical))?;
        let mut remaining = span.length;
        let mut crc = 0;
        let mut buffer = [0_u8; 4096];
        while remaining != 0 {
            let n = remaining.min(buffer.len() as u64) as usize;
            input.read_exact(&mut buffer[..n])?;
            crc = repair_checksum(crc, &buffer[..n]);
            for line in buffer[..n].chunks(64) {
                for byte in line {
                    write!(output, "{byte:02x}")?;
                }
                writeln!(output)?;
            }
            remaining -= n as u64;
        }
        writeln!(output, "crc64_ecma={crc:016x}")?;
    }
    if input.metadata()?.len() != identity.len() || input.metadata()?.modified()? != identity.modified()? {
        return Err(reject("source changed during evidence export; report must be treated as incomplete"));
    }
    writeln!(output, "source_unchanged=1")?;
    output.sync_all()?;
    Ok(())
}

/// Repair validated redundant metadata and allocation in a new offline image.
/// Publication is separate from repair: interrupted work keeps the explicit
/// .repair-incomplete suffix. Only an audited, synced result gets the final name.
pub fn repair_to(
    source: &Path,
    destination: &Path,
    stop_after: Option<usize>,
    progress: &mut dyn FnMut(RepairProgress),
    options: RepairOptions,
) -> io::Result<()> {
    repair_to_with_maintenance(source, destination, stop_after, progress, None, options)
}

/// Private, synced copy of an offline image under destination plus suffix.
/// The source was opened by the caller, so changes since then are detected.
struct StagedCopy {
    output: File,
    temporary: std::path::PathBuf,
}

impl StagedCopy {
    fn create(
        input: &mut File,
        original: &std::fs::Metadata,
        destination: &Path,
        suffix: &str,
        progress: &mut dyn FnMut(RepairProgress),
    ) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::symlink_metadata(destination) {
            Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut temporary = destination.as_os_str().to_owned();
        temporary.push(suffix);
        let temporary = std::path::PathBuf::from(temporary);
        let mut output =
            OpenOptions::new().create_new(true).read(true).write(true).mode(PRIVATE_FILE_MODE).open(&temporary)?;
        let copied = copy_image(input, &mut output, original.len().div_ceil(NTFS_SECTOR_BYTES as u64), progress)?;
        if copied != original.len() || input.metadata()?.modified()? != original.modified()? {
            return Err(reject("source changed during copy"));
        }
        output.sync_all()?;
        parent_directory(destination)?.sync_all()?;
        Ok(Self { output, temporary })
    }
}

/// Publish a validated staged copy; hard_link never replaces a racing destination.
fn publish_staged(output: &File, temporary: &Path, destination: &Path) -> io::Result<()> {
    output.sync_all()?;
    let parent = parent_directory(destination)?;
    std::fs::hard_link(temporary, destination)?;
    parent.sync_all()?;
    std::fs::remove_file(temporary)?;
    parent.sync_all()
}

fn parent_directory(path: &Path) -> io::Result<File> {
    File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))
}

// Image-copy callers retain source-stability checks and durable publication.
fn copy_image(
    input: &mut File,
    output: &mut File,
    total: u64,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<u64> {
    let mut copied = 0_u64;
    let mut buffer = vec![0; IMAGE_COPY_BUFFER_BYTES];
    progress(RepairProgress::new(Phase::Copy, 0, total));
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            return Ok(copied);
        }
        output.write_all(&buffer[..n])?;
        copied += n as u64;
        progress(RepairProgress::new(Phase::Copy, copied.div_ceil(NTFS_SECTOR_BYTES as u64), total));
    }
}

fn repair_to_with_maintenance(
    source: &Path,
    destination: &Path,
    stop_after: Option<usize>,
    progress: &mut dyn FnMut(RepairProgress),
    bad: Option<&File>,
    options: RepairOptions,
) -> io::Result<()> {
    let mut input = File::open(source)?;
    let original = input.metadata()?;
    if !original.is_file() {
        return Err(reject("source must be an offline regular image file"));
    }
    // Replay the supported native/Slate history on the private copy before
    // deriving structural repairs. Never discard an unrecognized journal.
    let replay = checker::probe(source)
        .ok()
        .and_then(|p| checker::inspect_recovery(Image::open(source).ok()?, p.boot).ok())
        .is_some_and(|r| r.log == ntfs_rs::logfile::LogState::ReplayRequired);
    let replay_plan = if replay { Some(plan(source)?) } else { None };
    let planned = if replay {
        None
    } else {
        Some(structural_repair_plan(source, progress, PlanInputs { bad, options, ..Default::default() })?)
    };
    if stop_after.is_some_and(|n| n == 0 || planned.as_ref().is_some_and(|p| n > p.len() + 1)) {
        return Err(reject("test flush boundary is outside this repair plan"));
    }
    let StagedCopy { mut output, temporary, .. } =
        StagedCopy::create(&mut input, &original, destination, ".repair-incomplete", progress)?;
    let temporary = temporary.as_path();
    let mut flushes = 0;
    flush(&mut output, &mut flushes, stop_after)?;
    if let Some(replay_plan) = replay_plan {
        progress(RepairProgress::new(Phase::Replay, 0, 0));
        if !plan(temporary)?.matches(&replay_plan)? {
            return Err(reject("copied journal changed"));
        }
        recover_created_copy(temporary, &mut output, &mut flushes, stop_after)?;
    }
    // Recovery directories use the pre-copy plan's creation time, so the
    // independently checked copy must still match every planned physical byte.
    let actual = structural_repair_plan(
        temporary,
        progress,
        PlanInputs {
            bad,
            options,
            recovery_created: planned.as_ref().map(|plan| plan.recovery_created),
            ..Default::default()
        },
    )?;
    if let Some(expected) = planned {
        if !expected.matches(&actual)? {
            return Err(reject("copied image does not match the repair plan"));
        }
    }
    let planned = actual;
    let total = planned.iter().try_fold(0_u64, |total, patch| -> io::Result<u64> {
        let p = patch?;
        total
            .checked_add((p.physical % 512 + p.after.len() as u64).div_ceil(512))
            .ok_or_else(|| reject("repair work overflow"))
    })?;
    let mut done = 0;
    progress(RepairProgress::new(Phase::Repair, 0, total));
    for patch in planned.iter() {
        let patch = patch?;
        patch.apply_to(&output, "allocation preimage changed")?;
        flush(&mut output, &mut flushes, stop_after)?;
        done += (patch.physical % 512 + patch.after.len() as u64).div_ceil(512);
        progress(RepairProgress::new(Phase::Repair, done, total));
    }
    progress(RepairProgress::new(Phase::Verification, 0, 0));
    if !structural_repair_plan(temporary, progress, PlanInputs { options, ..Default::default() })?.is_empty() {
        return Err(reject("post-repair allocation audit failed"));
    }
    progress(RepairProgress::new(Phase::Publication, 0, 0));
    publish_staged(&output, temporary, destination)?;
    progress(RepairProgress::new(Phase::Complete, total, total));
    Ok(())
}

// CRC-64/ECMA protects the external repair journal against torn/truncated
// storage. This is not an NTFS attribute or a change to the NTFS log format.
fn repair_checksum(mut crc: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        crc ^= u64::from(byte) << 56;
        for _ in 0..8 {
            crc = (crc << 1) ^ if crc >> 63 != 0 { 0x42f0e1eba9ea3693 } else { 0 };
        }
    }
    crc
}

// Saved good bytes remain authoritative when the source becomes unreadable.
// Every newly confirmed failed interval is staged for durable error history.
fn verify_rescue_payload<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    saved: &[u8],
    sector: u32,
    failed: &mut dyn FnMut(u64, u64) -> io::Result<()>,
) -> io::Result<()> {
    for (index, saved) in saved.chunks(sector as usize).enumerate() {
        let at = offset + index as u64 * u64::from(sector);
        scan_surface_reader(
            input,
            at..at + u64::from(sector),
            sector,
            &mut |_, current| {
                if current != saved {
                    return Err(reject("rescue source changed; retained data preserved"));
                }
                Ok(())
            },
            failed,
            &mut |_| {},
        )?;
    }
    Ok(())
}

/// Preserve readable sectors in an external, checksummed rescue archive.
/// The archive is NOT a mountable volume: failed ranges have explicit records
/// and no fabricated payload. Resume authenticates the archive and retries only
/// ranges without a durable good copy. Returns the unresolved 512-byte sectors.
pub fn rescue_to_with_progress(
    source: &Path,
    archive: &Path,
    resume: bool,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<u64> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    };
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
        fn geteuid() -> u32;
    }
    let (mut input, length, sector) = open_surface_source(source)?;
    let identity = input.metadata()?;
    let parent = File::open(archive.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
    if identity.file_type().is_block_device() && parent.metadata()?.dev() == identity.rdev() {
        return Err(reject("rescue archive must reside outside the damaged device"));
    }
    let mut expected = b"SLTRSC01".to_vec();
    for word in [
        length,
        identity.dev(),
        identity.ino(),
        identity.rdev(),
        if identity.is_file() { identity.mtime() as u64 } else { 0 },
        if identity.is_file() { identity.mtime_nsec() as u64 } else { 0 },
        u64::from(sector),
    ] {
        expected.extend_from_slice(&word.to_le_bytes());
    }
    expected.extend_from_slice(&repair_checksum(0, &expected).to_le_bytes());
    let mut options = OpenOptions::new();
    options.read(true).write(true).custom_flags(libc::O_NOFOLLOW).mode(PRIVATE_FILE_MODE);
    if !resume {
        options.create_new(true);
    }
    let mut output = options.open(archive)?;
    let meta = output.metadata()?;
    if !meta.is_file()
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { geteuid() }
        || (meta.dev(), meta.ino()) == (identity.dev(), identity.ino())
    {
        return Err(reject("unsafe rescue archive"));
    }
    if unsafe { flock(output.as_raw_fd(), 2 | 4) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if resume {
        let mut header = vec![0; expected.len()];
        output.read_exact(&mut header)?;
        if header != expected {
            return Err(reject("rescue archive source identity/geometry mismatch"));
        }
    } else {
        output.write_all(&expected)?;
        output.sync_all()?;
        parent.sync_all()?;
    }
    let total = length / 512;
    let mut coverage = checker::consistency::scratch_file()?;
    coverage.set_len(total.div_ceil(8))?;
    // A sparse disk bitmap records durable good sectors; it is never held in RAM.
    fn covered(file: &mut File, offset: u64, bytes: u64, mark: bool) -> io::Result<u64> {
        let first = offset / 512;
        let end = first + bytes / 512;
        let start = first / 8;
        let size = (end.div_ceil(8) - start) as usize;
        let mut bits = [0_u8; 17];
        if size > bits.len() {
            return Err(reject("rescue coverage range too large"));
        }
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut bits[..size])?;
        let mut count = 0;
        for bit in first..end {
            let index = (bit / 8 - start) as usize;
            let mask = 1 << (bit % 8);
            if bits[index] & mask != 0 {
                count += 1;
            }
            if mark {
                bits[index] |= mask;
            }
        }
        if mark {
            file.seek(SeekFrom::Start(start))?;
            file.write_all(&bits[..size])?;
        }
        Ok(count)
    }
    let mut buffer = [0; 65536];
    let mut recovered = 0;
    let archive_length = output.metadata()?.len();
    let mut error_history = checker::consistency::DiskInventory::new();
    let mut position = expected.len() as u64;
    // Only an incomplete trailing append is truncated. A complete record with
    // a bad checksum is evidence of corruption, and is retained/refused.
    while position < archive_length {
        if archive_length - position < 32 {
            output.set_len(position)?;
            output.sync_all()?;
            break;
        }
        output.seek(SeekFrom::Start(position))?;
        let mut header = [0; 32];
        output.read_exact(&mut header)?;
        let offset = u64_at(&header, 0)?;
        let size = u64_at(&header, 8)?;
        let status = u64_at(&header, 16)?;
        if size == 0
            || size > 65536
            || size % u64::from(sector) != 0
            || offset % u64::from(sector) != 0
            || offset.checked_add(size).is_none_or(|end| end > length)
            || ![0, 5].contains(&status)
        {
            return Err(reject("invalid rescue archive range/status"));
        }
        let payload = if status == 0 { size as usize } else { 0 };
        if archive_length - position - 32 < payload as u64 {
            output.set_len(position)?;
            output.sync_all()?;
            break;
        }
        output.read_exact(&mut buffer[..payload])?;
        let crc = repair_checksum(repair_checksum(0, &header[..24]), &buffer[..payload]);
        if crc != u64_at(&header, 24)? {
            return Err(reject("rescue record checksum mismatch; archive preserved"));
        }
        if status == 0 {
            // Device identity alone cannot prove that another OS did not write
            // the volume between rescue attempts. Compare every still-readable
            // sector with its retained copy while the source claim is held.
            verify_rescue_payload(&mut input, offset, &buffer[..payload], sector, &mut |at, bytes| {
                error_history.push([at, bytes, 0, 0])
            })?;
            recovered += size / 512 - covered(&mut coverage, offset, size, true)?;
        }
        position += 32 + payload as u64;
    }
    output.seek(SeekFrom::End(0))?;
    // Retained good bytes remain authority, but a later failed source read is
    // also durable evidence for cluster retirement. Validate old records first.
    let mut history = error_history.finish()?;
    while let Some(row) = checker::consistency::inventory_next(&mut history)? {
        let mut entry = Vec::with_capacity(32);
        for word in [row[0], row[1], 5] {
            entry.extend_from_slice(&word.to_le_bytes());
        }
        entry.extend_from_slice(&repair_checksum(0, &entry).to_le_bytes());
        output.write_all(&entry)?;
    }
    output.sync_all()?;
    progress(RepairProgress::new(Phase::Copy, recovered, total));
    fn append_entry(
        output: &mut File,
        coverage: &mut File,
        recovered: &mut u64,
        at: u64,
        size: u64,
        payload: &[u8],
    ) -> io::Result<()> {
        let status = if payload.is_empty() { 5_u64 } else { 0 };
        let mut entry = Vec::with_capacity(32);
        for word in [at, size, status] {
            entry.extend_from_slice(&word.to_le_bytes());
        }
        entry.extend_from_slice(&repair_checksum(repair_checksum(0, &entry), payload).to_le_bytes());
        output.write_all(&entry)?;
        output.write_all(payload)?;
        output.sync_all()?;
        if status == 0 {
            *recovered += size / 512 - covered(coverage, at, size, true)?;
        }
        Ok(())
    }
    let mut offset = 0;
    while offset < length {
        let size = (length - offset).min(buffer.len() as u64);
        let good = covered(&mut coverage, offset, size, false)?;
        if good != size / 512 {
            let stride = if good == 0 { size } else { u64::from(sector) };
            let mut at = offset;
            while at < offset + size {
                if covered(&mut coverage, at, stride, false)? != stride / 512 {
                    // Both callbacks write the same archive in scanner order.
                    // A borrowed tuple keeps their shared state local and small.
                    let state = std::cell::RefCell::new((&mut output, &mut coverage, &mut recovered));
                    scan_surface_reader(
                        &mut input,
                        at..at + stride,
                        sector,
                        &mut |physical, bytes| {
                            for (index, bytes) in bytes.chunks(65536).enumerate() {
                                let mut state = state.borrow_mut();
                                let (output, coverage, recovered) = &mut *state;
                                append_entry(
                                    output,
                                    coverage,
                                    recovered,
                                    physical + index as u64 * 65536,
                                    bytes.len() as u64,
                                    bytes,
                                )?;
                            }
                            Ok(())
                        },
                        &mut |physical, bytes| {
                            let mut done = 0;
                            while done < bytes {
                                let size = (bytes - done).min(65536);
                                let mut state = state.borrow_mut();
                                let (output, coverage, recovered) = &mut *state;
                                append_entry(output, coverage, recovered, physical + done, size, &[])?;
                                done += size;
                            }
                            Ok(())
                        },
                        &mut |_| {},
                    )?;
                    progress(RepairProgress::new(Phase::Copy, recovered, total));
                }
                at += stride;
            }
        }
        offset += size;
    }
    let now = input.metadata()?;
    if identity.is_file()
        && (now.len(), now.mtime(), now.mtime_nsec()) != (identity.len(), identity.mtime(), identity.mtime_nsec())
    {
        return Err(reject("source changed during rescue; archive retained for review"));
    }
    let path_identity = std::fs::metadata(source)?;
    if image_length(&input)? != length
        || (now.dev(), now.ino(), now.rdev(), now.ctime(), now.ctime_nsec())
            != (identity.dev(), identity.ino(), identity.rdev(), identity.ctime(), identity.ctime_nsec())
        || (path_identity.dev(), path_identity.ino(), path_identity.rdev())
            != (identity.dev(), identity.ino(), identity.rdev())
    {
        return Err(reject("source identity changed during rescue; archive retained"));
    }
    output.sync_all()?;
    progress(RepairProgress::new(if recovered == total { Phase::Complete } else { Phase::Failed }, recovered, total));
    Ok(total - recovered)
}

/// Extract a complete sector rescue archive to a new image. An incomplete
/// archive remains evidence, not a filesystem image: missing sectors are never
/// silently represented by sparse-file zeros. The final name is published only
/// after every sector, duplicate and checksum has been checked twice.
pub fn extract_rescue_to(archive: &Path, destination: &Path) -> io::Result<u64> {
    extract_rescue_image(archive, destination, false).map(|image| image.good_sectors)
}

struct RescueImage {
    good_sectors: u64,
    sector: u64,
    length: u64,
    locations: File,
    archive_header: [u8; 72],
    archive_checksum: u64,
}

// Missing bytes are allowed only in private recovery scratch. Its caller must
// prove their ownership and publish an explicit loss map before any final image.
fn extract_rescue_image(archive: &Path, destination: &Path, allow_missing: bool) -> io::Result<RescueImage> {
    use std::os::unix::fs::OpenOptionsExt;
    let input = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(archive)?;
    extract_rescue_file(input, destination, allow_missing)
}

fn extract_rescue_file(mut input: File, destination: &Path, allow_missing: bool) -> io::Result<RescueImage> {
    use std::os::unix::fs::OpenOptionsExt;
    // Each hook models an interruption immediately after a publication step.
    // It is inert unless the disposable-image matrix explicitly enables it.
    let stop_after = std::env::var("SLATE_NTFS_TEST_RESCUE_STOP_AFTER")
        .ok()
        .map(|value| value.parse::<u8>().map_err(|_| reject("invalid rescue stop point")))
        .transpose()?;
    let stop = |step| -> io::Result<()> {
        if stop_after == Some(step) {
            Err(reject("injected rescue publication interruption"))
        } else {
            Ok(())
        }
    };
    input.seek(SeekFrom::Start(0))?;
    if !input.metadata()?.is_file() {
        return Err(reject("rescue archive must be a regular file"));
    }
    let mut header = [0_u8; 72];
    input.read_exact(&mut header)?;
    if &header[..8] != b"SLTRSC01" || repair_checksum(0, &header[..64]) != u64_at(&header, 64)? {
        return Err(reject("invalid rescue archive header"));
    }
    let length = u64_at(&header, 8)?;
    let sector = u64_at(&header, 56)?;
    if length == 0 || !(512..=65536).contains(&sector) || !sector.is_power_of_two() || length % sector != 0 {
        return Err(reject("invalid rescue archive geometry"));
    }
    let total = length / sector;
    let mut locations = checker::consistency::scratch_file()?;
    locations.set_len(total.checked_mul(8).ok_or_else(|| reject("rescue map overflow"))?)?;
    let archive_length = input.metadata()?.len();
    let mut first_pass_crc = 0_u64;
    let mut good = 0_u64;
    for pass in 0..2 {
        input.seek(SeekFrom::Start(72))?;
        let mut position = 72_u64;
        let mut pass_crc = 0_u64;
        let mut buffer = [0_u8; 65536];
        while position < archive_length {
            if archive_length - position < 32 {
                return Err(reject("incomplete rescue archive tail"));
            }
            let mut entry = [0_u8; 32];
            input.read_exact(&mut entry)?;
            let offset = u64_at(&entry, 0)?;
            let size = u64_at(&entry, 8)?;
            let status = u64_at(&entry, 16)?;
            if size == 0
                || size > 65536
                || size % sector != 0
                || offset % sector != 0
                || offset.checked_add(size).is_none_or(|end| end > length)
                || ![0, 5].contains(&status)
            {
                return Err(reject("invalid rescue archive entry"));
            }
            let payload = if status == 0 { size as usize } else { 0 };
            if archive_length - position - 32 < payload as u64 {
                return Err(reject("incomplete rescue archive payload"));
            }
            input.read_exact(&mut buffer[..payload])?;
            if repair_checksum(repair_checksum(0, &entry[..24]), &buffer[..payload]) != u64_at(&entry, 24)? {
                return Err(reject("rescue archive checksum mismatch"));
            }
            pass_crc = repair_checksum(pass_crc, &entry);
            pass_crc = repair_checksum(pass_crc, &buffer[..payload]);
            if status == 0 {
                for (index, bytes) in buffer[..payload].chunks(sector as usize).enumerate() {
                    let sector_number = offset / sector + index as u64;
                    locations.seek(SeekFrom::Start(sector_number * 8))?;
                    let mut saved = [0_u8; 8];
                    locations.read_exact(&mut saved)?;
                    let previous = u64::from_le_bytes(saved);
                    if previous == 0 || previous == u64::MAX {
                        if pass == 0 {
                            locations.seek(SeekFrom::Current(-8))?;
                            locations.write_all(&(position + 33 + index as u64 * sector).to_le_bytes())?;
                            good += 1;
                        } else {
                            return Err(reject("rescue archive changed during extraction"));
                        }
                    } else if pass == 0 {
                        let next = input.stream_position()?;
                        input.seek(SeekFrom::Start(previous - 1))?;
                        let mut original = vec![0_u8; sector as usize];
                        input.read_exact(&mut original)?;
                        input.seek(SeekFrom::Start(next))?;
                        if original != bytes {
                            return Err(reject("conflicting rescue copies of one sector"));
                        }
                    }
                }
            }
            if status == 5 && pass == 0 {
                for number in offset / sector..(offset + size) / sector {
                    locations.seek(SeekFrom::Start(number * 8))?;
                    let mut saved = [0; 8];
                    locations.read_exact(&mut saved)?;
                    if saved == [0; 8] {
                        locations.seek(SeekFrom::Current(-8))?;
                        locations.write_all(&u64::MAX.to_le_bytes())?;
                    }
                }
            }
            position += 32 + payload as u64;
        }
        if pass == 0 {
            first_pass_crc = pass_crc;
            if good != total && !allow_missing {
                return Err(reject("rescue archive lacks sectors; no image published"));
            }
            // The second pass verifies the same archive bytes before creating an
            // output. The source archive is never modified by extraction.
        } else if pass_crc != first_pass_crc {
            return Err(reject("rescue archive changed during extraction"));
        }
    }
    stop(1)?; // Archive validated twice; no output created.
    let parent_path = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = File::open(parent_path)?;
    let name = destination.file_name().ok_or_else(|| reject("invalid rescue output name"))?;
    let (temporary, mut target) = (0..1000)
        .find_map(|attempt| {
            let mut candidate = name.to_os_string();
            candidate.push(format!(".rescue-incomplete-{}-{attempt}", std::process::id()));
            let path = parent_path.join(candidate);
            match OpenOptions::new().read(true).write(true).create_new(true).mode(PRIVATE_FILE_MODE).open(&path) {
                Ok(file) => Some(Ok((path, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .ok_or_else(|| reject("no private rescue output name available"))??;
    stop(2)?; // Private output name exists, but cannot be mistaken for success.
    target.set_len(length)?;
    input.seek(SeekFrom::Start(72))?;
    let mut position = 72_u64;
    let mut copied_crc = 0_u64;
    let mut buffer = [0_u8; 65536];
    while position < archive_length {
        let mut entry = [0_u8; 32];
        input.read_exact(&mut entry)?;
        let offset = u64_at(&entry, 0)?;
        let payload = if u64_at(&entry, 16)? == 0 { u64_at(&entry, 8)? as usize } else { 0 };
        input.read_exact(&mut buffer[..payload])?;
        copied_crc = repair_checksum(copied_crc, &entry);
        copied_crc = repair_checksum(copied_crc, &buffer[..payload]);
        if payload != 0 {
            target.seek(SeekFrom::Start(offset))?;
            target.write_all(&buffer[..payload])?;
        }
        position += 32 + payload as u64;
    }
    if copied_crc != first_pass_crc {
        return Err(reject("rescue archive changed; incomplete output retained separately"));
    }
    target.sync_all()?;
    stop(3)?; // Complete private output is durable; final name absent.
    std::fs::hard_link(&temporary, destination)?;
    stop(4)?; // Final name points only to a complete, synced image.
    parent.sync_all()?;
    stop(5)?; // Final name is durable; private name may remain.
    std::fs::remove_file(temporary)?;
    parent.sync_all()?;
    Ok(RescueImage {
        good_sectors: good * sector / 512,
        sector,
        length,
        locations,
        archive_header: header,
        archive_checksum: first_pass_crc,
    })
}

// Read the authenticated archive after resume. Every recorded EIO is evidence
// that its containing cluster should be retired, even if a later read recovered
// the bytes. The returned inventory is sorted on disk, not kept in memory.
fn rescue_bad_clusters(mut input: File, expected_length: u64, cluster_bytes: u32) -> io::Result<File> {
    input.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; 72];
    input.read_exact(&mut header)?;
    if &header[..8] != b"SLTRSC01"
        || repair_checksum(0, &header[..64]) != u64_at(&header, 64)?
        || u64_at(&header, 8)? != expected_length
    {
        return Err(reject("rescue archive identity changed before bad-cluster planning"));
    }
    let sector = u64_at(&header, 56)?;
    if sector == 0 || sector > u64::from(cluster_bytes) || u64::from(cluster_bytes) % sector != 0 {
        return Err(reject("rescue sector geometry does not fit NTFS clusters"));
    }
    let mut inventory = checker::consistency::DiskInventory::new();
    let mut bytes = [0_u8; 65536];
    let archive_length = input.metadata()?.len();
    let mut position = 72_u64;
    while position < archive_length {
        if archive_length - position < 32 {
            return Err(reject("truncated rescue entry"));
        }
        let mut entry = [0_u8; 32];
        input.read_exact(&mut entry)?;
        let offset = u64_at(&entry, 0)?;
        let length = u64_at(&entry, 8)?;
        let status = u64_at(&entry, 16)?;
        if length == 0
            || length > 65536
            || length % sector != 0
            || offset % sector != 0
            || offset.checked_add(length).is_none_or(|end| end > expected_length)
            || ![0, 5].contains(&status)
        {
            return Err(reject("invalid rescue entry geometry/status"));
        }
        let payload = if status == 0 { length as usize } else { 0 };
        if archive_length - position - 32 < payload as u64 {
            return Err(reject("truncated rescue payload"));
        }
        input.read_exact(&mut bytes[..payload])?;
        if repair_checksum(repair_checksum(0, &entry[..24]), &bytes[..payload]) != u64_at(&entry, 24)? {
            return Err(reject("rescue entry checksum changed"));
        }
        if status == 5 {
            let first = offset / u64::from(cluster_bytes);
            let last = (offset + length - 1) / u64::from(cluster_bytes);
            for cluster in first..=last {
                inventory.push([cluster, 0, 0, 0])?;
            }
        }
        position += 32 + payload as u64;
    }
    inventory.finish()
}

/// Retry unresolved archive sectors against the same source identity, then
/// publish a complete physical image without changing NTFS mappings.
pub fn reintegrate_rescue_to(
    source: &Path,
    archive: &Path,
    destination: &Path,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<u64> {
    let missing = rescue_to_with_progress(source, archive, true, progress)?;
    if missing != 0 {
        return Err(reject("rescue still has unreadable sectors; no image published"));
    }
    extract_rescue_to(archive, destination)
}

/// Recover readable sectors privately, retire prior EIO clusters in $BadClus:$Bad,
/// and relocate their surviving owners. Publish only after the full structural
/// audit; unsupported ownership retains private evidence without publishing
/// the requested destination.
pub fn repair_rescue_to(
    source: &Path,
    archive: &Path,
    destination: &Path,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<u64> {
    let missing = rescue_to_with_progress(source, archive, true, progress)?;
    if missing != 0 {
        return Err(reject("rescue still has unreadable sectors; no image published"));
    }
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = destination.file_name().ok_or_else(|| reject("invalid rescue output name"))?;
    let private = (0..1000)
        .find_map(|attempt| {
            let mut candidate = name.to_os_string();
            candidate.push(format!(".rescue-source-{}-{attempt}", std::process::id()));
            let path = parent.join(candidate);
            if path.exists() {
                None
            } else {
                Some(path)
            }
        })
        .ok_or_else(|| reject("no private rescue source name available"))?;
    let sectors = extract_rescue_to(archive, &private)?;
    let boot = checker::probe(&private)?.boot;
    let length = image_length(&File::open(&private)?)?;
    let bad = rescue_bad_clusters(File::open(archive)?, length, boot.cluster_bytes)?;
    repair_to_with_maintenance(&private, destination, None, progress, Some(&bad), RepairOptions::default())?;
    std::fs::remove_file(&private)?;
    File::open(parent)?.sync_all()?;
    Ok(sectors)
}

/// A metadata-consistent output can still contain explicitly documented file
/// loss. Recovered bytes count authenticated physical source payload, never
/// zero replacements or a guarantee of decoded plaintext integrity.
#[derive(Debug)]
pub struct FileRecoveryReport {
    pub recovered_bytes: u64,
    pub unreadable_bytes: u64,
    pub lost_file_bytes: u64,
    pub encoded_storage_loss_bytes: u64,
    pub affected_compressed_bytes: u64,
}

impl FileRecoveryReport {
    pub fn has_data_loss(&self) -> bool {
        self.lost_file_bytes != 0 || self.encoded_storage_loss_bytes != 0 || self.affected_compressed_bytes != 0
    }
}

pub fn recover_rescue_to(
    source: &Path,
    archive: &Path,
    loss_map: &Path,
    destination: &Path,
    resume: bool,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<FileRecoveryReport> {
    rescue_to_with_progress(source, archive, resume, progress)?;
    recover_archive_to(archive, loss_map, destination, progress)
}

struct PreparedRecovery {
    plan: RepairPlan,
    report: FileRecoveryReport,
    template: std::path::PathBuf,
    archive: File,
    archive_header: [u8; 72],
    archive_checksum: u64,
    loss_map: File,
    loss_map_checksum: u64,
    locations: File,
    bad: File,
    sector: u64,
    length: u64,
    boot: ntfs_rs::boot::BootSector,
    image_checksum: u64,
}

// Copy recovery and guarded device recovery share one classifier and plan.
// This wrapper publishes only after the plan's authenticated preimages, final
// audit and loss-map-bound image digest have all been checked on the copy.
fn recover_archive_to(
    archive: &Path,
    loss_map: &Path,
    destination: &Path,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<FileRecoveryReport> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let prepared = prepare_archive_recovery(archive, loss_map, destination, progress)?;
    let ready = recovery_private_name(destination, "recovery-ready")?;
    let mut input = File::open(&prepared.template)?;
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(PRIVATE_FILE_MODE)
        .open(&ready)?;
    if io::copy(&mut input, &mut output)? != prepared.length {
        return Err(reject("recovery template changed during copy"));
    }
    for patch in prepared.plan.iter() {
        let patch = patch?;
        patch.apply_to(&output, "recovery copy preimage changed")?;
    }
    output.sync_all()?;
    if !structural_repair_plan(&ready, progress, PlanInputs::default())?.is_empty() {
        return Err(reject("recovery copy final audit failed"));
    }
    if recovery_file_checksum(&mut output)? != prepared.image_checksum {
        return Err(reject("recovery copy differs from its durable loss map"));
    }
    let map_identity = prepared.loss_map.metadata()?;
    let published_identity = std::fs::symlink_metadata(loss_map)?;
    if published_identity.dev() != map_identity.dev()
        || published_identity.ino() != map_identity.ino()
        || recovery_file_checksum(&prepared.loss_map)? != prepared.loss_map_checksum
    {
        return Err(reject("published recovery loss map changed before image publication"));
    }
    let parent_path = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = File::open(parent_path)?;
    match std::fs::hard_link(&ready, destination) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut old = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(destination)?;
            if old.metadata()?.mode() & 0o077 != 0 || old.metadata()?.uid() != unsafe { libc::geteuid() } {
                return Err(reject("unsafe existing recovery image"));
            }
            output.seek(SeekFrom::Start(0))?;
            compare_recovery_files(&mut old, &mut output)?;
        }
        Err(error) => return Err(error),
    }
    parent.sync_all()?;
    recovery_publication_stop("image-published")?;
    std::fs::remove_file(&prepared.template)?;
    std::fs::remove_file(ready)?;
    parent.sync_all()?;
    Ok(prepared.report)
}

fn recovery_publication_stop(step: &str) -> io::Result<()> {
    if std::env::var("SLATE_NTFS_TEST_FILE_RECOVERY_STOP_AFTER").ok().as_deref() == Some(step) {
        Err(reject("injected file recovery publication interruption"))
    } else {
        Ok(())
    }
}

// Only the fixed summary prefix is needed after a journal has authenticated
// the whole retained map. An attacker-sized row cannot grow this parser's RAM.
fn read_recovery_report(map: &mut File) -> io::Result<FileRecoveryReport> {
    map.seek(SeekFrom::Start(0))?;
    let mut prefix = [0; 1024];
    let n = map.read(&mut prefix)?;
    let text = std::str::from_utf8(&prefix[..n]).map_err(|_| reject("invalid recovery loss map text"))?;
    let mut lines = text.lines();
    let schema = match lines.next() {
        Some("SLATE_FILE_RECOVERY_LOSS_MAP 1") => 1,
        Some("SLATE_FILE_RECOVERY_LOSS_MAP 2") => 2,
        _ => return Err(reject("unsupported recovery loss map schema")),
    };
    let source = lines.next().ok_or_else(|| reject("missing recovery source identity"))?;
    if !source.starts_with("source_header=") || source.len() != 158 {
        return Err(reject("invalid recovery source identity"));
    }
    let image = lines.next().ok_or_else(|| reject("missing recovery image summary"))?;
    let number = |fields: &str, key: &str| -> io::Result<u64> {
        fields
            .split_whitespace()
            .find_map(|field| field.strip_prefix(key))
            .ok_or_else(|| reject("missing recovery byte count"))?
            .parse()
            .map_err(|_| reject("invalid recovery byte count"))
    };
    let length = number(image, "image_bytes=")?;
    let summary = lines.next().ok_or_else(|| reject("missing recovery byte summary"))?;
    let report = FileRecoveryReport {
        recovered_bytes: number(summary, "recovered_bytes=")?,
        unreadable_bytes: number(summary, "unreadable_bytes=")?,
        lost_file_bytes: number(summary, "lost_file_bytes=")?,
        encoded_storage_loss_bytes: if schema == 2 { number(summary, "encoded_storage_loss_bytes=")? } else { 0 },
        affected_compressed_bytes: if schema == 2 { number(summary, "affected_compressed_bytes=")? } else { 0 },
    };
    if report.recovered_bytes.checked_add(report.unreadable_bytes) != Some(length)
        || report.lost_file_bytes > length
        || report.encoded_storage_loss_bytes > report.unreadable_bytes
    {
        return Err(reject("inconsistent recovery byte summary"));
    }
    let status = lines.next().ok_or_else(|| reject("missing recovery loss status"))?;
    if number(status, "metadata_consistent=")? != 1
        || number(status, "surface_clean=")? != 0
        || number(status, "data_loss=")? != u64::from(report.has_data_loss())
    {
        return Err(reject("inconsistent recovery loss status"));
    }
    Ok(report)
}

// Authenticated sector locations distinguish absent bytes from genuine zero
// payload. Only checked free space and uniquely owned supported nonresident DATA may be
// represented by zeros in the private proposal; metadata remains mandatory.
fn prepare_archive_recovery(
    archive: &Path,
    loss_map: &Path,
    work_base: &Path,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<PreparedRecovery> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let mut archive_claim = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(archive)?;
    if !archive_claim.metadata()?.is_file()
        || unsafe { libc::flock(archive_claim.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0
    {
        return Err(reject("recovery archive cannot be claimed for reading"));
    }
    let private = recovery_private_name(work_base, "recovery-source")?;
    let mut image = extract_rescue_file(archive_claim.try_clone()?, &private, true)?;
    let boot = checker::probe(&private)?.boot;
    let cluster = u64::from(boot.cluster_bytes);
    if image.sector > cluster || cluster % image.sector != 0 {
        return Err(reject("recovery sector does not fit an NTFS cluster"));
    }
    // Allocation and family ownership must already agree. Structural recovery
    // cannot invent unreadable metadata to authorize a lossy file rewrite.
    let audit = checker::consistency::audit(&private, boot, Default::default())?;
    if !audit.complete || audit.errors != 0 {
        return Err(reject("unreadable or inconsistent metadata prevents file recovery"));
    }
    let mut volume = Volume::new(Image(File::open(&private)?), boot)?;
    let zero = checker::consistency::mft_image(&mut volume)?;
    let mft = MftRecord::from_decoded(&zero)?;
    let mut ownership = repair_owned_ranges(&mut volume, &mft)?;
    let bitmap_image = checked_family_image(&mut volume, &mft, 6)?;
    let bitmap_record = MftRecord::from_decoded(&bitmap_image)?;
    let allocation = bitmap_record.stream(ATTR_DATA, &[])?;
    let clusters = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let mut allocation_cache = (u64::MAX, [0; 8192]);
    let mut owner = checker::consistency::inventory_next(&mut ownership)?;
    let mut next_owner = checker::consistency::inventory_next(&mut ownership)?;
    let mut rows = checker::consistency::scratch_file()?;
    let mut lost_file_bytes = 0_u64;
    let mut encoded_storage_loss_bytes = 0_u64;
    let mut affected_compressed_bytes = 0_u64;
    let mut compressed_units = checker::consistency::DiskInventory::new();
    let mut unresolved_clusters = checker::consistency::DiskInventory::new();
    let mut raw = vec![0; boot.record_bytes as usize];
    for physical in (0..image.length).step_by(image.sector as usize) {
        image.locations.seek(SeekFrom::Start(physical / image.sector * 8))?;
        let mut location = [0; 8];
        image.locations.read_exact(&mut location)?;
        if location == [0; 8] {
            return Err(reject("rescue archive has unattempted sectors; finish its surface scan first"));
        }
        if u64::from_le_bytes(location) != u64::MAX {
            continue;
        }
        let lcn = physical / cluster;
        if lcn >= clusters {
            return Err(reject("unreadable trailing volume metadata"));
        }
        unresolved_clusters.push([lcn, lcn + 1, 0, 0])?;
        while owner.is_some_and(|row| row[1] <= lcn) {
            owner = next_owner;
            next_owner = checker::consistency::inventory_next(&mut ownership)?;
        }
        if next_owner.is_some_and(|row| row[0] <= lcn) {
            return Err(reject("unreadable bytes have competing physical owners"));
        }
        let claim = owner.filter(|row| row[0] <= lcn && lcn < row[1]);
        let Some(claim) = claim else {
            if bitmap_byte(&mut volume, allocation, lcn / 8, clusters.div_ceil(8), &mut allocation_cache)?
                & (1 << (lcn % 8))
                != 0
            {
                return Err(reject("unreadable allocated cluster lacks a validated owner"));
            }
            writeln!(rows, "free\t0\t-\t0\t0\t{physical}\t{}", image.sector)?;
            continue;
        };
        volume.read_mft_record(&mft, claim[2], &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let attr = record
            .attributes()
            .collect::<ntfs_rs::Result<Vec<_>>>()?
            .into_iter()
            .find(|a| u64::from(a.id) == claim[3])
            .ok_or_else(|| reject("unreadable allocation owner disappeared"))?;
        let owner_number = match record.base_file_reference()? {
            0 => claim[2],
            reference => reference_number(reference),
        };
        let name = attr.name_utf16le()?.to_vec();
        if owner_number == 8 && attr.kind == ATTR_DATA && name == b"$\0B\0a\0d\0" {
            let family = RepairFamily::load(&mut volume, &mft, 8)?;
            let base = MftRecord::from_decoded(&family.logical)?;
            let bad = base
                .local_attribute(ATTR_DATA, &name)?
                .ok_or_else(|| reject("declared bad-cluster stream disappeared"))?;
            if !bad.nonresident
                || bad.flags()? & !0x8000 != 0
                || bad.data_size()? != clusters * cluster
                || bitmap_byte(&mut volume, allocation, lcn / 8, clusters.div_ceil(8), &mut allocation_cache)?
                    & (1 << (lcn % 8))
                    == 0
            {
                return Err(reject("invalid declared bad-cluster reservation"));
            }
            let mut declared = false;
            let mut end = 0;
            for run in ntfs_rs::runlist::DataRuns::new(bad.data_runs()?, 0) {
                let run = run?;
                if run.vcn != end || run.lcn.is_some_and(|physical| physical != run.vcn) {
                    return Err(reject("nonidentity declared bad-cluster mapping"));
                }
                end = run
                    .vcn
                    .checked_add(run.len)
                    .filter(|end| *end <= clusters)
                    .ok_or_else(|| reject("declared bad-cluster mapping exceeds volume"))?;
                declared |= run.lcn.is_some() && run.vcn <= lcn && lcn < end;
            }
            if end != clusters || !declared {
                return Err(reject("unreadable cluster is not a checked bad-cluster reservation"));
            }
            writeln!(rows, "declared-bad\t0\t-\t0\t0\t{physical}\t{}", image.sector)?;
            continue;
        }
        if owner_number < 16 || attr.kind != ATTR_DATA {
            return Err(reject("unreadable critical or non-DATA metadata cannot be zero filled"));
        }
        let family = RepairFamily::load(&mut volume, &mft, owner_number)?;
        let base = MftRecord::from_decoded(&family.logical)?;
        let stream = base
            .local_attribute(ATTR_DATA, &name)?
            .ok_or_else(|| reject("unreadable DATA stream has no complete family"))?;
        relocation::validate_data_stream(&family.logical, stream, boot)?;
        let flags = stream.flags()?;
        let mut logical = None;
        for run in ntfs_rs::runlist::DataRuns::new(stream.data_runs()?, 0) {
            let run = run?;
            if let Some(start) = run.lcn {
                let end = start
                    .checked_add(run.len)
                    .filter(|end| *end <= clusters)
                    .ok_or_else(|| reject("invalid recovery stream extent"))?;
                if start <= lcn && lcn < end {
                    logical = Some(
                        run.vcn
                            .checked_mul(cluster)
                            .and_then(|offset| offset.checked_add(physical - start * cluster))
                            .ok_or_else(|| reject("recovery logical interval overflow"))?,
                    );
                }
            }
        }
        let logical = logical.ok_or_else(|| reject("family does not own unreadable bytes"))?;
        let initialized = stream.initialized_size()?;
        let reference = owner_number | (u64::from(base.sequence_number()?) << 48);
        let encoded = flags & 0x4001 != 0;
        let lost = if encoded {
            encoded_storage_loss_bytes = encoded_storage_loss_bytes
                .checked_add(image.sector)
                .ok_or_else(|| reject("encoded storage loss count overflow"))?;
            0
        } else {
            initialized.saturating_sub(logical).min(image.sector)
        };
        if flags & 1 != 0 {
            let (start, end) = relocation::compressed_loss_range(&family.logical, stream, boot, lcn)?
                .ok_or_else(|| reject("compressed family does not own unreadable bytes"))?;
            let end = end.min(initialized);
            if start < end {
                compressed_units.push([reference, stream.record_offset() as u64, start, end])?;
            }
        }
        lost_file_bytes = lost_file_bytes.checked_add(lost).ok_or_else(|| reject("lost file byte count overflow"))?;
        let kind = if flags & 1 != 0 {
            "compressed-storage-loss"
        } else if flags & 0x4000 != 0 {
            "ciphertext-loss"
        } else if lost == 0 {
            "uninitialized"
        } else {
            "file-loss"
        };
        write!(rows, "{kind}\t{reference:016x}\t")?;
        if name.is_empty() {
            rows.write_all(b"-")?;
        } else {
            for byte in name {
                write!(rows, "{byte:02x}")?;
            }
        }
        writeln!(rows, "\t{logical}\t{lost}\t{physical}\t{}", image.sector)?;
    }
    // Physical encoded errors and decoded unit loss are separate evidence.
    // Sort on disk so repeated bad sectors cannot count the same unit twice.
    let mut units = compressed_units.finish()?;
    let mut previous = None;
    while let Some(unit) = checker::consistency::inventory_next(&mut units)? {
        if previous == Some(unit) {
            continue;
        }
        previous = Some(unit);
        let [reference, attribute_offset, start, end] = unit;
        affected_compressed_bytes = affected_compressed_bytes
            .checked_add(end - start)
            .ok_or_else(|| reject("compressed unit loss count overflow"))?;
        let family = RepairFamily::load(&mut volume, &mft, reference_number(reference))?;
        let base = MftRecord::from_decoded(&family.logical)?;
        let stream = base
            .attributes()
            .collect::<ntfs_rs::Result<Vec<_>>>()?
            .into_iter()
            .find(|attr| attr.kind == ATTR_DATA && attr.record_offset() as u64 == attribute_offset)
            .ok_or_else(|| reject("compressed loss stream identity disappeared"))?;
        write!(rows, "compressed-unit-zeroed\t{reference:016x}\t")?;
        let name = stream.name_utf16le()?;
        if name.is_empty() {
            rows.write_all(b"-")?;
        } else {
            for byte in name {
                write!(rows, "{byte:02x}")?;
            }
        }
        writeln!(rows, "\t{start}\t{}\t0\t0", end - start)?;
    }
    drop(volume);
    let bad = rescue_bad_clusters(archive_claim.try_clone()?, image.length, boot.cluster_bytes)?;
    let unresolved_clusters = unresolved_clusters.finish()?;
    let plan = structural_repair_plan(
        &private,
        progress,
        PlanInputs { bad: Some(&bad), unresolved: Some(&unresolved_clusters), ..Default::default() },
    )?;
    let mut proposed = PlannedImage { image: Image(File::open(&private)?), patches: &plan };
    let mut digest = 0_u64;
    let mut buffer = [0; 65536];
    let mut offset = 0;
    while offset < image.length {
        let n = (image.length - offset).min(buffer.len() as u64) as usize;
        proposed.read_exact_at(offset, &mut buffer[..n])?;
        digest = repair_checksum(digest, &buffer[..n]);
        offset += n as u64;
    }
    archive_claim.seek(SeekFrom::Start(0))?;
    let mut retained_header = [0; 72];
    archive_claim.read_exact(&mut retained_header)?;
    if retained_header != image.archive_header {
        return Err(reject("rescue archive identity changed during file recovery"));
    }
    let mut archive_digest = 0_u64;
    loop {
        let n = archive_claim.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        archive_digest = repair_checksum(archive_digest, &buffer[..n]);
    }
    if archive_digest != image.archive_checksum {
        return Err(reject("rescue archive changed during file recovery"));
    }
    let recovered_bytes = image.good_sectors * 512;
    let unreadable_bytes = image.length - recovered_bytes;
    let map_parent_path = loss_map.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let map_parent = File::open(map_parent_path)?;
    let map_private = recovery_private_name(loss_map, "recovery-incomplete")?;
    let mut map = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(PRIVATE_FILE_MODE)
        .open(&map_private)?;
    writeln!(map, "SLATE_FILE_RECOVERY_LOSS_MAP 2")?;
    write!(map, "source_header=")?;
    for byte in image.archive_header {
        write!(map, "{byte:02x}")?;
    }
    writeln!(map, "\nimage_bytes={} image_crc64={digest:016x}", image.length)?;
    writeln!(
        map,
        concat!(
            "recovered_bytes={} unreadable_bytes={} lost_file_bytes={} ",
            "encoded_storage_loss_bytes={} affected_compressed_bytes={}"
        ),
        recovered_bytes, unreadable_bytes, lost_file_bytes, encoded_storage_loss_bytes, affected_compressed_bytes,
    )?;
    writeln!(
        map,
        concat!(
            "metadata_consistent=1 data_loss={} surface_clean=0 ",
            "recovered_basis=authenticated_physical_source encoded_integrity=not_certified"
        ),
        u8::from(lost_file_bytes != 0 || encoded_storage_loss_bytes != 0 || affected_compressed_bytes != 0)
    )?;
    writeln!(
        map,
        concat!(
            "class\trecord_reference\tstream_utf16le_hex\tstream_offset_or_unit_start\t",
            "decoded_loss_bytes\tphysical_offset\tunreadable_bytes"
        )
    )?;
    rows.seek(SeekFrom::Start(0))?;
    io::copy(&mut rows, &mut map)?;
    map.sync_all()?;
    map_parent.sync_all()?;
    recovery_publication_stop("map-private")?;
    match std::fs::hard_link(&map_private, loss_map) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut old = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(loss_map)?;
            if !old.metadata()?.is_file()
                || old.metadata()?.mode() & 0o077 != 0
                || old.metadata()?.uid() != unsafe { libc::geteuid() }
            {
                return Err(reject("unsafe existing recovery loss map"));
            }
            map.seek(SeekFrom::Start(0))?;
            compare_recovery_files(&mut old, &mut map)?;
        }
        Err(error) => return Err(error),
    }
    map_parent.sync_all()?;
    recovery_publication_stop("map-published")?;
    let mut published_map = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(loss_map)?;
    let published_identity = published_map.metadata()?;
    if !published_identity.is_file()
        || published_identity.mode() & 0o077 != 0
        || published_identity.uid() != unsafe { libc::geteuid() }
    {
        return Err(reject("unsafe published recovery loss map"));
    }
    map.seek(SeekFrom::Start(0))?;
    compare_recovery_files(&mut published_map, &mut map)?;
    if unsafe { libc::flock(published_map.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(reject("published recovery loss map cannot be claimed"));
    }
    let loss_map_checksum = recovery_file_checksum(&published_map)?;
    let archive_checksum = recovery_file_checksum(&mut archive_claim)?;
    std::fs::remove_file(map_private)?;
    map_parent.sync_all()?;
    Ok(PreparedRecovery {
        plan,
        report: FileRecoveryReport {
            recovered_bytes,
            unreadable_bytes,
            lost_file_bytes,
            encoded_storage_loss_bytes,
            affected_compressed_bytes,
        },
        template: private,
        archive: archive_claim,
        archive_header: image.archive_header,
        archive_checksum,
        loss_map: published_map,
        loss_map_checksum,
        locations: image.locations,
        bad,
        sector: image.sector,
        length: image.length,
        boot,
        image_checksum: digest,
    })
}

// Private names retain evidence from earlier attempts. Creation and final
// hard links still use no-replace operations, so a racing name is refused.
fn recovery_private_name(destination: &Path, suffix: &str) -> io::Result<std::path::PathBuf> {
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let original = destination.file_name().ok_or_else(|| reject("invalid recovery output name"))?;
    for attempt in 0..1000 {
        let mut name = original.to_os_string();
        name.push(format!(".{suffix}-{}-{attempt}", std::process::id()));
        let candidate = parent.join(name);
        match std::fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
    Err(reject("no private recovery name available"))
}

// An interrupted publication may be resumed only when both retained names
// describe exactly the same bytes. Existing output is never overwritten.
fn compare_recovery_files(left: &mut File, right: &mut File) -> io::Result<()> {
    if !left.metadata()?.is_file() || left.metadata()?.len() != right.metadata()?.len() {
        return Err(reject("existing recovery output does not match this archive"));
    }
    let mut a = [0; 65536];
    let mut b = [0; 65536];
    loop {
        let n = left.read(&mut a)?;
        if n == 0 {
            return Ok(());
        }
        right.read_exact(&mut b[..n])?;
        if a[..n] != b[..n] {
            return Err(reject("existing recovery output does not match this archive"));
        }
    }
}

// A journal entry is one redo unit. New journals split large data writes at
// 64 KiB; complete metadata records retain their existing publication order.
fn read_repair_patch(reader: &mut impl Read, length: u64) -> io::Result<Patch> {
    let mut header = [0; 16];
    reader.read_exact(&mut header)?;
    let physical = u64_at(&header, 0)?;
    let size = u64_at(&header, 8)?;
    if size == 0 || size > 64 * 1024 * 1024 || physical.checked_add(size).is_none_or(|end| end > length) {
        return Err(reject("invalid repair journal range"));
    }
    let mut before = vec![0; size as usize];
    let mut after = before.clone();
    reader.read_exact(&mut before)?;
    reader.read_exact(&mut after)?;
    Ok(Patch::new(physical, before, after))
}

/// Offline block-device repair, with a durable external redo/preimage journal.
/// Linux O_EXCL claims the device against mounted filesystems and other claims.
/// Regular files must be exposed through an exclusively claimable loop device;
/// an advisory file lock is not treated as proof that an image is unmounted.
pub fn spotfix_in_place(
    source: &Path,
    queue: &Path,
    journal: &Path,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<()> {
    let ticket = checker::read_spotfix_ticket(queue)?;
    repair_in_place_queued(
        source,
        journal,
        false,
        Some((queue, ticket)),
        if ticket.index_audit == checker::consistency::AuditOptions::default() {
            InPlaceOperation::Repair
        } else {
            InPlaceOperation::RepairIndexes(ticket.index_audit)
        },
        progress,
    )
}

struct RecoveryJournal {
    archive: File,
    loss_map: File,
    archive_checksum: u64,
    loss_map_checksum: u64,
    changes: Option<RepairPlan>,
    template: Option<std::path::PathBuf>,
    bad: File,
    cluster_bytes: u32,
}

impl RecoveryJournal {
    // The retained files authorize the recorded loss and redo bytes. Resume
    // consumes stored patches, so it must not recapture the changed volume.
    fn verify_binding(&self) -> io::Result<()> {
        if recovery_file_checksum(&self.archive)? != self.archive_checksum
            || recovery_file_checksum(&self.loss_map)? != self.loss_map_checksum
        {
            return Err(reject("recovery archive or loss map changed; no writes made"));
        }
        Ok(())
    }
}

fn recovery_file_checksum(file: &File) -> io::Result<u64> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut checksum = 0;
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(checksum);
        }
        checksum = repair_checksum(checksum, &buffer[..count]);
    }
}

// Compare every captured good byte that remains readable under the new claim.
// Saved payload can survive a new EIO inside an already retired cluster;
// those bytes still never authorize a target preimage or write.
fn verify_recovery_source<R: Read + Seek>(
    device: &mut R,
    template: &mut File,
    locations: &mut File,
    bad: &mut File,
    length: u64,
    sector: u32,
    cluster: u32,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<()> {
    if !(512..=65536).contains(&sector)
        || !sector.is_power_of_two()
        || cluster < sector
        || cluster % sector != 0
        || length % u64::from(sector) != 0
    {
        return Err(reject("invalid in-place recovery geometry"));
    }
    let mut start = None;
    locations.seek(SeekFrom::Start(0))?;
    for offset in (0..=length).step_by(sector as usize) {
        let readable = if offset == length {
            false
        } else {
            let mut saved = [0; 8];
            locations.read_exact(&mut saved)?;
            let location = u64::from_le_bytes(saved);
            if location == 0 {
                return Err(reject("unattempted sector cannot authorize in-place recovery"));
            }
            location != u64::MAX
        };
        if readable && start.is_none() {
            start = Some(offset);
        }
        if let Some(first) = start {
            if !readable || offset - first == 1024 * 1024 {
                let mut expected = vec![0; sector as usize];
                scan_surface_reader(
                    device,
                    first..offset,
                    sector,
                    &mut |at, bytes| {
                        template.seek(SeekFrom::Start(at))?;
                        for chunk in bytes.chunks(sector as usize) {
                            template.read_exact(&mut expected)?;
                            if chunk != expected {
                                return Err(reject("source changed since recovery capture"));
                            }
                        }
                        Ok(())
                    },
                    &mut |at, length| {
                        for lcn in at / u64::from(cluster)..=(at + length - 1) / u64::from(cluster) {
                            if checker::consistency::inventory_find(bad, lcn)?.is_none() {
                                return Err(reject("readable recovery preimage now returns EIO"));
                            }
                        }
                        Ok(())
                    },
                    &mut |_| {},
                )?;
                start = readable.then_some(offset);
            }
        }
        if offset % (1024 * 1024) == 0 || offset == length {
            progress(RepairProgress::new(Phase::Failed, offset / 512, length / 512));
        }
    }
    Ok(())
}

fn validate_recovery_plan(changes: &RepairPlan, bad: &mut File, cluster: u32) -> io::Result<()> {
    for patch in changes.iter() {
        validate_retired_range(&patch?, bad, cluster)?;
    }
    Ok(())
}

fn validate_retired_range(patch: &Patch, bad: &mut File, cluster: u32) -> io::Result<()> {
    if cluster == 0 {
        return Err(reject("invalid retired-cluster geometry"));
    }
    let end = patch
        .physical
        .checked_add(patch.after.len() as u64)
        .ok_or_else(|| reject("recovery patch interval overflow"))?;
    if end == patch.physical {
        return Err(reject("empty recovery patch"));
    }
    for lcn in patch.physical / u64::from(cluster)..=(end - 1) / u64::from(cluster) {
        if checker::consistency::inventory_find(bad, lcn)?.is_some() {
            return Err(reject("recovery patch intersects a retired physical cluster"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum InPlaceOperation<'a> {
    Repair,
    Replay(completion::CompletionMode),
    ResizeLog(u64),
    RepairIndexes(checker::consistency::AuditOptions),
    Recover(&'a RecoveryJournal),
}

use completion::CompletionMode as Mode;

impl InPlaceOperation<'_> {
    fn header_bytes(self) -> usize {
        match self {
            Self::Repair | Self::Replay(Mode::Replay(_) | Mode::Summaries(_)) => 40,
            Self::ResizeLog(_) | Self::RepairIndexes(_) => 48,
            Self::Recover(_) => 56,
            Self::Replay(Mode::Widths(_) | Mode::WidthsAndAliases(_)) => 80,
        }
    }

    fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Repair => b"SLTRPR01",
            Self::Replay(Mode::Replay(_)) => b"SLTRPL01",
            Self::Replay(Mode::Summaries(_)) => b"SLTRDS01",
            Self::Replay(Mode::Widths(_)) => b"SLTRW001",
            Self::Replay(Mode::WidthsAndAliases(_)) => b"SLTRWA01",
            Self::ResizeLog(_) => b"SLTLRS01",
            Self::RepairIndexes(_) => b"SLTRPI01",
            Self::Recover(_) => b"SLTRCV01",
        }
    }
}

fn index_policy_word(options: checker::consistency::AuditOptions) -> u64 {
    options.index_policy_word()
}

pub fn repair_in_place(
    source: &Path,
    journal: &Path,
    resume: bool,
    progress: &mut dyn FnMut(RepairProgress),
    options: RepairOptions,
) -> io::Result<()> {
    if options.rescan_bad_clusters || options.cleanup_security || options.index_audit.skip_directory_cycles {
        return Err(reject("in-place repair does not accept optional maintenance or skipped cycle checking"));
    }
    let operation = if options.index_audit == checker::consistency::AuditOptions::default() {
        InPlaceOperation::Repair
    } else {
        InPlaceOperation::RepairIndexes(options.index_audit)
    };
    repair_in_place_queued(source, journal, resume, None, operation, progress)
}

/// Resize an exclusively claimed offline device using a durable external journal.
/// Resuming requires the original size argument and the retained journal.
pub fn resize_log_in_place(
    source: &Path,
    journal: &Path,
    bytes: u64,
    resume: bool,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<()> {
    log_resize::validate_size(bytes)?;
    repair_in_place_queued(source, journal, resume, None, InPlaceOperation::ResizeLog(bytes), progress)
}

fn repair_in_place_queued(
    source: &Path,
    journal: &Path,
    resume: bool,
    queued: Option<(&Path, checker::SpotfixTicket)>,
    operation: InPlaceOperation<'_>,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<()> {
    let device = claim_in_place_source(source)?;
    let stop_after = std::env::var("SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC")
        .ok()
        .map(|value| value.parse::<u64>().map_err(|_| reject("invalid repair stop point")))
        .transpose()?;
    apply_in_place_journal(device, journal, resume, queued, operation, stop_after, progress)
}

/// Retire captured unreadable clusters on an exclusively claimed offline device.
/// The archive and loss map remain required when resuming the external journal.
pub fn recover_archive_in_place(
    source: &Path,
    archive: &Path,
    loss_map: &Path,
    journal: &Path,
    resume: bool,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<FileRecoveryReport> {
    recover_archive_on_claimed_source(claim_in_place_source(source)?, archive, loss_map, journal, resume, progress)
}

fn claim_recovery_artifact(path: &Path, target: u64) -> io::Result<File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let file = OpenOptions::new().read(true).custom_flags(crate::linux::NO_FOLLOW_NONBLOCK).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } || meta.dev() == target {
        return Err(reject("recovery artifacts require private external regular files"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

// Private descriptor tests bypass only the public block-device claim. The
// archive binding, readable preimages and exact journal engine remain shared.
fn recover_archive_on_claimed_source(
    mut device: File,
    archive: &Path,
    loss_map: &Path,
    journal: &Path,
    resume: bool,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<FileRecoveryReport> {
    use std::os::unix::fs::MetadataExt;
    let identity = device.metadata()?;
    let length = image_length(&device)?;
    for path in [archive, loss_map, journal] {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        if File::open(parent)?.metadata()?.dev() == identity.rdev() {
            return Err(reject("recovery artifacts must reside outside the target device"));
        }
    }
    let mut archive_claim = claim_recovery_artifact(archive, identity.rdev())?;
    let mut header = [0; 72];
    archive_claim.read_exact(&mut header)?;
    if &header[..8] != b"SLTRSC01"
        || repair_checksum(0, &header[..64]) != u64_at(&header, 64)?
        || u64_at(&header, 8)? != length
        || u64_at(&header, 32)? != identity.rdev()
    {
        return Err(reject("recovery archive belongs to another claimed source"));
    }
    let recovery;
    let report;
    let template;
    if resume {
        let mut map = claim_recovery_artifact(loss_map, identity.rdev())?;
        report = read_recovery_report(&mut map)?;
        let mut direct = open_in_place_direct(&device)?;
        let mut raw_boot = [0; 512];
        read_in_place_range(&mut device, &mut direct, 0, &mut raw_boot)?;
        let boot = ntfs_rs::boot::BootSector::parse(&raw_boot)?;
        let bad = rescue_bad_clusters(archive_claim.try_clone()?, length, boot.cluster_bytes)?;
        recovery = RecoveryJournal {
            archive_checksum: recovery_file_checksum(&archive_claim)?,
            loss_map_checksum: recovery_file_checksum(&map)?,
            archive: archive_claim,
            loss_map: map,
            changes: None,
            template: None,
            bad,
            cluster_bytes: boot.cluster_bytes,
        };
        template = None;
    } else {
        let mut prepared = prepare_archive_recovery(archive, loss_map, journal, progress)?;
        let opened_archive = archive_claim.metadata()?;
        let prepared_archive = prepared.archive.metadata()?;
        if prepared.archive_header != header
            || prepared.length != length
            || (opened_archive.dev(), opened_archive.ino()) != (prepared_archive.dev(), prepared_archive.ino())
            || recovery_file_checksum(&archive_claim)? != prepared.archive_checksum
        {
            return Err(reject("recovery archive identity changed during preparation"));
        }
        validate_recovery_plan(&prepared.plan, &mut prepared.bad, prepared.boot.cluster_bytes)?;
        let mut captured = File::open(&prepared.template)?;
        let mut direct = open_in_place_direct(&device)?;
        if direct.as_ref().is_some_and(|(_, sector)| *sector != prepared.sector as u32) {
            return Err(reject("recovery archive logical sector geometry changed"));
        }
        let reader = direct.as_mut().map_or(&mut device, |(file, _)| file);
        verify_recovery_source(
            reader,
            &mut captured,
            &mut prepared.locations,
            &mut prepared.bad,
            length,
            prepared.sector as u32,
            prepared.boot.cluster_bytes,
            progress,
        )?;
        let current = device.metadata()?;
        if image_length(&device)? != length
            || (
                current.dev(),
                current.ino(),
                current.rdev(),
                current.mtime(),
                current.mtime_nsec(),
                current.ctime(),
                current.ctime_nsec(),
            ) != (
                identity.dev(),
                identity.ino(),
                identity.rdev(),
                identity.mtime(),
                identity.mtime_nsec(),
                identity.ctime(),
                identity.ctime_nsec(),
            )
        {
            return Err(reject("claimed source changed during recovery verification"));
        }
        let map = claim_recovery_artifact(loss_map, identity.rdev())?;
        let published_map = prepared.loss_map.metadata()?;
        let claimed_map = map.metadata()?;
        if (published_map.dev(), published_map.ino()) != (claimed_map.dev(), claimed_map.ino())
            || recovery_file_checksum(&map)? != prepared.loss_map_checksum
        {
            return Err(reject("published loss map changed during recovery preparation"));
        }
        report = prepared.report;
        template = Some(prepared.template);
        recovery = RecoveryJournal {
            archive: prepared.archive,
            loss_map: map,
            archive_checksum: prepared.archive_checksum,
            loss_map_checksum: prepared.loss_map_checksum,
            changes: Some(prepared.plan),
            template: template.clone(),
            bad: prepared.bad,
            cluster_bytes: prepared.boot.cluster_bytes,
        };
    }
    let stop_after = std::env::var("SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC")
        .ok()
        .map(|value| value.parse::<u64>().map_err(|_| reject("invalid repair stop point")))
        .transpose()?;
    apply_in_place_journal(device, journal, resume, None, InPlaceOperation::Recover(&recovery), stop_after, progress)?;
    if let Some(template) = template {
        std::fs::remove_file(template)?;
    }
    Ok(report)
}

// Keep source ownership and writability checks identical for every journaled
// operation, before any proposal or external recovery artifact is produced.
fn claim_in_place_source(source: &Path) -> io::Result<File> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    };

    // Resolve only verified block targets. The final exclusive, no-follow
    // open must still identify the same device if its alias changes meanwhile.
    // Regular images require a loop device to exclude concurrent mounts.
    let identity = std::fs::metadata(source)?;
    if !identity.file_type().is_block_device() {
        return Err(reject("in-place repair requires an unmounted block/loop device"));
    }
    let canonical = std::fs::canonicalize(source)?;
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(canonical)?;
    let opened = device.metadata()?;
    if !opened.file_type().is_block_device()
        || (opened.dev(), opened.ino(), opened.rdev()) != (identity.dev(), identity.ino(), identity.rdev())
    {
        return Err(reject("opened device differs from the verified block target"));
    }
    // Opening a read-only block device with O_RDWR can succeed. Refuse before
    // planning or creating a journal rather than discovering it on a write.
    let mut read_only: libc::c_int = 0;
    if unsafe { libc::ioctl(device.as_raw_fd(), libc::_IO(0x12, 94), &mut read_only) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if read_only != 0 {
        return Err(reject("in-place repair requires a writable block device"));
    }
    Ok(device)
}

// Open a separate direct descriptor through the claimed identity. Duplicating
// a descriptor would share status flags with buffered planning and writes.
fn open_in_place_direct(device: &File) -> io::Result<Option<(File, u32)>> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    };
    let identity = device.metadata()?;
    if !identity.file_type().is_block_device() {
        return Ok(None);
    }
    let stable = format!("/proc/self/fd/{}", device.as_raw_fd());
    let direct =
        OpenOptions::new().read(true).write(true).custom_flags(libc::O_DIRECT | libc::O_NONBLOCK).open(stable)?;
    let opened = direct.metadata()?;
    if !opened.file_type().is_block_device()
        || (opened.dev(), opened.ino(), opened.rdev()) != (identity.dev(), identity.ino(), identity.rdev())
    {
        return Err(reject("direct descriptor differs from the claimed device"));
    }
    let mut sector: libc::c_int = 0;
    if unsafe { libc::ioctl(direct.as_raw_fd(), 0x1268, &mut sector) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let sector = u32::try_from(sector).map_err(|_| reject("invalid logical sector size"))?;
    if !(512..=65536).contains(&sector) || !sector.is_power_of_two() || image_length(device)? % u64::from(sector) != 0 {
        return Err(reject("invalid claimed device logical sector geometry"));
    }
    Ok(Some((direct, sector)))
}

fn read_in_place_range(
    device: &mut File,
    direct: &mut Option<(File, u32)>,
    offset: u64,
    output: &mut [u8],
) -> io::Result<()> {
    if let Some((file, sector)) = direct {
        transfer_in_place_sectors(file, *sector, offset, output, false)
    } else {
        device.seek(SeekFrom::Start(offset))?;
        device.read_exact(output)
    }
}

fn write_in_place_range(
    device: &mut File,
    direct: &mut Option<(File, u32)>,
    offset: u64,
    payload: &mut [u8],
) -> io::Result<()> {
    if let Some((file, sector)) = direct {
        // Merge against fresh whole logical sectors, so a small flag update
        // cannot publish unrelated bytes from an old buffered page.
        transfer_in_place_sectors(file, *sector, offset, payload, true)?;
        file.sync_all()
    } else {
        device.seek(SeekFrom::Start(offset))?;
        device.write_all(payload)?;
        device.sync_all()
    }
}

fn transfer_in_place_sectors<R: Read + Write + Seek>(
    file: &mut R,
    sector: u32,
    offset: u64,
    payload: &mut [u8],
    write: bool,
) -> io::Result<()> {
    if !(512..=65536).contains(&sector) || !sector.is_power_of_two() || payload.is_empty() {
        return Err(reject("invalid in-place transfer geometry"));
    }
    let unit = u64::from(sector);
    let end = offset.checked_add(payload.len() as u64).ok_or_else(|| reject("in-place interval overflow"))?;
    let terminal = end.div_ceil(unit).checked_mul(unit).ok_or_else(|| reject("in-place sector interval overflow"))?;
    let first = offset / unit * unit;
    let capacity = (terminal - first).min(1024 * 1024) as usize;
    let mut backing = vec![0; capacity + sector as usize - 1];
    let alignment = backing.as_ptr().align_offset(sector as usize);
    let aligned = &mut backing[alignment..alignment + capacity];
    let mut physical = first;
    while physical < terminal {
        let length = (terminal - physical).min(capacity as u64) as usize;
        let bytes = &mut aligned[..length];
        file.seek(SeekFrom::Start(physical))?;
        file.read_exact(bytes)?;
        let from = physical.max(offset);
        let to = (physical + length as u64).min(end);
        let part = &mut payload[(from - offset) as usize..(to - offset) as usize];
        let current = &mut bytes[(from - physical) as usize..(to - physical) as usize];
        if write {
            current.copy_from_slice(part);
            file.seek(SeekFrom::Start(physical))?;
            file.write_all(bytes)?;
        } else {
            part.copy_from_slice(current);
        }
        physical += length as u64;
    }
    Ok(())
}

// The public entry points establish the device claim before reaching this engine.
// Descriptor-based tests exercise the same journal ordering on disposable files.
fn apply_in_place_journal(
    mut device: File,
    journal: &Path,
    resume: bool,
    queued: Option<(&Path, checker::SpotfixTicket)>,
    operation: InPlaceOperation<'_>,
    stop_after: Option<u64>,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<()> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let mut sync_point = 0_u64;
    let mut stop = || -> io::Result<()> {
        sync_point += 1;
        if stop_after == Some(sync_point) {
            Err(reject("injected in-place repair interruption"))
        } else {
            Ok(())
        }
    };
    let identity = device.metadata()?;
    let length = image_length(&device)?;
    let mut direct = open_in_place_direct(&device)?;
    let replay_only = matches!(operation, InPlaceOperation::Replay(_));
    let retained_completion = replay_only || matches!(operation, InPlaceOperation::Recover(_));
    let expected_serial = match operation {
        InPlaceOperation::Replay(mode) => mode.expected_serial(),
        _ => None,
    };
    if let Some(expected) = expected_serial {
        let mut boot = [0; 512];
        read_in_place_range(&mut device, &mut direct, 0, &mut boot)?;
        if ntfs_rs::boot::BootSector::parse(&boot)?.serial_number != expected {
            return Err(reject("claimed device volume serial differs from the authorized target; no writes made"));
        }
    }
    // All planning reads refer to the claimed descriptor, not a replaceable path.
    let stable = std::path::PathBuf::from(format!("/proc/self/fd/{}", device.as_raw_fd()));
    if let Some((queue, ticket)) = queued {
        let index_audit = match operation {
            InPlaceOperation::Repair => checker::consistency::AuditOptions::default(),
            InPlaceOperation::RepairIndexes(options) => options,
            InPlaceOperation::ResizeLog(_) | InPlaceOperation::Recover(_) | InPlaceOperation::Replay(_) => {
                return Err(reject("spotfix queue cannot authorize this operation"));
            }
        };
        if index_audit != ticket.index_audit {
            return Err(reject("spotfix repair policy disagrees with queued scan"));
        }
        let probe = checker::probe(&stable)?;
        if ticket.device != identity.rdev()
            || ticket.serial != probe.boot.serial_number
            || ticket.sectors != probe.boot.total_sectors
        {
            return Err(reject("spotfix queue belongs to another volume"));
        }
        let mut audit = checker::consistency::audit(&stable, probe.boot, ticket.index_audit)?;
        if audit.errors != ticket.errors || audit.fingerprint != ticket.fingerprint {
            return Err(reject("spotfix findings changed since online scan; run a new scan"));
        }
        checker::verify_spotfix_worklist(queue, &mut audit, ticket)?;
    }
    let parent = journal.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let parent = File::open(parent)?;
    let mut completed = journal.as_os_str().to_owned();
    completed.push(".completed");
    let completed = Path::new(&completed);
    let already_linked = if completed.try_exists()? {
        let a = std::fs::symlink_metadata(completed)?;
        if !resume || !a.is_file() {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        match std::fs::symlink_metadata(journal) {
            Ok(b) if b.is_file() && (a.dev(), a.ino()) == (b.dev(), b.ino()) => {}
            Err(error) if retained_completion && error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        }
        true
    } else {
        false
    };
    if parent.metadata()?.dev() == identity.rdev() {
        return Err(reject("repair journal must reside outside the target device"));
    }
    if let InPlaceOperation::Recover(recovery) = operation {
        recovery.verify_binding()?;
    }
    let journal_file;
    if resume {
        let retained =
            if retained_completion && already_linked && !journal.try_exists()? { completed } else { journal };
        journal_file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(retained)?;
        let meta = journal_file.metadata()?;
        if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { geteuid() } {
            return Err(reject("unsafe repair journal ownership or permissions"));
        }
    } else {
        let planned;
        let changes = if let InPlaceOperation::Recover(recovery) = operation {
            recovery.changes.as_ref().ok_or_else(|| reject("fresh recovery requires a verified repair plan"))?
        } else {
            planned = match operation {
                InPlaceOperation::Replay(mode) => completion::completion_plan(&stable, mode)?,
                InPlaceOperation::Repair => structural_repair_plan(&stable, progress, PlanInputs::default())?,
                InPlaceOperation::RepairIndexes(index_audit) => structural_repair_plan(
                    &stable,
                    progress,
                    PlanInputs { options: RepairOptions { index_audit, ..Default::default() }, ..Default::default() },
                )?,
                InPlaceOperation::ResizeLog(bytes) => log_resize::plan_resize(&stable, bytes, progress)?,
                InPlaceOperation::Recover(_) => unreachable!(),
            };
            &planned
        };
        // Damaged boot or MFT mapping can be the very defect being repaired.
        // Resolve guard locations through the same checked bootstrap authority
        // without publishing any prerequisite repair to the target.
        let guard_source = match operation {
            InPlaceOperation::Recover(recovery) => {
                recovery.template.as_deref().ok_or_else(|| reject("fresh recovery requires its validated template"))?
            }
            _ => &stable,
        };
        let (boot, initial) = bootstrap_repairs(guard_source)?;
        let mut bootstrap = RepairPlan::new(length)?;
        for patch in initial {
            bootstrap.push(patch)?;
        }
        let mut volume = PlannedImage::volume(guard_source, &bootstrap, boot)?;
        let zero = checker::consistency::mft_image(&mut volume)?;
        let mft = MftRecord::from_decoded(&zero)?;
        let mut raw = vec![0; boot.record_bytes as usize];
        volume.read_mft_record(&mft, 3, &mut raw)?;
        let record = MftRecord::parse(&mut raw, boot.bytes_per_sector)?;
        let info = ntfs_rs::volume_info::VolumeInfo::from_record(&record)?;
        // A dirty-only volume still needs durable guards and final validation.
        if changes.is_empty() && info.flags & 1 == 0 && !matches!(operation, InPlaceOperation::Recover(_)) {
            progress(RepairProgress::new(Phase::Complete, 0, 0));
            return Ok(());
        }
        let attr = record.stream(ntfs_rs::volume_info::ATTR_VOLUME_INFORMATION, &[])?;
        let at = attr.record_offset() + attr.resident_value_offset()? + 10;
        // Update only the flags word: never bypass multi-sector fixups.
        if at % 512 >= 509 {
            return Err(reject("volume flags overlap a protected sector tail"));
        }
        let flags = info.flags.to_le_bytes();
        let dirty = (info.flags | 1).to_le_bytes();
        let mut guards = Vec::new();
        plan_nonresident_overwrite(
            mft.stream(ATTR_DATA, &[])?,
            boot,
            3 * u64::from(boot.record_bytes) + at as u64,
            2,
            |span| {
                if span.length != 2 {
                    return Err(ntfs_rs::Error::Unsupported);
                }
                guards.push(Patch::new(span.physical_offset, flags.to_vec(), dirty.to_vec()));
                Ok(())
            },
        )?;
        guards.push(Patch::new(
            boot.mft_mirror_lcn * u64::from(boot.cluster_bytes) + 3 * u64::from(boot.record_bytes) + at as u64,
            flags.to_vec(),
            dirty.to_vec(),
        ));
        // Journal guards retain genuine original flag words. If bootstrap also
        // changed either word, the existing guard format cannot represent it.
        for guard in &guards {
            let mut original = [0; 2];
            read_in_place_range(&mut device, &mut direct, guard.physical, &mut original)?;
            if original != flags {
                return Err(reject("bootstrap changed volume flags before dirty-guard admission"));
            }
        }
        let mut finalizers: Vec<_> = guards
            .iter()
            .map(|p| {
                Patch::new(
                    p.physical,
                    p.after.clone(),
                    match operation {
                        InPlaceOperation::Repair
                        | InPlaceOperation::RepairIndexes(_)
                        | InPlaceOperation::Recover(_)
                        | InPlaceOperation::Replay(_) => (info.flags & !1).to_le_bytes().to_vec(),
                        InPlaceOperation::ResizeLog(_) => (info.flags & !2).to_le_bytes().to_vec(),
                    },
                )
            })
            .collect();
        // Clear the mirror first; the primary dirty flag is the final
        // admission gate and stays set until both layouts are validated.
        finalizers.reverse();
        let count = changes.len() as u64 + 4;
        let total =
            changes.iter().try_fold(operation.header_bytes() as u64 + 8 + 4 * 20, |sum, p| -> io::Result<u64> {
                sum.checked_add(16 + 2 * p?.after.len() as u64).ok_or_else(|| reject("journal size overflow"))
            })?;
        journal_file =
            OpenOptions::new().create_new(true).read(true).write(true).mode(PRIVATE_FILE_MODE).open(journal)?;
        let mut writer = std::io::BufWriter::new(&journal_file);
        let mut crc = 0;
        let mut written = 0_u64;
        let mut emit = |bytes: &[u8]| -> io::Result<()> {
            writer.write_all(bytes)?;
            crc = repair_checksum(crc, bytes);
            written += bytes.len() as u64;
            progress(RepairProgress::new(Phase::Journal, written.div_ceil(512), total.div_ceil(512)));
            Ok(())
        };
        emit(operation.magic())?;
        for value in [identity.rdev(), length, boot.serial_number, count] {
            emit(&value.to_le_bytes())?;
        }
        match operation {
            InPlaceOperation::Replay(Mode::Widths(target) | Mode::WidthsAndAliases(target)) => {
                emit(&target.record.to_le_bytes())?;
                emit(&target.raw_sha256)?;
            }
            InPlaceOperation::ResizeLog(bytes) => emit(&bytes.to_le_bytes())?,
            InPlaceOperation::RepairIndexes(options) => emit(&index_policy_word(options).to_le_bytes())?,
            InPlaceOperation::Recover(recovery) => {
                emit(&recovery.archive_checksum.to_le_bytes())?;
                emit(&recovery.loss_map_checksum.to_le_bytes())?;
            }
            InPlaceOperation::Repair | InPlaceOperation::Replay(Mode::Replay(_) | Mode::Summaries(_)) => {}
        }
        let ordered = guards.iter().cloned().map(Ok).chain(changes.iter()).chain(finalizers.into_iter().map(Ok));
        for (number, patch) in ordered.enumerate() {
            let mut patch = patch?;
            if let InPlaceOperation::Recover(recovery) = operation {
                validate_retired_range(&patch, &mut recovery.bad.try_clone()?, recovery.cluster_bytes)?;
            }
            if number >= 2 && (number as u64) < count - 2 {
                for guard in &guards {
                    for i in 0..2 {
                        if let Some(index) =
                            (guard.physical + i).checked_sub(patch.physical).filter(|n| *n < patch.after.len() as u64)
                        {
                            patch.before[index as usize] = dirty[i as usize];
                            patch.after[index as usize] = dirty[i as usize];
                        }
                    }
                }
            }
            emit(&patch.physical.to_le_bytes())?;
            emit(&(patch.after.len() as u64).to_le_bytes())?;
            emit(&patch.before)?;
            emit(&patch.after)?;
        }
        drop(emit);
        writer.write_all(&crc.to_le_bytes())?;
        writer.flush()?;
        drop(writer);
        journal_file.sync_all()?;
        parent.sync_all()?;
    }
    stop()?; // Durable external journal, before any target write.
    unsafe extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
        fn geteuid() -> u32;
    }
    if unsafe { flock(journal_file.as_raw_fd(), 2 | 4) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Authenticate the entire journal before any device write, without loading
    // it into memory. Truncation, trailing data, identity and every range fail closed.
    let journal_length = journal_file.metadata()?.len();
    let header_bytes = operation.header_bytes();
    if journal_length < header_bytes as u64 + 8 {
        return Err(reject("truncated repair journal"));
    }
    let mut reader = std::io::BufReader::new(&journal_file);
    reader.seek(SeekFrom::Start(0))?;
    let mut header = vec![0; header_bytes];
    reader.read_exact(&mut header)?;
    let count = u64_at(&header, 32)?;
    if &header[..8] != operation.magic()
        || u64_at(&header, 8)? != identity.rdev()
        || u64_at(&header, 16)? != length
        || count < 4
        || count > (journal_length - header_bytes as u64 - 8) / 18
    {
        return Err(reject("repair journal identity/count mismatch"));
    }
    if let Some(target) = match operation {
        InPlaceOperation::Replay(mode) => mode.width_target(),
        _ => None,
    } {
        if u64_at(&header, 40)? != target.record || header[48..80] != target.raw_sha256 {
            return Err(reject("mapping-width journal target or preimage digest mismatch"));
        }
    }
    if let InPlaceOperation::ResizeLog(bytes) = operation {
        if u64_at(&header, 40)? != bytes {
            return Err(reject("log resize journal size mismatch"));
        }
    }
    if let InPlaceOperation::RepairIndexes(options) = operation {
        if u64_at(&header, 40)? != index_policy_word(options) {
            return Err(reject("repair journal index checking policy mismatch"));
        }
    }
    if let InPlaceOperation::Recover(recovery) = operation {
        if u64_at(&header, 40)? != recovery.archive_checksum || u64_at(&header, 48)? != recovery.loss_map_checksum {
            return Err(reject("recovery journal archive or loss map mismatch"));
        }
    }
    // A damaged primary boot may still await its recorded redo. Reuse the
    // checked terminal-backup authority without depending on MFT repair state.
    let (boot, _) = bootstrap_boot(&stable)?;
    if boot.serial_number != u64_at(&header, 24)? {
        return Err(reject("repair journal volume serial mismatch"));
    }
    let mut crc = repair_checksum(0, &header);
    let mut remaining = journal_length - header_bytes as u64 - 8;
    let mut buffer = [0; 65536];
    while remaining != 0 {
        let n = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..n])?;
        crc = repair_checksum(crc, &buffer[..n]);
        remaining -= n as u64;
    }
    let mut checksum = [0; 8];
    reader.read_exact(&mut checksum)?;
    if crc != u64::from_le_bytes(checksum) {
        return Err(reject("repair journal checksum mismatch"));
    }
    reader.seek(SeekFrom::Start(header_bytes as u64))?;
    let mut guards = Vec::new();
    let mut finalizers = Vec::new();
    let mut total = 0_u64;
    for index in 0..count {
        let patch = read_repair_patch(&mut reader, length)?;
        if let InPlaceOperation::Recover(recovery) = operation {
            validate_retired_range(&patch, &mut recovery.bad.try_clone()?, recovery.cluster_bytes)?;
        }
        total = total
            .checked_add((patch.physical % 512 + patch.after.len() as u64).div_ceil(512))
            .ok_or_else(|| reject("repair work size overflow"))?;
        if index < 2 {
            guards.push(patch);
        } else if index >= count - 2 {
            finalizers.push(patch);
        }
    }
    if reader.stream_position()? != journal_length - 8 {
        return Err(reject("trailing repair journal data"));
    }

    // Validate every range before changing the device. The first two entries
    // are dirty guards and the last two publish validated final words. A full
    // record patch overlapping a guard expects the dirty word even when this
    // is the first attempt and the device still contains its original word.
    let matching_finalizers = guards
        .iter()
        .map(|guard| {
            finalizers
                .iter()
                .find(|finalizer| finalizer.physical == guard.physical)
                .cloned()
                .ok_or_else(|| reject("repair journal guard/finalizer mismatch"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    for (guard, finalizer) in guards.iter().zip(&matching_finalizers) {
        if guard.before.len() != 2
            || guard.after.len() != 2
            || finalizer.before.len() != 2
            || finalizer.after.len() != 2
            || guard.physical != finalizer.physical
            || match operation {
                InPlaceOperation::Replay(_) => {
                    (u16::from_le_bytes(guard.before[..].try_into().unwrap()) & !1).to_le_bytes().as_slice()
                        != finalizer.after
                }
                InPlaceOperation::Repair | InPlaceOperation::RepairIndexes(_) | InPlaceOperation::Recover(_) => {
                    // Retained older journals restore the original dirty word.
                    // New journals clear only the dirty bit after validation.
                    guard.before != finalizer.after
                        && (u16::from_le_bytes(guard.before[..].try_into().unwrap()) & !1).to_le_bytes().as_slice()
                            != finalizer.after
                }
                InPlaceOperation::ResizeLog(_) => {
                    (u16::from_le_bytes(guard.before[..].try_into().unwrap()) & !2).to_le_bytes().as_slice()
                        != finalizer.after
                }
            }
            || guard.after != finalizer.before
            || u16::from_le_bytes(guard.after[..].try_into().unwrap())
                != u16::from_le_bytes(guard.before[..].try_into().unwrap()) | 1
        {
            return Err(reject("invalid repair journal dirty guards; no writes made"));
        }
    }
    let mut verified = 0;
    progress(RepairProgress::new(Phase::Verification, 0, total));
    reader.seek(SeekFrom::Start(header_bytes as u64))?;
    for index in 0..count {
        let patch = read_repair_patch(&mut reader, length)?;
        let mut observed = vec![0; patch.before.len()];
        read_in_place_range(&mut device, &mut direct, patch.physical, &mut observed)?;
        if index >= 2 && index < count - 2 {
            for (guard, finalizer) in guards.iter().zip(&matching_finalizers) {
                for i in 0..2 {
                    if let Some(at) =
                        (guard.physical + i as u64).checked_sub(patch.physical).filter(|at| *at < observed.len() as u64)
                    {
                        let byte = &mut observed[at as usize];
                        if *byte != guard.before[i] && *byte != guard.after[i] && *byte != finalizer.after[i] {
                            return Err(reject("repair dirty-guard conflict; no writes made"));
                        }
                        *byte = guard.after[i];
                    }
                }
            }
        }
        let original_guard = index >= count - 2
            && guards.iter().any(|guard| guard.physical == patch.physical && observed == guard.before);
        let finalized_guard = index < 2 && observed == matching_finalizers[index as usize].after;
        if !original_guard
            && !finalized_guard
            && observed.iter().zip(&patch.before).zip(&patch.after).any(|((&now, &old), &new)| now != old && now != new)
        {
            return Err(reject("repair preimage conflict; no writes made"));
        }
        verified += (patch.physical % 512 + patch.after.len() as u64).div_ceil(512);
        progress(RepairProgress::new(Phase::Verification, verified, total));
    }
    if let InPlaceOperation::Recover(recovery) = operation {
        recovery.verify_binding()?;
    }
    if replay_only {
        completion::validate_journal_candidate(
            &stable,
            &mut reader,
            header_bytes,
            count,
            length,
            &guards,
            &matching_finalizers,
        )?;
    }
    // Complete each logged range from either its preimage, postimage, or a
    // sector/byte mixture caused by interruption. Foreign bytes stop repair.
    let mut done = 0;
    reader.seek(SeekFrom::Start(header_bytes as u64))?;
    for index in 0..count {
        let mut patch = read_repair_patch(&mut reader, length)?;
        if index == count - 2 {
            match operation {
                InPlaceOperation::Replay(_) => {
                    completion::validate_completed_targets(&stable, length, &matching_finalizers)?;
                }
                InPlaceOperation::Repair | InPlaceOperation::Recover(_) => {
                    if !structural_repair_plan(&stable, progress, PlanInputs::default())?.is_empty() {
                        return Err(reject("post-repair validation failed; dirty flags and journal retained"));
                    }
                }
                InPlaceOperation::RepairIndexes(index_audit) => {
                    if !structural_repair_plan(
                        &stable,
                        progress,
                        PlanInputs {
                            options: RepairOptions { index_audit, ..Default::default() },
                            ..Default::default()
                        },
                    )?
                    .is_empty()
                    {
                        return Err(reject("post-repair validation failed; dirty flags and journal retained"));
                    }
                }
                InPlaceOperation::ResizeLog(bytes) => {
                    log_resize::validate_in_place_result(&stable, bytes, &finalizers)?;
                }
            }
        }
        let mut observed = vec![0; patch.before.len()];
        read_in_place_range(&mut device, &mut direct, patch.physical, &mut observed)?;
        // A resumed operation may have already published its final flag word.
        // Reapply the dirty guard before replaying any intermediate metadata.
        let finalized_guard = index < 2 && observed == matching_finalizers[index as usize].after;
        if !finalized_guard
            && observed.iter().zip(&patch.before).zip(&patch.after).any(|((&now, &old), &new)| now != old && now != new)
        {
            return Err(reject("repair preimage conflict; dirty flags and journal retained"));
        }
        if observed != patch.after {
            write_in_place_range(&mut device, &mut direct, patch.physical, &mut patch.after)?;
            read_in_place_range(&mut device, &mut direct, patch.physical, &mut observed)?;
            if observed != patch.after {
                return Err(reject("durable repair readback differs; dirty flags and journal retained"));
            }
        }
        stop()?; // One preimage-checked redo unit is durable.
        done += (patch.physical % 512 + patch.after.len() as u64).div_ceil(512);
        progress(RepairProgress::new(Phase::Repair, done, total));
    }
    // Retain the preimages for review; publication is no-replace and durable.
    journal_file.sync_all()?;
    stop()?; // Completion record/journal durable; link not published.
    progress(RepairProgress::new(Phase::Publication, 0, 0));
    if !already_linked {
        std::fs::hard_link(journal, completed)?;
        parent.sync_all()?;
    }
    stop()?; // Completed name durable; original journal still available.
    if !retained_completion || journal.try_exists()? {
        std::fs::remove_file(journal)?;
    }
    parent.sync_all()?;
    stop()?; // Final name only; successful operation can be audited.
    progress(RepairProgress::new(Phase::Complete, total, total));
    Ok(())
}

pub use completion::{replay_in_place, validate_replay, CompletionMode};
pub use widths::WidthRepairTarget;

/// Never opens source for writing and never overwrites an existing output.
/// stop_after is a test-only fault-injection hook after each durable boundary.
pub fn replay_to(source: &Path, destination: &Path, stop_after: Option<usize>) -> io::Result<()> {
    let mut input = File::open(source)?;
    if !input.metadata()?.is_file() {
        return Err(reject("source must be an offline regular image file"));
    }
    let planned = plan(source)?; // Refuse unsupported inputs before output creation.
    let boundaries = planned
        .preparation
        .iter()
        .chain(planned.patches.iter())
        .chain(planned.publication.iter())
        .try_fold(0_usize, |count, patch| -> io::Result<usize> { Ok(count + usize::from(!patch?.continuation)) })?;
    if stop_after.is_some_and(|n| n == 0 || n > 1 + boundaries) {
        return Err(reject("test flush boundary is outside this replay plan"));
    }
    let mut output = OpenOptions::new().create_new(true).read(true).write(true).open(destination)?;
    io::copy(&mut input, &mut output)?;
    // Make the new directory entry durable before changing the copied image.
    output.sync_all()?;
    let parent = destination.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    let mut flushes = 0;
    flush(&mut output, &mut flushes, stop_after)?;
    // Re-plan the actual copy, rejecting changed source contents or targets.
    if !plan(destination)?.matches(&planned)? {
        return Err(reject("image changed during copy"));
    }
    recover_created_copy(destination, &mut output, &mut flushes, stop_after)
}

/// Internal adapter for an output created exclusively by this process. Never
/// expose this as a device/in-place repair API without exclusive ownership.
pub(crate) fn recover_created_copy(
    destination: &Path,
    output: &mut File,
    flushes: &mut usize,
    stop_after: Option<usize>,
) -> io::Result<()> {
    let planned = plan(destination)?;
    let mut redo = 0;
    let mut undo = 0;
    let mut pending: Vec<Patch> = Vec::new();
    for patch in planned.preparation.iter().chain(planned.patches.iter()).chain(planned.publication.iter()) {
        let patch = patch?;
        patch.apply_to(output, "physical preimage changed")?;
        let continuation = patch.continuation;
        pending.push(patch);
        if continuation {
            continue;
        }
        flush(output, flushes, stop_after)?;
        for written in pending.drain(..) {
            let mut observed = vec![0; written.after.len()];
            std::os::unix::fs::FileExt::read_exact_at(&*output, &mut observed, written.physical)?;
            if observed != written.after {
                return Err(reject("durable replay readback differs"));
            }
        }
    }
    if !pending.is_empty() {
        return Err(reject("unterminated metadata transfer"));
    }
    for patch in planned.patches.iter() {
        let patch = patch?;
        if patch.undo {
            undo += 1;
        } else {
            redo += 1;
        }
    }
    let verified = plan(destination)?;
    if !verified.preparation.is_empty() || !verified.patches.is_empty() || !verified.publication.is_empty() {
        return Err(reject("checkpoint publication did not converge"));
    }
    let dirty = u8::from(checker::probe(destination)?.info.is_dirty());
    println!("redo_records={redo}\nundo_records={undo}\ndurable_boundaries={flushes}\ndirty={dirty}\ncheckpoint_published=1\nwrite_mount_ready=0");
    Ok(())
}

#[cfg(test)]
mod mirror_reconstruction_checks {
    include!("../tests/recovery/coordinator_mirror_reconstruction_checks.rs");
}

#[cfg(test)]
mod semantic_view_checks {
    include!("../tests/recovery/coordinator_semantic_view_checks.rs");
}

#[cfg(test)]
mod mft_list_growth_checks {
    include!("../tests/recovery/coordinator_mft_list_growth_checks.rs");
}

#[cfg(test)]
mod split_mft_growth_checks {
    include!("../tests/recovery/coordinator_split_mft_growth_checks.rs");
}

#[cfg(test)]
mod unrecoverable_evidence_checks {
    include!("../tests/recovery/coordinator_unrecoverable_evidence_checks.rs");
}

#[derive(Clone, Copy, Debug)]
pub struct SurfaceReport {
    pub total_bytes: u64,
    pub unreadable_bytes: u64,
    // Failed read attempts include bulk requests whose sector retries recover.
    pub io_error_count: u64,
}

// Classify each source byte once after any retries. Callbacks own durable
// publication; progress cannot advance beyond an unreported failed interval.
pub(crate) fn scan_surface_reader<R: Read + Seek>(
    input: &mut R,
    range: std::ops::Range<u64>,
    sector: u32,
    readable: &mut dyn FnMut(u64, &[u8]) -> io::Result<()>,
    unreadable: &mut dyn FnMut(u64, u64) -> io::Result<()>,
    progress: &mut dyn FnMut(RepairProgress),
) -> io::Result<SurfaceReport> {
    if !sector.is_power_of_two()
        || !(512..=65536).contains(&sector)
        || range.start >= range.end
        || range.start % u64::from(sector) != 0
        || range.end % u64::from(sector) != 0
    {
        return Err(reject("invalid surface-scan sector geometry"));
    }
    // Extra backing bytes allow sector-aligned direct I/O without an allocator
    // dependency. Short resume ranges allocate only the bytes they can consume.
    let capacity = (range.end - range.start).min(1024 * 1024) as usize;
    let alignment = sector as usize;
    let mut bulk_storage = vec![0_u8; capacity + alignment - 1];
    let bulk_start = bulk_storage.as_ptr().align_offset(alignment);
    let buffer = &mut bulk_storage[bulk_start..bulk_start + capacity];
    let mut retry_storage = vec![0_u8; sector as usize + alignment - 1];
    let retry_start = retry_storage.as_ptr().align_offset(alignment);
    let retry = &mut retry_storage[retry_start..retry_start + sector as usize];
    let mut offset = range.start;
    let mut failed = 0;
    let mut io_errors = 0;
    let mut pending = None::<(u64, u64)>;
    let total = (range.end - range.start) / 512;
    let mut completed = 0;
    progress(RepairProgress::new(Phase::Failed, 0, total));
    while offset < range.end {
        let n = (range.end - offset).min(buffer.len() as u64) as usize;
        input.seek(SeekFrom::Start(offset))?;
        match input.read_exact(&mut buffer[..n]) {
            Ok(()) => {
                if let Some((start, length)) = pending.take() {
                    unreadable(start, length)?;
                }
                readable(offset, &buffer[..n])?;
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                io_errors += 1;
                // A partial bulk read can fail after advancing the descriptor.
                // Retry from each absolute sector boundary, including its prefix.
                for at in (0..n).step_by(sector as usize) {
                    let physical = offset + at as u64;
                    input.seek(SeekFrom::Start(physical))?;
                    match input.read_exact(retry) {
                        Ok(()) => {
                            if let Some((start, length)) = pending.take() {
                                unreadable(start, length)?;
                            }
                            readable(physical, &retry)?;
                        }
                        Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                            io_errors += 1;
                            let interval = pending.get_or_insert((physical, 0));
                            interval.1 += u64::from(sector);
                            failed += u64::from(sector);
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Err(error) => return Err(error),
        }
        offset += n as u64;
        let published = pending.map_or(offset, |(start, _)| start);
        let current = (published - range.start) / 512;
        if current > completed {
            completed = current;
            progress(RepairProgress::new(Phase::Failed, completed, total));
        }
    }
    if let Some((start, length)) = pending {
        unreadable(start, length)?;
    }
    if completed != total {
        progress(RepairProgress::new(Phase::Failed, total, total));
    }
    Ok(SurfaceReport { total_bytes: range.end - range.start, unreadable_bytes: failed, io_error_count: io_errors })
}

// Diagnostics and durable rescue must observe the same uncached block bytes
// while holding one source claim. Images use ordinary read-only file I/O.
pub(crate) fn open_surface_source(source: &Path) -> io::Result<(File, u64, u32)> {
    let input = {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        };
        // Device aliases resolve once; compare the claimed target with the
        // opened descriptor before reading. Regular images still refuse links.
        let requested = std::fs::metadata(source)?;
        let block_path =
            if requested.file_type().is_block_device() { Some(std::fs::canonicalize(source)?) } else { None };
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_EXCL | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(block_path.as_deref().unwrap_or(source))?;
        if block_path.is_some() {
            let opened = input.metadata()?;
            if !opened.file_type().is_block_device()
                || opened.dev() != requested.dev()
                || opened.ino() != requested.ino()
                || opened.rdev() != requested.rdev()
            {
                return Err(reject("surface-scan block target changed before opening"));
            }
        }
        if unsafe { libc::flock(input.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        input
    };

    let identity = input.metadata()?;
    let length = image_length(&input)?;
    let mut sector = 512_u32;
    {
        use std::os::{fd::AsRawFd, unix::fs::FileTypeExt};
        if identity.file_type().is_block_device() {
            if unsafe { libc::ioctl(input.as_raw_fd(), 0x1268, &mut sector) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if !sector.is_power_of_two() || !(512..=65536).contains(&sector) {
                return Err(reject("unsupported raw source sector geometry"));
            }
            // Bypass ordinary block page cache after prior buffered reads.
            // This does not bypass firmware caches or establish future health.
            // Buffers and ranges satisfy logical-sector direct I/O alignment.
            let flags = unsafe { libc::fcntl(input.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(input.as_raw_fd(), libc::F_SETFL, flags | libc::O_DIRECT) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    if length == 0 || length % u64::from(sector) != 0 {
        return Err(reject("invalid raw source length"));
    }
    Ok((input, length, sector))
}

/// Read every allocated/free physical sector. Report each failed interval;
/// EIO identifies unreadable bytes during this scan. Other failures stop it.
/// This does not mark clusters, change a bitmap, or clear a dirty flag.
pub fn surface_check(
    source: &Path,
    progress: &mut dyn FnMut(RepairProgress),
    unreadable: &mut dyn FnMut(u64, u64),
) -> io::Result<SurfaceReport> {
    let (mut input, length, sector) = open_surface_source(source)?;
    let identity = input.metadata()?;
    let mut terminal = None;
    let report = scan_surface_reader(
        &mut input,
        0..length,
        sector,
        &mut |_, _| Ok(()),
        &mut |offset, length| {
            unreadable(offset, length);
            Ok(())
        },
        &mut |value| {
            if value.completed_sectors == value.total_sectors {
                terminal = Some(value);
            } else {
                progress(value);
            }
        },
    )?;
    let current = input.metadata()?;
    if image_length(&input)? != length || (identity.is_file() && current.modified()? != identity.modified()?) {
        return Err(reject("source changed during surface scan"));
    }
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let path_identity = if identity.file_type().is_block_device() {
            std::fs::metadata(source)?
        } else {
            std::fs::symlink_metadata(source)?
        };
        if current.dev() != identity.dev()
            || current.ino() != identity.ino()
            || current.rdev() != identity.rdev()
            || current.ctime() != identity.ctime()
            || current.ctime_nsec() != identity.ctime_nsec()
            || path_identity.dev() != identity.dev()
            || path_identity.ino() != identity.ino()
            || path_identity.rdev() != identity.rdev()
        {
            return Err(reject("source identity changed during surface scan"));
        }
    }
    if let Some(value) = terminal {
        progress(value);
    }
    Ok(report)
}

#[cfg(test)]
#[path = "../tests/checker/surface_scan.rs"]
mod surface_scan_tests;

pub use log_resize::resize_to as resize_log_to;

#[cfg(test)]
#[path = "../tests/checker/log_resize_journal.rs"]
mod log_resize_journal_tests;

#[cfg(test)]
#[path = "../tests/checker/in_place_recovery.rs"]
mod in_place_recovery_tests;

#[cfg(test)]
#[path = "../tests/checker/file_recovery.rs"]
mod file_recovery_tests;

#[cfg(test)]
#[path = "../tests/checker/index_repair_journal.rs"]
mod index_repair_journal_tests;

#[cfg(test)]
include!("../tests/recovery/coordinator_support.rs");
