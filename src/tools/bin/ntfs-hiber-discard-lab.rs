//! Module: slate_ntfs_tools::bin::ntfs_hiber_discard_lab
//! Purpose: Experiment with hiberfil unlinking on a newly copied image.
//! Created: 2026-10-01
//! Architecture: The laboratory uses shared preflight and preserves the read-only source.
//! Its uninitialized-log copy operation cannot authorize in-place repair or
//! kernel writes and cannot repair a Windows journal.

use checker::Image;
use ntfs_rs::mft::reference_number;
use slate_ntfs_tools::{checker, delete_plan};

use delete_plan::{plan_hiberfile_deletion, ClusterRange};
use ntfs_rs::boot::BootSector;
use ntfs_rs::hibernation::HibernationState;
use ntfs_rs::index::{IndexBlock, IndexRoot};
use ntfs_rs::logfile::LogState;
use ntfs_rs::mft::{MftRecord, ATTR_BITMAP, ATTR_DATA, ATTR_INDEX_ALLOCATION, ATTR_INDEX_ROOT};
use ntfs_rs::volume::Volume;
use ntfs_rs::write_plan::plan_nonresident_overwrite;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

struct Patch {
    offset: u64,
    before: Vec<u8>,
    after: Vec<u8>,
}

fn push_attribute_patch(
    patches: &mut Vec<Patch>,
    attr: ntfs_rs::mft::Attribute<'_>,
    boot: BootSector,
    logical_offset: u64,
    before: &[u8],
    after: &[u8],
) -> io::Result<()> {
    if before.len() != after.len() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    plan_nonresident_overwrite(attr, boot, logical_offset, before.len() as u64, |span| {
        let start = span.source_offset as usize;
        let end = start + span.length as usize;
        patches.push(Patch {
            offset: span.physical_offset,
            before: before[start..end].to_vec(),
            after: after[start..end].to_vec(),
        });
        Ok(())
    })?;
    Ok(())
}

fn hiber_reference(volume: &mut Volume<Image>, root: &MftRecord<'_>, boot: BootSector) -> io::Result<u64> {
    let mut block =
        vec![0; boot.index_block_bytes as usize + 2 * ntfs_rs::tx::RECORD_IMAGE + 2 * boot.record_bytes as usize];
    let mut reference = None;
    volume.visit_directory(root, &mut block, |entry| {
        let expected = b"hiberfil.sys";
        let mut name = entry.name.code_units();
        let matched = expected
            .iter()
            .all(|byte| name.next().is_some_and(|unit| unit <= 0x7f && (unit as u8).eq_ignore_ascii_case(byte)))
            && name.next().is_none();
        if matched && reference.replace(entry.file_reference).is_some() {
            return Err(ntfs_rs::Error::InvalidIndex);
        }
        Ok(())
    })?;
    reference.ok_or_else(|| io::ErrorKind::NotFound.into())
}

fn clear_allocated_bits(bitmap: &mut [u8], ranges: &[ClusterRange]) -> io::Result<()> {
    for range in ranges {
        for cluster in range.lcn..range.lcn + range.length {
            let byte = (cluster / 8) as usize;
            let mask = 1_u8 << (cluster % 8);
            let slot = bitmap.get_mut(byte).ok_or(io::ErrorKind::InvalidData)?;
            if *slot & mask == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "hiberfil cluster is not allocated"));
            }
            *slot &= !mask;
        }
    }
    Ok(())
}

fn build_patches(source: &Path, boot: BootSector) -> io::Result<Vec<Patch>> {
    let mut volume = Volume::new(Image(File::open(source)?), boot)?;
    let mut mft_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut mft_bytes)?;
    let mft = MftRecord::parse(&mut mft_bytes, boot.bytes_per_sector)?;
    let mft_data = mft.stream(ATTR_DATA, &[])?;

    let mut root_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 5, &mut root_bytes)?;
    let root = MftRecord::parse(&mut root_bytes, boot.bytes_per_sector)?;
    let reference = hiber_reference(&mut volume, &root, boot)?;

    let number = reference_number(reference);
    let mut file_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, number, &mut file_bytes)?;
    let file_before = file_bytes.clone();
    let mut ranges = Vec::new();
    {
        let file = MftRecord::parse(&mut file_bytes, boot.bytes_per_sector)?;
        plan_hiberfile_deletion(&file, reference, boot, |range| {
            ranges.push(range);
            Ok(())
        })?;
    }
    file_bytes[0x12..0x14].copy_from_slice(&0_u16.to_le_bytes());
    file_bytes[0x16..0x18].copy_from_slice(&0_u16.to_le_bytes());
    ntfs_rs::mft::protect_fixups(&mut file_bytes)?;
    let mut patches = Vec::new();
    push_attribute_patch(
        &mut patches,
        mft_data,
        boot,
        number * u64::from(boot.record_bytes),
        &file_before,
        &file_bytes,
    )?;

    let index_root = root.stream(ATTR_INDEX_ROOT, &[])?;
    let root_value = index_root.resident_value()?;
    let root_index = IndexRoot::parse(root_value)?;
    if !root_index.has_children() {
        return Err(unsupported("resident root index deletion is not supported by this lab"));
    }
    let index_attr = root.stream(ATTR_INDEX_ALLOCATION, &[])?;
    if index_attr.data_size()? != u64::from(boot.index_block_bytes) {
        return Err(unsupported("multi-block root index deletion is not supported by this lab"));
    }
    let mut index_bytes = vec![0; boot.index_block_bytes as usize];
    volume.read_attribute(index_attr, 0, &mut index_bytes)?;
    let index_before = index_bytes.clone();
    let (start, stop) = {
        let block = IndexBlock::parse(&mut index_bytes, boot.bytes_per_sector, 0)?;
        if block.has_children() {
            return Err(unsupported("nested root index deletion is not supported by this lab"));
        }
        let mut cursor = block.first_entry_offset();
        let mut found = None;
        loop {
            let slot = block.slot_at(cursor)?;
            if let Some(entry) = slot.entry {
                if entry.file_reference == reference {
                    if found.replace((cursor, slot.next_offset)).is_some() || slot.child_vcn.is_some() {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                }
            } else {
                break;
            }
            cursor = slot.next_offset;
        }
        found.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
    };
    let old_length = u32::from_le_bytes(index_bytes[0x1c..0x20].try_into().unwrap()) as usize;
    let end = 0x18 + old_length;
    let removed = stop - start;
    if stop > end || end > index_bytes.len() || removed == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    index_bytes.copy_within(stop..end, start);
    index_bytes[end - removed..end].fill(0);
    index_bytes[0x1c..0x20].copy_from_slice(&((old_length - removed) as u32).to_le_bytes());
    ntfs_rs::mft::protect_fixups(&mut index_bytes)?;
    push_attribute_patch(&mut patches, index_attr, boot, 0, &index_before, &index_bytes)?;

    let mft_bitmap = mft.stream(ATTR_BITMAP, &[])?;
    let mft_bitmap_size = mft_bitmap.data_size()? as usize;
    if mft_bitmap_size > 16 * 1024 * 1024 {
        return Err(unsupported("MFT bitmap exceeds lab limit"));
    }
    let mut mft_bits = vec![0; mft_bitmap_size];
    volume.read_attribute(mft_bitmap, 0, &mut mft_bits)?;
    let mft_bits_before = mft_bits.clone();
    clear_allocated_bits(&mut mft_bits, &[ClusterRange { lcn: number, length: 1 }])?;
    push_attribute_patch(&mut patches, mft_bitmap, boot, 0, &mft_bits_before, &mft_bits)?;

    let mut volume_bitmap_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 6, &mut volume_bitmap_bytes)?;
    let volume_bitmap = MftRecord::parse(&mut volume_bitmap_bytes, boot.bytes_per_sector)?;
    let bitmap_attr = volume_bitmap.stream(ATTR_DATA, &[])?;
    let bitmap_size = bitmap_attr.data_size()? as usize;
    if bitmap_size > 64 * 1024 * 1024 {
        return Err(unsupported("volume bitmap exceeds lab limit"));
    }
    let mut bits = vec![0; bitmap_size];
    volume.read_attribute(bitmap_attr, 0, &mut bits)?;
    let bits_before = bits.clone();
    clear_allocated_bits(&mut bits, &ranges)?;
    push_attribute_patch(&mut patches, bitmap_attr, boot, 0, &bits_before, &bits)?;

    patches.sort_by_key(|patch| patch.offset);
    for window in patches.windows(2) {
        let end = window[0].offset.checked_add(window[0].before.len() as u64).ok_or(io::ErrorKind::InvalidData)?;
        if end > window[1].offset {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(patches)
}

fn apply_patches(candidate: &mut File, patches: &[Patch]) -> io::Result<()> {
    for patch in patches {
        let mut actual = vec![0; patch.before.len()];
        candidate.seek(SeekFrom::Start(patch.offset))?;
        candidate.read_exact(&mut actual)?;
        if actual != patch.before {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "physical preimage changed"));
        }
    }
    for patch in patches {
        candidate.seek(SeekFrom::Start(patch.offset))?;
        candidate.write_all(&patch.after)?;
    }
    candidate.sync_all()
}

fn run() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--override-hibernation")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: ntfs-hiber-discard-lab --override-hibernation SOURCE.img NEW-COPY.img",
        ));
    }
    let source = PathBuf::from(args.next().ok_or(io::ErrorKind::InvalidInput)?);
    let destination = PathBuf::from(args.next().ok_or(io::ErrorKind::InvalidInput)?);
    if args.next().is_some() || !source.is_file() || destination.exists() || source == destination {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let probe = checker::probe(&source)?;
    let recovery = checker::inspect_recovery(checker::Image::open(&source)?, probe.boot)?;
    if probe.info.is_dirty()
        || recovery.log != LogState::Uninitialized
        || recovery.hibernation != HibernationState::ActiveImage
    {
        return Err(unsupported(
            "copy-only deletion requires clean flags, an uninitialized log, and a recognized active HIBR image",
        ));
    }
    let patches = build_patches(&source, probe.boot)?;
    let temp = destination.with_file_name(format!(
        "{}.incomplete-{}",
        destination.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    let mut input = File::open(&source)?;
    let mut output = OpenOptions::new().read(true).write(true).create_new(true).open(&temp)?;
    let result = (|| -> io::Result<()> {
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        apply_patches(&mut output, &patches)?;
        drop(output);
        let after = checker::inspect_recovery(checker::Image::open(&temp)?, probe.boot)?;
        if after.hibernation != HibernationState::Absent || after.log != LogState::Uninitialized {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "post-delete recovery check failed"));
        }
        checker::audit_mft_records(&temp, probe.boot)?;
        checker::check_known_structures(&temp, probe.boot)?;
        if destination.exists() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        fs::rename(&temp, &destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    println!("discarded_hibernation=1");
    println!("metadata_spans={}", patches.len());
    println!("destination={}", destination.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ntfs-hiber-discard-lab: {error}");
        std::process::exit(1);
    }
}
