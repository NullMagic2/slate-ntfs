//! Module: slate_ntfs_tools::bin::ntfs_write_lab
//! Purpose: Experiment with writes on newly created offline image copies.
//! Created: 2026-10-01
//! Architecture: write_io overwrites existing initialized unnamed DATA after validation;
//! the command never authorizes kernel writes or metadata transactions.

use checker::{invalid, Image};
use ntfs_rs::mft::reference_number;
use slate_ntfs_tools::{checker, metadata_lab, write_io};

use ntfs_rs::boot::BootSector;
use ntfs_rs::hibernation::{write_gate, HibernationWriteGate};
use ntfs_rs::logfile::LogState;
use ntfs_rs::mft::{MftRecord, ATTR_ATTRIBUTE_LIST, ATTR_DATA};
use ntfs_rs::volume::Volume;
use ntfs_rs::write_plan::{plan_nonresident_overwrite, WriteSpan};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

fn hex_bytes(value: &str) -> io::Result<Vec<u8>> {
    if value.is_empty() || value.len() > 8192 || value.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "hex payload must contain 1..4096 bytes"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| io::ErrorKind::InvalidInput)?;
            u8::from_str_radix(text, 16).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid hex payload"))
        })
        .collect()
}

fn plan(source: &Path, boot: BootSector, name: &str, offset: u64, expected: &[u8]) -> io::Result<Vec<WriteSpan>> {
    let mut volume = Volume::new(Image(File::open(source)?), boot)?;
    let mut mft_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_zero(&mut mft_bytes)?;
    let mft = MftRecord::parse(&mut mft_bytes, boot.bytes_per_sector)?;
    let mut root_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, 5, &mut root_bytes)?;
    let root = MftRecord::parse(&mut root_bytes, boot.bytes_per_sector)?;
    let mut block =
        vec![0; boot.index_block_bytes as usize + 2 * ntfs_rs::tx::RECORD_IMAGE + 2 * boot.record_bytes as usize];
    let requested: Vec<u16> = name.encode_utf16().collect();
    let mut reference = None;
    volume.visit_directory(&root, &mut block, |entry| {
        if entry.name.code_units().eq(requested.iter().copied()) {
            if reference.replace(entry.file_reference).is_some() {
                return Err(ntfs_rs::Error::InvalidIndex);
            }
        }
        Ok(())
    })?;
    let reference = reference.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "root file not found"))?;
    let number = reference_number(reference);
    if number < 16 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "system file is not a lab target"));
    }
    let mut target_bytes = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, number, &mut target_bytes)?;
    let target = MftRecord::parse(&mut target_bytes, boot.bytes_per_sector)?;
    if target.sequence_number()? != (reference >> 48) as u16 || target.flags()? & 3 != 1 {
        return Err(invalid(ntfs_rs::Error::InvalidRecord));
    }
    let mut data = None;
    for entry in target.attributes() {
        let attribute = entry?;
        if matches!(attribute.kind, ATTR_ATTRIBUTE_LIST | 0xc0) {
            return Err(invalid(ntfs_rs::Error::Unsupported));
        }
        if attribute.kind == ATTR_DATA && attribute.name_utf16le()?.is_empty() {
            if data.replace(attribute).is_some() {
                return Err(invalid(ntfs_rs::Error::InvalidAttribute));
            }
        }
    }
    let data = data.ok_or(ntfs_rs::Error::InvalidAttribute)?;
    let mut original = vec![0; expected.len()];
    volume.read_attribute(data, offset, &mut original)?;
    if original != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "logical preimage differs from expected bytes"));
    }
    let mut spans = Vec::new();
    plan_nonresident_overwrite(data, boot, offset, expected.len() as u64, |span| {
        spans.push(span);
        Ok(())
    })?;
    Ok(spans)
}

fn run() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--metadata") {
        return metadata_lab::run(&args[1..]);
    }
    let journaled = args.first().is_some_and(|arg| arg == "--journaled");
    let args = if journaled { &args[1..] } else { &args[..] };
    let override_hibernation = args.first().is_some_and(|arg| arg == "--override-hibernation");
    let args = if override_hibernation { &args[1..] } else { &args[..] };
    if args.len() != 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "usage: ntfs-write-lab [--journaled|--override-hibernation] SOURCE_IMAGE NEW_IMAGE ROOT_FILENAME OFFSET EXPECTED_HEX REPLACEMENT_HEX"));
    }
    let source = PathBuf::from(&args[0]);
    let destination = PathBuf::from(&args[1]);
    let name =
        args[2].to_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root filename must be Unicode"))?;
    let offset = args[3]
        .to_str()
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset must be a nonnegative integer"))?;
    let expected = hex_bytes(args[4].to_str().unwrap_or(""))?;
    let replacement = hex_bytes(args[5].to_str().unwrap_or(""))?;
    if expected.len() != replacement.len() || expected == replacement {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "equal-length, differing byte strings are required"));
    }
    if journaled {
        if override_hibernation {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hibernation discard is not part of journaled overwrite",
            ));
        }
        let stop = env::var("SLATE_NTFS_TEST_STOP_AFTER_FLUSH")
            .ok()
            .map(|s| {
                s.parse::<usize>().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid flush boundary"))
            })
            .transpose()?;
        if stop.is_some_and(|n| !(1..=11).contains(&n)) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "flush boundary must be 1..11"));
        }
        return write_io::journaled_write_to(
            &source,
            &destination,
            name,
            offset as usize,
            &expected,
            &replacement,
            stop,
        );
    }
    if !File::open(&source)?.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "source must be a regular image file"));
    }
    let probe = checker::probe(&source)?;
    let recovery = checker::inspect_recovery(checker::Image::open(&source)?, probe.boot)?;
    match write_gate(recovery.hibernation, override_hibernation) {
        HibernationWriteGate::Clear => {}
        HibernationWriteGate::DiscardRequired => {
            return Err(io::Error::new(io::ErrorKind::Unsupported,
                "override requested, but transactional hiberfil.sys deletion is not implemented; source was not opened for writing"));
        }
        HibernationWriteGate::Blocked => {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "hibernation state blocks the write lab"));
        }
    }
    if probe.info.is_dirty() || recovery.log != LogState::Uninitialized {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "dirty or initialized-log image is not a lab target",
        ));
    }
    let spans = plan(&source, probe.boot, name, offset, &expected)?;
    let mut input = File::open(&source)?;
    let mut output = OpenOptions::new().read(true).write(true).create_new(true).open(&destination)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    // Validate all physical preimages before the first write.
    for span in &spans {
        let start = span.source_offset as usize;
        let len = span.length as usize;
        let mut bytes = vec![0; len];
        output.seek(SeekFrom::Start(span.physical_offset))?;
        output.read_exact(&mut bytes)?;
        if bytes != expected[start..start + len] {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "physical preimage differs from expected bytes"));
        }
    }
    for span in &spans {
        let start = span.source_offset as usize;
        let len = span.length as usize;
        output.seek(SeekFrom::Start(span.physical_offset))?;
        output.write_all(&replacement[start..start + len])?;
        output.sync_all()?;
    }
    drop(output);
    let mut copy = Volume::new(Image(File::open(&destination)?), probe.boot)?;
    let mut mft_bytes = vec![0; probe.boot.record_bytes as usize];
    copy.read_mft_zero(&mut mft_bytes)?;
    let mft = MftRecord::parse(&mut mft_bytes, probe.boot.bytes_per_sector)?;
    let mut root_bytes = vec![0; probe.boot.record_bytes as usize];
    copy.read_mft_record(&mft, 5, &mut root_bytes)?;
    let root = MftRecord::parse(&mut root_bytes, probe.boot.bytes_per_sector)?;
    let mut block = vec![
        0;
        probe.boot.index_block_bytes as usize
            + 2 * ntfs_rs::tx::RECORD_IMAGE
            + 2 * probe.boot.record_bytes as usize
    ];
    let requested: Vec<u16> = name.encode_utf16().collect();
    let mut reference = None;
    copy.visit_directory(&root, &mut block, |entry| {
        if entry.name.code_units().eq(requested.iter().copied()) {
            reference = Some(entry.file_reference);
        }
        Ok(())
    })?;
    let number = reference_number(reference.ok_or(ntfs_rs::Error::InvalidIndex)?);
    let mut target_bytes = vec![0; probe.boot.record_bytes as usize];
    copy.read_mft_record(&mft, number, &mut target_bytes)?;
    let target = MftRecord::parse(&mut target_bytes, probe.boot.bytes_per_sector)?;
    let mut actual = vec![0; replacement.len()];
    copy.read_data(&target, offset, &mut actual)?;
    if actual != replacement {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "written bytes failed logical readback"));
    }
    checker::audit_mft_records(&destination, probe.boot)?;
    checker::check_known_structures(&destination, probe.boot)?;
    println!("written_bytes={}", replacement.len());
    println!("physical_spans={}", spans.len());
    println!("destination={}", destination.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ntfs-write-lab: {error}");
        std::process::exit(1);
    }
}
