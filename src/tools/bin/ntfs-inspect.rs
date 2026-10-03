//! Module: slate_ntfs_tools::bin::ntfs_inspect
//! Purpose: Provide the ntfs-inspect command-line entry point.
//! Created: 2026-10-01
//! Architecture: Userspace commands use this module with checked core formats and owned image
//! I/O.

use ntfs_rs::boot::BootSector;
use ntfs_rs::mft::reference_number;
use ntfs_rs::mft::MftRecord;
use ntfs_rs::upcase::{UpcaseTable, UPCASE_BYTES};
use ntfs_rs::volume::{ReadAt, Volume};
use slate_ntfs_tools::bitlocker_cli::{self, SecretInput, USAGE};
use slate_ntfs_tools::checker::{invalid as invalid_data, Image};
use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

fn main() {
    if let Err(error) = run() {
        eprintln!("ntfs-inspect: {error}");
        std::process::exit(1);
    }
}

fn usage() -> String {
    format!("usage: ntfs-inspect [{USAGE}] <NTFS image or device> [root filename]")
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = None;
    let mut fd = None;
    let mut positional = Vec::new();
    for arg in env::args_os().skip(1) {
        if let Some(text) = arg.to_str() {
            if SecretInput::accept(&mut input, &mut fd, text)? {
                continue;
            }
        }
        positional.push(arg);
    }
    let input = SecretInput::finish(input, fd)?;
    if positional.is_empty() || positional.len() > 2 {
        return Err(usage().into());
    }
    let path = positional.remove(0);
    let requested_name =
        positional.pop().map(|name| name.into_string().map_err(|_| "root filename must be Unicode")).transpose()?;
    let mut image = File::open(&path)?;
    if bitlocker_cli::probe_file(&mut image)?.is_some() {
        let (reader, boot, unlocked) =
            bitlocker_cli::open_path(path.as_ref(), input.as_ref())?.ok_or("BitLocker header disappeared")?;
        println!(
            "BitLocker: {}; volume {}; fully encrypted={}",
            unlocked.key.method.name(),
            bitlocker_cli::guid_string(&unlocked.key.volume_guid),
            u8::from(unlocked.info.fully_encrypted())
        );
        let claimed_len =
            boot.total_sectors.checked_mul(u64::from(boot.bytes_per_sector)).ok_or("volume length overflow")?;
        if unlocked.device_bytes < claimed_len {
            return Err("device is shorter than the NTFS volume geometry".into());
        }
        let volume = Volume::new(reader, boot).map_err(invalid_data)?;
        return inspect(volume, boot, claimed_len, requested_name);
    }
    if input.is_some() {
        return Err("--bitlocker was given but the volume is not BitLocker-encrypted".into());
    }
    // BitLocker probing consumes bytes even for an ordinary NTFS volume.
    image.seek(SeekFrom::Start(0))?;
    let mut boot_bytes = [0_u8; 512];
    image.read_exact(&mut boot_bytes)?;
    let boot = BootSector::parse(&boot_bytes).map_err(invalid_data)?;
    let image_len = image.metadata()?.len();
    let claimed_len =
        boot.total_sectors.checked_mul(u64::from(boot.bytes_per_sector)).ok_or("volume length overflow")?;
    if image_len < claimed_len {
        return Err("image is shorter than the NTFS volume geometry".into());
    }
    let volume = Volume::new(Image(image), boot).map_err(invalid_data)?;
    inspect(volume, boot, claimed_len, requested_name)
}

fn inspect<R: ReadAt>(
    mut volume: Volume<R>,
    boot: BootSector,
    claimed_len: u64,
    requested_name: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut record_bytes = vec![0_u8; boot.record_bytes as usize];
    volume.read_mft_zero(&mut record_bytes).map_err(invalid_data)?;
    let record = MftRecord::parse(&mut record_bytes, boot.bytes_per_sector).map_err(invalid_data)?;
    let mut attribute_count = 0_u32;
    for attribute in record.attributes() {
        let _ = attribute.map_err(invalid_data)?;
        attribute_count += 1;
    }
    let mut root_bytes = vec![0_u8; boot.record_bytes as usize];
    volume.read_mft_record(&record, 5, &mut root_bytes).map_err(invalid_data)?;
    let root = MftRecord::parse(&mut root_bytes, boot.bytes_per_sector).map_err(invalid_data)?;
    if root.flags().map_err(invalid_data)? & 2 == 0 {
        return Err("MFT record 5 is not a directory".into());
    }
    let mut upcase_bytes = Vec::new();
    if requested_name.is_some() {
        let mut upcase_record_bytes = vec![0_u8; boot.record_bytes as usize];
        volume.read_mft_record(&record, 10, &mut upcase_record_bytes).map_err(invalid_data)?;
        let upcase_record = MftRecord::parse(&mut upcase_record_bytes, boot.bytes_per_sector).map_err(invalid_data)?;
        if upcase_record.flags().map_err(invalid_data)? & 1 == 0 {
            return Err("$UpCase MFT record is not in use".into());
        }
        let mut extension_bytes = vec![0_u8; 2 * ntfs_rs::tx::RECORD_IMAGE + boot.record_bytes as usize];
        let table_size =
            volume.data_size_resolved(&record, &upcase_record, 10, &mut extension_bytes).map_err(invalid_data)?;
        if table_size != UPCASE_BYTES as u64 {
            return Err("$UpCase has an unexpected size".into());
        }
        upcase_bytes.resize(UPCASE_BYTES, 0);
        volume
            .read_data_resolved(&record, &upcase_record, 10, &mut extension_bytes, 0, &mut upcase_bytes)
            .map_err(invalid_data)?;
    }
    let upcase =
        if requested_name.is_some() { Some(UpcaseTable::parse(&upcase_bytes).map_err(invalid_data)?) } else { None };
    let requested_units = requested_name.as_ref().map(|name| name.encode_utf16().collect::<Vec<_>>());
    let mut block_buffer =
        vec![0_u8; boot.index_block_bytes as usize + 2 * ntfs_rs::tx::RECORD_IMAGE + 2 * boot.record_bytes as usize];
    let mut root_entries = 0_u32;
    let mut found_reference = None;
    volume
        .visit_directory(&root, &mut block_buffer, |entry| {
            if upcase
                .as_ref()
                .zip(requested_units.as_ref())
                .is_some_and(|(table, units)| table.matches(entry.name, units))
            {
                match found_reference {
                    Some(existing) if existing != entry.file_reference => {
                        return Err(ntfs_rs::Error::InvalidIndex);
                    }
                    _ => found_reference = Some(entry.file_reference),
                }
            }
            root_entries += 1;
            Ok(())
        })
        .map_err(invalid_data)?;
    println!("NTFS volume serial: {:016x}", boot.serial_number);
    println!("sector/cluster/record: {}/{}/{} bytes", boot.bytes_per_sector, boot.cluster_bytes, boot.record_bytes);
    println!("volume size: {} bytes", claimed_len);
    println!("$MFT first record: valid fixups; {attribute_count} attributes");
    println!("root directory: {root_entries} reachable index entries");
    if let Some(name) = requested_name {
        let reference = found_reference.ok_or("root filename not found")?;
        let number = reference_number(reference);
        let sequence = (reference >> 48) as u16;
        let mut file_bytes = vec![0_u8; boot.record_bytes as usize];
        volume.read_mft_record(&record, number, &mut file_bytes).map_err(invalid_data)?;
        let file = MftRecord::parse(&mut file_bytes, boot.bytes_per_sector).map_err(invalid_data)?;
        if file.sequence_number().map_err(invalid_data)? != sequence {
            return Err("stale root directory file reference".into());
        }
        if file.flags().map_err(invalid_data)? & 3 != 1 {
            return Err("requested root entry is not an in-use regular file".into());
        }
        let mut extension_bytes = vec![0_u8; 2 * ntfs_rs::tx::RECORD_IMAGE + boot.record_bytes as usize];
        let size = volume.data_size_resolved(&record, &file, number, &mut extension_bytes).map_err(invalid_data)?;
        let preview_len = size.min(64) as usize;
        let mut preview = vec![0_u8; preview_len];
        volume
            .read_data_resolved(&record, &file, number, &mut extension_bytes, 0, &mut preview)
            .map_err(invalid_data)?;
        let hex: String = preview.iter().map(|byte| format!("{byte:02x}")).collect();
        println!("root file {name}: {size} bytes; first {preview_len} bytes: {hex}");
    }
    Ok(())
}
