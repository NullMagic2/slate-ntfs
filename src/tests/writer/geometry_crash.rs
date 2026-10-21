//! Module: writer_crash::geometry_crash
//! Purpose: Verify replay of nonadjacent metadata writes after interruption.
//! Created: 2026-10-21
//! Architecture: Uses the volatile image adapter and production recovery;
//! directory membership and complete allocation audits check each surviving state.

use super::*;
use ntfs_rs::mft::{reference_number, system_record};

const ROOT_SEQUENCE: u16 = 5;
const FIRST_SECTOR_BYTES: usize = 512;
const SURVIVAL_MODES: usize = 4;

fn entries(image: &mut Image, boot: BootSector, number: u64) -> Vec<(String, u64)> {
    let mut volume = Volume::new(image, boot).unwrap();
    let mut zero = vec![0; ntfs_rs::volume::mft_space_bytes(boot.record_bytes as usize)];
    let mft = volume.load_mft(&mut zero).unwrap();
    let mut raw = vec![0; boot.record_bytes as usize];
    volume.read_mft_record(&mft, reference_number(number), &mut raw).unwrap();
    let parent = MftRecord::parse(&mut raw, boot.bytes_per_sector).unwrap();
    let mut block = vec![0; ntfs_rs::tx::BLOCK];
    let mut result = Vec::new();
    volume
        .visit_directory(&parent, &mut block, |entry| {
            let units: Vec<_> = entry
                .name
                .utf16le
                .chunks_exact(core::mem::size_of::<u16>())
                .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
                .collect();
            result.push((String::from_utf16(&units).unwrap(), entry.file_reference));
            Ok(())
        })
        .unwrap();
    result
}

#[test]
#[ignore = "requires SLATE_GEOMETRY_SCATTERED_SOURCE, the disposable scattered metadata fixture"]
fn scattered_metadata_delete_recovers_each_write_prefix() {
    let source = std::env::var_os("SLATE_GEOMETRY_SCATTERED_SOURCE").unwrap();
    let dir = crash_directory("geometry-scattered");
    let path = dir.join("cut.img");
    let mut image = Image { bytes: fs::read(&source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..FIRST_SECTOR_BYTES]).unwrap();
    let root = ntfs_rs::mft::file_reference(system_record::ROOT, ROOT_SEQUENCE).unwrap();
    let parent = entries(&mut image, boot, root).into_iter().find(|(name, _)| name == "scattered-directory").unwrap().1;
    let witness =
        entries(&mut image, boot, root).into_iter().find(|(name, _)| name == "scattered-witness.bin").unwrap().1;
    let original = entries(&mut image, boot, parent);
    let (name, victim) = original.iter().find(|(name, _)| name.starts_with("scattered-00-")).unwrap().clone();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::BLANK;
    writer.attach_journal_map(Box::leak(vec![0; ntfs_rs::resident_writer::JOURNAL_MAP_WORDS].into_boxed_slice()));
    writer.prepare_in(&mut image, boot, &mut scratch, |_| {}).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.remove_node(&mut image, parent, &name, victim, false, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let trace = std::mem::take(&mut image.trace);
    let mut durable = baseline.clone();
    let mut visible = baseline.clone();
    let mut checked = BTreeSet::new();
    for cut in 0..=trace.len() {
        let mut isolated = durable.clone();
        let mut torn = durable.clone();
        if cut != 0 {
            match &trace[cut - 1] {
                Some((at, bytes)) => {
                    let start = *at as usize;
                    let end = start + bytes.len();
                    visible[start..end].copy_from_slice(bytes);
                    isolated[start..end].copy_from_slice(bytes);
                    let len = bytes.len().min(FIRST_SECTOR_BYTES);
                    torn[start..start + len].copy_from_slice(&bytes[..len]);
                }
                None => durable.copy_from_slice(&visible),
            }
        }
        let variants: [&[u8]; SURVIVAL_MODES] = [&durable, &visible, &isolated, &torn];
        for (mode, bytes) in variants.into_iter().enumerate() {
            let mut hash = DefaultHasher::new();
            bytes.hash(&mut hash);
            if !checked.insert(hash.finish()) {
                continue;
            }
            fs::write(&path, bytes).unwrap();
            let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            super::super::recover_created_copy(&path, &mut file, &mut 0, None)
                .unwrap_or_else(|error| panic!("cut={cut} mode={mode}: {error}"));
            assert_eq!(content(&path, boot, witness), vec![b'S'; 8192], "cut={cut} mode={mode}");
            let mut recovered = Image { bytes: fs::read(&path).unwrap(), held: Vec::new(), trace: Vec::new() };
            let names = entries(&mut recovered, boot, parent);
            let present = names.iter().any(|(_, reference)| *reference == victim);
            assert_eq!(names.len(), original.len() - usize::from(!present));
            if present {
                assert_eq!(content(&path, boot, victim), vec![b'S'; 8192]);
            }
            let audit = crate::checker::consistency::audit(&path, boot, Default::default()).unwrap();
            assert!(audit.complete && audit.errors == 0, "cut={cut} mode={mode}: {:?}", audit.findings);
            assert_eq!(audit.allocated_clusters, audit.referenced_clusters);
        }
    }
    eprintln!(
        "PASS scattered metadata deletion: {} distinct replayed states across {} write/flush boundaries",
        checked.len(),
        trace.len()
    );
    fs::remove_dir_all(dir).unwrap();
}
