//! Module: in_place_recovery_tests
//! Purpose: Verify captured preimages and retired ranges bound journaled recovery.
//! Created: 2026-10-02
//! Architecture: Exercises the shared journal engine and source admission on
//!     private disposable descriptors; public writes require an offline device claim.

use super::*;

#[test]
fn capture_gap_rejects_changed_or_unreadable_good_bytes() {
    let bytes: Vec<u8> = (0..12288).map(|at| (at % 251) as u8).collect();
    let mut template = checker::consistency::scratch_file().unwrap();
    template.write_all(&bytes).unwrap();
    let mut locations = checker::consistency::scratch_file().unwrap();
    for number in 0..24_u64 {
        locations.write_all(&(number + 1).to_le_bytes()).unwrap();
    }
    let mut retired = checker::consistency::DiskInventory::new();
    retired.push([1, 0, 0, 0]).unwrap();
    let mut retired = retired.finish().unwrap();
    let mut current = bytes.clone();
    let mut input = std::io::Cursor::new(current.clone());
    verify_recovery_source(
        &mut input,
        &mut template,
        &mut locations,
        &mut retired,
        bytes.len() as u64,
        512,
        4096,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(input.into_inner(), current);
    current[4096..8192].fill(0);
    let error = verify_recovery_source(
        &mut std::io::Cursor::new(current.clone()),
        &mut template,
        &mut locations,
        &mut retired,
        bytes.len() as u64,
        512,
        4096,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("source changed"));
    current = bytes.clone();
    current[8192] ^= 1;
    let error = verify_recovery_source(
        &mut std::io::Cursor::new(current),
        &mut template,
        &mut locations,
        &mut retired,
        bytes.len() as u64,
        512,
        4096,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("source changed"));

    struct FailingReader(std::io::Cursor<Vec<u8>>);
    impl Read for FailingReader {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.0.position() < 512 {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                self.0.read(bytes)
            }
        }
    }
    impl Seek for FailingReader {
        fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
            self.0.seek(at)
        }
    }
    let error = verify_recovery_source(
        &mut FailingReader(std::io::Cursor::new(bytes.clone())),
        &mut template,
        &mut locations,
        &mut retired,
        bytes.len() as u64,
        512,
        4096,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("preimage now returns EIO"));
    locations.seek(SeekFrom::Start(0)).unwrap();
    locations.write_all(&0_u64.to_le_bytes()).unwrap();
    let error = verify_recovery_source(
        &mut std::io::Cursor::new(bytes),
        &mut template,
        &mut locations,
        &mut retired,
        12288,
        512,
        4096,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("unattempted"));
}

#[test]
fn retired_cluster_siblings_cannot_authorize_writes() {
    let mut retired = checker::consistency::DiskInventory::new();
    retired.push([1, 0, 0, 0]).unwrap();
    let mut retired = retired.finish().unwrap();
    for (offset, size, allowed) in [
        (0, 4096, true),
        (8192, 4096, true),
        (4096, 512, false),
        (7680, 512, false),
        (3584, 1024, false),
        (7680, 1024, false),
    ] {
        let mut changes = RepairPlan::new(12288).unwrap();
        changes.push(Patch::new(offset, vec![0; size], vec![1; size])).unwrap();
        assert_eq!(validate_recovery_plan(&changes, &mut retired, 4096).is_ok(), allowed, "{offset}/{size}");
    }
}

#[test]
fn changed_loss_binding_precedes_journal_and_target_writes() {
    let directory = std::env::temp_dir().join(format!(
        "slate-recovery-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let image = directory.join("source.img");
    let journal = directory.join("repair.journal");
    std::fs::write(&image, vec![0x5a; 4096]).unwrap();
    let archive = checker::consistency::scratch_file().unwrap();
    let mut loss_map = checker::consistency::scratch_file().unwrap();
    loss_map.write_all(b"retained loss").unwrap();
    let recovery = RecoveryJournal {
        archive_checksum: recovery_file_checksum(&archive).unwrap(),
        loss_map_checksum: recovery_file_checksum(&loss_map).unwrap(),
        archive,
        loss_map,
        changes: Some(RepairPlan::new(4096).unwrap()),
        template: None,
        bad: checker::consistency::scratch_file().unwrap(),
        cluster_bytes: 4096,
    };
    let mut altered = recovery.loss_map.try_clone().unwrap();
    altered.seek(SeekFrom::Start(0)).unwrap();
    altered.write_all(b"changed!").unwrap();
    let error = apply_in_place_journal(
        OpenOptions::new().read(true).write(true).open(&image).unwrap(),
        &journal,
        false,
        None,
        InPlaceOperation::Recover(&recovery),
        None,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("loss map changed"));
    assert!(!journal.exists());
    assert_eq!(std::fs::read(&image).unwrap(), vec![0x5a; 4096]);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn direct_sector_merges_preserve_current_unrelated_bytes() {
    struct AlignedDevice {
        bytes: std::io::Cursor<Vec<u8>>,
        sector: usize,
    }
    impl Read for AlignedDevice {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            assert_eq!(output.as_ptr().align_offset(self.sector), 0);
            assert_eq!(output.len() % self.sector, 0);
            assert_eq!(self.bytes.position() % self.sector as u64, 0);
            self.bytes.read(output)
        }
    }
    impl Write for AlignedDevice {
        fn write(&mut self, payload: &[u8]) -> io::Result<usize> {
            assert_eq!(payload.as_ptr().align_offset(self.sector), 0);
            assert_eq!(payload.len() % self.sector, 0);
            assert_eq!(self.bytes.position() % self.sector as u64, 0);
            self.bytes.write(payload)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Seek for AlignedDevice {
        fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(at)
        }
    }
    for sector in [512_u32, 4096, 65536] {
        let bytes: Vec<u8> = (0..3 * sector).map(|at| (at % 251) as u8).collect();
        let mut device = AlignedDevice { bytes: std::io::Cursor::new(bytes.clone()), sector: sector as usize };
        let offset = u64::from(sector) - 1;
        let mut readback = [0; 2];
        transfer_in_place_sectors(&mut device, sector, offset, &mut readback, false).unwrap();
        assert_eq!(readback, bytes[offset as usize..offset as usize + 2]);
        assert_eq!(device.bytes.get_ref(), &bytes);
        // A neighboring byte changes after the earlier read. Sector publication
        // must merge with its current value, rather than the old read buffer.
        device.bytes.get_mut()[0] ^= 0xff;
        let mut expected = device.bytes.get_ref().clone();
        expected[offset as usize..offset as usize + 2].copy_from_slice(&[0x91, 0x23]);
        transfer_in_place_sectors(&mut device, sector, offset, &mut [0x91, 0x23], true).unwrap();
        assert_eq!(device.bytes.get_ref(), &expected);
    }
}
