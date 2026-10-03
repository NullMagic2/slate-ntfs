//! Module: tests::checker::consistency_tests
//! Purpose: Verify split $MFT assembly, forced offline queues and cycle detection.
//! Created: 2026-10-03
//! Architecture: Included by slate_ntfs_tools::checker::consistency under cfg(test).

use super::*;

#[cfg(test)]
mod split_mft_checks {
    use super::*;
    use ntfs_rs::{record_edit as e, runlist::Extent};
    struct Memory(Vec<u8>);
    impl ReadAt for Memory {
        fn read_exact_at(&mut self, at: u64, out: &mut [u8]) -> ntfs_rs::Result<()> {
            out.copy_from_slice(self.0.get(at as usize..at as usize + out.len()).ok_or(ntfs_rs::Error::Io)?);
            Ok(())
        }
    }
    fn fixture(stale: bool) -> Volume<Memory> {
        let boot = BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_bytes: 4096,
            total_sectors: 512,
            mft_lcn: 4,
            mft_mirror_lcn: 2,
            record_bytes: 1024,
            index_block_bytes: 4096,
            serial_number: 1,
        };
        let mut base = vec![0; 1024];
        e::format_empty(&mut base, 0).unwrap();
        e::p16(&mut base, 16, 5).unwrap();
        e::p16(&mut base, 22, 1).unwrap();
        let mut a = vec![0; 1024];
        let n = e::build_nonresident(
            ATTR_DATA,
            &[],
            &[Extent { vcn: 0, lcn: Some(4), len: 4 }],
            32768,
            32768,
            32768,
            &mut a,
        )
        .unwrap();
        e::insert(&mut base, &a[..n]).unwrap();
        let mut ext = vec![0; 1024];
        e::format_empty(&mut ext, 3).unwrap();
        e::p16(&mut ext, 16, 7).unwrap();
        e::p16(&mut ext, 22, 1).unwrap();
        e::p64(&mut ext, 32, 5u64 << 48).unwrap();
        let n =
            e::build_nonresident(ATTR_DATA, &[], &[Extent { vcn: 0, lcn: Some(20), len: 4 }], 0, 0, 0, &mut a).unwrap();
        e::p64(&mut a, 16, 4).unwrap();
        e::p64(&mut a, 24, 7).unwrap();
        e::insert(&mut ext, &a[..n]).unwrap();
        let mut list = vec![0; 64];
        for (i, (vcn, reference)) in
            [(0, 5u64 << 48), (4, 3 | ((if stale { 8u64 } else { 7 }) << 48))].into_iter().enumerate()
        {
            let part = &mut list[i * 32..(i + 1) * 32];
            e::p32(part, 0, ATTR_DATA).unwrap();
            e::p16(part, 4, 32).unwrap();
            part[7] = 26;
            e::p64(part, 8, vcn).unwrap();
            e::p64(part, 16, reference).unwrap();
        }
        let n = e::build_resident(ATTR_ATTRIBUTE_LIST, &[], &list, &mut a).unwrap();
        e::insert(&mut base, &a[..n]).unwrap();
        ntfs_rs::replay::protect_mft_record(&mut base, 512).unwrap();
        ntfs_rs::replay::protect_mft_record(&mut ext, 512).unwrap();
        let mut image = vec![0; 512 * 512];
        image[16384..17408].copy_from_slice(&base);
        image[19456..20480].copy_from_slice(&ext);
        image[86016..87040].fill(0x5a);
        Volume::new(Memory(image), boot).unwrap()
    }
    #[test]
    fn resolves_a_record_beyond_base_mft_extent() {
        let mut volume = fixture(false);
        let image = mft_image(&mut volume).unwrap();
        let mft = MftRecord::from_decoded(&image).unwrap();
        let mut record = vec![0; 1024];
        volume.read_mft_record(&mft, 20, &mut record).unwrap();
        assert!(record.iter().all(|b| *b == 0x5a));
    }
    #[test]
    fn stale_mft_extension_is_rejected() {
        assert!(mft_image(&mut fixture(true)).is_err());
    }
}

#[cfg(test)]
mod forced_offline_queue_tests {
    use super::super::super::{queue_scan_findings, read_spotfix_ticket, verify_spotfix_worklist, OnlineScanOptions};
    use super::*;

    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn forced_queue_retains_all_defects_and_planner_blocker() {
        let directory = Directory(std::env::temp_dir().join(format!(
            "slate-forceoffline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let parent = File::open(&directory.0).unwrap();
        let queue = directory.0.join("scan.queue");
        let mut audit = Audit::default();
        audit.worklist = Some(scratch_file().unwrap());
        audit.complete = true;
        audit.directory_cycles_checked = true;
        audit.finding("unsupported-layout", Some(25), "requires full offline repair");
        audit.finding("security-invalid", Some(26), "invalid descriptor");
        audit.finding("cross-linked-clusters", Some(27), "shared cluster");
        let boot = BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_bytes: 4096,
            total_sectors: 1024,
            mft_lcn: 4,
            mft_mirror_lcn: 2,
            record_bytes: 1024,
            index_block_bytes: 4096,
            serial_number: 123,
        };
        let mut status = OnlineRepairStatus {
            unresolved_findings: audit.errors,
            blocker: Some("unsupported-layout".into()),
            ..Default::default()
        };
        // Default mode still requires a successful planner preflight.
        queue_scan_findings(&queue, &parent, 42, boot, &mut audit, &mut status, OnlineScanOptions::default()).unwrap();
        assert!(!queue.exists());
        queue_scan_findings(
            &queue,
            &parent,
            42,
            boot,
            &mut audit,
            &mut status,
            OnlineScanOptions { force_offline_fix: true, ..Default::default() },
        )
        .unwrap();
        assert!(status.queue_written);
        assert_eq!(status.queued_findings, 3);
        assert_eq!(status.unresolved_findings, 3);
        assert_eq!(status.blocker.as_deref(), Some("unsupported-layout"));
        let ticket = read_spotfix_ticket(&queue).unwrap();
        assert_eq!((ticket.device, ticket.serial, ticket.sectors, ticket.errors), (42, 123, 1024, 3));
        verify_spotfix_worklist(&queue, &mut audit, ticket).unwrap();
        let bytes = std::fs::read(&queue).unwrap();
        assert_eq!(
            queue_scan_findings(
                &queue,
                &parent,
                42,
                boot,
                &mut audit,
                &mut status,
                OnlineScanOptions { force_offline_fix: true, ..Default::default() }
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&queue).unwrap(), bytes);
        // A different post-scan defect must not be accepted by spotfix.
        audit.finding("new-defect", Some(28), "volume changed");
        assert!(verify_spotfix_worklist(&queue, &mut audit, ticket).is_err());
    }

    #[test]
    fn queued_index_policy_preserves_legacy_offsets_and_rejects_changes() {
        let directory = Directory(std::env::temp_dir().join(format!(
            "slate-index-queue-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let parent = File::open(&directory.0).unwrap();
        let boot = BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_bytes: 4096,
            total_sectors: 1024,
            mft_lcn: 4,
            mft_mirror_lcn: 2,
            record_bytes: 1024,
            index_block_bytes: 4096,
            serial_number: 123,
        };
        let checksum = |bytes: &mut Vec<u8>, at: usize| {
            let hash = bytes[..at]
                .iter()
                .fold(0xcbf29ce484222325_u64, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3));
            bytes[at..at + 8].copy_from_slice(&hash.to_le_bytes());
        };
        for (number, policy) in [
            AuditOptions::default(),
            AuditOptions {
                index_check: IndexCheck::Quick,
                index_cache_passes: IndexCachePasses::Streaming,
                ..Default::default()
            },
            AuditOptions {
                index_cache_passes: IndexCachePasses::Count(std::num::NonZeroU16::new(3).unwrap()),
                ..Default::default()
            },
        ]
        .into_iter()
        .enumerate()
        {
            let queue = directory.0.join(format!("scan-{number}.queue"));
            let mut audit = Audit {
                index_check: policy.index_check,
                directory_cycles_checked: true,
                complete: true,
                worklist: Some(scratch_file().unwrap()),
                ..Default::default()
            };
            audit.finding("directory-index-stale", Some(37), "sequence mismatch");
            queue_scan_findings(
                &queue,
                &parent,
                42,
                boot,
                &mut audit,
                &mut OnlineRepairStatus::default(),
                OnlineScanOptions { force_offline_fix: true, index_audit: policy, ..Default::default() },
            )
            .unwrap();
            let ticket = read_spotfix_ticket(&queue).unwrap();
            assert_eq!(ticket.index_audit, policy);
            verify_spotfix_worklist(&queue, &mut audit, ticket).unwrap();
            audit.index_check =
                if policy.index_check == IndexCheck::Quick { IndexCheck::Full } else { IndexCheck::Quick };
            assert!(verify_spotfix_worklist(&queue, &mut audit, ticket).is_err());
            audit.index_check = policy.index_check;

            let original = std::fs::read(&queue).unwrap();
            assert_eq!(&original[..8], b"SLTSPT04");
            let mut invalid = original.clone();
            invalid[71] |= 0x80;
            checksum(&mut invalid, 72);
            std::fs::write(&queue, &invalid).unwrap();
            assert!(read_spotfix_ticket(&queue).unwrap_err().to_string().contains("invalid spotfix index policy"));
            let mut corrupt = original.clone();
            *corrupt.last_mut().unwrap() ^= 1;
            std::fs::write(&queue, corrupt).unwrap();
            assert!(read_spotfix_ticket(&queue).is_err());

            if policy == AuditOptions::default() {
                let mut legacy = original.clone();
                legacy[..8].copy_from_slice(b"SLTSPT03");
                legacy.drain(64..72);
                checksum(&mut legacy, 64);
                std::fs::write(&queue, legacy).unwrap();
                let ticket = read_spotfix_ticket(&queue).unwrap();
                assert_eq!(ticket.index_audit, AuditOptions::default());
                verify_spotfix_worklist(&queue, &mut audit, ticket).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod directory_cycle_tests {
    use super::*;
    use std::io::Read;

    fn check(directories: &[u64], files: &[u64], edges: &[(u64, u64)]) -> Audit {
        check_with_options(directories, files, edges, AuditOptions::default())
    }

    fn check_with_options(directories: &[u64], files: &[u64], edges: &[(u64, u64)], options: AuditOptions) -> Audit {
        let slots = directories.iter().chain(files).copied().max().unwrap_or(5) + 1;
        let records = RecordStore::new(slots).unwrap();
        for (&number, directory) in directories.iter().map(|n| (n, true)).chain(files.iter().map(|n| (n, false))) {
            records
                .insert(
                    number,
                    Record {
                        reference: number | (1 << 48),
                        base: 0,
                        directory,
                        names: Vec::new(),
                        has_attribute_list: false,
                        canonical: None,
                    },
                )
                .unwrap();
        }
        let mut sorted = DiskInventory::new();
        for &(owner, child) in edges {
            sorted.push([owner, child, 0, 0]).unwrap();
        }
        let mut children = sorted.finish().unwrap();
        let mut audit = Audit::default();
        audit.worklist = Some(scratch_file().unwrap());
        audit_directory_cycles(&records, &mut children, &mut audit, options).unwrap();
        audit
    }

    #[test]
    fn reduced_check_skips_cycles_and_marks_coverage() {
        let edges = [(5, 24), (24, 25), (25, 24)];
        let full = check(&[5, 24, 25], &[], &edges);
        assert_eq!(full.errors, 1);
        assert!(full.directory_cycles_checked);
        let reduced = check_with_options(
            &[5, 24, 25],
            &[],
            &edges,
            AuditOptions { skip_directory_cycles: true, ..Default::default() },
        );
        assert_eq!(reduced.errors, 0);
        assert!(!reduced.directory_cycles_checked);
    }

    #[test]
    fn finds_reachable_disconnected_and_self_directory_cycles() {
        let audit = check(&[5, 24, 25, 26, 27, 28], &[], &[(5, 24), (24, 25), (25, 24), (26, 27), (27, 26), (28, 28)]);
        assert_eq!(audit.errors, 3);
        let mut worklist = audit.worklist.unwrap();
        worklist.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        worklist.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes.windows(b"directory-cycle".len()).filter(|w| *w == b"directory-cycle").count(), 3);
    }

    #[test]
    fn aliases_file_hardlinks_root_self_link_and_deep_tree_are_not_cycles() {
        let directories: Vec<_> = std::iter::once(5).chain(24..4096).collect();
        let mut edges = vec![(5, 5), (5, 24), (5, 24), (24, 5000), (25, 5000)];
        edges.extend((24..4095).map(|n| (n, n + 1)));
        assert_eq!(check(&directories, &[5000], &edges).errors, 0);
    }
}
