//! Module: recovery_io::bad_cluster_reassessment_tests
//! Purpose: Verify declared-bad transitions and authenticated publication resume.
//! Created: 2026-11-24
//! Architecture: Uses the real repair planner and shared archive fixtures on
//! private regular images; public device admission is checked independently.

use super::file_recovery_tests::{append_test_entry, error_archive};
use super::*;
use ntfs_rs::mft::system_record;
use ntfs_rs::runlist::DataRuns;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const SOURCE_ENV: &str = "SLATE_B12_SOURCE";
const FIRST_CANDIDATE_CLUSTER: u64 = 64;
const DECLARED_CLUSTER_COUNT: usize = 3;
const CANDIDATE_CLUSTER_COUNT: usize = DECLARED_CLUSTER_COUNT + 2;
const MAX_INTERRUPTION_BOUNDARIES: u64 = 64;
const TEST_DIRECTORY_MODE: u32 = 0o700;
const TEST_CLUSTER_BYTES: u32 = 4096;
const REASSESS_MAGIC: &[u8; 8] = b"SLTRCB02";

fn options() -> RepairOptions {
    RepairOptions { rescan_bad_clusters: true, ..Default::default() }
}

fn directory(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("slate-b12-{label}-{}-{unique}", std::process::id()));
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(TEST_DIRECTORY_MODE)).unwrap();
    path
}

fn bad_clusters(source: &Path) -> BTreeSet<u64> {
    let mut volume = checker::open_volume(source).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, system_record::BADCLUS).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, b"$\0B\0a\0d\0").unwrap();
    let mut clusters = BTreeSet::new();
    for run in DataRuns::new(data.data_runs().unwrap(), 0) {
        let run = run.unwrap();
        if let Some(lcn) = run.lcn {
            assert_eq!(lcn, run.vcn);
            clusters.extend(lcn..lcn + run.len);
        }
    }
    clusters
}

fn allocation(source: &Path, cluster: u64) -> bool {
    let mut volume = checker::open_volume(source).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, system_record::BITMAP).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let mut byte = [0];
    volume.read_attribute(data, cluster / u64::from(u8::BITS), &mut byte).unwrap();
    byte[0] & (1 << (cluster % u64::from(u8::BITS))) != 0
}

fn planned_allocation(source: &Path, patches: &RepairPlan, boot: BootSector, cluster: u64) -> bool {
    let mut volume = PlannedImage::volume(source, patches, boot).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let bitmap = checked_family_image(&mut volume, &mft, system_record::BITMAP).unwrap();
    let bitmap = MftRecord::from_decoded(&bitmap).unwrap();
    let mut byte = [0];
    volume.read_attribute(bitmap.stream(ATTR_DATA, &[]).unwrap(), cluster / u64::from(u8::BITS), &mut byte).unwrap();
    byte[0] & (1 << (cluster % u64::from(u8::BITS))) != 0
}

fn declared_fixture(directory: &Path) -> (PathBuf, BootSector, Vec<u64>) {
    let input = PathBuf::from(std::env::var_os(SOURCE_ENV).expect("Set SLATE_B12_SOURCE to a fresh disposable image"));
    let source = directory.join("declared.img");
    std::fs::copy(input, &source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let audit = checker::consistency::audit(&source, boot, Default::default()).unwrap();
    assert!(audit.complete && audit.errors == 0);
    let count = boot.total_sectors / u64::from(boot.sectors_per_cluster);
    let candidates: Vec<_> = (FIRST_CANDIDATE_CLUSTER..count)
        .filter(|cluster| !allocation(&source, *cluster))
        .step_by(DECLARED_CLUSTER_COUNT)
        .take(CANDIDATE_CLUSTER_COUNT)
        .collect();
    assert_eq!(candidates.len(), CANDIDATE_CLUSTER_COUNT);
    let mut bad = checker::consistency::DiskInventory::new();
    for cluster in &candidates[..DECLARED_CLUSTER_COUNT] {
        bad.push([*cluster, 0, 0, 0]).unwrap();
    }
    let bad = bad.finish().unwrap();
    let plan =
        structural_repair_plan(&source, &mut |_| {}, PlanInputs { bad: Some(&bad), ..Default::default() }).unwrap();
    let output = OpenOptions::new().read(true).write(true).open(&source).unwrap();
    for patch in plan.iter() {
        patch.unwrap().apply_to(&output, "test fixture preimage changed").unwrap();
    }
    output.sync_all().unwrap();
    assert_eq!(bad_clusters(&source), candidates[..DECLARED_CLUSTER_COUNT].iter().copied().collect());
    assert!(checker::check_device(&source, Default::default(), None).unwrap().passed());
    (source, boot, candidates)
}

#[test]
fn reassessment_journal_policy_has_a_distinct_identity() {
    let recovery = RecoveryJournal {
        archive: checker::consistency::scratch_file().unwrap(),
        loss_map: checker::consistency::scratch_file().unwrap(),
        archive_checksum: 0,
        loss_map_checksum: 0,
        changes: None,
        template: None,
        bad: checker::consistency::scratch_file().unwrap(),
        cluster_bytes: TEST_CLUSTER_BYTES,
        rescan_bad_clusters: true,
        latest_classification: true,
    };
    assert_eq!(InPlaceOperation::Recover(&recovery).magic(), REASSESS_MAGIC);
    let reassessment_header = InPlaceOperation::Recover(&recovery).header_bytes();
    let ordinary = RecoveryJournal { rescan_bad_clusters: false, ..recovery };
    assert_ne!(InPlaceOperation::Recover(&ordinary).magic(), REASSESS_MAGIC);
    assert_eq!(InPlaceOperation::Recover(&ordinary).header_bytes(), reassessment_header);
}

#[test]
fn recovery_reassessment_refuses_unrelated_maintenance_options() {
    assert!(validate_recovery_options(options()).is_ok());
    assert!(validate_recovery_options(RepairOptions { cleanup_security: true, ..options() }).is_err());
    assert!(validate_recovery_options(RepairOptions {
        index_audit: checker::consistency::AuditOptions { skip_directory_cycles: true, ..Default::default() },
        ..options()
    })
    .is_err());
}

#[test]
#[ignore = "requires SLATE_B12_SOURCE formatted disposable image"]
fn reassessment_releases_only_readable_declarations_and_retains_new_failures() {
    let directory = directory("transitions");
    let (source, boot, candidates) = declared_fixture(&directory);
    let original = std::fs::read(&source).unwrap();
    let archive = directory.join("complete.rescue");
    let failed: Vec<_> = [candidates[1], candidates[DECLARED_CLUSTER_COUNT]]
        .into_iter()
        .map(|cluster| cluster * u64::from(boot.cluster_bytes))
        .collect();
    error_archive(&source, &archive, &original, &failed, false);
    for reassess in [false, true] {
        let label = if reassess { "reassessed" } else { "preserved" };
        let output = directory.join(format!("{label}.img"));
        let map = directory.join(format!("{label}.tsv"));
        let options = RepairOptions { rescan_bad_clusters: reassess, ..Default::default() };
        let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, options).unwrap();
        assert!(!report.has_data_loss());
        assert_eq!(report.unreadable_bytes, 2 * boot.bytes_per_sector as u64);
        let expected: BTreeSet<_> = if reassess {
            [candidates[1], candidates[DECLARED_CLUSTER_COUNT]].into_iter().collect()
        } else {
            candidates[..=DECLARED_CLUSTER_COUNT].iter().copied().collect()
        };
        assert_eq!(bad_clusters(&output), expected);
        for cluster in &candidates {
            assert_eq!(allocation(&output, *cluster), expected.contains(cluster));
        }
        assert!(checker::check_device(&output, Default::default(), None).unwrap().passed());
        assert_eq!(std::fs::read_to_string(map).unwrap().contains("bad_cluster_reassessment=1"), reassess);
    }
    let readable_archive = directory.join("readable.rescue");
    let readable_map = directory.join("readable.tsv");
    let readable_output = directory.join("readable.img");
    let report = recover_rescue_to_with_options(
        &source,
        &readable_archive,
        &readable_map,
        &readable_output,
        false,
        &mut |_| {},
        options(),
    )
    .unwrap();
    assert_eq!(report.unreadable_bytes, 0);
    assert!(!report.has_data_loss());
    assert!(bad_clusters(&readable_output).is_empty());
    assert!(checker::check_device(&readable_output, Default::default(), None).unwrap().passed());
    let retained_bytes = std::fs::metadata(&readable_archive).unwrap().len();
    capture_surface(&source, &readable_archive, true, true, &mut |_| {}).unwrap();
    assert_eq!(std::fs::metadata(&readable_archive).unwrap().len(), retained_bytes);
    if let Some(output) = std::env::var_os("SLATE_B12_RESULTS") {
        let output = PathBuf::from(output);
        std::fs::create_dir_all(&output).unwrap();
        for (input, name) in [
            (&source, "declared.img"),
            (&readable_output, "all-readable-result.img"),
            (&directory.join("reassessed.img"), "persistent-new-result.img"),
        ] {
            std::fs::copy(input, output.join(name)).unwrap();
        }
    }
    for (label, failed, omit) in [("critical", 0, false), ("partial", failed[1], true)] {
        let archive = directory.join(format!("{label}.rescue"));
        error_archive(&source, &archive, &original, &[failed], omit);
        let map = directory.join(format!("{label}.tsv"));
        let output = directory.join(format!("{label}.img"));
        assert!(recover_archive_to(&archive, &map, &output, &mut |_| {}, options()).is_err());
        assert!(!map.exists() && !output.exists());
        assert_eq!(bad_clusters(&source), candidates[..DECLARED_CLUSTER_COUNT].iter().copied().collect());
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_B12_SOURCE formatted disposable image; serial environment fault injection"]
fn reassessment_journal_resumes_every_durable_boundary_and_rejects_changed_policy() {
    let directory = directory("journal");
    let (fixture, _, candidates) = declared_fixture(&directory);
    let original = std::fs::read(&fixture).unwrap();
    let source = directory.join("device.img");
    let mut completed = false;
    let mut interrupted = 0;
    for boundary in 1..=MAX_INTERRUPTION_BOUNDARIES {
        std::fs::write(&source, &original).unwrap();
        let archive = directory.join(format!("capture-{boundary}.rescue"));
        error_archive(&source, &archive, &original, &[], false);
        let map = directory.join(format!("loss-{boundary}.tsv"));
        let journal = directory.join(format!("repair-{boundary}.journal"));
        unsafe {
            std::env::set_var("SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC", boundary.to_string());
        }
        let result = recover_archive_on_claimed_source(
            OpenOptions::new().read(true).write(true).open(&source).unwrap(),
            &archive,
            &map,
            &journal,
            false,
            &mut |_| {},
            options(),
        );
        unsafe {
            std::env::remove_var("SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC");
        }
        if let Err(error) = result {
            assert!(error.to_string().contains("injected"), "boundary {boundary}: {error}");
            interrupted += 1;
            let stopped = std::fs::read(&source).unwrap();
            let refused = recover_archive_on_claimed_source(
                OpenOptions::new().read(true).write(true).open(&source).unwrap(),
                &archive,
                &map,
                &journal,
                true,
                &mut |_| {},
                RepairOptions::default(),
            );
            assert!(refused.is_err(), "resume must preserve the original reassessment policy");
            assert_eq!(std::fs::read(&source).unwrap(), stopped);
            recover_archive_on_claimed_source(
                OpenOptions::new().read(true).write(true).open(&source).unwrap(),
                &archive,
                &map,
                &journal,
                true,
                &mut |_| {},
                options(),
            )
            .unwrap();
        } else {
            completed = true;
        }
        assert!(bad_clusters(&source).is_empty());
        for cluster in &candidates[..DECLARED_CLUSTER_COUNT] {
            assert!(!allocation(&source, *cluster));
        }
        assert!(checker::check_device(&source, Default::default(), None).unwrap().passed());
        for path in [archive, map] {
            std::fs::remove_file(path).unwrap();
        }
        let mut completed_name = journal.as_os_str().to_owned();
        completed_name.push(".completed");
        let completed_journal = PathBuf::from(completed_name);
        assert!(completed_journal.exists());
        std::fs::remove_file(completed_journal).unwrap();
        if completed {
            break;
        }
    }
    assert!(completed && interrupted > 0);
    std::eprintln!("B12 interruption boundaries passed: {interrupted}");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scheduled_capture_identity_exception_preserves_geometry_and_checksums() {
    const SOURCE_WORDS: [u64; 7] = [4096, 11, 12, 13, 0, 0, 512];
    const WORD_BYTES: usize = std::mem::size_of::<u64>();
    fn checksum(header: &mut [u8]) {
        let checksum = repair_checksum(0, &header[..RESCUE_CHECKSUM_OFFSET]);
        header[RESCUE_CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_le_bytes());
    }
    let mut expected = b"SLTRSC01".to_vec();
    for word in SOURCE_WORDS {
        expected.extend_from_slice(&word.to_le_bytes());
    }
    expected.resize(RESCUE_HEADER_BYTES, 0);
    checksum(&mut expected);
    assert!(rescue_header_matches(&expected, &expected, false).unwrap());
    for offset in (RESCUE_IDENTITY_START..RESCUE_IDENTITY_END).step_by(WORD_BYTES) {
        let mut captured = expected.clone();
        captured[offset] ^= 1;
        checksum(&mut captured);
        assert!(!rescue_header_matches(&captured, &expected, false).unwrap());
        assert!(rescue_header_matches(&captured, &expected, true).unwrap());
        captured[RESCUE_CHECKSUM_OFFSET] ^= 1;
        assert!(!rescue_header_matches(&captured, &expected, true).unwrap());
    }
    for offset in
        (0..RESCUE_CHECKSUM_OFFSET).filter(|offset| !(RESCUE_IDENTITY_START..RESCUE_IDENTITY_END).contains(offset))
    {
        let mut captured = expected.clone();
        captured[offset] ^= 1;
        checksum(&mut captured);
        assert!(!rescue_header_matches(&captured, &expected, true).unwrap());
    }
    assert!(!rescue_header_matches(&expected[..RESCUE_CHECKSUM_OFFSET], &expected, true).unwrap());
}

#[test]
#[ignore = "requires SLATE_B12_SOURCE formatted disposable image"]
fn reassessment_uses_latest_complete_reads_while_preserving_error_history() {
    let directory = directory("retry-outcomes");
    let (source, boot, candidates) = declared_fixture(&directory);
    let original = std::fs::read(&source).unwrap();
    let sector = u64::from(boot.bytes_per_sector);
    let first = candidates[0] * u64::from(boot.cluster_bytes);
    let newly_bad = candidates[DECLARED_CLUSTER_COUNT] * u64::from(boot.cluster_bytes);
    let archive = directory.join("retry.rescue");
    error_archive(&source, &archive, &original, &[first, first + sector, newly_bad], false);
    for (index, at) in [first, first + sector].into_iter().enumerate() {
        let mut output = OpenOptions::new().append(true).open(&archive).unwrap();
        append_test_entry(&mut output, at, sector, 0, &original[at as usize..(at + sector) as usize]);
        output.sync_all().unwrap();
        let output = directory.join(format!("retry-{index}.img"));
        let map = directory.join(format!("retry-{index}.tsv"));
        let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, options()).unwrap();
        assert_eq!(report.unreadable_bytes, (2 - index as u64) * sector);
        assert!(!report.has_data_loss());
        let expected = if index == 0 {
            [candidates[0], candidates[DECLARED_CLUSTER_COUNT]].into_iter().collect()
        } else {
            [candidates[DECLARED_CLUSTER_COUNT]].into_iter().collect()
        };
        assert_eq!(bad_clusters(&output), expected);
        assert!(checker::check_device(&output, Default::default(), None).unwrap().passed());
    }
    let latest_failure = candidates[1] * u64::from(boot.cluster_bytes);
    let mut output = OpenOptions::new().append(true).open(&archive).unwrap();
    append_test_entry(&mut output, latest_failure, sector, u64::from(RESCUE_FAILED_OUTCOME), &[]);
    output.sync_all().unwrap();
    let failed_output = directory.join("latest-failure.img");
    let failed_map = directory.join("latest-failure.tsv");
    recover_archive_to(&archive, &failed_map, &failed_output, &mut |_| {}, options()).unwrap();
    assert_eq!(bad_clusters(&failed_output), [candidates[1], candidates[DECLARED_CLUSTER_COUNT]].into_iter().collect());
    let recovered = directory.join("fresh-complete.img");
    let map = directory.join("fresh-complete.tsv");
    let report =
        recover_rescue_to_with_options(&source, &archive, &map, &recovered, true, &mut |_| {}, options()).unwrap();
    assert_eq!(report.unreadable_bytes, 0);
    assert!(bad_clusters(&recovered).is_empty());
    let mut history =
        rescue_bad_clusters(File::open(&archive).unwrap(), original.len() as u64, boot.cluster_bytes).unwrap();
    for cluster in [candidates[0], candidates[1], candidates[DECLARED_CLUSTER_COUNT]] {
        assert!(checker::consistency::inventory_find(&mut history, cluster).unwrap().is_some());
    }
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_B12_SOURCE formatted disposable image"]
fn legacy_reassessment_journal_resumes_its_recorded_retirement_policy() {
    const JOURNAL_ONLY_BOUNDARY: u64 = 1;
    let directory = directory("legacy-journal");
    let (source, boot, candidates) = declared_fixture(&directory);
    let original = std::fs::read(&source).unwrap();
    let failed: Vec<_> =
        candidates[..DECLARED_CLUSTER_COUNT].iter().map(|cluster| cluster * u64::from(boot.cluster_bytes)).collect();
    let archive = directory.join("legacy.rescue");
    error_archive(&source, &archive, &original, &failed, false);
    let mut appended = OpenOptions::new().append(true).open(&archive).unwrap();
    let sector = u64::from(boot.bytes_per_sector);
    for at in failed {
        append_test_entry(&mut appended, at, sector, 0, &original[at as usize..(at + sector) as usize]);
    }
    appended.sync_all().unwrap();
    let map = directory.join("legacy.tsv");
    let journal = directory.join("legacy.journal");
    let prepared = prepare_archive_recovery(&archive, &map, &journal, &mut |_| {}, RepairOptions::default()).unwrap();
    let template = prepared.template;
    let recovery = RecoveryJournal {
        archive: prepared.archive,
        loss_map: prepared.loss_map,
        archive_checksum: prepared.archive_checksum,
        loss_map_checksum: prepared.loss_map_checksum,
        changes: Some(prepared.plan),
        template: Some(template.clone()),
        bad: prepared.bad,
        cluster_bytes: boot.cluster_bytes,
        rescan_bad_clusters: true,
        latest_classification: false,
    };
    assert_eq!(InPlaceOperation::Recover(&recovery).magic(), b"SLTRCB01");
    let error = apply_in_place_journal(
        OpenOptions::new().read(true).write(true).open(&source).unwrap(),
        &journal,
        false,
        None,
        InPlaceOperation::Recover(&recovery),
        Some(JOURNAL_ONLY_BOUNDARY),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(error.to_string().contains("injected"));
    drop(recovery);
    assert_eq!(std::fs::read(&source).unwrap(), original);
    recover_archive_on_claimed_source(
        OpenOptions::new().read(true).write(true).open(&source).unwrap(),
        &archive,
        &map,
        &journal,
        true,
        &mut |_| {},
        options(),
    )
    .unwrap();
    assert_eq!(bad_clusters(&source), candidates[..DECLARED_CLUSTER_COUNT].iter().copied().collect());
    assert!(checker::check_device(&source, Default::default(), None).unwrap().passed());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn reassessment_classification_refuses_unattempted_trailing_sectors() {
    const SOURCE_BYTES: usize = TEST_CLUSTER_BYTES as usize;
    const SECTOR_BYTES: usize = 512;
    let directory = directory("trailing");
    let source = directory.join("source.bin");
    let bytes = vec![0; SOURCE_BYTES];
    std::fs::write(&source, &bytes).unwrap();
    for offset in [0, SOURCE_BYTES - SECTOR_BYTES] {
        let archive = directory.join(format!("missing-{offset}.rescue"));
        error_archive(&source, &archive, &bytes, &[offset as u64], true);
        let error = rescue_classified_bad_clusters(
            File::open(&archive).unwrap(),
            SOURCE_BYTES as u64,
            TEST_CLUSTER_BYTES,
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("complete surface coverage"));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_B12_SOURCE and optional SLATE_B12_RESULTS disposable fixture paths"]
fn reassessment_retains_only_individually_failed_clusters_and_preserves_neighbors() {
    const FAILURE_CLUSTERS: [u64; 2] = [60, 67];
    const SECTOR_IN_CLUSTER: u64 = 2;
    let directory = directory("native-sector-control");
    let (source, boot, candidates) = declared_fixture(&directory);
    assert_eq!(&candidates[..DECLARED_CLUSTER_COUNT], &[64, 67, 70]);
    let original = std::fs::read(&source).unwrap();
    let failed: Vec<_> = FAILURE_CLUSTERS
        .into_iter()
        .map(|cluster| cluster * u64::from(boot.cluster_bytes) + SECTOR_IN_CLUSTER * u64::from(boot.bytes_per_sector))
        .collect();
    let archive = directory.join("sector-errors.rescue");
    error_archive(&source, &archive, &original, &failed, false);
    let output = directory.join("sector-errors.img");
    let map = directory.join("sector-errors.tsv");
    let report = recover_archive_to(&archive, &map, &output, &mut |_| {}, options()).unwrap();
    assert_eq!(report.unreadable_bytes, FAILURE_CLUSTERS.len() as u64 * u64::from(boot.bytes_per_sector));
    assert!(!report.has_data_loss());
    assert_eq!(bad_clusters(&output), FAILURE_CLUSTERS.into_iter().collect());
    for failed in FAILURE_CLUSTERS {
        assert!(allocation(&output, failed));
        assert!(!bad_clusters(&output).contains(&(failed - 1)));
        assert!(!bad_clusters(&output).contains(&(failed + 1)));
    }
    assert!(checker::check_device(&output, Default::default(), None).unwrap().passed());
    assert_eq!(std::fs::read(&source).unwrap(), original);
    if let Some(destination) = std::env::var_os("SLATE_B12_RESULTS") {
        let destination = PathBuf::from(destination);
        std::fs::create_dir_all(&destination).unwrap();
        for (input, name) in [(&output, "native-sector-result.img"), (&map, "native-sector-loss.tsv")] {
            std::fs::copy(input, destination.join(name)).unwrap();
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires SLATE_B12_RELOCATION_SOURCE private image with declared bad clusters and one-cluster ordinary DATA"]
fn reassessment_reuses_only_verified_unowned_reservations_before_relocation() {
    use ntfs_rs::runlist::Extent;
    let directory = directory("early-reclaim");
    let source = directory.join("source.img");
    std::fs::copy(std::env::var_os("SLATE_B12_RELOCATION_SOURCE").unwrap(), &source).unwrap();
    let boot = checker::probe(&source).unwrap().boot;
    let declared = bad_clusters(&source);
    assert_eq!(declared.len(), DECLARED_CLUSTER_COUNT);
    assert!(checker::check_device(&source, Default::default(), None).unwrap().passed());
    let mut volume = checker::open_volume(&source).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let slots = mft.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap() / u64::from(boot.record_bytes);
    let mut selected = None;
    for number in system_record::RESERVED..slots {
        let Ok(family) = RepairFamily::load(&mut volume, &mft, number) else {
            continue;
        };
        let record = MftRecord::from_decoded(&family.logical).unwrap();
        let Ok(data) = record.stream(ATTR_DATA, &[]) else {
            continue;
        };
        if data.nonresident && data.flags().unwrap() == 0 && data.data_size().unwrap() == u64::from(boot.cluster_bytes)
        {
            selected = Some((
                number,
                data.id,
                DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap().lcn.unwrap(),
            ));
            break;
        }
    }
    let (number, id, old_lcn) = selected.expect("fixture requires one-cluster ordinary DATA");
    let witness: Vec<_> = (0..boot.cluster_bytes).map(|index| index as u8).collect();
    std::os::unix::fs::FileExt::write_all_at(
        &OpenOptions::new().write(true).open(&source).unwrap(),
        &witness,
        old_lcn * u64::from(boot.cluster_bytes),
    )
    .unwrap();
    let original = std::fs::read(&source).unwrap();
    let bitmap_image = checked_family_image(&mut volume, &mft, system_record::BITMAP).unwrap();
    let bitmap = MftRecord::from_decoded(&bitmap_image).unwrap();
    let data = bitmap.stream(ATTR_DATA, &[]).unwrap();
    let mut patches = RepairPlan::new(original.len() as u64).unwrap();
    stage_overwrite(&mut volume, data, 0, &vec![u8::MAX; data.data_size().unwrap() as usize], &mut patches).unwrap();
    drop(volume);
    // Reserved bitmap bits exclude every other otherwise-unused cluster.
    // The only legal relocation destinations must come from old declarations.
    let no_bad = checker::consistency::scratch_file().unwrap();
    badclus_repairs(&source, boot, &mut patches, &no_bad, true).unwrap();
    let mut volume = PlannedImage::volume(&source, &patches, boot).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let mut space = RepairSpace::new(&mut volume, &mft).unwrap();
    let available = space.fragments(&mut volume, declared.len() as u64).unwrap();
    let allocated: BTreeSet<_> = available
        .iter()
        .flat_map(|run| {
            let first = run.lcn.unwrap();
            first..first + run.len
        })
        .collect();
    assert_eq!(allocated, declared);
    assert!(space.fragments(&mut volume, 1).is_err());
    drop(volume);
    relocation::relocate(&source, boot, &mut patches, number, id, None, None).unwrap();
    let mut volume = PlannedImage::volume(&source, &patches, boot).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let family = RepairFamily::load(&mut volume, &mft, number).unwrap();
    let record = MftRecord::from_decoded(&family.logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let runs: Vec<_> = DataRuns::new(data.data_runs().unwrap(), 0).collect::<ntfs_rs::Result<_>>().unwrap();
    assert_eq!(runs.len(), 1);
    assert!(declared.contains(&runs[0].lcn.unwrap()));
    let mut payload = vec![0; boot.cluster_bytes as usize];
    volume.read_attribute(data, 0, &mut payload).unwrap();
    assert_eq!(payload, witness);
    let record_offset = number * u64::from(boot.record_bytes);
    let physical =
        overwrite_spans(mft.stream(ATTR_DATA, &[]).unwrap(), boot, record_offset, 1).unwrap()[0].physical_offset;
    let destination = runs[0].lcn.unwrap();
    let bitmap_image = checked_family_image(&mut volume, &mft, system_record::BITMAP).unwrap();
    let bitmap = MftRecord::from_decoded(&bitmap_image).unwrap();
    let allocation = bitmap.stream(ATTR_DATA, &[]).unwrap();
    let byte_offset = destination / u64::from(u8::BITS);
    let mut byte = [0];
    volume.read_attribute(allocation, byte_offset, &mut byte).unwrap();
    byte[0] |= 1 << (destination % u64::from(u8::BITS));
    let mut extra = RepairPlan::new(original.len() as u64).unwrap();
    stage_overwrite(&mut volume, allocation, byte_offset, &byte, &mut extra).unwrap();
    drop(volume);
    for patch in extra.iter() {
        patches.compose(patch.unwrap()).unwrap();
    }
    assert!(planned_allocation(&source, &patches, boot, destination));
    let mut protected = RunSpool::new().unwrap();
    protected.push(Extent { vcn: runs[0].lcn.unwrap(), lcn: runs[0].lcn, len: 1 }).unwrap();
    let count = patches.len();
    reclaim_bad_reservations(&source, boot, &mut patches, &protected).unwrap();
    assert_eq!(patches.len(), count, "surviving DATA ownership must prevent release");
    assert!(planned_allocation(&source, &patches, boot, destination));
    patches.compose(Patch::new(physical, vec![b'F'], vec![b'X'])).unwrap();
    let count = patches.len();
    reclaim_bad_reservations(&source, boot, &mut patches, &protected).unwrap();
    assert_eq!(patches.len(), count, "incomplete ownership must not add bitmap writes");
    assert!(planned_allocation(&source, &patches, boot, destination));
    patches.compose(Patch::new(physical, vec![b'X'], vec![b'F'])).unwrap();
    let mut volume = PlannedImage::volume(&source, &patches, boot).unwrap();
    let zero = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&zero).unwrap();
    let mft_bitmap = mft.stream(ATTR_BITMAP, &[]).unwrap();
    let mut bit = [0];
    volume.read_attribute(mft_bitmap, number / u64::from(u8::BITS), &mut bit).unwrap();
    let bitmap_offset = if mft_bitmap.nonresident {
        overwrite_spans(mft_bitmap, boot, number / u64::from(u8::BITS), 1).unwrap()[0].physical_offset
    } else {
        let offset = mft_bitmap.record_offset()
            + mft_bitmap.resident_value_offset().unwrap()
            + (number / u64::from(u8::BITS)) as usize;
        overwrite_spans(mft.stream(ATTR_DATA, &[]).unwrap(), boot, offset as u64, 1).unwrap()[0].physical_offset
    };
    drop(volume);
    patches
        .compose(Patch::new(bitmap_offset, bit.to_vec(), vec![bit[0] & !(1 << (number % u64::from(u8::BITS)))]))
        .unwrap();
    let count = patches.len();
    reclaim_bad_reservations(&source, boot, &mut patches, &protected).unwrap();
    assert_eq!(patches.len(), count, "bitmap-free in-use records must withhold early reuse");
    assert!(planned_allocation(&source, &patches, boot, destination));
    assert_eq!(std::fs::read(&source).unwrap(), original);
    std::fs::remove_dir_all(directory).unwrap();
}
