//! Module: index_check_tests
//! Purpose: Verify reduced reference checks, suspect-target fallback and caching.
//! Created: 2026-10-01
//! Architecture: Builds private catalogs and validated keys for the shared entry
//!     checker; whole-image tests separately exercise index framing and repairs.

use super::*;

const OWNER: u64 = 5 | (1 << 48);
const TARGET: u64 = 24 | (1 << 48);

struct Key {
    reference: u64,
    parent: u64,
    namespace: u8,
    text: Vec<u8>,
    duplicate: [u8; 56],
}

impl Key {
    fn new(text: &str) -> Self {
        Self {
            reference: TARGET,
            parent: OWNER,
            namespace: 1,
            text: text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            duplicate: [0; 56],
        }
    }
}

fn check(mode: IndexCheck, passes: IndexCachePasses, keys: &[Key], base: u64) -> (Audit, Vec<[u64; 4]>) {
    check_with_budget(mode, passes, keys, base, CACHE_BYTES)
}

fn check_with_budget(
    mode: IndexCheck,
    passes: IndexCachePasses,
    keys: &[Key],
    base: u64,
    budget: u64,
) -> (Audit, Vec<[u64; 4]>) {
    let records = RecordStore::new(64).unwrap();
    let names = ["alpha", "beta"]
        .map(|text| {
            let key = Key::new(text);
            Name { parent: OWNER, namespace: 1, duplicate: [0; 56], text: key.text }
        })
        .to_vec();
    records
        .insert(
            24,
            Record {
                reference: TARGET,
                base,
                directory: false,
                names,
                has_attribute_list: false,
                canonical: Some([0; 56]),
            },
        )
        .unwrap();
    let mut entries = Entries::new().unwrap();
    for key in keys {
        let mut value = key.parent.to_le_bytes().to_vec();
        value.extend_from_slice(&key.duplicate);
        entries
            .push(
                OWNER,
                IndexEntry {
                    file_name_value: &value,
                    file_reference: key.reference,
                    flags: 0,
                    name: ntfs_rs::index::FileName { namespace: key.namespace, utf16le: &key.text },
                },
            )
            .unwrap();
    }
    let mut links = DiskInventory::new();
    let mut audit = Audit {
        complete: true,
        index_check: mode,
        index_slots: 64,
        report_file: Some(scratch_file().unwrap()),
        index_full_targets: Some(scratch_file().unwrap()),
        index_repair_directories: Some(scratch_file().unwrap()),
        ..Default::default()
    };
    entries
        .finish(
            &records,
            &mut links,
            &mut audit,
            AuditOptions { index_check: mode, index_cache_passes: passes, ..Default::default() },
            budget,
        )
        .unwrap();
    audit.findings = Findings::open(audit.report_file.as_ref().unwrap(), audit.finding_count).unwrap();
    let mut file = links.finish().unwrap();
    let mut rows = Vec::new();
    while let Some(row) = inventory_next(&mut file).unwrap() {
        rows.push(row);
    }
    (audit, rows)
}

#[test]
fn reduced_mode_uses_counts_instead_of_sequence_name_namespace_and_duplicates() {
    for defect in 0..4 {
        let mut keys = [Key::new("alpha"), Key::new("beta")];
        match defect {
            0 => keys[0].reference += 1 << 48,
            1 => keys[0].text = Key::new("unknown").text,
            2 => keys[0].namespace = 2,
            _ => keys[0].duplicate[0] = 1,
        }
        let (full, _) = check(IndexCheck::Full, IndexCachePasses::Auto, &keys, 0);
        assert_eq!(full.errors, u64::from(defect != 3), "defect {defect}");
        assert_eq!(full.finding_count, 1);
        let (quick, links) = check(IndexCheck::Quick, IndexCachePasses::Auto, &keys, 0);
        assert_eq!(quick.errors, 0);
        assert_eq!((quick.index_entries_full, quick.index_entries_reduced, quick.index_cache_passes), (0, 2, 0));
        assert_eq!(links, vec![[24, 0, 5, 0], [24, 1, 5, 0]]);
    }
}

#[test]
fn depleted_count_rechecks_all_earlier_entries_for_the_target() {
    let mut keys = vec![Key::new("alpha"), Key::new("beta"), Key::new("alpha")];
    keys[0].reference += 1 << 48;
    let (mut quick, links) = check(IndexCheck::Quick, IndexCachePasses::Streaming, &keys, 0);
    assert_eq!(quick.errors, 1);
    assert_eq!(quick.findings.iter().next().unwrap().code, "stale-index-reference");
    assert_eq!(quick.index_rechecked_records, 1);
    assert_eq!((quick.index_entries_full, quick.index_entries_reduced), (3, 0));
    assert_eq!(links.len(), 2);
    assert!(quick.index_directory_needs_repair(5).unwrap());
}

#[test]
fn wrong_parent_does_not_consume_a_reference_and_missing_counts_are_reported() {
    let mut keys = [Key::new("alpha"), Key::new("beta")];
    keys[0].parent += 1 << 48;
    let (mut quick, links) = check(IndexCheck::Quick, IndexCachePasses::Auto, &keys, 0);
    assert_eq!(quick.errors, 2);
    assert!(quick.findings.iter().any(|f| f.code == "index-parent-reference"));
    assert!(quick.findings.iter().any(|f| f.code == "missing-directory-link"));
    assert_eq!(quick.index_rechecked_records, 0);
    assert_eq!(links.len(), 1);
    assert!(quick.index_directory_needs_repair(5).unwrap());
    let (missing, _) = check(IndexCheck::Quick, IndexCachePasses::Auto, &[Key::new("alpha")], 0);
    assert_eq!(missing.errors, 1);
}

#[test]
fn unallocated_out_of_range_and_extension_targets_use_full_validation() {
    for (reference, base, code) in [
        (39 | (1 << 48), 0, "dangling-index-reference"),
        (ntfs_rs::mft::FILE_REFERENCE_NUMBER_MASK, 0, "dangling-index-reference"),
        (TARGET, 25 | (1 << 48), "index-extension-reference"),
    ] {
        let mut key = Key::new("alpha");
        key.reference = reference;
        let (quick, links) = check(IndexCheck::Quick, IndexCachePasses::Auto, &[key], base);
        assert_eq!(quick.errors, 1);
        assert_eq!(quick.findings.iter().next().unwrap().code, code);
        assert_eq!(quick.index_rechecked_records, 1);
        assert!(links.is_empty());
    }
}

#[test]
fn every_full_cache_strategy_has_identical_findings_and_edges() {
    let mut keys = [Key::new("alpha"), Key::new("beta")];
    keys[0].reference += 1 << 48;
    let mut expected = None;
    for value in ["0", "1", "7", "auto", "65534"] {
        let passes = IndexCachePasses::parse(value).unwrap();
        let (audit, edges) = check(IndexCheck::Full, passes, &keys, 0);
        let findings: Vec<_> = audit.findings.iter().map(|f| (f.code.clone(), f.record)).collect();
        let actual = (findings, edges);
        if let Some(expected) = &expected {
            assert_eq!(&actual, expected);
        } else {
            expected = Some(actual);
        }
        assert_eq!(audit.index_entries_full, 2);
        assert_eq!(audit.index_entries_reduced, 0);
        assert!(!audit.index_cache_fallback);
    }
    for invalid in ["", "-1", "65535", "65536", "1.0", "AUTO"] {
        assert!(IndexCachePasses::parse(invalid).is_none(), "{invalid}");
    }
}

#[test]
fn exhausted_cache_falls_back_without_losing_checks() {
    let mut keys = [Key::new("alpha"), Key::new("beta")];
    keys[0].reference += 1 << 48;
    let (audit, edges) = check_with_budget(IndexCheck::Full, IndexCachePasses::parse("1").unwrap(), &keys, 0, 1);
    let (streaming, expected) = check(IndexCheck::Full, IndexCachePasses::Streaming, &keys, 0);
    assert!(audit.index_cache_fallback);
    assert_eq!(audit.index_cache_passes, 1);
    assert_eq!(audit.errors, streaming.errors);
    assert_eq!(audit.index_entries_full, 2);
    assert_eq!(edges, expected);
}

#[test]
fn repair_marks_never_expand_beyond_the_mft_catalog() {
    let mut audit =
        Audit { index_slots: 64, index_repair_directories: Some(scratch_file().unwrap()), ..Default::default() };
    audit.index_needs_repair(ntfs_rs::mft::FILE_REFERENCE_NUMBER_MASK).unwrap();
    assert_eq!(audit.index_repair_directories.as_ref().unwrap().metadata().unwrap().len(), 0);
    audit.index_needs_repair(5).unwrap();
    assert!(audit.index_directory_needs_repair(5).unwrap());
    assert!(audit.index_repair_directories.as_ref().unwrap().metadata().unwrap().len() <= 64 * 8);
}

#[test]
fn additional_cache_memory_reduces_passes_without_changing_findings_or_links() {
    let mut keys = [Key::new("alpha"), Key::new("beta")];
    keys[0].reference += 1 << 48;
    let (balanced, balanced_links) = check_with_budget(IndexCheck::Full, IndexCachePasses::Auto, &keys, 0, 4096);
    let (high, high_links) = check_with_budget(IndexCheck::Full, IndexCachePasses::Auto, &keys, 0, 16384);
    assert!(balanced.index_cache_passes > high.index_cache_passes);
    assert_eq!(balanced_links, high_links);
    assert_eq!(balanced.errors, high.errors);
    let findings = |audit: &Audit| {
        audit.findings.iter().map(|finding| (finding.code, finding.record, finding.detail)).collect::<Vec<_>>()
    };
    assert_eq!(findings(&balanced), findings(&high));
}

#[test]
fn zero_cache_budget_streams_without_losing_findings_or_links() {
    let mut keys = [Key::new("alpha"), Key::new("beta")];
    keys[0].reference += 1 << 48;
    let (expected, edges) = check(IndexCheck::Full, IndexCachePasses::Streaming, &keys, 0);
    for passes in [IndexCachePasses::Auto, IndexCachePasses::parse("3").unwrap()] {
        let (actual, actual_edges) = check_with_budget(IndexCheck::Full, passes, &keys, 0, 0);
        assert_eq!(actual_edges, edges);
        assert_eq!(actual.errors, expected.errors);
        assert_eq!(actual.index_entries_full, expected.index_entries_full);
        let findings = |audit: &Audit| {
            audit.findings.iter().map(|finding| (finding.code, finding.record, finding.detail)).collect::<Vec<_>>()
        };
        assert_eq!(findings(&actual), findings(&expected));
    }
}
