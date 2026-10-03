// Module: slate_ntfs_tools::recovery_io::models::metadata::filename_metadata_tests
// Purpose: Exercise metadata recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

fn add_resident(record: &mut [u8], kind: u32, value: &[u8]) {
    let mut attribute = vec![0; 1024];
    let length = e::build_resident(kind, &[], value, &mut attribute).unwrap();
    e::insert(record, &attribute[..length]).unwrap();
}

fn filename(namespace: u8, parent: u64, text: &str) -> Vec<u8> {
    let name: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut value = vec![0; 66 + name.len()];
    value[..8].copy_from_slice(&parent.to_le_bytes());
    value[64] = (name.len() / 2) as u8;
    value[65] = namespace;
    value[66..].copy_from_slice(&name);
    value
}

#[test]
fn filename_rules_preserve_raw_namespace_and_valid_unicode() {
    for (namespace, text) in [
        (0, "Unicode\u{1f642}"),
        (1, "name+with=punctuation"),
        (2, "SHORT~1.TXT"),
        (3, "."),
        (5, "WPSettings.dat"),
        (4, "CaseSensitive"),
        (6, "SHORT~1.TXT"),
    ] {
        let value = filename(namespace, 5, text);
        assert!(filename_value_valid(&value), "{namespace}: {text}");
        assert_eq!(value[65], namespace);
    }
    for namespace in [0, 1, 2, 3, 4, 5] {
        for text in ["", "invalid/name", "embedded\0null", "control\u{1f}"] {
            assert!(!filename_value_valid(&filename(namespace, 5, text)));
        }
    }
}

#[test]
fn dos_name_rules_check_shape_without_restricting_win32_names() {
    for text in ["TOOLONGSTEM", "A.LONG", "A.", ".A", "A.B.C", "A+.TXT", "A .TXT", "A.TXT "] {
        assert!(!filename_value_valid(&filename(2, 5, text)), "{text}");
        assert!(filename_value_valid(&filename(1, 5, text)), "{text}");
    }
    let mut truncated = filename(1, 5, "complete");
    truncated.pop();
    assert!(!filename_value_valid(&truncated));
    truncated.truncate(32);
    assert!(!filename_value_valid(&truncated));
}

#[test]
fn root_name_admission_requires_the_indexed_bit() {
    for flags in [0, 1, 2, 3] {
        let mut raw = vec![0; 1024];
        e::format_empty(&mut raw, 5).unwrap();
        add_resident(&mut raw, 0x30, &filename(3, 5, "."));
        let at = e::require(&raw, 0x30, &[]).unwrap();
        raw[at + 22] = flags;
        assert_eq!(root_filename_valid(&MftRecord::from_decoded(&raw).unwrap(), 5).unwrap(), flags & 1 != 0,);
    }
}

#[test]
fn conventional_system_names_preserve_high_bits_and_parent_authority() {
    for (number, text) in [(4, "$AttrDef"), (10, "$UpCase"), (11, "$Extend")] {
        for namespace in [0, 3, 7] {
            let mut raw = vec![0; 1024];
            e::format_empty(&mut raw, number).unwrap();
            add_resident(&mut raw, 0x30, &filename(namespace, 36, text));
            let record = MftRecord::from_decoded(&raw).unwrap();
            assert_eq!(system_filename_valid(&record, number).unwrap(), namespace & 3 == 3);
        }
        let mut raw = vec![0; 1024];
        e::format_empty(&mut raw, number).unwrap();
        assert!(!system_filename_valid(&MftRecord::from_decoded(&raw).unwrap(), number).unwrap());
        add_resident(&mut raw, 0x30, &filename(3, 5, "incorrect"));
        assert!(!system_filename_valid(&MftRecord::from_decoded(&raw).unwrap(), number).unwrap());
    }
}

#[test]
fn sole_alias_namespace_preserves_raw_bits_when_becoming_posix() {
    for namespace in [0, 1, 2, 3, 4, 5, 6, 7] {
        let mut raw = vec![0; 1024];
        e::format_empty(&mut raw, 37).unwrap();
        let value = filename(namespace, 5, "NAME.TXT");
        add_resident(&mut raw, 0x30, &value);
        let at = e::require(&raw, 0x30, &[]).unwrap();
        raw[at + 22] = 3;
        let record = MftRecord::from_decoded(&raw).unwrap();
        let alias = matches!(namespace & 3, 1 | 2);
        assert_eq!(filename_alias_projection(&record, None).unwrap().is_some(), alias);
        let mut changes = vec![StreamChange::resident(0x30, &[], &value).unwrap()];
        changes[0].attribute.as_mut().unwrap()[22] = 3;
        assert_eq!(super::super::normalize_surviving_aliases(&mut changes).unwrap(), alias);
        let attribute = changes[0].attribute.as_ref().unwrap();
        let at = usize::from(u16_at(attribute, 20).unwrap());
        assert_eq!(attribute[at + 65], if alias { namespace & !3 } else { namespace });
        assert_eq!(attribute[22], 3);
        assert_eq!(&attribute[at + 66..at + value.len()], &value[66..]);
    }
}

#[test]
fn ordinary_aliases_validate_family_counts_parent_and_folded_text() {
    let mut table = vec![0; ntfs_rs::upcase::UPCASE_BYTES];
    for unit in 0..=u16::MAX {
        let folded = if (97..=122).contains(&unit) { unit - 32 } else { unit };
        table[usize::from(unit) * 2..usize::from(unit) * 2 + 2].copy_from_slice(&folded.to_le_bytes());
    }
    for claims in [
        vec![(5, 36, "LongName.dat"), (6, 36, "LONGNA~1.DAT"), (5, 36, "Other.dat")],
        vec![(1, 36, "LongName.dat"), (2, 36, "LONGNA~1.DAT"), (2, 36, "OTHER~1.DAT")],
        vec![(1, 36, "LongName.dat"), (2, 5, "LONGNA~1.DAT")],
        vec![(1, 36, "LongName.dat"), (0, 36, "posix-link")],
    ] {
        let mut names: Vec<_> = claims.iter().map(|&(ns, parent, text)| (filename(ns, parent, text), 3)).collect();
        let original = names.clone();
        assert!(normalize_file_aliases(&mut names, Some(&table)).unwrap());
        for ((value, flags), (original, _)) in names.iter().zip(original) {
            assert_eq!(value[65], original[65] & !3);
            assert_eq!(&value[..65], &original[..65]);
            assert_eq!(&value[66..], &original[66..]);
            assert_eq!(*flags, 3);
        }
        assert!(!normalize_file_aliases(&mut names, Some(&table)).unwrap());
    }
    let mut names = vec![
        (filename(5, 36, "ABCDEFGH.TXT"), 255),
        (filename(6, 36, "abcdefgh.txt"), 3),
        (filename(0, 11, "posix-link"), 1),
    ];
    assert!(normalize_file_aliases(&mut names, Some(&table)).unwrap());
    assert_eq!(names.len(), 2);
    assert_eq!(names[0], (filename(7, 36, "ABCDEFGH.TXT"), 255));
    assert_eq!(names[1], (filename(0, 11, "posix-link"), 1));
    assert!(!normalize_file_aliases(&mut names, Some(&table)).unwrap());
    let mut names = vec![(filename(1, 36, "LongName.dat"), 1), (filename(2, 36, "LONGNA~1.DAT"), 1)];
    assert!(!normalize_file_aliases(&mut names, Some(&table)).unwrap());
}

#[test]
fn header_counts_each_filename_including_dos_aliases() {
    for namespaces in [vec![1, 2], vec![3], vec![0, 1, 2], vec![2, 2]] {
        let mut raw = vec![0; 1024];
        e::format_empty(&mut raw, 37).unwrap();
        for (index, namespace) in namespaces.iter().enumerate() {
            add_resident(&mut raw, 0x30, &filename(*namespace, 5, &format!("name{index}")));
        }
        let record = MftRecord::from_decoded(&raw).unwrap();
        assert_eq!(link_count(&record).unwrap(), namespaces.len() as u16);
    }
}

#[test]
fn link_count_checks_framing_and_content_but_preserves_namespace_bits() {
    for value in [vec![0; 65], filename(1, 5, "invalid/name"), vec![0; 68]] {
        let mut raw = vec![0; 1024];
        e::format_empty(&mut raw, 37).unwrap();
        add_resident(&mut raw, 0x30, &value);
        assert!(link_count(&MftRecord::from_decoded(&raw).unwrap()).is_err());
    }
    for namespace in [4, 5, 7] {
        let mut raw = vec![0; 1024];
        e::format_empty(&mut raw, 37).unwrap();
        add_resident(&mut raw, 0x30, &filename(namespace, 5, "name"));
        assert_eq!(link_count(&MftRecord::from_decoded(&raw).unwrap()).unwrap(), 1);
    }
}

struct NoReads;

impl ReadAt for NoReads {
    fn read_exact_at(&mut self, _: u64, _: &mut [u8]) -> ntfs_rs::Result<()> {
        panic!("resident duplicated metadata must not read physical storage")
    }
}

#[test]
fn live_metadata_comes_from_standard_information_and_data() {
    let boot = ntfs_rs::boot::BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: 8192,
        mft_lcn: 4,
        mft_mirror_lcn: 2,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    };
    let mut volume = Volume::new(NoReads, boot).unwrap();
    let mut raw = vec![0; 1024];
    e::format_empty(&mut raw, 37).unwrap();
    let mut standard = vec![0; 72];
    standard[..32].fill(0x12);
    standard[32..36].copy_from_slice(&0x20_u32.to_le_bytes());
    add_resident(&mut raw, 0x10, &standard);
    add_resident(&mut raw, 0x30, &filename(1, 36, "settings.dat"));
    add_resident(&mut raw, ATTR_DATA, &[0x42; 12]);
    let record = MftRecord::from_decoded(&raw).unwrap();
    let summary = ntfs_rs::filename_metadata::duplicated_information(&mut volume, &record).unwrap();
    assert_eq!(&summary[..32], &standard[..32]);
    assert_eq!(u64_at(&summary, 32).unwrap(), 16);
    assert_eq!(u64_at(&summary, 40).unwrap(), 12);
    assert_eq!(u32_at(&summary, 48).unwrap(), 0x20);
    let cache = record.local_attribute(0x30, &[]).unwrap().unwrap().resident_value().unwrap();
    assert_eq!(u64_at(cache, 48).unwrap(), 0);
}
