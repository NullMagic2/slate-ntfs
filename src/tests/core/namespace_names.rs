//! Module: namespace_writer::name_tests
//! Purpose: Check canonical and legacy filename selection across record families.
//! Created: 2026-10-21
//! Architecture: Exercises the shared selector used by Tx and selective loading;
//! image-backed lifecycle tests validate the resulting namespace mutations.

use super::super::{filename::MAX_NAME_BYTES, linux_names, upcase::UPCASE_BYTES, Error};
use super::ExistingNames;
use std::vec;
use std::vec::Vec;

fn encoded(name: &[u8], escaped: bool) -> Vec<u8> {
    let mut bytes = vec![0; MAX_NAME_BYTES];
    let size =
        if escaped { linux_names::encode_linux(name, &mut bytes) } else { linux_names::encode(name, &mut bytes) }
            .unwrap();
    bytes.truncate(size);
    bytes
}

fn upcase() -> Vec<u8> {
    let mut bytes = vec![0; UPCASE_BYTES];
    for (unit, value) in bytes.chunks_exact_mut(core::mem::size_of::<u16>()).enumerate() {
        let unit = unit as u16;
        let folded = if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit - u16::from(b'a') + u16::from(b'A')
        } else {
            unit
        };
        value.copy_from_slice(&folded.to_le_bytes());
    }
    bytes
}

#[test]
fn canonical_exact_wins_over_legacy_in_either_record_order() {
    let request = encoded(b"name:part", true);
    let legacy = encoded(b"name:part", false);
    for reverse in [false, true] {
        let mut names = ExistingNames::new();
        let mut candidates = [(&request, "canonical"), (&legacy, "legacy")];
        if reverse {
            candidates.reverse();
        }
        for (stored, value) in candidates {
            names.consider(stored, &request, false, &[], value);
        }
        assert_eq!(names.finish(), Ok(Some("canonical")));
    }
}

#[test]
fn legacy_exact_wins_over_ambiguous_native_case_matches() {
    let request = encoded(b"name:part", true);
    let folded = encoded(b"NAME:PART", true);
    let legacy = encoded(b"name:part", false);
    let table = upcase();
    for exact_first in [false, true] {
        let mut names = ExistingNames::new();
        if exact_first {
            names.consider(&legacy, &request, true, &table, "exact");
        }
        for value in ["folded-a", "folded-b"] {
            names.consider(&folded, &request, true, &table, value);
        }
        if !exact_first {
            names.consider(&legacy, &request, true, &table, "exact");
        }
        assert_eq!(names.finish(), Ok(Some("exact")));
    }
}

#[test]
fn legacy_case_folding_remains_native_only() {
    let request = encoded(b"NAME:PART", true);
    let legacy = encoded(b"name:part", false);
    let table = upcase();
    for native in [false, true] {
        let mut names = ExistingNames::new();
        names.consider(&legacy, &request, native, &table, "legacy");
        assert_eq!(names.finish(), Ok(native.then_some("legacy")));
    }
}

#[test]
fn duplicate_best_matches_still_refuse_selection() {
    let request = encoded(b"name:part", true);
    let mut names = ExistingNames::new();
    for candidate in ["first", "second"] {
        names.consider(&request, &request, false, &[], candidate);
    }
    assert_eq!(names.finish(), Err(Error::InvalidAttribute));
}
