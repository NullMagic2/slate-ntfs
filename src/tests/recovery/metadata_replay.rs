//! Module: src.tests.recovery.metadata_replay
//! Purpose: Metadata fixtures are encoded independently of the replay implementation.
//! Created: 2026-10-01
//! Architecture: Disposable fixtures exercise the production core or its mounted adapter and
//! verify resulting state.

//! Metadata fixtures are encoded independently of the replay implementation.
use ntfs_rs::bytes::{u16_at, u32_at, u64_at};
use ntfs_rs::logfile::{encode_ntfs_operation, NtfsLogOperation, NtfsOperationInput};
use slate_ntfs_tools::metadata_replay::apply;

fn p16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn p32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn resident(kind: u32, id: u16, value: &[u8]) -> Vec<u8> {
    let mut a = vec![0; (24 + value.len() + 7) & !7];
    let len = a.len();
    p32(&mut a, 0, kind);
    p32(&mut a, 4, len as u32);
    p16(&mut a, 14, id);
    p32(&mut a, 16, value.len() as u32);
    p16(&mut a, 20, 24);
    a[24..24 + value.len()].copy_from_slice(value);
    a
}
fn file(attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..4].copy_from_slice(b"FILE");
    p16(&mut b, 4, 48);
    p16(&mut b, 6, 3);
    p16(&mut b, 16, 7);
    p16(&mut b, 18, 1);
    p16(&mut b, 20, 56);
    p16(&mut b, 22, 1);
    p32(&mut b, 28, 1024);
    p16(&mut b, 40, 10);
    let mut at = 56;
    for a in attributes {
        b[at..at + a.len()].copy_from_slice(a);
        at += a.len();
    }
    p32(&mut b, at, u32::MAX);
    p32(&mut b, 24, (at + 8) as u32);
    b
}
fn operation(code: u16, undo_code: u16, ro: u16, ao: u16, redo: &[u8], undo: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 128 + redo.len() + undo.len()];
    let n = encode_ntfs_operation(
        &NtfsOperationInput {
            redo_code: code,
            undo_code,
            target_attribute: 24,
            target_vcn: 0,
            lcns: &[10],
            redo,
            undo,
        },
        &mut b,
    )
    .unwrap();
    b.truncate(n);
    p16(&mut b, 16, ro);
    p16(&mut b, 18, ao);
    b
}
fn execute(b: &mut [u8], encoded: &[u8], undo: bool, index: bool) {
    apply(b, &mut vec![0; b.len()], NtfsLogOperation::parse(encoded).unwrap(), undo, index).unwrap();
}
fn reject_unchanged(b: &mut [u8], encoded: &[u8], index: bool) {
    let before = b.to_vec();
    assert!(apply(b, &mut vec![0; b.len()], NtfsLogOperation::parse(encoded).unwrap(), false, index).is_err());
    assert_eq!(b, before);
}

#[test]
fn create_remove_attribute_preserves_unrelated_descriptor() {
    let security = resident(0x50, 2, b"opaque security descriptor bytes");
    let mut b = file(&[security.clone()]);
    let at = 56 + security.len();
    let extra = resident(0x80, 3, b"payload");
    let op = operation(5, 6, at as u16, 0, &extra, &[]);
    execute(&mut b, &op, false, false);
    assert_eq!(&b[56..at], security);
    assert_eq!(&b[at..at + extra.len()], extra);
    execute(&mut b, &op, true, false);
    assert_eq!(&b[56..at], security);
    assert_eq!(u32_at(&b, at).unwrap(), u32::MAX);
    let filename = resident(0x30, 4, &[0; 72]);
    let op = operation(5, 6, 56, 0, &filename, &[]);
    execute(&mut b, &op, false, false);
    assert_eq!(u16_at(&b, 18).unwrap(), 2);
    execute(&mut b, &op, true, false);
    assert_eq!(u16_at(&b, 18).unwrap(), 1);
}
#[test]
fn initialize_deallocate_and_write_record_end() {
    let original = file(&[resident(0x80, 0, b"AAAA")]);
    let mut b = original.clone();
    let op = operation(3, 2, 0, 0, &[], &original);
    execute(&mut b, &op, false, false);
    assert_eq!(u16_at(&b, 22).unwrap() & 1, 0);
    assert_eq!(u16_at(&b, 16).unwrap(), 8);
    execute(&mut b, &op, true, false);
    assert_eq!(b, original);
    let marker = [255, 255, 255, 255, 0, 0, 0, 0];
    let op = operation(4, 0, 56, 0, &marker, &[]);
    execute(&mut b, &op, false, false);
    assert_eq!(u32_at(&b, 24).unwrap(), 64);
}
#[test]
fn resident_growth_shrink_and_failure_atomicity() {
    let original = file(&[resident(0x80, 0, b"abcdefgh"), resident(0xe0, 1, b"preserved")]);
    let mut b = original.clone();
    let op = operation(7, 7, 56, 26, b"0123456789efgh", b"cdefgh");
    execute(&mut b, &op, false, false);
    assert_eq!(&b[80..96], b"ab0123456789efgh");
    assert_eq!(u32_at(&b, 72).unwrap(), 16);
    execute(&mut b, &op, true, false);
    assert_eq!(b, original);
    // Unequal lengths replace the suffix, so an offset inside the old value
    // is valid even when the undo payload is longer. Reject a true gap beyond
    // the old value end (24-byte header + 8-byte value), instead.
    reject_unchanged(&mut b, &operation(7, 7, 56, 33, b"X", b"too long"), false);
    // Equal-length replacement may not run past the existing value either.
    reject_unchanged(&mut b, &operation(7, 7, 56, 31, b"XY", b"gh"), false);
    reject_unchanged(&mut b, &operation(5, 6, 57, 0, &resident(0x80, 2, b"X"), &[]), false);
}
#[test]
fn runlist_resize_and_size_field_order() {
    let mut a = vec![0; 72];
    p32(&mut a, 0, 0x80);
    p32(&mut a, 4, 72);
    a[8] = 1;
    p16(&mut a, 32, 64);
    p64(&mut a, 24, 1);
    p64(&mut a, 40, 8192);
    p64(&mut a, 48, 6000);
    p64(&mut a, 56, 5000);
    a[64..68].copy_from_slice(&[0x11, 2, 20, 0]);
    let mut b = file(&[a]);
    let op = operation(9, 9, 56, 64, &[0x11, 1, 20, 0], &[0x11, 2, 20, 0]);
    execute(&mut b, &op, false, false);
    assert_eq!(u64_at(&b, 80).unwrap(), 0);
    execute(&mut b, &op, true, false);
    assert_eq!(u64_at(&b, 80).unwrap(), 1);
    let mut sizes = vec![0; 24];
    p64(&mut sizes, 0, 8192);
    p64(&mut sizes, 8, 4000);
    p64(&mut sizes, 16, 4500);
    execute(&mut b, &operation(11, 0, 56, 0, &sizes, &[]), false, false);
    assert_eq!(u64_at(&b, 96).unwrap(), 8192);
    assert_eq!(u64_at(&b, 104).unwrap(), 4500);
    assert_eq!(u64_at(&b, 112).unwrap(), 4000);
    p64(&mut sizes, 8, 9000);
    reject_unchanged(&mut b, &operation(11, 0, 56, 0, &sizes, &[]), false);
    reject_unchanged(&mut b, &operation(9, 0, 56, 64, &[0x11, 0, 1, 0], &[]), false);
}
fn entry(child: bool, terminal: bool) -> Vec<u8> {
    let size = if terminal { 16 } else { 88 } + if child { 8 } else { 0 };
    let mut b = vec![0; size];
    p16(&mut b, 8, size as u16);
    p16(&mut b, 10, if terminal { 0 } else { 72 });
    p16(&mut b, 12, u16::from(child) | if terminal { 2 } else { 0 });
    if child {
        p64(&mut b, size - 8, 5);
    }
    b
}
fn index(child: bool) -> Vec<u8> {
    let mut b = vec![0; 4096];
    b[..4].copy_from_slice(b"INDX");
    p16(&mut b, 4, 40);
    p16(&mut b, 6, 9);
    let end = entry(child, true);
    p32(&mut b, 24, 40);
    p32(&mut b, 28, (40 + end.len()) as u32);
    p32(&mut b, 32, 4072);
    b[36] = u8::from(child);
    b[64..64 + end.len()].copy_from_slice(&end);
    b
}
#[test]
fn allocation_insert_delete_end_and_child_pointer() {
    for child in [false, true] {
        let mut b = index(child);
        let original = b.clone();
        let e = entry(child, false);
        let op = operation(14, 15, 0, 64, &e, &[]);
        execute(&mut b, &op, false, true);
        assert_eq!(&b[64..64 + e.len()], e);
        if child {
            execute(&mut b, &operation(18, 0, 0, 64, &9u64.to_le_bytes(), &[]), false, true);
            assert_eq!(u64_at(&b, 64 + e.len() - 8).unwrap(), 9);
        }
        execute(&mut b, &op, true, true);
        assert_eq!(b, original);
        execute(&mut b, &op, false, true);
        execute(&mut b, &operation(16, 0, 0, 64, &entry(child, true), &[]), false, true);
        assert_eq!(u32_at(&b, 28).unwrap(), u32_at(&original, 28).unwrap());
        reject_unchanged(&mut b, &operation(15, 0, 0, 64, &[], &[]), true);
    }
}
#[test]
fn root_insert_delete_and_child_pointer() {
    for child in [false, true] {
        let end = entry(child, true);
        let mut root = vec![0; 32 + end.len()];
        p32(&mut root, 0, 0x30);
        p32(&mut root, 4, 1);
        p32(&mut root, 8, 4096);
        root[12] = 1;
        p32(&mut root, 16, 16);
        p32(&mut root, 20, (16 + end.len()) as u32);
        p32(&mut root, 24, (16 + end.len()) as u32);
        root[28] = u8::from(child);
        root[32..].copy_from_slice(&end);
        let mut b = file(&[resident(0x90, 1, &root), resident(0xe0, 2, b"adjacent")]);
        let original = b.clone();
        let e = entry(child, false);
        let op = operation(12, 13, 56, 56, &e, &[]);
        execute(&mut b, &op, false, false);
        assert_eq!(&b[112..112 + e.len()], e);
        if child {
            execute(&mut b, &operation(17, 0, 56, 56, &9u64.to_le_bytes(), &[]), false, false);
            assert_eq!(u64_at(&b, 112 + e.len() - 8).unwrap(), 9);
        }
        execute(&mut b, &op, true, false);
        assert_eq!(b, original);
    }
}
#[test]
fn index_duplicate_information_and_view_data() {
    let mut b = index(false);
    let e = entry(false, false);
    execute(&mut b, &operation(14, 0, 0, 64, &e, &[]), false, true);
    execute(&mut b, &operation(20, 0, 0, 64, &[0xab; 56], &[]), false, true);
    assert_eq!(&b[88..144], &[0xab; 56]);
    p16(&mut b, 64, 80);
    p16(&mut b, 66, 8);
    execute(&mut b, &operation(34, 0, 0, 64, b"VIEWDATA", &[]), false, true);
    assert_eq!(&b[144..152], b"VIEWDATA");
    execute(&mut b, &operation(34, 0, 0, 64, b"bad", &[]), false, true);
    assert_eq!(&b[144..152], b"badWDATA");
    reject_unchanged(&mut b, &operation(34, 0, 0, 64, b"too long!", &[]), true);
}
#[test]
fn fresh_index_block_initialization_and_noop_undo() {
    // A newly allocated index block is published as one full-image
    // UpdateNonresidentValue with a Noop undo: rollback leaves free space.
    let image = index(false);
    let op = operation(8, 0, 0, 0, &image, &[]);
    let mut garbage = vec![0x5a; 4096];
    let before = garbage.clone();
    execute(&mut garbage, &op, true, true);
    assert_eq!(garbage, before, "Noop undo must not touch an unused block");
    let mut target = vec![0; 4096];
    target[..4].copy_from_slice(b"INDX");
    p16(&mut target, 4, 40);
    p16(&mut target, 6, 9);
    execute(&mut target, &op, false, true);
    assert_eq!(target, image);
    // The same Noop applies to MFT-record targets.
    let mut record = file(&[]);
    let unchanged = record.clone();
    execute(&mut record, &operation(2, 0, 0, 0, &unchanged, &[]), true, false);
    assert_eq!(record, unchanged);
}

#[test]
fn partial_index_value_redo_undo_preserves_suffix_and_child() {
    for child in [false, true] {
        let mut b = index(child);
        let mut e = entry(child, false);
        p16(&mut e, 0, 40);
        p16(&mut e, 2, 16);
        e[40..56].copy_from_slice(b"abcdefghijklmnop");
        execute(&mut b, &operation(14, 15, 0, 64, &e, &[]), false, true);
        let original = b.clone();
        let change = operation(34, 34, 0, 64, b"XY", b"ab");
        execute(&mut b, &change, false, true);
        assert_eq!(&b[104..120], b"XYcdefghijklmnop");
        if child {
            assert_eq!(u64_at(&b, 64 + e.len() - 8).unwrap(), 5);
        }
        execute(&mut b, &change, true, true);
        assert_eq!(b, original);
        reject_unchanged(&mut b, &operation(34, 0, 0, 64, &[0; 17], &[]), true);
    }
}

#[test]
fn index_value_cannot_overlap_child_pointer() {
    let mut b = index(true);
    let mut e = entry(true, false);
    p16(&mut e, 0, 80);
    p16(&mut e, 2, 16);
    execute(&mut b, &operation(14, 15, 0, 64, &e, &[]), false, true);
    reject_unchanged(&mut b, &operation(34, 0, 0, 64, &[0; 2], &[]), true);
}

#[test]
fn relative_index_deltas_use_declared_data_offset() {
    let mut e = entry(false, false);
    p16(&mut e, 0, 40);
    p16(&mut e, 2, 16);
    p16(&mut e, 10, 16);
    p32(&mut e, 40, u32::MAX - 2);
    // An identical value elsewhere in the entry must not redirect the write.
    p32(&mut e, 48, u32::MAX - 2);
    let mut allocation = index(false);
    execute(&mut allocation, &operation(14, 0, 0, 64, &e, &[]), false, true);
    let original = allocation.clone();
    let delta = operation(36, 36, 0, 64, &5u32.to_le_bytes(), &(-5i32).to_le_bytes());
    execute(&mut allocation, &delta, false, true);
    assert_eq!(u32_at(&allocation, 104).unwrap(), 2);
    assert_eq!(u32_at(&allocation, 112).unwrap(), u32::MAX - 2);
    execute(&mut allocation, &delta, true, true);
    assert_eq!(allocation, original);

    let mut root = vec![0; 32 + e.len() + 16];
    p32(&mut root, 4, 0x13);
    p32(&mut root, 8, 4096);
    p32(&mut root, 16, 16);
    p32(&mut root, 20, (16 + e.len() + 16) as u32);
    p32(&mut root, 24, (16 + e.len() + 16) as u32);
    root[32..32 + e.len()].copy_from_slice(&e);
    root[32 + e.len()..].copy_from_slice(&entry(false, true));
    let mut record = file(&[resident(0x90, 1, &root)]);
    let original = record.clone();
    let delta = operation(35, 35, 56, 56, &5u32.to_le_bytes(), &(-5i32).to_le_bytes());
    execute(&mut record, &delta, false, false);
    assert_eq!(u32_at(&record, 152).unwrap(), 2);
    assert_eq!(u32_at(&record, 160).unwrap(), u32::MAX - 2);
    execute(&mut record, &delta, true, false);
    assert_eq!(record, original);
    reject_unchanged(&mut record, &operation(36, 0, 56, 56, &1u32.to_le_bytes(), &[]), false);
    reject_unchanged(&mut allocation, &operation(35, 0, 0, 64, &1u32.to_le_bytes(), &[]), true);
    reject_unchanged(&mut allocation, &operation(36, 36, 0, 64, &1u32.to_le_bytes(), &1u32.to_le_bytes()), true);
}

#[test]
fn relative_index_64_bit_delta_and_bounds() {
    let mut e = entry(true, false);
    p16(&mut e, 0, 40);
    p16(&mut e, 2, 8);
    p16(&mut e, 10, 16);
    p64(&mut e, 40, u64::MAX - 2);
    let mut b = index(true);
    execute(&mut b, &operation(14, 0, 0, 64, &e, &[]), false, true);
    let original = b.clone();
    let delta = operation(36, 36, 0, 64, &5u64.to_le_bytes(), &(-5i64).to_le_bytes());
    execute(&mut b, &delta, false, true);
    assert_eq!(u64_at(&b, 104).unwrap(), 2);
    assert_eq!(u64_at(&b, 64 + e.len() - 8).unwrap(), 5);
    execute(&mut b, &delta, true, true);
    assert_eq!(b, original);
    reject_unchanged(&mut b, &operation(36, 0, 0, 64, &[1; 6], &[]), true);
    p16(&mut b, 64, 24); // An offset inside the key is never a data value.
    reject_unchanged(&mut b, &operation(36, 0, 0, 64, &1u64.to_le_bytes(), &[]), true);
    p16(&mut b, 64, 88);
    reject_unchanged(&mut b, &operation(36, 0, 0, 64, &1u64.to_le_bytes(), &[]), true);
}
