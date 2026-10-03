// Module: slate_ntfs_tools::recovery_io::models::storage::tests
// Purpose: Exercise storage recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;
use std::io::{Read, Seek, SeekFrom, Write};

#[test]
fn spool_preserves_framing_mapping_and_equal_length_replacement() {
    let mut records = RecordStore::new().unwrap();
    assert!(records.is_empty());
    let prefix = vec![0x35; MAPPING_ALIGNMENT as usize - 3];
    let payload = b"record crossing an allocation boundary";
    records.push(&prefix).unwrap();
    records.push(payload).unwrap();
    records.push(&[]).unwrap();
    records.push(&37u64.to_le_bytes()).unwrap();
    assert_eq!(records.len(), 4);
    assert_eq!(records.get(0).unwrap(), prefix);
    assert_eq!(records.get(1).unwrap(), payload);
    assert_eq!(&*records.view(1).unwrap(), payload);
    assert_eq!(records.get(2).unwrap(), Vec::<u8>::new());
    assert_eq!(records.index(3).unwrap(), 37);

    // Inspect the fixed-width table independently of the descriptor decoder.
    let mut table = [0; INDEX_ENTRY_BYTES * 4];
    records.index.read_exact_at(&mut table, 0).unwrap();
    let rows = [
        (0u64, prefix.len() as u64),
        (prefix.len() as u64, payload.len() as u64),
        ((prefix.len() + payload.len()) as u64, 0),
        ((prefix.len() + payload.len()) as u64, WORD_BYTES as u64),
    ];
    let expected: Vec<u8> =
        rows.into_iter().flat_map(|(offset, len)| offset.to_le_bytes().into_iter().chain(len.to_le_bytes())).collect();
    assert_eq!(table.as_slice(), expected);

    let replacement = vec![0xa6; payload.len()];
    records.replace(1, &replacement).unwrap();
    assert_eq!(records.get(1).unwrap(), replacement);
    assert_eq!(&*records.view(1).unwrap(), replacement);
    assert_eq!(records.get(0).unwrap(), prefix);
    assert_eq!(records.index(3).unwrap(), 37);
    records.replace(2, &[]).unwrap();
    assert_eq!(records.get(2).unwrap(), Vec::<u8>::new());
}

#[test]
fn spool_rejects_invalid_access_without_changing_adjacent_records() {
    let mut records = RecordStore::new().unwrap();
    records.push(b"before").unwrap();
    records.push(&[]).unwrap();
    records.push(b"after").unwrap();
    assert_eq!(records.view(1).err().unwrap().to_string(), "empty record mapping");
    assert_eq!(records.index(0).unwrap_err().to_string(), "invalid schedule entry");
    assert_eq!(records.replace(0, b"short").unwrap_err().kind(), io::ErrorKind::InvalidInput);
    let number = records.len();
    assert_eq!(records.get(number).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(records.view(number).err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(records.replace(number, b"").unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(records.get(0).unwrap(), b"before");
    assert_eq!(records.get(2).unwrap(), b"after");
}

#[test]
fn spool_rejects_truncated_index_and_data() {
    let mut records = RecordStore::new().unwrap();
    records.push(b"payload").unwrap();
    records.index.set_len((INDEX_ENTRY_BYTES - 1) as u64).unwrap();
    assert_eq!(records.get(0).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(records.view(0).err().unwrap().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(records.replace(0, b"payload").unwrap_err().kind(), io::ErrorKind::UnexpectedEof);

    let mut records = RecordStore::new().unwrap();
    records.push(b"payload").unwrap();
    records.data.set_len(2).unwrap();
    assert_eq!(records.get(0).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn replacement_rejects_large_descriptor_length_as_invalid_input() {
    let mut records = RecordStore::new().unwrap();
    records.push(b"payload").unwrap();
    records.index.write_all_at(&u64::MAX.to_le_bytes(), WORD_BYTES as u64).unwrap();
    // Replacement compares unsigned lengths before platform-sized allocation.
    assert_eq!(records.replace(0, b"payload").unwrap_err().kind(), io::ErrorKind::InvalidInput);
    let mut actual = [0; 7];
    records.data.read_exact_at(&mut actual, 0).unwrap();
    assert_eq!(&actual, b"payload");
}

#[test]
fn fixed_word_rows_preserve_little_endian_bytes_and_neighboring_words() {
    const OFFSET: u64 = 3;
    const WORDS: [u64; 3] = [0x0807060504030201, u64::MAX, 0x1112131415161718];
    const GOLDEN: [u8; 27] =
        [9, 9, 9, 1, 2, 3, 4, 5, 6, 7, 8, 255, 255, 255, 255, 255, 255, 255, 255, 24, 23, 22, 21, 20, 19, 18, 17];
    let mut file = super::super::checker::consistency::scratch_file().unwrap();
    file.write_all(&[9; OFFSET as usize]).unwrap();
    write_words(&mut file, OFFSET, WORDS).unwrap();
    let mut observed = [0; GOLDEN.len()];
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_exact(&mut observed).unwrap();
    assert_eq!(observed, GOLDEN);
    assert_eq!(read_words::<3>(&mut file, OFFSET).unwrap(), WORDS);
    write_words(&mut file, OFFSET, [0_u64; 2]).unwrap();
    assert_eq!(read_words::<3>(&mut file, OFFSET).unwrap(), [0, 0, WORDS[2]]);
    file.set_len(GOLDEN.len() as u64 - 1).unwrap();
    assert_eq!(read_words::<3>(&mut file, OFFSET).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}
