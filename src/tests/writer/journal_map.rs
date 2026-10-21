//! Module: ntfs_rs::resident_writer::tests
//! Purpose: Verify scattered journal transfers and restart durability ordering.
//! Created: 2026-10-21
//! Architecture: In-memory device gaps and injected failures check the shared
//! journal mapper without changing production I/O adapters.

use super::*;
use std::{boxed::Box, vec, vec::Vec};

const FRAGMENT_BYTES: usize = super::super::boot::MIN_SECTOR_BYTES as usize;
const FRAGMENTS_PER_PAGE: usize = LOG_PAGE as usize / FRAGMENT_BYTES;
const RESTART_COPIES: usize = RESTART_PAIR_BYTES as usize / LOG_PAGE as usize;
const FRAGMENTS: usize = RESTART_COPIES * FRAGMENTS_PER_PAGE;
const DEVICE_STRIDE: usize = 3 * FRAGMENT_BYTES;
const SENTINEL: u8 = 0xa5;
const RESTART_BYTE: u8 = 0x3c;

#[derive(Debug, PartialEq)]
enum Event {
    Write(u64),
    Flush,
}

struct Device {
    bytes: Vec<u8>,
    events: Vec<Event>,
    fail: Option<u64>,
}

impl ReadAt for Device {
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<()> {
        out.copy_from_slice(&self.bytes[offset as usize..offset as usize + out.len()]);
        Ok(())
    }
}

impl WriteIo for Device {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        if self.fail == Some(offset) {
            return Err(Error::Io);
        }
        self.bytes[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
        self.events.push(Event::Write(offset));
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.events.push(Event::Flush);
        Ok(())
    }
}

fn fixture() -> (LogMap, Device) {
    let mut storage = vec![0; FRAGMENTS * PIECE_WORDS];
    for (index, words) in storage.chunks_exact_mut(PIECE_WORDS).enumerate() {
        words.copy_from_slice(
            &LogPiece {
                logical: (index * FRAGMENT_BYTES) as u32,
                bytes: FRAGMENT_BYTES as u32,
                start: (index * DEVICE_STRIDE) as u64,
            }
            .words(),
        );
    }
    let map = LogMap { lent: Some(Box::leak(storage.into_boxed_slice())), count: FRAGMENTS, ..LogMap::EMPTY };
    let device = Device { bytes: vec![SENTINEL; FRAGMENTS * DEVICE_STRIDE], events: Vec::new(), fail: None };
    (map, device)
}

#[test]
fn split_journal_transfers_preserve_device_gaps() {
    let (map, mut device) = fixture();
    let payload: Vec<_> = (0..RESTART_PAIR_BYTES as usize).map(|index| (index / FRAGMENT_BYTES) as u8).collect();
    map.write(&mut device, 0, &payload).unwrap();
    let mut readback = vec![0; payload.len() - FRAGMENT_BYTES];
    let offset = FRAGMENT_BYTES / 2;
    map.read(&mut device, offset as u64, &mut readback).unwrap();
    assert_eq!(readback, payload[offset..offset + readback.len()]);
    for (index, region) in device.bytes.chunks_exact(DEVICE_STRIDE).enumerate() {
        assert_eq!(&region[..FRAGMENT_BYTES], &payload[index * FRAGMENT_BYTES..(index + 1) * FRAGMENT_BYTES]);
        assert!(region[FRAGMENT_BYTES..].iter().all(|byte| *byte == SENTINEL));
    }
}

#[test]
fn invalid_journal_range_is_rejected_before_first_write() {
    let (map, mut device) = fixture();
    let before = device.bytes.clone();
    let payload = vec![RESTART_BYTE; LOG_PAGE as usize + FRAGMENT_BYTES];
    assert_eq!(map.write(&mut device, LOG_PAGE, &payload), Err(Error::InvalidLog));
    assert_eq!(device.bytes, before);
    assert!(device.events.is_empty());
    assert_eq!(map.write(&mut device, u64::MAX, &payload), Err(Error::Overflow));
    assert!(device.events.is_empty());
}

#[test]
fn secondary_restart_fragments_are_durable_before_primary() {
    let (map, mut device) = fixture();
    write_restarts(&mut device, &map, &vec![RESTART_BYTE; LOG_PAGE as usize]).unwrap();
    let mut expected = Vec::new();
    for first in [FRAGMENTS_PER_PAGE, 0] {
        expected.extend((first..first + FRAGMENTS_PER_PAGE).map(|index| Event::Write((index * DEVICE_STRIDE) as u64)));
        expected.push(Event::Flush);
    }
    assert_eq!(device.events, expected);
}

#[test]
fn failed_secondary_fragment_leaves_primary_untouched() {
    let (map, mut device) = fixture();
    device.fail = Some(((FRAGMENTS_PER_PAGE + 1) * DEVICE_STRIDE) as u64);
    assert_eq!(write_restarts(&mut device, &map, &vec![RESTART_BYTE; LOG_PAGE as usize]), Err(Error::Io));
    assert_eq!(device.events, vec![Event::Write((FRAGMENTS_PER_PAGE * DEVICE_STRIDE) as u64)]);
    let mut primary = vec![0; LOG_PAGE as usize];
    map.read(&mut device, 0, &mut primary).unwrap();
    assert!(primary.iter().all(|byte| *byte == SENTINEL));
}
