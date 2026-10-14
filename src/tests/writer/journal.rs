//! Module: ntfs_rs::journal::tests
//! Purpose: Check circular reservations against live checkpoints and sequence overflow.
//! Created: 2026-10-09
//! Architecture: Exercises the shared reservation API without performing I/O.
use super::super::logfile::{advance_restart_checkpoint, encode_initial_restart};
use super::*;

fn restart(at: u64, generation: u64) -> RestartPage {
    let mut page = [0; 4096];
    let start = (generation << 15) | ((4 * 4096 + 64) / 8);
    encode_initial_restart(&mut page, 196608, start).unwrap();
    let lsn = (generation << 15) | ((at + 64) / 8);
    if lsn != start {
        advance_restart_checkpoint(&mut page, 512, lsn).unwrap();
    }
    RestartPage::parse(&mut page, 512).unwrap()
}

#[test]
fn reserves_across_wrap_without_overwriting_live_checkpoint() {
    let before = restart(46 * 4096, 1);
    let slots = reserve_resident(before).unwrap();
    assert_eq!(slots.map(|s| s.offset), [47 * 4096, 4 * 4096, 5 * 4096, 6 * 4096]);
    assert_eq!(slots.map(|s| s.lsn >> 15), [1, 2, 2, 2]);
    assert!(slots.windows(2).all(|s| s[0].lsn < s[1].lsn));
}

#[test]
fn refuses_pending_transactions_and_generation_overflow() {
    let mut before = restart(4 * 4096, 1);
    before.current_lsn += 512;
    assert_eq!(reserve_resident(before), Err(Error::Unsupported));
    let before = restart(47 * 4096, (1_u64 << 49) - 1);
    assert_eq!(next_slot(before), Err(Error::Overflow));
}

#[test]
fn computed_reservations_match_sequential_slots_and_live_limits() {
    for page in 4..48 {
        let checkpoint = restart(page * 4096, 1);
        let reservation = PageReservation::new(checkpoint, 43).unwrap();
        let mut head = checkpoint;
        for i in 0..43 {
            let next = next_slot(head).unwrap();
            assert_eq!(reservation.slot(i).unwrap(), next);
            head.current_lsn = next.lsn;
        }
        assert!(matches!(PageReservation::new(checkpoint, 44), Err(Error::NoSpace)));
        assert!(matches!(PageReservation::new(head, 1), Err(Error::NoSpace)));
    }
}

#[test]
fn fragmented_transactions_are_not_limited_by_a_slot_buffer() {
    let mut raw = [0; 4096];
    encode_initial_restart(&mut raw, 8 * 1024 * 1024, (1 << 21) | ((4 * 4096 + 64) / 8)).unwrap();
    let restart = RestartPage::parse(&mut raw, 512).unwrap();
    let reservation = PageReservation::new(restart, 512).unwrap();
    let mut head = restart;
    for i in 0..512 {
        let next = next_slot(head).unwrap();
        assert_eq!(reservation.slot(i).unwrap(), next);
        head.current_lsn = next.lsn;
    }
}
