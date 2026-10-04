//! Module: progress_display_tests
//! Purpose: Verify the progress line format and what each kind of output shows.
//! Created: 2026-10-04
//! Architecture: Drives the display with an in-memory writer; no process is spawned.

use super::*;

fn report(phase: Phase, done: u64, total: u64) -> RepairProgress {
    RepairProgress::new(phase, done, total)
}

fn shown(live: bool, reports: &[RepairProgress]) -> String {
    let mut display = ProgressDisplay::new(Vec::new(), live);
    for progress in reports {
        display.update(*progress).unwrap();
    }
    String::from_utf8(display.out).unwrap()
}

#[test]
fn written_lines_parse_back_and_other_lines_do_not() {
    for progress in [report(Phase::ScanMft, 512, 2048), report(Phase::Planning, 0, 0), report(Phase::Complete, 7, 7)] {
        let parsed = RepairProgress::parse_line(&progress.to_string()).unwrap();
        assert_eq!(
            (parsed.phase, parsed.completed_sectors, parsed.total_sectors, parsed.sector_bytes, parsed.percentage),
            (progress.phase, 512.min(progress.completed_sectors).max(progress.completed_sectors), progress.total_sectors, progress.sector_bytes, progress.percentage)
        );
    }
    assert!(RepairProgress::parse_line("ntfs-chkdsk: repair: Resource busy (os error 16)").is_none());
    assert!(RepairProgress::parse_line("progress phase=x").is_none());
}

#[test]
fn every_phase_code_has_a_name() {
    for code in 0..=Phase::Failed as u32 {
        assert_eq!(Phase::from_code(code).unwrap() as u32, code);
        assert!(!Phase::from_code(code).unwrap().label().is_empty());
    }
    assert!(Phase::from_code(Phase::Failed as u32 + 1).is_none());
}

#[test]
fn bar_fills_with_the_percentage() {
    assert_eq!(bar(Some(0)), format!("[{}]   0%", "-".repeat(BAR_CELLS)));
    assert_eq!(bar(Some(50)), format!("[{}{}]  50%", "#".repeat(BAR_CELLS / 2), "-".repeat(BAR_CELLS / 2)));
    assert_eq!(bar(Some(100)), format!("[{}] 100%", "#".repeat(BAR_CELLS)));
    assert_eq!(bar(None), format!("[{}]  --%", "-".repeat(BAR_CELLS)));
}

#[test]
fn terminal_redraws_one_line_and_erases_it_when_complete() {
    let text = shown(
        true,
        &[
            report(Phase::ScanMft, 0, 1000),
            report(Phase::ScanMft, 1, 1000),
            report(Phase::ScanMft, 500, 1000),
            report(Phase::Complete, 0, 0),
        ],
    );
    assert!(!text.contains('\n'));
    // The second report shows the same whole percentage and draws nothing.
    assert_eq!(text.matches("scanning file records").count(), 2);
    assert!(text.contains(" 50%"));
    assert!(text.ends_with(ERASE_LINE));
}

#[test]
fn plain_output_writes_a_line_per_phase_and_quarter() {
    let reports: Vec<_> = (0..=100).map(|done| report(Phase::Directories, done, 100)).collect();
    let text = shown(false, &reports);
    assert!(!text.contains('\r'));
    assert_eq!(text.lines().count(), 5);
    assert_eq!(text.lines().next().unwrap(), "  checking directories: 0%");
    assert_eq!(shown(false, &[report(Phase::Planning, 0, 0), report(Phase::Planning, 0, 0)]), "  planning\n");
}

#[test]
fn messages_stay_clear_of_the_bar() {
    let mut display = ProgressDisplay::new(Vec::new(), true);
    display.update(report(Phase::Repair, 1, 4)).unwrap();
    display.message("ntfs-chkdsk: note").unwrap();
    display.update(report(Phase::Repair, 1, 4)).unwrap();
    let text = String::from_utf8(display.out).unwrap();
    assert!(text.contains(&format!("{ERASE_LINE}ntfs-chkdsk: note\n{ERASE_LINE}[")));
}
