//! Module: slate_ntfs_tools::progress_display
//! Purpose: Show the progress a repair backend reports to a person.
//! Created: 2026-10-04
//! Architecture: Consumes the `RepairProgress` lines ntfs-chkdsk writes with --progress.
//! A terminal gets one redrawn bar; any other output gets occasional plain lines.

use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::process::{Command, ExitStatus, Stdio};

use crate::recovery_io::{Phase, RepairProgress};

/// Cells in the drawn bar.
const BAR_CELLS: usize = 30;
/// Percentage points between two lines on an output that is not a terminal.
const PLAIN_STEP_PERCENT: u32 = 25;
const FULL_PERCENT: u32 = 100;
/// Return to the line start and erase it.
const ERASE_LINE: &str = "\r\x1b[K";

/// What is currently shown: the phase and its whole percentage, if known.
type Shown = (Phase, Option<u32>);

pub struct ProgressDisplay<W: Write> {
    out: W,
    live: bool,
    shown: Option<Shown>,
    drawn: bool,
}

/// The bar for a whole percentage, or a blank one while the total is unknown.
pub fn bar(percent: Option<u32>) -> String {
    let filled = percent.map_or(0, |percent| BAR_CELLS * percent.min(FULL_PERCENT) as usize / FULL_PERCENT as usize);
    let number = percent.map_or_else(|| " --%".to_owned(), |percent| format!("{percent:3}%"));
    format!("[{}{}] {number}", "#".repeat(filled), "-".repeat(BAR_CELLS - filled))
}

impl<W: Write> ProgressDisplay<W> {
    /// `live` selects the redrawn bar; without it only plain lines are written.
    pub fn new(out: W, live: bool) -> Self {
        Self { out, live, shown: None, drawn: false }
    }

    /// Show one report. Reports that would draw the same thing are skipped.
    pub fn update(&mut self, progress: RepairProgress) -> io::Result<()> {
        let Some(phase) = Phase::from_code(progress.phase) else {
            return Ok(());
        };
        if phase == Phase::Complete {
            self.shown = None;
            return self.clear();
        }
        let percent = (progress.percentage >= 0.0).then_some(progress.percentage as u32);
        let now = (phase, percent);
        if self.shown == Some(now) {
            return Ok(());
        }
        if self.live {
            write!(self.out, "{ERASE_LINE}{}  {}", bar(percent), phase.label())?;
            self.drawn = true;
        } else {
            let step = |shown: Shown| (shown.0, shown.1.map(|percent| percent / PLAIN_STEP_PERCENT));
            if self.shown.map(step) != Some(step(now)) {
                match percent {
                    Some(percent) => writeln!(self.out, "  {}: {percent}%", phase.label())?,
                    None => writeln!(self.out, "  {}", phase.label())?,
                }
            }
        }
        self.shown = Some(now);
        self.out.flush()
    }

    /// Write a line that is not progress, keeping it clear of the bar.
    pub fn message(&mut self, line: &str) -> io::Result<()> {
        self.clear()?;
        // The next report redraws the bar below this line.
        if self.live {
            self.shown = None;
        }
        writeln!(self.out, "{line}")?;
        self.out.flush()
    }

    /// Remove the bar so later output starts on a clean line.
    pub fn clear(&mut self) -> io::Result<()> {
        if self.drawn {
            write!(self.out, "{ERASE_LINE}")?;
            self.drawn = false;
            self.out.flush()?;
        }
        Ok(())
    }
}

/// Run a backend command that reports progress on its standard error and
/// show that progress on ours. Its other diagnostics pass through unchanged.
pub fn run(command: &mut Command) -> io::Result<ExitStatus> {
    let mut child = command.stderr(Stdio::piped()).spawn()?;
    let reports = child.stderr.take().ok_or_else(|| io::Error::other("backend diagnostics are not piped"))?;
    let stderr = io::stderr();
    let mut display = ProgressDisplay::new(stderr.lock(), stderr.is_terminal());
    for line in BufReader::new(reports).lines() {
        let line = line?;
        match RepairProgress::parse_line(&line) {
            Some(progress) => display.update(progress)?,
            None => display.message(&line)?,
        }
    }
    display.clear()?;
    child.wait()
}

#[cfg(test)]
#[path = "../tests/checker/progress_display.rs"]
mod tests;
