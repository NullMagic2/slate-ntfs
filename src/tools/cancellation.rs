//! Module: slate_ntfs_tools::cancellation
//! Purpose: Confirm terminal interrupts and stop work at cooperative boundaries.
//! Created: 2026-10-09
//! Architecture: CLI entry points install signal handlers; readers and durable
//!     recovery boundaries poll requests. Parents confirm for delegated workers.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

const DELEGATED_ENV: &str = "SLATE_NTFS_DELEGATED_CANCELLATION";
const SIGNAL_EXIT_BASE: i32 = 128;
const POLL_MILLIS: i32 = 50;
const ANSWER_BYTES: usize = 32;
static OUTPUT: Mutex<()> = Mutex::new(());
static REQUEST: AtomicI32 = AtomicI32::new(0);
static CANCELLED: AtomicI32 = AtomicI32::new(0);
static DEFERRED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn request(signal: libc::c_int) {
    // Only lock-free atomics run in the handler. Termination takes precedence
    // over an interactive request, including while a confirmation is pending.
    if signal == libc::SIGINT {
        let _ = REQUEST.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
    } else {
        REQUEST.store(signal, Ordering::Relaxed);
    }
}

/// Install before starting any work. A delegated worker ignores terminal
/// interrupts; its parent owns the prompt and sends SIGTERM after confirmation.
pub fn install() -> io::Result<()> {
    let delegated = std::env::var_os(DELEGATED_ENV).is_some();
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: sigaction receives initialized storage and a static C handler.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction =
            if delegated && signal == libc::SIGINT { libc::SIG_IGN } else { request as *const () as usize };
        action.sa_flags = libc::SA_RESTART;
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

pub fn exit_code() -> Option<i32> {
    match CANCELLED.load(Ordering::Relaxed) {
        0 => None,
        signal => Some(SIGNAL_EXIT_BASE + signal),
    }
}

fn cancelled() -> io::Error {
    // Interrupted would be retried by read_exact/write_all. This is a terminal
    // cancellation decision, not a transient interrupted system call.
    io::Error::other("operation cancelled safely; retain any unfinished recovery journal and resume it later")
}

/// Keep backend progress from erasing or interleaving the terminal question.
pub(crate) fn output_guard() -> MutexGuard<'static, ()> {
    OUTPUT.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn confirm() -> io::Result<bool> {
    let Ok(mut terminal) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return Ok(true);
    };
    // A background service must never read another foreground job's terminal.
    if unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) != libc::getpgrp() } {
        return Ok(true);
    }
    let _output = output_guard();
    terminal.write_all(b"\r\x1b[K\nAbort this operation safely? [y/N] ")?;
    terminal.flush()?;
    let mut answer = Vec::with_capacity(ANSWER_BYTES);
    let mut overflow = false;
    loop {
        let pending = REQUEST.load(Ordering::Relaxed);
        if pending != 0 && pending != libc::SIGINT {
            return Ok(true);
        }
        let mut poll = libc::pollfd { fd: terminal.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, POLL_MILLIS) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        let mut byte = [0];
        match terminal.read(&mut byte) {
            Ok(0) => return Ok(true),
            Ok(_) if byte[0] == b'\n' || byte[0] == b'\r' => {
                let answer = std::str::from_utf8(&answer).unwrap_or("").trim();
                return Ok(!overflow && (answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")));
            }
            Ok(_) => {
                if answer.len() < ANSWER_BYTES {
                    answer.push(byte[0]);
                } else {
                    overflow = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Call only where returning an error cannot leave an unjournaled target write
/// or an incomplete external journal. Denial continues the same operation.
pub fn checkpoint() -> io::Result<()> {
    if DEFERRED.load(Ordering::Relaxed) != 0 {
        return Ok(());
    }
    if exit_code().is_some() {
        return Err(cancelled());
    }
    let signal = REQUEST.swap(0, Ordering::Relaxed);
    if signal == 0 {
        return Ok(());
    }
    let confirmed = signal != libc::SIGINT || confirm().unwrap_or(true);
    let pending = REQUEST.swap(0, Ordering::Relaxed);
    let termination = pending != 0 && pending != libc::SIGINT;
    if confirmed || termination {
        CANCELLED.store(if termination { pending } else { signal }, Ordering::Relaxed);
        return Err(cancelled());
    }
    eprintln!("Continuing operation.");
    Ok(())
}

/// Defer confirmation until a bounded write/publication unit is durable.
/// Dropping the guard never aborts; the caller polls at the next safe boundary.
#[must_use]
pub struct Deferred;
impl Drop for Deferred {
    fn drop(&mut self) {
        DEFERRED.fetch_sub(1, Ordering::Relaxed);
    }
}
pub fn defer() -> Deferred {
    DEFERRED.fetch_add(1, Ordering::Relaxed);
    Deferred
}

/// Spawn a checker worker with one confirmation owner. Ignore SIGINT before
/// exec as well, closing the startup gap before its own handlers are installed.
pub fn spawn(command: &mut Command) -> io::Result<Child> {
    checkpoint()?;
    command.env(DELEGATED_ENV, "1");
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGINT, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// Do not abandon an active worker. After confirmation, request cooperative
/// termination and wait for it to finish its current durable unit.
pub fn wait(child: &mut Child) -> io::Result<ExitStatus> {
    let mut stopping = false;
    loop {
        if let Some(status) = child.try_wait()? {
            if stopping {
                return Err(cancelled());
            }
            if let Some(signal) = status.signal() {
                return Err(io::Error::other(format!(
                    "worker terminated by signal {signal}; no further repair started"
                )));
            }
            return Ok(status);
        }
        if !stopping && checkpoint().is_err() {
            stopping = true;
            eprintln!("Cancellation confirmed; waiting for the worker to stop safely.");
            if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    eprintln!("Cannot signal the worker ({error}); waiting for it to finish safely.");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(POLL_MILLIS as u64));
    }
}
