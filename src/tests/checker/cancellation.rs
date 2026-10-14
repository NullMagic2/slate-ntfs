//! Module: cancellation_tests
//! Purpose: Exercise real terminal confirmation and worker signal forwarding.
//! Created: 2026-10-09
//! Architecture: Isolated test subprocesses use the production cancellation API;
//!     pseudo terminals generate actual foreground process-group interrupts.

use slate_ntfs_tools::{cancellation, progress_display};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MODE: &str = "SLATE_CANCELLATION_TEST_MODE";
const TIMEOUT: Duration = Duration::from_secs(10);

fn worker(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--ignored", "--exact", "cancellation_worker", "--nocapture", "--test-threads=1"]);
    command.env(MODE, mode);
    command
}

#[test]
#[ignore = "subprocess worker for isolated signal tests"]
fn cancellation_worker() {
    let mode = std::env::var(MODE).unwrap();
    cancellation::install().unwrap();
    let result = if mode == "delegate" {
        progress_display::run(&mut worker("checkpoint")).map(|_| ())
    } else {
        if mode == "deferred" {
            let unit = cancellation::defer();
            println!("unit-start");
            std::io::stdout().flush().unwrap();
            std::thread::sleep(Duration::from_millis(300));
            cancellation::checkpoint().unwrap();
            println!("unit-durable");
            std::io::stdout().flush().unwrap();
            drop(unit);
        } else {
            println!("ready");
            std::io::stdout().flush().unwrap();
        }
        loop {
            if let Err(error) = cancellation::checkpoint() {
                break Err(error);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    assert!(result.is_err());
    println!("stopped-safely");
    std::process::exit(cancellation::exit_code().unwrap());
}

struct Terminal {
    master: File,
    child: Child,
    output: String,
}
impl Terminal {
    fn start(mode: &str) -> Self {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) },
            0
        );
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let mut command = worker(mode);
        command.stdin(slave.try_clone().unwrap()).stdout(slave.try_clone().unwrap()).stderr(slave);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self { master, child: command.spawn().unwrap(), output: String::new() }
    }
    fn until(&mut self, text: &str) {
        let deadline = Instant::now() + TIMEOUT;
        while !self.output.contains(text) {
            assert!(Instant::now() < deadline, "missing {text:?}: {}", self.output);
            let mut poll = libc::pollfd { fd: self.master.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut poll, 1, 50) } <= 0 {
                continue;
            }
            let mut bytes = [0; 4096];
            let n = self.master.read(&mut bytes).unwrap_or_else(|e| panic!("{e}: {}", self.output));
            assert!(n > 0, "terminal closed: {}", self.output);
            self.output.push_str(&String::from_utf8_lossy(&bytes[..n]));
        }
    }
    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap();
    }
    fn finish(&mut self, code: i32) {
        self.until("stopped-safely");
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(code), "{}", self.output);
                break;
            }
            assert!(Instant::now() < deadline, "worker did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        // Every helper owns a fresh session. A failed test must not leak children.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}

#[test]
fn terminal_denial_continues_and_confirmation_cancels() {
    let mut terminal = Terminal::start("checkpoint");
    terminal.until("ready");
    terminal.send(b"\x03");
    terminal.until("Abort this operation safely?");
    for answer in [b"n\n".as_slice(), b"\n"] {
        terminal.send(answer);
        terminal.until("Continuing operation.");
        assert!(terminal.child.try_wait().unwrap().is_none());
        terminal.output.clear();
        terminal.send(b"\x03");
        terminal.until("Abort this operation safely?");
    }
    // Another Ctrl+C while awaiting confirmation must not force termination.
    terminal.send(b"\x03");
    terminal.send(b"yes\n");
    terminal.finish(130);
}

#[test]
fn interrupt_waits_for_the_durable_unit_before_prompting() {
    let mut terminal = Terminal::start("deferred");
    terminal.until("unit-start");
    terminal.send(b"\x03");
    terminal.until("Abort this operation safely?");
    assert!(
        terminal.output.find("unit-durable").unwrap() < terminal.output.find("Abort this operation safely?").unwrap()
    );
    terminal.send(b"y\n");
    terminal.finish(130);
}

#[test]
fn parent_owns_one_prompt_and_waits_for_worker_cancellation() {
    let mut terminal = Terminal::start("delegate");
    terminal.until("ready");
    terminal.send(b"\x03");
    terminal.until("Abort this operation safely?");
    terminal.send(b"y\n");
    terminal.finish(130);
    assert_eq!(terminal.output.matches("Abort this operation safely?").count(), 1);
    assert!(terminal.output.contains("waiting for the worker to stop safely"));
}

#[test]
fn service_termination_defers_without_an_unanswerable_prompt() {
    let mut command = worker("deferred");
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| if libc::setsid() < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) });
    }
    let mut child = command.spawn().unwrap();
    let mut output = child.stdout.take().unwrap();
    let mut first = [0; 1];
    output.read_exact(&mut first).unwrap();
    // The harness prints before the worker starts; wait for its explicit marker.
    let mut captured = vec![first[0]];
    while !String::from_utf8_lossy(&captured).contains("unit-start\n") {
        output.read_exact(&mut first).unwrap();
        captured.push(first[0]);
    }
    assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) }, 0);
    output.read_to_end(&mut captured).unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(143));
    assert!(String::from_utf8_lossy(&captured).contains("unit-durable"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("Abort this operation"));
}
