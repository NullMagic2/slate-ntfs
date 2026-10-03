//! Module: slate_ntfs_tools
//! Purpose: Expose userspace NTFS inspection, recovery and write tooling.
//! Created: 2026-10-01
//! Architecture: Command-line tools wrap the shared core with owned image I/O and recovery
//! plans.

// Userspace tools target 64-bit Linux; integer widths below rely on it.
const _: () = assert!(usize::BITS == u64::BITS);

pub mod bitlocker_cli;
pub mod checker;
pub mod delete_plan;
pub mod linux;
pub mod metadata_lab;
pub mod metadata_replay;
pub mod recovery_io;
pub use recovery_io::recovery_journal;
pub mod write_io;
