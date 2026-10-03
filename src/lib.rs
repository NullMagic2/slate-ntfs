//! Module: ntfs_rs
//! Purpose: Expose the allocation-free NTFS validation and write engine.
//! Created: 2026-10-01
//! Architecture: Kernel and userspace adapters share this crate and supply their own I/O.

#![no_std]
#![deny(unsafe_code)]

#[cfg(any(test, feature = "std"))]
extern crate std;

mod format;
pub use format::*;
