//! Module: kernel::freestanding
//! Purpose: Supply runtime primitives for freestanding Rust kernel code.
//! Created: 2026-10-01
//! Architecture: The kernel build links these routines without a userspace Rust runtime.

// SPDX-License-Identifier: GPL-2.0
#![no_std]

#[path = "ntfs_parser.rs"]
mod parser;

extern "C" {
    fn ntfs_rs_panic() -> !;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: The C bridge defines this non-returning kernel BUG handler.
    unsafe { ntfs_rs_panic() }
}
