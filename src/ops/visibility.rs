//! Module: ntfs_rs::visibility
//! Purpose: Define the shared Linux directory-view visibility policy.
//! Created: 2026-10-14
//! Architecture: Kernel presentation hints and userspace policy adapters share these
//! flags; file permissions and protected metadata classification remain separate.

use super::std_info::{HIDDEN, SYSTEM};

pub const SHOW_HIDDEN: u32 = 1;
pub const SHOW_SYSTEM: u32 = SHOW_HIDDEN << 1;
pub const SHOW_METADATA: u32 = SHOW_SYSTEM << 1;
pub const ALL: u32 = SHOW_HIDDEN | SHOW_SYSTEM | SHOW_METADATA;
pub const DEFAULT: u32 = 0;

/// Build the shared wire flags without duplicating their values in adapters.
pub const fn flags(hidden: bool, system: bool, metadata: bool) -> u32 {
    (hidden as u32 * SHOW_HIDDEN) | (system as u32 * SHOW_SYSTEM) | (metadata as u32 * SHOW_METADATA)
}

/// Display hints never remove entries from filesystem enumeration.
pub fn display_visible(attributes: u32, flags: u32) -> bool {
    (attributes & HIDDEN == 0 || flags & SHOW_HIDDEN != 0) && (attributes & SYSTEM == 0 || flags & SHOW_SYSTEM != 0)
}
