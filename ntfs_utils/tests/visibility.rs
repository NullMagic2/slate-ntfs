//! Module: ntfs_utils::tests::visibility
//! Purpose: Check display defaults and the explicit visibility protocol.
//! Created: 2026-10-14
//! Architecture: Verifies the userspace policy against the shared kernel flags;
//! mounted copy/removal coverage lives in the private VM regression.

use ntfs_rs::{std_info, visibility};
use ntfs_utils::Visibility;

#[test]
fn ordinary_hidden_files_are_display_hints_only() {
    let policy = Visibility::default();
    assert!(!policy.show_hidden);
    assert!(!policy.show_system);
    assert!(!policy.show_metadata);
    assert_eq!(policy.flags(), visibility::DEFAULT);
    assert!(visibility::display_visible(0, policy.flags()));
    for attributes in [std_info::HIDDEN, std_info::SYSTEM, std_info::HIDDEN | std_info::SYSTEM] {
        assert!(!visibility::display_visible(attributes, policy.flags()));
        assert!(visibility::display_visible(attributes, visibility::SHOW_HIDDEN | visibility::SHOW_SYSTEM));
    }
}

#[test]
fn explicit_visibility_flags_preserve_the_protocol() {
    for flags in 0..=visibility::ALL {
        assert_eq!(Visibility::from_flags(flags).unwrap().flags(), flags);
    }
    assert!(Visibility::from_flags(visibility::ALL << 1).is_err());
    assert!(Visibility::all().show_metadata);
}
