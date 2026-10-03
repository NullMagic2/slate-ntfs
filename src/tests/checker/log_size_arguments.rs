//! Module: tests::checker::log_size_arguments
//! Purpose: Verify ntfs-chkdsk log-size argument parsing.
//! Created: 2026-10-03
//! Architecture: Included by the ntfs-chkdsk binary under cfg(test).

use super::*;

#[test]
fn accepts_binary_units_and_rejects_overflow_and_ambiguous_units() {
    for input in ["2097152", "2097152B", "2048k", "2048KiB", "2M", "2mib"] {
        assert_eq!(parse_log_size(input), Ok(2 * 1024 * 1024));
    }
    assert_eq!(parse_log_size("3G"), Ok(3 * 1024 * 1024 * 1024));
    for input in ["", "2", "1M", "4G", "2MB", "-2M", "2.5M", "18446744073709551615G", "2097153"] {
        assert!(parse_log_size(input).is_err(), "{input}");
    }
}
