//! Module: fsck_ntfsrs::tests
//! Purpose: Check wrapper mode selection, paths and explicit maintenance requests.
//! Created: 2026-11-24
//! Architecture: Pure argument tests call the real CLI parser without opening devices.

use super::*;

fn options(args: &[&str]) -> Result<Options, &'static str> {
    parse(args.iter().map(OsString::from))
}

#[test]
fn repair_requires_selected_mode_or_affirmative_answer() {
    assert_eq!(options(&["device"]).unwrap().mode, Mode::Ask);
    assert_eq!(options(&["--repair", "device"]).unwrap().mode, Mode::Repair);
    assert_eq!(options(&["--check", "device"]).unwrap().mode, Mode::Check);
    assert_eq!(answer(b'\n'), Some(true));
    assert_eq!(answer(b'n'), Some(false));
    assert_eq!(answer(b's'), Some(false));
    assert_eq!(answer(b'x'), None);
}

#[test]
fn system_fsck_aliases_preserve_the_write_boundary() {
    for flag in ["-y", "-a", "-p", "-fy", "-af"] {
        assert_eq!(options(&[flag, "device"]).unwrap().mode, Mode::Repair);
    }
    assert_eq!(options(&["-fn", "device"]).unwrap().mode, Mode::Check);
    for (args, force) in [(&["-fn", "device"][..], true), (&["--force", "device"], true), (&["-n", "device"], false)] {
        assert_eq!(options(args).unwrap().force, force);
    }
    for args in [["-n", "-y", "device"], ["--repair", "--check", "device"]] {
        assert!(options(&args).is_err());
    }
    assert!(options(&["-ny", "device"]).is_err());
}

#[test]
fn paths_and_mode_selection_remain_unambiguous() {
    let parsed = options(&["--journal", "a path", "--repair", "--log", "log", "device"]).unwrap();
    assert_eq!(parsed.journal, Some(PathBuf::from("a path")));
    assert_eq!(parsed.log, Some(PathBuf::from("log")));
    assert!(options(&["--journal", "a", "--journal", "b", "device"]).is_err());
    assert!(options(&["--journal"]).is_err());
    assert!(options(&["device", "other"]).is_err());
    assert_eq!(options(&["--check", "--", "-device"]).unwrap().device, PathBuf::from("-device"));
}

#[test]
fn cleanup_requires_repair_and_retains_its_explicit_request() {
    let parsed = options(&["--repair", "--security-cleanup", "device"]).unwrap();
    assert!(parsed.cleanup_security);
    assert!(!options(&["--repair", "device"]).unwrap().cleanup_security);
    assert!(options(&["--check", "--security-cleanup", "device"]).is_err());
}
