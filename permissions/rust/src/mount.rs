//! Module: ntfs_permissions::mount
//! Purpose: inspect live mount state and apply saved permissions safely.
//! Created: 2026-10-01
//! Architecture: the privileged policy backend calls this module to remount
//! drives; the GTK model reads it to show actual read-only state. The kernel
//! writer remains responsible for deciding whether NTFS can accept writes.

use crate::core::{Applied, Outcome, Result};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountState {
    pub fstype: String,
    pub read_only: bool,
    pub live_permissions: bool,
    pub owner_uid: Option<u32>,
}

/// Require one exact mount and explicit state; missing information must not
/// be treated as writable. A read-only view also restricts a writable superblock.
pub fn parse_state(text: &str) -> Result<MountState> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("findmnt: {e}"))?;
    let mounts = value
        .get("filesystems")
        .and_then(Value::as_array)
        .filter(|mounts| mounts.len() == 1)
        .ok_or("findmnt: expected one mount")?;
    let mount = &mounts[0];
    let field = |key| mount.get(key).and_then(Value::as_str).ok_or_else(|| format!("findmnt: missing {key}"));
    let vfs = field("vfs-options")?;
    let fs = field("fs-options")?;
    if !vfs.split(',').any(|o| o == "ro" || o == "rw") {
        return Err("findmnt: missing read-only/write state".into());
    }
    Ok(MountState {
        fstype: field("fstype")?.to_owned(),
        read_only: vfs.split(',').chain(fs.split(',')).any(|o| o == "ro" || o == "view_readonly"),
        live_permissions: fs.split(',').any(|o| o.starts_with("permissions=")),
        owner_uid: fs.split(',').find_map(|o| o.strip_prefix("uid=")).and_then(|uid| uid.parse().ok()),
    })
}

/// Inspect the exact mountpoint, including paths with spaces. Separate VFS and
/// filesystem options preserve both mount-wide and Slate view restrictions.
pub fn query_with(target: &str, run: &mut impl FnMut(&str, &[&str]) -> (bool, String)) -> Result<MountState> {
    let (ok, text) = run("findmnt", &["-J", "-o", "FSTYPE,VFS-OPTIONS,FS-OPTIONS", "--mountpoint", target]);
    if !ok {
        return Err(format!("Could not inspect the mounted drive: {text}"));
    }
    parse_state(&text)
}

/// Shared live-state lookup for the privileged backend and read-only GUI model.
pub fn query(target: &str) -> Result<MountState> {
    query_with(target, &mut crate::core::run)
}

pub const READ_ONLY_MESSAGE: &str = "Permissions saved, but the drive is still open read-only. Creating, changing and deleting files remain disabled. Close the drive in the file manager and open it again to retry supported journal recovery.";
pub const READ_ONLY_HINT: &str = "Write permissions cannot override a read-only mount. Close the drive in the file manager and open it again to retry supported journal recovery. Busy drives cannot be recovered while mounted. Hibernation or unsupported damage may still prevent writing; hibernated volumes require a complete Windows shutdown.";

/// A write selection retries the driver's normal writable admission. A failed
/// retry leaves the drive read-only and still installs the saved permissions.
/// Never repair the disk or bypass the driver's admission checks here.
pub fn apply_with(
    target: &str,
    options: &str,
    wants_write: bool,
    current: &MountState,
    run: &mut impl FnMut(&str, &[&str]) -> (bool, String),
) -> Outcome {
    if current.fstype != "ntfsrs" {
        return Outcome::new(Applied::Pending,
            "Saved. The drive is open with another NTFS driver. Close it in the file manager and open it again to use Slate permissions.", "");
    }
    if !current.live_permissions {
        return Outcome::new(
            Applied::Pending,
            "Saved. Restart the computer once to load the updated driver; after that, changes apply instantly.",
            "",
        );
    }
    // Removing write bits affects access policy, not the shared mount state.
    // Only an already read-only mount without write intent stays read-only.
    let mut refusal = String::new();
    let state = if current.read_only && !wants_write { "ro" } else { "rw" };
    // -i bypasses the mount helper: its automatic read-only fallback must not
    // hide a rejected writable remount from this explicit apply workflow.
    let (ok, text) = run("mount", &["-i", "-t", "ntfsrs", "-o", &format!("remount,{state},{options}"), target]);
    if !ok {
        if !current.read_only || !wants_write {
            return Outcome::new(Applied::Error, "Could not apply the new permissions:", text);
        }
        // A rejected writer must not discard a valid saved access policy.
        // Apply it on the read-only mount and retain the original refusal.
        refusal = text;
        let (ok, text) = run("mount", &["-i", "-t", "ntfsrs", "-o", &format!("remount,ro,{options}"), target]);
        if !ok {
            return Outcome::new(Applied::Error, "Could not apply the new permissions:", format!("{refusal}\n{text}"));
        }
    }
    // Command success is insufficient: verify the live mount before reporting
    // success, including drivers that return success while retaining ro.
    match query_with(target, run) {
        Ok(actual) if actual.fstype == "ntfsrs" && !actual.read_only => {
            Outcome::new(Applied::Applied, "Permissions updated.", "")
        }
        Ok(actual) if actual.fstype == "ntfsrs" => Outcome::new(Applied::ReadOnly, READ_ONLY_MESSAGE, refusal),
        Ok(_) => Outcome::new(
            Applied::Error,
            "Could not apply the new permissions:",
            "The mount changed while applying permissions.",
        ),
        Err(error) => Outcome::new(Applied::Error, "Could not verify the new permissions:", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn state(ro: bool) -> String {
        serde_json::json!({"filesystems": [{"fstype": "ntfsrs",
            "vfs-options": if ro { "nosuid,nodev,ro" } else { "nosuid,nodev,rw" },
            "fs-options": "permissions=desktop,uid=1000,gid=1000,fmask=0177,dmask=0077"}]})
        .to_string()
    }

    fn apply(ro: bool, write: bool, replies: Vec<(bool, String)>) -> (Outcome, Vec<Vec<String>>) {
        let mut replies = VecDeque::from(replies);
        let mut calls = Vec::new();
        let result = apply_with(
            "/media/x/My Drive",
            "permissions=desktop,uid=1000",
            write,
            &parse_state(&state(ro)).unwrap(),
            &mut |program, args| {
                calls.push(std::iter::once(program.to_owned()).chain(args.iter().map(|s| s.to_string())).collect());
                replies.pop_front().expect("unexpected command")
            },
        );
        assert!(replies.is_empty());
        (result, calls)
    }

    #[test]
    fn write_selection_retries_read_only_mount_and_verifies_rw() {
        let (result, calls) = apply(true, true, vec![(true, String::new()), (true, state(false))]);
        assert_eq!(result.status, Applied::Applied);
        assert_eq!(calls[0][5], "remount,rw,permissions=desktop,uid=1000");
        assert_eq!(calls[0][6], "/media/x/My Drive");
        assert_eq!(calls[1][0], "findmnt");
    }

    #[test]
    fn rejected_writer_keeps_ro_and_reports_saved_but_blocked() {
        let (result, calls) = apply(
            true,
            true,
            vec![(false, "volume needs recovery".into()), (true, String::new()), (true, state(true))],
        );
        assert_eq!(result.status, Applied::ReadOnly);
        assert_eq!(result.detail, "volume needs recovery");
        assert_eq!(calls[1][5], "remount,ro,permissions=desktop,uid=1000");
    }

    #[test]
    fn success_exit_code_does_not_prove_writable_mount() {
        let (result, _) = apply(true, true, vec![(true, String::new()), (true, state(true))]);
        assert_eq!(result.status, Applied::ReadOnly);
        let (result, _) = apply(false, true, vec![(true, String::new()), (false, "gone".into())]);
        assert_eq!(result.status, Applied::Error);
    }

    #[test]
    fn read_only_policy_does_not_start_a_writer() {
        let (result, calls) = apply(true, false, vec![(true, String::new()), (true, state(true))]);
        assert_eq!(result.status, Applied::ReadOnly);
        assert!(calls[0][5].starts_with("remount,ro,"));
        // Removing a person's write bits must not turn a shared writable mount read-only.
        let (result, calls) = apply(false, false, vec![(true, String::new()), (true, state(false))]);
        assert_eq!(result.status, Applied::Applied);
        assert!(calls[0][5].starts_with("remount,rw,"));
    }

    #[test]
    fn failed_remounts_are_errors_and_are_not_reported_as_applied() {
        let (result, calls) = apply(false, true, vec![(false, "failure".into())]);
        assert_eq!(result.status, Applied::Error);
        assert_eq!(calls.len(), 1);
        let (result, _) = apply(true, true, vec![(false, "write failure".into()), (false, "ro failure".into())]);
        assert_eq!(result.status, Applied::Error);
        assert!(result.detail.contains("write failure") && result.detail.contains("ro failure"));
    }

    #[test]
    fn other_and_old_drivers_do_not_receive_slate_remounts() {
        for (fstype, live_permissions) in [("ntfs3", true), ("ntfsrs", false)] {
            let current = MountState { fstype: fstype.into(), read_only: true, live_permissions, owner_uid: None };
            let result = apply_with("/mnt", "", true, &current, &mut |_, _| panic!("unexpected remount"));
            assert_eq!(result.status, Applied::Pending);
        }
    }

    #[test]
    fn mount_state_requires_unambiguous_data_and_includes_view_limits() {
        assert_eq!(parse_state(&state(false)).unwrap().owner_uid, Some(1000));
        assert!(parse_state("{}").is_err());
        assert!(parse_state("{\"filesystems\":[]}").is_err());
        assert!(parse_state("{\"filesystems\":[{},{}]}").is_err());
        assert!(parse_state("bad json").is_err());
        assert!(parse_state(&state(false).replace("nodev,rw", "nodev")).is_err());
        assert!(
            parse_state(&state(false).replace("permissions=desktop", "view_readonly,permissions=desktop"))
                .unwrap()
                .read_only
        );
    }
}
