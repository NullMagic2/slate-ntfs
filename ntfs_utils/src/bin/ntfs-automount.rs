//! Module: ntfs_utils::bin::ntfs_automount
//! Purpose: mount hotplugged NTFS volumes for the selected local session user.
//! Created: 2026-10-01
//! Architecture: system services select the session and prepare managed fstab
//! entries; this adapter submits an unprivileged UDisks request. UDisks owns
//! mount authorization and remembers who may later unmount without a password.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

const ROOT_UID: u32 = 0;
const ACCOUNT_LOOKUP_BUFFER_BYTES: usize = 65_536;
const UNTRUSTED_WRITE_BITS: u32 = libc::S_IWGRP | libc::S_IWOTH;
const MOUNT_DIRECTORY_MODE: u32 = libc::S_IRWXU | libc::S_IRGRP | libc::S_IXGRP | libc::S_IROTH | libc::S_IXOTH;
const PRIVATE_FILE_MODE: u32 = libc::S_IRUSR | libc::S_IWUSR;
const FSTAB_FILE_MODE: u32 = PRIVATE_FILE_MODE | libc::S_IRGRP | libc::S_IROTH;
const ACL_PERMISSION_CHARACTERS: usize = 3;
const ACL_READ: u8 = libc::S_IROTH as u8;
const ACL_WRITE: u8 = libc::S_IWOTH as u8;
const ACL_EXECUTE: u8 = libc::S_IXOTH as u8;
const ACL_LIST_AND_TRAVERSE: u8 = ACL_READ | ACL_EXECUTE;
const MOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(10);
const DEVICE_SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const MAX_MOUNT_ATTEMPTS: u8 = 3;

fn output(program: &str, args: &[&str]) -> io::Result<String> {
    let result = Command::new(program).args(args).output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!("{program}: {}", String::from_utf8_lossy(&result.stderr).trim())));
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}
fn properties(text: &str) -> BTreeMap<&str, &str> {
    text.lines().filter_map(|line| line.split_once('=')).collect()
}
fn mounted(device: &str) -> bool {
    Command::new("findmnt").args(["-n", "--source", device]).output().is_ok_and(|o| o.status.success())
}
/// Select one active, local, non-root user on the device seat. Ambiguous or
/// absent sessions defer mounting rather than assigning ownership arbitrarily.
fn session_uid(device_properties: &BTreeMap<&str, &str>) -> io::Result<Option<u32>> {
    let seat = device_properties.get("ID_SEAT").copied().unwrap_or("seat0");
    let sessions = output("loginctl", &["list-sessions", "--no-legend", "--no-pager"])?;
    let mut users = Vec::new();
    for id in sessions.lines().filter_map(|s| s.split_whitespace().next()) {
        let text = output(
            "loginctl",
            &[
                "show-session",
                id,
                "--no-pager",
                "-p",
                "Active",
                "-p",
                "Remote",
                "-p",
                "Class",
                "-p",
                "User",
                "-p",
                "Seat",
            ],
        )?;
        let session = properties(&text);
        if session.get("Active") != Some(&"yes")
            || session.get("Remote") != Some(&"no")
            || !matches!(session.get("Class"), Some(&"user") | Some(&"user-early"))
            || session.get("Seat") != Some(&seat)
        {
            continue;
        }
        if let Some(uid) = session.get("User").and_then(|s| s.parse::<u32>().ok()) {
            if uid != ROOT_UID {
                users.push(uid);
            }
        }
    }
    users.sort_unstable();
    users.dedup();
    Ok(if users.len() == 1 { Some(users[0]) } else { None })
}
/// What happened to one device, so the watch loop knows whether to retry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Done,
    NoSession,
}

/// Resolve the account and administrator-managed mountpoint before submitting
/// the request as that account. Never retry an authorization failure as root.
fn mount_device(device: &str, requested_user: Option<u32>) -> io::Result<Outcome> {
    if !ntfs_utils::get_desktop_policy()?.automount || mounted(device) {
        return Ok(Outcome::Done);
    }
    let device = std::fs::canonicalize(device)?;
    let device = device.to_str().ok_or_else(|| io::Error::other("device path encoding"))?;
    if !device.starts_with("/dev/") {
        return Err(io::Error::other("not a /dev block device"));
    }
    let text = output("udevadm", &["info", "--query=property", "--name", device])?;
    let props = properties(&text);
    if props.get("ID_FS_TYPE") != Some(&"ntfs") || props.get("UDISKS_IGNORE") == Some(&"1") {
        return Ok(Outcome::Done);
    }
    let uid = match requested_user {
        Some(uid) => uid,
        None => match session_uid(&props)? {
            Some(uid) => uid,
            None => return Ok(Outcome::NoSession),
        },
    };
    if unsafe { libc::geteuid() } != ROOT_UID && unsafe { libc::geteuid() } != uid {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let mut buffer = vec![0u8; ACCOUNT_LOOKUP_BUFFER_BYTES];
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    let error = unsafe { libc::getpwuid_r(uid, &mut passwd, buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    if found.is_null() {
        return Err(io::Error::other("unknown local user"));
    }
    let gid = passwd.pw_gid;
    let name = unsafe { std::ffi::CStr::from_ptr(passwd.pw_name) }.to_string_lossy();
    if !prepare_mountpoint(device, &props, uid, gid, &name)? {
        return Ok(Outcome::Done);
    }

    let is_root = unsafe { libc::geteuid() } == ROOT_UID;
    let use_user_manager = is_root && std::path::Path::new("/run/systemd/system").is_dir();
    let mut command = mount_command(device, uid, gid, &name, is_root, use_user_manager);
    let result = command.output()?;
    if result.status.success() || mounted(device) {
        Ok(Outcome::Done)
    } else {
        Err(io::Error::other(String::from_utf8_lossy(&result.stderr).trim().to_owned()))
    }
}
/// The mount request must carry the session user's real process credentials.
/// Filesystem uid/gid options do not set UDisks' recorded mounting user.
/// A custom root changes fstab preparation, never the identity of this request.
fn mount_command(device: &str, uid: u32, gid: u32, username: &str, is_root: bool, use_user_manager: bool) -> Command {
    let mut command = if use_user_manager {
        let mut command = Command::new("systemd-run");
        // A service is spawned by the selected user's manager with that
        // user's credentials. --scope alone would retain the launcher's UID.
        command.args([
            "--quiet",
            "--collect",
            "--no-ask-password",
            "--user",
            "--wait",
            "--pipe",
            &format!("--machine={username}@.host"),
            "--",
            "udisksctl",
        ]);
        command
    } else {
        Command::new("udisksctl")
    };
    // Fail without prompting during background automount. UDisks still checks
    // authorization and records the actual request user for later unmounting.
    command.args(["mount", "--block-device", device, "--no-user-interaction"]);

    if is_root && !use_user_manager {
        // Without a user manager, drop before udisksctl starts. Clear
        // privileged supplementary groups and all saved root IDs too.
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    command
}

/// A named traversal-only ACL overrides otherwise readable directory modes.
/// Grant the mounting user listing access without changing other accounts.
fn allow_mount_parent_listing(parent: &std::path::Path, uid: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // Pin the verified directory so path replacement cannot redirect the
    // privileged ACL commands. Both children use this process's open handle.
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let metadata = directory.metadata()?;
    if unsafe { libc::geteuid() } == ROOT_UID
        && (metadata.uid() != ROOT_UID || metadata.mode() & UNTRUSTED_WRITE_BITS != 0)
    {
        return Err(io::Error::other("mount account directory must remain protected"));
    }
    let parent = format!("/proc/{}/fd/{}", std::process::id(), directory.as_raw_fd());
    let original = output("getfacl", &["-acpnE", &parent])?;
    let bits = |permissions: &str| -> io::Result<u8> {
        if permissions.len() != ACL_PERMISSION_CHARACTERS {
            return Err(io::Error::other("invalid mount directory ACL"));
        }
        let mut result = 0;
        for (actual, (expected, bit)) in
            permissions.bytes().zip([(b'r', ACL_READ), (b'w', ACL_WRITE), (b'x', ACL_EXECUTE)])
        {
            if actual == expected {
                result |= bit;
            } else if actual != b'-' {
                return Err(io::Error::other("invalid mount directory ACL"));
            }
        }
        Ok(result)
    };
    let spelling = |bits: u8| {
        format!(
            "{}{}{}",
            if bits & ACL_READ != 0 { 'r' } else { '-' },
            if bits & ACL_WRITE != 0 { 'w' } else { '-' },
            if bits & ACL_EXECUTE != 0 { 'x' } else { '-' },
        )
    };
    let entries: Vec<_> = original.lines().map(|line| line.split(':').collect::<Vec<_>>()).collect();
    let old_mask = entries
        .iter()
        .find_map(|entry| match entry.as_slice() {
            ["mask", "", permissions] => Some(*permissions),
            _ => None,
        })
        .or_else(|| {
            entries.iter().find_map(|entry| match entry.as_slice() {
                ["group", "", permissions] => Some(*permissions),
                _ => None,
            })
        })
        .ok_or_else(|| io::Error::other("missing mount directory ACL mask"))?;
    let old_mask = bits(old_mask)?;
    let mut updates = vec![format!("u:{uid}:r-x"), format!("m::{}", spelling(old_mask | ACL_LIST_AND_TRAVERSE))];
    // Expanding the mask must not activate previously masked rights belonging
    // to other users or groups, including writes to this protected parent.
    for entry in &entries {
        if let [kind, qualifier, permissions] = entry.as_slice() {
            if *kind == "group" || (*kind == "user" && !qualifier.is_empty() && *qualifier != uid.to_string()) {
                updates.push(format!("{kind}:{qualifier}:{}", spelling(bits(permissions)? & old_mask)));
            }
        }
    }
    output("setfacl", &["-n", "-m", &updates.join(","), &parent])?;
    Ok(())
}

/// Represent a custom root in fstab so UDisks and file managers share the
/// mountpoint. Only root may rewrite entries with our marker; manual entries
/// take precedence. File-access UID/GID does not confer UDisks mount ownership.
fn prepare_mountpoint(
    device: &str,
    props: &BTreeMap<&str, &str>,
    uid: u32,
    gid: u32,
    username: &str,
) -> io::Result<bool> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let root = match std::fs::read_to_string("/etc/slate-ntfs/mount-root") {
        Ok(root) => Some(root.trim().to_owned()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let has_fstab =
        Command::new("findmnt").args(["--fstab", "--evaluate", "-n", "--source", device]).output()?.status.success();
    let Some(root) = root else {
        return Ok(!has_fstab);
    };
    let Some(uuid) =
        props.get("ID_FS_UUID").filter(|u| !u.is_empty() && u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
    else {
        return Err(io::Error::other("NTFS UUID is required for a custom mount root"));
    };
    if unsafe { libc::geteuid() } != ROOT_UID {
        // An authorized user may use an existing managed fstab entry, but
        // only the host administrator can create or replace one.
        let text = std::fs::read_to_string("/etc/fstab")?;
        return Ok(text
            .lines()
            .any(|line| line.starts_with(&format!("UUID={uuid} ")) && line.ends_with("# slate-ntfs-managed")));
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        || username.is_empty()
        || username == "."
        || username == ".."
    {
        return Err(io::Error::other("invalid local account name"));
    }
    let root = std::path::Path::new(&root);
    if !root.is_absolute()
        || root == std::path::Path::new("/")
        || root.components().any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(io::Error::other("mount root must be an absolute directory"));
    }
    // Serialize competing hotplug services before reading and replacing fstab;
    // O_NOFOLLOW prevents the privileged lock open from following a symlink.
    let lock = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/etc/.slate-ntfs-fstab.lock")?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let text = std::fs::read_to_string("/etc/fstab")?;
    let source = format!("UUID={uuid}");
    let managed =
        |line: &str| line.split_whitespace().next() == Some(source.as_str()) && line.ends_with("# slate-ntfs-managed");
    let manual = text.lines().any(|line| line.split_whitespace().next() == Some(source.as_str()) && !managed(line));
    if manual || (has_fstab && !text.lines().any(managed)) {
        return Ok(false);
    }
    let label = props.get("ID_FS_LABEL").copied().unwrap_or(uuid);
    let label: String = label.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect();
    let label = if label.trim().is_empty() || label == "." || label == ".." { uuid.to_string() } else { label };
    let user_root = root.join(username);
    let mut target = user_root.join(&label);
    let escape =
        |value: &str| value.replace('\\', "\\134").replace(' ', "\\040").replace('\t', "\\011").replace('\n', "\\012");
    let occupied = |path: &std::path::Path| {
        text.lines().any(|line| {
            !managed(line) && line.split_whitespace().nth(1) == Some(escape(&path.to_string_lossy()).as_str())
        })
    };
    if occupied(&target) {
        target = user_root.join(format!("{label}-{uuid}"));
    }
    for directory in [root, user_root.as_path(), target.as_path()] {
        match std::fs::symlink_metadata(directory) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && metadata.uid() == ROOT_UID
                    && metadata.mode() & UNTRUSTED_WRITE_BITS == 0 => {}
            Ok(_) => {
                return Err(io::Error::other("mount directories must be root-owned and not writable by other users"))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(directory)?;
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(MOUNT_DIRECTORY_MODE))?;
            }
            Err(e) => return Err(e),
        }
    }
    // The account directory is owned by root. Prepare its ACL before UDisks
    // uses our fstab entry, including parents left by older package versions.
    allow_mount_parent_listing(&user_root, uid)?;
    let entry = format!(
        "{source} {} ntfs noauto,nosuid,nodev,uid={uid},gid={gid},x-gvfs-show 0 0 # slate-ntfs-managed\n",
        escape(&target.to_string_lossy())
    );
    let mut updated = String::new();
    for line in text.split_inclusive('\n') {
        if !managed(line.trim_end_matches('\n')) {
            updated.push_str(line);
        }
    }
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&entry);
    if updated != text {
        let temporary = format!("/etc/.slate-fstab-{}", std::process::id());
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(FSTAB_FILE_MODE)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(updated.as_bytes())?;
            file.sync_all()?;
            // Atomic replacement plus directory fsync preserves the old or new
            // complete fstab across interruption, never a partially written one.
            std::fs::rename(&temporary, "/etc/fstab")?;
            std::fs::File::open("/etc")?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result?;
    }
    Ok(true)
}

fn run() -> io::Result<()> {
    let mut user = None;
    let mut watch = false;
    let mut device = None;
    for argument in std::env::args().skip(1) {
        if argument == "--watch" {
            watch = true;
        } else if let Some(value) = argument.strip_prefix("--user=") {
            user = Some(value.parse().map_err(|_| io::Error::other("invalid UID"))?);
        } else if argument == "--help" {
            println!("ntfs-automount DEVICE [--user=UID]\nntfs-automount --watch --user=UID\nAutomatic mounting respects desktop policy and fstab. The watch mode can run under any init system.");
            return Ok(());
        } else if device.replace(argument).is_some() {
            return Err(io::Error::other("one device expected"));
        }
    }
    if watch {
        // Each device is handled once per appearance: a volume the user
        // unmounts stays unmounted. "No active local session yet" is retried,
        // so a disk attached at boot mounts at login; errors get a few spaced
        // retries (UDisks may still be starting) and are then left alone.
        let mut handled = std::collections::BTreeSet::new();
        let mut failures: BTreeMap<String, (u8, std::time::Instant)> = BTreeMap::new();
        loop {
            let listing = output("lsblk", &["-pnr", "-o", "NAME,FSTYPE"])?;
            let mut present = Vec::new();
            for line in listing.lines() {
                let mut fields = line.split_whitespace();
                if let (Some(device), Some("ntfs")) = (fields.next(), fields.next()) {
                    present.push(device.to_owned());
                    if handled.contains(device) {
                        continue;
                    }
                    if failures.get(device).is_some_and(|(_, last)| last.elapsed() < MOUNT_RETRY_DELAY) {
                        continue;
                    }
                    match mount_device(device, user) {
                        Ok(Outcome::NoSession) => {}
                        Ok(Outcome::Done) => {
                            handled.insert(device.to_owned());
                            failures.remove(device);
                        }
                        Err(e) => {
                            let count = failures.get(device).map_or(1, |(n, _)| n + 1);
                            eprintln!("ntfs-automount: {device}: {e}");
                            if count >= MAX_MOUNT_ATTEMPTS {
                                handled.insert(device.to_owned());
                                failures.remove(device);
                            } else {
                                failures.insert(device.to_owned(), (count, std::time::Instant::now()));
                            }
                        }
                    }
                }
            }
            handled.retain(|device| present.contains(device));
            failures.retain(|device, _| present.contains(device));
            std::thread::sleep(DEVICE_SCAN_INTERVAL);
        }
    }
    mount_device(&device.ok_or_else(|| io::Error::other("device required; see --help"))?, user).map(|_| ())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ntfs-automount: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const TEST_UID: u32 = 12_345;
    const TEST_GID: u32 = 23_456;
    const OTHER_UID: u32 = 34_567;
    const PROC_CREDENTIAL_FIELDS: usize = 4;

    #[test]
    fn account_directory_acl_allows_listing_and_preserves_other_users() {
        for old_acl in ["new", "traverse-only", "masked"] {
            let directory =
                std::env::temp_dir().join(format!("slate-parent-acl-test-{}-{old_acl}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(MOUNT_DIRECTORY_MODE)).unwrap();
            let path = directory.to_str().unwrap();
            let entries = match old_acl {
                "traverse-only" => format!("u:{TEST_UID}:--x,u:{OTHER_UID}:--x"),
                "masked" => format!("u:{TEST_UID}:--x,u:{OTHER_UID}:rwx,m::r--"),
                _ => format!("u:{OTHER_UID}:--x"),
            };
            output("setfacl", &["-m", &entries, path]).unwrap();
            let before = std::fs::metadata(&directory).unwrap();
            allow_mount_parent_listing(&directory, TEST_UID).unwrap();
            let acl = output("getfacl", &["-cpn", path]).unwrap();
            assert!(acl.lines().any(|line| line == format!("user:{TEST_UID}:r-x")));
            let other =
                if old_acl == "masked" { format!("user:{OTHER_UID}:r--") } else { format!("user:{OTHER_UID}:--x") };
            assert!(acl.lines().any(|line| line == other));
            assert!(acl.lines().any(|line| line == "mask::r-x"));
            let after = std::fs::metadata(&directory).unwrap();
            assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
            assert_eq!(after.mode() & UNTRUSTED_WRITE_BITS, 0);
            allow_mount_parent_listing(&directory, TEST_UID).unwrap();
            assert_eq!(output("getfacl", &["-cpn", path]).unwrap(), acl);
            std::fs::remove_dir(&directory).unwrap();
        }
    }

    #[test]
    fn systemd_mount_is_spawned_by_the_selected_users_manager() {
        let command = mount_command("/dev/test", TEST_UID, TEST_GID, "test-user", true, true);
        assert_eq!(command.get_program(), "systemd-run");
        let args: Vec<_> = command.get_args().map(|arg| arg.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--quiet",
                "--collect",
                "--no-ask-password",
                "--user",
                "--wait",
                "--pipe",
                "--machine=test-user@.host",
                "--",
                "udisksctl",
                "mount",
                "--block-device",
                "/dev/test",
                "--no-user-interaction",
            ]
        );
        assert!(!args.contains(&"--scope"));
    }

    #[test]
    fn non_systemd_and_user_invocations_use_udisks_directly() {
        for root in [true, false] {
            let command = mount_command("/dev/test", TEST_UID, TEST_GID, "test-user", root, false);
            assert_eq!(command.get_program(), "udisksctl");
            let args: Vec<_> = command.get_args().map(|arg| arg.to_str().unwrap()).collect();
            assert_eq!(args, ["mount", "--block-device", "/dev/test", "--no-user-interaction"]);
        }
    }

    #[test]
    fn failed_credential_drop_never_executes_a_mount_request() {
        if unsafe { libc::geteuid() } == ROOT_UID {
            return; // The root-only test below checks successful credential dropping.
        }
        let mut command = mount_command("/dev/test", TEST_UID, TEST_GID, "test-user", true, false);
        assert_eq!(command.output().unwrap_err().raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    #[ignore = "requires a root test host"]
    fn root_mount_child_has_no_root_ids_or_groups() {
        assert_eq!(unsafe { libc::geteuid() }, ROOT_UID, "run this ignored test as root");
        let directory = std::env::temp_dir().join(format!("slate-automount-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(MOUNT_DIRECTORY_MODE)).unwrap();
        let probe = directory.join("udisksctl");
        std::fs::write(&probe, "#!/bin/sh\nexec /bin/cat /proc/self/status\n").unwrap();
        std::fs::set_permissions(
            &probe,
            std::fs::Permissions::from_mode(
                libc::S_IRWXU | libc::S_IRGRP | libc::S_IXGRP | libc::S_IROTH | libc::S_IXOTH,
            ),
        )
        .unwrap();
        let mut command = mount_command("/dev/test", TEST_UID, TEST_GID, "test-user", true, false);
        command.env("PATH", &directory);
        let result = command.output();
        std::fs::remove_dir_all(&directory).unwrap();
        let result = result.unwrap();
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        let field = |name: &str| {
            text.lines().find_map(|line| line.strip_prefix(name)).unwrap().split_whitespace().collect::<Vec<_>>()
        };
        let uid = TEST_UID.to_string();
        let gid = TEST_GID.to_string();
        assert_eq!(field("Uid:"), [uid.as_str(); PROC_CREDENTIAL_FIELDS]);
        assert_eq!(field("Gid:"), [gid.as_str(); PROC_CREDENTIAL_FIELDS]);
        assert!(field("Groups:").is_empty());
    }
}
