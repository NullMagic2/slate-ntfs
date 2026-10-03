//! Module: ntfs_utils::application
//! Purpose: Application-scoped views.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

//! Application-scoped views. Namespace setup runs only in a newly spawned
//! child; the library caller's mounts and credentials are never changed.
use crate::Compatibility;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

#[derive(Clone, Debug, Default)]
pub struct ApplicationOptions {
    pub compatibility: Compatibility,
    /// None inherits the source; Some creates a mutable private visibility policy.
    pub visibility: Option<crate::Visibility>,
    /// Empty selects all currently visible slate-ntfs mounts.
    pub mounts: Vec<PathBuf>,
    /// Optional privilege drop before namespace setup (never an elevation).
    pub run_as: Option<(u32, u32)>,
}

#[derive(Debug)]
struct Mount {
    id: u64,
    parent: u64,
    target: CString,
    fs: String,
    options: String,
    super_options: String,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn cstring(bytes: impl Into<Vec<u8>>) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| invalid("embedded NUL"))
}
fn unescape(text: &str) -> io::Result<CString> {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let escape = bytes.get(i + 1..i + 4).ok_or_else(|| invalid("mount escape"))?;
            output.push(match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid("mount escape")),
            });
            i += 4;
        } else {
            output.push(bytes[i]);
            i += 1;
        }
    }
    cstring(output)
}
fn parse_mounts(text: &str) -> io::Result<Vec<Mount>> {
    text.lines()
        .map(|line| {
            let (left, right) = line.split_once(" - ").ok_or_else(|| invalid("mountinfo separator"))?;
            let a: Vec<_> = left.split_whitespace().collect();
            let b: Vec<_> = right.split_whitespace().collect();
            if a.len() < 6 || b.len() != 3 {
                return Err(invalid("mountinfo fields"));
            }
            Ok(Mount {
                id: a[0].parse().map_err(|_| invalid("mount ID"))?,
                parent: a[1].parse().map_err(|_| invalid("mount parent"))?,
                target: unescape(a[4])?,
                fs: b[0].into(),
                options: a[5].into(),
                super_options: b[2].into(),
            })
        })
        .collect()
}
fn flag(text: &str, name: &str) -> bool {
    text.split(',').any(|s| s == name)
}

struct ChildMount {
    target: CString,
    fd: i32,
}
struct View {
    target: CString,
    attributes: u32,
    children: Vec<ChildMount>,
}

fn plan(mounts: &[Mount], selected: &[PathBuf]) -> io::Result<Vec<View>> {
    let selected: Vec<_> = selected.iter().map(std::fs::canonicalize).collect::<io::Result<_>>()?;
    let mut views = Vec::new();
    for m in mounts.iter().filter(|m| m.fs == "ntfsrs") {
        let path = Path::new(OsStr::from_bytes(m.target.to_bytes()));
        if !selected.is_empty() && !selected.iter().any(|p| p == path) {
            continue;
        }
        if mounts.iter().filter(|other| other.target == m.target).count() != 1 {
            return Err(invalid("stacked mounts at the same path must be unstacked before launching"));
        }
        let mut attributes = 0;
        for (name, bit) in [
            ("ro", 1),
            ("nosuid", 2),
            ("nodev", 4),
            ("noexec", 8),
            ("noatime", 0x10),
            ("strictatime", 0x20),
            ("nodiratime", 0x80),
            ("nosymfollow", 0x0020_0000),
        ] {
            if flag(&m.options, name) {
                attributes |= bit;
            }
        }
        if flag(&m.super_options, "view_readonly") {
            attributes |= 1;
        }
        if flag(&m.super_options, "view_noexec") {
            attributes |= 8;
        }
        let children = mounts
            .iter()
            .filter(|c| c.parent == m.id)
            .map(|c| ChildMount { target: c.target.clone(), fd: -1 })
            .collect();
        views.push(View { target: m.target.clone(), attributes, children });
    }
    if views.is_empty() || (!selected.is_empty() && views.len() != selected.len()) {
        return Err(invalid("select an existing slate-ntfs mount (not a device or an arbitrary subdirectory)"));
    }
    views.sort_by_key(|v| v.target.as_bytes().iter().filter(|&&b| b == b'/').count());
    Ok(views)
}

/// Resolve supplementary groups before fork. No NSS or allocation in pre_exec.
fn groups_for(uid: u32, gid: u32) -> io::Result<Vec<u32>> {
    let mut buffer = vec![0u8; 65536];
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let error = unsafe { libc::getpwuid_r(uid, &mut pw, buffer.as_mut_ptr().cast(), buffer.len(), &mut result) };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    if result.is_null() {
        return Ok(vec![gid]);
    }
    let mut groups = vec![0; 65536];
    let mut count = groups.len() as i32;
    if unsafe { libc::getgrouplist(pw.pw_name, gid, groups.as_mut_ptr(), &mut count) } < 0 || count < 0 {
        return Err(invalid("too many supplementary groups"));
    }
    groups.truncate(count as usize);
    Ok(groups)
}

// Child-only syscall helpers. No heap allocation, logging, NSS or Rust locks.
fn checked(value: libc::c_long) -> io::Result<i32> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value as i32)
    }
}
unsafe fn close(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}
unsafe fn config(fd: i32, key: &std::ffi::CStr, value: Option<&std::ffi::CStr>) -> io::Result<()> {
    checked(unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fd,
            if value.is_some() { 1 } else { 0 },
            key.as_ptr(),
            value.map_or(std::ptr::null(), |v| v.as_ptr()),
            0,
        )
    })?;
    Ok(())
}
unsafe fn move_to(fd: i32, target: &std::ffi::CStr) -> io::Result<()> {
    checked(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            fd,
            c"".as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            0x4, /* MOVE_MOUNT_F_EMPTY_PATH */
        )
    })?;
    Ok(())
}
unsafe fn write_map(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    let fd = checked(unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) } as _)?;
    let result = checked(unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) } as _);
    unsafe {
        close(fd);
    }
    if result? as usize != data.len() {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}
unsafe fn mount_view(view: &mut View, mode: &std::ffi::CStr, visibility: Option<&std::ffi::CStr>) -> io::Result<()> {
    // Clone immediate child mounts recursively before covering their parent.
    for child in &mut view.children {
        child.fd = checked(unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                libc::AT_FDCWD,
                child.target.as_ptr(),
                1 | libc::O_CLOEXEC | libc::AT_RECURSIVE,
            )
        })?;
    }
    let fs = checked(unsafe { libc::syscall(libc::SYS_fsopen, c"ntfsrs".as_ptr(), 1) })?;
    let result = (|| unsafe {
        config(fs, c"view", Some(&view.target))?;
        config(fs, c"compatibility", Some(mode))?;
        if let Some(value) = visibility {
            config(fs, c"visibility", Some(value))?;
        }
        checked(libc::syscall(libc::SYS_fsconfig, fs, 6 /* CREATE */, 0usize, 0usize, 0))?;
        let tree = checked(libc::syscall(libc::SYS_fsmount, fs, 1, view.attributes))?;
        let result = move_to(tree, &view.target);
        close(tree);
        result?;
        for child in &mut view.children {
            move_to(child.fd, &child.target)?;
            close(child.fd);
            child.fd = -1;
        }
        Ok(())
    })();
    unsafe {
        close(fs);
    }
    result
}

/// Launch with private views of existing mounts. Unprivileged callers use a
/// user namespace; the host must permit unprivileged user namespaces. The
/// kernel inherits source restrictions and checks the caller's real SID/ACL.
/// Never installs a setuid helper or invokes sudo. No shell interpretation.
/// Inherited file descriptors retain the view through which they were opened.
pub fn spawn_application(program: &OsStr, arguments: &[OsString], options: &ApplicationOptions) -> io::Result<Child> {
    if program.is_empty() {
        return Err(invalid("empty application"));
    }
    let mounts = parse_mounts(&std::fs::read_to_string("/proc/self/mountinfo")?)?;
    let mut views = plan(&mounts, &options.mounts)?;
    let mode = cstring(options.compatibility.name())?;
    let visibility = options.visibility.map(|v| cstring(v.flags().to_string())).transpose()?;
    let cwd = cstring(std::env::current_dir()?.as_os_str().as_bytes())?;
    let identity = options.run_as.map(|(uid, gid)| groups_for(uid, gid).map(|g| (uid, gid, g))).transpose()?;
    let (uid, gid) = options.run_as.unwrap_or_else(|| unsafe { (libc::geteuid(), libc::getegid()) });
    let status = std::fs::read_to_string("/proc/self/status")?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .unwrap_or(0);
    let user_namespace = uid != 0 || effective & (1 << 21) == 0;
    let uid_map = format!("{uid} {uid} 1\n").into_bytes();
    let gid_map = format!("{gid} {gid} 1\n").into_bytes();
    let mut command = Command::new(program);
    command.args(arguments);
    // SAFETY: The closure runs after fork, in the new child only. It uses
    // precomputed buffers and async-signal-safe Linux syscalls exclusively.
    unsafe {
        command.pre_exec(move || {
            if let Some((uid, gid, ref groups)) = identity {
                checked(libc::setgroups(groups.len(), groups.as_ptr()) as _)?;
                checked(libc::setresgid(gid, gid, gid) as _)?;
                checked(libc::setresuid(uid, uid, uid) as _)?;
            }
            if user_namespace {
                checked(libc::unshare(libc::CLONE_NEWUSER) as _)?;
                write_map(c"/proc/self/uid_map", &uid_map)?;
                write_map(c"/proc/self/setgroups", b"deny")?;
                write_map(c"/proc/self/gid_map", &gid_map)?;
            }
            checked(libc::unshare(libc::CLONE_NEWNS) as _)?;
            checked(libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) as _)?;
            for view in &mut views {
                mount_view(view, &mode, visibility.as_deref())?;
            }
            // Re-resolve cwd; otherwise a process launched from a volume retains
            // its old working-directory mount even though its path was replaced.
            checked(libc::chdir(cwd.as_ptr()) as _)?;
            checked(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as _)?;
            Ok(())
        });
    }
    command.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaped_paths_and_mount_policy() {
        assert_eq!(Compatibility::default(), Compatibility::Ntfs);
        assert_eq!(ApplicationOptions::default().compatibility, Compatibility::Ntfs);
        let text = "10 1 7:0 / /games\\040disk rw,nosuid,nodev - ntfsrs /dev/loop0 rw,compatibility=linux,sidmap=u:0:S-1-5-18;g:0:S-1-5-18\n11 10 0:1 / /games\\040disk/sub rw - tmpfs tmpfs rw\n";
        let mounts = parse_mounts(text).unwrap();
        let views = plan(&mounts, &[]).unwrap();
        assert_eq!(views[0].target.to_bytes(), b"/games disk");
        assert_eq!(views[0].attributes, 6);
        assert_eq!(views[0].children.len(), 1);
        assert!(unescape("bad\\777").is_err());
        assert!(parse_mounts("bad").is_err());
    }
}
