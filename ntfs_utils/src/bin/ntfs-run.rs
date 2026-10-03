//! Module: ntfs_utils::bin::ntfs_run
//! Purpose: Provide the ntfs-run command-line entry point.
//! Created: 2026-10-01
//! Architecture: Utility API callers and commands use this module over the shared NTFS core.

use ntfs_utils::{spawn_application, ApplicationOptions, Compatibility, Visibility};
use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;

fn main() {
    let mut options = ApplicationOptions::default();
    let mut program = None;
    let mut mount_device = None;
    let mut mount_target = None;
    let mut unmount_target = None;
    let mut readonly = false;
    let mut sidmap = None;
    let mut uid = None;
    let mut gid = None;
    let mut automount = None;
    let mut policy_only = false;
    let mut refresh_policy = false;
    let mut live = false;
    let mut mode_seen = false;
    let mut permissions: Option<bool> = None; // Some(true) = desktop
    let mut file_mode = None;
    let mut dir_mode = None;
    let mut arguments = Vec::new();
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--" {
            arguments.extend(args);
            break;
        }
        if arg == "--mount-volume" && mount_device.is_none() {
            mount_device = Some(std::path::PathBuf::from(args.next().unwrap_or_else(|| usage())));
            mount_target = Some(std::path::PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if arg == "--unmount-volume" && unmount_target.is_none() {
            unmount_target = Some(std::path::PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--permissions=")) {
            if permissions.is_some() {
                usage();
            }
            permissions = Some(match value {
                "desktop" => true,
                "windows" => false,
                _ => usage(),
            });
        } else if arg == "--file-mode" && file_mode.is_none() {
            file_mode = Some(
                args.next()
                    .and_then(|s| s.to_str().and_then(|s| u32::from_str_radix(s, 8).ok()))
                    .filter(|m| *m <= 0o777)
                    .unwrap_or_else(|| usage()),
            );
        } else if arg == "--dir-mode" && dir_mode.is_none() {
            dir_mode = Some(
                args.next()
                    .and_then(|s| s.to_str().and_then(|s| u32::from_str_radix(s, 8).ok()))
                    .filter(|m| *m <= 0o777)
                    .unwrap_or_else(|| usage()),
            );
        } else if arg == "--read-only" {
            readonly = true;
        } else if arg == "--sidmap" && sidmap.is_none() {
            sidmap = Some(args.next().and_then(|s| s.into_string().ok()).unwrap_or_else(|| usage()));
        } else if arg == "--uid" && uid.is_none() {
            uid = Some(
                args.next().and_then(|s| s.to_str().and_then(|s| s.parse::<u32>().ok())).unwrap_or_else(|| usage()),
            );
        } else if arg == "--gid" && gid.is_none() {
            gid = Some(
                args.next().and_then(|s| s.to_str().and_then(|s| s.parse::<u32>().ok())).unwrap_or_else(|| usage()),
            );
        } else if arg == "--application" && program.is_none() {
            program = args.next();
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--compatibility=")) {
            if mode_seen {
                usage();
            }
            options.compatibility = Compatibility::parse(value).unwrap_or_else(|| usage());
            mode_seen = true;
        } else if arg == "--show-hidden" {
            options.visibility = Some(Visibility::all());
        } else if arg == "--hide-hidden" {
            options.visibility = Some(Visibility::default());
        } else if arg == "--show-meta" {
            options.visibility.get_or_insert_with(Visibility::default).show_metadata = true;
        } else if arg == "--live" {
            live = true;
        } else if arg == "--refresh-desktop-policy" {
            policy_only = true;
            refresh_policy = true;
        } else if arg == "--desktop-policy" {
            policy_only = true;
        } else if let Some(value) = arg.to_str().and_then(|s| s.strip_prefix("--automount=")) {
            automount = Some(match value {
                "on" => true,
                "off" => false,
                _ => usage(),
            });
        } else if arg == "--desktop-mount-options" {
            let uid = args.next().and_then(|s| s.to_str().and_then(|s| s.parse().ok())).unwrap_or_else(|| usage());
            let gid = args.next().and_then(|s| s.to_str().and_then(|s| s.parse().ok())).unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            match ntfs_utils::desktop::desktop_mount_options(uid, gid) {
                Ok(text) => {
                    println!("{text}");
                    return;
                }
                Err(e) => fail(e),
            }
        } else if arg == "--mount" {
            options.mounts.push(args.next().unwrap_or_else(|| usage()).into());
        } else if arg == "--help" || arg == "-h" {
            println!("ntfs-run --mount-volume DEVICE TARGET [--uid UID --gid GID | --sidmap MAP] [--read-only] [--compatibility=ntfs|linux] [--show-hidden|--show-meta]\n         [--permissions=desktop [--uid UID] [--gid GID] [--file-mode 0600] [--dir-mode 0700] | --permissions=windows --sidmap MAP]\n         desktop: one owner/group and rwx bits for the whole mount (Windows ACLs kept, not enforced);\n         windows: strict Windows ACLs for mapped identities. Use --file-mode 0660 --dir-mode 0770 to share with --gid.\nntfs-run --unmount-volume TARGET\nntfs-run [--compatibility=ntfs|linux] [--show-hidden|--hide-hidden|--show-meta] [--mount PATH] --application PROGRAM [-- ARG ...]\nntfs-run --live --mount PATH --show-hidden|--hide-hidden\nntfs-run --automount=on|off\nntfs-run --desktop-policy [--automount=on|off] [--show-hidden|--hide-hidden]\nHost policy changes require administrator privileges; private view toggles do not.\nDefault: native NTFS. Selects existing slate-ntfs mounts in a private namespace.\nUnprivileged users require enabled user namespaces; source permissions still apply.\nWhen invoked through sudo, drops to SUDO_UID/SUDO_GID before creating views.");
            return;
        } else {
            usage();
        }
    }
    if mount_device.is_some() || unmount_target.is_some() {
        if program.is_some()
            || policy_only
            || automount.is_some()
            || live
            || !options.mounts.is_empty()
            || !arguments.is_empty()
        {
            usage();
        }
        let result = if let Some(target) = unmount_target {
            if mount_device.is_some()
                || readonly
                || sidmap.is_some()
                || uid.is_some()
                || gid.is_some()
                || mode_seen
                || options.visibility.is_some()
            {
                usage();
            }
            ntfs_utils::unmount_fs(&target)
        } else {
            let device = mount_device.unwrap();
            let target = mount_target.unwrap();
            let visibility = options.visibility.unwrap_or_default();
            if (file_mode.is_some() || dir_mode.is_some()) && permissions != Some(true) {
                usage();
            }
            if let Some(desktop) = permissions {
                let sudo_id = |name: &str| -> Option<u32> {
                    if unsafe { libc::geteuid() } != 0 {
                        return None;
                    }
                    std::env::var(name).ok().map(|v| v.parse().unwrap_or_else(|_| usage()))
                };
                let access = if desktop {
                    ntfs_utils::AccessPolicy::Desktop {
                        uid: uid.or_else(|| sudo_id("SUDO_UID")).unwrap_or_else(|| unsafe { libc::geteuid() }),
                        gid: gid.or_else(|| sudo_id("SUDO_GID")).unwrap_or_else(|| unsafe { libc::getegid() }),
                        file_mode: file_mode.unwrap_or(0o600),
                        dir_mode: dir_mode.unwrap_or(0o700),
                    }
                } else {
                    if sidmap.is_none() || uid.is_some() || gid.is_some() {
                        usage();
                    }
                    ntfs_utils::AccessPolicy::Windows
                };
                let result = ntfs_utils::mount_fs_with_access(
                    &device,
                    &target,
                    sidmap.as_deref(),
                    options.compatibility,
                    readonly,
                    visibility,
                    access,
                );
                if result.is_success() {
                    println!("{}", result.message);
                    return;
                }
                eprintln!("ntfs-run: {}", result.message);
                std::process::exit(result.status as i32);
            }
            if let Some(map) = sidmap {
                if uid.is_some() || gid.is_some() {
                    usage();
                }
                ntfs_utils::mount_fs_with_visibility(
                    &device,
                    &target,
                    &map,
                    options.compatibility,
                    readonly,
                    visibility,
                )
            } else {
                // sudo callers normally intend their desktop account to own the view.
                let sudo_id = |name: &str| -> Option<u32> {
                    if unsafe { libc::geteuid() } != 0 {
                        return None;
                    }
                    match std::env::var(name) {
                        Ok(v) => Some(v.parse().unwrap_or_else(|_| usage())),
                        Err(std::env::VarError::NotPresent) => None,
                        Err(_) => usage(),
                    }
                };
                let uid = uid.or_else(|| sudo_id("SUDO_UID")).unwrap_or_else(|| unsafe { libc::geteuid() });
                let gid = gid.or_else(|| sudo_id("SUDO_GID")).unwrap_or_else(|| unsafe { libc::getegid() });
                ntfs_utils::mount_fs_for_user(&device, &target, uid, gid, options.compatibility, readonly, visibility)
            }
        };
        if result.is_success() {
            println!("{}", result.message);
            return;
        }
        eprintln!("ntfs-run: {}", result.message);
        std::process::exit(result.status as i32);
    }
    if readonly || sidmap.is_some() || uid.is_some() || gid.is_some() {
        usage();
    }
    if policy_only {
        let mut policy = ntfs_utils::get_desktop_policy().unwrap_or_else(|e| fail(e));
        if let Some(value) = automount {
            policy.automount = value;
        }
        if let Some(value) = options.visibility {
            policy.visibility = value;
        }
        if refresh_policy || automount.is_some() || options.visibility.is_some() {
            ntfs_utils::set_desktop_policy(policy).unwrap_or_else(|e| fail(e));
        }
        println!("automount={} visibility={}", policy.automount, policy.visibility.flags());
        if program.is_none() {
            return;
        }
    } else if let Some(enabled) = automount {
        ntfs_utils::set_automount(enabled).unwrap_or_else(|e| fail(e));
        if program.is_none() && !live {
            return;
        }
    }
    if live {
        if options.mounts.is_empty() || options.visibility.is_none() {
            usage();
        }
        for path in &options.mounts {
            ntfs_utils::set_visibility(path, options.visibility.unwrap()).unwrap_or_else(|e| fail(e));
        }
        if program.is_none() {
            return;
        }
    }
    let program: OsString = program.unwrap_or_else(|| usage());
    if unsafe { libc::geteuid() } == 0 {
        match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
            (Ok(uid), Ok(gid)) => {
                options.run_as =
                    Some((uid.parse().unwrap_or_else(|_| usage()), gid.parse().unwrap_or_else(|_| usage())))
            }
            (Err(_), Err(_)) => {}
            _ => usage(),
        }
    }
    let result = spawn_application(&program, &arguments, &options).and_then(|mut child| child.wait());
    match result {
        Ok(status) => std::process::exit(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(1))),
        Err(error) => {
            eprintln!("ntfs-run: {error}");
            std::process::exit(125);
        }
    }
}
fn usage() -> ! {
    eprintln!("usage: ntfs-run [--show-hidden|--hide-hidden] [--mount PATH] --application PROGRAM [-- ARG ...]; or --live --mount PATH --show-hidden|--hide-hidden; or --mount-volume DEVICE TARGET; or --unmount-volume TARGET; or --automount=on|off; see --help");
    std::process::exit(125)
}

fn fail(error: std::io::Error) -> ! {
    eprintln!("ntfs-run: {error}");
    std::process::exit(125)
}
