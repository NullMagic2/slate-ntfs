<!--
Module: packaging.debian.documentation
Purpose: Explain package generation, installation and runtime requirements.
Created: 2026-09-30
Architecture: Documents the Debian builder and its DKMS installation adapters.
-->

# Slate NTFS Debian packages

Run `bash generate_packages/generate_package.sh` and select one or more
numbered Ubuntu, Linux Mint, or Debian targets. The generated `.deb` files
are for amd64. The package checks `/etc/os-release` before installation.
Build on an x86_64 Linux host with `cargo`, `rustup`, `rust-lld`, and
`dpkg-deb`. The builder downloads the musl Rust target and locked Cargo
dependencies when they are not cached.
For an Ubuntu 26.04 build using its installed native Rust target, set
`SLATE_PACKAGE_TOOL_TARGET=x86_64-unknown-linux-gnu`. These tools require the
Ubuntu 26.04 runtime libraries; other profiles retain static musl tools.
Set `SLATE_PACKAGE_VERSION` to give a snapshot a distinct Debian version.
The permissions application also requires GTK 3 development libraries at build time.
The package ships a complete offline vendor bundle (including memmap2 0.9.11
and both locked libc versions) and skips installation-time userspace compilation
on Ubuntu 26.04. The generator validates offline dependency resolution before
packaging and retains its persistent Cargo build cache.
The corrected Ubuntu package was checked for package integrity, offline
dependency resolution, C/Python loading and simulated maintainer-script behavior.
Kernel compilation and a real Ubuntu 26.04 installation were not repeated.

Install with `sudo apt install ./slate-ntfs_*.deb` using the file matching
your distribution. APT removes `ntfs-3g` because the package conflicts
with it. The package blacklists the loadable `ntfs` and `ntfs3` modules,
loads `ntfs_rs` at boot, and builds the module for kernels with installed
headers. Built-in NTFS drivers cannot be removed by a Debian package.

The command-line tools are static musl binaries so they work with older
glibc releases. DKMS uses a matching Rust source tree. Ubuntu 26.04 uses
its packaged Rust 1.93 and bundled standard-library dependencies for
offline builds. On older targets, DKMS installs pinned Rust 1.97.1 and
`rust-src` into `/var/lib/slate-ntfs/rustup` when a suitable system
toolchain is unavailable. That first DKMS build needs access to the Rust
distribution server and Cargo registry. Later kernel updates reuse the
installed toolchain and Cargo cache.

The installer updates initramfs and includes Slate's root and shutdown
hooks. With Secure Boot, the distro may require MOK enrolment before an
unsigned module can load. The package does not alter disk contents.

`mount -t ntfs`, `mount -t ntfs3`, and `mount -t ntfs-3g` route through the
provided helper to `ntfsrs`. The helper supplies a default root SID map
when the mount options do not provide one. UDisks supplies the authorized
user UID/GID; desktop requests project that user and their groups explicitly. An NTFS root needs the boot
entry's `rootfstype=ntfsrs` and matching `rootflags=sidmap=...`; packaging
does not rewrite existing bootloader entries or mounted roots.

The package provides shared udev/UDisks integration, automount policy, live
visibility controls, physical disk capacity, and installed C/Python APIs for
all nine distribution profiles. GNOME is not required. The packaged systemd
adapter starts UDisks requests in the active local user's manager; other init
systems may launch the standalone adapter in an authorized user session.
Existing fstab entries, including temporary `noauto` entries, override this
adapter and must be removed if automatic mounting should manage that volume.

Hidden NTFS attributes and internal metadata are filtered by default. Use
`sudo ntfs-run --live --mount PATH --show-hidden` to reveal them without
unmounting, or `--hide-hidden` to hide them again. Refresh the file manager.
Use `sudo ntfs-run --automount=off` to stop future automatic mounts without
unmounting existing volumes. All controls are also exposed by Rust, C and
Python. The host policy is `/etc/slate-ntfs/settings.conf` and survives upgrade.
An administrator can supply `/etc/slate-ntfs/sidmap.conf` for custom identities.

The package installs the C library/header and system Python module. The Ubuntu 26.04 package installs its prebuilt native
library directly (glibc 2.39 or newer, plus libgcc-s1). Other profiles rebuild
the library against their older target libc during installation. The offline
bundle includes the userspace dependencies as well as the Rust 1.93
standard-library dependencies. Python `get_device('/dev/sdb2').physical_size_bytes` reports the whole
hardware disk; `size_bytes` continues to report the NTFS volume. Unknown
hardware capacity is None. Legacy C v2 probe/list entry points are preserved;
new v3 entry points include an availability flag and physical capacity.

Ubuntu and Linux Mint automatic mounts use `/media/<user>/<volume-label>`.
A duplicate label gets the UUID appended. The root is configured in
`/etc/slate-ntfs/mount-root`. The adapter creates marked `noauto` fstab
entries for discovered NTFS volumes; UDisks then mounts at the same location.
Existing administrator-defined entries take precedence. Disabling automatic
mounting keeps these entries available for manual mounting and does not unmount
volumes. Other profiles keep the standard UDisks mountpoint policy.

The adapter grants the mounting user read and traversal access to their account
directory before mounting. This also upgrades a traversal-only parent ACL left
by an older package, so listing the mounted drives works from a terminal.
The hotplug mount service allows ten minutes for its request, including any
supported journal recovery and metadata validation performed by the mount helper.

The administrator-installed adapter prepares custom-root fstab entries, then
submits the UDisks mount request with the selected local user's credentials.
UDisks records that user as the mounting user, so the same user can unmount in
the file manager or with `udisksctl unmount` without providing a password.
The entry's UID/GID controls filesystem access separately; changing a saved
permission owner does not transfer UDisks unmount ownership. Other users remain
subject to the distribution's normal authorization, and busy volumes can still
refuse unmounting. Existing volumes mounted by an older root request need one
ordinary authorized unmount and a fresh mount to acquire the correct ownership.
