#!/usr/bin/env bash
# Module: boot.install_initramfs
# Purpose: Install the kernel module and initramfs integration.
# Created: 2026-10-02
# Architecture: Connects the built kernel adapter to the host boot hooks through depmod and
# initramfs-tools.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo 'Run as root to install the kernel module and initramfs hooks.' >&2
    exit 1
fi
if ! command -v update-initramfs >/dev/null || ! command -v depmod >/dev/null; then
    echo 'Ubuntu initramfs-tools and kmod are required.' >&2
    exit 1
fi

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version=${1:-$(uname -r)}
module="$repo/kernel/slate-ntfs.ko"
if [[ ! -f $module ]]; then
    echo "Build the module before installing: $module" >&2
    exit 1
fi
if [[ $(modinfo -F vermagic "$module" | cut -d' ' -f1) != "$version" ]]; then
    echo "Module was not built for Linux $version" >&2
    exit 1
fi
if [[ ! -d /lib/modules/$version ]]; then
    echo "No module directory for Linux $version" >&2
    exit 1
fi

install -D -m 0644 "$module" "/lib/modules/$version/updates/slate-ntfs.ko"
# Earlier releases installed the module as ntfs_rs; both register ntfsrs.
rm -f -- "/lib/modules/$version/updates/ntfs_rs.ko"
install -D -m 0755 "$repo/boot/initramfs-tools/hooks/ntfsrs" \
    /etc/initramfs-tools/hooks/ntfsrs
install -D -m 0755 "$repo/boot/initramfs-tools/scripts/local-top/ntfsrs" \
    /etc/initramfs-tools/scripts/local-top/ntfsrs
install -D -m 0755 "$repo/boot/systemd/system-shutdown/ntfsrs" \
    /lib/systemd/system-shutdown/ntfsrs
depmod -a "$version"
if [[ -e /boot/initrd.img-$version ]]; then
    update-initramfs -u -k "$version"
else
    update-initramfs -c -k "$version"
fi

echo "Installed Slate NTFS root support for Linux $version."
echo 'Set rootfstype=ntfsrs and rootflags=compatibility=linux,sidmap=YOUR_MAP in the boot entry.'
