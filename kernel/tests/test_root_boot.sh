#!/usr/bin/env bash
# Module: kernel.tests.test_root_boot
# Purpose: Verify root boot behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail

if [[ $# -ne 3 || $EUID -ne 0 ]]; then
    echo "usage: sudo $0 KERNEL_BZIMAGE INITRAMFS NTFS_IMAGE" >&2
    exit 2
fi
kernel=$1
initrd=$2
image=$3
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
for tool in qemu-system-x86_64 mkfs.ntfs ntfs-3g ntfsinfo losetup busybox timeout; do
    command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
[[ -f $kernel && -f $initrd ]] || { echo 'Missing kernel or initramfs' >&2; exit 2; }

if [[ ! -e $image ]]; then
    mkdir -p "$(dirname -- "$image")"
    truncate -s 256M "$image"
    mkfs.ntfs -F -Q -L SLATEROOT -s 512 -c 4096 "$image" >/dev/null
    mountpoint=$(mktemp -d)
    loop=$(losetup --find --show "$image")
    cleanup() {
        umount "$mountpoint" 2>/dev/null || true
        losetup -d "$loop" 2>/dev/null || true
        rmdir "$mountpoint" 2>/dev/null || true
    }
    trap cleanup EXIT
    ntfs-3g -o permissions "$loop" "$mountpoint"
    mkdir -p "$mountpoint"/{bin,sbin,dev,proc,sys,run,tmp}
    cp "$(command -v busybox)" "$mountpoint/bin/busybox"
    cp "$repo/kernel/tests/root_boot_init" "$mountpoint/sbin/init"
    chmod 755 "$mountpoint/bin/busybox" "$mountpoint/sbin/init"
    sync
    cleanup
    trap - EXIT
    echo "Created retained image: $image"
else
    echo "Reusing retained image: $image"
fi

if [[ -n $(losetup -j "$image") ]]; then
    echo 'Image is attached to a loop device; refusing to boot it concurrently.' >&2
    exit 2
fi
for pass in 1 2; do
    log="$image.boot-$pass.log"
    timeout 90 qemu-system-x86_64 \
        -machine pc,accel=kvm:tcg -cpu max -m 1024 -smp 2 \
        -display none -serial stdio -monitor none -no-reboot \
        -kernel "$kernel" -initrd "$initrd" \
        -append 'console=ttyS0,115200 loglevel=5 panic=-1 noresume root=/dev/sda rootfstype=ntfsrs rootflags=compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18 ro' \
        -drive "file=$image,if=ide,format=raw,cache=none" > "$log" 2>&1 || {
            tail -80 "$log"
            exit 1
        }
    for marker in SLATE_NTFS_ROOT_INIT_REACHED SLATE_NTFS_ROOT_WRITE_OK SLATE_NTFS_ROOT_CLEAN_REMOUNT_OK; do
        grep -q "$marker" "$log" || { tail -80 "$log"; exit 1; }
    done
    ntfsinfo -m "$image" | grep 'Volume Flags: 0x0000' >/dev/null || {
        echo "Volume dirty after boot $pass" >&2
        exit 1
    }
    echo "Boot $pass: reached NTFS init, wrote root, clean shutdown"
done
