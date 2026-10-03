#!/usr/bin/env bash
# Module: kernel.tests.test_ubuntu_root_boot
# Purpose: Verify ubuntu root boot behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail

if [[ $# -ne 4 || $EUID -ne 0 ]]; then
    echo "usage: sudo $0 KERNEL_BZIMAGE INITRAMFS UBUNTU_ROOT_TREE NTFS_IMAGE" >&2
    exit 2
fi
kernel=$1
initrd=$2
root_tree=$3
image=$4
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
for tool in qemu-system-x86_64 mkfs.ntfs ntfs-3g ntfsinfo losetup rsync timeout; do
    command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 2; }
done
[[ -f $kernel && -f $initrd && -x $root_tree/sbin/init ]] || {
    echo 'Missing kernel, initramfs, or Ubuntu /sbin/init' >&2
    exit 2
}

if [[ ! -e $image ]]; then
    mkdir -p "$(dirname -- "$image")"
    truncate -s 768M "$image"
    mkfs.ntfs -F -Q -L SLATEUBUNTU -s 512 -c 4096 "$image" >/dev/null
    mountpoint=$(mktemp -d)
    loop=$(losetup --find --show "$image")
    cleanup() {
        umount "$mountpoint" 2>/dev/null || true
        losetup -d "$loop" 2>/dev/null || true
        rmdir "$mountpoint" 2>/dev/null || true
    }
    trap cleanup EXIT
    ntfs-3g -o permissions "$loop" "$mountpoint"
    rsync -aH --numeric-ids \
        --exclude='/dev/*' --exclude='/proc/*' --exclude='/sys/*' --exclude='/run/*' \
        "$root_tree/" "$mountpoint/"
    mkdir -p "$mountpoint/etc/systemd/system/multi-user.target.wants"
    cat > "$mountpoint/etc/systemd/system/slate-root-proof.service" <<'EOF'
[Unit]
Description=Verify Ubuntu boot and writable NTFS root
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo SLATE_UBUNTU_INIT_REACHED > /dev/console; mount -o remount,rw / && echo ubuntu-boot-ok > /boot-proof.txt && sync && echo SLATE_UBUNTU_ROOT_WRITE_OK > /dev/console; systemctl poweroff'

[Install]
WantedBy=multi-user.target
EOF
    ln -s ../slate-root-proof.service \
        "$mountpoint/etc/systemd/system/multi-user.target.wants/slate-root-proof.service"
    install -D -m 0755 "$repo/boot/systemd/system-shutdown/ntfsrs" \
        "$mountpoint/lib/systemd/system-shutdown/ntfsrs"
    printf 'slate-ntfs-ubuntu\n' > "$mountpoint/etc/hostname"
    sync
    cleanup
    trap - EXIT
    echo "Created retained Ubuntu image: $image"
else
    echo "Reusing retained Ubuntu image: $image"
fi

if [[ -n $(losetup -j "$image") ]]; then
    echo 'Image is attached to a loop device; refusing concurrent boot.' >&2
    exit 2
fi
for pass in 1 2; do
    log="$image.boot-$pass.log"
    timeout 120 qemu-system-x86_64 \
        -machine pc,accel=kvm:tcg -cpu max -m 1024 -smp 2 \
        -display none -serial stdio -monitor none -no-reboot \
        -kernel "$kernel" -initrd "$initrd" \
        -append 'console=ttyS0,115200 loglevel=5 panic=-1 noresume root=/dev/sda rootfstype=ntfsrs rootflags=compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18 ro' \
        -drive "file=$image,if=ide,format=raw,cache=none" > "$log" 2>&1 || {
            tail -100 "$log"
            exit 1
        }
    for marker in SLATE_UBUNTU_INIT_REACHED SLATE_UBUNTU_ROOT_WRITE_OK; do
        grep -q "$marker" "$log" || { tail -100 "$log"; exit 1; }
    done
    ntfsinfo -m "$image" | grep 'Volume Flags: 0x0000' >/dev/null || {
        echo "Volume dirty after Ubuntu boot $pass" >&2
        exit 1
    }
    echo "Ubuntu boot $pass: systemd started, wrote root, clean shutdown"
done
