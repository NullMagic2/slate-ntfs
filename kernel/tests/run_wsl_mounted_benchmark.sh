#!/usr/bin/env bash
# Module: kernel.tests.run_wsl_mounted_benchmark
# Purpose: Run as root in WSL with a module built for the running kernel.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

# Run as root in WSL with a module built for the running kernel.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
module=${SLATE_MODULE:-$repo/kernel/ntfs_rs.ko}
rounds=${1:-3}
temporary=$(mktemp -d /var/tmp/slate-mounted-bench.XXXXXX)
slate_mount="$temporary/slate"
ntfs3g_mount="$temporary/ntfs3g"
loop_device=
loaded_here=false
mkdir "$slate_mount" "$ntfs3g_mount"
cleanup() {
    if mountpoint -q "$ntfs3g_mount"; then umount "$ntfs3g_mount"; fi
    if mountpoint -q "$slate_mount"; then umount "$slate_mount"; fi
    if [[ -n "$loop_device" ]]; then losetup -d "$loop_device"; fi
    if "$loaded_here"; then rmmod ntfs_rs; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT

if ! lsmod | grep -q '^ntfs_rs '; then
    insmod "$module"
    loaded_here=true
fi
truncate -s 128M "$temporary/source.img"
mkfs.ntfs -F -Q -c 4096 "$temporary/source.img" >/dev/null 2>&1
cp "$temporary/source.img" "$temporary/slate.img"
cp "$temporary/source.img" "$temporary/ntfs3g.img"
loop_device=$(losetup --find --show "$temporary/slate.img")
mount -t ntfsrs -o 'rw,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18' \
    "$loop_device" "$slate_mount"
ntfs-3g "$temporary/ntfs3g.img" "$ntfs3g_mount"
python3 "$repo/kernel/tests/benchmark_writes.py" \
    "$slate_mount" "$ntfs3g_mount" --rounds "$rounds"
