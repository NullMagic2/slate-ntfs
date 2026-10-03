#!/usr/bin/env bash
# Module: kernel.tests.test_wsl_module
# Purpose: Verify wsl module behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
for tool in insmod rmmod modinfo mkfs.ntfs ntfscp ntfs-3g losetup python3 truncate; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required" >&2
        exit 1
    }
done
[[ $(id -u) -eq 0 ]] || {
    echo 'error: run the module test as root' >&2
    exit 1
}
kernel=$(uname -r)
module_kernel=$(modinfo -F vermagic kernel/ntfs_rs.ko | cut -d ' ' -f 1)
[[ "$kernel" == "$module_kernel" ]] || {
    echo "error: module targets $module_kernel but WSL runs $kernel" >&2
    exit 1
}
cluster=${1:-4096}
temporary=$(mktemp -d)
loop_device=
mounted=0
loaded=0
fuse_mounted=0
cleanup() {
    if [[ $mounted -eq 1 ]]; then umount "$temporary/mount" || true; fi
    if [[ $loaded -eq 1 ]]; then rmmod ntfs_rs || true; fi
    if [[ $fuse_mounted -eq 1 ]]; then umount "$temporary/prep" || true; fi
    if [[ -n "$loop_device" ]]; then losetup -d "$loop_device" || true; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
truncate -s "${SLATE_TEST_IMAGE_BYTES:-64M}" "$temporary/test.img"
mkfs.ntfs -F -Q -c "$cluster" "$temporary/test.img" >/dev/null 2>&1
printf 'hello from ntfs-rs\n' > "$temporary/hello"
python3 - "$temporary/large" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(bytes(range(256)) * 32)
pathlib.Path(sys.argv[1] + '.tail').write_bytes(bytes(range(256)) * 32 + b'partial page tail')
PY
ntfscp -f "$temporary/test.img" "$temporary/hello" /hello.txt
ntfscp -f "$temporary/test.img" "$temporary/large" /large.bin
ntfscp -f "$temporary/test.img" "$temporary/large.tail" /tail.bin
for n in {0..89}; do
    printf -v name 'f%02d.txt' "$n"
    ntfscp -f "$temporary/test.img" "$temporary/hello" "/$name" >/dev/null
done
mkdir "$temporary/prep"
ntfs-3g -o loop "$temporary/test.img" "$temporary/prep"
fuse_mounted=1
mkdir "$temporary/prep/sub"
cp "$temporary/hello" "$temporary/prep/sub/child.txt"
umount "$temporary/prep"
fuse_mounted=0
mkdir "$temporary/mount"
loop_device=$(losetup --find --show "$temporary/test.img")
insmod kernel/ntfs_rs.ko
loaded=1
mount -t ntfsrs -o 'ro,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18' "$loop_device" "$temporary/mount"
mounted=1
python3 - "$temporary/mount" <<'PY'
import os, sys
names = os.listdir(sys.argv[1])
print(f"directory entries: {len(names)}")
assert all(f"f{n:02d}.txt" in names for n in range(90))
assert "sub" in names
PY
cat "$temporary/mount/hello.txt"
cmp "$temporary/large" "$temporary/mount/large.bin"
cat "$temporary/mount/f89.txt"
cat "$temporary/mount/sub/child.txt"
python3 kernel/tests/kernel_cached_reads.py "$temporary/mount"
if touch "$temporary/mount/denied" 2>/dev/null; then
    echo 'error: write unexpectedly succeeded' >&2
    exit 1
fi
if mount -o remount,rw "$temporary/mount" 2>/dev/null; then
    echo 'error: read/write remount unexpectedly succeeded' >&2
    exit 1
fi
echo "read-only VFS mount trial passed (${cluster}-byte clusters)"
