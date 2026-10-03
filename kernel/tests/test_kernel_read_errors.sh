#!/usr/bin/env bash
# Module: kernel.tests.test_kernel_read_errors
# Purpose: Real block I/O failure and retry on a disposable device-mapper target only.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

# Real block I/O failure and retry on a disposable device-mapper target only.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ $(id -u) -eq 0 ]]
[[ $(modinfo -F vermagic kernel/ntfs_rs.ko | cut -d ' ' -f 1) == "$(uname -r)" ]]
command -v dmsetup >/dev/null
temporary=$(mktemp -d)
mapping=slate-read-errors-$$
loop_device=
loaded=0
mounted=0
mapped=0
cleanup() {
    if [[ $mapped == 1 ]]; then
        dmsetup resume "$mapping" 2>/dev/null || true
    fi
    if [[ $mounted == 1 ]]; then umount "$temporary/mount"; fi
    if [[ $loaded == 1 ]]; then rmmod ntfs_rs; fi
    if [[ $mapped == 1 ]]; then dmsetup remove "$mapping"; fi
    if [[ -n $loop_device ]]; then losetup -d "$loop_device"; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
mkdir "$temporary/mount"
truncate -s 128M "$temporary/image"
mkfs.ntfs -F -Q "$temporary/image" >/dev/null 2>&1
loop_device=$(losetup --find --show "$temporary/image")
ntfs-3g "$loop_device" "$temporary/mount"
mounted=1
python3 kernel/tests/benchmark_reads.py prepare "$temporary/mount"
umount "$temporary/mount"
mounted=0
before=$(sha256sum "$temporary/image" | cut -d ' ' -f1)
sectors=$(blockdev --getsz "$loop_device")
dmsetup create "$mapping" --table "0 $sectors linear $loop_device 0"
mapped=1
insmod kernel/ntfs_rs.ko
loaded=1
mount -t ntfsrs -o 'ro,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18' "/dev/mapper/$mapping" "$temporary/mount"
mounted=1
python3 - "$temporary/mount/large.bin" "$mapping" "$sectors" "$loop_device" <<'PY'
import errno, os, subprocess, sys
path, mapping, sectors, loop = sys.argv[1:]
fd = os.open(path, os.O_RDONLY)  # Resolve metadata before fault injection.
def table(value):
    subprocess.run(['dmsetup', 'suspend', mapping], check=True)
    try:
        subprocess.run(['dmsetup', 'reload', mapping, '--table', value], check=True)
    finally:
        subprocess.run(['dmsetup', 'resume', mapping], check=True)
try:
    table(f'0 {sectors} error')
    for _ in range(2):
        try:
            os.pread(fd, 65536, 0)
        except OSError as error:
            assert error.errno == errno.EIO, error
        else:
            raise AssertionError('failed block read returned data')
finally:
    table(f'0 {sectors} linear {loop} 0')
try:
    assert os.pread(fd, 65536, 0) == bytes(range(256)) * 256
    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    assert os.pread(fd, 65536, 0) == bytes(range(256)) * 256
finally:
    os.close(fd)
PY
[[ $(sha256sum "$temporary/image" | cut -d ' ' -f1) == "$before" ]]
cleanup
trap - EXIT
echo 'Injected block errors returned EIO twice; restored reads and cache refill passed.'
