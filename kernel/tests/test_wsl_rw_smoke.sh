#!/usr/bin/env bash
# Module: kernel.tests.test_wsl_rw_smoke
# Purpose: Run as root in WSL after loading slate_ntfs.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

# Run as root in WSL after loading slate_ntfs. Uses one disposable image.
set -euo pipefail

temporary=$(mktemp -d /var/tmp/slate-wsl-rw.XXXXXX)
image="$temporary/volume.img"
mount_dir="$temporary/mount"
loop_device=
mkdir "$mount_dir"
cleanup() {
    if mountpoint -q "$mount_dir"; then umount "$mount_dir"; fi
    if [[ -n "$loop_device" ]]; then losetup -d "$loop_device"; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT

truncate -s 128M "$image"
mkfs.ntfs -F -Q -c 4096 "$image" >/dev/null 2>&1
loop_device=$(losetup --find --show "$image")
mapping='sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18'

mount -t ntfsrs -o "ro,$mapping" "$loop_device" "$mount_dir"
ls "$mount_dir" >/dev/null
umount "$mount_dir"

mount -t ntfsrs -o "rw,$mapping" "$loop_device" "$mount_dir"
python3 - "$mount_dir" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1]) / "smoke.bin"
with path.open("w+b", buffering=0) as file:
    file.write(b"slate-wsl-smoke" * 256)
    os.fsync(file.fileno())
    file.seek(0)
    assert file.read() == b"slate-wsl-smoke" * 256
assert path.stat().st_size == 3840
assert path.read_bytes() == b"slate-wsl-smoke" * 256
PY
umount "$mount_dir"

ntfs-3g "$loop_device" "$mount_dir"
python3 - "$mount_dir" <<'PY'
import pathlib
import sys
assert (pathlib.Path(sys.argv[1]) / "smoke.bin").read_bytes() == b"slate-wsl-smoke" * 256
PY
echo 'WSL mounted read/write smoke passed'
