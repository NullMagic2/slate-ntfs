#!/bin/sh
# Module: ntfs_utils.tests.test_fresh_mount
# Purpose: Creates and formats only a new disposable image.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

# Creates and formats only a new disposable image. Requires an installed driver.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root on the test machine.' >&2; exit 1; }
for command in ntfs-format ntfs-run losetup modprobe findmnt python3; do
    command -v "$command" >/dev/null || { echo "Missing $command" >&2; exit 1; }
done
work=$(mktemp -d /var/tmp/slate-fresh-mount.XXXXXXXX)
image=$work/test.img
target=$work/mounted
loop=
cleanup() {
    if findmnt -rn --mountpoint "$target" >/dev/null 2>&1; then
        if ! ntfs-run --unmount-volume "$target"; then
            echo "Volume is busy; retaining $work and $loop" >&2
            return
        fi
    fi
    if [ -n "$loop" ] && ! losetup --detach "$loop"; then
        echo "Could not detach $loop; retaining $work" >&2
        return
    fi
    rm -f "$image"
    rmdir "$target" "$work" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir "$target"
truncate -s 128M "$image"
ntfs-format "$image" --yes --label SlateTest --sector-size 512 --cluster-size 4096
modprobe ntfs_rs
loop=$(losetup --find --show "$image")
ntfs-run --mount-volume "$loop" "$target" --uid 0 --gid 0
[ "$(findmnt -rn --mountpoint "$target" -o FSTYPE)" = ntfsrs ]
python3 - "$target" <<'PY'
import os, sys
from pathlib import Path
root = Path(sys.argv[1])
first, second = root/'created.bin', root/'renamed.bin'
data = bytes(range(256)) * 256
with first.open('wb') as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
assert first.read_bytes() == data
first.rename(second)
with second.open('r+b') as stream:
    stream.truncate(5000)
    stream.flush()
    os.fsync(stream.fileno())
assert second.read_bytes() == data[:5000]
PY
ntfs-run --unmount-volume "$target"
ntfs-run --mount-volume "$loop" "$target" --uid 0 --gid 0 --read-only
python3 - "$target" <<'PY'
import errno, sys
from pathlib import Path
root = Path(sys.argv[1])
assert (root/'renamed.bin').read_bytes() == (bytes(range(256)) * 256)[:5000]
try:
    (root/'must-not-write').write_bytes(b'fail')
except OSError as error:
    assert error.errno == errno.EROFS, error
else:
    raise AssertionError('read-only mount accepted a write')
PY
ntfs-run --unmount-volume "$target"
echo 'PASS: fresh NTFS volume mount, write/fsync, rename, truncate, remount, read-only and unmount'
