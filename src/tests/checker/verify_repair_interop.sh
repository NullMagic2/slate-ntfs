#!/usr/bin/env bash
# Module: src.tests.checker.verify_repair_interop
# Purpose: Explicit, read-only ntfs-3g matrix for images staged by test_repair_expansion.py.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

# Explicit, read-only ntfs-3g matrix for images staged by test_repair_expansion.py.
set -euo pipefail
stage=$(realpath -- "${1:?usage: verify_repair_interop.sh STAGE_DIR}")
[[ $EUID == 0 ]] || { echo 'ntfs-3g mount requires root' >&2; exit 2; }
command -v ntfs-3g >/dev/null || { echo 'ntfs-3g is required' >&2; exit 2; }
cd -- "$stage"
sha256sum -c SHA256SUMS
mountpoint=$(mktemp -d -t slate-interop-XXXXXXXX)
cleanup() {
    if mountpoint -q -- "$mountpoint"; then umount -- "$mountpoint"; fi
    rmdir -- "$mountpoint"
}
trap cleanup EXIT
for image in *.img; do
    [[ -f $image ]] || continue
    mount -t ntfs-3g -o ro,loop,norecover -- "$stage/$image" "$mountpoint"
    stat -- "$mountpoint" >/dev/null
    find "$mountpoint" -maxdepth 1 -mindepth 1 -print >/dev/null
    umount -- "$mountpoint"
    echo "PASS ntfs-3g read-only mount: $image"
done
sha256sum -c SHA256SUMS
