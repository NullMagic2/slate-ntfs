#!/usr/bin/env bash
# Module: examples.run_wsl_comparison
# Purpose: Compare core and ntfs-3g workloads using disposable images.
# Created: 2026-10-02
# Architecture: Creates benchmark fixtures and mounts; delegates measurements to the Rust and
# Python examples.

# Run as root inside WSL. Uses only newly formatted disposable image files.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
writer=${SLATE_WRITER_BENCH:-/tmp/slate-ntfs-target/release/examples/benchmark_writer}
mount_dir=$(mktemp -d /tmp/slate-ntfs3g-mount.XXXXXX)
image_dir=$(mktemp -d /tmp/slate-benchmark.XXXXXX)
rounds=${1:-3}

cleanup() {
    if mountpoint -q "$mount_dir"; then umount "$mount_dir"; fi
    rmdir "$mount_dir"
    rm -rf -- "$image_dir"
}
trap cleanup EXIT

for ((round = 1; round <= rounds; round++)); do
    source_image="$image_dir/source.img"
    core_image="$image_dir/core.img"
    fuse_image="$image_dir/ntfs3g.img"
    truncate -s 128M "$source_image"
    mkfs.ntfs -F -Q -c 4096 "$source_image" >/dev/null 2>&1
    cp "$source_image" "$core_image"
    cp "$source_image" "$fuse_image"
    printf 'ROUND %d slate-core\n' "$round"
    "$writer" "$core_image"
    ntfs-3g "$fuse_image" "$mount_dir"
    printf 'ROUND %d ntfs-3g\n' "$round"
    python3 "$repo/examples/benchmark_ntfs3g.py" "$mount_dir"
    umount "$mount_dir"
done
