#!/usr/bin/env bash
# Module: kernel.tests.test_image_reads
# Purpose: Verify image reads behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
for tool in cargo mkfs.ntfs ntfscp python3 truncate grep; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool is required for the WSL image smoke test" >&2
        exit 1
    fi
done

image=$(mktemp --suffix=.img)
small=$(mktemp)
large=$(mktemp)
trap 'rm -f -- "$image" "$small" "$large"' EXIT

truncate -s 64M "$image"
mkfs.ntfs -F -Q -L NTFS_RS_TEST "$image" >/dev/null 2>&1
printf 'hello from ntfs-rs\n' > "$small"
python3 -c 'import pathlib, sys; pathlib.Path(sys.argv[1]).write_bytes(bytes(range(256)) * 32)' "$large"
ntfscp -f "$image" "$small" /hello.txt
ntfscp -f "$image" "$large" /large.bin

NTFS_RS_TEST_IMAGE="$image" cargo test --test kernel_probe --locked
cargo build --release --locked
small_result=$(./target/release/ntfs-inspect "$image" hello.txt)
large_result=$(./target/release/ntfs-inspect "$image" large.bin)
grep -Fq 'root file hello.txt: 19 bytes; first 19 bytes: 68656c6c6f2066726f6d206e7466732d72730a' <<< "$small_result"
grep -Fq 'root file large.bin: 8192 bytes; first 64 bytes: 000102030405060708090a0b0c0d0e0f' <<< "$large_result"
baseline=$(sed -n 's/^root directory: \([0-9]*\) reachable index entries$/\1/p' <<< "$large_result")
if [[ -z "$baseline" ]]; then
    echo 'error: missing root directory count' >&2
    exit 1
fi
for n in {0..89}; do
    printf -v name 'f%02d.txt' "$n"
    ntfscp -f "$image" "$small" "/$name" >/dev/null
done
NTFS_RS_TEST_IMAGE="$image" cargo test --test kernel_probe --locked
tree_result=$(./target/release/ntfs-inspect "$image" f89.txt)
tree_count=$(sed -n 's/^root directory: \([0-9]*\) reachable index entries$/\1/p' <<< "$tree_result")
if [[ -z "$tree_count" || "$tree_count" -ne $((baseline + 90)) ]]; then
    echo 'error: multi-block root index traversal omitted entries' >&2
    exit 1
fi
grep -Fq 'root file f89.txt: 19 bytes; first 19 bytes: 68656c6c6f2066726f6d206e7466732d72730a' <<< "$tree_result"
./target/release/ntfs-chkdsk --check "$image"
for cluster in 512 8192; do
    alternate=$(mktemp --suffix=.img)
    trap 'rm -f -- "$image" "$small" "$large" "${alternate:-}"' EXIT
    truncate -s 64M "$alternate"
    mkfs.ntfs -F -Q -c "$cluster" "$alternate" >/dev/null 2>&1
    before=$(./target/release/ntfs-inspect "$alternate")
    before_count=$(sed -n 's/^root directory: \([0-9]*\) reachable index entries$/\1/p' <<< "$before")
    for n in {0..89}; do
        printf -v name 'f%02d.txt' "$n"
        ntfscp -f "$alternate" "$small" "/$name" >/dev/null
    done
    after=$(./target/release/ntfs-inspect "$alternate" f89.txt)
    after_count=$(sed -n 's/^root directory: \([0-9]*\) reachable index entries$/\1/p' <<< "$after")
    if [[ -z "$before_count" || -z "$after_count" || "$after_count" -ne $((before_count + 90)) ]]; then
        echo "error: root index traversal failed with ${cluster}-byte clusters" >&2
        exit 1
    fi
    grep -Fq 'root file f89.txt: 19 bytes; first 19 bytes: 68656c6c6f2066726f6d206e7466732d72730a' <<< "$after"
    ./target/release/ntfs-chkdsk --check "$alternate"
    rm -f -- "$alternate"
    alternate=
done
echo 'WSL NTFS image smoke test passed (resident/nonresident reads and three index geometries).'
