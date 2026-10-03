#!/usr/bin/env bash
# Module: kernel.tests.benchmark_reads
# Purpose: Disposable loop image only.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

# Disposable loop image only. Warm-cache comparisons, with byte verification.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ $(id -u) -eq 0 ]]
[[ $(modinfo -F vermagic kernel/ntfs_rs.ko | cut -d ' ' -f 1) == "$(uname -r)" ]]
baseline=${SLATE_BASELINE_MODULE:-}
rounds=${SLATE_BENCH_ROUNDS:-3}
[[ $rounds =~ ^[1-9][0-9]?$ && $rounds -ge 3 ]] || {
    echo 'SLATE_BENCH_ROUNDS must be an integer from 3 to 99' >&2
    exit 1
}
if [[ -n $baseline ]]; then
    [[ $(modinfo -F vermagic "$baseline" | cut -d ' ' -f 1) == "$(uname -r)" ]]
fi
output=${1:?usage: bash kernel/tests/benchmark_reads.sh NEW_RESULTS_DIRECTORY}
mkdir -- "$output" # Refuse to overwrite an earlier run.
output=$(realpath "$output")
temporary=$(mktemp -d)
loop_device=
mounted=0
loaded=0
cleanup() {
    if [[ $mounted == 1 ]]; then umount "$temporary/mount"; fi
    if [[ $loaded == 1 ]]; then rmmod ntfs_rs; fi
    if [[ -n $loop_device ]]; then losetup -d "$loop_device"; fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
mkdir "$temporary/mount"
truncate -s 128M "$temporary/image"
mkfs.ntfs -F -Q "$temporary/image" >"$output/format.log" 2>&1
loop_device=$(losetup --find --show "$temporary/image")
ntfs-3g "$loop_device" "$temporary/mount"
mounted=1
python3 kernel/tests/benchmark_reads.py prepare "$temporary/mount"
umount "$temporary/mount"
mounted=0
sha256sum "$temporary/image" | cut -d ' ' -f1 > "$output/image.sha256"
{
    uname -a
    ntfs-3g --version 2>&1
    lscpu
    sha256sum kernel/ntfs_rs.ko kernel/vfs_bridge.c kernel/ntfs_parser.rs
    if [[ -n $baseline ]]; then sha256sum "$baseline"; fi
    echo "Mount rounds per driver: $rounds"
    echo 'Warm cache; same 128 MiB loop image on WSL ext4; no global cache flush.'
    echo 'ntfs-3g: ro,permissions; slate: ro,explicit root/SYSTEM SID mapping.'
    echo 'NTFS-3g and slate implement different permission semantics; see report.'
} > "$output/environment.txt"
for ((round=1; round<=rounds; round++)); do
    drivers=(ntfsrs ntfs-3g)
    ((round % 2)) || drivers=(ntfs-3g ntfsrs)
    if [[ -n $baseline ]]; then
        case $(((round - 1) % 3 + 1)) in
            1) drivers=(baseline ntfsrs ntfs-3g);;
            2) drivers=(ntfs-3g baseline ntfsrs);;
            3) drivers=(ntfsrs ntfs-3g baseline);;
        esac
    fi
    for driver in "${drivers[@]}"; do
        if [[ $driver != ntfs-3g ]]; then
            module=kernel/ntfs_rs.ko
            [[ $driver != baseline ]] || module=$baseline
            insmod "$module"
            loaded=1
            mount -t ntfsrs -o 'ro,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18' "$loop_device" "$temporary/mount"
        else
            ntfs-3g -o ro,permissions "$loop_device" "$temporary/mount"
        fi
        mounted=1
        python3 kernel/tests/benchmark_reads.py "$driver" "$temporary/mount" "$round" | tee -a "$output/samples.jsonl"
        umount "$temporary/mount"
        mounted=0
        if [[ $loaded == 1 ]]; then rmmod ntfs_rs; loaded=0; fi
    done
done
[[ $(sha256sum "$temporary/image" | cut -d ' ' -f1) == "$(cat "$output/image.sha256")" ]]
cleanup
trap - EXIT
echo 'Benchmark completed; bytes verified and disposable mounts cleaned up.'
