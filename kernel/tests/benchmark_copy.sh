#!/usr/bin/env bash
# Module: kernel.tests.benchmark_copy
# Purpose: Time cold reads and copies of one large file from a real NTFS partition, per driver.
# Created: 2026-10-05
# Architecture: The README's real-world benchmark. Each driver mounts the same partition
# read-only through its own read-only loop device and GIO copies the file to a local
# directory; benchmark_copy.py summarises the samples, also those of the VM benchmark.

set -euo pipefail
# Name the failing command rather than stopping silently.
trap 'echo "benchmark_copy.sh: line $LINENO failed: $BASH_COMMAND" >&2' ERR
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
# A decimal-comma locale would print the seconds as "5,166" and split the CSV field.
export LC_ALL=C

readonly MINIMUM_ROUNDS=3
readonly MAXIMUM_ROUNDS=99
readonly DEFAULT_ROUNDS=5
# /sys/block/DISK/stat counts reads in 512-byte units on every device.
readonly STAT_SECTOR_BYTES=512
# Bytes per dd block for the read-only pass.
readonly READ_BLOCK=1M
# Field 3 of /sys/block/DISK/stat: sectors read.
readonly STAT_SECTORS_READ_FIELD=3
readonly MOUNT_OPTIONS=ro,noatime,nosuid,nodev,noexec
# The same explicit identity map as the synthetic read benchmark.
readonly SLATE_SIDMAP='u:0:S-1-5-32-544;g:0:S-1-5-18'
readonly ENVIRONMENT=host

usage() {
    echo 'usage: sudo bash kernel/tests/benchmark_copy.sh PARTITION FILE DESTINATION NEW_RESULTS_DIRECTORY' >&2
    echo '  FILE is relative to the volume root; DESTINATION is a directory on another disk.' >&2
    echo '  SLATE_BENCH_ROUNDS (default 5), SLATE_NTFS3G (ntfs-3g binary), SLATE_NTFS3G_LIBRARY.' >&2
    exit 2
}

[[ $# -eq 4 ]] || usage
[[ $(id -u) -eq 0 ]] || { echo 'run as root' >&2; exit 1; }
partition=$1
file=$2
destination=$(realpath -- "$3")
rounds=${SLATE_BENCH_ROUNDS:-$DEFAULT_ROUNDS}
ntfs3g=${SLATE_NTFS3G:-ntfs-3g}
[[ -b $partition ]] || { echo "$partition is not a block device" >&2; exit 1; }
# A setuid ntfs-3g run by root switches user: the loader then ignores
# LD_LIBRARY_PATH, and the switched user cannot open the loop devices.
if [[ -u $(command -v -- "$ntfs3g" || echo "$ntfs3g") ]]; then
    echo "$ntfs3g is setuid; use a plain copy (cp drops the bit)" >&2
    exit 1
fi
LD_LIBRARY_PATH=${SLATE_NTFS3G_LIBRARY:-} "$ntfs3g" --version >/dev/null 2>&1 || {
    echo "cannot run $ntfs3g; set SLATE_NTFS3G_LIBRARY to its library directory" >&2
    exit 1
}
[[ $rounds =~ ^[0-9]+$ ]] && ((rounds >= MINIMUM_ROUNDS && rounds <= MAXIMUM_ROUNDS)) || {
    echo "SLATE_BENCH_ROUNDS must be an integer from $MINIMUM_ROUNDS to $MAXIMUM_ROUNDS" >&2
    exit 1
}
# Each driver needs the partition to itself: a writable mount could change it mid-run.
if findmnt --source "$partition" >/dev/null; then
    echo "$partition is mounted; unmount it (close Steam and file managers) and run again" >&2
    exit 1
fi
[[ -d $destination ]] || { echo "$destination is not a directory" >&2; exit 1; }
disk=$(lsblk -no PKNAME "$partition")
[[ -n $disk ]] || disk=$(basename "$partition")
destination_disk=$(lsblk -no PKNAME "$(findmnt -no SOURCE --target "$destination")" 2>/dev/null || true)
[[ $destination_disk != "$disk" ]] || { echo 'DESTINATION must be on another disk' >&2; exit 1; }
output=$4
mkdir -- "$output" # Refuse to overwrite an earlier run.
output=$(realpath -- "$output")
target="$destination/benchmark-copy-$$"

temporary=$(mktemp -d)
loops=()
mounted=
cleanup() {
    if [[ -n $mounted ]]; then umount "$mounted" || true; fi
    for loop in "${loops[@]}"; do losetup -d "$loop" || true; done
    rm -f -- "$target"
    rm -rf -- "$temporary"
}
trap cleanup EXIT

drivers=(ntfsrs ntfs-3g)
declare -A loop_of
for driver in "${drivers[@]}"; do
    # One read-only loop device per driver, so no driver reuses another's cached pages.
    loop=$(losetup --read-only --find --show "$partition")
    loops+=("$loop")
    loop_of[$driver]=$loop
    mkdir "$temporary/$driver"
done

mount_driver() {
    local driver=$1
    local where="$temporary/$driver"
    case $driver in
        ntfsrs) mount -t ntfsrs -o "$MOUNT_OPTIONS,sidmap=$SLATE_SIDMAP" "${loop_of[$driver]}" "$where" ;;
        ntfs-3g)
            LD_LIBRARY_PATH=${SLATE_NTFS3G_LIBRARY:-} "$ntfs3g" -o "$MOUNT_OPTIONS" "${loop_of[$driver]}" "$where"
            ;;
    esac
    mounted=$where
}

unmount_driver() {
    umount "$mounted"
    mounted=
}

# Every copy must read the file from the SSD: drop all clean pages, the loop
# devices' and the partition's included, before each timed copy.
evict_caches() {
    sync
    for loop in "${loops[@]}"; do blockdev --flushbufs "$loop"; done
    blockdev --flushbufs "$partition"
    echo 3 > /proc/sys/vm/drop_caches
}

sectors_read() {
    awk -v field="$STAT_SECTORS_READ_FIELD" '{ print $field }' "/sys/block/$disk/stat"
}

mount_driver "${drivers[0]}"
source="$temporary/${drivers[0]}/$file"
[[ -f $source ]] || { echo "$file not found on $partition" >&2; exit 1; }
bytes=$(stat -c %s -- "$source")
reference=$(sha256sum -- "$source" | cut -d ' ' -f1)
unmount_driver

{
    uname -a
    echo "slate-ntfs module: $(cat /sys/module/slate_ntfs/version) srcversion $(cat /sys/module/slate_ntfs/srcversion)"
    LD_LIBRARY_PATH=${SLATE_NTFS3G_LIBRARY:-} "$ntfs3g" --version 2>&1 | head -1
    lsblk -dno MODEL,TRAN,SIZE "/dev/$disk"
    echo "destination: $(findmnt -no SOURCE,FSTYPE --target "$destination")"
    echo "file: $file ($bytes bytes, sha256 $reference)"
    echo "rounds: $rounds; mount options: $MOUNT_OPTIONS"
    echo "read: dd to /dev/null in $READ_BLOCK blocks; copy: gio copy, then fsync of the copy"
} > "$output/environment.txt"
echo 'environment,round,driver,operation,seconds,bytes,disk_read_bytes,verified' > "$output/samples.csv"

# One cold measurement. A read alone measures the driver; a copy also includes
# the destination's writes and its final flush, as a file manager would do.
measure() {
    local driver=$1 operation=$2 before after start finish digest verified seconds read_bytes
    mount_driver "$driver"
    evict_caches
    before=$(sectors_read)
    start=$(date +%s%N)
    if [[ $operation == read ]]; then
        dd if="$temporary/$driver/$file" of=/dev/null bs=$READ_BLOCK status=none
    else
        gio copy -- "$temporary/$driver/$file" "$target"
        sync -- "$target"
    fi
    finish=$(date +%s%N)
    after=$(sectors_read)
    unmount_driver
    verified=-
    if [[ $operation == copy ]]; then
        # Checked outside the timed section.
        digest=$(sha256sum -- "$target" | cut -d ' ' -f1)
        verified=$([[ $digest == "$reference" ]] && echo yes || echo no)
        rm -f -- "$target"
        sync
    fi
    seconds=$(awk -v a="$start" -v b="$finish" 'BEGIN { printf "%.3f", (b - a) / 1e9 }')
    read_bytes=$(( (after - before) * STAT_SECTOR_BYTES ))
    echo "$ENVIRONMENT,$round,$driver,$operation,$seconds,$bytes,$read_bytes,$verified" | tee -a "$output/samples.csv"
    [[ $verified != no ]] || { echo "copy through $driver does not match the source" >&2; exit 1; }
}

for ((round = 1; round <= rounds; round++)); do
    order=("${drivers[@]}")
    # Alternate the order between rounds, so neither driver always runs first.
    if ((round % 2 == 0)); then
        order=()
        for ((i = ${#drivers[@]} - 1; i >= 0; i--)); do order+=("${drivers[i]}"); done
    fi
    for driver in "${order[@]}"; do
        measure "$driver" read
        measure "$driver" copy
    done
done

cleanup
trap - EXIT
python3 kernel/tests/benchmark_copy.py "$output/samples.csv" | tee "$output/summary.md"
echo "Results in $output; remount the drive from your file manager."
