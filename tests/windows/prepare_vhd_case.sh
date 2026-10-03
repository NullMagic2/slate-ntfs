#!/usr/bin/env bash
# Module: tests.windows.prepare_vhd_case
# Purpose: Stage disposable VHD cases for Windows repair interoperability.
# Created: 2026-10-02
# Architecture: Creates raw test images and invokes the VHD wrapper; the Windows guest verifier
# owns native checks.

set -euo pipefail
if [[ $# -ne 1 ]]; then
    echo 'usage: prepare_vhd_case.sh NEW_OUTPUT_DIRECTORY' >&2
    exit 16
fi
output=$1
if [[ -e "$output" ]]; then
    echo 'error: output directory must not exist' >&2
    exit 16
fi
mkdir -p -- "$output"
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source_image="$output/source.img"
candidate_image="$output/candidate.img"
payload="$output/payload.bin"
truncate -s 64M "$source_image"
mkfs.ntfs -F -Q "$source_image" >/dev/null 2>&1
python3 - "$payload" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(bytes(i % 256 for i in range(16384)))
PY
ntfscp -f "$source_image" "$payload" /write-target.bin
"$project_root/target/release/ntfs-write-lab" "$source_image" "$candidate_image" \
    write-target.bin 4090 fafbfcfdfeff00010203040506070809 \
    102030405060708090a0b0c0d0e0f000
python3 "$project_root/tests/windows/wrap_ntfs_image_vhd.py" \
    "$candidate_image" "$output/candidate.vhd"
echo "Read-only Windows chkdsk fixture: $output/candidate.vhd"
