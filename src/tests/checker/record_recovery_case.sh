#!/usr/bin/env bash
# Module: src.tests.checker.record_recovery_case
# Purpose: Verify record recovery case behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo 'usage: record_recovery_case.sh DISPOSABLE_IMAGE CASE_ID OUTPUT_DIRECTORY' >&2
    exit 16
fi
image=$1
case_id=$2
output=$3
if [[ ! -f "$image" || ! "$case_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo 'error: provide a regular disposable image and a simple case ID' >&2
    exit 16
fi
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
if [[ ! -x "$project_root/target/release/ntfs-chkdsk" ]]; then
    echo 'error: build ntfs-chkdsk first' >&2
    exit 16
fi
mkdir -p -- "$output"
before=$(sha256sum -- "$image" | cut -d' ' -f1)
summary="$output/$case_id.slate.txt"
{
    printf 'case_id=%s\n' "$case_id"
    printf 'image_sha256_before=%s\n' "$before"
    printf 'image_bytes=%s\n' "$(stat -c %s -- "$image")"
} > "$summary"
for mode in status recovery-status log-inventory check; do
    set +e
    timeout 180 "$project_root/target/release/ntfs-chkdsk" "--$mode" "$image" \
        > "$output/$case_id.$mode.txt" 2>&1
    result=$?
    set -e
    printf '%s_exit=%s\n' "$mode" "$result" >> "$summary"
done
after=$(sha256sum -- "$image" | cut -d' ' -f1)
printf 'image_sha256_after=%s\n' "$after" >> "$summary"
if [[ "$before" != "$after" ]]; then
    echo 'error: the source image changed during read-only inspection' >&2
    exit 8
fi
echo "$summary"
