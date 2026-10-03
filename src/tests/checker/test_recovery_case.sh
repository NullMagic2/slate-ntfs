#!/usr/bin/env bash
# Module: src.tests.checker.test_recovery_case
# Purpose: Verify recovery case behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
image=$(mktemp --suffix=.img)
output=$(mktemp -d)
trap 'rm -f -- "$image"; rm -rf -- "$output"' EXIT
truncate -s 64M "$image"
mkfs.ntfs -F -Q "$image" >/dev/null 2>&1
bash src/tests/checker/record_recovery_case.sh "$image" clean-case "$output" >/dev/null
grep -q '^status_exit=0$' "$output/clean-case.slate.txt"
grep -q '^check_exit=0$' "$output/clean-case.slate.txt"
grep -q '^image_sha256_before=' "$output/clean-case.slate.txt"
before=$(sed -n 's/^image_sha256_before=//p' "$output/clean-case.slate.txt")
after=$(sed -n 's/^image_sha256_after=//p' "$output/clean-case.slate.txt")
[[ "$before" == "$after" ]]
printf HIBR > "$output/hiber.page"
truncate -s 4096 "$output/hiber.page"
[[ "$(./target/release/ntfs-chkdsk --hibernation-page "$output/hiber.page")" == 'hibernation_state=active-image' ]]
echo 'Recovery case and hibernation sample smoke test passed.'
