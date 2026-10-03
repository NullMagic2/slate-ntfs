#!/usr/bin/env bash
# Module: src.tests.checker.test_checkfs
# Purpose: Verify checkfs behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
for tool in cargo cp cut mkfs.ntfs ntfscp python3 sha256sum timeout truncate; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool is required" >&2
        exit 1
    }
done

cargo build --release --locked --manifest-path src/tools/Cargo.toml \
    --bin ntfs-checkfs --bin ntfs-chkdsk --bin fsck_ntfsrs
binaries=./src/tools/target/release
image=$(mktemp --suffix=.img)
corrupt=$(mktemp --suffix=.img)
hiber=$(mktemp --suffix=.img)
zeroed_hiber=$(mktemp --suffix=.img)
hiber_file=$(mktemp)
trap 'rm -f -- "$image" "$corrupt" "$hiber" "$zeroed_hiber" "$hiber_file"' EXIT
truncate -s 64M "$image"
mkfs.ntfs -F -Q "$image" >/dev/null 2>&1

[[ "$("$binaries"/ntfs-checkfs --status "$image")" == 'dirty=0' ]]
[[ "$("$binaries"/ntfs-chkdsk --status "$image")" == 'dirty=0' ]]
"$binaries"/ntfs-chkdsk --check "$image"
[[ "$("$binaries"/ntfs-chkdsk --recovery-status "$image")" == *'log_state=uninitialized'* ]]
[[ "$("$binaries"/ntfs-chkdsk --log-inventory "$image")" == *'log_inventory=uninitialized'* ]]
"$binaries"/ntfs-checkfs "$image"
"$binaries"/fsck_ntfsrs --repair "$image"

cp -- "$image" "$hiber"
python3 - "$hiber_file" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b'HIBR' + b'\0' * 4092)
PY
ntfscp -f "$hiber" "$hiber_file" /hiberfil.sys
[[ "$("$binaries"/ntfs-chkdsk --recovery-status "$hiber")" == *'hibernation_file_present=1'* ]]
[[ "$("$binaries"/ntfs-chkdsk --recovery-status "$hiber")" == *'hibernation_state=active-image'* ]]
set +e
"$binaries"/ntfs-chkdsk --check "$hiber"
result=$?
set -e
[[ "$result" -eq 4 ]]

cp -- "$image" "$zeroed_hiber"
python3 - "$hiber_file" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b'\0' * 4096)
PY
ntfscp -f "$zeroed_hiber" "$hiber_file" /hiberfil.sys
[[ "$("$binaries"/ntfs-chkdsk --recovery-status "$zeroed_hiber")" == *'hibernation_state=zeroed-header'* ]]

cp -- "$image" "$corrupt"
python3 - "$corrupt" <<'PY'
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("r+b") as image:
    boot = image.read(512)
    cluster = int.from_bytes(boot[0x0b:0x0d], "little") * boot[0x0d]
    encoded = int.from_bytes(boot[0x40:0x41], "little", signed=True)
    record_size = cluster * encoded if encoded > 0 else 1 << -encoded
    mft_lcn = int.from_bytes(boot[0x30:0x38], "little")
    image.seek(mft_lcn * cluster + 4 * record_size + 510)
    image.write(b"\0\0")
PY
set +e
"$binaries"/ntfs-chkdsk --check "$corrupt"
result=$?
set -e
[[ "$result" -eq 4 ]]

# Alter only the $Volume dirty flag on a disposable, unmounted image.
python3 - "$image" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open('r+b') as image:
    boot = image.read(512)
    sector = int.from_bytes(boot[0x0b:0x0d], 'little')
    cluster = sector * boot[0x0d]
    encoded = int.from_bytes(boot[0x40:0x41], 'little', signed=True)
    record_size = cluster * encoded if encoded > 0 else 1 << -encoded
    mft_lcn = int.from_bytes(boot[0x30:0x38], 'little')
    position = mft_lcn * cluster + 3 * record_size
    image.seek(position)
    record = image.read(record_size)
    assert record[:4] == b'FILE'
    offset = int.from_bytes(record[0x14:0x16], 'little')
    while offset + 8 <= len(record):
        kind = int.from_bytes(record[offset:offset + 4], 'little')
        if kind == 0xffffffff:
            break
        length = int.from_bytes(record[offset + 4:offset + 8], 'little')
        assert length >= 0x18 and offset + length <= len(record)
        if kind == 0x70:
            assert record[offset + 8] == 0
            value = offset + int.from_bytes(record[offset + 0x14:offset + 0x16], 'little')
            flags = int.from_bytes(record[value + 10:value + 12], 'little')
            image.seek(position + value + 10)
            image.write((flags | 1).to_bytes(2, 'little'))
            break
        offset += length
    else:
        raise AssertionError('$VOLUME_INFORMATION not found')
PY

[[ "$("$binaries"/ntfs-checkfs --status "$image")" == 'dirty=1' ]]
[[ "$("$binaries"/ntfs-chkdsk --status "$image")" == 'dirty=1' ]]
before=$(sha256sum "$image" | cut -d' ' -f1)
set +e
"$binaries"/ntfs-chkdsk --repair "$image"
result=$?
set -e
[[ "$result" -eq 8 ]]
[[ "$(sha256sum "$image" | cut -d' ' -f1)" == "$before" ]]
set +e
"$binaries"/ntfs-chkdsk --check "$image"
result=$?
set -e
[[ "$result" -eq 4 ]]
set +e
"$binaries"/ntfs-checkfs "$image"
result=$?
set -e
[[ "$result" -eq 4 ]]
set +e
timeout 18s "$binaries"/fsck_ntfsrs --check "$image"
result=$?
set -e
[[ "$result" -eq 4 ]]
# Regular images cannot establish the exclusive block-device claim for repairs.
set +e
"$binaries"/fsck_ntfsrs --repair "$image"
result=$?
set -e
[[ "$result" -eq 8 ]]
[[ "$(sha256sum "$image" | cut -d' ' -f1)" == "$before" ]]
echo 'Checker smoke test passed (clean and marked-dirty disposable images).'
