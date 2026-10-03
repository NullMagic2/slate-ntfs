#!/usr/bin/env bash
# Module: src.tests.writer.test_write_lab
# Purpose: Verify write lab behavior on disposable fixtures.
# Created: 2026-10-01
# Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
for tool in cmp mkfs.ntfs ntfscp ntfscat python3 sha256sum truncate; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing $tool" >&2; exit 1; }
done
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
source_image="$scratch/source.img"
candidate_image="$scratch/candidate.img"
payload="$scratch/payload.bin"
expected_file="$scratch/expected.bin"
truncate -s 64M "$source_image"
mkfs.ntfs -F -Q "$source_image" >/dev/null 2>&1
python3 - "$payload" "$expected_file" <<'PY'
import pathlib, sys
payload = bytearray(i % 256 for i in range(16384))
pathlib.Path(sys.argv[1]).write_bytes(payload)
payload[4090:4106] = bytes.fromhex('102030405060708090a0b0c0d0e0f000')
pathlib.Path(sys.argv[2]).write_bytes(payload)
PY
ntfscp -f "$source_image" "$payload" /write-target.bin
source_before=$(sha256sum "$source_image" | cut -d' ' -f1)
./target/release/ntfs-write-lab "$source_image" "$candidate_image" write-target.bin 4090 \
    fafbfcfdfeff00010203040506070809 102030405060708090a0b0c0d0e0f000
source_after=$(sha256sum "$source_image" | cut -d' ' -f1)
[[ "$source_before" == "$source_after" ]]
changed_bytes=$(( $( (cmp -l "$source_image" "$candidate_image" || true) | wc -l) ))
[[ "$changed_bytes" -eq 16 ]]
ntfscat "$candidate_image" /write-target.bin > "$scratch/observed.bin"
cmp "$expected_file" "$scratch/observed.bin"
./target/release/ntfs-chkdsk --check "$candidate_image" >/dev/null
if ./target/release/ntfs-write-lab "$source_image" "$scratch/rejected.img" write-target.bin 4090 \
    00000000000000000000000000000000 102030405060708090a0b0c0d0e0f000 \
    > "$scratch/rejected.txt" 2>&1; then
    echo 'error: incorrect preimage was accepted' >&2
    exit 1
fi
[[ ! -e "$scratch/rejected.img" ]]
cp -- "$source_image" "$scratch/dirty.img"
python3 - "$scratch/dirty.img" <<'PY'
import pathlib, sys
with pathlib.Path(sys.argv[1]).open('r+b') as image:
    boot = image.read(512)
    cluster = int.from_bytes(boot[0x0b:0x0d], 'little') * boot[0x0d]
    encoded = int.from_bytes(boot[0x40:0x41], 'little', signed=True)
    record_size = cluster * encoded if encoded > 0 else 1 << -encoded
    position = int.from_bytes(boot[0x30:0x38], 'little') * cluster + 3 * record_size
    image.seek(position)
    record = image.read(record_size)
    assert record[:4] == b'FILE'
    offset = int.from_bytes(record[0x14:0x16], 'little')
    while offset + 8 <= record_size:
        kind = int.from_bytes(record[offset:offset + 4], 'little')
        if kind == 0xffffffff:
            break
        length = int.from_bytes(record[offset + 4:offset + 8], 'little')
        assert length >= 0x18 and offset + length <= record_size
        if kind == 0x70:
            value = offset + int.from_bytes(record[offset + 0x14:offset + 0x16], 'little')
            flag_position = position + value + 10
            flags = int.from_bytes(record[value + 10:value + 12], 'little')
            image.seek(flag_position)
            image.write((flags | 1).to_bytes(2, 'little'))
            break
        offset += length
    else:
        raise AssertionError('no $VOLUME_INFORMATION found')
PY
if ./target/release/ntfs-write-lab "$scratch/dirty.img" "$scratch/dirty-rejected.img" write-target.bin 4090 \
    fafbfcfdfeff00010203040506070809 102030405060708090a0b0c0d0e0f000 \
    > "$scratch/dirty-rejected.txt" 2>&1; then
    echo 'error: dirty image was accepted' >&2
    exit 1
fi
[[ ! -e "$scratch/dirty-rejected.img" ]]
cp -- "$source_image" "$scratch/hiber.img"
python3 - "$scratch/hiber.page" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b'HIBR' + bytes(4092))
PY
ntfscp -f "$scratch/hiber.img" "$scratch/hiber.page" /hiberfil.sys
plan=$(./target/release/ntfs-chkdsk --plan-hibernation-discard "$scratch/hiber.img")
[[ "$plan" == *'hiber_clusters=1'* ]]
[[ "$plan" == *'discard_ready=0'* ]]
if ./target/release/ntfs-write-lab "$scratch/hiber.img" "$scratch/hiber-rejected.img" write-target.bin 4090 \
    fafbfcfdfeff00010203040506070809 102030405060708090a0b0c0d0e0f000 \
    > "$scratch/hiber-rejected.txt" 2>&1; then
    echo 'error: hibernated image was accepted' >&2
    exit 1
fi
[[ ! -e "$scratch/hiber-rejected.img" ]]
if ./target/release/ntfs-write-lab --override-hibernation "$scratch/hiber.img" \
    "$scratch/hiber-override.img" write-target.bin 4090 \
    fafbfcfdfeff00010203040506070809 102030405060708090a0b0c0d0e0f000 \
    > "$scratch/hiber-override.txt" 2>&1; then
    echo 'error: override wrote without transactional hiberfil deletion' >&2
    exit 1
fi
[[ ! -e "$scratch/hiber-override.img" ]]
[[ "$(cat "$scratch/hiber-override.txt")" == *'transactional hiberfil.sys deletion is not implemented'* ]]
echo 'Disposable NTFS image write and independent NTFS-3G readback passed.'
