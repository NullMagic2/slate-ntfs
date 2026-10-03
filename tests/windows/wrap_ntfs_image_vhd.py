#!/usr/bin/env python3
"""Module: tests.windows.wrap_ntfs_image_vhd
Purpose: Wrap disposable raw NTFS images in fixed VHD containers.
Created: 2026-10-02
Architecture: Preparation scripts supply raw images; this helper owns container encoding for
read-only Windows checks.

Wrap a disposable raw NTFS partition image in a fixed VHD for read-only Windows checks."""

import argparse
import datetime
import pathlib
import shutil
import struct
import uuid

SECTOR = 512
PARTITION_START = 2048


def footer(size: int) -> bytes:
    sectors = size // SECTOR
    heads, sectors_per_track = 16, 63
    cylinders = max(1, min(65535, sectors // (heads * sectors_per_track)))
    result = bytearray(512)
    result[0:8] = b"conectix"
    struct.pack_into(">I", result, 8, 2)
    struct.pack_into(">I", result, 12, 0x00010000)
    struct.pack_into(">Q", result, 16, 0xFFFFFFFFFFFFFFFF)
    epoch = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
    stamp = int((datetime.datetime.now(datetime.timezone.utc) - epoch).total_seconds())
    struct.pack_into(">I", result, 24, stamp)
    result[28:32] = b"slat"
    struct.pack_into(">I", result, 32, 0x00010000)
    result[36:40] = b"Wi2k"
    struct.pack_into(">Q", result, 40, size)
    struct.pack_into(">Q", result, 48, size)
    struct.pack_into(">HBB", result, 56, cylinders, heads, sectors_per_track)
    struct.pack_into(">I", result, 60, 2)
    result[68:84] = uuid.uuid4().bytes
    struct.pack_into(">I", result, 64, (~sum(result)) & 0xFFFFFFFF)
    return bytes(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("partition_image", type=pathlib.Path)
    parser.add_argument("new_vhd", type=pathlib.Path)
    args = parser.parse_args()
    with args.partition_image.open("rb") as source:
        boot = source.read(512)
        size = source.seek(0, 2)
        source.seek(0)
        if size < 32 * 1024 * 1024 or size % SECTOR or size // SECTOR > 0xFFFFFFFF:
            parser.error("NTFS partition must be a 512-byte-aligned regular image of at least 32 MiB")
        if boot[3:11] != b"NTFS    " or boot[510:512] != b"\x55\xaa":
            parser.error("source does not have an NTFS boot sector")
        if int.from_bytes(boot[0x28:0x30], "little") not in (size // SECTOR, size // SECTOR - 1):
            parser.error("NTFS boot geometry does not match source image length")
        total_sectors = PARTITION_START + size // SECTOR
        if total_sectors > 0xFFFFFFFF:
            parser.error("partition exceeds MBR range")
        mbr = bytearray(512)
        entry = 446
        mbr[entry + 1 : entry + 4] = b"\xfe\xff\xff"
        mbr[entry + 4] = 0x07
        mbr[entry + 5 : entry + 8] = b"\xfe\xff\xff"
        struct.pack_into("<II", mbr, entry + 8, PARTITION_START, size // SECTOR)
        mbr[510:512] = b"\x55\xaa"
        with args.new_vhd.open("xb") as output:
            output.write(mbr)
            output.write(bytes((PARTITION_START - 1) * SECTOR))
            shutil.copyfileobj(source, output)
            output.write(footer(total_sectors * SECTOR))
            output.flush()
    print(args.new_vhd)


if __name__ == "__main__":
    main()
