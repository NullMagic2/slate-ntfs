#!/usr/bin/env python3
"""Module: checker_filename_cache_tests
Purpose: Preserve valid stale name caches while repairing genuine corruption.
Created: 2026-10-02
Architecture: Independent image encoders exercise the shared checker and
    structural planner through the CLI; copy repairs never modify the source.
"""

import os
from pathlib import Path
import shutil
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT / "tests/support"))
from ntfs_image import (
    CHECKER, attr, attrs, decode, digest, first_extent, protect, put, run, u,
)
from test_consistency import damage

FORMATTER = Path(os.environ.get(
    "SLATE_NTFS_FORMATTER", PROJECT / "ntfs_utils/target/release/ntfs-format",
))
IMAGE_BYTES = 64 << 20
BOOT_BYTES = 512
BOOT_SECTOR_SIZE = 11
BOOT_CLUSTER_SECTORS = 13
BOOT_MFT_CLUSTER = 48
BOOT_RECORD_SIZE = 64
ATTR_FILE_NAME = 0x30
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_VALUE_OFFSET = 20
ATTR_VALUE_LENGTH = 16
INDEX_ROOT_HEADER = 16
INDEX_BLOCK_HEADER = 24
INDEX_USED_LENGTH = 4
INDEX_ENTRY_LENGTH = 8
INDEX_ENTRY_FLAGS = 12
INDEX_KEY_OFFSET = 16
INDEX_END = 2
REFERENCE_BYTES = 8
REFERENCE_RECORD_MASK = (1 << 48) - 1
WORD_BYTES = 2
DWORD_BYTES = 4
TARGET_RECORDS = (10, 24)
PARENT_RECORDS = (5, 11)
FN_CREATION_TIME = 8
FN_MODIFICATION_TIME = 16
FN_MFT_TIME = 24
FN_ALLOCATED_SIZE = 40
FN_DATA_SIZE = 48
FN_FLAGS = 56
FILE_ARCHIVE = 0x20
STALE_SIZE_INCREMENT = 4096
INDEX_BLOCK_BYTES = 4096


def stale_cache(value):
    # Change cached fields only, retaining the parent, type and exact name.

    for offset in (FN_CREATION_TIME, FN_MODIFICATION_TIME, FN_MFT_TIME):
        put(value, offset, u(value, offset, REFERENCE_BYTES) ^ 1, REFERENCE_BYTES)
    for offset in (FN_ALLOCATED_SIZE, FN_DATA_SIZE):
        put(value, offset, u(value, offset, REFERENCE_BYTES) + STALE_SIZE_INCREMENT,
            REFERENCE_BYTES)
    put(value, FN_FLAGS, u(value, FN_FLAGS, DWORD_BYTES) ^ FILE_ARCHIVE, DWORD_BYTES)


def alter_caches(path, change_names, change_indexes):
    with path.open("r+b") as image:
        boot = image.read(BOOT_BYTES)
        sector = u(boot, BOOT_SECTOR_SIZE, WORD_BYTES)
        cluster = sector * boot[BOOT_CLUSTER_SECTORS]
        encoding = int.from_bytes(boot[BOOT_RECORD_SIZE:BOOT_RECORD_SIZE + 1],
                                  "little", signed=True)
        record_bytes = (1 << -encoding) if encoding < 0 else encoding * cluster
        mft = u(boot, BOOT_MFT_CLUSTER, REFERENCE_BYTES) * cluster

        def get(number):
            image.seek(mft + number * record_bytes)
            return decode(image.read(record_bytes), sector)

        def save(number, record):
            image.seek(mft + number * record_bytes)
            image.write(protect(record, sector))

        if change_names:
            for number in TARGET_RECORDS:
                record = get(number)
                offset = attr(record, ATTR_FILE_NAME)
                value_at = offset + u(record, offset + ATTR_VALUE_OFFSET, WORD_BYTES)
                length = u(record, offset + ATTR_VALUE_LENGTH, DWORD_BYTES)
                value = bytearray(record[value_at:value_at + length])
                stale_cache(value)
                record[value_at:value_at + length] = value
                save(number, record)

        changed = set()

        def index_keys(record, header):
            cursor = header + u(record, header, DWORD_BYTES)
            end = header + u(record, header + INDEX_USED_LENGTH, DWORD_BYTES)
            while cursor < end:
                length = u(record, cursor + INDEX_ENTRY_LENGTH, WORD_BYTES)
                assert length >= INDEX_KEY_OFFSET
                if u(record, cursor + INDEX_ENTRY_FLAGS, WORD_BYTES) & INDEX_END:
                    break
                number = u(record, cursor, REFERENCE_BYTES) & REFERENCE_RECORD_MASK
                if number in TARGET_RECORDS:
                    key = cursor + INDEX_KEY_OFFSET
                    value = bytearray(record[key:cursor + length])
                    stale_cache(value)
                    record[key:cursor + length] = value
                    changed.add(number)
                cursor += length

        if change_indexes:
            for number in PARENT_RECORDS:
                record = get(number)
                for offset, kind in list(attrs(record)):
                    if kind == ATTR_INDEX_ROOT:
                        value_at = offset + u(record, offset + ATTR_VALUE_OFFSET, WORD_BYTES)
                        index_keys(record, value_at + INDEX_ROOT_HEADER)
                    elif kind == ATTR_INDEX_ALLOCATION:
                        lcn, clusters = first_extent(record, offset)
                        for at in range(lcn * cluster, (lcn + clusters) * cluster,
                                        INDEX_BLOCK_BYTES):
                            image.seek(at)
                            raw = image.read(INDEX_BLOCK_BYTES)
                            if raw[:DWORD_BYTES] != b"INDX":
                                continue
                            block = decode(raw, sector)
                            index_keys(block, INDEX_BLOCK_HEADER)
                            image.seek(at)
                            image.write(protect(block, sector))
                save(number, record)
            assert changed == set(TARGET_RECORDS), changed


def empty_plan(path, quick=False):
    args = [CHECKER]
    if quick:
        args.append("--index-check=quick")
    result = run(*args, "--repair-plan", path)
    assert result.stdout.strip() == b"repair_supported=1 ranges=0 bytes=0", result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="slate-filename-cache-") as folder:
        work = Path(folder)
        base = work / "base.img"
        with base.open("xb") as image:
            image.truncate(IMAGE_BYTES)
        run(FORMATTER, "--yes", "--quick", base)
        for names, indexes in ((True, False), (False, True), (True, True)):
            stale = work / f"stale-{names}-{indexes}.img"
            shutil.copyfile(base, stale)
            alter_caches(stale, names, indexes)
            expected = digest(stale)
            run(CHECKER, "--check", stale)
            empty_plan(stale)
            empty_plan(stale, quick=True)
            assert digest(stale) == expected, "read-only scan changed source"
            copied = work / "copied.img"
            run(CHECKER, "--repair-to", stale, copied)
            assert digest(copied) == expected, "clean copy rewrote filename caches"
            copied.unlink()

            damaged = work / "damaged.img"
            shutil.copyfile(stale, damaged)
            damage(damaged, "cluster-marked-free")
            before = digest(damaged)
            audit = run(CHECKER, "--check", damaged, ok=False)
            assert b"finding=cluster-marked-free" in audit.stdout
            plan = run(CHECKER, "--repair-plan", damaged)
            assert b"ranges=0 " not in plan.stdout
            run(CHECKER, "--repair-to", damaged, copied)
            run(CHECKER, "--check", copied)
            assert digest(copied) == expected, "bitmap repair rewrote filename caches"
            assert digest(damaged) == before, "copy repair changed source"
            copied.unlink()

        damage(stale, "stale-index-reference")
        audit = run(CHECKER, "--check", stale, ok=False)
        assert b"finding=stale-index-reference" in audit.stdout
    print("Filename cache regressions passed: MFT, index and combined caches; "
          "full/quick plans; byte-identical copies; genuine allocation repairs; "
          "stale index sequence detection and source preservation.")


if __name__ == "__main__":
    main()
