#!/usr/bin/env python3
"""Module: checker_readonly_assessment_tests
Purpose: Verify clean-volume acceptance and targeted whole-volume damage reports.
Created: 2026-10-01
Architecture: Independently edits disposable images and invokes the public checker;
    callers supply an immutable clean NTFS fixture and retain resulting evidence.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess


CASES = (
    "baseline", "filename-cache", "header-links", "header-links-zero",
    "header-links-one", "header-links-max", "standard-created",
    "volume-dirty", "log-dirty", "log-torn", "record-torn",
    "record-unallocated", "allocation-missing", "allocation-leak",
    "security-id", "reparse-flag",
    "upcase-information-missing", "upcase-information-short",
    "upcase-information-size", "upcase-information-checksum",
    "upcase-table-checksum", "resident-value-offset", "resident-value-length",
)

ACCEPTED = {
    "baseline", "filename-cache", "header-links", "header-links-zero",
    "header-links-one", "header-links-max", "standard-created", "volume-dirty",
    "log-dirty", "log-torn",
}


def integer(data, offset, size):
    return int.from_bytes(data[offset:offset + size], "little")


def put(data, offset, value, size):
    data[offset:offset + size] = value.to_bytes(size, "little")


def attributes(record):
    offset = integer(record, 20, 2)
    while integer(record, offset, 4) != 0xFFFFFFFF:
        length = integer(record, offset + 4, 4)
        assert length >= 24 and offset + length <= len(record)
        yield offset
        offset += length


def decode(data, sector):
    result = bytearray(data)
    offset, count = struct.unpack_from("<HH", result, 4)
    for number in range(1, count):
        tail = number * sector - 2
        assert result[tail:tail + 2] == result[offset:offset + 2]
        result[tail:tail + 2] = result[offset + number * 2:offset + number * 2 + 2]
    return result


def protect(data, sector):
    result = bytearray(data)
    offset, count = struct.unpack_from("<HH", result, 4)
    for number in range(1, count):
        tail = number * sector - 2
        result[offset + number * 2:offset + number * 2 + 2] = result[tail:tail + 2]
        result[tail:tail + 2] = result[offset:offset + 2]
    return result


class Image:
    def __init__(self, path):
        self.file = path.open("r+b")
        self.boot = self.file.read(512)
        self.sector = integer(self.boot, 11, 2)
        self.cluster = self.sector * self.boot[13]
        factor = int.from_bytes(self.boot[64:65], "little", signed=True)
        self.record_bytes = self.cluster * factor if factor > 0 else 1 << -factor
        self.file.seek(integer(self.boot, 48, 8) * self.cluster)
        self.zero = decode(self.file.read(self.record_bytes), self.sector)
        self.mft_runs = self.runs(self.zero, self.attribute(self.zero, 0x80))

    @staticmethod
    def attribute(record, kind):
        return next(
            offset for offset in attributes(record)
            if integer(record, offset, 4) == kind and record[offset + 9] == 0
        )

    @staticmethod
    def value(record, attribute):
        return attribute + integer(record, attribute + 20, 2)

    @staticmethod
    def runs(record, attribute):
        offset = attribute + integer(record, attribute + 32, 2)
        vcn = integer(record, attribute + 16, 8)
        lcn = 0
        result = []
        while record[offset]:
            count_bytes = record[offset] & 15
            delta_bytes = record[offset] >> 4
            offset += 1
            count = integer(record, offset, count_bytes)
            offset += count_bytes
            lcn += int.from_bytes(
                record[offset:offset + delta_bytes], "little", signed=True
            )
            offset += delta_bytes
            assert delta_bytes != 0
            result.append((vcn, lcn, count))
            vcn += count
        return result

    def physical(self, runs, offset):
        vcn = offset // self.cluster
        run = next(run for run in runs if run[0] <= vcn < run[0] + run[2])
        return run[1] * self.cluster + offset - run[0] * self.cluster

    def get(self, number):
        self.file.seek(self.physical(self.mft_runs, number * self.record_bytes))
        return decode(self.file.read(self.record_bytes), self.sector)

    def save(self, number, record):
        raw = protect(record, self.sector)
        self.file.seek(self.physical(self.mft_runs, number * self.record_bytes))
        self.file.write(raw)
        if number < 4:
            mirror = integer(self.boot, 56, 8) * self.cluster
            self.file.seek(mirror + number * self.record_bytes)
            self.file.write(raw)

    def bit(self, runs, number, allocated):
        offset = self.physical(runs, number // 8)
        self.file.seek(offset)
        old = self.file.read(1)[0]
        mask = 1 << (number % 8)
        self.file.seek(offset)
        self.file.write(bytes([old | mask if allocated else old & ~mask]))

    def mutate(self, case):
        if case == "baseline":
            return
        if case.startswith("upcase-"):
            record = self.get(10)
            if case == "upcase-table-checksum":
                data = self.attribute(record, 0x80)
                runs = self.runs(record, data)
                position = self.physical(runs, 0x378 * 2)
                self.file.seek(position)
                assert self.file.read(4) == bytes.fromhex("78037903")
                self.file.seek(position)
                self.file.write(bytes.fromhex("7903"))
                return
            information = next(
                offset for offset in attributes(record)
                if integer(record, offset, 4) == 0x80
                and record[offset + 9]
                and record[
                    offset + integer(record, offset + 10, 2):
                    offset + integer(record, offset + 10, 2) + record[offset + 9] * 2
                ] == "$Info".encode("utf-16le")
            )
            value = self.value(record, information)
            if case == "upcase-information-missing":
                length = integer(record, information + 4, 4)
                used = integer(record, 24, 4)
                record[information:used - length] = record[information + length:used]
                record[used - length:used] = bytes(length)
                put(record, 24, used - length, 4)
            elif case == "upcase-information-short":
                put(record, information + 16, 16, 4)
            elif case == "upcase-information-size":
                put(record, value, 16, 4)
            else:
                record[value + 8] ^= 1
            self.save(10, record)
        elif case in ("resident-value-offset", "resident-value-length"):
            record = self.get(37)
            information = self.attribute(record, 0x10)
            if case == "resident-value-offset":
                put(record, information + 20, 0, 2)
            else:
                put(record, information + 16, 1000, 4)
            self.save(37, record)
        elif case in (
            "filename-cache", "header-links", "header-links-zero",
            "header-links-one", "header-links-max", "standard-created",
            "security-id", "reparse-flag",
        ):
            record = self.get(37)
            if case.startswith("header-links"):
                count = {
                    "header-links": 3,
                    "header-links-zero": 0,
                    "header-links-one": 1,
                    "header-links-max": 65535,
                }[case]
                put(record, 18, count, 2)
            elif case == "filename-cache":
                for offset in attributes(record):
                    if integer(record, offset, 4) == 0x30:
                        value = self.value(record, offset)
                        put(record, value + 8, 12345, 8)
                        put(record, value + 48, 999, 8)
            else:
                value = self.value(record, self.attribute(record, 0x10))
                if case == "standard-created":
                    put(record, value, integer(record, value, 8) + 1, 8)
                elif case == "security-id":
                    put(record, value + 52, 65535, 4)
                else:
                    put(record, value + 32, integer(record, value + 32, 4) | 0x400, 4)
            self.save(37, record)
        elif case == "volume-dirty":
            record = self.get(3)
            value = self.value(record, self.attribute(record, 0x70))
            put(record, value + 10, integer(record, value + 10, 2) | 1, 2)
            self.save(3, record)
        elif case in ("log-dirty", "log-torn"):
            record = self.get(2)
            runs = self.runs(record, self.attribute(record, 0x80))
            for logical in (0, 4096):
                physical = self.physical(runs, logical)
                self.file.seek(physical)
                raw = self.file.read(4096)
                if case == "log-torn":
                    if logical == 0:
                        raw = bytearray(raw)
                        raw[510] ^= 1
                        self.file.seek(physical)
                        self.file.write(raw)
                else:
                    page = decode(raw, self.sector)
                    area = integer(page, 24, 2)
                    put(page, area + 14, integer(page, area + 14, 2) & ~2, 2)
                    self.file.seek(physical)
                    self.file.write(protect(page, self.sector))
        elif case == "record-torn":
            offset = self.physical(self.mft_runs, 37 * self.record_bytes)
            offset += self.sector - 2
            self.file.seek(offset)
            value = self.file.read(1)[0]
            self.file.seek(offset)
            self.file.write(bytes([value ^ 1]))
        elif case == "record-unallocated":
            self.bit(self.runs(self.zero, self.attribute(self.zero, 0xB0)), 37, False)
        elif case in ("allocation-missing", "allocation-leak"):
            bitmap = self.get(6)
            runs = self.runs(bitmap, self.attribute(bitmap, 0x80))
            number = (
                integer(self.boot, 48, 8)
                if case == "allocation-missing" else 15000
            )
            self.bit(runs, number, case == "allocation-leak")
        else:
            raise ValueError(case)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "fixture", type=Path,
        help="Clean 64 MiB fixture with an ordinary file at MFT record 37 "
             "and free cluster 15000",
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument("--checker", required=True, type=Path)
    args = parser.parse_args()
    original_hash = digest(args.fixture)
    args.directory.mkdir(parents=True, exist_ok=False)
    results = []
    for case in CASES:
        image = args.directory / f"{case}.img"
        shutil.copyfile(args.fixture, image)
        editor = Image(image)
        try:
            editor.mutate(case)
        finally:
            editor.file.close()
        before = digest(image)
        result = subprocess.run(
            [str(args.checker), "--json", "--check", str(image)],
            capture_output=True, text=True,
        )
        assert before == digest(image), f"check modified {case}"
        report = json.loads(result.stdout)
        results.append({
            "case": case,
            "sha256": before,
            "exit": result.returncode,
            "report": report,
            "stderr": result.stderr,
        })
    assert original_hash == digest(args.fixture), "original fixture changed"
    (args.directory / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    clean = next(result for result in results if result["case"] == "baseline")
    assert clean["exit"] == 0 and clean["report"]["complete"], clean
    cached = next(result for result in results if result["case"] == "filename-cache")
    assert cached["exit"] == 0, cached
    for result in results:
        if result["case"] in ACCEPTED:
            assert result["exit"] == 0, result
        else:
            assert result["exit"] != 0, result
    print(f"{len(results)} immutable read-only assessment cases passed")


if __name__ == "__main__":
    main()
